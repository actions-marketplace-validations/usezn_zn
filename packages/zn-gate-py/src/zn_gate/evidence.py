"""
Cryptographic Evidence Engine for zn-gate-py.
Maintains a tamper-evident SHA-256 hash-chained audit ledger at ~/.zn/evidence.jsonl.
Pure Python stdlib. Zero external dependencies.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple


def _redact(text: str) -> str:
    from .rules import mask_token_runs, redact_secrets  # local import avoids import cycles
    return mask_token_runs(redact_secrets(text)[0])

ZN_DIR = os.path.expanduser("~/.zn")
EVIDENCE_FILE = os.path.join(ZN_DIR, "evidence.jsonl")
GENESIS_HASH = "0" * 64


def _ensure_dir(file_path: str) -> None:
    # The ledger directory is private to the user (POSIX; the mode is ignored on Windows).
    dirname = os.path.dirname(file_path)
    if dirname and not os.path.exists(dirname):
        os.makedirs(dirname, mode=0o700, exist_ok=True)


def _open_for_append(file_path: str):
    """Opens the ledger for appending. New files are created 0600 and an existing
    file that is readable by others is restricted to 0600 (POSIX only)."""
    fd = os.open(file_path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    if os.name == "posix" and os.fstat(fd).st_mode & 0o077:
        os.fchmod(fd, 0o600)
    return os.fdopen(fd, "a", encoding="utf-8")


class EvidenceLedgerError(Exception):
    """The ledger exists but cannot be trusted or read (invalid bytes, a broken last line, an I/O error)."""


_warned_corrupt = False


def _read_ledger(file_path: str) -> Tuple[List[str], Dict[int, str]]:
    """Reads the ledger as raw bytes and decodes it line by line.
    Returns (lines, bad) where lines are the non-empty lines (undecodable bytes replaced) and
    bad maps a 0-based line index to the reason that line is not valid UTF-8.
    Raises EvidenceLedgerError when the file cannot be read."""
    try:
        with open(file_path, "rb") as f:
            raw = f.read()
    except OSError as e:
        raise EvidenceLedgerError(f"Cannot read the evidence log: {e.strerror or e}") from e
    lines: List[str] = []
    bad: Dict[int, str] = {}
    for chunk in raw.split(b"\n"):
        chunk = chunk.strip()
        if not chunk:
            continue
        try:
            lines.append(chunk.decode("utf-8"))
        except UnicodeDecodeError as e:
            bad[len(lines)] = f"Invalid UTF-8 bytes at line {len(lines) + 1} (byte {e.start}): the log was corrupted or modified."
            lines.append(chunk.decode("utf-8", errors="replace"))
    return lines, bad


def _corrupt_result(total: int, index: int, error: str) -> Dict[str, Any]:
    return {"valid": False, "total": total, "verified": index, "broken_index": index, "error": error}


def get_last_hash(file_path: str = EVIDENCE_FILE) -> str:
    """Reads the record_hash of the last line in the ledger.
    A missing or empty file is the start of a new chain (genesis). A log that exists but cannot be
    read or trusted raises EvidenceLedgerError: it never falls back to genesis, which would
    silently restart the chain."""
    if not os.path.exists(file_path):
        return GENESIS_HASH
    lines, bad = _read_ledger(file_path)
    if bad:
        raise EvidenceLedgerError(next(iter(bad.values())))
    if not lines:
        return GENESIS_HASH
    try:
        last_rec = json.loads(lines[-1])
    except ValueError as e:
        raise EvidenceLedgerError(f"Malformed JSON at line {len(lines)}: {e}") from e
    last_hash = last_rec.get("record_hash") if isinstance(last_rec, dict) else None
    if not isinstance(last_hash, str) or len(last_hash) != 64:
        raise EvidenceLedgerError(f"Last record (line {len(lines)}) has no valid record_hash.")
    return last_hash


def log_evidence(event: Dict[str, Any], file_path: str = EVIDENCE_FILE) -> Optional[Dict[str, Any]]:
    """
    Appends a cryptographically hash-chained evidence record to the ledger.
    Formula: record_hash = sha256(prev_hash + ":" + json(base_record))

    If the existing ledger is corrupt or unreadable, nothing is appended (the chain is never
    restarted), one warning is printed to stderr per process and None is returned. This never
    raises for a damaged log, so it does not block the user's command; run
    `zn-gate evidence --verify` for details.
    """
    global _warned_corrupt
    _ensure_dir(file_path)
    try:
        prev_hash = get_last_hash(file_path)
    except EvidenceLedgerError as e:
        if not _warned_corrupt:
            _warned_corrupt = True
            sys.stderr.write(
                f"zn-gate: the evidence log {file_path} is damaged ({e}) "
                "This event was not recorded. Run 'zn-gate evidence --verify' for details.\n"
            )
        return None
    timestamp = datetime.now(timezone.utc).isoformat()
    record_id = f"ev_{int(time.time() * 1000):x}_{secrets.token_hex(4)}"

    payload_raw = event.get("payload", "")
    payload_str = payload_raw if isinstance(payload_raw, str) else json.dumps(payload_raw, separators=(",", ":"))
    payload_sha256 = hashlib.sha256(payload_str.encode("utf-8")).hexdigest()

    raw_conf = event.get("confidence", 1.0)
    conf_val = int(raw_conf) if isinstance(raw_conf, (int, float)) and float(raw_conf).is_integer() else float(raw_conf)

    base_record = {
        "id": record_id,
        "timestamp": timestamp,
        "agent_environment": event.get("agent") or event.get("agent_environment") or "python-agent",
        "phase": event.get("phase", "tool-call"),
        "tool_name": event.get("tool_name") or event.get("tool") or "unknown",
        "payload_sha256": payload_sha256,
        # Redact the full payload first, then cut, so a secret straddling the cut is not leaked.
        "payload_preview": (_redact(payload_str) or "")[:120],
        "verdict": event.get("verdict", "allow"),
        "rule": event.get("rule", None),
        "reason": event.get("reason", None),
        "confidence": conf_val,
        "latency_us": int(event.get("latency_us", 0)),
        "engine": event.get("engine", "python-deterministic"),
        "prev_hash": prev_hash,
    }

    serialized_base = json.dumps(base_record, separators=(",", ":"))
    hash_input = f"{prev_hash}:{serialized_base}".encode("utf-8")
    record_hash = hashlib.sha256(hash_input).hexdigest()

    final_record = dict(base_record)
    final_record["record_hash"] = record_hash

    with _open_for_append(file_path) as f:
        f.write(json.dumps(final_record, separators=(",", ":")) + "\n")

    return final_record


def verify_evidence_ledger(file_path: str = EVIDENCE_FILE) -> Dict[str, Any]:
    """
    Verifies the cryptographic integrity of the entire ledger chain from genesis.
    Returns { "valid": bool, "total": int, "verified": int, "broken_index": Optional[int], "error": Optional[str] }
    """
    if not os.path.exists(file_path):
        return {"valid": True, "total": 0, "verified": 0, "broken_index": None, "error": None}

    try:
        lines, bad = _read_ledger(file_path)
    except EvidenceLedgerError as e:
        return _corrupt_result(0, 0, str(e))

    expected_prev = GENESIS_HASH

    for i, line in enumerate(lines):
        if i in bad:
            return _corrupt_result(len(lines), i, bad[i])
        try:
            rec = json.loads(line)
        except Exception as e:
            return {
                "valid": False,
                "total": len(lines),
                "verified": i,
                "broken_index": i,
                "error": f"Malformed JSON at line {i+1}: {e}",
            }
        if not isinstance(rec, dict):
            return _corrupt_result(len(lines), i, f"Malformed record at line {i+1}: not a JSON object.")

        rec_prev = rec.get("prev_hash")
        if rec_prev != expected_prev:
            return {
                "valid": False,
                "total": len(lines),
                "verified": i,
                "broken_index": i,
                "error": f"Broken chain link at line {i+1} (record {rec.get('id')}): expected {expected_prev[:8]}... found {str(rec_prev)[:8]}...",
            }

        recorded_hash = rec.get("record_hash")
        base_record = {k: v for k, v in rec.items() if k != "record_hash"}
        # Ensure confidence preserves whole number integer representation if whole
        if "confidence" in base_record and isinstance(base_record["confidence"], (int, float)) and float(base_record["confidence"]).is_integer():
            base_record["confidence"] = int(base_record["confidence"])
            
        serialized_base = json.dumps(base_record, separators=(",", ":"))
        computed_hash = hashlib.sha256(f"{expected_prev}:{serialized_base}".encode("utf-8")).hexdigest()

        if computed_hash != recorded_hash:
            return {
                "valid": False,
                "total": len(lines),
                "verified": i,
                "broken_index": i,
                "error": f"Tamper detected at line {i+1} (record {rec.get('id')}): hash mismatch! Log contents were modified.",
            }

        expected_prev = recorded_hash

    return {"valid": True, "total": len(lines), "verified": len(lines), "broken_index": None, "error": None}


def get_evidence_stats(file_path: str = EVIDENCE_FILE, limit: int = 50) -> Dict[str, Any]:
    """Generates aggregated stats from the evidence ledger."""
    if not os.path.exists(file_path):
        return {
            "total": 0,
            "blocks": 0,
            "allows": 0,
            "shadows": 0,
            "valid": True,
            "top_rules": {},
            "top_tools": {},
            "recent": [],
        }

    try:
        lines, bad = _read_ledger(file_path)
    except EvidenceLedgerError as e:
        return {"total": 0, "blocks": 0, "allows": 0, "shadows": 0, "valid": False, "error": str(e),
                "top_rules": {}, "top_tools": {}, "recent": []}

    blocks = 0
    allows = 0
    shadows = 0
    top_rules: Dict[str, int] = {}
    top_tools: Dict[str, int] = {}
    recent: List[Dict[str, Any]] = []

    for line in reversed(lines):
        try:
            rec = json.loads(line)
            if not isinstance(rec, dict):
                continue
            v = rec.get("verdict")
            if v == "block":
                blocks += 1
                r = rec.get("rule")
                if r:
                    top_rules[r] = top_rules.get(r, 0) + 1
            elif v == "shadow":
                shadows += 1
            else:
                allows += 1

            t = rec.get("tool_name")
            if t:
                top_tools[t] = top_tools.get(t, 0) + 1

            if len(recent) < limit:
                recent.append(rec)
        except Exception:
            continue

    check = verify_evidence_ledger(file_path)

    return {
        "total": len(lines),
        "blocks": blocks,
        "allows": allows,
        "shadows": shadows,
        "valid": check["valid"],
        "error": check.get("error"),
        "top_rules": top_rules,
        "top_tools": top_tools,
        "recent": recent,
    }


def export_evidence_ledger(file_path: Optional[str] = None, format: str = "jsonl") -> Dict[str, Any]:
    """
    Exports the evidence ledger into JSONL or CSV with cryptographic verification.
    Suitable for enterprise compliance audits (SOC 2, ISO 27001, EU AI Act Art. 12).
    """
    target_path = file_path if file_path else EVIDENCE_FILE
    norm_format = "csv" if (format or "jsonl").lower() == "csv" else "jsonl"

    if not os.path.exists(target_path):
        empty_content = (
            "timestamp,verdict,phase,tool_name,agent_environment,rule,reason,payload_sha256,record_hash,prev_hash,latency_us\n"
            if norm_format == "csv"
            else ""
        )
        return {
            "content": empty_content,
            "format": norm_format,
            "valid": True,
            "tip_hash": GENESIS_HASH,
            "total": 0,
        }

    verify_result = verify_evidence_ledger(target_path)
    try:
        lines, _bad = _read_ledger(target_path)
    except EvidenceLedgerError:
        lines = []

    tip_hash = GENESIS_HASH
    if lines:
        try:
            tip_hash = json.loads(lines[-1]).get("record_hash", GENESIS_HASH)
        except Exception:
            pass

    if norm_format == "csv":
        headers = [
            "timestamp",
            "verdict",
            "phase",
            "tool_name",
            "agent_environment",
            "rule",
            "reason",
            "payload_sha256",
            "record_hash",
            "prev_hash",
            "latency_us",
        ]
        rows = [",".join(headers)]
        for line in lines:
            try:
                obj = json.loads(line)
                row_vals = []
                for h in headers:
                    val = str(obj.get(h, "")) if obj.get(h) is not None else ""
                    escaped = val.replace('"', '""')
                    row_vals.append(f'"{escaped}"')
                rows.append(",".join(row_vals))
            except Exception:
                pass

        return {
            "content": "\n".join(rows) + "\n",
            "format": "csv",
            "valid": verify_result["valid"],
            "error": verify_result.get("error"),
            "tip_hash": tip_hash,
            "total": len(lines),
        }

    try:
        with open(target_path, "rb") as f:
            raw = f.read().decode("utf-8", errors="replace")
    except OSError:
        raw = ""

    return {
        "content": raw if raw.endswith("\n") else raw + "\n",
        "format": "jsonl",
        "valid": verify_result["valid"],
        "error": verify_result.get("error"),
        "tip_hash": tip_hash,
        "total": len(lines),
    }
