"""The Python rules must stay identical to the Node.js rules in packages/zn-gate.

The Node.js side is exported as JSON by packages/zn-gate/test/helpers/export_rules.js.
These tests need the monorepo checkout and a `node` binary; they are skipped
with a message when either is missing (for example when testing an sdist).
"""

import json
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from zn_gate import rules as R

NODE_PKG = Path(__file__).resolve().parents[2] / "zn-gate"
EXPORT_SCRIPT = NODE_PKG / "test" / "helpers" / "export_rules.js"
SAMPLES_FILE = NODE_PKG / "test" / "fixtures" / "rules_parity_samples.json"

# Secret patterns whose Python form differs on purpose, with the reason.
SECRET_PATTERN_EXCEPTIONS = {
    "secret:aws_secret_key": "the Python replacement keeps the original quotes, so its groups differ",
}


def _expand(sample):
    if isinstance(sample, str):
        return sample
    return sample.get("prefix", "") + sample["repeat"] * sample["times"] + sample.get("suffix", "")


def _py_table(entries):
    return [(rule_id, pat.pattern, bool(pat.flags & re.IGNORECASE)) for rule_id, pat, _ in entries]


def _js_table(entries):
    return [(e["id"], e["source"], "i" in e["flags"]) for e in entries]


def _js_regex(e):
    return (e["source"], "i" in e["flags"])


def _py_regex(pat):
    return (pat.pattern, bool(pat.flags & re.IGNORECASE))


_EXPORT = None


def _node_export():
    global _EXPORT
    if _EXPORT is None:
        node = shutil.which("node")
        if node is None:
            raise unittest.SkipTest("node is not installed: skipping the Node.js/Python rules parity check")
        if not EXPORT_SCRIPT.is_file() or not SAMPLES_FILE.is_file():
            raise unittest.SkipTest("packages/zn-gate is not next to this package: skipping the rules parity check")
        # Run from an empty directory so no .znrules / zn.config.json is picked up.
        with tempfile.TemporaryDirectory() as cwd:
            proc = subprocess.run(
                [node, str(EXPORT_SCRIPT), str(SAMPLES_FILE)],
                cwd=cwd, capture_output=True, timeout=120, check=True,
            )
        _EXPORT = json.loads(proc.stdout.decode("utf-8"))
    return _EXPORT


class TestPatternParity(unittest.TestCase):
    def setUp(self):
        self.js = _node_export()

    def test_rules_version(self):
        self.assertEqual(self.js["rules_version"], R.RULES_VERSION)

    def test_detection_tables(self):
        for name in ("INJECTION_RULES", "INDIRECT_INJECTION_RULES", "EVASION_RULES",
                     "SENSITIVE_PATH_RULES", "MARKDOWN_EXFIL_RULES"):
            with self.subTest(table=name):
                self.assertEqual(_py_table(getattr(R, name)), _js_table(self.js["tables"][name]))

    def test_exfil_compound(self):
        (rule,) = self.js["exfil"]
        self.assertEqual(rule["id"], "exfil:credentials")
        self.assertEqual([_py_regex(R.EXFIL_VERBS), _py_regex(R.CRED_OBJECTS)],
                         [_js_regex(e) for e in rule["compound"]])

    def test_helper_patterns(self):
        for name, e in self.js["helpers"].items():
            with self.subTest(helper=name):
                self.assertEqual(_py_regex(getattr(R, name)), _js_regex(e))

    def test_secret_patterns(self):
        js = {e["id"]: e for e in self.js["tables"]["SECRET_PATTERNS"]}
        py = {rule_id: pat for rule_id, pat, _ in R.SECRET_PATTERNS}
        self.assertEqual(list(py), list(js))
        for rule_id, pat in py.items():
            if rule_id in SECRET_PATTERN_EXCEPTIONS:
                continue
            with self.subTest(rule=rule_id):
                self.assertEqual(_py_regex(pat), _js_regex(js[rule_id]))
        self.assertEqual(R.SECRET_PATTERN_REQUIRES, self.js["secret_requires"])

    def test_size_limits(self):
        for name, value in self.js["limits"].items():
            with self.subTest(limit=name):
                self.assertEqual(getattr(R, name), value)


class TestBehaviourParity(unittest.TestCase):
    def test_same_verdicts_on_shared_samples(self):
        js = _node_export()
        samples = json.loads(SAMPLES_FILE.read_text(encoding="utf-8"))["samples"]
        self.assertEqual(len(samples), len(js["results"]))
        for i, (sample, expected) in enumerate(zip(samples, js["results"])):
            text = _expand(sample)
            res = R.evaluate(text)
            label = f"sample {i}: {text[:40]!r}"
            with self.subTest(sample=label):
                self.assertEqual(
                    (res.verdict, res.rule, res.truncated),
                    (expected["verdict"], expected["rule"], expected["truncated"]),
                )
                if expected["stripped"] is not None:
                    self.assertEqual(R.normalize_input(text)[1], expected["stripped"])


if __name__ == "__main__":
    unittest.main()
