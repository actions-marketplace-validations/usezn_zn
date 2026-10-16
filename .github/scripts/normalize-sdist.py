#!/usr/bin/env python3
"""Rewrite a Python sdist (.tar.gz) so that two builds of the same commit are byte for byte the same.

setuptools stamps the files it generates (PKG-INFO, setup.cfg, *.egg-info) and their folders with the
build time, and gzip stores the time it wrote the archive. This keeps every name and every byte of
content and only sets: member order by name, mtime = SOURCE_DATE_EPOCH, owner 0/0 with no names,
mode 0755 for folders and executable files and 0644 for the others, and a gzip header with no time and no file name.

Usage: normalize-sdist.py <sdist.tar.gz> [...]   (SOURCE_DATE_EPOCH must be set)
"""
import gzip
import io
import os
import sys
import tarfile


def normalize(path: str, epoch: int) -> None:
    with tarfile.open(path, "r:gz") as src:
        members = []
        for m in src.getmembers():
            if not (m.isfile() or m.isdir()):
                raise SystemExit(f"{path}: unexpected member type: {m.name}")
            data = src.extractfile(m).read() if m.isfile() else None
            members.append((m, data))
    members.sort(key=lambda x: x[0].name)
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as out:
        for m, data in members:
            info = tarfile.TarInfo(m.name)
            info.type = m.type
            info.mtime = epoch
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            # Keep the execute bit of a file that has one (git only knows 644 and 755).
            info.mode = 0o755 if m.isdir() or (m.mode & 0o111) else 0o644
            if m.isfile():
                info.size = len(data)
                out.addfile(info, io.BytesIO(data))
            else:
                out.addfile(info)
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        with gzip.GzipFile(filename="", mode="wb", fileobj=f, mtime=0, compresslevel=9) as gz:
            gz.write(raw.getvalue())
    os.replace(tmp, path)


def main(argv: list) -> int:
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    if not epoch or not epoch.isdigit():
        print("normalize-sdist: SOURCE_DATE_EPOCH must be set to the commit time", file=sys.stderr)
        return 2
    if not argv:
        print(__doc__.strip().splitlines()[-1], file=sys.stderr)
        return 2
    for p in argv:
        normalize(p, int(epoch))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
