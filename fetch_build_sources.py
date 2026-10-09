"""Pin the historical PBS build recipe source without unpacking or running it."""

from __future__ import annotations

import hashlib
import json
import subprocess
import tarfile
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent
REPOSITORY = "astral-sh/python-build-standalone"


def main() -> None:
    destination = ROOT / "source-audit"
    destination.mkdir(exist_ok=True)
    receipts = []
    for tag in ("20200822", "20200823"):
        commit = json.loads(subprocess.check_output(
            ["vx", "gh", "api", f"repos/{REPOSITORY}/commits/{tag}"], text=True
        ))
        revision = commit["sha"]
        if len(revision) != 40 or any(c not in "0123456789abcdef" for c in revision):
            raise ValueError("invalid source commit identity")
        url = f"https://codeload.github.com/{REPOSITORY}/tar.gz/{revision}"
        archive = destination / f"pbs-{tag}-{revision}.tar.gz"
        if not archive.exists():
            request = urllib.request.Request(url, headers={"User-Agent": "vx-rez-packages/1"})
            temporary = archive.with_suffix(".partial")
            with urllib.request.urlopen(request, timeout=120) as source, temporary.open("wb") as out:
                while chunk := source.read(1024 * 1024):
                    out.write(chunk)
            temporary.replace(archive)
        with archive.open("rb") as stream:
            sha256 = hashlib.file_digest(stream, "sha256").hexdigest()
        members = []
        copied = []
        audit = destination / tag
        audit.mkdir(exist_ok=True)
        with tarfile.open(archive, "r:gz") as source:
            for member in source:
                members.append({"name": member.name, "size": member.size, "type": member.type.decode("ascii")})
                basename = Path(member.name).name
                if member.isfile() and (
                    basename in {"downloads.py", "download.py", "LICENSE", "README.rst", "README.md", "pythonbuild.py"}
                    or basename.endswith((".patch", ".sh"))
                ):
                    if member.size > 4 * 1024 * 1024:
                        raise ValueError("source audit file too large")
                    file = source.extractfile(member)
                    if file is None:
                        raise ValueError("source member unavailable")
                    data = file.read()
                    name = f"{len(copied):03d}-{basename}"
                    (audit / name).write_bytes(data)
                    copied.append({"source_path": member.name, "audit_file": name, "sha256": hashlib.sha256(data).hexdigest()})
        receipt = {
            "repository": f"https://github.com/{REPOSITORY}", "tag": tag,
            "revision": revision, "source_url": url, "source_sha256": sha256,
            "source_sha256_origin": "computed after official HTTPS intake; not a publisher signature",
            "archive": archive.name, "size": archive.stat().st_size,
            "members": members, "audit_files": copied,
        }
        (audit / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
        receipts.append({key: value for key, value in receipt.items() if key not in {"members", "audit_files"}})
        print(json.dumps(receipts[-1]), flush=True)
    (destination / "sources.json").write_text(json.dumps(receipts, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
