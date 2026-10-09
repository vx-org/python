"""Read local historical PBS archives without extracting or executing runtimes."""

from __future__ import annotations

import argparse
import hashlib
import json
import posixpath
import tarfile
from collections import Counter
from pathlib import Path, PurePosixPath

import zstandard


MAX_METADATA_BYTES = 4 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 100_000


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def metadata_member(name: str) -> bool:
    path = PurePosixPath(name)
    lower = name.lower()
    basename = path.name.lower()
    return (
        basename in {"python.json", "build_info.json", "build-info.json"}
        or basename.startswith(("license", "licence", "copying", "copyright"))
        or "/licenses/" in lower
    )


def audit_links(members: list[dict]) -> list[dict]:
    entries = {member["name"].rstrip("/"): member for member in members}
    resolved = []
    for member in members:
        if member["kind"] not in {"symlink", "hardlink"}:
            continue
        current = member["name"]
        seen = set()
        while entries[current]["kind"] in {"symlink", "hardlink"}:
            if current in seen:
                raise ValueError(f"link cycle: {member['name']}")
            seen.add(current)
            entry = entries[current]
            target = entry["linkname"]
            if PurePosixPath(target).is_absolute() or "\\" in target:
                raise ValueError(f"absolute or nonportable link: {current}")
            if entry["kind"] == "symlink":
                target = posixpath.join(posixpath.dirname(current), target)
            current = posixpath.normpath(target)
            if current not in entries or not current.startswith("python/"):
                raise ValueError(f"missing or escaping link target: {member['name']}")
        if entries[current]["kind"] not in {"file", "directory"}:
            raise ValueError(f"unsupported final link target: {current}")
        resolved.append({
            "source": member["name"],
            "target": member["linkname"],
            "final_target": current,
            "final_kind": entries[current]["kind"],
        })
    return resolved


def audit_asset(candidate: Path, asset: dict, output: Path) -> dict:
    source = candidate / asset["name"]
    actual_sha256 = digest(source)
    if actual_sha256 != asset["sha256"] or source.stat().st_size != asset["size"]:
        raise ValueError(f"candidate identity mismatch: {asset['name']}")
    target = asset["target"]
    target_output = output / target
    target_output.mkdir(parents=True, exist_ok=True)
    members = []
    metadata = []
    python_metadata = None
    kinds = Counter()
    with (
        source.open("rb") as raw,
        zstandard.ZstdDecompressor().stream_reader(raw) as decompressed,
        tarfile.open(fileobj=decompressed, mode="r|") as archive,
    ):
        for index, member in enumerate(archive):
            if index >= MAX_ARCHIVE_MEMBERS:
                raise ValueError("archive exceeds audit member bound")
            name = member.name
            path = PurePosixPath(name)
            if path.is_absolute() or ".." in path.parts or "\\" in name:
                raise ValueError(f"unsafe member name: {name!r}")
            kind = (
                "file" if member.isfile() else "directory" if member.isdir()
                else "symlink" if member.issym() else "hardlink" if member.islnk()
                else "special"
            )
            kinds[kind] += 1
            members.append({
                "name": name,
                "kind": kind,
                "size": member.size,
                "mode": oct(member.mode),
                **({"linkname": member.linkname} if member.issym() or member.islnk() else {}),
            })
            if not member.isfile() or not metadata_member(name):
                continue
            if member.size > MAX_METADATA_BYTES:
                raise ValueError(f"metadata exceeds audit size bound: {name}")
            stream = archive.extractfile(member)
            if stream is None:
                raise ValueError(f"cannot read regular metadata file: {name}")
            contents = stream.read(MAX_METADATA_BYTES + 1)
            if len(contents) != member.size:
                raise ValueError(f"metadata read length mismatch: {name}")
            # Numbered flat files ensure archive paths never become filesystem paths.
            filename = f"metadata-{len(metadata):03d}-{path.name}"
            destination = target_output / filename
            destination.write_bytes(contents)
            metadata.append({
                "archive_path": name,
                "audit_file": filename,
                "sha256": hashlib.sha256(contents).hexdigest(),
                "size": len(contents),
            })
            if path.name.lower() == "python.json":
                python_metadata = json.loads(contents)
    (target_output / "members.json").write_text(
        json.dumps(members, indent=2) + "\n", encoding="utf-8"
    )
    names = [member["name"] for member in members]
    checks = {
        "python_executables": [name for name in names if PurePosixPath(name).name in {"python.exe", "python3", "python3.7", "python3.7m"}],
        "python_headers": [name for name in names if PurePosixPath(name).name == "Python.h"],
        "python_link_libraries": [name for name in names if any(token in PurePosixPath(name).name.lower() for token in ("python37.lib", "libpython3.7"))],
        "stdlib_os": [name for name in names if name.endswith("/os.py")],
        "stdlib_venv": [name for name in names if name.endswith("/venv/__init__.py")],
        "stdlib_ensurepip": [name for name in names if name.endswith("/ensurepip/__init__.py")],
        "stdlib_ssl": [name for name in names if name.endswith("/ssl.py")],
        "stdlib_ctypes": [name for name in names if name.endswith("/ctypes/__init__.py")],
    }
    report = {
        "target": target,
        "asset": asset,
        "verified_local_sha256": actual_sha256,
        "member_count": len(members),
        "member_kinds": dict(kinds),
        "top_level_entries": sorted({PurePosixPath(name).parts[0] for name in names if PurePosixPath(name).parts}),
        "payload_structure_checks": checks,
        "resolved_internal_links": audit_links(members),
        "metadata": metadata,
        "python_metadata": python_metadata,
    }
    (target_output / "audit.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
    return {key: value for key, value in report.items() if key != "python_metadata"}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    provenance = json.loads((args.candidate / "provenance.json").read_text(encoding="utf-8"))
    args.output.mkdir(parents=True, exist_ok=True)
    reports = [audit_asset(args.candidate, asset, args.output) for asset in provenance["assets"]]
    (args.output / "inventory.json").write_text(
        json.dumps({"provenance": provenance, "targets": reports}, indent=2) + "\n",
        encoding="utf-8",
    )
    for report in reports:
        print(json.dumps({
            "target": report["target"],
            "member_count": report["member_count"],
            "member_kinds": report["member_kinds"],
            "payload_structure_checks": report["payload_structure_checks"],
            "metadata_files": len(report["metadata"]),
        }))


if __name__ == "__main__":
    main()
