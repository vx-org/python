"""Verify the Python intake release's downloaded files against local public pins."""

from __future__ import annotations

import argparse
import hashlib
import json
import stat
import tarfile
from pathlib import Path

import verify_intake as intake


RELEASE_MANIFEST = "release-assets.json"
INTAKE_MANIFEST = "intake-assets.json"
METADATA_ARCHIVE = "intake-metadata.tar.gz"
ANCILLARY_FILES = {RELEASE_MANIFEST, INTAKE_MANIFEST, METADATA_ARCHIVE}
ORGANIZATION_BASE = (
    "https://github.com/vx-org/python/releases/download/python-3.7.9-pbs-20200823"
)


class ReadbackError(ValueError):
    """Downloaded assets do not satisfy the pinned intake release contract."""


def inventory(directory: Path, expected: set[str]) -> dict[str, Path]:
    """Require a flat directory of exactly the expected, portable regular files."""
    attributes = directory.lstat()
    if (
        not stat.S_ISDIR(attributes.st_mode)
        or stat.S_ISLNK(attributes.st_mode)
        or getattr(attributes, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    ):
        raise ReadbackError("release asset directory must be an ordinary directory")
    files = {}
    folded = set()
    for path in directory.iterdir():
        name = intake.safe_relative(path.name, flat=True)
        if name.casefold() in folded:
            raise ReadbackError("release asset names collide on a portable filesystem")
        folded.add(name.casefold())
        files[name] = intake.contained_regular(directory, name)
    if set(files) != expected:
        raise ReadbackError("release asset directory has missing or unexpected files")
    return files


def verify_checksum_companion(files: dict[str, Path], name: str, sha256: str) -> None:
    canonical = f"{sha256}  {name}\n".encode("ascii")
    if files[f"{name}.sha256"].read_bytes() != canonical:
        raise ReadbackError(f"release checksum companion differs from its pinned asset: {name}")


def validate_release_manifest(value: dict, manifest: dict) -> None:
    if not isinstance(value, dict) or set(value) != {"schema_version", "assets"}:
        raise ReadbackError("retained release manifest has unexpected fields")
    assets = value["assets"]
    if type(value["schema_version"]) is not int or value["schema_version"] != 1 or not isinstance(assets, list) or len(assets) != intake.ARCHIVE_COUNT:
        raise ReadbackError("retained release manifest requires 27 schema-v1 assets")
    expected = {asset["name"]: asset for asset in manifest["assets"]}
    observed = set()
    folded = set()
    for asset in assets:
        if not isinstance(asset, dict) or set(asset) != {"name", "url", "sha256", "size"}:
            raise ReadbackError("retained release asset fields differ from the intake contract")
        name = intake.safe_relative(asset["name"], flat=True)
        if name.casefold() in folded:
            raise ReadbackError("retained release manifest contains duplicate asset names")
        folded.add(name.casefold())
        original = expected.get(name)
        if (
            original is None
            or type(asset["size"]) is not int
            or asset["sha256"] != original["sha256"]
            or asset["size"] != original["size"]
            or asset["url"] not in {original["url"], f"{ORGANIZATION_BASE}/{name}"}
        ):
            raise ReadbackError("retained release asset differs from its historical identity")
        intake.validate_https(asset["url"])
        observed.add(name)
    if observed != set(expected):
        raise ReadbackError("retained release identities do not cover the intake manifest")
    intake.scan_public_json(value, RELEASE_MANIFEST)


def verify_metadata_archive(root: Path, files: list[str], archive_path: Path) -> None:
    """Read regular TAR members without extracting or executing archive contents."""
    expected = set(files)
    if len(expected) != len(files):
        raise ReadbackError("public metadata inventory contains duplicate file names")
    seen = []
    folded = set()
    with tarfile.open(archive_path, "r|gz") as archive:
        for member in archive:
            name = intake.safe_relative(member.name)
            if name.casefold() in folded:
                raise ReadbackError("metadata archive contains duplicate portable member names")
            folded.add(name.casefold())
            if name not in expected or len(seen) >= len(expected):
                raise ReadbackError("metadata archive contains an unexpected member")
            if not member.isreg() or member.issparse():
                raise ReadbackError("metadata archive members must be ordinary regular files")
            if (
                member.mode, member.mtime, member.uid, member.gid,
                member.uname, member.gname,
            ) != (0o644, 0, 0, 0, "", ""):
                raise ReadbackError("metadata archive member attributes are not canonical")
            source = intake.contained_regular(root, name)
            if member.size != source.stat().st_size:
                raise ReadbackError("metadata archive member differs from its public pinned size")
            stream = archive.extractfile(member)
            if stream is None:
                raise ReadbackError("metadata archive member cannot be read")
            with stream:
                observed_digest = hashlib.file_digest(stream, "sha256").hexdigest()
            if observed_digest != intake.digest(source):
                raise ReadbackError("metadata archive member differs from its public pinned bytes")
            seen.append(name)
    if seen != sorted(expected):
        raise ReadbackError("metadata archive inventory or deterministic member order differs")


def verify_release_readback(
    root: Path,
    tooling: Path,
    expected_directory: Path,
    downloaded_directory: Path,
) -> dict:
    """Verify provenance, the exact 60 asset names, all bytes and every checksum."""
    manifest, metadata_files = intake.verify_intake(root, tooling)
    raw_names = {asset["name"] for asset in manifest["assets"]}
    base_names = raw_names | ANCILLARY_FILES
    expected_names = base_names | {f"{name}.sha256" for name in base_names}
    if len(raw_names) != intake.ARCHIVE_COUNT or len(expected_names) != 60:
        raise ReadbackError("Python intake release requires exactly 60 distinct asset names")
    expected = inventory(expected_directory, expected_names)
    downloaded = inventory(downloaded_directory, expected_names)

    # A downloaded checksum file alone is not a trust anchor. Raw archives use
    # historical byte pins; ancillary files use the validated local release.
    intake_source = intake.contained_regular(root, INTAKE_MANIFEST)
    intake_pin = (intake.digest(intake_source), intake_source.stat().st_size)
    for group in (expected, downloaded):
        intake.verify_bytes(group[INTAKE_MANIFEST], *intake_pin)
        validate_release_manifest(intake.read_json(group[RELEASE_MANIFEST]), manifest)
        for asset in manifest["assets"]:
            intake.verify_bytes(group[asset["name"]], asset["sha256"], asset["size"])
            verify_checksum_companion(group, asset["name"], asset["sha256"])

    ancillary_pins = {}
    for name in sorted(ANCILLARY_FILES):
        sha256 = intake.digest(expected[name])
        size = expected[name].stat().st_size
        intake.verify_bytes(downloaded[name], sha256, size)
        for group in (expected, downloaded):
            verify_checksum_companion(group, name, sha256)
        ancillary_pins[name] = {"sha256": sha256, "size": size}
    verify_metadata_archive(root, metadata_files, expected[METADATA_ARCHIVE])
    verify_metadata_archive(root, metadata_files, downloaded[METADATA_ARCHIVE])
    return {
        "status": "verified-release-asset-readback",
        "release_asset_count": len(expected_names),
        "raw_archive_assets": len(raw_names),
        "total_pinned_raw_archive_bytes": manifest["total_size"],
        "metadata_files": len(metadata_files),
        "ancillary_pins": ancillary_pins,
        "github_immutable_release_state": "not-checked-by-local-file-verifier",
        "native_runtime_acceptance": "not-run",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--tooling", type=Path, required=True)
    parser.add_argument("--expected-dir", type=Path, required=True)
    parser.add_argument("--downloaded-dir", type=Path, required=True)
    args = parser.parse_args()
    report = verify_release_readback(
        args.root, args.tooling, args.expected_dir, args.downloaded_dir,
    )
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ReadbackError, intake.IntakeError, OSError, ValueError, KeyError, TypeError, tarfile.TarError) as error:
        raise SystemExit(f"release readback failed ({type(error).__name__}): {error}") from error
