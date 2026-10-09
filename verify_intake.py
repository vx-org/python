"""Validate public intake contracts without acquiring or executing runtimes."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import importlib.util
import json
import re
import stat
import tarfile
import tempfile
import urllib.parse
from pathlib import Path, PurePosixPath


ARCHIVE_COUNT = 27
SOURCE_COUNT = 22
BUILD_RECIPE_COUNT = 2
RUNTIME_COUNT = 3
SIGNED_QUERY_KEYS = {
    "sig", "signature", "token", "access_token", "auth", "authorization",
    "credential", "jwt", "policy", "key-pair-id", "api_key", "apikey",
}
WINDOWS_PATH = re.compile(r"(?i)(?<![a-z0-9])[a-z]:[\\/]|\\\\[^\\\s]+\\[^\\\s]+")
URL_IN_TEXT = re.compile(r"https?://[^\s<>\"']+")
RUNTIME_SUFFIXES = {".exe", ".dll", ".pyd", ".so", ".dylib", ".lib", ".a", ".zip", ".7z", ".zst", ".gz", ".xz", ".bz2"}
METADATA_ROOT_FILES = {"README.md", "LICENSE", "package.py", "intake-assets.json", "source-closure.json"}
LGPL_LIBRARY_NOTICES = {
    "metadata/gettext-source/gettext-runtime/intl/COPYING.LIB",
    "metadata/gettext-source/gettext-runtime/libasprintf/COPYING.LIB",
}


class IntakeError(ValueError):
    """A public intake contract failed validation."""


def no_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise IntakeError("public JSON contains a duplicate object key")
        result[key] = value
    return result


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=no_duplicate_keys)


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def safe_relative(value: str, *, flat: bool = False) -> str:
    if not isinstance(value, str) or not value or "\\" in value or ":" in value:
        raise IntakeError("file reference must be a portable relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in value.split("/")):
        raise IntakeError("file reference must stay inside its root")
    if flat and len(path.parts) != 1:
        raise IntakeError("intake archive names must be flat")
    reserved = {"CON", "PRN", "AUX", "NUL", *(f"COM{index}" for index in range(1, 10)), *(f"LPT{index}" for index in range(1, 10))}
    for part in path.parts:
        if part.endswith((" ", ".")) or part.split(".", 1)[0].upper() in reserved or any(ord(character) < 32 or character in '<>"|?*' for character in part):
            raise IntakeError("file reference is not portable on Windows")
    return value


def contained_regular(root: Path, relative: str) -> Path:
    safe_relative(relative)
    current = root
    for part in PurePosixPath(relative).parts:
        current = current / part
        attributes = current.lstat()
        if stat.S_ISLNK(attributes.st_mode) or getattr(attributes, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400):
            raise IntakeError("public input cannot contain filesystem links")
    current.resolve(strict=True).relative_to(root.resolve(strict=True))
    if not current.is_file():
        raise IntakeError("public input must be a regular file")
    return current


def verify_bytes(path: Path, sha256: str, size: int | None = None) -> None:
    if not isinstance(sha256, str) or re.fullmatch(r"[a-f0-9]{64}", sha256) is None:
        raise IntakeError("asset requires a lowercase SHA256 pin")
    if size is not None and (type(size) is not int or size <= 0 or path.stat().st_size != size):
        raise IntakeError("asset does not match its positive pinned size")
    if digest(path) != sha256:
        raise IntakeError("asset does not match its pinned SHA256")


def validate_https(value: str) -> None:
    try:
        parsed = urllib.parse.urlsplit(value)
        valid = parsed.scheme == "https" and bool(parsed.hostname) and parsed.username is None and parsed.password is None and not parsed.fragment and parsed.port != 0
    except (TypeError, ValueError) as error:
        raise IntakeError("asset requires a valid HTTPS URL") from error
    if not valid or "\\" in value or any(character.isspace() or ord(character) < 32 for character in value):
        raise IntakeError("asset requires HTTPS without credentials or fragments")


def scan_public_json(value, label: str, field: str = "") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            scan_public_json(key, label)
            scan_public_json(item, label, key)
    elif isinstance(value, list):
        for item in value:
            scan_public_json(item, label, field)
    elif isinstance(value, str):
        if WINDOWS_PATH.search(value):
            raise IntakeError(f"public JSON contains a Windows local path: {label}")
        for match in URL_IN_TEXT.finditer(value):
            parsed = urllib.parse.urlsplit(match.group())
            keys = {key.casefold() for key, _ in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)}
            signed = bool(keys & SIGNED_QUERY_KEYS) or any(key.startswith(("x-amz-", "x-goog-")) for key in keys)
            if parsed.username or parsed.password or signed or (field.casefold() == "final_url" and parsed.query):
                # Never print the URL or parameter values when reporting a failure.
                raise IntakeError(f"public JSON contains credentials or temporary redirect parameters: {label}")


def expected_assets(root: Path) -> dict[str, dict]:
    intake = read_json(contained_regular(root, "metadata/archive-intake.json"))
    closure = read_json(contained_regular(root, "metadata/source-closure.json"))
    retention = read_json(contained_regular(root, "metadata/source-retention.json"))
    builds = read_json(contained_regular(root, "metadata/build-source-intake.json"))
    runtimes = intake["provenance"]["assets"]
    sources = closure["sources"]
    receipts = retention["sources"]
    if len(runtimes) != RUNTIME_COUNT or len(sources) != SOURCE_COUNT or len(receipts) != SOURCE_COUNT or len(builds) != BUILD_RECIPE_COUNT:
        raise IntakeError("public provenance requires 3 runtimes, 22 component sources and 2 build recipes")
    if closure["status"] != "sources-verified-local" or retention["status"] != "complete-local-verified" or retention.get("notice_error") is not None:
        raise IntakeError("source and notice retention has not completed")
    if len(retention["gettext_notices"]) != 10:
        raise IntakeError("ten audited gettext notices are required")
    source_map = {(source["name"], source["version"]): source for source in sources}
    receipt_map = {(source["name"], source["version"]): source for source in receipts}
    if len(source_map) != SOURCE_COUNT or len(receipt_map) != SOURCE_COUNT or source_map.keys() != receipt_map.keys():
        raise IntakeError("source retention identities do not match the pinned closure")
    result = {}

    def add(name, url, sha256, size):
        safe_relative(name, flat=True)
        validate_https(url)
        if name.casefold() in {entry.casefold() for entry in result}:
            raise IntakeError("public provenance contains duplicate archive names")
        result[name] = {"name": name, "url": url, "sha256": sha256, "size": size}

    for runtime in runtimes:
        add(runtime["name"], runtime["url"], runtime["sha256"], runtime["size"])
    for key, source in source_map.items():
        receipt = receipt_map[key]
        acquisition = receipt if receipt["status"] == "verified-download" else receipt.get("intake", {})
        if acquisition.get("status") != "verified-download":
            raise IntakeError("component source lacks its original acquisition receipt")
        for observation in (receipt, acquisition):
            if observation.get("sha256") != source["sha256"] or observation.get("size") != source["size"]:
                raise IntakeError("component source receipt differs from historical byte pins")
        add(receipt["archive"], acquisition["requested_url"], source["sha256"], source["size"])
    for build in builds:
        add(build["archive"], build["source_url"], build["source_sha256"], build["size"])
    if len(result) != ARCHIVE_COUNT:
        raise IntakeError("expected exactly 27 unchanged archive assets")
    return result


def validate_manifest(manifest: dict, expected: dict[str, dict]) -> None:
    assets = manifest.get("assets", [])
    if manifest.get("schema_version") != 1 or manifest.get("asset_count") != ARCHIVE_COUNT or len(assets) != ARCHIVE_COUNT:
        raise IntakeError("intake manifest requires exactly 27 schema-v1 archive assets")
    observed = {}
    folded = set()
    for asset in assets:
        if set(asset) != {"name", "url", "sha256", "size"}:
            raise IntakeError("intake asset fields must be name, url, sha256 and size")
        name = safe_relative(asset["name"], flat=True)
        if name.casefold() in folded:
            raise IntakeError("intake asset names collide on a portable filesystem")
        folded.add(name.casefold())
        validate_https(asset["url"])
        if not isinstance(asset["sha256"], str) or re.fullmatch(r"[a-f0-9]{64}", asset["sha256"]) is None or type(asset["size"]) is not int or asset["size"] <= 0:
            raise IntakeError("intake asset requires a SHA256 pin and positive byte size")
        observed[name] = asset
    if observed != expected:
        raise IntakeError("intake archive names, URLs or byte pins differ from public source provenance")
    if type(manifest.get("total_size")) is not int or manifest["total_size"] != sum(asset["size"] for asset in assets):
        raise IntakeError("intake aggregate byte size does not match its assets")
    origins = manifest.get("origins", [])
    if len(origins) != ARCHIVE_COUNT or {origin["name"] for origin in origins} != set(expected):
        raise IntakeError("each intake archive requires one matching provenance origin")


def shared_validator(tooling: Path):
    source = contained_regular(tooling, "tools/build_bundle.py")
    specification = importlib.util.spec_from_file_location("_vx_intake_shared_bundle", source)
    if specification is None or specification.loader is None:
        raise IntakeError("shared package tooling cannot be loaded")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module.validate_definition


def verify_intake(root: Path, tooling: Path, asset_dir: Path | None = None) -> tuple[dict, list[str]]:
    recipe = read_json(contained_regular(root, "recipe.json"))
    shared_validator(tooling)(recipe)
    manifest = read_json(contained_regular(root, "intake-assets.json"))
    validate_manifest(manifest, expected_assets(root))
    metadata_files = set()
    for record in recipe["metadata"]:
        relative = safe_relative(record["source"])
        if not relative.startswith("metadata/") or relative.casefold() in {name.casefold() for name in metadata_files}:
            raise IntakeError("recipe metadata requires unique contained metadata files")
        verify_bytes(contained_regular(root, relative), record["sha256"])
        metadata_files.add(relative)
    actual_metadata = {path.relative_to(root).as_posix() for path in (root / "metadata").rglob("*") if not path.is_dir()}
    if actual_metadata != metadata_files:
        raise IntakeError("public metadata directory differs from the checksum-pinned recipe files")
    definition = recipe["package"]["definition"]
    if definition["source"] != "package.py":
        raise IntakeError("Python intake requires the actual repository package.py")
    verify_bytes(contained_regular(root, definition["source"]), definition["sha256"])
    root_closure = read_json(contained_regular(root, "source-closure.json"))
    if root_closure != read_json(contained_regular(root, "metadata/source-closure.json")):
        raise IntakeError("root and bundled source closure disagree")
    public_json_files = {path.relative_to(root).as_posix() for path in root.glob("*.json")}
    public_json_files.update(relative for relative in metadata_files if relative.endswith(".json"))
    for relative in sorted(public_json_files):
        scan_public_json(read_json(contained_regular(root, relative)), relative)
    if asset_dir is not None:
        for asset in manifest["assets"]:
            verify_bytes(contained_regular(asset_dir, asset["name"]), asset["sha256"], asset["size"])
    files = sorted(metadata_files | METADATA_ROOT_FILES)
    for relative in files:
        contained_regular(root, relative)
    return manifest, files


def is_lgpl_library_notice(relative: str, source: Path) -> bool:
    """Recognize the two retained gettext LGPL texts despite their .LIB suffix."""
    if relative not in LGPL_LIBRARY_NOTICES or source.stat().st_size > 128 * 1024:
        return False
    content = source.read_bytes()
    if b"\0" in content:
        return False
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        return False
    if any(ord(character) < 32 and character not in "\t\r\n\f" for character in text):
        return False
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    return lines[:2] == [
        "GNU LESSER GENERAL PUBLIC LICENSE",
        "Version 2.1, February 1999",
    ]


def write_metadata_archive(root: Path, files: list[str], output: Path) -> dict:
    sources = []
    for relative in sorted(set(files)):
        safe_relative(relative)
        if not relative.startswith("metadata/") and relative not in METADATA_ROOT_FILES:
            raise IntakeError("metadata archive input is outside the explicit public metadata boundary")
        source = contained_regular(root, relative)
        binary_suffixes = {suffix.lower() for suffix in PurePosixPath(relative).suffixes} & RUNTIME_SUFFIXES
        if binary_suffixes and not (binary_suffixes == {".lib"} and is_lgpl_library_notice(relative, source)):
            raise IntakeError("metadata archive cannot include runtime or source archive binaries")
        if output.resolve() == source.resolve() or output.with_name(output.name + ".sha256").resolve() == source.resolve():
            raise IntakeError("metadata archive output cannot replace a verified public input")
        sources.append((relative, source))
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=output.parent, prefix=".intake-metadata-", delete=False) as raw:
            temporary = Path(raw.name)
            with gzip.GzipFile(filename="", fileobj=raw, mode="wb", mtime=0) as compressed, tarfile.open(fileobj=compressed, mode="w|", format=tarfile.PAX_FORMAT) as archive:
                for relative, source in sources:
                    info = tarfile.TarInfo(relative)
                    info.size = source.stat().st_size
                    info.mode = 0o644
                    info.mtime = 0
                    info.uid = info.gid = 0
                    info.uname = info.gname = ""
                    with source.open("rb") as stream:
                        archive.addfile(info, stream)
        temporary.replace(output)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    checksum = digest(output)
    output.with_name(output.name + ".sha256").write_text(f"{checksum}  {output.name}\n", encoding="ascii", newline="\n")
    return {"name": output.name, "sha256": checksum, "size": output.stat().st_size, "files": len(set(files))}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--tooling", type=Path, required=True)
    parser.add_argument("--asset-dir", type=Path)
    parser.add_argument("--metadata-output", type=Path)
    args = parser.parse_args()
    manifest, files = verify_intake(args.root.resolve(), args.tooling.resolve(), args.asset_dir)
    report = {"status": "verified-public-intake-contract", "raw_archive_assets": len(manifest["assets"]), "raw_archive_bytes_verified": args.asset_dir is not None, "total_pinned_bytes": manifest["total_size"], "metadata_files": len(files), "native_runtime_acceptance": "not-run", "publication_readback": "not-run"}
    if args.metadata_output:
        report["ancillary_metadata_archive"] = write_metadata_archive(args.root.resolve(), files, args.metadata_output)
    print(json.dumps(report))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (IntakeError, OSError, ValueError, KeyError, TypeError) as error:
        raise SystemExit(f"intake validation failed ({type(error).__name__}): {error}") from error
