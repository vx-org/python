"""Retain exact historical source archives and their acquisition receipts."""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
import re
import tarfile
import tempfile
import urllib.parse
import urllib.request
from pathlib import Path, PurePosixPath


ROOT = Path(__file__).resolve().parent
NOTICE_NAMES = {"copying", "copying.lib", "copying.lesser", "copyright", "license", "license.txt"}


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def https_url(value: str, *, upgrade: bool = False) -> str:
    parsed = urllib.parse.urlsplit(value)
    if upgrade and parsed.scheme in {"http", "ftp"}:
        parsed = parsed._replace(scheme="https")
    if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password or parsed.fragment:
        raise ValueError("source acquisition requires a credential-free HTTPS URL")
    return urllib.parse.urlunsplit(parsed)


class HTTPSRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        https_url(new_url)
        return super().redirect_request(request, response, code, message, headers, new_url)


def acquire(source: dict, output: Path, overrides: dict) -> dict:
    key = f"{source['name']}@{source['version']}"
    url = https_url(overrides.get(key, source["url"]), upgrade=True)
    basename = urllib.parse.unquote(PurePosixPath(urllib.parse.urlsplit(source["url"]).path).name)
    filename = f"{source['name']}-{basename}"
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]*", filename):
        raise ValueError(f"nonportable archive filename: {filename!r}")
    destination = output / filename
    intake_receipt = output / f"{filename}.receipt.json"
    receipt = {
        "name": source["name"], "version": source["version"],
        "original_url": source["url"], "requested_url": url,
        "archive": filename, "expected_sha256": source["sha256"],
        "expected_size": source["size"], "digest_origin": source["digest_origin"],
        "build_tags": source["build_tags"],
    }
    temporary = None
    try:
        if destination.exists():
            if destination.stat().st_size != source["size"] or digest(destination) != source["sha256"]:
                raise ValueError("existing source archive fails its fixed size or SHA256; retained for inspection")
            intake = None
            if intake_receipt.exists():
                intake = json.loads(intake_receipt.read_text(encoding="utf-8"))
                if intake.get("sha256") != source["sha256"] or intake.get("size") != source["size"]:
                    raise ValueError("cached source intake receipt does not match the fixed byte pins")
            return {
                **receipt, "status": "verified-cache", "sha256": source["sha256"],
                "size": source["size"], "intake": intake,
                "intake_note": "Original acquisition receipt retained." if intake else "Cache bytes verified; original network acquisition was not observed by this script.",
            }
        descriptor, temporary_name = tempfile.mkstemp(prefix=".source-", suffix=".part", dir=output)
        temporary = Path(temporary_name)
        opener = urllib.request.build_opener(HTTPSRedirectHandler())
        request = urllib.request.Request(url, headers={"User-Agent": "VX-Python-Source-Retention/1"})
        with os.fdopen(descriptor, "wb") as target, opener.open(request, timeout=60) as response:
            final_url = https_url(response.geturl())
            checksum = hashlib.sha256()
            size = 0
            while block := response.read(1024 * 1024):
                size += len(block)
                if size > source["size"]:
                    raise ValueError("download exceeds the pinned byte size")
                checksum.update(block)
                target.write(block)
            target.flush()
            os.fsync(target.fileno())
        actual_sha256 = checksum.hexdigest()
        if size != source["size"] or actual_sha256 != source["sha256"]:
            raise ValueError("download does not match the fixed historical size and SHA256")
        os.replace(temporary, destination)
        temporary = None
        result = {**receipt, "status": "verified-download", "final_url": final_url, "sha256": actual_sha256, "size": size}
        write_json(intake_receipt, result)
        return result
    except Exception as error:
        return {**receipt, "status": "failed", "error": f"{type(error).__name__}: {error}"}
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def retain_gettext_notices(source_archive: Path) -> list[dict]:
    metadata_root = ROOT / "metadata"
    notices = []
    seen = set()
    with tarfile.open(source_archive, "r:gz") as archive:
        for member in archive:
            path = PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts or "\\" in member.name:
                raise ValueError("unsafe gettext source member")
            if path.name.lower() not in NOTICE_NAMES or not member.isfile():
                continue
            if member.size > 2 * 1024 * 1024 or len(notices) >= 200:
                raise ValueError("gettext legal metadata exceeds retention bound")
            relative = "gettext-source/" + PurePosixPath(*path.parts[1:]).as_posix()
            if relative.casefold() in seen:
                raise ValueError("gettext legal metadata has a portable path collision")
            seen.add(relative.casefold())
            destination = metadata_root / relative
            destination.resolve().relative_to(metadata_root.resolve())
            stream = archive.extractfile(member)
            if stream is None:
                raise ValueError("cannot read gettext regular notice")
            contents = stream.read(2 * 1024 * 1024 + 1)
            if len(contents) != member.size:
                raise ValueError("gettext notice length mismatch")
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(contents)
            notices.append({
                "archive_path": member.name,
                "source": f"metadata/{relative}",
                "destination": f"upstream-metadata/{relative}",
                "sha256": hashlib.sha256(contents).hexdigest(),
                "size": len(contents),
            })
    required = {
        "gettext-source/COPYING": ("GNU GENERAL PUBLIC LICENSE", "Version 3"),
        "gettext-source/gettext-runtime/intl/COPYING.LIB": ("GNU LESSER GENERAL PUBLIC LICENSE", "Version 2.1"),
        "gettext-source/gettext-runtime/libasprintf/COPYING.LIB": ("GNU LESSER GENERAL PUBLIC LICENSE", "Version 2.1"),
        "gettext-source/gettext-tools/COPYING": ("This subpackage is under the GPL", "toplevel directory"),
        "gettext-source/libtextstyle/COPYING": ("GNU GENERAL PUBLIC LICENSE", "Version 3"),
    }
    retained_paths = {entry["source"].removeprefix("metadata/") for entry in notices}
    for relative, expected_markers in required.items():
        if relative not in retained_paths:
            raise ValueError(f"gettext source lacks required component notice: {relative}")
        contents = (metadata_root / relative).read_text(encoding="utf-8")
        if not all(marker in contents for marker in expected_markers):
            raise ValueError(f"gettext component notice has unexpected license text: {relative}")
    return notices


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8", newline="\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--closure", type=Path, default=ROOT / "source-closure.json")
    parser.add_argument("--output", type=Path, default=ROOT / "source-downloads")
    parser.add_argument("--parallelism", type=int, choices=range(1, 5), default=4)
    parser.add_argument("--url-overrides", type=Path, help="Explicit name@version-to-HTTPS URL map; byte pins cannot change.")
    args = parser.parse_args()
    closure = json.loads(args.closure.read_text(encoding="utf-8"))
    overrides = json.loads(args.url_overrides.read_text(encoding="utf-8")) if args.url_overrides else {}
    allowed_keys = {f"{source['name']}@{source['version']}" for source in closure["sources"]}
    if not isinstance(overrides, dict) or set(overrides) - allowed_keys:
        raise ValueError("source URL overrides must identify an existing fixed source")
    for override in overrides.values():
        https_url(override)
    args.output.mkdir(parents=True, exist_ok=True)
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.parallelism) as executor:
        receipts = list(executor.map(lambda source: acquire(source, args.output, overrides), closure["sources"]))
    notices = []
    notice_error = None
    gettext_receipt = next((entry for entry in receipts if entry["name"] == "gettext"), None)
    if gettext_receipt and gettext_receipt["status"] != "failed":
        try:
            notices = retain_gettext_notices(args.output / gettext_receipt["archive"])
        except Exception as error:
            notice_error = f"{type(error).__name__}: {error}"
    failures = [entry for entry in receipts if entry["status"] == "failed"]
    result = {
        "schema_version": 1,
        "status": "failed" if failures or notice_error else "complete-local-verified",
        "publication_status": "not-published",
        "publication_status_scope": "observation-at-build-time; immutable release readback is a separate receipt",
        "expected_total_size": sum(source["size"] for source in closure["sources"]),
        "verified_total_size": sum(entry.get("size", 0) for entry in receipts),
        "sources": receipts,
        "gettext_notices": notices,
        "notice_error": notice_error,
        "trust_statement": "Source byte pins are from the fixed historical PBS build recipes. HTTPS acquisition and local SHA256 verification do not add a publisher signature or prove historical reproducibility.",
    }
    write_json(args.output / "source-retention.json", result)
    metadata_receipt = ROOT / "metadata" / "source-retention.json"
    write_json(metadata_receipt, result)
    closure["status"] = "sources-partially-verified-local" if failures or notice_error else "sources-verified-local"
    closure["publication_status"] = "not-published"
    closure["publication_status_scope"] = result["publication_status_scope"]
    closure["retention"] = {
        "expected_sources": len(receipts), "verified_sources": len(receipts) - len(failures),
        "expected_total_size": result["expected_total_size"],
        "verified_total_size": result["verified_total_size"],
        "receipt": "source-retention.json", "gettext_notice_error": notice_error,
    }
    write_json(args.closure, closure)
    metadata_closure = ROOT / "metadata" / "source-closure.json"
    write_json(metadata_closure, closure)
    recipe_path = ROOT / "recipe.json"
    recipe = json.loads(recipe_path.read_text(encoding="utf-8"))
    records = {record["source"]: record for record in recipe["metadata"]}
    for notice in notices:
        records[notice["source"]] = {field: notice[field] for field in ("source", "destination", "sha256")}
    records["metadata/source-retention.json"] = {
        "source": "metadata/source-retention.json",
        "destination": "upstream-metadata/source-retention.json",
        "sha256": digest(metadata_receipt),
    }
    records["metadata/source-closure.json"] = {
        "source": "metadata/source-closure.json",
        "destination": "upstream-metadata/source-closure.json",
        "sha256": digest(metadata_closure),
    }
    recipe["metadata"] = list(records.values())
    write_json(recipe_path, recipe)
    print(json.dumps({
        "status": result["status"], "verified_sources": len(receipts) - len(failures),
        "expected_sources": len(receipts), "verified_total_size": result["verified_total_size"],
        "expected_total_size": result["expected_total_size"], "gettext_notices": len(notices),
        "failures": [{"name": entry["name"], "url": entry["requested_url"], "error": entry["error"]} for entry in failures],
        "notice_error": notice_error,
    }))
    return 1 if failures or notice_error else 0


if __name__ == "__main__":
    raise SystemExit(main())
