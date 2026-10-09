"""Read and retain the exact BDB source license and pinned PBS statements."""

from __future__ import annotations

import argparse
import hashlib
import json
import tarfile
import urllib.parse
from pathlib import Path, PurePosixPath

from public_receipts import public_acquisition


ROOT = Path(__file__).resolve().parent
MAX_DOCUMENT_BYTES = 256 * 1024
MAX_ARCHIVE_MEMBERS = 100_000


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def read_document(archive_path: Path, expected_sha256: str, expected_size: int, member_name: str) -> bytes:
    if archive_path.is_symlink() or not archive_path.is_file():
        raise ValueError("source archive must be a regular file")
    if archive_path.stat().st_size != expected_size or digest(archive_path) != expected_sha256:
        raise ValueError("source archive does not match its fixed byte identity")
    result = None
    with tarfile.open(archive_path, "r:gz") as archive:
        for index, member in enumerate(archive):
            if index >= MAX_ARCHIVE_MEMBERS:
                raise ValueError("source archive exceeds metadata audit member bound")
            path = PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts or "\\" in member.name:
                raise ValueError("source archive contains a non-contained member name")
            if path.as_posix() != member_name:
                continue
            if result is not None or not member.isfile() or member.size > MAX_DOCUMENT_BYTES:
                raise ValueError("requested source document is duplicate, non-regular, or oversized")
            stream = archive.extractfile(member)
            if stream is None:
                raise ValueError("source document cannot be read")
            result = stream.read(MAX_DOCUMENT_BYTES + 1)
            if len(result) != member.size:
                raise ValueError("source document length mismatch")
    if result is None:
        raise ValueError(f"source document missing: {member_name}")
    return result


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8", newline="\n")


def retained_document(contents: bytes, relative: str) -> dict:
    destination = ROOT / "metadata" / relative
    destination.resolve().relative_to((ROOT / "metadata").resolve())
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(contents)
    return {
        "source": f"metadata/{relative}",
        "destination": f"upstream-metadata/{relative}",
        "sha256": hashlib.sha256(contents).hexdigest(), "size": len(contents),
    }


def oracle_url(value: str) -> str:
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme != "https" or not (parsed.hostname or "").endswith(".oracle.com") or parsed.username or parsed.password or parsed.fragment:
        raise ValueError("Oracle evidence must link to its official HTTPS host")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--oracle-announcement-url", type=oracle_url, required=True)
    parser.add_argument("--oracle-changelog-url", type=oracle_url, required=True)
    args = parser.parse_args()
    retention = read_json(ROOT / "source-downloads" / "source-retention.json")
    if retention.get("status") != "complete-local-verified" or retention.get("notice_error") is not None:
        raise ValueError("license audit requires the complete verified source corpus")
    source = next(source for source in retention["sources"] if source["name"] == "bdb")
    if source["version"] != "6.0.19" or source["status"] not in {"verified-download", "verified-cache"}:
        raise ValueError("license audit requires the exact verified BDB 6.0.19 source")
    archive_path = ROOT / "source-downloads" / source["archive"]
    archive_path.resolve(strict=True).relative_to((ROOT / "source-downloads").resolve())
    license_bytes = read_document(archive_path, source["sha256"], source["size"], "db-6.0.19/LICENSE")
    source_license = retained_document(license_bytes, "bdb-source/LICENSE")
    literal_text = license_bytes.decode("utf-8")
    comparisons = []
    for target in ("x86_64-pc-windows-msvc", "x86_64-unknown-linux-gnu", "x86_64-apple-darwin"):
        path = ROOT / "metadata" / target / "python" / "licenses" / "LICENSE.bdb.txt"
        comparisons.append({
            "target": target, "sha256": digest(path), "size": path.stat().st_size,
            "matches_retained_source_license": digest(path) == source_license["sha256"],
        })

    build_sources = read_json(ROOT / "source-audit" / "sources.json")
    documents = [source_license]
    statements = []
    for build_source in build_sources:
        revision = build_source["revision"]
        path = ROOT / "source-audit" / build_source["archive"]
        contents = read_document(
            path, build_source["source_sha256"], build_source["size"],
            f"python-build-standalone-{revision}/docs/technotes.rst",
        )
        document = retained_document(contents, f"bdb-license-evidence/pbs-{build_source['tag']}-technotes.rst")
        documents.append(document)
        lines = contents.decode("utf-8").splitlines()
        matching = [
            {"line": index + 1, "text": line}
            for index, line in enumerate(lines)
            if any(token in line.lower() for token in ("6.0.19", "sleepycat", "agpl", "berkeley"))
        ]
        statements.append({
            "publisher": "Python Build Standalone", "kind": "pinned-build-documentation",
            "tag": build_source["tag"], "revision": revision,
            "url": f"{build_source['repository']}/blob/{revision}/docs/technotes.rst",
            "retained_document": document, "matching_literal_lines": matching,
        })
    statements.extend([
        {
            "publisher": "Oracle", "kind": "announcement", "url": args.oracle_announcement_url,
            "statement_summary": "The 6.0 announcement describes the 6.x release under AGPL terms.",
            "evidence_method": "Coordinator primary-source review; this local audit does not fetch the page.",
        },
        {
            "publisher": "Oracle", "kind": "6.0.20-changelog", "url": args.oracle_changelog_url,
            "statement_summary": "The 6.0.20 changelog records an update of the LICENSE file to AGPL.",
            "evidence_method": "Coordinator primary-source review; this local audit does not fetch the page.",
        },
    ])
    evidence = {
        "schema_version": 1, "component": "Berkeley DB", "version": "6.0.19",
        "status": "literal-source-license-retained; differing-publisher-statements-recorded",
        "source_archive": {
            "name": source["archive"], "sha256": source["sha256"], "size": source["size"],
            "digest_origin": source["digest_origin"], "acquisition": public_acquisition(source),
        },
        "source_license": {"archive_path": "db-6.0.19/LICENSE", **source_license},
        "literal_observations": {
            "contains_redistribution_clause": "Redistribution and use in source and binary forms" in literal_text,
            "contains_affero_name": "affero" in literal_text.lower(),
            "contains_sleepycat_name": "sleepycat" in literal_text.lower(),
        },
        "upstream_runtime_license_comparisons": comparisons,
        "publisher_statements": statements,
        "license_review_boundary": "This record preserves literal source terms and differing publisher statements. It does not settle their legal interpretation or guarantee redistribution rights. Licensing review is independent from byte integrity, source retention and native runtime acceptance.",
    }
    evidence_path = ROOT / "metadata" / "bdb-license-provenance.json"
    write_json(evidence_path, evidence)
    documents.append({
        "source": "metadata/bdb-license-provenance.json",
        "destination": "upstream-metadata/bdb-license-provenance.json",
        "sha256": digest(evidence_path), "size": evidence_path.stat().st_size,
    })
    closure = read_json(ROOT / "source-closure.json")
    closure["license_evidence"] = {
        "bdb-6.0.19": {
            "record": "bdb-license-provenance.json", "source_license_sha256": source_license["sha256"],
            "status": evidence["status"], "review_boundary": evidence["license_review_boundary"],
        },
    }
    write_json(ROOT / "source-closure.json", closure)
    write_json(ROOT / "metadata" / "source-closure.json", closure)
    recipe = read_json(ROOT / "recipe.json")
    records = {record["source"]: record for record in recipe["metadata"]}
    for document in documents:
        records[document["source"]] = {field: document[field] for field in ("source", "destination", "sha256")}
    records["metadata/source-closure.json"]["sha256"] = digest(ROOT / "metadata" / "source-closure.json")
    recipe["metadata"] = list(records.values())
    write_json(ROOT / "recipe.json", recipe)
    print(json.dumps({
        "source_license_sha256": source_license["sha256"], "source_license_size": source_license["size"],
        "literal_observations": evidence["literal_observations"],
        "all_runtime_copies_match_source": all(record["matches_retained_source_license"] for record in comparisons),
        "publisher_evidence_records": len(statements), "license_interpretation": "not-settled-by-this-audit",
    }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
