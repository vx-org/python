"""Stage verified historical archives for an organization intake release."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import tempfile
import urllib.parse
from pathlib import Path

from public_receipts import public_acquisition, update_public_retention


ROOT = Path(__file__).resolve().parent
REPOSITORY = "https://github.com/vx-org/python"
INTAKE_TAG = "python-3.7.9-pbs-20200823"
RUNTIME_TARGETS = {
    "x86_64-pc-windows-msvc",
    "x86_64-unknown-linux-gnu",
    "x86_64-apple-darwin",
}
REQUIRED_GETTEXT_NOTICES = {
    "metadata/gettext-source/COPYING",
    "metadata/gettext-source/gettext-runtime/intl/COPYING.LIB",
    "metadata/gettext-source/gettext-runtime/libasprintf/COPYING.LIB",
    "metadata/gettext-source/gettext-tools/COPYING",
    "metadata/gettext-source/libtextstyle/COPYING",
}


def read_json(path: Path) -> dict | list:
    return json.loads(path.read_text(encoding="utf-8"))


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def verify(path: Path, sha256: str, size: int) -> None:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"asset is not a regular file: {path.name}")
    if not re.fullmatch("[a-f0-9]{64}", sha256) or type(size) is not int or size <= 0:
        raise ValueError(f"invalid fixed asset identity: {path.name}")
    if path.stat().st_size != size or digest(path) != sha256:
        raise ValueError(f"fixed asset identity mismatch: {path.name}")


def contained_file(directory: Path, relative: str) -> Path:
    path = directory / relative
    path.resolve(strict=True).relative_to(directory.resolve(strict=True))
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"expected contained regular file: {relative}")
    return path


def https_url(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    if (
        parsed.scheme != "https" or not parsed.hostname
        or parsed.username or parsed.password or parsed.fragment
        or "\\" in url or any(character.isspace() for character in url)
    ):
        raise ValueError("intake asset URLs must use credential-free HTTPS")
    return url


def acquisition(receipt: dict) -> dict:
    if receipt.get("status") == "verified-download":
        return receipt
    if receipt.get("status") == "verified-cache":
        original = receipt.get("intake")
        if isinstance(original, dict) and original.get("status") == "verified-download":
            return original
    raise ValueError(f"source lacks a successful original acquisition receipt: {receipt.get('name')}")


def stage_verified(source: Path, destination: Path, sha256: str, size: int) -> None:
    verify(source, sha256, size)
    if destination.exists() or destination.is_symlink():
        verify(destination, sha256, size)
        return
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(prefix=".intake-", suffix=".part", dir=destination.parent, delete=False) as stream:
            temporary = Path(stream.name)
        shutil.copyfile(source, temporary)
        verify(temporary, sha256, size)
        # Install without replacing an asset created concurrently.
        try:
            os.link(temporary, destination)
        except FileExistsError:
            verify(destination, sha256, size)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8", newline="\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", type=Path, required=True, help="Directory containing the three unchanged historical runtime archives and provenance.json.")
    parser.add_argument("--source-dir", type=Path, default=ROOT / "intake-source-dir")
    args = parser.parse_args()
    retention = read_json(ROOT / "source-downloads" / "source-retention.json")
    closure = read_json(ROOT / "source-closure.json")
    if retention.get("status") != "complete-local-verified" or retention.get("notice_error") is not None:
        raise ValueError("all 22 component sources and gettext notices must pass retention before staging")
    if closure.get("status") != "sources-verified-local":
        raise ValueError("source closure must record completed local verification")
    sources = closure["sources"]
    source_receipts = retention["sources"]
    expected_sources = {(source["name"], source["version"]): source for source in sources}
    observed_sources = {(source["name"], source["version"]): source for source in source_receipts}
    if len(sources) != 22 or len(source_receipts) != 22 or len(expected_sources) != 22 or set(expected_sources) != set(observed_sources):
        raise ValueError("intake requires exactly the 22 pinned component sources")
    expected_total_size = sum(source["size"] for source in sources)
    if retention["verified_total_size"] != expected_total_size or retention["expected_total_size"] != expected_total_size:
        raise ValueError("source retention aggregate byte counts do not match the fixed closure")
    notices = retention["gettext_notices"]
    if len(notices) != 10 or not REQUIRED_GETTEXT_NOTICES <= {notice["source"] for notice in notices}:
        raise ValueError("all 10 audited gettext notices, including the five component licenses, are required")
    for notice in notices:
        verify(contained_file(ROOT, notice["source"]), notice["sha256"], notice["size"])

    recipe = read_json(ROOT / "recipe.json")
    for metadata in recipe["metadata"]:
        path = contained_file(ROOT, metadata["source"])
        if digest(path) != metadata["sha256"]:
            raise ValueError(f"recipe metadata checksum mismatch: {metadata['source']}")
    definition = recipe["package"]["definition"]
    if digest(contained_file(ROOT, definition["source"])) != definition["sha256"]:
        raise ValueError("recipe package.py checksum mismatch")

    assets = []
    origins = []
    local_sources = []

    def add(path: Path, name: str, url: str, sha256: str, size: int, origin: dict) -> None:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]*", name):
            raise ValueError(f"nonportable intake asset name: {name!r}")
        if any(asset["name"].casefold() == name.casefold() for asset in assets):
            raise ValueError(f"duplicate portable intake asset name: {name}")
        verify(path, sha256, size)
        assets.append({"name": name, "url": https_url(url), "sha256": sha256, "size": size})
        origins.append({"name": name, **origin})
        local_sources.append(path)

    runtime_intake = read_json(args.candidate / "provenance.json")
    runtimes = runtime_intake["assets"]
    if len(runtimes) != 3 or {runtime["target"] for runtime in runtimes} != RUNTIME_TARGETS:
        raise ValueError("intake requires the three audited original runtime variants")
    for runtime in runtimes:
        add(
            contained_file(args.candidate, runtime["name"]), runtime["name"], runtime["url"],
            runtime["sha256"], runtime["size"], {
                "kind": "original-runtime", "target": runtime["target"],
                "original_url": runtime["url"], "requested_url": runtime["url"],
                "github_asset_id": runtime["github_asset_id"], "release_tag": runtime["release_tag"],
                "digest_origin": runtime_intake["integrity"]["statement"],
                "publisher_digest": runtime_intake["integrity"]["publisher_digest"],
                "intake_integrity": runtime_intake["integrity"],
            },
        )
    for key, source in expected_sources.items():
        receipt = observed_sources[key]
        original = acquisition(receipt)
        public_original = public_acquisition(original)
        for observed in (receipt, original):
            if observed.get("sha256") != source["sha256"] or observed.get("size") != source["size"]:
                raise ValueError(f"source acquisition receipt conflicts with historical byte pins: {source['name']}")
        add(
            contained_file(ROOT / "source-downloads", receipt["archive"]), receipt["archive"],
            original["requested_url"], source["sha256"], source["size"], {
                "kind": "component-source", "component": source["name"], "version": source["version"],
                "original_url": source["url"], "requested_url": original["requested_url"],
                "final_url": public_original.get("final_url"), "digest_origin": source["digest_origin"],
                "build_tags": source["build_tags"], "acquisition_receipt": public_original,
            },
        )
    build_sources = read_json(ROOT / "source-audit" / "sources.json")
    if len(build_sources) != 2 or {source["tag"] for source in build_sources} != {"20200822", "20200823"}:
        raise ValueError("both exact historical PBS build recipes must be retained")
    for source in build_sources:
        add(
            contained_file(ROOT / "source-audit", source["archive"]), source["archive"],
            source["source_url"], source["source_sha256"], source["size"], {
                "kind": "build-recipe", "repository": source["repository"],
                "tag": source["tag"], "revision": source["revision"],
                "original_url": source["source_url"], "requested_url": source["source_url"],
                "digest_origin": source["source_sha256_origin"],
            },
        )
    if len(assets) != 27:
        raise ValueError("intake must contain exactly 27 unchanged archives")

    args.source_dir.mkdir(parents=True, exist_ok=True)
    for asset, source in zip(assets, local_sources, strict=True):
        stage_verified(source, args.source_dir / asset["name"], asset["sha256"], asset["size"])
    order = sorted(range(len(assets)), key=lambda index: assets[index]["name"].casefold())
    assets = [assets[index] for index in order]
    origins = [origins[index] for index in order]
    # Original receipts in source-downloads remain byte-for-byte intact.
    update_public_retention(ROOT, retention, recipe)
    write_json(ROOT / "recipe.json", recipe)
    write_json(ROOT / "intake-assets.json", {
        "schema_version": 1, "repository": REPOSITORY, "tag": INTAKE_TAG,
        "publication_status": "prepared-locally-not-published",
        "release_purpose": "Verified historical acquisition intake; native Rez releases and installed VX consumer acceptance remain separate gates.",
        "asset_count": len(assets), "total_size": sum(asset["size"] for asset in assets),
        "assets": assets, "origins": origins,
    })
    organization_base = f"{REPOSITORY}/releases/download/{INTAKE_TAG}"
    proposed = json.loads(json.dumps(recipe))
    proposed["release_assets"] = [{**asset, "url": f"{organization_base}/{asset['name']}"} for asset in assets]
    runtime_names = {runtime["target"]: runtime["name"] for runtime in runtimes}
    for target in proposed["targets"]:
        target["upstream"]["url"] = f"{organization_base}/{runtime_names[target['triple']]}"
    proposed["upstream_manifest"] = f"{REPOSITORY}/releases/tag/{INTAKE_TAG}"
    base_source = next(source for source in build_sources if source["tag"] == "20200822")
    proposed["provenance"]["source_url"] = f"{organization_base}/{base_source['archive']}"
    write_json(ROOT / "recipe.organization-proposed.json", proposed)
    print(json.dumps({
        "status": "prepared-locally-not-published", "assets": len(assets),
        "total_size": sum(asset["size"] for asset in assets), "organization_intake_tag": INTAKE_TAG,
        "current_recipe_upstream_urls_modified": False,
        "public_receipt_and_metadata_digest_updated": True,
        "promotion_gate": "Verify public immutable intake asset names, sizes and SHA256 before promoting recipe.organization-proposed.json.",
    }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
