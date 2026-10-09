"""Prepare local package metadata and a pinned recipe from completed audits."""

from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent
PLATFORMS = {
    "x86_64-pc-windows-msvc": ("windows", "windows-2025", "20200822"),
    "x86_64-unknown-linux-gnu": ("linux", "ubuntu-24.04", "20200822"),
    "x86_64-apple-darwin": ("osx", "macos-15-intel", "20200823"),
}
RUNTIME_SOURCE_NAMES = {
    "bdb", "bzip2", "cpython-3.7", "gettext", "libX11", "libXau",
    "libedit", "libffi", "libressl", "libxcb", "ncurses", "openssl",
    "pip", "readline", "setuptools", "sqlite", "tcl", "tix", "tk",
    "uuid", "xz", "zlib",
}


def sha256(contents: bytes) -> str:
    return hashlib.sha256(contents).hexdigest()


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8", newline="\n")


def source_manifest(source: Path) -> dict:
    module = ast.parse(source.read_bytes())
    for statement in module.body:
        if (
            isinstance(statement, ast.Assign)
            and len(statement.targets) == 1
            and isinstance(statement.targets[0], ast.Name)
            and statement.targets[0].id == "DOWNLOADS"
        ):
            return ast.literal_eval(statement.value)
    raise ValueError("historical build source lacks literal DOWNLOADS manifest")


def main() -> None:
    inventory = json.loads((ROOT / "audit" / "inventory.json").read_text(encoding="utf-8"))
    build_sources = json.loads((ROOT / "source-audit" / "sources.json").read_text(encoding="utf-8"))
    metadata = []

    def copy_metadata(contents: bytes, relative: str) -> None:
        destination = ROOT / "metadata" / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(contents)
        metadata.append({
            "source": f"metadata/{relative}",
            "destination": f"upstream-metadata/{relative}",
            "sha256": sha256(contents),
        })

    for report in inventory["targets"]:
        target = report["target"]
        for entry in report["metadata"]:
            contents = (ROOT / "audit" / target / entry["audit_file"]).read_bytes()
            if sha256(contents) != entry["sha256"]:
                raise ValueError("audited metadata hash changed")
            copy_metadata(contents, f"{target}/{entry['archive_path']}")
    copy_metadata(
        (ROOT / "audit" / "inventory.json").read_bytes(), "archive-intake.json"
    )
    copy_metadata(
        (ROOT / "source-audit" / "sources.json").read_bytes(), "build-source-intake.json"
    )

    sources = {}
    for source in build_sources:
        tag = source["tag"]
        directory = ROOT / "source-audit" / tag
        manifests = list(directory.glob("*-downloads.py"))
        if len(manifests) != 1:
            raise ValueError(f"expected one historical download manifest for {tag}")
        manifest = source_manifest(manifests[0])
        # This intentionally includes both cryptographic-library recipes and
        # retained build-library sources. The archive's full build tree is kept.
        for name, entry in manifest.items():
            if name not in RUNTIME_SOURCE_NAMES:
                continue
            key = (name, entry["sha256"])
            record = sources.setdefault(key, {
                "name": name,
                **{field: entry[field] for field in ("version", "url", "sha256", "size")},
                "digest_origin": "pinned historical PBS build recipe",
                "build_tags": [],
            })
            record["build_tags"].append(tag)
        copy_metadata((directory / "receipt.json").read_bytes(), f"build-sources/{tag}/receipt.json")
        copy_metadata(manifests[0].read_bytes(), f"build-sources/{tag}/downloads.py")
        license_path = next(directory.glob("*-LICENSE"))
        copy_metadata(license_path.read_bytes(), f"build-sources/{tag}/LICENSE")
    closure = {
        "status": "sources-pinned-not-yet-persisted",
        "scope": "CPython and runtime/static libraries retained in the three original PBS archives",
        "build_recipes": build_sources,
        "sources": list(sources.values()),
        "publication_gate": "Retain required corresponding sources, build recipes, patches and notices alongside immutable runtime assets before publication.",
    }
    write_json(ROOT / "source-closure.json", closure)
    copy_metadata((ROOT / "source-closure.json").read_bytes(), "source-closure.json")

    common_smoke = (ROOT / "smoke.py").read_text(encoding="utf-8")
    targets = []
    for asset in inventory["provenance"]["assets"]:
        target = asset["target"]
        platform, runner, _ = PLATFORMS[target]
        mappings = [{"source": "python", "destination": "."}]
        executable = "{root}/payload/install/python{exe}"
        if platform != "windows":
            mappings.append({
                "source": "python/install/bin/python3.7m",
                "destination": "install/bin/python",
                "executable": True,
            })
            executable = "{root}/payload/install/bin/python"
        targets.append({
            "triple": target,
            "platform": platform,
            "arch": "x86_64",
            "runner": runner,
            "status": "supported",
            "upstream": {"url": asset["url"], "sha256": asset["sha256"]},
            "payload": {"format": "tar.zst", "mappings": mappings},
            "smoke_test": {
                "command": [executable, "-I", "-c", common_smoke],
                "expect": "VX_PYTHON_NATIVE_SMOKE_OK",
                "timeout_seconds": 120,
            },
        })
    base_source = next(source for source in build_sources if source["tag"] == "20200822")
    recipe = {
        "schema_version": 1,
        "tool": "python",
        "version": "3.7.9",
        "release_date": "2020-08-23",
        "upstream_manifest": "https://github.com/astral-sh/python-build-standalone/releases/tag/20200822",
        "compatibility": {"rez_next": ">=0.3.9", "vx_rez_adapter": ">=0.1.0"},
        "package": {
            "definition": {"source": "package.py", "sha256": sha256((ROOT / "package.py").read_bytes())},
            "description": "CPython 3.7.9 standalone interpreter with standard library and development files",
            "tools": ["python"],
            "path_entries": ["payload/install", "payload/install/bin"],
            "smoke_test": targets[0]["smoke_test"],
        },
        "provenance": {
            **{field: base_source[field] for field in ("repository", "revision", "source_url", "source_sha256")},
            "license": "Python-2.0 AND CNRI-Python AND LicenseRef-PBS-Bundled-Dependencies",
        },
        "metadata": metadata,
        "targets": targets,
        "unsupported_targets": [
            {"triple": triple, "status": "unsupported", "reason": "No Python 3.7.9 standalone archive in the audited historical PBS releases."}
            for triple in ("aarch64-pc-windows-msvc", "aarch64-unknown-linux-gnu", "aarch64-apple-darwin")
        ],
    }
    write_json(ROOT / "recipe.json", recipe)
    print(json.dumps({
        "targets": len(targets),
        "metadata_files": len(metadata),
        "pinned_runtime_sources": len(sources),
        "package_definition_sha256": recipe["package"]["definition"]["sha256"],
        "status": "staged; source closure and native publication gates remain open",
    }))


if __name__ == "__main__":
    main()
