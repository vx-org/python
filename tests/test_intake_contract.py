"""Offline tests for intake validation and reproducible legal metadata retention."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SPEC = importlib.util.spec_from_file_location(
    "verify_intake", Path(__file__).resolve().parents[1] / "verify_intake.py"
)
intake = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(intake)


def write_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def pinned_asset(name: str) -> tuple[dict, bytes]:
    content = f"unchanged original bytes for {name}\n".encode()
    return {
        "name": name,
        "url": f"https://upstream.example.org/{name}",
        "sha256": hashlib.sha256(content).hexdigest(),
        "size": len(content),
    }, content


def fixture(root: Path) -> tuple[dict, Path]:
    assets = []
    raw = root / "raw"
    raw.mkdir()
    for index in range(27):
        asset, content = pinned_asset(f"archive-{index}.tar.gz")
        assets.append(asset)
        (raw / asset["name"]).write_bytes(content)
    sources = [
        {"name": f"component-{index}", "version": "1", "sha256": asset["sha256"], "size": asset["size"]}
        for index, asset in enumerate(assets[3:25])
    ]
    closure = {"status": "sources-verified-local", "sources": sources}
    retention = {
        "status": "complete-local-verified",
        "sources": [
            {**source, "status": "verified-download", "archive": asset["name"], "requested_url": asset["url"]}
            for source, asset in zip(sources, assets[3:25], strict=True)
        ],
        "gettext_notices": [{"source": f"notice-{index}"} for index in range(10)],
    }
    write_json(root / "metadata/archive-intake.json", {"provenance": {"assets": assets[:3]}})
    write_json(root / "metadata/source-closure.json", closure)
    write_json(root / "source-closure.json", closure)
    write_json(root / "metadata/source-retention.json", retention)
    write_json(root / "metadata/build-source-intake.json", [
        {"archive": asset["name"], "source_url": asset["url"], "source_sha256": asset["sha256"], "size": asset["size"]}
        for asset in assets[25:]
    ])
    (root / "metadata/LICENSE").write_bytes(b"Literal upstream legal text\r\n\xff\n")
    (root / "README.md").write_text("Historical acquisition intake.\n", encoding="utf-8")
    (root / "LICENSE").write_bytes(b"MIT License\r\n\r\nCopyright (c) VX contributors\r\n")
    (root / "package.py").write_text('name = "python"\nversion = "3.7.9"\n', encoding="utf-8")
    recipe = {
        "package": {"definition": {"source": "package.py", "sha256": intake.digest(root / "package.py")}},
        "metadata": [
            {"source": path.relative_to(root).as_posix(), "sha256": intake.digest(path)}
            for path in sorted((root / "metadata").rglob("*")) if path.is_file()
        ],
    }
    write_json(root / "recipe.json", recipe)
    manifest = {
        "schema_version": 1,
        "asset_count": 27,
        "total_size": sum(asset["size"] for asset in assets),
        "assets": assets,
        "origins": [{"name": asset["name"]} for asset in assets],
    }
    write_json(root / "intake-assets.json", manifest)
    return recipe, raw


class IntakeContractTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def verify_fixture(self, *, raw=False):
        # Shared schema validation is exercised by the real repository CI invocation.
        # These fixtures isolate byte, path, provenance and publication-boundary checks.
        with mock.patch.object(intake, "shared_validator", return_value=lambda recipe: None):
            return intake.verify_intake(self.root, self.root, self.root / "raw" if raw else None)

    def test_all_27_original_archives_and_metadata_verify_offline(self):
        fixture(self.root)
        manifest, files = self.verify_fixture(raw=True)
        self.assertEqual(len(manifest["assets"]), 27)
        self.assertEqual(len(files), 10)
        self.assertNotIn("recipe.organization-proposed.json", files)

    def test_manifest_cannot_change_a_historical_pin_or_duplicate_a_name(self):
        assets = {asset["name"]: asset for asset, _ in (pinned_asset(f"asset-{index}.tar.gz") for index in range(27))}
        manifest = {"schema_version": 1, "asset_count": 27, "assets": list(assets.values()), "total_size": sum(asset["size"] for asset in assets.values()), "origins": [{"name": name} for name in assets]}
        intake.validate_manifest(manifest, assets)
        changed = copy.deepcopy(manifest)
        changed["assets"][0]["sha256"] = "0" * 64
        with self.assertRaisesRegex(intake.IntakeError, "byte pins differ"):
            intake.validate_manifest(changed, assets)
        changed = copy.deepcopy(manifest)
        changed["assets"][1] = copy.deepcopy(changed["assets"][0])
        with self.assertRaisesRegex(intake.IntakeError, "collide"):
            intake.validate_manifest(changed, assets)

    def test_corrupt_package_definition_is_rejected(self):
        fixture(self.root)
        (self.root / "package.py").write_text('name = "changed"\n', encoding="utf-8")
        with self.assertRaisesRegex(intake.IntakeError, "SHA256"):
            self.verify_fixture()

    def test_corrupt_raw_asset_is_rejected(self):
        _, raw = fixture(self.root)
        path = next(raw.iterdir())
        content = path.read_bytes()
        path.write_bytes(b"!" + content[1:])
        with self.assertRaisesRegex(intake.IntakeError, "SHA256"):
            self.verify_fixture(raw=True)

    def test_unregistered_metadata_is_rejected(self):
        fixture(self.root)
        (self.root / "metadata/unregistered.json").write_text("{}", encoding="utf-8")
        with self.assertRaisesRegex(intake.IntakeError, "metadata directory differs"):
            self.verify_fixture()

    def test_hash_pinned_nested_metadata_still_requires_public_sanitization(self):
        recipe, _ = fixture(self.root)
        path = self.root / "metadata/private.json"
        write_json(path, {"nested": [{"final_url": "https://assets.example.org/file?sig=DO_NOT_PRINT"}]})
        recipe["metadata"].append({"source": "metadata/private.json", "sha256": intake.digest(path)})
        write_json(self.root / "recipe.json", recipe)
        with self.assertRaisesRegex(intake.IntakeError, "temporary redirect") as caught:
            self.verify_fixture()
        self.assertNotIn("DO_NOT_PRINT", str(caught.exception))

    def test_incomplete_source_notice_retention_is_rejected(self):
        fixture(self.root)
        path = self.root / "metadata/source-retention.json"
        value = intake.read_json(path)
        value["gettext_notices"].pop()
        write_json(path, value)
        with self.assertRaisesRegex(intake.IntakeError, "ten audited gettext"):
            self.verify_fixture()

    def test_public_json_rejects_paths_and_signed_queries_without_echoing_values(self):
        samples = [r"C:\Users\private\receipt.json", r"\\server\private\receipt.json", "https://host.example/file?X-Amz-Signature=DO_NOT_PRINT", "https://host.example/file?access_token=DO_NOT_PRINT"]
        for value in samples:
            with self.subTest(value=value), self.assertRaises(intake.IntakeError) as caught:
                intake.scan_public_json({"nested": [{"value": value}]}, "metadata/receipt.json")
            self.assertNotIn(value, str(caught.exception))
            self.assertNotIn("DO_NOT_PRINT", str(caught.exception))
        intake.scan_public_json({"source_url": "https://host.example/file?download=1"}, "receipt.json")
        with self.assertRaises(intake.IntakeError):
            intake.scan_public_json({"final_url": "https://host.example/file?download=1"}, "receipt.json")

    def test_duplicate_json_keys_and_nonportable_paths_are_rejected(self):
        path = self.root / "duplicate.json"
        path.write_text('{"sha256": "first", "sha256": "second"}', encoding="utf-8")
        with self.assertRaisesRegex(intake.IntakeError, "duplicate"):
            intake.read_json(path)
        for value in ["../escape", "/absolute", "metadata/../escape", "file:stream", "CON.txt", "trailing.", "metadata//file", "file?.txt"]:
            with self.subTest(value=value), self.assertRaises(intake.IntakeError):
                intake.safe_relative(value)

    def test_metadata_archive_is_deterministic_and_preserves_literal_license_bytes(self):
        fixture(self.root)
        _, files = self.verify_fixture()
        first = self.root / "dist/one.tar.gz"
        second = self.root / "dist/two.tar.gz"
        first_record = intake.write_metadata_archive(self.root, files, first)
        second_record = intake.write_metadata_archive(self.root, list(reversed(files)), second)
        self.assertEqual(first.read_bytes(), second.read_bytes())
        self.assertEqual(first_record["sha256"], second_record["sha256"])
        self.assertEqual(first.read_bytes()[4:8], b"\0" * 4)
        with tarfile.open(first, "r:gz") as archive:
            self.assertEqual(archive.getnames(), sorted(files))
            self.assertEqual(archive.extractfile("LICENSE").read(), (self.root / "LICENSE").read_bytes())
            self.assertEqual(archive.extractfile("metadata/LICENSE").read(), (self.root / "metadata/LICENSE").read_bytes())
            for member in archive.getmembers():
                self.assertTrue(member.isreg())
                self.assertEqual((member.mode, member.mtime, member.uid, member.gid, member.uname, member.gname), (0o644, 0, 0, 0, "", ""))
        self.assertEqual(first.with_name(first.name + ".sha256").read_text(encoding="ascii"), f"{first_record['sha256']}  one.tar.gz\n")

    def test_metadata_archive_preflights_binary_inputs_and_output_collisions(self):
        fixture(self.root)
        output = self.root / "dist/metadata.tar.gz"
        (self.root / "metadata/runtime.so.3").write_bytes(b"runtime bytes")
        with self.assertRaisesRegex(intake.IntakeError, "runtime or source archive"):
            intake.write_metadata_archive(self.root, ["metadata/runtime.so.3"], output)
        self.assertFalse(output.exists())
        with self.assertRaisesRegex(intake.IntakeError, "explicit public metadata boundary"):
            intake.write_metadata_archive(self.root, ["recipe.organization-proposed.json"], output)
        with self.assertRaisesRegex(intake.IntakeError, "cannot replace"):
            intake.write_metadata_archive(self.root, ["package.py"], self.root / "package.py")

    def test_actual_gettext_copying_lib_notices_are_retained_unchanged(self):
        project_root = Path(__file__).resolve().parents[1]
        files = sorted(intake.LGPL_LIBRARY_NOTICES)
        for relative in files:
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((project_root / relative).read_bytes())
        output = self.root / "dist/legal.tar.gz"
        intake.write_metadata_archive(self.root, files, output)
        with tarfile.open(output, "r:gz") as archive:
            self.assertEqual(archive.getnames(), files)
            for relative in files:
                self.assertEqual(archive.extractfile(relative).read(), (project_root / relative).read_bytes())

    def test_copying_lib_name_does_not_allow_binary_or_arbitrary_library_files(self):
        relative = sorted(intake.LGPL_LIBRARY_NOTICES)[0]
        target = self.root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        output = self.root / "dist/legal.tar.gz"
        header = b"GNU LESSER GENERAL PUBLIC LICENSE\nVersion 2.1, February 1999\n"
        for content in [b"!<arch>\nimport.obj/\x00\x01", header + b"\0binary payload", header + b"\xff", b"ordinary UTF-8 library data\n"]:
            target.write_bytes(content)
            with self.subTest(content=content), self.assertRaisesRegex(intake.IntakeError, "runtime or source archive"):
                intake.write_metadata_archive(self.root, [relative], output)
            self.assertFalse(output.exists())
        arbitrary = "metadata/arbitrary/COPYING.LIB"
        path = self.root / arbitrary
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(header)
        with self.assertRaisesRegex(intake.IntakeError, "runtime or source archive"):
            intake.write_metadata_archive(self.root, [arbitrary], output)

    def test_symlink_metadata_is_rejected(self):
        source = self.root / "original.txt"
        source.write_bytes(b"original")
        link = self.root / "link.txt"
        try:
            link.symlink_to(source)
        except OSError:
            self.skipTest("host does not permit unprivileged symlinks")
        with self.assertRaisesRegex(intake.IntakeError, "filesystem links"):
            intake.contained_regular(self.root, "link.txt")


if __name__ == "__main__":
    unittest.main()
