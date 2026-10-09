"""Offline contracts for the exact Python intake release publication boundary."""

from __future__ import annotations

import importlib.util
import io
import json
import shutil
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import verify_release_readback as readback


# Reuse the existing provenance fixture, including its 22 pinned source receipts.
SPEC = importlib.util.spec_from_file_location(
    "_intake_readback_fixtures", Path(__file__).with_name("test_intake_contract.py")
)
fixtures = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixtures)


def write_companion(directory: Path, name: str) -> None:
    sha256 = readback.intake.digest(directory / name)
    (directory / f"{name}.sha256").write_bytes(f"{sha256}  {name}\n".encode("ascii"))


class ReleaseReadbackTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        base = Path(self.temporary.name)
        self.root = base / "source"
        self.root.mkdir()
        _, raw = fixtures.fixture(self.root)
        self.expected = base / "expected"
        self.expected.mkdir()
        self.downloaded = base / "downloaded"
        for path in raw.iterdir():
            shutil.copyfile(path, self.expected / path.name)
        shutil.copyfile(self.root / readback.INTAKE_MANIFEST, self.expected / readback.INTAKE_MANIFEST)
        manifest = readback.intake.read_json(self.root / readback.INTAKE_MANIFEST)
        (self.expected / readback.RELEASE_MANIFEST).write_text(
            json.dumps({"schema_version": 1, "assets": manifest["assets"]}), encoding="utf-8"
        )
        self.metadata_files = sorted(
            {path.relative_to(self.root).as_posix() for path in (self.root / "metadata").rglob("*") if path.is_file()}
            | readback.intake.METADATA_ROOT_FILES
        )
        readback.intake.write_metadata_archive(
            self.root, self.metadata_files, self.expected / readback.METADATA_ARCHIVE,
        )
        for path in list(self.expected.iterdir()):
            if not path.name.endswith(".sha256"):
                write_companion(self.expected, path.name)
        shutil.copytree(self.expected, self.downloaded)

    def verify(self):
        # The shared schema's real recipe validation is exercised by repository CI.
        with mock.patch.object(readback.intake, "shared_validator", return_value=lambda recipe: None):
            return readback.verify_release_readback(
                self.root, self.root, self.expected, self.downloaded,
            )

    def replace_json(self, name: str, value) -> None:
        for directory in (self.expected, self.downloaded):
            (directory / name).write_text(json.dumps(value), encoding="utf-8")
            write_companion(directory, name)

    def test_exact_60_assets_and_original_metadata_verify_without_claiming_native_acceptance(self):
        report = self.verify()
        self.assertEqual(report["release_asset_count"], 60)
        self.assertEqual(report["raw_archive_assets"], 27)
        self.assertEqual(report["metadata_files"], 10)
        self.assertEqual(report["native_runtime_acceptance"], "not-run")
        self.assertEqual(report["github_immutable_release_state"], "not-checked-by-local-file-verifier")
        self.assertEqual(set(report["ancillary_pins"]), readback.ANCILLARY_FILES)

    def test_missing_or_unexpected_download_is_rejected(self):
        path = self.downloaded / "archive-0.tar.gz"
        content = path.read_bytes()
        path.unlink()
        with self.assertRaisesRegex(readback.ReadbackError, "missing or unexpected"):
            self.verify()
        path.write_bytes(content)
        (self.downloaded / "extra.txt").write_bytes(b"unexpected")
        with self.assertRaisesRegex(readback.ReadbackError, "missing or unexpected"):
            self.verify()

    def test_nonflat_download_is_rejected(self):
        (self.downloaded / "nested").mkdir()
        with self.assertRaisesRegex(readback.intake.IntakeError, "regular file"):
            self.verify()

    def test_raw_corruption_cannot_be_hidden_by_a_changed_downloaded_checksum(self):
        name = "archive-0.tar.gz"
        original = (self.downloaded / name).read_bytes()
        (self.downloaded / name).write_bytes(b"!" + original[1:])
        write_companion(self.downloaded, name)
        with self.assertRaisesRegex(readback.intake.IntakeError, "pinned SHA256"):
            self.verify()

    def test_checksum_companion_requires_exact_digest_filename_and_lf(self):
        name = "archive-0.tar.gz"
        path = self.downloaded / f"{name}.sha256"
        original = path.read_bytes()
        for content in [original.replace(b"archive-0", b"archive-1"), original.upper(), original.replace(b"\n", b"\r\n")]:
            path.write_bytes(content)
            with self.subTest(content=content), self.assertRaisesRegex(readback.ReadbackError, "checksum companion"):
                self.verify()

    def test_release_manifest_rejects_duplicate_names_and_changed_historical_pins(self):
        original = readback.intake.read_json(self.expected / readback.RELEASE_MANIFEST)
        value = json.loads(json.dumps(original))
        value["assets"][1] = value["assets"][0]
        self.replace_json(readback.RELEASE_MANIFEST, value)
        with self.assertRaisesRegex(readback.ReadbackError, "duplicate asset names"):
            self.verify()
        value = json.loads(json.dumps(original))
        value["assets"][0]["sha256"] = "0" * 64
        self.replace_json(readback.RELEASE_MANIFEST, value)
        with self.assertRaisesRegex(readback.ReadbackError, "historical identity"):
            self.verify()

    def test_release_manifest_accepts_only_original_or_exact_organization_urls(self):
        value = readback.intake.read_json(self.expected / readback.RELEASE_MANIFEST)
        for asset in value["assets"]:
            asset["url"] = f"{readback.ORGANIZATION_BASE}/{asset['name']}"
        self.replace_json(readback.RELEASE_MANIFEST, value)
        self.verify()
        value["assets"][0]["url"] += "?sig=DO_NOT_PRINT"
        self.replace_json(readback.RELEASE_MANIFEST, value)
        with self.assertRaises(readback.ReadbackError) as caught:
            self.verify()
        self.assertNotIn("DO_NOT_PRINT", str(caught.exception))

    def test_changed_intake_manifest_cannot_replace_the_local_public_trust_anchor(self):
        value = readback.intake.read_json(self.expected / readback.INTAKE_MANIFEST)
        value["publication_status"] = "different bytes"
        self.replace_json(readback.INTAKE_MANIFEST, value)
        with self.assertRaisesRegex(readback.intake.IntakeError, "pinned"):
            self.verify()

    def test_duplicate_json_keys_in_release_manifest_are_rejected(self):
        for directory in (self.expected, self.downloaded):
            path = directory / readback.RELEASE_MANIFEST
            path.write_text('{"schema_version":1,"schema_version":1,"assets":[]}', encoding="utf-8")
            write_companion(directory, path.name)
        with self.assertRaisesRegex(readback.intake.IntakeError, "duplicate object key"):
            self.verify()

    def rewrite_metadata(self, transform) -> None:
        path = self.expected / readback.METADATA_ARCHIVE
        with tarfile.open(path, "w:gz", format=tarfile.PAX_FORMAT) as archive:
            for name in self.metadata_files:
                content = (self.root / name).read_bytes()
                member = tarfile.TarInfo(name)
                member.size = len(content)
                member.mode = 0o644
                member.mtime = member.uid = member.gid = 0
                member.uname = member.gname = ""
                content = transform(member, content)
                archive.addfile(member, io.BytesIO(content))
        write_companion(self.expected, path.name)
        for name in (path.name, f"{path.name}.sha256"):
            shutil.copyfile(self.expected / name, self.downloaded / name)

    def test_self_consistent_metadata_archive_still_requires_original_public_bytes(self):
        def corrupt(member, content):
            return b"!" + content[1:] if member.name == "LICENSE" else content
        self.rewrite_metadata(corrupt)
        with self.assertRaisesRegex(readback.ReadbackError, "public pinned bytes"):
            self.verify()

    def test_metadata_archive_cannot_smuggle_links_or_traversal_members(self):
        def link(member, content):
            if member.name == "LICENSE":
                member.type = tarfile.SYMTYPE
                member.linkname = "../../outside"
                member.size = 0
                return b""
            return content
        self.rewrite_metadata(link)
        with self.assertRaisesRegex(readback.ReadbackError, "ordinary regular"):
            self.verify()
        def traversal(member, content):
            if member.name == "LICENSE":
                member.name = "../outside"
            return content
        self.rewrite_metadata(traversal)
        with self.assertRaisesRegex(readback.intake.IntakeError, "stay inside"):
            self.verify()

    def test_ancillary_download_corruption_is_rejected_even_with_matching_companion(self):
        name = readback.METADATA_ARCHIVE
        content = (self.downloaded / name).read_bytes()
        (self.downloaded / name).write_bytes(content[:-1] + bytes([content[-1] ^ 1]))
        write_companion(self.downloaded, name)
        with self.assertRaisesRegex(readback.intake.IntakeError, "pinned SHA256"):
            self.verify()

    def test_symlink_download_is_rejected(self):
        path = self.downloaded / "archive-0.tar.gz"
        path.unlink()
        try:
            path.symlink_to(self.expected / path.name)
        except OSError:
            self.skipTest("host does not permit unprivileged symlinks")
        with self.assertRaisesRegex(readback.intake.IntakeError, "filesystem links"):
            self.verify()


if __name__ == "__main__":
    unittest.main()
