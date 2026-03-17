import hashlib
import json
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "tests" / "fixture_manifest.json"


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            digest.update(chunk)
    return digest.hexdigest()


class FixtureManifestTest(unittest.TestCase):
    def test_manifest_files_have_expected_hash(self) -> None:
        with MANIFEST_PATH.open("r", encoding="utf-8") as f:
            manifest = json.load(f)

        files = manifest.get("files", [])
        self.assertGreater(len(files), 0, "fixture manifest is empty")

        for item in files:
            rel_path = item["path"]
            expected_sha = item["sha256"].lower()
            abs_path = ROOT / rel_path

            self.assertTrue(abs_path.exists(), f"missing fixture: {rel_path}")
            self.assertTrue(abs_path.is_file(), f"not a file: {rel_path}")
            self.assertEqual(sha256_file(abs_path), expected_sha, f"hash mismatch: {rel_path}")


if __name__ == "__main__":
    unittest.main()
