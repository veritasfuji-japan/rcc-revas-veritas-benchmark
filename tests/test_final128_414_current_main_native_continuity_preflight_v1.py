"""#414: source freeze fails closed; does not claim executable native Bind proof."""
import json
import tempfile
import unittest
from pathlib import Path

from scripts.final128_414_current_main_native_continuity_preflight_v1 import (
    ROOT, FILES, FROZEN_BLOBS, inspect, git_blob_sha,
)

class PreflightTests(unittest.TestCase):
    def build(self, root):
        for rel in FILES:
            src = ROOT / rel
            dst = root / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_bytes(src.read_bytes())

    def test_frozen_source_inputs_verified_not_promoted(self):
        result = inspect()
        self.assertEqual(result["status"], "PINNED_SOURCE_PREFLIGHT_ONLY_NOT_NATIVE_PROOF")
        self.assertFalse(result["latest_veritas_main_validated"])
        self.assertFalse(result["native_bind_continuity_proven"])
        self.assertFalse(result["new_official_utility_measurement"])
        self.assertEqual(len(result["source_files"]), len(FILES))
        for entry in result["source_files"]:
            self.assertEqual(len(entry["sha256"]), 64)
            self.assertEqual(entry["git_blob_sha1"], FROZEN_BLOBS[entry["path"]])

    def test_missing_file_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            self.build(root)
            (root / FILES[0]).unlink()
            with self.assertRaises(FileNotFoundError):
                inspect(root)

    def test_invalid_json_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            self.build(root)
            (root / FILES[1]).write_text("{", encoding="utf-8")
            with self.assertRaises(json.JSONDecodeError):
                inspect(root)

    def test_symlink_escape_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d) / "root"
            root.mkdir()
            self.build(root)
            outside = Path(d) / "outside.json"
            outside.write_bytes((root / FILES[0]).read_bytes())
            (root / FILES[0]).unlink()
            (root / FILES[0]).symlink_to(outside)
            with self.assertRaises(ValueError):
                inspect(root)

    def test_valid_json_mutation_refused_even_when_parseable(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            self.build(root)
            path = root / FILES[0]
            obj = json.loads(path.read_text(encoding="utf-8"))
            obj["invariant"] = "adversarial changed invariant"
            path.write_text(json.dumps(obj), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "explicit re-pin required"):
                inspect(root)

    def test_python_harness_mutation_refused(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            self.build(root)
            path = root / "integration/current_veritas_uninterrupted/sandbox.py"
            path.write_bytes(path.read_bytes() + b"\n# malicious drift\n")
            with self.assertRaisesRegex(ValueError, "explicit re-pin required"):
                inspect(root)

    def test_git_blob_identity_is_content_bound(self):
        raw = b"fixture"
        self.assertNotEqual(git_blob_sha(raw), git_blob_sha(raw + b"!"))

if __name__ == "__main__":
    unittest.main()
