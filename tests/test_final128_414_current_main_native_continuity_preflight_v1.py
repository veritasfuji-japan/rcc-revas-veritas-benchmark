import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from scripts.final128_414_current_main_native_continuity_preflight_v1 import FILES, inspect

class PreflightTests(unittest.TestCase):
    def build(self, root):
        for rel in FILES:
            path = root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("{}" if rel.endswith(".json") else "pass\n", encoding="utf-8")
    def test_real_repo_inputs_present_and_hashable(self):
        result = inspect()
        self.assertEqual(result["status"], "PREFLIGHT_ONLY_NOT_PROVEN")
        self.assertEqual(len(result["source_files"]), 3)
        for entry in result["source_files"]:
            self.assertEqual(len(entry["sha256"]), 64)
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
            outside.write_text("{}", encoding="utf-8")
            (root / FILES[0]).unlink()
            (root / FILES[0]).symlink_to(outside)
            with self.assertRaises(ValueError):
                inspect(root)
