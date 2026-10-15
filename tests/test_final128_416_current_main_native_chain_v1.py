"""#416: independent current-main source profile and fail-closed regressions."""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import scripts.final128_416_current_main_native_chain_v1 as mod

class CurrentMainProfileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.profile = json.loads(mod.PROFILE_FILE.read_text(encoding="utf-8"))
        self.baseline = json.loads(mod.FROZEN_MANIFEST.read_text(encoding="utf-8"))

    def test_independent_profile_preserves_legacy_manifest(self):
        self.assertEqual(self.profile["status"], "RUN_PENDING_NOT_PROVEN")
        self.assertEqual(self.baseline["status"], "IMPLEMENTATION_PROOF_PENDING")
        self.assertEqual(self.profile["veritas_commit"], mod.MAIN_PIN)
        self.assertEqual(self.baseline["veritas_commit"], mod.FROZEN_PIN)
        self.assertNotEqual(mod.MAIN_PIN, mod.FROZEN_PIN)
        self.assertEqual(self.profile["critical_sources"],
                         self.baseline["critical_sources"])
        self.assertFalse(self.profile["external_validation"])
        self.assertFalse(self.profile["production_authority_proven"])
        self.assertFalse(self.profile["new_official_utility_measured"])

    def test_original_sandbox_bytes_are_immutable(self):
        self.assertEqual(mod.git_blob_sha(mod.EXISTING_FIXTURE.read_bytes()),
                         "db63ea47d07f75b288fd5a64108e91a6230ce6c4")

    def test_commit_mismatch_refuses_even_if_source_hashes_match(self):
        with patch.object(mod, "git_head", return_value=mod.FROZEN_PIN):
            with self.assertRaisesRegex(ValueError, "416_OS_CHECKOUT_WRONG_COMMIT"):
                mod.verify_current_profile(mod.ROOT)

    def test_changed_manifest_is_not_accepted_as_fresh_authority(self):
        bad = deepcopy(self.profile)
        bad["production_authority_proven"] = True
        with patch.object(mod, "read_json", side_effect=[bad, self.baseline]):
            with self.assertRaisesRegex(ValueError, "416_UNBOUNDED_CLAIM"):
                mod.verify_current_profile(mod.ROOT)

    def test_wrong_os_pin_manifest_fails(self):
        bad = deepcopy(self.profile)
        bad["veritas_commit"] = mod.FROZEN_PIN
        with patch.object(mod, "read_json", side_effect=[bad, self.baseline]):
            with self.assertRaisesRegex(ValueError, "416_CROSS_PROFILE_PIN_MISMATCH"):
                mod.verify_current_profile(mod.ROOT)

    def test_overridden_core_digest_rejected_even_if_shape_valid(self):
        bad = deepcopy(self.profile)
        key = next(iter(bad["critical_sources"]))
        bad["critical_sources"][key] = "0" * 64
        with patch.object(mod, "read_json", side_effect=[bad, self.baseline]):
            with self.assertRaisesRegex(ValueError, "416_FROZEN_CORE_HASH_REWRITE"):
                mod.verify_current_profile(mod.ROOT)

    def test_runtime_file_drift_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            for key in self.profile["critical_sources"]:
                path = root / key
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("tampered\n", encoding="utf-8")
            with patch.object(mod, "git_head", return_value=mod.MAIN_PIN):
                with self.assertRaisesRegex(ValueError,
                                            "416_CURRENT_MAIN_CORE_SOURCE_DRIFT"):
                    mod.verify_current_profile(root)

    def test_no_preexisting_artifact_clobber(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            out = root / "existing"
            out.mkdir()
            with patch.object(mod, "git_head", return_value=mod.BEN_PIN):
                with self.assertRaisesRegex(ValueError, "416_OUTPUT_ALREADY_EXISTS"):
                    mod.run_current(root, root, out)


if __name__ == "__main__":
    unittest.main()
