"""#415 offline contract-level refusals for the EXISTING native-chain runner."""
from __future__ import annotations

from copy import deepcopy
import json
import tempfile
import unittest
from pathlib import Path

from scripts.final128_415_native_chain_pinned_seven_mode_v1 import (
    BEN_PIN, MODES, NEGATIVE_EVENTS, VERITAS_PIN,
    verify_case, verify_continuity, verify_fixture_files,
    digest_bytes,
)

H = "a" * 64
G = "b" * 64
D = "c" * 64


def sample_chain() -> dict:
    return {
        "original_request_digest": H,
        "candidate_hash": G,
        "request_id": "request-1",
        "decision_id": "decision-1",
        "expected_state_fingerprint": D,
        "execution_intent_id": "intent-1",
        "observations": {
            "factory_input": {"original_request_digest": H, "candidate_hash": G},
            "decide_request": {
                "original_request_digest": H, "candidate_hash": G,
            },
            "CDA": {"request_id": "request-1", "decision_id": "decision-1"},
            "promotion_packet": {
                "request_id": "request-1", "decision_id": "decision-1",
                "original_request_digest": H,
            },
            "ExecutionIntent": {
                "request_id": "request-1", "decision_id": "decision-1",
                "execution_intent_id": "intent-1",
                "expected_state_fingerprint": D,
            },
            "verified_authority": {
                "observed": True, "verification_proof_hash": H,
            },
            "BindReceipt": {
                "decision_id": "decision-1",
                "execution_intent_id": "intent-1",
                "expected_state_fingerprint": D,
            },
            "apply_count": 1,
        },
    }


def sample_report(mode: str) -> dict:
    applied = 1 if mode == "valid" else 0
    return {
        "mode": mode, "status": "PASS", "veritas_source_commit": VERITAS_PIN,
        "claim_scope": "LOCAL_ENGINEERING_ACCEPTANCE_NOT_MODEL_PERFORMANCE",
        "provider_mode": "CONTROLLED_TRANSCRIPT_AT_LLM_CLIENT_ONLY",
        "paid_provider_calls": 0, "controlled_provider_calls": 1,
        "successful_native_kernel_calls": 1,
        "production_authority_claimed": False,
        "production_WORM_claimed": False,
        "native_chain_verified": True,
        "native_outcome": "COMMITTED" if applied else "BLOCKED",
        "apply_count": applied, "final_state": {"counter": applied},
    }


class NativeSevenModeVerifierTests(unittest.TestCase):
    def test_seven_modes_are_distinct_and_pins_complete(self):
        self.assertEqual(len(MODES), 7)
        self.assertEqual(len(set(MODES)), 7)
        self.assertEqual(len(BEN_PIN), 40)
        self.assertEqual(len(VERITAS_PIN), 40)

    def test_exact_continuity_passes(self):
        self.assertEqual(verify_continuity(sample_chain())["apply_count"], 1)

    def test_original_request_substitution_denied(self):
        value = sample_chain()
        value["observations"]["promotion_packet"]["original_request_digest"] = G
        with self.assertRaisesRegex(ValueError, "ORIGINAL_REQUEST_BREAK"):
            verify_continuity(value)

    def test_candidate_substitution_denied(self):
        value = sample_chain()
        value["observations"]["decide_request"]["candidate_hash"] = D
        with self.assertRaisesRegex(ValueError, "CANDIDATE_BREAK"):
            verify_continuity(value)

    def test_request_decision_intent_and_prestate_drift_denied(self):
        for target, field, error in (
            ("CDA", "request_id", "REQUEST_ID_BREAK"),
            ("BindReceipt", "decision_id", "DECISION_ID_BREAK"),
            ("BindReceipt", "execution_intent_id", "INTENT_ID_BREAK"),
            ("BindReceipt", "expected_state_fingerprint", "PRESTATE_BREAK"),
        ):
            with self.subTest(field=field):
                value = sample_chain()
                value["observations"][target][field] = "substituted"
                with self.assertRaisesRegex(ValueError, error):
                    verify_continuity(value)

    def test_unsigned_authority_or_missing_continuity_denied(self):
        value = sample_chain()
        value["observations"]["verified_authority"]["verification_proof_hash"] = ""
        with self.assertRaisesRegex(ValueError, "VERIFIED_AUTHORITY_PROOF_MISSING"):
            verify_continuity(value)
        with self.assertRaisesRegex(ValueError, "CONTINUITY_MISSING"):
            verify_continuity({})

    def test_real_valid_mode_shape(self):
        events = {"CONTINUITY_MATRIX_VERIFIED", "NATIVE_BIND_PERSISTENCE_VERIFIED"}
        self.assertEqual(verify_case(sample_report("valid"), "valid",
                                     events, sample_chain())["native_apply_count"], 1)

    def test_negative_six_modes_zero_effect(self):
        for mode in MODES[1:]:
            events = {NEGATIVE_EVENTS[mode]} if mode in NEGATIVE_EVENTS else {
                "NATIVE_BIND_PERSISTENCE_VERIFIED",
            }
            with self.subTest(mode=mode):
                result = verify_case(sample_report(mode), mode, events, None)
                self.assertEqual(result["native_apply_count"], 0)

    def test_negative_case_rejects_extra_effect(self):
        for mode in MODES[1:]:
            with self.subTest(mode=mode):
                report = sample_report(mode)
                report["apply_count"] = 1
                with self.assertRaisesRegex(ValueError, "APPLY_COUNT_MISMATCH"):
                    verify_case(report, mode, set(), None)

    def test_rejects_provider_spend_and_production_promotions(self):
        report = sample_report("valid")
        report["paid_provider_calls"] = 1
        with self.assertRaisesRegex(ValueError, "PAID_PROVIDER_NOT_ZERO"):
            verify_case(report, "valid", set(), None)
        report = sample_report("valid")
        report["production_authority_claimed"] = True
        with self.assertRaisesRegex(ValueError, "PRODUCTION_CLAIM_INVALID"):
            verify_case(report, "valid", set(), None)

    def test_refusal_needs_observed_event_and_no_continuity(self):
        with self.assertRaisesRegex(ValueError, "EXPECTED_REFUSAL_EVIDENCE_MISSING"):
            verify_case(sample_report("candidate_substitution"),
                        "candidate_substitution", set(), None)
        with self.assertRaisesRegex(ValueError, "DENIED_CASE_HAS_COMMITTED_CONTINUITY"):
            verify_case(sample_report("candidate_substitution"),
                        "candidate_substitution", set(), sample_chain())

    def test_bounded_file_digest_enforced(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            file = root / "journal.jsonl"
            file.write_text("fixture\n", encoding="utf-8")
            report = {"files": {"journal.jsonl": digest_bytes(file.read_bytes())}}
            verify_fixture_files(root, report)
            file.write_text("drift\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "FIXTURE_FILE_DIGEST_MISMATCH"):
                verify_fixture_files(root, report)

    def test_symlink_artifact_denied(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            target = root / "target"
            target.write_text("safe", encoding="utf-8")
            link = root / "journal.jsonl"
            link.symlink_to(target)
            with self.assertRaisesRegex(ValueError, "FIXTURE_FILE_MISSING"):
                verify_fixture_files(root, {
                    "files": {"journal.jsonl": digest_bytes(target.read_bytes())},
                })


if __name__ == "__main__":
    unittest.main()
