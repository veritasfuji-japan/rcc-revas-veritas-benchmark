"""#417 negative gate: two successful independent runs are not one authority chain."""
from __future__ import annotations

from copy import deepcopy
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

from scripts import final128_417_canonical_iam_join_admission_v1 as gate


class CanonicalIamJoinAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.contract = gate.read_contract()

    def test_real_reviewed_distinct_ids_are_not_admitted(self):
        source = self.contract["sources"]
        report = gate.assess(source["canonical"]["valid"],
                             source["iam"]["valid"], zip_verified=False)
        self.assertEqual(report["status"], gate.STATUS)
        self.assertIs(report["request_id_equal"], False)
        self.assertIs(report["execution_intent_id_equal"], False)
        self.assertIs(report["same_source_bound_execution_authorized"], False)
        self.assertIs(report["real_both_artifact_zip_hashes_checked_this_run"], False)
        self.assertIs(report["production_proven"], False)

    def test_forged_same_ids_still_cannot_create_authority(self):
        source = self.contract["sources"]
        upstream = source["canonical"]["valid"]
        downstream = deepcopy(source["iam"]["valid"])
        downstream["request_id"] = upstream["request_id"]
        downstream["execution_intent_id"] = upstream["execution_intent_id"]
        report = gate.assess(upstream, downstream, zip_verified=True)
        self.assertIs(report["request_id_equal"], True)
        self.assertIs(report["execution_intent_id_equal"], True)
        self.assertIs(report["same_source_bound_execution_authorized"], False)
        self.assertIs(report["native_issuer_proved_source_bound_candidate"], False)

    def test_changed_claims_cannot_promote_reviewed_contract(self):
        for mutation in ("two_separate_runs_are_one_executed_intent",
                         "source_bound_issuer_integrated", "production_authority_proven",
                         "official_final128_utility_recovered"):
            bad = deepcopy(self.contract)
            bad["nonclaims"][mutation] = True
            with tempfile.TemporaryDirectory() as folder:
                path = Path(folder) / "input.json"
                path.write_text(json.dumps(bad), encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "417_PROOF_CLAIMS_DRIFT"):
                    gate.read_contract(path)

    def test_source_pin_invalid_refused(self):
        bad = deepcopy(self.contract)
        bad["sources"]["canonical"]["zip_sha256"] = "0" * 63
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "input.json"
            path.write_text(json.dumps(bad), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "417_SOURCE_PIN_INVALID"):
                gate.read_contract(path)

    def test_required_issuer_boundary_cannot_be_reclassified_optional(self):
        bad = deepcopy(self.contract)
        bad["required_new_native_boundary"]["source_bound_authorization_at_issuance"] = False
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "input.json"
            path.write_text(json.dumps(bad), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "417_NATIVE_BRIDGE_REQUIREMENTS_DOWNGRADED"):
                gate.read_contract(path)

    def test_canonical_mode_matrix_cannot_hide_denial_effect(self):
        source = self.contract["sources"]["canonical"]
        rows = []
        for mode in sorted(gate.REQUIRED_MODES):
            valid = mode == "valid"
            rows.append(dict(mode=mode, outcome="COMMITTED" if valid else "BLOCKED",
                             native_apply_count=1 if valid else 0,
                             native_lineage=deepcopy(source["valid"]) if valid else None))
        report = dict(
            schema="veritas.final128-416.current-os-main-native-chain-seven-mode.v1",
            status="CURRENT_OS_MAIN_COMMIT_416_PINNED_LOCAL_CHAIN_REPLAY_NOT_PRODUCTION",
            rcc_tested_checkout_sha=source["source_head"],
            veritas_tested_current_main_commit=source["reviewed_os_commit"],
            ben_upstream_pin=source["ben_upstream"],
            positive_mock_commits=1, negative_cases=6, negative_additional_effects=0,
            production_or_customer_effects=0, real_provider_calls=0,
            official_agentdojo_scorer_calls=0, new_official_utility_recovery=False,
            independent_validation=False, cases=rows)
        self.assertEqual(gate.check_canonical(report, self.contract),
                         source["valid"])
        bad = deepcopy(report)
        bad["cases"][0]["native_apply_count"] = 1  # Some negative mode after sorting
        with self.assertRaisesRegex(ValueError, "417_CANONICAL_CASE_OUTCOME_INVALID"):
            gate.check_canonical(bad, self.contract)
        bad = deepcopy(report)
        bad["cases"][0]["mode"] = "unknown"
        with self.assertRaisesRegex(ValueError, "417_CANONICAL_SEVEN_MODE_MATRIX_MISSING"):
            gate.check_canonical(bad, self.contract)

    def test_iam_reconciliation_exact_native_lineage_or_refuse(self):
        spec = self.contract["sources"]["iam"]
        data = spec["valid"]
        issuer = {key: val for key, val in data.items() if key != "challenge_sha256"}
        issuer.update(native_signed_human_approval_verified=True,
                      native_authorization_consumed=True, native_store_durable=True,
                      external_iam_provider_called=False, production_claim=False)
        rec = dict(effect_state_before="EFFECT_UNKNOWN",
                   effect_state_after="CONFIRMED_EFFECT",
                   operation_id=issuer["consumption_id"],
                   freshness_challenge_digest=data["challenge_sha256"],
                   target_ack_signature_verified=True,
                   durable_challenge_consumed_with_effect=True,
                   target_post_retried=False, permit_reissued=False,
                   production_claim=False)
        post = dict(native_postgres_consumption_rows=1, target_grants=1,
                    real_mtls_allowed_exactly_once=True, mutation_retried=False,
                    native_permit_reissued=False, production_claim=False,
                    source_sha=spec["tested_workflow_merge_sha"],
                    expected_sha=spec["tested_workflow_merge_sha"])
        registered = dict(state="ISSUED", challenge_sha256=data["challenge_sha256"])
        consumed = dict(state="CONSUMED", challenge_sha256=data["challenge_sha256"])
        records = {
            "native_issuer_receipt.json": issuer,
            "iam_reconciliation_reconcile.json": rec,
            "verification_post_native.json": post,
            "iam_challenge_registered.json": registered,
            "iam_challenge_consumed.json": consumed,
        }
        self.assertEqual(gate.check_iam(records, self.contract), issuer)
        for key, value, refused in (
            ("native_issuer_receipt.json", "request_id", "IAM_ORIGINAL_LINEAGE_CHANGED"),
            ("iam_reconciliation_reconcile.json", "effect_state_after", "IAM_RECONCILIATION_CLAIM_DRIFT"),
            ("verification_post_native.json", "target_grants", "IAM_EFFECT_OR_PIN_DRIFT"),
            ("iam_challenge_consumed.json", "state", "IAM_CHALLENGE_NOT_CONSUMED"),
        ):
            bad = deepcopy(records)
            bad[key][value] = "tampered"
            with self.subTest(key=key, value=value):
                with self.assertRaisesRegex(ValueError, "417_" + refused):
                    gate.check_iam(bad, self.contract)
        bad = deepcopy(records)
        bad["native_issuer_receipt.json"]["source_bound_canonical_receipt"] = {"claimed": True}
        with self.assertRaisesRegex(ValueError, "417_IAM_SOURCE_BINDING_UNREVIEWED"):
            gate.check_iam(bad, self.contract)

    def test_sha256sum_dot_slash_manifest_matches_safe_zip_member(self):
        """Real #2382 manifests list ./name while ZIP stores bare name."""
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "native-iam.zip"
            evidence = b'{"phase":"signed-target","result":"PASS"}'
            signature = hashlib.sha256(evidence).hexdigest()
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("receipt.json", evidence)
                archive.writestr("manifest.sha256",
                                 signature + "  ./receipt.json\\n")
            self.assertEqual(gate.read_artifact(
                path, hashlib.sha256(path.read_bytes()).hexdigest()),
                {"receipt.json": {"phase": "signed-target", "result": "PASS"}})

            # Different spellings of one member may not be counted twice.
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("receipt.json", evidence)
                archive.writestr("manifest.sha256",
                                 signature + "  receipt.json\\n" +
                                 signature + "  ./receipt.json\\n")
            with self.assertRaisesRegex(ValueError, "417_MANIFEST_MEMBER_INVALID"):
                gate.read_artifact(path, hashlib.sha256(path.read_bytes()).hexdigest())

            # Never use the legit sha256sum prefix to tolerate traversal.
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("receipt.json", evidence)
                archive.writestr("manifest.sha256",
                                 signature + "  ./../receipt.json\\n")
            with self.assertRaisesRegex(ValueError, "417_MANIFEST_MEMBER_INVALID"):
                gate.read_artifact(path, hashlib.sha256(path.read_bytes()).hexdigest())

    def test_zip_digest_is_required_before_manifest_can_be_read(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "proof.zip"
            with zipfile.ZipFile(path, "w") as archive:
                report = b'{"result":"PASS"}'
                archive.writestr("report.json", report)
                archive.writestr("manifest.sha256",
                                 hashlib.sha256(report).hexdigest() + "  report.json\n")
            expected = hashlib.sha256(path.read_bytes()).hexdigest()
            self.assertEqual(gate.read_artifact(path, expected)["report.json"],
                             {"result": "PASS"})
            with self.assertRaisesRegex(ValueError, "417_ARTIFACT_ZIP_SHA_MISMATCH"):
                gate.read_artifact(path, "0" * 64)
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("report.json", b'{"result":"PASS"}')
                archive.writestr("manifest.sha256", "0" * 64 + "  report.json\n")
            with self.assertRaisesRegex(ValueError, "417_MANIFEST_MEMBER_HASH_DRIFT"):
                gate.read_artifact(path, hashlib.sha256(path.read_bytes()).hexdigest())


if __name__ == "__main__":
    unittest.main()
