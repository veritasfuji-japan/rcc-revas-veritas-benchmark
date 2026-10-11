#!/usr/bin/env python3
"""#313: OFFLINE-only infrastructure-selection and external-attestation preflight.

This validator does NOT inspect actual cloud/IAM, DB privilege, network, vault,
billing, or human approvals. It creates no protected resources, credentials,
grant, execution path, Provider calls, bank effects, or Final128 scores.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATH = "contracts/TASK4_313_EXTERNAL_CONTROL_READINESS_PREFLIGHT_V1.json"
SCHEMA = "veritas.task4.external-control-readiness-preflight.v1"
RULE = "TASK4_313_EXTERNAL_CONTROL_READINESS_BLOCKS_UNATTESTED_DEPLOYMENT_V1"
PARENT = "a04ed01396e8d7a35ef82f437db1a93e28bd4762"
CONSUMED_TAG_SHA = "95ff6be8c5875ed3827a00fe71fb54bd9de48130"
BLOCKED = "BLOCKED_AWAITING_OWNER_INFRA_AND_INDEPENDENT_ATTESTATION"
PINS = {
    "contracts/TASK4_PROTECTED_ISSUER_CREDENTIAL_EGRESS_ARCHITECTURE_V1.json":
        "4c7351cc04bf0356c7e1056f3cebe065ccf61329",
    "scripts/task4_protected_issuer_credential_egress_architecture_v1.py":
        "5da8d295bc851cedd36cad3fc3826bf4cd9bac15",
    "tests/test_task4_protected_issuer_credential_egress_architecture_v1.py":
        "a660de80ee621b1b5af0feb573a11b8ce33d0386",
    ".github/workflows/task4-protected-issuer-credential-egress-architecture-v1.yml":
        "9fca4aa1c18d0b8502d1133343870b756ad89114",
    "docs/TASK4_PROTECTED_ISSUER_CREDENTIAL_EGRESS_ARCHITECTURE_V1.md":
        "1063e9a1e44d6b92c33121cc635bde79fa053cac",
}
GATES = frozenset("""
NEW_HUMAN_SCOPED_APPROVAL ISSUER_WORKLOAD_IDENTITY PROTECTED_LEDGER_CAS
DB_ADMIN_BREAKGLASS_RECONCILIATION EPHEMERAL_PROVIDER_SECRET_BROKER
NETWORK_EGRESS_ENFORCEMENT PROTECTED_SENDER_CODE_INTEGRITY
FRESH_ACCOUNT_BILLING_ENFORCEMENT EXACT_REQUEST_ISSUER_TIME_AND_PRESTATE
COMMITTED_RECEIPT_BEFORE_SEND UNKNOWN_REMOTE_STATE_NEVER_RETRY
INDEPENDENT_AUDIT_AND_NO_REISSUE
""".split())
DIMENSIONS = frozenset("""
identity_provider protected_issuer_runtime independent_ledger_and_database_admin
ephemeral_secret_broker protected_sender_runtime deny_by_default_egress
out_of_band_audit_sink verified_billing_controls
""".split())
SENSITIVE_ENVS = (
    "OPENAI_API_KEY", "TASK4_OPENAI_API_KEY", "ANTHROPIC_API_KEY",
    "OPENAI_BASE_URL", "VERITAS_DATABASE_URL",
    "TASK4_THIRD_APPROVAL_PHRASE", "TASK4_312_APPROVAL_PHRASE",
    "TASK4_313_APPROVAL_PHRASE",
)
EXPECTED_FIELDS = frozenset("""
schema rule_of_one parent_merged_main parent_blobs
historical_real_provider_approval consumed_tag_target scope
infrastructure_selection administrative_separation decision_dimensions
pre_send_controls remaining_privileged_bypass external_cloud_iam_inspected
actual_vault_permissions_inspected actual_egress_enforcement_inspected
provider_billing_controls_inspected production_deployment_created
new_human_provider_authorization real_provider_posts real_bank_effects
official_final128_scores live_dispatch_decision result
""".split())

class Denied(ValueError):
    pass

def require(condition, reason):
    if not condition:
        raise Denied(reason)

def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")

def blob_sha(content):
    return hashlib.sha1(b"blob " + str(len(content)).encode("ascii")
                        + b"\0" + content).hexdigest()

def load_spec(root=ROOT):
    base = Path(root).resolve()
    path = (base / PATH).resolve()
    require(path.is_relative_to(base), "CONTRACT_PATH_ESCAPE")
    return json.loads(path.read_bytes())

def verify_parent_pins(root=ROOT):
    base = Path(root).resolve()
    found = {}
    for rel, sha in sorted(PINS.items()):
        p = (base / rel).resolve()
        require(p.is_relative_to(base), "PIN_PATH_ESCAPE")
        data = p.read_bytes()
        require(blob_sha(data) == sha, "PARENT_312_SOURCE_DRIFT_" + p.name)
        found[rel] = sha
    return found

def validate_spec(spec):
    require(type(spec) is dict and set(spec) == EXPECTED_FIELDS,
            "EXTRA_OR_MISSING_CONTRACT_FIELDS")
    require(spec["schema"] == SCHEMA and spec["rule_of_one"] == RULE
            and spec["parent_merged_main"] == PARENT
            and spec["parent_blobs"] == PINS
            and spec["consumed_tag_target"] == CONSUMED_TAG_SHA
            and spec["historical_real_provider_approval"] ==
                "CONSUMED_DO_NOT_REUSE",
            "PARENT_312_OR_CONSUMED_AUTHORIZATION_MISMATCH")
    require(spec["scope"] == "OFFLINE_NON_DEPLOYED_DECISION_PREFLIGHT_ONLY"
            and spec["infrastructure_selection"] ==
                "UNDECIDED_OWNER_ACTION_REQUIRED"
            and spec["administrative_separation"] == "NOT_ESTABLISHED"
            and spec["remaining_privileged_bypass"] ==
                "DB_BREAKGLASS_ADMIN_NOT_EXTERNALLY_CONTROLLED"
            and spec["result"] == BLOCKED,
            "OWNER_INFRA_DECISION_OR_DB_ADMIN_BYPASS_FALSIFIED")
    decisions = spec["decision_dimensions"]
    require(type(decisions) is list and len(decisions) == len(DIMENSIONS)
            and all(type(d) is dict and set(d) == {
                "id", "chosen_service", "account_or_tenant",
                "independent_control_owner", "externally_verified_evidence"
            } and type(d["id"]) is str and
                all(d[k] is None for k in (
                    "chosen_service", "account_or_tenant",
                    "independent_control_owner", "externally_verified_evidence"))
                    for d in decisions)
            and {d["id"] for d in decisions} == DIMENSIONS,
            "UNVERIFIED_INFRA_SELECTION_OR_OWNER_CLAIM")
    gates = spec["pre_send_controls"]
    require(type(gates) is list and len(gates) == len(GATES)
            and all(type(g) is dict and set(g) == {
                "id", "status", "independent_evidence_uri", "attestor_identity"
            } and type(g["id"]) is str and
                g["status"] == "NOT_ATTESTED" and
                g["independent_evidence_uri"] is None and
                g["attestor_identity"] is None for g in gates)
            and {g["id"] for g in gates} == GATES,
            "UNATTESTED_GATE_ILLEGALLY_PROMOTED_OR_OMITTED")
    for key in ("external_cloud_iam_inspected",
                "actual_vault_permissions_inspected",
                "actual_egress_enforcement_inspected",
                "provider_billing_controls_inspected",
                "production_deployment_created",
                "new_human_provider_authorization"):
        require(spec[key] is False, "FALSE_EXTERNAL_EVIDENCE_" + key)
    for key in ("real_provider_posts", "real_bank_effects",
                "official_final128_scores"):
        require(type(spec[key]) is int and spec[key] == 0,
                "LIVE_EFFECT_OR_SCORE_FALSIFIED_" + key)
    require(spec["live_dispatch_decision"] == "DENY",
            "LIVE_PROVIDER_DISPATCH_MUST_REMAIN_DENY")
    return True

def audit(*, root=ROOT, spec_override=None, untrusted_claim=None):
    require(not any(os.environ.get(name) for name in SENSITIVE_ENVS),
            "OFFLINE_PREFLIGHT_CANNOT_RUN_WITH_PROVIDER_SECRETS")
    spec = deepcopy(spec_override) if spec_override is not None else load_spec(root)
    validate_spec(spec)
    pin_evidence = verify_parent_pins(root)
    # Deliberately do not parse approval, billing, IAM, or attestation claims:
    # only the external owner can obtain and evaluate actual external proofs.
    report = {
        "rule_of_one": RULE,
        "parent_merged_main": PARENT,
        "parent_blobs": pin_evidence,
        "consumed_real_provider_approval_tag_target": CONSUMED_TAG_SHA,
        "readiness": BLOCKED,
        "selection_owner_action_required": True,
        "independent_admin_required": True,
        "unresolved_infrastructure_dimensions": sorted(DIMENSIONS),
        "unattested_external_pre_send_gates": sorted(GATES),
        "external_attestation_count": 0,
        "remaining_db_superuser_bypass": True,
        "cloud_iam_or_network_enforced": False,
        "provider_credentials_read": False,
        "new_provider_authorizations": 0,
        "real_provider_calls": 0,
        "bank_effects": 0,
        "official_final128_scores": 0,
        "forged_user_claims_used": False,
        "final_live_decision": "DENY",
        "proof_scope": "STATIC_MANIFEST_AND_PIN_AUDIT_ONLY_NOT_DEPLOYED_SECURITY",
        "contract_sha256": hashlib.sha256(canonical(spec)).hexdigest(),
    }
    report["report_sha256"] = hashlib.sha256(canonical(report)).hexdigest()
    return report

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    opts = parser.parse_args()
    output = opts.output.resolve()
    require(output.is_relative_to(ROOT), "OUTPUT_MUST_REMAIN_INSIDE_REPOSITORY")
    report = audit()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n",
                      encoding="utf-8")
    print("TASK4_313_OFFLINE_PREFLIGHT_PASS_ALL_12_EXTERNAL_GATES_NOT_ATTESTED_LIVE_DENY")

if __name__ == "__main__":
    main()
