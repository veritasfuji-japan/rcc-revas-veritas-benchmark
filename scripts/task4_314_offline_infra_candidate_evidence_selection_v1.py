#!/usr/bin/env python3
"""#314: offline infrastructure comparison, NEVER a production attestation."""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATH = "contracts/TASK4_314_OFFLINE_INFRA_CANDIDATE_EVIDENCE_SELECTION_V1.json"
PARENT_PATH = "contracts/TASK4_313_EXTERNAL_CONTROL_READINESS_PREFLIGHT_V1.json"
PARENT = "221ca18c00effdacbfd8d6d4d74aa181860ae857"
RULE = "TASK4_314_CANDIDATE_COMPARISON_IS_NEVER_PRODUCTION_AUTHORIZATION_V1"
SCHEMA = "veritas.task4.offline-infrastructure-candidate-evidence-selection.v1"
PINS = {
    "contracts/TASK4_313_EXTERNAL_CONTROL_READINESS_PREFLIGHT_V1.json": "5fa051c5ac50429394958c8cd2231c8fc20e76d6",
    "scripts/task4_313_external_control_readiness_preflight_v1.py": "8f935dff2d2590826fd839a6630d8f804e96a0ee",
    "tests/test_task4_313_external_control_readiness_preflight_v1.py": "c6f0c989bbde73e86c1a9bb236ed6169f48d7625",
    ".github/workflows/task4-313-external-control-readiness-preflight-v1.yml": "2da09fa18be4ce63511d7c2f706951e070e6e194",
    "docs/TASK4_313_EXTERNAL_CONTROL_READINESS_PREFLIGHT_V1.md": "3f430d2c10cd4e234a6e176bd6750e2ab0b2ec7c",
}
CANDIDATES = {
    "LOCAL_OFFLINE_FIXTURE": "OFFLINE_TESTS_ONLY",
    "GITHUB_ENV_ONLY": "NOT_A_SUFFICIENT_PRODUCTION_BOUNDARY",
    "GCP_MANAGED_SEPARATION": "CANDIDATE_REQUIRES_EXTERNAL_ATTESTATION_AND_BILLING",
    "AWS_MANAGED_SEPARATION": "CANDIDATE_REQUIRES_EXTERNAL_ATTESTATION_AND_BILLING",
}
ROLES = frozenset("""
human_approver security_issuer_admin ledger_data_admin secrets_admin
network_admin sender_release_admin billing_admin external_audit_admin
""".split())
GATE_OWNER = {
    "NEW_HUMAN_SCOPED_APPROVAL": "human_approver",
    "ISSUER_WORKLOAD_IDENTITY": "security_issuer_admin",
    "PROTECTED_LEDGER_CAS": "ledger_data_admin",
    "DB_ADMIN_BREAKGLASS_RECONCILIATION": "external_audit_admin",
    "EPHEMERAL_PROVIDER_SECRET_BROKER": "secrets_admin",
    "NETWORK_EGRESS_ENFORCEMENT": "network_admin",
    "PROTECTED_SENDER_CODE_INTEGRITY": "sender_release_admin",
    "FRESH_ACCOUNT_BILLING_ENFORCEMENT": "billing_admin",
    "EXACT_REQUEST_ISSUER_TIME_AND_PRESTATE": "security_issuer_admin",
    "COMMITTED_RECEIPT_BEFORE_SEND": "sender_release_admin",
    "UNKNOWN_REMOTE_STATE_NEVER_RETRY": "sender_release_admin",
    "INDEPENDENT_AUDIT_AND_NO_REISSUE": "external_audit_admin",
}
SENSITIVE_ENV = (
    "OPENAI_API_KEY", "TASK4_OPENAI_API_KEY", "ANTHROPIC_API_KEY",
    "OPENAI_BASE_URL", "VERITAS_DATABASE_URL",
    "TASK4_THIRD_APPROVAL_PHRASE", "TASK4_313_APPROVAL_PHRASE",
    "TASK4_314_APPROVAL_PHRASE",
)
CANDIDATE_KEYS = frozenset("""
id label components fit status cost_quote_usd_month actual_cost_verified
external_admin_verified tenant_identity_verified physical_egress_denial_verified
db_superuser_bypass_closed secret_scope_verified independent_audit_verified
provider_billing_cap_verified approved_to_provision approved_to_send documentation_source
""".split())
ROOT_KEYS = frozenset("""
schema rule_of_one parent_merged_main parent_git_blobs previous_real_provider_consent
current_budget_approval cost_and_pricing_validation objective candidates
owner_roles gate_plan selected_candidate external_attestations_count
independent_administrator_established cloud_config_inspected
network_egress_verified db_breakglass_risk_closed budget_hard_stop_verified
cloud_resources_provisioned provider_calls bank_effects official_final128_scores
real_provider_grants_issued decision next_gate
""".split())
FALSE_CANDIDATE_FIELDS = frozenset("""
actual_cost_verified external_admin_verified tenant_identity_verified
physical_egress_denial_verified db_superuser_bypass_closed secret_scope_verified
independent_audit_verified provider_billing_cap_verified approved_to_provision
approved_to_send
""".split())
FALSE_ROOT_FIELDS = frozenset("""
independent_administrator_established cloud_config_inspected
network_egress_verified db_breakglass_risk_closed budget_hard_stop_verified
""".split())
ZERO_ROOT_FIELDS = frozenset("""
external_attestations_count cloud_resources_provisioned provider_calls bank_effects
official_final128_scores real_provider_grants_issued
""".split())

class OfflineDenied(ValueError):
    pass

def need(ok, code):
    if not ok:
        raise OfflineDenied(code)

def canon(obj):
    return json.dumps(obj, sort_keys=True, ensure_ascii=False,
                      allow_nan=False, separators=(",", ":")).encode("utf-8")

def git_blob(content):
    return hashlib.sha1(b"blob " + str(len(content)).encode("ascii")
                        + b"\0" + content).hexdigest()

def load(root=ROOT):
    base = Path(root).resolve()
    path = (base / PATH).resolve()
    need(path.is_relative_to(base), "CONTRACT_LOCATION_INVALID")
    return json.loads(path.read_bytes())

def verify_parent(root=ROOT):
    base = Path(root).resolve()
    for path, expected in PINS.items():
        file = (base / path).resolve()
        need(file.is_relative_to(base), "PARENT_SOURCE_LOCATION_INVALID")
        need(git_blob(file.read_bytes()) == expected,
             "PINNED_313_SOURCE_CHANGED_" + file.name)
    parent = json.loads((base / PARENT_PATH).read_bytes())
    need(parent["parent_merged_main"] ==
         "a04ed01396e8d7a35ef82f437db1a93e28bd4762",
         "PARENT_313_BASE_DRIFT")
    need(parent["current_budget_approval"] == "NONE"
         and parent["selected_candidate"] is None
         if "current_budget_approval" in parent else
         parent["infrastructure_selection"] == "UNDECIDED_OWNER_ACTION_REQUIRED",
         "PARENT_313_NOT_OFFLINE")
    need({g["id"] for g in parent["pre_send_controls"]} == set(GATE_OWNER),
         "PARENT_313_EXTERNAL_GATE_DRIFT")
    return PINS

def check(model):
    need(type(model) is dict and set(model) == ROOT_KEYS,
         "MODEL_EXTRA_OR_MISSING_FIELDS")
    need(model["schema"] == SCHEMA and model["rule_of_one"] == RULE
         and model["parent_merged_main"] == PARENT
         and model["parent_git_blobs"] == PINS
         and model["previous_real_provider_consent"] == "CONSUMED_DO_NOT_REUSE",
         "PARENT_PIN_OR_CONSENT_INVALID")
    need(model["current_budget_approval"] == "NONE"
         and model["cost_and_pricing_validation"] == "NO_LIVE_QUOTES_VERIFIED"
         and model["selected_candidate"] is None
         and model["next_gate"] ==
             "OWNER_SELECTION_AND_INDEPENDENT_ADMIN_BUDGET_BEFORE_ANY_PROVISIONING",
         "UNAUTHORIZED_COST_OR_INFRA_SELECTION")
    need(type(model["objective"]) is str and len(model["objective"]) > 24,
         "MISSING_COMPARISON_OBJECTIVE")
    choices = model["candidates"]
    need(type(choices) is list and len(choices) == len(CANDIDATES)
         and all(type(c) is dict and set(c) == CANDIDATE_KEYS for c in choices)
         and {c["id"] for c in choices} == set(CANDIDATES),
         "CANDIDATE_MATRIX_MISSING_OR_MODIFIED")
    for c in choices:
        need(c["fit"] == CANDIDATES[c["id"]]
             and c["status"] == "RESEARCH_ONLY_NON_DEPLOYED"
             and c["cost_quote_usd_month"] is None
             and all(c[k] is False for k in FALSE_CANDIDATE_FIELDS)
             and all(type(c[k]) is str and len(c[k]) >= 8 for k in
                     ("label", "components", "documentation_source"))
             and c["documentation_source"].startswith("https://"),
             "CANDIDATE_FALSE_PRODUCTION_OR_COST_CLAIM")
    roles = model["owner_roles"]
    need(type(roles) is list and len(roles) == len(ROLES)
         and all(type(r) is dict and set(r) == {
             "id", "assigned_independent_person", "admin_tenancy",
             "verified_separation"} for r in roles)
         and {r["id"] for r in roles} == ROLES,
         "ROLE_ACCOUNTABILITY_TOPOLOGY_MISSING")
    for r in roles:
        need(r["assigned_independent_person"] is None
             and r["admin_tenancy"] is None
             and r["verified_separation"] is False,
             "SINGLE_OPERATOR_OR_SELF_DECLARED_INDEPENDENCE")
    gates = model["gate_plan"]
    need(type(gates) is list and len(gates) == len(GATE_OWNER)
         and all(type(g) is dict and set(g) == {
             "id", "required_owner_role", "independent_proof_needed", "status",
             "evidence"} for g in gates)
         and {g["id"] for g in gates} == set(GATE_OWNER),
         "EXTERNAL_EVIDENCE_PLAN_INCOMPLETE")
    for g in gates:
        need(g["required_owner_role"] == GATE_OWNER[g["id"]]
             and type(g["independent_proof_needed"]) is str
             and len(g["independent_proof_needed"]) > 25
             and g["status"] == "NOT_ATTESTED" and g["evidence"] is None,
             "FAKE_EXTERNAL_EVIDENCE_OR_OWNER")
    need(all(model[k] is False for k in FALSE_ROOT_FIELDS),
         "EXTERNAL_SECURITY_NOT_INSPECTED")
    need(all(type(model[k]) is int and model[k] == 0
             for k in ZERO_ROOT_FIELDS),
         "NO_BILLING_PROVISIONING_OR_PROVIDER_EFFECT")
    need(model["decision"] == "DENY",
         "NEVER_AUTHORIZE_PROVIDER_WITH_COMPARISON")
    return True

def audit(*, root=ROOT, override=None, untrusted_claim=None):
    need(not any(os.environ.get(name) for name in SENSITIVE_ENV),
         "NO_LIVE_CREDENTIAL_OR_APPROVAL_CONTEXT")
    model = deepcopy(override) if override is not None else load(root)
    check(model)
    verify_parent(root)
    report = {
        "rule_of_one": RULE,
        "parent_main": PARENT,
        "parent_source_pins": PINS,
        "candidate_ids": sorted(CANDIDATES),
        "candidate_count": len(CANDIDATES),
        "independent_owner_roles_unassigned": len(ROLES),
        "external_gates_unattested": len(GATE_OWNER),
        "cost_quotes_verified": 0,
        "production_selection": None,
        "privileged_admin_bypass_unresolved": True,
        "live_provider_calls": 0,
        "cloud_resources_created": 0,
        "new_human_authorizations": 0,
        "official_final128_scores": 0,
        "untrusted_claims_used_as_evidence": False,
        "scope": "OFFLINE_RESEARCH_NOT_SECURITY_ATTESTATION",
        "readiness": "BLOCKED_NO_OWNER_INFRA_OR_EXTERNAL_PROOF",
        "final_live_decision": "DENY",
        "contract_sha256": hashlib.sha256(canon(model)).hexdigest(),
    }
    report["report_sha256"] = hashlib.sha256(canon(report)).hexdigest()
    return report

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    opts = parser.parse_args()
    path = opts.output.resolve()
    need(path.is_relative_to(ROOT), "OUTPUT_OUTSIDE_REPO")
    report = audit()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n",
                    encoding="utf-8")
    print("TASK4_314_OFFLINE_MATRIX_PASS_FOUR_OPTIONS_TWELVE_GATES_DENY")

if __name__ == "__main__":
    main()
