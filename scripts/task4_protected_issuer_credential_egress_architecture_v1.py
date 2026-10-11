#!/usr/bin/env python3
"""Task4 #312: OFFLINE-only protected issuer/credential/egress design audit.

This audits a NON-DEPLOYED, declared capability graph and exact-parent sources.
It does not read GitHub org/IAM settings, cloud infrastructure, real DB grants,
protected environments, egress configuration, live billing or Provider keys.
It has NO live sender/approval/secret broker, no network calls and no bank effect.
A passing graph is a design PROPERTY only, never evidence of deployed control.
"""
from __future__ import annotations

import argparse
from collections import deque
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import re

ROOT=Path(__file__).resolve().parents[1]
RULE="TASK4_PROTECTED_ISSUER_CREDENTIAL_EGRESS_REFERENCE_ARCHITECTURE_V1"
PARENT_MAIN="333e1b4d5e2a1b1bf5fb1d8717bea2d3599532f4"
SCHEMA="veritas.task4.protected-issuer-credential-egress-architecture.v1"
PATH="contracts/TASK4_PROTECTED_ISSUER_CREDENTIAL_EGRESS_ARCHITECTURE_V1.json"
CONSUMED_TAG_SHA="95ff6be8c5875ed3827a00fe71fb54bd9de48130"
BLOCKED="BLOCKED_NOT_ATTESTED_NO_REAL_PROVIDER_DISPATCH"
EXPECTED_NODES=frozenset("""
agent pr_runner regular_ci repo_writer public_submitter read_only_repo
mock_executor human_approver issuer_svc grant_ledger receipt_verifier
protected_sender provider_vault egress_proxy provider_api policy_control
external_billing_control audit_store db_breakglass_admin
""".split())
UNTRUSTED=frozenset("agent pr_runner regular_ci repo_writer public_submitter".split())
PROTECTED=frozenset("""
issuer_svc grant_ledger receipt_verifier protected_sender provider_vault
egress_proxy provider_api policy_control external_billing_control
audit_store db_breakglass_admin
""".split())
EXPECTED_EDGES=frozenset((
    ("agent","mock_executor","invoke_mock_only"),
    ("pr_runner","mock_executor","invoke_mock_only"),
    ("regular_ci","mock_executor","invoke_mock_only"),
    ("repo_writer","read_only_repo","propose_public_diff"),
    ("public_submitter","read_only_repo","propose_public_diff"),
    ("mock_executor","read_only_repo","read_public"),
    ("human_approver","issuer_svc","approve_fresh_out_of_band"),
    ("issuer_svc","grant_ledger","issue_scoped_grant"),
    ("issuer_svc","audit_store","append_attestation"),
    ("protected_sender","grant_ledger","consume_once"),
    ("protected_sender","receipt_verifier","verify_committed"),
    ("receipt_verifier","grant_ledger","read_exact_receipt"),
    ("protected_sender","provider_vault","exchange_ephemeral_token"),
    ("protected_sender","egress_proxy","submit_scoped_request"),
    ("egress_proxy","provider_api","allowlisted_provider_post"),
    ("protected_sender","audit_store","append_event"),
    ("policy_control","protected_sender","authorize_control_policy"),
    ("external_billing_control","egress_proxy","bound_actual_spend"),
    ("db_breakglass_admin","grant_ledger",
     "admin_maintenance_requires_out_of_band_audit"),
))
EXPECTED_PINS={
    "sql/task4_310_offline_postgres_consume_v1.sql":
      "0b891930f50fc17747a9854666450c9438ef7945",
    "scripts/task4_310_postgres_single_use_ci.py":
      "8e9dad92aa2b548f525b81c8fe8cc281cf97fe70",
    "sql/task4_311_committed_receipt_handoff_ci_v1.sql":
      "db93a03db99c3f714e648a03cb31a8a6c27b3884",
    "scripts/task4_311_committed_receipt_handoff_ci.py":
      "65680beb063c095b5f6d59fb2415071db05a7c8d",
    ".github/workflows/task4-committed-receipt-handoff-ci-v1.yml":
      "fe293e0f7cf7bb05bac76e8e5b73fe49539012dc",
}
REQUIRED_PRE_SEND=frozenset("""
NEW_HUMAN_SCOPED_APPROVAL ISSUER_WORKLOAD_IDENTITY PROTECTED_LEDGER_CAS
DB_ADMIN_BREAKGLASS_RECONCILIATION EPHEMERAL_PROVIDER_SECRET_BROKER
NETWORK_EGRESS_ENFORCEMENT PROTECTED_SENDER_CODE_INTEGRITY
FRESH_ACCOUNT_BILLING_ENFORCEMENT EXACT_REQUEST_ISSUER_TIME_AND_PRESTATE
COMMITTED_RECEIPT_BEFORE_SEND UNKNOWN_REMOTE_STATE_NEVER_RETRY
INDEPENDENT_AUDIT_AND_NO_REISSUE
""".split())
REQUIRED_POST_SEND=frozenset("""
PROVIDER_ORIGIN_REQUEST_RESPONSE_AND_USAGE_RECEIPT
NATIVE_RCC_VERITAS_BIND_REAL_EFFECT_COVERAGE
HELDOUT_INDEPENDENT_UTILITY_ATTACK_SCORER
""".split())
SENSITIVE_ENVS=(
    "OPENAI_API_KEY","TASK4_OPENAI_API_KEY","ANTHROPIC_API_KEY",
    "OPENAI_BASE_URL","VERITAS_DATABASE_URL","TASK4_THIRD_APPROVAL_PHRASE",
    "TASK4_307_APPROVAL_PHRASE","TASK4_308_APPROVAL_PHRASE",
    "TASK4_309_APPROVAL_PHRASE","TASK4_310_APPROVAL_PHRASE",
    "TASK4_311_APPROVAL_PHRASE","TASK4_312_APPROVAL_PHRASE",
)

class AuditDenied(ValueError):pass

def need(condition, message):
    if not condition:raise AuditDenied(message)

def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(",",":"),
                      ensure_ascii=False,allow_nan=False).encode("utf8")

def git_blob_sha1(content):
    return hashlib.sha1(
        b"blob "+str(len(content)).encode("ascii")+b"\0"+content
    ).hexdigest()

def load_contract(base=ROOT):
    root=Path(base).resolve()
    path=(root/PATH).resolve()
    need(path.is_relative_to(root),"CONTRACT_LOCATION_NOT_IN_REPOSITORY")
    contract=json.loads(path.read_bytes())
    need(type(contract) is dict,"CONTRACT_OBJECT_REQUIRED")
    return contract

def source_pins(base=ROOT):
    root=Path(base).resolve()
    answer={}
    for relative, expected in EXPECTED_PINS.items():
        path=(root/relative).resolve()
        need(path.is_relative_to(root),"FROZEN_SOURCE_PATH_OUTSIDE_REPOSITORY")
        data=path.read_bytes()
        need(git_blob_sha1(data)==expected,
             "FROZEN_PARENT_GIT_BLOB_DRIFT_"+Path(relative).name.upper())
        answer[relative]={
           "git_blob_sha1":expected,
           "content_sha256":hashlib.sha256(data).hexdigest(),
           "proof_scope":"SOURCE_PIN_ONLY_NOT_PRODUCTION_IDENTITY",
        }
    return answer

def reachable(graph, start):
    adjacent={}
    for source,dest,_action in graph:
        adjacent.setdefault(source,set()).add(dest)
    seen={start}
    steps=deque([start])
    while steps:
        node=steps.popleft()
        for nxt in adjacent.get(node,()):
            if nxt not in seen:
                seen.add(nxt)
                steps.append(nxt)
    return seen

def check_reference_policy(contract):
    """Model-check ONLY the declared reference edges, not real IAM/firewalls."""
    need(type(contract) is dict,"REFERENCE_CONTRACT_DICT_REQUIRED")
    need(contract.get("schema")==SCHEMA and
         contract.get("rule_of_one")==RULE and
         contract.get("previous_merged_main")==PARENT_MAIN and
         contract.get("previous_real_provider_approval_consumed_sha")==
           CONSUMED_TAG_SHA,"EXACT_PREDICATE_BASELINE_NOT_MATCHED")
    need(contract.get("runtime_permission_model")=="NON_DEPLOYED_REFERENCE_GRAPH_ONLY"
         and contract.get("external_live_evidence_status")==
             "ALL_UNATTESTED_BY_THIS_PR" and
         contract.get("live_dispatch_decision")=="DENY" and
         contract.get("new_human_approval_issued") is False and
         contract.get("real_provider_posts")==0 and
         contract.get("real_bank_effects")==0 and
         contract.get("actual_native_bind_calls")==0 and
         contract.get("official_final128_scores")==0,
         "CANNOT_PROMOTE_ARCHITECTURE_TO_LIVE_AUTHORITY")
    need(contract.get("exact_parent_git_blobs")==EXPECTED_PINS,
         "FROZEN_LINEAGE_PINS_TAMPERED")
    nodes=contract.get("actor_nodes")
    need(type(nodes) is list and all(type(n) is str for n in nodes)
         and len(nodes)==len(set(nodes))
         and set(nodes)==EXPECTED_NODES,"REFERENCE_IDENTITIES_CHANGED")
    need(type(contract.get("untrusted_sources")) is list
         and set(contract["untrusted_sources"])==UNTRUSTED
         and len(contract["untrusted_sources"])==len(UNTRUSTED),
         "UNTRUSTED_ACTOR_OMITTED")
    need(type(contract.get("protected_targets")) is list
         and set(contract["protected_targets"])==PROTECTED
         and len(contract["protected_targets"])==len(PROTECTED),
         "PROTECTED_TARGET_OMITTED")
    edges=contract.get("reference_edges")
    need(type(edges) is list
         and all(type(edge) is list and len(edge)==3
                 and all(type(n) is str for n in edge) for edge in edges),
         "REFERENCE_EDGES_FORMAT_INVALID")
    arcs=[tuple(edge) for edge in edges]
    need(len(arcs)==len(set(arcs))
         and all(a in EXPECTED_NODES and b in EXPECTED_NODES
                 for a,b,_ in arcs),
         "DUPLICATE_OR_UNRECOGNIZED_GRAPH_ARC")
    reachable_targets={}
    for actor in sorted(UNTRUSTED):
        compromised=sorted(reachable(arcs,actor)&PROTECTED)
        reachable_targets[actor]=compromised
    need(all(not endpoints for endpoints in reachable_targets.values()),
         "UNTRUSTED_TO_PROTECTED_PRIVILEGE_OR_EGRESS_PATH")
    # Exact allowed capabilities supplement path analysis: a reference
    # source cannot silently widen protected identities' rights.
    need(set(arcs)==EXPECTED_EDGES,"UNREVIEWED_GRAPH_CAPABILITY_EDGE")
    inv=contract.get("design_separation_invariants")
    need(type(inv) is dict
         and inv.get("untrusted_can_reach_protected_targets") is False
         and inv.get("issuer_may_read_provider_key") is False
         and inv.get("issuer_may_submit_provider_request") is False
         and inv.get("handoff_verifier_may_send") is False
         and inv.get("sender_may_issue_or_reissue_grant") is False
         and inv.get("ordinary_ci_may_assume_sender_or_issuer") is False
         and inv.get("db_admin_without_independent_controls_is_a_remaining_privileged_bypass") is True
         and inv.get("CI_grant_receipt_as_live_permission") is False
         and inv.get("human_approval_alone_as_consume_receipt") is False
         and inv.get("permitted_real_provider_posts_in_this_PR")==0,
         "REFERENCE_BOUNDARY_INVARIANT_TAMPERED")
    gates=contract.get("pre_send_evidence_requirements")
    need(type(gates) is list and len(gates)==len(REQUIRED_PRE_SEND)
         and all(type(t) is dict and type(t.get("owner")) is str
                 and type(t.get("proof")) is str
                 and len(t["owner"])>2 and len(t["proof"])>20
                 for t in gates)
         and {t.get("id") for t in gates}==REQUIRED_PRE_SEND,
         "PRODUCTION_EVIDENCE_P0_REQUIREMENT_MISSING")
    after=contract.get("after_live_evidence_requirements")
    need(type(after) is list and set(after)==REQUIRED_POST_SEND
         and len(after)==len(REQUIRED_POST_SEND),
         "POST_SEND_OBSERVATION_REQUIREMENT_MISSING")
    return {
        "node_count":len(nodes),
        "design_edge_count":len(arcs),
        "untrusted_count":len(UNTRUSTED),
        "protected_count":len(PROTECTED),
        "untrusted_to_protected_paths":reachable_targets,
        "all_untrusted_paths_excluded_in_declared_reference_graph":True,
        "pr_author_and_regular_CI_lack_live_provider_paths_in_declared_graph":True,
        "privileged_db_admin_not_externally_controlled":True,
        "actual_production_network_and_iam_not_inspected":True,
    }

def refuse_real_provider(_submitted_evidence=None):
    # True for every argument: strings, fake signatures, completed receipts,
    # cost/billing screenshots, or falsely signed human approvals.
    return {
        "decision":"DENY",
        "reason":"NO_EXTERNALLY_ATTESTED_PROTECTED_ISSUER_OR_CREDENTIAL_EGRESS_ROOT",
        "new_live_provider_posts_authorized":0,
        "db_fixture_receipt_grants_execution_authority":False,
        "credential_access_created":False,
        "provider_sender_exists_in_this_PR":False,
    }

def audit(*,base=ROOT,claim=None,contract_override=None):
    need(not any(os.environ.get(k) for k in SENSITIVE_ENVS),
         "OFFLINE_ARCHITECTURE_REFUSES_REAL_CREDENTIAL_CONTEXT")
    contract=deepcopy(contract_override) if contract_override is not None else load_contract(base)
    design=check_reference_policy(contract)
    pins=source_pins(base)
    claims_ignored=True
    report={
        "rule_of_one":RULE,
        "determination":"REFERENCE_GRAPH_SEPARATION_CHECK_PASSED_LIVE_NOT_ATTESTED",
        "readiness":BLOCKED,
        "previous_merged_main":PARENT_MAIN,
        "old_real_provider_approval_consumed_sha":CONSUMED_TAG_SHA,
        "reference_contract_sha256":hashlib.sha256(canonical(contract)).hexdigest(),
        "previous_sources":pins,
        "reference_design":design,
        "pre_send_requirements":[{
           "id":g["id"],"responsible_owner":g["owner"],
           "required_evidence":g["proof"],
           "status":"NOT_ATTESTED" # no external attestor used
        } for g in contract["pre_send_evidence_requirements"]],
        "post_send_requirements":[{
           "id":requirement,"status":"CANNOT_CHECK_BEFORE_REAL_CALL"
        } for requirement in contract["after_live_evidence_requirements"]],
        "untrusted_or_user_claims_can_issue_grant":not claims_ignored,
        "externally_verified_real_enforcements":0,
        "production_issuer_verified":False,
        "production_db_admin_bypass_blocked":False,
        "production_egress_restriction_verified":False,
        "production_secret_boundary_verified":False,
        "actual_provider_billing_cap_verified":False,
        "new_human_authorization_issued":False,
        "real_provider_calls":0,
        "native_bind_real_effects":0,
        "official_final128_scores":0,
        "final_live_decision":refuse_real_provider(claim),
        "limitations":"Every allowed privilege edge is a proposed design, not a deployed IAM permission. No GitHub environment/organization settings, cloud/firewall configuration, secret broker, trusted external ledger, billing policy, or real Provider response inspected. Privileged DB admin bypass persists until externally proved otherwise.",
    }
    report["report_sha256"]=hashlib.sha256(canonical(report)).hexdigest()
    return report

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--output",type=Path,required=True)
    opts=parser.parse_args()
    report=audit()
    opts.output.parent.mkdir(parents=True,exist_ok=True)
    opts.output.write_text(json.dumps(report,sort_keys=True,indent=2,
                                      ensure_ascii=False)+"\n",encoding="utf8")
    print("TASK4_312_DESIGN_GRAPH_AUDIT_PASS_LIVE_PROVIDER_DENY_ALL_EXTERNAL_GAPS")

if __name__=="__main__":main()
