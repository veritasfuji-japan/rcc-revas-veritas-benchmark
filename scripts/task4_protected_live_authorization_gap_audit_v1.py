#!/usr/bin/env python3
"""#309: proof-scoped Task4 REAL Provider readiness gap audit -- fail CLOSED.

Evidence is exact Git blobs for OFFLINE parents #303-#308 and workflow #308.
NOT evidence of protected live credentials, human approval, billing controls,
global durable grants, production time, Provider origin, or live Bind coverage.

Neither this file nor its workflow creates or exercises a Provider credential,
human approval, authorization token, payment/bank executor, or real SDK sender.
No input can change the final decision from BLOCKED. Do not treat GREEN CI
as production readiness.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
RULE = "TASK4_PROTECTED_LIVE_AUTHORIZATION_GAP_AUDIT_V1"
EXACT_PARENT_MAIN = "89cf1a35135b019b62e8f2cf8f90a50e18be3072"
PREVIOUS_REAL_APPROVAL_TAG = "refs/tags/task4-third-two-real-provider-v1-consumed"
PREVIOUS_REAL_APPROVAL_CONSUMED_SHA = "95ff6be8c5875ed3827a00fe71fb54bd9de48130"
STATUS = "BLOCKED_NOT_READY_FOR_REAL_PROVIDER_DISPATCH"

# SHA-1 here is ONLY a Git blob identity hash, NOT a security authenticator.
# Direct live authorization may NOT use this SHA-1 as an integrity root.
PINNED_BLOBS = {
    "issuer_date_profile": (
        "task4_trusted_execution_date_profile_v1.py",
        "4eb8646b18cae7130c217fa3a04d05a3d71756d3"),
    "prospective_frozen_model_wire_303": (
        "scripts/task4_prospective_model_wire_date_boundary_v1.py",
        "83ad7d3f229084633c28729d592330c477c76316"),
    "local_completion_fixture_304": (
        "scripts/task4_prospective_offline_completion_envelope_bridge_v1.py",
        "b7ca0e41125a4a137397d41f8bc2650c7e179088"),
    "native_bind_in_memory_305": (
        "scripts/task4_prospective_local_envelope_native_rcc_bind_v1.py",
        "a287ff67878f22cd552552a31c9b8451be1e5751"),
    "real_sdk_mock_transport_306": (
        "scripts/task4_future_provider_sdk_predispatch_mock_v1.py",
        "f3d2bc13a813faa405f29bd276e93b8d4458d0ec"),
    "consent_evidence_default_deny_307": (
        "scripts/task4_future_provider_consent_evidence_default_deny_v1.py",
        "d45511882e9cb9fc9f89128dee7c36dac377e672"),
    "sqlite_atomic_oneuse_local_308": (
        "scripts/task4_future_provider_atomic_oneuse_preflight_v1.py",
        "9d14cf421a2d5e33b252bc2ae45662306cc2772b"),
    "sqlite_atomic_oneuse_offline_workflow_308": (
        ".github/workflows/task4-future-provider-atomic-oneuse-preflight-v1.yml",
        "204981a0cdf4b0df997e2329c8111ad41fb8b19a"),
}

# This maps *missing independent live evidence* to auditable closure
# deliverables. Presence of an offline implementation or arbitrary claim is
# insufficient; every item is NOT_ATTESTED for the proposed future call.
REQUIRED_LIVE_EVIDENCE = (
    ("HUMAN_APPROVAL_SCOPED", "BLOCKER",
     "A new independently attributable, explicit human approval for one exact case, issuer-context, model, immutable request SHA, call limit, and monetary ceiling."),
    ("PROTECTED_GLOBAL_SINGLE_USE", "BLOCKER",
     "Independently controlled cross-run atomic consume-before-send store with immutable per-attempt identity, denial under contention, rollback and crash recovery."),
    ("CREDENTIAL_AND_EGRESS_ISOLATION", "BLOCKER",
     "Provider key isolated from PR/tests/logs and executable ONLY through the approved send boundary, with network egress enforced outside the Python process."),
    ("ACCOUNT_SPEND_ENFORCEMENT", "BLOCKER",
     "Fresh model-specific pricing and verified project/organization billing controls; historical estimated token rates do not enforce a hard billing ceiling."),
    ("PRODUCTION_ISSUER_CLOCK", "BLOCKER",
     "Production-owned non-test time authority and fresh pre-request issuance bound to exact native prestate, request and execution window."),
    ("REMOTE_UNKNOWN_NO_RETRY", "BLOCKER",
     "New live sender with disabled transport/SDK retries, consumed grant before remote POST, durable UNKNOWN terminal evidence on timeout, and no re-issuance."),
    ("PROVIDER_ORIGIN_RECEIPT", "BLOCKER",
     "Actual response provenance and request ID/usage/response hash from the intended real Provider, with independently checked response-to-request correlation."),
    ("LIVE_NATIVE_BIND_EFFECT_COVERAGE", "BLOCKER",
     "Exact same native candidate/context/prestate through real RCC + VERITAS Bind with IAM/credential/network bypass refusal and terminal reconciliation."),
    ("INDEPENDENT_UTILITY_AND_ATTACK_EVAL", "BLOCKER",
     "A separately authorized, frozen held-out native test that measures model utility and attack failure with scorer provenance; no Final128 inference from offline mocks."),
)

BLOCKED_ENV = (
    "OPENAI_API_KEY", "TASK4_OPENAI_API_KEY", "ANTHROPIC_API_KEY",
    "OPENAI_BASE_URL", "VERITAS_DATABASE_URL", "TASK4_THIRD_APPROVAL_PHRASE",
    "TASK4_307_APPROVAL_PHRASE", "TASK4_308_APPROVAL_PHRASE",
    "TASK4_309_APPROVAL_PHRASE",
)

class AuditRefused(ValueError):
    pass

def need(value, reason):
    if not value:
        raise AuditRefused(reason)

def canonical(value):
    return json.dumps(value,ensure_ascii=False,separators=(",",":"),
                      sort_keys=True,allow_nan=False).encode("utf-8")

def sha256(data):
    return hashlib.sha256(data).hexdigest()

def git_blob_sha1(data):
    return hashlib.sha1(
        f"blob {len(data)}\0".encode("ascii")+data).hexdigest()

def _source_file(base, name, path, pin, *, overrides=None):
    if overrides is not None and name in overrides:
        content=overrides[name]
        need(type(content) is bytes,"SOURCE_OVERRIDE_BYTES_REQUIRED")
    else:
        root=Path(base).resolve()
        location=(root/path).resolve()
        need(location.is_relative_to(root),"SOURCE_PATH_LEAVES_REPOSITORY")
        content=location.read_bytes()
    need(git_blob_sha1(content)==pin,"FROZEN_OFFLINE_SOURCE_BLOB_DRIFT_"+name.upper())
    return content

def verify_frozen_scope(*,base=ROOT,overrides=None):
    """Verify existing offline provenance only; never production attestations."""
    need(isinstance(base,(str,Path)),"REPOSITORY_ROOT_REQUIRED")
    result={}
    sources={}
    for key,(path,pin) in PINNED_BLOBS.items():
        data=_source_file(base,key,path,pin,overrides=overrides)
        sources[key]=data
        result[key]={"path":path,"git_blob_sha1":pin,
                     "content_sha256":sha256(data),
                     "scope":"OFFLINE_FROZEN_SOURCE_ONLY"}
    py306=sources["real_sdk_mock_transport_306"].decode("utf-8")
    py307=sources["consent_evidence_default_deny_307"].decode("utf-8")
    py308=sources["sqlite_atomic_oneuse_local_308"].decode("utf-8")
    yml=sources["sqlite_atomic_oneuse_offline_workflow_308"].decode("utf-8")
    need("httpx.MockTransport(intercept)" in py306 and
         "max_retries=0" in py306,
         "PARENT_MOCK_TRANSPORT_MUST_REMAIN_OFFLINE")
    need("def future_live_dispatch_decision(" in py307 and
         '"decision": "DENY"' in py307,
         "PARENT_DEFAULT_DENY_MUST_REMAIN")
    need("BEGIN IMMEDIATE" in py308 and
         "ALREADY_CONSUMED_ATOMIC_LOCAL_SLOT_NO_RETRY" in py308 and
         "def always_deny_real_api(" in py308,
         "PARENT_SQLITE_ATOMIC_REHEARSAL_EXPECTED")
    need("on:\n  pull_request:" in yml and
         "  push:\n" in yml and
         "permissions:\n  contents: read\n  actions: read" in yml and
         "persist-credentials: false" in yml and
         "TASK4_308_OFFLINE_PROOF:" in yml,
         "PARENT_WORKFLOW_IS_NOT_EXPECTED_OFFLINE_READONLY_SHAPE")
    need(not re.search(r"(?m)^\s*(workflow_dispatch|repository_dispatch|pull_request_target):",yml) and
         "secrets." not in yml,
         "PARENT_WORKFLOW_HAS_UNEXPECTED_DISPATCH_OR_SECRET")
    return result

def _check_no_live_credentials():
    need(not any(os.getenv(k) for k in BLOCKED_ENV),
         "LIVE_CREDENTIAL_OR_APPROVAL_PHRASE_IS_FORBIDDEN_IN_AUDIT")

def authorize_actual_provider(*_args,**_kwargs):
    """This audit CANNOT authorize anything, including forged evidence."""
    return {"decision":"DENY",
            "reason":"MISSING_INDEPENDENTLY_ATTESTED_LIVE_PRECONDITIONS",
            "real_provider_posts_authorized":0,
            "send_entrypoint_exists_in_this_PR":False}

def audit(*, base=ROOT, claimed_attestations=None, overrides=None):
    """The untrusted 'claimed_attestations' parameter is always ignored.

    It is deliberately impossible for this audit to become a live-allow gate.
    """
    _check_no_live_credentials()
    sources=verify_frozen_scope(base=base,overrides=overrides)
    missing=[{"id":id_,"severity":severity,"status":"NOT_ATTESTED",
              "required_evidence":requirement}
             for id_,severity,requirement in REQUIRED_LIVE_EVIDENCE]
    need(len(missing)==9 and all(x["status"]=="NOT_ATTESTED" for x in missing),
         "ALL_EXTERNAL_LIVE_PROOFS_MUST_REMAIN_NOT_ATTESTED")
    proposal={
        "rule_of_one":RULE,
        "parent_main_sha":EXACT_PARENT_MAIN,
        "source_scope":"FROZEN_TASK4_OFFLINE_TESTS_303_TO_308_ONLY",
        "existing_real_approval_consumed_tag":PREVIOUS_REAL_APPROVAL_TAG,
        "existing_real_approval_consumed_sha":PREVIOUS_REAL_APPROVAL_CONSUMED_SHA,
        "proposed_live_provider_calls":1,
        "approved_live_provider_calls":0,
        "human_live_approval_issued":False,
        "protected_production_single_use_consumed":False,
        "production_execution_authority_proven":False,
        "real_model_utility_proven":False,
        "real_provider_requests_sent":0,
        "native_bank_effects":0,
        "official_task4_or_final128_scores":0,
        "verified_frozen_offline_sources":sources,
        "external_live_prerequisites":missing,
        "operator_assertions_or_forged_evidence_can_grant_authority":False,
        "external_attestations_provided_or_validated":False,
        "explicit_warning":"CI GREEN / offline SQLite success NEVER implies protected global grant, live provider permission, or actual billing limit.",
        "live_authorization_decision":authorize_actual_provider(claimed_attestations),
        "readiness":STATUS,
        "limit":"Static exact-source audit: no GitHub branch/environment protection, remote ledger service, network restrictions, real pricing or billing, credential boundary, external identity, production clock, remote Provider receipts, native production effect, or independent utility has been checked.",
    }
    proposal["report_sha256"]=sha256(canonical(proposal))
    return proposal

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--output",required=True,type=Path)
    args=parser.parse_args()
    outcome=audit()
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_bytes(json.dumps(outcome,indent=2,ensure_ascii=False,
                                      sort_keys=True).encode("utf-8")+b"\n")
    print("TASK4_PROTECTED_PROVIDER_GAP_AUDIT_OFFLINE_SUCCESS_LIVE_DISPATCH_BLOCKED")

if __name__=="__main__":
    main()
