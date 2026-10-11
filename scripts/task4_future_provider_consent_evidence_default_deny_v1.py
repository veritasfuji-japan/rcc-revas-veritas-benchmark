#!/usr/bin/env python3
"""Task4 #307: offline future-provider consent/evidence boundary, DEFAULT DENY.

This module has NO real Provider client, transport, credential loader, network
operation, live execution permission, native Bind invocation or bank executor.
A local fake response can prove ONLY evidence shape and durable *rehearsal*
single-use. Future real API authorization requires a NEW, separate audited
implementation, explicit human consent, a new protected consumption mechanism,
and independent accounting/credential controls. Prior consent is consumed.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
from decimal import Decimal
import json
import os
from pathlib import Path
import tempfile

ROOT = Path(__file__).resolve().parents[1]
import sys
for p in (ROOT, ROOT / "scripts"):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from task4_prospective_model_wire_date_boundary_v1 import (
    ProspectiveWireBoundary, date_session, canonical, sha, MODEL, REQUEST,
)
from task4_prospective_offline_completion_envelope_bridge_v1 import (
    OfflineCompletionBridge, local_completion_fixture,
)
from task4_future_provider_sdk_predispatch_mock_v1 import (
    strict_estimated_cost, MAX_INPUT_TOKENS_FIXTURE, MAX_OUTPUT_TOKENS,
    LOCAL_ESTIMATE_THRESHOLD, SDK_VERSION,
)

RULE = "TASK4_FUTURE_PROVIDER_CONSENT_EVIDENCE_DEFAULT_DENY_V1"
MAIN_BASE = "cd683bb392cc871d79d145c3ae9cc3194f8af2a9"
HISTORICAL_THIRD_CONSUMED = "95ff6be8c5875ed3827a00fe71fb54bd9de48130"
PROPOSED_FUTURE_PROVIDER_CALLS = 1
ALLOWED_REAL_PROVIDER_POSTS = 0
EMPTY_SHA = "0" * 64
OFFLINE_SOURCE = "OFFLINE_REHEARSAL_ONLY_NO_PROVIDER"
OFFLINE_EVENTS = (
    "OFFLINE_REHEARSAL_SLOT_CONSUMED_BEFORE_VALIDATION",
    "LOCAL_SYNTHETIC_COMPLETION_CAPTURED_BEFORE_BIND_ONLY",
    "OFFLINE_TERMINAL_NO_PROVIDER_EFFECT",
)
BLOCKED_ENV = (
    "OPENAI_API_KEY", "TASK4_OPENAI_API_KEY", "ANTHROPIC_API_KEY",
    "OPENAI_BASE_URL", "VERITAS_DATABASE_URL",
    "TASK4_THIRD_APPROVAL_PHRASE", "TASK4_307_APPROVAL_PHRASE",
)

class Refused(ValueError):
    pass

def require(ok, why):
    if not ok:
        raise Refused(why)

def ensure_no_live_context():
    require(not any(os.getenv(k) for k in BLOCKED_ENV),
            "OFFLINE_PROOF_REFUSES_REAL_SECRETS_AND_APPROVAL_PHRASES")

def future_live_dispatch_decision(_manifest=None, _claimed_consent=None):
    """Unconditionally deny. No real Provider send function exists anywhere."""
    return {
        "decision": "DENY",
        "reason": "NEW_EXPLICIT_HUMAN_APPROVAL_DURABLE_SINGLE_USE_AND_LIVE_GUARD_ABSENT",
        "allowed_real_provider_posts": 0,
        "real_provider_dispatch_possible_from_this_module": False,
    }

def evidence_promotion_decision(_evidence=None, _provider_origin=None):
    """No offline evidence, even with forged status fields, can prove live origin."""
    return {
        "decision": "DENY",
        "reason": "NO_AUTHENTICATED_REAL_PROVIDER_RESPONSE_OR_NEW_ISSUED_AUTHORITY",
        "real_model_utility_proven": False,
        "native_bank_execution_permitted": False,
    }

def proposed_manifest(boundary):
    require(type(boundary) is ProspectiveWireBoundary and
            boundary.phase == "FROZEN_NOT_DISPATCHABLE",
            "TRUSTED_ISSUER_FROZEN_WIRE_REQUIRED")
    bound = strict_estimated_cost(MAX_INPUT_TOKENS_FIXTURE, MAX_OUTPUT_TOKENS)
    require(bound <= LOCAL_ESTIMATE_THRESHOLD,
            "HISTORICAL_OFFLINE_ESTIMATE_LIMIT_EXCEEDED")
    return {
        "schema": "veritas.task4.future-provider-consent-evidence-rehearsal.v1",
        "rule_of_one": RULE,
        "source_parent_main": MAIN_BASE,
        "source": OFFLINE_SOURCE,
        "target": "banking:user_task_4:prospective-new-date-future-provider-307",
        "original_request_sha256": sha(REQUEST),
        "issuer_context_sha256": boundary.context.digest,
        "immutable_wire_sha256": sha(json.loads(boundary.wire_bytes)),
        "model_id": MODEL,
        "sdk_package_version": SDK_VERSION,
        "proposed_future_provider_posts_not_authorized": PROPOSED_FUTURE_PROVIDER_CALLS,
        "allowed_real_provider_posts": ALLOWED_REAL_PROVIDER_POSTS,
        "max_completion_tokens": MAX_OUTPUT_TOKENS,
        "hypothetical_input_ceiling_tokens": MAX_INPUT_TOKENS_FIXTURE,
        "historical_price_estimate_usd_not_current_quote": str(bound),
        "offline_estimate_threshold_not_billing_cap_usd": str(LOCAL_ESTIMATE_THRESHOLD),
        "old_real_provider_third_authorization_consumed_sha": HISTORICAL_THIRD_CONSUMED,
        "human_approval_for_this_future_round_granted": False,
        "new_protected_single_use_token_issued": False,
        "provider_secret_present": False,
        "provider_response_authenticated": False,
        "live_provider_endpoint_enabled": False,
        "native_bind_dispatch_enabled": False,
        "real_bank_dispatch_enabled": False,
        "future_release_prerequisites": [
            "new separate explicit human approval bound to model and exact wire, amount, case and call-count",
            "new protected non-reusable durable grant consumed BEFORE any request",
            "locked per-call identity and no retry after unknown remote outcome",
            "fresh provider pricing, project/organization spending controls and independent billing review",
            "real Provider-origin request-ID and usage evidence checked separately from all local fixtures",
            "issuer-owned production clock, real IAM/credentials isolation and native Bind proof",
            "separate reviewed send entrypoint not supplied by this PR"
        ],
        "live_decision": "DENY",
        "no_authority_at_issue_or_execution": True,
    }

def _line(seq, event, prior, manifest_sha, facts):
    data = {
        "seq": seq, "event": event, "prior_sha256": prior,
        "manifest_sha256": manifest_sha, "facts": facts,
    }
    return {**data, "entry_sha256": sha(data)}

def _write_new(path, row):
    path = Path(path)
    require(path.parent.is_dir(), "REHEARSAL_LEDGER_PARENT_DIRECTORY_REQUIRED")
    # Atomic on-disk single-use local evidence ONLY; never a production grant.
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as exc:
        raise Refused("DURABLE_OFFLINE_REHEARSAL_SLOT_ALREADY_CONSUMED_NO_RETRY") from exc
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(canonical(row).decode("utf8") + "\n")
        f.flush()
        os.fsync(f.fileno())
    # Linux Actions filesystem: persist directory entry for best-effort local durability.
    if hasattr(os, "O_DIRECTORY"):
        dfd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)

def _append(path, row):
    # Can only be called by the holder of the local rehearsal slot.
    with open(path, "a", encoding="utf8") as f:
        f.write(canonical(row).decode("utf8") + "\n")
        f.flush()
        os.fsync(f.fileno())

def check_rehearsal_evidence(path, *, expected_manifest):
    """Authenticate internal structure/continuity, NOT Provider provenance."""
    require(type(expected_manifest) is dict and
            expected_manifest["live_decision"] == "DENY" and
            expected_manifest["allowed_real_provider_posts"] == 0,
            "OFFLINE_ONLY_MANIFEST_REQUIRED")
    manifest_sha = sha(expected_manifest)
    raw = Path(path).read_text(encoding="utf8").splitlines()
    require(len(raw) in (2,3) and all(line for line in raw),
            "PARTIAL_OR_OVERSIZE_REHEARSAL_LEDGER_NO_EVIDENCE_PROMOTION")
    prior = EMPTY_SHA
    rows = []
    for i, line in enumerate(raw):
        try:
            row = json.loads(line)
        except (ValueError, TypeError) as exc:
            raise Refused("MALFORMED_OFFLINE_LEDGER") from exc
        require(type(row) is dict and
                set(row) == {"seq","event","prior_sha256","manifest_sha256","facts","entry_sha256"} and
                type(row["seq"]) is int and row["seq"] == i and
                row["prior_sha256"] == prior and
                row["manifest_sha256"] == manifest_sha and
                type(row["facts"]) is dict,
                "REHEARSAL_LEDGER_SEQUENCE_OR_MANIFEST_MISMATCH")
        core={k:row[k] for k in ("seq","event","prior_sha256","manifest_sha256","facts")}
        require(sha(core)==row["entry_sha256"],
                "REHEARSAL_LEDGER_EVENT_INTEGRITY_FAILURE")
        prior = row["entry_sha256"]
        rows.append(row)
    require(rows[0]["event"]==OFFLINE_EVENTS[0] and
            rows[0]["facts"]=={
                "source": OFFLINE_SOURCE, "actual_real_provider_posts":0,
                "retry_permitted":False,
                "real_provider_approval_granted":False,
            },"FIRST_EVENT_MUST_CONSUME_OFFLINE_SLOT")
    terminal=rows[-1]["event"]
    require(terminal in (OFFLINE_EVENTS[2],"OFFLINE_UNKNOWN_STOP_NO_RETRY"),
            "TERMINAL_EVENT_MISSING_OR_OUT_OF_ORDER")
    if terminal==OFFLINE_EVENTS[2]:
        require(len(rows)==3 and rows[1]["event"]==OFFLINE_EVENTS[1] and
                rows[1]["facts"]["candidate_sha256"] and
                rows[1]["facts"]["binding_sha256"] and
                rows[1]["facts"]["fake_local_response_sha256"] and
                rows[1]["facts"]["server_request_id"] is None and
                rows[-1]["facts"]=={
                    "actual_real_provider_posts":0,
                    "real_bank_effects":0,
                    "live_approval_issued":False,
                    "official_scores":0,
                },
                "OFFLINE_RECEIPT_FIELDS_OR_ORDER_MISSING")
        state="COMPLETE_LOCAL_SIMULATION_NOT_PROVIDER_EVIDENCE"
    else:
        require(len(rows)==2 and rows[-1]["facts"].get("retry_permitted") is False and
                rows[-1]["facts"].get("provider_reply_authenticated") is False,
                "UNKNOWN_OUTCOME_MUST_REMAIN_CONSUMED")
        state="UNKNOWN_OFFLINE_REHEARSAL_CONSUMED_NOT_RETRIABLE"
    return {"verification":"LOCAL_STRUCTURE_ONLY",
            "rehearsal_status":state,
            "manifest_sha256":manifest_sha,
            "terminal_chain_sha256":prior,
            "real_provider_origin_proven":False,
            "any_real_dispatch_authorized":False,
            "event_count":len(rows)}

class ConsentEvidenceOfflineRound:
    """Atomically consume one local rehearsal slot, then handle fake data."""
    def __init__(self, *, ledger_path, boundary=None):
        self.boundary=boundary or ProspectiveWireBoundary(date_session())
        if boundary is None:
            self.boundary.issue_and_freeze()
        self.manifest=proposed_manifest(self.boundary)
        self._manifest_bytes=canonical(self.manifest)
        self.ledger_path=Path(ledger_path)
        self.attempted=False
        self.response_data=None

    def simulate_once(self, *, supplied_manifest=None, packet_mutator=None,
                      interrupt_before_fake_capture=False):
        require(not self.attempted, "REHEARSAL_SINGLE_ATTEMPT_ALREADY_CONSUMED")
        self.attempted=True
        base_sha=sha(self.manifest)
        first=_line(0,OFFLINE_EVENTS[0],EMPTY_SHA,base_sha,{
            "source":OFFLINE_SOURCE,"actual_real_provider_posts":0,
            "retry_permitted":False,"real_provider_approval_granted":False})
        _write_new(self.ledger_path, first)
        previous=first
        try:
            ensure_no_live_context()
            offered=self.manifest if supplied_manifest is None else supplied_manifest
            require(canonical(offered)==self._manifest_bytes and
                    canonical(self.manifest)==self._manifest_bytes,
                    "FROZEN_MANIFEST_CANNOT_CHANGE_OR_PROMOTE_AUTHORITY")
            self.boundary._verify_wire(json.loads(self.boundary.wire_bytes))
            require(self.manifest["live_decision"]=="DENY" and
                    not self.manifest["human_approval_for_this_future_round_granted"] and
                    not self.manifest["new_protected_single_use_token_issued"] and
                    self.manifest["allowed_real_provider_posts"]==0,
                    "NO_LIVE_APPROVAL_OR_PROVIDER_POSTS_PERMITTED")
            require(future_live_dispatch_decision(self.manifest)["decision"]=="DENY",
                    "NO_FUTURE_LIVE_DISPATCH_FROM_OFFLINE_REHEARSAL")
            require(not interrupt_before_fake_capture,
                    "INTERRUPTED_AFTER_DURABLE_SLOT_CONSUMPTION")
            packet=local_completion_fixture(self.boundary)
            if packet_mutator is not None:
                packet_mutator(packet)
            bridge=OfflineCompletionBridge(self.boundary)
            candidate_sha=bridge.receive_once(
                supplied_wire=json.loads(self.boundary.wire_bytes),
                local_packet=packet)
            binding_sha=bridge.verify_before_bind(
                supplied_wire=json.loads(self.boundary.wire_bytes))
            second=_line(1,OFFLINE_EVENTS[1],previous["entry_sha256"],base_sha,{
                "candidate_sha256":candidate_sha,
                "binding_sha256":binding_sha,
                "fake_local_response_sha256":sha(packet["response"]),
                "response_origin":OFFLINE_SOURCE,
                "server_request_id":None,
                "new_provider_request_count":0,
            })
            _append(self.ledger_path, second)
            previous=second
            last=_line(2,OFFLINE_EVENTS[2],previous["entry_sha256"],base_sha,{
                "actual_real_provider_posts":0,"real_bank_effects":0,
                "live_approval_issued":False,"official_scores":0})
            _append(self.ledger_path,last)
        except BaseException as exc:
            # If a partial fake-capture event exists, the journal must NEVER
            # be accepted as valid completed provider evidence or restarted.
            log=_line(previous["seq"]+1,"OFFLINE_UNKNOWN_STOP_NO_RETRY",
                      previous["entry_sha256"],base_sha,{
                          "error_class":type(exc).__name__,
                          "retry_permitted":False,
                          "provider_reply_authenticated":False,
                          "actual_real_provider_posts":0})
            _append(self.ledger_path, log)
            raise
        self.response_data=check_rehearsal_evidence(
            self.ledger_path, expected_manifest=self.manifest)
        return self.response_data

def audit():
    ensure_no_live_context()
    with tempfile.TemporaryDirectory(prefix="task4-307-offline-") as tmp:
        journal=Path(tmp)/"consumed-local-rehearsal.jsonl"
        round_=ConsentEvidenceOfflineRound(ledger_path=journal)
        initial=future_live_dispatch_decision(round_.manifest)
        completed=round_.simulate_once()
        checked=check_rehearsal_evidence(journal,
                                        expected_manifest=round_.manifest)
        require(initial["decision"]=="DENY" and
                completed==checked and
                completed["rehearsal_status"]=="COMPLETE_LOCAL_SIMULATION_NOT_PROVIDER_EVIDENCE",
                "DEFAULT_DENY_LOCAL_REHEARSAL_NOT_VERIFIED")
        try:
            ConsentEvidenceOfflineRound(ledger_path=journal).simulate_once()
        except Refused as e:
            require(str(e)=="DURABLE_OFFLINE_REHEARSAL_SLOT_ALREADY_CONSUMED_NO_RETRY",
                    "DURABLE_REPLAY_REFUSAL_CHANGED")
        else:
            raise Refused("REHEARSAL_REPLAY_WAS_NOT_REFUSED")
        return {
            "rule_of_one":RULE,
            "determination":"OFFLINE_CONSENT_AND_EVIDENCE_BOUNDARY_DEFAULT_DENY_REHEARSAL",
            "parent_main":MAIN_BASE,
            "proposal_sha256":sha(round_.manifest),
            "model_configured_only":MODEL,
            "future_real_provider_posts_proposed_not_authorized":PROPOSED_FUTURE_PROVIDER_CALLS,
            "real_provider_posts_authorized":0,
            "actual_provider_calls":0,
            "new_human_approval_issued":False,
            "prior_third_approval_consumption_unchanged":True,
            "future_single_use_rehearsed_locally_only":True,
            "local_simulated_response_not_a_real_model":True,
            "local_ledger_verification":checked,
            "durable_local_retry_denial":True,
            "old_approval_reused":False,
            "estimated_spend_not_billing_guarantee":True,
            "external_bank_effects":0,
            "native_bind_adjudications":0,
            "official_task4_scores":0,
            "final128_scores":0,
            "real_model_utility_proven":False,
            "production_execution_authority_proven":False,
            "future_live_dispatch_decision":initial,
            "future_evidence_promotion_decision":evidence_promotion_decision(),
            "limitations":"A local filesystem exclusive-create and hash-chain rehearse fail-closed consumption, not globally durable workflow authorization, human consent, authenticated Provider responses, billing controls, live API posts, native Bind, or actual bank effects.",
        }

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--output",type=Path,required=True)
    args=p.parse_args()
    result=audit()
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
    print("TASK4_FUTURE_PROVIDER_CONSENT_EVIDENCE_OFFLINE_DEFAULT_DENY_PASS_NO_API")

if __name__=="__main__":
    main()
