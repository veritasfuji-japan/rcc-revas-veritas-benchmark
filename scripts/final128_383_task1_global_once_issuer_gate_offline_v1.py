#!/usr/bin/env python3
"""#383 Task1 proposed protected issuer and globally single-use Git ref contract.

PR-ONLY, OFFLINE. This code NEVER invokes GitHub APIs, Provider endpoints,
bank effects or scorers. Only a deliberately in-memory, exact-type fake Git
ref store is usable. A successful fake "201" is NEVER an authenticated tag.

Unlike #351's SHA/run-derived proposed tag, the #383 ref is a FIXED
protocol-wide singleton, so creating a new run_id cannot reset the
hypothetical one-use gate. Real protection of that tag, environment approval,
GitHub auth and billing remain EXTERNAL, UNVERIFIED prerequisites.

No workflow_dispatch, environment secret, CLI sender, network client, remote
tag-create operation or operator-approval shortcut is installed by this PR.
"""
from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from threading import Lock
import hashlib
import json
import os

from scripts import final128_382_first_two_responses_once_transport_v1 as transport
from scripts import final128_381_task1_real_responses_capture_contract_v1 as wire
from scripts import final128_351_task1_durable_lease_preflight_v1 as prior

RULE="FINAL128_383_PROPOSED_GLOBALLY_SINGLE_USE_TASK1_FIRST_TWO_ISSUER_OFFLINE_V1"
REPO="veritasfuji-japan/rcc-revas-veritas-benchmark"
ACTOR="veritasfuji-japan"
ENV=prior.ENVIRONMENT
PROTOCOL_REF=transport.CONSUMED_REF
CASE=wire.guard.CASE
MODEL=wire.MODEL
MAX_USD=Decimal("1.00")
MAX_CALLS=2
GITHUB_REF_POST=f"/repos/{REPO}/git/refs"

UNVERIFIED_EXTERNAL_GATES=(
 "FRESH_OPERATOR_APPROVAL_EXACT_TASK1_FIRST_AB_MODEL_TWO_CALLS_USD_1",
 "GITHUB_PROTECTED_ENVIRONMENT_REVIEWER_AND_RESTRICTIONS_LIVE_CHECK",
 "DEDICATED_ENVIRONMENT_SCOPED_PROVIDER_CREDENTIAL_LIVE_CHECK",
 "ACTUAL_BILLING_PROJECT_LIMIT_MODEL_ACCESS_AND_CURRENT_PRICING_CHECK",
 "PROTECTED_IMMUTABLE_GLOBAL_SINGLETON_TAG_RULESET_AND_BYPASS_AUDIT",
 "TRUSTED_GITHUB_API_CREDENTIAL_CAN_CREATE_REF_ONCE_NOT_DELETE_OR_UPDATE",
 "DIRECT_PROTECTED_TLS_ORIGIN_OF_ACTUAL_PROVIDER_RECEIPTS",
 "REAL_NATIVE_TOOL_EFFECT_AND_TERMINAL_SCORER_CHAIN",
 "NETWORK_IAM_CREDENTIAL_BYPASS_RESISTANCE_THIRD_PARTY_AUDIT",
)

class Blocked(RuntimeError):pass
class UnknownAfterAttempt(Blocked):pass

def need(ok,reason):
    if ok is not True:raise Blocked("383_"+reason)

def canonical(value):
    return json.dumps(value,sort_keys=True,ensure_ascii=False,
                      separators=(",",":"),allow_nan=False).encode("utf8")

def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()

@dataclass(frozen=True)
class CandidateContext:
    """Untrusted candidate runner metadata; NOT independently authenticated."""
    repository:str
    ref:str
    main_sha:str
    run_id:str
    run_attempt:int
    event:str
    actor:str
    environment:str
    case_id:str
    model:str
    max_usd:str
    max_calls:int

def candidate_context(*,main_sha,run_id):
    return CandidateContext(REPO,"refs/heads/main",main_sha,run_id,1,
                            "workflow_dispatch",ACTOR,ENV,CASE,MODEL,"1.00",2)

def inspect_candidate(ctx):
    """Static scope check. No actor identity or environment is proven by JSON."""
    need(type(ctx) is CandidateContext,"CONTEXT_TYPE")
    need(ctx.repository==REPO and ctx.ref=="refs/heads/main"
         and type(ctx.main_sha) is str
         and prior.SHA_RE.fullmatch(ctx.main_sha) is not None,
         "REPOSITORY_REF_OR_SHA_DRIFT")
    need(type(ctx.run_id) is str
         and prior.RUN_RE.fullmatch(ctx.run_id) is not None
         and type(ctx.run_attempt) is int and ctx.run_attempt==1,
         "NO_RETRY_EXACT_RUN_REQUIRED")
    need(ctx.event=="workflow_dispatch" and ctx.actor==ACTOR
         and ctx.environment==ENV,
         "MANUAL_PROTECTED_ACTOR_OR_ENV_SCOPE")
    need(ctx.case_id==CASE and ctx.model==MODEL
         and ctx.max_usd=="1.00" and type(ctx.max_calls) is int
         and ctx.max_calls==MAX_CALLS,
         "FIRST_TWO_CASE_MODEL_CALL_OR_BUDGET_DRIFT")
    first=wire.first_real_wire_packet()
    estimate=transport.prepare_two_first_packets()
    need(estimate["live_dispatch_authorized"] is False
         and estimate["max_first_two_provider_attempts_proposed"]==MAX_CALLS
         and estimate["model"]==MODEL
         and estimate["project_hard_spend_stop_verified"] is False
         and Decimal(estimate["local_budget_reserved_max_usd_for_2_calls"]) < MAX_USD,
         "382_PARENT_FIRST_REQUEST_BUDGET_BOUNDARY_DRIFT")
    return {
      "rule":RULE,"status":"EXACT_SCOPE_CANDIDATE_NOT_TRUSTED",
      "repository":REPO,"ref":ctx.ref,
      "candidate_main_sha":ctx.main_sha,"candidate_run_id":ctx.run_id,
      "candidate_actor":ctx.actor,"candidate_event":ctx.event,
      "candidate_environment":ctx.environment,
      "case_id":CASE,"model":MODEL,
      "max_first_model_attempts_proposed":MAX_CALLS,
      "requested_total_usd_max_not_billing_cap":ctx.max_usd,
      "local_reservation_estimate_usd_not_provider_hard_cap":
         estimate["local_budget_reserved_max_usd_for_2_calls"],
      "original_first_wire_sha256":wire.sha(first),
      "proposed_protocol_global_once_ref":PROTOCOL_REF,
      "proposed_global_tag_create_url":GITHUB_REF_POST,
      "fresh_real_operator_approval_observed":False,
      "trusted_issuer_configuration_verified":False,
      "real_global_single_use_ref_created":False,
      "actual_model_posts":0,
      "new_utility_scores":None,
      "live_dispatch_authorized":False,
      "unverified_external_gates":list(UNVERIFIED_EXTERNAL_GATES),
    }

def proposed_git_ref_create_request(ctx):
    """Reviewable GitHub REST packet, NOT executed or authenticated.

    GitHub 201 must be observed by a separately trusted protected issuer.
    Even a 201 is not immutable protection unless independent ruleset
    policy and bypass rights were verified. Ref is NOT per-run/per-SHA.
    """
    plan=inspect_candidate(ctx)
    return {
        "method":"POST","path":GITHUB_REF_POST,
        "body":{"ref":PROTOCOL_REF,"sha":ctx.main_sha},
        "expected_status":201,
        "on_422":"REF_ALREADY_EXISTS_OR_INVALID_FAIL_CLOSED_NO_RETRY",
        "on_timeout":"OUTCOME_UNKNOWN_PERMANENT_STOP_NO_RETRY",
        "protocol_wide_ref_not_derived_from_sha_or_run":True,
        "candidate_plan_sha256":digest(plan),
        "external_post_executed":False,
        "real_authorization_granted":False,
    }

class OfflineOnlyFakeGitRefs:
    """Exact-type local stub; no arbitrary network adapter injection."""
    def __init__(self,*,fault="none"):
        need(fault in ("none","prewrite_unknown","postwrite_unknown",
                       "server_reject"),"BAD_FAULT_MODE")
        self.fault=fault
        self._lock=Lock()
        self._tags={}
        self.attempts=0

    def _create_once(self,ref,sha):
        with self._lock:
            self.attempts+=1
            if self.fault=="prewrite_unknown":
                raise UnknownAfterAttempt("383_UNKNOWN_BEFORE_FAKE_REF_WRITE_STOP")
            if ref in self._tags or self.fault=="server_reject":
                raise Blocked("383_FAKE_GITHUB_REF_CREATE_REFUSED_REPLAY_OR_422")
            self._tags[ref]=sha
            if self.fault=="postwrite_unknown":
                raise UnknownAfterAttempt("383_UNKNOWN_AFTER_FAKE_REF_WRITE_STOP")
            return {"status":201,"ref":ref,"sha":sha,
                    "source":"OFFLINE_IN_MEMORY_FAKE_NOT_GITHUB"}

    def snapshot(self):
        with self._lock:return dict(self._tags)

class OfflineJournal:
    """A local fsync hash-chain. No cross-run immutability or tag protection."""
    def __init__(self,path):
        self.path=Path(path)
        need(self.path.parent.is_dir() and not self.path.is_symlink(),
             "JOURNAL_PARENT_REQUIRED")
        # O_EXCL avoids local accidental reuse but is NOT a global lease.
        try:
            fd=os.open(self.path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        except FileExistsError as exc:
            raise Blocked("383_LOCAL_EVIDENCE_REPLAY_DENIED") from exc
        self.handle=os.fdopen(fd,"w",encoding="utf8")
        self.prev="0"*64
        self.sequence=0

    def add(self,event):
        need(type(event) is dict and not any(
            key in canonical(event).decode("utf8").lower()
            for key in ("api_key","bearer ","operator_phrase","secret_value")),
            "PROTECTED_MATERIAL_MUST_NOT_BE_LOGGED")
        payload={"sequence":self.sequence,"previous_sha256":self.prev,
                 "event":event}
        value=digest(payload)
        record={**payload,"record_sha256":value}
        self.handle.write(canonical(record).decode("utf8")+"\n")
        self.handle.flush();os.fsync(self.handle.fileno())
        self.prev=value;self.sequence+=1
        return value

    def close(self):
        self.handle.close()

def rehearse_offline_atomic_once(*,ctx,store,evidence_path):
    """Fake tag creation attempted once; never passes permission to #382."""
    need(type(store) is OfflineOnlyFakeGitRefs,
         "LOCAL_FAKE_STORE_EXACT_TYPE_REQUIRED")
    proposal=proposed_git_ref_create_request(ctx)
    journal=OfflineJournal(evidence_path)
    outcome="UNKNOWN_STOP_NEVER_RETRY"
    try:
        journal.add({"phase":"PROPOSED_CONTEXT_ACCEPTED_SCOPE_ONLY",
                     "plan_sha256":proposal["candidate_plan_sha256"],
                     "no_live_authorization":True})
        # The fsynced journal exists before the fake atomic operation.
        journal.add({"phase":"BEFORE_FAKE_ATOMIC_REF_CREATE_NO_RETRY",
                     "ref_sha256":digest(PROTOCOL_REF),
                     "sha":ctx.main_sha})
        try:
            reply=store._create_once(PROTOCOL_REF,ctx.main_sha)
            need(reply=={"status":201,"ref":PROTOCOL_REF,"sha":ctx.main_sha,
                 "source":"OFFLINE_IN_MEMORY_FAKE_NOT_GITHUB"},
                 "FAKE_GITHUB_REPLY_DRIFT")
            outcome="OFFLINE_FAKE_SINGLETON_CONSUMED_NOT_REAL"
            journal.add({"phase":"FAKE_REF_CREATED_NOT_PROTECTED",
                         "reply_sha256":digest(reply),
                         "real_global_lease_created":False})
        except BaseException as exc:
            journal.add({"phase":"FAKE_CONSUMPTION_UNKNOWN_OR_REFUSED_STOP",
                         "exception_type":type(exc).__name__,
                         "no_retry":True})
            raise
        result={
          "rule":RULE,"status":outcome,
          "candidate_context_sha256":digest(proposal),
          "proposed_global_once_ref_sha256":digest(PROTOCOL_REF),
          "local_fake_ref_points_to_candidate_sha":True,
          "local_fake_ref_store_used":True,
          "local_fake_create_attempts":store.attempts,
          "local_audit_chain_tip_sha256":journal.prev,
          "real_github_ref_created":False,
          "github_ruleset_live_verified":False,
          "real_environment_protection_verified":False,
          "provider_project_spend_limit_verified":False,
          "fresh_operator_approval_verified":False,
          "actual_paid_provider_calls":0,
          "actual_native_scorer_calls":0,
          "official_utility_or_attack_scores":None,
          "permission_to_call_provider":False,
        }
        journal.add({"phase":"OFFLINE_REHEARSAL_ENDED_LIVE_DENIED",
                     "result_sha256":digest(result)})
        result["local_audit_chain_tip_sha256"]=journal.prev
        return result
    finally:
        journal.close()

def live_execution_gate(*_args,**_kwargs):
    """A test-created local tag, JSON consent, or prior approval NEVER unlocks."""
    raise Blocked("383_REAL_PROTECTED_ISSUER_ENV_RULESET_BILLING_AND_FRESH_APPROVAL_UNVERIFIED")
