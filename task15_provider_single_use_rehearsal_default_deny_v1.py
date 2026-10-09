"""Offline Task15 one-shot rehearsal for a future, separately authorized model call.

An offline rehearsal marker is NOT an authorization, bearer token, signature,
provider receipt, authenticated user consent, or cross-process replay defense.
No provider transport exists in this module. A failure burns the local rehearsal.
"""
from __future__ import annotations
import copy
import hashlib
import json
from threading import Lock
from datetime import datetime, timezone

RULE = "TASK15_PROVIDER_SINGLE_USE_REHEARSAL_DEFAULT_DENY_V1"
PREDECESSOR_RULE = "TASK15_REAL_PROVIDER_PREFLIGHT_DEFAULT_DENY_V1"
MODEL_ID = "gpt-4.1-mini-2025-04-14"
HISTORICAL_LIMIT_MICRO_USD = 5_000_000
MERGED_MAIN_269 = "5206a8e032362f0c362dba444a99ce38dd146a87"
CASES = tuple(
    f"banking:user_task_15:injection_task_{n}:direct"
    for n in (0,1,2,3,4,5,6,8)
)
ARMS = ("A", "B")
ISSUED_AT = "2026-10-09T12:24:00+00:00"
EXPIRES_AT = "2026-10-09T12:29:00+00:00"
TEST_NONCE = "OFFLINE-REHEARSAL-NOT-A-SECRET-OR-PROVIDER-TOKEN"

def canonical(x):
    return json.dumps(x,sort_keys=True,separators=(",",":"),
                      ensure_ascii=False,allow_nan=False)

def sha(x):
    return hashlib.sha256(canonical(x).encode()).hexdigest()

class RehearsalViolation(ValueError):
    pass

def require(ok, reason):
    if not ok:
        raise RehearsalViolation(reason)

def timestamp(s):
    require(type(s) is str and s.endswith("+00:00"),
            "EXACT_EXPLICIT_UTC_TIME_REQUIRED")
    try:
        parsed=datetime.fromisoformat(s)
        require(parsed.tzinfo is not None and
                parsed.utcoffset().total_seconds()==0,
                "UTC_CLOCK_REQUIRED")
        return parsed
    except (ValueError,OverflowError) as exc:
        raise RehearsalViolation("VALID_UTC_CLOCK_REQUIRED") from exc

class Task15ProviderSingleUseRehearsalV1:
    """Local in-memory consume of a non-executable future grant *proposal*."""

    def __init__(self, *, prior, transport_present=False,
                 actual_operator_consent=False,
                 mode="OFFLINE_REHEARSAL_NEVER_LIVE"):
        require(type(prior) is dict and
                mode=="OFFLINE_REHEARSAL_NEVER_LIVE" and
                transport_present is False and
                actual_operator_consent is False,
                "NO_REAL_TRANSPORT_OR_APPROVAL_IN_THIS_PROOF")
        require(prior.get("rule_of_one")==PREDECESSOR_RULE
                and prior.get("determination")==
                    "SIXTEEN_TASK15_OFFLINE_REQUESTS_PINNED_REAL_PROVIDER_GATE_CLOSED"
                and prior.get("model_id")==MODEL_ID
                and prior.get("case_count")==8
                and prior.get("case_arm_request_count")==16
                and prior.get("budget_ceiling_usd")==5.0
                and prior.get("budget_ceiling_is_expenditure_authority") is False
                and prior.get("operator_approval_issued") is False
                and prior.get("single_use_provider_authority_issued") is False
                and prior.get("permission_to_call_provider") is False
                and prior.get("response_authenticity_proven") is False
                and prior.get("model_candidate_observed") is False
                and prior.get("transport_adapter_enabled") is False
                and prior.get("real_provider_calls")==
                    prior.get("real_provider_charges_usd")==
                    prior.get("scorer_calls")==
                    prior.get("native_write_dispatches")==
                    prior.get("external_effects")==0
                and prior.get("full_canonical_trajectory_proven") is False
                and prior.get("final128_utility_measured") is False
                and prior.get("injection_success_measured") is False,
                "EXACT_CLOSED_PR269_PROOF_REQUIRED")
        req=prior.get("requests")
        require(type(req) is list and len(req)==16,
                "SIXTEEN_CLOSED_CASE_ARM_REQUESTS_REQUIRED")
        ids=set()
        for i,case in enumerate(CASES):
            for k,arm in enumerate(ARMS):
                rec=req[2*i+k]
                require(type(rec) is dict
                        and rec.get("case_id")==case
                        and rec.get("arm")==arm
                        and rec.get("frozen_model_snapshot")==MODEL_ID
                        and rec.get("offline_source_only") is True
                        and all(rec.get(key) is False for key in (
                            "provider_response_authenticated",
                            "provider_request_issued",
                            "provider_response_received",
                            "provider_executable_authority",
                            "bind_permit_from_future_model",
                            "native_effect_dispatch_authorized"))
                        and all(rec.get(key) is None for key in (
                            "provider_response_id","provider_usage","provider_charge_usd"))
                        and all(type(rec.get(key)) is str and
                            len(rec[key])==64 and
                            all(c in "0123456789abcdef" for c in rec[key])
                            for key in (
                                "native_postread_request_sha256",
                                "native_tool_schemas_sha256",
                                "original_user_message_sha256",
                                "prior_offline_candidate_sha256",
                                "prior_offline_rcc_review_sha256",
                                "prior_native_read_result_sha256")),
                        "EXACT_UNAUTHENTICATED_SOURCE_RECORD_REQUIRED")
                rid=rec.get("prior_native_read_call_id")
                require(type(rid) is str and rid and rid not in ids,
                        "NO_ALIASING_OF_PREDECESSOR_NATIVE_READ_CALL_IDS")
                ids.add(rid)
        require(len(ids)==16,"SIXTEEN_UNIQUE_SOURCE_READ_CALLS_REQUIRED")
        self._prior=copy.deepcopy(prior)
        self._prior_sha=sha(prior)
        self._state="READY"
        self._used=False
        self._lock=Lock()
        self._draft=None
        self._journal=[]

    def draft(self, *, case_id=CASES[0], arm="A",
              model_id=MODEL_ID,
              max_cost_micro_usd=HISTORICAL_LIMIT_MICRO_USD,
              nonce=TEST_NONCE):
        with self._lock:
            require(self._state=="READY","ONE_DRAFT_PER_REHEARSAL_ONLY")
            require(case_id in CASES and arm in ARMS,
                    "EXACT_TASK15_CASE_AND_ARM_REQUIRED")
            require(model_id==MODEL_ID,
                    "FROZEN_EXACT_MODEL_SNAPSHOT_REQUIRED")
            require(type(max_cost_micro_usd) is int and
                    0<max_cost_micro_usd<=HISTORICAL_LIMIT_MICRO_USD,
                    "COST_LIMIT_NOT_EXECUTION_PERMISSION")
            require(nonce==TEST_NONCE,
                    "ONLY_NONSECRET_OFFLINE_REHEARSAL_MARKER_SUPPORTED")
            pos=2*CASES.index(case_id)+ARMS.index(arm)
            req=self._prior["requests"][pos]
            plan={
                "schema":"task15.future-model-capture-request-plan.v1",
                "rule_of_one":RULE,
                "kind":"NON_EXECUTABLE_OFFLINE_REHEARSAL_PROPOSAL",
                "predecessor_merged_main_sha":MERGED_MAIN_269,
                "predecessor_proof_sha256":self._prior_sha,
                "case_id":case_id,"arm":arm,
                "frozen_model_snapshot":model_id,
                "source_request_sha256":req["native_postread_request_sha256"],
                "source_tool_schemas_sha256":req["native_tool_schemas_sha256"],
                "source_user_message_sha256":req["original_user_message_sha256"],
                "source_read_call_id":req["prior_native_read_call_id"],
                "max_cost_micro_usd":max_cost_micro_usd,
                "historical_ceiling_is_not_spend_permission":True,
                "issued_at":ISSUED_AT,"expires_at":EXPIRES_AT,
                "offline_public_nonce":nonce,
                "transport_adapter_present":False,
                "trusted_human_approval_attested":False,
                "trusted_issuer_present":False,
                "live_provider_authority_issued":False,
                "native_bank_execution_authority_issued":False,
                "provider_response_authenticated":False,
                "provider_response_id":None,
            }
            self._draft=copy.deepcopy(plan)
            self._state="DRAFTED"
            self._journal.append("NON_EXECUTABLE_PLAN_DRAFTED")
            return copy.deepcopy(plan)

    def consume_rehearsal(self, *, proposal, now=ISSUED_AT):
        with self._lock:
            require(self._state=="DRAFTED" and not self._used,
                    "REHEARSAL_ONCE_ONLY_NO_RETRY")
            self._used=True  # Burn before checking date, scope or identity
            self._state="CONSUMPTION_IN_PROGRESS"
        try:
            require(type(proposal) is dict and
                    canonical(proposal)==canonical(self._draft),
                    "EXACT_FROZEN_OFFLINE_PLAN_ONLY")
            t=timestamp(now)
            require(timestamp(ISSUED_AT)<=t<timestamp(EXPIRES_AT),
                    "REHEARSAL_EXPIRED_OR_UNISSUED")
            require(sha(self._prior)==self._prior_sha,
                    "SOURCE_EVIDENCE_CHANGED_AFTER_DRAFT")
            require(proposal["historical_ceiling_is_not_spend_permission"] is True
                    and proposal["trusted_human_approval_attested"] is False
                    and proposal["trusted_issuer_present"] is False
                    and proposal["transport_adapter_present"] is False
                    and proposal["live_provider_authority_issued"] is False
                    and proposal["native_bank_execution_authority_issued"] is False
                    and proposal["provider_response_authenticated"] is False
                    and proposal["provider_response_id"] is None,
                    "NO_LIVE_AUTHORITY_CAN_BE_PROMOTED")
            result={
                "rule_of_one":RULE,
                "determination":"ONE_LOCAL_REHEARSAL_CONSUMED_PROVIDER_AUTHORITY_ABSENT",
                "plan_sha256":sha(proposal),
                "predecessor_proof_sha256":self._prior_sha,
                "case_id":proposal["case_id"],"arm":proposal["arm"],
                "model_snapshot":MODEL_ID,
                "max_cost_micro_usd":proposal["max_cost_micro_usd"],
                "local_rehearsal_consumed":True,
                "in_memory_single_use_only":True,
                "durable_replay_protection_proven":False,
                "human_approval_verified":False,
                "live_provider_capability_issued":False,
                "permission_to_call_provider":False,
                "provider_request_sent":False,
                "provider_response_authenticated":False,
                "provider_calls":0,"provider_charges_usd":0,
                "native_write_dispatch_count":0,
                "scorer_calls":0,"external_effects":0,
                "canonical_final128_measured":False,
            }
            with self._lock:
                self._state="REHEARSAL_CONSUMED_NO_TRANSPORT"
                self._journal.append("LOCAL_REHEARSAL_CONSUMED_ONLY")
            return result
        except BaseException:
            with self._lock:
                self._state="TERMINAL_FAILED_CONSUMED_NO_TRANSPORT"
                self._journal.append("FAILED_OR_EXPIRED_REHEARSAL_PERMANENTLY_BURNED")
            raise

    def attempt_live_provider(self, *, transport=None, approval=None):
        del transport,approval
        raise RehearsalViolation(
            "FRESH_EXTERNAL_APPROVAL_AND_SEPARATE_TRANSPORT_PR_REQUIRED")

    def observation(self):
        with self._lock:
            return {
                "state":self._state,"consumed":self._used,
                "draft_sha256":sha(self._draft) if self._draft is not None else None,
                "journal":copy.deepcopy(self._journal),
                "provider_authority_issued":False,"provider_calls":0,
                "provider_charges_usd":0,"native_bank_writes":0,
                "external_effects":0,"durable_replay_protection_proven":False,
            }
