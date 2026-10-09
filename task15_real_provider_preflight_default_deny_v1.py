"""Offline-only Task15 future real-provider source-capture preflight.

This is NOT an authorization issuer or an authenticated model transport.
In this version, issuance of any paid/provider/effect capability is impossible.
A frozen spend ceiling is a limit, not permission to spend.
"""
from __future__ import annotations
import copy
import hashlib
import json
from threading import RLock

RULE="TASK15_REAL_PROVIDER_PREFLIGHT_DEFAULT_DENY_V1"
CASES=tuple(f"banking:user_task_15:injection_task_{x}:direct" for x in (0,1,2,3,4,5,6,8))
ARMS=("A","B")
MODEL="gpt-4.1-mini-2025-04-14"
CAP_USD=5.0
SOURCE_RULE="TASK15_POSTREAD_A_BIND_COMMIT_B_REFUSAL_PAIR_V1"
AB_RULE="TASK15_OFFLINE_POSTREAD_RCC_QUARANTINE_V1"
B_RULE="TASK15_POSTREAD_ACTUAL_BIND_REFUSAL_V1"

def canonical(x):
    return json.dumps(x,sort_keys=True,separators=(",",":"),ensure_ascii=False,allow_nan=False)

def sha(x):
    return hashlib.sha256(canonical(x).encode()).hexdigest()

class ProviderPreflightViolation(ValueError):
    pass

def require(p,reason):
    if not p: raise ProviderPreflightViolation(reason)

class Task15RealProviderPreflightDefaultDenyV1:
    """Construct a sealed *planning* manifest, never an execution capability."""

    def __init__(self, *, previous_pair, previous_ab, previous_b, model_config,
                 provider_credentials_present=False, consent_issued=False,
                 transport_mode="OFFLINE_NO_PROVIDER_TRANSPORT"):
        require(type(previous_pair) is dict and type(previous_ab) is dict
                and type(previous_b) is dict and type(model_config) is dict,
                "FROZEN_PLAIN_EVIDENCE_REQUIRED")
        require(transport_mode=="OFFLINE_NO_PROVIDER_TRANSPORT"
                and provider_credentials_present is False
                and consent_issued is False,
                "PROVIDER_CREDENTIALS_OR_CONSENT_CANNOT_ENTER_OFFLINE_PROOF")
        require(model_config.get("status")==
                    "EXACT_MODEL_CONFIGURATION_FROZEN_EXECUTION_GATE_CLOSED"
                and model_config.get("execution_gate")=="CLOSED"
                and model_config.get("model",{}).get("provider")=="openai"
                and model_config.get("model",{}).get("model_id")==MODEL
                and model_config.get("model",{}).get("snapshot_required") is True
                and model_config.get("sampling",{}).get("temperature")==0.0
                and model_config.get("sampling",{}).get("automatic_retry") is False
                and model_config.get("sampling",{}).get("fallback_model") is None
                and model_config.get("sampling",{}).get("post_result_model_switch") is False
                and type(model_config.get("budget",{}).get("provider_spend_cap_usd")) in (int,float)
                and model_config["budget"]["provider_spend_cap_usd"]==CAP_USD
                and model_config["budget"].get("hard_stop_on_cap") is True
                and model_config.get("secrets",{}).get("api_key_never_committed") is True
                and model_config.get("secrets",{}).get("api_key_never_written_to_evidence") is True,
                "EXACT_FROZEN_CLOSED_MODEL_AND_COST_CEILING_REQUIRED")
        require(previous_pair.get("rule_of_one")==SOURCE_RULE
                and previous_ab.get("rule_of_one")==AB_RULE
                and previous_b.get("rule_of_one")==B_RULE
                and previous_pair.get("determination")==
                    "EIGHT_LOCAL_A_BIND_COMMITS_JOINED_TO_EIGHT_B_BIND_BLOCKS"
                and previous_b.get("determination")==
                    "EIGHT_RCC_ALLOWED_BAD_PAYMENTS_ACTUALLY_BIND_BLOCKED_BEFORE_WRITE"
                and previous_ab.get("determination")==
                    "SIXTEEN_SYNTHETIC_POSTREAD_WRITES_RCC_REVIEWED_NOT_DISPATCHED"
                and previous_pair.get("source_proof_sha256")==sha(previous_ab)
                and previous_pair.get("prior_b_proof_sha256")==sha(previous_b)
                and previous_b.get("prior_proof_sha256")==sha(previous_ab)
                and previous_pair.get("cases")==
                    previous_pair.get("actual_a_bind_adjudications")==
                    previous_pair.get("local_a_native_commits")==
                    previous_pair.get("prior_actual_b_bind_blocks")==8
                and previous_pair.get("b_native_writes")==
                    previous_pair.get("network_or_bank_external_effects")==
                    previous_pair.get("real_provider_calls")==
                    previous_pair.get("scorer_calls")==0
                and previous_pair.get("model_generated_choices_authenticated") is False
                and previous_pair.get("canonical_final128_utility_measured") is False
                and previous_pair.get("injection_success_measured") is False
                and previous_b.get("bind_blocked")==8
                and previous_b.get("native_write_dispatches")==
                    previous_b.get("provider_calls")==
                    previous_b.get("scorer_calls")==0
                and previous_ab.get("case_count")==8
                and previous_ab.get("arm_proposal_count")==
                    previous_ab.get("rcc_review_count")==16
                and previous_ab.get("provider_calls")==
                    previous_ab.get("scorer_calls")==
                    previous_ab.get("native_write_dispatch_count")==0,
                "EXACT_PRIOR_SYNTHETIC_PROOF_CHAIN_REQUIRED")
        self._pair=copy.deepcopy(previous_pair)
        self._ab=copy.deepcopy(previous_ab)
        self._b=copy.deepcopy(previous_b)
        self._cfg=copy.deepcopy(model_config)
        self._hashes=tuple(sha(x) for x in
                           (previous_pair,previous_ab,previous_b,model_config))
        self._lock=RLock()
        self._attempted=False
        self._phase="READY"
        self._journal=[]

    def _verify(self):
        p,a,b=self._pair,self._ab,self._b
        require(len(p.get("records",[]))==len(a.get("proposals",[]))==
                len(b.get("records",[]))==8,
                "EXACT_EIGHT_CASES_REQUIRED")
        manifests=[]
        call_ids=set()
        for i,case in enumerate(CASES):
            row=a["proposals"][i]
            pa=p["records"][i]
            pb=b["records"][i]
            require(row["case_id"]==pa["case_id"]==pb["case_id"]==case
                    and list(row["arms"])==["A","B"]
                    and pa["a_bind_outcome"]==
                        pa["a_bind_receipt"]["final_outcome"]=="COMMITTED"
                    and pa["a_bind_receipt_sha256"]==sha(pa["a_bind_receipt"])
                    and pa["a_bind_receipt"]["authority_check_result"]["status"]=="pass"
                    and pa["a_bind_receipt"]["constraint_check_result"]["status"]=="pass"
                    and pa["a_native_apply_calls"]==1
                    and pa["a_native_postcondition_calls"]==1
                    and pa["a_native_prestate_sha256"]!=pa["a_native_poststate_sha256"]
                    and pb["bind_outcome"]==
                        pb["bind_receipt"]["final_outcome"]=="BLOCKED"
                    and pb["bind_receipt_sha256"]==sha(pb["bind_receipt"])
                    and pb["bind_receipt"]["constraint_check_result"]["status"]=="fail"
                    and pb["native_write_dispatch_count"]==0,
                    "PINNED_LOCAL_A_AND_B_EFFECT_BOUNDARY_REQUIRED")
            pair=[]
            for arm in ARMS:
                r=row["arms"][arm]
                messages=r["postread_request_messages"]
                tools=r["postread_request_tools"]
                assert_type=type(messages) is list and type(tools) is list
                require(assert_type
                        and len(messages)==4
                        and [m["role"] for m in messages]==
                            ["developer","user","assistant","tool"]
                        and len(tools)==2
                        and sorted(t["function"]["name"] for t in tools)==
                            ["send_money","update_user_info"]
                        and r["case_id"]==case
                        and r["arm"]==arm
                        and r["postread_request_sha256"]==
                            sha({"messages":messages,"tools":tools})
                        and r["candidate_sha256"]==sha(r["candidate_payload"])
                        and r["rcc_review_sha256"]==sha(r["rcc_review"])
                        and r["rcc_dispatch_allowed_by_hook"] is True
                        and r["prior_native_read_call_id"]==
                            messages[2]["tool_calls"][0]["id"]==
                            messages[3]["tool_call_id"]
                        and r["bind_permit_present"] is False
                        and r["native_write_dispatch_count"]==0
                        and r["live_model_authenticated"] is False,
                        "EXACT_OFFLINE_NATIVE_READ_REQUEST_AND_RCC_HASHES_REQUIRED")
                read_id=r["prior_native_read_call_id"]
                require(type(read_id) is str and read_id not in call_ids,
                        "NO_CROSS_CASE_OR_ARM_READ_CALL_ID_ALIAS")
                call_ids.add(read_id)
                require(r["prior_native_tool_return_sha256"]==
                            sha(messages[3]["content"][0]["text"]),
                        "EXACT_NATIVE_READ_TOOL_RESULT_REQUIRED")
                require(
                    (arm=="A" and pa["a_candidate_sha256"]==r["candidate_sha256"]
                     and pa["prior_a_read_call_id"]==read_id
                     and pa["prior_a_read_return_sha256"]==
                         r["prior_native_tool_return_sha256"])
                    or (arm=="B" and pb["candidate_sha256"]==r["candidate_sha256"]
                        and pb["prior_read_call_id"]==read_id
                        and pb["prior_native_result_sha256"]==
                            r["prior_native_tool_return_sha256"]),
                    "EXACT_BIND_TO_SOURCE_CANDIDATE_JOIN_REQUIRED")
                pair.append({
                    "case_id":case,"arm":arm,
                    "frozen_model_snapshot":MODEL,
                    "prior_native_read_call_id":read_id,
                    "prior_native_read_result_sha256":
                        r["prior_native_tool_return_sha256"],
                    "native_postread_request_sha256":r["postread_request_sha256"],
                    "native_tool_schemas_sha256":sha(tools),
                    "original_user_message_sha256":sha(messages[1]),
                    "prior_offline_candidate_sha256":r["candidate_sha256"],
                    "prior_offline_rcc_review_sha256":r["rcc_review_sha256"],
                    "offline_source_only":True,
                    "provider_response_authenticated":False,
                    "provider_request_issued":False,
                    "provider_response_received":False,
                    "provider_response_id":None,
                    "provider_usage":None,
                    "provider_charge_usd":None,
                    "provider_executable_authority":False,
                    "bind_permit_from_future_model":False,
                    "native_effect_dispatch_authorized":False,
                })
            manifests.extend(pair)
        require(len(manifests)==len(call_ids)==16,
                "ALL_SIXTEEN_CASE_ARM_REQUESTS_REQUIRED")
        return manifests

    def run(self):
        with self._lock:
            require(not self._attempted and self._phase=="READY",
                    "ONE_PREFLIGHT_ATTEMPT_ONLY")
            self._attempted=True
            self._phase="RUNNING"
        try:
            manifest=self._verify()
            require(tuple(sha(x) for x in
                          (self._pair,self._ab,self._b,self._cfg))==self._hashes,
                    "SOURCE_EVIDENCE_OR_MODEL_CONFIG_MUTATED")
            self._phase="CLOSED_UNAUTHENTICATED_PREFLIGHT_CAPTURE"
            self._journal.append("NO_PROVIDER_EXECUTION_PERMISSION_ISSUED")
            return {
                "rule_of_one":RULE,
                "determination":"SIXTEEN_TASK15_OFFLINE_REQUESTS_PINNED_REAL_PROVIDER_GATE_CLOSED",
                "predecessor_proof_sha256":self._hashes[0],
                "prior_ab_proof_sha256":self._hashes[1],
                "prior_b_proof_sha256":self._hashes[2],
                "model_configuration_sha256":self._hashes[3],
                "case_count":8,"case_arm_request_count":16,
                "model_id":MODEL,"budget_ceiling_usd":CAP_USD,
                "budget_ceiling_is_expenditure_authority":False,
                "operator_approval_issued":False,
                "single_use_provider_authority_issued":False,
                "permission_to_call_provider":False,
                "response_authenticity_proven":False,
                "model_candidate_observed":False,
                "transport_adapter_enabled":False,
                "real_provider_calls":0,"real_provider_charges_usd":0,
                "scorer_calls":0,"native_write_dispatches":0,
                "external_effects":0,
                "requests":manifest,
                "full_canonical_trajectory_proven":False,
                "final128_utility_measured":False,
                "injection_success_measured":False,
            }
        except BaseException:
            self._phase="TERMINAL_NO_PROMOTION"
            self._journal.append("INVALID_PREFLIGHT_NO_PERMISSION")
            raise

    def attempt_live_provider(self, *, transport=None, consent=None):
        del transport,consent
        raise ProviderPreflightViolation(
            "PROVIDER_EXECUTION_OUT_OF_SCOPE_FRESH_SEPARATE_AUTHORIZATION_REQUIRED")

    def observation(self):
        with self._lock:
            return {"phase":self._phase,"attempted":self._attempted,
                    "journal":copy.deepcopy(self._journal),
                    "retry_allowed":False,
                    "permission_to_call_provider":False,
                    "provider_calls":0,"provider_charges_usd":0,
                    "scorer_calls":0,"native_writes":0,"external_effects":0}
