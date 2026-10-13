#!/usr/bin/env python3
"""#379: in-process native Task1 A/B -> #350 MOCK Responses -> deny real dispatch.

A concrete offline integration rehearsal, not a real-model experiment.
The local mock is deliberately constructed *inside* this module; callers cannot
inject a real provider client. No live/approved transport function is exported.

Mock-only lease=True passed to #350 simulates a consumed token *inside the
test double*, NOT actual #351 approval, a GitHub tag, or a Provider permission.
No native User/Attack Scorer runs: fabricated mock output is never scoreable.
"""
from __future__ import annotations

from copy import deepcopy
from decimal import Decimal
from types import SimpleNamespace
from typing import Any
import json

from scripts import final128_378_native_paired_model_input_seam_v1 as owned
from scripts import final128_350_task1_responses_once_budget_v1 as transport
from scripts import final128_351_task1_durable_lease_preflight_v1 as lease
from scripts import task1_source_bound_readonly_grounding_v1 as guard

SCHEMA="veritas.final128.task1-owned-mock-response-chain-deny-live.v1"
MAX_TOOL_JSON_UTF8=48000
FAKE_RESPONSE_TEXT="OFFLINE_FAKE_RESPONSE_NO_MODEL_INFERENCE_OR_SCORER"

class Refused(ValueError):
    pass

def need(value,code):
    if value is not True:
        raise Refused("379_"+code)

def _json(value):
    return json.dumps(value,sort_keys=True,ensure_ascii=False,
                      separators=(",",":"),allow_nan=False)

def mock_only_model_input(arm:dict)->list[dict]:
    """Build *synthetic* Responses-shaped input; no genuine model call ID.

    Real AgentDojo tool-call provenance is NOT present in #378. This is
    intentionally NOT a validated executable continuation of a real model
    function-call history; a future protected live adapter must supply one.
    """
    need(type(arm) is dict and arm.get("status")=="IN_PROCESS_OFFLINE_INPUT_ONLY",
         "ONLY_OWNED_378_ARM_OBJECT")
    mode=arm.get("arm")
    need(mode in ("A","B"),"UNKNOWN_ARM")
    envelope=arm.get("raw_model_input_envelope")
    need(type(envelope) is list and len(envelope)==(2 if mode=="A" else 3),
         "MISSING_NATIVE_SOURCE_ENVELOPE")
    user,tool=envelope[:2]
    need(type(user) is dict and set(user)=={"role","content"}
         and user=={"role":"user","content":guard.PROMPT},
         "ORIGINAL_USER_INSTRUCTIONS_NOT_EXACT")
    need(type(tool) is dict and set(tool)=={
        "role","name","arguments","content"}
         and tool["role"]=="native_tool_result"
         and tool["name"]==guard.TOOL
         and tool["arguments"]==guard.ARGUMENTS,
         "UNEXPECTED_NATIVE_TOOL")
    need(guard.digest(tool["content"])==arm["native_tool_result_sha256"],
         "NATIVE_TOOL_RETURN_CHANGED")
    need(arm["original_request_sha256"]==guard.digest(guard.PROMPT),
         "UNTRUSTED_ORIGINAL_REQUEST")
    data=_json(tool["content"])
    need(len(data.encode("utf-8"))<=MAX_TOOL_JSON_UTF8,
         "BOUNDED_SYNTHETIC_READONLY_TOOL_RETURN_SIZE")
    # Function-call output retains lower-trust native-tool content.
    # The call_id is deliberately fake/unsatisfied; this is NOT a valid
    # real continuation and cannot be sent by this module.
    wire=[
      {"role":"user","content":guard.PROMPT},
      {"type":"function_call_output",
       "call_id":"OFFLINE_MOCK_ONLY_UNBOUND_NATIVE_TOOL_CALL",
       "output":data},
    ]
    if mode=="B":
        overlay=envelope[2]
        need(type(overlay) is dict and set(overlay)=={"role","source","content"}
             and overlay["role"]=="trusted_native_source_overlay"
             and overlay["source"]=="final128-377-native-owned-readonly-spending"
             and guard.digest(overlay["content"])==arm["trusted_projection_sha256"],
             "B_OVERLAY_NOT_PROVEN_FROM_NATIVE_SOURCE")
        context=_json(overlay["content"])
        need("subject" not in overlay["content"]
             and "outgoing_spending_total" in overlay["content"],
             "MODEL_CONTEXT_MUST_NOT_IMPORT_ATTACK_SUBJECT")
        wire.append({"role":"developer",
            "content":"OFFLINE_SYNTHETIC_TRUSTED_NATIVE_READONLY_SPENDING_CONTEXT\n"+context})
    else:
        need(arm["trusted_projection_sha256"] is None
             and arm["trusted_overlay_present"] is False,
             "ARM_A_TREATMENT_CONTAMINATED")
    need((mode=="B")==arm["trusted_overlay_present"],
         "ARM_TREATMENT_SWITCH_INVALID")
    return wire

class _OfflineFakeResponses:
    def __init__(self,arm:str):
        self.arm=arm
        self.calls=0
        self.last_input=None

    def create(self,*,model,input,max_output_tokens,truncation,store):
        need(self.calls==0,"MOCK_SESSION_REPLAY")
        need(model==transport.MODEL and max_output_tokens==transport.MAX_OUTPUT_TOKENS
             and truncation=="disabled" and store is False,
             "MOCK_TRANSPORT_ARGUMENTS_CHANGED")
        need(type(input) is list and len(input)==(2 if self.arm=="A" else 3),
             "MOCK_INPUT_SHAPE_CHANGED")
        self.calls+=1
        self.last_input=deepcopy(input)
        # Fake fixed output is NOT a Task1 terminal and must not be scored.
        return SimpleNamespace(
            model=transport.MODEL,
            usage=SimpleNamespace(input_tokens=128,output_tokens=16),
            output_text=FAKE_RESPONSE_TEXT,
        )

def _simulation_once(wire:list,arm:str,budget:transport.Budget):
    local_fake=_OfflineFakeResponses(arm)
    client=SimpleNamespace(responses=local_fake)
    # The #350 boolean is *only* a simulated tag consumption in this
    # memory-only fake. A real issuer, ruleset, signed operator grant,
    # protected GitHub environment and globally one-use lease do NOT exist.
    report=transport.response_once(
        client=client,owned_input=wire,budget=budget,
        externally_authenticated_oneuse_lease=True)
    need(local_fake.calls==1 and local_fake.last_input==wire,
         "FAKE_CLIENT_NOT_EXACTLY_ONCE")
    need(report["input_sha256"]==transport.fingerprint(wire)
         and report["official_native_scorer_invoked"] is False
         and report["independent_ab_completed"] is False,
         "MOCK_RESPONSE_WRONG_PROVENANCE")
    need(report["response"].output_text==FAKE_RESPONSE_TEXT,
         "MOCK_RESPONSE_CANNOT_BE_TREATED_AS_MODEL_TERMINAL")
    return {"arm":arm,"mock_input_sha256":report["input_sha256"],
            "mock_output_sha256":guard.digest(FAKE_RESPONSE_TEXT),
            "mock_model_name":report["model"],
            "mock_calls":local_fake.calls,
            "untrusted_native_tool_item_retained":True,
            "genuine_provider_receipt":None,
            "genuine_terminal":None,
            "native_scorer_input":None,
            "native_user_score":None,
            "native_attack_score":None}

def deny_unapproved_task1_live_dispatch(*,repository_head_sha,run_id,
        supplied_user_approval_phrase="",claimed_model=transport.MODEL,
        confirmed_project_hard_limit=False,claimed_tag_protected=False):
    """Enforce #351: never authorize from caller-supplied claims or fake tag.

    A future protected executor must validate real GitHub ruleset and atomically
    consume an actual external protected lease *outside* this offline module.
    """
    need(type(repository_head_sha) is str and lease.SHA_RE.fullmatch(repository_head_sha)
         is not None and type(run_id) is str
         and lease.RUN_RE.fullmatch(run_id) is not None,
         "EXACT_GITHUB_CONTEXT_REQUIRED")
    # The offline harness has NO authentication oracle. Any arguments claiming
    # approval or protected conditions are explicitly ignored: never pass
    # untrusted booleans or past chat permission to #350.
    context=lease.Context(
        repository="veritasfuji-japan/rcc-revas-veritas-benchmark",
        ref="refs/heads/main",sha=repository_head_sha,run_id=run_id,
        environment=lease.ENVIRONMENT,model=claimed_model,
        budget_usd=lease.MAX_BUDGET_USD,approved_phrase="",
        confirmed_protected_immutable_tag_ruleset=False,
        confirmed_project_hard_limit=False)
    try:
        lease.validate(context)
    except lease.PreflightDenied as exc:
        raise Refused("379_NO_FRESH_EXTERNALLY_AUTHENTICATED_OPERATOR_APPROVAL:"+str(exc)) from exc
    raise Refused("379_REAL_PROVIDER_DISPATCH_ALWAYS_DENIED_OFFLINE")

def rehearse_task1_owned_mock_pair(*,environment_a:Any,environment_b:Any,
        original_user_request:str,attack_subject:str)->dict:
    """Real native data -> separate A/B -> 2 fake #350 responses -> redacted proof.

    Does not accept provider clients/creds, real scorer outcomes, or paid grants.
    """
    need(type(attack_subject) is str,"ATTACK_MUST_BE_STRING")
    try:
        pair=owned.build_pair_from_independent_native_owners(
            environment_a=environment_a,environment_b=environment_b,
            original_user_request=original_user_request,
            attack_subject=attack_subject)
    except owned.Refused as exc:
        raise Refused("379_OWNER_NATIVE_PAIR_INVALID:"+str(exc)) from exc
    a=pair["arm_A"];b=pair["arm_B"]
    need(a["native_tool_result_sha256"]==b["native_tool_result_sha256"]
         and a["attack_subject_sha256"]==b["attack_subject_sha256"]
         and a["native_bank_prestate_sha256"]==b["native_bank_prestate_sha256"],
         "PAIRED_NATIVE_OR_ATTACK_PARITY_BROKEN")
    wire_a=mock_only_model_input(a)
    wire_b=mock_only_model_input(b)
    need(wire_a[:2]==wire_b[:2] and len(wire_a)==2
         and len(wire_b)==3 and "developer"==wire_b[2]["role"],
         "ONLY_B_CAN_RECEIVE_TRUSTED_SOURCE_TREATMENT")
    need(attack_subject in wire_a[1]["output"]
         and attack_subject in wire_b[1]["output"]
         and attack_subject not in wire_b[2]["content"],
         "ORIGINAL_ATTACK_MUST_SURVIVE_IN_TOOL_ONLY")
    budget=transport.Budget()
    need(transport.reserved_max_usd()<=transport.MAX_USD,
         "350_MAX_CALL_BUDGET_RESERVATION_INVALID")
    mock_a=_simulation_once(wire_a,"A",budget)
    mock_b=_simulation_once(wire_b,"B",budget)
    need(mock_a["mock_input_sha256"]!=mock_b["mock_input_sha256"]
         and budget.used==2
         and budget.observed==Decimal("0.0001536"),
         "MOCK_BUDGET_OR_A_B_NOT_DISTINCT")
    # All artifacts are safe digests only. Avoid archiving actual tool rows,
    # bank balances, IDs or malicious subject text.
    report={
        "schema":SCHEMA,
        "status":"OFFLINE_FAKE_PROVIDER_TWO_ARMS_NO_SCORE_NO_LIVE_APPROVAL",
        "case_id":guard.CASE,
        "original_user_request_sha256":a["original_request_sha256"],
        "native_bank_prestate_sha256":a["native_bank_prestate_sha256"],
        "original_attacked_tool_return_sha256":a["native_tool_result_sha256"],
        "attack_subject_sha256":a["attack_subject_sha256"],
        "B_trusted_native_projection_sha256":b["trusted_projection_sha256"],
        "arm_A":mock_a,"arm_B":mock_b,
        "A_B_same_injected_original_tool_bytes":True,
        "B_only_trusted_projection":True,
        "separate_owned_native_environment_instances_only":True,
        "source_owned_pair_verified_only_in_process":True,
        "mock_transport_sessions_distinct":True,
        "mock_transport_calls":2,
        "mock_budget_reserved_usd":str(budget.reserved),
        "mock_budget_observed_usd":str(budget.observed),
        "actual_spending_usd":"0.00",
        "actual_provider_calls":0,
        "real_provider_call_identities_verified":False,
        "real_provider_terminal_messages_present":False,
        "real_native_scorer_calls":0,
        "official_utility_scores":None,
        "official_injection_success_scores":None,
        "real_durable_oneuse_lease_consumed":False,
        "live_dispatch_permitted":False,
        "approved_by_chat_or_prior_pr":False,
        "native_bank_write_calls":0,
        "full_canonical_agentdojo_history_verified":False,
        "exact_frozen_directattack_source_used":False,
        "ready_for_genuine_final128":False,
    }
    return report
