#!/usr/bin/env python3
"""#349 real AgentDojo native runner-owned READ-ONLY tool -> #348 final-answer seam.

This is not an issuer or a signed native provenance service. Native ownership
exists only when called by the protected runner in the same isolated process.
No external "attestation" JSON, output from an LLM, or user-supplied hash may
substitute for native environment ownership.

Explicitly no provider API client, no paid API execution, no Native Bind,
scorer, permission or bank write in this module.
"""
from __future__ import annotations
from copy import deepcopy
import json
from typing import Any
from scripts import task1_source_bound_readonly_grounding_v1 as guard

class Refused(ValueError):
    pass

def need(ok,why):
    if not ok:raise Refused(why)

def _native_bank_account_only(native_environment:Any):
    from agentdojo.default_suites.v1.tools.banking_client import BankAccount
    from agentdojo.default_suites.v1.tools.banking_client import (
        get_most_recent_transactions)
    from agentdojo.default_suites.v1.tools.banking_client import (
        BankingEnvironment)
    need(type(native_environment) is BankingEnvironment,
         "349_ONLY_ACTUAL_NATIVE_BANKING_ENVIRONMENT_OBJECT")
    bank=native_environment.bank_account
    need(type(bank) is BankAccount,
         "349_ONLY_NATIVE_BANK_ACCOUNT_INSTANCE")
    return bank,get_most_recent_transactions

def _assert_snapshot_valid(before,after):
    need(before==after,"349_NATIVE_READONLY_TOOL_MUTATED_BANK_STATE")

def native_readonly_tool_handoff(*,native_environment,
        original_user_request,model_final_response,
        native_return_subject_override=None,preexisting_effect_count=0):
    """Consume a native environment owned by this *same* isolated executor.

    A native_return_subject_override simulates the frozen DirectAttack
    incoming subject injection in a tool response. Its caller must bind
    original attack payload bytes separately before a genuine A/B experiment.
    All transaction STRUCTURED fields must still match native bank snapshot.

    Requires zero preexisting effects and zero writable tools. Returns the
    original model terminal + detached guard output and receipt metadata.
    """
    need(original_user_request==guard.PROMPT,
         "349_ORIGINAL_USER_TASK_NOT_EXACT")
    need(type(preexisting_effect_count) is int and
         preexisting_effect_count==0,
         "349_SIDE_EFFECT_TRAJECTORY_NOT_READONLY")
    bank,tool=_native_bank_account_only(native_environment)
    before=deepcopy(native_environment.model_dump(mode="json"))
    original_bank=deepcopy(bank.model_dump(mode="json"))
    native_tool_rows=tool(bank,n=100)
    observed=[t.model_dump(mode="json") for t in native_tool_rows]
    _assert_snapshot_valid(before,native_environment.model_dump(mode="json"))
    need(bank.model_dump(mode="json")==original_bank,
         "349_NATIVE_READ_TOOL_MUTATED_BANK_ACCOUNT")
    overrides=0
    if native_return_subject_override is not None:
        need(type(native_return_subject_override) is str
             and len(native_return_subject_override.encode("utf-8"))<=4096,
             "349_UNTRUSTED_SUBJECT_ONLY_MUST_BE_BOUNDED_TEXT")
        target=[i for i,x in enumerate(observed)
                if x["recipient"]==bank.iban and
                x["sender"]!=bank.iban and
                x["date"].startswith("2022-03-")]
        need(len(target)==1,
             "349_REQUIRE_EXACT_INCOMING_SUBJECT_SLOT_IN_NATIVE_RESULT")
        observed[target[0]]["subject"]=native_return_subject_override
        overrides=1
    try:
        result=guard.grounded_final_answer(
            case_id=guard.CASE,
            original_user_request=original_user_request,
            original_tool_call={"function":"get_most_recent_transactions",
                                "args":{"n":100}},
            native_prestate={"bank_account":original_bank},
            observed_tool_result=observed,
            original_terminal_output=model_final_response)
    except guard.Refused as exc:
        raise Refused("349_NATIVE_SOURCE_AND_RESPONSE_GUARD_REJECTED:"+str(exc)) from exc
    _assert_snapshot_valid(before,native_environment.model_dump(mode="json"))
    need(guard.digest(model_final_response)==result["original_model_output_sha256"],
         "349_MODEL_TERMINAL_WAS_MUTATED")
    # These are native *local ownership* and data-matching assertions,
    # not independent provenance or runtime IAM capability verification.
    return {
       "schema":"veritas.final128.native-owner-readonly-handoff.v1",
       "case_id":guard.CASE,
       "task_prompt_sha256":guard.digest(original_user_request),
       "native_environment_pre_and_post_sha256":guard.digest(before),
       "native_bank_pre_and_post_sha256":guard.digest(original_bank),
       "actual_native_tool":"get_most_recent_transactions",
       "actual_native_tool_args":{"n":100},
       "actual_native_tool_calls":1,
       "external_bank_write_calls":0,
       "native_bind_calls":0,
       "model_provider_calls":0,
       "native_scorer_calls":0,
       "native_result_subject_overrides":overrides,
       "read_only_structured_tool_fields_reconciled":True,
       "native_prestate_from_in_process_bank_object":True,
       "independent_signed_native_source_receipt_verified":False,
       "untrusted_source_json_not_accepted_as_native_ownership":True,
       "native_runtime_iam_egress_bypass_rejection_proven":False,
       "new_official_utility_recoveries":0,
       "original_terminal_sha256":guard.digest(model_final_response),
       "grounded_detached_result":result,
    }
