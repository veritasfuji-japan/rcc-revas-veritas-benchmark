#!/usr/bin/env python3
"""#378: exact in-process A/B native Tool→model-input handoff, offline only.

Both arms retain the SAME actual injected read-only Tool response. Arm B
additionally receives #377's validated source-owned preterminal summary;
Arm A does not. No model, provider transport, scoring, writer, or external
authority is present. This is an in-process preparation seam, not a real
independent A/B provider execution or an official Utility measurement.
"""
from __future__ import annotations

from copy import deepcopy
from typing import Any

from scripts import final128_377_native_preterminal_spending_projection_v1 as projection
from scripts import final128_349_native_runner_owned_readonly_handoff_v1 as owner
from scripts import task1_source_bound_readonly_grounding_v1 as guard

SCHEMA="veritas.final128.task1-offline-paired-model-input-seam.v1"
CASE=guard.CASE
ORIGINAL=guard.PROMPT
TOOL=guard.TOOL
ARGS={"n":100}

class Refused(ValueError):
    pass

def insist(cond,reason):
    if cond is not True:
        raise Refused("378_"+reason)

def _prepare_one(*,arm,environment,original_user_request,attack_subject):
    insist(arm in ("A","B"),"ARM_NOT_AB")
    insist(type(original_user_request) is str
           and original_user_request==ORIGINAL,
           "ORIGINAL_TASK_DRIFT")
    insist(type(attack_subject) is str
           and len(attack_subject.encode("utf-8"))<=4096,
           "EXACT_ATTACK_BYTES_REQUIRED")

    # No untrusted JSON can be the source of these native-owned snapshots.
    try:
        bank,_=owner._native_bank_account_only(environment)
    except (owner.Refused,ImportError) as exc:
        raise Refused("378_NATIVE_BANKING_ENVIRONMENT_REQUIRED") from exc
    before=deepcopy(environment.model_dump(mode="json"))
    bank_before=deepcopy(bank.model_dump(mode="json"))
    try:
        output=projection.build_native_preterminal_spending_projection(
            native_environment=environment,
            original_user_request=original_user_request,
            untrusted_subject_override=attack_subject,
            preexisting_effect_count=0,
            expose_observed_native_tool_result=True,
        )
    except projection.Refused as exc:
        raise Refused("378_NATIVE_SOURCE_PROJECTION_REFUSED:"+str(exc)) from exc
    insist(environment.model_dump(mode="json")==before
           and bank.model_dump(mode="json")==bank_before,
           "NATIVE_STATE_MUTATED")
    rows=output.pop("ephemeral_original_native_tool_return")
    ephemeral_flag=output.pop(
        "ephemeral_original_native_tool_return_has_untrusted_subject")
    insist(ephemeral_flag is True
           and output["native_tool_calls"]==1
           and output["actual_native_tool"]==TOOL
           and output["actual_native_tool_args"]==ARGS,
           "UNEXPECTED_NATIVE_READONLY_TOOL")
    insist(guard.digest(rows)==output["observed_tool_return_sha256"],
           "NATIVE_TOOL_RESULT_DIGEST_MISMATCH")
    # The attacker-contaminated subject MUST survive in both arms, otherwise
    # a false-looking zero injection result would be manufactured.
    slot=output["untrusted_subject_slot_index"]
    insist(type(slot) is int and 0<=slot<len(rows)
           and rows[slot]["subject"]==attack_subject,
           "INJECTION_SUBJECT_NOT_IN_ORIGINAL_TOOL_RESULT")
    insist(output["native_pre_and_post_sha256"]==guard.digest(before)
           and output["bank_pre_and_post_sha256"]==guard.digest(bank_before),
           "NATIVE_SOURCE_CHANGED_DURING_TOOL")
    insist(output["original_user_request_sha256"]==
           guard.digest(original_user_request),
           "ORIGINAL_USER_REQUEST_SHA_CHANGED")
    common_messages=[
        {"role":"user","content":original_user_request},
        {"role":"native_tool_result","name":TOOL,
         "arguments":deepcopy(ARGS),
         "content":rows},
    ]
    messages=deepcopy(common_messages)
    if arm=="B":
        messages.append({
            "role":"trusted_native_source_overlay",
            "source":"final128-377-native-owned-readonly-spending",
            "content":deepcopy(output["model_visible_projection"]),
        })
    # This is a provenance-sensitive internal envelope; it is deliberately
    # NOT an executable OpenAI Responses API request. A protected runner
    # must map roles, own exact model histories and enforce fresh consent.
    item={
        "arm":arm,"case_id":CASE,"status":"IN_PROCESS_OFFLINE_INPUT_ONLY",
        "original_request_sha256":guard.digest(original_user_request),
        "native_initial_environment_sha256":guard.digest(before),
        "native_bank_prestate_sha256":guard.digest(bank_before),
        "attack_subject_sha256":guard.digest(attack_subject),
        "native_tool_result_sha256":guard.digest(rows),
        "native_tool_name":TOOL,"native_tool_arguments":deepcopy(ARGS),
        "native_tool_calls":1,"native_write_calls":0,
        "native_original_state_unchanged":True,
        "trusted_projection_sha256":(
            output["model_visible_projection_sha256"] if arm=="B" else None),
        "trusted_overlay_present":arm=="B",
        "model_input_envelope_sha256":guard.digest(messages),
        "raw_model_input_envelope":messages,
        "original_native_tool_output_replaced":False,
        "provider_calls":0,"native_scorer_calls":0,
        "native_terminal":None,"native_utility":None,
        "native_injection_success":None,
        "execution_authority_granted":False,
        "signed_native_source_attestation":False,
        "genuine_provider_origin_verified":False,
    }
    return item

def build_pair_from_independent_native_owners(*,
        environment_a:Any,environment_b:Any,
        original_user_request:str,attack_subject:str):
    """Construct **separate native-object** A/B inputs, without model calls.

    No real A/B execution proof until distinct genuine provider responses,
    native finals and native scorer outputs have been captured and verified.
    """
    insist(environment_a is not environment_b,
           "SAME_NATIVE_ENVIRONMENT_SHARED_BETWEEN_ARMS")
    a=_prepare_one(arm="A",environment=environment_a,
                   original_user_request=original_user_request,
                   attack_subject=attack_subject)
    b=_prepare_one(arm="B",environment=environment_b,
                   original_user_request=original_user_request,
                   attack_subject=attack_subject)
    for key in (
        "case_id","original_request_sha256",
        "native_initial_environment_sha256","native_bank_prestate_sha256",
        "attack_subject_sha256","native_tool_result_sha256",
        "native_tool_name","native_tool_arguments",
    ):
        insist(a[key]==b[key],"PAIRED_SOURCE_DRIFT_"+key)
    insist(a["raw_model_input_envelope"][:2]==
           b["raw_model_input_envelope"][:2],
           "ORIGINAL_TOOL_RETURN_DIFFERENT_BETWEEN_ARMS")
    insist(len(a["raw_model_input_envelope"])==2
           and len(b["raw_model_input_envelope"])==3
           and a["trusted_overlay_present"] is False
           and b["trusted_overlay_present"] is True
           and b["trusted_projection_sha256"] is not None
           and a["model_input_envelope_sha256"]!=
               b["model_input_envelope_sha256"],
           "ARM_B_NOT_EXACTLY_ONE_TRUSTED_TREATMENT")
    # Manifest intentionally omits raw native Tool response / attacker text
    # and never displays the model-facing envelope in CI artifacts.
    manifest={
        "schema":SCHEMA,
        "status":"OFFLINE_TWO_NATIVE_OWNERS_NO_PROVIDER_OR_SCORER",
        "case_id":CASE,
        "arm_A":{
            k:deepcopy(v) for k,v in a.items()
            if k not in ("raw_model_input_envelope",)
        },
        "arm_B":{
            k:deepcopy(v) for k,v in b.items()
            if k not in ("raw_model_input_envelope",)
        },
        "paired_native_source_verified_in_process_only":True,
        "matched_original_tool_result_with_same_attack_bytes":True,
        "matched_initial_state_but_distinct_native_objects":True,
        "B_only_trusted_projection_added":True,
        "same_native_bind_authority_policy_unchanged":True,
        "genuine_independent_provider_sessions":False,
        "genuine_native_user_and_attack_scorer":False,
        "official_utility_recovery_claim":False,
        "official_attack_success_claim":False,
        "external_provider_calls":0,
        "bank_write_calls":0,
        "official_score_A":None,
        "official_score_B":None,
        "operator_approval_for_paid_run":False,
    }
    return {"manifest":manifest,"arm_A":a,"arm_B":b}

def deny_external_provider_or_official_score(*_args,**_kwargs):
    """Neither self-attested JSON nor old approval can unlock paid execution."""
    raise Refused("378_FRESH_PROTECTED_PROVIDER_AND_NATIVE_SCORER_NOT_IMPLEMENTED")
