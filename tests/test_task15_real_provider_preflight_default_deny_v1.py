"""Provider-free Task15 real-model-source preflight: 16 source requests, 14 denials."""
from __future__ import annotations
import copy
import json
import os
from pathlib import Path
import pytest

if os.environ.get("TASK15_REAL_PROVIDER_PREFLIGHT_PROOF")!="1":
    pytest.skip("Only frozen zero-provider Task15 preflight CI",allow_module_level=True)

from task15_real_provider_preflight_default_deny_v1 import (
    RULE,CASES,ARMS,MODEL,CAP_USD,sha,
    ProviderPreflightViolation,Task15RealProviderPreflightDefaultDenyV1,
)

@pytest.fixture(scope="module")
def sources():
    root=Path(os.environ["TASK15_REAL_PROVIDER_PREFLIGHT_PREDECESSOR_DIR"])
    def load(n):
        f=root/(n+".evidence.jsonl")
        obj=[json.loads(s) for s in f.read_text().splitlines()]
        assert len(obj)==1
        return obj[0]["proof"]
    config=json.loads((Path(__file__).resolve().parents[1]/
        "contracts/AGENTDOJO_EXACT_MODEL_CONFIGURATION_v0.1.json").read_text())
    return {
        "previous_pair":load("task15-postread-a-bind-commit-b-refusal-pair-v1"),
        "previous_ab":load("task15-offline-postread-rcc-quarantine-v1"),
        "previous_b":load("task15-postread-actual-bind-refusal-v1"),
        "model_config":config
    }

def save(which,entry):
    name=os.environ.get("TASK15_REAL_PROVIDER_PREFLIGHT_"+which)
    if name:
        with Path(name).open("a") as h:h.write(json.dumps(entry,sort_keys=True)+"\n")

def test_sixteen_pinned_requests_have_zero_live_provider_authorization(sources,monkeypatch):
    for name in ("OPENAI_API_KEY","VERITAS_DATABASE_URL"):
        monkeypatch.delenv(name,raising=False)
    obj=Task15RealProviderPreflightDefaultDenyV1(**copy.deepcopy(sources))
    proof=obj.run()
    assert proof["rule_of_one"]==RULE
    assert proof["determination"]=="SIXTEEN_TASK15_OFFLINE_REQUESTS_PINNED_REAL_PROVIDER_GATE_CLOSED"
    assert proof["case_count"]==8 and proof["case_arm_request_count"]==16
    assert proof["model_id"]==MODEL
    assert proof["budget_ceiling_usd"]==CAP_USD
    assert proof["budget_ceiling_is_expenditure_authority"] is False
    assert proof["operator_approval_issued"] is False
    assert proof["single_use_provider_authority_issued"] is False
    assert proof["permission_to_call_provider"] is False
    assert proof["response_authenticity_proven"] is False
    assert proof["model_candidate_observed"] is False
    assert proof["transport_adapter_enabled"] is False
    assert proof["real_provider_calls"]==proof["real_provider_charges_usd"]==0
    assert proof["scorer_calls"]==proof["native_write_dispatches"]==proof["external_effects"]==0
    assert proof["full_canonical_trajectory_proven"] is False
    assert proof["final128_utility_measured"] is False
    assert proof["injection_success_measured"] is False
    assert proof["predecessor_proof_sha256"]==sha(sources["previous_pair"])
    assert proof["prior_ab_proof_sha256"]==sha(sources["previous_ab"])
    assert proof["prior_b_proof_sha256"]==sha(sources["previous_b"])
    assert proof["model_configuration_sha256"]==sha(sources["model_config"])
    keys=set()
    for i,case in enumerate(CASES):
        for j,arm in enumerate(ARMS):
            r=proof["requests"][i*2+j]
            old=sources["previous_ab"]["proposals"][i]["arms"][arm]
            assert (r["case_id"],r["arm"])==(case,arm)
            assert r["frozen_model_snapshot"]==MODEL
            assert r["prior_native_read_call_id"]==old["prior_native_read_call_id"]
            assert r["prior_native_read_result_sha256"]==old["prior_native_tool_return_sha256"]
            assert r["native_postread_request_sha256"]==old["postread_request_sha256"]
            assert r["native_tool_schemas_sha256"]==sha(old["postread_request_tools"])
            assert r["original_user_message_sha256"]==sha(old["postread_request_messages"][1])
            assert r["prior_offline_candidate_sha256"]==old["candidate_sha256"]
            assert r["prior_offline_rcc_review_sha256"]==old["rcc_review_sha256"]
            assert r["offline_source_only"] is True
            for name in ("provider_response_authenticated","provider_request_issued",
                         "provider_response_received","provider_executable_authority",
                         "bind_permit_from_future_model","native_effect_dispatch_authorized"):
                assert r[name] is False
            assert r["provider_response_id"] is r["provider_usage"] is r["provider_charge_usd"] is None
            assert r["prior_native_read_call_id"] not in keys
            keys.add(r["prior_native_read_call_id"])
    assert len(keys)==16
    with pytest.raises(ProviderPreflightViolation,match="ONE_PREFLIGHT_ATTEMPT_ONLY"):
        obj.run()
    save("EVIDENCE",{"proof":proof})

@pytest.mark.parametrize("fault",[
    "wrong_model","cost_increase","auto_retry","fallback_enabled",
    "model_alias","gate_open","credentials_present","consent_self_attested",
    "prior_b_outcome_forged","prior_a_candidate_forged",
    "read_call_id_substituted","native_tool_schema_forged",
    "claims_authenticated_model","provider_call_attempt"
])
def test_fourteen_strict_closed_gate_refusals_without_transport(sources,fault):
    src=copy.deepcopy(sources)
    extra={}
    if fault=="wrong_model":
        src["model_config"]["model"]["model_id"]="gpt-4.1-mini"
    elif fault=="cost_increase":
        src["model_config"]["budget"]["provider_spend_cap_usd"]=6.0
    elif fault=="auto_retry":
        src["model_config"]["sampling"]["automatic_retry"]=True
    elif fault=="fallback_enabled":
        src["model_config"]["sampling"]["fallback_model"]="arbitrary"
    elif fault=="model_alias":
        src["model_config"]["model"]["snapshot_required"]=False
    elif fault=="gate_open":
        src["model_config"]["execution_gate"]="OPEN"
    elif fault=="credentials_present":
        extra["provider_credentials_present"]=True
    elif fault=="consent_self_attested":
        extra["consent_issued"]=True
    elif fault=="prior_b_outcome_forged":
        src["previous_b"]["records"][7]["bind_outcome"]="COMMITTED"
    elif fault=="prior_a_candidate_forged":
        src["previous_pair"]["records"][7]["a_candidate_sha256"]="0"*64
    elif fault=="read_call_id_substituted":
        src["previous_ab"]["proposals"][7]["arms"]["B"]["prior_native_read_call_id"]="counterfeit"
        # Recalculate all declared source-parent digests to demonstrate that
        # hash integrity alone is not authority or native call-ID continuity.
        src["previous_pair"]["source_proof_sha256"]=sha(src["previous_ab"])
        src["previous_b"]["prior_proof_sha256"]=sha(src["previous_ab"])
        src["previous_pair"]["prior_b_proof_sha256"]=sha(src["previous_b"])
    elif fault=="native_tool_schema_forged":
        src["previous_ab"]["proposals"][7]["arms"]["A"]["postread_request_tools"][0]["function"]["description"]="forged"
        src["previous_pair"]["source_proof_sha256"]=sha(src["previous_ab"])
        src["previous_b"]["prior_proof_sha256"]=sha(src["previous_ab"])
        src["previous_pair"]["prior_b_proof_sha256"]=sha(src["previous_b"])
    elif fault=="claims_authenticated_model":
        src["previous_pair"]["model_generated_choices_authenticated"]=True
    elif fault=="provider_call_attempt":
        obj=Task15RealProviderPreflightDefaultDenyV1(**src)
        with pytest.raises(ProviderPreflightViolation,match="PROVIDER_EXECUTION_OUT_OF_SCOPE"):
            obj.attempt_live_provider(transport=object(),consent="forged")
        assert obj.observation()["permission_to_call_provider"] is False
        assert obj.observation()["provider_calls"]==0
        save("REFUSALS",{"fault":fault,"stage":"LIVE_PROVIDER_DISPATCH_IMPOSSIBLE",
             "result":"NO_PROVIDER_AUTHORITY_PROMOTION"})
        return
    try:
        obj=Task15RealProviderPreflightDefaultDenyV1(**src,**extra)
    except ProviderPreflightViolation:
        stage="CONSTRUCTOR_PREFLIGHT_REJECTED"
    else:
        with pytest.raises(ProviderPreflightViolation):
            obj.run()
        state=obj.observation()
        assert state["phase"]=="TERMINAL_NO_PROMOTION"
        assert state["permission_to_call_provider"] is False
        assert state["provider_calls"]==state["provider_charges_usd"]==0
        with pytest.raises(ProviderPreflightViolation,match="ONE_PREFLIGHT_ATTEMPT_ONLY"):
            obj.run()
        stage="ONE_SHOT_SOURCE_PREFLIGHT_REJECTED"
    save("REFUSALS",{"fault":fault,"stage":stage,
         "result":"NO_PROVIDER_AUTHORITY_PROMOTION"})
