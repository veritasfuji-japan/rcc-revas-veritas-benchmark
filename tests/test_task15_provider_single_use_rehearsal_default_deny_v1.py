"""Offline-only single-use rehearsal; never issuer of a live Provider capability."""
from __future__ import annotations
import copy
import json
import os
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from pathlib import Path
import pytest

if os.environ.get("TASK15_SINGLE_USE_REHEARSAL_PROOF")!="1":
    pytest.skip("Dedicated pinned Task15 offline rehearsal only",
                allow_module_level=True)

from task15_provider_single_use_rehearsal_default_deny_v1 import (
    RULE,MODEL_ID,CASES,HISTORICAL_LIMIT_MICRO_USD,sha,
    RehearsalViolation,Task15ProviderSingleUseRehearsalV1,
)

@pytest.fixture(scope="module")
def prior():
    root=Path(os.environ["TASK15_SINGLE_USE_REHEARSAL_PREDECESSOR_DIR"])
    source=root/"task15-real-provider-preflight-default-deny-v1.evidence.jsonl"
    lines=[json.loads(x) for x in source.read_text().splitlines()]
    assert len(lines)==1
    return lines[0]["proof"]

@pytest.fixture(autouse=True)
def no_external_credentials_or_provider_transport(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY","")
    monkeypatch.setenv("VERITAS_DATABASE_URL","")
    # A network request is a test failure even if a dependency later imports one.
    import socket
    def prohibited(*_args,**_kwargs):
        raise AssertionError("ANY_REAL_NETWORK_REQUEST_IS_FORBIDDEN")
    monkeypatch.setattr(socket.socket,"connect",prohibited)
    monkeypatch.setattr(socket,"create_connection",prohibited)

def save(which,record):
    name=os.environ.get("TASK15_SINGLE_USE_REHEARSAL_"+which)
    if name:
        with Path(name).open("a") as f:
            f.write(json.dumps(record,sort_keys=True)+"\n")

def test_one_in_memory_consumption_under_sixteen_competing_threads(prior):
    runner=Task15ProviderSingleUseRehearsalV1(prior=copy.deepcopy(prior))
    proposal=runner.draft()
    assert proposal["case_id"]==CASES[0] and proposal["arm"]=="A"
    assert proposal["frozen_model_snapshot"]==MODEL_ID
    assert proposal["max_cost_micro_usd"]==HISTORICAL_LIMIT_MICRO_USD
    assert proposal["kind"]=="NON_EXECUTABLE_OFFLINE_REHEARSAL_PROPOSAL"
    assert proposal["trusted_issuer_present"] is False
    assert proposal["trusted_human_approval_attested"] is False
    assert proposal["live_provider_authority_issued"] is False
    assert proposal["native_bank_execution_authority_issued"] is False
    assert proposal["transport_adapter_present"] is False
    assert proposal["historical_ceiling_is_not_spend_permission"] is True
    assert proposal["predecessor_proof_sha256"]==sha(prior)
    with pytest.raises(RehearsalViolation,match="ONE_DRAFT_PER_REHEARSAL_ONLY"):
        runner.draft()

    barrier=Barrier(16)
    def compete(_):
        # Require all sixteen actual worker threads at the same start gate.
        # Without this, a threadpool can pass the test purely sequentially.
        barrier.wait(timeout=20)
        try:
            return runner.consume_rehearsal(proposal=copy.deepcopy(proposal))
        except RehearsalViolation as ex:
            assert str(ex)=="REHEARSAL_ONCE_ONLY_NO_RETRY"
            return None
    with ThreadPoolExecutor(max_workers=16) as pool:
        outcomes=list(pool.map(compete,range(16)))
    successes=[x for x in outcomes if x is not None]
    assert len(successes)==1
    result=successes[0]
    assert result["rule_of_one"]==RULE
    assert result["determination"]=="ONE_LOCAL_REHEARSAL_CONSUMED_PROVIDER_AUTHORITY_ABSENT"
    assert result["plan_sha256"]==sha(proposal)
    assert result["predecessor_proof_sha256"]==sha(prior)
    assert result["case_id"]==CASES[0] and result["arm"]=="A"
    assert result["model_snapshot"]==MODEL_ID
    assert result["local_rehearsal_consumed"] is True
    assert result["in_memory_single_use_only"] is True
    assert result["durable_replay_protection_proven"] is False
    for name in ("human_approval_verified","live_provider_capability_issued",
                 "permission_to_call_provider","provider_request_sent",
                 "provider_response_authenticated","canonical_final128_measured"):
        assert result[name] is False
    for name in ("provider_calls","provider_charges_usd",
                 "native_write_dispatch_count","scorer_calls","external_effects"):
        assert result[name]==0
    assert runner.observation()["state"]=="REHEARSAL_CONSUMED_NO_TRANSPORT"
    assert runner.observation()["consumed"] is True
    with pytest.raises(RehearsalViolation,match="REHEARSAL_ONCE_ONLY_NO_RETRY"):
        runner.consume_rehearsal(proposal=proposal)
    with pytest.raises(RehearsalViolation,match="FRESH_EXTERNAL_APPROVAL_AND_SEPARATE_TRANSPORT_PR_REQUIRED"):
        runner.attempt_live_provider(transport=object(),approval=object())
    assert runner.observation()["provider_calls"]==0
    save("EVIDENCE",{"proof":result,
                     "plan":proposal,
                     "concurrent_attempts":16,
                     "concurrency_barrier_parties":barrier.parties,
                     "rehearsals_consumed":1,
                     "replay_refusals":15})

@pytest.mark.parametrize("fault",[
    "wrong_model","wrong_case","wrong_arm","over_cap","bool_cap",
    "forged_nonce","forged_request_hash","forged_approval",
    "forged_transport_bit","expired","premature",
    "prior_source_claims_live","parent_case_swap","direct_live_transport",
])
def test_fourteen_fail_closed_consume_and_transport_bypasses(prior,fault):
    data=copy.deepcopy(prior)
    if fault=="prior_source_claims_live":
        data["requests"][0]["provider_response_authenticated"]=True
    elif fault=="parent_case_swap":
        data["requests"][0]["case_id"]=CASES[1]
    if fault in ("prior_source_claims_live","parent_case_swap"):
        with pytest.raises(RehearsalViolation):
            Task15ProviderSingleUseRehearsalV1(prior=data)
        stage="PREDECESSOR_NOT_ELIGIBLE"
    else:
        runner=Task15ProviderSingleUseRehearsalV1(prior=data)
        if fault=="direct_live_transport":
            with pytest.raises(RehearsalViolation,match="FRESH_EXTERNAL_APPROVAL_AND_SEPARATE_TRANSPORT_PR_REQUIRED"):
                runner.attempt_live_provider(transport=object(),approval="FORGED")
            assert runner.observation()["state"]=="READY"
            stage="LIVE_DISPATCH_FORBIDDEN"
        elif fault in ("wrong_model","wrong_case","wrong_arm",
                       "over_cap","bool_cap","forged_nonce"):
            kwargs={
                "wrong_model":{"model_id":"gpt-4.1-mini"},
                "wrong_case":{"case_id":"banking:user_task_15:forged"},
                "wrong_arm":{"arm":"C"},
                "over_cap":{"max_cost_micro_usd":5000001},
                "bool_cap":{"max_cost_micro_usd":True},
                "forged_nonce":{"nonce":"SIGNATURE_NOT_VALID"},
            }[fault]
            with pytest.raises(RehearsalViolation):
                runner.draft(**kwargs)
            assert runner.observation()["state"]=="READY"
            assert runner.observation()["consumed"] is False
            stage="DRAFT_REJECTED"
        else:
            plan=runner.draft()
            now="2026-10-09T12:24:00+00:00"
            if fault=="forged_request_hash":
                plan["source_request_sha256"]="0"*64
            elif fault=="forged_approval":
                plan["trusted_human_approval_attested"]=True
            elif fault=="forged_transport_bit":
                plan["transport_adapter_present"]=True
            elif fault=="expired":
                now="2026-10-09T12:29:00+00:00"
            elif fault=="premature":
                now="2026-10-09T12:23:59+00:00"
            with pytest.raises(RehearsalViolation):
                runner.consume_rehearsal(proposal=plan,now=now)
            obs=runner.observation()
            assert obs["state"]=="TERMINAL_FAILED_CONSUMED_NO_TRANSPORT"
            assert obs["consumed"] is True
            assert obs["provider_calls"]==obs["provider_charges_usd"]==0
            with pytest.raises(RehearsalViolation,match="REHEARSAL_ONCE_ONLY_NO_RETRY"):
                runner.consume_rehearsal(proposal=plan)
            stage="CONSUME_BURNED_NO_RETRY"
        obs=runner.observation()
        assert obs["provider_authority_issued"] is False
        assert obs["provider_calls"]==obs["provider_charges_usd"]==0
        assert obs["native_bank_writes"]==obs["external_effects"]==0
        assert obs["durable_replay_protection_proven"] is False
    save("REFUSALS",{"fault":fault,"stage":stage,
                    "result":"NO_LIVE_PROVIDER_CAPABILITY"})
