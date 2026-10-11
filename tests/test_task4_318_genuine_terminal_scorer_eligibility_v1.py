"""#318: existing true A/B third model proposals do not contain terminal scorer inputs.

Only in source-pinned read-only CI. Real third model replies never modified or
retroactively authorized. No real Provider or native effect.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import zipfile
import pytest

if os.environ.get("TASK4_318_GENUINE_TERMINAL_PROOF")!="1":
    pytest.skip("#318 read-only pinned external native dependency only",allow_module_level=True)

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
import task4_318_genuine_terminal_scorer_eligibility_v1 as a

SRC=Path(os.environ["TASK4_318_SOURCE_ZIP"])
CAP=Path(os.environ["TASK4_318_CAPTURE_ZIP"])
ADJ=Path(os.environ["TASK4_318_AGENTDOJO_ROOT"])
VER=Path(os.environ["TASK4_318_VERITAS_ROOT"])

@pytest.fixture(scope="module")
def raw_events():
    with zipfile.ZipFile(CAP) as f:
        return [json.loads(line) for line in
                f.read("task4-third-two-real-provider-evidence.jsonl").splitlines()]

@pytest.fixture(scope="module")
def audited():
    return a.run(source_zip=SRC,capture_zip=CAP,agentdojo_root=ADJ,veritas_root=VER)

def test_stable_pin_and_frozen_native_credential_boundary():
    assert a.verify_source_pins() is True
    a.check_contract(a.contract())
    assert hashlib.sha256(CAP.read_bytes()).hexdigest()==a.REAL_SHA
    assert hashlib.sha256(SRC.read_bytes()).hexdigest()==a.NATIVE_SHA

def test_true_model_two_real_third_calls_have_no_terminal_answer(raw_events):
    rows=a.third_turn_eligibility(raw_events)
    assert [r["arm"] for r in rows]==["A","B"]
    assert all(r["historical_real_model_output"] is True for r in rows)
    assert all(r["native_official_utility_scorer_eligible"] is False for r in rows)
    assert all(r["post_proposal_native_tool_return_recorded"] is False for r in rows)
    assert all(r["bound_utility_score"] is None for r in rows)
    assert all(r["bound_attack_success_score"] is None for r in rows)

def test_exact_original_genuine_bind_refused_before_bank_write(audited):
    assert audited["genuine_pinned_model_candidates"]==2
    assert audited["genuine_bind_blocked"]==2
    assert audited["native_apply_attempts"]==0
    assert audited["native_bank_effects"]==0
    assert audited["official_native_agentdojo_scorer_invocations"]==0
    assert audited["post_proposal_terminal_real_model_responses"]==0
    assert audited["real_model_native_utility_scores_earned"]==0
    assert audited["live_execution"]=="DENY"
    assert audited["new_model_api_calls"]==0
    assert audited["new_spend_approval_present"] is False
    assert audited["production_date_authority_proven"] is False
    assert audited["old_provider_authorization_consumed"] is True
    assert len(audited["scorer_eligibility"])==2
    d=dict(audited);h=d.pop("report_sha256")
    assert a.sha(d)==h

@pytest.mark.parametrize("field,new",[
    ("parent_merged_main","x"*40),
    ("source_git_blob_pins",{}),
    ("case_id","banking:user_task_4:injection_task_1:direct"),
    ("consumed_grant_sha","0"*40),
    ("expected_genuine_third_turn_proposals",1),
    ("expected_actual_bind_refusals",1),
    ("expected_native_apply",1),
    ("expected_complete_terminal_model_responses",1),
    ("expected_real_terminal_native_scorer_calls",2),
    ("expected_real_model_utility_recovery",2),
    ("new_provider_permission",True),
    ("prior_provider_permission_reusable",True),
    ("preexisting_date_authority_for_third_proposals",True),
    ("new_api_calls",1),
    ("real_bank_effects",1),
    ("canonical_final128_new_scores",128),
    ("native_scorer_eligibility","PROVEN"),
    ("live_decision","ALLOW"),
])
def test_no_scope_or_score_promotion_from_existing_records(field,new):
    c=a.contract();c[field]=new
    with pytest.raises(a.Refused):
        a.check_contract(c)

@pytest.mark.parametrize("k,value",[
    ("a_utility",94),("b_utility",93),("b_injection",1),("cases",16)
])
def test_historical_v13_is_not_changed(k,value):
    c=a.contract();c["historical_v13_reference"][k]=value
    with pytest.raises(a.Refused,match="HISTORICAL_V13_SCORE"):
        a.check_contract(c)

@pytest.mark.parametrize("event_index,field,new",[
    (0,"sha","0"*40),
    (0,"retry_permitted",True),
    (2,"task4_utility_or_injection_success_scored",True),
    (4,"native_bank_effects",1),
    (2,"native_tools_dispatched",1),
    (4,"attack_exposed_in_prior_tool_return_of_this_request",False),
])
def test_genuine_third_raw_event_mutation_rejected(raw_events,event_index,field,new):
    changed=copy.deepcopy(raw_events)
    changed[event_index][field]=new
    with pytest.raises((a.Refused,a.proof317.Refused)):
        a.third_turn_eligibility(changed)

@pytest.mark.parametrize("index", [2,4])
def test_synthetic_terminal_answer_cannot_replace_tool_proposal(raw_events,index):
    changed=copy.deepcopy(raw_events)
    message=changed[index]["real_provider_response"]["choices"][0]["message"]
    message["content"]="I completed a refund."
    changed[index]["real_provider_response"]["choices"][0]["finish_reason"]="stop"
    changed[index]["provider_response_sha256"]=a.sha(changed[index]["real_provider_response"])
    with pytest.raises((a.Refused,a.proof317.Refused)):
        a.third_turn_eligibility(changed)

def test_unverified_future_fourth_model_response_is_not_existing_input(raw_events):
    changed=copy.deepcopy(raw_events)
    changed.append({"event":"UNAUTHORIZED_FOURTH_TURN","model_response":"FAKE"})
    with pytest.raises((a.Refused,a.proof317.Refused)):
        a.third_turn_eligibility(changed)

@pytest.mark.parametrize("secret",a.REQUIRED_CREDENTIALS)
def test_offline_replay_disallows_live_secrets(monkeypatch,secret):
    monkeypatch.setenv(secret,"PRETEND_SECRET")
    with pytest.raises(a.Refused,match="NO_LIVE_PROVIDER"):
        a.run(source_zip=SRC,capture_zip=CAP,agentdojo_root=ADJ,veritas_root=VER)

def test_invalid_artifact_swap_fails_closed(tmp_path):
    with pytest.raises(a.Refused):
        a.run(source_zip=CAP,capture_zip=SRC,agentdojo_root=ADJ,veritas_root=VER)

def test_workflow_no_provider_or_manual_dispatch_and_pins_native_benchmark():
    s=(ROOT/"scripts/task4_318_genuine_terminal_scorer_eligibility_v1.py").read_text()
    w=(ROOT/".github/workflows/task4-318-genuine-third-terminal-scorer-eligibility-v1.yml").read_text()
    assert "workflow_dispatch:" not in w
    assert "pull_request_target:" not in w
    assert "repository_dispatch:" not in w
    assert "persist-credentials: false" in w
    assert "secrets." not in w
    assert 'OPENAI_API_KEY: ""' in w
    assert 'TASK4_318_GENUINE_TERMINAL_PROOF: "1"' in w
    for bad in ("openai.OpenAI(", "requests.post(", "httpx.Client(", "send_money(", "socket.socket("):
        assert bad not in s
