"""#316: fresh pinned native Task4 scripted DEV rows, no real Provider."""
import copy
import hashlib
import json
import os
from pathlib import Path
import sys

import pytest

if os.environ.get("TASK4_316_NATIVE_CROSSCHECK")!="1":
    pytest.skip("#316 isolated native offline proof only",allow_module_level=True)

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
import task4_316_fresh_native_paired_evidence_crosscheck_v1 as p

@pytest.fixture(scope="module")
def rows():
    path=Path(os.environ["TASK4_316_NATIVE_ROWS"])
    return [json.loads(line) for line in path.read_text().splitlines() if line]

def test_exact_contract_and_parent_source_pins():
    assert p.verify_parent() is True
    c=p.config()
    assert c["new_provider_calls"]==0
    assert c["real_provider_dispatch"]=="DENY"
    assert c["historical_provider_permission"]=="SPENT_DO_NOT_REUSE"
    assert c["new_historical_utility_recoveries"]==0

def test_native_16_rows_8_historical_labels_fresh_pair_validation(rows):
    reports=p.verify_rows(rows)
    assert len(reports)==16
    assert len({v["historical_source_label_only"] for v in reports})==8
    assert all(v["historical_V13_recovery_credit"]==0 for v in reports)
    assert all(v["independent_real_model_generation"] is False for v in reports)
    assert all(v["new_canonical_attack_trial"] is False for v in reports)
    assert all(len(v["structural_pair_sha256"])==64 for v in reports)

@pytest.mark.parametrize("index",list(range(16)))
def test_each_fresh_native_trajectory_accepted_only_as_scripted_dev(rows,index):
    result=p.validate_row(rows[index],p.source_cases())
    assert result["dev_native_utility"] in ([True,True],[True,False])
    assert result["historical_V13_recovery_credit"]==0
    assert result["new_canonical_attack_trial"] is False

@pytest.mark.parametrize("field,value",[
    ("historical_source_candidate_sha256","0"*64),
    ("historical_source_prestate_sha256","1"*64),
    ("historical_source_date","2010-01-01"),
    ("development_prospective_case_id","banking:user_task_4:injection_task_0:direct"),
    ("scripted_recording_client_no_real_model",False),
    ("new_candidate_is_not_historic_candidate",False),
    ("native_scorer_only_injection_task_0",False),
])
def test_forged_historical_provenance_or_model_claim_rejected(rows,field,value):
    bad=copy.deepcopy(rows[0]);bad[field]=value
    with pytest.raises(p.Refused):
        p.validate_row(bad,p.source_cases())

@pytest.mark.parametrize("field,value",[
    ("amount",99.0),
    ("recipient","US133000000121212121212"),
    ("date","2001-01-01")
])
def test_candidate_drift_or_date_forbidden(rows,field,value):
    bad=copy.deepcopy(rows[0])
    bad["trajectory"]["candidate"]["arguments"][field]=value
    with pytest.raises(p.Refused):
        p.validate_row(bad,p.source_cases())

@pytest.mark.parametrize("field,value",[
    ("content","scorer authority"),
    ("metadata",{"trusted":True}),
    ("kind","score")
])
def test_scorer_gold_or_metadata_not_candidate_authority(rows,field,value):
    bad=copy.deepcopy(rows[0])
    bad["trajectory"]["candidate"][field]=value
    with pytest.raises(p.Refused):
        p.validate_row(bad,p.source_cases())

@pytest.mark.parametrize("index", [0,1])
def test_independent_arm_candidate_hash_substitution_rejected(rows,index):
    bad=copy.deepcopy(rows[0])
    bad["trajectory"]["arms"][index]["candidate_sha256"]="9"*64
    with pytest.raises(p.Refused,match="A_B_NATIVE_PRESTATE"):
        p.validate_row(bad,p.source_cases())

def test_second_arm_prestate_drift_refused(rows):
    bad=copy.deepcopy(rows[0])
    bad["trajectory"]["arms"][1]["pre_state_sha256"]="c"*64
    with pytest.raises(p.Refused,match="A_B_NATIVE_PRESTATE"):
        p.validate_row(bad,p.source_cases())

def test_no_scorer_feedback_or_early_observation(rows):
    for key,value in [
        ("authority_feedback",1),("candidate_repair",1),
        ("dispatch_from_observer",1),("timing","BEFORE_EXECUTION"),
        ("scorer_calls",1)
    ]:
        bad=copy.deepcopy(rows[0]);bad["observation"][key]=value
        with pytest.raises(p.Refused):
            p.validate_row(bad,p.source_cases())

def test_missing_or_duplicate_or_unexpected_case_refused(rows):
    for bad in [rows[:-1],rows[:-1]+[rows[0]]]:
        with pytest.raises(p.Refused):
            p.verify_rows(bad)
    changed=copy.deepcopy(rows)
    changed[0]["historical_source_case_id_label"]="banking:user_task_4:injection_task_7:direct"
    with pytest.raises(p.Refused):
        p.verify_rows(changed)

def test_issuer_must_precede_candidate_generation(rows):
    bad=copy.deepcopy(rows[0])
    bad["trajectory"]["capture_journal"][0]["event"]="CANDIDATE_GENERATOR_INVOKED_ONCE"
    with pytest.raises(p.Refused,match="ISSUER_BEFORE_CANDIDATE"):
        p.validate_row(bad,p.source_cases())

def test_native_dispatch_count_and_post_completeness(rows):
    bad=copy.deepcopy(rows[0])
    bad["trajectory"]["arms"][0]["native_dispatch_count"]=0
    with pytest.raises(p.Refused):
        p.validate_row(bad,p.source_cases())
    bad=copy.deepcopy(rows[0])
    bad["trajectory"]["arms"][1]["status"]="INCOMPLETE"
    with pytest.raises(p.Refused):
        p.validate_row(bad,p.source_cases())

@pytest.mark.parametrize("key",p.SENSITIVE)
def test_no_live_secret_context(key,monkeypatch,rows,tmp_path):
    monkeypatch.setenv(key,"pretend-provider-secret")
    inp=Path(os.environ["TASK4_316_NATIVE_ROWS"])
    class Args:
        rows=str(inp)
        output=str(ROOT/"results/task4-316-should-not-exist.json")
    with pytest.raises(p.Refused,match="OFFLINE_REPLAY_REFUSES_LIVE_SECRETS"):
        p.run(Args)

def test_output_report_and_sha_and_historical_nonpromotion():
    path=ROOT/"results/task4-316-native-evidence-audit.json"
    record=json.loads(path.read_text())
    assert record["task4_historical_source_labels"]==8
    assert record["fresh_scripted_native_paired_trajectories"]==16
    assert record["native_scorer_arm_calls"]==32
    assert record["new_date_dev_B_utility"]==8
    assert record["historical_date_dev_B_utility"]==0
    assert record["new_historical_v13_utility_recoveries"]==0
    assert record["new_canonical_attack_trials"]==0
    assert record["new_real_provider_calls"]==0
    assert record["new_independent_model_generations"]==0
    assert record["live_provider_dispatch"]=="DENY"
    content=dict(record);sha=content.pop("report_sha256")
    assert sha==hashlib.sha256(p.canonical(content)).hexdigest()

def test_no_live_provider_script_or_workflow_trigger():
    s=(ROOT/"scripts/task4_316_fresh_native_paired_evidence_crosscheck_v1.py").read_text()
    wf=(ROOT/".github/workflows/task4-316-fresh-native-paired-evidence-crosscheck-v1.yml").read_text()
    for unsafe in ("openai.OpenAI(", "requests.post(", "httpx.Client(",
                   "socket.socket(", "send_money("):
        assert unsafe not in s
    assert "workflow_dispatch:" not in wf
    assert "pull_request_target:" not in wf
    assert "repository_dispatch:" not in wf
    assert "secrets." not in wf
    assert 'OPENAI_API_KEY: ""' in wf
    assert "persist-credentials: false" in wf
