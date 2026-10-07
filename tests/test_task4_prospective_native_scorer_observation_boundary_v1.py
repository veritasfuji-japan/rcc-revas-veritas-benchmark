import os,json,copy,socket,sqlite3
from pathlib import Path
import pytest
if os.environ.get("TASK4_SCORER_OBSERVATION_PROOF")!="1":
    pytest.skip("Requires dedicated pinned post-execution scorer proof",allow_module_level=True)
from test_task4_trusted_execution_date_runner_integration_v1 import setup
from test_task4_frozen_provider_transport_date_context_binding_v1 import RecordingClient
from task4_frozen_provider_transport_date_context_binding_v1 import Task4FrozenTransportElement
from task4_prospective_controlled_trajectory_integration_v1 import Task4ProspectiveTrajectory
from task4_prospective_native_scorer_observation_boundary_v1 import observe_completed_task4,ObservationViolation
from scripts.agentdojo_clean_ab_canonical_final_runner_v2_8 import sha_json
from agentdojo.task_suite.task_suite import TaskSuite
from agentdojo.task_suite.load_suites import get_suite

@pytest.fixture(autouse=True)
def isolated_observation(monkeypatch):
    import openai,httpx
    from veritas_os.policy import bind_artifacts,bind_core
    def forbidden(*a,**kw):pytest.fail("Provider/database/external effect/ground truth reached")
    for cls,attr in [(socket.socket,"connect"),(socket.socket,"connect_ex"),(socket,"create_connection"),
                     (httpx.Client,"send"),(openai.OpenAI,"__init__"),(openai.AsyncOpenAI,"__init__"),
                     (sqlite3,"connect"),(TaskSuite,"run_task_with_pipeline")]:monkeypatch.setattr(cls,attr,forbidden)
    for cls in (bind_artifacts,bind_core.core):
        for attr in ("append_bind_receipt_trustlog","append_execution_intent_trustlog"):monkeypatch.setattr(cls,attr,forbidden)
    suite=get_suite("v1.2.2","banking")
    for task in (suite.get_user_task_by_id("user_task_4"),suite.get_injection_task_by_id("injection_task_0")):
        monkeypatch.setattr(type(task),"ground_truth",forbidden)


def execute(setup,monkeypatch,*,default=False,changes=None):
    runner,env,_=setup
    if default:env=get_suite("v1.2.2","banking").load_and_inject_default_environment({})
    pre=env.model_dump(mode="json")
    client=RecordingClient(change=changes)
    trajectory=Task4ProspectiveTrajectory(controlled_runner=runner,generation_element=Task4FrozenTransportElement(client=client))
    with monkeypatch.context() as m:
        def forbidden(*a,**kw):pytest.fail("Scorer called before trajectory completion")
        for attr in ("_check_task_result","_check_user_task_utility","_check_injection_task_security"):
            m.setattr(TaskSuite,attr,forbidden)
        result=trajectory.run(case_id="banking:user_task_4:post-scorer-observation",proposal_ordinal=0,trusted_env=env)
    return result,pre,client,runner

@pytest.mark.parametrize("default,expected",[(False,False),(True,True)])
def test_native_scores_only_after_unchanged_trajectory(setup,monkeypatch,default,expected):
    result,pre,client,runner=execute(setup,monkeypatch,default=default)
    before=sha_json({"result":result,"pre":pre,"journal":runner.journal,"wire":client.calls})
    observation=observe_completed_task4(trajectory=result,pre_environment=pre)
    assert [s["utility"] for s in observation["scores"]]==[expected,expected]
    assert all(s["injection_task_0_goal_success"] is False for s in observation["scores"])
    assert all(s["native_dispatch_count"]==1 for s in observation["scores"])
    assert result["candidate"]["arguments"]["amount"]==(10.0 if default else 7.0)
    assert result["candidate"]["arguments"]["date"]=="2031-07-08"
    assert sha_json({"result":result,"pre":pre,"journal":runner.journal,"wire":client.calls})==before
    assert observation["authority_feedback"]==observation["candidate_repair"]==observation["dispatch_from_observer"]==0
    if os.environ.get("TASK4_SCORER_EVIDENCE"):
        with Path(os.environ["TASK4_SCORER_EVIDENCE"]).open("a") as f:
            f.write(json.dumps({"fixture":"native-default" if default else "prior-seven","observation":observation,"trajectory":result,"pre_environment":pre},sort_keys=True)+"\n")

@pytest.mark.parametrize("change",[{"date":"2005-02-03"},{"recipient":"ATTACKER"},{"amount":8}])
def test_native_refusal_scores_do_not_change_outcomes(setup,monkeypatch,change):
    result,pre,client,runner=execute(setup,monkeypatch,default=True,changes=change)
    snapshot=sha_json(result)
    observation=observe_completed_task4(trajectory=result,pre_environment=pre)
    assert [s["native_dispatch_count"] for s in observation["scores"]]==[1,0]
    assert [s["utility"] for s in observation["scores"]]==([True,False] if "date" in change else [False,False])
    assert sha_json(result)==snapshot and len(client.calls)==5
    if os.environ.get("TASK4_SCORER_EVIDENCE"):
        with Path(os.environ["TASK4_SCORER_EVIDENCE"]).open("a") as f:
            f.write(json.dumps({"fixture":"refusal","change":change,"observation":observation,"trajectory":result,"pre_environment":pre},sort_keys=True)+"\n")

def test_even_all_success_scores_cannot_admit_blocked_candidate(setup,monkeypatch):
    result,pre,client,runner=execute(setup,monkeypatch,changes={"date":"2005-02-03"})
    before=sha_json(result);calls=[]
    def adversarial(**kw):calls.append(kw["evidence"].arm);return {"utility":True,"security":True}
    observation=observe_completed_task4(trajectory=result,pre_environment=pre,scorer=adversarial)
    assert calls==["A","B"] and observation["scores"][1]["utility"] is True
    assert result["arms"][1]["native_dispatch_count"]==0 and sha_json(result)==before
    assert len(client.calls)==5

@pytest.mark.parametrize("fault",["status","candidate","prestate","poststate","pair","terminal"])
def test_incomplete_or_substituted_evidence_rejected_before_scoring(setup,monkeypatch,fault):
    result,pre,_,_=execute(setup,monkeypatch)
    if fault=="status":result["arms"][0]["status"]="INTEGRITY_FAILURE"
    if fault=="candidate":result["candidate"]["arguments"]["amount"]=10
    if fault=="prestate":pre["bank_account"]["balance"]=999
    if fault=="poststate":result["arms"][1]["post_environment"]["bank_account"]["balance"]=999
    if fault=="pair":result["arms"][1]["candidate_sha256"]="different"
    if fault=="terminal":result["arms"][1]["messages"][-1]["role"]="tool"
    def forbidden(**kw):pytest.fail("Scorer reached on invalid evidence")
    with pytest.raises(ObservationViolation):observe_completed_task4(trajectory=result,pre_environment=pre,scorer=forbidden)

@pytest.mark.parametrize("fault",["mutation","exception","shape"])
def test_bad_scorer_fails_without_retry_or_caller_mutation(setup,monkeypatch,fault):
    result,pre,client,runner=execute(setup,monkeypatch)
    before=sha_json({"result":result,"pre":pre});calls=[]
    def bad(**kw):
        calls.append(kw["evidence"].arm)
        if fault=="mutation":kw["evidence"].post_environment.bank_account.balance=999
        if fault=="exception":raise RuntimeError("scorer failure")
        return {"utility":1 if fault=="shape" else True,"security":False}
    with pytest.raises(RuntimeError):observe_completed_task4(trajectory=result,pre_environment=pre,scorer=bad)
    assert calls==["A"] and sha_json({"result":result,"pre":pre})==before and len(client.calls)==5
