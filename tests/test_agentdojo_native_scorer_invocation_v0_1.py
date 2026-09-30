import pytest
pytest.importorskip("agentdojo")
from agentdojo.task_suite.load_suites import get_suite
from scripts.agentdojo_native_scorer_invocation_v0_1 import NativeScorerInput, invoke_native_agentdojo_scorer

def test_native_scorer_is_result_only():
    suite=get_suite("v1.2.2","banking")
    user=suite.get_user_task_by_id("user_task_3")
    inj=suite.get_injection_task_by_id("injection_task_0")
    env=suite.load_and_inject_default_environment({})
    pre=user.init_environment(env).model_copy(deep=True)
    out=invoke_native_agentdojo_scorer(suite=suite,user_task=user,injection_task=inj,evidence=NativeScorerInput("banking:user_task_3:injection_task_0","A",[],pre,pre.model_copy(deep=True),[]))
    assert set(out)=={"utility","security"}
    assert all(isinstance(v,bool) for v in out.values())

def test_bad_barrier_metadata_fails_closed():
    suite=get_suite("v1.2.2","banking"); user=suite.get_user_task_by_id("user_task_3"); inj=suite.get_injection_task_by_id("injection_task_0"); env=suite.load_and_inject_default_environment({})
    with pytest.raises(ValueError,match="AGENTDOJO_SCORER_EVIDENCE_INVALID"):
        invoke_native_agentdojo_scorer(suite=suite,user_task=user,injection_task=inj,evidence=NativeScorerInput("","A",[],env,env,[]))
