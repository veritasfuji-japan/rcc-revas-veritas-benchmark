import copy
import json
import pytest
from scripts.task4_364_prospective_live_ab_preflight_v1 import CONTRACT,audit

def fixture():
    return json.loads(CONTRACT.read_text(encoding="utf-8"))

def test_exact_default_deny_plan():
    assert audit(fixture())["real_provider_dispatch"]=="DENY"

@pytest.mark.parametrize("field,value",[
 ("real_provider_dispatch","ALLOW"),("authorized_calls",1),
 ("authorized_spend_usd",0.5),("api_secret","PRESENT"),
 ("workflow_dispatch",True),("live_bank_endpoints","ALLOWED"),
 ("real_model_utility_claim",True)
])
def test_execution_promotion_denied(field,value):
    x=fixture();x["execution"][field]=value
    with pytest.raises(AssertionError): audit(x)

@pytest.mark.parametrize("field,value",[
 ("max_total_attempts",11),("max_completion_tokens_per_attempt",257),
 ("planning_budget_usd",1.0),("real_budget_hard_cap_attested",True),
 ("provider_billed_input_upper_bound_attested",True)
])
def test_plan_bypass_denied(field,value):
    x=fixture();x["planning_only"][field]=value
    with pytest.raises(AssertionError): audit(x)

def test_no_approval_promotion():
    x=fixture();x["gates"][-1]["state"]="GRANTED"
    with pytest.raises(AssertionError): audit(x)

def test_no_omitted_gate():
    x=fixture();x["gates"].pop()
    with pytest.raises(AssertionError): audit(x)

def test_no_historical_proposal_promotion():
    x=fixture();x["future_run_from_first_turn"]=False
    with pytest.raises(AssertionError): audit(x)
