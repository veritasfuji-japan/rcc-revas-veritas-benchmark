import copy
import json
import pytest
from scripts.final128_362_independent_ab_readiness_audit_v1 import EVIDENCE, audit

def data():
    return json.loads(EVIDENCE.read_text(encoding="utf-8"))

def test_readiness_gaps_are_explicit():
    assert audit(data())["result"] == "PASS"

@pytest.mark.parametrize("field,value",[
    ("provider_calls",1),("external_effects",1),("spend_authorized_usd",1),
    ("mode","live"),("status","PROVEN"),("base_main_sha","0"*40)
])
def test_fail_closed_fields(field,value):
    d=copy.deepcopy(data());d[field]=value
    with pytest.raises(AssertionError):
        audit(d)

def test_no_gate_can_be_promoted():
    for i in range(7):
        d=copy.deepcopy(data());d["gates"][i]["met"]=True
        with pytest.raises(AssertionError):
            audit(d)

def test_no_source_can_be_omitted():
    d=data();d["sources"].pop()
    with pytest.raises(AssertionError):
        audit(d)
