from types import SimpleNamespace as NS
from decimal import Decimal
import pytest
from scripts import final128_350_task1_responses_once_budget_v1 as m

class FakeResponses:
    def __init__(self,usage=None,model=m.MODEL):
        self.calls=0
        self.usage=usage or NS(input_tokens=100,output_tokens=20)
        self.model=model
    def create(self,**kwargs):
        self.calls+=1
        assert kwargs["model"]==m.MODEL
        assert kwargs["store"] is False
        assert kwargs["truncation"]=="disabled"
        assert kwargs["max_output_tokens"]==256
        return NS(model=self.model,usage=self.usage,output_text="The total spending is £1050.")
def client(f):
    return NS(responses=f)
def inp():
    return [{"role":"user","content":"What's my total spending in March 2022?"}]
def test_max_reservation_under_one_dollar():
    assert m.reserved_max_usd()==Decimal("0.0416768")
    assert m.reserved_max_usd()<m.MAX_USD
def test_default_deny_no_lease():
    f=FakeResponses()
    with pytest.raises(m.Refused,match="ONEUSE"):
        m.response_once(client=client(f),owned_input=inp(),budget=m.Budget())
    assert f.calls==0
def test_successful_mock_one_call_no_native_scorer():
    f=FakeResponses()
    b=m.Budget()
    r=m.response_once(client=client(f),owned_input=inp(),budget=b,
       externally_authenticated_oneuse_lease=True)
    assert f.calls==1
    assert r["model"]==m.MODEL
    assert r["independent_ab_completed"] is False
    assert r["official_native_scorer_invoked"] is False
    assert b.used==1
    assert b.observed==Decimal("0.000072")
def test_limit_eight_and_ninth_denied():
    f=FakeResponses()
    b=m.Budget()
    for _ in range(8):
        m.response_once(client=client(f),owned_input=inp(),budget=b,
          externally_authenticated_oneuse_lease=True)
    with pytest.raises(m.Refused,match="CALL_COUNT"):
        m.response_once(client=client(f),owned_input=inp(),budget=b,
          externally_authenticated_oneuse_lease=True)
    assert f.calls==8
@pytest.mark.parametrize("usage",[
    NS(input_tokens=None,output_tokens=10),
    NS(input_tokens=10,output_tokens=-1),
    NS(input_tokens=12001,output_tokens=10),
    NS(input_tokens=10,output_tokens=257),
])
def test_usage_invalid_fails_closed_and_no_retry(usage):
    f=FakeResponses(usage=usage)
    with pytest.raises(m.Refused):
        m.response_once(client=client(f),owned_input=inp(),budget=m.Budget(),
          externally_authenticated_oneuse_lease=True)
    assert f.calls==1
def test_wrong_model_refused():
    f=FakeResponses(model="other-model")
    with pytest.raises(m.Refused,match="MODEL_MISMATCH"):
        m.response_once(client=client(f),owned_input=inp(),budget=m.Budget(),
          externally_authenticated_oneuse_lease=True)
    assert f.calls==1
def test_invalid_input_denied_without_provider_call():
    f=FakeResponses()
    with pytest.raises(m.Refused,match="EMPTY"):
        m.response_once(client=client(f),owned_input=[],budget=m.Budget(),
          externally_authenticated_oneuse_lease=True)
    assert f.calls==0
def test_provider_exception_not_retried():
    class Broken:
        calls=0
        def create(self,**kw):
            self.calls+=1
            raise ConnectionError("network")
    f=Broken()
    with pytest.raises(ConnectionError):
        m.response_once(client=client(f),owned_input=inp(),budget=m.Budget(),
          externally_authenticated_oneuse_lease=True)
    assert f.calls==1
def test_boolean_lease_only_exact_true():
    f=FakeResponses()
    with pytest.raises(m.Refused,match="ONEUSE"):
        m.response_once(client=client(f),owned_input=inp(),budget=m.Budget(),
          externally_authenticated_oneuse_lease=1)
    assert f.calls==0
