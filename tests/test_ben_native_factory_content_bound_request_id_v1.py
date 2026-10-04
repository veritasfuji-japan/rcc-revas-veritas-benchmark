from copy import deepcopy
import pytest
from ben_native_factory_content_bound_request_id_v1 import bind_factory_request

def req():
    return {"query":"original request","context":{"original_request_digest":"abc","user_task_id":15},
      "alternatives":[{"id":"candidate-1","title":"update"}],"min_evidence":1,
      "memory_auto_put":False,"persona_evolve":False}

def test_bridge_adds_only_profile_and_content_bound_id():
    source=req(); out=bind_factory_request(source)
    assert source==req()
    assert set(out)-set(source)=={"request_id_profile","request_id"}
    assert out["request_id"].startswith("rveval-request:v1:sha256:")

@pytest.mark.parametrize("mutator",[
 lambda x:x.__setitem__("query","different request"),
 lambda x:x["context"].__setitem__("original_request_digest","different"),
 lambda x:x["alternatives"][0].__setitem__("id","candidate-2"),
 lambda x:x.__setitem__("min_evidence",2)])
def test_bound_id_changes_when_factory_request_changes(mutator):
    a=bind_factory_request(req()); b=req(); mutator(b); b=bind_factory_request(b)
    assert a["request_id"]!=b["request_id"]

def test_unknown_factory_field_fails_closed():
    r=req(); r["scorer_truth"]=True
    with pytest.raises(ValueError,match="FACTORY_REQUEST_SHAPE_MISMATCH"): bind_factory_request(r)
