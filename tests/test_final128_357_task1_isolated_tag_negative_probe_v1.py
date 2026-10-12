import json
import pytest
from scripts.final128_357_task1_isolated_tag_negative_probe_v1 import probe, ProbeDenied
SHA="a"*40
OTHER="b"*40
REF="refs/tags/final128-task1-real-ab-once-v1-"+SHA+"-38235658146"
class Response:
    def __init__(self,status,data):self.status=status;self.data=data
    def __enter__(self):return self
    def __exit__(self,*a):return False
    def read(self,n):return json.dumps(self.data).encode()
def transport(req,timeout):
    if req.method=="POST":
        return Response(201,{"ref":json.loads(req.data)["ref"]})
    if req.method=="GET":
        return Response(200,{"ref":REF,"object":{"sha":SHA}})
    if req.method in ("PATCH","DELETE"):
        return Response(403,{"message":"Repository rule violations found for refs/tags"})
    raise AssertionError(req.method)
def run(transport_override=None):
    return probe(token="mock",sha=SHA,target_sha=OTHER,run_id="38235658146",
                 consent=True,transport=transport_override or transport)
def test_protected():
    result=run()
    assert result["readback_unchanged"] is True
    assert result["update_status"]==result["delete_status"]==403
def test_no_consent():
    with pytest.raises(ProbeDenied,match="CONSENT"):
        probe(token="mock",sha=SHA,target_sha=OTHER,run_id="38235658146",
              transport=lambda *_:pytest.fail("network"))
def test_same_sha_not_proof():
    with pytest.raises(ProbeDenied,match="DISTINCT"):
        probe(token="mock",sha=SHA,target_sha=SHA,run_id="38235658146",
              consent=True,transport=lambda *_:pytest.fail("network"))
def test_422_not_proof():
    def bad(req,timeout):
        if req.method=="PATCH":return Response(422,{"message":"Validation failed"})
        return transport(req,timeout)
    with pytest.raises(ProbeDenied,match="UPDATE_RULESET"):
        run(transport_override=bad)
def test_generic_403_not_proof():
    def bad(req,timeout):
        if req.method=="PATCH":return Response(403,{"message":"Resource not accessible"})
        return transport(req,timeout)
    with pytest.raises(ProbeDenied,match="UPDATE_RULESET"):
        run(transport=bad)
def test_changed_ref_not_proof():
    def bad(req,timeout):
        if req.method=="GET":return Response(200,{"ref":REF,"object":{"sha":OTHER}})
        return transport(req,timeout)
    with pytest.raises(ProbeDenied,match="REF_NOT_UNCHANGED"):
        run(transport=bad)
