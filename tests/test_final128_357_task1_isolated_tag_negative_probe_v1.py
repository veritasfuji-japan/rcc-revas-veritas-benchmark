import pytest
from scripts.final128_357_task1_isolated_tag_negative_probe_v1 import probe,ProbeDenied
SHA="a"*40
class Response:
    def __init__(self,status,data):self.status=status;self.data=data
    def __enter__(self):return self
    def __exit__(self,*a):return False
    def read(self,n):return __import__("json").dumps(self.data).encode()
def fake(req,timeout):
    if req.method=="POST":
        body=__import__("json").loads(req.data)
        return Response(201,{"ref":body["ref"]})
    if req.method=="PATCH":return Response(403,{})
    if req.method=="DELETE":return Response(403,{})
    raise AssertionError("unexpected method")
def test_isolated_rejections():
    r=probe(token="mock",sha=SHA,run_id="38235658146",consent=True,transport=fake)
    assert r["update_status"]==403 and r["delete_status"]==403
def test_no_consent_no_mutations():
    with pytest.raises(ProbeDenied,match="CONSENT"):
        probe(token="mock",sha=SHA,run_id="38235658146",transport=lambda *_:pytest.fail("network"))
def test_bad_run_id_no_mutations():
    with pytest.raises(ProbeDenied,match="RUN_ID"):
        probe(token="mock",sha=SHA,run_id="1",consent=True,transport=lambda *_:pytest.fail("network"))
def test_unprotected_update_refuses():
    def unprotected(req,timeout):
        if req.method=="PATCH":return Response(200,{})
        return fake(req,timeout)
    with pytest.raises(ProbeDenied,match="UPDATE"):
        probe(token="mock",sha=SHA,run_id="38235658146",consent=True,transport=unprotected)
def test_unprotected_delete_refuses():
    def unprotected(req,timeout):
        if req.method=="DELETE":return Response(204,{})
        return fake(req,timeout)
    with pytest.raises(ProbeDenied,match="DELETE"):
        probe(token="mock",sha=SHA,run_id="38235658146",consent=True,transport=unprotected)
