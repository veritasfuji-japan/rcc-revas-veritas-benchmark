import json
import pytest
from scripts.final128_354_task1_live_ruleset_fetch_v1 import fetch_and_verify,FetchDenied,API
TAG="final128-task1-real-ab-once-v1-"+"a"*40+"-38230518370"
RULE={"id":123,"name":"immutable","target":"tag","enforcement":"active",
 "conditions":{"ref_name":{"include":["refs/tags/final128-task1-real-ab-once-v1-*"],"exclude":[]}},
 "bypass_actors":[],"rules":[{"type":"deletion"},{"type":"update"}]}
class Response:
    status=200
    def __init__(self,body):self.body=json.dumps(body).encode()
    def __enter__(self):return self
    def __exit__(self,*a):return False
    def read(self,n=None):return self.body if n is None else self.body[:n]
def transport(req,timeout):
    assert req.method=="GET"
    if req.full_url==API:return Response([{"id":123,"target":"tag"}])
    assert req.full_url.endswith("/rulesets/123")
    return Response(RULE)
def test_reads_summary_and_detail():
    r=fetch_and_verify(token="placeholder",tag_name=TAG,transport=transport)
    assert r["ruleset_id"]==123
    assert r["read_only"] is True
    assert r["proof_of_live_rejection"] is False
def test_missing_token_no_request():
    with pytest.raises(FetchDenied,match="TOKEN"):
        fetch_and_verify(token="",tag_name=TAG,transport=transport)
def test_missing_ruleset_fails():
    with pytest.raises(FetchDenied,match="NO_TAG"):
        fetch_and_verify(token="test",tag_name=TAG,transport=lambda req,timeout:Response([]))
def test_inactive_ruleset_fails():
    def fake(req,timeout):
        if req.full_url==API:return Response([{"id":123,"target":"tag"}])
        return Response({**RULE,"enforcement":"evaluate"})
    with pytest.raises(FetchDenied,match="NO_ACCEPTABLE"):
        fetch_and_verify(token="test",tag_name=TAG,transport=fake)
def test_network_failure_fails():
    def fail(req,timeout):raise TimeoutError()
    with pytest.raises(FetchDenied,match="FETCH"):
        fetch_and_verify(token="test",tag_name=TAG,transport=fail)
def test_wrong_detail_id_fails():
    def wrong(req,timeout):
        if req.full_url==API:return Response([{"id":123,"target":"tag"}])
        return Response({**RULE,"id":456})
    with pytest.raises(FetchDenied,match="ID_MISMATCH"):
        fetch_and_verify(token="test",tag_name=TAG,transport=wrong)
