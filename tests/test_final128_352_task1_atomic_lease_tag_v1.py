import io,json,urllib.error
import pytest
from scripts.final128_352_task1_atomic_lease_tag_v1 import LeaseRequest,LeaseRefused,issue_once
SHA="a"*40
TAG="refs/tags/final128-task1-real-ab-once-v1-"+SHA+"-38228439438"
GOOD=LeaseRequest("veritasfuji-japan/rcc-revas-veritas-benchmark",TAG,SHA,True,True)
class Reply:
    status=201
    def __init__(self,data):self.data=data
    def __enter__(self):return self
    def __exit__(self,*a):return False
    def read(self):return json.dumps(self.data).encode()
def ok(req,timeout):
    assert req.method=="POST"
    assert json.loads(req.data)=={"ref":TAG,"sha":SHA}
    return Reply({"ref":TAG,"object":{"sha":SHA}})
def test_issuer_exact_created_ref():
    assert issue_once(GOOD,token="placeholder-test-only",transport=ok)==TAG
@pytest.mark.parametrize("req",[
 LeaseRequest("other/repo",TAG,SHA,True,True),
 LeaseRequest(GOOD.repository,"refs/tags/other",SHA,True,True),
 LeaseRequest(GOOD.repository,TAG,"b"*40,True,True),
 LeaseRequest(GOOD.repository,TAG,SHA,False,True),
 LeaseRequest(GOOD.repository,TAG,SHA,True,False),
])
def test_bad_boundaries_refused_without_transport(req):
    def forbidden(*a,**k):raise AssertionError("transport must not be called")
    with pytest.raises(LeaseRefused):
        issue_once(req,token="test",transport=forbidden)
def test_missing_token_refused():
    with pytest.raises(LeaseRefused,match="TOKEN"):
        issue_once(GOOD,token="",transport=ok)
@pytest.mark.parametrize("status",[409,422,403,500])
def test_github_http_failures_never_retried(status):
    calls=[]
    def reject(req,timeout):
        calls.append(1)
        raise urllib.error.HTTPError(req.full_url,status,"failed",{},io.BytesIO(b""))
    with pytest.raises(LeaseRefused):
        issue_once(GOOD,token="test",transport=reject)
    assert len(calls)==1
def test_wrong_returned_ref_refused():
    with pytest.raises(LeaseRefused,match="RESPONSE_BIND"):
        issue_once(GOOD,token="test",transport=lambda req,timeout:Reply({"ref":"wrong","object":{"sha":SHA}}))
def test_uncertain_timeout_refused_no_retry():
    calls=[]
    def fail(req,timeout):
        calls.append(1)
        raise TimeoutError()
    with pytest.raises(LeaseRefused,match="UNCERTAIN"):
        issue_once(GOOD,token="test",transport=fail)
    assert len(calls)==1
