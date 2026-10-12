"""#352: fail-closed atomic GitHub ref creation for a Task1 once-only lease.

This is a narrow primitive. It does not verify tag ruleset enforcement, Actions
identity, protected environment, operator consent, or provider permission.
Never call it with untrusted self-asserted approval flags.
"""
import json
import urllib.error
import urllib.request
from dataclasses import dataclass

class LeaseRefused(RuntimeError):pass

@dataclass(frozen=True)
class LeaseRequest:
    repository:str
    tag_ref:str
    commit_sha:str
    ruleset_independently_verified:bool
    authorized_execution_identity_verified:bool

def issue_once(request:LeaseRequest,*,token:str,transport=None)->str:
    if type(request) is not LeaseRequest:
        raise LeaseRefused("352_BAD_REQUEST_TYPE")
    if request.repository!="veritasfuji-japan/rcc-revas-veritas-benchmark":
        raise LeaseRefused("352_REPOSITORY_MISMATCH")
    if not request.tag_ref.startswith("refs/tags/final128-task1-real-ab-once-v1-"):
        raise LeaseRefused("352_TAG_NAMESPACE")
    if not request.tag_ref[len("refs/tags/final128-task1-real-ab-once-v1-"):].endswith("-") and len(request.tag_ref.split("-"))<2:
        raise LeaseRefused("352_BAD_TAG")
    import re
    if not re.fullmatch(r"refs/tags/final128-task1-real-ab-once-v1-[0-9a-f]{40}-[1-9][0-9]{5,19}",request.tag_ref):
        raise LeaseRefused("352_BAD_TAG")
    if not re.fullmatch(r"[0-9a-f]{40}",request.commit_sha):
        raise LeaseRefused("352_BAD_SHA")
    if not request.tag_ref.endswith(request.commit_sha+"-"+request.tag_ref.rsplit("-",1)[-1]):
        raise LeaseRefused("352_SHA_BIND_MISMATCH")
    if request.ruleset_independently_verified is not True:
        raise LeaseRefused("352_RULESET_UNVERIFIED")
    if request.authorized_execution_identity_verified is not True:
        raise LeaseRefused("352_IDENTITY_UNVERIFIED")
    if not isinstance(token,str) or not token:
        raise LeaseRefused("352_TOKEN_MISSING")
    body=json.dumps({"ref":request.tag_ref,"sha":request.commit_sha}).encode()
    url="https://api.github.com/repos/"+request.repository+"/git/refs"
    req=urllib.request.Request(url,data=body,method="POST",headers={
        "Authorization":"Bearer "+token,"Accept":"application/vnd.github+json",
        "Content-Type":"application/json","X-GitHub-Api-Version":"2022-11-28"})
    sender=transport if transport is not None else urllib.request.urlopen
    try:
        with sender(req,timeout=15) as resp:
            if resp.status!=201:raise LeaseRefused("352_NOT_CREATED")
            result=json.loads(resp.read())
    except urllib.error.HTTPError as e:
        if e.code in (409,422):
            raise LeaseRefused("352_ALREADY_CONSUMED_OR_CONFLICT") from e
        raise LeaseRefused("352_GITHUB_HTTP_FAILURE") from e
    except Exception as e:
        if isinstance(e,LeaseRefused):raise
        raise LeaseRefused("352_UNCERTAIN_CREATION_STATE_FAIL_CLOSED") from e
    if result.get("ref")!=request.tag_ref or result.get("object",{}).get("sha")!=request.commit_sha:
        raise LeaseRefused("352_RESPONSE_BIND_MISMATCH")
    return request.tag_ref
