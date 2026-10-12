"""#354: GitHub REST read-only ruleset fetch, conservative fail-closed.

The caller must supply a trusted credential. No token is logged or persisted.
Only the REST GET is permitted; no tag mutations or model API calls.
"""
import json
import urllib.request
import urllib.error
from scripts.final128_353_task1_tag_ruleset_readonly_v1 import verify_ruleset,RuleDenied

REPOSITORY="veritasfuji-japan/rcc-revas-veritas-benchmark"
API="https://api.github.com/repos/"+REPOSITORY+"/rulesets?includes_parents=true"

class FetchDenied(RuntimeError):pass

def fetch_and_verify(*,token,tag_name,transport=None):
    if not isinstance(token,str) or not token:
        raise FetchDenied("354_NO_GITHUB_TOKEN")
    if not isinstance(tag_name,str) or len(tag_name)>160:
        raise FetchDenied("354_INVALID_TAG")
    req=urllib.request.Request(API,method="GET",headers={
      "Authorization":"Bearer "+token,
      "Accept":"application/vnd.github+json",
      "X-GitHub-Api-Version":"2022-11-28"})
    sender=transport if transport is not None else urllib.request.urlopen
    try:
        with sender(req,timeout=15) as response:
            if response.status!=200:
                raise FetchDenied("354_UNEXPECTED_HTTP_STATUS")
            raw=response.read(2_000_001)
            if len(raw)>2_000_000:
                raise FetchDenied("354_OVERSIZED_RESPONSE")
            items=json.loads(raw)
    except Exception as exc:
        if isinstance(exc,FetchDenied):raise
        raise FetchDenied("354_RULESET_FETCH_OR_PARSE_FAILURE") from exc
    if not isinstance(items,list):
        raise FetchDenied("354_UNEXPECTED_JSON")
    # List endpoint may return only summary rulesets, without 'rules'. Fetch each
    # individual ruleset to avoid silently treating summaries as full proofs.
    detailed=[]
    for item in items:
        if not isinstance(item,dict) or item.get("target")!="tag":continue
        rid=item.get("id")
        if type(rid) is not int or rid<=0:raise FetchDenied("354_INVALID_RULESET_ID")
        url="https://api.github.com/repos/"+REPOSITORY+"/rulesets/"+str(rid)
        detail_req=urllib.request.Request(url,method="GET",headers=req.headers)
        try:
            with sender(detail_req,timeout=15) as response:
                if response.status!=200:raise FetchDenied("354_DETAIL_STATUS")
                raw=response.read(2_000_001)
                if len(raw)>2_000_000:raise FetchDenied("354_DETAIL_OVERSIZED")
                detail=json.loads(raw)
        except Exception as exc:
            if isinstance(exc,FetchDenied):raise
            raise FetchDenied("354_DETAIL_FETCH_FAILURE") from exc
        if not isinstance(detail,dict) or detail.get("id")!=rid:
            raise FetchDenied("354_DETAIL_ID_MISMATCH")
        detailed.append(detail)
    if not detailed:raise FetchDenied("354_NO_TAG_RULESETS")
    try:
        result=verify_ruleset(rulesets=detailed,tag_name=tag_name,
                              verified_rest_origin=True)
    except RuleDenied as exc:
        raise FetchDenied("354_NO_ACCEPTABLE_RULESET") from exc
    result["source_endpoint"]=API
    result["read_only"]=True
    result["proof_of_live_rejection"]=False
    return result
