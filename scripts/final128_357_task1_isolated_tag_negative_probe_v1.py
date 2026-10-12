"""#357 isolated GitHub tag negative probe; never touches a real Task1 lease.

Requires explicit opt-in from workflow and exact isolated run-bound tag.
Uses the workflow's own token to create tag, then probes update/delete
and fails unless both are rejected. This is an intentional write test.
"""
import json
import re
import urllib.request
import urllib.error

REPO="veritasfuji-japan/rcc-revas-veritas-benchmark"
class ProbeDenied(RuntimeError):pass

def safe_api_evidence(phase,status,body):
    """Allowlisted diagnostic fields only: never dump raw HTTP bodies or credentials."""
    message=body.get("message","") if isinstance(body,dict) else ""
    message=str(message).replace("\\n"," ")[:400]
    # API messages are untrusted; redact anything resembling credentials/URLs.
    message=re.sub(r"https?://\S+","[url]",message)
    message=re.sub(r"(?i)(gh[pousr]_[A-Za-z0-9_]+|github_pat_[A-Za-z0-9_]+|Bearer\s+\S+)","[redacted]",message)
    return {"phase":phase,"http_status":status,"api_message":message}


def probe(*,token,sha,run_id,target_sha,consent=False,transport=None):
    if consent is not True:raise ProbeDenied("357_EXPLICIT_CONSENT_REQUIRED")
    if not isinstance(token,str) or not token:raise ProbeDenied("357_MISSING_TOKEN")
    if not isinstance(sha,str) or not re.fullmatch("[0-9a-f]{40}",sha):
        raise ProbeDenied("357_INVALID_SHA")
    if not isinstance(run_id,str) or not re.fullmatch("[1-9][0-9]{5,19}",run_id):
        raise ProbeDenied("357_INVALID_RUN_ID")
    if not isinstance(target_sha,str) or not re.fullmatch("[0-9a-f]{40}",target_sha) or target_sha==sha:
        raise ProbeDenied("357_DISTINCT_TARGET_SHA_REQUIRED")
    tag="final128-task1-real-ab-once-v1-"+sha+"-"+run_id
    ref="refs/tags/"+tag
    root="https://api.github.com/repos/"+REPO+"/git/refs"
    sender=transport if transport is not None else urllib.request.urlopen
    def call(method,url,payload=None):
        headers={"Authorization":"Bearer "+token,"Accept":"application/vnd.github+json",
                 "X-GitHub-Api-Version":"2022-11-28"}
        req=urllib.request.Request(url,method=method,headers=headers,
              data=json.dumps(payload).encode() if payload is not None else None)
        try:
            with sender(req,timeout=15) as response:
                raw=response.read(100000)
                return response.status,json.loads(raw) if raw else {}
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read(100000) or b'{}')
        except Exception as exc:
            raise ProbeDenied("357_AMBIGUOUS_GITHUB_API_FAILURE") from exc
    status,data=call("POST",root,{"ref":ref,"sha":sha})
    if status!=201 or data.get("ref")!=ref:
        raise ProbeDenied("357_TAG_CREATION_NOT_CONFIRMED")
    # Only attempt modifications on the exact isolated tag just created.
    url=root+"/tags/"+tag
    def assert_unchanged(phase):
        status,body=call("GET",url)
        if status!=200 or body.get("ref")!=ref or body.get("object",{}).get("sha")!=sha:
            raise ProbeDenied("357_"+phase+"_REF_NOT_UNCHANGED")
    def ruleset_denied(status,body):
        if status not in (403,422) or not isinstance(body,dict):return False
        msg=body.get("message","")
        if not isinstance(msg,str):return False
        msg=msg.lower()
        # Explicit rule violation is required: generic 403/422 must never pass.
        return ("repository rule violations found" in msg and
                ("cannot update this protected ref" in msg or
                 "cannot delete this protected ref" in msg or
                 "cannot force-push to this tag" in msg))
    assert_unchanged("CREATED")
    update_status,update_body=call("PATCH",url,{"sha":target_sha,"force":True})
    print(json.dumps(safe_api_evidence("UPDATE",update_status,update_body),sort_keys=True),flush=True)
    assert_unchanged("UPDATE")
    if not ruleset_denied(update_status,update_body):
        raise ProbeDenied("357_UPDATE_RULESET_DENIAL_NOT_PROVEN")
    delete_status,delete_body=call("DELETE",url)
    print(json.dumps(safe_api_evidence("DELETE",delete_status,delete_body),sort_keys=True),flush=True)
    assert_unchanged("DELETE")
    if not ruleset_denied(delete_status,delete_body):
        raise ProbeDenied("357_DELETE_RULESET_DENIAL_NOT_PROVEN")
    return {"tag_ref":ref,"creation_status":201,"update_status":update_status,
            "delete_status":delete_status,"readback_unchanged":True,
            "no_provider_calls":True,"note":"Diagnostic tag; not provider lease"}
