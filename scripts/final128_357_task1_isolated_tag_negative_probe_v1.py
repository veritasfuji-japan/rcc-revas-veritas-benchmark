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

def probe(*,token,sha,run_id,consent=False,transport=None):
    if consent is not True:raise ProbeDenied("357_EXPLICIT_CONSENT_REQUIRED")
    if not isinstance(token,str) or not token:raise ProbeDenied("357_MISSING_TOKEN")
    if not isinstance(sha,str) or not re.fullmatch("[0-9a-f]{40}",sha):
        raise ProbeDenied("357_INVALID_SHA")
    if not isinstance(run_id,str) or not re.fullmatch("[1-9][0-9]{5,19}",run_id):
        raise ProbeDenied("357_INVALID_RUN_ID")
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
            return exc.code,{}
        except Exception as exc:
            raise ProbeDenied("357_AMBIGUOUS_GITHUB_API_FAILURE") from exc
    status,data=call("POST",root,{"ref":ref,"sha":sha})
    if status!=201 or data.get("ref")!=ref:
        raise ProbeDenied("357_TAG_CREATION_NOT_CONFIRMED")
    # Only attempt modifications on the exact isolated tag just created.
    url=root+"/tags/"+tag
    update_status,_=call("PATCH",url,{"sha":sha,"force":True})
    if update_status not in (403,422):
        raise ProbeDenied("357_UPDATE_NOT_PROVEN_REJECTED")
    delete_status,_=call("DELETE",url)
    if delete_status not in (403,422):
        raise ProbeDenied("357_DELETE_NOT_PROVEN_REJECTED")
    return {"tag_ref":ref,"creation_status":201,"update_status":update_status,
            "delete_status":delete_status,"no_provider_calls":True,
            "note":"Isolated run-bound diagnostic tag; not provider lease"}
