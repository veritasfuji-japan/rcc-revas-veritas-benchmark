"""#355 read-only live Ruleset evidence. Never prints GitHub credentials."""
import argparse
import hashlib
import json
import os
import sys
from scripts.final128_354_task1_live_ruleset_fetch_v1 import fetch_and_verify,FetchDenied

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--tag-name",required=True)
    parser.add_argument("--output",required=True)
    args=parser.parse_args()
    if os.environ.get("GITHUB_REPOSITORY")!="veritasfuji-japan/rcc-revas-veritas-benchmark":
        raise SystemExit("355_REPOSITORY_MISMATCH")
    if os.environ.get("GITHUB_REF")!="refs/heads/main":
        raise SystemExit("355_NOT_MAIN")
    token=os.environ.get("GH_RULESET_READ_TOKEN","")
    if not token:raise SystemExit("355_MISSING_READ_TOKEN")
    try:
        proof=fetch_and_verify(token=token,tag_name=args.tag_name)
    except FetchDenied as exc:
        print(str(exc),file=sys.stderr)
        raise SystemExit(2)
    # This report proves only API readback under supplied credential, not enforcement.
    evidence={"schema":"final128-task1-ruleset-live-readback-v1",
       "repository":os.environ["GITHUB_REPOSITORY"],
       "ref":os.environ["GITHUB_REF"],
       "run_id":os.environ.get("GITHUB_RUN_ID"),
       "commit_sha":os.environ.get("GITHUB_SHA"),
       "ruleset":proof,
       "provider_calls":0,"tag_mutations":0,
       "live_update_delete_rejection_proven":False,
       "single_use_proven":False}
    blob=(json.dumps(evidence,sort_keys=True,indent=2)+"\n").encode()
    with open(args.output,"wb") as f:f.write(blob)
    print("355_READBACK_PASS sha256="+hashlib.sha256(blob).hexdigest())
if __name__=="__main__":main()
