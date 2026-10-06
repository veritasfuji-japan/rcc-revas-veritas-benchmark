#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, os, subprocess, sys
from pathlib import Path

RCC_COMMIT="1d3782d3aae5ff9c88036709c1a5642320cc53c2"

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--rcc-root",required=True)
    a=p.parse_args()
    root=Path(a.rcc_root).resolve()
    src=root/"external-eval/v0.3.9/src"
    policy=src/"rveval/resources/policy.json"
    if not src.is_dir() or not policy.is_file():
        raise SystemExit("RCC_V039_LAYOUT_MISSING")
    sys.path.insert(0,str(src))
    from rveval.integrations.rcc_external import ExternalRCCGate
    from rveval.canonical import sha_json
    from rveval.models import CandidateAction
    assert ExternalRCCGate is not None and sha_json is not None and CandidateAction is not None
    print(json.dumps({
      "status":"PASS_RCC_V039_RUNTIME_IMPORT",
      "rcc_commit":RCC_COMMIT,
      "rveval_src":str(src),
      "policy_exists":True,
      "provider_credential_access":0,
      "provider_api_calls":0,
      "final_128_execution":0
    },sort_keys=True))
if __name__=="__main__":
    main()
