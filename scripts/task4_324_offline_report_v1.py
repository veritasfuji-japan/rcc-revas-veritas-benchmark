#!/usr/bin/env python3
"""#324 CI-only report from an OFFLINE simulated reservation, not a sender."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from scripts.task4_324_offline_predispatch_guard_v1 import (
    exact_offline_example, digest, Denied,
)


def main() -> None:
    p=argparse.ArgumentParser()
    p.add_argument("--output",required=True)
    args=p.parse_args()
    target=(ROOT/args.output).resolve()
    if not target.is_relative_to(ROOT/"results") or target.suffix != ".json":
        raise Denied("ONLY_LOCAL_RESULTS_JSON_PATH")
    if target.exists():
        raise Denied("REFUSE_EXISTING_SIMULATED_PROOF_OVERWRITE")
    result=exact_offline_example()
    validated=dict(result)
    signature=validated.pop("report_sha256")
    if digest(validated)!=signature or result["real_provider_post_allowed"] is not False:
        raise Denied("LOCAL_HASH_OR_LIVE_DENIAL_INTEGRITY_FAILURE")
    target.parent.mkdir(parents=True,exist_ok=True)
    target.write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
    print("TASK4_324_10_LOCAL_RESERVATIONS_UNKNOWN_FREEZE_NO_PROVIDER_POST")

if __name__=="__main__":
    main()
