#!/usr/bin/env python3
import json
from pathlib import Path
p=Path("contracts/AGENTDOJO_FINAL_128_V8_BURNED_NO_RESULT_v1.json")
d=json.loads(p.read_text())
assert d["status"]=="CONSUMED_BURNED_FINAL_128_NOT_COMPLETED"
assert d["authorization_id"]=="AGENTDOJO_CANONICAL_FINAL_128_EXECUTION_V8"
assert d["dispatch_evidence"]["workflow_run_id"]==37486065624
assert d["dispatch_evidence"]["job_id"]==112346254963
assert d["dispatch_evidence"]["conclusion"]=="failure"
assert "rveval" in d["dispatch_evidence"]["failure"]
assert d["disposition"]["authorization_consumed"] is True
assert d["disposition"]["authorization_burned"] is True
assert d["disposition"]["rerun_authorized"] is False
assert d["disposition"]["final_128_completed"] is False
assert d["disposition"]["final_result_claimed"] is False
assert d["disposition"]["artifact_present"] is False
assert d["evidence_semantics"]["v8_must_never_be_reused"] is True
print("PASS_V8_BURNED_NO_RESULT_FREEZE")
