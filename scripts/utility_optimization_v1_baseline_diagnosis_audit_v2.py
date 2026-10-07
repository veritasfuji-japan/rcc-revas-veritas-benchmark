#!/usr/bin/env python3
from pathlib import Path

source = Path("scripts/utility_optimization_v1_baseline_diagnosis_audit.py")
text = source.read_text()
old = 'if "user_task_1" in cid:'
new = 'if ":user_task_1:" in cid:'
if text.count(old) != 1:
    raise SystemExit("UTILITY_DIAGNOSIS_EXPECTED_SINGLE_TASK_MATCH_SITE")
patched = text.replace(old, new)
exec(compile(patched, str(source), "exec"), {"__name__": "__main__", "__file__": str(source)})
