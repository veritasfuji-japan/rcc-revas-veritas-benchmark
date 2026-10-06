#!/usr/bin/env python3
import ast, json, subprocess
from pathlib import Path
R=Path("scripts/agentdojo_clean_ab_canonical_final_runner_v2_5.py")
W=Path("scripts/final_128_real_provider_wrapper_v8.py")
D=Path(".github/workflows/final-128-v10-manual-dispatch.yml")
P=Path(".github/workflows/final-128-v10-provider-free-full-path.yml")
G=json.loads(Path("contracts/AGENTDOJO_FINAL_128_V10_REGRESSION_GATES_v1.json").read_text())
assert len(G["gates"])==9
for p in (R,W,D,P): assert p.is_file() and p.stat().st_size>0
ast.parse(R.read_text()); ast.parse(W.read_text())
w=W.read_text(); d=D.read_text(); p=P.read_text()
assert 'RUNNER_BLOB="undefined"' not in w and 'RUNNER_BLOB="da86e5cb4ed44a1fb4cf991eade9cfc67ba92806"' in w
assert "wrapper_v6.py" not in w and "wrapper_v7.py" not in w
assert "AGENTDOJO_CANONICAL_FINAL_128_EXECUTION_V10" in w
assert "AGENTDOJO_FINAL_128_V10_HUMAN_CONFIRMATION_v1.json" in w
assert 'a["dispatch"]["provider_dispatch_authorized"] is True' in w
assert 'c["authorization_git_blob_sha"]==a["_self_blob"]' in w
assert "RUN_FINAL_128_V10_ONCE" in d and "final_128_real_provider_wrapper_v8.py --execute" in d
assert 'openai==1.53.0' in d and 'pip check' in d and 'pip check' in p
assert d.count('OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}') == 1
execute_block=d.split("- name: Execute exact V10 chain",1)[1]
assert 'OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}' in execute_block
assert "actions/upload-artifact@v4" in d and "results/agentdojo-clean-ab-final-v10" in d
assert 'OPENAI_API_KEY: ""' in p and 'VERITAS_DATABASE_URL: ""' in p
assert "final_128_real_provider_wrapper_v8.py --provider-free-preflight" in p
assert not Path("contracts/AGENTDOJO_FINAL_128_EXECUTION_AUTHORIZATION_v10.json").exists()
print("PASS_V10_COMPLETE_CHAIN_STATIC_SEMANTICS")
