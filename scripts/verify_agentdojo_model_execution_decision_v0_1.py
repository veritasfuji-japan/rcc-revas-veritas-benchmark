#!/usr/bin/env python3
import ast,hashlib,json,os
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]; C=json.loads((ROOT/"contracts"/"AGENTDOJO_MODEL_EXECUTION_DECISION_v0.1.json").read_text()); AD=Path(os.environ["AGENTDOJO_REPO"]); P=AD/C["verified_agentdojo_local_surface"]["source_path"]
src=P.read_text(); tree=ast.parse(src)
assert "class LocalLLM" in src and "random.randint(0, 1000000)" in src and "vllm serve" in src
assert C["execution_gate"]=="CLOSED" and C["zero_cost_constraints"]["provider_spend_cap_usd"]==0
report={"status":"PASS_MODEL_DECISION_GATE_CLOSED","agentdojo_local_llm_sha256":hashlib.sha256(P.read_bytes()).hexdigest(),"required_before_model_freeze":C["required_before_model_freeze"],"execution_gate":"CLOSED","clean_ab_executed":False}
Path("agentdojo-model-execution-decision-v0_1-audit.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n");print(json.dumps(report,indent=2,sort_keys=True))
