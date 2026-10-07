#!/usr/bin/env python3
import json, subprocess
from pathlib import Path
F=Path("contracts/AGENTDOJO_FINAL_128_V10_TARGET_FREEZE_v1.json")
d=json.loads(F.read_text())
assert d["status"]=="FROZEN_PRE_AUTHORIZATION"
assert d["frozen_from_main_sha"]=="b2fa8c28e4d0e319e52ff6619983bdadcaa7971b"
paths={
"runner_v2_5":"scripts/agentdojo_clean_ab_canonical_final_runner_v2_5.py",
"wrapper_v8":"scripts/final_128_real_provider_wrapper_v8.py",
"manual_dispatch_workflow":".github/workflows/final-128-v10-manual-dispatch.yml",
"provider_free_full_path_workflow":".github/workflows/final-128-v10-provider-free-full-path.yml",
"complete_chain_semantic_audit":"scripts/final_128_v10_complete_chain_audit_v1.py",
"complete_chain_audit_workflow":".github/workflows/final-128-v10-complete-chain-audit.yml"}
def blob(p): return subprocess.run(["git","hash-object",p],check=True,capture_output=True,text=True).stdout.strip()
for k,p in paths.items(): assert blob(p)==d["frozen_blobs"][k],(k,blob(p),d["frozen_blobs"][k])
assert d["external_pins"]=={"agentdojo":"a75aba7631d3ca5fb7ab938965c97ead2f9ff84b","rcc":"1d3782d3aae5ff9c88036709c1a5642320cc53c2","veritas_os":"a1d66aef02262cf8a913295270c3aafd159c6adb","model":"gpt-4.1-mini-2025-04-14","python":"3.11.16"}
assert d["bounded_runtime"]["openai"]=="1.109.1"
assert d["execution_state"]=={"authorization_issued":False,"human_confirmation_received":False,"durable_consume":0,"provider_credential_access":0,"provider_api_calls":0,"final_128_execution":0}
assert not Path("contracts/AGENTDOJO_FINAL_128_EXECUTION_AUTHORIZATION_v10.json").exists()
print("PASS_V10_EXACT_TARGET_FREEZE")
