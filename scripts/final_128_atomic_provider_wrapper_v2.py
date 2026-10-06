#!/usr/bin/env python3
"""Final 128 atomic provider wrapper V2.

Audit-only in this frozen version. Execution wiring is structurally defined but
cannot be entered until a later exact-target V4 authorization contract exists.
"""
from __future__ import annotations
import argparse, asyncio, hashlib, json, os, subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
AUTH_PATH="contracts/AGENTDOJO_FINAL_128_EXECUTION_AUTHORIZATION_v4.json"
AUTH_ID="AGENTDOJO_CANONICAL_FINAL_128_EXECUTION_V4"
CONFIRM="RUN_FINAL_128_V4_ONCE"
RUNNER="scripts/agentdojo_clean_ab_canonical_final_runner_v1.py"
RUNNER_BLOB="d1e5d7bfda41d7dcd9ee7e16a5b0e8dbba5cb89c"
def sha(s): return hashlib.sha256(s.encode()).hexdigest()
def blob(p): return subprocess.run(["git","hash-object",str(ROOT/p)],check=True,capture_output=True,text=True).stdout.strip()
def audit():
 assert blob(RUNNER)==RUNNER_BLOB
 assert not (ROOT/AUTH_PATH).exists(), "V4_MUST_BE_ISSUED_ONLY_AFTER_WRAPPER_FREEZE"
 return {"proof":"FINAL_128_ATOMIC_PROVIDER_WRAPPER_V2","mode":"AUDIT_ONLY","v4_exists":False,
 "database_access":0,"provider_credential_access":0,"provider_api_calls":0,"final_128_execution":0}
async def execute(args):
 if not (ROOT/AUTH_PATH).exists(): raise SystemExit("V4_AUTHORIZATION_MISSING")
 a=json.loads((ROOT/AUTH_PATH).read_text())
 assert a["authorization"]["id"]==AUTH_ID and a["authorization"]["issued"] is True
 assert a["authorization"]["single_use"] is True and a["authorization"]["consumed"] is False
 assert a["dispatch"]["provider_dispatch_authorized"] is True
 assert a["cost_boundary"]["maximum_usd"]==5
 assert a["exact_target"]["wrapper_git_blob_sha"]==blob("scripts/final_128_atomic_provider_wrapper_v2.py")
 assert a["exact_target"]["runner_git_blob_sha"]==RUNNER_BLOB
 if args.confirmation!=CONFIRM: raise SystemExit("EXACT_V4_EXECUTION_CONFIRMATION_REQUIRED")
 from veritas_os.policy.live_adapter_bind_authorization_consumption_store import PostgresAtomicAuthorizationConsumptionStore, build_authorization_consumption_record
 from veritas_os.storage.db import close_pool
 if not os.environ.get("VERITAS_DATABASE_URL","").startswith(("postgres://","postgresql://")): raise SystemExit("REAL_POSTGRES_REQUIRED")
 rec=build_authorization_consumption_record(
  live_adapter_bind_authorization_id=AUTH_ID,
  live_adapter_bind_authorization_hash=sha("agentdojo-final-128-execution-v4:"+AUTH_ID),
  idempotency_key="agentdojo-final-128-v4:"+sha(AUTH_ID),
  bind_context_hash=sha("canonical-final-128-provider-dispatch-v4"),
  execution_intent_id="agentdojo-canonical-final-128-provider-v4",
  execution_intent_hash=sha("agentdojo-canonical-final-128-provider-v4"),
  endpoint_identity_binding_digest=sha("openai:gpt-4.1-mini-2025-04-14"),
  credential_reference_digest=sha("github-actions:OPENAI_API_KEY"),
  credential_scope_binding_digest=sha("openai:model:gpt-4.1-mini-2025-04-14"),
  consumed_at="2026-10-06T00:00:00+00:00")
 try:
  won=await PostgresAtomicAuthorizationConsumptionStore().consume_once(rec)
  if not won: raise SystemExit("V4_ALREADY_CONSUMED_FAIL_CLOSED")
 finally: await close_pool()
 # Credential is checked only after durable consumption winner is established.
 if not os.environ.get("OPENAI_API_KEY"): raise SystemExit("OPENAI_API_KEY_MISSING_AFTER_CONSUME_AUTH_BURNED")
 cmd=["python",RUNNER,"--execute","--confirmation","RUN_CANONICAL_AGENTDOJO_CLEAN_AB_V1",
      "--agentdojo-root",args.agentdojo_root,"--rcc-root",args.rcc_root,"--veritas-root",args.veritas_root,
      "--output-dir",args.output_dir]
 raise SystemExit(subprocess.call(cmd))
def main():
 p=argparse.ArgumentParser(); p.add_argument("--execute",action="store_true"); p.add_argument("--confirmation",default="")
 p.add_argument("--agentdojo-root",default="_pins/agentdojo"); p.add_argument("--rcc-root",default="_pins/rcc")
 p.add_argument("--veritas-root",default="_pins/veritas"); p.add_argument("--output-dir",default="results/agentdojo-clean-ab-final-v4")
 x=p.parse_args()
 if not x.execute: print(json.dumps(audit(),sort_keys=True)); return
 asyncio.run(execute(x))
if __name__=="__main__": main()
