#!/usr/bin/env python3
"""Final 128 real provider wrapper V3 — frozen fail-closed implementation.

No V5 authorization is issued by this file. Audit/preflight cannot consume an
authorization, read OPENAI_API_KEY, call a provider, or execute Final 128.
"""
from __future__ import annotations
import argparse, asyncio, hashlib, json, os, subprocess, tempfile
from datetime import datetime, timezone
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
AUTH_PATH="contracts/AGENTDOJO_FINAL_128_EXECUTION_AUTHORIZATION_v5.json"
AUTH_ID="AGENTDOJO_CANONICAL_FINAL_128_EXECUTION_V5"
CONFIRM="RUN_FINAL_128_V5_ONCE"
RUNNER="scripts/agentdojo_clean_ab_canonical_final_runner_v2_1.py"
RUNNER_BLOB="d1f146cafbb649537fadaa3f593b7620918847fd"
RECEIPT_SCHEMA="veritas.agentdojo-final-128-runtime-dispatch-receipt.v1"
def sha(s): return hashlib.sha256(s.encode()).hexdigest()
def blob(p): return subprocess.run(["git","hash-object",str(ROOT/p)],check=True,capture_output=True,text=True).stdout.strip()
def audit():
 assert blob(RUNNER)==RUNNER_BLOB
 assert not (ROOT/AUTH_PATH).exists(), "V5_MUST_NOT_EXIST_BEFORE_REAL_WRAPPER_FREEZE"
 return {"proof":"FINAL_128_REAL_PROVIDER_WRAPPER_V3","mode":"AUDIT_ONLY","v5_exists":False,
 "database_write":0,"provider_credential_access":0,"provider_api_calls":0,"final_128_execution":0}
async def execute(args):
 if not (ROOT/AUTH_PATH).exists(): raise SystemExit("V5_AUTHORIZATION_MISSING")
 a=json.loads((ROOT/AUTH_PATH).read_text())
 assert a["authorization"]["id"]==AUTH_ID and a["authorization"]["issued"] is True
 assert a["authorization"]["single_use"] is True and a["authorization"]["consumed"] is False
 assert a["authorization"]["rerun_authorized"] is False
 assert a["dispatch"]["provider_dispatch_authorized"] is True
 assert a["cost_boundary"]["maximum_usd"]==5 and a["cost_boundary"]["cost_confirmation_received"] is True
 assert a["frozen_target"]["wrapper_git_blob_sha"]==blob("scripts/final_128_real_provider_wrapper_v3.py")
 assert a["frozen_target"]["runner_git_blob_sha"]==RUNNER_BLOB
 if args.confirmation!=CONFIRM: raise SystemExit("EXACT_V5_EXECUTION_CONFIRMATION_REQUIRED")
 from veritas_os.policy.live_adapter_bind_authorization_consumption_store import PostgresAtomicAuthorizationConsumptionStore, build_authorization_consumption_record
 from veritas_os.storage.db import close_pool
 if not os.environ.get("VERITAS_DATABASE_URL","").startswith(("postgres://","postgresql://")): raise SystemExit("REAL_POSTGRES_REQUIRED")
 rec=build_authorization_consumption_record(
  live_adapter_bind_authorization_id=AUTH_ID,
  live_adapter_bind_authorization_hash=sha("agentdojo-final-128-execution-v5:"+AUTH_ID),
  idempotency_key="agentdojo-final-128-v5:"+sha(AUTH_ID),
  bind_context_hash=sha("canonical-final-128-provider-dispatch-v5"),
  execution_intent_id="agentdojo-canonical-final-128-provider-v5",
  execution_intent_hash=sha("agentdojo-canonical-final-128-provider-v5"),
  endpoint_identity_binding_digest=sha("openai:gpt-4.1-mini-2025-04-14"),
  credential_reference_digest=sha("github-actions:OPENAI_API_KEY"),
  credential_scope_binding_digest=sha("openai:model:gpt-4.1-mini-2025-04-14"),
  consumed_at=datetime.now(timezone.utc).isoformat())
 store=PostgresAtomicAuthorizationConsumptionStore()
 try:
  won=await store.consume_once(rec)
  if not won: raise SystemExit("V5_ALREADY_CONSUMED_FAIL_CLOSED")
  durable=await store.get(AUTH_ID)
  if durable is None: raise SystemExit("V5_DURABLE_ROW_MISSING_AFTER_CONSUME")
  if durable.consumption_id!=rec.consumption_id or durable.consumption_hash!=rec.consumption_hash:
   raise SystemExit("V5_DURABLE_ROW_IDENTITY_MISMATCH")
 finally:
  await close_pool()
 receipt={"schema_version":RECEIPT_SCHEMA,"authorization_id":AUTH_ID,"durable_authorization_id":AUTH_ID,
  "atomic_consumption_won":True,"single_use":True,"rerun_authorized":False,"provider_spend_cap_usd":5.0,
  "consumption_id":rec.consumption_id,"consumption_hash":rec.consumption_hash}
 with tempfile.NamedTemporaryFile("w",suffix=".json",delete=False) as f:
  json.dump(receipt,f,sort_keys=True); receipt_path=f.name
 # Provider credential is inspected only after atomic durable winner + read-back.
 if not os.environ.get("OPENAI_API_KEY"): raise SystemExit("OPENAI_API_KEY_MISSING_AFTER_CONSUME_AUTH_BURNED")
 cmd=["python",RUNNER,"--execute","--confirmation","RUN_CANONICAL_AGENTDOJO_CLEAN_AB_V2_1",
      "--runtime-dispatch-receipt",receipt_path,
      "--agentdojo-root",args.agentdojo_root,"--rcc-root",args.rcc_root,"--veritas-root",args.veritas_root,
      "--output-dir",args.output_dir]
 raise SystemExit(subprocess.call(cmd))
def main():
 p=argparse.ArgumentParser(); p.add_argument("--execute",action="store_true"); p.add_argument("--confirmation",default="")
 p.add_argument("--agentdojo-root",default="_pins/agentdojo"); p.add_argument("--rcc-root",default="_pins/rcc")
 p.add_argument("--veritas-root",default="_pins/veritas"); p.add_argument("--output-dir",default="results/agentdojo-clean-ab-final-v5")
 x=p.parse_args()
 if not x.execute: print(json.dumps(audit(),sort_keys=True)); return
 asyncio.run(execute(x))
if __name__=="__main__": main()
