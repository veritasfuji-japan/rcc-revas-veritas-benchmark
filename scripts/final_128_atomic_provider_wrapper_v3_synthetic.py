#!/usr/bin/env python3
"""Provider-disabled synthetic proof for the V5 wrapper/receipt/runner-v2 chain."""
from __future__ import annotations
import argparse, asyncio, hashlib, json, os, subprocess, tempfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
AUTH_ID_PREFIX="AGENTDOJO_CANONICAL_FINAL_128_EXECUTION_V5_SYNTHETIC"
RUNNER="scripts/agentdojo_clean_ab_canonical_final_runner_v2_1.py"
RUNNER_BLOB="8fbbe1e82e59ec2b5cdfa04c83fb805a83181b79"
SCHEMA="veritas.agentdojo-final-128-runtime-dispatch-receipt.v1"

def h(s:str)->str: return hashlib.sha256(s.encode()).hexdigest()
async def attempt(i:int, semaphore, auth_id):
 from veritas_os.policy.live_adapter_bind_authorization_consumption_store import PostgresAtomicAuthorizationConsumptionStore, build_authorization_consumption_record
 rec=build_authorization_consumption_record(
  live_adapter_bind_authorization_id=auth_id,
  live_adapter_bind_authorization_hash=h("synthetic-v5:"+auth_id),
  idempotency_key="synthetic-v5:"+h(auth_id),
  bind_context_hash=h("canonical-final-128-wrapper-v3-synthetic"),
  execution_intent_id="synthetic-final-128-v5",
  execution_intent_hash=h("synthetic-final-128-v5"),
  endpoint_identity_binding_digest=h("openai:gpt-4.1-mini-2025-04-14"),
  credential_reference_digest=h("github-actions:OPENAI_API_KEY"),
  credential_scope_binding_digest=h("openai:model:gpt-4.1-mini-2025-04-14"),
  consumed_at="2026-10-06T00:00:00+00:00")
 async with semaphore:
  won=await PostgresAtomicAuthorizationConsumptionStore().consume_once(rec)
 return i,won,rec

async def main_async(a):
 from veritas_os.storage.db import close_pool
 if not os.environ.get("VERITAS_DATABASE_URL","").startswith(("postgres://","postgresql://")): raise SystemExit("REAL_POSTGRES_REQUIRED")
 if os.environ.get("OPENAI_API_KEY"): raise SystemExit("PROVIDER_CREDENTIAL_MUST_BE_ABSENT")
 if not a.synthetic_run_id or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for c in a.synthetic_run_id): raise SystemExit("VALID_SYNTHETIC_RUN_ID_REQUIRED")
 auth_id=AUTH_ID_PREFIX+"_"+a.synthetic_run_id
 semaphore=asyncio.Semaphore(a.max_db_concurrency)
 try: rows=await asyncio.gather(*(attempt(i,semaphore,auth_id) for i in range(a.attempts)))
 finally: await close_pool()
 winners=[x for x in rows if x[1]]
 if len(winners)!=1: raise SystemExit(f"ATOMIC_WINNER_COUNT:{len(winners)}")
 _,_,rec=winners[0]
 # Synthetic auth is translated to the exact V5 receipt shape solely for the
 # provider-disabled runner gate test; no real V5 authorization exists/consumes.
 receipt={"schema_version":SCHEMA,"authorization_id":"AGENTDOJO_CANONICAL_FINAL_128_EXECUTION_V5",
 "atomic_consumption_won":True,"single_use":True,"rerun_authorized":False,"provider_spend_cap_usd":5.0,
 "synthetic_source_authorization_id":auth_id,"durable_authorization_id":auth_id,"consumption_id":rec.consumption_id,"consumption_hash":rec.consumption_hash,
 "runner_git_blob_sha":RUNNER_BLOB}
 with tempfile.TemporaryDirectory() as d:
  p=Path(d)/"receipt.json"; p.write_text(json.dumps(receipt,sort_keys=True))
  cmd=["python",RUNNER,"--preflight-runtime-receipt","--runtime-dispatch-receipt",str(p),
       "--agentdojo-root",a.agentdojo_root,"--rcc-root",a.rcc_root,"--veritas-root",a.veritas_root]
  cp=subprocess.run(cmd,check=True,capture_output=True,text=True)
 print(json.dumps({"proof":"WRAPPER_V3_SYNTHETIC_INTEGRATION_V1","synthetic_source_authorization_id":auth_id,"attempts":a.attempts,"max_db_concurrency":a.max_db_concurrency,"winners":1,
 "losers":a.attempts-1,"runner_v2_preflight":True,"provider_credential_access":0,"provider_api_calls":0,
 "final_128_execution":0,"human_v5_authorization_consumed":False,"runner_output":cp.stdout.strip()},sort_keys=True))

def main():
 p=argparse.ArgumentParser();p.add_argument("--attempts",type=int,default=32);p.add_argument("--max-db-concurrency",type=int,default=4);p.add_argument("--synthetic-run-id",required=True)
 p.add_argument("--agentdojo-root",default="_pins/agentdojo");p.add_argument("--rcc-root",default="_pins/rcc");p.add_argument("--veritas-root",default="_pins/veritas")
 asyncio.run(main_async(p.parse_args()))
if __name__=="__main__": main()
