#!/usr/bin/env python3
from __future__ import annotations
import argparse, asyncio, hashlib, json, os, subprocess, tempfile, uuid
from datetime import datetime, timezone
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
RUNNER="scripts/agentdojo_clean_ab_canonical_final_runner_v2_3.py"
AUTH_PREFIX="AGENTDOJO_CANONICAL_FINAL_128_EXECUTION_V8_SYNTHETIC_"
def sha(s): return hashlib.sha256(s.encode()).hexdigest()
async def main():
 p=argparse.ArgumentParser(); p.add_argument("--agentdojo-root",required=True); p.add_argument("--rcc-root",required=True); p.add_argument("--veritas-root",required=True); a=p.parse_args()
 if not os.environ.get("VERITAS_DATABASE_URL","").startswith(("postgres://","postgresql://")): raise SystemExit("REAL_POSTGRES_REQUIRED")
 auth=AUTH_PREFIX+uuid.uuid4().hex
 from veritas_os.policy.live_adapter_bind_authorization_consumption_store import PostgresAtomicAuthorizationConsumptionStore, build_authorization_consumption_record
 from veritas_os.storage.db import close_pool
 rec=build_authorization_consumption_record(live_adapter_bind_authorization_id=auth,live_adapter_bind_authorization_hash=sha("v8-synthetic:"+auth),idempotency_key="v8-synthetic:"+sha(auth),bind_context_hash=sha("v8-synthetic-bind"),execution_intent_id="v8-synthetic",execution_intent_hash=sha("v8-synthetic"),endpoint_identity_binding_digest=sha("synthetic:no-provider"),credential_reference_digest=sha("synthetic:no-credential"),credential_scope_binding_digest=sha("synthetic:no-scope"),consumed_at=datetime.now(timezone.utc).isoformat())
 store=PostgresAtomicAuthorizationConsumptionStore()
 try:
  results=await asyncio.gather(*[store.consume_once(rec) for _ in range(4)])
  durable=await store.get(auth)
 finally: await close_pool()
 assert sum(bool(x) for x in results)==1 and durable is not None
 receipt={"schema_version":"veritas.agentdojo-final-128-runtime-dispatch-receipt.v1","authorization_id":"AGENTDOJO_CANONICAL_FINAL_128_EXECUTION_V8","durable_authorization_id":auth,"atomic_consumption_won":True,"single_use":True,"rerun_authorized":False,"provider_spend_cap_usd":5.0,"consumption_id":rec.consumption_id,"consumption_hash":rec.consumption_hash}
 with tempfile.NamedTemporaryFile("w",suffix=".json",delete=False) as f: json.dump(receipt,f); rp=f.name
 env=dict(os.environ); env.pop("OPENAI_API_KEY",None)
 cmd=["python",RUNNER,"--preflight-runtime-receipt","--runtime-dispatch-receipt",rp,"--agentdojo-root",a.agentdojo_root,"--rcc-root",a.rcc_root,"--veritas-root",a.veritas_root]
 cp=subprocess.run(cmd,env=env,check=True,capture_output=True,text=True)
 print(json.dumps({"status":"PASS_V8_SYNTHETIC_DURABLE_DB_PROOF","attempts":4,"winners":1,"losers":3,"durable_row":1,"runner_preflight":cp.stdout.strip(),"provider_credential_access":0,"provider_api_calls":0,"final_128_execution":0},sort_keys=True))
if __name__=="__main__": asyncio.run(main())
