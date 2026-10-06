#!/usr/bin/env python3
"""Real-auth atomic consume implementation. Audit is default; consume requires explicit invocation."""
from __future__ import annotations
import argparse, asyncio, hashlib, json, os
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
AUTH_ID="AGENTDOJO_CANONICAL_FINAL_128_SINGLE_USE_V2"
CONFIRM="CONSUME_REAL_AUTH_V2_ONCE"
def sha(s): return hashlib.sha256(s.encode()).hexdigest()
def load(p): return json.loads((ROOT/p).read_text())
def validate():
 a=load("contracts/AGENTDOJO_FINAL_128_HUMAN_AUTHORIZATION_ISSUANCE_v2.json")
 assert a["human_approval"]["authorization_id"]==AUTH_ID
 assert a["human_approval"]["single_use"] is True
 assert a["authorization_state"]["issued"] is True
 assert a["authorization_state"]["consumed"] is False
 assert a["authorization_state"]["dispatch_performed"] is False
 assert a["execution_gate"]=="CLOSED"
 assert a["provider_execution_authorized"] is False
 return a
async def consume():
 from veritas_os.policy.live_adapter_bind_authorization_consumption_store import PostgresAtomicAuthorizationConsumptionStore, build_authorization_consumption_record
 from veritas_os.storage.db import close_pool
 dsn=os.environ.get("VERITAS_DATABASE_URL","")
 if not dsn.startswith(("postgres://","postgresql://")): raise SystemExit("REAL_POSTGRES_REQUIRED")
 rec=build_authorization_consumption_record(
  live_adapter_bind_authorization_id=AUTH_ID,
  live_adapter_bind_authorization_hash=sha("agentdojo-final-128-human-authorization-v2:"+AUTH_ID),
  idempotency_key="agentdojo-final-128:"+sha(AUTH_ID),
  bind_context_hash=sha("canonical-final-128-bind-context-v1"),
  execution_intent_id="agentdojo-canonical-final-128-v1",
  execution_intent_hash=sha("agentdojo-canonical-final-128-v1"),
  endpoint_identity_binding_digest=sha("provider-boundary-disabled-preflight"),
  credential_reference_digest=sha("provider-credential-not-accessed"),
  credential_scope_binding_digest=sha("provider-scope-not-accessed"),
  consumed_at="2026-10-06T00:00:00+00:00")
 try:
  won=await PostgresAtomicAuthorizationConsumptionStore().consume_once(rec)
  if not won: raise SystemExit("REAL_AUTH_ALREADY_CONSUMED_FAIL_CLOSED")
  print(json.dumps({"proof":"REAL_AUTH_ATOMIC_CONSUME_V1","consumed":True,
   "provider_boundary_reached":False,"provider_credential_access":0,"provider_api_calls":0,"final_128_execution":0},sort_keys=True))
 finally: await close_pool()
def main():
 ap=argparse.ArgumentParser(); ap.add_argument("--consume",action="store_true"); ap.add_argument("--confirmation",default="")
 x=ap.parse_args(); validate()
 if not x.consume:
  print(json.dumps({"proof":"REAL_AUTH_ATOMIC_CONSUME_IMPLEMENTATION_V1","mode":"AUDIT_ONLY","consumed":False,
   "database_access":0,"provider_credential_access":0,"provider_api_calls":0,"final_128_execution":0},sort_keys=True)); return
 if x.confirmation!=CONFIRM: raise SystemExit("EXACT_CONSUME_CONFIRMATION_REQUIRED")
 asyncio.run(consume())
if __name__=="__main__": main()
