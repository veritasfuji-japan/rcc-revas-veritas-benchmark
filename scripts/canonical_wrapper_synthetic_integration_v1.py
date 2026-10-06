#!/usr/bin/env python3
"""Synthetic-only actual-wrapper integration proof against shared PostgreSQL."""
from __future__ import annotations
import asyncio, hashlib, json, os
from uuid import uuid4
from veritas_os.policy.live_adapter_bind_authorization_consumption_store import (
 PostgresAtomicAuthorizationConsumptionStore, build_authorization_consumption_record)
from veritas_os.storage.db import get_pool, close_pool

REAL="AGENTDOJO_CANONICAL_FINAL_128_SINGLE_USE_V2"
def h(x): return hashlib.sha256(x.encode()).hexdigest()

async def main():
 dsn=os.environ.get("VERITAS_DATABASE_URL","")
 if not dsn.startswith(("postgres://","postgresql://")): raise SystemExit("REAL_POSTGRES_REQUIRED")
 token=uuid4().hex
 aid="synthetic:canonical-wrapper-integration:v1:"+h(token)
 assert aid != REAL and aid.startswith("synthetic:")
 rec=build_authorization_consumption_record(
  live_adapter_bind_authorization_id=aid,
  live_adapter_bind_authorization_hash=h("auth:"+aid),
  idempotency_key="synthetic-wrapper:"+h("idem:"+token),
  bind_context_hash=h("wrapper-bind:"+token),
  execution_intent_id="synthetic-wrapper-intent:"+token,
  execution_intent_hash=h("intent:"+token),
  endpoint_identity_binding_digest=h("endpoint:"+token),
  credential_reference_digest=h("credential-disabled:"+token),
  credential_scope_binding_digest=h("scope-disabled:"+token),
  consumed_at="2026-10-06T00:00:00+00:00")
 store=PostgresAtomicAuthorizationConsumptionStore()
 boundary=0
 lock=asyncio.Lock()
 async def contender():
  nonlocal boundary
  won=await store.consume_once(rec)
  if won:
   async with lock: boundary += 1
  return won
 try:
  pool=await get_pool()
  out=await asyncio.gather(*(contender() for _ in range(32)))
  async with pool.connection() as conn:
   cur=await conn.execute("SELECT count(*) FROM bind_authorization_consumptions WHERE authorization_id=%s",(aid,))
   row=await cur.fetchone()
  winners=out.count(True); losers=out.count(False); rows=int(row[0])
  assert (winners,losers,rows,boundary)==(1,31,1,1)
  print(json.dumps({"proof":"CANONICAL_WRAPPER_SYNTHETIC_INTEGRATION_V1","synthetic_authorization":True,
   "attempts":32,"winners":winners,"losers":losers,"authorization_rows":rows,
   "provider_boundary_markers":boundary,"human_authorization_v2_consumed":False,
   "provider_credential_access":0,"provider_api_calls":0,"final_128_execution":0},sort_keys=True))
 finally: await close_pool()
if __name__=="__main__": asyncio.run(main())
