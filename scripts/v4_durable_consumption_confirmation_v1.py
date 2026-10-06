#!/usr/bin/env python3
import asyncio, json, os
AUTH_ID="AGENTDOJO_CANONICAL_FINAL_128_EXECUTION_V4"
async def main():
 from veritas_os.storage.db import get_pool, close_pool
 if not os.environ.get("VERITAS_DATABASE_URL","").startswith(("postgres://","postgresql://")): raise SystemExit("REAL_POSTGRES_REQUIRED")
 try:
  pool=await get_pool()
  async with pool.connection() as conn:
   async with conn.cursor() as cur:
    await cur.execute("SELECT authorization_id, consumption_hash, consumed_at FROM bind_authorization_consumptions WHERE authorization_id=%s",(AUTH_ID,))
    rows=await cur.fetchall()
  assert len(rows)==1, f"EXPECTED_EXACTLY_ONE_DURABLE_V4_ROW_GOT_{len(rows)}"
  print(json.dumps({"proof":"V4_DURABLE_CONSUMPTION_CONFIRMATION_V1","authorization_id":AUTH_ID,"durable_rows":1,"burned":True,
    "provider_api_result_claimed":False,"final_128_result_claimed":False},sort_keys=True))
 finally: await close_pool()
asyncio.run(main())
