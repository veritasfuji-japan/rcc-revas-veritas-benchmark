#!/usr/bin/env python3
from __future__ import annotations
import asyncio, json, os
AUTH_ID="AGENTDOJO_CANONICAL_FINAL_128_EXECUTION_V8"
async def main():
    if not os.environ.get("VERITAS_DATABASE_URL","").startswith(("postgres://","postgresql://")):
        raise SystemExit("REAL_POSTGRES_REQUIRED")
    from veritas_os.policy.live_adapter_bind_authorization_consumption_store import PostgresAtomicAuthorizationConsumptionStore
    from veritas_os.storage.db import close_pool
    store=PostgresAtomicAuthorizationConsumptionStore()
    try:
        durable=await store.get(AUTH_ID)
    finally:
        await close_pool()
    if durable is not None:
        raise SystemExit("V8_ALREADY_CONSUMED_OR_ROW_EXISTS_FAIL_CLOSED")
    print(json.dumps({
        "status":"PASS_V8_DURABLE_UNCONSUMED_CHECK",
        "authorization_id":AUTH_ID,
        "durable_row":0,
        "provider_credential_access":0,
        "provider_api_calls":0,
        "final_128_execution":0
    },sort_keys=True))
if __name__=="__main__":
    asyncio.run(main())
