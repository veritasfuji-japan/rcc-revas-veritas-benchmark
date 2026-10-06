#!/usr/bin/env python3
"""Real PostgreSQL atomic-consumption proof. No provider access."""

from __future__ import annotations
import asyncio
import hashlib
import json
import os
from uuid import uuid4

from veritas_os.policy.live_adapter_bind_authorization_consumption_store import (
    PostgresAtomicAuthorizationConsumptionStore,
    build_authorization_consumption_record,
)
from veritas_os.storage.db import close_pool, get_pool

def digest(v: str) -> str:
    return hashlib.sha256(v.encode()).hexdigest()

async def main() -> None:
    dsn = os.environ.get("VERITAS_DATABASE_URL", "")
    if not dsn.startswith(("postgres://", "postgresql://")):
        raise SystemExit("real PostgreSQL VERITAS_DATABASE_URL required")

    token = uuid4().hex
    auth_hash = digest("authorization:" + token)
    authorization_id = f"synthetic:canonical-dispatch-proof:v1:{auth_hash}"
    idempotency_key = f"synthetic-idem:v1:{digest('idem:' + token)}"
    record = build_authorization_consumption_record(
        live_adapter_bind_authorization_id=authorization_id,
        live_adapter_bind_authorization_hash=auth_hash,
        idempotency_key=idempotency_key,
        bind_context_hash=digest("bind-context:" + token),
        execution_intent_id="synthetic-intent:" + token,
        execution_intent_hash=digest("intent:" + token),
        endpoint_identity_binding_digest=digest("endpoint:" + token),
        credential_reference_digest=digest("credential:" + token),
        credential_scope_binding_digest=digest("scope:" + token),
        consumed_at="2026-10-06T00:00:00+00:00",
    )
    store = PostgresAtomicAuthorizationConsumptionStore()
    try:
        pool = await get_pool()
        outcomes = await asyncio.gather(*(store.consume_once(record) for _ in range(32)))
        async with pool.connection() as conn:
            cur = await conn.execute(
                "SELECT count(*) FROM bind_authorization_consumptions WHERE authorization_id = %s",
                (authorization_id,),
            )
            row = await cur.fetchone()
        winners = outcomes.count(True)
        losers = outcomes.count(False)
        rows = int(row[0]) if row else 0
        assert winners == 1, outcomes
        assert losers == 31, outcomes
        assert rows == 1, rows
        print(json.dumps({
            "proof":"CANONICAL_DISPATCH_ATOMIC_CONSUMPTION_V1",
            "synthetic_authorization": True,
            "attempts": 32,
            "winners": winners,
            "losers": losers,
            "authorization_rows": rows,
            "provider_credential_access": 0,
            "provider_api_calls": 0,
            "final_128_execution": 0,
            "human_authorization_v2_consumed": False
        }, sort_keys=True))
    finally:
        await close_pool()

if __name__ == "__main__":
    asyncio.run(main())
