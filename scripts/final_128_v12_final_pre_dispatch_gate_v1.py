#!/usr/bin/env python3
import json
import os
import psycopg

AUTH_ID = "AGENTDOJO_CANONICAL_FINAL_128_EXECUTION_V12"

if os.environ.get("OPENAI_API_KEY"):
    raise SystemExit("OPENAI_API_KEY_PRESENT_DURING_V12_PRE_DISPATCH_GATE")

dsn = os.environ.get("VERITAS_DATABASE_URL", "")
if not dsn.startswith(("postgres://", "postgresql://")):
    raise SystemExit("REAL_POSTGRES_REQUIRED_FOR_V12_PRE_DISPATCH_GATE")

with psycopg.connect(dsn) as c:
    with c.cursor() as cur:
        cur.execute(
            "SELECT COUNT(*) FROM bind_authorization_consumptions WHERE authorization_id=%s",
            (AUTH_ID,),
        )
        n = cur.fetchone()[0]

if n != 0:
    raise SystemExit(f"FAIL_V12_ALREADY_CONSUMED durable_row={n}")

print(json.dumps({
    "status": "PASS_V12_FINAL_PRE_DISPATCH_DURABLE_UNCONSUMED",
    "authorization_id": AUTH_ID,
    "durable_row": n,
    "database_write": 0,
    "provider_credential_access": 0,
    "provider_api_calls": 0,
    "final_128_execution": 0
}, sort_keys=True))
