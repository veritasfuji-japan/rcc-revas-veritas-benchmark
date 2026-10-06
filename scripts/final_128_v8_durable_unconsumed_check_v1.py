#!/usr/bin/env python3
from __future__ import annotations
import json, os
import psycopg

AUTH_ID="AGENTDOJO_CANONICAL_FINAL_128_EXECUTION_V8"

def main():
    dsn=os.environ.get("VERITAS_DATABASE_URL","")
    if not dsn.startswith(("postgres://","postgresql://")):
        raise SystemExit("REAL_POSTGRES_REQUIRED")
    with psycopg.connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT COUNT(*) FROM bind_authorization_consumptions WHERE authorization_id=%s",
                (AUTH_ID,),
            )
            count=int(cur.fetchone()[0])
    if count != 0:
        raise SystemExit(f"V8_ALREADY_CONSUMED_OR_ROW_EXISTS_FAIL_CLOSED count={count}")
    print(json.dumps({
        "status":"PASS_V8_DURABLE_UNCONSUMED_CHECK",
        "authorization_id":AUTH_ID,
        "durable_row":0,
        "provider_credential_access":0,
        "provider_api_calls":0,
        "final_128_execution":0
    },sort_keys=True))

if __name__=="__main__":
    main()
