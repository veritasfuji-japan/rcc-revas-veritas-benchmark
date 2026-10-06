#!/usr/bin/env python3
import json, os
import psycopg
AUTH_ID="AGENTDOJO_CANONICAL_FINAL_128_EXECUTION_V9"
dsn=os.environ["VERITAS_DATABASE_URL"]
with psycopg.connect(dsn) as c:
  with c.cursor() as cur:
    cur.execute("SELECT COUNT(*) FROM bind_authorization_consumptions WHERE authorization_id=%s",(AUTH_ID,))
    n=cur.fetchone()[0]
if n != 0:
  raise SystemExit(f"FAIL_V9_ALREADY_CONSUMED durable_row={n}")
print(json.dumps({"status":"PASS_V9_FINAL_PRE_DISPATCH_GATE","authorization_id":AUTH_ID,"durable_row":n,"provider_credential_access":0,"provider_api_calls":0,"final_128_execution":0},sort_keys=True))
