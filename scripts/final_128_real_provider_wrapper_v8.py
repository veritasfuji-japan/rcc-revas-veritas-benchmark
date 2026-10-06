#!/usr/bin/env python3
"""V10 winner-only wrapper. Authorization is intentionally not issued here."""
from __future__ import annotations
import argparse, asyncio, hashlib, json, os, subprocess, tempfile
from datetime import datetime, timezone
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
AUTH_PATH=ROOT/"contracts/AGENTDOJO_FINAL_128_EXECUTION_AUTHORIZATION_v10.json"
CONFIRM_PATH=ROOT/"contracts/AGENTDOJO_FINAL_128_V10_HUMAN_CONFIRMATION_v1.json"
AUTH_ID="AGENTDOJO_CANONICAL_FINAL_128_EXECUTION_V10"
CONFIRM="RUN_FINAL_128_V10_ONCE"
RUNNER="scripts/agentdojo_clean_ab_canonical_final_runner_v2_5.py"
RUNNER_BLOB="da86e5cb4ed44a1fb4cf991eade9cfc67ba92806"
RECEIPT_SCHEMA="veritas.agentdojo-final-128-runtime-dispatch-receipt.v1"
def sha(s): return hashlib.sha256(s.encode()).hexdigest()
def blob(p): return subprocess.run(["git","hash-object",str(ROOT/p)],check=True,capture_output=True,text=True).stdout.strip()
def validate_runtime_contract(a,c,confirmation):
    assert blob(RUNNER)==RUNNER_BLOB
    assert a["authorization"]["id"]==AUTH_ID and a["authorization"]["issued"] is True
    assert a["authorization"]["single_use"] is True and a["authorization"]["consumed"] is False
    assert a["authorization"]["rerun_authorized"] is False
    assert a["dispatch"]["provider_dispatch_authorized"] is True
    assert a["dispatch"]["manual_dispatch_authorized"] is True
    assert a["cost_boundary"]["maximum_usd"]==5
    assert c["authorization_id"]==AUTH_ID and c["confirmation"]["received"] is True
    assert c["confirmation"]["maximum_usd"]==5 and c["confirmation"]["single_consumption_only"] is True
    assert c["confirmation"]["rerun_authorized"] is False
    assert c["authorization_git_blob_sha"]==a["_self_blob"]
    assert a["frozen_target"]["runner_git_blob_sha"]==RUNNER_BLOB
    assert confirmation==CONFIRM
def provider_free_preflight():
    if AUTH_PATH.exists() or CONFIRM_PATH.exists(): raise SystemExit("V10_AUTH_OR_CONFIRMATION_MUST_NOT_EXIST_DURING_PREAUTH_PREFLIGHT")
    synthetic_blob="PREAUTH_SYNTHETIC_AUTH_BLOB"
    a={"_self_blob":synthetic_blob,"authorization":{"id":AUTH_ID,"issued":True,"single_use":True,"consumed":False,"rerun_authorized":False},"dispatch":{"provider_dispatch_authorized":True,"manual_dispatch_authorized":True},"cost_boundary":{"maximum_usd":5},"frozen_target":{"runner_git_blob_sha":RUNNER_BLOB}}
    c={"authorization_id":AUTH_ID,"authorization_git_blob_sha":synthetic_blob,"confirmation":{"received":True,"maximum_usd":5,"single_consumption_only":True,"rerun_authorized":False}}
    validate_runtime_contract(a,c,CONFIRM)
    assert not os.environ.get("OPENAI_API_KEY")
    print(json.dumps({"status":"PASS_V10_PROVIDER_FREE_EXECUTE_PATH_TO_CONSUME_BOUNDARY","authorization_exists":False,"database_write":0,"provider_credential_access":0,"provider_api_calls":0,"final_128_execution":0},sort_keys=True))
async def execute(args):
    if not AUTH_PATH.exists() or not CONFIRM_PATH.exists(): raise SystemExit("V10_AUTHORIZATION_OR_CONFIRMATION_MISSING")
    a=json.loads(AUTH_PATH.read_text()); c=json.loads(CONFIRM_PATH.read_text())
    a["_self_blob"]=blob(AUTH_PATH.relative_to(ROOT))
    validate_runtime_contract(a,c,args.confirmation)
    from veritas_os.policy.live_adapter_bind_authorization_consumption_store import PostgresAtomicAuthorizationConsumptionStore, build_authorization_consumption_record
    from veritas_os.storage.db import close_pool
    if not os.environ.get("VERITAS_DATABASE_URL","").startswith(("postgres://","postgresql://")): raise SystemExit("REAL_POSTGRES_REQUIRED")
    rec=build_authorization_consumption_record(live_adapter_bind_authorization_id=AUTH_ID,live_adapter_bind_authorization_hash=sha("agentdojo-final-128-execution-v10:"+AUTH_ID),idempotency_key="agentdojo-final-128-v10:"+sha(AUTH_ID),bind_context_hash=sha("canonical-final-128-provider-dispatch-v10"),execution_intent_id="agentdojo-canonical-final-128-provider-v10",execution_intent_hash=sha("agentdojo-canonical-final-128-provider-v10"),endpoint_identity_binding_digest=sha("openai:gpt-4.1-mini-2025-04-14"),credential_reference_digest=sha("github-actions:OPENAI_API_KEY"),credential_scope_binding_digest=sha("openai:model:gpt-4.1-mini-2025-04-14"),consumed_at=datetime.now(timezone.utc).isoformat())
    store=PostgresAtomicAuthorizationConsumptionStore()
    try:
        won=await store.consume_once(rec)
        if not won: raise SystemExit("V10_ALREADY_CONSUMED_FAIL_CLOSED")
        durable=await store.get(AUTH_ID)
        if durable is None or durable.consumption_id!=rec.consumption_id or durable.consumption_hash!=rec.consumption_hash: raise SystemExit("V10_DURABLE_READBACK_MISMATCH")
    finally: await close_pool()
    receipt={"schema_version":RECEIPT_SCHEMA,"authorization_id":AUTH_ID,"durable_authorization_id":AUTH_ID,"atomic_consumption_won":True,"single_use":True,"rerun_authorized":False,"provider_spend_cap_usd":5.0,"consumption_id":rec.consumption_id,"consumption_hash":rec.consumption_hash}
    with tempfile.NamedTemporaryFile("w",suffix=".json",delete=False) as f: json.dump(receipt,f,sort_keys=True); rp=f.name
    if not os.environ.get("OPENAI_API_KEY"): raise SystemExit("OPENAI_API_KEY_MISSING_AFTER_CONSUME_AUTH_BURNED")
    cmd=["python",RUNNER,"--execute","--confirmation","RUN_CANONICAL_AGENTDOJO_CLEAN_AB_V2_5","--runtime-dispatch-receipt",rp,"--agentdojo-root",args.agentdojo_root,"--rcc-root",args.rcc_root,"--veritas-root",args.veritas_root,"--output-dir",args.output_dir]
    raise SystemExit(subprocess.call(cmd))
def main():
    p=argparse.ArgumentParser(); g=p.add_mutually_exclusive_group(required=True); g.add_argument("--execute",action="store_true"); g.add_argument("--provider-free-preflight",action="store_true")
    p.add_argument("--confirmation",default=""); p.add_argument("--agentdojo-root",default="_pins/agentdojo"); p.add_argument("--rcc-root",default="_pins/rcc"); p.add_argument("--veritas-root",default="_pins/veritas"); p.add_argument("--output-dir",default="results/agentdojo-clean-ab-final-v10")
    x=p.parse_args()
    if x.provider_free_preflight: provider_free_preflight(); return
    asyncio.run(execute(x))
if __name__=="__main__": main()
