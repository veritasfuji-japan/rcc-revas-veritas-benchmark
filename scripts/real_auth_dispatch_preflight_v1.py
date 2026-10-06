#!/usr/bin/env python3
import json, subprocess
from pathlib import Path
R=Path(__file__).resolve().parents[1]
def j(p): return json.loads((R/p).read_text())
def blob(p): return subprocess.run(["git","hash-object",str(R/p)],check=True,capture_output=True,text=True).stdout.strip()
p=j("contracts/AGENTDOJO_REAL_AUTH_DISPATCH_PREFLIGHT_v1.json")
a=j(p["authorization"]["path"]); f=j(p["freeze"]["path"])
assert a["human_approval"]["authorization_id"]==p["authorization"]["id"]
assert a["human_approval"]["single_use"] is True
assert a["authorization_state"]["issued"] is True and a["authorization_state"]["consumed"] is False
assert a["authorization_state"]["dispatch_performed"] is False
assert a["execution_gate"]=="CLOSED" and a["provider_execution_authorized"] is False
assert blob(p["authorization"]["path"])==p["authorization"]["git_blob_sha"]
assert blob(p["freeze"]["path"])==p["freeze"]["git_blob_sha"]
assert blob(p["runner"]["path"])==p["runner"]["git_blob_sha"]
assert f["pins"]["veritas_commit"]==p["pins"]["veritas"]
assert f["pins"]["agentdojo_commit"]==p["pins"]["agentdojo"]
assert f["pins"]["rcc_revas_commit"]==p["pins"]["rcc_revas"]
assert f["pins"]["model"]==p["pins"]["model"]
assert all(p["disabled"].values())
print(json.dumps({"proof":"REAL_AUTH_DISPATCH_PREFLIGHT_V1","status":"PASS_OFFLINE_ONLY",
"real_authorization_consumed":False,"database_access":0,"provider_credential_access":0,
"provider_api_calls":0,"final_128_execution":0},sort_keys=True))
