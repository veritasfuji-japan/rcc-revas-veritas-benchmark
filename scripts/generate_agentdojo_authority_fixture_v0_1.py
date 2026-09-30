#!/usr/bin/env python3
import base64,hashlib,json
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
ROOT=Path(__file__).resolve().parents[1]; D=ROOT/"fixtures"/"agentdojo_authority_v0_1"; D.mkdir(parents=True,exist_ok=True)
# Deterministic benchmark-only seed. Public by design: this is not a production trust root.
seed=hashlib.sha256(b"VERITAS_AGENTDOJO_BENCHMARK_AUTHORITY_V0_1").digest()
sk=Ed25519PrivateKey.from_private_bytes(seed); pk=sk.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
(D/"public_key.raw.b64").write_text(base64.b64encode(pk).decode()+"\n")
artifact={"schema_version":"veritas.authority-evidence.v0.1","evidence_id":"agentdojo-clean-ab-authority-v0-1","issuer_identity":"veritas-benchmark-authority-fixture","actor_identity":"agentdojo:banking:benchmark-user","authority_scope":["agentdojo-banking-protected-mutation"],"policy_snapshot_id":"agentdojo-banking-clean-ab-v0.1","benchmark_only":True}
payload=json.dumps(artifact,sort_keys=True,separators=(",",":")).encode(); artifact["benchmark_fixture_signature"]=base64.b64encode(sk.sign(payload)).decode()
(D/"authority_fixture.json").write_text(json.dumps(artifact,indent=2,sort_keys=True)+"\n")
(D/"signer_policy.json").write_text(json.dumps({"policy_id":"agentdojo-clean-ab-authority-verifier-policy-v0-1","allowed_key_ids":["agentdojo-clean-ab-benchmark-ed25519-v0-1"],"allowed_issuers":["veritas-benchmark-authority-fixture"],"benchmark_only":True},indent=2,sort_keys=True)+"\n")
(D/"revocations.json").write_text(json.dumps({"source_identity":"veritas-benchmark-revocations","version":"v0.1","as_of":"2026-09-30T00:00:00Z","status_by_id":{"agentdojo-clean-ab-authority-v0-1":False}},indent=2,sort_keys=True)+"\n")
files=["public_key.raw.b64","authority_fixture.json","signer_policy.json","revocations.json"]
m={f:hashlib.sha256((D/f).read_bytes()).hexdigest() for f in files};(D/"SHA256SUMS.json").write_text(json.dumps(m,indent=2,sort_keys=True)+"\n")
print(json.dumps(m,sort_keys=True))
