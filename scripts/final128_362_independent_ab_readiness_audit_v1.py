"""Provider-free audit of exact pinned Final128 A/B readiness claims."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "evidence/final128_362_independent_ab_readiness_v1.json"
EXPECTED_MAIN = "d30756650272817e0495b8bbbc80b1bfe2ab7b88"
DOCS = {
 "docs/TASK4_322_INDEPENDENT_AB_FIRST_REQUEST_OFFLINE_V1.md": ("fully offline", "no genuine real-model generation"),
 "docs/TASK15_INDEPENDENT_AB_NATIVE_CANDIDATE_SOURCE_V1.md": ("first-proposal", "not a complete independent three-action model trajectory"),
 "docs/TASK4_TWO_ARM_FIRST_LIVE_REQUEST_PACKET_V1.md": ("not authorized", "independent real llm responses"),
}
GATES = {f"G{i}" for i in range(1, 8)}

def audit(data, root=ROOT):
    assert data["schema"] == "final128-independent-ab-readiness-v1"
    assert data["base_main_sha"] == EXPECTED_MAIN
    assert data["mode"] == "offline-readonly"
    assert data["status"] == "NOT_READY_FOR_REAL_FINAL128_UTILITY"
    assert data["provider_calls"] == data["external_effects"] == data["spend_authorized_usd"] == 0
    assert {x["path"] for x in data["sources"]} == set(DOCS)
    for p, needles in DOCS.items():
        content = (root / p).read_text(encoding="utf-8").lower()
        assert all(n in content for n in needles), p
    gates = data["gates"]
    assert {x["id"] for x in gates} == GATES
    assert all(x["met"] is False for x in gates)
    assert len(data["claims_not_established"]) >= 4
    return {"result":"PASS","classification":"OFFLINE_READINESS_GAP_ONLY","unmet_gates":sorted(GATES),"real_provider_calls":0}

if __name__ == "__main__":
    print(json.dumps(audit(json.loads(EVIDENCE.read_text(encoding="utf-8"))),sort_keys=True))
