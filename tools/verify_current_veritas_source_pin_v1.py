#!/usr/bin/env python3
import hashlib, json, subprocess, sys
from pathlib import Path

MANIFEST = Path(__file__).resolve().parents[1] / "contracts" / "CURRENT_VERITAS_CRITICAL_SOURCE_HASHES_V1.json"

def fail(code: str) -> None:
    raise SystemExit(code)

def verify(checkout: Path) -> None:
    data=json.loads(MANIFEST.read_text())
    required={"schema_version","status","profile","veritas_repository","veritas_commit","hash_algorithm","critical_sources","fail_closed_on","external_validation","paid_provider_calls","historical_128_case_rerun"}
    if set(data) != required or data["hash_algorithm"] != "sha256" or not isinstance(data["critical_sources"], dict) or not data["critical_sources"]:
        fail("CURRENT_VERITAS_SOURCE_PIN_MANIFEST_INVALID")
    head=subprocess.check_output(["git","-C",str(checkout),"rev-parse","HEAD"],text=True).strip()
    if head != data["veritas_commit"]:
        fail("CURRENT_VERITAS_SOURCE_PIN_COMMIT_MISMATCH")
    for rel, expected in sorted(data["critical_sources"].items()):
        if not isinstance(rel,str) or not isinstance(expected,str) or len(expected)!=64:
            fail("CURRENT_VERITAS_SOURCE_PIN_MANIFEST_INVALID")
        path=checkout / rel
        if not path.is_file():
            fail("CURRENT_VERITAS_SOURCE_PIN_PATH_MISSING:" + rel)
        actual=hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != expected:
            fail("CURRENT_VERITAS_SOURCE_PIN_HASH_MISMATCH:" + rel)
    print("CURRENT_VERITAS_CRITICAL_SOURCE_HASH_PINNING_V1: VERIFIED")

if __name__=="__main__":
    if len(sys.argv)!=2: fail("usage: verify_current_veritas_source_pin_v1.py CHECKOUT")
    verify(Path(sys.argv[1]).resolve())
