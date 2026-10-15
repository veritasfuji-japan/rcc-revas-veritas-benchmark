#!/usr/bin/env python3
"""Fail-closed source-freeze preflight, NOT a native continuity or Utility proof.

#413's preflight inputs are compared with their exact frozen #413-main Git
blob identities. The separately pinned VERITAS source bytes are validated in
CI by the existing tools/verify_current_veritas_source_pin_v1.py. The pinned
2026-era VERITAS checkout is NOT the moving latest veritas_os main.
"""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# Independently recorded from merged #413 baseline f5635852187805fa562e815d567f1514322a4d3a.
# If canonical inputs change, deliberate review and re-pinning are required.
FROZEN_BLOBS = {
    "contracts/SINGLE_CANDIDATE_UNINTERRUPTED_CANONICAL_CHAIN_V1.json":
        "1c8ba395df935c2d4c0d1da1358cd3d874e34575",
    "contracts/CURRENT_VERITAS_CRITICAL_SOURCE_HASHES_V1.json":
        "51ae2dd242a55a6f70bfd64ce34c3338b1a86545",
    "integration/current_veritas_uninterrupted/sandbox.py":
        "db63ea47d07f75b288fd5a64108e91a6230ce6c4",
    "contracts/CURRENT_VERITAS_SOURCE_PIN_PROFILE_V1.json":
        "40a72b393d53632dae14ff2449582e6bb7563038",
}
FILES = tuple(FROZEN_BLOBS)
PINNED_VERITAS_COMMIT = "9b7376ba0077365b9d89004b06c80e76c8bfadc8"

def git_blob_sha(raw: bytes) -> str:
    """Git object identity of an exact source file, including length prefix."""
    return hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()

def inspect(root: Path = ROOT) -> dict:
    resolved_root = root.resolve(strict=True)
    entries = []
    parsed = {}
    for rel, expected_blob in FROZEN_BLOBS.items():
        path = (resolved_root / rel).resolve(strict=True)
        if not path.is_relative_to(resolved_root) or not path.is_file():
            raise ValueError(f"unsafe continuity input: {rel}")
        raw = path.read_bytes()
        if not raw:
            raise ValueError(f"empty continuity input: {rel}")
        if rel.endswith(".json"):
            data = json.loads(raw)
            if not isinstance(data, dict):
                raise ValueError(f"unexpected JSON shape: {rel}")
            parsed[rel] = data
        actual_blob = git_blob_sha(raw)
        if actual_blob != expected_blob:
            raise ValueError(f"frozen Git blob changed; explicit re-pin required: {rel}")
        entries.append({"path": rel, "git_blob_sha1": actual_blob,
                        "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)})

    chain = parsed["contracts/SINGLE_CANDIDATE_UNINTERRUPTED_CANONICAL_CHAIN_V1.json"]
    manifest = parsed["contracts/CURRENT_VERITAS_CRITICAL_SOURCE_HASHES_V1.json"]
    profile = parsed["contracts/CURRENT_VERITAS_SOURCE_PIN_PROFILE_V1.json"]
    if (chain.get("veritas_pin") != PINNED_VERITAS_COMMIT
        or manifest.get("veritas_commit") != PINNED_VERITAS_COMMIT
        or profile.get("current_veritas_commit") != PINNED_VERITAS_COMMIT):
        raise ValueError("cross-contract VERITAS commit mismatch")
    if (manifest.get("status") != "IMPLEMENTATION_PROOF_PENDING"
        or manifest.get("hash_algorithm") != "sha256"
        or not isinstance(manifest.get("critical_sources"), dict)
        or not manifest["critical_sources"]):
        raise ValueError("source profile scope or critical source shape invalid")
    if chain.get("status") != "PROVEN_WITHIN_BOUNDED_LOCAL_ENGINEERING_SCOPE":
        raise ValueError("historical bounded fixture scope changed")
    return {
        "status": "PINNED_SOURCE_PREFLIGHT_ONLY_NOT_NATIVE_PROOF",
        "frozen_rcc_baseline": "f5635852187805fa562e815d567f1514322a4d3a",
        "frozen_veritas_commit": PINNED_VERITAS_COMMIT,
        "latest_veritas_main_validated": False,
        "native_bind_continuity_proven": False,
        "new_official_utility_measurement": False,
        "source_files": entries,
    }

def main() -> None:
    print(json.dumps(inspect(), sort_keys=True, indent=2))

if __name__ == "__main__":
    main()
