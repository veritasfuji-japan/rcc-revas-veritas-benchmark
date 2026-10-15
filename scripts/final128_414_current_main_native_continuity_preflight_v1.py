#!/usr/bin/env python3
"""Fail-closed, read-only preflight for current-main canonical continuity artifacts.

This is NOT executable native Bind continuity proof, nor a utility measurement.
"""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FILES = (
    "contracts/SINGLE_CANDIDATE_UNINTERRUPTED_CANONICAL_CHAIN_V1.json",
    "contracts/CURRENT_VERITAS_CRITICAL_SOURCE_HASHES_V1.json",
    "integration/current_veritas_uninterrupted/sandbox.py",
)
def inspect(root: Path = ROOT) -> dict:
    resolved_root = root.resolve(strict=True)
    entries = []
    for rel in FILES:
        path = (resolved_root / rel).resolve(strict=True)
        if not path.is_relative_to(resolved_root) or not path.is_file():
            raise ValueError(f"unsafe or absent continuity input: {rel}")
        raw = path.read_bytes()
        if not raw:
            raise ValueError(f"empty continuity input: {rel}")
        if rel.endswith(".json"):
            data = json.loads(raw)
            if not isinstance(data, dict):
                raise ValueError(f"unexpected JSON shape: {rel}")
        entries.append({"path": rel, "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)})
    return {"status": "PREFLIGHT_ONLY_NOT_PROVEN", "source_files": entries}

def main() -> None:
    print(json.dumps(inspect(), sort_keys=True, indent=2))

if __name__ == "__main__":
    main()
