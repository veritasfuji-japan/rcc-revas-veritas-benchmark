#!/usr/bin/env python3
from pathlib import Path
p=Path(".github/workflows/final-128-v11-manual-dispatch-template.yml").read_text()
a=p.index("- name: Phase 1 durable consume")
b=p.index("- name: Phase 2 provider execution")
phase1=p[a:b]; phase2=p[b:]
assert 'OPENAI_API_KEY: ""' in phase1
assert "secrets.OPENAI_API_KEY" not in phase1
assert "secrets.VERITAS_ATOMIC_CONSUMPTION_DATABASE_URL" in phase1
assert "if: success()" in phase2
assert "secrets.OPENAI_API_KEY" in phase2
assert "exit 1" in phase1 and "exit 1" in phase2
print("PASS_V11_CREDENTIAL_BOUNDARY_STATIC_SEMANTICS")
