#!/usr/bin/env python3
from pathlib import Path

workflow=Path(".github/workflows/final-128-v11-manual-dispatch-template.yml").read_text()
wrapper=Path("scripts/final_128_real_provider_wrapper_v9.py").read_text()

# The future manual-dispatch surface and provider-free proof are bound to the
# same wrapper. Before V11 authorization/freeze, the real surface is inert.
assert "python scripts/final_128_real_provider_wrapper_v9.py --real-dispatch" in workflow
assert 'OPENAI_API_KEY: ""' in workflow
assert 'VERITAS_DATABASE_URL: ""' in workflow
assert "secrets.OPENAI_API_KEY" not in workflow
assert "secrets.VERITAS_ATOMIC_CONSUMPTION_DATABASE_URL" not in workflow
assert 'g.add_argument("--real-dispatch",action="store_true")' in wrapper
assert 'raise RuntimeError("V11_REAL_DISPATCH_DISABLED_PRE_AUTHORIZATION")' in wrapper
assert 'assert not os.environ.get("OPENAI_API_KEY")' in wrapper
print("PASS_V11_CREDENTIAL_BOUNDARY_STATIC_SEMANTICS")
