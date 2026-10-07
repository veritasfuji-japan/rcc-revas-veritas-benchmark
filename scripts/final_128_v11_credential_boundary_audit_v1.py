#!/usr/bin/env python3
from pathlib import Path

workflow = Path(".github/workflows/final-128-v11-manual-dispatch-template.yml").read_text()
wrapper = Path("scripts/final_128_real_provider_wrapper_v9.py").read_text()

# One shared wrapper/control-flow implementation serves provider-free proof and
# both future real phases.
assert "async def execute_control_flow(args" in wrapper
assert "asyncio.run(execute_control_flow(build_parser().parse_args()))" in wrapper
assert "if args.provider_free_preflight:" in wrapper
assert "receipt = await consume_phase(a, provider_free=True)" in wrapper
assert "provider_phase(receipt, args, provider_free=True)" in wrapper
assert "if args.phase1_real:" in wrapper
assert "receipt = await consume_phase(a, provider_free=False)" in wrapper
assert "if args.phase2_real:" in wrapper
assert "provider_phase(receipt, args, provider_free=False)" in wrapper
assert "AGENTDOJO_FINAL_128_EXECUTION_AUTHORIZATION_v11.json" in wrapper
assert "AGENTDOJO_FINAL_128_V11_HUMAN_CONFIRMATION_v1.json" in wrapper
assert "V11_AUTHORIZATION_OR_CONFIRMATION_MISSING" in wrapper

# The actual manual-dispatch surface calls the same wrapper for both phases.
assert "final_128_real_provider_wrapper_v9.py" in workflow
assert "--phase1-real" in workflow
assert "--phase2-real" in workflow
assert "RUN_FINAL_128_V11_ONCE" in workflow

phase1_start = workflow.index("- name: Phase 1 durable consume and receipt")
phase2_start = workflow.index("- name: Phase 2 receipt verification and provider execution")
assert phase1_start < phase2_start
phase1 = workflow[phase1_start:phase2_start]
phase2 = workflow[phase2_start:]

# Provider credential is unavailable during durable consume.
assert "secrets.VERITAS_ATOMIC_CONSUMPTION_DATABASE_URL" in phase1
assert 'OPENAI_API_KEY: ""' in phase1
assert "secrets.OPENAI_API_KEY" not in phase1

# Provider credential appears only after successful Phase 1.
assert "if: success()" in phase2
assert "secrets.OPENAI_API_KEY" in phase2
assert "secrets.VERITAS_ATOMIC_CONSUMPTION_DATABASE_URL" in phase2

# Receipt handoff is explicit and the same path is used by both real phases.
assert phase1.count(".v11_handoff/v11_dispatch_receipt.json") == 1
assert phase2.count(".v11_handoff/v11_dispatch_receipt.json") >= 1

print("PASS_V11_SHARED_CONTROL_FLOW_STATIC_SEMANTICS")
print("PASS_V11_CREDENTIAL_BOUNDARY_STATIC_SEMANTICS")
