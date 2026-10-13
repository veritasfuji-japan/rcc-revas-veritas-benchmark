# Final128 #386 — manual + Secret workflow Actions SHA pinning, stage 2

## Change scope: no paid execution

This PR continues #385's repository-wide inventory and fixes the 4 known
**manually dispatched, Provider Secret-consuming development workflows**:

| Workflow | SHA replacements |
| --- | ---: |
| agentdojo-task2-development-validation-v1.yml | 6 |
| agentdojo-task12-development-validation-v1.yml | 6 |
| agentdojo-task13-development-validation-v1.yml | 6 |
| agentdojo-task15-development-validation-v1.yml | 6 |
| **Total** | **24** |

Each replaces only:
- \`actions/checkout@v4\` → \`actions/checkout@11d5960a326750d5838078e36cf38b85af677262\` (4 uses)
- \`actions/setup-python@v5\` → \`actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065\` (1 use)
- \`actions/upload-artifact@v4\` → \`actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02\` (1 use)

All three commits have been exercised in earlier repository CI. This is
Action integrity pinning only. It does not prove the Actions are benign.

\`scripts/final128_386_manual_secret_sha_stage2_audit_v1.py\` checks the
**full exact PR-base git blob against new file bytes**: only the 6 expected
Action replacements per file are allowed. Trigger, actor confirmation,
runtime, secret mapping, dependency installation, runner SHA, external
repositories and exact checkout pins **must not drift in #386**. Changes
outside that specific scope are rejected. Full #385 repository inventory
is recomputed against the exact PR base and any newly introduced mutable
Action reference blocks this stage. The new workflow tests and writes
only SHA/redacted files (no Provider secret access or transport).

## Material remaining security risk — NOT fixed by stage 2

These four workflows **still have \`workflow_dispatch\`, reference
\`secrets.OPENAI_API_KEY\`, and do not declare a protected job
\`environment:\`**. As configured, an authorized GitHub workflow
dispatcher may run the existing model scripts; merely fixing Action
versions does not close the original spending/approval bypass or make
the old manually supplied confirmation string a trustworthy fresh
paid-use authorization. Do NOT trigger them for this PR. If they still
serve a purpose, prioritize a separate reviewed fail-closed protected
Environment/issuer mechanism, with exact case+spend bounds and server
side account limits; otherwise decommission their live triggers in
a separately reviewed change. This PR intentionally does not change
their historical execution behavior to avoid silently invalidating
old frozen protocol proofs.

Other historical Final128 manual Provider workflows and Actions with
version tags may remain. The #385 global inventory is the audit
baseline; changes to just four paths are not repository-wide
completion. **Do not turn on global 'Require actions pinned to a
full-length commit SHA'** until the complete inventory is cleared.

GitHub Environment \`task1-real-model-pilot\` is a separate protection
configuration and does not automatically protect jobs that do not
reference it. Task1 globally consumed Git reference is a distinct
boundary, not verified end-to-end by this change.

## CI and evidence gates

The new dedicated PR-only CI:
- checks out exact PR HEAD and fetches exact base SHA;
- verifies zero Provider tokens / no environment secrets;
- unit-tests tampered triggers, extra commands, secret substitution,
  privilege escalation, runner change, unexpected third-party Actions;
- audits all \`.github/workflows/*.yml\` and \`*.yaml\` and disallows
  *new* mutable Action references against base;
- proves the 24 expected replacements in four selected files with
  byte-exact controls, and records SHA-only evidence.

The four modified manual workflows do not run on PR. Shared CI must
remain green on exact HEAD, independent of dedicated audit results.
No actual Provider request, billing change, Google/GitHub auth grant,
native scorer or official Utility result is part of this PR. No automatic
merge or live execution.

Historical Final128 V13 A Utility 93/128, B Utility 64/128 and
B injection success 0/128 are not remeasured.
