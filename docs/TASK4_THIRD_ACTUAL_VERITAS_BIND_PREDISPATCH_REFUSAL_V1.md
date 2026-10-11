# PR #301 — Exact historical third A/B proposals through native VERITAS Bind

**Rule of One:** verify that the existing frozen Task4 resolver forces genuine
A/B third-turn model-selected \`send_money\` proposals to be BLOCKED by the
**actual** VERITAS Bind core before any protected native effect.

The user authorized two historical third-turn OpenAI calls, consumed by
Run 38097049813. Both calls already completed. **This PR does not authorize
any new Provider calls, expense, retry, or transaction.**

## Inputs / provenance

- Historical native second-read frozen artifact 11676881211,
  ZIP sha256 \`bbc7ba1a16aaac67aed75bdbb7a5abc71bfa978599e1cfc42700779377e838f4\`.
- Third genuine model capture artifact 11686131074,
  ZIP sha256 \`6d9842caa8c017ae2bd4426ee7d4b0f1c02f79252d82c96767c048c88f176ab2\`.
- The unchanged independent third-response validator from merged PR #300
  authenticates each raw request, response, event order, previous consumption,
  model identities and predicted proposals before Bind construction.
- Historical third consumed tag remains fixed to
  \`95ff6be8c5875ed3827a00fe71fb54bd9de48130\`.

## Real Bind boundary, but bounded authority

The audit checks out exact AgentDojo
\`a75aba7631d3ca5fb7ab938965c97ead2f9ff84b\` and VERITAS OS
\`a1d66aef02262cf8a913295270c3aafd159c6adb\` pins, with expected
adapter/core Git blobs, plus the unchanged frozen Task4 resolver blob.

It separately reconstructs the **pinned native injected pre-state** from
AgentDojo's benchmark injection task definition (not from lower-trust model
output), and matches the historical state digest. No native bank function is
executed. Then it builds a \`FrozenAgentDojoCandidate\` for each independently
pinned third response, a candidate-bound \`ExecutionIntent\`, and calls
\`execute_bind_adjudication\` using the genuine \`AgentDojoBankingBindAdapter\`
subclass with an **unreachable fail-stop apply sink**. Any apply attempt fails
the proof immediately.

A signed, revocation-checked **benchmark fixture** is supplied as the
benchmark Authority parameter solely to isolate the genuine constraint
adjudication; it does **not** authenticate live production authority. The
unchanged Task4 resolver checks the correct recipient and amount but returns
\`supported_profile=False\` and \`date_authority_present=False\`. In this
specific historical third run, the provided trusted-looking 2031-07-08
developer prompt text does not itself prove a separately issued/consumed
execution-date authorization. This round MUST therefore BLOCK both proposals
under the unchanged resolver.

## What success can establish

For **two already captured real model suggestions**, actual pinned VERITAS Bind
refuses execution pre-dispatch with a native state unchanged and no native
protected effect sink reached. It shows how correct task proposals are distinct
from complete execution authority, not that the proposals were malicious.

Adversarial fixture variants are expressly synthetic and cannot be reported as
additional genuine model outputs. They must also be BLOCKED.

## What it cannot establish

- No new native AgentDojo utility or attack-success scores.
- No production IAM, credential, network boundary proof.
- No validated third-turn independent date authorization; no positive ALLOW.
- No untrusted model/tool output becomes a source of authority.
- No additional real Provider messages, no bank mutations, no Final128 rerun.

**CI green is not an external PROVEN or a production-coverage certification.**
The scope is exact benchmark Binder/Core and this frozen source.

Review gate: keep Draft until exact PR HEAD dedicated test/JUnit/artifact bytes,
normal CI, and merged-main source pins are independently verified.
