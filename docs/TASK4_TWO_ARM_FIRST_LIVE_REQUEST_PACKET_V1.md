# TASK4_TWO_ARM_FIRST_LIVE_REQUEST_PACKET_V1 — PR #292

## What has moved from the synthetic environment toward the actual first model request

Previous #291 merged main:
\`2bfd1daa736b33964b6aa8d275d0695d75079e3b\`.

From one exact pinned native AgentDojo injected Task4 case, we now have
TWO FULL OpenAI Chat Completions request JSON payloads for the **FIRST**
A/B model calls, each tied to its own synthetic TEST source provenance.

The first two requests are **byte-identical** because the first prompts
and native tool schemas are supposed to match. They are separately
*owned* by A and B; identical first request hashes do not prove the
same client instance or independent provider completion.

Source first-request SHA-256:
\`c83bca26d25f6a6332cc1b7266c84ee5974f1f7904d0d77d4f6a913100233dc7\`.

Each complete provider payload preserves original developer/user
messages and 11 actual native declared banking tool JSON schemas, plus
\`model=gpt-4.1-mini-2025-04-14\`,
\`max_completion_tokens=256\`, \`temperature=0\`, \`n=1\`,
\`tool_choice=auto\`, \`stream=false\`, \`store=false\`.
All exact payload bytes/hash and source ownership are archived and
audited, *not* issued.

## Critical execution status

| Scope | Status |
| --- | --- |
| TWO first A/B provider-format payloads | MATERIALIZED, exact-sha-bounded |
| Proposed per first request cost ceiling | $0.25, **not authorized** |
| Proposed total for two first requests | $0.50, **not authorized** |
| Approved budget / calls | $0 / 0 |
| Live Provider sender or API key | NONE |
| Independent real LLM responses | NONE |
| Native bank-network writes | FORBIDDEN |
| Genuine attacked native tool read exposure to live model | NOT YET |
| Re-measured Utility or injection on full Canonical Final128 | NONE |

An application's proposed dollar cap is not an OpenAI billing hard
cap; actual model access, token accounting, current prices and
provider-side spending controls require a new operator decision
before any live request. No historical V13 $5 authorization carries
forward.

**Important:** AgentDojo's real injected malicious transaction is only
present *after* the model has independently asked the native read
tool for data. It is NOT present in the first model request. A real
two-call-first-turn capture therefore does **not** alone show prompt
injection exposure or Utility improvement. To evaluate those, complete
each independently generated read/tool-return/next-model-turn trajectory
and safely score it; that continuation is not authorized by this PR.

## Proof boundary

Read only the original TEST-native A/B evidence, recompute
#291 no-fake-continuation source validity, serialize the exact
full first requests and hash them. Refuse source-swapped,
modified trusted request, fake model result, fake human approval,
client, API key, spend permission or scorer-based promotion.
Dedicated suite has 19 tests (16 adversarial refusals).
Output includes full initial JSON payloads, original native source
data, tests, SHA/summary and source-lock manifests.

No calls, no new simulator policy, no transport, no bank effects,
no operator root enrollment, no new V13 score.

**CI GREEN != independently PROVEN.**
Manual merge only after all latest-head checks and independently
downloaded Artifact/JUnit/raw packet SHA inspection.
