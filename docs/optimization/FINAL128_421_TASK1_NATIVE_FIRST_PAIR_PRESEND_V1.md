# Final128 #421 — source-owned Native Chat FIRST A/B presend contract (no paid call)

## Why #421 cannot simply wire existing #350/#382 to #419

`#419` derives three Chat Completions request stages from an actual pinned Native AgentDojo `AgentPipeline`. However the assistant responses at ALL stages were fabricated by #403's scripted recorder. **Only the initial FIRST request is a legitimate starting wire packet for a future genuine run.** The 'post_read' and 'post_mutation' packets have histories containing fake native Tool IDs/assistant proposals and may NEVER be submitted as real model continuations.

Existing #350/#382 use the **Responses API**, not the full-tool frozen Native Chat Completions contract. Existing `agentdojo_openai_frozen_adapter_v0_1.create_completion_once` illustrates the one-call Native Chat request but has NO verified hard output budget, no protected issuer, no GitHub Environment/egress binding and no durable global once-only grant. Calling it now, even by copying a consent flag, would be premature.

#389–393 observed a real GitHub Environment approval gate and test-only single-use tag create/duplicate/update/delete refusal for ONE narrowly scoped operator/token. **They did NOT exercise the intended production Task1 consumed tag**, prove independent approval, global credential/egress isolation, project hard billing stop, or issue permission to call the Provider. The old test-only tag MUST NOT be reused.

## New, narrowly bounded implementation

- `scripts/final128_421_task1_native_first_pair_presend_v1.py`: invokes the exact existing #418/#419 Native offline source checks, isolates the FIRST native full-tool request independently in each arm, requires equal bytes but distinct ownership, and refuses importing synthetic later-stage tool IDs/outputs.
- Derives the minimal proposed **first A and first B** Chat Completions envelopes from exact Native source, with `model=gpt-4.1-mini-2025-04-14`, `tool_choice=auto`, full Native banking tool catalog, `temperature=0`, `n=1`, `max_completion_tokens=256`, `store=false`, `stream=false`. Do not prune tools or change canonical Native prompts and attack placement. This is a **bounded proposed experimental profile**: extra transport parameters are not separately validated for exact native-agent model trajectory parity.
- Verifies request SHA/size and the distinct A/B locally owned copies, rejects any modified model, Tool catalog, output cap, B-only treatment at first turn, helper approval flag or synthetic later packet being substituted at the first send boundary.
- Reuses #350's exact token price constants to compute a **LOCAL UPPER-BOUND ESTIMATE**, not a real effective provider billing cap, and never claims that a request under the size cap has fewer than 12k tokens without actual tokenizer/provider usage evidence. Positive estimate is NOT authorization.
- Redacted status report contains only hashes of first native request, catalog, case source, budget proposed and denied-provider-scoring fields; it does NOT publish the raw prompt, fake call IDs, attacks, or account data.
- Cross-uses #420's Chat reply parser with ONE entirely mocked local first-call shape to show its source correlation; mock ID and text remain UNAUTHENTICATED and UNSCORED. No new mock Provider implementation or AgentDojo scorer is created.

## Explicit non-claims / blockers

This PR has **NO protected live sender or workflow_dispatch**, no Provider credentials, no GitHub mutation, no real native writes, no independent TLS sender, no consumed production singleton, no fresh operator consent, no account-level enforced USD stop, no genuine independent first A/B response, no later real Native Tool read, no full real model terminal, no official Native User/Attack scorer and no measured Utility recovery. The CIs never attempt live traffic; the `eligible_for_live_dispatch` field remains false.

To run a genuine first A/B in the future:
1. Independently review *one* production-bound protected GitHub Environment sender job, exact main SHA, model, case, full catalog, and 2 attempts maximum; obtain **NEW** explicit user consent.
2. Verify immutable protected **production** singleton and prove no replay/UNKNOWN retry, independent runtime credential/egress restrictions and enforced provider project spending stop. GitHub Environment self-review alone is not independent authority.
3. Obtain and independently attest actual Provider request/response bytes (first A and B), different session/call IDs and usage before Native tool execution. Treat model proposals as untrusted: read-only calls may go to source-owned Native; protected writes remain behind VERITAS Bind.
4. Only derive subsequent real per-arm Chat inputs from **that arm's genuine model response and Native Tool return**, never from #403's scripted historical packets; close the model terminal and same-run official Native User+Attack scorers for 1 case. Never join old #395 synthetic scorer diagnostic to this run.

Historical V13 A Utility 93/128, B Utility 64/128, B injection success 0/128. New genuine measured recovery: **0**.

## Review process

Only strict exact-pinned PR CI with actual source-owned Native #403 tests can validate this presend. In generic CI without pinned native checkout, the integration tests skip; the dedicated exact-pinned CI requires ZERO skipped tests. Validate the exact PR HEAD, whole workflow status, JUnit, SHA integrity and absence of credentials and unauthorized write surfaces before merge. The source tree can be merged without a paid action; future live API use requires a separate explicit authorization and reviewed implementation.
