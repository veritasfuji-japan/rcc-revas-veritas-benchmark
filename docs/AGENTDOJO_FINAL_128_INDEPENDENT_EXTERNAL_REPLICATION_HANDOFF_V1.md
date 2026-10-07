# AgentDojo Final 128 — Independent External Replication Handoff V1

Status: **HANDOFF READY / NOT YET INDEPENDENTLY REPLICATED**

This packet hands off the successful V13 Canonical Final 128 evidence for independent review and future replication.

It does **not** itself establish independent third-party validation.

## Canonical source evidence

Repository:

`veritasfuji-japan/rcc-revas-veritas-benchmark`

Successful V13 source run:

- Run: `37585673492`
- Job: `112675107243`
- Attempt: `1`
- Event: `workflow_dispatch`
- Source main SHA: `2454ba69818d1a46b910f33fab9b57017cd7a83e`

Terminal disposition:

- Path: `contracts/AGENTDOJO_FINAL_128_V13_TERMINAL_DISPOSITION_v1.json`
- Git blob SHA: `2f2a5dd1a91d4068776e39a064f167cd304767b2`

Post-execution analysis boundary:

- Path: `contracts/AGENTDOJO_FINAL_128_V13_POST_EXECUTION_ANALYSIS_BOUNDARY_v1.json`
- Git blob SHA: `6b78872b42ffae12ccd54b1802146b8a96a76469`

Handoff contract:

- Path: `contracts/AGENTDOJO_FINAL_128_INDEPENDENT_EXTERNAL_REPLICATION_HANDOFF_v1.json`
- Git blob SHA: `b6a2bbb8da505608ed94fb4198edb1c8a3525f70`

## Exact V13 result artifact

- Artifact ID: `11466539107`
- Name: `agentdojo-clean-ab-final-v13-37585673492`
- ZIP SHA-256: `9fbb2a1614c237e92c4239bb5d60f83d40d33b81e0092d3f82958931969c9e7a`
- GitHub expiry: `2027-01-05T07:10:01Z`

Expected members:

1. `results/agentdojo-clean-ab-final-v13/execution_records.jsonl`
2. `results/agentdojo-clean-ab-final-v13/native_scores.jsonl`
3. `results/agentdojo-clean-ab-final-v13/summary.json`
4. `results/v13-runtime-dependency-import-closure.json`
5. `.v13_handoff/v13_dispatch_receipt.json`

## Observed result to recompute

The reviewer should recompute these values from the artifact rather than trusting this document:

- 128 paired cases
- 256 arm records
- 0 execution errors
- 128/128 same initial pre-state
- Arm A utility: 93/128
- Arm A native injection-task success: 20/128
- Arm B utility: 64/128
- Arm B native injection-task success: 0/128
- A utility success / B utility failure: 30
- A utility failure / B utility success: 1
- Provider calls: 820
- Runner-estimated provider cost: USD 0.3221684

The native `security` field is the AgentDojo injection-task success result. Therefore lower is safer for this direct-injection corpus.

## Track A — independent evidence recomputation

Purpose: independently verify the **already completed V13 artifact**.

This track must not perform provider execution.

Prerequisites:

- GitHub access sufficient to read the repository and artifact.
- No OpenAI API key.
- No VERITAS database credential.

Suggested flow:

```text
fetch exact source metadata
→ download artifact ID 11466539107
→ verify ZIP SHA-256
→ verify exact 5 members
→ recompute record and score counts
→ recompute paired utility transitions
→ verify claim boundary
→ emit independent reviewer attestation
```

Passing Track A supports only:

**Independent evidence recomputation of the same V13 artifact.**

It does not establish an independent model execution.

## Track B — independent same-corpus new execution

Purpose: have a distinct operator execute the same frozen corpus and implementation independently.

Critical rule:

**V13 must not be reused.**

The V13 authorization and human confirmation are terminal and single-use.

A Track B execution requires, before any provider access:

- a new versioned authorization;
- a new single-use durable consumption identity;
- fresh operator confirmation;
- exact source pins;
- frozen scorer and pairing rules;
- an explicit provider spend cap;
- a new execution artifact and evidence chain.

Passing Track B supports only:

**Independent same-corpus execution replication.**

It still does not establish held-out generalization.

## Track C — held-out independent execution

Purpose: test generalization on a corpus not previously exposed to the development loop.

Required before execution:

- a newly frozen held-out corpus;
- new versioned authorization;
- new single-use durable consumption identity;
- fresh operator confirmation;
- frozen scorer and pairing semantics;
- independent operator preferred;
- explicit claim boundary.

Passing Track C can support held-out evidence only within the new frozen corpus and assumptions.

## Reviewer attestation

An independent claim requires a reviewer attestation containing at least:

- reviewer name or pseudonymous identifier;
- organization or independence context;
- UTC date;
- source commit;
- artifact SHA-256 or new-execution artifact SHA-256;
- commands or workflow used;
- result;
- known deviations;
- explicit acknowledgement of the claim boundary.

## Prohibited claims before external replication

Do not claim:

- independent third-party validation completed;
- held-out generalization proven;
- production readiness proven;
- universal zero-injection-success guarantee.

## V13 reuse prohibition

The following are terminal and must not be reused:

- Authorization ID: `AGENTDOJO_CANONICAL_FINAL_128_EXECUTION_V13`
- V13 Authorization blob: `7a1b42fb47f84844e0db9701e28eab40153c196d`
- V13 Human Confirmation blob: `a458b7cb1917e01823235aa2e9448025ed735cd5`

`rerun_authorized = false`

## Next Rule-of-One

`INDEPENDENT_REVIEWER_ATTESTATION_V1`
