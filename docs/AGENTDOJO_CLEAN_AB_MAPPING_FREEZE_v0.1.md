# AgentDojo Banking Clean A/B — Mapping Freeze v0.1

Status: **MAPPING FROZEN / RUN-SPECIFIC FREEZE INCOMPLETE / EXECUTION GATE CLOSED**

## Purpose

This freezes the benchmark-specific semantics for the next RCC/REVAS × VERITAS
AgentDojo Banking comparison **before** any new benchmark execution.

It deliberately does not choose a model or case enrollment on behalf of the
operator. Those are run-specific experimental inputs and must be frozen in a
separate reviewable step before execution.

## Exact source pins

- Ben canonical substrate:
  `effacermonexistence/rcc-revas-veritas-benchmark@1d3782d3aae5ff9c88036709c1a5642320cc53c2`
- VERITAS:
  `veritasfuji-japan/veritas_os@825e5c5c539c98e12b0c9702f3cb4a12d67539d3`
- AgentDojo:
  `ethz-spylab/agentdojo@a75aba7631d3ca5fb7ab938965c97ead2f9ff84b`
- AgentDojo release: `v0.1.35`
- benchmark version: `v1.2.2`
- suite: `banking`

## Arm definition

### Arm A — RCC/REVAS only

The exact AgentDojo proposed tool call is validated by the native runtime, passed
through the same RCC/REVAS candidate/adoption semantics, and—if admitted—executed
by the native AgentDojo runtime.

VERITAS native governance is not invoked.

### Arm B — same RCC/REVAS + VERITAS

The same RCC/REVAS semantics feed:

`NativeDecisionIntentFactory`
→ `NativeAuthorityResolver`
→ `NativeBindExecutor`.

For admitted protected mutations, VERITAS Bind is the sole effect owner.
The benchmark wrapper may not apply the operation a second time.

## Candidate identity

The AgentDojo native runtime first validates the final tool name/arguments.

That exact typed call becomes:

`CandidateAction(tool_call, name, validated arguments)`

and is then frozen through VERITAS
`freeze_agentdojo_candidate`.

Candidate identity, request identity, RCC decision identity, CDA identity and
ExecutionIntent identity remain distinct.

No scorer/gold/oracle information may be used to form the candidate or request.

## Request lineage

The native Decide request query comes from the exact enrolled AgentDojo user-task
instruction, not from the proposed candidate or RCC rationale.

Runtime context may contain only runtime-visible benchmark/case/state metadata.

## Authority and Human Approval

RCC ADOPT grants no authority.

The benchmark profile uses a separately signed synthetic AuthorityEvidence for a
fixed benchmark principal. The exact public key, signer policy, artifact and
revocation-snapshot hashes must be frozen before execution.

Human Approval is `NOT_REQUIRED` for this first simulated AgentDojo profile.
The user prompt is never treated as approval and zero fake approval references may
be created.

This does not test an approval-required branch or production banking authority.

## State and effect

Both arms must begin an enrolled case from equivalent independently restored
AgentDojo initial state.

Arm B's protected effect may occur only inside
`NativeBindExecutor.Adapter.apply`.

After a treatment-induced effect difference, later model trajectories may diverge.
That is treatment behavior and must not be rewritten into a same-candidate claim.

A separate immediate same-candidate/same-prestate replay may be retained as a
mechanism measurement, but it must not be scored as whole-task utility/security.

## Native scoring

Whole-task utility/security must come only from AgentDojo's original pinned native
scorer after the execution barrier.

Scorer-private data is unavailable to runtime governance.

## Important exposure limitation

This AgentDojo Banking corpus has already been used in earlier VERITAS engineering
work (TASK-023).

Therefore a future fully frozen A/B on this same corpus may be a clean
**integration replication**, but it is not an unseen held-out validation result.

For a stronger confirmatory claim after this integration lane, use a genuinely
unseen benchmark/suite or a precommitted held-out condition.

## Execution gate remains closed

The following must still be frozen exactly before a run:

- model/provider/version;
- prompt/tool-format version;
- sampling/seed/retry/budget;
- immutable case enrollment;
- injection/attack enrollment and seeds;
- exact native scorer hashes/aggregation;
- signed benchmark authority/public key/signer policy;
- revocation snapshot;
- current-pin Decide source pins and receipt verifier;
- Bind receipt/TrustLog verifier;
- runtime/scorer inputs;
- stopping/invalid-run criteria;
- maximum provider budget.

A later commit must replace all unresolved fields and explicitly open the execution
gate. No benchmark run is authorized by this mapping-freeze PR.

## Claim boundary

This PR establishes a preregistered mapping contract only.

It does not establish a run result, held-out validation, independent third-party
validation, production readiness, certification, or customer evidence.
