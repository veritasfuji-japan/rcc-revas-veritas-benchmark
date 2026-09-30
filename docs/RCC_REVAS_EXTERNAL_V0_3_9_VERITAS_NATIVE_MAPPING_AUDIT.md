# RCC/REVAS External v0.3.9 — VERITAS Native Mapping Audit

Status: **PRIMITIVES VERIFIED / EXPLICIT ADAPTER LAYER REQUIRED / NO EXTERNAL RUN**

## Exact pins

Ben canonical package:

`effacermonexistence/rcc-revas-veritas-benchmark@1d3782d3aae5ff9c88036709c1a5642320cc53c2`

VERITAS native source:

`veritasfuji-japan/veritas_os@825e5c5c539c98e12b0c9702f3cb4a12d67539d3`

Ben mapping contract:

`external-eval/v0.3.9/contracts/VERITAS_MAPPING_v0.3.4.json`

Expected SHA-256:

`3362038842f889b49aaf0e05c4491eaf688f20b97905c19233e9e09168728385`

## Audit conclusion

Ben's package names three integration wrapper surfaces:

- `NativeDecisionIntentFactory`
- `NativeAuthorityResolver`
- `NativeBindExecutor`

The current VERITAS product does not expose those exact wrapper classes as its
native public implementation. Instead, the required product-native semantics are
available through lower-level verified primitives.

Therefore the correct next state is:

```text
Ben canonical wrapper surface
→ explicit versioned RCC/REVAS↔VERITAS adapter
→ current VERITAS native primitives
```

Do not rename Ben's wrapper identities into product-native classes or claim that
the connection already exists.

## Decision / candidate surface

Current native primitives include:

- `DecisionCandidate`
- `hash_decision_candidate`
- `try_promote_verified_canonical_decision_candidate_to_execution_intent`
- `verify_canonical_decision_artifact`

The adapter must freeze an exact typed projection from RCC `CandidateAction` to
VERITAS `DecisionCandidate`, preserve the original request separately, and
ensure the exact candidate hash is the candidate selected by the verified native
CDA.

No scorer/gold information may participate in this path.

## Authority / approval surface

Current native primitives include:

- signed AuthorityEvidence verification to `VerifiedAuthorityEvidence`;
- verified-authority revalidation;
- `ActionClassContract`;
- Human Approval requirement resolution;
- Human Approval requirement satisfaction, including the explicit
  `NOT_REQUIRED_BY_ACTION_CONTRACT` zero-reference path.

The adapter must source actor, policy, authority, revocation state and required
approval independently of RCC adoption.

## Bind surface

Current native primitives include:

- `ExecutionIntent`;
- `BindAdapterContract`;
- `execute_bind_adjudication`.

The eventual benchmark adapter must make VERITAS Bind the sole owner of an
admitted effect. The benchmark wrapper must not execute the same operation again
after Bind invokes the callback.

Unknown post-dispatch state remains UNKNOWN until independent reconciliation.

## Current interface gaps to freeze before execution

The mapping audit intentionally leaves these as explicit work:

1. Exact `CandidateAction → DecisionCandidate` typed projection.
2. Original request/context lineage independent of candidate content.
3. Persisted canonical decision receipt verification.
4. Exact actor/policy/authority/revocation/approval sources for the selected benchmark.
5. Benchmark-native `BindAdapterContract` state/effect callbacks.
6. Persisted Bind receipt / TrustLog membership verification.
7. Exact benchmark/model/enrollment/scorer/metrics/success/failure freeze.

These must be closed before looking at results from a fresh external benchmark.

## AgentDojo

The pinned VERITAS source already contains the benchmark-only AgentDojo Banking
candidate/Bind adapter primitives and the public AgentDojo pin
`a75aba7631d3ca5fb7ab938965c97ead2f9ff84b` / benchmark `v1.2.2`.

This audit only verifies their availability. It does not wire them into Ben's
external package and does not execute AgentDojo.

## Claim boundary

This audit does not establish:

- native RCC/REVAS ↔ VERITAS integration completion;
- external benchmark execution;
- clean A/B results;
- independent third-party validation;
- production readiness;
- certification.

The next versioned step is implementation of the explicit adapter layer, followed
by interface tests and a new freeze **before** any fresh external benchmark run.
