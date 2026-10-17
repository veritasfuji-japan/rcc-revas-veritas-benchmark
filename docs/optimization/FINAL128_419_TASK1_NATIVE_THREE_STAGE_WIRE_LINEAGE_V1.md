# Final128 #419 — Task1 Native three-stage A/B model-input lineage (UNSENT)

## Narrow Rule-of-One

Following merged #418 (measurement gap), do not add another scripted
candidate, synthetic terminal, Native scorer, new independent wallet or
policy/BIND permit. #403 already captures the REAL Native AgentDojo
`AgentPipeline` model-visible `first`, `post_read`, and `post_mutation`
wire requests for A and B, while ONLY the assistant model is substituted
with a controlled scripted recorder. #395 has a scorer, but on a different
offline trajectory; it must NOT be stitched to this run for a real score.

**#419 verifies and freezes those six UNSENT native request packets** from
one unchanged #403 execution and records only their canonical SHA-256. This
provides an exact request-stage lineage contract for a future independently
authorized protected Provider sender. Nothing in this PR sends a packet.

## Invariants

1. Exact source-pinned AgentDojo and VERITAS, case `banking:user_task_1:injection_task_2:direct`,
   immutable original attack and complete unchanged Native tool catalogue,
   source-owned B-only post-read spending overlay, real local B Bind refusal
   and zero B protected mutations are verified through unchanged merged #418.
2. **A and B first Native model packet bytes** match. Both have native
   `developer,user` message roles; neither is a copied Provider response.
3. After actual local Native `ToolsExecutor` read, both arms retain the
   *same malicious original Tool response content*, but their owned Tool
   call IDs are **distinct**. Only B receives the source-owned additional
   developer-mapped read-only context.
4. The third packet after actual local Native protected-tool dispatch /
   denial contains the exact previous history prefix, one proposed assistant
   tool-call message and its ordered native Tool messages with exact matching
   **per-arm tool_call_id**. A/B must not share IDs; shuffling one ID fails.
5. Every packet retains model, auto tool choice, zero temperature, full tool
   schema and canonical digest. Missing/reordered/substituted stages or
   tools fail. #403's native scripted terminal is not a Provider completion.
6. A six-hash redacted lineage and two per-arm hashed call-ID summaries are
   published. No original attack subject, account contents, full messages,
   provider credentials, model results or raw call IDs are included.
7. `eligible_for_paid_dispatch=false`,
   `eligible_for_official_scoring=false`, scorer result NULL, recovered
   Utility = **0** regardless of any local test success.

This is read-only packet materialization, not a durable multi-run data
store, cryptographically signed Provider provenance, protected consent,
IAM/credential/network control, or scorer eligibility. The hashing alone
does not authenticate messages from an untrusted external exporter; only
the live in-process pinned #403 Native execution in dedicated CI is in
scope. The existing Task1 real-model Provider bridge remains **NOT BUILT**
and requires fresh explicit approval/cost cap.

## Next real integration and spend boundary

A future separately reviewed protected sender must consume the exact
source-owned stage requests, generate independently observed A/B genuine
Provider replies with verifiable source/TLS receipts, prevent reruns,
preserve native tool output and protected execution/NO_EFFECT/UNKNOWN
state, and only then submit *same-run* Native User and Attack Scorers
with terminal content/stack trace. Do NOT just import fake IDs or join
#395's independent diagnostic. Do NOT convert denied protected proposals
to ALLOW to increase Utility.

## Local verification

Only dedicated CI provides pinned Native checkouts. In the generic
pytest job lacking them, integration tests may skip; strict CI sets
`FINAL128_419_REQUIRE_NATIVE=1` and **requires zero skips**.
The dedicated workflow executes existing #418 / #403 / #395 tests and
new order/ID/refusal assertions on an unmodified frozen source checkout.
It issues 0 Provider calls, 0 live bank effects, 0 new official scores.

Review exact PR HEAD, all CI checks, JUnit without skipped/error/failure,
and redacted artifact hashes before considering merge. No automatic merge.
