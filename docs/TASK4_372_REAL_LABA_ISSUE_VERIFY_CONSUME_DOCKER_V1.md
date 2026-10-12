# Task4 #372 — Real upstream LABA issuance, signature verification and single-use Bind consumption in networkless Docker

## Scope of this proof

Run **actual code from** the exact pinned upstream
`veritasfuji-japan/veritas_os` commit
`b1835c9f5044855a7b69f82de997056bba8847ab`, including
`build_live_adapter_bind_authorization_artifact`,
`verify_live_adapter_bind_authorization_artifact`, and
`consume_live_adapter_bind_authorization_and_invoke_bind`.
The official source is copied unmodified into a real Docker image and checked
by SHA-256 before execution. The Docker test runs nonroot, `--network=none`,
read-only rootfs, no published ports, with all Linux capabilities dropped and
without a Docker socket or live API credentials.

Two **independently issued signed upstream fixture** authorizations are
tested: one with a test human approval required and cryptographically verified,
one with human approval not required. Both are verified by the real upstream
signature, governance, authority and artifact checks.

Each is consumed by the real upstream v1 consumption gate and enters its
existing Bind core using a **purely local, non-networked recording adapter**.
Attempt replay is denied without any further secret resolution or adapter
construction. A tampered artifact and an expired artifact are denied before
consumption; after-claim credential resolution failure leaves the upstream
in-memory authorization store consumed and denies replay.

The upstream fixture uses test-only Ed25519 keys, artificial authority,
frozen fixture timestamps, a non-production credential resolver and an
`InMemoryAtomicAuthorizationConsumptionStore` which explicitly declares
`production_safe=False`. No real authority or enterprise effects arise.

## Critical target-binding safety finding

**The upstream official signed authorization targets a billing test target
that is NOT the `http://mock-effect:8081/mock-effect` sink of Task4 #371.**

We deliberately **reject treating this legitimate but unrelated signed
authorization as permission for the #371 sink.** Its valid signature, one-use
receipt and Bind invocation do not grant a transferable execution capability.
The runner asserts both signed authorizations are target-mismatched and
never sends an operation to #371 as a result of either artifact.

The formal API tests and #371 Docker mock-effects are separate evidence, not
a fabricated end-to-end continuation. A future PR must build a **native
authorization for the exact action, target, adapter and credentials** and
apply production-grade atomic consumption at that same broker boundary
before it may claim end-to-end bind-to-effect enforcement.

## Evidence/CI

Dedicated CI checks out the upstream commit with a sparse checkout of the
whole `veritas_os/` and `schemas/` subtrees and verifies pin and source
SHA-256. The real Docker image packages that checked-out source, installs
only pinned dependencies during a trusted build phase and runs with no
network. The audit emits:

- JUnit for 16 identity, signature, consumption, replay, failure and
  nonclaim invariants.
- Original upstream source SHA-256 and commit, Docker image/runtime inspect,
  real formal authorization IDs and consumption hashes, Bind invocation
  evidence, failure reason codes, and evidence/source SHA-256.
- 0 real Provider requests, 0 cost, 0 real banking effects and **0 synthetic
  sink dispatch** on behalf of these target-mismatched authorizations.

## Nonclaims

This PR does not demonstrate actual independent enterprise authority,
production postgresql consumption, authorized Docker sink effect, an
independent reviewer, real model output, cloud IAM enforcement or a full
production-eligible issue→Bind→effect→reconciliation trace. Host and Docker
daemon control are trusted in this demonstration. Earlier paid API approval
is not reused.

**The stop condition matters:** Do not enable Docker sink effect merely
because a formally signed artifact is valid. Require exact target binding
to match **before** an effectful adapter becomes accessible.
