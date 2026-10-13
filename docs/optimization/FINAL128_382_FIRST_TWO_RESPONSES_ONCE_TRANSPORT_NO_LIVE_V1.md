# Final128 #382 — Task1 first-two Responses HTTPS capture core: no live dispatcher

## What changes compared to #381

Task1 #381 froze an actual Responses API-shaped *first* read-only request and
validated the **shape** of caller-provided, untrusted captured JSON. #382 adds
a byte-exact **HTTP adapter core** that actually invokes
`conn.request("POST", "/v1/responses", ...)`, reads the observed
`x-request-id` header and bounded body from an injected connection, checks the
read-only function-call schema, and writes a synchronous, append-only-ish local
JSONL before each possible send and after its outcome.

A/B share identical first request bytes; actual captures must have distinct
server-request, Response and Tool-call IDs. Refusal of invalid first response,
bad status, missing ID, or transport uncertainty stops further calls without
retry. Fixed-size output token and local pessimistic cost reservation bound
the **theoretical** first two attempts (USD 0.0104192 under existing #350
rates), but project billing is **not** proven limited by this local estimate.

The adapter is not another fake Task1 final-answer generator; it is a
transport protocol/data-capture step needed before an authentic Provider
read → native Tool → final model trajectory can be measured.

## Crucial safety boundary

**This PR does NOT ship or activate a live sender.** It contains no
`workflow_dispatch` trigger, OpenAI SDK client, environment secret injection,
external GitHub tag mutation, production issuer, scheduler or live CLI.
The HTTP core accepts a caller-owned connection: the test suite supplies
local `FakeConn` objects only. An attacker can forge HTTP-like data in a fake
connection; therefore the raw receipt and claimed ID are **NOT** authenticated
Provider-origin evidence and must never be promoted to scored Utility.

A future trusted GitHub Actions issuer would need to own the connection
factory directly and use a real TLS-verifying HTTPS client, bind each
request/response hash to an exact main SHA / run ID, restrict egress to the
exact Provider endpoint and forbid concurrent dispatch. It must protect
the raw evidence because it may include original user/banking data.

Real external capability creation remains **unimplemented**:
- fresh case-scoped user authorization of A/B, exact model and maximum spend;
- independently verified model availability/pricing and project billing limits;
- protected GitHub environment for narrowly scoped Provider secret;
- verified immutable tag protections, **atomic external one-use tag
  creation before any real request**, unique consumption across workers;
- no rerun or automatic retry even when first POST is UNKNOWN;
- source authentication from trusted TLS transport + protected CI,
  rather than self-declared JSON `approved` or `provider_verified` flags;
- real native original DirectAttack payload, genuine call-ID → returned
  Native read → real model terminal, then pinned Native User/Attack Scorer;
- IAM/credential/egress bypass resistance, third-party audit.

The deliberately inaccessible `protected_live_dispatch_gate` always refuses.
Do not call the local fake-connection rehearsal a production credential
or network control. No GitHub protected configuration was changed.
No actual API spending, bank effects or new Native scores are generated.

## Evidence and merge gate

Dedicated #382 CI (pull_request/main only) tests the transport core using
deterministic in-memory connections, with Python socket interception, zero
secrets and no actual Provider posts; and reruns #381/#380/#379/#378/#377/
#350/#351 pinned source tests. It checks all tests PASS with no skips,
exact AgentDojo source/HEAD, redacted SHA-only evidence, `UNKNOWN` refusal/no retry
and both-arm isolation.

The journal is local to the CI host; its fsync and
"already exists" checks **do not provide an immutable globally durable
single-use lease**. A crash mid-journal, external concurrent worker or
malicious same-process caller is not a controlled production boundary.

#382 prepares a future manually approved run; it is **not** the actual
protected run and must not trigger an API. Historical V13 remains
Arm A Utility 93/128, Arm B Utility 64/128, B Injection success 0/128.
A one-case genuine pilot would not prove full Final128 recovery.

Merge requires exact-head CI all-success, artifact SHA and security review.
No automatic merge, no future-paid approval implied by merge.
