# PR #304 — Prospective local completion-envelope-to-candidate bridge

**Rule of One:** Construct a strict, read-only **local fixture** resembling one
Chat Completions response, bind it to the immutable **issuer-owned** #303
prospective wire and context, and convert exactly one proposed \`send_money\`
tool call into the existing trusted date candidate capture and Bind-facing
integrity gate. **No real model is called or impersonated.**

## Frozen predecessor and authentication limits

- Parent: merged PR #303 at main
  \`ad930d2344322d4e8a067ec170ad75c6f6c5b0dc\`.
- Existing prospective wire and date profile source Git blobs are checked.
- The historical third real-model calls were already consumed. #304 neither
  reads their real response artifact nor reuses their authorization.
- A Chat Completions-shaped *local* fixture has no genuine Provider
  authentication; the \`local_client_correlation\` is explicitly only local
  bookkeeping. It hashes both the frozen model wire and the **particular
  issuance context digest**, since two different sessions can legitimately
  produce identical public wire bytes.

## Positive bounded path

Issue new synthetic harness date before request -> freeze request bytes ->
fabricate an **explicitly fake** completion with one tool proposal ->
check exact local source marker, session+wire correlation, model, single choice,
tool call schema, JSON duplicate keys, typed arguments, and non-billed usage
markers -> consume a response slot -> call unchanged #303
\`capture_stub_response\` -> verify unchanged #303
\`verify_before_bind\` with original trusted state.

## Negative cases

Fail closed for mismatched model, source, response ID, client correlation,
session, wire, untrusted role promotion, forged tool/function, multiple calls,
bad arguments, duplicated JSON keys, non-finite amounts, attacker recipient,
wrong amount/date, expired context, changed protected candidate or trusted
prestate, and repeated response attempt even after failure.

## Strict limits

This is a **local test double**, not an implementation of a live model SDK,
provider identity verification, independent server receipt, native Bind
adjudication, physical-clock attestation, production execution authority, or
an actual financial action. The reported synthetic zero-token usage is not
a billable API measurement. No Final128 results or Task4 official scorer are
produced. PR #301's original real-model Bind refusals and #302's separate
synthetic positive native Bind proof remain unchanged.

No dispatchable endpoint, no provider API key and no bank mutation are
introduced. **CI success only proves this local envelope's bounded checks.**

Remain Draft until exact HEAD's dedicated and ordinary CI results, new
evidence ZIP SHA256, report and JUnit have been independently reviewed.
