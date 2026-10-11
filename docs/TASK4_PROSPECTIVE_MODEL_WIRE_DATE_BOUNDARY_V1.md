# Task4 #303 — Prospective date-issued model-wire boundary, OFFLINE ONLY

**Central invariant:** An issuer-controlled execution-date context is created
BEFORE the *prospective* model-compatible request is constructed. The original
user request, fixed benchmark prestate, attacker-controlled transaction subject,
and request SHA are captured without letting a model or tool result change
date authority. After an untrusted **local stand-in**, the candidate's
date, amount, recipient, frozen bytes and issuer context must be rechecked
before it could ever reach a real Bind adapter.

This is **not** another real OpenAI request. The model name in the frozen
request is only configuration. The "model" proposal is fabricated locally
as an adversarial-test fixture and **not** a real model completion.

## Predecessors (all remain separate)

- #300: immutable genuine third-turn A/B model response observations.
- #301: native VERITAS Bind BLOCKED both genuine third-turn proposals without
  an independent date authorization.
- #302: separate *new* prospective local-only generation using a trusted
  synthetic date could COMMIT two independent in-memory native simulations.
  **Nothing in #303 reissues authority for historical third-turn replies.**
- Historical third run 38097049813 remains consumed; its tag must never be
  deleted, replayed or interpreted as future permission.

## What #303 does

- Calls the existing immutable Task4DateProfileSession to issue a scoped,
  ephemeral, locally HMAC-signed date context before wire construction.
  Existing date profile source and runner files are SHA-pinned unchanged.
- Assembles an OpenAI Chat Completions-*compatible* **dry-run** request with
  fixed model, max 256 output tokens, read-only synthetic transaction return,
  and a single proposed \`send_money\` tool definition. The lower-trust
  injection text occurs only in the \`tool\` message, never in the developer
  date metadata or original user request. No issuer secret/signature enters
  the request body.
- Freezes exact request bytes for a later, **different authorization round**.
  The source code has no network dispatch or direct Provider connection.
- Accepts exactly one *local fake response* and checks its proposed candidate
  with the existing trusted date-profile amount/date/recipient predicates.
  The slot is consumed even if the candidate is rejected, with no repairs.
- Revalidates issuer/session freshness, UTC date scope, frozen wire, candidate
  digest and original trusted state in a **Bind-facing preflight**. That
  preflight **does not invoke native Bind**; #302 already handled the separate
  synthetic Bind permit experiment, and #301 the historical real-model denial.

## Adversarial test requirements

Fail closed if model, user request, trusted date, lower-trust tool data,
tool inventory, request parameters, response identity, candidate target,
amount, date, case, original trusted state, or capture order changes.
Fail closed if issuer context expires, crosses UTC date, or originates
from another session. No replay/repair after a failed model response.

## Claim limits

Do **not** claim actual real-model integration or Utility recovery.
A compatible wire is not a live model request; an HMAC signed date is not
physical time or production bank authorization; a verified local proposal
is not an executable grant. There is no final native Bind call or bank
effect in this PR. No actual Provider charge or Final128 change occurs.

This PR changes five additive files only. Keep Draft until exact-HEAD
dedicated JUnit/report and ordinary CI are independently verified.
