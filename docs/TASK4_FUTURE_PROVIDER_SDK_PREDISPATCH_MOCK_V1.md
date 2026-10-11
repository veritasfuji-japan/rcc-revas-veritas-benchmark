# PR #306 — Prospective real SDK pre-dispatch, **offline mock transport only**

**Rule of One:** Check that the *actual pinned OpenAI Python SDK*
(\`openai==1.109.1\`) serializes exactly the request frozen by the
pre-existing **issuer-owned** Task4 execution-date context, without a
single external API request. All SDK calls are intercepted by an
in-process \`httpx.MockTransport\` with \`max_retries=0\`.

**There is NO approval to call any live model** and this PR does not create,
use, restore or transfer Provider authorization.

## Inherited frozen boundary

- #303: single trusted synthetic execution date issued **before** wire
  construction; original request and untrusted transaction subject cannot
  configure the issuer.
- #304: local synthetic response and strict tool-call candidate checks.
- #305: separate in-memory AgentDojo full-native RCC/actual VERITAS Bind
  positive and fail-closed tests.
- #306 only tests the **pre-dispatch SDK serialization seam**, not another
  #305 positive Bind decision, a fourth real Provider call, or Final128.
- The earlier third two-call authorization remains *consumed*. The
  consumed tag must not be reused, deleted or re-pointed.

## SDK interception

An OpenAI client is constructed **inside the test only** with a literal
dummy non-usable API key and an \`httpx.Client\` whose ONLY transport is
\`httpx.MockTransport\`. The callback observes the SDK-generated POST,
requires exact HTTPS target \`/v1/chat/completions\`, the expected dummy
Authorization header, exact canonical JSON body, identical model,
original request, trusted date, tools, and max output token bound.
The callback returns a clearly fabricated local completion with a known
\`offline-only\` id and zero synthetic usage; no network path exists.

One preflight attempt is consumed **before** all checks, so both a
verification failure and any SDK error leave the instance non-retriable.
The local completion cannot become Provider proof, and it is parsed
through the original #303 date candidate binding and Bind-facing
verification only. No native actual Bind is called by #306.

## Cost limitation

The local static estimate uses the historical #299 frozen price
assumptions \`$0.40\` / million input tokens and \`$1.60\` / million
output tokens, with hypothetical ceilings of 10,000 input and 256
output, total hypothetical estimate \`$0.0044096\` (below local
\`$0.005\` threshold). These are **not verified current prices**,
not actual measured prompt usage, not a budget authorization and
**not an enforceable billing hard cap**. Real usage and pricing can
change. Any future real call requires a separately authorized,
freshly priced and durably consumed execution contract and one-use
external spend/effect control.

## Explicitly not proven

No real model output or server response, API charge, externally
authenticated Provider receipt, live human approval, native VERITAS
Bind call, real banking operation, authoritative date/clock trust
root, IAM bypass resistance, Task4 native utility score, or
Canonical Final128 results.

The test suite exercises SDK serialization, strict transport target,
one-shot semantics, input/output limits, expiry, stale/cross-session
date scope, changed request, unexpected provider-like response,
wrong candidate and missing Provider secrecy boundaries.

**DRAFT until the exact HEAD's dedicated CI + JUnit/report artifact
and all ordinary checks are independently verified. Do not merge
on source review or partial passing tests alone.**
