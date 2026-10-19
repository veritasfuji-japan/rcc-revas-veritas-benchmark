# Task4 #464 — Signed issuer date and scope, OFFLINE HARD NO-GO

## What this adds
An isolated Ed25519 verification boundary for an **externally supplied, signed** issuer envelope, with exact case, model, baseline main SHA, frozen prestate and injection SHA, original user-request digest, recipient digest, USD minor-unit amount, signed UTC issue/expiry/execution date, arm, and the SDK first-request digest. The verifier checks cryptographic integrity, strict schema, key fingerprint, issuer role, a 15-minute maximum issuance window and that a separately supplied observed time lies in that window.

**Important:** This is a *synthetic fixture*, not a real human decision or real trusted clock. The test-only signer key is generated afresh in tests, never installed or enrolled as a real authority. The verifier unconditionally refuses `enrolled_by_independent_operator=True`, and returns `live_provider_post_allowed=False` even for a perfectly signed valid synthetic fixture.

## Boundary and limitations
- No new Provider client, API key, paid call, external bank effect, protected Environment, GitHub ref/tag, Ruleset, credential or workflow dispatch.
- The signed issuer is **not** a trusted real issuer. Valid Ed25519 signatures prove integrity under the supplied public key only; they do not prove that the signer had permission to authorize the recipient, amount or date.
- The observed timestamp is caller supplied; it is **not** independently attested real wall-clock time. The synthetic test date 2026-10-19 is a fixture, not authority evidence.
- Request, recipient and user hashes must come from independently verified original sources in any future implementation. The fixture uses synthetic SHA placeholders, not real user/bank data.
- The envelope is not wired to a real Native first request or to the #463 broker yet. Do not promote it to a production permission or treat it as an execution-time send grant.
- A future real trusted issuer needs separately enrolled public-key provenance, verifiable key custody and authority scope, issuance BEFORE first SDK request, and a trustworthy clock. Independent A/B and external one-use replay prevention are still unresolved.
- The original #455 HARD DENY remains unchanged. Task4 Issue #321 and Task1 Issue #427 remain OPEN/NO-GO; genuine A/B Utility remains UNSCORED.

## Review gate
Only 4 new files. Check latest PR HEAD, dedicated pytest JUnit, all inherited CI, no `secrets.*`, no Environment and no paid dispatch. Do not merge automatically. Any future real issuer enrollment, bank recipient authorization or Provider use needs a separate design, review and explicit owner approval.

## CI regression correction
The first PR HEAD exposed a real gap: a correctly re-signed but substituted recipient digest passed because it was not compared to an independently supplied trusted recipient. The validator now compares the signed recipient digest, amount, and currency against independently supplied owned-scope inputs; mismatch fails closed. These inputs are still test-only caller claims, NOT independently authenticated bank/issuer facts. Real authority enrollment remains NO-GO.
