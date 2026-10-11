# PR #302 — Historical third model denial vs *new* prospective date-bound control

**Rule-of-One:** Join frozen real third-turn A/B Bind refusals (merged #301)
to an explicitly separate prospective, synthetic, harness-owned date-issued
Task4 candidate. Do **not** reauthorize the historical model messages.

## Frozen negative arm: genuine model, never granted new authority

- Model replies were already captured in Run 38097049813, Artifact
  11686131074. No new Provider calls are made.
- Source ZIP Artifact 11676881211, and historical A/B requests and responses,
  have independently frozen SHA256 lineage from #300 and #301.
- Actual pinned VERITAS Bind adjudicates each old candidate with the **unchanged**
  resolver; \`date_authority_present=False\`, \`supported_profile=False\`, so
  both remain \`BLOCKED\` before any native Apply.
- The consumed tag \`task4-third-two-real-provider-v1-consumed\` stays locked.

## Separate positive control: synthetic offline fixture, not the real model

This round deliberately **does not** take the existing third-turn model
arguments and attach a new date token. The pre-existing prospective date
profile and native runner from earlier PRs #207/#208 already define issuance
before candidate generation. This PR *reuses* them instead of rewriting
production authority semantics.

A new \`Task4DateProfileSession\` owns a random ephemeral HMAC key and a
**synthetic UTC clock** fixed at 2031-07-08. A new *deterministic local-only
callback*, invoked **once after issuance**, uses the detached native
AgentDojo prestate's structured sender/amount to generate a fresh
\`send_money\` candidate, with the session-issued date. The callback never
receives a signing key, authority issuer, or historical provider response.
It is not a fourth model call.

The new capture is exact-paired across Arms A/B, verified after RCC and at
the original VERITAS Bind boundary. The positive \`COMMITTED\` result is an
**in-memory AgentDojo simulator** dispatch in disposable A/B state clones;
these two simulator transactions are NOT a real bank transfer. There are no
external effect endpoints or real financial credentials.

This comparison makes the authorization provenance distinction explicit:
- **Historical third A/B genuine model outputs**: 2 BLOCKED, no effects.
- **New prospective deterministic fixture**: 2 in-memory COMMITTED, **not**
  new real-model utility or a production ALLOW.

The original Task4 resolver remains fail-closed if the date context is absent
or not composed through the established prospective runner. Existing trusted
date profile negative tests for stale, forged, mismatched, reordered,
clock-rollback, and replay attempts remain in place.

## Proof limits

A synthetic harness clock is **not** a physically attested trusted time source.
An ephemeral HMAC token is not production IAM, a human authorization, or
credential isolation. This does not solve live service approval,
network/effect-sink bypass resistance, or actual third-model Utility/Attack
score, and does not alter the Canonical Final128 cohort. A production
deployment would need independent trusted clock, issued/consumed authority
against real execution context, system-wide interception at final sink, and
external validation.

**Do not merge** until the exact PR HEAD's dedicated CI, JSON/JUnit artifact
and all existing checks are independently verified. No approval is granted for
further API calls or bank writes.
