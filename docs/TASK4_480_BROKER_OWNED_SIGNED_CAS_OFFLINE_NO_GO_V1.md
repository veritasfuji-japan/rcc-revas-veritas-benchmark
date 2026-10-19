# Task4 #480 — broker-owned signed synthetic NO_SEND claim and local CAS

**Status: OFFLINE research only / NO-GO.** Based on merged #479 `070d8095af1788cdd5cb17784d46eb3eb06efa21`.

## What changes from #479

#479 confirmed that direct legacy #458 `consume` can bypass the client-side #478 Python CAS hook. #480 introduces a **new, explicit protected broker endpoint**, not a production migration or replacement of all legacy listeners. The protected UNIX socket handler routes requests only to `SignedGate.consume`; it **never** exposes raw `legacy.action` directly.

The protected broker checks **inside the server**:
1. Exact packet schema and synthetic `consume` opcode, trial, arm, ordinal, original Native SDK request SHA-256.
2. Locally derived expected synthetic #474 claim, fixed policy digest/nonce, model/case/audience and `provider_post_allowed=false`.
3. Ed25519 signature against a pinned public key returned by the separately spawned #475 synthetic signer process.
4. Server-owned #477 SQLite CAS on `(trial, arm, ordinal)` with `UNKNOWN_PERMANENTLY_NO_SEND` and `synchronous=FULL`, **before** calling the #458 NO_SEND-only action.
5. Refuse missing auth, fake signature, changed request SHA, signed replay, `send_live`, revoked scope and missing store. Storage exception means denial; **no retry after ambiguous committed slot**.

The dedicated workflow reuses the original frozen AgentDojo Native SDK integration from #473/#472: hook at the original SDK request preflight, before #472 deny-only worker. It submits all **8 A/B original request hashes** through the new protected UNIX socket; returned receipts must match original preflight wire hashes. Synthetic local AEAD scripted responses and native local worker still run, with **zero Provider POSTs** and **genuine Utility UNSCORED**.

## Critical limitations / evidence boundaries

- **The original legacy #458 Broker and its raw `action()` function remain unchanged and can still be used if deployed as a separate socket endpoint or imported directly.** #480 only guards the new protected endpoint, not all possible paths. This is not a globally enforced broker migration.
- Same Runner and OS identity controls signer IPC, protected socket, signer public key, and both SQLite files. A hostile same-identity process can tamper with the local store, launch an unprotected legacy Broker, or bypass the wrapper. No independent IAM, remote issuer, egress pinning or credentials isolation is proven.
- Broker validates the signed SDK request **hash** from the parent; it does not independently attest raw Native SDK origin or Provider identity.
- Two local SQLite transactions (#477 gate CAS, then #458 legacy consume) are **not** a distributed atomic commit; after gate-CAS commit failure of the downstream broker, the slot stays consumed and must not be retried.
- Local scope is not a production permission to execute; ALL accepted decisions mean **NO_SEND**, not allow. Real owner approval absent, Provider POSTs **0**, external bank effects **0**. Issues #321 and #427 remain OPEN / NO-GO.
- Tests are synthetic and local even if original frozen Native SDK bytes are used. Any claim of production bypass resistance, cross-runner single-use or genuine model utility would be incorrect.

## Reproduction & merge policy

The dedicated PR-only workflow installs frozen public AgentDojo/RCC/VERITAS pins. It runs unit/negative tests, reruns the eight original Native SDK requests through the protected broker and creates hash-only JSON/JUnit evidence. No secrets, paid workflow, tags, Rulesets, Environment or settings changes. Draft until checks pass; repository owner reviews and merges manually, never auto-merge.

## Next milestone

If the research result is reproducible, consider making the independently operated Broker the **only** viable executor endpoint, eliminating or disabling any legacy direct action and enforcing independent IAM/credentials/egress and cross-runner durable CAS. These require separate design and user approval, not implied by this PR.
