# Task4 #476 — original Native SDK wire joined to local separate-process signer (NO-GO)

**Scope:** PR-only, offline, synthetic research evidence. No real Provider send.

#476 hooks the #473 `check_sdk_wire` boundary reached from the actual local Native SDK request path before #472 isolated-worker claims. For each of eight scripted A/B SDK requests (A0–A3, B0–B3), it binds the original SDK wire SHA256 and frozen synthetic policy digest into a #474 NO_SEND claim, requests a signature from a #475 spawned signer process, and verifies the signature in the parent with only the public key. It then continues the existing local #472 worker, #471 AEAD before Native parse, scripted terminal and local scoring path.

The offline proof checks eight same-run wire hashes against #473 receipts, eight worker claims, eight AEAD scripted responses, eight restart replay refusals, duplicate signed-claim refusal and live-send opcode refusal. Only hashes and synthetic metadata are written.

## Limitations / NO-GO

- Signer and verifier are **different OS processes on the same Runner and OS identity**. Not independent IAM, independent network egress, separate machine, protected issuer, or real authorization.
- Private key is ephemeral and synthetic, no real owner approval. Same-run in-memory consumed set is **not** durable cross-runner single-use enforcement.
- #475 child signs only synthetic `provider_post_allowed=False` fixtures; this proves provenance and **always NO_SEND**, never live execution authority.
- Native traffic is scripted local SDK traffic, not real Provider response. No genuine Native Utility score; no real external bank effects.
- Provider POSTs: **0**; bank effects: **0**; utility: **UNSCORED**. Task4 #321 and Task1 #427 remain **OPEN / NO-GO**.
- No GitHub Secret, Environment, Ruleset, tag, workflow_dispatch, real Sender, payment or billed model invocation is introduced.

Source base: #475 merged `c0e8c667a763876acee12bdf43cba3bbbc358a48`. Four additive files; PR remains Draft pending CI and owner review.

Next missing proof: independently managed issuer authority, independently enforced network/credential boundary, durable atomic consumption/revocation across runners, original Provider sender integration and a new explicit owner-approved bounded paid trial before any live POST.
