# Task4 #481 — protected-only broker process without legacy listener (OFFLINE / NO-GO)

Based on merged #480 `b58e8cba44e0aad7ec3e371354470204ef4ce381`.

## The narrow improvement

#480 introduced a signed, broker-owned CAS gate but called the raw #458 `legacy.action()` after CAS, and ran a protected endpoint beside still-deployable legacy code. #481 constructs a **single protected-only local broker process** whose execution call graph contains **no raw legacy #458 broker action or socket listener**. The protected child registers only the #480 signed-packet UNIX socket handler, and explicitly trips if the legacy broker, `spawn_server` or `action` is invoked inside that child.

This is a *bounded harness deployment property*, not global security isolation: Python monkeypatch tripwires are test controls, **not a protective OS policy**. Original legacy #458 module, direct `action()` and CLI remain globally available in the same repository and OS identity. Another process can deploy the legacy Broker or modify the SQLite database: no external network or credential chokepoint exists. **Do not claim the global legacy bypass is removed or that production non-bypassability is PROVEN.**

## Protected process execution boundary

- **Three spawned OS processes** on one test runner: orchestration parent, ephemeral Ed25519 signer #475, and the protected-only Broker child.
- New protected-only Broker validates original SDK request SHA-256, frozen trial/case/model/arm/ordinal/policy/audience/nonce, exact synthetic NO_SEND claim, pinned signer public key and signature **server-side**, before SQLite CAS consumption.
- Broker child writes to exactly one protected SQLite `protected_attempt` table in one `BEGIN IMMEDIATE` / `synchronous=FULL` transaction; it **does not** call raw #458 `action()` and does not create a second legacy Broker listener. All successful consume statuses are `UNKNOWN_PERMANENTLY_NO_SEND`.
- Explicit negative probes: unsigned direct #458-format `consume`, live send opcode, forged signature, changed request digest, signed replay.
- Restart the **broker process** with the same local database; signed and unsigned repeats still deny, and eight consumed slots persist.
- With frozen original AgentDojo Native SDK dependencies in dedicated PR CI, eight original A/B requests pass through protected-only broker *before* the #472 local deny-only worker and #471 scripted response AEAD. Hash-only original-wire evidence must agree with #473 preflight.
- The protected-only test directory is mode `0700`, the SQLite database and UNIX socket mode `0600`. These permissions do **not** isolate processes sharing the same Unix identity.

## Integrity and safety boundaries

**This PR does not revoke old #458 entrypoints outside the protected process or establish that no other legacy listener can ever start.** A same-identity adversary can bypass the harness and execute legacy code; Python functions can be imported directly. No independent IAM, remote issuer, protected remote CAS, cross-runner durability, network-egress enforcement, production sender or paid owner consent. Broken/unknown local transactions fail closed in this controlled code path; no global distributed exactly-once guarantee is claimed.

Provider POST **0**, external bank effects **0**, genuine Native Utility **UNSCORED**; Task4 #321 and Task1 #427 remain OPEN / NO-GO. No Secrets/Environments/Rulesets/tags/paid workflows changed. Dedicated PR-only `contents: read` workflow, frozen public sources, hash-only/JUnit artifact. Four additive files; Draft until dedicated and inherited CI succeed, owner reviews and merges manually.

## Next milestone

Remove or deprecate all legacy executable Broker paths under a separately reviewed migration without breaking prior evidence; then provision independently governed credentials and egress, protected remote issuer/CAS, and adversarial cross-runner validation. Those separate changes require explicit design and approval.
