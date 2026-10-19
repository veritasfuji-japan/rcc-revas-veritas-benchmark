# Fixed synthetic recipient in the Native signing scope

Base: merged #486, `d60caa968eec989bb13d6e4de6350b2bbb370ccb`.
Status: **OFFLINE ONLY / PUBLIC TEST KEY / REAL PROVIDER NO-GO**.

#486 constrained request hashes, but let the parent select the first recipient.
This selected runner adds a fixed recipient manifest loaded inside the signer
child. Every consume/attach/read must name its exact recipient digest, including
the first consume. A rejected swap does not mutate signing state. The prior frozen
A/B request scope and operation-order policy still apply. No caller-selected path
or recipient enrollment opcode exists. Missing or byte-changed manifests fail
closed. Custody additionally checks signed claim and ciphertext header binding.

The new manifest links to #486's unchanged request manifest SHA256 and contains a
32-byte X25519 public key plus its SHA256. It is fixed before this run:

- Recipient manifest SHA256: `18e3d1c2776f029a57012beae669ac25c9bf3c680fc5239b0ee851196bedb93c`
- Recipient public-key SHA256: `8f15bcc58f2ddb4f6d5e490191d96b84d1f67b5872f5ec3871afd2e33c3f6aa1`

## Public test-key limitation

**The recipient private key is publicly reproducible from a labeled synthetic
fixture seed in the code. Never use it for real data.** This lets offline CI
recover the scripted responses without Secrets or production key provisioning.
It proves recipient equality/binding behavior, not confidentiality from other
users, independent custody, or real owner approval. The issuer signing key remains
random and child-only; it is a different key with a different role.

The wrapper uses the hash-pinned #484 generation order: first the fixed fixture
recipient, then eight ordinary random X25519 ephemeral keys. It verifies exactly
nine calls and refuses an extra call or an ephemeral equal to the recipient.
The vault's HKDF salts and AES-GCM nonces remain random. Original files/pins are
unchanged. This fixture is scoped to the selected runner, not a new general-purpose
key-generation facility. Historical vault wording about an ephemeral recipient
must not be used to describe this fixed-recipient variant; the new report declares
its public reproducibility and lack of real-data confidentiality explicitly.

## Evidence and limits

Unit tests cover modified manifests, missing manifest, wrong recipient before
first consume and at later operations, state preservation, replacement of the
fixture key, and preservation of random envelope ephemerals. A spawned-child test
sends invalid recipient claims over raw IPC before each valid operation, ensuring
child enforcement rather than relying on parent-side helpers. Full dedicated CI
must retain eight request-hash matches, 24 signatures, eight ciphertext recoveries,
eight original-token replay refusals, two custody startups and 32 protected connects.
A separate standalone run emits hash-only evidence and explicit limitation flags.

The signer verifies a claimed recipient digest; the controlled vault/custody path
checks actual recipient bytes and envelope binding. This is repository-frozen
synthetic configuration, not an independently approved production recipient.
Same-UID code/pin replacement, credential/egress isolation, independent IAM,
operational key management, cross-runner CAS and production-wide bypass resistance
remain unproven. Old entrypoints remain callable. Provider/bank effects stay zero,
Utility UNSCORED. #321/#427 remain unresolved. No Secrets, Environment, Rulesets,
tags or paid workflows are changed or executed.
