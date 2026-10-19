# Frozen synthetic request scope in the Native signer

Base: merged #485, `452cabe80679a39f9fbb1d17055f4f8131aebb82`.
Disposition: **SCRIPTED OFFLINE ONLY / REAL PROVIDER NO-GO / UNSCORED**.

#485 separated the issuer key from the parent, but accepted any correctly shaped
parent-supplied request digest. This selected runner adds a fixed manifest checked
inside the signer child before its sequence/recipient policy is updated. The
manifest has exactly A/B ordinals 0..3. Every consume, attach and read must match
the exact request hash for that arm/ordinal. Wrong scope cannot consume signer
state. The prior sequence, signature, restart replay and protected-custody checks
remain in place. Parent cannot select a manifest through the signing protocol or
an environment variable. The fixed file is loaded in the child; missing, symlinked
or byte-changed files fail closed before the signer announces readiness.

## Provenance of the fixture

The manifest was extracted from the previously verified #485 standalone artifact:

- HEAD `b1685e5fd179c2f2ecde2eb119425df7c226532b`
- Run `39290083693`, Job `118188156160`, Artifact `12205515951`
- ZIP SHA256 `5fbf53ccbaca8611bec253405ee40e038ff93473247b6bbd65de95dda7cd5b78`
- Manifest SHA256 `ee33c0a2d768ad4c7ceb4699a1abb702f6eb8e2f1ca8e0a64ce6c1867f860309`

Only the eight request hashes, arm/ordinal, output cap and public source metadata
are retained. Random ciphertext/receipt hashes and recipient identity are not
frozen. The first A/B requests have the same body hash; arm/ordinal remain explicit
signed fields. The new Native run must reproduce all eight exact wire hashes,
including the original request bodies with cap 256. A change in those requests
fails this fixture instead of silently regenerating its scope from the new run.

## What this does not establish

This is a **repository-frozen synthetic manifest**, derived from an earlier
scripted run. It is not a real owner approval, independent policy decision,
production issuer, or an authorization to send requests to a Provider. Hash
matching checks equality of claimed request digests; the signer does not observe
raw request bytes. The controlled Native transport is what computes those hashes
from the actual local SDK request. Arbitrary malicious replacement of that driver
is outside this proof.

The recipient is still supplied by the parent on first consume and pinned for the
session. Receipt/envelope claims are still parent-supplied and checked by custody.
There is no independently preapproved recipient, independent IAM or protected
filesystem, durable signer state, expiry/revocation or cross-runner CAS. A same-UID
actor able to replace code and its pins is outside these Python checks. Historical
entrypoints remain executable. No production-wide bypass-resistance claim follows.

## Validation

Unit tests cover altered manifests, missing manifest, unlisted and cross-slot
request hashes, and failure without state mutation. The spawned-signer negative
test uses raw IPC to ensure the child, not just the parent helper, rejects altered
scope before issuing any signature. Full Native CI must show 24 verified
signatures, eight exact manifest-matching requests, eight cached-token replay
refusals, two protected custody startups and 32 parent protected socket connects.
The standalone report records manifest hash and explicit unproven approval/IAM
fields. Downloaded JUnit and JSON must be tied to the latest HEAD before merge.

All responses remain scripted. Real Provider and bank effects stay zero, Utility
UNSCORED. No existing runtime sources, Secrets, Environment, Rulesets, tags or paid
workflows are changed. #321/#427 remain unresolved.
