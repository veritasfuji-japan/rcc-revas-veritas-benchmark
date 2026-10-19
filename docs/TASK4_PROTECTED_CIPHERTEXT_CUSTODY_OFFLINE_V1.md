# Task4 protected ciphertext custody — offline component

Base: merged #482, `dfc1762535650c2b6919ecf190c6834c33323597`.
Disposition: **LOCAL_COMPONENT_ONLY / PROVIDER_NO_GO / UTILITY_UNSCORED**.

## Purpose and scope

#482 identified that #481's Native harness still starts a legacy custody Broker
through #471. A replacement must support encrypted-response attachment and
readback, not just signed single-use consumption. This additive component provides
a new signed consume/attach/read protocol without importing or invoking #458.
It does **not** connect the Native SDK harness yet. The old indirect startup
identified by #482 remains unchanged. This is the first migration component,
not a claim that the migration or whole-system bypass prevention is complete.

## Protocol

All three operations require an Ed25519 signature over an exact canonical claim:
schema, synthetic trial, banking Task4 case, model, operation, arm/ordinal,
request SHA-256, recipient SHA-256, receipt SHA-256, envelope SHA-256 and literal
`provider_post_allowed=false`. The synthetic trial is distinct from #458.

| Operation | Bound fields and behavior |
|---|---|
| consume | Receipt/envelope hash must be null. Atomically inserts a unique arm/ordinal slot and commits `CONSUMED_UNKNOWN_NO_SEND` before returning a receipt. Repeat consumption is denied, including a changed request for the same slot. |
| attach | Requires the consumed request/receipt, pinned recipient and signed hash of exact envelope bytes. Strict #457 envelope/header shape and scope checks; a single atomic attachment is permitted. Duplicate attachment is denied, even after restart. |
| read | Requires the same signed request/receipt/envelope digest and recipient. Stored bytes are rehashed before returning ciphertext. Reads are intentionally repeatable and never issue a new execution permit. Missing ciphertext is denied; the slot stays consumed. |

The database persists the issuer and recipient pins; reopening with different
pins fails. Restart opens an existing DB only. Missing, locked or inaccessible
storage fails closed. The UNIX listener is local and bounded; it has no HTTP
client, Provider opcode, plaintext-response field, legacy entrypoint or private
recipient key. The test parent creates a private 0700 directory and 0600 DB;
the server socket is 0600. These permissions do not isolate same-UID code.

## Evidence and limitations

Tests use fresh synthetic Ed25519 and X25519 keys. The existing #457 vault creates
an AES-GCM envelope from synthetic bytes; a separate Broker OS process stores it,
is terminated and restarted, then returns ciphertext that the recipient decrypts.
The recipient key remains in the test parent. Tests cover unsigned requests,
forged signatures, changed payloads, wrong request/arm/ordinal/receipt/recipient/
digest, live flags/opcodes, pre-consume attach/read, duplicate JSON, replay,
storage tampering, identity drift, missing/locked DB and competing consume/attach.
The concurrency test uses separate SQLite connections in threads, not independent
Runners. Termination after an acknowledged consume tests persistent unknown state;
it does not prove crash-at-every-instruction or commit-before-lost-ACK behavior.

The Broker checks envelope structure, scope, issuer signature and ciphertext
digest. **It cannot authenticate the AES-GCM tag or plaintext without the recipient
key.** A trusted signer can sign malformed cryptographic material; that is not
detected as a valid model response here. The honest synthetic roundtrip proves
recipient recovery in that fixture only. No actual SDK wire, genuine model reply,
Provider identity, billing or Utility evidence is produced by this component.

The fixture parent holds the synthetic signing key and initializes storage. There
is no independent issuer service, expiry/rotation/revocation service, authenticated
remote caller or tenant isolation. Signed read requests function as replayable
read capabilities. Same-UID operators can change files, keys or code; DB tamper
tests cover limited detected inconsistencies, not an immutable store or rollback
resistance. No independent IAM, credentials, egress or cross-Runner CAS is proven.

## Validation

```sh
python -m pytest -q -o addopts= tests/test_task4_protected_ciphertext_custody_v1.py
```

Dedicated PR-only CI installs pytest and cryptography, runs the component suite
and uploads JUnit only. It has read permissions, no secret references, no protected
Environment and no manual paid-dispatch entrypoint. Results must be checked for
the current PR HEAD. Local development initially passed the 23 non-socket tests;
the two process/socket cases were blocked by the local runtime's AF_UNIX permission
restriction and are left enabled for GitHub CI, not skipped or declared passed.

## Next migration gate

Adapt the selected original Native SDK/AEAD path to this protocol with exact wire,
receipt and ciphertext provenance, preserving local recovery and scorer behavior.
Verify descendants/restarts do not start #458 anywhere in that selected run.
Retain historical #458 fixtures separately. Integration must resolve the gap
between a consume receipt and later signed attachment without turning a response
or scorer observation into execution authority. No live Provider authorization
is implied by this component or its CI. #321/#427 remain unresolved checkpoints.
