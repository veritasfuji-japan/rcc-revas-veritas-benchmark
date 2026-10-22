# Create-once receipt key custody

This closes one preparation gap in the [deployment runbook](TASK4_SIGNED_LEDGER_MANUAL_DEPLOYMENT_RUNBOOK_V1.md): an explicit create-once Ed25519 key initializer and a pin-required reopen function. It does not deploy a ledger, connect GitHub, enroll a run, start a service or authorize Provider access.

`REAL_PROVIDER_NO_GO / UTILITY_UNSCORED / PRODUCTION_BYPASS_RESISTANCE_NOT_PROVEN`

## Host preparation

Use a dedicated service account and an existing account-owned 0700 parent outside Git, cloud synchronization and artifact directories. For the operator's Linux VM, the prepared parent is `/var/lib/veritas-ledger`, owned by `veritas-ledger`. The initializer creates a **new child** such as `receipt-custody`; do not use the already-existing parent as its target.

The deployed Python environment and source must be administrator-controlled and executable by the service account. A virtual environment in an ordinary user's home is a test environment, not a reviewed service runtime. Do not broaden home-directory permissions or run service-key commands from client-writable source to work around this. Runtime provisioning and operator approval are still required before creating an actual key.

## Interface and failure behavior

Module: `scripts.task4_receipt_key_custody_v1`.

| Interface | Behavior |
| --- | --- |
| `init --directory ABSOLUTE_NEW_CHILD` | Explicit administrative action; exclusively creates a 0700 slot and 0600 raw 32-byte `receipt.key`; fsyncs parent, key and slot before reporting success |
| `inspect --directory EXISTING_SLOT --expected-public-sha256 APPROVED_DIGEST` | Opens only existing material and checks the independently retained SHA-256 of the raw public key |
| `load(path, expected_public_sha256)` | Returns a signing key only after the same checks; intended for a future reviewed service entry point, never calls initialization |

Successful CLI output contains only schema, algorithm, raw public-key hex and its SHA-256. Record that public identity outside the private slot and approve it before using it in a ledger root. Never infer the expected pin from whatever key is currently present. CLI failures return nonzero and a generic denial message; no private bytes or traceback are emitted.

Any existing slot blocks initialization, including empty, partially written or corrupt slots. An interrupted attempt is deliberately retained: no deletion, overwrite, repair or automatic retry. A missing key inside an existing slot cannot be recreated with `init`. Missing storage, changed pins, wrong owners/modes, hardlinks, symlinks, unexpected files and malformed lengths stop reopen. Directory traversal uses no-follow directory descriptors, and non-regular keys are rejected without blocking on a FIFO.

Ancestor directories must be owned by root or the effective service UID and not writable by group/others. Root-owned sticky ancestors are permitted for private temporary test fixtures. The immediate custody parent and slot must be owned by the effective UID and mode 0700. A privileged administrator and all code running as the service UID remain trusted.

## Evidence and limits

Tests cover competing initializers, separate-process reopen, public signature verification, retained interrupted attempts, replacement/missing/corrupt keys, path and permission failures, and sanitized CLI errors. The existing every-PR Native offline workflow runs the tests under sudo so that an actual two-UID access test must run without skips. That test uses only a disposable synthetic marker; temporary authority keys remain in test scratch and are not uploaded. Only JUnit results are exported.

This is filesystem custody, not an HSM or proof against root, Mac administrators, a compromised service UID, memory inspection, snapshots or rollback. Deleting the entire custody slot and initializing again is possible for its trusted owner; the independently approved public pin must reject the replacement. Losing the slot or its public approval record requires stopping, not selecting a new root to resume an old authorization. Fsync calls do not constitute a power-loss durability experiment.

The existing mTLS reference service and GitHub adapter are unchanged. They do not automatically adopt this loader. A reviewed real-API execution entry point, isolated backend writer, explicit genesis approval, TLS/role custody and remote access design remain open deployment gates. No operator VM key, credential, namespace or service is created by this PR or its CI.
