# Native archive close failure v1

This explicit isolated profile calls the frozen original archive routine once.
Real encryption, exclusive creation, the entire buffered write, explicit flush
and archive-file fsync run before either selected close error. A scoped facade
observes/faults only this archive file's context-manager exit. Other files and
journal/audit fsync operations delegate unchanged.

| Case | Selected close boundary | Actual descriptor release | Archive acknowledgement |
| --- | --- | --- | --- |
| normal | Original close returns after real file fsync | Real close; closed stream and EBADF on its saved descriptor are observed | Original seal returns only after real directory fsync |
| close-before-release | Synthetic EIO before underlying context-manager exit | Explicit fixture-only cleanup releases the still-open descriptor; no second seal or repair | None |
| close-after-release | Real context-manager exit releases the descriptor, then facade raises synthetic EIO | Closed stream and EBADF are observed before the injected error | None |

These are selected API-level error simulations, not a claim that the kernel,
filesystem or physical disk actually returned EIO on close. In the before-release
case, the mandatory fixture cleanup occurs in a finally block solely to release
its descriptor. Its separate CLOSE_CLEANUP events do not represent a successful
original close acknowledgement. There is no retry of the sealer or mutation.
The after-release case exercises the important distinction between releasing a
resource and successfully returning from the operation that owns it.

## Ordering and retained uncertainty

Every negative receives a complete valid 556-byte EOF response through the
existing fixed total receive deadline, then physically closes the connection.
The original sealer completes real write/explicit flush/file fsync and raises at
close. Neither directory fsync nor original SEAL_RETURN, SEALED_FSYNCED, HTTP
parse, Native response, continuation or scorer call occurs. Bind reports its
actual APPLY_FAILED with zero verified returned apply calls, although one backend
effect has already committed. Signed ledger revision two and Custody remain
CONSUMED_UNKNOWN; issuer remains pending.

Ledger, issuer, Custody and backend undergo four actual SIGKILL/reopens with new
PIDs. Separate Custody snapshot workers retain the same archive bytes, length,
inode and hash. The backend reopens its same pinned SQLite database read-only,
with no POST dispatch. Repeated Native request, consume replay and reissue stay
denied; reconciliation grants no permission. No archive is deleted, overwritten,
repaired or resealed. Normal Custody retains its frozen TERM/reopen control.

A fresh separate recipient-owner process calls the original recovery routine on
a copied synthetic ciphertext after the restarts. Both files actually authenticate
and decrypt to the exact captured raw response. That proves the observed bytes
and recipient join, not permission to parse/deliver or retry. A successful file
fsync without completed directory fsync/seal return does not prove successful
archive acknowledgement or power-loss durability.

## Complete evidence and positive control

The normal profile audits 120 archive events across eight original seals,
including both real fsyncs, close completion, closed-stream state and actual
EBADF on the saved descriptor before another observer can reuse its number. It
retains eight real SDK steps, two terminals/scorers, sixteen signed mutations and
all original request/body/receipt/parent/tool/archive/owner joins.

Validators join exact proposed/written ciphertext and encryption hashes,
AAD/header commitments, file/directory identity, strict integer descriptor fields,
close begin/cleanup/release ordering, actual errno/class, restored scoped functions,
owner recovery, UID/namespace and the complete signed/backend state. Neither
fixture cleanup nor descriptor release is promoted to seal success.

CI requires 164 new portable tests, 21 joined normal checks and 24 per close
failure, with zero skips. Portable I/O/crypto tests use explicit role stubs; actual
UID/capability/NNP, Unix TLS CA/hostname/leaf and network denials are proved only
in disposable-root CI. Earlier encryption, write/flush, receive and normal controls
remain mandatory. The combined job retains its 45-minute budget; authority,
receive deadlines and no-retry conditions are unchanged.

Not covered: all real close outcomes, arbitrary short successful writes, abrupt
crash between all possible storage instructions, concurrent hostile writers,
hardware failure, power loss/reboot, independent storage/operator administration
or full-runtime attestation. The root synthetic controller knows fixture keys.
No operator VM, token, real Provider, remote GitHub backend, persistent host rule,
trust store, live permission or service cutover is changed.

**REAL_PROVIDER_NO_GO / UTILITY_UNSCORED /
PRODUCTION_BYPASS_RESISTANCE_NOT_PROVEN** remain unchanged.
