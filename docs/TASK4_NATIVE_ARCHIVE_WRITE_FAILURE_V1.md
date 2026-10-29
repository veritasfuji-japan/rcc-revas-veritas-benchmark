# Native archive partial write and explicit flush failure v1

This explicit isolated profile calls the frozen original sealer once, through a
scoped observer on the selected archive file. Real encryption, exclusive creation
and real buffered file close remain in place. Previous profiles, collector,
HTTP bytes, SDK, grants, ledger and Bind are unchanged.

| Case | Selected synthetic boundary | Actual visible file after real close | Archive acknowledgement |
| --- | --- | --- | --- |
| normal | No injected error | Complete authenticated ciphertext; explicit flush and both real fsyncs return | Original return after directory fsync |
| partial-write-error | Real buffered write of exactly the first half of the proposed encrypted envelope, then ENOSPC | Exact partial envelope; fresh owner rejects its incomplete JSON | None |
| flush-failure | Original full buffered write returns, explicit flush facade raises EIO before calling the underlying flush | Real context-manager close can flush the buffer; complete ciphertext survives the observed process restarts and fresh owner decrypts it | None |

The partial write is a selected API-level error simulation after a real prefix
write, not a physically full disk. The explicit flush error is synthetic, not a
hardware or machine-wide storage failure. Real file close runs during exception
unwinding. Its visible bytes do not turn an unsuccessful explicit flush into a
successful call, a durability acknowledgement or permission. Both negatives stop
before any archive file or directory fsync; no replacement archive is created.
A short successful write return without an exception is a separate, untested
case; this profile does not claim to handle every Python file implementation.

## Ordering, state and recovery

Normal evidence contains 120 strictly ordered archive events for eight original
seals: encryption, exclusive file open, write, explicit flush, file fsync, close,
directory fsync and original return. The normal original SDK completes eight
steps, two terminals/scorers and sixteen signed mutations. Actual receiver close
precedes sealing; original archive acknowledgement precedes HTTP parsing, guards
and SDK delivery. All original parent, tool, signed receipt and owner joins remain.

Each failure receives the complete valid EOF response and closes the connection.
The real original sealer raises the selected error. Neither successful seal
return nor SEALED_FSYNCED, HTTP parsing, body delivery, Native continuation or
scoring occurs. Bind's actual APPLY_FAILED reports zero verified returned apply
calls, while the backend has already committed one effect. Issuer remains pending,
Custody and the signed ledger remain CONSUMED_UNKNOWN at revision two.

Ledger, issuer, Custody and backend undergo four actual SIGKILL/reopens with new
PIDs. Custody snapshot workers read the same encrypted file bytes, length, inode
and SHA256 before and after. Backend reopens its same pinned SQLite database
read-only with no POST dispatch. Reconciliation, duplicate consume and reissue do
not retry the mutation or produce permission. No file is deleted, repaired,
overwritten or resealed. Normal Custody retains its frozen TERM/reopen control.

A fresh separate recipient-owner process calls the original recovery routine on
a copied synthetic ciphertext. Partial-envelope parsing actually raises
JSONDecodeError; no decrypted raw response is claimed. For the flush failure the
full ciphertext actually authenticates/decrypts to the exact received raw bytes.
Neither outcome issues permission. The original archive remains unchanged.
A decryptable file after process restart does not prove power-loss durability.

## Evidence and scope

The exact proposed ciphertext envelope, written prefix, byte counts and hashes
are joined to encryption output, AAD/header, request/run/recipient commitments,
held no-follow archive snapshots, descriptor identity, exception class/errno,
real close completion, restored scoped functions and actual UID/namespace.
Audit and journal fsyncs use the original function; only the selected archive
file's write/explicit flush are faulted. No secret or private key is exported.

CI requires 139 new portable tests, 21 joined actual normal checks and 24 joined
checks for each negative, without skips. Portable filesystem/crypto tests use
explicit role stubs; they do not establish Native UID isolation. Mandatory root
proofs run only in disposable CI with original Unix TLS UID/CA/hostname/leaf,
network denials, signed ledger and SDK. Prior archive-failure and receive controls
remain mandatory. The combined job's execution budget is 45 minutes; per-response
deadlines, authority conditions and retry rules are unchanged.

Not covered: arbitrary short returns, close failures, disk/power loss, reboot,
all I/O faults, concurrent hostile writers, independent operator/storage
administration or full-runtime attestation. The synthetic root controller knows
fixture keys. No operator VM, token, real Provider, remote GitHub mutation,
persistent host rule, trust store, live permission or service cutover is changed.

**REAL_PROVIDER_NO_GO / UTILITY_UNSCORED /
PRODUCTION_BYPASS_RESISTANCE_NOT_PROVEN** remain unchanged.
