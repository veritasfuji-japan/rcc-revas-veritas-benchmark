# Native actual archive SIGKILL v1

This explicit isolated profile sends SIGKILL to the actual Custody process at
three selected boundaries of the frozen original archive routine. No fabricated
exception, successful archive return or exception unwind stands in for death.
Earlier storage-failure and receive profiles remain unchanged.

| Crash point | Real original operations completed | Retained archive | Fresh owner recovery |
| --- | --- | --- | --- |
| after-create | Encryption and exclusive file create | Empty 0600 single-link file; no write reached | Original JSON decoder rejects the empty file |
| after-file-fsync | Full write, explicit flush and real file fsync | Complete encrypted envelope; file still open at kill intent | Actual authentication/decryption to exact received raw response |
| after-directory-fsync | File fsync, real file close and real directory fsync | Complete encrypted envelope; directory descriptor still open at kill intent | Same exact recovery, without restoring acknowledgement or permission |

The last case deliberately kills before the original routine returns, even
though both fsync calls completed. Storage completion is not acknowledgement to
the caller. All three cases have no successful seal return, SEALED_FSYNCED,
HTTP parse, SDK response, Native continuation or scorer call.

## Actual process death and caller evidence

Immediately before SIGKILL, the selected scoped observer records the actual PID,
signal, UID/namespace, held file/directory descriptor identity and exact archive
snapshot. The audit record is flushed/fsynced through its original separate log
function. The process then calls os.kill on itself with SIGKILL. No Python finally,
file-close observer, seal exception marker or function-restoration claim is made
for the killed process. The kernel's process exit is observed separately by the
supervisor as -9, matching the intent PID, before the supervisor kills other roles.
An intent marker alone is not treated as proof of death.

The real Native caller observes a zero-byte IPC EOF and its unchanged frame
reader raises BOUNDED_FRAME. The original boundary stops execution without SDK
retry. There is no fabricated Bind APPLY_FAILED outcome: the dead Custody cannot
return from Bind. Its prior BLOCKED negative-control receipt remains, but the
allowed attempt has no completed Bind receipt or stored result/acknowledgement.
One backend effect and the signed ledger's revision-two CONSUMED_UNKNOWN already
exist; verified reserve/consume receipts remain, but Custody's effect-returned
marker does not. A missing response never means no effect happened.

The supervisor then SIGKILLs ledger, issuer and backend, and reopens all four
roles with new PIDs. It does not send another kill to the already-dead Custody.
The same archive bytes/inode/hash and pending/unknown records remain. Backend
reopens its same pinned SQLite database read-only, without dispatch. Duplicate
Native request, consume replay and reissue are denied. Reconciliation and owner
recovery issue no permission, repair, reseal or mutation retry.

## Complete joined evidence and normal control

Each negative captures the complete valid response at EOF through the existing
fixed total deadline and physically closes that connection before archive work.
Strict validators join collection/close timing, exact storage-event prefix,
request/run/recipient/AAD/ciphertext commitments, descriptor and snapshot identity,
actual exit/PID, zero-byte caller IPC, signed receipts and backend readback.
Separate Custody snapshot workers compare archive state before and after reopens.
A fresh recipient-owner process runs the original recovery routine after restarts;
it never modifies the original archive or delivers a response to Native.

The matching normal control retains 120 original archive events, eight real SDK
steps, two terminals/scorers, sixteen signed mutations, actual descriptor release,
both fsyncs and all request/body/parent/tool/archive/owner/receipt joins. Normal
Custody retains its frozen TERM/reopen path; negatives use four actual SIGKILL
exits, the first occurring inside archive work.

CI requires 149 new portable tests, 21 joined normal checks and 24 for each of
three crash points, without skips. Portable tests themselves kill actual child
processes and inspect the resulting filesystem bytes, with an explicitly stubbed
same-UID role check; they do not claim Native UID/network isolation. Mandatory
root cases use original separated UIDs, capabilities/NNP, Unix TLS CA/hostname/leaf,
network denials, Native SDK and signed ledger in disposable CI only. The combined
job retains its 45-minute budget; receive and authority/retry conditions are fixed.

These are selected process-crash points, not power loss or reboot. Visible or
fsynced ciphertext does not establish hardware durability or a successful caller
acknowledgement. Arbitrary partial writes, all instruction interleavings, hostile
concurrent writers, independent operator/storage administration and full-runtime
attestation are outside this proof. The synthetic root controller knows fixture
keys. No operator VM, token, real Provider, remote GitHub backend, persistent host
rule, trust store, live permission or service cutover is changed.

**REAL_PROVIDER_NO_GO / UTILITY_UNSCORED /
PRODUCTION_BYPASS_RESISTANCE_NOT_PROVEN** remain unchanged.
