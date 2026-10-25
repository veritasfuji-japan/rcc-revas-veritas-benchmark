# Task4 operator VM systemd isolated-recovery evidence v1

The operator deployed merge `a71fbe78abb945cf35b6faff09815b00bd506b5c`
(#548), verified the three source hashes and ran the explicitly acknowledged
systemd rehearsal on the Linux VM. This PR retains the complete public result
without modifying the runtime, policy, approved ledger or operator host firewall.

- [Exact full record](../evidence/task4_native_vm_systemd_recovery_v1/report.json):
  **4,997 bytes**, SHA256
  `5d1d85a3ec80125e4613fa98815f8901941ac596462431ab0a7bf60745df0a64`.
  The canonical bytes have no trailing newline.
- [Evidence index](../evidence/task4_native_vm_systemd_recovery_v1/index.json):
  source pins, outcomes, observation/provenance limits and separate CI reference.
- Rehearsal source SHA256:
  `7e7dcf6d62bf4b3c4abc73204587a87b9a2cb2748b6cec3c70dd6232d5878ebb`.

## Provenance and scope

Reader UID 61109 exported the root-owned public result at
`/etc/veritas-native-ledger/systemd-isolated-egress-a71fbe7.json` through a
no-follow, root-ancestor, owner/mode/single-link/size check. Those VM filesystem
checks are **operator-reported**. The transfer was pasted gzip/Base64, boundedly
decompressed with gzip CRC verification, matched to the reported SHA256 and
length, canonical-JSON checked and replayed through the exact pinned #548
validator. These byte/logical checks were performed on the received full record,
not inferred from the preceding terminal summary.

This is not direct VM file access, independent host/clock attestation or a signed
report. Source hashes establish consistency with selected reviewed files, not
full runtime origin. The recording date is 2026-10-25 JST; no precise observation
timestamp or kernel release was emitted by this report.

`REAL_PROVIDER_NO_GO / UTILITY_UNSCORED /
PRODUCTION_BYPASS_RESISTANCE_NOT_PROVEN` remains unchanged.

## Reported and replay-verified outcomes

| Case | Outcome | Reported worker PID |
| --- | --- | ---: |
| Deadline | Exact owned table removed | 8083 |
| Controller SIGKILL | Exact owned table removed after controller death | 8124 |
| Foreign table nonce | No deletion of replacement | 8163 |
| Extra rule | No deletion of altered table | 8201 |
| Table-name collision | Stop with existing table unchanged | None |

All four worker identities report UID 0, parent PID 1, `NoNewPrivs=true`, exact
three-source pins and a namespace matching their case's isolated namespace.
Every isolated namespace differs from the host guard namespace. Some numerical
namespace identities recur across these sequential cases; this record makes no
claim of globally unique lifetime namespace IDs.

Every case reports an unchanged unrelated canary table and stopped transient
units. The overall record reports the root-private stage removed, parent
namespace `(device 4, inode 4026531840)` preserved and host table names unchanged.
It explicitly reports `host_rule_contents_attested=false`. A table-name check
is not an assertion that every existing rule's contents were attested, nor is it
an existing-service liveness/control test.

Temporary systemd units **were created on the host**; that bounded host-side
mutation is explicitly recorded as true. The nft operations were confined to
isolated namespaces. `host_rules_applied=false`, `execution_permission_issued=false`
and zero Provider requests remain explicit. No host nft enforcement or Native
execution permission is established by the rehearsal.

## Operator VM evidence versus CI evidence

The VM report records `systemd 255 (255.4-1ubuntu8.18)`. The separate #548 root
CI proof recorded `systemd 255 (255.4-1ubuntu8.17)` and 39 tests with zero skips
(run 40125900144, artifact 12573706037, ZIP SHA256
`6c5359b7dc7039a07c2fa4ba4d6cc18360abc232a357c65aeec397fd74fab6af`).

The public VM CLI exercised exactly the **five cases above**. It did not execute
the separate CI test that deliberately creates a foreign-tagged systemd timer
and proves cleanup refuses to stop it. That real-manager foreign-unit refusal
is CI evidence only. The operator report still exercises the normal tagged-unit
cleanup path, but it is not a VM observation of that negative unit-ownership case.
Do not turn the CI count of 39 into a claim of 39 executed VM cases.

The [implementation boundary](TASK4_NATIVE_SYSTEMD_EGRESS_V1.md) remains:
root/CAP_NET_ADMIN races, a killed watchdog/manager, lost guard anchor, reboot and
power failure are outside recovery guarantees. Five-UID policy does not cover
SDK agent 61101, executor 61102, stranger 61104, reader 61109, service 109 or root.
Reader GitHub-only egress, retained-signer confinement, full actor/proxy/socket
coverage, persistent recovery and real Provider use remain separate gates.
The expired Native approval is not extended and no enrollment is performed.

## Evidence validation

Seven read-only regression checks pin the full record bytes and source closure,
replay its validator, independently join outcomes/identity/canary/cleanup data,
preserve provenance and CI/VM distinctions, and reject promotion of this result
to host enforcement or execution permission. The existing mandatory root #548
39-case proof and all earlier root gates remain unchanged. This evidence PR adds
no rule-installation, service-control or live-host trial entry point.
