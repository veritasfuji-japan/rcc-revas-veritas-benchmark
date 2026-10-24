# Task4 VM isolated egress evidence and host-policy review candidate v1

## Result and provenance

The operator ran the reviewed #545 tool on the Linux VM after deploying merge
`384962f289aa0365f4b342750874fa22672e0c56`. The full public result was exported
as gzip/Base64 by reader UID 61109. The transferred bytes were decompressed,
CRC-checked, SHA256-matched, canonical-JSON checked and replayed through the
exact reviewed v1 report validator.

- [Full report](../evidence/task4_native_vm_egress_rehearsal_v1/report.json):
  **18,453 bytes**, SHA256
  `5450e2639db054f176a3f01c9978513232a661497e365610b995adbd645e7c72`.
- [Evidence index](../evidence/task4_native_vm_egress_rehearsal_v1/index.json):
  source/provenance, phase counts, namespace identities, errno summary and
  explicit limitations.
- Reviewed rehearsal source SHA256:
  `f6865825a1f7435a1821e56f3e2e64db806c4ffad23f402d21cba8b394e48857`.

This is **operator-reported VM isolated-namespace evidence**, not direct file
access to the VM, independent VM attestation or a signed report. The source
and whole-record hashes establish byte consistency; they do not independently
prove its origin, a trusted clock or the absence of omitted host activity.
The recording date is 2026-10-25 JST; no exact observation timestamp was emitted.
No token, credential digest, private key or actual Provider payload is included.

`REAL_PROVIDER_NO_GO / UTILITY_UNSCORED /
PRODUCTION_BYPASS_RESISTANCE_NOT_PROVEN` remains unchanged.

## Full-data checks

| Phase | Reported and verified records |
| --- | ---: |
| Before installing isolated rules | 32 successes |
| Five target UIDs, IPv4/IPv6 × TCP/UDP | 20 denials |
| Exempt service/reader/root UID controls | 12 successes |
| After removing the isolated table | 32 successes |

All 20 denied flows contain actual UID/GID, zero effective capabilities,
`no_new_privs`, the family/protocol, errno and before/after kernel UID counters.
Each individual counter increased. Per-UID counter sequences were monotonic
and covered by the final counters. All five final counters recorded 5 packets.
IPv4 TCP returned errno 113, IPv6 TCP 13 and both UDP families 1; these values
are accepted only together with the full counter/control joins, not alone.

The report records kernel `6.8.0-147-generic`, nftables `1.0.9`, iproute2 `6.1.0`
(lib bpf `1.3.0`) and util-linux `2.39.3` for setpriv/unshare. Parent network
namespace `(device 4, inode 4026531840)` was unchanged; the child was distinct
`(device 4, inode 4026532347)`, with loopback only. Both were kernel identities
reported by the tool, not host identity attestation.

The [earlier CI proof](TASK4_NATIVE_EGRESS_REHEARSAL_V1.md) ran on a different
kernel (`6.17.0-1022-azure`). Its result and the operator VM result are separate.
The new VM report still says `host_rules_applied: false`,
`operator_host_egress_verified: false` and `execution_permission_issued: false`.
The actual host firewall has **not** been installed or proven by this result.

## Concrete host-policy candidate

The candidate files below are review artifacts, **not an authorization or an
installation mechanism**:

- [Manifest](plans/task4_native_host_egress_v1/manifest.json)
- [Atomic creation batch](plans/task4_native_host_egress_v1/apply.nft)
- [Single-table inverse](plans/task4_native_host_egress_v1/rollback.nft)

| Item | Candidate |
| --- | --- |
| Family | `inet`, both IPv4 and IPv6 |
| Dedicated table | `veritas_native_host_egress_v1` |
| Table ownership comment | `veritas-native-host-egress-v1` |
| Base chain | `output`, filter hook, priority 0, default accept |
| Rejected socket UIDs | backend 61103, issuer 61105, custody 61106, archive 61107, runtime 61108 |
| Not matched by this candidate | service 109, reader 61109, root 0, all other UIDs |
| Rejection | Counter plus `icmpx admin-prohibited` |
| IP scope for the five UIDs | All IP output, including loopback and DNS packets |
| Inverse | Delete only the dedicated table after verifying ownership and exact shape |

Creation uses **`create table`**, followed by creation of its chain and exactly
five reject rules in one nft batch. An existing table name is a collision,
not permission to append, merge, flush, replace or repair it. Failure of the
transaction must leave the existing table unchanged. Never substitute `add
table`, a global flush or a permissive existing-connection shortcut.

The two file byte pins are retained in the manifest:

| File | SHA256 |
| --- | --- |
| `apply.nft` | `8e78a32fc31a24d32da1576869db5795d214544461c8d60ef6f30c5eb4dd9345` |
| `rollback.nft` | `fed2c2c26ddc887d84afdce11ab292f24d4170fbcce337b2c8756e6cd173bb55` |

This proposal changes no INPUT/FORWARD rules or default host policy. Its five
socket-UID matches do not themselves block a different UID's traffic; this
is not proof that an existing SSH session, reader GitHub request or signer
service has been exercised under an installed host table. Existing tables,
namespace placement and actual process/socket ownership need fresh review.

The rule also denies a future legitimate local IP connection by one of the five
roles. The current Native transport and local scripted backend need a separately
reviewed design before execution can be expected to work under this policy.
AF_UNIX/privileged proxies, inherited sockets opened by another UID, other
network namespaces, root or a CAP_NET_ADMIN holder are outside this UID-output
candidate's bypass coverage. It is not a full host/network isolation boundary.

Reader UID 61109 is **not** restricted to GitHub by this batch. The existing
signer UID 109's egress is also not restricted. Dedicated token permissions,
DNS policy, shared-IP/CDN limitations, proxy behavior and service-specific
network confinement remain separate unresolved gates.

## Proposed application and inverse sequence — not executed

The artifacts make the exact mutation and inverse reviewable. This PR does not
supply a live-host apply wrapper, an ownership-checking rollback wrapper,
a watchdog timer or reboot persistence. Its manifest intentionally marks all
of these deployment claims false. Do not feed the candidate into host nft as
part of merely reviewing or merging this PR.

Before any host trial:

1. Take a fresh read-only inventory of the host's current network namespace,
   all nft families/tables, UID/GID memberships, capabilities and active
   processes/sockets for the five target UIDs. Do not use process command lines
   that could print credentials. Review any unexpected activity before proceeding.
2. Pin reviewed protected source and both candidate file bytes. Confirm a root
   recovery session/VM console and a tested independent bounded rollback path.
   No independent automatic rollback is implemented by these files.
3. Ensure the dedicated table is absent. Save an inventory for comparison;
   an inventory is **not** a file to restore with a global ruleset replacement.
4. In a reviewed host-trial wrapper, perform an nft check of the pinned batch
   without mutation, arm the independent bounded rollback, then execute that
   same atomic batch exactly once. A name collision or error stops before
   claiming installation; do not delete an unexpected existing table to retry.
5. Read the installed nft JSON and verify the exact ownership comment, one
   filter/output chain, priority/policy, exactly five numeric socket-UID rules,
   intended reject expression/counters and no extra chains, sets or objects.
   Run bounded local probes and recheck the existing service/reader/admin
   controls. A failed or unknown result requires the reviewed inverse, not
   execution permission or broader allow rules.
6. For inverse operation, recheck **ownership and exact table shape** before
   issuing the single command in `rollback.nft`. A changed/unrecognized table
   stops automatic deletion and requires recovery-session review. The inverse
   removes only this table, preserving all unrelated tables. Do not flush
   the host, restore an entire snapshot or silently remove other administrator
   rules. Verify the table is absent and separately verify recovery controls.

For later steady-state enforcement, the rollback cancellation/ownership rules,
startup ordering, persistence, crash/power-loss behavior, planned exceptions and
live-host evidence must be reviewed and implemented. A temporary isolated test
or candidate merge cannot establish these properties. The expired Native context
and earlier read-only approval are historical and are not extended by this work.

## Validation

Seven portable tests check full report bytes/source replay, all flow/counter
results, provenance/secret boundaries, candidate byte pins, fixed UID scope,
exclusive creation and the single-table inverse. An eighth mandatory root test
creates a **fresh network namespace** using the reviewed guard, with loopback
only, and performs actual kernel checks of the exact candidate bytes:

- Syntax check has no state effect; the creation batch installs only the
  commented candidate table, one chain and the expected five kernel rules.
  JSON reject codes are matched as the exact symbolic admin-prohibited value
  or its numeric ICMPX ABI value 3; other reject codes are not accepted.
- A duplicate create fails and the existing kernel table state stays identical;
  the transaction does not append rules or overwrite the table.
- Inverse check does not delete; the exact inverse removes the candidate table
  while a separately created canary table remains byte-equivalent in kernel
  JSON. The test then removes its own canary before namespace teardown. Parent
  namespace identity is unchanged.

The successful isolated transaction JSON is retained in the actual test case's
JUnit property. This kernel test is not host policy deployment or another VM
observation. Root capability skips are permitted locally but forbidden in the
mandatory CI job. No live-host firewall operation is executed by the tests.
The #545 rehearsal source remains unchanged so its historical report can be
replayed against its pinned v1 semantics.

To recheck the frozen VM report without applying rules:

```sh
python - <<'PY'
import hashlib,json
from pathlib import Path
from scripts import task4_native_egress_rehearsal_v1 as e
root=Path('evidence/task4_native_vm_egress_rehearsal_v1')
raw=(root/'report.json').read_bytes()
index=json.loads((root/'index.json').read_bytes())
assert len(raw)==index['report_size_bytes']==18453
assert hashlib.sha256(raw).hexdigest()==index['report_sha256']
report=json.loads(raw)
assert e.canonical(report)==raw
e.validate_report(report)
print('Frozen public VM report byte and logical checks passed; no rules applied')
PY
```
