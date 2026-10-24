# Task4 isolated Native UID egress rehearsal v1

## Problem and resulting behavior

The operator VM read-only observation retained an egress **plan**, not applied
or observed host rules. Its inventory reported nftables 1.0.9, iptables 1.8.10
with the nf_tables backend, CAP_NET_ADMIN/CAP_SYS_ADMIN and default routes for
both IPv4 and IPv6. IPv6 was enabled. This makes IPv4-only validation inadequate.

The new stdlib-only CLI renders an explicit candidate policy or rehearses it
in a newly created, loopback-only network namespace. There is **no host apply
command**. No service configuration, authority key, credential, trust store,
DNS record, veth, default route, account or persistent namespace is created or
changed. Existing reader/signer process connectivity is not used as a probe.

`REAL_PROVIDER_NO_GO / UTILITY_UNSCORED /
PRODUCTION_BYPASS_RESISTANCE_NOT_PROVEN` remains unchanged.

## Policy scope

| Role | UID | Candidate behavior inside the isolated namespace |
| --- | ---: | --- |
| backend | 61103 | Reject all IPv4/IPv6 output |
| issuer | 61105 | Reject all IPv4/IPv6 output |
| custody | 61106 | Reject all IPv4/IPv6 output |
| archive | 61107 | Reject all IPv4/IPv6 output |
| runtime | 61108 | Reject all IPv4/IPv6 output |
| retained service control | 109 (GID 110) | Not matched; positive loopback controls |
| reader control | 61109 | Not matched; positive loopback controls |
| root control | 0 | Not matched; positive loopback controls |

The fixed `inet` output chain uses numeric socket UID (`meta skuid`), counters
and `reject with icmpx type admin-prohibited`; its default policy is accept.
The five exact target UIDs are denied, including loopback traffic. This is not
a default-deny policy for every process, nor a GitHub-only policy for reader
UID 61109. UID 109, UID 61109 and root egress remain outside this candidate.
Other UIDs are not silently included. The role numbers are fixed; the CLI
accepts no arbitrary UID, target host, table name or firewall file.

Blocking every IP output for those five roles also blocks a future closed-local
TCP/UDP API connection. Only separately reviewed exceptions or another reviewed
transport design could permit such a connection. The proposal does not claim
that the future Native runtime already works under this policy. AF_UNIX traffic
and indirect privileged proxies are outside this IP rule's coverage.

## Commands

Use a reviewed protected source and interpreter. An old regular `scripts`
package can shadow a newly deployed namespace package; the explicit bootstrap
from the [operator materials handoff](TASK4_NATIVE_OPERATOR_MATERIALS_V1.md)
applies here too. The examples show module arguments, not permission to change
host firewall configuration:

```sh
python -I -B -m scripts.task4_native_egress_rehearsal_v1 plan
sudo python -I -B -m scripts.task4_native_egress_rehearsal_v1 rehearse \
  --acknowledge-isolated-network-test
```

`plan` performs no tool execution or network operation. It emits a candidate
rule string, its SHA256 and explicit false host/execution flags. Do not pipe
that rule string into a host nft command. `rehearse` requires root UID/GID 0,
the explicit acknowledgement, the kernel capabilities needed for netns and UID
changes, and preinstalled `unshare`, `ip`, `nft` and `setpriv`. Resolved tool
files and their ancestor directories must be root-owned and not group/other
writable. The operator CLI does not install packages or relax permissions.

The tool itself writes no report file. Retain stdout as a public report using
exclusive creation/readback in a trusted directory, with a separately retained
byte digest. A constant STOP message means no successful rehearsal report.
Unsupported tools/kernel features are a stop, not permission to fall back to
host rules, IPv4-only probing or a different UID profile.

## Rehearsal sequence

1. Record the parent's network namespace device/inode. Start a child with
   `unshare --net`; it shares the existing UID namespace, so these are actual
   numeric UIDs, not user-namespace remappings. No persistent named netns or
   host interface is created.
2. Before nft syntax checking or mutation, require root, a live unchanged
   parent namespace, a different current network namespace, and exactly one
   interface named `lo`. The guards run again before rule installation and
   local table removal. Turn up loopback only. No external link or route,
   HTTP/Provider endpoint, hostname resolution or credential is used.
3. Bind four root-owned synthetic sinks at ephemeral loopback ports:
   TCP/IPv4, TCP/IPv6, UDP/IPv4 and UDP/IPv6. Clients expect a fixed synthetic
   banner. Baseline probes succeed as all eight UIDs: **32 successes**.
4. Syntax-check and install only the fixed candidate table in the child netns.
   Fork clients through `setpriv` with the exact UID/GID, cleared supplementary
   groups, empty capability bounds and `no_new_privs`. Each child verifies its
   effective capabilities are zero and that its real/effective IDs match.
5. All five target UIDs must fail with administrative EACCES/EPERM in each of
   the four flows: **20 denials**. Timeout, missing route, connection refused,
   a missing IPv6 result or success is a stop. Join these results to all five
   numeric kernel socket-UID rule counters; each must have at least four
   rejected packets. Counter increases alone are not sufficient.
6. The three exempt UIDs must still exchange the banner in each flow:
   **12 positive controls**. These are new controlled processes under the
   same numeric UIDs, not a live GitHub GET, retained service or SSH session.
7. After rechecking isolation, delete only this test table in the disposable
   child namespace. All eight UIDs must succeed again: **32 successes**.
   This causal check distinguishes firewall denial from a failed sink, dead
   route or permanent inability to run a role process. No host table is
   flushed, restored or repaired. Namespace teardown removes its remaining
   local resources when the probe exits.
8. Verify the parent's namespace identity is unchanged and validate every
   expected role/flow, scope, limitation, counter and source hash before
   emitting a successful report. No automatic retry is performed on failure.

Source hash matching is a selected-file consistency check, not interpreter,
full dependency, host or independent-origin attestation. A malicious root can
alter the program or namespace state; the rehearsal does not defend against
root compromise. The report is not signed permission or an enrollment input.

## Report boundaries

The report retains the kernel release, four tool versions, full public phase
results and counter joins rather than a single summary boolean. It states:

- `isolated_rules_applied: true` and `isolated_table_removed: true` only for the
  child namespace; parent/child namespace identities must differ.
- `host_rules_applied: false` and `operator_host_egress_verified: false` under
  `limitations`, even if an operator VM rehearsal later succeeds.
- Reader GitHub egress, retained signer egress, DNS policy and indirect proxy
  bypass resistance remain unverified. The actual reader token is not opened.
- Native runtime/ledger binding, mTLS/receipt checks, expired context renewal,
  enrollment, Native execution and real Provider calls are not performed.
- No production bypass, paid execution or utility conclusion is issued.

The previous [VM read-only evidence](TASK4_NATIVE_OPERATOR_VM_READONLY_EVIDENCE_V1.md)
remains historical and unchanged. Its `os_rules_applied: false` must not be
rewritten after this isolated rehearsal. Host policy installation and observed
host UID denials require a separate reviewed change, with explicit reader,
retained signer, DNS, local transport, existing connections and rollback scope.

## Validation and evidence separation

The targeted suite has 61 cases. Pure tests cover fixed UID/family scope, no
commands in plan mode, root/ack checks, namespace/loopback guards, public report
confusion, capability/flow/counter substitution, administrative-denial errno
classification, missing/untrusted tools and constant errors. Synthetic report
fixtures are shape tests and are never presented as kernel observations.

A mandatory root CI case performs the actual isolated rehearsal: 20 TCP/UDP
IPv4/IPv6 denials, 12 exempt controls, successful baselines/removal controls,
actual dropped capabilities, per-UID kernel counters and unchanged parent
netns identity. All 61 cases must run with zero skips/failures in that job; its
JUnit artifact is retained. A workspace without root network capabilities
skips the actual case locally, which is not counted as proof. CI conditionally
installs nftables if missing; this provisioning is not in the operator CLI.

The root CI run uses a temporary network namespace on the runner. It does not
claim that host firewall rules were installed on the operator VM, nor that the
VM rehearsal has already occurred. No account/home provisioning is needed,
and registered operator UID numbers are not grounds to initialize their keys
or touch their storage.

## Primary references

- [nft(8), Netfilter project](https://netfilter.org/projects/nftables/manpage.html):
  `inet` covers IPv4/IPv6, output hooks filter local-process packets, and check
  mode validates commands without applying changes.
- [Socket UID matching, nftables project wiki](https://wiki.nftables.org/wiki-nftables/index.php/Matching_packet_metainformation).
- [network_namespaces(7), Linux man-pages](https://man7.org/linux/man-pages/man7/network_namespaces.7.html):
  network namespaces isolate interfaces, IPv4/IPv6 stacks, routing and firewall
  state. This isolation is not a full security boundary against privileged root.
