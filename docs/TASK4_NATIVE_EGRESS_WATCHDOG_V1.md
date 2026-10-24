# Task4 isolated egress watchdog and guarded inverse v1

A controller can die after applying a temporary firewall table. This change
adds a separate, session-detached watchdog that owns both creation and timed
removal, and tests it in fresh loopback-only network namespaces. It does not
install a firewall on the operator host or provide a host-apply command.

`REAL_PROVIDER_NO_GO / UTILITY_UNSCORED /
PRODUCTION_BYPASS_RESISTANCE_NOT_PROVEN` remains unchanged.

## Operator inventory and remaining host boundary

After #546, the operator reported that PID 1 is systemd, the inventory process
and PID 1 share the same network namespace, nft lists no tables, and systemd
reports `running`. The only process among the reviewed UIDs was the existing
service, PID 3520 with all four UID fields equal to 109. No processes were
reported for target UIDs 61103, 61105, 61106, 61107 or 61108. These observations
are operator-pasted inventory, not independent host attestation or a complete
socket/capability/actor audit. They are historical preflight data, not a lease
permitting a later host mutation.

The inventory also reports SDK agent 61101, executor 61102 and stranger 61104
as unregistered. They remain outside this five-UID rehearsal. Reader 61109,
existing signer/service 109, administrator 0 and every other UID remain outside
its deny scope. No new accounts or runtime execution permissions are created.

## Implementation

[The new module](../scripts/task4_native_egress_watchdog_v1.py) imports the frozen
#545 guard and requires its exact SHA256. It does not change that source or the
#546 static candidate files. Its distinct table is `veritas_native_watchdog_v1`;
the ownership comment adds a 128-bit trial nonce. The five numeric socket-UID
rules reject all IPv4/IPv6 output, including local IP and DNS, as in #546.
AF_UNIX, inherited other-UID sockets, proxies and privileged bypasses remain
outside this policy's coverage.

The worker starts a new session with no terminal, stdin, stdout or stderr.
Its only inherited application descriptors are readiness and result pipes.
It validates the isolated namespace and absence of its table, sets a monotonic
deadline of at most ten seconds, checks and exclusively creates the whole batch,
then reports installation. The worker itself owns the nft creation command:
there is no separate controller apply that can arrive after timed cleanup.
The deadline cannot be cancelled or extended through the pipes.

The controller can be SIGKILLed after installation. The watchdog continues in
its separate session and removes its exact table at the deadline. The root
supervisor used as the namespace guard anchor must remain alive. If that
anchor disappears, inspection fails or ownership changes, the worker stops
without deleting an unrecognized table. This fail-closed inverse deliberately
does **not** promise universal cleanup after every failure.

Before deletion, the worker requires an exact ownership comment and full table
shape: exactly one table, one filter/output chain with priority zero and policy
accept, and five ordered UID/counter/admin-prohibited rules with the expected
role comments. It rejects extra fields, objects, chains, rules or expressions.
Only numeric handles and live counter values are variable. After nft's check
operation, it inspects again and requires the same identity and all handles;
only counters may have advanced. It deletes only this table and verifies absence.
A missing table is an absent result, not evidence of a prior owned installation.

This is a bounded test primitive, not a privileged-adversary isolation boundary.
A root/CAP_NET_ADMIN actor can kill the watchdog, alter its namespace or race a
replacement between the final inspection and deletion. Two reads do not make
that check/delete sequence atomic. The trial nonce and exact shape prevent
accidental deletion of an unrelated or visibly changed table, not privileged
concurrent replacement. nft errors and unknown responses are not retried as
permission to create or replace rules.

## Validation and scope

Thirty-three tests run in the mandatory root CI job with **zero skips** required:
28 portable ownership/shape/nonce/scope checks plus five real kernel scenarios.
Each kernel scenario creates a separate namespace, preserves an unrelated
canary table and checks that the parent namespace remains unchanged:

| Scenario | Required result |
| --- | --- |
| Deadline with controller alive | Exact owned table removed |
| Controller SIGKILL after installation | Detached worker survives and removes table |
| Replacement with another trial nonce | No deletion; replacement unchanged |
| Extra rule inserted after installation | No deletion; altered table unchanged |
| Table name already present | Stop before launch; existing table unchanged |

The disposable test harness removes its own altered test tables at teardown;
that action is not counted as successful automatic rollback. Full per-scenario
public results are retained in JUnit `watchdog_rehearsal_json` properties.
Local runs without the required namespace/admin capabilities may skip the five
kernel cases; the mandatory CI gate rejects any skip, missing case or missing
proof. Earlier #545 network and #546 transaction tests remain separate gates.

Only `plan` is exposed by the module CLI. No host-apply, reboot persistence,
systemd timer or host service is installed. Before an operator-host trial,
a reviewed independent host recovery mechanism (including its failure and
ownership behavior), protected source/configuration, a fresh complete actor /
process / socket / capability inventory and an explicit bounded operator trial
remain necessary. In particular, this session-detached process is **not** proof
of systemd-managed rollback, recovery after reboot, host firewall enforcement,
reader GitHub-only confinement, signer confinement, Native execution readiness,
real Provider use or production bypass resistance.
