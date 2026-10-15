# Final128 #412 — Linux network namespace, real TCP/mTLS and gateway-only mock effect

## Frozen baseline and explicit scope

Parent #411 merged \`baecab5dc733d6e2a3451e896df6dfc543bcd704\`.
Frozen AgentDojo banking v1.2.2 \`a75aba7631d3ca5fb7ab938965c97ead2f9ff84b\`,
VERITAS \`a1d66aef02262cf8a913295270c3aafd159c6adb\`,
Task1 DirectAttack and 128-case original enrollment unchanged.
CI retains #411–#377 dedicated regressions (signed Ed25519 issuer,
rotation, revocation, freshness fail-closed, original Native Task1
NO_MUTATION, cross-UID DAC, SQLite crash/restart and concurrency).

This is a **real isolated Linux network namespace on ONE GitHub Actions
Ubuntu test VM**, not a separate cloud server, remote enterprise network,
third-party effect provider, production IAM or real banking service.
The sole positive effect is a source-owned disposable mock counter.

## Actual Linux network and transport enforcement

The trusted test runner creates a distinct **kernel network namespace**
\`veritas412\`, with a physical veth pair for simulated cross-boundary
TCP traffic:
- Host/gateway side: \`10.242.41.1/30\`, interface \`veth412h\`
- Sink namespace: \`10.242.41.2/30\`, interface \`veth412n\`
- TCP service: \`10.242.41.2:18412\`

The source-owned mock effect sink runs **inside the namespace** as the
existing separate unprivileged Linux backend UID and owns its SQLite
database under a \`0700\` directory. The actual Linux netns inode is
asserted different from the host's inode and recorded redacted.

The runner installs a real kernel **iptables OUTPUT UID-owner rule** that
refuses TCP egress to the sink service for ALL host UIDs except the
exact gateway UID. Agent direct TCP connect is proven refused. An
unrelated OS UID also cannot call the gateway's group-accessible UNIX
socket because its \`SO_PEERCRED\` UID mismatches.

This is a host-specific Linux rule installed by **trusted sudo/root** in
a CI sandbox. A hostile root/NET_ADMIN could change iptables, bridge
routes, identities or certificates; such attacks are out of scope.

## Mutual TLS credential confinement

A fresh **ephemeral test CA**, sink server certificate and authorized
gateway client certificate are generated in the trusted supervisor
process. The test CA private key is never written to an artifact or
persistent repository. **Only public CA bytes** are placed under a
root-owned readable directory.

The backend's TLS server private key is backend-UID-only \`0700/0600\`;
gateway client certificate/private key are gateway-UID-only
\`0700/0600\`, with real cross-UID file-read refusals checked.
Mutual TLS requires the gateway's CA-authenticated client certificate,
matching the exact authorized subject CN, and checks the backend SNI
\`sink.veritas412.test\`. A *gateway UID without the client certificate*
is independently refused at the TCP/TLS effect service. There is no
plaintext or unsigned fallback.

The gateway itself never exposes this TLS private key to the agent; it
accepts exactly one source-owned versioned mock request through a Unix
socket, verified against actual kernel \`SO_PEERCRED\`.

## Signed-authority and Bind continuity

#412's transport-positive request is a **source-owned fake fixture**,
NOT a third-party signed business grant. The distinct-issuer Ed25519
revocation, rotation and freshness safety of #410–#411 are **regression
tested**, rather than falsely claimed as integrated into #412's
separate mTLS network backend.

The local gateway still calls the actual pinned VERITAS
\`execute_bind_adjudication\` and uses a \`ReferenceBindAdapter\` whose
\`apply\` crosses the real Linux netns over TCP/mTLS. The backend rechecks
the exact target, grant, integer units, revision and single-use state
INSIDE a SQLite \`BEGIN IMMEDIATE\` transaction. Positive evidence
requires actual Bind \`COMMITTED\` and exactly one target-owned
counter increment, matching independent Bind/backend receipt SHA and
poststate digest.

Invalid target, grant, amount, expected revision, extra admin fields and
replay fail. Even the admitted gateway's direct TCP/mTLS replay **after
backend restart** is refused by the backend's persisted consumed record.

Original Native Task1 \`send_money\` remains protected by actual pinned
VERITAS Bind and must return BLOCKED with unchanged source bank state.

## Strict nonclaims

No separate remote host, production credential vault, cloud IAM role,
organizational third-party issuer or human approval, real bank account,
remote network control plane, real AgentDojo Official Native Utility/
Injection scorer, independent Provider A/B history or paid model call.
The CA and rule are created by **trusted test-runner sudo**, not a
production trust authority. A real enterprise attacker may have
additional routes, stolen credentials, permitted APIs or privileged
access not exercised here. A green CI **does not** constitute production
non-bypassability PROVEN.

## Exact merge criteria

- Same AgentDojo/VERITAS pins and original immutable banking roster.
- Real kernel Linux netns with veth TCP, different network namespace
  inode, strict UID-owner iptables egress deny for the agent.
- Backend/Gateway private TLS key 0600 inside separate 0700 owner
  directories, actual OS read refusal for other users.
- mTLS client authentication: gateway UID **without a certificate**
  cannot call effect sink; authorized gateway cert succeeds.
- One real pinned VERITAS Bind COMMITTED through mTLS to sink; one
  backend-owned SQLite transaction and exact receipt reconciliation.
- Denied bypass/forgery/replay/extra fields including direct authorized
  gateway replay after backend restart.
- Original Native Task1 no-write policy preserved; #411–#377 tests all
  rerun with zero skips, no real provider/bank/scorer.
- Redacted hashes only, exact HEAD SHA, all CI green.

## Next after #412

Test across **two independently administered actual hosts/cloud
accounts** with service-network IAM/policy and a genuine
external backend credential held only by the executor, then perform
independent adversarial bypass review with real endpoint audit evidence.
Only proceed to paid model/provider experiments on a *fresh*
user-approved bounded budget.
