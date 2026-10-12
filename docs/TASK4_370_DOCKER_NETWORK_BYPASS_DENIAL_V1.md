# Task4 #370 — Docker dual-network direct-bypass refusal (offline)

## Frozen topology

- Trusted CI host builds one pinned Python 3.11.16-slim image and creates two
  **distinct Docker bridge networks with `--internal`**. Docker host alone
  owns network membership and image/container control.
- Untrusted `agent` joins only the front network and has **no Docker socket,
  broker/sink private secret, live API key or backend network attachment**.
  All containers use UID:GID 65534:65534, read-only rootfs, drop ALL capabilities,
  `no-new-privileges`, no published ports and bounded resources.
- Trusted `broker` joins front **and** back networks. Back-only
  `mock-effect` sink is reachable over TCP 8081 from the broker, not from
  an agent on the front network. Broker front TCP 8080 remains reachable.
- An isolated disposable `rogue-back` probe is **deliberately placed by the
  trusted host** on the back network to show the sink's separately mounted
  synthetic HMAC credential rejects an unauthenticated direct operation.
  This is defense-in-depth; it does not claim that an ordinary worker can
  attach itself to the back network.

## Real observed tests (no Provider or real bank)

1. Trusted host signs two synthetic grants bound to `Task4` case, arm A/B,
   exact operation ID, effect type and constant synthetic amount.
2. Two legitimate workers send their signed grants to the broker; broker
   atomically INSERTs one-use SQLite `CONSUMED_UNKNOWN` **before** sending
   each operation to the sink. Sink verifies a **separately mounted test-only
   private key**, records two mock entries durably and returns receipts.
3. Broker turns only those two consumed entries into `LOCAL_MOCK_OBSERVED`,
   keeping sink receipt and request hashes for correlation.
4. A replayed arm A grant receives 409 (the unique consumption key cannot
   be spent twice). Modified or unsigned grants receive 403.
5. The untrusted agent probes the **actual sink container IP** on TCP 8081:
   connection fails. Effect DNS alias is absent from front network. Broker
   independently demonstrates successful TCP to the very same sink.
6. The agent's TCP attempt toward TEST-NET IP 192.0.2.1:443 fails on its
   internal Docker network.
7. A host-injected `rogue-back` container reaches the sink network but
   receives 403 without the mounted HMAC credential.

Each test creates fresh network/container names; inspect snapshots assert
exact membership, mounts, no privilege and no host published ports.
The CI archives 19 assertions (JUnit), container evidence, broker SQLite rows,
mock effect events and source SHA-256 checks.

## Strict proof boundary

- This is **real Docker bridge network isolation** in a bounded, trusted
  GitHub runner against an unprivileged container, not just a Python patch.
- The sink is synthetic. This PR does **not** execute an external banking
  operation or Provider inference; actual spend and real bank effects are 0.
- The **host / Docker daemon operator remains trusted** and can reattach
  networks, mount the private key or alter images. A process with Docker
  socket access can bypass this demonstration.
- CI Docker networking is not equivalent to production IAM, cloud service
  identities, cloud egress policies, a globally enforced execution gateway,
  external audit or third-party-validated real operating effects.
- Broker grants are **trusted-host fixture HMACs**, not live user approvals.
  SQLite is confined to this one broker, not a distributed authorization
  service; failure after sink execution may leave an UNKNOWN attempt.
- No real API authorization is created or inferred by this PR. Historical
  Provider permissions are not reused.

## Next proof

A production-bound integration must place VERITAS authorization, credential
issuance, network egress and effect reconciliation into externally enforced
boundaries, then test rogue processes with credentials/network access denied
independently of application code. Real Provider A/B evaluation remains gated
by a **fresh explicit cost/secret/run approval**.
