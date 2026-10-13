# Task4 #375 — Native-v2 Docker network bypass denial with **same** TLS effect target

## New evidence, not replayed #370/#371 fixtures

This isolated GitHub-hosted proof boots the actual VERITAS OS **Native-v2**
sandbox service from pin `9b7376ba0077365b9d89004b06c80e76c8bfadc8`,
uses the existing pinned BEN Native-v2 runner from #374, and tests actual
Docker kernel bridge separation around **the same exact service endpoint**:
`https://sandbox.example.invalid/v1/events`.

- Trusted CI creates two distinct `docker network create --internal`
  bridge networks: `front` and `back`.
- A nonroot, read-only **broker** joins both networks and alone has the
  synthetic issuer/risk fixture, dedicated PostgreSQL URL, reviewed TLS
  CA and synthetic writer credential. It runs the existing
  `native_v2_action_capability.py` on pinned code, including signed
  Native-v2 authorization, PostgreSQL atomic consumption, single-send
  `SandboxHTTPSTransport`, target-owned persistence, independent read-only
  reconciliation and matching Bind/Outcome receipts verified under #374.
- A dedicated PostgreSQL service and an independently configured actual
  `run_native_v2_sandbox_service.py` TLS backend join **back only**. Both
  are private; no host port published.
- A nonroot **untrusted agent** joins **front only**. It gets no writer or
  reader token, database URL, source tree, signer, CA/private TLS key, Docker
  socket or destination bridge membership. It cannot resolve the sink by
  Docker network DNS or reach the actual sink IP TCP 443. It also cannot
  open a TCP connection to TEST-NET IP 192.0.2.1 over its internal bridge.
  The agent can resolve the front-side broker identity but cannot attach
  itself to another Docker network.
- An **independently host-created rogue-back probe** is deliberately put
  on the sink network to show the separate *credential* boundary: using
  the real pinned TLS cert and SNI, it reaches the actual sandbox service
  but receives HTTP **401** for an unauthenticated write. This is not a
  claim that an ordinary agent can join the back network.

The broker's positive TLS control also uses verified CA+SNI against this
actual sandbox. The **same signed Native-v2 action target** is then used
by the broker to perform one synthetic event. Evidence includes the #374
strict full lineage: signed authorization and execution intent hash,
PostgreSQL consumed authorization, immutable single-send dispatch,
actual sandbox target-owned record, read-only independently retrieved
reconciliation proof and Bind/Outcome receipts. Real #374 replay-after-
consumption and signed target substitution remain denied.

## Reproducibility and pins

- `veritas_os` pin:
  `9b7376ba0077365b9d89004b06c80e76c8bfadc8`
- BEN canonical pin:
  `1d3782d3aae5ff9c88036709c1a5642320cc53c2`
- Both are checked out independently, exact Git commit confirmed, and
  key upstream source files hashed.
- The Docker runtime dependencies are installed only at trusted image
  build time, not from the runtime --internal network. Python base image
  uses a fixed SHA-256 OCI manifest. PostgreSQL `postgres:16` is resolved
  by the host, and the resulting exact image ID is recorded as evidence.
- All scoped results include Docker inspect summaries of network membership,
  user, capabilities, read-only roots, mounts and no published host ports,
  plus attacker output, a nonsecret positive runtime report, JUnit and
  source hashes. Never archive TLS signing keys, private test server key,
  writer or reader credentials, full container environment or Docker socket.

## Critical boundaries and limitations

1. **Not a real enterprise deployment.** The owner of the CI host and Docker
   daemon can change networks, inject credentials, or forge test results;
   it is explicitly trusted. No third-party independent validation.
2. The Native-v2 target is an actual networked **synthetic sandbox**, not
   real banking, payments or production application control. The target
   record is an independent read-only observation by a service owned by
   the **same local operator**, not a bank consequence statement.
3. The positive broker **initiates a pinned synthetic controlled candidate**;
   the front agent in this experiment is an adversarial network probe,
   **not an API client submitting arbitrary candidate actions to a
   decision-enforcing broker listener**. No unverified candidate is promoted
   to authority or effect here.
4. A running agent with Docker daemon/admin privileges or legitimately
   distributed writer credentials is outside this proof. Production IAM,
   VPC/firewall/cloud workload identity, host compromise, bridge escapes,
   and secret/credential lifecycle policies remain unvalidated.
5. `sandbox.example.invalid` is the Native-v2 TLS target from #374, **not**
   #370/#371's `http://mock-effect:8081/mock-effect`. Valid LABA-v1
   billing fixture authorization from #373 does not permit this action;
   this uses actual independent Native-v2 target-bound authorization.
6. No real Provider/model API, billed token, banking effect or authorized
   spend occurs. Historical API authorizations are not reused.
7. Existing intermittent `CONTROLLED_ACTION_ACK_MISSING` in the host
   compatibility workflow is not suppressed. Any ambiguity fails
   closed; an HTTP ACK alone is not consequence confirmation.

## Merge gate

Accept only if all of these hold on the **exact PR HEAD**:

- Genuine Native-v2 action runner executes successfully **inside the
  network-separated broker container**, not just on the CI host.
- Same exact target endpoint + signed Native-v2 issuer hash + Postgres
  consumption + one dispatch + target-owned record + independent
  reconciliation + Bind/Outcome Receipt pass #374's strict verifier.
- The front agent's real backend-IP and TEST-NET socket probes fail,
  its DNS does not resolve the sink, and the backend rogue reaches the
  TLS service but gets HTTP 401 without writer token.
- The dedicated Docker CI records 25 positive/negative invariant
  assertions, JUnit and evidence, and all existing GitHub checks succeed.

The next proof must couple an untrusted agent's request **through an
actual broker ingress API**, with externally enforced real workload
identity and network egress. Do not label local CI as production PROVEN.
