# Task4 #376 — Synthetic front-agent HTTP ingress → exact Native-v2 TLS effect

## Engineering objective

Upgrade #375's broker-initiated controlled operation to an actual
**unprivileged front-only Docker agent → broker HTTP POST → Native-v2
authorization/consumption/dispatch/reconciliation** on the **same**
upstream pinned sandbox target, https://sandbox.example.invalid/v1/events.

This is a controlled engineering test, **not** a general-purpose agent API,
not arbitrary semantic authorization, and not production proof.

## Real execution path

1. Reuse #375's two non-attachable Docker internal front/back bridges,
   nonroot broker, back-only PostgreSQL, actual pinned upstream TLS sandbox,
   no host ports and no Docker socket in probe containers.
2. Start an actual stdlib HTTPServer inside the broker listening on
   port 8080 (no host publication). The API accepts POST /v1/agent/actions
   with bounded JSON and one exactly matched hardcoded synthetic test
   candidate. It does **not** trust agent-supplied authority or approval.
3. Launch a separate no-credentials, front-only nonroot agent and have it
   send six mutated requests, malformed JSON and wrong content type.
   All eight get 403, 400 or 415 **before native issuance/effect**.
4. The same agent sends the exact test fixture once. The broker validates
   it, writes a locally durable O_EXCL admission marker (never reopens on
   failure), and passes the **actual admitted request** as a broker-owned
   file into the pinned Native-v2 runner.
5. The native runner **independently revalidates** the admitted agent
   bytes; it constructs its CandidateAction from that input rather than
   fabricating an unrelated replacement. Upstream controlled fixture issuer,
   real Native-v2 verification, atomic Postgres single-use consumption,
   bound permit, one TLS POST, actual sandbox record, independently read-only
   reconciliation, Bind/Outcome receipts and #374's seven exact invariants
   remain mandatory.
6. The broker responds 200 COMMITTED only after the full verified trace.
   The same agent sends the exact request again and gets 409 with
   no second launch. The front agent cannot directly reach the real sink IP,
   and a host-attached back rogue still gets 401 without test writer token.
   The previous 25/25 checks must remain green.

## Trust boundary (important)

- **The untrusted HTTP request is not authorization.** Matching this
  fixture is a tightly scoped test admission filter. Native-v2
  source-pinned issuer verification and consumption remain separate
  controls. The internally trusted original request and issuer are synthetic,
  **not authenticated real human intent**. Anyone who knows the fixed
  fixture and reaches the broker might race the intended agent; the test
  does not establish real caller identity or prevent that attack.
- The O_EXCL marker prevents a second HTTP admission within this shared
  Docker volume; it is **not** a distributed production ledger or
  independent persistent protection. Postgres Native-v2 consumption is
  separately tested.
- The broker uses the same fixed upstream test target and credential as
  #374/#375; it does not upgrade the distinct #370/#371 sink or #373's
  LABA-v1 fixture to native authority.
- The Docker host/daemon and sandbox operator are trusted. Host-root,
  secret theft, container escape, forged operator input, external workload
  identity, cloud IAM/VPC, third-party validation and enterprise
  consequences are outside this proof.
- This deterministic single-process test listener is **not** a hardened
  production API: no rate limiting, mutual TLS, durable external
  identity authentication or disaster-recovery guarantees.
- Provider calls 0, real bank effects 0, billed spend 0. This experiment
  neither issues model requests nor changes Utility or native AgentDojo
  scorer results. No historical paid consent is reused.
- Failures or uncertain reconciliation burn the admission marker and
  are never retried. An HTTP ACK is not evidence of confirmed effect;
  target-owned read-only reconciliation is mandatory.

## Evidence and merge conditions

The dedicated CI must produce all of the following at the exact PR HEAD:

- task4-376-agent-http-evidence.json: ten real agent HTTP cases (eight
  pre-execution denials, one commit, one replay denial).
- task4-376-broker-receipt.json: receipt whose request, candidate and
  Native-v2 trace hashes equal the admitted bytes and native runtime report.
- native-v2-authorized-lineage.json: actual native runtime report initiated
  by HTTP, not an independent host-launched fixture.
- task4-375-native-v2-docker-network-evidence.json and
  task4-375-junit.xml: all **25** old network and Native-v2 checks.
- task4-376-native-v2-agent-http-ingress-evidence.json and
  task4-376-junit.xml: all **18** new predicates true.
- Exact repository HEAD, pinned VERITAS/BEN SHAs, safe source hashes,
  workflow artifact digest, no secret/private key uploads.

Mark Ready and merge only after dedicated + entire PR CI success, with
independent review of emitted ZIP/JUnit/trace. CI green never means production proven.

## Next after this proof

Return optimization to Ben's single objective: **Arm B injection success
0 with genuine independently scored A/B Utility >= paired Arm A**,
preserving original request→candidate→CDA→Bind→effect/denial→terminal
scorer continuity. Frozen V13 was A 93/128, B 64/128; #376 is **not**
a Utility recovery and cannot count as one.
