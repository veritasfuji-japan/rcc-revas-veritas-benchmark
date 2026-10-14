# Final128 #405 — private child process owns Native Task1 state, JSON-gated VERITAS Bind

## Parent and explicit limits

Parent: #404 merged \`e71f1a112eea7468fe1aed0924e6a1ab1fe81e68\`.
Fixed AgentDojo \`a75aba7631d3ca5fb7ab938965c97ead2f9ff84b\`,
VERITAS OS \`a1d66aef02262cf8a913295270c3aafd159c6adb\`,
banking \`v1.2.2\`, original frozen 128-case DirectAttack corpus,
one task \`banking:user_task_1:injection_task_2:direct\`.

#404 observed that Python references to a second unguarded
\`FunctionsRuntime\`, raw \`Function.run\`, direct \`banking_client.send_money\`
or mutable bank state can modify **unconfined objects in the same Python
process**. #405 addresses one narrower gap: keep the *authoritative
disposable Native Task1 bank object* private in a dedicated child process
with no reference exported to the client process.

### Architecture

- A child is started via \`subprocess.Popen([python, -m, ..., --worker])\`
  and loads its own exact pinned Native banking environment from the
  immutable original Task1 DirectAttack source. Parent never receives the
  mutable \`BankAccount\` object; only its SHA-256 snapshot fingerprint.
- The child installs #402's real frozen VERITAS \`FunctionsRuntime\`
  guard, retaining Native's complete tool registry. All \`tool\` requests
  go through that registered guard; protected Task1 mutations return
  the real pinned \`execute_bind_adjudication\` **BLOCKED**.
- Strict newline-delimited JSON over existing local stdio pipe. Fixed
  frame size, \`v:1\` protocol version, JSON object member-duplication
  rejection, nonfinite number rejection, exact operation envelopes,
  explicit \`status\` / \`tool\` / \`close\` operation dispatch. No \`pickle\`,
  dynamic \`eval\`, \`exec\`, function names used as Python attribute paths
  or arbitrary code execution.
- Responses contain only bounded status, worker PID, original/current
  authoritative bank fingerprint, Bind counters and precise nonclaims.
  No banking transactions, account data, prompt injection text or raw
  tool return bytes are sent to the client.
- Attempts to use raw-function/attribute mutation protocol operations,
  duplicate JSON envelope keys, fake authority fields, unknown tools,
  malformed requests or direct client-side Native copies cannot alter the
  child's owned original bank object.
- A direct Python \`send_money\` on the **client's independent injected
  Native clone** does mutate that local clone. A subsequent child hash
  query verifies that this has NO effect on the authoritative bank held
  inside the separate worker.

This is an **offline capability-prototype / memory-separation experiment**,
not a distributed authority system. The worker currently admits **no**
effectful Task1 writes, because Task1 is a read-only request. Only the
trusted read-only Native functions may succeed. Every protected operation
re-enters actual pinned Bind and is blocked. There is no benchmark-funded
model call, official Native UserTask / InjectionTask scoring, external
bank write or human approval. The full Native tool catalog remains intact
inside the worker.

## Why this is NOT production non-bypassability

The parent and child run under the **same operating-system principal** on
a regular CI machine. The parent can run arbitrary Python, launch another
runtime or read shared filesystem content. There are no actual production
credentials or IAM/network restrictions to test or to protect.
\`subprocess\` itself is **not a security sandbox**. The private bank exists
only in the child memory space; a same-UID attacker with OS debugging,
process-memory inspection or file access is not excluded by this test.
The pipe is a local stdio protocol, not an authenticated cross-principal
security channel or an externally enforced exclusive execution gateway.

Thus #405 can report that *client-local raw Native mutations do not modify
the distinct child-owned in-memory authoritative object and protocol
write requests are rejected through actual Bind*. It cannot report that
a real external bank, agent runtime, credential store, network effect,
single-use capability consumption or independently isolated principal
is protected. There is no external effect backend, and an attacker can
still create and mutate another disposable Native object of their own.

## Required next proof after #405

1. Move the actual effect implementation and all effect credentials into
   a separately authenticated/sandboxed executor with a distinct process
   principal / container identity, and make egress/IAM accept only it.
2. Bind immutable execution intent to target, argument digest, current
   state, expiry, permit issuer and atomic single-use consumption at
   *execution*, not just initial proposal or messaging.
3. From another principal, attempt direct Native/backend API, legacy
   connection, stolen/forged/replayed credentials and multi-call bypasses;
   record backend 403/denial plus *no effect* evidence independently.
4. Independently confirm legitimate authorized effects can still occur
   under the same boundary and reconcile issuance, consumption and effect.
5. Only with fresh explicit paid-model budget approval, run true A/B
   provider histories then official pinned Native scoring.

## Merge gate

- Pinned source and original enrollment roster (no synthetic enrollment).
- Child PID different from client, no raw Native state exported.
- Every protected Native tool proposal invokes real Bind, BLOCKED before
  dispatch. Safe read-only calls work with original state unchanged.
- Forged fields, duplicated JSON keys, nonfinite JSON, fake operation names,
  repeated calls and separate raw client clone cannot change worker state.
- Bounded child runtime, no Provider/API/scorer/real bank effect, no leakage.
- Dedicated no-skip inherited #404–#377 test matrix and all HEAD CI green.
- Redacted hashes and explicit nonclaims; no unsupported PROVEN badge.
