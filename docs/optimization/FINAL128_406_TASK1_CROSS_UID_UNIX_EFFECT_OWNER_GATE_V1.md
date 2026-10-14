# Final128 #406 — distinct Linux OS identity, DAC and peer-credential Native Task1 guard

## Objective

#405 proved that a new child process keeps a separate in-memory Native bank
object from its parent. However it used **the same OS UID** and therefore
did **not** prove the parent could not open the child's private files or use
that UID's privileges.

#406 introduces three distinct **actual Linux UIDs** in a dedicated Ubuntu
GitHub Actions job: \`veritas406owner\`, \`veritas406agent\` and
\`veritas406stranger\`. A fourth UID, the GitHub runner, drives the test.
Only the owner process loads the original frozen Native AgentDojo Task1
environment. The agent process makes strict JSON requests through a UNIX
domain socket; \`SO_PEERCRED\` enforces the *kernel-observed* client UID.
An unrelated group member ("stranger") is rejected even though it has
filesystem permission to connect to the socket.

## Mechanism and observations

- The owner runs as a **different unprivileged OS UID** and holds a dedicated
  private directory (\`0700\`) containing a **fake offline-only** marker file
  (\`0600\`). The agent's direct file-open attempt must receive OS
  \`PermissionError\`; an absent file is **not** accepted as proof.
  The runner UID independently cannot read that file.
- The socket is \`0660\` in a directory owned by the effect owner with mode
  \`2770\`. Agent, stranger and owner share an IPC group. Filesystem DAC
  allows that group to connect, but **peer UID validation** is an independent
  second boundary: only the exact predesignated agent UID can dispatch to
  Native code.
- The owner directly calls #405's strict JSON decoder, Native Task1 source
  loader and #402's guarded VERITAS \`FunctionsRuntime\`.
  Read-only Native calls remain available.
  All protected Native functions use **actual pinned**
  \`execute_bind_adjudication\`, which BLOCKS Task1 mutations before Native
  effect dispatch. Repeated writes and forged admin JSON are refused, and
  the worker's real Native bank state stays unchanged.
- The agent cannot signal/check the owner PID using \`kill(pid, 0)\` under
  the tested Linux default permission rules; the owner process remains alive.
- The untrusted caller is never given raw bank transactions, attack strings,
  test marker bytes or direct references to the authoritative bank object.
  Evidence emits hashes, counters and precise scope-qualified claims only.

## Exact source chain and reuse

Parent #405 merged at \`fb892c81f2b81dce790c1352fb43d0ac6f950b3f\`.
Original AgentDojo:
\`a75aba7631d3ca5fb7ab938965c97ead2f9ff84b\`,
banking \`v1.2.2\`. VERITAS OS:
\`a1d66aef02262cf8a913295270c3aafd159c6adb\`.
Unchanged pinned direct attack and canonical 128-case enrollment,
single instance of
\`banking:user_task_1:injection_task_2:direct\`.
All inherited #405–#377 tests remain in the dedicated workflow.

## IMPORTANT: no production-bypass-resistance claim

The marker is deliberately **not a real credential**. The OS permissions
apply to a **locally fabricated file** and child process state, not to
an external effect backend or an actual transaction endpoint. No
credential/IAM/egress policy restricts the broader host's actual banking
capabilities, because none are deployed here.

The dedicated job uses \`sudo\` **only to create the temporary test UIDs and
permissions**. A root process or a UID with \`CAP_DAC_OVERRIDE\`,
\`CAP_SYS_PTRACE\`, sudo capabilities or access to an external backend
can still evade the local test boundaries. No container, namespace,
LSM/seccomp, privileged-hostile actor, alternate real effect service,
production IAM control or independently enforced single-use permit is
proven. The enrolled Task1 is **read-only**, so this test deliberately
shows no authorized effectful production operation.

The agent and stranger share an IPC filesystem group; peer UID rejection
is verified even when a group member can connect. This is *local Unix
identity enforcement*, not authenticated cross-network authorization.

Neither the official AgentDojo UserTask/InjectionTask scorer nor a real
Provider/LLM A/B model was invoked. No new cost authorization was used.
All official Utility and attack-success metrics remain unmeasured.

## Next required proof beyond #406

1. Move effect credentials to a real isolated executor principal with no
   alternate service path to the effect system, and enforce IAM/egress in the
   *backend*, not just via a process wrapper.
2. Demonstrate that another process/identity cannot execute an effect even
   when it constructs a correctly formatted request, imports the Native
   callable, or replays an issued decision.
3. Verify one genuinely authorized, bounded **simulated external effect**
   succeeds through a single-use Bind grant while all other principals
   and replayed capabilities fail at the backend.
4. Reconcile issuance, effect credential use, state mutation and terminal
   evidence via independently verifiable event receipts.
5. Only after fresh explicit approval of bounded paid model spend, produce
   true independent AgentDojo A/B histories and official scoring.

## Merge criteria

- Three distinct non-root Linux UIDs and source-owned test configuration.
- Native/VERITAS SHA-pinned, frozen 128-case roster unmodified.
- \`0700\` owner directory, \`0600\` offline marker, \`0660\` socket in
  setgid directory, kernel \`SO_PEERCRED\` enforced.
- Real OS denial of agent and runner private-file reads and agent signal,
  plus different group member's denied Native request.
- Agent safe reads work; protected calls are actual Bind BLOCKED before
  dispatch, including repeated/forged requests.
- Owner bank original/final hashes equal; no real effect/API/scorer or
  credential contents disclosed.
- No production IAM or global bypass-proof promotion. Dedicated zero-skip
  and inherited CI all green on one exact PR HEAD.
