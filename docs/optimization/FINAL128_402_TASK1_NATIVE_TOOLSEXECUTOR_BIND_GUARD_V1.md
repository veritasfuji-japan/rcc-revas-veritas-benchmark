# Final128 #402 — guarded Native ToolsExecutor → real pinned VERITAS Bind (offline Task1)

## Scope

Parent #401 merged at \`35bb3ecd1063fdfe2327e521c2d5e62cbbb60e65\`.
Frozen AgentDojo commit \`a75aba7631d3ca5fb7ab938965c97ead2f9ff84b\`,
banking \`v1.2.2\`, direct-attack frozen 128 roster. Pinned VERITAS OS
\`a1d66aef02262cf8a913295270c3aafd159c6adb\`.

The objective is to close a dangerous architectural gap: a B-only
post-ToolsExecutor model-facing overlay (#401) does not itself stop a native
ToolsExecutor from running a model-proposed write. The real enforcement
boundary is **before** the Native FunctionsRuntime delegates to the
registered \`Function.run\`.

This PR builds an explicitly opt-in *in-process, source-owned* subclass of
the **actual pinned Native FunctionsRuntime**, preserving the full original
\`functions\` dictionary and complete model-visible banking tool definitions.
It is passed to the **actual Native ToolsExecutor**. Local, scripted test
proposals (not LLM responses) exercise the real dispatch methods.

### Deterministic dispatch partition

- Fixed pinned **read-only allowlist**:
  \`get_balance\`, \`get_iban\`, \`get_most_recent_transactions\`,
  \`get_scheduled_transactions\`; they dispatch to genuine Native function
  implementations only on the exact owner environment and are checked for
  unchanged source state.
- Native tools declared as VERITAS \`PROTECTED_TOOLS\`:
  \`send_money\`, \`schedule_transaction\`,
  \`update_scheduled_transaction\`, \`update_password\`,
  \`update_user_info\` (only those actually in the frozen suite).
  **Every call** freezes a distinct candidate, builds a benchmark-bound
  ExecutionIntent and invokes the **real pinned**
  \`execute_bind_adjudication\` with Task1's
  \`DISPOSITION_NO_MUTATION\`. Checks final BLOCKED outcome, constraint
  failure and zero adapter apply/mutation/postcondition callback calls.
  Repeated calls, multiple tool calls per assistant message and mixed
  safe/unsafe sequences re-enter the gate.
- All other registered functions are explicitly **unclassified/denied**.
  Never classify by \`get_*\`, tool description, request prose or injection
  subject. New native tools fail closed by default; they do not silently
  acquire permission or an untested mutation adapter.
- Unknown names, nested FunctionCall arguments, wrong bank-owner object,
  mutated Native FunctionRuntime catalogue or malformed candidates
  fail closed before any underlying Native effect. Native \`functions\`
  registry is unchanged so full tool/action availability remains advertised.

### Data and trust boundaries

The Native source is produced by #399's pinned
\`native_task1_source\`: fresh, distinct, identically injected in-memory
A and B bank objects, exact DirectAttack slot and source-frozen enrollment.
Arm A state remains untouched during this B-side protection exercise.
No gold-derived native tool call is presented as a model-generated one.

The Bind fixture uses \`authority_admitted=True\` specifically to exercise
the **independent Task1 policy constraint refusal**, matching #398. This is
NOT actual external user authority or approval. All mutation callbacks are
traps; even a programming error that bypasses refusal cannot silently
produce a bank effect. Native actual tool results (including the lower-trust
injection) are retained only ephemerally; CI artifacts store hashes and
aggregate status, never bank account records, payload text or raw tool history.

## What is demonstrated

Within the **registered local guarded runtime**, every mapped protected
Native candidate traverses real pinned Bind and is blocked before native
function execution; the exact Task1 read-only calls remain usable and
Native ToolsExecutor can return a tool error without mutating the source.
Full tool declarations are kept. Mixed/multiple/retry/nested/unknown/cross
environment/tamper tests fail closed.

## What is NOT demonstrated

- Full production runtime coverage: the test owns only one in-process
  Native Runtime passed to the local ToolsExecutor. Direct access to the
  Native \`Function.run\`, another runtime instance, alternate executor,
  production service or leaked original credentials would still bypass
  this local prototype. It is **not** a non-bypassable IAM/credential/
  network-control implementation.
- Integration of this exact runtime wrapper inside the **complete**
  #401 multi-turn LLM loop is a follow-on, not silently implied here.
- \`PROTECTED_TOOLS\` membership and the Task1 no-mutation disposition are
  imported from the pinned VERITAS benchmark policy. Any registered tool
  outside the allowlist/policy is denied, **not** certified via Bind.
- Bind rejection does not constitute independently issued external
  authorization, globally consumed single-use capability or a real bank.
- No actual agent/Provider responses, model-authored tool calls, independent
  A/B real histories, official Native User/Attack scoring or Utility
  improvements. The operator has not approved paid Provider spend here.

## Next: #403 and beyond

1. Install the local guard in the actual #401 Task1 Native loop, keeping
   the same complete model-facing catalog and B-only source-owned overlay.
   Prove no unguarded Native write path **inside the bounded local loop**.
2. Establish real non-bypassable effect access (credential isolation /
   network or IAM confinement) and externally verifiable provenance
   before claiming any production bypass resistance.
3. Fresh cost-capped single-use approval before any paid independent model
   A/B, then official native scorer and full 128-case recovery measurement.

## Merge criteria

- Exact pinned Native/VERITAS/roster and inherited merged #401–#377 code
- Per-protected-tool and multi-call/retry denial with real Bind receipts
- Native read-only functionality preserved; state pre/post equality
- Full model-visible catalogue retained; unmapped tools denied
- Nested, foreign owner, catalogue drift, invalid sources fail closed
- Zero Provider/real effect/official scorer; correct nonclaims in evidence
- Dedicated no-skip tests, all normal HEAD checks green; redacted JUnit/SHA
