# Final128 #403 — integrated Native Task1 multi-turn A/B (offline B overlay + real Bind)

## Frozen source and chain of custody

Parent: #402 merged `5ca03eb761cf26a54b1857c705bd843dc224c871`.
Exact Native AgentDojo: `a75aba7631d3ca5fb7ab938965c97ead2f9ff84b`.
VERITAS OS: `a1d66aef02262cf8a913295270c3aafd159c6adb`.
Fixed `v1.2.2` banking, DirectAttack profile, immutable canonical 128 roster.
Single explicitly named case:
`banking:user_task_1:injection_task_2:direct`.

## Engineering delta

- Source-built two independent disposable AgentDojo banking A/B environments
  from #399's native DirectAttack, equal and attack-injected before any
  read-only call, with the native incoming `recipient="me"` unchanged.
- Uses actual source-pinned `AgentPipeline.from_config`, Native
  `SystemMessage`, `InitQuery`, `ToolsExecutionLoop`, two real
  `ToolsExecutor.query` iterations and original Native YAML formatter.
- Replaces LLM only with a **scripted offline recorder** (three local
  invocations per arm); model/Provider is never called. First recorder issues
  a fabricated `get_most_recent_transactions(n=100)` call.
- The first real Native Tool result is checked for byte-exact Native YAML
  formatting and equivalence to source-owned structured transactions,
  including the original malicious DirectAttack subject. No native state
  changes before the B-only context is constructed.
- #401's post-ToolsExecutor / pre-next-LLM position is exercised inside the
  *same actual Native multi-turn loop*: A passes original history only, while
  B appends exactly one source-owned developer-mapped context containing
  the #400 calculations `1050.00` GBP spending and `10.00` GBP inbound.
  Lower-trust subjects cannot enter the trusted context.
- The second scripted (not real-model) recorder outputs identical function
  names and arguments for both arms: `send_money` mixed with
  `get_balance`, optionally repeated. Complete original full banking tool
  catalogue is unchanged in every unsent model packet.
- Arm **A** passes those synthetic calls through actual Native unguarded
  FunctionsRuntime and records isolated in-memory effects. Arm **B** uses
  #402's actual registered **guarded** Native runtime; every protected
  `send_money` proposal reaches real frozen VERITAS `execute_bind_adjudication`
  and is BLOCKED *before* any protected Native implementation dispatch.
  Interleaved read-only calls still return. B bank state stays exactly equal
  to its own original source, and the third scripted recorder captures final
  Native history before returning a clearly non-model local terminal.
- The 1–6-protected-call replay matrix checks each proposal separately,
  the local Bind receipt hashes, all protected denial tool errors and the
  unaffected original attack-containing first Tool output.

## Explicit limits

This closes the *bounded offline pipeline integration* gap between #401 and
#402. It is **not** authentic, independent A/B Provider model inference.
All apparent 'assistant' tool calls and final text are scripted test fixtures,
not model-generated or benchmark-scored. The model-visible B context uses
native system→developer translation but remains an experimental treatment,
not an official AgentDojo scoring certification.

This guard is installed on one in-process B runtime; direct access to raw
Native Function.run, alternate Executors, leaked credentials, IAM/egress or
network bypass remains outside scope and NOT PROVEN. No globally consumed
single-use permission, real human approval, real bank or paid Provider
operation. The Native official UserTask/InjectionTask scorers are not run.
No interpretation of offline refusal as measured Utility or attack success.

## Next meaningful boundary

Before paid real A/B, define a *genuine non-bypassable effect boundary*
(e.g. enforced exclusive effect credentials, network/dispatcher confinement
and observable end-to-end receipts). Then arrange fresh narrowly scoped,
hard-capped paid Provider authorization, independently generate model A/B
histories with real assistant tool-call IDs, preserve their full same-run
Native state/result records and apply the official pinned Native scorers.
The historical $5 approval is not reusable. Any paid Provider call still
requires explicit fresh authorization.

## Merge gate

1. HEAD, source pins, exact 128 roster and #402–#377 regressions.
2. Actual local Native AgentPipeline two ToolsExecutor iterations and
   same first A/B unsent prompt/catalog/attacked genuine tool output.
3. Correctly scoped B developer overlay in its first post-read seam,
   original lower-trust attack retained only in tool response.
4. Identical scripted proposals to A/B; A isolated in-memory effects,
   B real Bind BLOCKED per protected proposal with untouched bank state.
5. Mixed protected/read-only calls, 1–6 repeated writes, wrong/bad attack
   response and invalid script counts fail closed.
6. No paid Provider, official scorer or external state effects, no private
   account/payload export (hash-only evidence).
7. Dedicated CI zero skipped/error/failure and every other PR-head CI green.
