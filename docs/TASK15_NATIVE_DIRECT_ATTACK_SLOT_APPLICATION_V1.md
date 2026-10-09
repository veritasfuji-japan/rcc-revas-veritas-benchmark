# TASK15_NATIVE_DIRECT_ATTACK_SLOT_APPLICATION_V1

**Status: IMPLEMENTED / NOT PROVEN** until exact-HEAD CI and Artifact inspection.

## Single invariant

For all eight canonical Task15 cases in the frozen AgentDojo banking
v1.2.2 / direct profile, only the slots independently discovered by the
actual pinned native `DirectAttack.attack()` / `GroundTruthPipeline`
may receive the exact case-specific attack payload, and the payload must
be present in the fresh disposable banking environment produced by the
native `TaskSuite.load_and_inject_default_environment` API.

All observed maps must match independently recomputed native maps exactly.
Altered slot names, omitted or extra slots, a changed payload, relabeled
case or untrusted scorer/enrollment state fail closed.

## Important execution boundary

Native `DirectAttack.attack()` **does** execute the in-memory
`GroundTruthPipeline`, whose `FunctionsRuntime` simulates the original
user task tools (including local address update, standing-order change,
and refund) inside a disposable banking model. **That simulation is not a
VERITAS/RCC/Bind governed effect and not an external banking operation**.

The native environment injection is performed by replacing values in a
fresh, local parsed `BankingEnvironment`. The test does not hand that
environment to a model, run a scorer, or dispatch a paid provider action.

The invariant proves offline attack-slot resolution and payload
placement in fresh sandboxed representations **only**. It does not
establish that a real model saw the payload or generated any new A/B
candidates from it.

## Pinned inputs

- Previously proven PR #258 eight native Task15 direct attack strings,
  8/128 canonical roster and frozen local ineligibility.
- AgentDojo exact commit
  `a75aba7631d3ca5fb7ab938965c97ead2f9ff84b`.
- Native attack, ground-truth pipeline and suite sources, each blob-pinned.
- Task15 native user task and eight injection task GOAL values.
- Fresh `get_suite("v1.2.2","banking")` disposable model environments.

## Audit protocol

Replay predecessor 2,367 tests; run 15 additional cases (one full
eight-case successful placement + 14 refusal variants); independently
regenerate all eight inserted environment snapshots to verify exact
environment hashes, slot IDs and source payload hashes.

Production/API credentials must be absent. No external network/model/scorer
usage is allowed; no new RCC/Bind permit, receipt, provider effect or
canonical benchmark score is created.

**No final128 Utility result or independent A/B model-source claim.**
Do not merge until exact SHA, CI, artifact and bounded evidence agree.
