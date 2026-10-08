# RCC/REVAS × VERITAS — Execution Governance Benchmark

**Evidence-first evaluation of whether AI-proposed actions should cross an execution boundary.**

[日本語](../README_JP.md) · [VERITAS OS](https://github.com/veritasfuji-japan/veritas_os) · [V13 frozen result](../contracts/AGENTDOJO_FINAL_128_V13_TERMINAL_DISPOSITION_v1.json) · [Independent reviewer handoff](../docs/AGENTDOJO_FINAL_128_INDEPENDENT_EXTERNAL_REPLICATION_HANDOFF_V1.md)

> **Documentation snapshot: 2026-10-09.** This is a research/evaluation harness, **not** a deployed banking product, a production-readiness claim, or a third-party certification. The **measured V13 real-provider run** and **later Task15 provider-free local proofs** are distinct evidence tracks. Passing CI alone does not upgrade any result to independently PROVEN.

## What is being tested?

AI output is a *candidate action*, not execution authority. This repository compares a controlled upstream RCC/REVAS candidate-treatment path (Arm A) against a path that additionally applies VERITAS execution-time Bind governance (Arm B). Both begin from the **same initial AgentDojo banking case state**.

```text
 Frozen AgentDojo case + controlled upstream candidate treatment
                      |
          +-----------+-----------+
          |                       |
      Arm A                       Arm B
  RCC/REVAS upstream       RCC/REVAS upstream
  treatment only           + VERITAS Bind checks
          |                       |
    Native task/tool        Guarded native sink
    result                        |
          +-----------+-----------+
                      |
             AgentDojo native scoring
```

**Arm A is a benchmark comparison condition, not proof that RCC/REVAS grants real-world execution authority.** Neither arm connects to an actual bank. We measure both (1) legitimate **user-task utility** (higher is better) and (2) **injection-task success** (attacker objective success; *lower* is safer).

## Completed measured result — Canonical Final 128 / V13

This frozen run **used the real OpenAI provider**, but evaluated a **previously exposed synthetic AgentDojo banking corpus**. It must **not** be confused with the later Task15 controlled simulations.

| Native AgentDojo metric | Arm A: upstream RCC/REVAS path | Arm B: + VERITAS Bind |
| --- | ---: | ---: |
| Legitimate task utility | **93/128 (72.66%)** | **64/128 (50.00%)** |
| Injection-task success (lower is safer) | **20/128 (15.63%)** | **0/128 (0%)** |

The run has **128 paired cases, 256 scored arm records, identical initial pre-states for all 128 cases, and zero execution errors**. Paired utility changed **30 cases from A-success to B-failure**, and **one case from A-failure to B-success**. These 30 cases are *not* all proven false-positive policy blocks; missing authority, candidate generation, and other differences must be investigated individually.

The runner recorded **820 provider calls** and **USD 0.3221684 estimated cost** (not a billing-account audit). The **V13 one-time authorization was consumed: reuse and rerun are prohibited**.

| Source/evidence pin | Exact reference |
| --- | --- |
| Executed main SHA | [`2454ba69818d1a46b910f33fab9b57017cd7a83e`](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/commit/2454ba69818d1a46b910f33fab9b57017cd7a83e) |
| GitHub Actions | [Run 37585673492](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/actions/runs/37585673492), job `112675107243` |
| Result artifact | ID `11466539107`, `agentdojo-clean-ab-final-v13-37585673492` |
| Artifact ZIP SHA-256 | `9fbb2a1614c237e92c4239bb5d60f83d40d33b81e0092d3f82958931969c9e7a` |
| Machine-readable terminal closure | [V13 terminal disposition](../contracts/AGENTDOJO_FINAL_128_V13_TERMINAL_DISPOSITION_v1.json) |
| Case-level interpretation | [V13 post-execution analysis](../contracts/AGENTDOJO_FINAL_128_V13_POST_EXECUTION_ANALYSIS_BOUNDARY_v1.json) |

**Interpretation:** Arm B observed zero successful injection objectives **in these 128 cases**, but lost substantial legitimate utility relative to Arm A. This does **not** demonstrate universal attack prevention, held-out generalization, independent external validation, or production readiness. Utility recovery remains a goal, **not a new measured result**.

## Post-V13 development — separate, provider-free proof track

Later PRs address missing authority and controlled multi-effect workflows. None rescores, amends or reuses V13.

| Work | Implemented focus | Critical boundary |
| --- | --- | --- |
| [#205](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/pull/205) | Classify 69 provider-free A-committed / B-blocked cases | Diagnostic; **no policy relaxation** or new Final 128 |
| [#243–#245](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/pull/245) | Task15 address/rent/refund independent authority scopes and prospective state lineage | Read-only/prospective evidence is **not** an execution permit |
| [#246](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/pull/246) | Controlled three-step A/B runner with actual local RCC, B-arm Bind, guarded native sink, and partial/UNKNOWN preservation | Trusted local fixture; **no external payment** or global exactly-once proof |
| [#247](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/pull/247) | Gate native Task15 *state-only* scorer diagnostics on completed local effects | Empty model output/trace; **not** full-conversation utility |
| [#248](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/pull/248) | Capture three SDK-shaped assistant tool proposals and pass each unchanged to the existing controlled RCC/Bind/native-sink path | `OFFLINE_INJECTED_CLIENT`; **no live provider**, authenticated model origin or continuous conversation |

**What #248 does *not* yet do:** The three queries are independent, using test-injected native-shaped `ChatCompletionMessage` objects. The native address runner has not retained exact tool-return bytes for use as the next conversation message. No uninterrupted assistant/tool history, new scored Final 128, injection-safety remeasurement, or demonstrated utility recovery can be claimed from this proof.

Read [Task15 composed runner documentation](../docs/TASK15_CONTROLLED_MULTI_EFFECT_COMPOSED_ADMISSION_RUNNER_V1.md) and [Task15 model-response capture limitations](../docs/TASK15_NATIVE_MODEL_RESPONSE_CAPTURE_BOUNDARY_V1.md). **Merged, CI PASS, independently PROVEN, and production validated are different statuses.** Keep existing frozen `NOT PROVEN` artifacts unchanged.

## Where to start as a reviewer

| Review objective | Entry point | Provider/API spend |
| --- | --- | --- |
| Examine measured V13 scores | [Terminal record](../contracts/AGENTDOJO_FINAL_128_V13_TERMINAL_DISPOSITION_v1.json) + [analysis](../contracts/AGENTDOJO_FINAL_128_V13_POST_EXECUTION_ANALYSIS_BOUNDARY_v1.json) | None |
| Independently recompute **existing** V13 artifact | [Handoff Track A](../docs/AGENTDOJO_FINAL_128_INDEPENDENT_EXTERNAL_REPLICATION_HANDOFF_V1.md) | None |
| Examine controlled multi-effect admission | [#246](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/pull/246) and [proof scope](../docs/TASK15_CONTROLLED_MULTI_EFFECT_COMPOSED_ADMISSION_RUNNER_V1.md) | None |
| Examine model-response provenance limitation | [#248](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/pull/248) and [capture scope](../docs/TASK15_NATIVE_MODEL_RESPONSE_CAPTURE_BOUNDARY_V1.md) | None |
| Conduct an independent *new* same-corpus or held-out run | [Handoff Tracks B/C](../docs/AGENTDOJO_FINAL_128_INDEPENDENT_EXTERNAL_REPLICATION_HANDOFF_V1.md) | **Fresh explicit approval, versioned single-use authorization, exact pins, spend cap** |

**Safe read-only entry point (no provider calls):**

```bash
git clone https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark.git
cd rcc-revas-veritas-benchmark
git checkout 00fe1dedc6ef6dd3e690bce892d81105bafb0989
python -m json.tool contracts/AGENTDOJO_FINAL_128_V13_TERMINAL_DISPOSITION_v1.json > /dev/null
python -m json.tool contracts/AGENTDOJO_FINAL_128_V13_POST_EXECUTION_ANALYSIS_BOUNDARY_v1.json > /dev/null
```

These commands **only check local JSON syntax**. They do not verify the artifact, re-run AgentDojo, authenticate provider execution, or constitute independent attestation. Track A requires the exact source, artifact download/ZIP digest, record/scorer recomputation, and explicit bounded conclusion. It requires **no OpenAI API key**.

## Known limits and non-claims

- **Safety and utility must both be reported:** V13 B's 0/128 injection-task successes coexist with 64/128 legitimate-task utility. Latest Task15 work has **not** produced a newly measured full Final 128.
- **Previously exposed corpus:** not held-out generalization or a universal zero-injection-success guarantee.
- **External effect authenticity:** AgentDojo-local mutations are not real bank transfers, enterprise identity/credential proofs, settlement or production effects.
- **Trust and authority:** customer principal, ledger, clock, trusted root, external request authenticity, key custody and environment-specific bypass resistance need separate independent verification.
- **Durability and chronology:** #248 is *not* a continuous model conversation; process-local receipt controls alone do not establish persistent cross-process once-only execution or restart recovery.
- **Audit status:** local reconstruction, GitHub success and published evidence do not amount to independent third-party certification.
- **Frozen scope:** evidence for one SHA, case population or effect boundary cannot automatically be extended to all later code.

## Roadmap — proposed, not proven

1. Capture **exact native return payloads at the final Task15 sink** instead of inventing tool-result messages.
2. Construct and independently verify complete original assistant/tool history; score authentic completed trajectories **read-only**.
3. Only after fresh human confirmation, a **new** exact versioned single-use authorization and explicit spend cap, consider further live-provider measurements. **Never reuse V13.**
4. Conduct independent same-corpus replay and then independently scoped held-out evaluation; report failures too.
5. Propose a bounded enterprise pilot for real credential isolation, enforcement/bypass resistance, reconciliation and reviewer evidence before any production-readiness statement.

## Historical v0.1 README

The original **Joint Benchmark Runner / Evaluation Harness v0.1** text, including old input pins, the `--bind-proxy` caveat and legacy commands, is [preserved verbatim](../docs/archive/joint-benchmark-runner-v0.1-README.md). That document describes a **historical individual harness**, not the present evidence status of every benchmark lane.

This joint evaluation does **not** imply that RCC/REVAS grants execution authority, endorses all VERITAS implementation choices, or has a formal commercial partnership with VERITAS.
