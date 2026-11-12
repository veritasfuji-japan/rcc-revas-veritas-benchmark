# Research-history coverage and gaps

**This PR's `SNAPSHOT.zip` is not a complete archive of every joint experiment.** It is a selected contributor evidence snapshot. Earlier public upstream results, contributor development iterations, incomplete attempts and future work must remain distinguishable. This index adds references and aggregate metadata; it does not enlarge or rewrite the original ZIP, evidence manifest, scores or experimental conditions.

The inventory was cross-checked against the accessible joint correspondence, preserved contributor run directories, the ZIP entry list and existing public repository material. It is not a claim to have reviewed every attachment, every correspondent alias, or every historical workflow artifact. A public reference is not a bundled file, and a recorded result is not a new independent reproduction.

## Coverage vocabulary

- **Bundled:** the specified stored evidence is in this contributor ZIP; the scope below still applies.
- **Partial:** only a stated subset is bundled.
- **Public reference:** relevant material already exists elsewhere on GitHub; it is not copied into this ZIP.
- **Local, unbundled:** preserved contributor material was found, but its raw files have not passed this PR's publication review and were not uploaded here.
- **Unlocated / correspondence-reported:** the historical claim was found in the correspondence, but a matching public raw bundle was not established by this inventory.
- **Excluded:** intentionally withheld private material, rather than an additional public result.
- **Not run:** proposed or future work; no measured result is asserted.

## Earlier collaboration and public references

The pinned upstream reference for the following paths is [`c4e75f15fff848fc4c67e4dfd15423ee8ac766e9`](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/tree/c4e75f15fff848fc4c67e4dfd15423ee8ac766e9). References do not extend third-party disclosure or reuse permissions.

| Stage | What the evidence represents | Where it is / coverage |
| --- | --- | --- |
| August boundary / artifact mapping | Architecture and interface design, not model Utility | Public successor: [field contract v0.2](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/blob/c4e75f15fff848fc4c67e4dfd15423ee8ac766e9/contracts/RCC_REVAS_VERITAS_Field_Contract_v0.2.json). Original private attachments are not bundled. |
| September early 20-case FUJI adoption pilot | Contributor correspondence reports identical B/C outputs on 20 cases, five FUJI decisions, no additional provider calls. This was not the full Authority/Approval/Bind execution chain. | **Unlocated public raw bundle; not in ZIP.** Do not substitute another small pilot or later 36-case run for this pilot. |
| Canonical RCC runtime publication | Implementation / engineering validation, separate from model Utility | Corrected [v0.1.0 package at 805cd5f](https://github.com/effacermonexistence/rcc-revas-veritas-benchmark/tree/805cd5ff17e431cf50a3dafa7f78a60a704613b9/rcc-revas-eval/v0.1.0); later [external-eval v0.3.9](https://github.com/effacermonexistence/rcc-revas-veritas-benchmark/tree/1d3782d3aae5ff9c88036709c1a5642320cc53c2/external-eval/v0.3.9). Referenced trees were located, not independently revalidated in full here. |
| First 36-case paired attempt | Dependency failure; incomplete treatment run | [Run 35801658815](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/actions/runs/35801658815). Not in ZIP; not a completed paired result. |
| Replacement 36-case run | Earlier adverse integration result, before later fixes | [Run 35813291352](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/actions/runs/35813291352). Public artifact metadata was located. Not bundled or freshly regraded here. |
| 36-case v1.1 / v1.2 hardening | Development testbed, not clean held-out model Utility | [v1.1 run](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/actions/runs/35823854662), [v1.2 run](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/actions/runs/35827320180), [v1.2 condition document](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/blob/c4e75f15fff848fc4c67e4dfd15423ee8ac766e9/docs/PAIRED_CLEAN_TESTBED_v1.2_APPROVAL_REQUIREMENT_SATISFACTION.md). Existing public references, not in ZIP. |
| Initial 128-case A/B | Existing public result reports A Utility 92, attack 21; B Utility 60, attack 0 | [Final clean A/B result contract](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/blob/c4e75f15fff848fc4c67e4dfd15423ee8ac766e9/contracts/AGENTDOJO_FINAL_CLEAN_AB_RESULT_v0.1.json). Separate from V13 and contributor runs. |
| Single-candidate canonical chain | Bounded local engineering proof; not another 128-case Utility score | [Canonical chain contract](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/blob/c4e75f15fff848fc4c67e4dfd15423ee8ac766e9/contracts/SINGLE_CANDIDATE_UNINTERRUPTED_CANONICAL_CHAIN_V1.json). Existing public reference. |
| Formal V13 128-case result | Existing public result reports A 93/128, attack 20/128; B 64/128, attack 0/128; 30 A-only and one B-only successes | [V13 terminal disposition](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/blob/c4e75f15fff848fc4c67e4dfd15423ee8ac766e9/contracts/AGENTDOJO_FINAL_128_V13_TERMINAL_DISPOSITION_v1.json). Not re-executed here; not in contributor ZIP. |
| Task-specific Utility diagnosis / Native integration | Task1/4/13/15, partial-response and authority-boundary work already documented upstream | [Baseline diagnosis](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/blob/c4e75f15fff848fc4c67e4dfd15423ee8ac766e9/contracts/UTILITY_OPTIMIZATION_V1_BASELINE_DIAGNOSIS.json), [optimization ledger](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/blob/c4e75f15fff848fc4c67e4dfd15423ee8ac766e9/docs/optimization/FINAL128_335_OPTIMIZATION_LEDGER_V1.md), [owner approval boundary research](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/tree/c4e75f15fff848fc4c67e4dfd15423ee8ac766e9/research/ben_approval_gate). Partial responses and offline engineering checks are not new whole-task Utility measurements. |

Related standalone VERITAS / AgentDojo candidate replay, Kiel ARM-B, BFCL and other projects are not interchangeable with these joint 128-case experiments. In particular, candidate-level blocking is not a whole-task attack-success score. Private third-party exploration is not republished through this index.

## Contributor experiments: exact coverage of this ZIP

All Utility / attack pairs below use a 128-case denominator per arm. The earlier 128 cases were exposed during development; none of these comparisons establishes a fresh held-out uplift.

| Stage | Recorded model results | ZIP coverage and limitation |
| --- | --- | --- |
| Historical matched run | Mini A 98/21, B 68/0, C 104/0 | **Partial:** only `manifest.json` and `native_scores.json` under `evidence/historical-matched-reference/`. Full trajectories and provider records are not bundled. C's unsupported harness date issuance remains an unresolved historical authority problem. |
| Date / feedback ablation | Mini A 96/21, B 65/0, F 66/0, S 72/0, N 72/0 | **Bundled stored records and code/control subset:** `evidence/previous-feedback-ablation/` has 26 entries. Its 896 stored records comprise 640 generated trajectories and 256 explicitly declared aliases, not 896 independent model trajectories. Earlier provider payloads are not bundled. |
| Darwin/Hinton D1–D3 development | Nano B 47/0, N 72/0, D1 49/0; D2 47/0; D3 72/0. Final Mini B 67/0, N 72/0, D3 72/0. | **Local, unbundled:** 1,024 selected completed case-arm records, source snapshots, scores and transport-recovery material were located. D1 has 4 gains / 2 regressions versus its Nano B; D2 has 3 / 3. Mini D3 has +5 / 0 versus its same-run B and +0 / 0 versus N. No improvement beyond N72 was demonstrated. |
| D2 interrupted attempts | Earlier attempts had 1/128 and 52/128 completed rows; remaining rows were errors | **Local, unbundled.** Recovery reused exact matching prior responses and completed cases. These attempts are not additional complete trials, and the selected records must not be summed with their prefixes as independent observations. Metadata and hashes are in [COVERAGE.json](COVERAGE.json). |
| Runtime repair D4 development | Nano N 72/0, D4 72/0 | **Local, unbundled:** 256 completed case-arm records and provider records. No additional Utility versus N. |
| Runtime repair D4 final model transfer | Mini B 64/0, N 72/0, D4 72/0 | **Bundled subset:** `evidence/previous-date-free-round2/` has 24 entries, including 384 stored case-arm records, source snapshots and controls. Earlier provider payloads and Nano D4 records are not bundled. |
| Feasibility diagnosis | Local source / scorer-referenced analysis of 32 date-authority and 24 policy-denial cases | **Local, unbundled.** This is an offline diagnosis using exposed material, not a new blind solver or official Native Utility run. |
| New owner-supported condition | Nano E_SUPPORT 112/0; final Mini B_SUPPORT 89/0, E_SUPPORT 112/0 | **Bundled selected current evidence:** 384 case-arm records, source snapshots, current provider request/SDK-response/usage records and separate controls in `evidence/current-approved/` (3,541 entries), plus two derived public grant views. Private approval originals, credentials and complete historical dependency trees are excluded. |
| November PR audit | ZIP/hash/manifest/locks/signature preservation and bounded publication review | Outside the historical ZIP: [audit-20261111](audit-20261111/README.md). No new model results or independent Native scorer execution. |
| Future Task1 G vs G+P / fresh held-out evaluation / external reproduction | No new result supplied by this snapshot or coverage inventory | **Not run here.** Needs separately agreed conditions, authority and budget. Historical execution approvals are not reusable. |

The archive has 3,595 entries and 1,664 locked stored records in total. Those counts do not mean every historical experiment, every provider exchange or every dependency is included.

## Conditions and causal limits

The current 112/128 is a **new owner-supported synthetic condition**: date scope for 32 cases and invoice-policy scope for 8 cases, with the same added recipient / amount / date / action metadata supplied to both arms. The other 16 original-policy refusals remain denied. Native Bind core, injected prestates and official scorer preservation does not make the effective permissions and trusted inputs identical to the earlier 72/128 condition.

Within the new condition, E_SUPPORT112 versus B_SUPPORT89 has 23 gains and zero regressions. This measures the whole engine package, not an isolated Darwin/Hinton feedback effect or a hosted model-weight update. The earlier F66's only gain over B65 had no corrective-feedback exposure; S and N both scored 72. Neither a pure feedback gain nor a pure 72→112 optimizer gain is established.

Mini E_SUPPORT has 72 protected COMMITTED receipts across 56 cases, including 40 newly approved payments; Mini B_SUPPORT has 51 receipts across 36 cases, including 24 newly approved payments. Utility112 is not 112 completed protected operations. Local research signatures are not independent proof of a real issuer or bank, and later approval does not retroactively validate C104.

## What this follow-up publishes and preserves

This follow-up publishes only an index, public links and contributor-generated aggregate / hash metadata. It does **not** publish the unreviewed raw local runs, original email threads, private approval source, private signing keys, personal Notes or privately shared third-party materials. Missing raw evidence is explicitly recorded rather than silently replaced. Publication-rights questions recorded in [the audit](audit-20261111/README.md#remaining-gates) remain open.

The original ZIP SHA-256 remains `085de648b4fbd53643e20f20bc9ed3ab7dc8634b9307581cf815d5d5dbba8a51`; the evidence manifest remains `f54d7fd9e2795bbfa97eaaf696166c8c192c8049e41d75b5a341e91105cf3603`. This inventory did not regenerate answers, rescore experiments, invoke a provider, approve a workflow, or merge the PR.

**한국어:** 이번 ZIP에 공동 연구의 모든 원본이 들어간 것은 아닙니다. 기존 상류 공개 자료, 부분 포함된 과거 실험, 로컬에만 남은 D1–D3 및 Nano D4, 미실행 G vs G+P를 구분했습니다. 112점은 새 승인 조건에서 전체 엔진과 같은 조건의 B를 비교한 결과이며 순수 반복 피드백의 +40점으로 해석할 수 없습니다.

**日本語:** 本ZIPは共同研究全体の完全な原本アーカイブではありません。既存の上流公開資料、部分収録、未公開の開発反復と中断試行、未実施のG vs G+Pを区別しています。112点は新しい承認条件での同条件Bとの比較であり、反復フィードバック単独の+40点を示すものではありません。
