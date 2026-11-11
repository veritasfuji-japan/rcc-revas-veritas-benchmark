# OmarAGI Utility experiments — evidence snapshot of 2026-11-01

[日本語](README_JA.md) · [Results](RESULTS.json) · [Publication scope](PUBLICATION_SCOPE.md) · [Evidence manifest](EVIDENCE_MANIFEST.json)

[November 11 follow-up to the maintainer audit](audit-20261111/README.md): exact-commit archive/grant checks, observed outputs, a minimal offline procedure, an explicit scanner-metadata correction, and remaining publication-rights/history limitations. The historical ZIP, manifest, scores and experiments are unchanged.

This contributor snapshot preserves the measured results, implementation and execution records shared for the RCC/REVAS × VERITAS research. It is submitted for maintainer review before the separately proposed Task1 **G vs G+P** experiment. This archive does not run that experiment or change the current RCC dispatch, VERITAS enforcement, Native scorer, original V13 results, policies or authorization records.

## Measured model runs

All rows use the existing 128-case development-exposed corpus. Each row is a separate run, not a controlled comparison across rows. Values are **official Native Utility / Injection success**, with 128 cases per arm.

| Run / condition | Model | Arms: Utility, Injection success |
| --- | --- | --- |
| Historical matched experiment; C included harness-self-issued date support | GPT-4.1-mini-2025-04-14 | A: 98,21 · B: 68,0 · C: 104,0 |
| Earlier date-free ablation under legacy authority | GPT-4.1-mini-2025-04-14 | A: 96,21 · B: 65,0 · feedback F: 66,0 · source supplementation S: 72,0 · combined N: 72,0 |
| Later date-free execution-repair experiment under legacy authority | GPT-4.1-mini-2025-04-14 | B: 64,0 · N: 72,0 · D4: 72,0 |
| New owner-supported condition, development | GPT-5-nano-2025-08-07 | E_SUPPORT: 112,0 |
| New owner-supported condition, final comparison | GPT-4.1-mini-2025-04-14 | B_SUPPORT: 89,0 · E_SUPPORT: 112,0 |

The final same-condition comparison has **23 gains and 0 regressions against B_SUPPORT**. There is no live Arm A run under the new condition. Historical local A98 and A96 have respectively **9 and 7 regressions** against E112 under different conditions. Those local A runs are distinct from Takeshi's original V13 A93/B64 result.

### What changed in the owner-supported condition

Profile: `OWNER_APPROVED_DISPOSABLE_RESEARCH_DATE_AND_INVOICE_V1`.

- A new owner decision and separate research policy supplied date/payment support for 32 cases and invoice-payment support for 8 cases. The other 16 legacy-policy refusals were retained; the denominator remained 128.
- Both arms received the same added recipient, amount, date and operation metadata. This changes both the effective permission set and trusted information available to the arms.
- Original injected environment prestates, the official scorer and Native Bind core were preserved. Preserving those files does **not** mean all authority conditions stayed identical.
- Local signatures bind the research scope. They do not independently authenticate an owner, external issuer, real bank, host or clock. New approval does not retroactively validate historical C104's date issuance.

The +23 is an observation for the **whole engine package**: receipt-derived hints, source/argument repair, calculations/planning, operation completion and final-output supplementation. It is not isolated Darwin/Hinton feedback causality or hosted-model weight improvement. The earlier 72 and current 112 must not be presented as a pure +40 optimizer gain.

The earlier feedback-only ablation also matters: F's sole gain over its same-run B had **no corrective-feedback exposure**. S and N both scored 72. An independent causal Utility gain from feedback alone was not established. The previous date-free experiments are different implementations/runs, not a one-factor toggle of the current engine.

### Official scores versus effects

| Final Mini arm | Protected COMMITTED receipts | Cases with a protected commit | Newly approved payments |
| --- | ---: | ---: | ---: |
| B_SUPPORT | 51 | 36 | 24 |
| E_SUPPORT | 72 | 56 | 40 |

Utility112 does not certify 112 protected actions or 112 fully completed requests. Read/no-op/refusal successes and partial effects must remain distinguishable. Model histories, final system output, before/after environments and Native receipts are archived separately from the saved scores.

## Historical offline evidence, separate from model scores

These are results recorded during the original local research, not new evaluations performed by this publication:

- 384 owner-supported case-arm records locally regraded with 0 mismatches.
- 19 Native/approval-origin checks passed.
- Same-scope candidate controls: 40 pairs, 0 new-arm judgment/effect differences; original-policy refusals retained.
- Recorded-trajectory controls: 80 trajectories, 250 tool-step pairs, 126 protected-candidate pairs, 0 arm differences and 0 final-state replay mismatches.

The control fixtures explicitly use TEST enrollment. They are not additional provider runs or external independent replication. Prior ablation aliases `C_STRICT` and `D_DENIED` are preserved in the score/record files but are not independent model trajectories: 896 stored records comprise 640 generated trajectories and 256 declared aliases.

## Files and offline inspection

- `SNAPSHOT.zip`: archived implementation/source snapshots, current provider request/SDK-response/usage records, locked execution JSONL, scores, local audits and separate offline controls. Earlier-run provider payloads and historical-matched full trajectories are not fully bundled.
- `EVIDENCE_MANIFEST.json`: each entry's size, SHA-256, source identity, omissions and two explicitly transformed public enrollment views.
- `RESULTS.json`, `EXPERIMENT_CONDITIONS.csv`, `CASE_COMPARISON.csv`, `FEEDBACK_ABLATION_CASES.csv`: condition and case-wise comparisons. Cross-condition references are labeled.
- `verify_snapshot.py`: read-only integrity, source-pin, record/score accounting, prestate, effect-count and comparison checks. It never imports the archived runners or calls a provider. With `--verify-signatures`, it additionally checks the preserved grant signatures using `cryptography`.

```sh
python3 research/omaragi_utility_snapshot_20261101/verify_snapshot.py
# Optional: use an environment already containing cryptography.
python3 research/omaragi_utility_snapshot_20261101/verify_snapshot.py --verify-signatures
```

The verifier compares stored evidence; it **does not invoke the official Native scorer**. The original local Native regrading scripts and dependency hashes are included for review, but the complete historical dependency trees and private approval source are not bundled. This is not a one-command independent live reproduction. Original host path literals remain inside some byte-preserved historical code; the files behind those paths and credentials are not included.

There are **no new provider calls or scores**, no fresh held-out evaluation and no external independent reproduction introduced here. The historical research approval is expired/consumed and is not permission to rerun. A new live run requires separately agreed conditions, fresh authority and budget. Production security, real banking authority, general token savings and commercial/customer outcomes are unproven by this snapshot.

## Provenance and next review

Contributor implementation commit: `9f148a82a9366ca6e7bb245fb0f1b2bd946ae6f2` in the author's preserved checkout. This identifier is not represented as a commit already merged into the joint repository. Byte-level implementation identity is available through the run manifests and source snapshots.

Prepared on 2026-11-08 for a PR to the joint repository. It preserves the contributor's source management and does not change existing IP, attribution or collaboration scope. Personal RCC/REVAS Notes and privately shared third-party AEGIS material are excluded. The maintainer can review evidence consistency, reproducibility limits and claim boundaries before adoption and before a new G vs G+P experiment.
