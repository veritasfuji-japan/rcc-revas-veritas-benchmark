# Task1 Real GitHub Ruleset Denial - bounded evidence freeze (PR #361)

This freeze reproduces and audits *already observed* evidence from [Run 38254439093](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/actions/runs/38254439093) / [Job 114828743640](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/actions/runs/38254439093/job/114828743640). It **does not** re-run GitHub tag writes.

- Source code and run HEAD: `9cb4345545dd17e9071d248ea8102f7d455e8c7f` (main, after PR #360)
- In real GitHub: isolated tag create 201; forced update 422 Ruleset denial; deletion 422 Ruleset denial; post-operation GET remained on the same SHA.
- Subsequent read-only API query found that same tag pointing to the same commit, while Ruleset 24921425 had active update, deletion and non-fast-forward restrictions without bypass actors.
- `evidence/final128_task1_github_denial_run_38254439093_v1.json` contains allowlisted field-level observations and selected job-log excerpts, not complete raw logs. Its .sha256 sidecar is anchored to this Git commit, not an independent trusted timestamp or signature.
- CI runs offline semantic negative controls and publishes a **derived evidence snapshot** artifact. The original run had no dedicated artifact.
- **Scope:** limited to GitHub tag protection and readback. Not proof of VERITAS runtime control, IAM/network bypass prevention, independent provider-egress verification, third-party replication, or full Final128 utility.

Offline verification (no tokens or network):

```bash
python scripts/final128_361_task1_github_denial_freeze_v1.py
python -m pytest -q -o addopts= tests/test_final128_361_task1_github_denial_freeze_v1.py
```
