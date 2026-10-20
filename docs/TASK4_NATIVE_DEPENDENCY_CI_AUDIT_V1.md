# Selected Task4 Native dependency and CI regression coverage

Baseline: main `1b1b56a1abb0941ec11106b0ea8ef902beff08a7` (merged #488).
This change closes a CI trigger/skip gap, not the P0 execution-authority gaps.

## Every PR runs the selected #487 integration

`task4-native-frozen-recipient-offline.yml` now has an unfiltered `pull_request`
trigger. Changes to lower custody/signing modules, root helpers, manifests,
fixtures, dependency installation/configuration or workflows cannot be omitted
by a manually maintained path list. Documentation-only PRs also run it; this
uses ordinary Actions time but authorizes no paid Provider calls. Existing
branch-required checks, permissions and GitHub workflow enable/disable settings
are not changed. A disabled workflow, Actions outage, GitHub event restriction,
or untrusted modification of the workflow can still prevent a run; check the
actual PR HEAD runs. There is no claim of independently protected change control.

Before installing dependencies, the job inventories the checked-out `HEAD`
(normally GitHub's PR merge commit). The artifact records that exact commit,
workflow digest, selected local import/literal-file dependency candidates and
their SHA256 values, unresolved dynamic execution syntax, and the repository-wide
legacy Broker inventory using the existing #482 source-only auditor. The latest
source is scanned rather than reusing #482's frozen JSON. The scripts parse source
without importing target execution modules or invoking Broker/SDK/Provider code.

This covers all tracked regular Python sources for the legacy syntactic audit;
the selected dependency closure follows local imports and exact literal file
references. Neither is an exhaustive runtime call graph, sender/credential/effect
inventory or universal Python reachability proof. Dynamic names, constructed
paths, reflection, callback forwarding and external repositories need manual
review. Inactive imports and pins may overapproximate runtime reachability.
Historical #458 callers are reported, not silently declared safe or deleted.

## Mandatory dedicated test completion

The job sets the existing dedicated proof flags and runs #487's test file.
The new JUnit gate checks actual testcase identities and all 13 baseline cases,
including the child recipient-substitution test and full Native integration.
Zero cases, a missing/renamed/duplicate case, a different module, any skip,
failure/error, or inconsistent suite counters fail the job. A deliberate test
addition/removal requires an explicit update of the reviewed expected inventory.
Normal pytest failures also fail via `set -euo pipefail`; standalone Native JSON
assertions remain required, including 32 protected connections. Missing artifacts
are errors. Checker tests exercise false-green reports and static import/pin
closure, without executing target sources.

Reproduce from a committed checkout:

```sh
python -m scripts.task4_native_dependency_ci_audit_v1 --ref HEAD
python -m pytest -q -o addopts= tests/test_task4_native_dependency_ci_audit_v1.py
python -m scripts.task4_native_dependency_ci_audit_v1 --junit results/task4-native-frozen-recipient-same-run-native-junit.xml
```

The dedicated JUnit command requires the real dedicated CI output, not a generic
pytest report. CI/artifact results must be recorded for the actual PR HEAD;
these reproduction commands are not evidence that a run passed.

## Unchanged production and research gates

Old Broker paths remain callable in historical offline code. The selected path's
runtime tripwires and new regression checks do not establish global removal,
independent OS/IAM/credential/egress enforcement, durable signer state or cross-runner
CAS. The #487 recipient private key remains PUBLICLY REPRODUCIBLE and must never
protect real data. No real inference, Utility result or independent owner approval
is established. The 15 legacy manual Provider workflows' GitHub enable/disable
state remains a separate unverified administration item; this PR neither enables
nor disables them. See the #488 gap register and #482 migration audit.

`REAL_PROVIDER_NO_GO` / `UTILITY_UNSCORED` /
`PRODUCTION_BYPASS_RESISTANCE_NOT_PROVEN` remain unchanged. No Secrets,
Environments, Rulesets, tags, historical runtime files or paid workflows changed.
