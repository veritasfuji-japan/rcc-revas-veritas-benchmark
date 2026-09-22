# Paired Clean Runner v1

## Purpose

This runner implements the execution machinery required by the frozen
RCC/REVAS × VERITAS Paired Clean Evaluation Contract v1.0 without changing the
contract bytes, frozen dataset, labels, preserved divergences, treatment pin,
or scoring semantics.

Runner implementation and runner pinning are deliberately separated from the
single scored 36-case execution.

## Frozen identity

- Contract SHA-256:
  `532958fc9371fb34e550fb2a108868c64e87a980833dd46e8a92c7a133d9ae1f`
- Dataset SHA-256:
  `1e6ea7f9366876b4cbf041cc0841ab72bd58d6f561ff78553deb6645e5bf2a88`
- RCC/REVAS publication commit:
  `805cd5ff17e431cf50a3dafa7f78a60a704613b9`
- RCC/REVAS source archive SHA-256:
  `4c736357ab93a8f4b5027b94c20340b973c760de1a0027df30bb53d3d10f47d8`
- VERITAS treatment commit:
  `b39961b003179aea70e320a57cb000f56a81951e`
- Frozen denominator: 36 cases
- Preserved divergences: `GOV-H06`, `GOV-H07`, `GOV-D08`

## Pin-before-score sequence

1. Review and merge the runner implementation.
2. Treat the resulting exact merge commit as the paired-runner pin.
3. Verify the pin-only workflow evidence.
4. Share the exact runner commit/hash with Ben / OmarAGI.
5. Only then invoke the manual scored workflow once with:
   - the exact pinned runner commit;
   - the exact acknowledged Contract v1.0 SHA-256;
   - the explicit one-run confirmation string.
6. Retain the full evidence artifact without selective rerun or denominator reduction.

The pull-request pin workflow does **not** execute the frozen paired corpus. It
only verifies source pins, runner invariants, native module compatibility, and
the no-effect configuration.

## Pairing semantics

For each frozen case:

- Arm A is the frozen RCC/REVAS result.
- Arm B begins from the exact RCC/REVAS-produced candidate/handoff and exact
  RCC evaluation pre-state.
- Candidate and pre-state identities are checked at the native
  `POST /v1/decide` request boundary.
- A valid VERITAS Canonical Decision Artifact is required.
- The exact RCC candidate is required to remain the selected candidate.
- That candidate is then bound into the frozen native decision-to-Bind
  governance chain.
- Treatment stops at native Bind eligibility / gate review.

The runner stops before credential-material handoff, transport invocation,
network dispatch, Bind authorization creation, execution-authority creation, or
external effect.

## Label isolation

Frozen `ground_truth` is not consumed by the treatment-construction helpers.
Labels are used only after treatment records exist, for scoring and reporting.

The runner unit suite statically checks the treatment helpers for accidental
`ground_truth` access.

## Unsupported cases and failures

- Unsupported cases remain in the denominator and are recorded explicitly.
- Infrastructure failures are recorded per case as `INFRASTRUCTURE_ERROR`; they are never converted to ALLOW/HOLD/DENY.
- A candidate mismatch after `POST /v1/decide` is recorded as a pairing violation, not as a governance outcome.
- Cases where RCC/REVAS withholds the candidate record candidate presence as false instead of claiming candidate equality.
- No automatic retry is permitted.
- No selective rerun is permitted.
- The scored workflow uploads the evidence bundle before marking an infrastructure- or pairing-invalid attempt failed.
- `evidence_index.json` records the raw SHA-256 of the final `run_manifest.json` plus all primary result artifacts.
- Frozen labels are attached to result rows only after all treatment attempts have been recorded; treatment helpers receive a case object with `ground_truth` removed.
- No post-result retuning of `GOV-H06`, `GOV-H07`, or `GOV-D08` is permitted.

## Manual scored invocation

After runner pinning, the equivalent CLI form is:

```bash
python paired_clean_runner_v1.py \
  --scored-run \
  --runner-commit <exact-pinned-runner-commit> \
  --acknowledged-contract-sha256 532958fc9371fb34e550fb2a108868c64e87a980833dd46e8a92c7a133d9ae1f \
  --upstream-repo <exact-rcc-checkout> \
  --veritas-repo <exact-veritas-checkout> \
  --output-dir results/paired-clean-v1
```

The runner refuses a scored execution if the current checkout is not the exact
supplied runner commit, if the acknowledged contract hash is wrong, if the
frozen source pins drift, or if the scored environment does not match the
frozen GitHub-hosted Linux x86_64 / Python 3.11.16 profile.

## Claim boundary

Runner implementation or pinning alone does not establish:

- a completed paired scored evaluation;
- a measured treatment delta;
- independent third-party validation;
- production validation;
- customer deployment;
- paid PoC;
- certification;
- formal partnership.

Those claims remain outside this runner-pin step.
