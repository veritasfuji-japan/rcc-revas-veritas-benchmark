# RCC/REVAS × VERITAS — Paired Clean Evaluation Contract v1.0

Date: 2026-09-22

Status: **VERITAS-SIDE FROZEN — COUNTERPARTY ACK REQUIRED BEFORE EXECUTION**

Contract SHA-256:

`532958fc9371fb34e550fb2a108868c64e87a980833dd46e8a92c7a133d9ae1f`

## Frozen baseline

- Repository: `effacermonexistence/rcc-revas-veritas-benchmark`
- Corrected publication commit: `805cd5ff17e431cf50a3dafa7f78a60a704613b9`
- Package: `rcc-revas-eval v0.1.0`
- Entrypoint: `python -m rcc_revas_eval evaluate`
- Source archive SHA-256: `4c736357ab93a8f4b5027b94c20340b973c760de1a0027df30bb53d3d10f47d8`
- VERITAS independent verification run: `35710486162`
- Verification artifact: `10686261092`
- Verification artifact SHA-256: `219a3389c03e809bee9b5e297594f4154d10ee70d5036bf684be244f07b2109c`

The superseded publication commit `4f6996329ec49c4968545e0c0235d463225d88b3` is not permitted.

## Frozen VERITAS treatment

- Repository: `veritasfuji-japan/veritas_os`
- Commit: `b39961b003179aea70e320a57cb000f56a81951e`
- Entry boundary: `POST /v1/decide`
- The decision response is **not** execution permission.
- Exact stop point: record native Bind eligibility / gate-review and associated governance evidence, then stop before credential-material handoff, transport invocation, network dispatch, or any external effect.

## Frozen dataset

- `fixtures/Governance_labelled_Evaluation_Set_v0.1.1.json`
- cases: `36`
- SHA-256: `1e6ea7f9366876b4cbf041cc0841ab72bd58d6f561ff78553deb6645e5bf2a88`
- labels: existing preregistered synthetic labels
- preserved semantic divergences: `GOV-H06`, `GOV-H07`, `GOV-D08`

No label or policy may be retuned after result inspection under this contract.

## Pairing rule

For each frozen case:

1. run the frozen RCC/REVAS executable;
2. preserve the exact RCC/REVAS result and candidate/handoff artifact;
3. Arm A records the RCC/REVAS baseline without VERITAS and without external effect;
4. Arm B consumes the **same RCC/REVAS candidate/handoff artifact** from the same paired pre-state under the frozen VERITAS treatment;
5. hash equality for the paired candidate/handoff and pre-state is required;
6. selective reruns and silent denominator reduction are prohibited.

## Runtime environment

- GitHub-hosted `ubuntu-24.04`, x86_64
- Python `3.11.16`
- RCC/REVAS runtime: standard library only as declared by the frozen upstream package
- VERITAS install: `python -m pip install ./veritas_os_checkout` from the exact frozen commit
- scored execution: no external network except loopback local-process communication
- evidence must capture `python --version`, `pip freeze`, `uname -a`, and available runner-image metadata

## Cost accounting

Only directly observed call counts, token counts, retries, timings and exact provider billing metadata may be recorded. Estimated provider cost is prohibited. Use `UNKNOWN` or `NOT_APPLICABLE` where appropriate.

## Execution gate

This contract is frozen on the VERITAS side, but **benchmark execution remains prohibited** until Ben/OmarAGI acknowledges this exact contract hash.

After acknowledgment:

1. implement the new paired runner against these exact frozen semantics;
2. pin and hash the runner;
3. verify the runner cannot dispatch externally;
4. run the complete 36-case paired evaluation once;
5. preserve Baseline / Treatment / Delta / exact provenance separately.

## Claim boundary

This freeze does not claim that the paired run has already executed, that a treatment delta has been measured, or that RCC/REVAS × VERITAS is production-validated, independently certified, commercially deployed, or a formal partnership.
