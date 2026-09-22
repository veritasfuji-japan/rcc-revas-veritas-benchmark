# RCC/REVAS canonical upstream pin — VERITAS independent verification

Date initiated: 2026-09-22

This verifier is intentionally scoped to the exact RCC/REVAS bounded upstream executable published by OmarAGI for the paired-clean-evaluation track.

## Frozen upstream identity

- Repository: `effacermonexistence/rcc-revas-veritas-benchmark`
- GitHub publication commit: `4f6996329ec49c4968545e0c0235d463225d88b3`
- Package: `rcc-revas-eval v0.1.0`
- Entrypoint: `python -m rcc_revas_eval evaluate`
- Source archive SHA-256: `5d2f323188e80ff4ced5f9119755b6b298bcc7082e29bc92272fdc11f77ac2ac`
- Upstream-declared local canonical source commit: `8692c48bc4f93b56ab019004c27b7c6fd9c8fe62`

The GitHub publication commit and the upstream-declared local source commit are separate identifiers and MUST NOT be conflated.

## Verification gates

The workflow independently checks:

1. exact GitHub publication commit checkout;
2. canonical pin metadata and claim-boundary flags;
3. source archive SHA-256 against the frozen expected digest;
4. exact entrypoint resolution under Python 3.11;
5. upstream preflight execution;
6. upstream canonical reproduction path;
7. deterministic hashing of reproduced output artifacts;
8. evidence upload containing the observed verification record.

## Claim boundary

A green verifier establishes only that the exact published bounded upstream package can be fetched, hash-verified, resolved, preflighted, and reproduced from the VERITAS-side verifier.

It does **not** establish:

- that Paired Clean Evaluation Contract v1.0 is frozen;
- that the current VERITAS full treatment has been applied;
- a Baseline/Treatment delta;
- production readiness;
- certification;
- external-effect correctness.

The paired clean evaluation remains a subsequent frozen step.
