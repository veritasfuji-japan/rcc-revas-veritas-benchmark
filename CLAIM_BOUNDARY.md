# Claim Boundary

Joint Benchmark Runner / Evaluation Harness v0.1 executes the native VERITAS `CanonicalDecisionHandoff v1` validator at the pinned source commit.

It does **not**:

- create execution authority;
- invoke a real Bind;
- dispatch credentials or network requests;
- cause external effects;
- execute the native dry-run Bind Authorization gate in v0.1;
- prove production interoperability;
- prove RCC/REVAS grants execution authority;
- establish regulatory or third-party validation.

The optional Bind proxy is runner plumbing only and is not native Bind-gate evidence.
