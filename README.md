# RCC/REVAS × VERITAS Benchmark

Initial public benchmark repository for an independently reproducible comparison of:

- Path A: RCC/REVAS upstream adoption baseline
- Path B: RCC/REVAS + VERITAS governance treatment

## Core invariant

**Decision Adoption != Execution Authority**

## Current branch staging

The initial Joint Benchmark Runner / Evaluation Harness v0.1 package is staged on
`feat/joint-benchmark-v0.1` as integrity-checked base64 archive parts because the
Codex task UI does not accept ZIP attachments directly.

Materialize the package in a Codex workspace with:

```bash
python bootstrap_package.py --force
```

The bootstrap script:

1. concatenates `staged_archive_parts/part-00.b64` through `part-07.b64`;
2. decodes the staged ZIP;
3. verifies ZIP SHA-256
   `b3b0e074c28c30714224157c6b4f8a5dc9a15f5c03e973c058efcd44b8e5c379`;
4. strips the package's outer `joint_benchmark_runner_v0_1/` directory;
5. writes the benchmark files into the repository working tree.

After extraction, Codex should critically review, test, refactor where necessary,
add CI/tests, and commit the materialized implementation on the task branch.

## Claim boundary

This repository does not claim production deployment, execution authority,
real Bind invocation, external effects, regulatory certification, or formal
endorsement by OmarAGI, NeoMundi, OpenAI, or any other third party.
