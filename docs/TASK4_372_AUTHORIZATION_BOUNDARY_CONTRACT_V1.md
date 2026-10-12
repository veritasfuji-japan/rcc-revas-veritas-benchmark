# Task4 #372 — Actual VERITAS authorization boundary: implementation contract (NOT EXECUTED)

## Baseline
Task4 #371 invokes the actual SHA-pinned `evaluate_bind_admissibility` at a Docker broker using HMAC-signed **synthetic host inputs**, with two synthetic mock effects and a SQLite one-use gate. That is **not** signed VERITAS OS authorization issuance or native consumption.

## Objective for the next runtime PR
Prove a complete, pinned VERITAS authorization **issuance -> independent verification -> bind-time recheck -> single-use consumption -> synthetic effect -> independent reconciliation** chain, with a real module/function call at every VERITAS-specific boundary. Preserve #371 Docker network separation and mock sink. Do not substitute a locally invented HMAC token for VERITAS-native authority.

## Preconditions (must be resolved before claiming execution)
1. Identify the actual upstream issuer, verifier, consumption and reconciliation entrypoints, with their import paths, input schemas and source hashes. A missing upstream implementation is a **BLOCKER**, not permission to fabricate one.
2. Pin a single `veritas_os` commit and verify both checked-out Git SHA and the exact source bytes inside the Docker image.
3. Distinguish host-controlled fixture identity from independently verified issuer identity. A host-generated test approval is **synthetic**, even if signed.
4. Separate verification of signature, audience, exact target, operation, subject, scope, expiry, policy, approval freshness, and bind-time state from the downstream mock sink's credential and network gates.
5. Define a durable atomic single-use consumption boundary and its crash/retry behavior. No check-then-act race, and no replay after successful consumption.
6. Bind the final synthetic sink receipt to the consumed authorization and exact request hash, then reconcile using target-owned evidence.

## Required test matrix
| Case | Expected | Independently checked evidence |
|---|---|---|
| ALLOW_01 | Exactly one synthetic effect | Native authorization issued and verified, bind eligible, consumed once, target-owned effect |
| DENY_01 | No effect | Missing or invalid human approval blocks issuance/bind |
| DENY_02 | No effect | Agent-to-sink direct network bypass denied |
| DENY_03 | No effect | Untrusted/missing executor identity rejected |
| DENY_04 | No effect | Trusted identity lacking target scope rejected |
| DENY_05 | No second effect | Replay after durable consumption denied |
| DENY_06 | No effect | Target/operation/scope mismatch denied |
| RECON_01 | Exactly one matched effect | Independent target snapshot agrees with receipt and consumption |

## Fail-closed negative tests
- Missing, malformed, tampered or wrong-audience authorization
- Valid signature with wrong target, operation, subject or scope
- Expired approval, TTL, policy drift, state drift and risk escalation
- Repeated delivery, concurrent replay and interruption between consumption and effect
- Broker-to-sink reachability positive control; agent direct-IP, external egress and rogue backend bypass negative controls
- Missing or inconsistent target audit, receipt, consumption record or provenance hash

## Evidence required for promotion
Exact benchmark and upstream commit SHAs, module and image source SHA-256, actual issuer/verifier/consumer entrypoint names, per-attempt verdict/reason codes, Docker network inspect, independent sink-owned SQLite/JSONL records, atomic consumption journal, sanitized JUnit, artifact manifest with SHA-256. Verify evidence against exact PR HEAD and after merge.

## Nonclaims
This document is a **specification-only checkpoint**. It does not implement or execute native VERITAS authorization issuance, native consumption, production IAM, a live banking effect, external provider inference or third-party audit. No API spend is authorized. #371's synthetic HMAC inputs remain synthetic until independently replaced and tested. CI passing for this contract must never be reported as full execution proof.

## Release gate
Do not implement the full runtime in a single blind change. First confirm native upstream interfaces and their tests; then implement a minimal executable slice with dedicated CI and independently inspect its evidence. Keep Draft until the actual runtime checks are green.
