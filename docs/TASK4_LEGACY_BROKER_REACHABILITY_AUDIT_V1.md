# Task4 legacy Broker reachability and migration audit

Audited source: `f20fdd26234116a4981a27b8ef5f00881e236bf0` (merged #481).
Disposition: **SOURCE_AUDIT_ONLY / REAL_PROVIDER_NO_GO / UTILITY_UNSCORED**.

## Finding: #481 isolates one process, not the whole Native harness

The protected child created by #481 does not start the #458 listener or call
its raw `action()`. However, **#481 `run(with_native=True)` still reaches #471,
which starts and later restarts a separate #458 Broker process**. This is an
active dependency in the source path, not merely unused historical code.
This audit establishes the source chain; it does not claim a newly observed
runtime trace or a successful real Provider bypass.

| Step | Source evidence at the audited commit | Meaning |
|---|---|---|
| Dedicated CI | `task4-481-protected-only-broker-offline.yml` invokes `--with-native` and enables `TASK4_481_NATIVE_PROOF` | Native branch is requested by that workflow |
| #481 | `NATIVE = prior.native`; `run()` calls `NATIVE.native.prior.run_offline_native_budget_join()` at line 336 | Follow module aliases, not only direct #458 imports |
| #480 / #476 / #474 | #480 `native` imports #476; #476 `native` imports #474; #474 `prior` imports #473 | Resolves the called function to #473 |
| #473 | `run_offline_native_budget_join()` calls #472 `run_native_with_isolated_deny_worker()` | Budget guard wraps the existing Native path |
| #472 | Imports #471 as `native`, then calls `native.run_local_native_allturn_join()` | Existing custody pipeline is retained |
| #471 | `broker.spawn_server(...)` at lines 235 and 324 | Starts legacy custody Broker, then restarts it |
| #458 | `spawn_server()` launches this file with `--mode broker`; `main()` instantiates `Broker` | Separate raw UNIX listener |
| #458 handler | `Handler.handle()` invokes `action()` at line 223 | Raw consume/attach/read protocol remains reachable |

#481's monkeypatch tripwires exist inside `broker_child()` only. Its socket
enumeration examines that child's private directory. Neither operation observes
all processes or all temporary directories in the Native run. Consequently:

- `protected_only_process_has_no_legacy_socket=True` remains a **child-local** claim.
- It must not be restated as “the entire Native run has no legacy listener.”
- The #481 protected signature/CAS checks are not invalidated by this finding;
  their scope is narrower than full legacy removal.
- #458 is synthetic and NO_SEND. Its reachability does not prove real Provider
  dispatch or real banking effects are possible.

## Inventory and classifications

The adjacent JSON contains paths, source line numbers and SHA-256 file hashes.
All **762 tracked regular Python files** at the audited commit parsed successfully.
The syntactic inventory found **30 call sites** for selected legacy entrypoints,
**36 import-closure candidate files** (18 scripts and 18 tests), and **18 dedicated
workflow textual-reference candidates**. These are source counts, not counts of
exploits or runtime listeners. The 18 literal-reference files are a different set
and include documentation and source-pin records.

| Category | Reviewed examples | Migration treatment |
|---|---|---|
| Raw implementation and CLI | #458 `action`, `Broker`, `spawn_server`, `--mode broker`, worker and demo | Historical local-only entrypoints; no production approval |
| Direct listener callers | #459, #462, #463, #469, #470, #471; two `spawn_server` sites each | Preserve historical reproductions; remove from the future protected Native path |
| Direct raw DB operations | #479 adversarial bypass fixture; #480 signed gate invokes `legacy.action` after CAS | #479 is intentional negative evidence; #480 is an intermediate design, not the final migration target |
| Indirect Native dependencies | #465 through #463; #472/#473/#474/#476/#478/#480/#481 through earlier Native wrappers | Audit resolved call chains before declaring an entrypoint protected-only |
| Shared helpers / aliases | #481 uses `prior.legacy` for constants, serialization and `exchange` | Import or helper reuse alone does not start a listener; separate helpers in a future design |
| Frozen source identities | #460 contract; #463/#466/#468/#469/#470/#471/#472 source-pin records | Editing/deleting #458 may invalidate historical checks; do not silently rewrite pins |
| Tests | #458 raw protocol tests; #465 negative test; transitive test imports | Keep historical fixtures and new-path acceptance tests distinct |
| CI entrypoints | 18 dedicated workflow candidates in JSON; generic `.github/workflows/ci.yml` invokes repository-wide pytest | Text/path filters are not dispatch proof; generic collection is an additional route not counted among the 18 |

The #481 Native path uses **both** the new protected CAS and the old custody
pipeline. #471 uses #470's `ScopedNativeAttemptGate` for raw `consume`, attaches
the AEAD envelope through `self.broker.exchange`, and reads ciphertext after
restart. Removing the old listener without replacing these custody operations
would break the original-response encryption/recovery evidence.

## Proposed migration and acceptance criteria

1. Keep #458 and its historical offline tests frozen for reproducibility. Select
   one new Native entrypoint for migration; do not treat a repository-wide deletion
   as a substitute for protected execution.
2. Define a protected custody protocol covering consume, attach and read. Bind
   attachment/read access to the exact signed request, consumed receipt, recipient
   and ciphertext digest. Preserve unknown-after-consume behavior and no replay.
   #481 currently exposes a protected consume gate, not a replacement custody API.
3. Route the selected Native SDK/AEAD continuation to that protected custody
   component. Remove its transitive calls to #471's legacy start/restart path,
   while preserving the original SDK wire and unchanged local scorer provenance.
4. Verify the whole selected run, including descendants and restarts: collect
   startup/socket evidence; reject unexpected legacy entrypoints; test unsigned,
   wrong-request, wrong-receipt, tampered-envelope and replay cases. A parent-local
   monkeypatch or a single-directory socket listing is insufficient evidence.
5. Add a CI regression check for this **selected entrypoint**, with an explicit
   historical-fixture allowlist. Static inventories are supporting evidence only;
   unresolved dynamic calls must not be labeled safe. This PR does not install
   that enforcement or claim the migration has occurred.
6. Separately establish independent identity, protected credentials/storage,
   network denial and cross-Runner consumption before production claims. Even a
   legacy-free local run cannot establish these properties.

## Reproduce the source inventory

From the repository root:

```sh
python scripts/task4_legacy_broker_static_inventory_v1.py \
  --ref f20fdd26234116a4981a27b8ef5f00881e236bf0
```

The tool reads a local `git archive` into memory, parses Python ASTs without
importing target modules, inventories selected direct-call syntax, builds a
conservative import closure, and records text references. It performs no SDK,
Broker, Provider or workflow execution. Compare its JSON output with
`docs/TASK4_LEGACY_BROKER_STATIC_INVENTORY_V1.json`.

Limitations: alias analysis is syntactic and not scope-sensitive; the import
closure overapproximates execution. Reflection, dynamically constructed module
names, forwarded aliases and injected callbacks need manual review. Workflow
text matches include filters and do not establish actual runtime behavior.
All source hashes and line numbers refer to the frozen audited commit, not a
promise about future main. This is not a universal proof of Python reachability.

## Validation and claim boundary

The frozen inventory was generated locally and checked against independent text
search and manual inspection of the #481 → #473 → #472 → #471 → #458 chain.
Existing execution code, workflows, source pins, secrets and environment settings
are unchanged. No new runtime/Native tests or genuine Utility measurement are
claimed by this source-only audit. CI results, if any, must be reported separately
for the actual PR HEAD.

Issues #321 (Task4 consent/control requirements) and #427 (Task1 paid-dispatch
NO-GO record) were OPEN when reviewed; they are distinct scopes and this audit
does not resolve either. No paid Provider consent is granted. Independent IAM,
egress, protected durable CAS and production-wide bypass resistance remain
**NOT PROVEN**.
