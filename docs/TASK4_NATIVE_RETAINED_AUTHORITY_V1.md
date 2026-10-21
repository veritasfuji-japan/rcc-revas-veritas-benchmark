# Same-host retained Native bounded authority

This increment retains the #516 changing-history issuer and Custody ledgers under one active root enrollment. It prevents supported processes in the same enrolled Linux `/run` view from selecting a different directory or silently creating a replacement ledger. It adds no public Provider capability or paid permission.

## Explicit scope

Run only in a disposable Linux CI host with:

```sh
sudo python -m scripts.task4_native_os_custody_v1 \
  --run --local-https --raw-ingress success --bounded-native --retained-bounded \
  --output results/task4-native-retained-authority
```

Root exclusively creates `/run/veritas-task4-retained-bounded-v1/enrollment.json` before either service starts. The non-configurable discovery path identifies one active enrollment in that `/run` namespace. The enrollment binds the exact base directory identity, run ID, bounded-manifest digest, issuer public key, random enrollment nonce, and each role's private directory, SQLite file device/inode/owner/mode and signing-key identity/hash. A local root-owned marker joins this enrollment. Neither service accepts an alternate path, replacement database or signing key. Missing or corrupt discovery metadata is an error, including when the directory still exists but its anchor is absent; it never selects the old create-on-start behavior.

Trusted bootstrap initializes both empty private databases before root records their identities. After enrollment, issuer construction and every issuer database operation must reopen the registered file. Custody validates its registered database and retained run/manifest row before startup and validates the enrollment again at request dispatch. Normal startup, including startup without a restart flag, cannot regenerate storage under an active enrollment. Different working directories may refer to the same enrolled absolute file; they cannot select a different file. The generic low-level NativePolicy constructor also checks an active enrollment before create/open.

The existing #516 profile remains separate when no retained enrollment is active. No frozen source, scope, recipient manifest, README or old replay proof is relaxed. The global flag `cross_directory_reset_resistance_proven` in the existing normal report remains false: the new companion reports the narrower `same_enrolled_host_directory_reset_resistance` claim.

## Pending and completed issuer restarts

The actual pinned Native driver and pinned SDK produce the first Arm A request. The issuer durably reserves and signs its actual bytes. The preparation process stops before calling Custody, returning an SDK response, running a tool, or invoking a scorer. The signature and request are retained privately by the trusted runtime.

Root SIGKILLs the issuer. A fresh process opens the same registered key and policy file; the pending state is identical and issuance is refused. No new API post, raw ingress event or Custody consumption is created by this restart. A new actual Native process reproduces the exact first SDK bytes and uses the already reserved grant once. It does not obtain a replacement grant. Custody then consumes it, executes actual Bind, captures/seals the closed TLS response, and the normal authenticated history chain proceeds for all eight A/B requests.

After both arms reach TERMINAL, root SIGKILLs the issuer again. A third issuer process retains the same keys, exact terminal records, budgets and observations and refuses both fresh arm requests. Existing immediate and post-Custody-restart replay tests still produce zero additional sends. Two diagnostic Native scorers execute over synthetic model output; Utility remains UNSCORED.

## Failure evidence

Dedicated unit tests cover storage identities, key changes, changed working directories, constructor reinitialization, live-operation anchor revalidation and missing/corrupt enrollment. Unit fixtures inject a temporary locator and owner constant only in Python tests; there is no CLI override for either in the actual proof.

The integrated fixture invokes the same admission/load helpers used at service startup in fresh unprivileged role processes. Fourteen probes cover both issuer and Custody: missing database, in-place corruption, same-byte replacement with a different inode, symlink replacement, replacement signing key, missing anchor and corrupt anchor. Every invalid load is refused without repair or regeneration. The supervisor explicitly restores the exact original bytes and identities between probes; no automatic repair is claimed. Admission probes do not start a daemon or acquire new execution permission. API posts and raw events remain unchanged throughout these probes. Ordinary-agent private-key/peer denials and all #516 Bind/archive/Native joins remain required.

Only sanitized evidence and JUnit are uploaded. Database contents, keys, cached packets, raw responses and ciphertexts remain ephemeral. Evidence includes public metadata about private file paths/device/inode and signed grants, not private key material or plaintext history. The root supervisor reads synthetic state for fault injection and restoration and is trusted throughout.

## Remaining deployment work

This is **not cross-runner retention**. Each GitHub Actions job has its own disposable host and `/run` namespace. The fixture explicitly retires its enrollment during trusted root cleanup; a subsequent fixture is a new test enrollment. No claim is made about preserving an authorization run after that retirement, a fresh VM/mount namespace, host reboot, root compromise or privileged rollback of a valid same-inode database. Root can change code, registration or storage. The storage has no independent administrator, monotonic anti-rollback witness or distributed compare-and-swap service.

Before live research, a concrete deployment must provision retained authority outside disposable job workspaces, define who can enroll/retire runs and enforce the sender's credential/egress boundary. A future live recipient/secret lifecycle, current cost review and fresh owner consent also remain necessary. No Secrets, Rulesets, Environments, tags or real credentials are modified here.

`REAL_PROVIDER_NO_GO / UTILITY_UNSCORED / PRODUCTION_BYPASS_RESISTANCE_NOT_PROVEN`
