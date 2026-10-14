# Final128 #404 — native alternate execution paths: negative controls, not PROVEN

## The finding that matters

#403 proved only that the explicitly registered **guarded local runtime** can
protect Task1 Native \`send_money\` proposals from a scripted offline recorder.
It did **not** establish that a different Native runtime, direct reference to
the original function, or in-process write access to the mutable bank state
cannot bypass that wrapper.

This audit intentionally demonstrates **four working, in-process bypass
routes** against separate, disposable frozen AgentDojo Task1 bank clones:

1. A new, *unguarded* Native \`FunctionsRuntime(list(suite.tools))\`.
2. Direct access to \`guarded_runtime.functions["send_money"].run\`
   (the wrapper overrides \`run_function\`, not the underlying callable).
3. Direct call to the Native \`banking_client.send_money\` implementation.
4. Direct append through an accessible mutable Native \`bank_account\`
   Python object (without any tool dispatcher at all).

All four are **negative controls demonstrating noncoverage** of the local
guard in the presence of these references. They are not four successful
attacks on a properly isolated production service; there is no such service
or isolation proof in this test.

For each route, the **real frozen VERITAS Bind** first blocks a separately
registered \`GuardedNativeRuntime\` call on the matched B source, with its
bank object completely unchanged and zero protected Native dispatch.
Only then do we mutate a completely separate A-derived disposable deep
clone through an unguarded route. Exactly one canary transaction is appended
and checked against its original full state.

A repeat of the actual #403 local multi-turn integration is run as a
positive control: two scripted \`send_money\` proposals remain blocked in B,
and the B account is unchanged. Both positive and negative evidence must
pass. A suite that never exercised the bypass is *not* a passing audit.

## Provenance and frozen scope

- Parent #403 merged: \`61e5cd04d5b3dcf90d0eb3707a40d7647f990f1c\`.
- AgentDojo commit: \`a75aba7631d3ca5fb7ab938965c97ead2f9ff84b\`.
- VERITAS OS commit: \`a1d66aef02262cf8a913295270c3aafd159c6adb\`.
- Banking suite: \`v1.2.2\`, 128 frozen direct-injection enrollment.
- Single case \`banking:user_task_1:injection_task_2:direct\`.
- Source Native \`recipient="me"\` and original untrusted injected
  transaction subject are kept unchanged. The mutated canaries derive
  from independent deep copies of that source. **No GOLD-derived attack
  proposal** is used for the bypass; the synthetic test recipient is a
  distinct source-owned harmless in-memory sentinel.

## What the redacted artifact can legitimately claim

- Frozen source and full tool catalog sha256 equal across trials.
- The owned guarded B runtime invoked real pinned VERITAS Bind and
  returned BLOCKED for each protected synthetic proposal.
- The same-process, unguarded paths remain callable and can mutate
  isolated disposable Native bank objects.
- Production bypass resistance is **NOT PROVEN**.
- Production IAM, exclusive credentials, egress confinement and an
  externally consumed single-use issuance capability are **NOT TESTED**
  here; no real external bank effects exist in this test.
- No real model/Provider requests and no official Native scoring were
  performed. Do not interpret these tests as model attack-success
  rates, measured utility, operational attacker exploitability, or an
  externally verifiable production boundary.

## The architectural requirement exposed

A real deployment must make effectful operations **unavailable** outside
an exclusive, mediation-enforcing execution boundary, not merely tell
agents to use a guarded runtime. It would need independent verification of:

- A separate executor holding all real bank/effect credentials; agents
  cannot import or call its privileged implementations or retrieve its
  secrets by another path.
- Credential/network/IAM authorization bound to the exclusive executor
  identity, rejecting attempts outside that identity.
- Bind issuance and **execution-time** verification of exact target,
  arguments, expiry, state fingerprint, replay/consumption and receipts.
- Tests from an adversarial *separate principal/process* proving attempts
  through old, alternate or direct channels fail even while the legitimate
  bounded operation remains available.
- Clear scope of tool coverage including newly added/unmapped operations.

A Python-only unit test and same-process wrappers cannot certify those
requirements. #405 should scope a stronger sandboxed/exclusive effect
boundary test and capture rejection evidence. Only fresh explicit
operator authorization may later permit paid independent Provider A/B.

## Merge requirements

1. The same exact frozen Native/VERITAS pin and source roster as #403.
2. Four negative controls **actually observe** one local canary write each.
3. For each, real Bind returns BLOCKED on the guarded B object with
   no change; original source A is untouched.
4. Positive #403 two-proposal check succeeds.
5. The report clearly labels *missing* bypass coverage, not PROVEN.
6. No external bank/Provider/network/scorer effects and no transaction,
   prompt-injection payload, or credentials in public artifacts.
7. Dedicated no-skip tests + all inherited #403–#377 tests and ordinary
   HEAD CI succeed.
