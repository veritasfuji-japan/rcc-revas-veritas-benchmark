# Signed ledger in the actual closed-local Native/Bind path

`REAL_PROVIDER_NO_GO / UTILITY_UNSCORED / PRODUCTION_BYPASS_RESISTANCE_NOT_PROVEN`

This explicit disposable research profile connects the durable intent gate from
PR #535 to `NativePolicy.authorize` and the actual bounded Custody handler. It
does not migrate, restart or enroll the operator's `/opt` service or GitHub run.
Normal historical proof profiles remain separate and keep their existing tests.

## Ordering and authority

In an active root-enrolled signed-ledger profile, Native authorization holds the
existing SQLite write lock while checking the actual clock, exact SDK parameters,
observed history, parent, ordinal and byte budget. The gate independently fsyncs
an exclusive issuer attempt before a fresh signed view and reserve. It verifies
and fsyncs the original receipts, repeats admission using the current clock and
root enrollment, and only then invokes Native signing and its local DB update.
Returning a grant still requires successful local transaction completion.

Custody retains the existing authenticated runtime peer, issuer signature,
manifest/run/recipient/request/expiry checks and contiguous observed consumption
checks. Its independent gate records the complete grant's canonical digest and
exact supplied SDK bytes, validates and retains signed consume receipts, and
rechecks admission before committing local consumption. Only then does the
existing `bind_post` execute the actual VERITAS Bind and closed-local TLS request,
followed by the same raw archive, archive signature and Native observer chain.
Ledger views never replace signed archive/tool observations in `complete`.

The local Native DB and external ledger are not an atomic transaction. Losing
an acknowledgement can leave the external state committed while the Native DB
rolls back. The independent exclusive attempt remains burned. No resume, repair,
mutation retry or cached-grant recovery is allowed by this profile. An exception
after signing or Bind may follow an effect; missing `effect-returned.json` is
not evidence of zero effects. Availability is deliberately sacrificed when the
outcome is uncertain.

## Closed-local deployment

The explicit `--signed-ledger-native` proof requires `--bounded-native`,
`--retained-bounded`, `--local-https` and `--raw-ingress success`. Existing retained
Native enrollment pins the issuer/Custody DB and signing-key identities. A second
root anchor at `/run/veritas-task4-native-signed-ledger-v1` pins the base, retained
enrollment digest, six-field ledger binding, service public key and both role
journal identities. Its root-owned local marker is checked at every admission.
A present anchor or local marker requires successful validation; damaged or
missing counterparts cannot select the historical ungated profile. RPC/model
JSON cannot supply or omit the gate, role, endpoint or enrollment.

The explicit root fixture setup creates a fresh service key/database under UID
61109 and role journals under the existing issuer/Custody UIDs. This initialization
is restricted to the disposable proof; ordinary role startup reopens enrollment
and storage and does not recreate them. No live credentials are accepted.

The signed ledger uses the existing SQLite `ReferenceService` in its own UID and
isolated network namespace. Its AF_UNIX service authenticates issuer/Custody with
SO_PEERCRED and pins the one approved binding. Clients reciprocally require the
ledger UID and verify the separately enrolled Ed25519 receipt key. Untrusted
Native UID access to ledger files and the ledger command socket is tested.
This is **not** the deployed signed GitHub backend or its mTLS transport. The
model-side Native/Custody/Bind/raw-TLS/archive path remains the actual existing
closed-local path. The administrator and trusted role processes remain trusted;
same-UID malicious code, privileged rollback, independent administration,
cross-runner retention and production bypass resistance are not proved.

The old retained fixture's cached first grant is disabled in this new profile.
The new proof does not reinterpret that old recovery demonstration as permission
to resume an uncertain externally committed attempt.

## Verification

27 new tests call the actual Native authorization and extracted actual Custody
handler with real fsynced gate journals, real Ed25519 signatures and the SQLite
reference ledger. They cover ordering before signing/Bind, lost reserve/consume
acknowledgements, burned attempts after reopening, expiry after remote commit,
unavailable service, enrollment faults, Native grant/history rejection, receipt
write failure, withdrawn admission, no ledger-view history promotion, concurrent
issuers, and an actual Unix peer-UID refusal. Unit fixtures share the test UID,
substitute the deployment authority loader/ledger transport and stop at the Bind
call boundary; they do not establish the kernel/TLS/Native proof by themselves.

The existing mandatory Native CI workflow runs those 27 tests plus the 35 gate
tests with zero skips required. It then runs the new explicit profile on the
same frozen AgentDojo/RCC/VERITAS sources and existing isolated Native/Bind/TLS
fixture. The resulting `signed-ledger-integration.json` joins all 16 mutations,
32 original signed command receipts, eight exact Native requests/full grants,
eight actual Bind/TLS/archive chains, the two Native terminal/scorer traces,
private-key/peer denials and retained replay rejection. Ledger and issuer are
SIGKILLed and reopened with the same enrolled storage; Custody is also restarted.
The final signed view must remain revision 16 after all replay probes.

The proof artifacts are generated by CI and must be inspected before calling
this integration verified. This document describes required checks, not a
pre-existing CI result. A development host that prohibits Unix sockets cannot
run the kernel transport case; mandatory CI refuses a skipped test.

```sh
python -m pytest -q tests/test_task4_native_signed_ledger_integration_v1.py \
  tests/test_task4_native_signed_ledger_gate_v1.py
# Disposable root-capable Linux CI only, with the existing frozen _pins installed:
sudo -n "$(command -v python)" -m scripts.task4_native_os_custody_v1 \
  --run --local-https --raw-ingress success --bounded-native --retained-bounded \
  --signed-ledger-native --output results/task4-native-signed-ledger
```

Controlled acknowledgement loss in handler tests is distinguished from actual
network failure. The abrupt-exit gate tests remain process-exit evidence, not
power-loss evidence. Full Native runtime interruption during an in-flight
reserve/consume, or a deployed GitHub/mTLS migration, needs further separate
validation. No utility or production claim follows from scripted scorer calls.
