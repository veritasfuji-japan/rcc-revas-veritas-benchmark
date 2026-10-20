# Separate synthetic issuer in the existing GitHub Actions proof

Current extension: [Bind Custody](CI_MOCK_BIND_CUSTODY_V1.md) moves the transport
credential, ledger and Bind execution out of the untrusted Executor into UID
61106. It requires 15 unit tests / 42 observations. The description below records
the earlier #493 boundary; the new extension narrows the trusted service but
does not prove resistance to a compromised Custody.

This extends #492's same-run real VERITAS Bind / mock effect proof. The existing
every-PR workflow now requires Ed25519 approval from UID 61105. The issuer runs
in the loopback-only agent namespace, with no capabilities or supplementary
groups, and actually fails to read both transport credential files. It generates
a fresh private key inside its own 0700 directory with a 0600 exclusive-create
file. No private key is returned to the supervisor or included in artifacts.

The trusted root supervisor enrolls the public key in a root-owned 0444 file
under a root-owned directory. Executor and backend each read that public key;
neither receives a shared approval-signing secret. Transport HMAC credentials
remain separate from the Ed25519 approval signature. Exact scope, operation,
target, request digest, unit and revision checks remain mandatory.

The agent and Executor each actually fail to read the issuer private key and
overwrite the enrolled public key. An Executor-UID probe uses its valid transport
credential but a grant signed by an attacker key: the backend must return 403
and authenticated backend state must remain zero. This probe happens before
the legitimate request. The backend independently verifies the issuer signature
before its SQLite transaction. Two backend denials (missing transport credential
and forged issuer signature) and exactly one effect are reconciled against the
Executor ledger. Existing Bind BLOCKED/BLOCKED/BLOCKED/COMMITTED receipts and
same-run/restart replay denials remain required.

The dedicated workflow requires 13 unit tests and 33 kernel/integration
observations, with zero skips, failures or errors, at the exact PR head.
Artifacts contain only sanitized observations, public-key fingerprint, source
hashes and synthetic Bind receipts; no signed packet or private credentials.

## Scope and limits

This proves signature forgery refusal under the enrolled key and the tested OS
file protections in a single trusted CI VM. Root, kernel, initial source and
key enrollment remain trusted. The issuer is a synthetic one-shot fixture, not
a real person's approval or independently administered approval service. Key
rotation, revocation, durable issuer state and distributed consumption are not
proved. The issuer and agent share a loopback-only network namespace but have
different UIDs; four authority-role UIDs and three network namespaces are checked.

The Executor remains trusted to invoke Bind. A compromised Executor already
holding an authentic unused grant and transport credential could submit that
approved request directly; the backend signature check does not independently
attest that Bind ran. Executor-owned ledger tampering is also outside this proof.
No production credential, real Provider request, bank operation, paid workflow,
Environment or repository administration setting is changed.

`REAL_PROVIDER_NO_GO / UTILITY_UNSCORED / PRODUCTION_BYPASS_RESISTANCE_NOT_PROVEN`
