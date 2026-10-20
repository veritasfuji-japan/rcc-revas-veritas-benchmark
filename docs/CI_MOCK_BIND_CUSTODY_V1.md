# Bind Custody outside the untrusted Executor

This supersedes #493's trust in the Executor invoking Bind. Within the existing
disposable GitHub Actions VM, UID 61102 now only forwards exact signed requests
from Agent UID 61101. UID 61106 (Bind Custody) owns the transport credential,
consumption ledger and real Bind adapter. Custody independently checks the
actual Unix peer UID and the issuer signature, consumes before effect, and calls
the fixed VERITAS Bind implementation. The sole effect POST is inside Bind.apply.
There is no supported no-Bind Custody mode: supervisor and Custody both fail
before provisioning/reading credentials when that mode is absent.

The host UID firewall permits backend TCP access only for Custody. The backend
requires both Custody's HMAC transport authentication and the issuer Ed25519
grant. The untrusted Executor has only the grant/public key; it cannot obtain
transport authority by supplying a caller-created Bind receipt.

## Required observations

The existing every-PR workflow requires 15 unit tests and 42 Linux/integration
observations, all passing with zero skips. Before the legitimate effect:

- An Executor-UID process validates the authentic grant and attempts HTTP from
  the host namespace; the installed UID firewall must deny network access.
- The trusted supervisor runs another Executor-UID probe in the backend network
  namespace, intentionally making the backend reachable. The authentic grant
  without Custody transport authentication must receive HTTP 403. This tests
  backend authorization separately from network denial; it does not represent
  an unprivileged process changing its own namespace.
- Executor actually fails to read Custody credential, ledger and evidence, and
  fails to overwrite the root-owned service and Bind adapter source files.
- Agent directly calling Custody is denied using kernel SO_PEERCRED. Executor
  sending an extra fabricated COMMITTED receipt is denied by exact packet checks.
- Existing missing-credential and attacker-signed grant probes run as Custody
  UID, deliberately isolating backend checks from the UID firewall. They must
  also receive 403. No real Provider endpoint is used.

Three backend denials and one effect must reconcile. The same Custody execution
must produce three real BLOCKED Bind receipts with zero apply calls and one
COMMITTED receipt with one apply call. Backend receipt, request digest and
Custody ledger must join. Replay is denied both before and after Custody restart
while the frontend Executor stays running. The issuer remains separate UID
61105, and the existing private-key and trust-file denials remain mandatory.

## Trust boundary

Five authority-role UIDs (Agent, Executor, issuer, Custody, backend) and three
network namespaces are checked. An additional stranger UID tests peer refusal.
The CI root/kernel, root-enrolled key, pinned sources, Custody and backend remain
trusted. This prevents the tested untrusted Executor from bypassing the trusted
Bind Custody; it does not protect against arbitrary malicious code already
running as UID 61106, which can read the transport credential. Custody-owned
ledger tampering, independent organizational administration, real owner approval,
distributed consumption and production-wide route coverage remain unproved.

This moves the trusted execution authority into a smaller separated service;
it does not cryptographically prove arbitrary remote Bind execution. No Native
Task4 production adapter, real Provider call, bank effect, paid workflow or
repository administration setting is introduced.

`REAL_PROVIDER_NO_GO / UTILITY_UNSCORED / PRODUCTION_BYPASS_RESISTANCE_NOT_PROVEN`
