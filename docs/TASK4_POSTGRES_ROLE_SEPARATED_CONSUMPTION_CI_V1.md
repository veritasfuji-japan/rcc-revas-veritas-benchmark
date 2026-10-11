# PR #310 — PostgreSQL role-separated atomic grant consumption (CI-only)

**What advances:** #308 established local SQLite contention resistance.
#310 moves that central invariant to a **real PostgreSQL 16 server**
running inside an isolated GitHub Actions service container, and uses
*separate database login roles* to isolate issuer and consumer rights.

The exact single-row SQL \`UPDATE ... WHERE state='ISSUED_FIXTURE_ONLY'\`
is atomic across separate PostgreSQL sessions: after a winning transaction
commits, a competing session cannot consume that same row, including a
later connection. The database schema also checks model, case, issuer-context
digest, original frozen wire digest, expected cost, one-use ceiling, and
server-side expiry; the caller cannot select, update or insert directly
as the consumer role. A fixture issuer can INSERT but cannot read, modify
or call the consumer function.

**Limits:** The roles and passwords are *published test fixtures*
created in a disposable CI database. They are not real production
credentials or genuine human approval. A PostgreSQL owner/admin can
alter the table; no externally administered trust boundary, HA/replica
consistency, backups, privilege monitoring or cross-run protected access
has been proven. The service image uses a tag, not a digest-pinned image.
This implementation has no outbound Provider client or bank effects.

## Exact executable CI proof

The dedicated job starts PostgreSQL 16.6 on loopback, installs pinned
\`psycopg[binary]\` and pytest, creates the issuer and consumer fixture
roles, and tests:

- 16 independent database sessions: exactly 1 commits the consumption,
  15 fail to consume, and later sessions cannot reuse the grant
- consumer \`SELECT\`, \`INSERT\`, \`UPDATE\` and \`DELETE\` forbidden;
  issuer cannot \`SELECT\`, \`UPDATE\`, \`DELETE\`, or invoke the
  single-use function; PUBLIC \`EXECUTE\` denied
- exact case/context/wire/model/cost fields, expiry, and attempt ID;
  tampered requests and expired grants cannot be consumed
- transaction rollback **does not** commit a grant. This demonstrates
  the production obligation: egress must remain forbidden until
  independent durable COMMIT acknowledgement is received.
- zero live Provider credentials, Provider POSTs, real bank writes,
  native VERITAS Bind decisions, or official benchmark scores

Parent main: \`cdcb5672e82f1c2109adff3bd9ae5404451d5359\`.
#309, #308 and #303 are pinned at exact Git blob identities; the
previous third-round Provider consent remains permanently consumed.

## Concrete production boundary still missing

**Do not infer production readiness from this CI proof.**
A real implementation needs an independently administered protected
PostgreSQL instance and unforgeable issuer, KMS/service-backed
authorization, cross-run identity and per-run credential isolation,
auditable one-use creation, committed consume receipt, network egress
restricted to a separately approved sender, no retries after unknown
remote state, real account/billing controls, new explicit human consent,
real Provider provenance, and native Bind/effect reconciliation.

A PostgreSQL function cannot itself commit a caller's outer transaction:
production policy must require a separately committed consume receipt
before a credentialed network POST. This PR does not implement that
credentialed sender or any live authorization route.

**No real API call. No newly issued live approval. No paid action.**
Merging a green Draft cannot change that. Audit full CI and artifacts
before user-directed merge.
