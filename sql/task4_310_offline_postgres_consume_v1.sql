-- #310 PostgreSQL 16 CI-ONLY isolated Task4 grant-consumption prototype.
-- NEVER create these test roles/passwords in production.
-- This database function is NOT human approval, not a live permission, and
-- cannot emit an OpenAI request, bank mutation, real charge or native Bind call.
-- Demo ledger is persistent only inside one ephemeral CI Postgres instance.
DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname='task4_310_fixture_issuer') THEN
    CREATE ROLE task4_310_fixture_issuer LOGIN PASSWORD 'task4-310-issuer-ci-only';
  END IF;
  IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname='task4_310_fixture_consumer') THEN
    CREATE ROLE task4_310_fixture_consumer LOGIN PASSWORD 'task4-310-consumer-ci-only';
  END IF;
END
$$;
CREATE SCHEMA IF NOT EXISTS task4_310 AUTHORIZATION postgres;
REVOKE ALL ON SCHEMA task4_310 FROM PUBLIC;
GRANT USAGE ON SCHEMA task4_310 TO task4_310_fixture_issuer,task4_310_fixture_consumer;

CREATE TABLE IF NOT EXISTS task4_310.offline_fixture_grants(
  grant_id text PRIMARY KEY,
  case_id text NOT NULL,
  issuer_context_sha256 text NOT NULL CHECK (issuer_context_sha256 ~ '^[a-f0-9]{64}$'),
  frozen_wire_sha256 text NOT NULL CHECK (frozen_wire_sha256 ~ '^[a-f0-9]{64}$'),
  model_id text NOT NULL,
  expected_cost_usd numeric(12,8) NOT NULL CHECK (expected_cost_usd > 0 AND expected_cost_usd <= 0.005),
  max_calls integer NOT NULL CHECK (max_calls=1),
  expires_at timestamptz NOT NULL,
  issued_at timestamptz NOT NULL DEFAULT statement_timestamp(),
  consumed_at timestamptz,
  attempt_id text UNIQUE,
  state text NOT NULL DEFAULT 'ISSUED_FIXTURE_ONLY' CHECK
    (state IN ('ISSUED_FIXTURE_ONLY','CONSUMED_FIXTURE_ONLY')),
  CHECK (state = 'ISSUED_FIXTURE_ONLY' AND consumed_at IS NULL AND attempt_id IS NULL
       OR state = 'CONSUMED_FIXTURE_ONLY' AND consumed_at IS NOT NULL AND attempt_id IS NOT NULL)
);
REVOKE ALL ON task4_310.offline_fixture_grants FROM PUBLIC;
REVOKE ALL ON task4_310.offline_fixture_grants FROM task4_310_fixture_issuer;
REVOKE ALL ON task4_310.offline_fixture_grants FROM task4_310_fixture_consumer;
GRANT INSERT ON task4_310.offline_fixture_grants TO task4_310_fixture_issuer;

-- The trusted DB-owning fixture account can seed rows. A consumer role
-- can invoke exactly this conditional consume function, NOT read/modify the
-- table, issue grants, or acquire a Provider credential.
-- A successful result means ONLY "local test row atomically consumed".
CREATE OR REPLACE FUNCTION task4_310.consume_offline_fixture_once(
  p_grant_id text,
  p_case_id text,
  p_context_sha256 text,
  p_wire_sha256 text,
  p_model_id text,
  p_exact_estimated_cost_usd numeric,
  p_attempt_id text
) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog
AS $BODY$
DECLARE
  affected integer;
BEGIN
  IF p_grant_id IS NULL OR length(p_grant_id)<12 OR
     p_attempt_id IS NULL OR length(p_attempt_id)<12 OR
     p_case_id IS NULL OR p_context_sha256 IS NULL OR
     p_wire_sha256 IS NULL OR p_model_id IS NULL OR
     p_exact_estimated_cost_usd IS NULL THEN
    RETURN false;
  END IF;
  UPDATE task4_310.offline_fixture_grants
     SET state='CONSUMED_FIXTURE_ONLY',
         consumed_at=statement_timestamp(),attempt_id=p_attempt_id
   WHERE grant_id=p_grant_id
     AND case_id=p_case_id
     AND issuer_context_sha256=p_context_sha256
     AND frozen_wire_sha256=p_wire_sha256
     AND model_id=p_model_id
     AND expected_cost_usd=p_exact_estimated_cost_usd
     AND max_calls=1
     AND state='ISSUED_FIXTURE_ONLY'
     AND attempt_id IS NULL
     AND expires_at>statement_timestamp();
  GET DIAGNOSTICS affected=ROW_COUNT;
  RETURN affected=1;
END
$BODY$;
REVOKE ALL ON FUNCTION task4_310.consume_offline_fixture_once(
  text,text,text,text,text,numeric,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION task4_310.consume_offline_fixture_once(
  text,text,text,text,text,numeric,text) FROM task4_310_fixture_issuer;
GRANT EXECUTE ON FUNCTION task4_310.consume_offline_fixture_once(
  text,text,text,text,text,numeric,text) TO task4_310_fixture_consumer;
