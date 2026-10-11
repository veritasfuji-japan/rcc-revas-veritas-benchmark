-- #311: CI-ONLY transactional consume+receipt; NEVER production permission.
-- Requires unchanged #310 PostgreSQL schema loaded first.
-- All credentials below are disposable, public CI fixtures.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles
                 WHERE rolname = 'task4_311_fixture_consumer') THEN
    CREATE ROLE task4_311_fixture_consumer LOGIN PASSWORD 'task4-311-consumer-ci-only';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles
                 WHERE rolname = 'task4_311_fixture_handoff') THEN
    CREATE ROLE task4_311_fixture_handoff LOGIN PASSWORD 'task4-311-handoff-ci-only';
  END IF;
END $$;

CREATE SCHEMA task4_311 AUTHORIZATION postgres;
REVOKE ALL ON SCHEMA task4_311 FROM PUBLIC;
GRANT USAGE ON SCHEMA task4_311
  TO task4_311_fixture_consumer, task4_311_fixture_handoff;

CREATE TABLE task4_311.offline_committed_receipts (
  grant_id text PRIMARY KEY REFERENCES task4_310.offline_fixture_grants(grant_id),
  attempt_id text UNIQUE NOT NULL,
  case_id text NOT NULL,
  issuer_context_sha256 text NOT NULL,
  frozen_wire_sha256 text NOT NULL,
  model_id text NOT NULL,
  estimated_cost_usd numeric(12,8) NOT NULL,
  committed_state text NOT NULL DEFAULT 'CONSUMED_FIXTURE_ONLY'
      CHECK (committed_state = 'CONSUMED_FIXTURE_ONLY'),
  db_consumed_at timestamptz NOT NULL,
  receipt_sha256 text NOT NULL CHECK (receipt_sha256 ~ '^[a-f0-9]{64}$')
);
REVOKE ALL ON task4_311.offline_committed_receipts FROM PUBLIC;
REVOKE ALL ON task4_311.offline_committed_receipts
  FROM task4_310_fixture_issuer,task4_310_fixture_consumer,
       task4_311_fixture_consumer,task4_311_fixture_handoff;

-- In this separate EPHEMERAL CI database, close the older #310
-- consume-without-receipt entrypoint. Parent source is unchanged.
REVOKE EXECUTE ON FUNCTION task4_310.consume_offline_fixture_once(
  text,text,text,text,text,numeric,text) FROM task4_310_fixture_consumer;

-- One SQL statement: atomic UPDATE of the grant AND INSERT of receipt.
-- Nothing can be observed across independent sessions before the
-- caller COMMITs. A successful function result INSIDE an uncommitted
-- transaction is NOT evidence of committed consumption.
CREATE FUNCTION task4_311.consume_and_record_fixture_once(
  p_grant_id text,
  p_case_id text,
  p_context_sha256 text,
  p_wire_sha256 text,
  p_model_id text,
  p_cost_usd numeric,
  p_attempt_id text
) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog
AS $BODY$
DECLARE
  affected integer;
BEGIN
  IF p_grant_id IS NULL OR length(p_grant_id)<12
     OR p_attempt_id IS NULL OR length(p_attempt_id)<12
     OR p_case_id IS NULL OR p_context_sha256 IS NULL
     OR p_wire_sha256 IS NULL OR p_model_id IS NULL
     OR p_cost_usd IS NULL THEN
    RETURN false;
  END IF;
  WITH changed AS (
    UPDATE task4_310.offline_fixture_grants
    SET state='CONSUMED_FIXTURE_ONLY',
        consumed_at=statement_timestamp(),
        attempt_id=p_attempt_id
    WHERE grant_id=p_grant_id
      AND case_id=p_case_id
      AND issuer_context_sha256=p_context_sha256
      AND frozen_wire_sha256=p_wire_sha256
      AND model_id=p_model_id
      AND expected_cost_usd=p_cost_usd
      AND max_calls=1
      AND attempt_id IS NULL
      AND state='ISSUED_FIXTURE_ONLY'
      AND expires_at>statement_timestamp()
    RETURNING grant_id,attempt_id,case_id,issuer_context_sha256,
              frozen_wire_sha256,model_id,expected_cost_usd,consumed_at
  ), inserted AS (
    INSERT INTO task4_311.offline_committed_receipts(
      grant_id,attempt_id,case_id,issuer_context_sha256,
      frozen_wire_sha256,model_id,estimated_cost_usd,
      db_consumed_at,receipt_sha256
    )
    SELECT grant_id,attempt_id,case_id,issuer_context_sha256,
           frozen_wire_sha256,model_id,expected_cost_usd,consumed_at,
      pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
        grant_id||'|'||attempt_id||'|'||case_id||'|'||
        issuer_context_sha256||'|'||frozen_wire_sha256||'|'||
        model_id||'|'||expected_cost_usd::text||'|'||
        consumed_at::text, 'UTF8')), 'hex')
    FROM changed
    RETURNING grant_id
  )
  SELECT COUNT(*) INTO affected FROM inserted;
  RETURN affected=1;
END $BODY$;
REVOKE ALL ON FUNCTION task4_311.consume_and_record_fixture_once(
  text,text,text,text,text,numeric,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION task4_311.consume_and_record_fixture_once(
  text,text,text,text,text,numeric,text) TO task4_311_fixture_consumer;

-- Separate handoff role sees only a boolean obtained from a separate
-- transaction/session with exact scope+attempt match and recomputed hash.
-- It has NO table access and cannot perform any external effect.
CREATE FUNCTION task4_311.verify_committed_fixture_receipt(
  p_grant_id text,
  p_case_id text,
  p_context_sha256 text,
  p_wire_sha256 text,
  p_model_id text,
  p_cost_usd numeric,
  p_attempt_id text
) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog
AS $BODY$
  SELECT EXISTS(
    SELECT 1 FROM task4_311.offline_committed_receipts AS r
    JOIN task4_310.offline_fixture_grants AS g ON g.grant_id=r.grant_id
    WHERE r.grant_id=p_grant_id
      AND r.attempt_id=p_attempt_id
      AND r.case_id=p_case_id
      AND r.issuer_context_sha256=p_context_sha256
      AND r.frozen_wire_sha256=p_wire_sha256
      AND r.model_id=p_model_id
      AND r.estimated_cost_usd=p_cost_usd
      AND r.committed_state='CONSUMED_FIXTURE_ONLY'
      AND g.state='CONSUMED_FIXTURE_ONLY'
      AND g.attempt_id=r.attempt_id
      AND g.consumed_at=r.db_consumed_at
      AND g.case_id=r.case_id
      AND g.issuer_context_sha256=r.issuer_context_sha256
      AND g.frozen_wire_sha256=r.frozen_wire_sha256
      AND g.model_id=r.model_id
      AND g.expected_cost_usd=r.estimated_cost_usd
      AND r.receipt_sha256=pg_catalog.encode(pg_catalog.sha256(
        pg_catalog.convert_to(r.grant_id||'|'||r.attempt_id||'|'||
        r.case_id||'|'||r.issuer_context_sha256||'|'||
        r.frozen_wire_sha256||'|'||r.model_id||'|'||
        r.estimated_cost_usd::text||'|'||r.db_consumed_at::text,
        'UTF8')), 'hex')
  )
$BODY$;
REVOKE ALL ON FUNCTION task4_311.verify_committed_fixture_receipt(
  text,text,text,text,text,numeric,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION task4_311.verify_committed_fixture_receipt(
  text,text,text,text,text,numeric,text) TO task4_311_fixture_handoff;
