#!/usr/bin/env python3
"""#308: OFFLINE atomic-consumption preflight for a PROPOSED future Task4 grant.

This is a standalone, fail-closed *simulation* of one-use admission. It binds
the exact #303 frozen issuer/wire, #307 proposed manifest, hypothetical #306
estimate, and a local SQLite transaction. All paths end with REAL_DISPATCH_DENIED.
NO live grant signer, new human consent, OpenAI client, Provider network,
secret loader, native VERITAS Bind, real bank, billing authorization or scorer.

SQLite's atomic transaction is local-only proof, NOT protected cross-run
production consumption nor adversarial immutable external evidence.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
from datetime import timezone
import json
import os
from pathlib import Path
import sqlite3
import tempfile

ROOT=Path(__file__).resolve().parents[1]
import sys
for p in (ROOT,ROOT/"scripts"):
    if str(p) not in sys.path:
        sys.path.insert(0,str(p))

from task4_prospective_model_wire_date_boundary_v1 import (
    ProspectiveWireBoundary, date_session, canonical, sha, MODEL, REQUEST,
)
from task4_future_provider_consent_evidence_default_deny_v1 import (
    proposed_manifest, ensure_no_live_context, future_live_dispatch_decision,
    evidence_promotion_decision, HISTORICAL_THIRD_CONSUMED,
)
from task4_future_provider_sdk_predispatch_mock_v1 import (
    strict_estimated_cost, MAX_INPUT_TOKENS_FIXTURE, MAX_OUTPUT_TOKENS,
    LOCAL_ESTIMATE_THRESHOLD, SDK_VERSION,
)

RULE="TASK4_FUTURE_PROVIDER_ATOMIC_ONEUSE_AUTHORIZATION_PREFLIGHT_OFFLINE_V1"
PARENT_MAIN="d76ba0a3539b2850367f6cb5e58e6128653351a5"
SOURCE="OFFLINE_SIMULATED_CONSENT_NOT_A_REAL_APPROVAL"
OFFLINE_ACK_KIND="OFFLINE_CONSENT_CHECK_ONLY_NO_AUTHORIZATION"
ZERO_POSTS=0

class Rejected(ValueError):
    pass

def need(ok,reason):
    if not ok:
        raise Rejected(reason)

def plan_from(boundary):
    need(type(boundary) is ProspectiveWireBoundary and
         boundary.phase=="FROZEN_NOT_DISPATCHABLE" and
         boundary.context is not None,
         "FRESH_FROZEN_ISSUER_CONTEXT_REQUIRED")
    old=proposed_manifest(boundary)
    estimated=strict_estimated_cost(MAX_INPUT_TOKENS_FIXTURE,MAX_OUTPUT_TOKENS)
    need(estimated<=LOCAL_ESTIMATE_THRESHOLD,"STATIC_COST_PREDICATE_FAILED")
    plan={
      "schema":"veritas.task4.future-provider-atomic-preflight.v1",
      "rule_of_one":RULE,
      "source":SOURCE,
      "main_parent":PARENT_MAIN,
      "previous_plan_sha256":sha(old),
      "old_provider_consent_consumed_sha":HISTORICAL_THIRD_CONSUMED,
      "benchmark_scope":old["target"],
      "original_request_sha256":sha(REQUEST),
      "issuer_context_sha256":boundary.context.digest,
      "immutable_wire_sha256":sha(json.loads(boundary.wire_bytes)),
      "model":MODEL,
      "sdk_version_not_loaded":SDK_VERSION,
      "proposed_call_count_not_allowed":1,
      "output_token_ceiling":MAX_OUTPUT_TOKENS,
      "hypothetical_input_token_ceiling":MAX_INPUT_TOKENS_FIXTURE,
      "estimated_spend_usd_historical_not_invoice":str(estimated),
      "local_estimate_threshold_usd_not_billing_cap":str(LOCAL_ESTIMATE_THRESHOLD),
      "live_provider_posts_authorized":ZERO_POSTS,
      "new_human_consent_issued":False,
      "production_grant_issued":False,
      "production_secret_exposed":False,
      "real_provider_response_authenticated":False,
      "native_bind_authorized":False,
      "bank_action_authorized":False,
      "mock_only":True,
    }
    need(old["live_decision"]=="DENY" and
         old["allowed_real_provider_posts"]==0 and
         old["old_real_provider_third_authorization_consumed_sha"]==
         HISTORICAL_THIRD_CONSUMED,"PARENT_DEFAULT_DENY_SCOPE_CHANGED")
    return plan

def planned_mock_ack(plan):
    """Plain local data, neither a real human's approval nor a signed permit."""
    return {
      "kind":OFFLINE_ACK_KIND,
      "proposal_sha256":sha(plan),
      "issued_context_sha256":plan["issuer_context_sha256"],
      "wire_sha256":plan["immutable_wire_sha256"],
      "case_id":plan["benchmark_scope"],
      "model":plan["model"],
      "proposed_call_count_not_allowed":1,
      "historical_estimate_not_billing_cap":plan["estimated_spend_usd_historical_not_invoice"],
      "real_execution_authorized":False,
      "server_request_id":None,
    }

def always_deny_real_api(_plan=None,_mock_ack=None,_receipt=None):
    return {
        "decision":"DENY",
        "reason":"NO_FRESH_EXPLICIT_HUMAN_CONSENT_OR_PROTECTED_PRODUCTION_SINGLE_USE_GRANT",
        "provider_posts_possible_through_308":False,
        "authorized_real_calls":0,
        "native_bank_actions_authorized":False,
    }

def _db_open(db_path):
    path=Path(db_path)
    need(path.parent.is_dir(),"LOCAL_REHEARSAL_DB_PARENT_REQUIRED")
    conn=sqlite3.connect(str(path),timeout=6.0,isolation_level=None)
    conn.execute("PRAGMA busy_timeout=6000")
    conn.execute("PRAGMA synchronous=FULL")
    conn.execute("""CREATE TABLE IF NOT EXISTS local_rehearsals(
        slot_id TEXT PRIMARY KEY,
        proposal_sha256 TEXT NOT NULL,
        state TEXT NOT NULL,
        first_event TEXT NOT NULL,
        terminal_event TEXT,
        response_sha256 TEXT,
        record_sha256 TEXT)""")
    return conn

class OfflineSingleUseAdmission:
    def __init__(self, *, db_path, boundary=None):
        self.boundary=boundary or ProspectiveWireBoundary(date_session())
        if boundary is None:
            self.boundary.issue_and_freeze()
        self.plan=plan_from(self.boundary)
        self.plan_bytes=canonical(self.plan)
        self.ack=planned_mock_ack(self.plan)
        self.db_path=Path(db_path)
        self.slot="offline-consumption-308-"+sha({
            "plan_sha256":sha(self.plan),
            "context_sha256":self.boundary.context.digest})[:40]
        self.attempted=False

    def attempt_once(self, *, offered_plan=None, offered_ack=None,
                     fail_after_consume=False, before_terminal_failure=False):
        need(not self.attempted,"IN_PROCESS_SIMULATION_ALREADY_ATTEMPTED")
        self.attempted=True
        plan_sha=sha(self.plan)
        conn=_db_open(self.db_path)
        try:
            try:
                conn.execute("BEGIN IMMEDIATE")
                conn.execute("""INSERT INTO local_rehearsals
                    (slot_id,proposal_sha256,state,first_event)
                    VALUES (?,?,?,?)""",
                    (self.slot,plan_sha,"CONSUMED_BEFORE_VALIDATION",
                     "OFFLINE_SLOT_ATOMICALLY_CONSUMED_NO_PROVIDER"))
                conn.commit()
            except sqlite3.IntegrityError as exc:
                conn.rollback()
                raise Rejected("ALREADY_CONSUMED_ATOMIC_LOCAL_SLOT_NO_RETRY") from exc

            state="UNKNOWN_CONSUMED_NO_RETRY"
            terminal="UNKNOWN_OFFLINE_STOP_NEVER_RETRY"
            response_sha=None
            try:
                ensure_no_live_context()
                check=self.plan if offered_plan is None else offered_plan
                ack=self.ack if offered_ack is None else offered_ack
                need(type(check) is dict and canonical(check)==self.plan_bytes and
                     canonical(self.plan)==self.plan_bytes,
                     "EXACT_PROPOSED_SCOPE_OR_BUDGET_DRIFT")
                need(type(ack) is dict and canonical(ack)==canonical(self.ack) and
                     ack["kind"]==OFFLINE_ACK_KIND and
                     ack["real_execution_authorized"] is False and
                     ack["server_request_id"] is None,
                     "FORGED_MOCK_CONSENT_CANNOT_BECOME_REAL_APPROVAL")
                need(check["live_provider_posts_authorized"]==0 and
                     check["new_human_consent_issued"] is False and
                     check["production_grant_issued"] is False and
                     check["mock_only"] is True,
                     "NO_REAL_GRANT_POSSIBLE")
                self.boundary._verify_wire(json.loads(self.boundary.wire_bytes))
                need(check["issuer_context_sha256"]==self.boundary.context.digest and
                     check["immutable_wire_sha256"]==sha(json.loads(self.boundary.wire_bytes)) and
                     check["model"]==MODEL and
                     check["old_provider_consent_consumed_sha"]==
                     HISTORICAL_THIRD_CONSUMED,
                     "TRUSTED_SCOPE_OR_OLD_CONSUMPTION_CHANGED")
                cost=strict_estimated_cost(
                    check["hypothetical_input_token_ceiling"],
                    check["output_token_ceiling"])
                need(str(cost)==check["estimated_spend_usd_historical_not_invoice"] and
                     check["local_estimate_threshold_usd_not_billing_cap"]==
                     str(LOCAL_ESTIMATE_THRESHOLD),
                     "ESTIMATE_OR_SPEND_PROFILE_CHANGED")
                need(always_deny_real_api(check,ack)["decision"]=="DENY" and
                     future_live_dispatch_decision(check,ack)["decision"]=="DENY" and
                     evidence_promotion_decision()["decision"]=="DENY",
                     "LIVE_PROVIDER_DISPATCH_MUST_REMAIN_DENIED")
                need(not fail_after_consume, "SYNTHETIC_UNKNOWN_AFTER_CONSUMPTION")
                # This is a synthetic internal validation receipt, not a model
                # response and not proof of any permission or Provider origin.
                receipt={
                  "source":SOURCE,"slot_id":self.slot,"plan_sha256":plan_sha,
                  "fake_consent_ack_sha256":sha(ack),
                  "issuer_context_sha256":self.boundary.context.digest,
                  "frozen_wire_sha256":sha(json.loads(self.boundary.wire_bytes)),
                  "provider_posts":0,"bank_effects":0,"native_bind_calls":0,
                  "future_live_dispatch_decision":"DENY",
                  "future_scoring_permitted":False,
                  "mock_consumed_before_any_remote_effect":True,
                }
                response_sha=sha(receipt)
                need(not before_terminal_failure,"SYNTHETIC_UNKNOWN_BEFORE_TERMINAL")
                state="OFFLINE_VALIDATED_REAL_DISPATCH_STILL_DENIED"
                terminal="ATOMIC_REHEARSAL_VERIFIED_NO_PROVIDER_POST"
            except BaseException:
                raise
            finally:
                record={
                    "slot_id":self.slot,"proposal_sha256":plan_sha,
                    "state":state,
                    "first_event":"OFFLINE_SLOT_ATOMICALLY_CONSUMED_NO_PROVIDER",
                    "terminal_event":terminal,"response_sha256":response_sha,
                }
                record_hash=sha(record)
                conn.execute("BEGIN IMMEDIATE")
                result=conn.execute("""UPDATE local_rehearsals
                      SET state=?,terminal_event=?,response_sha256=?,record_sha256=?
                      WHERE slot_id=? AND state='CONSUMED_BEFORE_VALIDATION'
                      AND proposal_sha256=?""",
                      (state,terminal,response_sha,record_hash,self.slot,plan_sha))
                need(result.rowcount==1,"ATOMIC_LEDGER_TRANSITION_LOST")
                conn.commit()
        finally:
            conn.close()
        return self.inspect()

    def inspect(self):
        conn=_db_open(self.db_path)
        try:
            rows=conn.execute("""SELECT slot_id,proposal_sha256,state,first_event,
                          terminal_event,response_sha256,record_sha256
                          FROM local_rehearsals WHERE slot_id=?""",(self.slot,)).fetchall()
        finally:
            conn.close()
        need(len(rows)==1,"LOCAL_CONSUMPTION_EVIDENCE_NOT_UNIQUE")
        names=("slot_id","proposal_sha256","state","first_event",
               "terminal_event","response_sha256","record_sha256")
        row=dict(zip(names,rows[0]))
        recorded_hash=row.pop("record_sha256")
        if row["state"]=="CONSUMED_BEFORE_VALIDATION":
            need(recorded_hash is None and row["terminal_event"] is None,
                 "PENDING_CONSUMPTION_CANNOT_PROVE_VALIDATION")
            status="CONSUMED_PENDING_NEVER_RETRY"
        else:
            need(sha(row)==recorded_hash and
                 row["proposal_sha256"]==sha(self.plan) and
                 row["first_event"]=="OFFLINE_SLOT_ATOMICALLY_CONSUMED_NO_PROVIDER" and
                 row["state"] in (
                     "OFFLINE_VALIDATED_REAL_DISPATCH_STILL_DENIED",
                     "UNKNOWN_CONSUMED_NO_RETRY"),
                 "LOCAL_SIMULATION_RECORD_INTEGRITY_OR_SCOPE_INVALID")
            if row["state"]=="OFFLINE_VALIDATED_REAL_DISPATCH_STILL_DENIED":
                need(row["terminal_event"]=="ATOMIC_REHEARSAL_VERIFIED_NO_PROVIDER_POST" and
                     type(row["response_sha256"]) is str and len(row["response_sha256"])==64,
                     "SIMULATED_TERMINAL_RECEIPT_REQUIRED")
            else:
                need(row["terminal_event"]=="UNKNOWN_OFFLINE_STOP_NEVER_RETRY",
                     "UNKNOWN_MUST_REMAIN_NONRETRIABLE")
            status=row["state"]
        return {
          "local_state":status,"slot_sha256":sha(self.slot),
          "manifest_sha256":sha(self.plan),
          "sqlite_atomic_consumption":True,
          "local_receipt_digest":row["response_sha256"],
          "record_sha256":recorded_hash,
          "live_api_dispatch":"DENY","provider_calls":0,
          "bank_effects":0,"native_bind_calls":0,
          "protected_production_grant_created":False,
          "globally_durable_single_use_proven":False,
          "provider_origin_proven":False,
          "provider_billings_proven":False,
        }

def audit():
    ensure_no_live_context()
    with tempfile.TemporaryDirectory(prefix="task4-308-offline-") as temp:
        file=Path(temp)/"local-rehearsal-consumption.sqlite3"
        round_=OfflineSingleUseAdmission(db_path=file)
        positive=round_.attempt_once()
        need(positive["local_state"]==
             "OFFLINE_VALIDATED_REAL_DISPATCH_STILL_DENIED" and
             positive["provider_calls"]==0,
             "POSITIVE_OFFLINE_CONSUMPTION_NOT_COMPLETE")
        repeat=OfflineSingleUseAdmission(db_path=file,boundary=round_.boundary)
        denied=False
        try:
            repeat.attempt_once()
        except Rejected as e:
            denied=str(e)=="ALREADY_CONSUMED_ATOMIC_LOCAL_SLOT_NO_RETRY"
        need(denied and repeat.inspect()==positive,
             "RESTART_REPLAY_NOT_ATOMICALLY_REFUSED")
        return {
          "rule_of_one":RULE,
          "determination":"LOCAL_SQLITE_ATOMIC_SINGLE_USE_PREFLIGHT_PASS_REAL_DISPATCH_DEFAULT_DENY",
          "parent_main_sha":PARENT_MAIN,
          "slot_hash":positive["slot_sha256"],
          "manifest_sha256":positive["manifest_sha256"],
          "receipt_sha256":positive["local_receipt_digest"],
          "old_real_provider_consent_consumed_sha":HISTORICAL_THIRD_CONSUMED,
          "new_human_approval_issued":False,
          "mock_ack_is_real_human_consent":False,
          "no_live_Provider_client_constructed":True,
          "offline_sqlite_atomic_consumption":True,
          "local_restart_replay_refused":denied,
          "live_api_post_count":0,
          "real_bank_effect_count":0,
          "actual_native_bind_adjudications":0,
          "official_task4_scorer_calls":0,
          "final128_calls":0,
          "real_model_utility_proven":False,
          "global_protected_consumption_proven":False,
          "tamper_evident_external_evidence_proven":False,
          "production_authority_proven":False,
          "local_record":positive,
          "future_live_execution":always_deny_real_api(),
          "limitations":"No human approval, live Provider sender, project spend hard cap, network, actual model response, external protected grant, distributed global single use, independent tamper-proof audit, real native Bind, bank action, Final128 scoring, or production authority. SQLite is local isolated rehearsal only.",
        }

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--output",type=Path,required=True)
    args=p.parse_args()
    a=audit()
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(a,sort_keys=True,indent=2)+"\n")
    print("TASK4_FUTURE_PROVIDER_SQLITE_ATOMIC_ONEUSE_PREFLIGHT_LOCAL_PASS_NO_API")

if __name__=="__main__":
    main()
