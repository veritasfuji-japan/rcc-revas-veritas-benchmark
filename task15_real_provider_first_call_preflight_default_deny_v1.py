"""Non-executable first real OpenAI model response capture PRE-FLIGHT.

NO OpenAI API client, network, credential, spend permission, request dispatch,
native bank effect or model invocation exists here. A future operator approval
for an exact call is not inferred from a historic $5 cap or synthetic fixture.
Only the planned one-case, one-model, one-call *request source* is pinned.
"""
from __future__ import annotations
import copy
import hashlib
import json
from pathlib import Path
import sqlite3

RULE="TASK15_REAL_PROVIDER_FIRST_CALL_PREFLIGHT_DEFAULT_DENY_V1"
PREDECESSOR_MAIN="7fdfed5cf4d8b1302fc376d36d97b67089dcfa12"
CASE="banking:user_task_15:injection_task_0:direct"
ARM="A"
MODEL="gpt-4.1-mini-2025-04-14"
PROPOSED_MAX_COST_MICRO_USD=250_000 # NOT permission to spend ($0.25 proposed)
MAX_OUTPUT_TOKENS=256

class FirstCallPreflightDenied(ValueError):
    pass

def require(ok,reason):
    if not ok:raise FirstCallPreflightDenied(reason)

def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(",",":"),
                      ensure_ascii=False,allow_nan=False)

def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()

def hex64(value):
    return type(value) is str and len(value)==64 and all(
        x in "0123456789abcdef" for x in value)

def check_predecessors(sink_proof,durable_source):
    require(type(sink_proof) is dict and type(durable_source) is dict,
            "EXACT_FROZEN_PR274_AND_PR271_PROOF_REQUIRED")
    require(sink_proof.get("rule_of_one")==
                "TASK15_AUTHORITATIVE_MOCK_SIGNED_SINK_V1"
            and sink_proof.get("determination")==
                "SIGNED_MOCK_SINK_REFUSES_GENERIC_UNSIGNED_PROMOTION"
            and sink_proof.get("source_prior_sha256")==digest(durable_source)
            and sink_proof.get("live_provider_calls")==0
            and sink_proof.get("real_provider_authenticity_proven") is False
            and sink_proof.get("system_wide_bypass_resistance_proven") is False
            and len(sink_proof.get("cases",[]))==4,
            "EXACT_PR274_BOUNDED_OFFLINE_RESULT_REQUIRED")
    require(durable_source.get("processes_started")==16
            and durable_source.get("barrier_arrivals")==16
            and durable_source.get("successful_process_consumptions")==1
            and durable_source.get("refused_process_consumptions")==15
            and type(durable_source.get("plan")) is dict
            and type(durable_source.get("durable_state")) is dict,
            "EXACT_PR271_DURABLE_SOURCE_REQUIRED")
    plan=durable_source["plan"]
    state=durable_source["durable_state"]
    require(plan.get("rule_of_one")==
                "TASK15_PROVIDER_SINGLE_USE_REHEARSAL_DEFAULT_DENY_V1"
            and plan.get("case_id")==CASE
            and plan.get("arm")==ARM
            and plan.get("frozen_model_snapshot")==MODEL
            and plan.get("historical_ceiling_is_not_spend_permission") is True
            and plan.get("trusted_issuer_present") is False
            and plan.get("trusted_human_approval_attested") is False
            and plan.get("transport_adapter_present") is False
            and plan.get("live_provider_authority_issued") is False
            and plan.get("native_bank_execution_authority_issued") is False
            and state["records"][0]["plan_sha256"]==digest(plan)
            and state["records"][0]["claims"]==1
            and state["records"][0]["state"]=="CONSUMED_OFFLINE"
            and len(state["records"])==1,
            "ONLY_FROZEN_NO_AUTHORITY_PREDECESSOR_PLAN_PERMITTED")
    for key in ("source_request_sha256","source_tool_schemas_sha256",
                "source_user_message_sha256","predecessor_proof_sha256"):
        require(hex64(plan.get(key)),"FROZEN_EXACT_SOURCE_HASH_MISSING_"+key)
    require(type(plan.get("source_read_call_id")) is str
            and bool(plan["source_read_call_id"]),
            "FROZEN_NATIVE_READ_CALL_ID_REQUIRED")
    return copy.deepcopy(plan)

def proposed_request_manifest(sink_proof,durable_source,*,model=MODEL,
                              case_id=CASE,arm=ARM,max_output_tokens=256,
                              proposed_cost_microusd=PROPOSED_MAX_COST_MICRO_USD,
                              provider="openai",operator_approval=None,
                              provider_credential=None,transport=None):
    prior=check_predecessors(sink_proof,durable_source)
    require(model==MODEL and case_id==CASE and arm==ARM and provider=="openai",
            "MODEL_CASE_ARM_PROVIDER_DRIFT")
    require(type(max_output_tokens) is int and max_output_tokens==MAX_OUTPUT_TOKENS
            and type(proposed_cost_microusd) is int
            and proposed_cost_microusd==PROPOSED_MAX_COST_MICRO_USD,
            "PROPOSED_LIMIT_OR_TOKEN_PROFILE_DRIFT")
    require(operator_approval is None and provider_credential is None
            and transport is None,
            "APPROVAL_CREDENTIAL_OR_TRANSPORT_NOT_ADMITTED_TO_OFFLINE_PROOF")
    source_sha=digest(prior)
    predecessor_sha=digest(sink_proof)
    return {
        "rule_of_one":RULE,
        "kind":"NON_EXECUTABLE_ONE_CALL_SOURCE_PREFLIGHT",
        "first_case_id":CASE,"first_arm":ARM,
        "provider_name":"openai","exact_model_snapshot":MODEL,
        "model_aliasing_allowed":False,
        "source_plan_sha256":source_sha,
        "source_pr271_evidence_sha256":digest(durable_source),
        "source_pr274_evidence_sha256":predecessor_sha,
        "source_request_sha256":prior["source_request_sha256"],
        "source_tool_schemas_sha256":prior["source_tool_schemas_sha256"],
        "source_user_message_sha256":prior["source_user_message_sha256"],
        "native_read_call_id":prior["source_read_call_id"],
        "requested_model_call_limit":1,
        "proposed_max_output_tokens":MAX_OUTPUT_TOKENS,
        "proposed_cost_ceiling_micro_usd":PROPOSED_MAX_COST_MICRO_USD,
        "cost_ceiling_authorizes_spend":False,
        "historical_five_dollars_authorizes_spend":False,
        "trusted_issuer_present":False,
        "operator_approval_attested":False,
        "provider_api_credential_present":False,
        "provider_transport_present":False,
        "live_provider_execution_authority_issued":False,
        "bank_write_capability_present":False,
        "native_effect_dispatch_allowed":False,
        "network_connectivity_permitted":False,
        "provider_call_recorded":False,
        "provider_response_authenticated":False,
        "provider_response_id":None,
        "response_token_usage":None,
        "actual_provider_spend_usd":0,
        "external_effects":0,
    }

class OfflineFirstCallPreflight:
    """SQLite-sealed request manifest; emphatically never an API capability."""
    def __init__(self,path,manifest,*,create):
        require(type(manifest) is dict and
                manifest.get("rule_of_one")==RULE and
                manifest.get("kind")=="NON_EXECUTABLE_ONE_CALL_SOURCE_PREFLIGHT",
                "EXACT_NON_EXECUTABLE_MANIFEST_REQUIRED")
        require(manifest.get("provider_transport_present") is False
                and manifest.get("provider_api_credential_present") is False
                and manifest.get("operator_approval_attested") is False
                and manifest.get("live_provider_execution_authority_issued") is False
                and manifest.get("bank_write_capability_present") is False
                and manifest.get("cost_ceiling_authorizes_spend") is False
                and manifest.get("network_connectivity_permitted") is False
                and manifest.get("provider_response_id") is None
                and manifest.get("requested_model_call_limit")==1,
                "CANNOT_ISSUE_REAL_PROVIDER_AUTHORITY")
        self.path=Path(path)
        self.expected=copy.deepcopy(manifest)
        self.manifest_sha256=digest(manifest)
        if create:
            require(not self.path.exists() and self.path.parent.is_dir(),
                    "FRESH_SINGLE_USE_NONEXECUTABLE_MANIFEST_ONLY")
            conn=self._conn(create=True)
            try:
                conn.executescript("""
                    CREATE TABLE preflight(
                        request_id TEXT PRIMARY KEY,
                        manifest_sha256 TEXT NOT NULL,
                        manifest_json TEXT NOT NULL,
                        state TEXT NOT NULL CHECK(state='PREPARED_NO_EXECUTION'),
                        actual_call_count INTEGER NOT NULL CHECK(actual_call_count=0),
                        actual_spend_usd INTEGER NOT NULL CHECK(actual_spend_usd=0),
                        bank_effect_count INTEGER NOT NULL CHECK(bank_effect_count=0)
                    );
                    CREATE TABLE audit(seq INTEGER PRIMARY KEY AUTOINCREMENT,
                        event TEXT NOT NULL);
                """)
                conn.execute("BEGIN IMMEDIATE")
                conn.execute("INSERT INTO preflight VALUES"
                             "(?,?,?,'PREPARED_NO_EXECUTION',0,0,0)",
                             (self.manifest_sha256,self.manifest_sha256,
                              canonical(manifest)))
                conn.execute("INSERT INTO audit(event) VALUES"
                             "('EXACT_SOURCE_MANIFEST_SEALED_NO_AUTHORITY')")
                conn.execute("COMMIT")
            finally:conn.close()
        else:
            require(self.path.is_file(),"FROZEN_PREFLIGHT_LEDGER_MISSING")
        self.observation()

    def _conn(self,*,create=False):
        db=sqlite3.connect(self.path,timeout=20,isolation_level=None)
        if create:db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
        return db

    def observation(self):
        db=sqlite3.connect("file:"+str(self.path.resolve())+"?mode=ro",uri=True)
        try:
            rows=db.execute("SELECT request_id,manifest_sha256,manifest_json,"
                            "state,actual_call_count,actual_spend_usd,"
                            "bank_effect_count FROM preflight").fetchall()
            events=db.execute("SELECT event FROM audit ORDER BY seq").fetchall()
            integrity=db.execute("PRAGMA integrity_check").fetchone()[0]
        except (sqlite3.Error,ValueError) as exc:
            raise FirstCallPreflightDenied("PREFLIGHT_LEDGER_INVALID") from exc
        finally:db.close()
        require(integrity=="ok" and len(rows)==1
                and len(events)==1
                and events[0][0]=="EXACT_SOURCE_MANIFEST_SEALED_NO_AUTHORITY",
                "EXACT_ONE_UNEXECUTABLE_SOURCE_RECORD_AND_JOURNAL_REQUIRED")
        row=rows[0]
        require(row[0]==row[1]==self.manifest_sha256
                and row[2]==canonical(self.expected)
                and row[3]=="PREPARED_NO_EXECUTION"
                and row[4]==row[5]==row[6]==0,
                "MANIFEST_MUTATED_OR_LIVE_EFFECT_PROMOTED")
        return {
            "rule_of_one":RULE,"state":row[3],
            "request_id":row[0],"manifest_sha256":row[1],
            "manifest":copy.deepcopy(self.expected),
            "audit_events":[x[0] for x in events],
            "real_provider_calls":0,"real_provider_charges_usd":0,
            "real_bank_writes":0,"external_effects":0,
            "operator_approval_issued":False,
            "real_provider_transport_present":False,
            "model_response_authenticated":False,
            "executable":False,
        }

    def issue_live_provider_request(self,*,approved=None,key=None,client=None):
        del approved,key,client
        raise FirstCallPreflightDenied(
            "LIVE_PROVIDER_EXECUTION_MUST_USE_SEPARATE_APPROVED_PROOF_ROUND")

    def retry(self):
        raise FirstCallPreflightDenied(
            "NO_REAL_PROVIDER_REQUEST_EXISTS_AND_NO_RETRY_RIGHTS")

    def authorize_bank_write(self):
        raise FirstCallPreflightDenied("REAL_BANK_EFFECT_AUTHORITY_NEVER_ISSUED")
