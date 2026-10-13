#!/usr/bin/env python3
"""Task4 #376: real front-agent HTTP→broker→pinned Native-v2 effect proof."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import sys
import xml.etree.ElementTree as ET

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from scripts.task4_375_native_v2_docker_network_audit_v1 import proof
from scripts.task4_376_native_v2_agent_ingress_v1 import ALLOWED, RULE, digest
from integration.current_veritas_uninterrupted.task4_374_native_v2_lineage import (
    verify_exact_native_v2_lineage,canonical_hash,
)

def file_hash(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--output-dir",type=Path,required=True)
    args=p.parse_args()
    out=args.output_dir.resolve()
    legacy=proof(out,agent_ingress=True)
    agent=legacy["task4_376_agent_ingress_evidence"]
    assert type(agent) is dict and agent["rule"]==RULE
    trace=legacy["positive_native_v2_trace"]
    checks_375=legacy["checks"]
    assert len(checks_375)==25 and all(checks_375.values())
    verified=verify_exact_native_v2_lineage(trace)
    receipt=agent["ingress_positive"]
    cases=agent["cases"]
    report=json.loads((out/"native-v2-authorized-lineage.json").read_text())
    checks={
        "preserves_existing_25_docker_native_v2_assertions":
            len(checks_375)==25 and all(checks_375.values()),
        "front_agent_client_unprivileged_no_backend_membership":
            any(role["role"]=="task4-376-front-client" and
                role["user"]=="65534:65534" and len(role["networks"])==1
                for role in legacy["roles"]),
        "exact_agent_origin_schema_and_request_digest":
            receipt["request_digest"]==digest(ALLOWED),
        "pre_execution_changed_event_denied":
            cases[0]["case"]=="changed_event" and cases[0]["http"]==403,
        "pre_execution_wrong_action_denied":
            cases[1]["case"]=="wrong_action" and cases[1]["http"]==403,
        "pre_execution_extra_authority_denied":
            cases[2]["case"]=="extra_authority" and cases[2]["http"]==403,
        "pre_execution_wrong_request_id_denied":
            cases[3]["case"]=="wrong_request" and cases[3]["http"]==403,
        "pre_execution_original_request_tamper_denied":
            all(x["http"]==403 for x in cases[4:6]),
        "malformed_json_and_media_type_denied":
            [x["http"] for x in cases[6:8]]==[400,415],
        "single_agent_post_reached_native_broker":
            cases[8]["case"]=="exact_approved_fixture" and cases[8]["http"]==200,
        "replay_after_effect_denied":
            cases[9]["case"]=="replay_after_commit" and cases[9]["http"]==409,
        "actual_input_is_native_candidate_not_internally_substituted":
            report["task4_376_input_candidate_sha256"]==
            trace["decision"]["candidate_sha256"]==receipt["candidate_sha256"],
        "exact_request_lineage_survives_native_verification":
            report["task4_376_ingress_request_digest"]==receipt["request_digest"]
            and report["task4_376_ingress_request_id"]==receipt["request_id"],
        "same_tls_target_real_postgres_one_effect":
            trace["authorization"]["target"]==receipt["target"]
            and trace["dispatch"]["send_calls"]==1
            and receipt["effect_count"]==1
            and trace["target_owned"]["state"]=="PERSISTED",
        "seven_exact_authorization_to_receipt_invariants":
            len(verified)==7 and all(verified.values())
            and receipt["trace_sha256"]==canonical_hash(trace),
        "real_tcp_bypass_and_no_credential_http_401_denied":
            legacy["probe_front"]["real_sink_ip_tcp_refused"] is True
            and legacy["probe_backend_without_credential"]["unauthenticated_direct_write_http_status"]==401,
        "no_real_provider_or_bank_effect":
            receipt["provider_calls"]==receipt["bank_effects"]==0
            and legacy["provider_spend_usd"]==0,
        "no_production_or_identity_authority_claim":
            report["task4_376_untrusted_request_is_execution_authority"] is False
            and legacy["actual_production_IAM_enforced"] is False
            and legacy["trusted_host_docker_administrator"] is True,
    }
    assert len(checks)==18 and all(checks.values()), checks
    evidence={
        "rule":RULE,"scope":"CONTROLLED_SYNTHETIC_INGRESS_NOT_PRODUCTION",
        "checks":checks,"checked_count":len(checks),
        "base_network_invariants":25,
        "source_sha":legacy["source_sha"],
        "veritas_pin":legacy["veritas_os_pin"],
        "ben_pin":legacy["ben_pin"],
        "approved_fixture_request_digest":receipt["request_digest"],
        "input_candidate_sha256":receipt["candidate_sha256"],
        "native_v2_trace_sha256":receipt["trace_sha256"],
        "broker_receipt":receipt,
        "agent_trials":cases,
        "real_provider_calls":0,"bank_effects":0,"spend_usd":0,
        "agent_authenticated_with_enterprise_identity":False,
        "preauthorized_synthetic_fixture_only":True,
        "production_IAM_enforced":False,
        "independent_external_validation":False,
        "source_hashes":{
            path:file_hash(ROOT/path) for path in (
                "scripts/task4_376_native_v2_agent_ingress_v1.py",
                "scripts/task4_376_native_v2_docker_ingress_audit_v1.py",
                "scripts/task4_375_native_v2_docker_network_audit_v1.py",
                "integration/current_veritas_uninterrupted/native_v2_action_capability.py",
                "docs/TASK4_376_NATIVE_V2_AGENT_HTTP_INGRESS_GATE_V1.md",
            )
        },
    }
    (out/"task4-376-native-v2-agent-http-ingress-evidence.json").write_text(
        json.dumps(evidence,sort_keys=True,indent=2)+"\n")
    suite=ET.Element("testsuite",name=RULE,tests=str(len(checks)),
                     failures="0",errors="0",skipped="0")
    for k in checks:
        ET.SubElement(suite,"testcase",classname=RULE,name=k)
    ET.ElementTree(suite).write(out/"task4-376-junit.xml",
                                encoding="utf-8",xml_declaration=True)
    print("TASK4_376_SYNTHETIC_AGENT_HTTP_TO_REAL_NATIVE_V2_18_OF_18_PASS")
    print("TASK4_375_NETWORK_AND_NATIVE_25_OF_25_STILL_PASS")
    print("DENY_BEFORE_EFFECT_SINGLE_TLS_COMMIT_REPLAY_DENIED_NOT_PRODUCTION_PROVEN")

if __name__=="__main__":
    main()
