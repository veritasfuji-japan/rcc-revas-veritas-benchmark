#!/usr/bin/env python3
"""Versioned exact native address return, with frozen legacy proof chain intact."""
from __future__ import annotations
import argparse,hashlib,json,os,subprocess,sys,xml.etree.ElementTree as ET
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
RULE="TASK15_EXACT_NATIVE_ADDRESS_RETURN_CAPTURE_V1"
NAME="task15-exact-native-address-return-capture-v1"

def require(value,reason):
    if not value:raise ValueError(reason)

def blob(path):
    b=path.read_bytes()
    return hashlib.sha1(b"blob "+str(len(b)).encode()+b"\0"+b).hexdigest()

def main():
    ap=argparse.ArgumentParser()
    for name in ("agentdojo","rcc","veritas"):
        ap.add_argument("--"+name+"-root",type=Path,required=True)
    for name in ("replay-artifact","v13-artifact","output-dir"):
        ap.add_argument("--"+name,type=Path,required=True)
    cfg=ap.parse_args()
    require(not os.getenv("OPENAI_API_KEY") and not os.getenv("VERITAS_DATABASE_URL"),
            "PROVIDER_OR_DATABASE_CREDENTIAL_FORBIDDEN")
    c=json.loads((ROOT/"contracts"/(RULE+".json")).read_text())
    require(c["rule_of_one"]==RULE and
            c["status"]=="IMPLEMENTED_NOT_PROVEN_PENDING_EXACT_HEAD_CI",
            "FROZEN_NEW_ADDRESS_RETURN_CONTRACT_REQUIRED")
    for path,expected in c["source_blobs"].items():
        require(blob(ROOT/path)==expected,"SOURCE_PIN_CHANGED:"+path)
    out=cfg.output_dir.resolve();out.mkdir(parents=True,exist_ok=True)
    env=dict(os.environ,OPENAI_API_KEY="",VERITAS_DATABASE_URL="",
             PYTEST_DISABLE_PLUGIN_AUTOLOAD="1",PYTEST_ADDOPTS="")
    prior=[
        sys.executable,
        "scripts/task15_native_model_response_capture_boundary_audit_v1.py",
        "--agentdojo-root",str(cfg.agentdojo_root.resolve()),
        "--rcc-root",str(cfg.rcc_root.resolve()),
        "--veritas-root",str(cfg.veritas_root.resolve()),
        "--replay-artifact",str(cfg.replay_artifact.resolve()),
        "--v13-artifact",str(cfg.v13_artifact.resolve()),
        "--output-dir",str(out)]
    run=subprocess.run(prior,cwd=ROOT,env=env,capture_output=True,text=True)
    (out/(NAME+".predecessor.log")).write_text(run.stdout+run.stderr)
    require(run.returncode==0,"PR248_FROZEN_NATIVE_PROOF_NOT_REPLAYED:"+
            (run.stdout+run.stderr)[-5500:])
    past=json.loads((out/"task15-native-model-response-capture-boundary-v1.json").read_text())
    require(past["new_tests"]==15 and past["predecessor_tests"]==2242 and
            past["owned_native_steps"]==3 and past["offline_injected_client_calls"]==3 and
            past["provider_calls"]==0 and
            past["determination"]=="BOUNDED_OFFLINE_SOURCE_AT_CAPTURE_LINKAGE_TESTED",
            "PR248_PREDECESSOR_REPORT_CHANGED")
    positive=out/(NAME+".evidence.jsonl")
    refusals=out/(NAME+".refusals.jsonl")
    junit=out/(NAME+".junit.xml")
    for f in (positive,refusals,junit):f.unlink(missing_ok=True)
    env.update({v:"1" for v in (
        "TASK15_NATIVE_ADDRESS_PROOF",
        "TASK15_EXACT_NATIVE_RETURN_PROOF",
        "TASK15_REFUND_DESIGN_PROOF",
        "TASK15_REFUND_METADATA_PROOF",
        "TASK15_REFUND_CORRELATION_PROOF")})
    env["TASK15_RCC_ROOT"]=str(cfg.rcc_root.resolve())
    env["TASK15_EXACT_RETURN_EVIDENCE"]=str(positive)
    env["TASK15_EXACT_RETURN_REFUSALS"]=str(refusals)
    cmd=[sys.executable,"-m","pytest","-q","-o","addopts=",
         "tests/test_task15_exact_native_address_return_capture_v1.py",
         "--junitxml",str(junit)]
    test=subprocess.run(cmd,cwd=ROOT,env=env,capture_output=True,text=True)
    (out/(NAME+".tests.log")).write_text(test.stdout+test.stderr)
    print(test.stdout,end="")
    require(test.returncode==0,"NEW_NATIVE_ADDRESS_RETURN_TEST_FAILURE:"+
            (test.stdout+test.stderr)[-5000:])
    cases=ET.parse(junit).getroot().findall(".//testcase")
    require(len(cases)==c["expected_tests"] and
            not any(x.find(k) is not None for x in cases for k in
                    ("failure","error","skipped")),"MISSING_OR_SKIPPED_TESTS")
    evidence=[json.loads(x) for x in positive.read_text().splitlines()]
    negatives=[json.loads(x) for x in refusals.read_text().splitlines()]
    require(len(evidence)==1 and
            len(negatives)==c["expected_refusal_cases"] and
            all(x["no_b_native_dispatch"] and x["no_b_native_return"] for x in negatives),
            "FROZEN_REFUSAL_POPULATION_OR_RETURN_LEAK")
    result=evidence[0]
    a,b=result["arms"]
    from task15_native_address_request_profile_issuance_v1 import canonical,sha
    require(result["rule_of_one"]==RULE and
            result["provider_calls"]==0 and
            result["old_source_untouched"] and
            result["external_effect_authenticated"] is False and
            result["continuous_native_conversation_proven"] is False and
            result["full_task15_execution_supported"] is False and
            a["disposition"]==b["disposition"]=="COMMITTED" and
            a["native_dispatch_count"]==b["native_dispatch_count"]==1 and
            a["native_return"]==b["native_return"] and
            a["native_return_canonical_json"]==canonical(a["native_return"]) and
            b["native_return_canonical_json"]==canonical(b["native_return"]) and
            a["native_return_sha256"]==b["native_return_sha256"]==sha(a["native_return"]),
            "CAPTURE_NOT_EXACT_OR_CLAIM_PROMOTED")
    determination=dict(rule_of_one=RULE,
        determination="BOUNDED_NATIVE_ADDRESS_RETURN_CAPTURE_TESTED",
        predecessor_tests=c["expected_predecessor_tests"],
        new_tests=len(cases),refused_b_returns=len(negatives),
        actual_native_a_b_returns_recorded=2,
        original_address_runner_mutated=False,
        unchanged_native_sink_contract=True,
        composed_runner_integration_proven=False,
        full_native_conversation_proven=False,
        provider_calls=0,external_effect_authenticated=False,
        final128_utility_recovery_proven=False,
        independent_external_validation=False)
    (out/(NAME+".json")).write_text(json.dumps(determination,sort_keys=True,indent=2)+"\n")
    print("PASS_"+RULE)
    print("new_tests="+str(len(cases))+" predecessor_tests="+str(c["expected_predecessor_tests"]))
    return 0

if __name__=="__main__":
    raise SystemExit(main())
