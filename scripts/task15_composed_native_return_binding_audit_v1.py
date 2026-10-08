#!/usr/bin/env python3
"""No-provider proof: replay immutable #249 chain, then V2 composed return linkage."""
from __future__ import annotations
import argparse,hashlib,json,os,subprocess,sys,xml.etree.ElementTree as ET
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
RULE="TASK15_COMPOSED_NATIVE_RETURN_BINDING_V1"
NAME="task15-composed-native-return-binding-v1"

def require(cond,why):
    if not cond:raise ValueError(why)

def blob(path):
    raw=path.read_bytes()
    return hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()

def main():
    ap=argparse.ArgumentParser()
    for k in ("agentdojo","rcc","veritas"):
        ap.add_argument("--"+k+"-root",type=Path,required=True)
    for k in ("replay-artifact","v13-artifact","output-dir"):
        ap.add_argument("--"+k,type=Path,required=True)
    cfg=ap.parse_args()
    require(not os.environ.get("OPENAI_API_KEY") and
            not os.environ.get("VERITAS_DATABASE_URL"),
            "PROVIDER_OR_DATABASE_CREDENTIAL_FORBIDDEN")
    contract=json.loads((ROOT/"contracts"/(RULE+".json")).read_text())
    require(contract["status"]=="IMPLEMENTED_NOT_PROVEN_PENDING_EXACT_HEAD_CI" and
            contract["rule_of_one"]==RULE,"FROZEN_PROOF_CONTRACT_REQUIRED")
    for path,digest in contract["source_blobs"].items():
        require(blob(ROOT/path)==digest,"CHANGED_SOURCE_BLOB:"+path)
    out=cfg.output_dir.resolve()
    out.mkdir(parents=True,exist_ok=True)
    env=dict(os.environ,OPENAI_API_KEY="",VERITAS_DATABASE_URL="",
             PYTEST_DISABLE_PLUGIN_AUTOLOAD="1",PYTEST_ADDOPTS="")
    previous=subprocess.run([
        sys.executable,"scripts/task15_exact_native_address_return_capture_audit_v1.py",
        "--agentdojo-root",str(cfg.agentdojo_root.resolve()),
        "--rcc-root",str(cfg.rcc_root.resolve()),
        "--veritas-root",str(cfg.veritas_root.resolve()),
        "--replay-artifact",str(cfg.replay_artifact.resolve()),
        "--v13-artifact",str(cfg.v13_artifact.resolve()),
        "--output-dir",str(out)],cwd=ROOT,env=env,capture_output=True,text=True)
    (out/(NAME+".predecessor.log")).write_text(previous.stdout+previous.stderr)
    require(previous.returncode==0,"PR249_PREDECESSOR_PROOF_FAILED:"+
            (previous.stdout+previous.stderr)[-5000:])
    p=json.loads((out/"task15-exact-native-address-return-capture-v1.json").read_text())
    require(p["determination"]=="BOUNDED_NATIVE_ADDRESS_RETURN_CAPTURE_TESTED"
            and p["new_tests"]==9 and p["predecessor_tests"]==2257
            and p["actual_native_a_b_returns_recorded"]==2
            and p["refused_b_returns"]==6
            and p["provider_calls"]==0,"PR249_BOUNDED_EVIDENCE_CHANGED")
    positive=out/(NAME+".evidence.jsonl")
    refuse=out/(NAME+".refusals.jsonl")
    junit=out/(NAME+".junit.xml")
    for path in (positive,refuse,junit):path.unlink(missing_ok=True)
    env.update({x:"1" for x in (
        "TASK15_COMPOSED_NATIVE_RETURN_PROOF","TASK15_COMPOSED_RUNNER_PROOF",
        "TASK15_NATIVE_ADDRESS_PROOF","TASK15_EXACT_NATIVE_RETURN_PROOF",
        "TASK15_REFUND_DESIGN_PROOF","TASK15_REFUND_METADATA_PROOF",
        "TASK15_REFUND_CORRELATION_PROOF")})
    env["TASK15_RCC_ROOT"]=str(cfg.rcc_root.resolve())
    env["TASK15_COMPOSED_NATIVE_EVIDENCE"]=str(positive)
    env["TASK15_COMPOSED_NATIVE_REFUSALS"]=str(refuse)
    cmd=[sys.executable,"-m","pytest","-q","-o","addopts=",
         "tests/test_task15_composed_native_return_binding_v1.py",
         "--junitxml",str(junit)]
    new=subprocess.run(cmd,cwd=ROOT,env=env,capture_output=True,text=True)
    (out/(NAME+".tests.log")).write_text(new.stdout+new.stderr)
    print(new.stdout,end="")
    require(new.returncode==0,"NEW_COMPOSED_RETURN_TEST_FAILURE:"+
            (new.stdout+new.stderr)[-7500:])
    cases=ET.parse(junit).getroot().findall(".//testcase")
    require(len(cases)==contract["expected_new_tests"] and
            not any(x.find(tag) is not None for x in cases for tag in
                    ("skipped","error","failure")),"NATIVE_RETURN_NEW_TESTS_INCOMPLETE")
    samples=[json.loads(x) for x in positive.read_text().splitlines()]
    negatives=[json.loads(x) for x in refuse.read_text().splitlines()]
    require(len(samples)==1 and len(negatives)==contract["expected_new_refusal_rows"],
            "SUCCESS_OR_REFUSAL_EVIDENCE_COUNT_CHANGED")
    r=samples[0]
    require(r["phase"]=="COMPLETE_LOCAL_COMPOSED_RUN" and
            r["native_return_history_fully_composed"] is True and
            not r["model_history_message_issued"] and
            not r["real_provider_conversation_proven"] and
            len(r["completed_steps"])==contract["expected_composed_steps"] and
            len(r["local_native_return_history"])==contract["expected_composed_steps"],
            "BOUNDED_NATIVE_HISTORY_REPORT_INVALID")
    from task15_native_address_request_profile_issuance_v1 import canonical,sha
    verified=0
    for step,(row,history) in enumerate(zip(r["completed_steps"],r["local_native_return_history"])):
        require(row["step"]==history["step"]==step and
                row["candidate_sha256"]==history["candidate_sha256"] and
                history["actual_generation_ordinal"]==(3,9,14)[step] and
                history["model_tool_call_id"] is None,"CANDIDATE_PROVENANCE_HISTORY_DRIFT")
        for arm in ("A","B"):
            actual=row["arms"][arm]
            bound=history["arms"][arm]
            require(actual["disposition"]=="COMMITTED" and
                    actual["native_dispatch_count"]==bound["native_dispatch_count"]==1 and
                    actual["native_return"]==bound["native_return"] and
                    canonical(actual["native_return"])==bound["native_return_canonical_json"] and
                    sha(actual["native_return"])==bound["native_return_sha256"] and
                    actual["candidate_sha256"]==bound["candidate_sha256"] and
                    actual["pre_state_sha256"]==bound["pre_state_sha256"] and
                    actual["post_state_sha256"]==bound["post_state_sha256"],
                    "NATIVE_RETURN_NOT_LINKED_TO_SAME_EXECUTED_CANDIDATE")
            verified+=1
    require(verified==contract["expected_return_bindings"],"RETURN_BINDING_COUNT_CHANGED")
    for row in negatives:
        obs=row["observation"]
        require(obs["phase"]=="TERMINAL_UNKNOWN_OR_FAILED"
                and obs["native_return_history_fully_composed"] is False
                and obs["model_history_message_issued"] is False,
                "FAILURE_PROMOTED_TO_COMPLETED_NATIVE_HISTORY")
    result=dict(rule_of_one=RULE,determination="BOUNDED_COMPOSED_NATIVE_RETURN_BINDING_TESTED",
                predecessor_tests=contract["expected_predecessor_tests"],
                new_tests=len(cases),success_native_return_bindings=verified,
                refusals=len(negatives),real_provider_calls=0,
                model_history_message_issued=False,actual_model_call_ids_bound=False,
                external_effect_authenticated=False,
                actual_model_conversation_proven=False,
                final128_utility_recovery_proven=False,independent_external_validation=False)
    (out/(NAME+".json")).write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
    print("PASS_"+RULE)
    print("new_tests="+str(len(cases))+" predecessor_tests="+str(contract["expected_predecessor_tests"]))
    print("successful_native_returns="+str(verified)+" refusals="+str(len(negatives)))
    return 0

if __name__=="__main__":raise SystemExit(main())
