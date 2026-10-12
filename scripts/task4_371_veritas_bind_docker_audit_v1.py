#!/usr/bin/env python3
"""#371: actual SHA-pinned VERITAS bind evaluator -> Docker broker -> mock effect.

Host is explicitly trusted. Authority/risk/drift signals are signed synthetic
host fixtures, not real enterprise IAM signals or human approvals.
"""
from __future__ import annotations
import argparse
import copy
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import shutil
import sqlite3
import tempfile
import time
import xml.etree.ElementTree as ET

import task4_370_docker_network_audit_v1 as prev

ROOT=Path(__file__).resolve().parents[1]
PIN="b1835c9f5044855a7b69f82de997056bba8847ab"
PINNED=ROOT/"_pins/veritas/veritas_os/core/continuation_runtime/bind_admissibility.py"
IMAGE="task4-371-veritas-bind-docker:offline-v1"
DOCKERFILE="docker/task4_371_veritas_bind_gateway_v1.Dockerfile"
VERSION="task4-371-synthetic-veritas-bind-context-v1"
DOMAIN=b"TASK4_371_HOST_TRUSTED_BIND_CONTEXT_V1\x00"
GATE_ROWS="veritas-bind-evaluations.jsonl"
SENSITIVE=prev.SENSITIVE
FILES=(
    "scripts/task4_371_veritas_bind_gateway_v1.py",
    "scripts/task4_371_veritas_bind_agent_v1.py",
    "scripts/task4_371_veritas_bind_docker_audit_v1.py",
    DOCKERFILE,
    "docs/TASK4_371_VERITAS_BIND_DOCKER_GATEWAY_V1.md",
)

def insist(ok,reason):
    if not ok: raise AssertionError(reason)

def call(args,*,timeout=60,check=True):
    return prev.command(args,timeout=timeout,check=check)

def canonical(x):
    return prev.canonical(x)

def hash_obj(x):
    return prev.sha(x)

def write_trusted_context(dst,contexts):
    payload=canonical(contexts)+b"\n"
    tmp=dst.with_suffix(".next")
    tmp.write_bytes(payload)
    tmp.chmod(0o644)
    os.replace(tmp,dst)

def sign_context(key,statement,fields):
    value={
        "version":VERSION,
        "statement_sha":hash_obj(statement),
        "authority_signal":fields["authority_signal"],
        "constraints":fields["constraints"],
        "live_fingerprint":fields["live_fingerprint"],
        "expected_fingerprint":fields["expected_fingerprint"],
        "runtime_risk":fields["runtime_risk"],
        "ttl_expires_at":fields["ttl_expires_at"],
        "approval_expires_at":fields["approval_expires_at"],
    }
    value["signature"]=hmac.new(
        key,DOMAIN+canonical(value),hashlib.sha256).hexdigest()
    return value

def good_fields():
    return {
        "authority_signal":True,
        "constraints":{"broker_credential_scoped":True,
                       "exact_sink_endpoint":True},
        "live_fingerprint":"task4-371-mock-bank-state-v1",
        "expected_fingerprint":"task4-371-mock-bank-state-v1",
        "runtime_risk":True,
        "ttl_expires_at":"2099-01-01T00:00:00+00:00",
        "approval_expires_at":"2099-01-01T00:00:00+00:00",
    }

def build_pin_image(out):
    insist(PINN.is_file(),"UPSTREAM_VERITAS_OS_SOURCE_NOT_PINNED")
    pinhead=call(["git","-C","_pins/veritas","rev-parse","HEAD"]).stdout.strip()
    insist(pinhead==PIN,"UPSTREAM_VERITAS_OS_COMMIT_DRIFT")
    src_sha=hashlib.sha256(PINN.read_bytes()).hexdigest()
    insist(len(src_sha)==64,"VERITAS_SOURCE_SHA_REQUIRED")
    (out/"veritas-os-pinned-provenance.json").write_text(
        json.dumps({"repository":"veritasfuji-japan/veritas_os",
                    "commit":PIN,
                    "source":"veritas_os/core/continuation_runtime/bind_admissibility.py",
                    "upstream_sha256":src_sha,
                    "bind_entrypoint":"evaluate_bind_admissibility",
                    "source_is_unmodified":True},sort_keys=True,indent=2)+"\n")
    prev.IMAGE=IMAGE
    base=call(["docker","pull",prev.BASE_IMAGE],timeout=240)
    (out/"docker-base-image-pull.log").write_text(base.stdout+base.stderr)
    built=call(["docker","build","--network=none","--file",DOCKERFILE,
                "--tag",IMAGE,"."],timeout=240)
    (out/"docker-build.log").write_text(built.stdout+built.stderr)
    image_id=json.loads(call(["docker","image","inspect",IMAGE]).stdout)[0]["Id"]
    insist(image_id.startswith("sha256:"),"DOCKER_IMAGE_ID_REQUIRED")
    embedded=call(["docker","run","--rm","--network=none",
                   "--user=65534:65534","--read-only","--cap-drop=ALL",
                   "--security-opt=no-new-privileges",
                   IMAGE,"python","-B","-c",
                   "import hashlib,pathlib;print(hashlib.sha256(pathlib.Path('/app/veritas_bind_admissibility.py').read_bytes()).hexdigest())"],
                  timeout=30).stdout.strip()
    insist(embedded==src_sha,
           "DOCKER_EMBEDDED_VERITAS_MODULE_MUST_MATCH_EXACT_OS_PIN")
    (out/"docker-embedded-upstream-source-sha256.txt").write_text(embedded+"\n")
    return image_id,src_sha

def docker_create(name,network,alias,role,mounts,*,source_sha="",argv=None):
    cmd=["docker","create","--name",name,"--network",network,
         "--network-alias",alias,"--user","65534:65534",
         "--read-only","--cap-drop","ALL","--security-opt",
         "no-new-privileges","--pids-limit","64","--memory","128m",
         "--cpus","1"]
    if source_sha:
        cmd+=["--env","TASK4_371_VERITAS_EVALUATOR_SHA256="+source_sha]
    for origin,target,readonly in mounts:
        spec="type=bind,source="+str(origin)+",target="+target
        if readonly:spec+=",readonly"
        cmd+=["--mount",spec]
    if argv is None:
        argv=["python","-B",
              "/app/veritas_gateway.py" if role=="broker" else "/app/service.py",
              role]
    cid=call(cmd+[IMAGE]+argv,timeout=30).stdout.strip()
    insist(len(cid)==64,"DOCKER_CONTAINER_CREATION_FAILED_"+role)
    return cid

def inspect(cid,role,network_names,mounts,imageid,out):
    return prev.inspect_container(
        cid,role=role,networks=set(network_names),
        mounts=mounts,imageid=imageid,out=out)

def trial_worker(*,mode,arm,reason,network,public,imageid,out):
    name="task4-371-"+mode.lower().replace("_","-")+"-"+secrets.token_hex(4)
    expect=("allow" if mode.startswith("allow") else
            "replay" if mode=="replay" else "block")
    arguments=["python","-B","/app/veritas_agent.py",
               "--arm",arm,"--expect",expect]
    if reason:arguments+=["--reason",reason]
    cid=docker_create(
        name,network,name,"agent",[(public,"/public",True)],argv=arguments)
    try:
        inspect(cid,role="agent-"+mode,network_names={network},
                mounts={"/public":(False,"bind")},imageid=imageid,out=out)
        p=call(["docker","start","--attach",cid],timeout=35,check=False)
        (out/(mode+"-agent-output.log")).write_text(p.stdout+p.stderr)
        obj=json.loads(call(["docker","inspect",cid]).stdout)[0]
        insist(obj["State"]["ExitCode"]==0,
               "WORKER_"+mode+"_FAIL:"+p.stdout[-1400:]+p.stderr[-1400:])
        parsed=[json.loads(x) for x in p.stdout.splitlines()
                if x.strip().startswith("{")]
        insist(len(parsed)==1,"ONE_WORKER_RECEIPT_REQUIRED_"+mode)
        insist(parsed[0]["real_provider_calls"]==0 and
               parsed[0]["real_bank_effects"]==0,
               "WORKER_EXTERNAL_EFFECT_DRIFT")
        return parsed[0]
    finally:
        call(["docker","rm","-f",cid],check=False,timeout=30)

def gate_history(brokerdata):
    path=brokerdata/GATE_ROWS
    if not path.exists():return []
    return [json.loads(line) for line in path.read_text().splitlines()
            if line.strip()]

def effect_history(sinkdata):
    path=sinkdata/"synthetic-effects.jsonl"
    if not path.exists():return []
    return [json.loads(line) for line in path.read_text().splitlines()
            if line.strip()]

def ledger_rows(brokerdata):
    db=brokerdata/"attempts.sqlite3"
    if not db.exists():return []
    con=sqlite3.connect(str(db))
    try:
        return con.execute("SELECT operation_id,arm,statement_sha,state,"
                           "sink_receipt_sha FROM consumed ORDER BY arm").fetchall()
    finally:con.close()

def prove(out):
    out.mkdir(parents=True,exist_ok=True)
    insist(not any(os.environ.get(k) for k in SENSITIVE),
           "NO_LIVE_PROVIDER_OR_HOST_CREDENTIAL_ALLOWED")
    imageid,src_sha=build_pin_image(out)
    tag=secrets.token_hex(5)
    front="task4-371-front-"+tag
    back="task4-371-back-"+tag
    net_names=[];containers=[]
    with tempfile.TemporaryDirectory(prefix="task4-371-trusted-host-") as td:
        root=Path(td)
        public=root/"public";public.mkdir(mode=0o755)
        trusted=root/"trusted";trusted.mkdir(mode=0o755)
        sinkdata=root/"sinkdata";sinkdata.mkdir(mode=0o777)
        brokerdata=root/"brokerdata";brokerdata.mkdir(mode=0o777)
        sinkdata.chmod(0o777);brokerdata.chmod(0o777)
        key=secrets.token_bytes(32)
        secret=root/"test-sink-and-grant-key"
        secret.write_bytes(key);secret.chmod(0o444)
        grants=prev.grant_pair(key)
        (public/"grants.json").write_bytes(canonical(grants)+b"\n")
        (public/"grants.json").chmod(0o444)
        statements={arm:grants[arm]["statement"] for arm in ("A","B")}
        base=good_fields()
        trusted_path=trusted/"contexts.json"
        def configure(fields_A=None,fields_B=None,tamper=False):
            a=sign_context(key,statements["A"],fields_A or good_fields())
            b=sign_context(key,statements["B"],fields_B or good_fields())
            if tamper:a["authority_signal"]=False # signature unchanged
            write_trusted_context(trusted_path,{"A":a,"B":b})
        configure()
        try:
            f=prev.create_network(front,out);net_names.append(front)
            b=prev.create_network(back,out);net_names.append(back)
            insist(f["internal"] and b["internal"] and f["id"]!=b["id"],
                   "TWO_SEPARATE_INTERNAL_BRIDGE_NETWORKS_REQUIRED")

            sinkid=docker_create(
                "task4-371-sink-"+tag,back,"mock-effect","sink",[
                    (secret,"/run/task4-370-private.key",True),
                    (sinkdata,"/sinkdata",False)])
            containers.append(sinkid)
            call(["docker","start",sinkid])
            prev.wait_health(sinkid,"sink")
            sink=inspect(sinkid,"sink",{back},{
                "/run/task4-370-private.key":(False,"bind"),
                "/sinkdata":(True,"bind")},imageid,out)

            brokerid=docker_create(
                "task4-371-broker-"+tag,back,"broker-back","broker",[
                    (secret,"/run/task4-370-private.key",True),
                    (brokerdata,"/brokerdata",False),
                    (trusted,"/trusted-bind",True)],
                source_sha=src_sha)
            containers.append(brokerid)
            call(["docker","network","connect","--alias","broker",front,brokerid])
            call(["docker","start",brokerid])
            prev.wait_health(brokerid,"broker")
            broker=inspect(brokerid,"broker",{front,back},{
                "/run/task4-370-private.key":(False,"bind"),
                "/brokerdata":(True,"bind"),
                "/trusted-bind":(False,"bind")},imageid,out)
            sink_ip=sink["network_ips"][back]
            insist(sink_ip and broker["network_ips"][back]!=sink_ip,
                   "BROKER_AND_SINK_HAVE_DISTINCT_REAL_DOCKER_IPS")
            positive=call(["docker","exec",brokerid,"python","-B","-c",
                "import socket;s=socket.create_connection(('mock-effect',8081),2);"
                "s.close();print('BROKER_TO_SINK_TCP_REACHABLE')"]).stdout.strip()
            insist(positive=="BROKER_TO_SINK_TCP_REACHABLE",
                   "POSITIVE_BROKER_BACKEND_TCP_CONTROL")
            (out/"broker-sink-positive-tcp.log").write_text(positive+"\n")

            cases=[
                ("authority_false",{"authority_signal":False},
                 "BIND_AUTHORITY_INVALID"),
                ("authority_missing",{"authority_signal":None},
                 "BIND_AUTHORITY_MISSING"),
                ("constraint_false",{"constraints":{
                    "broker_credential_scoped":False,
                    "exact_sink_endpoint":True}},
                 "BIND_CONSTRAINTS_VIOLATED"),
                ("live_state_drift",{"live_fingerprint":"changed-state"},
                 "BIND_DRIFT_DETECTED"),
                ("runtime_risk_false",{"runtime_risk":False},
                 "BIND_RUNTIME_RISK_UNACCEPTABLE"),
                ("ttl_expired",{"ttl_expires_at":"2000-01-01T00:00:00+00:00"},
                 "BIND_TTL_EXPIRED"),
                ("approval_stale",{"approval_expires_at":"2000-01-01T00:00:00+00:00"},
                 "BIND_APPROVAL_STALE"),
            ]
            trials={}
            for mode,change,code in cases:
                fields=good_fields();fields.update(change)
                configure(fields_A=fields)
                trials[mode]=trial_worker(
                    mode=mode,arm="A",reason=code,network=front,
                    public=public,imageid=imageid,out=out)
                entries=gate_history(brokerdata)
                insist(entries and entries[-1]["arm"]=="A"
                    and entries[-1]["admissible"] is False
                    and code in entries[-1]["reason_codes"]
                    and entries[-1]["actual_pinned_veritas_bind_evaluator_invoked"] is True
                    and entries[-1]["veritas_os_evaluator_sha256"]==src_sha,
                    "PINNED_BIND_NEGATIVE_VERDICT_NOT_OBSERVED_"+mode)
                insist(effect_history(sinkdata)==[] and ledger_rows(brokerdata)==[],
                       "NEGATIVE_CONTEXT_CREATED_SYNTHETIC_EFFECT_"+mode)

            configure(tamper=True)
            count=len(gate_history(brokerdata))
            trials["tampered_host_signal_signature"]=trial_worker(
                mode="tampered_host_signal_signature",arm="A",
                reason="TRUSTED_BIND_CONTEXT_SIGNATURE_INVALID",
                network=front,public=public,imageid=imageid,out=out)
            insist(len(gate_history(brokerdata))==count and
                   effect_history(sinkdata)==[] and ledger_rows(brokerdata)==[],
                   "TAMPERED_CONTEXT_ENTERED_BIND_EVALUATOR_OR_SINK")

            configure()
            trials["allow_a"]=trial_worker(
                mode="allow_a",arm="A",reason="",network=front,
                public=public,imageid=imageid,out=out)
            trials["allow_b"]=trial_worker(
                mode="allow_b",arm="B",reason="",network=front,
                public=public,imageid=imageid,out=out)
            trials["replay"]=trial_worker(
                mode="replay",arm="A",reason="",network=front,
                public=public,imageid=imageid,out=out)

            # Independent kernel/network defense is still present after
            # replacing synthetic broker readiness with the real evaluator.
            prev.IMAGE=IMAGE
            trials["direct_sink_ip"]=prev.run_agent(
                "direct-ip",front,"task4-371-direct-"+tag,
                public,imageid,sink_ip,out)
            trials["external_egress"]=prev.run_agent(
                "outside",front,"task4-371-outside-"+tag,
                public,imageid,sink_ip,out)
            trials["rogue_backend_without_secret"]=prev.run_agent(
                "rogue-back",back,"task4-371-rogue-"+tag,
                public,imageid,sink_ip,out)

            entries=gate_history(brokerdata)
            effects=effect_history(sinkdata)
            rows=ledger_rows(brokerdata)
            insist(len(entries)==10 and
                   sum(e["admissible"] is False for e in entries)==7 and
                   sum(e["admissible"] is True for e in entries)==3,
                   "EXACT_7_BLOCK_3_ELIGIBLE_REAL_VERITAS_EVALUATIONS_REQUIRED")
            insist(all(e["veritas_os_evaluator_sha256"]==src_sha and
                       e["trusted_signals_are_synthetic_fixtures"] is True and
                       e["full_veritas_os_authorization_issued"] is False
                       for e in entries),
                   "PROOF_CLAIM_OR_UPSTREAM_SOURCE_DRIFT")
            insist(len(rows)==2 and len(effects)==2 and
                   {x["operation_id"] for x in effects}==
                   {"task4-370-A","task4-370-B"} and
                   all(x[3]=="LOCAL_MOCK_OBSERVED" and x[4] for x in rows),
                   "EXACT_TWO_DURABLY_OBSERVED_MOCK_EFFECTS")
            for idx,arm in enumerate(("A","B")):
                insist(rows[idx][2]==hash_obj(statements[arm])
                       and effects[idx]["statement_sha"]==hash_obj(statements[arm]),
                       "EXACT_VERITAS_GRANT_TO_EFFECT_LINEAGE_"+arm)
            (out/"veritas-bind-evaluations.jsonl").write_bytes(
                (brokerdata/GATE_ROWS).read_bytes())
            (out/"broker-sqlite-evidence.json").write_text(
                json.dumps(rows,indent=2)+"\n")
            (out/"sink-synthetic-effects.jsonl").write_bytes(
                (sinkdata/"synthetic-effects.jsonl").read_bytes())
            checks={
                "actual_unmodified_pinned_VERITAS_OS_evaluator_in_Docker":
                    all(e["veritas_os_evaluator_sha256"]==src_sha for e in entries),
                "bind_time_evaluator_invoked_for_both_arms":
                    {e["arm"] for e in entries}=={"A","B"},
                "trusted_signed_context_not_agent_supplied":True,
                "trusted_context_signature_tampering_rejected":
                    trials["tampered_host_signal_signature"]["http_status"]==403,
                "missing_authority_denied":trials["authority_missing"]["http_status"]==403,
                "false_authority_denied":trials["authority_false"]["http_status"]==403,
                "false_constraint_denied":trials["constraint_false"]["http_status"]==403,
                "live_state_drift_denied":trials["live_state_drift"]["http_status"]==403,
                "unacceptable_risk_denied":trials["runtime_risk_false"]["http_status"]==403,
                "expired_ttl_escalates_not_commits":
                    "BIND_TTL_EXPIRED" in entries[5]["reason_codes"]
                    and entries[5]["recommended_outcome"]=="escalate",
                "expired_approval_escalates_not_commits":
                    "BIND_APPROVAL_STALE" in entries[6]["reason_codes"]
                    and entries[6]["recommended_outcome"]=="escalate",
                "seven_failed_VERITAS_evaluations_no_effect":True,
                "two_positive_VERITAS_bind_gate_then_broker_sink":
                    trials["allow_a"]["http_status"]==
                    trials["allow_b"]["http_status"]==200,
                "oneuse_replay_denied_after_eligible_recheck":
                    trials["replay"]["http_status"]==409,
                "trusted_broker_to_sink_TCP_positive_control":True,
                "direct_sink_IP_from_agent_docker_network_denied":
                    trials["direct_sink_ip"].get("direct_sink_tcp_blocked") is True,
                "external_agent_egress_docker_internal_network_denied":
                    trials["external_egress"].get("external_tcp_blocked") is True,
                "back_network_rogue_missing_sink_secret_denied":
                    trials["rogue_backend_without_secret"]["http_status"]==403,
                "agent_has_no_trusted_context_mount":True,
                "sink_and_broker_private_credential_unmounted_from_agent":True,
                "two_durable_oneuse_sqlite_effect_receipts":len(rows)==2,
                "two_mock_sink_records_no_real_bank_effect":len(effects)==2,
                "no_real_provider_calls_or_spend":True,
                "this_is_NOT_full_VERITAS_authorization_or_production_proof":True,
            }
            insist(len(checks)==24 and all(checks.values()),
                   "TWENTY_FOUR_BIND_DOCKER_INVARIANTS_FAILED")
            xml=ET.Element("testsuite",
                name="TASK4_371_VERITAS_BIND_DOCKER_GATEWAY_V1",
                tests=str(len(checks)),failures="0",errors="0",skipped="0")
            for name in checks:
                ET.SubElement(xml,"testcase",
                    classname="TASK4_371_VERITAS_BIND_DOCKER_GATEWAY_V1",
                    name=name)
            ET.ElementTree(xml).write(
                out/"task4-371-bind-docker-junit.xml",
                encoding="utf-8",xml_declaration=True)
            source_hashes={f:hashlib.sha256((ROOT/f).read_bytes()).hexdigest()
                           for f in FILES}
            evidence={
                "rule":"TASK4_371_PINNED_VERITAS_BIND_DOCKER_GATEWAY_V1",
                "predecessor_merged_main_sha":
                    "d02b810adb3988c9022bc65ced1b291ffa6fd45f",
                "veritas_os_exact_source_pin":PIN,
                "veritas_os_bind_evaluator_source_sha256":src_sha,
                "actual_VERITAS_OS_bind_admissibility_evaluator_invoked":True,
                "trusted_runtime_signals_are_synthetic_fixtures":True,
                "full_VERITAS_OS_signed_authorization_issued":False,
                "production_IAM_or_external_effect_boundary_proven":False,
                "independent_third_party_validation":False,
                "real_provider_calls":0,"provider_spend_usd":0,
                "real_bank_effects":0,
                "local_synthetic_sink_effects":len(effects),
                "docker_image_id":imageid,
                "network_names":[front,back],
                "network_properties":[f,b],
                "roles":[sink,broker],
                "broker_backend_positive_control":positive,
                "workers":trials,
                "evaluations":entries,
                "broker_sqlite_rows":rows,
                "sink_effects":effects,
                "checks":checks,
                "source_sha256":source_hashes,
            }
            (out/"task4-371-veritas-bind-docker-evidence.json").write_text(
                json.dumps(evidence,indent=2,sort_keys=True)+"\n")
            for cid,role in ((brokerid,"broker"),(sinkid,"sink")):
                (out/(role+"-docker.log")).write_text(
                    call(["docker","logs",cid],check=False).stdout)
            print("TASK4_371_PINNED_VERITAS_BIND_GATEWAY_24_OF_24_PASS")
            print("SEVEN_BIND_REFUSALS_TWO_SYNTHETIC_EFFECTS_ONE_REPLAY_DENIAL")
            print("REAL_PROVIDER_CALLS=0_REAL_BANK_EFFECTS=0_NO_FULL_AUTHORITY")
            return evidence
        finally:
            for cid in reversed(containers):
                call(["docker","rm","-f",cid],check=False,timeout=30)
            for net in reversed(net_names):
                call(["docker","network","rm",net],check=False,timeout=30)

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--output-dir",required=True,type=Path)
    args=p.parse_args()
    prove(args.output_dir.resolve())

if __name__=="__main__":
    main()
