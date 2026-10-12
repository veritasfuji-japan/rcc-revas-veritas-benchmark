#!/usr/bin/env python3
"""Trusted CI host audit of real upstream LABA API in networkless Docker."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import xml.etree.ElementTree as ET

ROOT=Path(__file__).resolve().parents[1]
PIN="b1835c9f5044855a7b69f82de997056bba8847ab"
UPSTREAM=ROOT/"_pins/veritas/veritas_os/policy/live_adapter_bind_authorization_consumption.py"
IMAGE="task4-372-real-laba-docker:offline-v1"
SENSITIVE=("OPENAI_API_KEY","OPENAI_BASE_URL","TASK4_OPENAI_API_KEY",
           "ANTHROPIC_API_KEY","AWS_SECRET_ACCESS_KEY","GH_TOKEN",
           "GITHUB_TOKEN","VERITAS_DATABASE_URL")
SOURCE=[
    "scripts/task4_372_real_laba_docker_proof_v1.py",
    "scripts/task4_372_real_laba_docker_audit_v1.py",
    "docker/task4_372_real_laba_docker_proof_v1.Dockerfile",
    "docs/TASK4_372_REAL_LABA_ISSUE_VERIFY_CONSUME_DOCKER_V1.md",
]
def insist(ok,reason):
    if not ok:raise AssertionError(reason)
def cmd(args,*,timeout=60,check=True):
    p=subprocess.run(args,capture_output=True,text=True,timeout=timeout,cwd=ROOT)
    if check and p.returncode:
        raise AssertionError("COMMAND_FAILED_"+repr(args)+":"+p.stderr[-1800:])
    return p
def audit(out):
    out.mkdir(parents=True,exist_ok=True)
    insist(not any(os.environ.get(k) for k in SENSITIVE),
           "LIVE_API_CREDENTIAL_NOT_ALLOWED")
    insist(UPSTREAM.is_file(),"EXACT_OS_SOURCE_CHECKOUT_MISSING")
    sha=hashlib.sha256(UPSTREAM.read_bytes()).hexdigest()
    git=cmd(["git","-C","_pins/veritas","rev-parse","HEAD"]).stdout.strip()
    insist(git==PIN,"PINNED_VERITAS_OS_COMMIT_INVALID")
    (out/"os-source-pin.json").write_text(json.dumps({
        "repo":"veritasfuji-japan/veritas_os","commit":git,
        "consumer_path":"veritas_os/policy/live_adapter_bind_authorization_consumption.py",
        "consumer_sha256":sha,"synthetic_fixture_type":"upstream official test fixtures"
    },indent=2,sort_keys=True)+"\n")
    build=cmd(["docker","build","--file",
        "docker/task4_372_real_laba_docker_proof_v1.Dockerfile",
        "--tag",IMAGE,"."],timeout=360)
    (out/"image-build.log").write_text(build.stdout+build.stderr)
    image=json.loads(cmd(["docker","image","inspect",IMAGE]).stdout)[0]["Id"]
    insist(image.startswith("sha256:"),"BUILT_IMAGE_ID_REQUIRED")
    name="task4-372-offline-"+os.environ.get("GITHUB_RUN_ID","ci")
    arguments=[
        "docker","create","--name",name,"--network=none",
        "--user=65534:65534","--read-only","--cap-drop=ALL",
        "--security-opt=no-new-privileges","--pids-limit=64",
        "--memory=512m","--cpus=1",
        "--env","TASK4_372_OS_CONSUMER_SOURCE_SHA256="+sha,
        IMAGE,"python","-B","/app/task4_372.py"
    ]
    cid=cmd(arguments,timeout=30).stdout.strip()
    try:
        raw=json.loads(cmd(["docker","inspect",cid]).stdout)[0]
        config=raw["Config"];host=raw["HostConfig"]
        insist(raw["Image"]==image and config["User"]=="65534:65534",
               "DOCKER_IMAGE_OR_UID_MISMATCH")
        insist(host["NetworkMode"]=="none" and host["ReadonlyRootfs"] and
               host["Privileged"] is False and
               {c.upper() for c in host.get("CapDrop") or []}=={"ALL"}
               and not host.get("CapAdd") and
               any("no-new-privileges" in v for v in host.get("SecurityOpt") or []),
               "REAL_DOCKER_OFFLINE_ISOLATION_NOT_ENFORCED")
        insist(not raw.get("Mounts") and not host.get("PortBindings")
               and not host.get("Binds"),
               "UNEXPECTED_DOCKER_MOUNT_OR_PORT")
        insist(not any(x.partition("=")[0] in SENSITIVE
                       for x in config.get("Env") or []),
               "LIVE_API_CREDENTIAL_IN_DOCKER")
        info={
            "image":image,"container_id":cid,
            "runtime_network_mode":host["NetworkMode"],
            "read_only_root":host["ReadonlyRootfs"],
            "uid_gid":config["User"],"dropped_capabilities":host["CapDrop"],
            "no_new_privileges":True,
            "docker_socket_mounted":False,
            "credential_environment_empty":True,
            "published_ports":[],
            "verification_on_actual_docker_container":True,
        }
        (out/"docker-runtime-inspect.json").write_text(
            json.dumps(info,sort_keys=True,indent=2)+"\n")
        run=cmd(["docker","start","--attach",cid],timeout=130,check=False)
        (out/"real-upstream-laba-docker-output.log").write_text(
            run.stdout+run.stderr)
        state=json.loads(cmd(["docker","inspect",cid]).stdout)[0]["State"]
        insist(state["ExitCode"]==0,
               "FORMAL_VERITAS_DOCKER_PROOF_FAILED:"+run.stdout[-1600:]+run.stderr[-1600:])
        lines=[json.loads(line) for line in run.stdout.splitlines()
               if line.strip().startswith("{")]
        insist(len(lines)==1,"ONE_PINNED_VERITAS_EVIDENCE_OBJECT_REQUIRED")
        evidence=lines[0]
        need=evidence["checks"]
        insist(evidence["rule"]=="TASK4_372_REAL_LABA_ISSUE_VERIFY_CONSUME_DOCKER_V1" and
               evidence["exact_os_pin"]==PIN and
               evidence["consumer_source_sha256"]==sha and
               len(need)==17 and all(need.values()),
               "REAL_LABA_ISSUANCE_CONSUMPTION_VERIFICATION_FAILED")
        insist(evidence["formal_target_mismatch_prevents_docker_sink_dispatch"] is True
               and evidence["full_prod_authority_end_to_end"] is False and
               evidence["real_provider_calls"]==evidence["real_bank_effects"]==
                   evidence["real_spend_usd"]==0,
               "WRONG_AUTHORITY_CLAIM_OR_EXTERNAL_EFFECT")
        recorded={
            "rule":evidence["rule"],"upstream":evidence,
            "upstream_sha256":sha,"exact_upstream_commit":git,
            "docker":info,
            "source_sha256":{
                file:hashlib.sha256((ROOT/file).read_bytes()).hexdigest()
                for file in SOURCE
            },
            "scope":"REAL_LABA_ISSUE_VERIFY_CONSUME_WITH_SYNTHETIC_FIXTURE_ONLY",
            "real_docker_sink_effect_from_formal_artifact":False,
            "full_production_authority_proven":False,
            "separate_previous_371_network_boundary_unmodified":True,
        }
        (out/"task4-372-formal-laba-docker-evidence.json").write_text(
            json.dumps(recorded,sort_keys=True,indent=2)+"\n")
        suite=ET.Element("testsuite",name=evidence["rule"],
                         tests=str(len(need)),failures="0",errors="0",skipped="0")
        for title in need:
            ET.SubElement(suite,"testcase",classname=evidence["rule"],name=title)
        ET.ElementTree(suite).write(out/"task4-372-junit.xml",
                                  encoding="utf-8",xml_declaration=True)
        print("TASK4_372_REAL_UPSTREAM_LABA_ISSUE_VERIFY_CONSUME_17_OF_17_PASS")
        print("FORMAL_TARGET_MISMATCH_FAIL_CLOSED_NO_SINK_REUSE")
        print("REAL_PROVIDER_0_REAL_BANK_EFFECT_0_PRODUCTION_AUTHORITY_NOT_PROVEN")
        return recorded
    finally:
        cmd(["docker","rm","-f",cid],timeout=30,check=False)

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--output-dir",type=Path,required=True)
    args=p.parse_args()
    audit(args.output_dir.resolve())

if __name__=="__main__":
    main()
