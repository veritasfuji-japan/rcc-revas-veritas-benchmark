#!/usr/bin/env python3
"""#281 offline-only, TWO Docker containers: trusted mock broker + untrusted worker.

Broker credentials and SQLite live in a host-owned, broker-only bind mounted
directory. Worker receives only the public TEST grant and Unix socket mount.
Each runtime container has its own networkless Linux namespace, no capabilities,
read-only root, no-new-privileges and exact non-root UID/GID.

This proof trusts the host, Docker daemon and kernel. No Provider credentials,
endpoint connections, production signing root or billable actions exist.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from scripts.task15_unix_ipc_mock_broker_process_audit_v1 import (
    IMAGE as WORKER_IMAGE, WORKER, SERVER, command, grant,
    inspect_worker, ask_host, audit_sqlite, require, sha,
)

RULE = "TASK15_BROKER_CONTAINER_SECRET_ISOLATION_V1"
BASE_MAIN = "02e462ba28823a2df5cad05b4320326dcb5b88ee"
DOCKERFILE = ROOT/"docker/task15_mock_broker_container_v1.Dockerfile"
CORE = ROOT/"task15_mock_broker_authorization_boundary_v1.py"
CONTRACT = ROOT/"contracts/TASK15_BROKER_CONTAINER_SECRET_ISOLATION_V1.json"

def validate_broker(info, private_dir, shared_dir, image_id, uid, gid):
    h=info["HostConfig"];c=info["Config"]
    require(uid>0 and gid>0 and uid!=65534 and gid!=65534,
            "TRUSTED_BROKER_ID_MUST_DIFFER_FROM_WORKER")
    require(info["Image"]==image_id and image_id.startswith("sha256:"),
            "BROKER_RUNTIME_IMAGE_ID_DRIFT")
    require(h["NetworkMode"]=="none" and h["ReadonlyRootfs"] is True
            and h["Privileged"] is False,"BROKER_NETWORK_ROOT_OR_PRIVILEGE_DRIFT")
    require(h.get("CapDrop") and {x.upper() for x in h["CapDrop"]}=={"ALL"}
            and not h.get("CapAdd"),"BROKER_ALL_CAPABILITIES_MUST_BE_DROPPED")
    require(any("no-new-privileges" in x for x in h.get("SecurityOpt") or []),
            "BROKER_NO_NEW_PRIVILEGES_REQUIRED")
    require(c.get("User")==str(uid)+":"+str(gid),"BROKER_NON_ROOT_ID_DRIFT")
    require(not c.get("Entrypoint"),"UNEXPECTED_BROKER_ENTRYPOINT")
    require(not h.get("PidMode") and h.get("IpcMode") in ("", "private", None),
            "BROKER_HOST_PID_OR_IPC_NAMESPACE_FORBIDDEN")
    require(not h.get("PortBindings") and not h.get("PublishAllPorts")
            and not h.get("Devices") and not h.get("Binds"),
            "BROKER_PRIVILEGED_DEVICE_OR_PORT_FORBIDDEN")
    require(h.get("PidsLimit")==64 and
            0<h.get("Memory",0)<=268435456,
            "BROKER_PROCESS_MEMORY_LIMIT_REQUIRED")
    mounts=info.get("Mounts") or []
    require(len(mounts)==2,"BROKER_EXACT_TWO_MOUNTS_REQUIRED")
    observed={(m["Destination"],str(Path(m["Source"]).resolve()),m["RW"])
              for m in mounts}
    expected={("/private",str(Path(private_dir).resolve()),True),
              ("/ipc",str(Path(shared_dir).resolve()),True)}
    require(observed==expected,"BROKER_SOURCE_MOUNTS_CHANGED")
    require(not any(x.startswith((
        "OPENAI_API_KEY=", "OPENAI_BASE_URL=", "ANTHROPIC_API_KEY=",
        "AWS_SECRET_ACCESS_KEY=", "GH_TOKEN=", "GITHUB_TOKEN="
    )) for x in c.get("Env") or []),"REAL_PROVIDER_OR_PLATFORM_SECRET_IN_BROKER_ENV")
    cmd=c.get("Cmd") or []
    require(len(cmd)>4 and cmd[:3]==["python","-B",
            "/app/scripts/task15_unix_ipc_mock_broker_server_v1.py"]
            and "--secret-file" in cmd and "/private/only-synthetic-credential" in cmd
            and "--ledger" in cmd and "/private/ledger.sqlite3" in cmd,
            "UNREVIEWED_BROKER_COMMAND")
    return True

def validate_host_private(private, credential):
    require(private.is_dir() and not private.is_symlink() and
            private.stat().st_mode&0o777==0o700,
            "BROKER_PRIVATE_DIRECTORY_OWNER_ONLY_REQUIRED")
    require(credential.is_file() and not credential.is_symlink() and
            credential.stat().st_mode&0o777==0o600,
            "SYNTHETIC_SECRET_FILE_OWNER_ONLY_REQUIRED")

def broker_process_probe(broker_id,uid):
    """Proof-only docker exec shares broker namespaces, never a live sender."""
    source = r'''
import errno,hashlib,json,os,pathlib,socket
p=pathlib.Path("/private/only-synthetic-credential")
db=pathlib.Path("/private/ledger.sqlite3")
assert os.geteuid()==int(os.environ.get("EXPECTED_UID","-1"))
assert p.is_file() and db.is_file() and p.stat().st_mode&0o777==0o600
assert not os.environ.get("OPENAI_API_KEY") and not os.environ.get("OPENAI_BASE_URL")
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.settimeout(2)
try: s.connect(("192.0.2.1",443))
except OSError as exc:
 assert exc.errno in (errno.ENETUNREACH,errno.EHOSTUNREACH,errno.ENETDOWN,errno.EAFNOSUPPORT),repr(exc)
else: raise AssertionError("BROKER_EXTERNAL_EGRESS_ALLOWED")
finally: s.close()
print(json.dumps({"broker_uid":os.geteuid(),"broker_private_file_access":True,
 "synthetic_credential_sha256":hashlib.sha256(p.read_bytes()).hexdigest(),
 "network_namespace_no_egress":True,"provider_key_absent":True},sort_keys=True))
'''
    proc=command(["docker","exec","--env","EXPECTED_UID="+str(uid),
                  broker_id,"python","-B","-c",source],timeout=20)
    return json.loads(proc.stdout.strip())

def junit(checks,output):
    s=ET.Element("testsuite",name=RULE,tests=str(len(checks)),
                 failures="0",errors="0")
    for name,ok in checks:
        require(ok,"JUNIT_PROOF_CONDITION_FALSE:"+name)
        ET.SubElement(s,"testcase",classname=RULE,name=name)
    ET.ElementTree(s).write(output,encoding="utf-8",xml_declaration=True)

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--output-dir",type=Path,required=True)
    a=ap.parse_args()
    out=a.output_dir.resolve()
    out.mkdir(parents=True,exist_ok=True)
    contract=json.loads(CONTRACT.read_text())
    require(contract["rule_of_one"]==RULE and
            contract["predecessor_merged_main_sha"]==BASE_MAIN and
            contract["live_provider_authorized"] is False,
            "WRONG_OR_LIVE_BROKER_ISOLATION_CONTRACT")
    require(not any(os.environ.get(k) for k in (
        "OPENAI_API_KEY","OPENAI_BASE_URL","ANTHROPIC_API_KEY",
        "AWS_SECRET_ACCESS_KEY","GH_TOKEN","GITHUB_TOKEN")),
        "NO_REAL_KEYS_IN_PROOF_ENVIRONMENT")
    uid,gid=os.geteuid(),os.getegid()
    require(uid>0 and gid>0 and uid!=65534 and gid!=65534,
            "UNEXPECTED_HOST_RUNNER_ID")
    # Build trusted image before any isolated runtime starts. Only pip's
    # fixed-version open-source dependencies may be downloaded: NO Provider.
    with tempfile.TemporaryDirectory(prefix="task15-broker-build-") as temp:
        ctx=Path(temp)
        (ctx/"scripts").mkdir()
        shutil.copy2(CORE,ctx/CORE.name)
        shutil.copy2(SERVER,ctx/"scripts"/SERVER.name)
        shutil.copy2(DOCKERFILE,ctx/"Dockerfile")
        source_sha={
           str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest()
           for p in (CORE,SERVER,DOCKERFILE,WORKER)
        }
        build=command(["docker","build","--pull","--file",str(ctx/"Dockerfile"),
                       "--tag","task15-isolated-mock-broker:v1",
                       str(ctx)],timeout=240)
        (out/"broker-image-build.log").write_text(build.stdout+build.stderr)
    broker_image=json.loads(command(["docker","image","inspect",
                                    "task15-isolated-mock-broker:v1"]).stdout)[0]
    image_id=broker_image["Id"]
    require(image_id.startswith("sha256:"),"BROKER_IMAGE_DIGEST_REQUIRED")
    pull=command(["docker","pull",WORKER_IMAGE],timeout=240)
    (out/"worker-image-pull.log").write_text(pull.stdout+pull.stderr)
    envelope,public_root=grant()
    broker_id=worker_id=None
    with tempfile.TemporaryDirectory(prefix="task15-two-isolated-containers-") as temp:
        root=Path(temp)
        root.chmod(0o755)
        shared=root/"shared";shared.mkdir(mode=0o755)
        private=root/"private";private.mkdir(mode=0o700)
        signed=shared/"grant.json"
        signed.write_text(json.dumps(envelope,sort_keys=True)+"\n")
        signed.chmod(0o644)
        credential=private/"only-synthetic-credential"
        credential.write_bytes(b"test-only-host-owned-"+secrets.token_hex(32).encode())
        credential.chmod(0o600)
        validate_host_private(private,credential)
        socket_path=shared/"broker.sock"
        ledger=private/"ledger.sqlite3"
        broker_events=private/"events.json"
        broker_cmd=[
          "docker","create","--network=none","--read-only",
          "--user="+str(uid)+":"+str(gid),"--cap-drop=ALL",
          "--security-opt=no-new-privileges","--pids-limit=64",
          "--memory=256m","--cpus=1",
          "--mount","type=bind,source="+str(shared)+",target=/ipc",
          "--mount","type=bind,source="+str(private)+",target=/private",
          "task15-isolated-mock-broker:v1",
          "python","-B","/app/scripts/task15_unix_ipc_mock_broker_server_v1.py",
          "--socket","/ipc/broker.sock",
          "--ledger","/private/ledger.sqlite3",
          "--secret-file","/private/only-synthetic-credential",
          "--operator-root-hex",public_root.hex(),
          "--output","/private/events.json"
        ]
        try:
            broker_id=command(broker_cmd,timeout=90).stdout.strip()
            require(len(broker_id)==64,"EXACT_BROKER_CONTAINER_ID_REQUIRED")
            info=json.loads(command(["docker","inspect",broker_id]).stdout)[0]
            validate_broker(info,private,shared,image_id,uid,gid)
            (out/"broker-container-inspect.json").write_text(
                json.dumps(info,sort_keys=True,indent=2)+"\n")
            command(["docker","start",broker_id],timeout=30)
            deadline=time.monotonic()+15
            while not socket_path.exists() and time.monotonic()<deadline:
                time.sleep(0.05)
            require(socket_path.is_socket(),"BROKER_SOCKET_NOT_READY_IN_OWN_CONTAINER")
            broker_probe=broker_process_probe(broker_id,uid)
            require(broker_probe["network_namespace_no_egress"] is True and
                    broker_probe["broker_private_file_access"] is True and
                    broker_probe["synthetic_credential_sha256"]==
                        hashlib.sha256(credential.read_bytes()).hexdigest(),
                    "BROKER_PRIVATE_MOUNT_OR_EGRESS_TEST_FAILED")
            (out/"broker-container-runtime-check.json").write_text(
                json.dumps(broker_probe,sort_keys=True,indent=2)+"\n")
            worker_cmd=[
                "docker","create","--network=none","--read-only",
                "--user=65534:65534","--cap-drop=ALL",
                "--security-opt=no-new-privileges","--pids-limit=64",
                "--memory=256m","--cpus=1",
                "--mount","type=bind,source="+str(shared)+",target=/ipc,readonly",
                "--mount","type=bind,source="+str(WORKER)+",target=/worker.py,readonly",
                WORKER_IMAGE,"python","-B","/worker.py"
            ]
            worker_id=command(worker_cmd,timeout=90).stdout.strip()
            require(len(worker_id)==64,"EXACT_WORKER_CONTAINER_ID_REQUIRED")
            winfo=json.loads(command(["docker","inspect",worker_id]).stdout)[0]
            inspect_worker(winfo,shared,WORKER)
            require(not any(m["Destination"]=="/private" for m in winfo["Mounts"]),
                    "BROKER_PRIVATE_STORAGE_EXPOSED_TO_WORKER")
            (out/"worker-container-inspect.json").write_text(
                json.dumps(winfo,sort_keys=True,indent=2)+"\n")
            result=command(["docker","start","--attach",worker_id],
                           timeout=45,check=False)
            (out/"worker-observation.log").write_text(result.stdout+result.stderr)
            worker_state=json.loads(command(["docker","inspect",worker_id]).stdout)[0]["State"]
            require(worker_state["ExitCode"]==0,"WORKER_ISOLATION_OR_IPC_FAILURE:"+
                    (result.stdout+result.stderr)[-1300:])
            messages=[s for s in result.stdout.splitlines() if s.strip()]
            require(len(messages)==1,"ONE_WORKER_OBSERVATION_REQUIRED")
            report=json.loads(messages[0])
            require(report["signed_mock_response"] is True and
                    report["replay_denied"] is True and
                    report["changed_target_denied"] is True and
                    report["broker_private_directory_absent"] is True and
                    report["external_tcp_testnet_blocked"] is True,
                    "NEGATIVE_WORKER_PROBES_MISSING")
            host_attempt=ask_host(socket_path,envelope)
            require(host_attempt=={"status":"DENIED",
                                   "code":"UNTRUSTED_UNIX_PEER_UID_GID"},
                    "HOST_PEER_IDENTITY_NOT_REJECTED")
            exit_status=command(["docker","wait",broker_id],timeout=30)
            require(exit_status.stdout.strip()=="0",
                    "BROKER_CONTAINER_NOT_SUCCESSFUL:"+exit_status.stdout.strip())
            events=json.loads(broker_events.read_text())
            require([x["decision"] for x in events["connections"]]==[
                    "MOCK_RECORDED","DENIED","DENIED","DENIED"]
                    and events["connections"][0]["peer_uid"]==65534
                    and events["connections"][-1]["peer_uid"]==uid
                    and events["mock_sink_calls"]==1,
                    "BROKER_AUTHORITY_OR_PEERCRED_TRACE_FAILED")
            (out/"broker-process.log").write_text(
                command(["docker","logs",broker_id],check=False).stdout)
            saved=out/"broker-ledger.sqlite3"
            ledger_proof=audit_sqlite(ledger,saved)
            require(ledger_proof["response_hash_matches"] and
                    ledger_proof["request_sha256"]==sha(envelope["request"]) and
                    ledger_proof["approval_sha256"]==sha(envelope["approval"]) and
                    len(ledger_proof["events"])==2,
                    "ONE_SHOT_SIGNED_SQLITE_INTEGRITY_FAILURE")
            (out/"broker-events.json").write_text(
                json.dumps(events,sort_keys=True,indent=2)+"\n")
            checks=[
               ("broker_runs_in_distinct_container",broker_id!=worker_id),
               ("broker_container_nonroot",uid not in (0,65534)),
               ("broker_no_external_network",broker_probe["network_namespace_no_egress"]),
               ("broker_private_credential_readable_only_in_broker_mount",broker_probe["broker_private_file_access"]),
               ("worker_cannot_mount_broker_private_storage",report["broker_private_directory_absent"]),
               ("worker_no_external_network",report["external_tcp_testnet_blocked"]),
               ("signed_test_grant_mock_once",events["connections"][0]["decision"]=="MOCK_RECORDED"),
               ("durable_duplicate_denied",events["connections"][1]["decision"]=="DENIED"),
               ("target_drift_denied",events["connections"][2]["decision"]=="DENIED"),
               ("wrong_os_peer_denied",events["connections"][3]["reason"]=="UNTRUSTED_UNIX_PEER_UID_GID"),
               ("sqlite_source_grant_receipt_integrity",ledger_proof["response_hash_matches"]),
               ("no_real_provider_or_bank_effects",events["real_provider_calls"]==0 and events["bank_effects"]==0),
            ]
            junit(checks,out/"task15-broker-container-junit.xml")
            evidence={
              "rule_of_one":RULE,
              "determination":"BOUNDED_CONTAINER_ONLY_MOCK_BROKER_SECRET_AND_LEDGER_ISOLATION_PASS_NOT_PRODUCTION_PROVEN",
              "base_main_sha":BASE_MAIN,
              "source_sha256":source_sha,
              "broker_image_id":image_id,
              "worker_image":WORKER_IMAGE,
              "broker_container_id":broker_id,
              "worker_container_id":worker_id,
              "broker_uid":uid,"worker_uid":65534,
              "signed_test_grant":envelope,"test_public_root_hex":public_root.hex(),
              "broker_probe":broker_probe,"worker_report":report,
              "connections":events["connections"],"durable_ledger":ledger_proof,
              "junit_passed":len(checks),"real_provider_requests":0,
              "real_provider_spend_usd":0,"real_bank_effects":0,
              "independent_auditor_determination":"PENDING",
            }
            (out/"task15-broker-container-evidence.json").write_text(
                json.dumps(evidence,sort_keys=True,indent=2)+"\n")
            print("PASS_BOUNDED_TWO_CONTAINER_MOCK_BROKER: "+
                  str(len(checks))+"/"+str(len(checks)))
            print("REAL_PROVIDER_REQUESTS=0; SPEND_USD=0; BANK_EFFECTS=0")
        finally:
            for cid in (worker_id,broker_id):
                if cid:
                    command(["docker","rm","-f",cid],check=False,timeout=30)

if __name__=="__main__":
    try:
        main()
    except BaseException as exc:
        print("BROKER_CONTAINER_ISOLATION_FAIL_CLOSED:"+repr(exc),file=sys.stderr)
        raise
