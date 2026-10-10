#!/usr/bin/env python3
"""Offline two-container broker plus same-UID impersonator proof.

Case 1: same-UID separate container with signed TEST grant but NO session key.
Cases 2-5: valid worker has session key, but only one exact request admitted.
Case 6: host user different UID denied before challenge.
Host/kernel/Docker trusted; no real API call or Provider credential.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from scripts.task15_unix_ipc_mock_broker_process_audit_v1 import (
    IMAGE as WORKER_IMAGE, command, grant, ask_host, audit_sqlite, require, sha
)
from scripts.task15_broker_container_secret_isolation_audit_v1 import (
    broker_process_probe,validate_host_private
)
RULE="TASK15_WORKER_SESSION_CHALLENGE_V1"
BASE="bda9fcd7137cdb504333a20472e6d7ae7dbf4718"
IMAGE="task15-worker-session-broker:v1"
SERVER=ROOT/"scripts/task15_session_challenge_broker_server_v1.py"
WORKER=ROOT/"scripts/task15_session_challenge_worker_v1.py"
DOCKERFILE=ROOT/"docker/task15_session_challenge_broker_v1.Dockerfile"
CORE=ROOT/"task15_mock_broker_authorization_boundary_v1.py"
PREV_SERVER=ROOT/"scripts/task15_unix_ipc_mock_broker_server_v1.py"

def assert_container(c,role,shared,private,token,imageid):
    h=c["HostConfig"]; cfg=c["Config"]
    require(h["NetworkMode"]=="none" and h["ReadonlyRootfs"] is True
            and h["Privileged"] is False,"RUNTIME_NET_ROOT_OR_PRIVILEGE")
    require({v.upper() for v in (h.get("CapDrop") or [])}=={"ALL"}
            and not h.get("CapAdd") and any(
                "no-new-privileges" in v for v in h.get("SecurityOpt") or []
            ),"RUNTIME_CAPABILITIES_OR_NEW_PRIVILEGES")
    require(h.get("PidsLimit")==64 and
            h.get("Memory")==268435456,"RESOURCE_LIMIT_REQUIRED")
    require(not h.get("PortBindings") and not h.get("Devices")
            and not h.get("Binds") and not h.get("PidMode")
            and h.get("IpcMode") in ("private","",None),
            "HOST_INTERFACE_EXPOSED")
    require(not any(x.startswith(("OPENAI_API_KEY=","OPENAI_BASE_URL=",
          "ANTHROPIC_API_KEY=","AWS_SECRET_ACCESS_KEY=",
          "GH_TOKEN=","GITHUB_TOKEN=")) for x in cfg.get("Env") or []),
          "REAL_CREDENTIAL_IN_CONTAINER")
    mounts=c["Mounts"]
    got={(m["Destination"],str(Path(m["Source"]).resolve()),m["RW"])
         for m in mounts}
    if role=="broker":
        require(c["Image"]==imageid and cfg["User"]==str(os.geteuid())+
                ":"+str(os.getegid()),"BROKER_ID_IMAGE_DRIFT")
        expected={("/ipc",str(shared.resolve()),True),
                  ("/private",str(private.resolve()),True)}
        require((cfg.get("Cmd") or [])[:3]==[
            "python","-B","/app/scripts/task15_session_challenge_broker_server_v1.py"
        ],"BROKER_ENTRYPOINT_DRIFT")
    else:
        require(cfg["User"]=="65534:65534"
                and c["Image"].startswith("sha256:"),
                "WORKER_ID_OR_IMAGE_MISSING")
        expected={("/ipc",str(shared.resolve()),False),
                  ("/worker.py",str(WORKER.resolve()),False)}
        if role=="legitimate":
            expected.add(("/worker-session.key",str(token.resolve()),False))
        require(cfg.get("Cmd")==["python","-B","/worker.py","--mode",role],
                "WORKER_ENTRYPOINT_CHANGED")
    require(got==expected,"UNEXPECTED_MOUNTS_FOR_"+role)
    require(cfg.get("Entrypoint") in (None,[]),
            "UNEXPECTED_RUNTIME_ENTRYPOINT")
    return True

def make_container(shared,private,token,imageid,public_root,role):
    common=["docker","create","--network=none","--read-only",
            "--cap-drop=ALL","--security-opt=no-new-privileges",
            "--pids-limit=64","--memory=256m","--cpus=1"]
    if role=="broker":
        cmd=common+[
            "--user="+str(os.geteuid())+":"+str(os.getegid()),
            "--mount","type=bind,source="+str(shared)+",target=/ipc",
            "--mount","type=bind,source="+str(private)+",target=/private",
            IMAGE,"python","-B",
            "/app/scripts/task15_session_challenge_broker_server_v1.py",
            "--socket","/ipc/broker.sock",
            "--ledger","/private/ledger.sqlite3",
            "--secret-file","/private/only-synthetic-credential",
            "--session-key-file","/private/worker-session.key",
            "--operator-root-hex",public_root.hex(),
            "--output","/private/events.json"
        ]
    else:
        cmd=common+[
            "--user=65534:65534",
            "--mount","type=bind,source="+str(shared)+",target=/ipc,readonly",
            "--mount","type=bind,source="+str(WORKER)+",target=/worker.py,readonly"
        ]
        if role=="legitimate":
            cmd+=["--mount","type=bind,source="+str(token)+
                  ",target=/worker-session.key,readonly"]
        cmd += [WORKER_IMAGE,"python","-B","/worker.py","--mode",role]
    cid=command(cmd,timeout=60).stdout.strip()
    require(len(cid)==64,"EXACT_DOCKER_CONTAINER_ID")
    info=json.loads(command(["docker","inspect",cid]).stdout)[0]
    assert_container(info,role,shared,private,token,imageid)
    return cid,info

def start_worker(cid,role,out):
    raw=command(["docker","start","--attach",cid],check=False,timeout=45)
    state=json.loads(command(["docker","inspect",cid]).stdout)[0]["State"]
    (out/(role+"-worker.log")).write_text(raw.stdout+raw.stderr)
    require(state["ExitCode"]==0,"FAILED_"+role+"_WORKER:"+raw.stderr[-1600:])
    lines=[x for x in raw.stdout.splitlines() if x.strip()]
    require(len(lines)==1,"ONE_"+role+"_EVIDENCE_ROW_REQUIRED")
    return json.loads(lines[0])

def write_junit(checks,out):
    require(len(checks)==15 and all(ok for _,ok in checks),
            "FIFTEEN_INVARIANT_ASSERTIONS_NOT_CLOSED")
    xml=ET.Element("testsuite",name=RULE,tests=str(len(checks)),
                   failures="0",errors="0",skipped="0")
    for name,_ in checks:
        ET.SubElement(xml,"testcase",classname=RULE,name=name)
    ET.ElementTree(xml).write(
        out/"task15-worker-session-challenge-junit.xml",
        encoding="utf-8",xml_declaration=True)

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--output-dir",required=True,type=Path)
    args=p.parse_args()
    out=args.output_dir.resolve();out.mkdir(parents=True,exist_ok=True)
    contract=json.loads(
        (ROOT/"contracts"/(RULE+".json")).read_text())
    require(contract["rule_of_one"]==RULE and
            contract["predecessor_merged_main_sha"]==BASE and
            contract["real_provider_calls_authorized"] is False,
            "FROZEN_SESSION_PROOF_PROFILE_MISMATCH")
    require(not any(os.environ.get(v) for v in (
        "OPENAI_API_KEY","OPENAI_BASE_URL","ANTHROPIC_API_KEY",
        "AWS_SECRET_ACCESS_KEY","GH_TOKEN","GITHUB_TOKEN"
    )),"LIVE_CREDENTIALS_IN_PROOF_ENVIRONMENT")
    require(os.geteuid() not in (0,65534) and os.getegid()!=65534,
            "HOST_ROOT_OR_WORKER_UID_NOT_ALLOWED")
    source_hashes={
        str(f.relative_to(ROOT)):hashlib.sha256(f.read_bytes()).hexdigest()
        for f in (SERVER,WORKER,DOCKERFILE,CORE,PREV_SERVER)
    }
    with tempfile.TemporaryDirectory(prefix="task15-session-build-") as td:
        context=Path(td)
        (context/"scripts").mkdir()
        for f in (CORE,SERVER,PREV_SERVER):
            dest=context/f.relative_to(ROOT)
            dest.parent.mkdir(parents=True,exist_ok=True)
            shutil.copy2(f,dest)
        shutil.copy2(DOCKERFILE,context/"Dockerfile")
        b=command(["docker","build","--pull","--file",
                   str(context/"Dockerfile"),"--tag",IMAGE,str(context)],
                  timeout=240)
        (out/"broker-image-build.log").write_text(b.stdout+b.stderr)
    broker_image=json.loads(command(["docker","image","inspect",IMAGE]).stdout)[0]["Id"]
    require(broker_image.startswith("sha256:"),"BROKER_IMAGE_DIGEST_MISSING")
    pull=command(["docker","pull",WORKER_IMAGE],timeout=240)
    (out/"worker-image-pull.log").write_text(pull.stdout+pull.stderr)
    envelope,pub=grant()
    ids=[]
    with tempfile.TemporaryDirectory(prefix="task15-session-") as td:
        root=Path(td);root.chmod(0o755)
        shared=root/"shared";shared.mkdir(mode=0o755)
        private=root/"private";private.mkdir(mode=0o700)
        signed=shared/"grant.json"
        signed.write_text(json.dumps(envelope,sort_keys=True)+"\n")
        signed.chmod(0o644)
        credential=private/"only-synthetic-credential"
        credential.write_bytes(b"test-only-host-owned-"+secrets.token_hex(32).encode())
        credential.chmod(0o600)
        token=private/"worker-session.key"
        token.write_bytes(secrets.token_bytes(32))
        token.chmod(0o444) # host private dir remains 0700; worker receives only this file mount
        validate_host_private(private,credential)
        require(token.stat().st_mode&0o777==0o444,
                "SESSION_KEY_READONLY_PUBLIC_FILE_MODE_INSIDE_PRIVATE_HOST_DIR_REQUIRED")
        try:
            broker_id,broker_inspect=make_container(
                shared,private,token,broker_image,pub,"broker")
            ids.append(broker_id)
            (out/"broker-container-inspect.json").write_text(
                json.dumps(broker_inspect,sort_keys=True,indent=2)+"\n")
            command(["docker","start",broker_id],timeout=30)
            deadline=time.monotonic()+15
            sock=shared/"broker.sock"
            while not sock.exists() and time.monotonic()<deadline:
                time.sleep(.05)
            require(sock.is_socket(),"BROKER_CHALLENGE_SOCKET_NOT_READY")
            observed=broker_process_probe(broker_id,os.geteuid())
            require(observed["network_namespace_no_egress"] is True and
                    observed["broker_private_file_access"] is True,
                    "BROKER_PRIVATE_STATE_OR_EGRESS_DRIFT")
            attacker_id,attacker_inspect=make_container(
                shared,private,token,broker_image,pub,"impersonator")
            ids.append(attacker_id)
            (out/"impersonator-container-inspect.json").write_text(
                json.dumps(attacker_inspect,sort_keys=True,indent=2)+"\n")
            attacker=start_worker(attacker_id,"impersonator",out)
            require(attacker["same_uid_request_denied"] is True
                    and attacker["session_mount_absent"] is True,
                    "SAME_UID_WITH_NO_KEY_NOT_REJECTED")
            legit_id,legit_inspect=make_container(
                shared,private,token,broker_image,pub,"legitimate")
            ids.append(legit_id)
            (out/"legitimate-container-inspect.json").write_text(
                json.dumps(legit_inspect,sort_keys=True,indent=2)+"\n")
            worker=start_worker(legit_id,"legitimate",out)
            require(worker["wrong_nonce_denied"] is True
                    and worker["signed_one_shot_passed"] is True
                    and worker["durable_replay_denied"] is True
                    and worker["target_mutation_denied"] is True,
                    "WORKER_FRESH_SESSION_NEGATIVE_OR_POSITIVE_CASE_FAILED")
            host=ask_host(sock,envelope)
            require(host=={"status":"DENIED",
                           "code":"UNTRUSTED_UNIX_PEER_UID_GID"},
                    "HOST_PEER_MUST_BE_DENIED_BEFORE_CHALLENGE")
            state=command(["docker","wait",broker_id],timeout=30)
            require(state.stdout.strip()=="0",
                    "SIX_CONNECTION_BROKER_RETURN_NONZERO:"+state.stdout)
            (out/"broker-process.log").write_text(
                command(["docker","logs",broker_id],check=False).stdout)
            events=json.loads((private/"events.json").read_text())
            con=events["connections"]
            require(len(con)==6 and [e["decision"] for e in con]==[
                "DENIED","DENIED","MOCK_RECORDED","DENIED","DENIED","DENIED"
            ],"EXPECTED_SIX_BROKER_SESSION_DECISIONS")
            require(all(e["peer_uid"]==65534 and e["peer_gid"]==65534
                        for e in con[:5]) and
                    con[5]["peer_uid"]==os.geteuid() and
                    con[5]["peer_gid"]==os.getegid(),
                    "SAME_UID_DIFFERENT_CONTAINER_AND_HOST_ID_AUDIT_FAILED")
            require(events["mock_sink_calls"]==1 and
                    con[0]["reason"]=="INVALID_SESSION_CHALLENGE_RESPONSE"
                    and con[1]["reason"]=="INVALID_SESSION_CHALLENGE_RESPONSE"
                    and con[3]["reason"]=="ONE_SHOT_REQUEST_ALREADY_CONSUMED_OR_UNKNOWN"
                    and con[4]["reason"]=="FROZEN_MODEL_SOURCE_OR_TARGET_DRIFT"
                    and con[5]["reason"]=="UNTRUSTED_UNIX_PEER_UID_GID",
                    "SIX_SESSION_DENIAL_REASONS_MISMATCH")
            raw=audit_sqlite(private/"ledger.sqlite3",out/"broker-ledger.sqlite3")
            require(raw["response_hash_matches"] and
                    raw["request_sha256"]==sha(envelope["request"]) and
                    raw["approval_sha256"]==sha(envelope["approval"]) and
                    raw["events"]==[
                      "CLAIMED_BEFORE_MOCK_SINK","MOCK_SINK_RECORDED"
                    ],"DURABLE_APPROVED_ONE_SHOT_LEDGER_NOT_MATCHED")
            checks=[
                ("separate_broker_and_workers",len(set(ids))==3),
                ("identical_worker_and_impersonator_uids",attacker["uid"]==worker["uid"]==65534),
                ("attacker_has_no_session_key",attacker["session_mount_absent"]),
                ("same_uid_attacker_rejected_before_mock",con[0]["decision"]=="DENIED"),
                ("nonce_substitution_rejected_before_mock",con[1]["decision"]=="DENIED"),
                ("genuine_session_grant_consumed_once",con[2]["decision"]=="MOCK_RECORDED"),
                ("replayed_approval_rejected",con[3]["decision"]=="DENIED"),
                ("changed_target_rejected",con[4]["decision"]=="DENIED"),
                ("host_wrong_uid_rejected",con[5]["decision"]=="DENIED"),
                ("broker_runtime_no_egress",observed["network_namespace_no_egress"]),
                ("worker_only_key_file_bind_mount",len(legit_inspect["Mounts"])==3),
                ("impersonator_same_uid_no_key_bind_mount",len(attacker_inspect["Mounts"])==2),
                ("one_sqlite_claim",events["broker_state"]["claims"]==[1]),
                ("sqlite_response_hash_integrity",raw["response_hash_matches"]),
                ("no_live_calls_spend_or_bank_effect",events["real_provider_calls"]==0
                 and events["real_provider_spend_usd"]==0 and events["bank_effects"]==0)
            ]
            write_junit(checks,out)
            (out/"broker-events.json").write_text(json.dumps(events,indent=2,sort_keys=True)+"\n")
            evidence={
                "rule_of_one":RULE,
                "determination":"BOUNDED_SESSION_KEYED_CHALLENGE_REJECTS_SAME_UID_NO_KEY_IMPERSONATOR_NOT_PRODUCTION_PROVEN",
                "base_main_sha":BASE,"source_sha256":source_hashes,
                "broker_image_id":broker_image,"worker_base_image":WORKER_IMAGE,
                "container_ids":{"broker":broker_id,"attacker":attacker_id,"worker":legit_id},
                "public_test_grant":envelope,"test_operator_root_hex":pub.hex(),
                "session_key_sha256":hashlib.sha256(token.read_bytes()).hexdigest(),
                "broker_probe":observed,"attacker_report":attacker,"worker_report":worker,
                "six_peer_decisions":con,"sqlite_proof":raw,
                "junit_assertions":len(checks),"real_provider_calls":0,
                "provider_spend_usd":0,"bank_effects":0,
                "independent_auditor_determination":"PENDING"
            }
            (out/"task15-session-challenge-evidence.json").write_text(
                json.dumps(evidence,indent=2,sort_keys=True)+"\n")
            print("PASS_SAME_UID_IMPERSONATOR_DENIED: 15/15 runtime assertions; six IPC events")
            print("REAL_PROVIDER_CALLS=0; SPEND_USD=0; BANK_EFFECTS=0")
        finally:
            for cid in reversed(ids):
                command(["docker","rm","-f",cid],check=False,timeout=30)

if __name__=="__main__":
    try:
        main()
    except BaseException as e:
        print("TASK15_SESSION_CHALLENGE_FAIL_CLOSED:"+repr(e),file=sys.stderr)
        raise
