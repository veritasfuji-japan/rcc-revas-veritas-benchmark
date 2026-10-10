#!/usr/bin/env python3
"""#284 offline Docker/Unix trusted-revocation-vs-stolen-worker proof.

Two separate, bounded runtime scenarios each have 3 Unix connections and
one host-authorized docker-exec revocation. Raw SQL, Docker inspect, TEST
Ed25519 grant, response and receipt hashes archived. Never real Provider.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import sys
import tempfile
import time
import xml.etree.ElementTree as ET

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey,Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from datetime import datetime,timedelta,timezone
import sqlite3
from task15_signed_admin_revocation_v1 import DOMAIN,ACTION
from task15_mock_broker_authorization_boundary_v1 import canonical,sha
from scripts.task15_unix_ipc_mock_broker_process_audit_v1 import (
    IMAGE as WORKER_IMAGE,command,grant,ask_host,require
)
from scripts.task15_broker_container_secret_isolation_audit_v1 import (
    broker_process_probe,validate_host_private
)
from scripts.task15_stolen_session_revocation_audit_v1 import inspect_and_copy

RULE="TASK15_SIGNED_ADMIN_REVOCATION_V1"
ADMIN_SIGNER=Ed25519PrivateKey.generate()
ADMIN_PUBLIC=ADMIN_SIGNER.public_key().public_bytes(
    serialization.Encoding.Raw,serialization.PublicFormat.Raw)

def build_test_admin_command(*,signer=None,expired=False,altered=False,nonce=None):
    now=datetime.now(timezone.utc)
    issued=now-timedelta(minutes=12 if expired else 1)
    expires=issued+timedelta(minutes=3)
    statement={
        "domain":DOMAIN,"action":ACTION,
        "request_sha256":sha(__import__(
           "task15_mock_broker_authorization_boundary_v1").exact_request()),
        "nonce":nonce or secrets.token_hex(32),
        "issued_at":issued.isoformat(),
        "expires_at":expires.isoformat(),
        "no_live_provider":True,"max_spend_micro_usd":0,
        "bank_effects":False
    }
    who=signer or ADMIN_SIGNER
    signed={"statement":statement,
            "signature_hex":who.sign(canonical(statement).encode()).hex()}
    if altered:
        signed["statement"]["request_sha256"]="f"*64
    return signed

BASE="3f1f7fe3c606a694d7b07330e0a3e2e86752e737"
IMAGE="task15-signed-admin-revocation-broker:v1"
SERVER=ROOT/"scripts/task15_signed_admin_docker_broker_v1.py"
WORKER=ROOT/"scripts/task15_docker_revocation_worker_v1.py"
DOCKERFILE=ROOT/"docker/task15_signed_admin_revocation_v1.Dockerfile"
SOURCE=[
    ROOT/"task15_mock_broker_authorization_boundary_v1.py",
    ROOT/"task15_stolen_session_revocation_fence_v1.py",
    ROOT/"task15_signed_admin_revocation_v1.py",
    ROOT/"scripts/task15_unix_ipc_mock_broker_server_v1.py",
    ROOT/"scripts/task15_session_challenge_broker_server_v1.py",
    SERVER,WORKER,DOCKERFILE
]

def inspect_runtime(info,role,shared,private,token,img):
    h=info["HostConfig"];c=info["Config"]
    require(h["NetworkMode"]=="none" and h["ReadonlyRootfs"] is True
            and h["Privileged"] is False and
            {z.upper() for z in h.get("CapDrop") or []}=={"ALL"}
            and not h.get("CapAdd"),"PRIVILEGED_OR_NETWORK_ENABLED_RUNTIME")
    require(any("no-new-privileges" in v for v in h.get("SecurityOpt") or [])
            and h.get("PidsLimit")==64 and h.get("Memory")==268435456,
            "CAPABILITY_OR_RESOURCE_DRIFT")
    require(not h.get("Binds") and not h.get("Devices") and
            not h.get("PortBindings") and not h.get("PidMode") and
            h.get("IpcMode") in ("private","",None),
            "RUNTIME_HOST_INTERFACE_FORBIDDEN")
    require(not any(e.startswith(("OPENAI_API_KEY=","OPENAI_BASE_URL=",
              "ANTHROPIC_API_KEY=","AWS_SECRET_ACCESS_KEY=",
              "GH_TOKEN=","GITHUB_TOKEN=")) for e in c.get("Env") or []),
            "REAL_PROVIDER_CREDENTIAL_ENV")
    got={(m["Destination"],str(Path(m["Source"]).resolve()),m["RW"])
         for m in info["Mounts"]}
    if role=="broker":
        expected={("/private",str(private.resolve()),True),
                  ("/ipc",str(shared.resolve()),True)}
        require(c["User"]==str(os.geteuid())+":"+str(os.getegid())
                and info["Image"]==img and (c.get("Cmd") or [])[:3]==[
                 "python","-B","/app/scripts/task15_signed_admin_docker_broker_v1.py"],
                "BROKER_USER_IMAGE_OR_ENTRYPOINT_DRIFT")
    else:
        expected={("/ipc",str(shared.resolve()),False),
                  ("/worker.py",str(WORKER.resolve()),False)}
        if role!="forged":
            expected.add(("/worker-session.key",str(token.resolve()),False))
        require(c["User"]=="65534:65534"
                and c.get("Cmd",[])[:3]==["python","-B","/worker.py"],
                "WORKER_USER_OR_ENTRYPOINT_DRIFT")
    require(got==expected,"UNEXPECTED_RUNTIME_MOUNT_"+role)
    require(c.get("Entrypoint") in (None,[]),"ENTRYPOINT_OVERRIDE_FORBIDDEN")
    return True

def create_runtime(scenario,role,shared,private,token,pub,imageid):
    common=["docker","create","--network=none","--read-only",
            "--cap-drop=ALL","--security-opt=no-new-privileges",
            "--pids-limit=64","--memory=256m","--cpus=1"]
    if role=="broker":
        cmd=common+[
          "--user="+str(os.geteuid())+":"+str(os.getegid()),
          "--mount","type=bind,source="+str(shared)+",target=/ipc",
          "--mount","type=bind,source="+str(private)+",target=/private",
          IMAGE,"python","-B","/app/scripts/task15_signed_admin_docker_broker_v1.py",
          "--mode","serve","--scenario",scenario,"--connections","3",
          "--socket","/ipc/broker.sock","--ledger","/private/ledger.sqlite3",
          "--secret-file","/private/only-synthetic-credential",
          "--session-key-file","/private/worker-session.key",
          "--operator-root-hex",pub.hex(),
          "--admin-root-hex",ADMIN_PUBLIC.hex(),"--output","/private/events.json"
        ]
    else:
        raise AssertionError("create_runtime only creates broker")
    cid=command(cmd,timeout=60).stdout.strip()
    require(len(cid)==64,"EXACT_FRESH_BROKER_CONTAINER_ID")
    info=json.loads(command(["docker","inspect",cid]).stdout)[0]
    inspect_runtime(info,"broker",shared,private,token,imageid)
    return cid,info

def worker_call(scenario,role,expect,shared,private,token,imageid,out,idx):
    cmd=["docker","create","--network=none","--read-only",
         "--user=65534:65534","--cap-drop=ALL",
         "--security-opt=no-new-privileges","--pids-limit=64",
         "--memory=256m","--cpus=1",
         "--mount","type=bind,source="+str(shared)+",target=/ipc,readonly",
         "--mount","type=bind,source="+str(WORKER)+",target=/worker.py,readonly"]
    if role!="forged":
        cmd+=["--mount","type=bind,source="+str(token)+
              ",target=/worker-session.key,readonly"]
    cmd += [WORKER_IMAGE,"python","-B","/worker.py",
            "--role",role,"--expect",expect]
    cid=command(cmd,timeout=60).stdout.strip()
    require(len(cid)==64,"EXACT_FRESH_WORKER_CONTAINER_ID")
    try:
        info=json.loads(command(["docker","inspect",cid]).stdout)[0]
        inspect_runtime(info,role,shared,private,token,imageid)
        (out/(scenario+"-worker"+str(idx)+"-inspect.json")).write_text(
            json.dumps(info,sort_keys=True,indent=2)+"\n")
        p=command(["docker","start","--attach",cid],check=False,timeout=40)
        (out/(scenario+"-worker"+str(idx)+".log")).write_text(p.stdout+p.stderr)
        state=json.loads(command(["docker","inspect",cid]).stdout)[0]["State"]
        require(state["ExitCode"]==0,"MOCK_WORKER_FAILED:"+p.stderr[-1400:])
        lines=[line for line in p.stdout.splitlines() if line.strip()]
        require(len(lines)==1,"EXACT_ONE_WORKER_EVIDENCE_ROW_REQUIRED")
        evidence=json.loads(lines[0])
        require(evidence["expected"]==expect and
                evidence["real_provider_calls"]==0 and
                evidence["external_network_blocked"] is True,
                "WORKER_EVIDENCE_MISMATCH")
        return evidence
    finally:
        command(["docker","rm","-f",cid],check=False,timeout=20)

def trusted_revoke(brokerid,pub,out,scenario):
    # Host controls Docker and may invoke trusted CLI. Docker privilege,
    # configured test admin trust root and host FS ownership remain assumptions.
    info=json.loads(command(["docker","inspect",brokerid]).stdout)[0]
    mounts=[m for m in info["Mounts"] if m["Destination"]=="/private"]
    require(len(mounts)==1,"TRUSTED_BROKER_PRIVATE_MOUNT_REQUIRED")
    private=Path(mounts[0]["Source"])
    admin_command=private/"admin-command.json"
    base_cmd=[
       "docker","exec",brokerid,"python","-B",
       "/app/scripts/task15_signed_admin_docker_broker_v1.py",
       "--mode","trusted-revoke",
       "--ledger","/private/ledger.sqlite3",
       "--secret-file","/private/only-synthetic-credential",
       "--operator-root-hex",pub.hex(),
       "--admin-root-hex",ADMIN_PUBLIC.hex(),
       "--signed-admin-command-file","/private/admin-command.json"
    ]
    refusal=[]
    def invoke(label,payload,code,should_fail=True):
        admin_command.write_text(json.dumps(payload,sort_keys=True)+"\n")
        admin_command.chmod(0o600)
        p=command(base_cmd,check=False,timeout=30)
        (out/(scenario+"-admin-"+label+".log")).write_text(p.stdout+p.stderr)
        if should_fail:
            require(p.returncode!=0 and code in p.stderr+p.stdout,
                    "ADMIN_NEGATIVE_TEST_FAILED_"+label+":"+(p.stderr+p.stdout)[-900:])
            refusal.append({"case":label,"denied":True,"code":code})
            return None
        require(p.returncode==0,"VALID_SIGNED_ADMIN_COMMAND_DENIED:"+
                (p.stderr+p.stdout)[-1000:])
        lines=[z for z in p.stdout.splitlines() if z.strip()]
        require(len(lines)==1,"ADMIN_SUCCESS_ONE_JSON_RECEIPT_REQUIRED")
        return json.loads(lines[0])
    invoke("wrong-key",
           build_test_admin_command(signer=Ed25519PrivateKey.generate()),
           "INVALID_INDEPENDENT_ADMIN_SIGNATURE")
    invoke("expired",build_test_admin_command(expired=True),
           "ADMIN_COMMAND_EXPIRED_FUTURE_OR_OVERLONG")
    invoke("changed-target",build_test_admin_command(altered=True),
           "ADMIN_COMMAND_ACTION_TARGET_OR_BUDGET_DRIFT")
    token=build_test_admin_command()
    parsed=invoke("valid",token,None,should_fail=False)
    invoke("replayed",token,"ADMIN_COMMAND_NONCE_ALREADY_CONSUMED")
    invoke("different-valid-after-revoke",build_test_admin_command(),
           "TARGET_ALREADY_REVOKED")
    with sqlite3.connect(private/"ledger.sqlite3") as db:
        cmds=db.execute("SELECT nonce,command_sha,request_sha,root_sha FROM admin_commands").fetchall()
        events=db.execute("SELECT nonce,command_sha,event FROM admin_audit").fetchall()
        revocations=db.execute("SELECT request_sha FROM revoked_requests").fetchall()
        integrity=db.execute("PRAGMA integrity_check").fetchone()[0]
    require(integrity=="ok" and len(cmds)==len(events)==len(revocations)==1,
            "SIGNED_ADMIN_ONESHOT_LEDGER_INTEGRITY_REQUIRED")
    require(cmds[0][0]==token["statement"]["nonce"] and
            cmds[0][1]==sha(token) and
            cmds[0][2]==sha(__import__(
                "task15_mock_broker_authorization_boundary_v1").exact_request()) and
            cmds[0][3]==hashlib.sha256(ADMIN_PUBLIC).hexdigest() and
            events[0]==(cmds[0][0],cmds[0][1],"SIGNED_ADMIN_REVOCATION_COMMITTED"),
            "SIGNED_ADMIN_COMMAND_WAS_NOT_ATOMICALLY_CONSUMED")
    require(parsed["admin_process_uid"]==os.geteuid() and
            parsed["trusted_side_revocation"]["state"]=="REVOKED",
            "VALID_ADMIN_COMMAND_TRUSTED_DOCKER_EXEC_FAILED")
    evidence={
       "signed_admin_command":token,
       "test_admin_public_root_hex":ADMIN_PUBLIC.hex(),
       "trusted_admin_receipt":dict(parsed),
       "denied_admin_attempts":refusal,
       "durable_admin_command":[list(z) for z in cmds],
       "durable_admin_event":[list(z) for z in events]
    }
    (out/(scenario+"-admin-auth.json")).write_text(
        json.dumps(evidence,sort_keys=True,indent=2)+"\n")
    # Keep #284 durable proof's same evidence shape.
    parsed["signed_admin_proof"]=evidence
    return parsed

def run_scenario(scenario,out,imageid):
    envelope,pub=grant()
    require(pub!=ADMIN_PUBLIC,"SEPARATE_TEST_SIGNER_ROOTS_REQUIRED")
    Ed25519PublicKey.from_public_bytes(pub).verify(
        bytes.fromhex(envelope["approval"]["signature_hex"]),
        canonical(envelope["approval"]["statement"]).encode("utf-8"))
    with tempfile.TemporaryDirectory(prefix="task15-docker-revoke-"+scenario) as td:
        home=Path(td);home.chmod(0o755)
        shared=home/"shared";shared.mkdir(mode=0o755)
        private=home/"private";private.mkdir(mode=0o700)
        fixture=shared/"grant.json";fixture.write_text(json.dumps(envelope,sort_keys=True)+"\n")
        fixture.chmod(0o644)
        cred=private/"only-synthetic-credential"
        cred.write_bytes(b"test-only-host-owned-"+secrets.token_hex(32).encode())
        cred.chmod(0o600)
        token=private/"worker-session.key"
        token.write_bytes(secrets.token_bytes(32));token.chmod(0o444)
        validate_host_private(private,cred)
        require(token.stat().st_mode&0o777==0o444,"TEST_SESSION_KEY_MODE_0444_REQUIRED")
        brokerid=None
        try:
            brokerid,inspect=create_runtime(scenario,"broker",shared,private,token,pub,imageid)
            (out/(scenario+"-broker-inspect.json")).write_text(
                json.dumps(inspect,sort_keys=True,indent=2)+"\n")
            command(["docker","start",brokerid],timeout=30)
            socket_path=shared/"broker.sock"
            deadline=time.monotonic()+15
            while not socket_path.exists() and time.monotonic()<deadline:
                time.sleep(.05)
            require(socket_path.is_socket(),"TRUSTED_BROKER_SOCKET_NOT_READY")
            check=broker_process_probe(brokerid,os.geteuid())
            require(check["network_namespace_no_egress"] is True and
                    check["broker_private_file_access"] is True,
                    "BROKER_EGRESS_OR_PRIVATE_STORAGE_DRIFT")
            (out/(scenario+"-broker-probe.json")).write_text(
                json.dumps(check,sort_keys=True,indent=2)+"\n")
            observed=[]
            if scenario=="revocation_first":
                observed.append(worker_call(scenario,"forged","session-deny",
                     shared,private,token,imageid,out,1))
                admin=trusted_revoke(brokerid,pub,out,scenario)
                observed.append(worker_call(scenario,"stolen","revoked",
                     shared,private,token,imageid,out,2))
                host_result=ask_host(socket_path,envelope)
                require(host_result=={"status":"DENIED",
                        "code":"UNTRUSTED_UNIX_PEER_UID_GID"},
                        "HOST_UID_NOT_REJECTED_BEFORE_CHALLENGE")
                observed.append({"role":"host_wrong_uid","expected":"peer-deny",
                                 "status":"DENIED","real_provider_calls":0})
            elif scenario=="claim_first":
                observed.append(worker_call(scenario,"stolen","mock-once",
                     shared,private,token,imageid,out,1))
                admin=trusted_revoke(brokerid,pub,out,scenario)
                observed.append(worker_call(scenario,"stolen","revoked",
                     shared,private,token,imageid,out,2))
                observed.append(worker_call(scenario,"legitimate","revoked",
                     shared,private,token,imageid,out,3))
            else:
                raise AssertionError("UNFROZEN_SCENARIO")
            waited=command(["docker","wait",brokerid],timeout=30)
            require(waited.stdout.strip()=="0",
                    "BROKER_CONTAINER_EXIT_FAILURE:"+waited.stdout.strip())
            (out/(scenario+"-broker.log")).write_text(
                command(["docker","logs",brokerid],check=False).stdout)
            event_path=private/"events.json"
            require(event_path.is_file(),"BROKER_AUDIT_EVENT_FILE_REQUIRED")
            ev=json.loads(event_path.read_text())
            (out/(scenario+"-events.json")).write_text(
                json.dumps(ev,indent=2,sort_keys=True)+"\n")
            archived=inspect_and_copy(private/"ledger.sqlite3",
                                     out/(scenario+"-ledger.sqlite3"))
            require(archived["response_sha256_verified"] and
                    archived["revocation_rows"][0][0]==sha(envelope["request"]) and
                    archived["revocation_audit"][0][1]=="REVOCATION_COMMITTED",
                    "DURABLE_REQUEST_REVOCATION_HASH_INTEGRITY")
            if scenario=="revocation_first":
                require(ev["mock_sink_calls"]==0 and
                        archived["dispatch_rows"]==[] and
                        archived["dispatch_audit"]==[] and
                        [x["reason"] for x in ev["connections"]]==[
                          "INVALID_SESSION_CHALLENGE_RESPONSE",
                          "TRUSTED_BROKER_REQUEST_REVOKED",
                          "UNTRUSTED_UNIX_PEER_UID_GID"
                        ],"REVOCATION_BEFORE_CLAIM_NOT_FAIL_CLOSED")
            else:
                require(ev["mock_sink_calls"]==1 and
                        len(archived["dispatch_rows"])==1 and
                        archived["dispatch_rows"][0][2]=="MOCK_RECORDED" and
                        archived["dispatch_rows"][0][3]==1 and
                        [x["reason"] for x in ev["connections"]]==[
                          "SIGNED_TEST_SINGLE_USE_MOCK_ADMITTED",
                          "TRUSTED_BROKER_REQUEST_REVOKED",
                          "TRUSTED_BROKER_REQUEST_REVOKED"
                        ],"CLAIM_BEFORE_REVOCATION_NONRETROACTIVE_RISK_NOT_SHOWN")
                require(archived["dispatch_rows"][0][0]==sha(envelope["request"])
                        and archived["dispatch_rows"][0][1]==sha(envelope["approval"]) and
                        [x[1] for x in archived["dispatch_audit"]]==[
                         "CLAIMED_BEFORE_MOCK_SINK","MOCK_SINK_RECORDED"
                        ],"SIGNED_TEST_CLAIM_AND_RECEIPT_SHA_MISMATCH")
            return {
               "scenario":scenario,"broker_container_id":brokerid,
               "operator_public_test_root_hex":pub.hex(),
               "test_only_signed_grant":envelope,
               "session_key_sha256":hashlib.sha256(token.read_bytes()).hexdigest(),
               "trusted_admin":admin,"workers":observed,
               "events":ev["connections"],"mock_sink_calls":ev["mock_sink_calls"],
               "revocation":ev["revocation"],"ledger":archived,
               "broker_runtime_no_external_network":True,
               "real_provider_calls":0,"real_provider_spend_usd":0,
               "bank_effects":0
            }
        finally:
            if brokerid:
                command(["docker","rm","-f",brokerid],check=False,timeout=30)

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--output-dir",required=True,type=Path)
    args=p.parse_args()
    out=args.output_dir.resolve();out.mkdir(parents=True,exist_ok=True)
    cfg=json.loads((ROOT/"contracts"/(RULE+".json")).read_text())
    require(cfg["rule_of_one"]==RULE and
            cfg["predecessor_merged_main_sha"]==BASE and
            cfg["real_provider_execution_authorized"] is False,
            "WRONG_PROOF_OR_REAL_PROVIDER_SCOPE")
    require(not any(os.environ.get(v) for v in (
       "OPENAI_API_KEY","OPENAI_BASE_URL","ANTHROPIC_API_KEY",
       "AWS_SECRET_ACCESS_KEY","GH_TOKEN","GITHUB_TOKEN"
    )),"REAL_API_SECRETS_IN_OFFLINE_PROOF")
    require(os.geteuid() not in (0,65534) and os.getegid()!=65534,
            "TRUSTED_CI_HOST_NON_ROOT_REQUIRED")
    source_sha={str(f.relative_to(ROOT)):hashlib.sha256(f.read_bytes()).hexdigest()
                for f in SOURCE}
    with tempfile.TemporaryDirectory(prefix="task15-revocation-image-") as temp:
        home=Path(temp)
        for source in SOURCE:
            if source==WORKER or source==DOCKERFILE:continue
            path=home/source.relative_to(ROOT)
            path.parent.mkdir(parents=True,exist_ok=True)
            shutil.copy2(source,path)
        shutil.copy2(DOCKERFILE,home/"Dockerfile")
        build=command(["docker","build","--pull","--file",
          str(home/"Dockerfile"),"--tag",IMAGE,str(home)],timeout=240)
        (out/"trusted-broker-image-build.log").write_text(build.stdout+build.stderr)
    broker_image=json.loads(command(["docker","image","inspect",IMAGE]).stdout)[0]["Id"]
    require(broker_image.startswith("sha256:"),"BROKER_IMAGE_HASH_MISSING")
    pulled=command(["docker","pull",WORKER_IMAGE],timeout=240)
    (out/"worker-pinned-image-pull.log").write_text(pulled.stdout+pulled.stderr)
    two=[run_scenario("revocation_first",out,broker_image),
         run_scenario("claim_first",out,broker_image)]
    require(sum(x["mock_sink_calls"] for x in two)==1
            and all(x["revocation"]["revoked_count"]==1 for x in two),
            "TWO_SCENARIO_EXACT_TOTAL_MOCK_EFFECT_VIOLATION")
    checks=[

      ("independent_admin_root_differs_from_model_grant",all(x["operator_public_test_root_hex"]!=ADMIN_PUBLIC.hex() for x in two)),
      ("four_invalid_admin_commands_denied_per_scenario",all(len(x["trusted_admin"]["signed_admin_proof"]["denied_admin_attempts"])==5 for x in two)),
      ("single_admin_token_record_per_scenario",all(len(x["trusted_admin"]["signed_admin_proof"]["durable_admin_command"])==1 for x in two)),
      ("test_admin_signature_never_claimed_as_real_enrollment",all(x["trusted_admin"]["signed_admin_proof"]["test_admin_public_root_hex"]==ADMIN_PUBLIC.hex() for x in two)),
      ("real_docker_brokers_distinct",two[0]["broker_container_id"]!=two[1]["broker_container_id"]),
      ("both_brokers_networkless",all(x["broker_runtime_no_external_network"] for x in two)),
      ("trusted_admin_exec_only",all(x["trusted_admin"]["trusted_side_revocation"]["state"]=="REVOKED" for x in two)),
      ("revocation_first_zero_effects",two[0]["mock_sink_calls"]==0),
      ("claim_first_single_mock_effect",two[1]["mock_sink_calls"]==1),
      ("stolen_key_after_revocation_denied",two[0]["workers"][1]["status"]=="DENIED"),
      ("stolen_key_after_claim_revoked",two[1]["workers"][1]["status"]=="DENIED"),
      ("legitimate_key_after_revoke_denied",two[1]["workers"][2]["status"]=="DENIED"),
      ("wrong_session_key_denied",two[0]["workers"][0]["status"]=="DENIED"),
      ("host_wrong_uid_denied",two[0]["events"][2]["reason"]=="UNTRUSTED_UNIX_PEER_UID_GID"),
      ("no_dispatch_row_before_revoked",two[0]["ledger"]["dispatch_rows"]==[]),
      ("one_signed_mock_row_before_revoked",len(two[1]["ledger"]["dispatch_rows"])==1),
      ("raw_sqlite_receipts_match",all(x["ledger"]["response_sha256_verified"] for x in two)),
      ("durable_revocation_audit_two_databases",all(len(x["ledger"]["revocation_audit"])==1 for x in two)),
      ("exact_six_ipc_decisions",sum(len(x["events"]) for x in two)==6),
      ("all_live_provider_and_bank_effects_zero",all(x["real_provider_calls"]==0 and x["bank_effects"]==0 for x in two))
    ]
    require(len(checks)==20 and all(ok for _,ok in checks),
            "TWENTY_SIGNED_ADMIN_DOCKER_INVARIANTS_NOT_CLOSED")
    xml=ET.Element("testsuite",name=RULE,tests="20",failures="0",errors="0",skipped="0")
    for name,_ in checks:
        ET.SubElement(xml,"testcase",classname=RULE,name=name)
    ET.ElementTree(xml).write(out/"task15-docker-revocation-junit.xml",
                               encoding="utf-8",xml_declaration=True)
    evidence={
       "rule_of_one":RULE,
       "determination":"BOUNDED_TRUSTED_DOCKER_EXEC_REVOCATION_ENFORCED_BY_AF_UNIX_BROKER_NOT_PRODUCTION_PROVEN",
       "predecessor_merged_main_sha":BASE,
       "broker_image_id":broker_image,"worker_image":WORKER_IMAGE,
       "source_sha256":source_sha,"scenarios":two,
       "runtime_junit_passed":len(checks),
       "provider_requests":0,"spend_usd":0,"bank_effects":0,
       "independent_auditor_determination":"PENDING"
    }
    (out/"task15-docker-revocation-evidence.json").write_text(
        json.dumps(evidence,sort_keys=True,indent=2)+"\n")
    print("PASS_SIGNED_ADMIN_DOCKER_REVOCATION: 20/20; REVOCATION_FIRST=0 EFFECT; CLAIM_FIRST=1 MOCK EFFECT")
    print("REAL_PROVIDER_REQUESTS=0; SPEND_USD=0; BANK_EFFECTS=0")

if __name__=="__main__":
    try:
        main()
    except BaseException as err:
        print("TASK15_DOCKER_REVOCATION_FAIL_CLOSED:"+repr(err),file=sys.stderr)
        raise
