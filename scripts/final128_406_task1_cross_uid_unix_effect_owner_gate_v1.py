#!/usr/bin/env python3
"""#406: distinct Unix UIDs, file DAC, SO_PEERCRED and real Native Task1 Bind.

Owned effect holder and requestor are two Linux OS identities in dedicated
Ubuntu CI. Real Native bank state remains ONLY in the owner process. Agent
may connect to a group-permitted local UNIX socket; SO_PEERCRED enforces
exact agent UID before any Native tool invocation. The owner checks a 0600
synthetic sentinel file in its 0700 owner-only directory; no real credentials
or external effect backend exist. Requests reuse #405 bounded JSON decode
and real pinned #402 VERITAS Bind, with Task1 write policy always DENY.

NOT a privileged production bank, container confinement, IAM/egress proof,
credential-specific backend enforcement, general Native action allow, or
unbypassable production execution. Root/capable insiders not modeled.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import stat
import struct
import sys

from scripts import final128_405_task1_separate_executor_json_gate_v1 as prior
from scripts import final128_399_task1_frozen_direct_native_bind_v1 as native
from scripts import task1_source_bound_readonly_grounding_v1 as grounding

SCHEMA = "veritas.final128.task1-406-cross-uid-unix-peercred-bind-gate-v1"
MAX_FRAME = prior.MAX_FRAME_BYTES
MAX_CONNECTIONS = 110
CANARY_FILENAME = "owner-only-simulated-credential.txt"


class Refused(ValueError):
    pass


def need(ok, code):
    if ok is not True:
        raise Refused("406_"+code)


def _no_links(path):
    """Reject symlink components of sensitive locations."""
    p=Path(path)
    need(p.is_absolute(),"ABSOLUTE_PATH_REQUIRED")
    cur=Path("/")
    for part in p.parts[1:]:
        need(part not in ("..",".",""),"RELATIVE_COMPONENT_REFUSED")
        cur=cur/part
        need(not cur.is_symlink(),"SYMLINK_PATH_REFUSED")


def check_owner_only_dir(secret_dir):
    _no_links(secret_dir)
    d=Path(secret_dir)
    ds=d.stat()
    uid=os.geteuid()
    need(os.getuid()==uid and uid!=0 and ds.st_uid==uid
         and stat.S_ISDIR(ds.st_mode)
         and stat.S_IMODE(ds.st_mode)==0o700,
         "PRIVATE_OWNER_DIRECTORY_DAC_REQUIRED")
    f=d/CANARY_FILENAME
    _no_links(str(f))
    fs=f.stat()
    need(fs.st_uid==uid and fs.st_nlink==1
         and stat.S_ISREG(fs.st_mode)
         and stat.S_IMODE(fs.st_mode)==0o600
         and fs.st_size>=24 and fs.st_size<=128,
         "OWNER_ONLY_SIMULATED_CREDENTIAL_DAC_REQUIRED")
    # Never send marker bytes, even in errors, logs or public manifests.
    fd=os.open(f,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        payload=os.read(fd,129)
    finally:
        os.close(fd)
    need(len(payload)==fs.st_size and len(payload)>=24,
         "SIMULATED_CANARY_CONTENT_UNAVAILABLE")
    del payload
    return True


def peercred(conn):
    need(sys.platform.startswith("linux")
         and hasattr(socket,"SO_PEERCRED"),
         "LINUX_SO_PEERCRED_REQUIRED")
    fmt="3i"
    raw=conn.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,
                        struct.calcsize(fmt))
    pid,uid,gid=struct.unpack(fmt,raw)
    need(pid>1 and uid>=0 and gid>=0,
         "INVALID_KERNEL_PEER_CREDENTIALS")
    return {"pid":pid,"uid":uid,"gid":gid}


def _public_reply(base,*,agent_uid,owner_uid,peer,canary_verified):
    result={
        "schema":SCHEMA,
        "ok":base["ok"],
        "code":base["code"],
        "worker_pid":base["worker_pid"],
        "owner_uid":owner_uid,
        "authenticated_peer_uid":peer["uid"],
        "expected_agent_uid":agent_uid,
        "os_peercred_exact_uid_admitted":peer["uid"]==agent_uid,
        "private_synthetic_canary_verified_by_owner":canary_verified,
        "authoritative_initial_sha256":base["initial_authoritative_state_sha256"],
        "authoritative_current_sha256":base["current_authoritative_state_sha256"],
        "guarded_bind_adjudications":base["guarded_bind_adjudications"],
        "guarded_bind_blocked":base["guarded_bind_blocked"],
        "native_readonly_dispatches":base["native_readonly_dispatches"],
        "native_protected_dispatches":base["native_protected_dispatches"],
        "source_owned_task1_policy":"NO_MUTATION",
        "local_separate_uid_dac_peercred_test_only":True,
        "real_external_effect_credentials_used":False,
        "external_bank_effects":0,
        "real_provider_requests":0,
        "native_official_scorer_calls":0,
        "production_iam_backend_enforced_proven":False,
        "production_network_egress_enforced_proven":False,
        "production_nonbypassable_execution_proven":False,
        "independent_real_model_histories_proven":False,
    }
    need(result["authoritative_initial_sha256"]==
         result["authoritative_current_sha256"]
         and result["native_protected_dispatches"]==0
         and result["guarded_bind_adjudications"]==
             result["guarded_bind_blocked"],
         "AUTHORITY_OWNER_DID_NOT_HOLD_NO_EFFECT")
    return result


def owner_server(*,socket_path,private_dir,agent_uid):
    """Distinct-UID socket owner; only its process contains authoritative bank."""
    need(sys.platform.startswith("linux")
         and type(agent_uid) is int and agent_uid>0
         and agent_uid!=os.geteuid()
         and os.geteuid()!=0
         and os.getuid()==os.geteuid(),
         "DISTINCT_UNPRIVILEGED_LINUX_IDS_REQUIRED")
    _no_links(socket_path)
    canary_verified=check_owner_only_dir(private_dir)
    socket_file=Path(socket_path)
    dir_stat=socket_file.parent.stat()
    need(dir_stat.st_uid==os.geteuid()
         and stat.S_IMODE(dir_stat.st_mode)==0o2770
         and stat.S_ISDIR(dir_stat.st_mode)
         and not socket_file.exists(),
         "CONTROLLED_GROUP_SOCKET_DIRECTORY_REQUIRED")
    env,original,runtime,journal=prior.build_worker_source()
    need(env.model_dump(mode="json")==original,
         "EXACT_NATIVE_TASK1_BANK_REQUIRED")
    pid=os.getpid()
    old_umask=os.umask(0o117)
    server=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
    try:
        server.bind(str(socket_file))
        os.chmod(socket_file,0o660)
        socket_mode=socket_file.stat()
        need(stat.S_ISSOCK(socket_mode.st_mode)
             and socket_mode.st_uid==os.geteuid()
             and stat.S_IMODE(socket_mode.st_mode)==0o660,
             "GROUP_SOCKET_DAC_REQUIRED")
        server.listen(8)
        count=0
        while count<MAX_CONNECTIONS:
            conn,_=server.accept()
            count+=1
            stop=False
            with conn:
                peer=peercred(conn)
                # An unrelated UID never reaches any Native source handler.
                if peer["uid"]!=agent_uid:
                    continue
                stream=conn.makefile("rb")
                try:
                    raw=stream.readline(MAX_FRAME+1)
                finally:
                    stream.close()
                try:
                    req=prior.decode_frame(raw)
                    base=prior._handle(
                        req,env=env,initial=original,runtime=runtime,
                        journal=journal,pid=pid)
                    stop=req["op"]=="close"
                except prior.Refused:
                    req=None
                    base=prior._stable_response(
                        ok=False,code="405_MALFORMED_OR_FORBIDDEN_REQUEST",
                        pid=pid,initial=original,
                        current=env.model_dump(mode="json"),journal=journal)
                reply=_public_reply(
                    base,agent_uid=agent_uid,owner_uid=os.geteuid(),
                    peer=peer,canary_verified=canary_verified)
                payload=json.dumps(reply,sort_keys=True,separators=(",",":"),
                                   ensure_ascii=False,allow_nan=False).encode()+b"\n"
                need(len(payload)<=MAX_FRAME,"BOUNDED_REDACTED_RESPONSE_REQUIRED")
                conn.sendall(payload)
            need(env.model_dump(mode="json")==original
                 and journal["native_protected_dispatches"]==0
                 and journal["bind_adjudications"]==journal["bind_blocked"],
                 "AUTHORITATIVE_BANK_CHANGED_BY_NATIVE_REQUEST")
            if stop:
                break
        return count
    finally:
        server.close()
        os.umask(old_umask)
        if socket_file.exists():
            socket_file.unlink()


def agent_json_request(socket_path,raw_json):
    """Strictly transport a caller's bytes: no bank object, no privilege."""
    need(type(raw_json) is str and len(raw_json.encode("utf8"))<MAX_FRAME,
         "BOUNDED_AGENT_TEXT_REQUIRED")
    data=raw_json.encode("utf8")+b"\n"
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as conn:
        conn.settimeout(8)
        conn.connect(socket_path)
        conn.sendall(data)
        with conn.makefile("rb") as stream:
            response=stream.readline(MAX_FRAME+1)
    need(response.endswith(b"\n") and len(response)<=MAX_FRAME,
         "MISSING_EXACT_BOUNDED_CHILD_RESPONSE")
    result=json.loads(response)
    need(result.get("schema")==SCHEMA
         and result.get("os_peercred_exact_uid_admitted") is True
         and result.get("authenticated_peer_uid")==os.geteuid()
         and result.get("owner_uid")!=os.geteuid(),
         "NO_KERNEL_AUTHENTICATED_CROSS_UID_RESPONSE")
    return result


def agent_owner_file_probe(filename):
    """OS DAC denial test, not a test of real privileged bank credentials."""
    try:
        with open(filename,"rb") as f:
            f.read(1)
    except (PermissionError,FileNotFoundError) as exc:
        # Only PermissionError is a meaningful test: absent file != denial.
        need(isinstance(exc,PermissionError),
             "SENSITIVE_CANARY_NOT_PRESENT_IS_NOT_DAC_DENIAL")
        return {
            "schema":SCHEMA,
            "os_denial_observed":True,
            "denial":"EACCES_OR_EPERM",
            "probe_uid":os.geteuid(),
            "real_credentials_used":False,
        }
    raise Refused("406_PRIVATE_FILE_READ_UNEXPECTEDLY_SUCCEEDED")


def agent_owner_signal_probe(pid):
    need(type(pid) is int and pid>1,"WORKER_PID_REQUIRED")
    try:
        os.kill(pid,0)
    except PermissionError:
        return {"schema":SCHEMA,"os_signal_permission_denied":True,
                "probe_uid":os.geteuid(),"worker_pid":pid}
    except ProcessLookupError as exc:
        raise Refused("406_WORKER_DID_NOT_EXIST_SIGNAL_TEST_INVALID") from exc
    raise Refused("406_UNPRIVILEGED_AGENT_CAN_SIGNAL_OWNER")


def redacted_summary(*,worker_uid,agent_uid,first,reading,denied,last,
                     os_file_denied,signal_denied):
    need(type(worker_uid) is int and type(agent_uid) is int
         and worker_uid>0 and agent_uid>0 and worker_uid!=agent_uid
         and all(x["schema"]==SCHEMA for x in (first,reading,denied,last))
         and all(x["owner_uid"]==worker_uid
                 and x["authenticated_peer_uid"]==agent_uid
                 and x["os_peercred_exact_uid_admitted"] is True
                 and x["private_synthetic_canary_verified_by_owner"] is True
                 for x in (first,reading,denied,last))
         and first["authoritative_initial_sha256"]==
             last["authoritative_current_sha256"]
         and reading["code"]=="405_NATIVE_READ_ONLY_OK"
         and denied["code"]=="405_VERITAS_PREEXECUTION_REFUSAL"
         and denied["guarded_bind_adjudications"]==
             first["guarded_bind_adjudications"]+1
         and denied["guarded_bind_blocked"]==
             first["guarded_bind_blocked"]+1
         and last["native_protected_dispatches"]==0
         and os_file_denied is True and signal_denied is True,
         "MULTI_ID_NATIVE_AUTHORITY_OR_OS_DAC_GUARD_FAILED")
    return {
        "schema":SCHEMA,
        "status":"LOCAL_DISTINCT_OS_UID_DAC_PEERCRED_AND_REAL_BIND_REFUSAL",
        "case_id":native.CASE,
        "agentdojo_pin":native.NATIVE_PIN,
        "veritas_pin":native.VERITAS_PIN,
        "owner_uid_distinct_from_agent_uid":True,
        "linux_so_peercred_verified":True,
        "unix_socket_group_dac_verified":True,
        "owner_only_synthetic_file_0600_and_directory_0700":True,
        "agent_owner_only_file_read_denied_by_os":os_file_denied,
        "agent_owner_process_signal_denied_by_os":signal_denied,
        "private_authoritative_original_sha256":first["authoritative_initial_sha256"],
        "private_authoritative_final_sha256":last["authoritative_current_sha256"],
        "authoritative_state_unchanged":True,
        "real_veritas_bind_refusals":1,
        "native_readonly_still_operational":True,
        "external_real_effect_credentials_used":False,
        "real_external_bank_effects":0,
        "paid_provider_requests":0,
        "official_native_scorer_calls":0,
        "real_iam_or_egress_boundary_proven":False,
        "globally_nonbypassable_production_effect_proven":False,
        "external_single_use_capability_consumed":False,
        "official_utility_A":None,
        "official_utility_B":None,
    }


def forbid_paid_provider_or_real_effect(*_a,**_kw):
    raise Refused("406_FRESH_SPEND_APPROVAL_AND_REAL_CREDENTIAL_BOUNDARY_MISSING")


def main(argv):
    if len(argv)==5 and argv[1]=="--server":
        return owner_server(socket_path=argv[2],private_dir=argv[3],
                            agent_uid=int(argv[4]))
    if len(argv)==4 and argv[1]=="--agent":
        print(json.dumps(agent_json_request(argv[2],argv[3]),
                         sort_keys=True))
        return 0
    if len(argv)==3 and argv[1]=="--probe-file":
        print(json.dumps(agent_owner_file_probe(argv[2]),sort_keys=True))
        return 0
    if len(argv)==3 and argv[1]=="--probe-signal":
        print(json.dumps(agent_owner_signal_probe(int(argv[2])),sort_keys=True))
        return 0
    raise SystemExit("406_LOCAL_LINUX_IDENTITY_TEST_ONLY")


if __name__=="__main__":
    main(sys.argv)
