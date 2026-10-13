#!/usr/bin/env python3
"""Task4 #375: isolated Native-v2 TLS sandbox + real broker authorization path.

Trusted GitHub host launches:
  front Docker --internal bridge: unprivileged agent + broker only.
  back Docker --internal bridge: actual pinned VERITAS sandbox TLS service,
    dedicated PostgreSQL, and broker only.
The broker runs the SAME #374 native-v2 signed/consumed/effect/reconciled code
inside its network namespace. Front agent lacks network access and all tokens.
A deliberately host-attached backend rogue receives 401 without writer token.

All data, keys, issuer, policy, Model output and effects are synthetic.
This is NOT production IAM/credential deployment, hostile host resistance,
independent third-party auditing, or proof of agent→authorized broker API.
"""
from __future__ import annotations
import argparse
from datetime import datetime,timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import tempfile
import time
import xml.etree.ElementTree as ET

ROOT=Path(__file__).resolve().parents[1]
WORKSPACE=ROOT.parent
OS_SRC=WORKSPACE/"veritas_os_source"
BEN_SRC=WORKSPACE/"ben_canonical_source"
OS_PIN="9b7376ba0077365b9d89004b06c80e76c8bfadc8"
BEN_PIN="1d3782d3aae5ff9c88036709c1a5642320cc53c2"
IMAGE="task4-375-native-v2-verified-broker:offline-v1"
PYIMAGE=("python:3.11.16-slim@sha256:"
         "e41613d42d4891e4930f79523f93f81bbc7632584ec65e36ab055f41a800b41e")
SINK="https://sandbox.example.invalid/v1/events"
SENSITIVE=("OPENAI_API_KEY","ANTHROPIC_API_KEY","OPENAI_BASE_URL",
    "GITHUB_TOKEN","GH_TOKEN","AWS_SECRET_ACCESS_KEY",
    "VERITAS_SANDBOX_WRITER_TOKEN","VERITAS_SANDBOX_READER_TOKEN")
SOURCE_FILES=(
    "scripts/task4_375_native_v2_docker_network_audit_v1.py",
    "scripts/task4_375_native_v2_agent_network_probe_v1.py",
    "docker/task4_375_native_v2_broker_runtime_v1.Dockerfile",
    "docs/TASK4_375_NATIVE_V2_DOCKER_NETWORK_BYPASS_DENIAL_V1.md",
)

def insist(ok,reason):
    if ok is not True:
        raise AssertionError("TASK4_375_"+reason)

def command(argv,*,timeout=90,check=True,cwd=WORKSPACE):
    p=subprocess.run(argv,text=True,capture_output=True,timeout=timeout,cwd=cwd)
    if check and p.returncode:
        # Synthetic credentials are passed through --env but must not be
        # reproduced in error messages or uploaded audit records.
        raise AssertionError("COMMAND_FAILED rc="+str(p.returncode)+
                             " stderr_tail="+p.stderr[-1500:])
    return p

def docker(*args,timeout=90,check=True):
    return command(["docker",*args],timeout=timeout,check=check)

def sha256_file(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def assert_source_pins(out):
    insist(command(["git","-C",str(OS_SRC),"rev-parse","HEAD"]).stdout.strip()==OS_PIN,
           "UPSTREAM_NATIVE_VERITAS_PIN_MISMATCH")
    insist(command(["git","-C",str(BEN_SRC),"rev-parse","HEAD"]).stdout.strip()==BEN_PIN,
           "UPSTREAM_BEN_CANONICAL_PIN_MISMATCH")
    git_head=command(["git","-C",str(ROOT),"rev-parse","HEAD"]).stdout.strip()
    insist(len(git_head)==40,"BENCHMARK_HEAD_REQUIRED")
    files=[
        "veritas_os/policy/native_bind_authorization.py",
        "veritas_os/policy/native_bind_authorization_consumption.py",
        "veritas_os/policy/sandbox_bind_execution.py",
        "veritas_os/policy/sandbox_https_transport.py",
        "veritas_os/policy/sandbox_event_service.py",
        "veritas_os/policy/sandbox_reconciliation.py",
        "veritas_os/policy/sandbox_receipt_outcome.py",
    ]
    hashes={p:sha256_file(OS_SRC/p) for p in files}
    (out/"exact-pinned-native-v2-source-provenance.json").write_text(
        json.dumps({"benchmark_sha":git_head,"veritas_os_sha":OS_PIN,
                    "ben_canonical_sha":BEN_PIN,"upstream_module_sha256":hashes},
                   indent=2,sort_keys=True)+"\n")
    return git_head,hashes

def create_network(name,out):
    ident=docker("network","create","--driver","bridge","--internal",name).stdout.strip()
    item=json.loads(docker("network","inspect",name).stdout)[0]
    insist(item["Id"]==ident and item["Driver"]=="bridge" and
           item["Internal"] is True and item["Attachable"] is False,
           "UNTRUSTED_EXTERNAL_NETWORK_PRESENT")
    info={"name":name,"id":ident,"internal":item["Internal"],
          "attachable":item["Attachable"],"driver":item["Driver"]}
    (out/(name+"-network.json")).write_text(json.dumps(info,sort_keys=True,indent=2)+"\n")
    return info

def inspect(cid,role,expected,*,source_mounts,strict_role):
    obj=json.loads(docker("inspect",cid).stdout)[0]
    host=obj["HostConfig"]
    config=obj["Config"]
    network=obj["NetworkSettings"]["Networks"]
    insist(set(network)==set(expected),"NETWORK_ROLE_WRONG_"+role)
    insist(host["NetworkMode"]!="host" and not host["Privileged"],
           "HOST_NETWORK_OR_PRIVILEGED_"+role)
    insist(not host.get("PortBindings"),"PUBLISHED_PORT_"+role)
    if strict_role:
        insist(config["User"]=="65534:65534" and
               host["ReadonlyRootfs"] is True and
               {x.upper() for x in host["CapDrop"] or []}=={"ALL"} and
               any("no-new-privileges" in x for x in (host.get("SecurityOpt") or [])),
               "UNTRUSTED_OR_BROKER_PROCESS_HARDENING_"+role)
    mounts={m["Destination"]:{
        "source":m["Source"],"type":m["Type"],"rw":m["RW"]}
        for m in obj["Mounts"]}
    insist(not any(m["Destination"]=="/var/run/docker.sock" for m in obj["Mounts"]),
           "DOCKER_SOCKET_MOUNTED_"+role)
    insist(set(mounts)==set(source_mounts),"ROLE_MOUNT_DRIFT_"+role)
    ret={"role":role,"container_id":cid,"image_id":obj["Image"],
         "networks":sorted(network),"ip_by_network":{k:v["IPAddress"] for k,v in network.items()},
         "user":config.get("User"),"readonly_root":host.get("ReadonlyRootfs"),
         "cap_drop":host.get("CapDrop"),"privileged":host.get("Privileged"),
         "no_published_ports":True,"docker_socket_mounted":False,
         "mount_destinations":sorted(mounts),
         # Do not expose Env, because broker/sink have test-only credentials.
         "test_only_credentials_redacted":True,
         }
    return ret

def mock_tls_material(folder):
    folder.mkdir(mode=0o755,exist_ok=True)
    (folder/"ext.cnf").write_text(
        "subjectAltName=DNS:sandbox.example.invalid\n"
        "extendedKeyUsage=serverAuth\n")
    command(["openssl","req","-x509","-newkey","rsa:2048","-nodes",
             "-days","1","-keyout",str(folder/"ca.key"),
             "-out",str(folder/"ca.crt"),
             "-subj","/CN=Task4-375 Synthetic Root CA",
             "-addext","basicConstraints=critical,CA:TRUE"],timeout=35)
    command(["openssl","req","-newkey","rsa:2048","-nodes",
             "-keyout",str(folder/"server.key"),"-out",str(folder/"server.csr"),
             "-subj","/CN=sandbox.example.invalid"],timeout=35)
    command(["openssl","x509","-req","-days","1",
             "-in",str(folder/"server.csr"),
             "-CA",str(folder/"ca.crt"),
             "-CAkey",str(folder/"ca.key"),"-CAcreateserial",
             "-out",str(folder/"server.crt"),
             "-extfile",str(folder/"ext.cnf")],timeout=35)
    for fname in ("server.key","server.crt","ca.crt"):
        (folder/fname).chmod(0o644) # ephemeral CI-only; read-only sink mount
    cert=command(["openssl","x509","-in",str(folder/"server.crt"),
                  "-noout","-text"]).stdout
    insist("DNS:sandbox.example.invalid" in cert,"EXACT_NATIVE_V2_TLS_SAN")
    return {"ca_sha256":sha256_file(folder/"ca.crt"),
            "server_cert_sha256":sha256_file(folder/"server.crt"),
            "tls_hostname":"sandbox.example.invalid",
            "ca_private_key_mounted_anywhere":False}

def new_container(name,network,alias,image,argv,*,mounts=(),env=(),
                  user="65534:65534",tmpfs=(),sysctls=(),memory="1g",
                  strict=True):
    args=["create","--name",name,"--network",network,"--network-alias",alias]
    if strict:
        args+=["--user",user,"--read-only","--cap-drop","ALL",
               "--security-opt","no-new-privileges","--pids-limit","128",
               "--memory",memory,"--cpus","2"]
    for key,value in env:
        args+=["--env",key+"="+value]
    for source,dest,ro in mounts:
        arg="type=bind,source="+str(source)+",target="+dest
        if ro:arg+=",readonly"
        args+=["--mount",arg]
    for tmp in tmpfs:
        args+=["--tmpfs",tmp]
    for x in sysctls:
        args+=["--sysctl",x]
    cid=docker(*args,image,*argv,timeout=40).stdout.strip()
    insist(len(cid)==64,"CONTAINER_CREATE_FAILED")
    return cid

def wait_pg(cid):
    for _ in range(80):
        p=docker("exec",cid,"pg_isready","-U","veritas",
                 "-d","veritas_action_capability",timeout=6,check=False)
        if p.returncode==0:return
        time.sleep(.35)
    raise AssertionError("TASK4_375_POSTGRES_HEALTH_TIMEOUT")

def wait_sink(gateway_id,out):
    # Verify actual TLS SNI/CA and require real upstream 401 before dispatch.
    # Build bytes from CR/LF integers to avoid shell-escaping ambiguities.
    script=(
        "import socket,ssl;"
        "ctx=ssl.create_default_context(cafile='/tls/ca.crt');"
        "s=socket.create_connection(('sandbox.example.invalid',443),3);"
        "t=ctx.wrap_socket(s,server_hostname='sandbox.example.invalid');"
        "cr=bytes((13,10));"
        "req=cr.join((b'GET /v1/operations?idempotency_key=t375-ready HTTP/1.1',"
        "b'Host: sandbox.example.invalid',b'Connection: close',b'',b''));"
        "t.sendall(req);"
        "reply=t.recv(512);"
        "assert reply.startswith(b'HTTP/1.1 401 '),repr(reply[:80]);"
        "print('NATIVE_V2_EXACT_TLS_POSITIVE_AND_AUTH_401');"
        "t.close()"
    )
    for _ in range(85):
        p=docker("exec",gateway_id,"python","-B","-c",script,timeout=6,check=False)
        if p.returncode==0:
            (out/"gateway-sink-tls-positive-control.log").write_text(p.stdout)
            return
        time.sleep(.35)
    raise AssertionError("TASK4_375_NATIVE_V2_SINK_TLS_POSITIVE_CONTROL_TIMEOUT")

def probe_agent(name,role,network,sink_ip,root,ca_cert,out):
    mounts=[(ROOT/"scripts/task4_375_native_v2_agent_network_probe_v1.py",
             "/agent.py",True)]
    if role=="rogue-back":
        mounts.append((ca_cert,"/tls/ca.crt",True))
    args=["python","-B","/agent.py",role]
    if role=="front":args+=["--sink-ip",sink_ip]
    cid=new_container(name,network,name,PYIMAGE,args,
                      mounts=mounts,memory="128m")
    try:
        snapshot=inspect(cid,role,{network},
            source_mounts=["/agent.py"]+
            (["/tls/ca.crt"] if role=="rogue-back" else []),strict_role=True)
        # Inspect before startup for FS/user settings, again after startup
        # if network IP values are needed (only the sink IP is passed here).
        proc=docker("start","--attach",cid,timeout=25,check=False)
        (out/(role+"-output.log")).write_text(proc.stdout+proc.stderr)
        status=json.loads(docker("inspect",cid).stdout)[0]["State"]["ExitCode"]
        insist(status==0,"NETWORK_ATTACK_PROBE_FAILED_"+role+":"+proc.stderr[-250:])
        records=[json.loads(line) for line in proc.stdout.splitlines()
                 if line.startswith("{")]
        insist(len(records)==1,"ONE_NETWORK_PROBE_RECORD_"+role)
        return snapshot,records[0]
    finally:
        docker("rm","-f",cid,timeout=20,check=False)

def proof(out):
    out.mkdir(parents=True,exist_ok=True)
    insist(not any(os.environ.get(x) for x in SENSITIVE),
           "EXTERNAL_OR_PAID_API_SECRETS_IN_CI")
    repo_sha,upstream_hashes=assert_source_pins(out)
    # Never put ephemeral CA private keys or sink TLS keys under results/.
    certdir=Path(tempfile.mkdtemp(prefix="task4-375-unpublished-tls-"))
    tls=mock_tls_material(certdir)
    # Build from a narrow context copied ONLY from exact verified BEN pin.
    # The image has runtime packages; pinned source is mounted read-only.
    with tempfile.TemporaryDirectory(prefix="task4-375-build-context-") as btd:
        context=Path(btd)
        pkg=context/"external-eval/v0.3.9"
        pkg.parent.mkdir(parents=True)
        shutil.copytree(BEN_SRC/"external-eval/v0.3.9",pkg,
                        ignore=shutil.ignore_patterns("__pycache__","*.pyc",".pytest_cache"))
        build=docker("build","--file",str(ROOT/"docker/task4_375_native_v2_broker_runtime_v1.Dockerfile"),
                     "--tag",IMAGE,str(context),timeout=660,check=False)
        (out/"native-v2-image-build.log").write_text(build.stdout+build.stderr)
        insist(build.returncode==0,"NATIVE_V2_BROKER_IMAGE_BUILD_FAILED")
    image_info=json.loads(docker("image","inspect",IMAGE).stdout)[0]
    insist(image_info["Id"].startswith("sha256:"),"IMMUTABLE_IMAGE_ID_REQUIRED")
    # Private test CA key is never included in published artifact.
    tag=secrets.token_hex(5)
    front="task4-375-front-"+tag
    back="task4-375-back-"+tag
    containers=[];networks=[]
    with tempfile.TemporaryDirectory(prefix="task4-375-host-") as tmp:
        root=Path(tmp)
        output=root/"output";output.mkdir(mode=0o777)
        output.chmod(0o777)
        writer=secrets.token_urlsafe(32)
        reader=secrets.token_urlsafe(32)
        insist(writer!=reader and len(writer)>=32 and len(reader)>=32,
               "DISTINCT_TEST_TOKENS_REQUIRED")
        postgres_image="postgres:16"
        pg_dsn="postgresql://veritas:veritas@postgres:5432/veritas_action_capability"
        sink_dsn="postgresql://veritas:veritas@postgres:5432/veritas_action_capability_sandbox"
        sandbox_env=[
            ("VERITAS_SANDBOX_DATABASE_URL",sink_dsn),
            ("VERITAS_SANDBOX_WRITER_TOKEN",writer),
            ("VERITAS_SANDBOX_READER_TOKEN",reader),
        ]
        gateway_env=[
            ("BEN_CANONICAL_PIN",BEN_PIN),("VERITAS_PIN",OS_PIN),
            ("VERITAS_DATABASE_URL",pg_dsn),
            ("VERITAS_SANDBOX_DATABASE_URL",sink_dsn),
            ("VERITAS_SANDBOX_WRITER_TOKEN",writer),
            ("VERITAS_SANDBOX_READER_TOKEN",reader),
            ("VERITAS_SANDBOX_CA_FILE","/tls/ca.crt"),
        ]
        try:
            front_info=create_network(front,out);networks.append(front)
            back_info=create_network(back,out);networks.append(back)
            insist(front_info["id"]!=back_info["id"],
                   "SEPARATE_BRIDGE_NETWORK_IDS_REQUIRED")

            pg=new_container("task4-375-postgres-"+tag,back,"postgres",
                postgres_image,[],env=[
                    ("POSTGRES_USER","veritas"),
                    ("POSTGRES_PASSWORD","veritas"),
                    ("POSTGRES_DB","veritas_action_capability")],
                strict=False)
            containers.append(pg)
            docker("start",pg,timeout=30)
            wait_pg(pg)
            created=docker("exec",pg,"psql","-U","veritas","-d","postgres",
                           "-v","ON_ERROR_STOP=1","-c",
                           "CREATE DATABASE veritas_action_capability_sandbox",
                           timeout=20)
            insist("CREATE DATABASE" in created.stdout,"SANDBOX_DB_NOT_CREATED")

            sink=new_container("task4-375-sink-"+tag,back,
                "sandbox.example.invalid",IMAGE,
                ["python","-B","/source/veritas_os_source/scripts/run_native_v2_sandbox_service.py",
                 "--host","0.0.0.0","--port","443",
                 "--cert","/tls/server.crt","--key","/tls/server.key"],
                mounts=[
                    (OS_SRC,"/source/veritas_os_source",True),
                    (certdir/"server.crt","/tls/server.crt",True),
                    (certdir/"server.key","/tls/server.key",True)],
                env=sandbox_env,
                tmpfs=["/tmp:rw,nosuid,nodev,size=64m"],
                sysctls=["net.ipv4.ip_unprivileged_port_start=0"],
                memory="384m")
            containers.append(sink)
            docker("start",sink,timeout=30)

            gateway=new_container("task4-375-gateway-"+tag,back,
                "native-v2-backend-broker",IMAGE,
                ["python","-B","-c","import time;time.sleep(720)"],
                mounts=[
                    (OS_SRC,"/source/veritas_os_source",True),
                    (ROOT,"/source/benchmark",True),
                    (certdir/"ca.crt","/tls/ca.crt",True),
                    (output,"/output",False)],
                env=gateway_env,
                tmpfs=["/tmp:rw,nosuid,nodev,size=256m"],
                memory="1500m")
            containers.append(gateway)
            docker("network","connect","--alias","native-v2-gateway",
                   front,gateway,timeout=30)
            docker("start",gateway,timeout=30)

            wait_sink(gateway,out)
            sink_snap=inspect(sink,"native-v2-tls-target",{back},
                source_mounts=[
                    "/source/veritas_os_source",
                    "/tls/server.crt","/tls/server.key"],strict_role=True)
            gateway_snap=inspect(gateway,"native-v2-authorizing-broker",
                {front,back},source_mounts=[
                    "/source/veritas_os_source","/source/benchmark",
                    "/tls/ca.crt","/output"],strict_role=True)
            pg_snap=inspect(pg,"postgres-target-state",{back},
                source_mounts=["/var/lib/postgresql/data"],strict_role=False)
            sink_ip=sink_snap["ip_by_network"][back]
            insist(bool(sink_ip) and
                   sink_ip!=gateway_snap["ip_by_network"][back],
                   "REAL_TLS_TARGET_BACKEND_IP_REQUIRED")

            front_snap,front_result=probe_agent(
                "task4-375-agent-"+tag,"front",front,sink_ip,
                root,certdir/"ca.crt",out)
            rogue_snap,rogue_result=probe_agent(
                "task4-375-rogue-"+tag,"rogue-back",back,sink_ip,
                root,certdir/"ca.crt",out)
            insist(front_result["real_sink_ip_tcp_refused"] is True and
                   front_result["sink_dns_hidden"] is True and
                   front_result["external_testnet_tcp_refused"] is True,
                   "REAL_NATIVE_V2_SINK_DOCKER_BYPASS_ROUTE_EXISTS")
            insist(rogue_result["unauthenticated_direct_write_http_status"]==401
                   and rogue_result["actual_upstream_sandbox_service_tls_verified"],
                   "REAL_NATIVE_V2_SINK_MISSING_CREDENTIAL_NOT_DENIED")

            migration=docker("exec","--workdir","/source/veritas_os_source",
                gateway,"python","-m","alembic","upgrade","head",
                timeout=140,check=False)
            (out/"native-v2-postgres-migration.log").write_text(
                migration.stdout+migration.stderr)
            insist(migration.returncode==0,"NATIVE_V2_POSTGRES_MIGRATION_FAILED")

            native=docker("exec","--workdir","/source/veritas_os_source",
                gateway,"python","-B",
                "/source/benchmark/integration/current_veritas_uninterrupted/native_v2_action_capability.py",
                "--veritas-root","/source/veritas_os_source",
                "--output","/output/native-v2-authorized-lineage.json",
                timeout=360,check=False)
            (out/"native-v2-gateway-execution.log").write_text(
                native.stdout+native.stderr)
            insist(native.returncode==0,
                   "REAL_NATIVE_V2_DOCKER_EXECUTION_FAILED")
            report_path=output/"native-v2-authorized-lineage.json"
            insist(report_path.is_file(),"ACTUAL_NATIVE_V2_REPORT_REQUIRED")
            report=json.loads(report_path.read_text())
            import sys
            sys.path.insert(0,str(ROOT))
            from integration.current_veritas_uninterrupted.task4_374_native_v2_lineage import (
                verify_exact_native_v2_lineage,canonical_hash,
            )
            trace=report.get("task4_374_native_v2_trace")
            match=verify_exact_native_v2_lineage(trace)
            insist(len(match)==7 and all(match.values()) and
                   report.get("task4_374_native_v2_trace_checks")==match and
                   report.get("task4_374_native_v2_trace_sha256")==canonical_hash(trace),
                   "ACTUAL_NATIVE_V2_RUNTIME_TRACE_UNVERIFIED")
            insist(trace["authorization"]["target"]==SINK and
                   trace["target_owned"]["source_identity"]==
                   "https://sandbox.example.invalid" and
                   trace["dispatch"]["send_calls"]==1 and
                   trace["reconciliation"]["effect_state"]=="CONFIRMED_EFFECT" and
                   report.get("task4_374_replay_after_reconciliation_rejected") is True,
                   "NATIVE_V2_SAME_TARGET_ONE_EFFECT_NOT_RECONCILED")
            (out/"native-v2-authorized-lineage.json").write_text(
                json.dumps(report,sort_keys=True,indent=2)+"\n")
            for role,cid in (("sink",sink),("gateway",gateway),("postgres",pg)):
                logs=docker("logs",cid,check=False,timeout=25)
                (out/(role+"-service-logs.txt")).write_text(
                    (logs.stdout+logs.stderr)[-50000:])
            # Explicit check accounting. These are check predicates over
            # genuine running containers and native runtime objects.
            checks={
                "source_pins_exact":True,
                "front_kernel_internal_bridge":front_info["internal"] is True,
                "back_kernel_internal_bridge":back_info["internal"] is True,
                "two_distinct_kernel_bridge_networks":front_info["id"]!=back_info["id"],
                "native_v2_tls_sandbox_back_only":sink_snap["networks"]==[back],
                "postgres_synthetic_target_back_only":pg_snap["networks"]==[back],
                "native_v2_authorizing_gateway_both_networks":
                    set(gateway_snap["networks"])=={front,back},
                "agent_front_only":front_snap["networks"]==[front],
                "positive_broker_to_exact_pinned_TLS_sandbox":True,
                "exact_target_native_v2_signed_authorization":
                    trace["authorization"]["target"]==SINK,
                "native_v2_atomic_postgres_single_use_record":
                    trace["consumption"]["durable_postgres"] is True,
                "real_native_v2_permit_one_send":
                    report.get("bound_execution_permit_consumed") is True and
                    trace["dispatch"]["send_calls"]==1,
                "real_target_owned_persisted_effect":
                    trace["target_owned"]["state"]=="PERSISTED",
                "independent_readonly_reconciliation":
                    trace["reconciliation"]["effect_state"]=="CONFIRMED_EFFECT",
                "exact_bind_and_outcome_receipt_identity":
                    all(match.values()) and len(match)==7,
                "native_v2_consumed_replay_denied":
                    report.get("task4_374_replay_after_reconciliation_rejected") is True,
                "untrusted_agent_backend_dns_hidden":
                    front_result["sink_dns_hidden"] is True,
                "untrusted_agent_actual_sink_IP_TCP_denied":
                    front_result["real_sink_ip_tcp_refused"] is True,
                "untrusted_agent_external_TCP_denied":
                    front_result["external_testnet_tcp_refused"] is True,
                "agent_has_no_private_credentials":
                    front_result["untrusted_agent_no_private_credentials"] is True,
                "host_attached_rogue_backend_real_TLS_verified":
                    rogue_result["actual_upstream_sandbox_service_tls_verified"] is True,
                "host_attached_rogue_backend_missing_writer_token_401":
                    rogue_result["unauthenticated_direct_write_http_status"]==401,
                "all_probe_clients_no_docker_socket":
                    not front_snap["docker_socket_mounted"] and
                    not rogue_snap["docker_socket_mounted"],
                "no_real_provider_or_bank_effect":True,
                "nonclaim_no_production_IAM_or_independent_third_party":True,
            }
            insist(len(checks)==25 and all(checks.values()),
                   "TWENTY_FIVE_NETWORK_NATIVE_V2_INVARIANTS_FAILED")
            evidence={
                "rule":"TASK4_375_NATIVE_V2_DOCKER_NETWORK_BYPASS_DENIAL_V1",
                "scope":"BOUNDED_TWO_INTERNAL_BRIDGE_DOCKER_TRUSTED_CI_ONLY",
                "predecessor_merged_main":"3038223c4132bee823b842a0bb971cc39840074e",
                "source_sha":repo_sha,
                "ben_pin":BEN_PIN,"veritas_os_pin":OS_PIN,
                "upstream_module_sha256":upstream_hashes,
                "docker_images":{
                    "native_v2_image":gateway_snap["image_id"],
                    "sandbox_image":sink_snap["image_id"],
                    "postgres_image":pg_snap["image_id"]},
                "networks":[front_info,back_info],
                "roles":[sink_snap,gateway_snap,pg_snap,front_snap,rogue_snap],
                "tls":tls,
                "probe_front":front_result,
                "probe_backend_without_credential":rogue_result,
                "positive_native_v2_trace":trace,
                "positive_native_v2_trace_hash":canonical_hash(trace),
                "native_v2_trace_checks":match,
                "checks":checks,
                "real_provider_calls":0,"real_bank_effects":0,
                "provider_spend_usd":0,
                "trusted_host_docker_administrator":True,
                "untrusted_agent_cannot_submit_unreviewed_action_to_gateway_test":True,
                "all_authority_signals_are_synthetic":True,
                "actual_production_IAM_enforced":False,
                "independent_external_audit":False,
                "foreign_370_371_HTTP_sink_authorized":False,
                "local_target_owned_effect_is_real_enterprise_effect":False,
                "runtime_network_gate_is_production_deployed":False,
                "test_key_or_token_material_exported":False,
                "source_sha256":{
                    f:sha256_file(ROOT/f) for f in SOURCE_FILES},
            }
            (out/"task4-375-native-v2-docker-network-evidence.json").write_text(
                json.dumps(evidence,sort_keys=True,indent=2)+"\n")
            junit=ET.Element("testsuite",name=evidence["rule"],
                tests=str(len(checks)),failures="0",errors="0",skipped="0")
            for key in checks:
                ET.SubElement(junit,"testcase",classname=evidence["rule"],name=key)
            ET.ElementTree(junit).write(out/"task4-375-junit.xml",
                                       encoding="utf-8",xml_declaration=True)
            print("TASK4_375_REAL_NATIVE_V2_DOCKER_NETWORK_GATE_25_OF_25_PASS")
            print("EXACT_SIGNED_NATIVE_V2_TARGET_ONE_TLS_EFFECT_ONE_RECONCILED_RECEIPT")
            print("FRONT_AGENT_DIRECT_IP_DENIED_BACK_ROGUE_WRITER_401")
            print("REAL_PROVIDER_0_REAL_BANK_EFFECT_0_NOT_PRODUCTION_PROVEN")
            return evidence
        finally:
            for cid in reversed(containers):
                docker("rm","-f","-v",cid,timeout=40,check=False)
            for net in reversed(networks):
                docker("network","rm",net,timeout=30,check=False)
            # Private test-only CA issuer key and TLS server key are NEVER
            # included in evidence uploads. Certs may be archived separately.
            shutil.rmtree(certdir,ignore_errors=True)

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--output-dir",required=True,type=Path)
    args=parser.parse_args()
    proof(args.output_dir.resolve())

if __name__=="__main__":
    main()
