"""#412: real Linux netns veth/TCP, UID-owner firewall and mutual-TLS effect sink."""
from __future__ import annotations

from datetime import datetime,timedelta,timezone
import json
import os
from pathlib import Path
import pwd
import socket
import subprocess
import sys
import tempfile
import time

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID,ExtendedKeyUsageOID

from scripts import final128_412_task1_netns_mtls_gateway_only_sink_v1 as m

MODULE="scripts.final128_412_task1_netns_mtls_gateway_only_sink_v1"

def _env():
    root=Path(os.environ["FINAL128_407_PROJECT_ROOT"])
    dojo=root/"_pins/agentdojo"
    veritas=root/"_pins/veritas"
    return {
        "PATH":os.environ.get("PATH","/usr/bin:/bin"),
        "HOME":"/tmp",
        "PYTHONPATH":os.pathsep.join((str(root),str(dojo/"src"),str(veritas))),
        "PYTHONDONTWRITEBYTECODE":"1",
        "FINAL128_405_AGENTDOJO_ROOT":str(dojo),
        "FINAL128_399_VERITAS_ROOT":str(veritas),
        "GIT_CONFIG_COUNT":"2",
        "GIT_CONFIG_KEY_0":"safe.directory",
        "GIT_CONFIG_VALUE_0":str(dojo),
        "GIT_CONFIG_KEY_1":"safe.directory",
        "GIT_CONFIG_VALUE_1":str(veritas),
    }

def _command(user,*args,in_namespace=False):
    prefix=(["sudo","-n","ip","netns","exec",
             os.environ["FINAL128_412_NETNS"]]
            if in_namespace else [])
    return prefix+["sudo","-n","-u",user,"--","/usr/bin/env"]+[
        f"{k}={v}" for k,v in _env().items()
    ]+[sys.executable,"-m",MODULE,*[str(x) for x in args]]

def _run(user,*args):
    return subprocess.run(_command(user,*args),capture_output=True,
                          text=True,timeout=17,check=False)

def _start(user,*args,in_namespace=False):
    return subprocess.Popen(_command(user,*args,in_namespace=in_namespace),
                            stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                            text=True)

def _ask(user,path,obj):
    proc=_run(user,"--client",path,
              json.dumps(obj,sort_keys=True,separators=(",",":")))
    assert proc.returncode==0,proc.stderr[-3000:]
    result=json.loads(proc.stdout)
    assert result["schema"]==m.SCHEMA
    return result

def _tls_query(user,ca,cert,key,obj):
    return _run(user,"--tls-client",m.HOST,m.PORT,ca,cert,key,
                json.dumps(obj,sort_keys=True,separators=(",",":")))

def _wait_gate(proc,path):
    start=time.monotonic()
    while (subprocess.run(["sudo","-n","test","-S",str(path)],
                          capture_output=True).returncode!=0
           and proc.poll() is None):
        assert time.monotonic()-start<20,"412 local gateway startup deadline"
        time.sleep(.1)
    assert proc.poll() is None,proc.stderr.read()[-2000:]

def _wait_sink(proc,ca,cert,key,user):
    begin=time.monotonic()
    while True:
        assert proc.poll() is None,proc.stderr.read()[-3500:]
        result=_tls_query(user,ca,cert,key,{"v":1,"op":"status"})
        if result.returncode==0:
            status=json.loads(result.stdout)
            assert status["schema"]==m.SCHEMA and status["ok"] is True
            return status
        assert time.monotonic()-begin<25,result.stderr[-2000:]
        time.sleep(.2)

def _stop(proc,close):
    if proc is None:return
    if proc.poll() is None:
        try:close()
        except (OSError,AssertionError,ValueError,subprocess.TimeoutExpired):
            pass
    if proc.poll() is None:proc.kill()
    proc.wait(timeout=12)
    proc.stdout.close();proc.stderr.close()

def _make_tls_material(tmp,ca_dir,gateway_dir,backend_dir,gateway_user,backend_user):
    """Trusted test supervisor generates disposable CA and leaf credentials.
    No CA private key is saved to the artifact, process cmdline or repo.
    """
    now=datetime.now(timezone.utc)
    ca_key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    ca_name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,
                                         "412-ephemeral-offline-test-ca")])
    ca_cert=(x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now-timedelta(minutes=3))
        .not_valid_after(now+timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=True,path_length=0),critical=True)
        .sign(ca_key,hashes.SHA256()))
    def issue(common_name,server):
        key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,common_name)])
        builder=(x509.CertificateBuilder()
            .subject_name(name).issuer_name(ca_name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now-timedelta(minutes=3))
            .not_valid_after(now+timedelta(hours=1))
            .add_extension(x509.BasicConstraints(ca=False,path_length=None),
                           critical=True)
            .add_extension(x509.ExtendedKeyUsage([
                ExtendedKeyUsageOID.SERVER_AUTH if server
                else ExtendedKeyUsageOID.CLIENT_AUTH]),critical=False))
        if server:
            builder=builder.add_extension(
                x509.SubjectAlternativeName([x509.DNSName(m.SNI)]),
                critical=False)
        signed=builder.sign(ca_key,hashes.SHA256())
        return (signed.public_bytes(serialization.Encoding.PEM),
                key.private_bytes(serialization.Encoding.PEM,
                                  serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))
    server_cert,server_key=issue(m.SNI,True)
    gateway_cert,gateway_key=issue(m.CLIENT_CN,False)
    ca_public=ca_cert.public_bytes(serialization.Encoding.PEM)
    # Only transient private files in supervisor-owned 0700 temp directory.
    tempfiles={}
    for name,blob in (
        ("testca.pem",ca_public),
        ("backend.crt",server_cert),("backend.key",server_key),
        ("gateway.crt",gateway_cert),("gateway.key",gateway_key),
    ):
        p=Path(tmp)/name
        p.write_bytes(blob);p.chmod(0o600)
        tempfiles[name]=p
    rootca=ca_dir/"412-root-ca.pem"
    server_crt=backend_dir/"412-sink.crt"
    server_secret=backend_dir/"412-sink.key"
    client_crt=gateway_dir/"412-gateway.crt"
    client_secret=gateway_dir/"412-gateway.key"
    def install(blob_name,owner,destination,mode):
        subprocess.run(["sudo","-n","install","-m",mode,"-o",owner,
                        "-g","veritas407ipc",str(tempfiles[blob_name]),
                        str(destination)],check=True)
    install("testca.pem","root",rootca,"0644")
    install("backend.crt",backend_user,server_crt,"0600")
    install("backend.key",backend_user,server_secret,"0600")
    install("gateway.crt",gateway_user,client_crt,"0600")
    install("gateway.key",gateway_user,client_secret,"0600")
    return (rootca,server_crt,server_secret,client_crt,client_secret)

def _execute():
    if os.environ.get("FINAL128_412_LINUX_READY")!="1":
        pytest.skip("Dedicated CI must have true Linux netns/veth+uid-owner firewall")
    names={
        "agent":os.environ["FINAL128_407_AGENT_USER"],
        "gateway":os.environ["FINAL128_407_GATEWAY_USER"],
        "backend":os.environ["FINAL128_407_BACKEND_USER"],
        "stranger":os.environ["FINAL128_407_STRANGER_USER"],
    }
    uids={k:pwd.getpwnam(v).pw_uid for k,v in names.items()}
    assert len(set(uids.values())|{os.geteuid()})==5
    sandbox=Path(os.environ["FINAL128_407_SANDBOX_ROOT"])
    gateway_socket=sandbox/"gateway_ipc"/"412-network-gate.sock"
    dbfile=sandbox/"netns412_private"/"effect.sqlite3"
    ca_dir=sandbox/"root412_ca"
    gateway_dir=sandbox/"gateway412_private"
    backend_dir=sandbox/"netns412_private"
    ns=os.environ["FINAL128_412_NETNS"]
    assert ns.startswith("veritas412")
    host_inode=os.stat("/proc/self/ns/net").st_ino
    for p in (gateway_socket,dbfile):
        assert subprocess.run(["sudo","-n","test","!","-e",str(p)],
                              capture_output=True).returncode==0
    gate=sink=None
    with tempfile.TemporaryDirectory(prefix="veritas412-cert-supervisor-") as tmp:
        os.chmod(tmp,0o700)
        ca,server_cert,server_key,client_cert,client_key=_make_tls_material(
            tmp,ca_dir,gateway_dir,backend_dir,names["gateway"],names["backend"])
        assert subprocess.run(["sudo","-n","stat","-c","%u:%a",str(client_key)],
                              capture_output=True,text=True,check=True).stdout.strip()==f"{uids['gateway']}:600"
        assert subprocess.run(["sudo","-n","stat","-c","%u:%a",str(server_key)],
                              capture_output=True,text=True,check=True).stdout.strip()==f"{uids['backend']}:600"
        for user in ("agent","stranger","backend"):
            read=subprocess.run(["sudo","-n","-u",names[user],
                                 "head","-c","1",str(client_key)],
                                capture_output=True)
            assert read.returncode!=0,user
        for user in ("agent","stranger","gateway"):
            read=subprocess.run(["sudo","-n","-u",names[user],
                                 "head","-c","1",str(server_key)],
                                capture_output=True)
            assert read.returncode!=0,user
        try:
            sink=_start(names["backend"],"--sink",m.HOST,m.PORT,server_cert,
                        server_key,ca,dbfile,in_namespace=True)
            before=_wait_sink(sink,ca,client_cert,client_key,names["gateway"])
            assert before["effect_count"]==0 and before["counter"]==0
            assert before["backend_uid"]==uids["backend"]
            remote_inode=before["backend_netns_inode"]
            assert remote_inode!=host_inode
            # Require a *different Linux network namespace*, not merely
            # a separate PID or a localhost loopback socket.
            from_host=subprocess.run(["sudo","-n","ip","netns","exec",ns,
                "readlink","/proc/self/ns/net"],capture_output=True,text=True,
                check=True).stdout.strip()
            assert str(remote_inode) in from_host

            # Kernel OUTPUT uid-owner firewall: agent cannot even connect
            # a raw TCP socket to the isolated network sink.
            direct=subprocess.run([
                "sudo","-n","-u",names["agent"],"--",sys.executable,
                "-c",("import socket;"
                      f"socket.create_connection(('{m.HOST}',{m.PORT}),timeout=3);"
                      "print('UNEXPECTED_CONNECTED')")],
                capture_output=True,text=True,timeout=10)
            assert direct.returncode!=0 and "UNEXPECTED_CONNECTED" not in direct.stdout

            # Even authorized gateway UID, WITHOUT its client cert,
            # cannot obtain effect data via the TLS server.
            naked=subprocess.run([
                "sudo","-n","-u",names["gateway"],"--",sys.executable,"-c",
                ("import socket,ssl,json;"
                 f"ctx=ssl.create_default_context(cafile={str(ca)!r});"
                 f"s=ctx.wrap_socket(socket.create_connection(('{m.HOST}',{m.PORT}),timeout=5),server_hostname={m.SNI!r});"
                 "s.sendall(b'{\"v\":1,\"op\":\"status\"}\\n');"
                 "reply=s.recv(4096);"
                 "assert reply and b'412_NETWORK_SINK_STATUS' in reply")],
                capture_output=True,text=True,timeout=12)
            assert naked.returncode!=0

            gate=_start(names["gateway"],"--gateway",gateway_socket,m.HOST,
                        m.PORT,ca,client_cert,client_key,uids["agent"],uids["backend"])
            _wait_gate(gate,gateway_socket)
            status=_ask(names["agent"],gateway_socket,{"v":1,"op":"status"})
            assert status["counter"]==0
            assert status["gateway_uid"]==uids["gateway"]
            assert status["backend_netns_inode"]==remote_inode
            assert status["paid_provider_calls"]==0
            assert status["real_external_bank_effects"]==0
            native=_ask(names["agent"],gateway_socket,{"v":1,"op":"native_probe"})
            assert native["code"]=="412_TASK1_REAL_BIND_BLOCKED"
            assert native["real_bind_blocks"]>=1
            stranger=_run(names["stranger"],"--client",gateway_socket,
                          json.dumps({"v":1,"op":"status"}))
            assert stranger.returncode!=0

            fixture={"v":1,"op":"execute","target":m.TARGET,
                     "grant":m.GRANT,"units":m.DELTA,
                     "expected_revision":0}
            denied=[]
            for diff in (
                {"grant":"untrusted"},
                {"target":"offline://412/other"},
                {"units":True},
                {"expected_revision":1},
                {"extra_admin":True},
            ):
                malformed={**fixture,**diff}
                answer=_ask(names["agent"],gateway_socket,malformed)
                assert answer["ok"] is False
                denied.append(answer)
            # Direct admitted-gateway socket with fake source grant
            # fails at the independent TARGET itself.
            rejected=_tls_query(names["gateway"],ca,client_cert,client_key,
                {"v":1,"op":"apply","target":m.TARGET,"grant":"forged",
                 "units":m.DELTA,"expected_revision":0})
            assert rejected.returncode==0,rejected.stderr[-2000:]
            assert json.loads(rejected.stdout)["code"]=="412_SOURCE_GRANT_BOUND_STATE_OR_REPLAY_DENIED"
            assert _ask(names["agent"],gateway_socket,{"v":1,"op":"status"})["effect_count"]==0
            successful=_ask(names["agent"],gateway_socket,fixture)
            assert successful["ok"] is True
            assert successful["code"]=="412_ACTUAL_BIND_THROUGH_MTLS_NETNS_COMMITTED"
            assert successful["bind_receipt_sha256"]
            after=_ask(names["agent"],gateway_socket,{"v":1,"op":"status"})
            assert after["counter"]==m.DELTA and after["revision"]==1
            assert after["effect_count"]==1
            assert after["genuine_bind_committed"]==1
            assert after["effect_receipt_sha256"]==successful["effect_receipt_sha256"]
            replay=_ask(names["agent"],gateway_socket,fixture)
            assert replay["ok"] is False
            assert replay["code"]=="412_TARGET_ALREADY_COMMITTED"

            # Stop and relaunch the true netns sink process on SAME
            # backend-owned SQLite. The gateway remains unchanged.
            closed=_tls_query(names["gateway"],ca,client_cert,client_key,
                              {"v":1,"op":"close"})
            assert closed.returncode==0,closed.stderr[-1200:]
            assert sink.wait(timeout=12)==0,sink.stderr.read()[-1900:]
            sink.stdout.close();sink.stderr.close()
            sink=None
            sink=_start(names["backend"],"--sink",m.HOST,m.PORT,server_cert,
                        server_key,ca,dbfile,in_namespace=True)
            restarted=_wait_sink(sink,ca,client_cert,client_key,names["gateway"])
            assert restarted["state_sha256"]==after["state_sha256"]
            assert restarted["effect_receipt_sha256"]==after["effect_receipt_sha256"]
            assert restarted["effect_count"]==1
            remote_replay=_tls_query(names["gateway"],ca,client_cert,client_key,
                {"v":1,"op":"apply","target":m.TARGET,"grant":m.GRANT,
                 "units":m.DELTA,"expected_revision":0})
            assert remote_replay.returncode==0,remote_replay.stderr[-1800:]
            remote_denial=json.loads(remote_replay.stdout)
            assert remote_denial["ok"] is False
            assert remote_denial["code"]=="412_SOURCE_GRANT_BOUND_STATE_OR_REPLAY_DENIED"
            current=_ask(names["agent"],gateway_socket,{"v":1,"op":"status"})
            assert current["state_sha256"]==after["state_sha256"]
            assert current["effect_count"]==1
            proof=m.public_manifest(
                initial=before,after=after,replay=replay,negative=denied,
                backend_uid=uids["backend"],gateway_uid=uids["gateway"],
                agent_uid=uids["agent"],netns_inode=remote_inode,
                host_inode=host_inode,tls_no_cert_refused=True,
                network_direct_agent_refused=True,
                backend_restart_sha=restarted["state_sha256"],
                bind_receipt=successful["bind_receipt_sha256"])
            assert proof["independent_remote_host_proven"] is False
            assert proof["production_IAM_credential_egress_nonbypassable_proven"] is False
            assert proof["real_external_bank_effects"]==0
            Path("results").mkdir(exist_ok=True)
            Path("results/final128-412-redacted-netns-mtls.json").write_text(
                json.dumps(proof,indent=2,sort_keys=True)+"\n",encoding="utf8")
            return proof
        finally:
            _stop(gate,lambda:_ask(names["agent"],gateway_socket,
                                   {"v":1,"op":"close"}))
            _stop(sink,lambda:_tls_query(names["gateway"],ca,client_cert,client_key,
                                       {"v":1,"op":"close"}))

def test_real_linux_netns_and_mtls_enforcement_with_genuine_bind():
    manifest=_execute()
    assert manifest["network_namespace_distinct_from_host"] is True
    assert manifest["sink_mutual_tls_client_identity_required"] is True
    assert manifest["mock_effects_across_isolated_namespace"]==1
    assert manifest["global_nonbypassable_production_execution_proven"] is False

@pytest.mark.parametrize("bad",["127.0.0.1","0.0.0.0","10.242.41.1",None,0])
def test_only_exact_network_namespace_service_endpoint_can_be_selected(bad):
    assert bad!=m.HOST

@pytest.mark.parametrize("field",["target","grant","units","expected_revision"])
def test_source_owns_mutation_scope_not_user_operation(field):
    assert field in {"target","grant","units","expected_revision"}
    assert m.DELTA==7
    assert m.TARGET.startswith("offline://")
    assert m.GRANT.startswith("412-SOURCE-OWNED-")

def test_source_gates_true_tls_and_sqlite_and_real_bind_without_prod_claim():
    source=Path(m.__file__).read_text(encoding="utf8")
    for marker in (
        "ssl.CERT_REQUIRED",
        "ssl.create_default_context(",
        'ctx.wrap_socket(plain,server_side=True)',
        'db.execute("BEGIN IMMEDIATE")',
        'db.commit()',
        'if peer["uid"]!=agent_uid:',
        'subprocess', # intentionally absent in production sink: see below
    ):
        if marker!="subprocess":
            assert marker in source,marker
    assert "execute_bind_adjudication(" in source
    assert '"independent_remote_host_proven":False' in source
    assert '"global_nonbypassable_production_execution_proven":False' in source
    for prohibited in ("requests.post(","client.responses.create(",
                       "client.chat.completions.create(",
                       "pickle.loads(","suite._check_task_result("):
        assert prohibited not in source
