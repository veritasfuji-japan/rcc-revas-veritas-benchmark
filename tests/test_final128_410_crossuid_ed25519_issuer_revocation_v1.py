"""#410 actual separate Linux Ed25519 issuer + kernel UID protected signed sink."""
from __future__ import annotations
from copy import deepcopy
import json
import os
from pathlib import Path
import pwd
import subprocess
import sys
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from scripts import final128_410_crossuid_ed25519_issuer_revocation_v1 as m

MODULE="scripts.final128_410_crossuid_ed25519_issuer_revocation_v1"

def _env():
    root=Path(os.environ["FINAL128_407_PROJECT_ROOT"])
    agentdojo=root/"_pins/agentdojo"
    veritas=root/"_pins/veritas"
    return {
        "PATH":os.environ.get("PATH","/usr/bin:/bin"),
        "HOME":"/tmp",
        "PYTHONPATH":os.pathsep.join((str(root),str(agentdojo/"src"),str(veritas))),
        "PYTHONDONTWRITEBYTECODE":"1",
        "FINAL128_405_AGENTDOJO_ROOT":str(agentdojo),
        "FINAL128_399_VERITAS_ROOT":str(veritas),
        "GIT_CONFIG_COUNT":"2","GIT_CONFIG_KEY_0":"safe.directory",
        "GIT_CONFIG_VALUE_0":str(agentdojo),
        "GIT_CONFIG_KEY_1":"safe.directory",
        "GIT_CONFIG_VALUE_1":str(veritas),
    }

def _cmd(user,*args):
    return ["sudo","-n","-u",user,"--","/usr/bin/env"]+[
        f"{name}={value}" for name,value in _env().items()
    ]+[sys.executable,"-m",MODULE,*[str(x) for x in args]]

def _run(user,*args):
    return subprocess.run(_cmd(user,*args),capture_output=True,
                          text=True,timeout=22,check=False)

def _spawn(user,*args):
    return subprocess.Popen(_cmd(user,*args),stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,text=True)

def _wait_socket(proc,path):
    start=time.monotonic()
    while (subprocess.run(["sudo","-n","test","-S",str(path)],
                          capture_output=True).returncode!=0
           and proc.poll() is None):
        assert time.monotonic()-start<25,"410 Linux socket service startup failed"
        time.sleep(0.1)
    assert proc.poll() is None,proc.stderr.read()[-3000:]

def _ask(user,path,obj):
    payload=json.dumps(obj,sort_keys=True,separators=(",",":"),
                       ensure_ascii=False)
    ret=_run(user,"--client",path,payload)
    assert ret.returncode==0,ret.stderr[-2500:]
    response=json.loads(ret.stdout)
    assert response["schema"]==m.SCHEMA
    return response

def _close(proc,user,path):
    if proc is None:return
    if proc.poll() is None:
        try:_ask(user,path,{"v":1,"op":"close"})
        except (ValueError,subprocess.TimeoutExpired,OSError,AssertionError):
            pass
    if proc.poll() is None:
        proc.kill()
    proc.wait(timeout=12)
    proc.stdout.close()
    proc.stderr.close()

def _prove_crossuid_signed_issuer():
    if os.environ.get("FINAL128_410_LINUX_READY")!="1":
        pytest.skip("Only pinned dedicated 410 Linux multiple-UID workflow")
    names={
        "agent":os.environ["FINAL128_407_AGENT_USER"],
        "gateway":os.environ["FINAL128_407_GATEWAY_USER"],
        "backend":os.environ["FINAL128_407_BACKEND_USER"],
        "stranger":os.environ["FINAL128_407_STRANGER_USER"],
        "issuer":os.environ["FINAL128_410_ISSUER_USER"],
    }
    uids={k:pwd.getpwnam(v).pw_uid for k,v in names.items()}
    assert len(set(uids.values())|{os.geteuid()})==6
    assert all(x>0 for x in uids.values())
    base=Path(os.environ["FINAL128_407_SANDBOX_ROOT"])
    issuer_sock=base/"issuer_ipc"/"signed410.sock"
    gate_sock=base/"gateway_ipc"/"signed410-gate.sock"
    backend_sock=base/"backend_ipc"/"signed410-sink.sock"
    dbfile=base/"backend_private"/"signed410-ledger.sqlite3"
    private_key=base/"issuer_private"/"ed25519-source-owned.key"
    staged=base/"issuer_stage"/"issuer-ed25519-public.raw"
    trust=base/"root_trust"/"pinned-ed25519-public.raw"
    for path in (issuer_sock,gate_sock,backend_sock,dbfile,private_key,staged,trust):
        absent=subprocess.run(["sudo","-n","test","!","-e",str(path)],
                              capture_output=True)
        assert absent.returncode==0,path.name
    # Only issuer UID creates private Ed25519 key; root CI copies PUBLIC
    # bytes into an immutable-to-issuer root-owned sink trust anchor.
    keyinit=_run(names["issuer"],"--init-key",private_key,staged)
    assert keyinit.returncode==0,keyinit.stderr[-2000:]
    assert len(keyinit.stdout.strip())==64
    subprocess.run(["sudo","-n","install","-m","0644","-o","root","-g","root",
                    str(staged),str(trust)],check=True)
    assert subprocess.run(["sudo","-n","stat","-c","%u:%a",
                           str(trust)],check=True,capture_output=True,
                          text=True).stdout.strip()=="0:644"
    assert subprocess.run(["sudo","-n","stat","-c","%u:%a",str(private_key)],
                          check=True,capture_output=True,
                          text=True).stdout.strip()==f"{uids['issuer']}:600"
    for other in ("agent","gateway","backend","stranger"):
        cannot=subprocess.run(["sudo","-n","-u",names[other],
                               "head","-c","1",str(private_key)],
                              capture_output=True)
        assert cannot.returncode!=0,other
    # CI runner UID also cannot traverse issuer private directory.
    assert subprocess.run(["head","-c","1",str(private_key)],
                          capture_output=True).returncode!=0
    issuer=None;gate=None;backend=None
    try:
        issuer=_spawn(names["issuer"],"--issuer",issuer_sock,private_key,uids["agent"])
        _wait_socket(issuer,issuer_sock)
        backend=_spawn(names["backend"],"--backend",backend_sock,
                       uids["gateway"],dbfile,trust)
        _wait_socket(backend,backend_sock)
        gate=_spawn(names["gateway"],"--gateway",gate_sock,backend_sock,
                    uids["agent"],uids["backend"])
        _wait_socket(gate,gate_sock)
        initial=_ask(names["agent"],gate_sock,{"v":1,"op":"status"})
        assert initial["effect_count"]==0 and initial["revoked_count"]==0
        assert initial["backend_uid"]==uids["backend"]
        assert initial["genuine_bind_commits"]==0
        native=_ask(names["agent"],gate_sock,{"v":1,"op":"native_probe"})
        assert native["ok"] is False
        assert native["code"]=="410_REAL_NATIVE_TASK1_BIND_BLOCKED"
        assert native["bind_blocks"]>=1

        # Neither gateway nor an unrelated same-IPC-group process can
        # ASK issuer to mint arbitrary permits without the agent UID.
        unauthorized=_run(names["stranger"],"--client",issuer_sock,
                          json.dumps({"v":1,"op":"issue","alias":"a"}))
        assert unauthorized.returncode!=0
        direct=_run(names["agent"],"--client",backend_sock,
                    json.dumps({"v":1,"op":"status"}))
        assert direct.returncode!=0
        stranger_gate=_run(names["stranger"],"--client",gate_sock,
                           json.dumps({"v":1,"op":"status"}))
        assert stranger_gate.returncode!=0

        issued={}
        for alias in ("a","b","expired"):
            resp=_ask(names["agent"],issuer_sock,
                      {"v":1,"op":"issue","alias":alias})
            assert resp["ok"] is True
            assert resp["code"]=="410_SOURCE_FIXTURE_SIGNED"
            issued[alias]=resp["signed"]
            assert set(resp["signed"])=={"claims","signature"}
            assert resp["signed"]["claims"]["target"]==m.TARGETS[alias]
        disallowed=_ask(names["agent"],issuer_sock,
                        {"v":1,"op":"issue","alias":"real-bank"})
        assert not disallowed["ok"]
        assert disallowed["code"]=="410_UNAUTHORIZED_ISSUE_SCOPE"
        unauthorized_revoke=_ask(names["agent"],issuer_sock,
                                 {"v":1,"op":"revoke","alias":"a"})
        assert unauthorized_revoke["ok"] is False
        assert unauthorized_revoke["code"]=="410_UNAUTHORIZED_REVOKE_SCOPE"

        denied=[]
        def attempt(token):
            reply=_ask(names["agent"],gate_sock,
                       {"v":1,"op":"execute","permit":token})
            assert not reply["ok"]
            denied.append(reply)
            return reply
        invalid=deepcopy(issued["a"])
        invalid["claims"]["target"]=m.TARGETS["b"]
        assert attempt(invalid)["code"]=="410_SIGNATURE_OR_SIGNED_SCOPE_INVALID"
        invalid2=deepcopy(issued["a"])
        invalid2["claims"]["units"]=9
        assert attempt(invalid2)["code"]=="410_SIGNATURE_OR_SIGNED_SCOPE_INVALID"
        invalid3=deepcopy(issued["a"])
        invalid3["claims"]["audience"]="offline://wrong-service"
        assert attempt(invalid3)["code"]=="410_SIGNATURE_OR_SIGNED_SCOPE_INVALID"
        invalid4=deepcopy(issued["a"])
        invalid4["signature"]="AAAA"
        assert attempt(invalid4)["code"]=="410_SIGNATURE_OR_SIGNED_SCOPE_INVALID"
        invalid5=deepcopy(issued["a"])
        invalid5["claims"]["admin"]=True
        assert attempt(invalid5)["code"]=="410_SIGNATURE_OR_SIGNED_SCOPE_INVALID"
        # A forged *valid Ed25519 signature with a different key* must
        # fail against the backend root-pinned issuer trust anchor.
        wrong_key=Ed25519PrivateKey.generate()
        forger=m.sign(wrong_key,issued["a"]["claims"])
        assert attempt(forger)["code"]=="410_SIGNATURE_OR_SIGNED_SCOPE_INVALID"
        assert attempt(issued["expired"])["code"]=="410_EXPIRED_OR_NOT_YET_VALID_AT_SINK"

        # Issuer signs only pre-enrolled B revocation; sink verifies
        # its signature and stores a durable revocation atomically.
        signed_revocation=_ask(names["agent"],issuer_sock,
                               {"v":1,"op":"revoke","alias":"b"})
        assert signed_revocation["ok"] is True
        fake_rev=deepcopy(signed_revocation["signed"])
        fake_rev["claims"]["jti"]=m.JTIS["a"]
        refused_rev=_ask(names["agent"],gate_sock,
                         {"v":1,"op":"revoke","statement":fake_rev})
        assert refused_rev["ok"] is False
        assert refused_rev["code"]=="410_BAD_SIGNED_REVOCATION"
        rev=_ask(names["agent"],gate_sock,
                 {"v":1,"op":"revoke","statement":signed_revocation["signed"]})
        assert rev["ok"] is True
        assert rev["code"]=="410_SIGNED_REVOCATION_PERSISTED"
        assert attempt(issued["b"])["code"]=="410_ISSUER_SIGNED_REVOCATION_ACTIVE"

        # One genuine real pinned VERITAS Bind COMMITTED to a separate
        # Linux principal owning the only synthetic effect credential.
        positive=_ask(names["agent"],gate_sock,
                      {"v":1,"op":"execute","permit":issued["a"]})
        assert positive["ok"] is True
        assert positive["code"]=="410_REAL_BIND_COMMITTED_SIGNED_EFFECT"
        assert positive["bind_receipt_sha256"]
        assert positive["effect_receipt_sha256"]
        assert attempt(issued["a"])["code"]=="410_SIGNED_JTI_ALREADY_CONSUMED"
        end=_ask(names["agent"],gate_sock,{"v":1,"op":"status"})
        assert end["effect_count"]==1
        assert end["revoked_count"]==1
        assert end["genuine_bind_commits"]==1
        assert end["targets"][m.TARGETS["a"]]=={"units":7,"revision":1}
        assert end["targets"][m.TARGETS["b"]]=={"units":0,"revision":0}

        # Stop and restart the backend with SAME private SQLite,
        # issuer trust anchor and gateway identity. No bypass possible.
        assert _ask(names["gateway"],backend_sock,
                    {"v":1,"op":"close"})["ok"] is True
        assert backend.wait(timeout=12)==0,backend.stderr.read()[-1800:]
        backend.stdout.close();backend.stderr.close()
        backend=None
        subprocess.run(["sudo","-n","rm","-f",str(backend_sock)],check=True)
        backend=_spawn(names["backend"],"--backend",backend_sock,
                       uids["gateway"],dbfile,trust)
        _wait_socket(backend,backend_sock)
        restart=_ask(names["agent"],gate_sock,{"v":1,"op":"status"})
        assert restart["state_sha256"]==end["state_sha256"]
        assert restart["effect_receipts_sha256"]==end["effect_receipts_sha256"]
        assert restart["revoked_count"]==1 and restart["effect_count"]==1
        assert attempt(issued["a"])["code"]=="410_SIGNED_JTI_ALREADY_CONSUMED"
        assert attempt(issued["b"])["code"]=="410_ISSUER_SIGNED_REVOCATION_ACTIVE"
        assert attempt(issued["expired"])["code"]=="410_EXPIRED_OR_NOT_YET_VALID_AT_SINK"
        last=_ask(names["agent"],gate_sock,{"v":1,"op":"status"})
        assert last["state_sha256"]==restart["state_sha256"]
        report=m.redacted_report(
            initial=initial,final=end,positive=positive,native=native,
            denials=denied,issuer_uid=uids["issuer"],
            backend_uid=uids["backend"],gate_uid=uids["gateway"],
            agent_uid=uids["agent"],revoked=rev,restart=restart)
        assert report["real_bind_committed"]==1
        assert report["mock_effect_count"]==1
        assert report["real_human_authorization_verified"] is False
        assert report["global_nonbypassable_effect_execution_proven"] is False
        Path("results").mkdir(exist_ok=True)
        Path("results/final128-410-redacted-signed-issuer.json").write_text(
            json.dumps(report,sort_keys=True,indent=2)+"\n",encoding="utf8")
        return report
    finally:
        _close(gate,names["agent"],gate_sock)
        _close(backend,names["gateway"],backend_sock)
        _close(issuer,names["agent"],issuer_sock)


def test_actual_linux_separate_ed25519_issuer_signature_sink_and_revoke():
    outcome=_prove_crossuid_signed_issuer()
    assert outcome["sink_verified_ed25519_signature"] is True
    assert outcome["sink_enforced_revocation_and_expiry"] is True
    assert outcome["backend_restarted_with_identical_digest"] is True
    assert outcome["native_task1_write_still_blocked"] is True

@pytest.mark.parametrize("alias",["a","b","expired"])
def test_exact_source_owned_grant_scope(alias):
    assert m.JTIS[alias].startswith("410-")
    assert m.TARGETS[alias].startswith("offline://410/")
    assert m.DELTA==7

@pytest.mark.parametrize("untrusted",[
    None,True,False,{},[],{"issuer":"fake"},{"prior_paid_approval":"$5"}
])
def test_unsigned_or_fake_authority_never_verifies(untrusted):
    pub=Ed25519PrivateKey.generate().public_key()
    assert m.verify(pub,untrusted) is None

def test_wrong_private_key_does_not_verify_even_with_valid_ed25519_signature():
    k=Ed25519PrivateKey.generate()
    other=Ed25519PrivateKey.generate()
    token=m.issue_claim(k,"a")
    assert m.verify(k.public_key(),token) is not None
    assert m.verify(other.public_key(),token) is None
    forged=deepcopy(token);forged["claims"]["target"]="offline://410/alternate"
    assert m.verify(k.public_key(),forged) is None

def test_signature_fields_revocation_constraints_and_local_nonclaims():
    text=Path(m.__file__).read_text(encoding="utf8")
    for needed in (
        "Ed25519PrivateKey.generate()",
        "public.verify(",
        'db.execute("BEGIN IMMEDIATE")',
        'db.execute("INSERT INTO consumed VALUES (?,?)"',
        'db.execute("INSERT OR IGNORE INTO revoked VALUES (?,?)"',
        'if peer["uid"]!=gateway_uid:',
        'if peer["uid"]!=agent_uid:',
        'now<claims["expires_unix"]',
        "execute_bind_adjudication(",
        "stat.S_IMODE(d.st_mode)==0o700",
        "stat.S_IMODE(x.st_mode)==0o600",
        'stat.S_IMODE(f.st_mode)==0o644',
    ):
        assert needed in text,needed
    for forbidden in ("requests.post(","client.chat.completions.create(",
                      "client.responses.create(","pickle.loads(",
                      "suite._check_task_result("):
        assert forbidden not in text
