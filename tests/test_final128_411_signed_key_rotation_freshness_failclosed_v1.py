"""#411 Linux-separated signing leaf rotation / sink freshness fail-closed."""
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

from scripts import final128_411_signed_key_rotation_freshness_failclosed_v1 as m

MODULE="scripts.final128_411_signed_key_rotation_freshness_failclosed_v1"

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

def _cmd(user,*args):
    return ["sudo","-n","-u",user,"--","/usr/bin/env"]+[
        f"{k}={v}" for k,v in _env().items()
    ]+[sys.executable,"-m",MODULE,*[str(arg) for arg in args]]

def _run(user,*args):
    return subprocess.run(_cmd(user,*args),capture_output=True,
                          text=True,timeout=18,check=False)

def _start(user,*args):
    return subprocess.Popen(_cmd(user,*args),stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,text=True)

def _wait(proc,p):
    clock=time.monotonic()
    while (subprocess.run(["sudo","-n","test","-S",str(p)],
                          capture_output=True).returncode!=0
           and proc.poll() is None):
        assert time.monotonic()-clock<25,"411 service startup timeout"
        time.sleep(.1)
    assert proc.poll() is None,proc.stderr.read()[-3000:]

def _ask(user,sock,message):
    call=_run(user,"--client",sock,json.dumps(message,sort_keys=True,separators=(",",":")))
    assert call.returncode==0,call.stderr[-2800:]
    parsed=json.loads(call.stdout)
    assert parsed["schema"]==m.SCHEMA
    return parsed

def _shutdown(proc,user,sock):
    if proc is None:return
    if proc.poll() is None:
        try:_ask(user,sock,{"v":1,"op":"close"})
        except (ValueError,AssertionError,TimeoutError,subprocess.TimeoutExpired,OSError):
            pass
    if proc.poll() is None:
        proc.kill()
    proc.wait(timeout=12)
    proc.stdout.close();proc.stderr.close()

def _run_real_linux_rotation():
    if os.environ.get("FINAL128_411_LINUX_READY")!="1":
        pytest.skip("Dedicated Linux multi-principal 411 CI required")
    names={
        "issuer":os.environ["FINAL128_410_ISSUER_USER"],
        "agent":os.environ["FINAL128_407_AGENT_USER"],
        "gateway":os.environ["FINAL128_407_GATEWAY_USER"],
        "backend":os.environ["FINAL128_407_BACKEND_USER"],
        "stranger":os.environ["FINAL128_407_STRANGER_USER"],
    }
    uids={k:pwd.getpwnam(v).pw_uid for k,v in names.items()}
    assert len(set(uids.values())|{os.geteuid()})==6
    sandbox=Path(os.environ["FINAL128_407_SANDBOX_ROOT"])
    keydir=sandbox/"issuer411_private"
    staged=sandbox/"issuer411_stage"/"control.pub"
    trust=sandbox/"root411_trust"/"control.pub"
    iss_sock=sandbox/"issuer_ipc"/"411rotate.sock"
    sink_sock=sandbox/"backend_ipc"/"411sink.sock"
    gate_sock=sandbox/"gateway_ipc"/"411gate.sock"
    dbfile=sandbox/"backend_private"/"411rotating.sqlite3"
    for path in (staged,trust,iss_sock,sink_sock,gate_sock,dbfile):
        assert subprocess.run(["sudo","-n","test","!","-e",str(path)],
                              capture_output=True).returncode==0
    boot=_run(names["issuer"],"--bootstrap",keydir,staged)
    assert boot.returncode==0,boot.stderr[-1800:]
    assert len(boot.stdout.strip())==64
    subprocess.run(["sudo","-n","install","-m","0644","-o","root","-g","root",
                    str(staged),str(trust)],check=True)
    stat=subprocess.run(["sudo","-n","stat","-c","%u:%a",str(trust)],
                        capture_output=True,text=True,check=True)
    assert stat.stdout.strip()=="0:644"
    for kid in ("authority","old","new"):
        private=keydir/(kid+".raw")
        got=subprocess.run(["sudo","-n","stat","-c","%u:%a",str(private)],
                           capture_output=True,text=True,check=True)
        assert got.stdout.strip()==f"{uids['issuer']}:600"
        for intruder in ("agent","gateway","backend","stranger"):
            denied=subprocess.run(["sudo","-n","-u",names[intruder],
                                   "head","-c","1",str(private)],
                                  capture_output=True)
            assert denied.returncode!=0
    backend=gate=issuer=None
    try:
        issuer=_start(names["issuer"],"--issuer",iss_sock,keydir,uids["agent"])
        _wait(issuer,iss_sock)
        backend=_start(names["backend"],"--backend",sink_sock,
                       uids["gateway"],dbfile,trust)
        _wait(backend,sink_sock)
        gate=_start(names["gateway"],"--gateway",gate_sock,sink_sock,
                    uids["agent"],uids["backend"])
        _wait(gate,gate_sock)
        first=_ask(names["agent"],gate_sock,{"v":1,"op":"status"})
        assert first["policy_epoch"]==0 and first["effect_count"]==0
        assert first["genuine_bind_commits"]==0
        native=_ask(names["agent"],gate_sock,{"v":1,"op":"native_probe"})
        assert native["code"]=="411_NATIVE_REAL_BIND_DENY"
        assert native["bind_blocks"]>=1
        # All public identifiers and signed bytes are visible to agent.
        # Knowing them is not permission to connect directly to effect sink.
        wrong=_run(names["agent"],"--client",sink_sock,json.dumps({"v":1,"op":"status"}))
        assert wrong.returncode!=0
        stranger=_run(names["stranger"],"--client",iss_sock,json.dumps({"v":1,"op":"policy","phase":"old"}))
        assert stranger.returncode!=0

        def policy(phase):
            msg=_ask(names["agent"],iss_sock,{"v":1,"op":"policy","phase":phase})
            assert msg["ok"] is True
            assert msg["code"]=="411_SOURCE_SIGNED_KEY_POLICY"
            return msg["signed"]
        def permit(kid,alias):
            x=_ask(names["agent"],iss_sock,{"v":1,"op":"issue","kid":kid,"alias":alias})
            assert x["ok"] is True
            return x["signed"]
        def install(token):
            return _ask(names["agent"],gate_sock,{"v":1,"op":"policy","signed":token})
        def execute(token):
            return _ask(names["agent"],gate_sock,{"v":1,"op":"execute","permit":token})
        def must_deny(token,code):
            response=execute(token)
            assert response["ok"] is False
            assert response["code"]==code
            return response
        phase1=policy("old")
        denied=[]
        # Wrong ROOT signature and altered policy must fail at sink.
        fake=deepcopy(phase1)
        fake["claims"]["active_kid"]="new"
        bad=install(fake)
        assert bad["code"]=="411_UNTRUSTED_OR_INVALID_CONTROL_SIGNATURE"
        denied.append(bad)
        alternate=Ed25519PrivateKey.generate()
        wrong_root=m.signature(alternate,phase1["claims"])
        bad=install(wrong_root)
        assert bad["code"]=="411_UNTRUSTED_OR_INVALID_CONTROL_SIGNATURE"
        denied.append(bad)
        signed1=install(phase1)
        assert signed1["ok"] is True and signed1["epoch"]==1
        old_a=permit("old","a")
        old_b=permit("old","b")
        new_b=permit("new","b")
        new_c=permit("new","c")
        must_deny(new_b,"411_REVOKED_OR_RETIRED_SIGNING_KEY")
        old_success=execute(old_a)
        assert old_success["ok"] is True
        assert old_success["code"]=="411_REAL_BIND_COMMITTED_FRESH_SIGNING_KEY"
        assert old_success["bind_receipt_sha256"]
        denied.append(must_deny(old_a,"411_DURABLE_SINGLEUSE_REPLAY_DENIED"))
        phase2=policy("rotated")
        newpolicy=install(phase2)
        assert newpolicy["ok"] is True and newpolicy["epoch"]==2
        s=_ask(names["agent"],gate_sock,{"v":1,"op":"status"})
        assert s["old_key_revoked"] is True and s["active_kid"]=="new"
        # OLD B signature is cryptographically valid, but is now revoked.
        denied.append(must_deny(old_b,"411_REVOKED_OR_RETIRED_SIGNING_KEY"))
        changed=deepcopy(phase1)
        denied.append(install(changed))
        assert denied[-1]["code"]=="411_OLD_OR_REPLAYED_CONTROL_EPOCH"
        tampered=deepcopy(new_b)
        tampered["claims"]["target"]=m.TARGETS["c"]
        denied.append(must_deny(tampered,"411_LEAF_SIGNATURE_OR_CLAIMS_TAMPERED"))
        fakeleaf=m.signature(Ed25519PrivateKey.generate(),new_b["claims"])
        denied.append(must_deny(fakeleaf,"411_LEAF_SIGNATURE_OR_CLAIMS_TAMPERED"))
        new_success=execute(new_b)
        assert new_success["ok"] is True
        assert new_success["code"]=="411_REAL_BIND_COMMITTED_FRESH_SIGNING_KEY"
        denied.append(must_deny(new_b,"411_DURABLE_SINGLEUSE_REPLAY_DENIED"))
        s2=_ask(names["agent"],gate_sock,{"v":1,"op":"status"})
        assert s2["effect_count"]==2 and s2["genuine_bind_commits"]==2
        assert s2["targets"][m.TARGETS["a"]]=={"units":7,"revision":1}
        assert s2["targets"][m.TARGETS["b"]]=={"units":7,"revision":1}
        assert s2["targets"][m.TARGETS["c"]]=={"units":0,"revision":0}

        # Control authority issues a short signed lease; issuer is then
        # unavailable, so no replacement freshness statement can arrive.
        phase3=policy("short")
        epoch3=install(phase3)
        assert epoch3["ok"] is True and epoch3["epoch"]==3
        assert _ask(names["agent"],gate_sock,{"v":1,"op":"status"})["backend_policy_fresh"] is True
        assert _ask(names["agent"],iss_sock,{"v":1,"op":"close"})["ok"] is True
        assert issuer.wait(timeout=12)==0,issuer.stderr.read()[-1700:]
        issuer.stdout.close();issuer.stderr.close();issuer=None
        noissuer=_run(names["agent"],"--client",iss_sock,
                      json.dumps({"v":1,"op":"policy","phase":"rotated"}))
        assert noissuer.returncode!=0
        time.sleep(3.1)
        stale=_ask(names["agent"],gate_sock,{"v":1,"op":"status"})
        assert stale["backend_policy_fresh"] is False
        denied.append(must_deny(new_c,"411_POLICY_STALE_FAIL_CLOSED"))
        denied.append(install(phase2))
        assert denied[-1]["code"]=="411_OLD_OR_REPLAYED_CONTROL_EPOCH"
        end=_ask(names["agent"],gate_sock,{"v":1,"op":"status"})
        assert end["effect_count"]==2 and end["policy_epoch"]==3

        # Restart the independently owned backend from its durable state.
        assert _ask(names["gateway"],sink_sock,{"v":1,"op":"close"})["ok"] is True
        assert backend.wait(timeout=12)==0,backend.stderr.read()[-1600:]
        backend.stdout.close();backend.stderr.close();backend=None
        subprocess.run(["sudo","-n","rm","-f",str(sink_sock)],check=True)
        backend=_start(names["backend"],"--backend",sink_sock,
                       uids["gateway"],dbfile,trust)
        _wait(backend,sink_sock)
        restarted=_ask(names["agent"],gate_sock,{"v":1,"op":"status"})
        assert restarted["state_sha256"]==end["state_sha256"]
        assert restarted["policy_epoch"]==3
        assert restarted["old_key_revoked"] is True
        assert restarted["effect_count"]==2
        denied.append(must_deny(old_b,"411_POLICY_STALE_FAIL_CLOSED"))
        denied.append(must_deny(new_c,"411_POLICY_STALE_FAIL_CLOSED"))
        final=_ask(names["agent"],gate_sock,{"v":1,"op":"status"})
        assert final["state_sha256"]==end["state_sha256"]
        evidence=m.manifest(
            first=first,last=final,old_commit=old_success,new_commit=new_success,
            denied=denied,native=native,epoch3=epoch3,issuer_uid=uids["issuer"],
            gateway_uid=uids["gateway"],backend_uid=uids["backend"],
            agent_uid=uids["agent"],backend_restart_ok=True,issuer_was_down=True)
        assert evidence["global_nonbypassable_effect_execution_proven"] is False
        assert evidence["real_external_bank_effects"]==0
        assert evidence["paid_provider_calls"]==0
        Path("results").mkdir(exist_ok=True)
        Path("results/final128-411-redacted-key-lifecycle.json").write_text(
            json.dumps(evidence,indent=2,sort_keys=True)+"\n",encoding="utf8")
        return evidence
    finally:
        _shutdown(gate,names["agent"],gate_sock)
        _shutdown(backend,names["gateway"],sink_sock)
        _shutdown(issuer,names["agent"],iss_sock)

def test_os_principals_key_rotation_old_key_revoked_and_issuer_outage_failclosed():
    proof=_run_real_linux_rotation()
    assert proof["real_pinned_veritas_bind_committed_receipts"]==2
    assert proof["issuer_unavailable_and_policy_expired_fail_closed"] is True
    assert proof["backend_restart_preserves_epoch_and_effects"] is True

@pytest.mark.parametrize("phase,epoch",[("old",1),("rotated",2),("short",3)])
def test_policy_issuance_stages_are_fixed(phase,epoch):
    assert {"old":1,"rotated":2,"short":3}[phase]==epoch
    assert m.KEYS==("old","new")
    assert m.UNITS==7
    assert m.SCHEMA.startswith("veritas.final128.task1-411")

@pytest.mark.parametrize("alias",["a","b","c"])
def test_distinct_source_owned_targets(alias):
    assert m.TARGETS[alias]=="offline://411/"+alias
    assert m.JTIS[alias]=="411-"+alias+"-single"

@pytest.mark.parametrize("bad",[None,True,False,{},[],0,{"claimed_human_approval":True}])
def test_unsigned_untrusted_authority_rejected(bad):
    assert m._verify(Ed25519PrivateKey.generate().public_key(),
                     bad,m.POLICY_FIELDS) is None

def test_cryptographic_signatures_bind_control_policy_bytes():
    key=Ed25519PrivateKey.generate()
    example={field:"fixed" for field in m.POLICY_FIELDS}
    good=m.signature(key,example)
    assert m._verify(key.public_key(),good,m.POLICY_FIELDS)==example
    modified=deepcopy(good)
    modified["claims"]["active_kid"]="different"
    assert m._verify(key.public_key(),modified,m.POLICY_FIELDS) is None
    assert m._verify(Ed25519PrivateKey.generate().public_key(),good,m.POLICY_FIELDS) is None

def test_source_enforces_true_backend_atomicity_and_offline_nonclaims():
    source=Path(m.__file__).read_text(encoding="utf8")
    for marker in ('db.execute("BEGIN IMMEDIATE")',
                   'db.commit()',
                   'if peer["uid"]!=gateway_uid:',
                   'if peer["uid"]!=agent_uid:',
                   'if p is None or int(time.time())>=p[2]:',
                   'return "411_REVOKED_OR_RETIRED_SIGNING_KEY",None',
                   '"411_POLICY_EPOCH_GAP_DENIED"',
                   "execute_bind_adjudication(",
                   'from veritas_os.policy.bind_core.core import ReferenceBindAdapter',
                   '"production_IAM_or_network_egress_proven":False'):
        assert marker in source,marker
    for forbidden in ("client.responses.create(","requests.post(",
                      "client.chat.completions.create(",
                      "pickle.loads(","suite._check_task_result("):
        assert forbidden not in source
