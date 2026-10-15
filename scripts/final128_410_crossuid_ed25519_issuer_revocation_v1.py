#!/usr/bin/env python3
"""#410 offline Ed25519 issuer UID -> signed permit -> separate sink UID -> real Bind.

Dedicated local Linux identities: issuer holds 0600 Ed25519 secret in 0700
directory; agent requests ONLY source-owned synthetic fixtures; gateway
calls actual pinned VERITAS execute_bind_adjudication; backend verifies
issuer signature, strict audience/target/units/revision/expiry/revocation
inside BEGIN IMMEDIATE prior to consuming a permit and updating SQLite.
A root-owned 0644 public key copy is the sink's pinned trust anchor.
No actual human authority, real bank, real credential, production IAM,
network egress, remote attestation or paid LLM calls are involved.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import socket
import sqlite3
import stat
import sys
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey,Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

from scripts import final128_409_multigrant_expiry_drift_concurrency_v1 as old
from scripts import final128_407_task1_synthetic_backend_singleuse_bind_v1 as transport
from scripts import final128_408_task1_durable_mock_backend_crash_recovery_v1 as durable
from scripts import final128_406_task1_cross_uid_unix_effect_owner_gate_v1 as linux

SCHEMA="veritas.final128.task1-410-signed-issuer-backend-revocation-v1"
ISSUER="410-offline-source-owned-ed25519-issuer"
AUDIENCE="410-local-mock-effect-backend-only"
TARGETS={"a":"offline://410/A","b":"offline://410/B","expired":"offline://410/expired"}
JTIS={"a":"410-A-ONCE","b":"410-B-REVOKABLE","expired":"410-E-EXPIRED"}
DELTA=7
CLAIM_KEYS=frozenset(("kind","issuer","audience","jti","target","units",
                       "expected_revision","issued_at_unix","not_before_unix",
                       "expires_unix"))
REVOCATION_KEYS=frozenset(("kind","issuer","audience","jti"))
SCHEMA_ENVELOPE=frozenset(("claims","signature"))
MAX_REQUESTS=100

class Refused(ValueError):
    pass

def need(ok,reason):
    if ok is not True:
        raise Refused("410_"+reason)

def canonical(data):
    return json.dumps(data,sort_keys=True,separators=(",",":"),
                      ensure_ascii=False,allow_nan=False).encode("utf8")

def hash_obj(data):
    return hashlib.sha256(canonical(data)).hexdigest()

def b64(data):
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")

def unb64(data):
    need(type(data) is str and len(data)<=120 and
         all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for c in data),
         "BOUNDED_SIGNATURE_ENCODING_REQUIRED")
    try:
        raw=base64.b64decode((data+"="*((-len(data))%4)).encode("ascii"),
                             altchars=b"-_",validate=True)
    except (ValueError,base64.binascii.Error) as exc:
        raise Refused("410_INVALID_SIGNATURE_ENCODING") from exc
    need(len(raw)==64,"ED25519_SIGNATURE_SIZE_REQUIRED")
    return raw

def _owner_private(path):
    linux._no_links(str(path))
    p=Path(path)
    d=p.parent.stat()
    need(os.geteuid()>0 and d.st_uid==os.geteuid()
         and stat.S_ISDIR(d.st_mode)
         and stat.S_IMODE(d.st_mode)==0o700,
         "ISSUER_PRIVATE_DIRECTORY_MUST_BE_OWNER_ONLY")
    if p.exists():
        x=p.lstat()
        need(stat.S_ISREG(x.st_mode) and x.st_uid==os.geteuid()
             and stat.S_IMODE(x.st_mode)==0o600 and x.st_nlink==1,
             "ISSUER_PRIVATE_KEY_0600_REQUIRED")

def init_key(private_path,staged_public_path):
    _owner_private(private_path)
    need(not Path(private_path).exists(),"EXISTING_ISSUER_KEY_MUST_NOT_BE_REPLACED")
    linux._no_links(staged_public_path)
    staged=Path(staged_public_path)
    d=staged.parent.stat()
    need(d.st_uid==os.geteuid() and stat.S_IMODE(d.st_mode)==0o755,
         "ISSUER_STAGING_DIRECTORY_REQUIRED")
    key=Ed25519PrivateKey.generate()
    seed=key.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,
                           serialization.NoEncryption())
    fd=os.open(private_path,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
    try:
        os.write(fd,seed);os.fsync(fd)
    finally:
        os.close(fd)
    pub=key.public_key().public_bytes(serialization.Encoding.Raw,
                                      serialization.PublicFormat.Raw)
    staged.write_bytes(pub)
    os.chmod(staged,0o644)
    _owner_private(private_path)
    need(len(pub)==32,"ED25519_PUBLIC_SIZE")
    return hashlib.sha256(pub).hexdigest()

def _issuer_key(path):
    _owner_private(path)
    secret=Path(path).read_bytes()
    need(len(secret)==32,"PRIVATE_KEY_EXACT_RAW_LENGTH")
    return Ed25519PrivateKey.from_private_bytes(secret)

def _pinned_public(path):
    linux._no_links(path)
    p=Path(path);root=p.parent.stat();f=p.stat()
    need(root.st_uid==0 and stat.S_IMODE(root.st_mode)==0o755
         and f.st_uid==0 and f.st_nlink==1
         and stat.S_ISREG(f.st_mode)
         and stat.S_IMODE(f.st_mode)==0o644,
         "ROOT_OWNED_PUBLIC_TRUST_ANCHOR_REQUIRED")
    raw=p.read_bytes()
    need(len(raw)==32,"PINNED_ED25519_PUBLIC_KEY_LENGTH")
    return Ed25519PublicKey.from_public_bytes(raw)

def sign(key,claims):
    return {"claims":claims,"signature":b64(key.sign(canonical(claims)))}

def verify(public,token):
    if type(token) is not dict or set(token)!=SCHEMA_ENVELOPE:
        return None
    claims=token.get("claims")
    if type(claims) is not dict or claims.get("kind") not in ("permit","revocation"):
        return None
    required=CLAIM_KEYS if claims["kind"]=="permit" else REVOCATION_KEYS
    if set(claims)!=required:
        return None
    try:
        public.verify(unb64(token["signature"]),canonical(claims))
    except (InvalidSignature,Refused,TypeError,ValueError):
        return None
    if (claims["issuer"]!=ISSUER or claims["audience"]!=AUDIENCE
        or type(claims["jti"]) is not str
        or claims["jti"] not in JTIS.values()):
        return None
    if claims["kind"]=="permit":
        if (type(claims["target"]) is not str
            or type(claims["units"]) is not int
            or claims["units"]!=DELTA
            or type(claims["expected_revision"]) is not int
            or claims["expected_revision"]!=0
            or any(type(claims[k]) is not int for k in
                   ("issued_at_unix","not_before_unix","expires_unix"))):
            return None
        alias=next((a for a,j in JTIS.items() if j==claims["jti"]),None)
        if alias is None or claims["target"]!=TARGETS[alias]:
            return None
    else:
        if claims["jti"]!=JTIS["b"]:
            return None
    return claims

def issue_claim(key,alias):
    need(type(alias) is str and alias in TARGETS,"SOURCE_FIXTURE_ISSUANCE_ONLY")
    now=int(time.time())
    return sign(key,{
        "kind":"permit","issuer":ISSUER,"audience":AUDIENCE,
        "jti":JTIS[alias],"target":TARGETS[alias],"units":DELTA,
        "expected_revision":0,"issued_at_unix":now-500,
        "not_before_unix":now-400,
        "expires_unix":now-10 if alias=="expired" else now+900,
    })

def issuer_server(socket_path,private_key_path,agent_uid):
    need(type(agent_uid) is int and agent_uid>0
         and agent_uid!=os.geteuid() and os.geteuid()>0,
         "ISSUER_SEPARATE_LINUX_OS_IDENTITY")
    key=_issuer_key(private_key_path)
    def handler(conn,peer):
        if peer["uid"]!=agent_uid:
            return False
        try:
            req=transport._read(conn)
        except transport.Refused:
            transport._send(conn,{"schema":SCHEMA,"ok":False,"code":"410_BAD_ISSUER_JSON"})
            return False
        if type(req) is not dict or type(req.get("v")) is not int or req["v"]!=1:
            transport._send(conn,{"schema":SCHEMA,"ok":False,"code":"410_ISSUER_BAD_VERSION"})
            return False
        if req.get("op")=="issue" and set(req)=={"v","op","alias"}:
            if type(req["alias"]) is not str or req["alias"] not in TARGETS:
                transport._send(conn,{"schema":SCHEMA,"ok":False,"code":"410_UNAUTHORIZED_ISSUE_SCOPE"})
            else:
                transport._send(conn,{"schema":SCHEMA,"ok":True,"code":"410_SOURCE_FIXTURE_SIGNED",
                                      "signed":issue_claim(key,req["alias"])})
            return False
        if req.get("op")=="revoke" and set(req)=={"v","op","alias"}:
            if req["alias"]!="b":
                transport._send(conn,{"schema":SCHEMA,"ok":False,"code":"410_UNAUTHORIZED_REVOKE_SCOPE"})
            else:
                statement={"kind":"revocation","issuer":ISSUER,
                           "audience":AUDIENCE,"jti":JTIS["b"]}
                transport._send(conn,{"schema":SCHEMA,"ok":True,
                                      "code":"410_SOURCE_FIXTURE_REVOKED",
                                      "signed":sign(key,statement)})
            return False
        if req.get("op")=="close" and set(req)=={"v","op"}:
            transport._send(conn,{"schema":SCHEMA,"ok":True,"code":"410_ISSUER_CLOSED"})
            return True
        transport._send(conn,{"schema":SCHEMA,"ok":False,"code":"410_ISSUER_METHOD_DENIED"})
        return False
    transport._listen(socket_path,handler)

def _open_db(path):
    durable._strict_db_path(path)
    oldumask=os.umask(0o077)
    try:
        db=sqlite3.connect(path,timeout=8,isolation_level=None)
        db.execute("PRAGMA journal_mode=DELETE")
        db.execute("PRAGMA synchronous=FULL")
        db.execute("CREATE TABLE IF NOT EXISTS targets (resource TEXT PRIMARY KEY,units INTEGER NOT NULL,revision INTEGER NOT NULL)")
        db.execute("CREATE TABLE IF NOT EXISTS consumed (jti TEXT PRIMARY KEY,receipt_sha256 TEXT NOT NULL)")
        db.execute("CREATE TABLE IF NOT EXISTS revoked (jti TEXT PRIMARY KEY,statement_sha256 TEXT NOT NULL)")
        for target in TARGETS.values():
            db.execute("INSERT OR IGNORE INTO targets VALUES (?,0,0)",(target,))
        db.commit()
    finally:
        os.umask(oldumask)
    durable._strict_db_path(path)
    return db

def _state(db):
    rows={r:{"units":u,"revision":v} for r,u,v in
          db.execute("SELECT resource,units,revision FROM targets ORDER BY resource")}
    used=[r for (r,) in db.execute("SELECT jti FROM consumed ORDER BY jti")]
    revoked=[r for (r,) in db.execute("SELECT jti FROM revoked ORDER BY jti")]
    receipts=[r for (r,) in db.execute("SELECT receipt_sha256 FROM consumed ORDER BY jti")]
    need(set(rows)==set(TARGETS.values()) and len(used)<=1
         and all(x["units"] in (0,DELTA) for x in rows.values())
         and all(x["revision"] in (0,1) for x in rows.values())
         and len(revoked)<=1,"MOCK_LEDGER_INVALID")
    return {"targets":rows,"consumed":used,"revoked":revoked,"receipts":receipts}

def status(db):
    state=_state(db)
    return {"schema":SCHEMA,"ok":True,"code":"410_SINK_LEDGER_STATUS",
            "backend_uid":os.geteuid(),"state_sha256":hash_obj(state),
            "targets":state["targets"],"effect_count":len(state["consumed"]),
            "consumed_count":len(state["consumed"]),
            "revoked_count":len(state["revoked"]),
            "effect_receipts_sha256":[hash_obj(x) for x in state["receipts"]],
            "only_synthetic_effects":True}

def _adjudicate(db,public,permit):
    claims=verify(public,permit)
    if claims is None or claims["kind"]!="permit":
        return "410_SIGNATURE_OR_SIGNED_SCOPE_INVALID",None
    now=int(time.time())
    if not (claims["not_before_unix"]<=now<claims["expires_unix"]
            and claims["issued_at_unix"]<=now):
        return "410_EXPIRED_OR_NOT_YET_VALID_AT_SINK",claims
    if db.execute("SELECT 1 FROM revoked WHERE jti=?",(claims["jti"],)).fetchone():
        return "410_ISSUER_SIGNED_REVOCATION_ACTIVE",claims
    if db.execute("SELECT 1 FROM consumed WHERE jti=?",(claims["jti"],)).fetchone():
        return "410_SIGNED_JTI_ALREADY_CONSUMED",claims
    record=db.execute("SELECT units,revision FROM targets WHERE resource=?",
                      (claims["target"],)).fetchone()
    if record is None or record[1]!=claims["expected_revision"]:
        return "410_TARGET_LIVE_REVISION_MISMATCH",claims
    return None,claims

def _apply(db,public,permit):
    db.execute("BEGIN IMMEDIATE")
    try:
        reason,claims=_adjudicate(db,public,permit)
        if reason:
            result={"schema":SCHEMA,"ok":False,"code":reason,
                    "state_sha256":status(db)["state_sha256"]}
            db.rollback()
            return result
        target=claims["target"];jti=claims["jti"]
        before=status(db)["state_sha256"]
        upd=db.execute("UPDATE targets SET units=units+?,revision=revision+1 WHERE resource=? AND revision=?",
                       (DELTA,target,claims["expected_revision"]))
        need(upd.rowcount==1,"SINK_EXPECTED_STATE_CAS_REQUIRED")
        receipt={"jti_sha256":hash_obj(jti),"target_sha256":hash_obj(target),
                 "before_sha256":before,"units":DELTA}
        receipt_hash=hash_obj(receipt)
        db.execute("INSERT INTO consumed VALUES (?,?)",(jti,receipt_hash))
        after=status(db)
        db.commit()
        return {"schema":SCHEMA,"ok":True,"code":"410_VERIFIED_SIGNED_EFFECT_APPLIED",
                "state_sha256":after["state_sha256"],
                "prestate_sha256":before,
                "effect_receipt_sha256":receipt_hash,
                "effect_count":after["effect_count"]}
    except BaseException:
        db.rollback()
        raise

def _revoke(db,public,token):
    claims=verify(public,token)
    if claims is None or claims["kind"]!="revocation":
        return {"schema":SCHEMA,"ok":False,"code":"410_BAD_SIGNED_REVOCATION"}
    db.execute("BEGIN IMMEDIATE")
    try:
        db.execute("INSERT OR IGNORE INTO revoked VALUES (?,?)",
                   (claims["jti"],hash_obj(token)))
        state=status(db)
        db.commit()
        return {"schema":SCHEMA,"ok":True,"code":"410_SIGNED_REVOCATION_PERSISTED",
                "state_sha256":state["state_sha256"],"revoked_count":1}
    except BaseException:
        db.rollback()
        raise

def backend_server(socket_path,gateway_uid,dbfile,public_key_path):
    need(type(gateway_uid) is int and gateway_uid>0
         and gateway_uid!=os.geteuid() and os.geteuid()>0,
         "SINK_SEPARATE_UNPRIVILEGED_IDENTITY")
    public=_pinned_public(public_key_path)
    db=_open_db(dbfile)
    def handler(conn,peer):
        if peer["uid"]!=gateway_uid:
            return False
        try:
            req=transport._read(conn)
        except transport.Refused:
            transport._send(conn,{"schema":SCHEMA,"ok":False,"code":"410_SINK_BAD_JSON"})
            return False
        if type(req) is not dict or type(req.get("v")) is not int or req["v"]!=1:
            transport._send(conn,{"schema":SCHEMA,"ok":False,"code":"410_SINK_BAD_PROTOCOL"})
            return False
        op=req.get("op")
        if op=="status" and set(req)=={"v","op"}:
            transport._send(conn,status(db));return False
        if op=="preview" and set(req)=={"v","op","permit"}:
            reason,_=_adjudicate(db,public,req["permit"])
            transport._send(conn,{"schema":SCHEMA,"ok":reason is None,
                                  "code":reason or "410_VALID_SIGNED_PREVIEW_NO_EFFECT"})
            return False
        if op=="apply" and set(req)=={"v","op","permit"}:
            transport._send(conn,_apply(db,public,req["permit"]));return False
        if op=="revoke" and set(req)=={"v","op","statement"}:
            transport._send(conn,_revoke(db,public,req["statement"]));return False
        if op=="close" and set(req)=={"v","op"}:
            transport._send(conn,{"schema":SCHEMA,"ok":True,"code":"410_SINK_CLOSED"})
            return True
        transport._send(conn,{"schema":SCHEMA,"ok":False,"code":"410_SINK_METHOD_DENIED"})
        return False
    try:
        transport._listen(socket_path,handler)
    finally:
        db.close()

def query(path,request):
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as sock:
        sock.settimeout(12);sock.connect(str(path))
        sock.sendall(transport._frame(request))
        result=transport._read(sock)
    need(type(result) is dict and result.get("schema")==SCHEMA,
         "STRICT_RESPONSE_SCHEMA_REQUIRED")
    return result

def bind_execute(backend_socket,permit):
    from veritas_os.policy.bind_core import execute_bind_adjudication
    from veritas_os.policy.bind_core.core import ReferenceBindAdapter
    from veritas_os.policy.bind_artifacts import ExecutionIntent
    from veritas_os.security.hash import sha256_of_canonical_json
    before=query(backend_socket,{"v":1,"op":"status"})
    claims=permit["claims"]
    target=claims["target"]
    state={"target":target,
           "entry":before["targets"][target],
           "ledger_sha256":before["state_sha256"]}
    attempts=[]
    class SignedAdapter(ReferenceBindAdapter):
        def snapshot(self):
            live=query(backend_socket,{"v":1,"op":"status"})
            return {"target":target,"entry":live["targets"][target],
                    "ledger_sha256":live["state_sha256"]}
        def validate_authority(self,intent,snapshot):
            return snapshot==state and intent.target_resource==target and intent.intended_action=="increment_exactly_seven"
        def validate_constraints(self,intent,snapshot):
            preview=query(backend_socket,{"v":1,"op":"preview","permit":permit})
            return {"verified_by_effect_sink":preview["ok"] is True,
                    "target_and_live_state":snapshot==state}
        def apply(self,intent,snapshot):
            result=query(backend_socket,{"v":1,"op":"apply","permit":permit})
            attempts.append(result)
            return result["ok"] is True and result["code"]=="410_VERIFIED_SIGNED_EFFECT_APPLIED"
        def verify_postconditions(self,intent,snapshot):
            live=query(backend_socket,{"v":1,"op":"status"})
            return len(attempts)==1 and attempts[0]["ok"] is True and live["state_sha256"]==attempts[0]["state_sha256"] and live["targets"][target]["revision"]==1
        def revert(self,intent,snapshot):
            return False
    intent=ExecutionIntent(
        decision_id="410-test-signed-authority-"+hash_obj(permit)[:14],
        request_id="410-bounded-synthetic-crossuid",
        policy_snapshot_id="410-frozen-offline-source-authority",
        actor_identity="410-gateway-verified-issuer-only",
        target_system="410-local-issuer-signed-mock-sink",
        target_resource=target,intended_action="increment_exactly_seven",
        evidence_refs=["410-permit:"+hash_obj(permit)],
        decision_hash="4"*64,
        decision_ts="2026-10-01T00:00:00Z",
        ttl_seconds=300,
        expected_state_fingerprint=sha256_of_canonical_json(state),
        approval_context={"source_owned_fixture":True,"real_human_approval":False},
        policy_lineage={"issuer":ISSUER,"signed_grant_sha256":hash_obj(permit)})
    adapter=SignedAdapter(state=dict(state),pending_changes={},
                          target_description=target)
    receipt=execute_bind_adjudication(execution_intent=intent,adapter=adapter,
                                      bind_ts="2026-10-01T00:00:03Z",
                                      append_trustlog=False).to_dict()
    after=query(backend_socket,{"v":1,"op":"status"})
    need(receipt["final_outcome"]=="COMMITTED" and len(attempts)==1
         and attempts[0]["ok"] is True and
         after["state_sha256"]==attempts[0]["state_sha256"],
         "GENUINE_BIND_SIGNED_SINK_COMMIT_NOT_RECONCILED")
    return {"code":"410_REAL_BIND_COMMITTED_SIGNED_EFFECT",
            "bind_receipt_sha256":hash_obj(receipt),
            "effect_receipt_sha256":attempts[0]["effect_receipt_sha256"],
            "state_sha256":after["state_sha256"]}

def gateway_server(socket_path,backend_socket,agent_uid,backend_uid):
    need(min(agent_uid,backend_uid,os.geteuid())>0 and
         len({agent_uid,backend_uid,os.geteuid()})==3,
         "GATE_DISTINCT_UID_REQUIRED")
    env,original,runtime,journal=old.old.prior.build_worker_source()
    commits=[]
    def handler(conn,peer):
        if peer["uid"]!=agent_uid:return False
        try:req=transport._read(conn)
        except transport.Refused:
            transport._send(conn,{"schema":SCHEMA,"ok":False,"code":"410_GATE_BAD_JSON"})
            return False
        if type(req) is not dict or type(req.get("v")) is not int or req["v"]!=1:
            transport._send(conn,{"schema":SCHEMA,"ok":False,"code":"410_GATE_BAD_VERSION"})
            return False
        op=req.get("op")
        if op=="close" and set(req)=={"v","op"}:
            transport._send(conn,{"schema":SCHEMA,"ok":True,"code":"410_GATE_CLOSED"})
            return True
        if op=="native_probe" and set(req)=={"v","op"}:
            _,err=runtime.run_function(env,"send_money",{"recipient":"OFFLINE",
                  "amount":1,"subject":"410-test","date":"2022-03-05"})
            need(err=="VERITAS_402_DENIED:REAL_VERITAS_TASK1_BIND_BLOCKED"
                 and env.model_dump(mode="json")==original,
                 "ORIGINAL_TASK1_WRITE_BLOCKED")
            transport._send(conn,{"schema":SCHEMA,"ok":False,
                                  "code":"410_REAL_NATIVE_TASK1_BIND_BLOCKED",
                                  "bind_blocks":journal["bind_blocked"]})
            return False
        if op=="status" and set(req)=={"v","op"}:
            result=query(backend_socket,{"v":1,"op":"status"})
            need(env.model_dump(mode="json")==original,"NATIVE_B_MUTATED")
            result["genuine_bind_commits"]=len(commits)
            transport._send(conn,result);return False
        if op=="revoke" and set(req)=={"v","op","statement"}:
            result=query(backend_socket,{"v":1,"op":"revoke","statement":req["statement"]})
            transport._send(conn,result);return False
        if op=="execute" and set(req)=={"v","op","permit"}:
            if type(req["permit"]) is not dict or type(req["permit"].get("claims")) is not dict:
                transport._send(conn,{"schema":SCHEMA,"ok":False,"code":"410_GATE_PERMIT_FORMAT"})
                return False
            preview=query(backend_socket,{"v":1,"op":"preview","permit":req["permit"]})
            if preview["ok"] is not True:
                transport._send(conn,{"schema":SCHEMA,"ok":False,"code":preview["code"]})
                return False
            result=bind_execute(backend_socket,req["permit"])
            commits.append(result)
            transport._send(conn,{"schema":SCHEMA,"ok":True,**result})
            return False
        transport._send(conn,{"schema":SCHEMA,"ok":False,"code":"410_GATE_UNKNOWN_METHOD"})
        return False
    transport._listen(socket_path,handler)

def redacted_report(*,initial,final,positive,native,denials,issuer_uid,
                    backend_uid,gate_uid,agent_uid,revoked,restart):
    need(len({issuer_uid,backend_uid,gate_uid,agent_uid})==4
         and min(issuer_uid,backend_uid,gate_uid,agent_uid)>0
         and initial["effect_count"]==0 and final["effect_count"]==1
         and final["consumed_count"]==1 and final["revoked_count"]==1
         and final["targets"][TARGETS["a"]]=={"units":7,"revision":1}
         and final["targets"][TARGETS["b"]]=={"units":0,"revision":0}
         and final["targets"][TARGETS["expired"]]=={"units":0,"revision":0}
         and positive["code"]=="410_REAL_BIND_COMMITTED_SIGNED_EFFECT"
         and native["code"]=="410_REAL_NATIVE_TASK1_BIND_BLOCKED"
         and native["bind_blocks"]>=1
         and len(denials)>=7 and all(x["ok"] is False for x in denials)
         and revoked["code"]=="410_SIGNED_REVOCATION_PERSISTED"
         and restart["state_sha256"]==final["state_sha256"],
         "SIGNED_ISSUER_REVOCATION_BIND_SINK_PROOF_INCOMPLETE")
    return {"schema":SCHEMA,
            "status":"OFFLINE_CROSSUID_ED25519_VERIFIED_AT_SINK_BIND_ONCE_REVOCATION",
            "issuer_backend_gate_agent_linux_uids_distinct":True,
            "issuer_private_key_0600_in_owner_only_0700":True,
            "root_owned_public_trust_anchor_0644":True,
            "sink_verified_ed25519_signature":True,
            "sink_enforced_revocation_and_expiry":True,
            "sink_precommit_atomic_singleuse":True,
            "native_task1_write_still_blocked":True,
            "real_bind_committed":1,
            "mock_effect_count":1,
            "backend_restarted_with_identical_digest":True,
            "state_initial_sha256":initial["state_sha256"],
            "state_final_sha256":final["state_sha256"],
            "bind_receipt_sha256":positive["bind_receipt_sha256"],
            "effect_receipt_sha256":positive["effect_receipt_sha256"],
            "agentdojo_pin":old.old.prior.native.NATIVE_PIN,
            "veritas_pin":old.old.prior.native.VERITAS_PIN,
            "real_human_authorization_verified":False,
            "production_issuer_credential_or_remote_identity_proven":False,
            "production_backend_network_iam_proven":False,
            "global_nonbypassable_effect_execution_proven":False,
            "real_external_bank_effects":0,"paid_provider_requests":0,
            "official_native_scorer_calls":0}

def main(argv):
    if len(argv)==4 and argv[1]=="--init-key":
        print(init_key(argv[2],argv[3]))
    elif len(argv)==5 and argv[1]=="--issuer":
        issuer_server(argv[2],argv[3],int(argv[4]))
    elif len(argv)==6 and argv[1]=="--backend":
        backend_server(argv[2],int(argv[3]),argv[4],argv[5])
    elif len(argv)==6 and argv[1]=="--gateway":
        gateway_server(argv[2],argv[3],int(argv[4]),int(argv[5]))
    elif len(argv)==4 and argv[1]=="--client":
        print(json.dumps(query(argv[2],json.loads(argv[3])),sort_keys=True))
    else:
        raise SystemExit("410_OFFLINE_NO_EXTERNAL_EFFECTS_OR_PROVIDER")
if __name__=="__main__":
    main(sys.argv)
