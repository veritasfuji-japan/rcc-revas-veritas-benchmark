#!/usr/bin/env python3
"""#411 source-owned Ed25519 key rotation, old-key revocation, freshness fail closed.

Dedicated offline Linux issuer UID controls three independent raw Ed25519
private seeds: authority root for signed key policies, old/new leaf for
fixture permits. Root-owned trust anchor carries ONLY authority public
key. Distinct sink UID persists signed monotonically increasing key
policy and permit consumption in SQLite, checking verified key status,
freshness, target/revision, and single use inside BEGIN IMMEDIATE.
Real pinned VERITAS execute_bind_adjudication dispatches one mock effect
per admitted signed leaf permit. All fixture identities and targets
are explicitly artificial; no real human permission, real credential,
remote network, production IAM or paid provider is tested.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
from pathlib import Path
import socket
import sqlite3
import stat
import sys
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey,Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

from scripts import final128_410_crossuid_ed25519_issuer_revocation_v1 as base
from scripts import final128_407_task1_synthetic_backend_singleuse_bind_v1 as wire
from scripts import final128_408_task1_durable_mock_backend_crash_recovery_v1 as durable
from scripts import final128_406_task1_cross_uid_unix_effect_owner_gate_v1 as linux

SCHEMA="veritas.final128.task1-411-signed-rotation-freshness-failclosed-v1"
ISSUER="411-offline-fixture-key-authority"
AUDIENCE="411-local-only-synthetic-effect-sink"
TARGETS={x:f"offline://411/{x}" for x in ("a","b","c")}
JTIS={x:f"411-{x}-single" for x in TARGETS}
KEYS=("old","new")
UNITS=7
PERMIT_FIELDS=frozenset(("kind","issuer","audience","kid","jti",
                         "target","units","expected_revision",
                         "not_before_unix","expires_unix"))
POLICY_FIELDS=frozenset(("kind","issuer","audience","epoch","active_kid",
                         "keys","revoked_kids","issued_unix","expires_unix"))

class Refused(ValueError):
    pass

def need(ok,code):
    if ok is not True:
        raise Refused("411_"+code)

def canonical(x):
    return json.dumps(x,sort_keys=True,separators=(",",":"),
                      allow_nan=False,ensure_ascii=False).encode()

def hash_obj(x):
    return hashlib.sha256(canonical(x)).hexdigest()

def _key(seed_file):
    base._owner_private(seed_file)
    seed=Path(seed_file).read_bytes()
    need(len(seed)==32,"PRIVATE_KEY_RAW_32_REQUIRED")
    return Ed25519PrivateKey.from_private_bytes(seed)

def bootstrap(keydir,public_stage):
    path=Path(keydir)
    linux._no_links(str(path))
    x=path.stat()
    need(x.st_uid==os.geteuid() and os.geteuid()>0
         and stat.S_IMODE(x.st_mode)==0o700,
         "PRIVATE_ISSUER_DIRECTORY_REQUIRED")
    for name in ("authority","old","new"):
        destination=path/(name+".raw")
        base._owner_private(str(destination))
        need(not destination.exists(),"PRIVATE_SEED_NO_OVERWRITE")
        seed=Ed25519PrivateKey.generate().private_bytes(
            serialization.Encoding.Raw,serialization.PrivateFormat.Raw,
            serialization.NoEncryption())
        fd=os.open(destination,os.O_EXCL|os.O_CREAT|os.O_WRONLY|os.O_NOFOLLOW,0o600)
        try:
            need(os.write(fd,seed)==32,"SECRET_SEED_WRITE_INCOMPLETE")
            os.fsync(fd)
        finally:os.close(fd)
    control=_key(str(path/"authority.raw"))
    pub=control.public_key().public_bytes(serialization.Encoding.Raw,
                                         serialization.PublicFormat.Raw)
    staged=Path(public_stage)
    linux._no_links(str(staged))
    need(staged.parent.stat().st_uid==os.geteuid()
         and stat.S_IMODE(staged.parent.stat().st_mode)==0o755,
         "PUBLIC_STAGING_OWNER_REQUIRED")
    staged.write_bytes(pub)
    os.chmod(staged,0o644)
    return hashlib.sha256(pub).hexdigest()

def signature(key,claims):
    return base.sign(key,claims)

def _verify(key,signed,fields):
    if (type(signed) is not dict or set(signed)!={"claims","signature"}
        or type(signed["claims"]) is not dict or set(signed["claims"])!=fields):
        return None
    try:key.verify(base.unb64(signed["signature"]),canonical(signed["claims"]))
    except (InvalidSignature,ValueError,TypeError,base.Refused):
        return None
    return signed["claims"]

def issue(keydir,kid,alias):
    need(kid in KEYS and type(kid) is str and alias in TARGETS
         and type(alias) is str,"SOURCE_OWNED_PERMIT_ONLY")
    now=int(time.time())
    return signature(_key(str(Path(keydir)/(kid+".raw"))),{
        "kind":"permit","issuer":ISSUER,"audience":AUDIENCE,
        "kid":kid,"jti":JTIS[alias],"target":TARGETS[alias],
        "units":UNITS,"expected_revision":0,
        "not_before_unix":now-15,"expires_unix":now+600,
    })

def policy(keydir,phase):
    need(type(phase) is str and phase in ("old","rotated","short"),
         "EXACT_CONTROLLED_ROTATION_PHASE_ONLY")
    now=int(time.time())
    epoch={"old":1,"rotated":2,"short":3}[phase]
    pub={}
    for name in KEYS:
        key=_key(str(Path(keydir)/(name+".raw")))
        pub[name]=base.b64(key.public_key().public_bytes(
            serialization.Encoding.Raw,serialization.PublicFormat.Raw))
    statement={
        "kind":"key_policy","issuer":ISSUER,"audience":AUDIENCE,
        "epoch":epoch,"active_kid":"old" if phase=="old" else "new",
        "keys":pub,"revoked_kids":[] if phase=="old" else ["old"],
        "issued_unix":now,"expires_unix":now+(2 if phase=="short" else 90),
    }
    return signature(_key(str(Path(keydir)/"authority.raw")),statement)

def issuer_server(socket_path,keydir,agent_uid):
    need(type(agent_uid) is int and agent_uid>0
         and os.geteuid()>0 and agent_uid!=os.geteuid(),
         "ISSUER_SEPARATE_UNPRIVILEGED_UID")
    for name in ("old","new","authority"):
        _key(str(Path(keydir)/(name+".raw")))
    def handle(conn,peer):
        if peer["uid"]!=agent_uid:return False
        try:req=wire._read(conn)
        except wire.Refused:
            wire._send(conn,{"schema":SCHEMA,"ok":False,"code":"411_BAD_ISSUER_FRAME"})
            return False
        if type(req) is not dict or type(req.get("v")) is not int or req.get("v")!=1:
            wire._send(conn,{"schema":SCHEMA,"ok":False,"code":"411_ISSUER_PROTOCOL"})
            return False
        if req.get("op")=="policy" and set(req)=={"v","op","phase"}:
            if type(req["phase"]) is not str or req["phase"] not in ("old","rotated","short"):
                response={"schema":SCHEMA,"ok":False,"code":"411_ISSUER_UNKNOWN_POLICY_PHASE"}
            else:
                response={"schema":SCHEMA,"ok":True,"code":"411_SOURCE_SIGNED_KEY_POLICY",
                          "signed":policy(keydir,req["phase"])}
            wire._send(conn,response)
            return False
        if req.get("op")=="issue" and set(req)=={"v","op","kid","alias"}:
            if (type(req["kid"]) is not str or req["kid"] not in KEYS
                or type(req["alias"]) is not str or req["alias"] not in TARGETS):
                response={"schema":SCHEMA,"ok":False,"code":"411_ISSUER_OUTSIDE_FIXTURE_SCOPE"}
            else:
                response={"schema":SCHEMA,"ok":True,"code":"411_SOURCE_SIGNED_PERMIT",
                          "signed":issue(keydir,req["kid"],req["alias"])}
            wire._send(conn,response)
            return False
        if req.get("op")=="close" and set(req)=={"v","op"}:
            wire._send(conn,{"schema":SCHEMA,"ok":True,"code":"411_ISSUER_STOPPED"})
            return True
        wire._send(conn,{"schema":SCHEMA,"ok":False,"code":"411_ISSUER_METHOD_DENIED"})
        return False
    wire._listen(socket_path,handle)

def _root_public(path):
    return base._pinned_public(path)

def open_db(path):
    durable._strict_db_path(path)
    umask=os.umask(0o077)
    try:
        db=sqlite3.connect(path,isolation_level=None,timeout=8)
        db.execute("PRAGMA journal_mode=DELETE")
        db.execute("PRAGMA synchronous=FULL")
        db.execute("CREATE TABLE IF NOT EXISTS targets (name TEXT PRIMARY KEY, units INTEGER NOT NULL, revision INTEGER NOT NULL)")
        db.execute("CREATE TABLE IF NOT EXISTS policy (id INTEGER PRIMARY KEY CHECK(id=1),epoch INTEGER NOT NULL,active_kid TEXT NOT NULL,expires_unix INTEGER NOT NULL, signed_digest TEXT NOT NULL)")
        db.execute("CREATE TABLE IF NOT EXISTS keys (kid TEXT PRIMARY KEY, public_b64 TEXT NOT NULL, revoked INTEGER NOT NULL)")
        db.execute("CREATE TABLE IF NOT EXISTS consumed (jti TEXT PRIMARY KEY, receipt_sha256 TEXT NOT NULL)")
        for x in TARGETS.values():
            db.execute("INSERT OR IGNORE INTO targets VALUES (?,0,0)",(x,))
        db.commit()
    finally:os.umask(umask)
    durable._strict_db_path(path)
    return db

def _state(db):
    targets={n:{"units":u,"revision":r} for n,u,r in
             db.execute("SELECT name,units,revision FROM targets ORDER BY name")}
    current=db.execute("SELECT epoch,active_kid,expires_unix,signed_digest FROM policy WHERE id=1").fetchone()
    keys={name:{"revoked":bool(rev),"public_key_sha256":hash_obj(pub)} for name,pub,rev in
          db.execute("SELECT kid,public_b64,revoked FROM keys ORDER BY kid")}
    effects=[(j,r) for j,r in db.execute("SELECT jti,receipt_sha256 FROM consumed ORDER BY jti")]
    need(set(targets)==set(TARGETS.values())
         and all(t["units"] in (0,UNITS) and t["revision"] in (0,1)
                 for t in targets.values())
         and len(effects)<=2,"BACKEND_TARGET_LEDGER_INCONSISTENT")
    return {"targets":targets,
            "policy":None if current is None else
                {"epoch":current[0],"active_kid":current[1],
                 "expires_unix":current[2],"signed_digest":current[3]},
            "keys":keys,"effects":effects}

def status(db):
    state=_state(db)
    return {"schema":SCHEMA,"ok":True,"code":"411_SINK_STATUS",
            "backend_uid":os.geteuid(),
            "policy_epoch":state["policy"]["epoch"] if state["policy"] else 0,
            "active_kid":state["policy"]["active_kid"] if state["policy"] else None,
            "old_key_revoked":state["keys"].get("old",{}).get("revoked",False),
            "effect_count":len(state["effects"]),
            "targets":state["targets"],
            "state_sha256":hash_obj(state),
            "backend_policy_fresh":bool(state["policy"] and int(time.time())<state["policy"]["expires_unix"]),
            "mock_effect_only":True}

def install_policy(db,control_public,signed):
    claims=_verify(control_public,signed,POLICY_FIELDS)
    if claims is None:return {"schema":SCHEMA,"ok":False,"code":"411_UNTRUSTED_OR_INVALID_CONTROL_SIGNATURE"}
    now=int(time.time())
    if (claims["kind"]!="key_policy" or claims["issuer"]!=ISSUER
        or claims["audience"]!=AUDIENCE
        or type(claims["epoch"]) is not int or claims["epoch"] not in (1,2,3)
        or type(claims["issued_unix"]) is not int
        or type(claims["expires_unix"]) is not int
        or not (claims["issued_unix"]<=now<claims["expires_unix"])
        or claims["issued_unix"]<now-120 or claims["issued_unix"]>now+2
        or type(claims["keys"]) is not dict or set(claims["keys"])!=set(KEYS)
        or type(claims["revoked_kids"]) is not list
        or claims["active_kid"] not in KEYS):
        return {"schema":SCHEMA,"ok":False,"code":"411_INVALID_OR_EXPIRED_SIGNED_POLICY"}
    expected=(("old",[]) if claims["epoch"]==1 else ("new",["old"]))
    if claims["active_kid"]!=expected[0] or claims["revoked_kids"]!=expected[1]:
        return {"schema":SCHEMA,"ok":False,"code":"411_POLICY_KEY_REVOKE_INCONSISTENCY"}
    try:
        decoded={}
        for kid,value in claims["keys"].items():
            if type(value) is not str or len(value)>50 or not value or any(
                c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
                for c in value):
                return {"schema":SCHEMA,"ok":False,"code":"411_CONTROL_KEY_ENCODING_REFUSED"}
            decoded[kid]=base64.b64decode(
                (value+"="*((-len(value))%4)).encode("ascii"),
                altchars=b"-_",validate=True)
    except (binascii.Error,ValueError):
        return {"schema":SCHEMA,"ok":False,"code":"411_CONTROL_KEY_ENCODING_REFUSED"}
    # Public-key length is 32, unlike 64-byte Ed25519 signatures.
    if any(len(x)!=32 for x in decoded.values()):
        return {"schema":SCHEMA,"ok":False,"code":"411_PUBLIC_KEY_NOT_RAW32"}
    db.execute("BEGIN IMMEDIATE")
    try:
        old=db.execute("SELECT epoch FROM policy WHERE id=1").fetchone()
        if old and old[0]>=claims["epoch"]:
            db.rollback()
            return {"schema":SCHEMA,"ok":False,"code":"411_OLD_OR_REPLAYED_CONTROL_EPOCH"}
        # Accepted authorized policy epochs are monotone, no skipped staging.
        if claims["epoch"]!=(old[0]+1 if old else 1):
            db.rollback()
            return {"schema":SCHEMA,"ok":False,"code":"411_POLICY_EPOCH_GAP_DENIED"}
        db.execute("INSERT OR REPLACE INTO policy VALUES (1,?,?,?,?)",
                   (claims["epoch"],claims["active_kid"],claims["expires_unix"],hash_obj(signed)))
        for kid in KEYS:
            db.execute("INSERT OR REPLACE INTO keys VALUES (?,?,?)",
                       (kid,claims["keys"][kid],int(kid in claims["revoked_kids"])))
        result=status(db)
        db.commit()
    except BaseException:
        db.rollback();raise
    return {"schema":SCHEMA,"ok":True,"code":"411_SIGNED_POLICY_ACCEPTED",
            "state_sha256":result["state_sha256"],"epoch":claims["epoch"]}

def adjudicate(db,permit):
    p=db.execute("SELECT epoch,active_kid,expires_unix FROM policy WHERE id=1").fetchone()
    if p is None or int(time.time())>=p[2]:
        return "411_POLICY_STALE_FAIL_CLOSED",None
    if type(permit) is not dict or set(permit)!={"claims","signature"}:
        return "411_INVALID_SIGNED_PERMIT",None
    claims=permit["claims"]
    if type(claims) is not dict or set(claims)!=PERMIT_FIELDS:
        return "411_INVALID_SIGNED_PERMIT",None
    kid=claims.get("kid")
    if type(kid) is not str or kid not in KEYS:
        return "411_UNKNOWN_SIGNING_KEY",None
    row=db.execute("SELECT public_b64,revoked FROM keys WHERE kid=?",(kid,)).fetchone()
    if row is None:return "411_UNKNOWN_SIGNING_KEY",None
    if row[1] or kid!=p[1]:
        return "411_REVOKED_OR_RETIRED_SIGNING_KEY",None
    try:
        public_text=row[0]
        if (type(public_text) is not str or len(public_text)>50 or not public_text
            or any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
                   for c in public_text)):
            raise ValueError("invalid 411 signer public key encoding")
        public_raw=base64.b64decode(
            (public_text+"="*((-len(public_text))%4)).encode("ascii"),
            altchars=b"-_",validate=True)
        if len(public_raw)!=32:
            raise ValueError("Ed25519 public key must be exactly 32 bytes")
        pub=Ed25519PublicKey.from_public_bytes(public_raw)
    except (ValueError,binascii.Error,base.Refused):
        return "411_INVALID_PINNED_LEAF_KEY",None
    verified=_verify(pub,permit,PERMIT_FIELDS)
    if verified is None:
        return "411_LEAF_SIGNATURE_OR_CLAIMS_TAMPERED",None
    if (verified["kind"]!="permit" or verified["issuer"]!=ISSUER
        or verified["audience"]!=AUDIENCE
        or type(verified["units"]) is not int or verified["units"]!=UNITS
        or type(verified["expected_revision"]) is not int
        or verified["expected_revision"]!=0
        or type(verified["not_before_unix"]) is not int
        or type(verified["expires_unix"]) is not int
        or verified["jti"] not in JTIS.values()
        or verified["target"] not in TARGETS.values()
        or JTIS[next(k for k,v in TARGETS.items() if v==verified["target"])]!=verified["jti"]):
        return "411_LEAF_SCOPE_MISMATCH",None
    now=int(time.time())
    if not verified["not_before_unix"]<=now<verified["expires_unix"]:
        return "411_LEAF_EXPIRED_OR_NOT_YET_VALID",None
    if db.execute("SELECT 1 FROM consumed WHERE jti=?",(verified["jti"],)).fetchone():
        return "411_DURABLE_SINGLEUSE_REPLAY_DENIED",None
    state=db.execute("SELECT units,revision FROM targets WHERE name=?",(verified["target"],)).fetchone()
    if state is None or state[1]!=verified["expected_revision"]:
        return "411_LIVE_RESOURCE_REVISION_DRIFT",None
    return None,verified

def apply(db,permit):
    db.execute("BEGIN IMMEDIATE")
    try:
        reason,claims=adjudicate(db,permit)
        if reason:
            digest=status(db)["state_sha256"]
            db.rollback()
            return {"schema":SCHEMA,"ok":False,"code":reason,"state_sha256":digest}
        before=status(db)["state_sha256"]
        changed=db.execute("UPDATE targets SET units=units+?,revision=revision+1 WHERE name=? AND revision=0",
                           (UNITS,claims["target"]))
        need(changed.rowcount==1,"SINK_COMPARE_AND_SWAP_REQUIRED")
        receipt=hash_obj({"jti_sha256":hash_obj(claims["jti"]),
                          "target_sha256":hash_obj(claims["target"]),
                          "prestate_sha256":before,"units":UNITS})
        db.execute("INSERT INTO consumed VALUES (?,?)",(claims["jti"],receipt))
        after=status(db)
        db.commit()
        return {"schema":SCHEMA,"ok":True,"code":"411_SIGNATURE_VERIFIED_EFFECT_ONCE",
                "state_sha256":after["state_sha256"],"effect_count":after["effect_count"],
                "effect_receipt_sha256":receipt}
    except BaseException:
        db.rollback();raise

def sink_server(socket_path,gateway_uid,dbfile,control_public_path):
    need(type(gateway_uid) is int and gateway_uid>0
         and gateway_uid!=os.geteuid() and os.geteuid()>0,
         "GATEWAY_AND_SINK_MUST_BE_DISTINCT_NONROOT")
    public=_root_public(control_public_path)
    db=open_db(dbfile)
    def handler(conn,peer):
        if peer["uid"]!=gateway_uid:return False
        try:req=wire._read(conn)
        except wire.Refused:
            wire._send(conn,{"schema":SCHEMA,"ok":False,"code":"411_BAD_SINK_JSON"})
            return False
        if type(req) is not dict or type(req.get("v")) is not int or req["v"]!=1:
            wire._send(conn,{"schema":SCHEMA,"ok":False,"code":"411_BAD_SINK_ENVELOPE"})
            return False
        op=req.get("op")
        if op=="status" and set(req)=={"v","op"}:
            wire._send(conn,status(db));return False
        if op=="policy" and set(req)=={"v","op","signed"}:
            wire._send(conn,install_policy(db,public,req["signed"]));return False
        if op=="preview" and set(req)=={"v","op","permit"}:
            error,_=adjudicate(db,req["permit"])
            wire._send(conn,{"schema":SCHEMA,"ok":error is None,
                             "code":error or "411_SIGNED_LEAF_PREVIEW_OK"});return False
        if op=="apply" and set(req)=={"v","op","permit"}:
            wire._send(conn,apply(db,req["permit"]));return False
        if op=="close" and set(req)=={"v","op"}:
            wire._send(conn,{"schema":SCHEMA,"ok":True,"code":"411_SINK_CLOSED"})
            return True
        wire._send(conn,{"schema":SCHEMA,"ok":False,"code":"411_UNKNOWN_SINK_OPERATION"})
        return False
    try:wire._listen(socket_path,handler)
    finally:db.close()

def query(socket_path,message):
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as conn:
        conn.settimeout(12);conn.connect(str(socket_path))
        conn.sendall(wire._frame(message))
        reply=wire._read(conn)
    need(type(reply) is dict and reply.get("schema")==SCHEMA,"RESPONSE_SCHEMA_BOUNDARY")
    return reply

def actual_bind_commit(backend_socket,permit):
    from veritas_os.policy.bind_core import execute_bind_adjudication
    from veritas_os.policy.bind_core.core import ReferenceBindAdapter
    from veritas_os.policy.bind_artifacts import ExecutionIntent
    from veritas_os.security.hash import sha256_of_canonical_json
    before=query(backend_socket,{"v":1,"op":"status"})
    target=permit["claims"]["target"]
    first={"target":target,"entry":before["targets"][target],
           "ledger_sha256":before["state_sha256"]}
    attempts=[]
    class RotatedKeyAdapter(ReferenceBindAdapter):
        def snapshot(self):
            x=query(backend_socket,{"v":1,"op":"status"})
            return {"target":target,"entry":x["targets"][target],
                    "ledger_sha256":x["state_sha256"]}
        def validate_authority(self,intent,snapshot):
            return snapshot==first and intent.target_resource==target
        def validate_constraints(self,intent,snapshot):
            accepted=query(backend_socket,{"v":1,"op":"preview","permit":permit})
            return {"fresh_sink_verified_signed_issuer":accepted["ok"] is True,
                    "exact_target_and_state":snapshot==first}
        def apply(self,intent,snapshot):
            result=query(backend_socket,{"v":1,"op":"apply","permit":permit})
            attempts.append(result)
            return result["ok"] is True and result["code"]=="411_SIGNATURE_VERIFIED_EFFECT_ONCE"
        def verify_postconditions(self,intent,snapshot):
            x=query(backend_socket,{"v":1,"op":"status"})
            return (len(attempts)==1 and attempts[0]["ok"] is True
                    and x["state_sha256"]==attempts[0]["state_sha256"]
                    and x["targets"][target]["revision"]==1)
        def revert(self,intent,snapshot):return False
    intent=ExecutionIntent(
        decision_id="411-offline-signed-leaf-"+hash_obj(permit)[:16],
        request_id="411-offline-key-rotation-positive",
        policy_snapshot_id="411-synthetic-source-owned-key-lifecycle",
        actor_identity="411-crossuid-verified-permit",
        target_system="411-offline-synthetic-effect-sink",
        target_resource=target,
        intended_action="increment_exactly_seven",
        evidence_refs=["411-signed-leaf:"+hash_obj(permit)],
        decision_hash="4"*64,
        decision_ts="2026-10-01T00:00:00Z",
        ttl_seconds=300,
        expected_state_fingerprint=sha256_of_canonical_json(first),
        approval_context={"source_owned_test_permit":True,"real_human_approval":False},
        policy_lineage={"signed_permit_sha256":hash_obj(permit)})
    adapter=RotatedKeyAdapter(state=dict(first),pending_changes={},
                              target_description=target)
    receipt=execute_bind_adjudication(execution_intent=intent,adapter=adapter,
                                     bind_ts="2026-10-01T00:00:03Z",
                                     append_trustlog=False).to_dict()
    last=query(backend_socket,{"v":1,"op":"status"})
    need(receipt["final_outcome"]=="COMMITTED" and len(attempts)==1
         and attempts[0]["ok"] is True
         and attempts[0]["state_sha256"]==last["state_sha256"],
         "PINNED_REAL_BIND_COMMIT_NOT_RECONCILED")
    return {"code":"411_REAL_BIND_COMMITTED_FRESH_SIGNING_KEY",
            "bind_receipt_sha256":hash_obj(receipt),
            "effect_receipt_sha256":attempts[0]["effect_receipt_sha256"],
            "state_sha256":last["state_sha256"]}

def gate_server(socket_path,backend_socket,agent_uid,backend_uid):
    need(type(agent_uid) is int and type(backend_uid) is int
         and len({agent_uid,backend_uid,os.geteuid()})==3
         and min(agent_uid,backend_uid,os.geteuid())>0,
         "GATE_SEPARATE_LINUX_UIDS")
    env,original,runtime,journal=base.old.old.prior.build_worker_source()
    commits=[]
    def handle(conn,peer):
        if peer["uid"]!=agent_uid:return False
        try:req=wire._read(conn)
        except wire.Refused:
            wire._send(conn,{"schema":SCHEMA,"ok":False,"code":"411_BAD_GATE_JSON"})
            return False
        if type(req) is not dict or type(req.get("v")) is not int or req["v"]!=1:
            wire._send(conn,{"schema":SCHEMA,"ok":False,"code":"411_BAD_GATE_VERSION"})
            return False
        op=req.get("op")
        if op=="status" and set(req)=={"v","op"}:
            x=query(backend_socket,{"v":1,"op":"status"})
            need(env.model_dump(mode="json")==original and journal["native_protected_dispatches"]==0,
                 "NATIVE_TASK1_PROTECTION_CHANGED")
            x["genuine_bind_commits"]=len(commits)
            wire._send(conn,x);return False
        if op=="native_probe" and set(req)=={"v","op"}:
            _,error=runtime.run_function(env,"send_money",{
                "recipient":"OFFLINE","amount":1,"subject":"411-test",
                "date":"2022-03-05"})
            need(error=="VERITAS_402_DENIED:REAL_VERITAS_TASK1_BIND_BLOCKED"
                 and env.model_dump(mode="json")==original,
                 "NATIVE_TASK1_BIND_NO_MUTATION_FAILED")
            wire._send(conn,{"schema":SCHEMA,"ok":False,
                             "code":"411_NATIVE_REAL_BIND_DENY",
                             "bind_blocks":journal["bind_blocked"]});return False
        if op=="policy" and set(req)=={"v","op","signed"}:
            wire._send(conn,query(backend_socket,req));return False
        if op=="execute" and set(req)=={"v","op","permit"}:
            p=query(backend_socket,{"v":1,"op":"preview","permit":req["permit"]})
            if p["ok"] is not True:
                wire._send(conn,{"schema":SCHEMA,"ok":False,"code":p["code"]})
                return False
            result=actual_bind_commit(backend_socket,req["permit"])
            commits.append(result)
            wire._send(conn,{"schema":SCHEMA,"ok":True,**result})
            return False
        if op=="close" and set(req)=={"v","op"}:
            wire._send(conn,{"schema":SCHEMA,"ok":True,"code":"411_GATE_CLOSED"})
            return True
        wire._send(conn,{"schema":SCHEMA,"ok":False,"code":"411_UNKNOWN_GATE_OPERATION"})
        return False
    wire._listen(socket_path,handle)

def manifest(*,first,last,old_commit,new_commit,denied,native,epoch3,issuer_uid,
             gateway_uid,backend_uid,agent_uid,backend_restart_ok,issuer_was_down):
    need(len({issuer_uid,gateway_uid,backend_uid,agent_uid})==4
         and min(issuer_uid,gateway_uid,backend_uid,agent_uid)>0
         and first["effect_count"]==0 and last["effect_count"]==2
         and last["policy_epoch"]==3 and last["old_key_revoked"] is True
         and old_commit["code"]=="411_REAL_BIND_COMMITTED_FRESH_SIGNING_KEY"
         and new_commit["code"]=="411_REAL_BIND_COMMITTED_FRESH_SIGNING_KEY"
         and native["code"]=="411_NATIVE_REAL_BIND_DENY"
         and len(denied)>=6 and all(x["ok"] is False for x in denied)
         and epoch3["epoch"]==3 and backend_restart_ok and issuer_was_down,
         "OFFLINE_KEY_LIFECYCLE_FAILCLOSED_RECONCILIATION_MISSING")
    return {
        "schema":SCHEMA,
        "status":"OFFLINE_ROOT_SIGNED_KEY_ROTATION_REVOKE_STALE_FAILCLOSED",
        "separate_nonroot_issuer_gate_sink_agent":True,
        "three_issuer_only_private_keys_0700_0600":True,
        "root_pinned_control_public_key":True,
        "key_rotation_monotone_epoch_1_to_3":True,
        "old_leaf_key_retired_and_revoked":True,
        "old_valid_signature_refused_after_rotation":True,
        "tampered_policy_and_epoch_rollback_refused":True,
        "issuer_unavailable_and_policy_expired_fail_closed":True,
        "sink_enforces_local_policy_freshness":True,
        "backend_restart_preserves_epoch_and_effects":backend_restart_ok,
        "real_pinned_veritas_bind_committed_receipts":2,
        "synthetic_effects":2,
        "native_task1_write_still_blocked":True,
        "initial_state_sha256":first["state_sha256"],
        "final_state_sha256":last["state_sha256"],
        "old_bind_sha256":old_commit["bind_receipt_sha256"],
        "new_bind_sha256":new_commit["bind_receipt_sha256"],
        "agentdojo_pin":base.old.old.prior.native.NATIVE_PIN,
        "veritas_pin":base.old.old.prior.native.VERITAS_PIN,
        "real_human_authorization_verified":False,
        "production_key_management_HSM_proven":False,
        "remote_online_revocation_freshness_proven":False,
        "production_IAM_or_network_egress_proven":False,
        "global_nonbypassable_effect_execution_proven":False,
        "real_external_bank_effects":0,
        "paid_provider_calls":0,
        "official_native_scorer_calls":0,
    }

def main(argv):
    if len(argv)==4 and argv[1]=="--bootstrap":
        print(bootstrap(argv[2],argv[3]))
    elif len(argv)==5 and argv[1]=="--issuer":
        issuer_server(argv[2],argv[3],int(argv[4]))
    elif len(argv)==6 and argv[1]=="--backend":
        sink_server(argv[2],int(argv[3]),argv[4],argv[5])
    elif len(argv)==6 and argv[1]=="--gateway":
        gate_server(argv[2],argv[3],int(argv[4]),int(argv[5]))
    elif len(argv)==4 and argv[1]=="--client":
        print(json.dumps(query(argv[2],json.loads(argv[3])),sort_keys=True))
    else:
        raise SystemExit("411_ONLY_OFFLINE_BOUND_KEY_LIFECYCLE_TEST")
if __name__=="__main__":
    main(sys.argv)
