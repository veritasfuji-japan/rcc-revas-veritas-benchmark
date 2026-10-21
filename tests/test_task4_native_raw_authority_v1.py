import copy
import time
from pathlib import Path
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts import task4_native_raw_authority_v1 as p
from scripts import task4_native_os_custody_v1 as n


@pytest.fixture
def enrolled(monkeypatch,tmp_path):
    now=int(time.time())
    context=dict(schema=p.SCHEMA,run_id='a'*64,raw_recipient_sha256='b'*64,local_leaf_sha256='c'*64,
        not_before=now-5,expires_at=now+295,endpoint=p.ingress.raw.URL,permission='CLOSED_LOCAL_SCRIPTED_ONLY')
    monkeypatch.setattr(p,'enabled',lambda b:b==tmp_path)
    monkeypatch.setattr(p,'load',lambda b:copy.deepcopy(context))
    key=Ed25519PrivateKey.generate();public=key.public_key().public_bytes_raw()
    grants={}
    for (arm,i),request in n.scope().items():
        claim=n.statement(arm,i,request,tmp_path)
        grants[arm+str(i)]=dict(statement=claim,signature=key.sign(b'TASK4_NATIVE_OS_V1\0'+p.canonical(claim)).hex())
    return tmp_path,context,key,public,grants


def test_actual_signature_accepts_complete_bound_scope(enrolled):
    base,c,key,public,grants=enrolled
    n.verify_grant(grants['A0'],'A',0,n.scope()[('A',0)],public,base)
    assert grants['A0']['statement']['raw_authority']==c


@pytest.mark.parametrize('name',sorted(p.EXPECTED))
def test_signed_or_tampered_context_refused_with_exact_reason(enrolled,name):
    base,c,key,public,grants=enrolled
    g=p.issue_denials(key,grants['A0'])[name]
    with pytest.raises(ValueError,match='^'+p.EXPECTED[name]+'$'):
        n.verify_grant(g,'A',0,n.scope()[('A',0)],public,base)


@pytest.mark.parametrize('offset,accepted',[(0,True),(1,True),(299,True),(-1,False),(300,False),(301,False)])
def test_validity_is_half_open_and_uses_explicit_unit_clock(enrolled,offset,accepted):
    base,c,_,_,_=enrolled
    if accepted:assert p.admit(base,c,now=c['not_before']+offset)
    else:
        with pytest.raises(ValueError):p.admit(base,c,now=c['not_before']+offset)


@pytest.mark.parametrize('fault',['bool-start','bool-expiry','extra','missing','wide','zero','negative','nonhex','endpoint','permission'])
def test_authority_schema_is_exact(enrolled,fault):
    _,c,_,_,_=enrolled;c=copy.deepcopy(c)
    if fault=='bool-start':c['not_before']=True
    elif fault=='bool-expiry':c['expires_at']=True
    elif fault=='extra':c['extra']=1
    elif fault=='missing':del c['run_id']
    elif fault=='wide':c['expires_at']=c['not_before']+301
    elif fault=='zero':c['expires_at']=c['not_before']
    elif fault=='negative':c['expires_at']=c['not_before']-1
    elif fault=='nonhex':c['run_id']='z'*64
    elif fault=='endpoint':c['endpoint']='https://example.invalid/'
    else:c['permission']='LIVE'
    with pytest.raises(ValueError,match='RAW_AUTHORITY_SCHEMA'):p.shape(c)


@pytest.mark.parametrize('clock',[float('nan'),float('inf'),True])
def test_unusable_clock_fails_closed(enrolled,clock):
    base,c,_,_,_=enrolled
    with pytest.raises(ValueError,match='RAW_AUTHORITY_CLOCK'):p.admit(base,c,now=clock)


def validation_evidence(enrolled,monkeypatch):
    base,c,key,public,grants=enrolled;candidates=p.issue_denials(key,grants['A0'])
    # This unit fixture isolates signed-evidence validation. Actual Native/OS
    # integration remains mandatory in the dedicated workflow and its validator.
    monkeypatch.setattr(p.ingress,'validate',lambda e:True)
    names=sorted(p.EXPECTED)
    before=dict(rows={'effects':[],'consumed':[]},posts_sha256='1'*64,raw_events_sha256='2'*64,tls_events_sha256='3'*64)
    e=dict(context=c,issuer_public=public.hex(),grants=grants,candidates=candidates,
        before=before,after=copy.deepcopy(before),final_denials_count=15,
        probe=dict(results=[dict(name=x,grant_sha256=p.digest(candidates[x]),decision='DENIED_OR_UNKNOWN_NO_RETRY') for x in names],
            request_sha256=n.scope()[('A',0)],transport_invocations=1,sdk_responses_returned=0,native_terminal_arms=0,scorer_calls=0,
            enrollment_writes_denied=[p.FILE,'public/recipient.pub','public/native-raw-plan.json'],frozen_source_git_blobs=list(range(9))),
        denials=[dict(grant_sha256=p.digest(candidates[x]),uid=p.ingress.kernel.CUSTODY,reason=p.EXPECTED[x],observed_at=time.time()) for x in names],
        validations=[dict(op=op,uid=p.ingress.kernel.CUSTODY,grant_sha256=p.digest(g),observed_at=time.time(),phase='SIGNED_CONTEXT_VALID')
                     for op,g in grants.items() for _ in range(5)])
    normal=dict(schema='task4.native-raw-ingress.v1',raw_recipient_bound_in_signed_grant=True,
        evidence=dict(plan=dict(mode='success',run_id=c['run_id'],recipient_sha256=c['raw_recipient_sha256'],leaf_sha256=c['local_leaf_sha256']),
            replay_denials=16))
    return e,normal


def test_complete_signed_evidence_validates(enrolled,monkeypatch):
    assert p.validate(*validation_evidence(enrolled,monkeypatch))


@pytest.mark.parametrize('fault',['signature','run','consume','tls','post','missing-denial','reason','grant-join','sdk','writes','replay','not-bound','validation-clock','validation-grant'])
def test_false_green_signed_evidence_refused(enrolled,monkeypatch,fault):
    e,normal=validation_evidence(enrolled,monkeypatch)
    if fault=='signature':e['grants']['A0']['signature']='0'*128
    elif fault=='run':normal['evidence']['plan']['run_id']='0'*64
    elif fault=='consume':e['after']['rows']['consumed']=[['A0']]
    elif fault=='tls':e['after']['tls_events_sha256']='0'*64
    elif fault=='post':e['after']['posts_sha256']='0'*64
    elif fault=='missing-denial':e['denials'].pop()
    elif fault=='reason':e['denials'][0]['reason']='OTHER_REFUSAL'
    elif fault=='grant-join':e['denials'][0]['grant_sha256']='0'*64
    elif fault=='sdk':e['probe']['sdk_responses_returned']=1
    elif fault=='writes':e['probe']['enrollment_writes_denied'].pop()
    elif fault=='replay':normal['evidence']['replay_denials']=0
    elif fault=='not-bound':normal['raw_recipient_bound_in_signed_grant']=False
    elif fault=='validation-clock':e['validations'][0]['observed_at']=e['context']['expires_at']
    else:e['validations'][0]['grant_sha256']='0'*64
    from cryptography.exceptions import InvalidSignature
    with pytest.raises((ValueError,InvalidSignature)):p.validate(e,normal)


def test_absent_enrollment_leaves_existing_modes_unchanged(tmp_path):assert p.enabled(tmp_path) is False


def test_signed_fixture_requires_full_raw_success(tmp_path):
    with pytest.raises(ValueError,match='SIGNED_RAW_AUTHORITY_REQUIRES'):
        n.run(tmp_path/'output',raw_authority=True)
