import copy
import os

import pytest

from scripts import task4_durable_issuer_restart_v1 as proof
from scripts import task4_native_os_custody_v1 as native


def base_folder(tmp_path):
    (tmp_path/'issuer').mkdir(mode=0o700)
    (tmp_path/'public').mkdir()
    return tmp_path


def test_durable_key_and_complete_issuance_ledger_reload_without_change(tmp_path):
    base=base_folder(tmp_path)
    value,raw=proof.initialize(base,owner=os.geteuid())
    assert proof.load(base,False,owner=os.geteuid())==(value,raw)
    assert len(value['grants'])==value['issued_count']==8
    assert proof.anchor(value,raw)['state_sha256']==proof.sha(raw)
    assert (base/proof.STATE).stat().st_mode & 0o777==0o600
    assert b'private_key' not in proof.canonical(proof.exported(value,raw))


@pytest.mark.parametrize('fault',['schema','epoch','private','public','scope','recipient','count','missing-grant',
    'signature','target','wire','extra'])
def test_corrupted_or_widened_persisted_state_refused(fault):
    value=proof.state_value()
    if fault=='schema':value['schema']='other'
    elif fault=='epoch':value['epoch']='not-an-epoch'
    elif fault=='private':value['private_key']='0'*64
    elif fault=='public':value['public']='0'*64
    elif fault=='scope':value['scope_sha256']='0'*64
    elif fault=='recipient':value['recipient_sha256']='0'*64
    elif fault=='count':value['issued_count']=9
    elif fault=='missing-grant':value['grants'].pop('A0')
    elif fault=='signature':value['grants']['A0']['signature']='0'*128
    elif fault=='target':value['grants']['A0']['statement']['target']='https://foreign.invalid/'
    elif fault=='wire':value['grants']['A0']['statement']['request_sha256']='0'*64
    else:value['fresh_grants_allowed']=True
    with pytest.raises(ValueError):proof.validate_state(value)


@pytest.mark.parametrize('fault',['missing','truncated','symlink','hardlink','permissions','noncanonical'])
def test_bad_disk_state_never_repaired_or_recreated(tmp_path,fault):
    base=base_folder(tmp_path);_,raw=proof.initialize(base,owner=os.geteuid());file=base/proof.STATE
    if fault=='missing':file.unlink()
    elif fault=='truncated':file.write_bytes(raw[:31])
    elif fault=='symlink':
        retained=base/'issuer/retained';file.rename(retained);file.symlink_to(retained)
    elif fault=='hardlink':os.link(file,base/'issuer/duplicate')
    elif fault=='permissions':file.chmod(0o644)
    else:file.write_bytes(raw+b'\n')
    before=file.read_bytes() if file.exists() else None
    with pytest.raises((ValueError,OSError)):proof.load(base,False,owner=os.geteuid())
    assert (file.read_bytes() if file.exists() else None)==before


def test_initialization_never_replaces_issued_state_or_bypasses_anchor(tmp_path):
    base=base_folder(tmp_path);_,raw=proof.initialize(base,owner=os.geteuid())
    with pytest.raises(ValueError,match='NO_ISSUER_STATE_REPLACEMENT'):proof.initialize(base,owner=os.geteuid())
    assert (base/proof.STATE).read_bytes()==raw
    (base/proof.ANCHOR).write_text('{}');(base/proof.STATE).unlink()
    with pytest.raises(ValueError,match='NO_ISSUER_REINITIALIZATION_AFTER_ENROLLMENT'):proof.initialize(base,owner=os.geteuid())
    assert not (base/proof.STATE).exists()


def test_valid_replacement_key_and_issuance_ledger_change_enrolled_anchor():
    first=proof.state_value();other=proof.state_value()
    assert proof.validate_state(other)==other
    assert proof.anchor(first,proof.canonical(first))!=proof.anchor(other,proof.canonical(other))
    assert first['public']!=other['public']


def evidence():
    identity=dict(pid=1,uid=proof.kernel.ISSUER,issued_count=8,state_sha256='s'*64,grants_sha256='g'*64,
        epoch='e'*64,public='11'*32,issuer_credential_reads_denied=True)
    records=[];effects=[];consumed=[]
    for (arm,i),request_sha in native.scope().items():
        r=dict(arm=arm,ordinal=i,request_sha256=request_sha,response_sha256=proof.digest({'response':arm+str(i)}),
            backend_receipt_sha256='b'*64,envelope_sha256='c'*64,bind_sha256='d'*64)
        records.append(r);op=arm+str(i)
        effects.append([op,request_sha,r['response_sha256'],r['backend_receipt_sha256']])
        consumed.append([op,'MOCK_OBSERVED',request_sha,r['response_sha256'],r['backend_receipt_sha256'],r['envelope_sha256'],r['bind_sha256']])
    normal=dict(native=dict(records=records,scorer_calls=2,replay_denials=8),restart=dict(restart_replay_denials=8),
        mock_http_effects=8,custody_consumptions=8,issuer_public_key_sha256=proof.sha(bytes.fromhex(identity['public'])))
    tls_e=dict(peers=[{'fixture':'peer'}],posts=[{'fixture':'post'}])
    tls_report=dict(normal_report_sha256=proof.digest(normal),evidence=tls_e,evidence_sha256=proof.digest(tls_e),
        checks={str(i):True for i in range(16)})
    snapshot=dict(rows=dict(effects=effects,consumed=consumed),state_sha256=identity['state_sha256'],
        custody_database_sha256='c'*64,backend_database_sha256='b'*64,issuer_anchor_sha256=proof.digest(dict(
            schema='task4.durable-issuer-anchor.v1',state_sha256=identity['state_sha256'],
            public_sha256=normal['issuer_public_key_sha256'],grants_sha256=identity['grants_sha256'],epoch=identity['epoch'],issued_count=8)),
        tls_peers_sha256=proof.digest(tls_e['peers']),backend_posts_sha256=proof.digest(tls_e['posts']))
    replay=dict(reexported_grant_replay_denials=8,grants_sha256=identity['grants_sha256'])
    e=dict(initial=identity,restarted=dict(identity,pid=2),final=dict(identity,pid=3),issuer_sigkill_exit=-9,
        reissue=dict(decision='DENIED_ALREADY_ISSUED',new_grants=0,issued_count=8),before=snapshot,
        after_issuer_restart=copy.deepcopy(snapshot),after_all=copy.deepcopy(snapshot),
        replay_before_custody_restart=replay,replay_after_custody_restart=copy.deepcopy(replay),
        faults=[dict(fault=f,decision='ISSUER_RESTART_DENIED',uid=proof.kernel.ISSUER,pid=i+4,ready=False,socket=False,
            state_unchanged=True,regenerated=False) for i,f in enumerate(['missing','truncated','replacement-key'])],
        restoration_by_trusted_root_only=True)
    return e,normal,tls_report


def test_complete_restart_and_no_extra_send_evidence_accepted():assert proof.validate(*evidence())


@pytest.mark.parametrize('fault',['pid','kill','key','issuance','database','extra-effect','receipt','replay','missing-fault',
    'regeneration','socket','tls-call','tls-post','normal-join','tls-check'])
def test_incomplete_restart_or_extra_execution_evidence_refused(fault):
    e,n,t=copy.deepcopy(evidence())
    if fault=='pid':e['restarted']['pid']=e['initial']['pid']
    elif fault=='kill':e['issuer_sigkill_exit']=0
    elif fault=='key':e['restarted']['public']='other'
    elif fault=='issuance':e['reissue']['new_grants']=8
    elif fault=='database':e['after_all']['custody_database_sha256']='0'*64
    elif fault=='extra-effect':e['before']['rows']['effects'].append(e['before']['rows']['effects'][0])
    elif fault=='receipt':n['native']['records'][0]['backend_receipt_sha256']='0'*64
    elif fault=='replay':e['replay_after_custody_restart']['reexported_grant_replay_denials']=0
    elif fault=='missing-fault':e['faults'].pop()
    elif fault=='regeneration':e['faults'][0]['regenerated']=True
    elif fault=='socket':e['faults'][0]['socket']=True
    elif fault=='tls-call':t['evidence']['peers'].append({'extra':'peer'});t['evidence_sha256']=proof.digest(t['evidence'])
    elif fault=='tls-post':t['evidence']['posts'].append({'extra':'post'});t['evidence_sha256']=proof.digest(t['evidence'])
    elif fault=='normal-join':t['normal_report_sha256']='0'*64
    else:t['checks']['0']=False
    with pytest.raises(ValueError):proof.validate(e,n,t)


def test_durable_issuer_requires_existing_closed_tls_fixture(tmp_path):
    with pytest.raises(ValueError,match='DURABLE_ISSUER_REQUIRES_LOCAL_TLS'):
        native.run(tmp_path,durable_issuer=True)
