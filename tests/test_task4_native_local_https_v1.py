import copy
import errno

import pytest

from scripts import task4_native_local_https_v1 as proof
from scripts import task4_native_os_custody_v1 as native


def fixture():
    phases = {}
    for phase in ('isolated', 'firewall', 'bad_ca', 'reachable'):
        rows = []
        for name in ['first'] if phase == 'bad_ca' else proof.tls.SOURCES:
            r = dict(helper=name, uid=proof.kernel.CUSTODY if phase=='bad_ca' else proof.kernel.AGENT,
                request_sha256=proof.tls.SOURCES[name][1], audit=[dict(event='HTTPS_CONNECT',hostname=proof.NAME,
                    port=443,certificate_required=True,hostname_checked=True),dict(event='SOCKET_CONNECT',ip=proof.IP,port=443)])
            if phase=='bad_ca': r.update(decision='CERTIFICATE_VERIFY_FAILED',verify_code=20)
            elif phase=='reachable': r.update(decision='HTTP_403',http_status=403)
            else: r.update(decision='NETWORK_DENIED',network_errno=errno.ENETUNREACH if phase=='isolated' else errno.ECONNREFUSED)
            rows.append(r)
        phases[phase] = dict(phase=phase, resolved_addresses=[proof.IP], records=rows,
            fixture_sha256=proof.tls.FIXTURE_SHA,helper_git_blobs={k:v[0] for k,v in proof.tls.SOURCES.items()},
            private_reads_denied=['backend/credential','backend/key.pem','backend/effects.sqlite3','custody/credential'])
    posts = [dict(method='POST',path='/v1/chat/completions',host=proof.NAME,body_sha256=v[1],decision='DENIED',
        record=None,tls_version='TLSv1.3',response_sha256=proof.digest({'decision':'DENIED'})) for v in proof.tls.SOURCES.values()]
    posts.append(dict(posts[0],path='/effect',body_sha256=proof.digest({})))
    records, bindings, lines, peers, packets = [], [], [], [], {}
    for (arm, ordinal), request_sha in native.scope().items():
        op = arm+str(ordinal)
        receipt = {'fixture': op}
        binding = dict(operation_id=op,bind_core_git_blob='0f64201e2599495ce4e3991348aa320995716ffc',records=[
            dict(outcome=x,apply_calls=c,receipt=receipt,receipt_sha256=proof.digest(receipt)) for x,c in [('BLOCKED',0),('COMMITTED',1)]])
        bindings.append(binding)
        r = dict(arm=arm,ordinal=ordinal,request_sha256=request_sha,response_sha256=proof.digest({'response':op}),
            bind_sha256=proof.digest({k:v for k,v in binding.items() if k!='operation_id'}))
        records.append(r)
        lines.append(dict(arm=arm,ordinal=ordinal,original_request_raw_sha256=request_sha,original_response_raw_sha256=r['response_sha256']))
        packets[op] = proof.digest({'packet':op})
        peer = dict(leaf_sha256='a'*64,tls_version='TLSv1.3',peer_ip=proof.IP,hostname=proof.NAME,port=443,
            certificate_required=True,hostname_checked=True,status=200,method='POST',path='/effect',
            body_sha256=packets[op],response_sha256=proof.digest({'wrapper':op}))
        peers.append(peer)
        posts.append(dict(method='POST',path='/effect',host=proof.NAME,body_sha256=packets[op],decision='EFFECT_COMMITTED',
            tls_version='TLSv1.3',record=dict(operation_id=op,request_sha256=request_sha,response_sha256=r['response_sha256']),
            response_sha256=peer['response_sha256']))
    lineage = dict(response_receipts=lines)
    normal = dict(schema='task4.native.os-custody.v1',checks={str(i):True for i in range(22)},
        mock_http_effects=8,custody_consumptions=8,bind_records_sha256=proof.digest(bindings),restart=dict(restart_replay_denials=8),
        native=dict(records=records,lineage=lineage,lineage_sha256=proof.digest(lineage),scorer_calls=2,scripted_native_arms=2,replay_denials=8))
    network = {name:dict(links=['lo'] if name=='isolated' else ['lo','veth'],routes=[] if name=='isolated' else
        [{'dst':'10.249.94.0/30'}],routes6=[]) for name in ('client','sink','isolated')}
    e = dict(phases=phases,posts=posts,peers=peers,packet_sha256=packets,certificates=dict(leaf_sha256='a'*64),
        negative_effects=0,negative_consumptions=0,topology=network,
        tls_events=[dict(event='SNI',hostname=proof.NAME)]*(5+len(peers))+[dict(event='TLS_HANDSHAKE_FAILED')])
    return e, normal, bindings


def test_complete_native_tls_evidence_accepted():
    assert proof.validate(*fixture())


@pytest.mark.parametrize('fault', ['normal-check','effect-count','scorer','replay','negative-effect','phase','source','dns',
    'helper-audit','network-error','ca-error','private-read','negative-body','extra-post','positive-body','response-wrapper',
    'inner-response','packet','bind','lineage','leaf','hostname-check','tls-failure','external-route'])
def test_incomplete_or_substituted_native_tls_evidence_refused(fault):
    e,n,b = copy.deepcopy(fixture())
    if fault=='normal-check': n['checks']['0']=False
    elif fault=='effect-count': n['mock_http_effects']=7
    elif fault=='scorer': n['native']['scorer_calls']=0
    elif fault=='replay': n['restart']['restart_replay_denials']=0
    elif fault=='negative-effect': e['negative_effects']=1
    elif fault=='phase': e['phases'].pop('firewall')
    elif fault=='source': e['phases']['reachable']['helper_git_blobs']['first']='0'*40
    elif fault=='dns': e['phases']['isolated']['resolved_addresses']=['1.1.1.1']
    elif fault=='helper-audit': e['phases']['isolated']['records'][0]['audit']=[]
    elif fault=='network-error': e['phases']['firewall']['records'][0]['network_errno']=0
    elif fault=='ca-error': e['phases']['bad_ca']['records'][0]['verify_code']=0
    elif fault=='private-read': e['phases']['reachable']['private_reads_denied']=[]
    elif fault=='negative-body': e['posts'][0]['body_sha256']='0'*64
    elif fault=='extra-post': e['posts'].append(e['posts'][-1])
    elif fault=='positive-body': e['posts'][4]['body_sha256']='0'*64
    elif fault=='response-wrapper': e['posts'][4]['response_sha256']='0'*64
    elif fault=='inner-response': e['posts'][4]['record']['response_sha256']='0'*64
    elif fault=='packet': e['packet_sha256']['A0']='0'*64
    elif fault=='bind': b[0]['records'][0]['apply_calls']=1
    elif fault=='lineage':
        n['native']['lineage']['response_receipts'][0]['original_response_raw_sha256']='0'*64
        n['native']['lineage_sha256']=proof.digest(n['native']['lineage'])
    elif fault=='leaf': e['peers'][0]['leaf_sha256']='b'*64
    elif fault=='hostname-check': e['peers'][0]['hostname_checked']=False
    elif fault=='tls-failure': e['tls_events']=[x for x in e['tls_events'] if x['event']!='TLS_HANDSHAKE_FAILED']
    else: e['topology']['client']['routes'].append({'dst':'default','gateway':'1.1.1.1'})
    with pytest.raises(ValueError):
        proof.validate(e,n,b)


@pytest.mark.parametrize('fault',['writable','content','symlink'])
def test_non_enrolled_tls_marker_refused(tmp_path,fault):
    folder=tmp_path/'public';folder.mkdir()
    file=folder/'local-https'
    if fault=='symlink':
        target=tmp_path/'other';target.write_text(proof.MARKER);target.chmod(0o444);file.symlink_to(target)
    else:
        file.write_text('other' if fault=='content' else proof.MARKER)
        file.chmod(0o600 if fault=='writable' else 0o444)
    with pytest.raises(ValueError,match='ROOT_ENROLLED_LOCAL_TLS_ONLY'):
        proof.enabled(tmp_path)


def test_tls_cannot_silently_replace_fault_fixture(tmp_path):
    with pytest.raises(ValueError,match='LOCAL_HTTPS_NORMAL_FIXTURE_ONLY'):
        native.run(tmp_path, fault='after-consume',local_https=True)
