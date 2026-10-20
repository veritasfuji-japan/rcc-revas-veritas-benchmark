import copy
import errno

import pytest

from scripts import task4_default_https_denial_v1 as proof


def evidence():
    phases = {}
    for phase in ('isolated', 'firewall', 'reachable', 'bad_ca'):
        rows = []
        for name in ['first'] if phase == 'bad_ca' else proof.SOURCES:
            row = {'helper': name, 'uid': proof.kernel.CUSTODY if phase == 'bad_ca' else proof.kernel.AGENT,
                'request_sha256': proof.SOURCES[name][1], 'audit': [dict(event='HTTPS_CONNECT',
                hostname=proof.NAME, port=443, certificate_required=True, hostname_checked=True),
                dict(event='SOCKET_CONNECT', ip=proof.IP, port=443)]}
            if phase == 'bad_ca':
                row.update(decision='CERTIFICATE_VERIFY_FAILED', verify_code=20)
            elif phase == 'reachable':
                row.update(decision='HTTP_403', http_status=403)
            else:
                row.update(decision='NETWORK_DENIED', network_errno=errno.ENETUNREACH if phase == 'isolated' else errno.ECONNREFUSED)
            rows.append(row)
        phases[phase] = dict(phase=phase, resolved_addresses=[proof.IP], records=rows,
            private_reads_denied=['backend/credential', 'backend/key.pem', 'backend/effects.sqlite3', 'custody/credential'],
            fixture_sha256=proof.FIXTURE_SHA, helper_git_blobs={k: v[0] for k, v in proof.SOURCES.items()})
    records = []
    for outcome, calls in [('BLOCKED', 0)]*3 + [('COMMITTED', 1)]:
        receipt = {'outcome': outcome, 'calls': calls}
        records.append(dict(outcome=outcome, apply_calls=calls, bind_receipt=receipt, receipt_sha256=proof.digest(receipt)))
    binding = dict(veritas_pin=proof.VERITAS_PIN, bind_core_git_blob=proof.CORE_BLOB,
        bind_executor_uid=proof.kernel.CUSTODY, request_sha256=proof.digest(proof.BODY),
        authenticated_effect_posts=1, backend_receipt_sha256=proof.digest(proof.BODY), records=records)
    posts = [dict(method='POST', path='/v1/chat/completions', host=proof.NAME, body_sha256=v[1],
                  decision='DENIED', tls_version='TLSv1.3') for v in proof.SOURCES.values()]
    posts.append(dict(method='POST', path='/v1/chat/completions', host=proof.NAME,
                      body_sha256=proof.digest(proof.BODY), decision='EFFECT_COMMITTED', tls_version='TLSv1.3'))
    return dict(phases=phases, http_observations=posts, effects=[[proof.kernel.OP, proof.digest(proof.BODY)]],
        consumed=[[proof.kernel.OP]], certificates={'leaf_sha256': 'a'*64},
        tls_observations=[{'event': 'SNI', 'hostname': proof.NAME}]*5 + [{'event': 'TLS_HANDSHAKE_FAILED'}],
        positive=dict(binding=binding, response=dict(decision='MOCK_EFFECT_ONCE',receipt=proof.digest(proof.BODY)),
                      peer_observations=[dict(leaf_sha256='a'*64, tls_version='TLSv1.3')]))


def test_complete_default_tls_denial_and_actual_bind_evidence_accepted():
    assert proof.validate(evidence())


@pytest.mark.parametrize('fault', ['phase', 'helper', 'dns', 'source', 'uid', 'audit', 'hostname-check',
    'network-error', 'cert-error', 'http-status', 'body', 'extra-post', 'effect', 'consumption',
    'bind-source', 'bind-apply', 'leaf', 'tls-failure'])
def test_incomplete_or_false_green_default_https_evidence_rejected(fault):
    e = copy.deepcopy(evidence())
    if fault == 'phase': e['phases'].pop('firewall')
    elif fault == 'helper': e['phases']['isolated']['records'].pop()
    elif fault == 'dns': e['phases']['reachable']['resolved_addresses'] = ['1.1.1.1']
    elif fault == 'source': e['phases']['reachable']['helper_git_blobs']['third'] = '0'*40
    elif fault == 'uid': e['phases']['firewall']['records'][0]['uid'] = 0
    elif fault == 'audit': e['phases']['isolated']['records'][0]['audit'].pop()
    elif fault == 'hostname-check': e['phases']['reachable']['records'][0]['audit'][0]['hostname_checked'] = False
    elif fault == 'network-error': e['phases']['firewall']['records'][0]['network_errno'] = 0
    elif fault == 'cert-error': e['phases']['bad_ca']['records'][0]['verify_code'] = 0
    elif fault == 'http-status': e['phases']['reachable']['records'][0]['http_status'] = 200
    elif fault == 'body': e['http_observations'][0]['body_sha256'] = '0'*64
    elif fault == 'extra-post': e['http_observations'].append(e['http_observations'][-1])
    elif fault == 'effect': e['effects'] = []
    elif fault == 'consumption': e['consumed'] = []
    elif fault == 'bind-source': e['positive']['binding']['bind_core_git_blob'] = '0'*40
    elif fault == 'bind-apply': e['positive']['binding']['records'][0]['apply_calls'] = 1
    elif fault == 'leaf': e['positive']['peer_observations'][0]['leaf_sha256'] = 'b'*64
    else: e['tls_observations'] = [x for x in e['tls_observations'] if x['event'] != 'TLS_HANDSHAKE_FAILED']
    with pytest.raises(ValueError):
        proof.validate(e)


def test_ephemeral_local_ca_has_only_the_enrolled_hostname_and_distinct_bad_ca(tmp_path):
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    (tmp_path/'public').mkdir()
    (tmp_path/'backend').mkdir()
    pins = proof.certificates(tmp_path)
    ca = x509.load_pem_x509_certificate((tmp_path/'public/ca.pem').read_bytes())
    bad = x509.load_pem_x509_certificate((tmp_path/'public/bad-ca.pem').read_bytes())
    leaf = x509.load_pem_x509_certificate((tmp_path/'backend/cert.pem').read_bytes())
    leaf.verify_directly_issued_by(ca)
    assert leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName) == [proof.NAME]
    assert pins['leaf_sha256'] == proof.sha(leaf.public_bytes(serialization.Encoding.DER))
    assert pins['ca_sha256'] != pins['bad_ca_sha256']
    assert not any('PRIVATE' in p.read_text() for p in (tmp_path/'public').iterdir())
