import base64
import copy
import io
import json
import socket
import ssl
import threading
import traceback
from types import SimpleNamespace

import pytest

from scripts import task4_signed_github_api_v1 as wire
from scripts import task4_signed_github_ledger_v1 as signed
from scripts import task4_signed_github_ledger_rehearsal_v1 as model
from scripts import task4_receipt_key_custody_v1 as custody
from scripts import task4_retained_signed_ledger_service_v1 as retained
from scripts.task4_external_ledger_contract_v1 import Denied, LedgerClient, canonical, sha

TOKEN = 'ghp_SYNTHETIC_TEST_TOKEN_NOT_A_CREDENTIAL'
PIN, ROOT = 'a'*64, 'b'*40
READ = wire.PREFIX + 'git/commits/' + ROOT


class Response:
    def __init__(self, data=b'{}', status=200, headers=None):
        self.data, self.status = io.BytesIO(data), status
        self.headers = headers if headers is not None else [('Content-Type', 'application/json')]
        self.closed = False

    def getheaders(self): return self.headers
    def read1(self, size): return self.data.read(size)
    def close(self): self.closed = True


@pytest.fixture
def network(monkeypatch):
    class Socket:
        def settimeout(self, timeout):
            assert 0 < timeout <= wire.TIMEOUT

    class Connection:
        def __init__(self, host, port, timeout, context):
            assert host == 'api.github.com' and port == 443 and timeout == wire.TIMEOUT
            assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname
            assert context.minimum_version >= ssl.TLSVersion.TLSv1_2
            self.sock, self.closed = Socket(), False
            net['connections'].append(self)

        def request(self, method, path, body=None, headers=None):
            net['requests'].append((method, path, body, headers))
            if net['request_fault']: raise net['request_fault']

        def getresponse(self):
            if net['responder']:
                return net['responder'](*net['requests'][-1])
            if net['response_fault']: raise net['response_fault']
            return net['response']

        def close(self): self.closed = True

    net = dict(connections=[], requests=[], response=Response(), request_fault=None,
               response_fault=None, responder=None)
    monkeypatch.setattr(wire.http.client, 'HTTPSConnection', Connection)
    for name in ('HTTPS_PROXY', 'HTTP_PROXY', 'ALL_PROXY', 'GITHUB_API_URL', 'GITHUB_TOKEN', 'GH_TOKEN'):
        monkeypatch.setenv(name, 'https://untrusted.invalid/DO_NOT_USE')
    return net


def payload():
    data = canonical(signed.empty(PIN))
    return dict(query=signed.MUTATION_QUERY, variables=dict(input=dict(
        branch=dict(repositoryNameWithOwner=signed.REPO, branchName=signed.BRANCH),
        expectedHeadOid=ROOT, clientMutationId='c'*64,
        message=dict(headline='Task4 synthetic signed-ledger transition ' + 'c'*64),
        fileChanges=dict(additions=[dict(path=signed.FILE, contents=base64.b64encode(data).decode())]))))


def test_constructs_without_connecting_or_ambient_credentials(network):
    backend = wire.approved_backend(TOKEN, ROOT, PIN)
    assert backend.genesis == ROOT and backend.signer == PIN
    assert not network['requests'] and not network['connections']
    assert TOKEN not in repr(backend.api)


@pytest.mark.parametrize('route', ['git/commits/' + ROOT, 'git/trees/' + ROOT, 'git/blobs/' + ROOT,
    'git/ref/heads/' + signed.BRANCH, 'compare/' + ROOT + '...' + 'c'*40])
def test_exact_reads_use_verified_fixed_host_and_explicit_headers(network, route):
    assert wire.API(TOKEN, ROOT, PIN).call('GET', wire.PREFIX + route) == {}
    method, path, body, headers = network['requests'][0]
    assert method == 'GET' and path == wire.PREFIX + route and body is None
    assert headers['Authorization'] == 'Bearer ' + TOKEN
    assert headers['X-GitHub-Api-Version'] == '2022-11-28'
    assert headers['Accept-Encoding'] == 'identity'
    assert network['connections'][0].closed and network['response'].closed


def test_exact_fixed_cas_mutation_has_one_request(network):
    data = payload()
    wire.API(TOKEN, ROOT, PIN).call('POST', '/graphql', data)
    assert len(network['requests']) == 1
    assert network['requests'][0][2] == canonical(data)


@pytest.mark.parametrize('token', [None, '', 'short', 'x'*256, 'x'*20+'\n', 'x'*20+' ', 'é'*20])
def test_invalid_or_missing_token_never_connects(network, token):
    with pytest.raises(Denied, match='^SIGNED_GITHUB_API_STOP$'):
        wire.API(token, ROOT, PIN)
    assert not network['connections']


@pytest.mark.parametrize('method,path', [
    ('GET', 'https://evil.invalid/'), ('GET', '//evil.invalid/'),
    ('GET', wire.PREFIX+'git/ref/heads/main'),
    ('GET', wire.PREFIX+'git/ref/heads/research/task4-retained-ledger-v1'),
    ('GET', READ+'?x=1'), ('GET', READ+'#fragment'),
    ('GET', wire.PREFIX+'git/blobs/'+'A'*40),
    ('GET', wire.PREFIX+'git/blobs/../commits/'+ROOT),
    ('GET', wire.PREFIX+'git/blobs/%2e%2e'),
    ('GET', wire.PREFIX+'compare/'+'c'*40+'...'+ROOT),
    ('GET', '/repos/other/repository/git/blobs/'+ROOT),
    ('POST', wire.PREFIX+'git/refs'), ('PATCH', READ), ('DELETE', READ), ('GET', '/graphql'),
])
def test_other_routes_and_methods_stop_before_token_use(network, method, path):
    with pytest.raises(Denied): wire.API(TOKEN, ROOT, PIN).call(method, path)
    assert not network['connections']


@pytest.mark.parametrize('fault', ['query', 'extra_operation', 'extra_variables', 'extra_input', 'repo',
    'branch', 'branch_id', 'head', 'nonce', 'message', 'deletions', 'two_files', 'file',
    'base64', 'noncanonical', 'signer', 'oversize', 'extra_state'])
def test_other_payloads_stop_before_any_request(network, fault):
    value = payload(); v = value['variables']['input']; row = v['fileChanges']['additions'][0]
    if fault == 'query': value['query'] = 'mutation { deleteRef(input:{refId:"x"}) {clientMutationId} }'
    if fault == 'extra_operation': value['query'] += '\nquery { viewer { login } }'
    if fault == 'extra_variables': value['variables']['other'] = True
    if fault == 'extra_input': v['force'] = True
    if fault == 'repo': v['branch']['repositoryNameWithOwner'] = 'other/repo'
    if fault == 'branch': v['branch']['branchName'] = 'main'
    if fault == 'branch_id': v['branch']['id'] = 'x'
    if fault == 'head': v['expectedHeadOid'] = 'main'
    if fault == 'nonce': v['clientMutationId'] = None
    if fault == 'message': v['message']['headline'] = 'arbitrary text'
    if fault == 'deletions': v['fileChanges']['deletions'] = []
    if fault == 'two_files': v['fileChanges']['additions'].append(copy.deepcopy(row))
    if fault == 'file': row['path'] = '.github/workflows/evil.yml'
    if fault == 'base64': row['contents'] = '!!'
    if fault == 'noncanonical': row['contents'] = base64.b64encode(json.dumps(signed.empty(PIN)).encode()).decode()
    if fault == 'signer': row['contents'] = base64.b64encode(canonical(signed.empty('d'*64))).decode()
    if fault == 'oversize': row['contents'] = 'A'*(4*((signed.MAX_BLOB+2)//3)+1)
    if fault == 'extra_state':
        state = dict(signed.empty(PIN), extra='not allowed')
        row['contents'] = base64.b64encode(canonical(state)).decode()
    with pytest.raises(Denied): wire.API(TOKEN, ROOT, PIN).call('POST', '/graphql', value)
    assert not network['connections']


@pytest.mark.parametrize('status', [201, 301, 302, 307, 308, 401, 403, 404, 409, 429, 500, 503])
def test_error_status_never_follows_retries_or_exposes_server_text(network, status, capsys):
    network['response'] = Response(TOKEN.encode(), status,
        [('Location', 'https://evil.invalid/'+TOKEN), ('Content-Type', 'application/json')])
    with pytest.raises(Denied) as error: wire.API(TOKEN, ROOT, PIN).call('GET', READ)
    assert str(error.value) == wire.STOP and error.value.__suppress_context__
    assert TOKEN not in ''.join(traceback.format_exception(error.value))
    assert len(network['requests']) == 1 and network['response'].data.tell() == 0
    assert network['response'].closed and network['connections'][0].closed
    assert capsys.readouterr() == ('', '')


@pytest.mark.parametrize('fault', ['duplicate', 'nonfinite', 'invalid_json', 'array', 'graphql_error',
    'large_body', 'large_length', 'duplicate_length', 'short_length', 'html', 'gzip', 'ambiguous_framing'])
def test_bad_responses_are_bounded_and_sanitized(network, fault):
    data = b'{}'; headers = [('Content-Type', 'application/json')]
    if fault == 'duplicate': data = b'{"x":1,"x":2}'
    if fault == 'nonfinite': data = b'{"x":NaN}'
    if fault == 'invalid_json': data = b'not json'
    if fault == 'array': data = b'[]'
    if fault == 'graphql_error': data = canonical(dict(errors=[dict(message=TOKEN)]))
    if fault == 'large_body': data = b' '*(wire.MAX_RESPONSE+1)
    if fault == 'large_length': headers += [('Content-Length', str(wire.MAX_RESPONSE+1))]
    if fault == 'duplicate_length': headers += [('Content-Length', '2'), ('content-length', '2')]
    if fault == 'short_length': headers += [('Content-Length', '3')]
    if fault == 'html': headers = [('Content-Type', 'text/html')]
    if fault == 'gzip': headers += [('Content-Encoding', 'gzip')]
    if fault == 'ambiguous_framing': headers += [('Content-Length', '2'), ('Transfer-Encoding', 'chunked')]
    network['response'] = Response(data, headers=headers)
    with pytest.raises(Denied, match='^SIGNED_GITHUB_API_STOP$'):
        wire.API(TOKEN, ROOT, PIN).call('GET', READ)
    assert len(network['requests']) == 1
    assert network['response'].data.tell() <= wire.MAX_RESPONSE+1
    assert network['response'].closed and network['connections'][0].closed


@pytest.mark.parametrize('stage', ['request', 'response', 'read', 'tls', 'deadline'])
def test_transport_failures_never_retry_or_leak(network, monkeypatch, stage, capsys):
    if stage in ('request', 'response'): network[stage+'_fault'] = TimeoutError(TOKEN)
    if stage == 'read':
        def broken(size): raise OSError(TOKEN)
        network['response'].read1 = broken
    if stage == 'tls':
        def broken(): raise ssl.SSLError(TOKEN)
        monkeypatch.setattr(wire.ssl, 'create_default_context', broken)
    if stage == 'deadline':
        clock = iter((0, wire.TIMEOUT+1))
        monkeypatch.setattr(wire.time, 'monotonic', lambda: next(clock))
    with pytest.raises(Denied, match='^SIGNED_GITHUB_API_STOP$'):
        wire.API(TOKEN, ROOT, PIN).call('GET', READ)
    assert len(network['requests']) <= 1
    assert capsys.readouterr() == ('', '')


def test_retained_service_uses_transport_and_denies_committed_timeout_without_retry(network, tmp_path):
    parent = tmp_path / 'authority'; parent.mkdir(mode=0o700)
    slot = parent / 'receipt-custody'; identity = custody.initialize(slot)
    pin = identity['public_key_sha256']; api_model = model.ModelGitAPI(pin)
    backend = wire.approved_backend(TOKEN, api_model.genesis, pin)
    def responder(method, path, body, headers):
        reply = api_model.call(method, path, json.loads(body) if body else None)
        return Response(canonical(reply))
    network['responder'] = responder
    service = retained.reopen_service(backend, slot, pin)
    witness = model.WitnessKey(service.key, api_model); service.key = witness
    b = dict(schema=signed.SCHEMA, ledger_id=signed.LEDGER_ID, run_id='a'*64,
             manifest_sha256='d'*64, issuer_public_sha256='b'*64, custody_public_sha256='c'*64)
    service.enroll(b)
    def client(role):
        return LedgerClient(b, bytes.fromhex(identity['public_key_hex']),
            lambda data: service.exchange(data, b[role+'_public_sha256']))
    effects = []
    client('issuer').gate('reserve', 'A0', sha(b'request'), lambda _: effects.append('issue'))
    client('custody').gate('consume', 'A0', sha(b'request'), lambda _: effects.append('send'), sha(b'grant'))
    client('issuer').gate('reserve', 'B0', sha(b'request'), lambda _: None)
    before = len(witness.signatures)
    posts = sum(m == 'POST' for m, _, _, _ in network['requests'])
    def lost(reply): raise TimeoutError(TOKEN)  # API model committed, response unavailable.
    api_model.response_fault = lost
    with pytest.raises(Denied):
        client('custody').gate('consume', 'B0', sha(b'request'), lambda _: effects.append('unexpected'), sha(b'grant'))
    assert len(witness.signatures) == before+1  # View only; no mutation signature.
    assert sum(m == 'POST' for m, _, _, _ in network['requests']) == posts+1
    api_model.response_fault = None
    service = retained.reopen_service(backend, slot, pin)
    with pytest.raises(Denied):
        client('custody').gate('consume', 'B0', sha(b'request'), lambda _: effects.append('replay'), sha(b'grant'))
    assert sum(m == 'POST' for m, _, _, _ in network['requests']) == posts+1
    assert effects == ['issue', 'send']
    assert all(connection.closed for connection in network['connections'])


@pytest.mark.parametrize('kind', ['length', 'chunked', 'eof', 'truncated', 'bad_chunk'])
def test_standard_http_parser_over_local_socket_pair(monkeypatch, kind):
    # Exercise the real stdlib HTTP response parser, not TLS or remote GitHub.
    # Production has no socket injection option: this patch exists only in tests.
    original = wire.http.client.HTTPSConnection
    client_socket, server_socket = socket.socketpair()
    seen, errors = [], []
    def connection(host, port, timeout, context):
        assert host == wire.HOST and port == 443
        result = original(host, port, timeout=timeout, context=context)
        client_socket.settimeout(timeout)
        result.sock = client_socket
        return result
    monkeypatch.setattr(wire, 'http', SimpleNamespace(client=SimpleNamespace(HTTPSConnection=connection)))
    frames = dict(length=b'Content-Length: 2\r\n\r\n{}',
                  chunked=b'Transfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n',
                  eof=b'\r\n{}', truncated=b'Content-Length: 3\r\n\r\n{}',
                  bad_chunk=b'Transfer-Encoding: chunked\r\n\r\nXYZ\r\n')
    def server():
        try:
            server_socket.settimeout(2)
            data = b''
            while b'\r\n\r\n' not in data:
                part = server_socket.recv(4096)
                assert part
                data += part
            seen.append(data)
            server_socket.sendall(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n'+frames[kind])
        except Exception as error:
            errors.append(type(error).__name__)
        finally:
            server_socket.close()
    thread = threading.Thread(target=server)
    thread.start()
    try:
        if kind in ('truncated', 'bad_chunk'):
            with pytest.raises(Denied): wire.API(TOKEN, ROOT, PIN).call('GET', READ)
        else:
            assert wire.API(TOKEN, ROOT, PIN).call('GET', READ) == {}
    finally:
        client_socket.close(); thread.join(5)
    assert not thread.is_alive() and not errors and len(seen) == 1
    assert seen[0].startswith(('GET '+READ+' HTTP/1.1\r\n').encode())
    assert ('Host: api.github.com\r\n').encode() in seen[0]
