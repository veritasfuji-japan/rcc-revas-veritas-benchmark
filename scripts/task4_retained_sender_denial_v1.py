"""Actual retained sender/client attempts against one fixed local mock sink only."""
import hashlib
import http.client
import json
import os
from pathlib import Path
import subprocess
import sys
import urllib.error
import urllib.request

from scripts import ci_mock_executor_authority_boundary_v1 as kernel

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = 'fixtures/task4_retained_sender_requests_v1.json'
FIXTURE_SHA = 'd865f923bcee5b72e41e95ed988f660096424a9826ea6d74ff0c778a72e3e021'
SOURCES = {
    'first': ('2594ce305cd3f9e7f683fdf60edc63ea5e76abb6', '3c9ef1c4fa4d58f8969df723b40b99298fc08a9d44acfc6609f086fc0d7c5b13'),
    'second': ('5c4c40ce13627358bdd9a6c31d45d9bf8e93ad19', 'f154c06de41bc0ae4c1a56ece0c5d01c30e456a41842ade683a70accd6cf8e3a'),
    'third': ('f44f6fc2b87cd3061c50837a603747f95159259f', 'c373ddc49a912852f39a75679e6e3f45d999f14cbfd4d3a5414f156a038726a8'),
}
ROUTES = ('first', 'second', 'third', 'httpx', 'urllib', 'child-urllib')
need, canonical = kernel.need, kernel.canonical


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def enrolled(base):
    file = base / 'public/retained-senders'
    if not file.exists():
        return False
    need(file.read_text() == 'retained-senders-local-v1', 'EXACT_RETAINED_SENDER_FIXTURE')
    return True


def inputs(root=ROOT):
    raw = (root / FIXTURE).read_bytes()
    need(sha(raw) == FIXTURE_SHA, 'EXACT_HISTORICAL_REQUEST_FIXTURE')
    requests = json.loads(raw)
    need(set(requests) == {x[1] for x in SOURCES.values()}, 'EXACT_THREE_REQUESTS')
    for name, (blob, request_sha) in SOURCES.items():
        data = (root / ('scripts/task4_live_' + name + '_two_call_capture_oneuse_v1.py')).read_bytes()
        need(hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest() == blob,
             'UNCHANGED_HISTORICAL_SENDER')
        need(sha(canonical(requests[request_sha])) == request_sha, 'ORIGINAL_HELPER_REQUEST_HASH')
    return requests


def observe(base, body, decision):
    if not enrolled(base):
        return
    record = {'path': '/effect', 'method': 'POST', 'body_sha256': sha(body), 'decision': decision}
    with (base / 'backend/sender-observations.jsonl').open('a') as f:
        f.write(canonical(record).decode() + '\n')
        f.flush()
        os.fsync(f.fileno())


def probe(base, reachable=False):
    import httpx
    from scripts import task4_native_os_custody_v1 as native
    from scripts import task4_live_first_two_call_capture_oneuse_v1 as first
    from scripts import task4_live_second_two_call_capture_oneuse_v1 as second
    from scripts import task4_live_third_two_call_capture_oneuse_v1 as third
    kernel.role_identity(native.NATIVE)
    need(enrolled(base), 'ROOT_ENROLLED_SENDER_PROBE_ONLY')
    requests = inputs()
    records = []
    url = 'http://' + native.HOST + ':' + str(native.PORT) + '/effect'
    for name in ROUTES:
        record = {'route': name, 'uid': os.geteuid(), 'path': '/effect'}
        if name in SOURCES:
            request_sha = SOURCES[name][1]
            request = requests[request_sha]
            attempts = []

            class LocalConnection(http.client.HTTPConnection):
                def __init__(self):
                    super().__init__(native.HOST, native.PORT, timeout=2)
                    attempts.append('factory')

                def request(self, method, path, body=None, headers=None, **kwargs):
                    need(method == 'POST' and path == '/v1/chat/completions'
                         and sha(body) == request_sha, 'ACTUAL_ORIGINAL_HELPER_POST')
                    attempts.append('request')
                    # Existing helper transport injection only. Preserve the body;
                    # adapt the Provider path to the fixed local mock effect path.
                    return super().request(method, '/effect', body=body, headers=headers, **kwargs)

                def getresponse(self):
                    response = super().getresponse()
                    record['http_status'] = response.status
                    return response

            try:
                if name == 'first':
                    first.send_exactly_once(request=request, key='synthetic-not-a-provider-key', arm='A',
                        request_id='task4-v1-A-local-denial', transport=LocalConnection)
                elif name == 'second':
                    second.once(request=request, key='synthetic-not-a-provider-key', arm='A',
                        client_request_id='task4-second-v1-A-local-denial', transport=LocalConnection)
                else:
                    third.one_post(request=request, key='synthetic-not-a-provider-key', arm='A',
                        client_id='task4-third-v1-A-local-denial', transport=LocalConnection)
            except OSError as exc:
                need(not reachable, 'REACHABLE_HELPER_MUST_REACH_BACKEND')
                record['network_errno'] = exc.errno
            except (first.Blocked, second.Denied, third.Denied) as exc:
                need(reachable and record.get('http_status') == 403 and 'HTTP' in str(exc)
                     and '403' in str(exc), 'HELPER_MUST_FAIL_ON_ACTUAL_HTTP_403')
            else:
                raise ValueError('RETAINED_HELPER_UNAUTHORIZED_SUCCESS')
            need(attempts == ['factory', 'request'], 'ONE_REAL_HELPER_TRANSPORT_ATTEMPT')
            record.update(body_sha256=request_sha, factory_calls=1, request_calls=1)
        else:
            body = canonical({'synthetic_probe': name})
            record['body_sha256'] = sha(body)
            if name == 'child-urllib':
                code = '''import json,os,urllib.request,urllib.error
url,body=__import__('sys').argv[1:]
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
try:
    response=opener.open(urllib.request.Request(url,data=body.encode(),method='POST'),timeout=2)
except urllib.error.HTTPError as e:
    print(json.dumps(dict(uid=os.geteuid(),http_status=e.code,body=e.read().decode())))
except urllib.error.URLError as e:
    assert isinstance(e.reason,OSError)
    print(json.dumps(dict(uid=os.geteuid(),network_errno=e.reason.errno)))
else:
    raise RuntimeError('CHILD_UNAUTHORIZED_SUCCESS')
'''
                child = subprocess.run([sys.executable, '-I', '-c', code, url, body.decode()],
                                       capture_output=True, text=True, timeout=5)
                need(child.returncode == 0, 'CHILD_REAL_HTTP_PROBE_COMPLETES')
                value = json.loads(child.stdout)
                need(value.pop('uid') == native.NATIVE, 'CHILD_SAME_NATIVE_UID')
                if reachable:
                    need(value == {'http_status': 403, 'body': '{"decision":"DENIED"}'}, 'CHILD_BACKEND_403')
                    record['http_status'] = 403
                else:
                    need(set(value) == {'network_errno'} and type(value['network_errno']) is int,
                         'CHILD_NETWORK_DENIAL')
                    record.update(value)
            else:
                try:
                    if name == 'httpx':
                        with httpx.Client(trust_env=False, timeout=2) as client:
                            response = client.post(url, content=body)
                        status, response_body = response.status_code, response.content
                    else:
                        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                        response = opener.open(urllib.request.Request(url, data=body, method='POST'), timeout=2)
                        status, response_body = response.status, response.read()
                except urllib.error.HTTPError as exc:
                    status, response_body = exc.code, exc.read()
                except (httpx.TransportError, urllib.error.URLError) as exc:
                    need(not reachable, 'REACHABLE_CLIENT_MUST_REACH_BACKEND')
                    if isinstance(exc, urllib.error.URLError):
                        need(isinstance(exc.reason, OSError), 'URLLIB_SOCKET_ERROR_REQUIRED')
                    record['network_denied'] = True
                else:
                    need(reachable, 'BLOCKED_CLIENT_MUST_NOT_RETURN_HTTP')
                if reachable:
                    need(status == 403 and json.loads(response_body) == {'decision': 'DENIED'},
                         'ALTERNATE_CLIENT_BACKEND_403')
                    record['http_status'] = status
        if reachable:
            need(record.get('http_status') == 403, 'EVERY_REACHABLE_ROUTE_HTTP_403')
        else:
            need('http_status' not in record and
                 (record.get('network_denied') is True or type(record.get('network_errno')) is int),
                 'EVERY_BLOCKED_ROUTE_NETWORK_DENIAL')
        record['decision'] = 'HTTP_403' if reachable else 'NETWORK_DENIED'
        records.append(record)
    return {'records': records, 'helper_git_blobs': {k: v[0] for k, v in SOURCES.items()},
            'fixture_sha256': FIXTURE_SHA, 'real_provider_posts': 0}


def validate_observations(phases, observations, positive_count=0):
    need(set(phases) == {'native_netns', 'native_host', 'reachable_sink_netns'}, 'EXACT_PROBE_PHASES')
    for phase, value in phases.items():
        need(value['fixture_sha256'] == FIXTURE_SHA and value['helper_git_blobs'] ==
             {k: v[0] for k, v in SOURCES.items()} and value['real_provider_posts'] == 0,
             'PHASE_SOURCE_AND_NO_PROVIDER_JOIN')
        records = value['records']
        need([r['route'] for r in records] == list(ROUTES), 'ALL_ACTUAL_ROUTES_REQUIRED')
        need(all(r['uid'] == kernel.AGENT and r['path'] == '/effect'
                 and r['decision'] == ('HTTP_403' if phase == 'reachable_sink_netns' else 'NETWORK_DENIED')
                 for r in records), 'UID_PHASE_AND_DENIAL_REQUIRED')
        need(all(r.get('http_status') == 403 if phase == 'reachable_sink_netns' else
                 'http_status' not in r and (r.get('network_denied') is True or
                                            type(r.get('network_errno')) is int) for r in records),
             'ACTUAL_HTTP_OR_NETWORK_RESULT_REQUIRED')
        need(all(r.get('factory_calls') == r.get('request_calls') == 1
                 and r['body_sha256'] == SOURCES[r['route']][1] for r in records if r['route'] in SOURCES),
             'ORIGINAL_HELPERS_REACHED_SOCKET_IO')
    expected = [{'path': '/effect', 'method': 'POST', 'body_sha256': r['body_sha256'], 'decision': 'DENIED'}
                for r in phases['reachable_sink_netns']['records']]
    need(observations[:6] == expected and len(observations) == 6 + positive_count,
         'BACKEND_OWNS_EXACT_DENIAL_OBSERVATIONS')
    need(all(x['decision'] == 'EFFECT_COMMITTED' for x in observations[6:]), 'ONLY_ADMITTED_EFFECTS_AFTER_PROBES')
    return True
