"""Explicit fixed-GitHub HTTPS transport for the signed synthetic ledger only.

No credential discovery, proxy, redirect, retry, bootstrap, CLI or deployment.
Caller-supplied credentials and all code in this service process remain trusted.
"""
import base64
import http.client
import re
import ssl
import time

from scripts.task4_external_ledger_contract_v1 import Denied, canonical, exact, hex64, need
from scripts.task4_github_ledger_research_v1 import decode, hx
from scripts.task4_signed_github_ledger_v1 import (
    BRANCH, FILE, MAX_BLOB, MUTATION_QUERY, REPO, GitState, validate,
)

HOST = 'api.github.com'
API_VERSION = '2022-11-28'
PREFIX = '/repos/' + REPO + '/'
MAX_RESPONSE = 1024 * 1024
MAX_REQUEST = 128 * 1024
TIMEOUT = 10.0
STOP = 'SIGNED_GITHUB_API_STOP'


class FixedHTTPS:
    """Shared fixed-host mechanics; concrete profiles must supply an allowlist."""
    def __init__(self, token):
        try:
            need(type(token) is str and re.fullmatch('[A-Za-z0-9_]{20,255}', token), 'EXPLICIT_TOKEN')
            self._token = token
        except Exception:
            raise Denied(STOP) from None

    def _request(self, method, path, value):
        raise Denied(STOP)

    def _status(self, method, path):
        return 200

    def _response(self, method, path, result):
        need(type(result) is dict and not result.get('errors'), 'API_ERRORS_STOP')
        return result

    def call(self, method, path, value=None):
        connection = response = None
        try:
            path, body = self._request(method, path, value)  # Before a socket/token is used.
            context = ssl.create_default_context()
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            connection = http.client.HTTPSConnection(HOST, 443, timeout=TIMEOUT, context=context)
            # http.client has no proxy/environment discovery, redirect handler or retry loop.
            connection.request(method, path, body=body, headers={
                'Authorization': 'Bearer ' + self._token,
                'Accept': 'application/vnd.github+json',
                'Content-Type': 'application/json',
                'Accept-Encoding': 'identity',
                'X-GitHub-Api-Version': API_VERSION,
                'User-Agent': 'task4-signed-ledger-api-v1',
                'Connection': 'close',
            })
            active_socket = connection.sock
            response = connection.getresponse()
            need(response.status == self._status(method, path), 'HTTP_STOP')  # Includes redirects, rate limits and auth errors.
            headers = response.getheaders()
            def values(name):
                return [v for k, v in headers if k.lower() == name]
            types = values('content-type')
            need(len(types) == 1 and types[0].split(';')[0].strip().lower()
                 in ('application/json', 'application/vnd.github+json'), 'JSON_RESPONSE')
            encoding = values('content-encoding')
            need(not encoding or encoding == ['identity'], 'NO_COMPRESSED_RESPONSE')
            lengths = values('content-length')
            need(not lengths or (len(lengths) == 1 and re.fullmatch('[0-9]{1,7}', lengths[0])
                 and int(lengths[0]) <= MAX_RESPONSE), 'BOUNDED_CONTENT_LENGTH')
            transfers = values('transfer-encoding')
            need(not transfers or (not lengths and transfers == ['chunked']), 'UNAMBIGUOUS_FRAMING')
            deadline, data = time.monotonic() + TIMEOUT, bytearray()
            while True:
                remaining = deadline - time.monotonic()
                need(remaining > 0, 'BODY_DEADLINE')
                need(active_socket is not None, 'CONNECTED_SOCKET')
                active_socket.settimeout(remaining)
                part = response.read1(min(65536, MAX_RESPONSE + 1 - len(data)))
                if not part:
                    break
                data.extend(part)
                need(len(data) <= MAX_RESPONSE, 'BOUNDED_RESPONSE')
                if lengths and len(data) == int(lengths[0]):
                    break  # HTTPResponse may already have closed the completed socket.
            need(not lengths or len(data) == int(lengths[0]), 'COMPLETE_RESPONSE')
            result = decode(bytes(data))  # Duplicate fields/nonfinite JSON are denied.
            return self._response(method, path, result)
        except Exception:
            # No server text, request headers/body, token or exception detail escapes.
            raise Denied(STOP) from None
        finally:
            for resource in (response, connection):
                if resource is not None:
                    try:
                        resource.close()
                    except Exception:
                        pass  # Cleanup must never expose a credential-bearing exception.


class API(FixedHTTPS):
    """One explicit request per call; no ambient token, proxy or endpoint setting.

    HTTPSConnection uses the default verified CA/hostname context. Socket timeouts
    apply to blocking operations; the body deadline is checked between reads.
    DNS, headers and parser subreads are not a hard wall-clock bounded execution.
    API and GitHub administrators remain trusted.
    """
    def __init__(self, token, genesis, signer_sha256):
        try:
            super().__init__(token)
            need(hx(genesis, 40) and hex64(signer_sha256), 'APPROVED_IDENTITY')
            self._token, self.genesis, self.signer = token, genesis, signer_sha256
        except Exception:
            raise Denied(STOP) from None

    def _request(self, method, path, value):
        need(type(method) is str and type(path) is str, 'EXACT_REQUEST')
        if method == 'GET':
            need(value is None, 'GET_WITHOUT_BODY')
            fixed_ref = PREFIX + 'git/ref/heads/' + BRANCH
            objects = re.fullmatch(re.escape(PREFIX) + r'git/(commits|trees|blobs)/[0-9a-f]{40}', path)
            compare = re.fullmatch(re.escape(PREFIX + 'compare/' + self.genesis) + r'\.\.\.[0-9a-f]{40}', path)
            need(path == fixed_ref or objects or compare, 'READ_ALLOWLIST')
            return path, None
        need(method == 'POST' and path == '/graphql', 'WRITE_ALLOWLIST')
        exact(value, 'query variables')
        need(value['query'] == MUTATION_QUERY, 'ONE_FIXED_MUTATION')
        exact(value['variables'], 'input')
        v = value['variables']['input']
        exact(v, 'branch expectedHeadOid clientMutationId message fileChanges')
        need(v['branch'] == dict(repositoryNameWithOwner=REPO, branchName=BRANCH), 'FIXED_BRANCH')
        need(hx(v['expectedHeadOid'], 40) and hex64(v['clientMutationId']), 'EXACT_CAS_NONCE')
        need(v['message'] == dict(headline='Task4 synthetic signed-ledger transition ' + v['clientMutationId']),
             'FIXED_MESSAGE')
        exact(v['fileChanges'], 'additions')
        additions = v['fileChanges']['additions']
        need(type(additions) is list and len(additions) == 1, 'ONE_FILE')
        row = additions[0]
        exact(row, 'path contents')
        need(row['path'] == FILE and type(row['contents']) is str
             and len(row['contents']) <= 4 * ((MAX_BLOB + 2) // 3), 'BOUNDED_LEDGER_FILE')
        data = base64.b64decode(row['contents'], validate=True)
        need(base64.b64encode(data).decode() == row['contents'], 'CANONICAL_BASE64')
        state = validate(decode(data), self.signer)
        need(data == canonical(state), 'CANONICAL_LEDGER')
        body = canonical(value)
        need(len(body) <= MAX_REQUEST, 'BOUNDED_REQUEST')
        return path, body



def approved_backend(token, genesis, signer_sha256):
    """Construct only; existing root validation occurs at retained service startup.

    Does not connect, create a branch/root, enroll, obtain a token or read a key.
    """
    return GitState(API(token, genesis, signer_sha256), genesis, signer_sha256)
