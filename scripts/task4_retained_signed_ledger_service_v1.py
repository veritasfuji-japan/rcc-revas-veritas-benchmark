"""Pinned existing receipt custody joined to the injected signed GitHub service.

No key/root creation, enrollment, API credential, remote listener or CLI.
The caller supplies reviewed backend and TLS configuration; startup is read-only.
"""
from contextlib import contextmanager

from scripts import task4_receipt_key_custody_v1 as custody
from scripts.task4_external_ledger_contract_v1 import Denied, need
from scripts.task4_external_ledger_mtls_v1 import listener
from scripts.task4_signed_github_ledger_v1 import SignedGitHubService


def reopen_service(backend, directory, expected_public_sha256):
    """Load an existing pinned key, then validate the approved backend before use.

    Never discover a replacement pin, initialize storage, enroll or retry reads.
    Exceptions are sanitized because filesystem/API errors may contain secrets.
    """
    try:
        key = custody.load(directory, expected_public_sha256)
        need(backend.signer == expected_public_sha256, 'EXACT_APPROVED_SIGNER')
        service = SignedGitHubService(backend, key)
        backend.read()  # Existing approved root/ref/state; no startup mutation.
        return service
    except Exception:
        raise Denied('RETAINED_SIGNED_LEDGER_STARTUP_STOP') from None


@contextmanager
def retained_listener(backend, directory, expected_public_sha256, context, peers):
    """Open loopback mTLS only after custody and read-only backend validation.

    Per-command backend verification, role checks and readback-before-signing
    remain in SignedGitHubService. No acknowledgement-discard runtime option.
    """
    service = reopen_service(backend, directory, expected_public_sha256)
    with listener(service, context, peers) as server:
        yield server
