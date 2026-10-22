"""Explicit, create-once receipt-key custody; no network or ledger bootstrap."""
import argparse
from contextlib import contextmanager
import hashlib
import json
import os
import re
import stat
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat


class CustodyDenied(ValueError):
    pass


DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
KEY_NAME = 'receipt.key'


def _parts(path):
    raw = os.fspath(path)
    parts = raw.split('/')
    if not raw.startswith('/') or any(p in ('', '.', '..') for p in parts[1:]):
        raise CustodyDenied('ABSOLUTE_CANONICAL_PATH_REQUIRED')
    return parts[1:]


def _private(info):
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise CustodyDenied('PRIVATE_OWNED_DIRECTORY_REQUIRED')


@contextmanager
def _directory(path):
    """Walk pinned directory descriptors; never resolve a symlink ancestor."""
    parts = _parts(path)
    fd = os.open('/', DIR_FLAGS)
    try:
        for part in parts:
            info = os.fstat(fd)
            # Root-owned sticky temporary ancestors are allowed for isolated tests.
            sticky = info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
            if info.st_uid not in (0, os.geteuid()) or (info.st_mode & 0o022 and not sticky):
                raise CustodyDenied('UNTRUSTED_ANCESTOR')
            child = os.open(part, DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = child
        _private(os.fstat(fd))
        yield fd
    finally:
        os.close(fd)


def _read_key(fd):
    if os.listdir(fd) != [KEY_NAME]:
        raise CustodyDenied('INCOMPLETE_OR_UNEXPECTED_CUSTODY_CONTENTS')
    key_fd = os.open(KEY_NAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=fd)
    try:
        info = os.fstat(key_fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1 or info.st_size != 32):
            raise CustodyDenied('PRIVATE_OWNED_SINGLE_LINK_32_BYTE_KEY_REQUIRED')
        raw = os.read(key_fd, 33)
        if len(raw) != 32:
            raise CustodyDenied('INVALID_KEY_LENGTH')
        return Ed25519PrivateKey.from_private_bytes(raw)
    finally:
        os.close(key_fd)


def public_identity(key):
    raw = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return dict(schema='task4.receipt-key-custody.v1', algorithm='Ed25519',
                public_key_hex=raw.hex(), public_key_sha256=hashlib.sha256(raw).hexdigest())


def initialize(path):
    """Administrator-only setup. Any existing slot, including empty, must stop.

    Never remove the slot on failure: it records an initialization attempt.
    Removing the entire slot by an administrator is outside this guarantee.
    """
    parts = _parts(path)
    parent = '/' + '/'.join(parts[:-1])
    with _directory(parent) as parent_fd:
        os.mkdir(parts[-1], 0o700, dir_fd=parent_fd)  # Exclusive; no exist_ok.
        os.fsync(parent_fd)  # Retain the attempt before generating material.
        fd = os.open(parts[-1], DIR_FLAGS, dir_fd=parent_fd)
        try:
            _private(os.fstat(fd))
            raw = Ed25519PrivateKey.generate().private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
            key_fd = os.open(KEY_NAME, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                             0o600, dir_fd=fd)
            with os.fdopen(key_fd, 'wb') as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            os.fsync(fd)
            return public_identity(_read_key(fd))
        finally:
            os.close(fd)


def load(path, expected_public_sha256):
    """Reopen only: no mkdir, key generation, permission repair or pin discovery."""
    if not isinstance(expected_public_sha256, str) or not re.fullmatch('[0-9a-f]{64}', expected_public_sha256):
        raise CustodyDenied('EXTERNAL_PUBLIC_PIN_REQUIRED')
    with _directory(path) as fd:
        key = _read_key(fd)
        if public_identity(key)['public_key_sha256'] != expected_public_sha256:
            raise CustodyDenied('PUBLIC_PIN_MISMATCH')
        return key


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    init = sub.add_parser('init', help='Explicit one-time administration; never run at service startup')
    init.add_argument('--directory', required=True)
    inspect = sub.add_parser('inspect', help='Read existing key using an independently retained public pin')
    inspect.add_argument('--directory', required=True)
    inspect.add_argument('--expected-public-sha256', required=True)
    args = parser.parse_args()
    try:
        result = initialize(args.directory) if args.action == 'init' else public_identity(
            load(args.directory, args.expected_public_sha256))
    except (OSError, CustodyDenied):
        print('RECEIPT_KEY_CUSTODY_DENIED', file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))  # Public material only.
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
