from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile

import pytest

from scripts import task4_receipt_key_custody_v1 as c


@pytest.fixture
def slot(tmp_path):
    parent = tmp_path / 'authority'
    parent.mkdir(mode=0o700)
    return parent / 'receipt-custody'


def test_reopen_and_fresh_process_keep_identity(slot):
    report = c.initialize(slot)
    key = c.load(slot, report['public_key_sha256'])
    key.public_key().verify(key.sign(b'synthetic probe'), b'synthetic probe')
    wire = subprocess.check_output([sys.executable, '-m', 'scripts.task4_receipt_key_custody_v1',
                                   'inspect', '--directory', str(slot), '--expected-public-sha256',
                                   report['public_key_sha256']], text=True)
    assert json.loads(wire) == report
    assert set(report) == {'schema', 'algorithm', 'public_key_hex', 'public_key_sha256'}
    assert len(bytes.fromhex(report['public_key_hex'])) == 32
    assert stat.S_IMODE(slot.stat().st_mode) == 0o700
    assert stat.S_IMODE((slot / c.KEY_NAME).stat().st_mode) == 0o600


def test_competing_initializers_do_not_replace(slot):
    def create():
        try:
            return c.initialize(slot)
        except FileExistsError:
            return None
    with ThreadPoolExecutor(2) as pool:
        reports = list(pool.map(lambda _: create(), range(2)))
    winner, = [r for r in reports if r is not None]
    assert c.public_identity(c.load(slot, winner['public_key_sha256'])) == winner


@pytest.mark.parametrize('pin', [None, '', 'x'*64, 'A'*64, '0'*63, '0'*65, '0'*64])
def test_missing_or_wrong_pin_never_repairs(slot, pin):
    c.initialize(slot)
    before = (slot / c.KEY_NAME).read_bytes()
    with pytest.raises(c.CustodyDenied):
        c.load(slot, pin)
    assert (slot / c.KEY_NAME).read_bytes() == before


@pytest.mark.parametrize('fault', ['missing', 'empty', 'short', 'long', 'replacement', 'mode',
                                        'hardlink', 'symlink', 'fifo', 'directory', 'extra', 'slot_mode'])
def test_bad_custody_denies_without_regeneration(slot, fault):
    report = c.initialize(slot)
    key = slot / c.KEY_NAME
    if fault == 'missing': key.unlink()
    if fault == 'empty': key.write_bytes(b'')
    if fault == 'short': key.write_bytes(b'x'*31)
    if fault == 'long': key.write_bytes(b'x'*33)
    if fault == 'replacement': key.write_bytes(b'x'*32)
    if fault == 'mode': key.chmod(0o644)
    if fault == 'hardlink': os.link(key, slot.parent / 'linked')
    if fault in ('symlink', 'fifo', 'directory'):
        key.unlink()
        if fault == 'symlink': key.symlink_to('/dev/null')
        if fault == 'fifo': os.mkfifo(key, 0o600)
        if fault == 'directory': key.mkdir(mode=0o700)
    if fault == 'extra': (slot / 'unexpected').write_text('synthetic')
    if fault == 'slot_mode': slot.chmod(0o755)
    with pytest.raises((c.CustodyDenied, OSError)):
        c.load(slot, report['public_key_sha256'])
    with pytest.raises(FileExistsError):
        c.initialize(slot)


def test_missing_slot_inspect_does_not_create(slot):
    with pytest.raises(FileNotFoundError): c.load(slot, 'a'*64)
    assert not slot.exists()


def test_interrupted_initialization_burns_slot(slot, monkeypatch):
    def fail(_): raise OSError('synthetic fsync failure')
    monkeypatch.setattr(c.os, 'fsync', fail)
    with pytest.raises(OSError): c.initialize(slot)
    assert slot.is_dir() and not list(slot.iterdir())
    with pytest.raises(FileExistsError): c.initialize(slot)
    with pytest.raises(c.CustodyDenied): c.load(slot, 'a'*64)


@pytest.mark.parametrize('kind', ['relative', 'dot', 'symlink_ancestor', 'writable_parent'])
def test_untrusted_paths_stop_before_creation(slot, kind):
    if kind == 'relative': path = 'relative-custody'
    if kind == 'dot': path = str(slot.parent) + '/./receipt-custody'
    if kind == 'symlink_ancestor':
        alias = slot.parent.parent / 'alias'
        alias.symlink_to(slot.parent, target_is_directory=True)
        path = alias / slot.name
    if kind == 'writable_parent':
        slot.parent.chmod(0o777)
        path = slot
    with pytest.raises((c.CustodyDenied, OSError)): c.initialize(path)
    assert not slot.exists()


def test_cli_failure_is_nonzero_and_sanitized(slot):
    c.initialize(slot)
    result = subprocess.run([sys.executable, '-m', 'scripts.task4_receipt_key_custody_v1',
                             'init', '--directory', str(slot)], capture_output=True, text=True)
    assert result.returncode == 1 and result.stdout == ''
    assert result.stderr.strip() == 'RECEIPT_KEY_CUSTODY_DENIED'


@pytest.mark.skipif(os.geteuid() != 0, reason='run explicitly under sudo for actual cross-UID proof')
def test_actual_crossuid_custody_access():
    for name in ('uid_map', 'gid_map'):
        ranges = [tuple(map(int, row.split())) for row in Path('/proc/self/' + name).read_text().splitlines()]
        if any(not any(start <= uid < start + count for start, _, count in ranges) for uid in (65530, 65531)):
            pytest.skip('container does not map the two test UIDs/GIDs; CI requires no skips')
    # Synthetic marker only; do not create or export any authority key here.
    with tempfile.TemporaryDirectory(prefix='task4-custody-os-') as folder:
        base = Path(folder)
        base.chmod(0o755)
        private = base / 'authority'
        private.mkdir(mode=0o700)
        os.chown(private, 65530, 65530)
        marker = private / 'synthetic-marker'
        marker.write_bytes(b'synthetic')
        marker.chmod(0o600)
        os.chown(marker, 65530, 65530)
        def probe(uid):
            def drop():
                os.setgroups([])
                os.setgid(uid)
                os.setuid(uid)
            return subprocess.run([sys.executable, '-c',
                'import sys;open(sys.argv[1],"rb").read()', str(marker)],
                preexec_fn=drop, capture_output=True)
        assert probe(65530).returncode == 0
        denied = probe(65531)
        assert denied.returncode != 0 and b'PermissionError' in denied.stderr
