"""Run the pinned archive verifier with read-only Python audit guards.

Use a clean environment and Python -I -B -S. This is an inspection aid for an
audited program, not an OS security boundary for arbitrary hostile Python.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import sys
import sysconfig

AUDITED_COMMIT = '4328be1d35d6494458708af6bd85a62d837aa8ca'
PINNED_ZIP = '085de648b4fbd53643e20f20bc9ed3ab7dc8634b9307581cf815d5d5dbba8a51'
PINNED_MANIFEST = 'f54d7fd9e2795bbfa97eaaf696166c8c192c8049e41d75b5a341e91105cf3603'
BASELINE_VERIFIER = '6b1f696a8398f1abb81bd088146c8e417651e31c8ffa7ceb21632e88707de396'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('snapshot_directory', type=Path)
    parser.add_argument('--expected-verifier-sha256', default=BASELINE_VERIFIER)
    args = parser.parse_args()
    root = args.snapshot_directory.resolve()
    target = root / 'verify_snapshot.py'
    for name, expected in [('SNAPSHOT.zip', PINNED_ZIP), ('EVIDENCE_MANIFEST.json', PINNED_MANIFEST), ('verify_snapshot.py', args.expected_verifier_sha256)]:
        if hashlib.sha256((root / name).read_bytes()).hexdigest() != expected:
            raise ValueError('Pinned input mismatch: ' + name)
    # Python/macOS may add these two locale/text-encoding variables to env={}.
    allowed_environment = {'LC_CTYPE', '__CF_USER_TEXT_ENCODING'}
    if (set(os.environ) - allowed_environment or
            os.environ.get('LC_CTYPE', 'UTF-8') not in {'UTF-8', 'C.UTF-8', 'C.utf8'} or
            not re.fullmatch(r'0x[0-9A-Fa-f]+:0x[0-9A-Fa-f]+:0x[0-9A-Fa-f]+', os.environ.get('__CF_USER_TEXT_ENCODING', '0x0:0x0:0x0'))):
        raise RuntimeError('Use env -i; only interpreter-added locale/text-encoding variables are allowed')
    if not (sys.flags.isolated and sys.flags.dont_write_bytecode and sys.flags.no_site):
        raise RuntimeError('Use Python -I -B -S')
    roots = [root, Path(sysconfig.get_path('stdlib')).resolve()]
    reads, denied = set(), []

    def audit(event, values):
        blocked = (event.startswith(('socket.', 'subprocess.', 'ctypes.', 'os.exec', 'os.spawn', 'os.fork')) or
                   event in {'os.system', 'os.posix_spawn', 'os.remove', 'os.unlink', 'os.rename', 'os.rmdir',
                             'os.mkdir', 'os.link', 'os.symlink', 'os.chmod', 'os.chown', 'os.truncate'})
        if event == 'open':
            filename, mode, flags = values
            blocked = blocked or (isinstance(mode, str) and any(x in mode for x in 'wax+'))
            blocked = blocked or bool(flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND))
            if isinstance(filename, (str, bytes, os.PathLike)):
                location = Path(os.fsdecode(filename)).resolve()
                allowed = any(location == base or base in location.parents for base in roots)
                blocked = blocked or not allowed
                if not blocked:
                    reads.add(str(location.relative_to(root)) if location == root or root in location.parents else '<python-stdlib>')
        if blocked:
            denied.append(event)
            raise PermissionError('Offline verification denies ' + event)

    sys.addaudithook(audit)
    namespace = runpy.run_path(str(target), run_name='pinned_archive_verifier')
    result = namespace['verify'](False)
    print(json.dumps({
        'audited_original_commit': AUDITED_COMMIT, 'verifier_sha256': args.expected_verifier_sha256,
        'environment_keys_after_interpreter_startup': sorted(os.environ), 'secret_environment_keys': [],
        'python_isolated': True, 'site_disabled': True,
        'bytecode_writes_disabled': True, 'read_scope': ['selected snapshot directory', 'Python standard library'],
        'python_audit_guard': 'deny network/process creation/write opens/filesystem mutations',
        'denied_operation_attempts': denied, 'read_paths': sorted(reads), 'verification': result,
        'sudo_used': False, 'packages_installed': False, 'archived_runner_or_Native_scorer_imported': False,
        'external_independent_reproduction': False,
        'limitation': 'Python audit hook for the pinned inspected program, not an OS sandbox or adversarial isolation proof.'
    }, indent=2))


if __name__ == '__main__':
    main()
