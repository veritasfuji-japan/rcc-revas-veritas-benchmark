"""Contract tests only: real files/signatures/SQLite, no Native/TLS/Provider run."""
import copy
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import multiprocessing
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from threading import Barrier
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from scripts import task4_external_ledger_contract_v1 as ledger
from scripts import task4_native_signed_ledger_gate_v1 as gate


DOMAIN = b'TASK4_BOUNDED_CONTINUATION_V1\0'


class Fixture:
    def __init__(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.key = Ed25519PrivateKey.generate()
        self.issuer_key = Ed25519PrivateKey.generate()
        self.custody_key = Ed25519PrivateKey.generate()
        self.public = self.key.public_key().public_bytes_raw()
        self.binding = dict(schema=ledger.SCHEMA, ledger_id='1'*64, run_id='2'*64,
            manifest_sha256='3'*64,
            issuer_public_sha256=ledger.sha(self.issuer_key.public_key().public_bytes_raw()),
            custody_public_sha256=ledger.sha(self.custody_key.public_key().public_bytes_raw()))
        self.service = ledger.ReferenceService.bootstrap(self.base/'ledger.sqlite3', '1'*64, self.key)
        self.service.enroll(self.binding)
        self.enrollments = {}
        for role in ('issuer', 'custody'):
            folder = self.base/role
            folder.mkdir(mode=0o700)
            e = dict(schema=gate.ENROLLMENT, scope=gate.SCOPE, binding=self.binding, role=role,
                     service_public_sha256=ledger.sha(self.public),
                     journal=gate._identity(str(folder), folder.stat()))
            record = folder/gate.ENROLLMENT_FILE
            record.write_bytes(ledger.canonical(e)); record.chmod(0o600)
            self.enrollments[role] = copy.deepcopy(e)
        self.wire = b'{"messages":[{"role":"user","content":"synthetic Native request"}],"model":"closed-local"}'
        self.calls = []; self.effects = []; self.admissions = []

    def close(self):
        self.temp.cleanup()

    def transport(self, role):
        def call(raw):
            self.calls.append(ledger.strict(raw))
            return self.service.exchange(raw, self.binding[role+'_public_sha256'])
        return call

    def client(self, role='issuer', transport='default'):
        if transport == 'default':
            transport = self.transport(role)
        return gate.NativeLedgerGate(self.enrollments[role], self.public, transport)

    def admit(self):
        self.admissions.append('checked')

    def grant(self, op='A0', wire=None):
        statement = dict(schema='task4.bounded-continuation-grant.v1',
            manifest_sha256=self.binding['manifest_sha256'], run_id=self.binding['run_id'],
            arm=op[0], ordinal=int(op[1]), request_sha256=ledger.sha(wire or self.wire),
            request_bytes=len(wire or self.wire), parent_receipt_sha256='6'*64,
            raw_recipient_sha256='7'*64, endpoint='https://closed-local.invalid/v1/chat/completions',
            output_cap=256, not_before=1, expires_at=2)
        return dict(statement=statement,
            signature=self.issuer_key.sign(DOMAIN+ledger.canonical(statement)).hex())

    def reserve(self, op='A0', transport='default', effect=None, admit=None, wire=None):
        def issue(snapshot):
            self.effects.append('issue'); return self.grant(op, wire)
        return self.client(transport=transport).execute(operation=op, wire=wire or self.wire,
            admit=admit or self.admit, effect=effect or issue)

    def consume(self, grant, transport='default', effect=None, admit=None, wire=None):
        def send(snapshot):
            self.effects.append('send'); return b'synthetic response'
        return self.client('custody', transport).execute(operation='A0', wire=wire or self.wire,
            grant=grant, admit=admit or self.admit, effect=effect or send)

    def slot(self, role='issuer', op='A0'):
        action = 'reserve' if role == 'issuer' else 'consume'
        return self.base/role/(self.binding['run_id']+'-'+action+'-'+op)

    def snapshot(self):
        return ledger.LedgerClient(self.binding, self.public, self.transport('issuer')).exchange('view')


def process_racer(enrollment, public, service, binding, start, queue):
    def transport(raw):
        return service.exchange(raw, binding['issuer_public_sha256'])
    start.wait(10)
    try:
        gate.NativeLedgerGate(enrollment, public, transport).execute(operation='A0', wire=b'actual bytes',
            admit=lambda: None, effect=lambda _: 'issued')
    except gate.GateDenied:
        queue.put('stop')
    else:
        queue.put('issued')


class GateTests(unittest.TestCase):
    def setUp(self):
        self.f = Fixture()
        self.addCleanup(self.f.close)

    def assert_stop(self, function):
        with self.assertRaisesRegex(gate.GateDenied, '^'+gate.STOP+'$'):
            function()

    def test_real_bytes_and_grant_committed_before_callbacks(self):
        f = self.f
        def issue(snapshot):
            slot=f.slot()
            self.assertTrue((slot/'intent.json').exists())
            self.assertTrue((slot/'verified-receipts.json').exists())
            self.assertFalse((slot/'effect-returned.json').exists())
            self.assertEqual(snapshot['attempts'][0]['request_sha256'], ledger.sha(f.wire))
            self.assertEqual(f.snapshot()['revision'], 1)
            f.effects.append('issue');return f.grant()
        grant = f.reserve(effect=issue)
        def send(snapshot):
            self.assertTrue((f.slot('custody')/'verified-receipts.json').exists())
            self.assertEqual(f.snapshot()['attempts'][0]['grant_sha256'], ledger.digest(grant))
            self.assertEqual(snapshot['revision'], 2)
            f.effects.append('send');return b'ok'
        self.assertEqual(f.consume(grant,effect=send), b'ok')
        self.assertEqual(f.effects,['issue','send'])
        self.assertEqual(len(f.admissions),4)
        self.assertEqual(f.snapshot()['attempts'][0]['state'],'CONSUMED_UNKNOWN')
        for role in ('issuer','custody'):
            record=json.loads((f.slot(role)/'verified-receipts.json').read_bytes())
            verifier=ledger.LedgerClient(f.binding,f.public)
            for x in record['exchanges']:
                receipt=x['receipt'];statement=receipt['statement']
                verifier.public.verify(bytes.fromhex(receipt['signature']),ledger.DOMAIN+ledger.canonical(statement))
            self.assertEqual((f.slot(role)/'intent.json').stat().st_mode&0o777,0o600)
            text=(f.slot(role)/'verified-receipts.json').read_text()
            self.assertNotIn(f.wire.decode(),text)
            self.assertNotIn(grant['signature'],text)

    def test_repeated_and_changed_request_stop_before_transport(self):
        f=self.f;f.reserve();before=len(f.calls)
        self.assert_stop(lambda:f.reserve())
        self.assert_stop(lambda:f.reserve(wire=b'changed'))
        self.assertEqual(len(f.calls),before)
        self.assertEqual(f.effects,['issue'])

    def test_consume_repeat_stops_before_transport(self):
        f=self.f;g=f.reserve();f.consume(g);before=len(f.calls)
        self.assert_stop(lambda:f.consume(g))
        self.assertEqual(len(f.calls),before);self.assertEqual(f.effects,['issue','send'])

    def test_issuer_cannot_accept_grant_or_custody_missing_grant(self):
        f=self.f
        self.assert_stop(lambda:f.client().execute(operation='A0',wire=f.wire,grant=f.grant(),admit=f.admit,effect=lambda _:None))
        self.assert_stop(lambda:f.consume(None))
        self.assertEqual(f.calls,[])

    def test_native_grant_join_mismatch_stops_without_claim(self):
        f=self.f
        for field,value in [('run_id','f'*64),('manifest_sha256','f'*64),('request_sha256','f'*64),('ordinal',True),('arm','B')]:
            with self.subTest(field=field):
                g=f.grant();g['statement'][field]=value
                self.assert_stop(lambda:f.consume(g))
        self.assertEqual(f.calls,[]);self.assertFalse(f.slot('custody').exists())

    def test_admission_failure_and_false_do_not_claim(self):
        f=self.f
        def fail():raise ValueError('private data must not escape')
        self.assert_stop(lambda:f.reserve(admit=fail))
        self.assert_stop(lambda:f.reserve(admit=lambda:False))
        self.assertEqual(f.calls,[]);self.assertFalse(f.slot().exists())

    def test_admission_must_recheck_after_exchange(self):
        f=self.f;calls=[]
        def admit():
            calls.append(1)
            if len(calls)==2:raise ValueError('expired')
        self.assert_stop(lambda:f.reserve(admit=admit))
        self.assertEqual(f.snapshot()['revision'],1);self.assertEqual(f.effects,[])
        self.assertTrue((f.slot()/'verified-receipts.json').exists())
        before=len(f.calls);self.assert_stop(lambda:f.reserve())
        self.assertEqual(len(f.calls),before)

    def test_no_transport_burns_attempt_without_effect_or_fallback(self):
        f=self.f;self.assert_stop(lambda:f.reserve(transport=None))
        self.assertTrue((f.slot()/'intent.json').exists());self.assertEqual(f.effects,[])
        self.assertEqual(f.calls,[])
        self.assert_stop(lambda:f.reserve())
        self.assertEqual(f.calls,[])

    def test_reserve_response_discard_preserves_remote_state_and_local_intent(self):
        f=self.f
        def discard(raw):
            reply=f.transport('issuer')(raw)
            if ledger.strict(raw)['action']=='reserve':raise OSError('lost')
            return reply
        self.assert_stop(lambda:f.reserve(transport=discard))
        self.assertEqual(f.snapshot()['revision'],1);self.assertEqual(f.effects,[])
        self.assertTrue((f.slot()/'intent.json').exists())
        self.assertFalse((f.slot()/'verified-receipts.json').exists())
        before=len(f.calls);self.assert_stop(lambda:f.reserve())
        self.assertEqual(len(f.calls),before)

    def test_consume_response_discard_stops_effect_and_replay(self):
        f=self.f;g=f.reserve()
        def discard(raw):
            reply=f.transport('custody')(raw)
            if ledger.strict(raw)['action']=='consume':raise OSError('lost')
            return reply
        self.assert_stop(lambda:f.consume(g,transport=discard))
        self.assertEqual(f.snapshot()['revision'],2);self.assertEqual(f.effects,['issue'])
        self.assertFalse((f.slot('custody')/'verified-receipts.json').exists())
        before=len(f.calls);self.assert_stop(lambda:f.consume(g))
        self.assertEqual(len(f.calls),before)

    def test_bad_signature_nonce_binding_and_state_never_reach_callback(self):
        for field in ('signature','nonce','binding_sha256','snapshot'):
            with self.subTest(field=field):
                f=Fixture()
                try:
                    def corrupt(raw):
                        reply=ledger.strict(f.transport('issuer')(raw))
                        if field=='signature':reply['signature']='0'*128
                        else:
                            reply['statement'][field]=({'revision':1,'attempts':[]} if field=='snapshot' else 'f'*64)
                            reply['signature']=f.key.sign(ledger.DOMAIN+ledger.canonical(reply['statement'])).hex()
                        return ledger.canonical(reply)
                    self.assert_stop(lambda:f.reserve(transport=corrupt))
                    self.assertEqual(f.effects,[])
                    self.assertEqual(len(f.calls),1)
                finally:f.close()

    def test_bad_mutation_signature_after_commit_still_burns_attempt(self):
        f=self.f
        def corrupt(raw):
            reply=ledger.strict(f.transport('issuer')(raw))
            if ledger.strict(raw)['action']=='reserve':reply['signature']='0'*128
            return ledger.canonical(reply)
        self.assert_stop(lambda:f.reserve(transport=corrupt))
        self.assertEqual(f.snapshot()['revision'],1);self.assertEqual(f.effects,[])
        before=len(f.calls);self.assert_stop(lambda:f.reserve())
        self.assertEqual(len(f.calls),before)

    def test_readonly_receipt_cannot_substitute_for_mutation(self):
        f=self.f;view=[]
        def substitute(raw):
            reply=f.transport('issuer')(raw)
            if ledger.strict(raw)['action']=='view':view.append(reply);return reply
            return view[0]
        self.assert_stop(lambda:f.reserve(transport=substitute))
        self.assertEqual(f.snapshot()['revision'],1);self.assertEqual(f.effects,[])

    def test_wrong_authenticated_role_stops_without_effect(self):
        f=self.f
        self.assert_stop(lambda:f.reserve(transport=f.transport('custody')))
        self.assertEqual(f.snapshot()['revision'],0);self.assertEqual(f.effects,[])

    def test_revision_conflict_stops_without_automatic_refresh_or_retry(self):
        f=self.f
        def race(raw):
            if ledger.strict(raw)['action']=='reserve':
                ledger.LedgerClient(f.binding,f.public,f.transport('issuer')).exchange('reserve',0,'B0','a'*64)
            return f.transport('issuer')(raw)
        self.assert_stop(lambda:f.reserve(transport=race))
        self.assertEqual(f.effects,[])
        snapshot=f.snapshot()
        self.assertEqual(snapshot['revision'],1)
        self.assertEqual([r['operation_id'] for r in snapshot['attempts']],['B0'])
        self.assertEqual(len([c for c in f.calls if c['operation_id']=='A0']),1)

    def test_admission_mutation_of_grant_is_rejected(self):
        f=self.f;g=f.grant()
        def mutate():g['statement']['output_cap']=999
        self.assert_stop(lambda:f.consume(g,admit=mutate))
        self.assertEqual(f.calls,[]);self.assertFalse(f.slot('custody').exists())

    def test_real_grant_signature_refusal_in_trusted_admission(self):
        f=self.f;g=f.grant();g['signature']='0'*128
        def verify():
            f.issuer_key.public_key().verify(bytes.fromhex(g['signature']),DOMAIN+ledger.canonical(g['statement']))
        self.assert_stop(lambda:f.consume(g,admit=verify))
        self.assertEqual(f.calls,[]);self.assertFalse(f.slot('custody').exists())

    def test_receipt_write_failure_prevents_callback_after_commit(self):
        f=self.f;original=gate._write
        def write(fd,name,value):
            if name=='verified-receipts.json':raise OSError('disk full')
            return original(fd,name,value)
        with patch.object(gate,'_write',side_effect=write):self.assert_stop(lambda:f.reserve())
        self.assertEqual(f.snapshot()['revision'],1);self.assertEqual(f.effects,[])
        self.assert_stop(lambda:f.reserve())

    def test_intent_write_failure_leaves_burned_empty_slot_before_network(self):
        f=self.f
        with patch.object(gate,'_write',side_effect=OSError('disk full')):self.assert_stop(lambda:f.reserve())
        self.assertTrue(f.slot().is_dir());self.assertEqual(f.calls,[])
        self.assert_stop(lambda:f.reserve());self.assertEqual(f.calls,[])

    def test_fsync_failure_before_network_does_not_continue(self):
        f=self.f
        with patch.object(gate.os,'fsync',side_effect=OSError('fsync failed')):self.assert_stop(lambda:f.reserve())
        self.assertEqual(f.calls,[]);self.assertTrue(f.slot().is_dir())
        self.assert_stop(lambda:f.reserve());self.assertEqual(f.calls,[])

    def test_callback_failure_does_not_clear_intent_or_allow_reissue(self):
        f=self.f
        def fail(snapshot):f.effects.append('attempted');raise RuntimeError('secret response')
        self.assert_stop(lambda:f.reserve(effect=fail))
        self.assertEqual(f.effects,['attempted']);self.assertTrue((f.slot()/'verified-receipts.json').exists())
        self.assertFalse((f.slot()/'effect-returned.json').exists())
        self.assert_stop(lambda:f.reserve());self.assertEqual(f.effects,['attempted'])

    def test_result_record_failure_is_unknown_not_zero_callback(self):
        f=self.f;original=gate._write
        def write(fd,name,value):
            if name=='effect-returned.json':raise OSError('disk full')
            return original(fd,name,value)
        with patch.object(gate,'_write',side_effect=write):self.assert_stop(lambda:f.reserve())
        self.assertEqual(f.effects,['issue']);self.assert_stop(lambda:f.reserve())
        self.assertEqual(f.effects,['issue'])

    def test_existing_partial_slot_blocks_before_network(self):
        f=self.f;f.slot().mkdir(mode=0o700)
        self.assert_stop(lambda:f.reserve());self.assertEqual(f.calls,[])

    def test_missing_or_changed_enrollment_does_not_recreate(self):
        f=self.f;client=f.client();path=f.base/'issuer'/gate.ENROLLMENT_FILE
        for raw in (b'broken',b'{}'):
            path.write_bytes(raw);self.assert_stop(lambda:client.execute(operation='A0',wire=f.wire,admit=f.admit,effect=lambda _:None))
        path.unlink();self.assert_stop(lambda:f.client())
        self.assertFalse(path.exists());self.assertEqual(f.calls,[])

    def test_same_bytes_replacement_directory_is_not_same_enrollment(self):
        f=self.f;client=f.client();old=f.base/'issuer';moved=f.base/'moved';old.rename(moved)
        old.mkdir(mode=0o700);record=old/gate.ENROLLMENT_FILE
        record.write_bytes((moved/gate.ENROLLMENT_FILE).read_bytes());record.chmod(0o600)
        self.assert_stop(lambda:client.execute(operation='A0',wire=f.wire,admit=f.admit,effect=lambda _:None))
        self.assertEqual(f.calls,[])

    def test_symlink_or_unsafe_enrollment_is_denied(self):
        f=self.f;record=f.base/'issuer'/gate.ENROLLMENT_FILE
        original=record.read_bytes();target=f.base/'other.json';target.write_bytes(original);target.chmod(0o600)
        record.unlink();record.symlink_to(target);self.assert_stop(lambda:f.client())
        record.unlink();record.write_bytes(original);record.chmod(0o644)
        self.assert_stop(lambda:f.client());self.assertEqual(f.calls,[])

    def test_wrong_public_pin_and_binding_fail_before_network(self):
        f=self.f
        self.assert_stop(lambda:gate.NativeLedgerGate(f.enrollments['issuer'],b'x'*32,f.transport('issuer')))
        changed=copy.deepcopy(f.enrollments['issuer']);changed['binding']['run_id']='f'*64
        self.assert_stop(lambda:gate.NativeLedgerGate(changed,f.public,f.transport('issuer')))
        self.assertEqual(f.calls,[])

    def test_service_signer_must_differ_from_role_keys(self):
        f=self.f;e=copy.deepcopy(f.enrollments['issuer'])
        e['service_public_sha256']=e['binding']['issuer_public_sha256']
        self.assert_stop(lambda:gate.NativeLedgerGate(e,f.issuer_key.public_key().public_bytes_raw()))

    def test_journal_directory_permissions_are_not_repaired(self):
        f=self.f;(f.base/'issuer').chmod(0o755)
        self.assert_stop(lambda:f.client())
        self.assertEqual((f.base/'issuer').stat().st_mode&0o777,0o755)

    def test_invalid_inputs_do_not_claim(self):
        f=self.f
        for op,wire in [('A9',b'x'),('A0',b''),('A0',b'x'*64001),('A0','text')]:
            with self.subTest(op=op,kind=type(wire).__name__):
                self.assert_stop(lambda:f.client().execute(operation=op,wire=wire,admit=f.admit,effect=lambda _:None))
        self.assertEqual(f.calls,[]);self.assertFalse(f.slot().exists())

    def test_thread_race_has_one_mutation_and_callback(self):
        f=self.f;barrier=Barrier(2)
        def worker():
            barrier.wait(5)
            try:f.reserve()
            except gate.GateDenied:return 'stop'
            return 'issued'
        with ThreadPoolExecutor(2) as pool:result=list(pool.map(lambda _:worker(),range(2)))
        self.assertEqual(sorted(result),['issued','stop']);self.assertEqual(f.effects,['issue'])
        self.assertEqual([c['action'] for c in f.calls],['view','reserve'])

    def test_two_processes_cannot_both_claim_same_slot(self):
        f=self.f;ctx=multiprocessing.get_context('fork');start=ctx.Event();queue=ctx.Queue()
        jobs=[ctx.Process(target=process_racer,args=(f.enrollments['issuer'],f.public,f.service,f.binding,start,queue)) for _ in range(2)]
        for job in jobs:job.start()
        start.set()
        try:
            answers=[queue.get(timeout=10) for _ in jobs]
            for job in jobs:job.join(10);self.assertEqual(job.exitcode,0)
            self.assertEqual(sorted(answers),['issued','stop']);self.assertEqual(f.snapshot()['revision'],1)
        finally:
            for job in jobs:
                if job.is_alive():job.kill();job.join()
            queue.close()

    def test_fresh_process_changed_cwd_cannot_repeat_consumed_slot(self):
        f=self.f;f.reserve()
        program='''
import json,sys
from scripts.task4_native_signed_ledger_gate_v1 import NativeLedgerGate,GateDenied
v=json.load(sys.stdin)
def no_network(raw):raise AssertionError('MUST_NOT_REACH_TRANSPORT')
try:NativeLedgerGate(v['enrollment'],bytes.fromhex(v['public']),no_network).execute(operation='A0',wire=b'changed bytes',admit=lambda:None,effect=lambda _:sys.exit(9))
except GateDenied:print('STOP_BEFORE_TRANSPORT')
else:sys.exit(8)
'''
        env=dict(os.environ);env['PYTHONPATH']=str(Path(gate.__file__).resolve().parents[1])
        result=subprocess.run([sys.executable,'-c',program],cwd=f.base,env=env,text=True,
            input=json.dumps(dict(enrollment=f.enrollments['issuer'],public=f.public.hex())),
            capture_output=True,timeout=15,check=True)
        self.assertEqual(result.stdout.strip(),'STOP_BEFORE_TRANSPORT')
        self.assertEqual(result.stderr,'')

    def crash_child(self,role,stage,grant=None):
        f=self.f
        program='''
import json,os,sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from scripts import task4_external_ledger_contract_v1 as l
from scripts.task4_native_signed_ledger_gate_v1 import NativeLedgerGate
v=json.load(sys.stdin);role=v['enrollment']['role']
service=l.ReferenceService(v['file'],v['binding']['ledger_id'],Ed25519PrivateKey.from_private_bytes(bytes.fromhex(v['test_key'])))
checks=[]
def transport(raw):
 reply=service.exchange(raw,v['binding'][role+'_public_sha256'])
 if v['stage']=='after-reserve-commit' and l.strict(raw)['action']=='reserve':os._exit(73)
 return reply
def admit():
 checks.append(1)
 if v['stage']=='after-consume-receipt' and len(checks)==2:os._exit(74)
def forbidden(snapshot):os._exit(99)
NativeLedgerGate(v['enrollment'],bytes.fromhex(v['public']),transport).execute(operation='A0',wire=bytes.fromhex(v['wire']),grant=v['grant'],admit=admit,effect=forbidden)
sys.exit(98)
'''
        env=dict(os.environ);env['PYTHONPATH']=str(Path(gate.__file__).resolve().parents[1])
        value=dict(enrollment=f.enrollments[role],public=f.public.hex(),file=str(f.service.file),
            binding=f.binding,test_key=f.key.private_bytes_raw().hex(),wire=f.wire.hex(),grant=grant,stage=stage)
        return subprocess.run([sys.executable,'-c',program],cwd=f.base,env=env,text=True,
            input=json.dumps(value),capture_output=True,timeout=15)

    def test_abrupt_process_exit_after_reserve_commit_retains_intent(self):
        f=self.f;result=self.crash_child('issuer','after-reserve-commit')
        self.assertEqual(result.returncode,73)
        self.assertEqual(result.stdout+result.stderr,'')
        self.assertEqual(f.snapshot()['revision'],1)
        self.assertTrue((f.slot()/'intent.json').exists())
        self.assertFalse((f.slot()/'verified-receipts.json').exists())
        before=len(f.calls);self.assert_stop(lambda:f.reserve())
        self.assertEqual(len(f.calls),before);self.assertEqual(f.effects,[])

    def test_abrupt_process_exit_after_consume_receipt_cannot_send_on_restart(self):
        f=self.f;g=f.reserve();result=self.crash_child('custody','after-consume-receipt',g)
        self.assertEqual(result.returncode,74)
        self.assertEqual(result.stdout+result.stderr,'')
        self.assertEqual(f.snapshot()['revision'],2)
        self.assertTrue((f.slot('custody')/'verified-receipts.json').exists())
        self.assertFalse((f.slot('custody')/'effect-returned.json').exists())
        before=len(f.calls);self.assert_stop(lambda:f.consume(g))
        self.assertEqual(len(f.calls),before);self.assertEqual(f.effects,['issue'])


if __name__ == '__main__':
    unittest.main()
