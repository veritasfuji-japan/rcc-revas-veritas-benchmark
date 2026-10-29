"""Scoped synthetic archive faults around the original encryption/fsync routine.

Only archive descriptors and the one AESGCM call are observed/injected. A visible
file or decryptable ciphertext is never promoted to a durability acknowledgement.
"""
import errno
import os
from pathlib import Path
import stat
import time
from unittest.mock import patch
from scripts import task4_native_bounded_unix_egress_v1 as m
n,u,e,ingress=m.n,m.u,m.e,m.ingress
need=m.need
MODES=('encrypt-failure','create-denied','file-fsync-failure','directory-fsync-failure')


def source_sha256():return e.sha(Path(__file__).read_bytes())


def identity(info):
    return dict(device=info.st_dev,inode=info.st_ino,uid=info.st_uid,gid=info.st_gid,
        mode=stat.S_IMODE(info.st_mode),links=info.st_nlink,size=info.st_size)


def snapshot(base,slot):
    need(slot in {a+str(i) for a in 'AB' for i in range(4)})
    folder=base/'custody/archives';directory=folder.lstat();need(stat.S_ISDIR(directory.st_mode))
    file=folder/(slot+'.enc.json')
    try:info=file.lstat()
    except FileNotFoundError:return dict(directory=identity(directory),exists=False)
    need(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_uid==n.CUSTODY
         and stat.S_IMODE(info.st_mode)==0o600 and 0<info.st_size<=1048576)
    fd=os.open(file,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        need(identity(os.fstat(fd))==identity(info))
        blob=os.read(fd,1048577);need(len(blob)==info.st_size and identity(os.fstat(fd))==identity(info))
    finally:os.close(fd)
    return dict(directory=identity(directory),exists=True,file=identity(info),blob_b64=n.encode(blob),blob_sha256=e.sha(blob))


def audit_seal(original,base,slot,wire,completion,plan,fault,emit):
    from cryptography.hazmat.primitives.ciphers import aead
    need(fault=='normal' or fault in MODES);n.kernel.role_identity(n.CUSTODY)
    real_encryptor=aead.AESGCM;real_fsync=os.fsync
    def event(phase,**data):emit(dict(op=slot,phase=phase,uid=os.geteuid(),namespace=e.namespace(),at_ns=time.monotonic_ns(),**data))
    event('SEAL_ENTER',fault=fault,raw_sha256=e.sha(wire),observed_bytes=len(wire),capture_completion=completion,before=snapshot(base,slot))
    class Encryptor:
        def __init__(self,key):self.impl=real_encryptor(key)
        def encrypt(self,nonce,data,aad):
            event('ENCRYPT_BEGIN',raw_sha256=e.sha(data),aad_sha256=e.sha(aad))
            if fault=='encrypt-failure':
                event('FAULT_INJECTED',boundary='encrypt',error_class='ValueError',error_errno=None)
                raise ValueError('SYNTHETIC_ARCHIVE_ENCRYPT_FAILURE')
            encrypted=self.impl.encrypt(nonce,data,aad)
            event('ENCRYPT_DONE',ciphertext_sha256=e.sha(encrypted),ciphertext_bytes=len(encrypted))
            return encrypted
    def sync(fd):
        info=os.fstat(fd);folder=base/'custody/archives';file=folder/(slot+'.enc.json')
        target=None
        if stat.S_ISDIR(info.st_mode) and (info.st_dev,info.st_ino)==(folder.stat().st_dev,folder.stat().st_ino):target='DIRECTORY'
        elif stat.S_ISREG(info.st_mode):
            try:expected=file.lstat()
            except FileNotFoundError:expected=None
            if expected is not None and (info.st_dev,info.st_ino)==(expected.st_dev,expected.st_ino):target='FILE'
        if target is None:return real_fsync(fd)
        event(target+'_FSYNC_BEGIN',descriptor=identity(info))
        wanted='file-fsync-failure' if target=='FILE' else 'directory-fsync-failure'
        if fault==wanted:
            event('FAULT_INJECTED',boundary=target.lower()+'_fsync',error_class='OSError',error_errno=errno.EIO)
            raise OSError(errno.EIO,'SYNTHETIC_ARCHIVE_FSYNC_FAILURE')
        result=real_fsync(fd);event(target+'_FSYNC_DONE',descriptor=identity(os.fstat(fd)));return result
    try:
        with patch.object(aead,'AESGCM',Encryptor),patch.object(os,'fsync',sync):
            archive=original(base,slot,wire,completion,plan)
    except Exception as error:
        event('SEAL_EXCEPTION',error_class=type(error).__name__,error_errno=getattr(error,'errno',None),
            snapshot=snapshot(base,slot),functions_restored=aead.AESGCM is real_encryptor and os.fsync is real_fsync)
        raise
    event('SEAL_RETURN',archive=archive,snapshot=snapshot(base,slot),functions_restored=aead.AESGCM is real_encryptor and os.fsync is real_fsync)
    return archive


def validate_snapshot(value,exists,directory_mode):
    need(type(value) is dict and value['exists'] is exists)
    expected={'directory','exists','file','blob_b64','blob_sha256'} if exists else {'directory','exists'}
    need(set(value)==expected)
    def check(row,mode):
        need(set(row)=={'device','inode','uid','gid','mode','links','size'}
             and all(type(x) is int and x>=0 for x in row.values())
             and row['inode']>0 and row['uid']==n.CUSTODY and row['mode']==mode and row['links']>=1)
    check(value['directory'],directory_mode)
    if exists:
        check(value['file'],0o600);blob=n.decode(value['blob_b64'])
        need(value['file']['links']==1 and value['file']['size']==len(blob)>0 and value['blob_sha256']==e.sha(blob))
    return True


def validate_audit(events,wire,plan,slot,fault,namespace,final):
    need(fault=='normal' or fault in MODES)
    phases={'normal':['SEAL_ENTER','ENCRYPT_BEGIN','ENCRYPT_DONE','FILE_FSYNC_BEGIN','FILE_FSYNC_DONE','DIRECTORY_FSYNC_BEGIN','DIRECTORY_FSYNC_DONE','SEAL_RETURN'],
        'encrypt-failure':['SEAL_ENTER','ENCRYPT_BEGIN','FAULT_INJECTED','SEAL_EXCEPTION'],
        'create-denied':['SEAL_ENTER','ENCRYPT_BEGIN','ENCRYPT_DONE','SEAL_EXCEPTION'],
        'file-fsync-failure':['SEAL_ENTER','ENCRYPT_BEGIN','ENCRYPT_DONE','FILE_FSYNC_BEGIN','FAULT_INJECTED','SEAL_EXCEPTION'],
        'directory-fsync-failure':['SEAL_ENTER','ENCRYPT_BEGIN','ENCRYPT_DONE','FILE_FSYNC_BEGIN','FILE_FSYNC_DONE','DIRECTORY_FSYNC_BEGIN','FAULT_INJECTED','SEAL_EXCEPTION']}[fault]
    need(type(events) is list and [x['phase'] for x in events]==phases)
    common={'op','phase','uid','namespace','at_ns'};last=0
    extra={'SEAL_ENTER':{'fault','raw_sha256','observed_bytes','capture_completion','before'},
        'ENCRYPT_BEGIN':{'raw_sha256','aad_sha256'},'ENCRYPT_DONE':{'ciphertext_sha256','ciphertext_bytes'},
        'FILE_FSYNC_BEGIN':{'descriptor'},'FILE_FSYNC_DONE':{'descriptor'},'DIRECTORY_FSYNC_BEGIN':{'descriptor'},'DIRECTORY_FSYNC_DONE':{'descriptor'},
        'FAULT_INJECTED':{'boundary','error_class','error_errno'},'SEAL_EXCEPTION':{'error_class','error_errno','snapshot','functions_restored'},
        'SEAL_RETURN':{'archive','snapshot','functions_restored'}}
    for row in events:
        need(set(row)==common|extra[row['phase']] and row['op']==slot and row['uid']==n.CUSTODY and row['namespace']==namespace
             and type(row['at_ns']) is int and row['at_ns']>0 and row['at_ns']>=last);last=row['at_ns']
    directory_mode=0o500 if fault=='create-denied' else 0o700
    first,finish=events[0],events[-1]
    validate_snapshot(first['before'],False,directory_mode)
    need(first['fault']==fault and first['raw_sha256']==e.sha(wire) and first['observed_bytes']==len(wire)
         and first['capture_completion']=='eof' and finish['functions_restored'] is True and finish['snapshot']==final)
    exists=fault in ('normal','file-fsync-failure','directory-fsync-failure')
    validate_snapshot(final,exists,directory_mode)
    need({k:v for k,v in first['before']['directory'].items() if k!='size'}=={k:v for k,v in final['directory'].items() if k!='size'})
    header=dict(schema='task4.closed-raw-http-envelope.v1',run_id=plan['run_id'],slot=slot,
        request_sha256=plan['request_sha256'],recipient_sha256=plan['recipient_sha256'],raw_sha256=e.sha(wire),
        observed_bytes=len(wire),capture_completion='eof',origin='CLOSED_LOCAL_TLS_NOT_PUBLIC_PROVIDER')
    need(events[1]['raw_sha256']==e.sha(wire) and events[1]['aad_sha256']==e.sha(n.canonical(header)))
    if fault!='normal':
        cls,number=('ValueError',None) if fault=='encrypt-failure' else ('PermissionError',errno.EACCES) if fault=='create-denied' else ('OSError',errno.EIO)
        need(finish['error_class']==cls and finish['error_errno']==number)
        if fault!='create-denied':
            injection=events[-2];boundary='encrypt' if fault=='encrypt-failure' else 'file_fsync' if fault=='file-fsync-failure' else 'directory_fsync'
            need(injection['boundary']==boundary and injection['error_class']==cls and injection['error_errno']==number)
    if fault!='encrypt-failure':
        encrypted=events[2];need(type(encrypted['ciphertext_bytes']) is int and encrypted['ciphertext_bytes']==len(wire)+16
            and type(encrypted['ciphertext_sha256']) is str and len(bytes.fromhex(encrypted['ciphertext_sha256']))==32)
    for row in events:
        if row['phase'].startswith('FILE_FSYNC'):need(row['descriptor']==final['file'])
        elif row['phase'].startswith('DIRECTORY_FSYNC'):need(row['descriptor']==final['directory'])
    if exists:
        blob=ingress.raw.strict(n.decode(final['blob_b64']));need(set(blob)=={'header','ephemeral','nonce','ciphertext'} and blob['header']==header
             and len(bytes.fromhex(blob['ephemeral']))==32 and len(bytes.fromhex(blob['nonce']))==12)
        import base64
        encrypted=base64.b64decode(blob['ciphertext'],validate=True)
        need(len(encrypted)==len(wire)+16 and events[2]['ciphertext_sha256']==e.sha(encrypted))
        if fault=='normal':need(finish['archive']==dict(header,envelope_sha256=final['blob_sha256'],local_fsync_completed=True))
    return True
