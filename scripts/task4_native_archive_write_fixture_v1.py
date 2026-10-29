"""Selected synthetic write/flush errors around the frozen original archive call.

The real buffered file is exclusively opened and closed; partial bytes remain.
Close-time flushing is observed, never promoted to a successful explicit flush,
fsync acknowledgement, raw response delivery or retry permission.
"""
import base64
import errno
import os
from pathlib import Path
import stat
import time
from unittest.mock import patch
from scripts import task4_native_archive_fault_fixture_v1 as old
m,n,u,e,ingress,need=old.m,old.n,old.u,old.e,old.ingress,old.need
MODES=('partial-write-error','flush-failure')
NORMAL_PHASES=('SEAL_ENTER','ENCRYPT_BEGIN','ENCRYPT_DONE','FILE_OPEN','WRITE_BEGIN','WRITE_DONE',
    'FLUSH_BEGIN','FLUSH_DONE','FILE_FSYNC_BEGIN','FILE_FSYNC_DONE','CLOSE_BEGIN','CLOSE_DONE',
    'DIRECTORY_FSYNC_BEGIN','DIRECTORY_FSYNC_DONE','SEAL_RETURN')
identity=old.identity
validate_snapshot=old.validate_snapshot


def source_sha256():
    need(old.source_sha256()=='937b0249c4df532703c1e79959e5b4b3e9c58544c48f9bfad4fd1fbf135f0fc9')
    return e.sha(Path(__file__).read_bytes())


def snapshot(base,slot):
    need(slot in {a+str(i) for a in 'AB' for i in range(4)})
    folder=base/'custody/archives';directory=folder.lstat();need(stat.S_ISDIR(directory.st_mode))
    file=folder/(slot+'.enc.json')
    try:info=file.lstat()
    except FileNotFoundError:return dict(directory=identity(directory),exists=False)
    need(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_uid==n.CUSTODY
         and stat.S_IMODE(info.st_mode)==0o600 and 0<=info.st_size<=1048576)
    fd=os.open(file,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        need(identity(os.fstat(fd))==identity(info))
        blob=os.read(fd,1048577);need(len(blob)==info.st_size and identity(os.fstat(fd))==identity(info))
    finally:os.close(fd)
    return dict(directory=identity(directory),exists=True,file=identity(info),blob_b64=n.encode(blob),blob_sha256=e.sha(blob))


def audit_seal(original,base,slot,wire,completion,plan,fault,emit):
    from cryptography.hazmat.primitives.ciphers import aead
    need(fault=='normal' or fault in MODES);n.kernel.role_identity(n.CUSTODY)
    real_encryptor,real_open,real_fsync=aead.AESGCM,Path.open,os.fsync
    target=base/'custody/archives'/(slot+'.enc.json');folder=target.parent
    def event(phase,**data):emit(dict(op=slot,phase=phase,uid=os.geteuid(),namespace=e.namespace(),at_ns=time.monotonic_ns(),**data))
    event('SEAL_ENTER',fault=fault,raw_sha256=e.sha(wire),observed_bytes=len(wire),capture_completion=completion,before=snapshot(base,slot))
    class Encryptor:
        def __init__(self,key):self.impl=real_encryptor(key)
        def encrypt(self,nonce,data,aad):
            event('ENCRYPT_BEGIN',raw_sha256=e.sha(data),aad_sha256=e.sha(aad))
            encrypted=self.impl.encrypt(nonce,data,aad)
            event('ENCRYPT_DONE',ciphertext_sha256=e.sha(encrypted),ciphertext_bytes=len(encrypted))
            return encrypted
    class ArchiveFile:
        def __init__(self,stream):self.stream=stream
        def __enter__(self):self.stream.__enter__();return self
        def __exit__(self,cls,error,tb):
            try:event('CLOSE_BEGIN',error_class=None if cls is None else cls.__name__,error_errno=getattr(error,'errno',None))
            finally:result=self.stream.__exit__(cls,error,tb)
            event('CLOSE_DONE',closed=self.stream.closed,snapshot=snapshot(base,slot))
            return result
        def fileno(self):return self.stream.fileno()
        def write(self,blob):
            event('WRITE_BEGIN',blob_b64=n.encode(blob),blob_sha256=e.sha(blob),blob_bytes=len(blob))
            if fault=='partial-write-error':
                prefix=blob[:len(blob)//2];count=self.stream.write(prefix)
                need(count==len(prefix))
                event('WRITE_PREFIX',written_bytes=count,written_sha256=e.sha(prefix))
                event('FAULT_INJECTED',boundary='write',error_class='OSError',error_errno=errno.ENOSPC)
                raise OSError(errno.ENOSPC,'SYNTHETIC_PARTIAL_ARCHIVE_WRITE')
            count=self.stream.write(blob);event('WRITE_DONE',written_bytes=count);return count
        def flush(self):
            event('FLUSH_BEGIN')
            if fault=='flush-failure':
                event('FAULT_INJECTED',boundary='flush',error_class='OSError',error_errno=errno.EIO)
                raise OSError(errno.EIO,'SYNTHETIC_ARCHIVE_EXPLICIT_FLUSH')
            result=self.stream.flush();event('FLUSH_DONE');return result
    def opened(path,mode='r',*args,**kwargs):
        stream=real_open(path,mode,*args,**kwargs)
        if path!=target or mode!='xb':return stream
        try:event('FILE_OPEN',descriptor=identity(os.fstat(stream.fileno())))
        except BaseException:stream.close();raise
        return ArchiveFile(stream)
    def sync(fd):
        info=os.fstat(fd);kind=None
        if stat.S_ISDIR(info.st_mode) and (info.st_dev,info.st_ino)==(folder.stat().st_dev,folder.stat().st_ino):kind='DIRECTORY'
        elif stat.S_ISREG(info.st_mode):
            try:expected=target.lstat()
            except FileNotFoundError:expected=None
            if expected is not None and (info.st_dev,info.st_ino)==(expected.st_dev,expected.st_ino):kind='FILE'
        if kind is None:return real_fsync(fd)
        event(kind+'_FSYNC_BEGIN',descriptor=identity(info));result=real_fsync(fd)
        event(kind+'_FSYNC_DONE',descriptor=identity(os.fstat(fd)));return result
    def restored():return aead.AESGCM is real_encryptor and Path.open is real_open and os.fsync is real_fsync
    try:
        with patch.object(aead,'AESGCM',Encryptor),patch.object(Path,'open',opened),patch.object(os,'fsync',sync):
            archive=original(base,slot,wire,completion,plan)
    except Exception as error:
        event('SEAL_EXCEPTION',error_class=type(error).__name__,error_errno=getattr(error,'errno',None),snapshot=snapshot(base,slot),functions_restored=restored())
        raise
    event('SEAL_RETURN',archive=archive,snapshot=snapshot(base,slot),functions_restored=restored())
    return archive


def validate_audit(events,wire,plan,slot,fault,namespace,final):
    need(fault=='normal' or fault in MODES)
    phases=list(NORMAL_PHASES) if fault=='normal' else (
        ['SEAL_ENTER','ENCRYPT_BEGIN','ENCRYPT_DONE','FILE_OPEN','WRITE_BEGIN','WRITE_PREFIX','FAULT_INJECTED','CLOSE_BEGIN','CLOSE_DONE','SEAL_EXCEPTION']
        if fault=='partial-write-error' else
        ['SEAL_ENTER','ENCRYPT_BEGIN','ENCRYPT_DONE','FILE_OPEN','WRITE_BEGIN','WRITE_DONE','FLUSH_BEGIN','FAULT_INJECTED','CLOSE_BEGIN','CLOSE_DONE','SEAL_EXCEPTION'])
    need(type(events) is list and [x['phase'] for x in events]==phases)
    common={'op','phase','uid','namespace','at_ns'}
    extra={'SEAL_ENTER':{'fault','raw_sha256','observed_bytes','capture_completion','before'},
        'ENCRYPT_BEGIN':{'raw_sha256','aad_sha256'},'ENCRYPT_DONE':{'ciphertext_sha256','ciphertext_bytes'},
        'FILE_OPEN':{'descriptor'},'WRITE_BEGIN':{'blob_b64','blob_sha256','blob_bytes'},'WRITE_DONE':{'written_bytes'},
        'WRITE_PREFIX':{'written_bytes','written_sha256'},'FLUSH_BEGIN':set(),'FLUSH_DONE':set(),
        'FILE_FSYNC_BEGIN':{'descriptor'},'FILE_FSYNC_DONE':{'descriptor'},'DIRECTORY_FSYNC_BEGIN':{'descriptor'},'DIRECTORY_FSYNC_DONE':{'descriptor'},
        'FAULT_INJECTED':{'boundary','error_class','error_errno'},'CLOSE_BEGIN':{'error_class','error_errno'},'CLOSE_DONE':{'closed','snapshot'},
        'SEAL_EXCEPTION':{'error_class','error_errno','snapshot','functions_restored'},'SEAL_RETURN':{'archive','snapshot','functions_restored'}}
    last=0
    for row in events:
        need(set(row)==common|extra[row['phase']] and row['op']==slot and type(row['uid']) is int and row['uid']==n.CUSTODY
            and row['namespace']==namespace and type(row['at_ns']) is int and row['at_ns']>0 and row['at_ns']>=last);last=row['at_ns']
    first,finish=events[0],events[-1];validate_snapshot(first['before'],False,0o700);validate_snapshot(final,True,0o700)
    need(first['fault']==fault and first['raw_sha256']==e.sha(wire) and type(first['observed_bytes']) is int and first['observed_bytes']==len(wire)
        and first['capture_completion']=='eof' and finish['functions_restored'] is True and finish['snapshot']==final)
    stable=lambda row:{k:v for k,v in row.items() if k!='size'}
    need(stable(first['before']['directory'])==stable(final['directory']))
    header=dict(schema='task4.closed-raw-http-envelope.v1',run_id=plan['run_id'],slot=slot,request_sha256=plan['request_sha256'],
        recipient_sha256=plan['recipient_sha256'],raw_sha256=e.sha(wire),observed_bytes=len(wire),capture_completion='eof',origin='CLOSED_LOCAL_TLS_NOT_PUBLIC_PROVIDER')
    need(events[1]['raw_sha256']==e.sha(wire) and events[1]['aad_sha256']==e.sha(n.canonical(header)))
    start=events[4];blob=n.decode(start['blob_b64'])
    need(type(start['blob_bytes']) is int and start['blob_bytes']==len(blob) and start['blob_sha256']==e.sha(blob))
    value=ingress.raw.strict(blob);need(set(value)=={'header','ephemeral','nonce','ciphertext'} and value['header']==header
        and len(bytes.fromhex(value['ephemeral']))==32 and len(bytes.fromhex(value['nonce']))==12)
    encrypted=base64.b64decode(value['ciphertext'],validate=True)
    need(len(encrypted)==len(wire)+16 and type(events[2]['ciphertext_bytes']) is int and events[2]['ciphertext_bytes']==len(encrypted)
        and events[2]['ciphertext_sha256']==e.sha(encrypted))
    need(stable(events[3]['descriptor'])==stable(final['file']) and events[3]['descriptor']['size']==0)
    expected=blob[:len(blob)//2] if fault=='partial-write-error' else blob
    need(n.decode(final['blob_b64'])==expected)
    written=events[5];need(type(written['written_bytes']) is int and written['written_bytes']==len(expected))
    if fault=='partial-write-error':need(written['written_sha256']==e.sha(expected))
    close=next(x for x in events if x['phase']=='CLOSE_BEGIN');closed=next(x for x in events if x['phase']=='CLOSE_DONE')
    need(closed['closed'] is True and closed['snapshot']==final)
    if fault=='normal':
        need(close['error_class'] is None and close['error_errno'] is None
            and finish['archive']==dict(header,envelope_sha256=final['blob_sha256'],local_fsync_completed=True))
    else:
        number=errno.ENOSPC if fault=='partial-write-error' else errno.EIO
        injection=next(x for x in events if x['phase']=='FAULT_INJECTED')
        need(injection==dict({k:injection[k] for k in common},boundary='write' if fault=='partial-write-error' else 'flush',error_class='OSError',error_errno=number))
        need(finish['error_class']==close['error_class']=='OSError' and type(finish['error_errno']) is int
             and finish['error_errno']==close['error_errno']==number)
    for row in events:
        if row['phase'].startswith('FILE_FSYNC'):need(row['descriptor']==final['file'])
        elif row['phase'].startswith('DIRECTORY_FSYNC'):need(row['descriptor']==final['directory'])
    return True
