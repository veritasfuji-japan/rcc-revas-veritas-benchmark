"""Selected synthetic close errors around the frozen original archive call.

Both selected errors follow real write, explicit flush and archive-file fsync.
A pre-release error has explicit fixture-only descriptor cleanup. Neither that
cleanup nor a released descriptor supplies successful seal acknowledgement.
"""
import base64
import errno
import os
from pathlib import Path
import stat
import time
from unittest.mock import patch
from scripts import task4_native_archive_write_fixture_v1 as old
m,n,u,e,ingress,need=old.m,old.n,old.u,old.e,old.ingress,old.need
MODES=('close-before-release','close-after-release')
NORMAL_PHASES=('SEAL_ENTER','ENCRYPT_BEGIN','ENCRYPT_DONE','FILE_OPEN','WRITE_BEGIN','WRITE_DONE',
    'FLUSH_BEGIN','FLUSH_DONE','FILE_FSYNC_BEGIN','FILE_FSYNC_DONE','CLOSE_BEGIN','CLOSE_DONE',
    'DIRECTORY_FSYNC_BEGIN','DIRECTORY_FSYNC_DONE','SEAL_RETURN')
identity=old.identity
validate_snapshot=old.validate_snapshot


def source_sha256():
    need(old.source_sha256()=='743c592757a5137071597d98047be6384ef4ef1ecc916f3d430c7632dc8d34ac')
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
            fd=self.stream.fileno()
            def state():
                try:os.fstat(fd)
                except OSError as caught:
                    need(caught.errno==errno.EBADF)
                    return dict(closed=self.stream.closed,descriptor_closed=True,descriptor_errno=caught.errno,snapshot=snapshot(base,slot))
                return dict(closed=self.stream.closed,descriptor_closed=False,descriptor_errno=None,snapshot=snapshot(base,slot))
            def begin():event('CLOSE_BEGIN',error_class=None if cls is None else cls.__name__,error_errno=getattr(error,'errno',None),descriptor=identity(os.fstat(fd)),stream_closed=self.stream.closed)
            if fault=='close-before-release':
                try:
                    begin()
                    event('FAULT_INJECTED',boundary='close_before_release',error_class='OSError',error_errno=errno.EIO,
                        stream_closed=self.stream.closed,descriptor_closed=False,descriptor=identity(os.fstat(fd)))
                    raise OSError(errno.EIO,'SYNTHETIC_CLOSE_BEFORE_RELEASE')
                finally:
                    # Explicit fixture-only resource cleanup. Not another seal,
                    # successful original close acknowledgement or storage repair.
                    try:event('CLOSE_CLEANUP_BEGIN',reason='FIXTURE_FD_RELEASE_ONLY_NO_ACK',descriptor=identity(os.fstat(fd)))
                    finally:self.stream.__exit__(cls,error,tb)
                    event('CLOSE_CLEANUP_DONE',**state())
            try:begin()
            finally:result=self.stream.__exit__(cls,error,tb)
            released=state();event('CLOSE_DONE',**released)
            if fault=='close-after-release':
                event('FAULT_INJECTED',boundary='close_after_release',error_class='OSError',error_errno=errno.EIO,
                    stream_closed=released['closed'],descriptor_closed=released['descriptor_closed'],descriptor=None)
                raise OSError(errno.EIO,'SYNTHETIC_CLOSE_AFTER_RELEASE')
            return result
        def fileno(self):return self.stream.fileno()
        def write(self,blob):
            event('WRITE_BEGIN',blob_b64=n.encode(blob),blob_sha256=e.sha(blob),blob_bytes=len(blob))
            count=self.stream.write(blob);event('WRITE_DONE',written_bytes=count);return count
        def flush(self):
            event('FLUSH_BEGIN')
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
    phases=list(NORMAL_PHASES) if fault=='normal' else list(NORMAL_PHASES[:10])+(
        ['CLOSE_BEGIN','FAULT_INJECTED','CLOSE_CLEANUP_BEGIN','CLOSE_CLEANUP_DONE','SEAL_EXCEPTION']
        if fault=='close-before-release' else ['CLOSE_BEGIN','CLOSE_DONE','FAULT_INJECTED','SEAL_EXCEPTION'])
    need(type(events) is list and [x['phase'] for x in events]==phases)
    common={'op','phase','uid','namespace','at_ns'}
    extra={'SEAL_ENTER':{'fault','raw_sha256','observed_bytes','capture_completion','before'},
        'ENCRYPT_BEGIN':{'raw_sha256','aad_sha256'},'ENCRYPT_DONE':{'ciphertext_sha256','ciphertext_bytes'},
        'FILE_OPEN':{'descriptor'},'WRITE_BEGIN':{'blob_b64','blob_sha256','blob_bytes'},'WRITE_DONE':{'written_bytes'},
        'WRITE_PREFIX':{'written_bytes','written_sha256'},'FLUSH_BEGIN':set(),'FLUSH_DONE':set(),
        'FILE_FSYNC_BEGIN':{'descriptor'},'FILE_FSYNC_DONE':{'descriptor'},'DIRECTORY_FSYNC_BEGIN':{'descriptor'},'DIRECTORY_FSYNC_DONE':{'descriptor'},
        'FAULT_INJECTED':{'boundary','error_class','error_errno','stream_closed','descriptor_closed','descriptor'},
        'CLOSE_BEGIN':{'error_class','error_errno','descriptor','stream_closed'},
        'CLOSE_DONE':{'closed','descriptor_closed','descriptor_errno','snapshot'},
        'CLOSE_CLEANUP_BEGIN':{'reason','descriptor'},'CLOSE_CLEANUP_DONE':{'closed','descriptor_closed','descriptor_errno','snapshot'},
        'SEAL_EXCEPTION':{'error_class','error_errno','snapshot','functions_restored'},'SEAL_RETURN':{'archive','snapshot','functions_restored'}}
    last=0
    for row in events:
        if 'descriptor' in row and row['descriptor'] is not None:
            need(type(row['descriptor']) is dict and all(type(x) is int for x in row['descriptor'].values()))
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
    expected=blob
    need(n.decode(final['blob_b64'])==expected)
    written=events[5];need(type(written['written_bytes']) is int and written['written_bytes']==len(expected))
    close=events[10];closed=events[13] if fault=='close-before-release' else events[11]
    need(close['error_class'] is None and close['error_errno'] is None and close['descriptor']==final['file'] and close['stream_closed'] is False)
    need(closed['closed'] is True and closed['descriptor_closed'] is True and type(closed['descriptor_errno']) is int
         and closed['descriptor_errno']==errno.EBADF and closed['snapshot']==final)
    if fault=='normal':
        need(finish['archive']==dict(header,envelope_sha256=final['blob_sha256'],local_fsync_completed=True))
    else:
        injection=events[11] if fault=='close-before-release' else events[12]
        need(injection['boundary']==fault.replace('-','_') and injection['error_class']=='OSError'
            and type(injection['error_errno']) is int and injection['error_errno']==errno.EIO)
        before=fault=='close-before-release'
        need(injection['stream_closed'] is (not before) and injection['descriptor_closed'] is (not before)
            and injection['descriptor']==(final['file'] if before else None))
        if before:need(events[12]['reason']=='FIXTURE_FD_RELEASE_ONLY_NO_ACK' and events[12]['descriptor']==final['file'])
        need(finish['error_class']=='OSError' and type(finish['error_errno']) is int and finish['error_errno']==errno.EIO)
    for row in events:
        if row['phase'].startswith('FILE_FSYNC'):need(row['descriptor']==final['file'])
        elif row['phase'].startswith('DIRECTORY_FSYNC'):need(row['descriptor']==final['directory'])
    return True
