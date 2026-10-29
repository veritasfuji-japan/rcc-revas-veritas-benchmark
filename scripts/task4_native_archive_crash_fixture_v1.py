"""Actual SIGKILL at selected boundaries of the frozen original archive call.

No synthetic exception stands in for process death. A normal control observes
all original storage calls. A killed process cannot claim unwind or restoration.
"""
import base64
import errno
import os
import signal
from pathlib import Path
import stat
import time
from unittest.mock import patch
from scripts import task4_native_archive_close_fixture_v1 as old
m,n,u,e,ingress,need=old.m,old.n,old.u,old.e,old.ingress,old.need
MODES=('after-create','after-file-fsync','after-directory-fsync')
NORMAL_PHASES=('SEAL_ENTER','ENCRYPT_BEGIN','ENCRYPT_DONE','FILE_OPEN','WRITE_BEGIN','WRITE_DONE',
    'FLUSH_BEGIN','FLUSH_DONE','FILE_FSYNC_BEGIN','FILE_FSYNC_DONE','CLOSE_BEGIN','CLOSE_DONE',
    'DIRECTORY_FSYNC_BEGIN','DIRECTORY_FSYNC_DONE','SEAL_RETURN')
identity=old.identity
validate_snapshot=old.validate_snapshot


def source_sha256():
    need(old.source_sha256()=='69dd5c9269cd72e965549a098a8b15ec6e6b224c29a7d43df820284fa8f21ea0')
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
    def halt(boundary,fd):
        info=os.fstat(fd)
        event('CRASH_INTENT',boundary=boundary,pid=os.getpid(),signal=int(signal.SIGKILL),
            descriptor_kind='directory' if stat.S_ISDIR(info.st_mode) else 'file',descriptor_open=True,
            descriptor=identity(info),snapshot=snapshot(base,slot))
        os.kill(os.getpid(),signal.SIGKILL)
        raise AssertionError('SIGKILL_MUST_NOT_RETURN')
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
            try:event('CLOSE_BEGIN',error_class=None if cls is None else cls.__name__,error_errno=getattr(error,'errno',None),descriptor=identity(os.fstat(fd)),stream_closed=self.stream.closed)
            finally:result=self.stream.__exit__(cls,error,tb)
            try:os.fstat(fd)
            except OSError as caught:
                need(caught.errno==errno.EBADF)
                event('CLOSE_DONE',closed=self.stream.closed,descriptor_closed=True,descriptor_errno=caught.errno,snapshot=snapshot(base,slot))
            else:raise ValueError('ARCHIVE_DESCRIPTOR_NOT_RELEASED')
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
        try:
            event('FILE_OPEN',descriptor=identity(os.fstat(stream.fileno())))
            if fault=='after-create':halt(fault,stream.fileno())
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
        event(kind+'_FSYNC_DONE',descriptor=identity(os.fstat(fd)))
        if fault==('after-file-fsync' if kind=='FILE' else 'after-directory-fsync'):halt(fault,fd)
        return result
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
    if fault=='normal':return old.validate_audit(events,wire,plan,slot,fault,namespace,final)
    need(fault in MODES)
    end={'after-create':4,'after-file-fsync':10,'after-directory-fsync':14}[fault]
    phases=list(NORMAL_PHASES[:end])+['CRASH_INTENT']
    need(type(events) is list and [x['phase'] for x in events]==phases)
    common={'op','phase','uid','namespace','at_ns'}
    extra={'SEAL_ENTER':{'fault','raw_sha256','observed_bytes','capture_completion','before'},
        'ENCRYPT_BEGIN':{'raw_sha256','aad_sha256'},'ENCRYPT_DONE':{'ciphertext_sha256','ciphertext_bytes'},
        'FILE_OPEN':{'descriptor'},'WRITE_BEGIN':{'blob_b64','blob_sha256','blob_bytes'},'WRITE_DONE':{'written_bytes'},
        'FLUSH_BEGIN':set(),'FLUSH_DONE':set(),'FILE_FSYNC_BEGIN':{'descriptor'},'FILE_FSYNC_DONE':{'descriptor'},
        'CLOSE_BEGIN':{'error_class','error_errno','descriptor','stream_closed'},
        'CLOSE_DONE':{'closed','descriptor_closed','descriptor_errno','snapshot'},
        'DIRECTORY_FSYNC_BEGIN':{'descriptor'},'DIRECTORY_FSYNC_DONE':{'descriptor'},
        'CRASH_INTENT':{'boundary','pid','signal','descriptor_kind','descriptor_open','descriptor','snapshot'}}
    last=0
    for row in events:
        need(set(row)==common|extra[row['phase']] and row['op']==slot and type(row['uid']) is int and row['uid']==n.CUSTODY
             and row['namespace']==namespace and type(row['at_ns']) is int and row['at_ns']>0 and row['at_ns']>=last);last=row['at_ns']
        if 'descriptor' in row:need(type(row['descriptor']) is dict and all(type(x) is int for x in row['descriptor'].values()))
    first,crash=events[0],events[-1];old.validate_snapshot(first['before'],False,0o700)
    need(first['fault']==fault and first['raw_sha256']==e.sha(wire) and type(first['observed_bytes']) is int and first['observed_bytes']==len(wire)
         and first['capture_completion']=='eof' and crash['boundary']==fault and type(crash['pid']) is int and crash['pid']>0
         and type(crash['signal']) is int and crash['signal']==int(signal.SIGKILL) and crash['descriptor_open'] is True and crash['snapshot']==final)
    need(type(final) is dict and set(final)=={'directory','exists','file','blob_b64','blob_sha256'} and final['exists'] is True)
    blob=n.decode(final['blob_b64'])
    need(final['blob_sha256']==e.sha(blob) and final['file']['size']==len(blob))
    if fault=='after-create':
        # The original create succeeded, but no original write was reached.
        need(blob==b'')
        for name,mode in (('directory',0o700),('file',0o600)):
            row=final[name];need(set(row)=={'device','inode','uid','gid','mode','links','size'}
                and all(type(x) is int and x>=0 for x in row.values()) and row['inode']>0 and row['uid']==n.CUSTODY
                and row['mode']==mode and row['links']>=1)
        need(final['file']['links']==1 and type(final['file']['size']) is int and final['file']['size']==0)
    else:old.validate_snapshot(final,True,0o700)
    stable=lambda x:{k:v for k,v in x.items() if k!='size'}
    need(stable(first['before']['directory'])==stable(final['directory']) and stable(events[3]['descriptor'])==stable(final['file'])
         and type(events[3]['descriptor']['size']) is int and events[3]['descriptor']['size']==0)
    header=dict(schema='task4.closed-raw-http-envelope.v1',run_id=plan['run_id'],slot=slot,request_sha256=plan['request_sha256'],recipient_sha256=plan['recipient_sha256'],
        raw_sha256=e.sha(wire),observed_bytes=len(wire),capture_completion='eof',origin='CLOSED_LOCAL_TLS_NOT_PUBLIC_PROVIDER')
    need(events[1]['raw_sha256']==e.sha(wire) and events[1]['aad_sha256']==e.sha(n.canonical(header))
        and type(events[2]['ciphertext_bytes']) is int and events[2]['ciphertext_bytes']==len(wire)+16
        and type(events[2]['ciphertext_sha256']) is str and len(events[2]['ciphertext_sha256'])==64
        and bytes.fromhex(events[2]['ciphertext_sha256']).hex()==events[2]['ciphertext_sha256'])
    kind='directory' if fault=='after-directory-fsync' else 'file'
    need(crash['descriptor_kind']==kind and crash['descriptor']==final[kind])
    if fault!='after-create':
        start=events[4];need(n.decode(start['blob_b64'])==blob and start['blob_sha256']==e.sha(blob)
            and type(start['blob_bytes']) is int and start['blob_bytes']==len(blob)
            and type(events[5]['written_bytes']) is int and events[5]['written_bytes']==len(blob))
        value=ingress.raw.strict(blob);need(set(value)=={'header','ephemeral','nonce','ciphertext'} and value['header']==header
             and len(bytes.fromhex(value['ephemeral']))==32 and len(bytes.fromhex(value['nonce']))==12)
        encrypted=base64.b64decode(value['ciphertext'],validate=True)
        need(len(encrypted)==len(wire)+16 and events[2]['ciphertext_sha256']==e.sha(encrypted))
        for row in events:
            if row['phase'].startswith('FILE_FSYNC'):need(row['descriptor']==final['file'])
            elif row['phase'].startswith('DIRECTORY_FSYNC'):need(row['descriptor']==final['directory'])
        if fault=='after-directory-fsync':
            close,closed=events[10:12]
            need(close['error_class'] is None and close['error_errno'] is None and close['descriptor']==final['file'] and close['stream_closed'] is False
                and closed['closed'] is True and closed['descriptor_closed'] is True and type(closed['descriptor_errno']) is int
                and closed['descriptor_errno']==errno.EBADF and closed['snapshot']==final)
    return True
