"""Native-specific GitHub readiness: local checks or explicit GET-only inspection.

No initializer, enrollment, mutation, signer/private receipt key, listener,
Native execution, Bind callback, credential discovery or live permission.
"""
import argparse
import importlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

from scripts import task4_native_bounded_continuation_v1 as native
from scripts import task4_signed_github_api_v1 as wire
from scripts import task4_signed_github_ledger_v1 as signed
from scripts.task4_signed_ledger_entrypoint_v1 import read_file
from scripts.task4_external_ledger_contract_v1 import canonical, digest, exact, hex64, need, sha, strict

PROFILE='task4.native-github-readiness.v1'
APPROVAL='task4.native-github-readiness-approval.v1'
RETAINED_APPROVAL='task4.native-github-retained-signer-approval.v1'
SCOPE='SYNTHETIC_NATIVE_GITHUB_READ_ONLY_NO_EXECUTION'
STOP='NATIVE_GITHUB_READINESS_STOP'
MODULES=(
    'task4_native_github_readiness_v1','task4_native_os_custody_v1',
    'task4_native_bounded_continuation_v1','task4_native_retained_authority_v1',
    'task4_native_signed_ledger_gate_v1','task4_native_signed_ledger_integration_v1',
    'task4_external_ledger_contract_v1','task4_signed_github_ledger_v1',
    'task4_signed_github_api_v1','task4_signed_ledger_entrypoint_v1',
    'task4_receipt_key_custody_v1',
)


class ReadinessDenied(ValueError):
    pass


def current_uid():return os.geteuid()


def source_manifest():
    result={}
    for name in MODULES:
        path=Path(importlib.import_module('scripts.'+name).__file__)
        need(path.suffix=='.py','INSTALLED_SOURCE_FILE_REQUIRED')
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
        with os.fdopen(fd,'rb') as stream:
            info=os.fstat(stream.fileno())
            need(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and 0<info.st_size<=256000,'BOUNDED_SOURCE_FILE')
            data=stream.read(256001);need(len(data)==info.st_size,'COMPLETE_SOURCE_FILE')
            result[name]=sha(data)
    return result


def validate_approval(a):
    if type(a) is dict and a.get('schema')==RETAINED_APPROVAL:
        from scripts import task4_native_retained_signer_profile_v1 as retained
        return retained.validate_approval(a)
    exact(a,'schema scope execution_source genesis binding native_manifest issuer_public_hex service_public_hex source_sha256 roles tls')
    need(a['schema']==APPROVAL and a['scope']==SCOPE and signed.hx(a['execution_source'],40)
         and signed.hx(a['genesis'],40),'EXPLICIT_NATIVE_READ_APPROVAL')
    native.validate_manifest(a['native_manifest'])
    from scripts.task4_external_ledger_contract_v1 import binding
    b=binding(a['binding']);m=a['native_manifest']
    need(b['ledger_id']==signed.LEDGER_ID and b['run_id']==m['execution']['run_id']
         and b['manifest_sha256']==digest(m),'NATIVE_MANIFEST_BINDING_NOT_SYNTHETIC_LABELS')
    need(hex64(a['issuer_public_hex']) and hex64(a['service_public_hex'])
         and b['issuer_public_sha256']==sha(bytes.fromhex(a['issuer_public_hex']))
         and b['custody_public_sha256']==sha(bytes.fromhex(m['custody_public'])),'NATIVE_ROLE_KEY_BINDING')
    identities=[b['issuer_public_sha256'],b['custody_public_sha256'],sha(bytes.fromhex(m['runtime_public'])),sha(bytes.fromhex(a['service_public_hex']))]
    need(len(set(identities))==4,'DISTINCT_NATIVE_AND_SERVICE_KEYS')
    exact(a['roles'],'ledger issuer custody runtime')
    need(all(type(v) is int and 0<v<2**31 for v in a['roles'].values())
         and len(set(a['roles'].values()))==4,'FOUR_DISTINCT_NONROOT_UIDS')
    from scripts import task4_native_signed_ledger_integration_v1 as integration
    need(a['roles']==dict(ledger=integration.LEDGER,issuer=native.kernel.ISSUER,
         custody=native.kernel.CUSTODY,runtime=native.RUNTIME),'MATCH_REVIEWED_NATIVE_PROFILE_UIDS')
    exact(a['tls'],'transport ca_sha256 server_certificate_sha256 issuer_certificate_sha256 custody_certificate_sha256')
    t=a['tls']
    need(t['transport']=='MTLS_OVER_AF_UNIX_WITH_SO_PEERCRED'
         and all(hex64(t[k]) for k in t if k!='transport')
         and len({t[k] for k in t if k.endswith('certificate_sha256')})==3,'EXPLICIT_NATIVE_MTLS_PLAN')
    need(type(a['source_sha256']) is dict and set(a['source_sha256'])==set(MODULES)
         and all(hex64(x) for x in a['source_sha256'].values())
         and a['source_sha256']==source_manifest(),'REVIEWED_SOURCE_BYTES_REQUIRED')
    return a


def prepare(configuration):
    cfg=strict(read_file(configuration,8192))
    exact(cfg,'schema scope approval_file token_file')
    need(cfg['schema']==PROFILE and cfg['scope']==SCOPE
         and type(cfg['approval_file']) is str and type(cfg['token_file']) is str,'EXACT_PRIVATE_READ_CONFIGURATION')
    from scripts.task4_receipt_key_custody_v1 import _parts
    _parts(cfg['token_file'])  # Validate the future credential path without opening it.
    a=validate_approval(strict(read_file(cfg['approval_file'],8192,public=True)))
    return cfg,a


def token(cfg):
    value=read_file(cfg['token_file'],256)
    need(re.fullmatch(b'[A-Za-z0-9_]{20,255}\n?',value),'EXPLICIT_PRIVATE_READ_TOKEN')
    return value.decode('ascii').rstrip('\n')


class ReadOnlyAPI(wire.API):
    """Deny every mutation before constructing SSL context/socket/headers."""
    def __init__(self,token,genesis,signer):
        super().__init__(token,genesis,signer);self.reads=[]
    def _request(self,method,path,value):
        need(method=='GET' and value is None,'GET_ONLY_NO_MUTATION')
        result=super()._request(method,path,value)
        self.reads.append(path)
        return result


def reader_uid(a):
    return a['roles']['reader'] if a['schema']==RETAINED_APPROVAL else a['roles']['ledger']


def service_uid(a):
    return a['roles']['service'] if a['schema']==RETAINED_APPROVAL else a['roles']['ledger']


def plan(a):
    """Reviewable desired rules, never an applied/observed firewall claim."""
    result=dict(schema='task4.native-github-egress-plan.v1',default_external_egress='DENY',
        allowed_github_https=dict(uid=reader_uid(a),host=wire.HOST,port=443,methods=['GET'],
            repository=signed.REPO,branch=signed.BRANCH,proxy=False,redirect=False,retry=False),
        denied_external_uids={role:a['roles'][role] for role in ('issuer','custody','runtime')},
        native_mtls_transport=a['tls']['transport'],dns_resolver_policy='REQUIRES_SEPARATE_REVIEW',
        token_permissions='DEDICATED_CONTENTS_READ_ONLY_REQUIRED_NOT_VERIFIED',
        os_rules_applied=False,os_egress_verified=False,tls_handshake_performed=False)
    if a['schema']==RETAINED_APPROVAL:
        result.update(applies_to_uids={role:a['roles'][role] for role in ('reader','issuer','custody','runtime')},
            retained_service_excluded_uid=service_uid(a),
            retained_service_egress_policy='OUTSIDE_READ_ONLY_CHECKER_PLAN_REQUIRES_SEPARATE_REVIEW')
    return result


def report(action,cfg,a):
    now=time.time();c=a['native_manifest']['execution']
    window='NOT_YET_VALID' if now<c['not_before'] else 'EXPIRED' if now>=c['expires_at'] else 'CURRENT'
    result=dict(schema=PROFILE,scope=SCOPE,action=action,approval_sha256=digest(a),configuration_sha256=digest(cfg),
        declared_execution_source=a['execution_source'],reviewed_source_bytes_match=True,genesis=a['genesis'],
        source_pin_scope=('FOURTEEN_SELECTED_FILES_NOT_FULL_RUNTIME_ATTESTATION'
                          if a['schema']==RETAINED_APPROVAL else 'ELEVEN_SELECTED_FILES_NOT_FULL_RUNTIME_ATTESTATION'),
        binding_sha256=digest(a['binding']),native_manifest_sha256=digest(a['native_manifest']),native_window_status=window,
        account_matches_ledger_uid=current_uid()==service_uid(a),
        account_matches_reader_uid=current_uid()==reader_uid(a),read_account_uid=reader_uid(a),
        service_account_uid=service_uid(a),egress_plan=plan(a),
        network_used=False,credential_loaded=False,backend_verified=False,native_run_present=None,
        credential_permissions_verified=False,
        execution_permission_issued=False,live_execution_ready=False,listener_started=False,
        service_receipt_verified=False,operator_mtls_verified=False,
        remote_mutations_attempted=0,real_provider_posts=0,native_execution_performed=False,
        provider_dispatch='DENY',utility='UNSCORED',production_bypass_resistance_proven=False)
    if a['schema']==RETAINED_APPROVAL:
        result.update(retained_private_key_loaded=False,retained_service_uid_observed=False,
            service_reconfigured=False,native_runtime_profile_applied=False)
    return result


def run(action,configuration,allow_github_read=False):
    try:
        need(action in ('check','read-existing') and type(allow_github_read) is bool
             and allow_github_read==(action=='read-existing'),'EXPLICIT_READ_ONLY_ACTION')
        cfg,a=prepare(configuration);result=report(action,cfg,a)
        if action=='check':return result  # No token contents, transport or socket.
        need(current_uid()==reader_uid(a),'APPROVED_NONROOT_READ_ACCOUNT')
        credential=token(cfg)
        api=ReadOnlyAPI(credential,a['genesis'],sha(bytes.fromhex(a['service_public_hex'])))
        backend=signed.GitState(api,a['genesis'],sha(bytes.fromhex(a['service_public_hex'])))
        head,state=backend.read()  # GET-only class cannot bootstrap/enroll/mutate.
        row=state['runs'].get(a['binding']['run_id'])
        need(row is None or row['binding']==a['binding'],'EXISTING_NATIVE_BINDING_MISMATCH')
        cfg_after,a_after=prepare(configuration)
        need(cfg_after==cfg and a_after==a and token(cfg_after)==credential
             and current_uid()==reader_uid(a),'UNCHANGED_READ_APPROVAL_CONFIGURATION_CREDENTIAL')
        result.update(network_used=True,credential_loaded=True,backend_verified=True,head_oid=head,
            github_get_requests=len(api.reads),native_run_present=row is not None,
            result='NATIVE_BINDING_OBSERVED_NO_EXECUTION_PERMISSION' if row else 'NATIVE_RUN_ABSENT_NO_ENROLLMENT',
            observed_snapshot=row['snapshot'] if row else None)
        return result
    except Exception:
        raise ReadinessDenied(STOP) from None


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=('source-manifest','check','read-existing'))
    parser.add_argument('--configuration')
    parser.add_argument('--allow-github-read',action='store_true')
    args=parser.parse_args(argv)
    try:
        if args.action=='source-manifest':
            need(args.configuration is None and not args.allow_github_read,'SOURCE_MANIFEST_ONLY')
            result=dict(schema=PROFILE,scope=SCOPE,source_sha256=source_manifest(),
                        approval_created=False,network_used=False,execution_permission_issued=False)
        else:
            need(args.configuration is not None,'EXPLICIT_READ_CONFIGURATION')
            result=run(args.action,args.configuration,args.allow_github_read)
        print(json.dumps(result,sort_keys=True),flush=True);return 0
    except KeyboardInterrupt:return 130
    except Exception:
        print(STOP,file=sys.stderr);return 1


if __name__=='__main__':raise SystemExit(main())
