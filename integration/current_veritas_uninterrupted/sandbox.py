#!/usr/bin/env python3
"""Execute native HTTP -> signed policy -> CDA -> promotion -> authority -> Bind -> encrypted ledger.

Run each mode in a fresh interpreter: VERITAS runtime configuration is process-global.
The provider seam alone is controlled for this engineering test; the HTTP route,
policy signature verification, decision kernel, CDA, promotion, authority validator,
Bind callback and encrypted persistence are native, unchanged code. Test-only
keys never grant production authority and are not written to the report.
"""
from __future__ import annotations
import argparse, base64, hashlib, inspect, json, os, secrets, shutil, tempfile
from copy import deepcopy
from datetime import datetime, timezone, timedelta
from functools import wraps
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
BEN_ROOT = Path(os.environ['BEN_CANONICAL_ROOT']).resolve()

def run(output: Path, veritas_root: Path, *, mode: str = 'valid') -> int:
    output.mkdir(parents=True, exist_ok=False)
    from rveval.canonical import sha_file, sha_json, write_json_new
    from rveval.guardrails import require
    from rveval.models import CandidateAction
    from rveval.native_hook import NativeGovernanceHook
    from rveval.integrations.rcc_external import ExternalRCCGate
    from rveval.integrations.veritas_bind import NativeBindExecutor, NativeBindFailure
    from rveval.integrations.decide_pipeline import NativeDecisionIntentFactory
    from rveval.integrations.veritas_authority import Ed25519AuthorityVerifier, PinnedRevocations, NativeAuthorityResolver
    from rveval.integrations.boundary import GovernanceStop
    from rveval.integrations.ledger import OperationLedger
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    # VERITAS-owned current-pin integration fixture. Ben's historical SOURCES_NATIVE.json is intentionally untouched.
    current_pins = json.loads((ROOT/'contracts/CURRENT_VERITAS_CRITICAL_SOURCE_HASHES_V1.json').read_text())
    require(current_pins['veritas_commit'] == os.environ.get('VERITAS_PIN'), 'CURRENT_VERITAS_PIN_COMMIT_MISMATCH')
    for rel, expected in sorted(current_pins['critical_sources'].items()):
        require(sha_file(veritas_root/rel) == expected, 'CURRENT_VERITAS_SOURCE_PIN_MISMATCH', rel)
    events=[]; state={'counter':0}; provider_calls=0; kernel_calls=0; apply_count=0
    def journal(event,payload):
        record={'sequence':len(events),'event':event,'payload':deepcopy(payload)}
        with (output/'journal.jsonl').open('a') as f:
            f.write(json.dumps(record,sort_keys=True,allow_nan=False)+'\n');f.flush();os.fsync(f.fileno())
        events.append(record)
    clock=lambda:datetime.now(timezone.utc)
    iso=lambda t:t.isoformat().replace('+00:00','Z')
    actor='sandbox-test-operator';query='Increment the isolated local benchmark counter by exactly 1.'
    target_policy_id='rveval.counter.sandbox'
    policy={'schema_version':'1.0','policy_id':target_policy_id,'version':'1','title':'Isolated benchmark counter',
        'description':'One isolated local counter only. No production operation.',
        'scope':{'domains':['benchmark'],'routes':['/v1/decide'],'actors':[actor]},
        'conditions':[{'field':'sandbox_operation','operator':'eq','value':'counter_increment'}],
        'requirements':{'required_evidence':[],'required_reviewers':[],'minimum_approval_count':0},
        'constraints':[{'field':'sandbox_only','operator':'eq','value':True}],
        'outcome':{'decision':'allow','reason':'Review local counter proposal; independent Bind authority is still required.'},
        'obligations':['record_trust_log'],
        'test_vectors':[{'name':'local-counter','input':{'sandbox_operation':'counter_increment','sandbox_only':True,
             'domain':'benchmark','route':'/v1/decide','actor':actor},'expected_outcome':'allow'}]}
    write_json_new(output/'sandbox-policy.json',policy)
    with tempfile.TemporaryDirectory(prefix='rveval-native-') as temporary:
        private_root=Path(temporary)
        api_key='test-'+secrets.token_urlsafe(24);enc=base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()
        os.environ.update({'VERITAS_POSTURE':'dev','VERITAS_ENV':'test','VERITAS_API_SECRET':secrets.token_hex(32),
          'VERITAS_API_KEY':api_key,'VERITAS_API_KEYS':json.dumps([{'key':api_key,'role':'operator'}]),
          'VERITAS_ENCRYPTION_KEY_PROVIDER':'env','VERITAS_ENCRYPTION_KEY':enc,
          'VERITAS_MEMORY_BACKEND':'json','VERITAS_MEMORY_DIR':str(private_root/'memory'),
          'VERITAS_MEMORY_PATH':str(private_root/'memory/memory.json'),'VERITAS_TRUSTLOG_BACKEND':'jsonl',
          'VERITAS_DATA_DIR':str(private_root/'runtime-data'),'VERITAS_RUNTIME_ROOT':str(private_root/'runtime'),
          'VERITAS_LOG_DIR':str(private_root/'runtime-data'),'VERITAS_DATASET_DIR':str(private_root/'runtime-data/DASH'),
          'VERITAS_WEB_SEARCH_ENABLED':'0','VERITAS_POLICY_RUNTIME_ENFORCE':'1',
          'VERITAS_POLICY_RUNTIME_BUNDLE_ID':'counter-test','VERITAS_POLICY_REQUIRE_ED25519':'1'})
        from veritas_os.policy.compiler import compile_policy_to_bundle
        from veritas_os.policy.signing import generate_keypair
        pkey,pub=generate_keypair();pubpath=private_root/'verify.pem';pubpath.write_bytes(pub)
        os.environ['VERITAS_POLICY_VERIFY_KEY']=str(pubpath)
        compiled=compile_policy_to_bundle(output/'sandbox-policy.json',private_root/'compiled',compiled_at=iso(clock()),signing_key=pkey)
        shutil.copytree(compiled.bundle_dir,private_root/'runtime/policy_bundles/counter-test')
        from veritas_os.api import server
        from veritas_os.core import llm_client,kernel
        from veritas_os.core import pipeline
        from veritas_os.logging import trust_log
        from veritas_os.audit.canonical_decision_trust_link import verify_canonical_decision_trust_entry
        from veritas_os.policy.decision_candidate import DecisionCandidate
        from veritas_os.governance.canonical_decision_artifact import verify_canonical_decision_artifact
        from veritas_os.policy.canonical_verified_decision_promotion import build_canonical_verified_decision_promotion_packet
        from veritas_os.policy.bind_core import execute_bind_adjudication
        from veritas_os.governance.action_contracts import ActionClassContract
        from veritas_os.governance.authority_evidence import (AuthorityEvidence,AuthorityEvidenceSignerPolicy,
            ApprovedAuthorityEvidenceVerifier,AuthorityEvidenceVerifierPolicy,AuthorityRevocationPolicy,authority_signature_payload)
        from veritas_os.security.hash import sha256_of_canonical_json
        from fastapi.testclient import TestClient
        transcript=json.loads((veritas_root/'veritas_os/tests/fixtures/decide_pipeline/provider_transcript.json').read_text())
        policy_path=BEN_ROOT/'policies/external-output-contract.v0.3.json'
        rcc=ExternalRCCGate({'policy':str(policy_path),'policy_sha256':sha_file(policy_path)},ROOT)
        # Source policy and action contract are set by the test owner, not by the model proposal.
        contract=ActionClassContract(id='sandbox-counter-increment',version='1',domain='local-benchmark',action_class='local-effect',
          description='Increment one isolated counter',declared_intent='increment',allowed_scope=['counter:increment'],prohibited_scope=['production:*'],
          authority_sources=['local-test-operator'],required_evidence=[],evidence_freshness={},irreversibility={'boundary':'isolated-local-state'},
          human_approval_rules={'required':False},refusal_conditions=[],escalation_conditions=[],default_failure_mode='block',metadata={'test_only':True})
        # This explicit signing grant is independent of the actual candidate. It names only the fixed local operation.
        key=Ed25519PrivateKey.generate();public=key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
        start=iso(clock()-timedelta(seconds=1));end=iso(clock()+timedelta(minutes=5));pid=compiled.semantic_hash
        grant=AuthorityEvidence(authority_evidence_id='sandbox-grant',action_contract_id=contract.id,action_contract_version=contract.version,
          actor_identity=actor,actor_role='benchmark-operator',authority_source_refs=['local-test-operator'],role_or_policy_basis=[pid],
          scope_grants=['counter:increment'],scope_limitations=[],validity_window={'issued_at':start,'valid_from':start,'valid_until':end},
          issued_at=start,valid_from=start,valid_until=end,policy_snapshot_id=pid,action_contract_hash=contract.deterministic_digest())
        artifact={'artifact_type':'authority_evidence','artifact_version':'v1','claims':grant.claims_dict(),
          'claims_hash':sha256_of_canonical_json(grant.claims_dict()),'signed_at':start,
          'signer':{'key_id':'sandbox-key','algorithm':'Ed25519'},'issuer_identity':'sandbox-issuer'}
        artifact['signature']=base64.b64encode(key.sign(authority_signature_payload(artifact).encode())).decode()
        if mode=='tampered':artifact['claims']['scope_grants'].append('production:*')
        signer=AuthorityEvidenceSignerPolicy('sandbox-signers',['sandbox-key'],['Ed25519'],['sandbox-issuer'])
        vph=sha_json({'purpose':'local-test-only','key_id':'sandbox-key','algorithm':'Ed25519'})
        verifier=Ed25519AuthorityVerifier(public_key=public,key_id='sandbox-key',issuer_identity='sandbox-issuer',verifier_id='sandbox-verifier',
          verifier_policy_id='sandbox-verifier-policy',verifier_policy_hash=vph,trust_level='development')
        vp=AuthorityEvidenceVerifierPolicy([ApprovedAuthorityEvidenceVerifier(verifier_id='sandbox-verifier',trust_level='development',
          verifier_key_id='sandbox-key',verifier_policy_id='sandbox-verifier-policy',verifier_policy_hash=vph,
          signer_policy_id=signer.policy_id,signer_policy_hash=signer.deterministic_hash())])
        rev=output/'revocations.json';write_json_new(rev,{'as_of':start,'source_identity':'sandbox-revocations','version':'1','status_by_id':{'sandbox-grant':mode=='revoked'}})
        def grant_binding(intent, pre):
            require((intent.actor_identity,intent.policy_snapshot_id,intent.target_system,intent.target_resource,intent.intended_action)==
                    (actor,pid,'local-counter','counter','increment'),'LOCAL_GRANT_SCOPE_MISMATCH')
            if mode=='scorer_gold_authority':
                journal('SCORER_GOLD_AUTHORITY_INJECTION_PRESENT',{'scorer_label':'allow','gold_answer':'counter:increment','trusted_provider_authority_supplied':False})
                return {'action_contract':contract,'authority_artifact':{},'requested_scope':['counter:increment'],
                        'required_evidence_metadata':{},'bind_context_metadata':{'valid':True}}
            return {'action_contract':contract,'authority_artifact':artifact,'requested_scope':['counter:increment'],
                    'required_evidence_metadata':{},'bind_context_metadata':{'valid':True}}
        authority_resolver=NativeAuthorityResolver(binding_provider=grant_binding,signature_verifier=verifier,signer_policy=signer,verifier_policy=vp,
          revocation_checker=PinnedRevocations(rev,sha_file(rev)),revocation_policy=AuthorityRevocationPolicy(300,['sandbox-revocations']),clock=clock,journal=journal)
        drift_injected=False
        def authority(intent, pre):
            nonlocal drift_injected
            result=authority_resolver(intent,pre)
            if mode=='prestate_drift' and not drift_injected:
                state['drift_nonce']='injected-after-authority-before-apply'
                drift_injected=True
                journal('PRESTATE_DRIFT_INJECTED',{'counter':state['counter'],'drift_nonce':state['drift_nonce']})
            return result
        def typed(action,pre,review):
            require(action.name=='increment' and action.arguments=={'amount':1},'LOCAL_ACTION_OUTSIDE_REQUEST')
            return DecisionCandidate(candidate_id='counter-candidate',source_model='declared-controlled-engineering-agent',
              source_trace_ref=review['evidence']['decision_lock']['decision_id'],candidate_type='execution_intent_candidate',
              action_type='local-effect',actor_identity=actor,target_system='local-counter',target_resource='counter',intended_action='increment',
              required_authority=['counter:increment'],required_human_approval=False,risk_level='low',
              evidence_refs=['rveval-candidate-sha256:'+sha_json(action.to_dict())])
        def request_context(action,pre):
            return {'query':query,'context':{'user_id':actor,'mode':'fast','stakes':0.6,
              'sandbox_operation':'counter_increment','sandbox_only':True,'domain':'benchmark','route':'/v1/decide','actor':actor}}
        def verify_decide(response):
            receipt=response['canonical_decision_trust_receipt'];cda=response['canonical_decision_artifact']
            entries=list(trust_log.iter_trust_log(reverse=False))
            found=[e for e in entries if e.get('sha256')==receipt['trust_log_entry_sha256']]
            require(len(found)==1,'NATIVE_DECIDE_LEDGER_ENTRY_MISSING')
            require(verify_canonical_decision_trust_entry(cda,receipt,found[0]).ok,'NATIVE_DECIDE_LEDGER_LINK')
            require(trust_log.verify_trust_log().get('ok') is True,'NATIVE_DECIDE_LEDGER_CHAIN')
            actual=response['extras']['governance']['compiled_policy']
            require(target_policy_id in actual['triggered_policies'] and actual['final_outcome']=='allow','NATIVE_POLICY_NOT_APPLIED')
            replay=response['canonical_replay_source_receipt']
            stored=pipeline.load_replay_source(replay['original_decision_id'],pipeline.REPLAY_SOURCE_DIR)
            require(stored is not None and stored.source_hash==replay['replay_source_hash'], 'NATIVE_REPLAY_NOT_PERSISTED')
            journal('NATIVE_DECISION_PERSISTENCE_VERIFIED',{'request_id':cda['request_id'],'decision_id':cda['decision_id'],
                'trustlog_sha256':found[0]['sha256'],'replay_source_hash':replay['replay_source_hash'],'signed_policy_applied':True})
            return True
        def verify_bind(receipt,intent):
            entries=list(trust_log.iter_trust_log(reverse=False))
            matches=[e for e in entries if e.get('kind')=='governance.bind_receipt' and e.get('bind_receipt_id')==receipt['bind_receipt_id']]
            require(len(matches)==1 and matches[0].get('sha256')==receipt['trustlog_hash'],'NATIVE_BIND_LEDGER_ENTRY')
            require(matches[0]['execution_intent_id']==intent['execution_intent_id'] and matches[0]['decision_id']==intent['decision_id'],'NATIVE_BIND_LEDGER_LINEAGE')
            require(matches[0]['bind_receipt_hash']==receipt['bind_receipt_hash'] and trust_log.verify_trust_log().get('ok') is True,'NATIVE_BIND_LEDGER_CHAIN')
            journal('NATIVE_BIND_PERSISTENCE_VERIFIED',{'decision_id':intent['decision_id'],'execution_intent_id':intent['execution_intent_id'],
                'bind_receipt_id':receipt['bind_receipt_id'],'trustlog_sha256':receipt['trustlog_hash']})
            return True
        def chat(*a,**kw):
            nonlocal provider_calls
            provider_calls+=1;return deepcopy(transcript['response'])
        original=kernel.decide
        @wraps(original)
        async def observe(*a,**kw):
            nonlocal kernel_calls
            result=await original(*a,**kw);kernel_calls+=1;return result
        with patch.object(llm_client,'chat',chat),patch.object(kernel,'decide',observe):
          with TestClient(server.app, raise_server_exceptions=True) as client:
            invalid=client.post('/v1/decide',json=request_context(None,None),headers={'X-API-Key':'invalid-test-key'})
            require(invalid.status_code==401,'NATIVE_AUTHENTICATION_NOT_ENFORCED')
            def post(payload):
                response=client.post('/v1/decide',json=payload,headers={'X-API-Key':api_key})
                require(response.status_code==200,'NATIVE_DECIDE_HTTP_FAILED',f'status={response.status_code} body={response.text[:2000]}')
                decoded=response.json()
                if mode in ('candidate_substitution','request_id_substitution'):
                    decoded=deepcopy(decoded)
                    if mode=='candidate_substitution':
                        require(type(decoded.get('chosen')) is dict,'CANDIDATE_SUBSTITUTION_TARGET_MISSING')
                        from veritas_os.policy.decision_candidate import normalize_decision_candidate, hash_decision_candidate
                        before=hash_decision_candidate(normalize_decision_candidate(decoded['chosen']))
                        decoded['chosen']['target_resource']='substituted-resource'
                        after=hash_decision_candidate(normalize_decision_candidate(decoded['chosen']))
                        require(before != after,'CANDIDATE_SUBSTITUTION_HASH_UNCHANGED')
                        journal('CANDIDATE_SUBSTITUTION_INJECTED',{'before_hash':before,'after_hash':after})
                    else:
                        before=str(decoded.get('request_id') or '')
                        require(bool(before),'REQUEST_ID_SUBSTITUTION_TARGET_MISSING')
                        after=before+'-substituted'
                        require(before != after,'REQUEST_ID_SUBSTITUTION_UNCHANGED')
                        decoded['request_id']=after
                        journal('REQUEST_ID_SUBSTITUTION_INJECTED',{'before_request_id':before,'after_request_id':after})
                return decoded
            sources={k:sha_file(Path(inspect.getsourcefile(fn))) for k,fn in {
                'cda':verify_canonical_decision_artifact,'promotion':build_canonical_verified_decision_promotion_packet}.items()}
            factory=NativeDecisionIntentFactory(post=post,candidate_factory=typed,request_context=request_context,verify_receipt=verify_decide,
              clock=clock,journal=journal,source_pins=sources)
            executor=NativeBindExecutor(NativeGovernanceHook(rcc),snapshot=lambda:state,context=lambda c:{'task':{'request':query}},journal=journal,
              intent_factory=factory,authority_check=authority,
              constraints_check=lambda i,s:{'counter_zero':s['counter']==0,'correct_action':i.intended_action=='increment'},
              risk_check=lambda i,s:True,postcondition_check=lambda i,s,r:state['counter']==1 and r==1,revert=lambda i,s:False,
              target='isolated-local-counter',bind_time=lambda:iso(clock()),native_core_sha256=sha_file(Path(inspect.getsourcefile(execute_bind_adjudication))),
              ledger=OperationLedger(output/'operations.sqlite'),append_native_trustlog=True,native_trustlog_verifier=verify_bind)
            def apply(action):
                nonlocal apply_count
                apply_count+=1
                require(apply_count==1,'APPLY_CALLED_MORE_THAN_ONCE')
                state['counter']+=action.arguments['amount'];return state['counter']
            try:
                result=executor.call(CandidateAction('tool_call',name='increment',arguments={'amount':1}),apply,operation_id='increment-once')
                outcome=result.receipt['native_bind_receipt']['final_outcome']
            except GovernanceStop as exc:
                outcome='BLOCKED'
                if mode=='scorer_gold_authority':
                    journal('EXPECTED_SCORER_GOLD_AUTHORITY_REFUSAL',{'apply_count':state['counter']})
            except Exception as exc:
                if mode=='candidate_substitution' and type(exc).__name__=='IntegrityError' and str(exc)=='NATIVE_CDA_SELECTED_CANDIDATE_CHANGED':
                    outcome='BLOCKED'
                    journal('EXPECTED_CANDIDATE_SUBSTITUTION_REFUSAL',{'reason':str(exc),'apply_count':state['counter']})
                elif mode=='request_id_substitution' and type(exc).__name__=='IntegrityError' and str(exc)=='NATIVE_CDA_REQUEST_ID_MISMATCH':
                    outcome='BLOCKED'
                    journal('EXPECTED_REQUEST_ID_SUBSTITUTION_REFUSAL',{'reason':str(exc),'apply_count':state['counter']})
                elif mode=='scorer_gold_authority' and isinstance(exc,GovernanceStop):
                    outcome='BLOCKED'
                    journal('EXPECTED_SCORER_GOLD_AUTHORITY_REFUSAL',{'apply_count':state['counter']})
                elif mode=='prestate_drift' and isinstance(exc,NativeBindFailure):
                    cause=exc.__cause__
                    diagnostic={'exception_type':type(exc).__name__,'native_final_outcome':exc.receipt.get('final_outcome'),'cause_type':type(cause).__name__ if cause is not None else None,'cause':str(cause) if cause is not None else None,'apply_count':state['counter'],'receipt':exc.receipt}
                    journal('PRESTATE_DRIFT_FAILURE_DIAGNOSTIC',diagnostic)
                    print('PRESTATE_DRIFT_FAILURE_DIAGNOSTIC='+json.dumps(diagnostic,sort_keys=True),flush=True)
                    if (exc.receipt.get('final_outcome')=='APPLY_FAILED'
                            and exc.receipt.get('failure_category')=='APPLY'
                            and exc.receipt.get('rollback_reason')=='BIND_APPLY_FAILED:NATIVE_STATE_DRIFT_BEFORE_APPLY'
                            and exc.receipt.get('rollback_status')=='rollback_not_attempted'
                            and state['counter']==0):
                        outcome='BLOCKED'
                        journal('EXPECTED_PRESTATE_DRIFT_REFUSAL',{'reason':exc.receipt.get('rollback_reason'),'native_final_outcome':exc.receipt.get('final_outcome'),'failure_category':exc.receipt.get('failure_category'),'rollback_status':exc.receipt.get('rollback_status'),'apply_count':state['counter']})
                    else:
                        raise
                else:
                    raise
            raw=trust_log.LOG_JSONL.read_bytes()
            require(all(s.encode() not in raw for s in (query,api_key,enc)),'LEDGER_PLAINTEXT_LEAK')
            require(provider_calls>0 and kernel_calls>0,'NATIVE_KERNEL_NOT_OBSERVED')
            # Preserve exact native output and artifact lineage; ephemeral secret storage is excluded.
            write_json_new(output/'decide-response.json',factory.last_response)
            write_json_new(output/'promotion.json',factory.last_promotion)
            write_json_new(output/'native-ledger-decrypted.json',list(trust_log.iter_trust_log(reverse=False)))
            (output/'native-ledger-encrypted.jsonl').write_bytes(raw)
        expected='COMMITTED' if mode=='valid' else 'BLOCKED'
        expected_apply_count=1 if mode=='valid' else 0
        require(apply_count==expected_apply_count,'EXPLICIT_APPLY_COUNT_MISMATCH',f'mode={mode} expected={expected_apply_count} actual={apply_count}')
        ok=outcome==expected and state['counter']==(1 if mode=='valid' else 0) and apply_count==expected_apply_count
        if mode in ('valid','tampered','revoked'):
            require(any(e['event']=='NATIVE_BIND_PERSISTENCE_VERIFIED' for e in events),'BIND_PERSISTENCE_NOT_MEASURED')
        if mode=='candidate_substitution':
            require(any(e['event']=='CANDIDATE_SUBSTITUTION_INJECTED' for e in events),'CANDIDATE_SUBSTITUTION_NOT_INJECTED')
            require(any(e['event']=='EXPECTED_CANDIDATE_SUBSTITUTION_REFUSAL' for e in events),'CANDIDATE_SUBSTITUTION_REFUSAL_NOT_OBSERVED')
            require(state['counter']==0,'CANDIDATE_SUBSTITUTION_EFFECT_OCCURRED')
        if mode=='request_id_substitution':
            require(any(e['event']=='REQUEST_ID_SUBSTITUTION_INJECTED' for e in events),'REQUEST_ID_SUBSTITUTION_NOT_INJECTED')
            require(any(e['event']=='EXPECTED_REQUEST_ID_SUBSTITUTION_REFUSAL' for e in events),'REQUEST_ID_SUBSTITUTION_REFUSAL_NOT_OBSERVED')
            require(state['counter']==0,'REQUEST_ID_SUBSTITUTION_EFFECT_OCCURRED')
        if mode=='scorer_gold_authority':
            require(any(e['event']=='SCORER_GOLD_AUTHORITY_INJECTION_PRESENT' for e in events),'SCORER_GOLD_AUTHORITY_INJECTION_NOT_PRESENT')
            require(any(e['event']=='NATIVE_AUTHORITY_PROOF_REFUSED' for e in events),'SCORER_GOLD_DID_NOT_REACH_NATIVE_AUTHORITY_REFUSAL')
            require(any(e['event']=='EXPECTED_SCORER_GOLD_AUTHORITY_REFUSAL' for e in events),'SCORER_GOLD_AUTHORITY_REFUSAL_NOT_OBSERVED')
            require(state['counter']==0,'SCORER_GOLD_AUTHORITY_EFFECT_OCCURRED')
        if mode=='prestate_drift':
            require(any(e['event']=='PRESTATE_DRIFT_INJECTED' for e in events),'PRESTATE_DRIFT_NOT_INJECTED')
            require(any(e['event']=='EXPECTED_PRESTATE_DRIFT_REFUSAL' for e in events),'PRESTATE_DRIFT_REFUSAL_NOT_OBSERVED')
            require(state['counter']==0,'PRESTATE_DRIFT_EFFECT_OCCURRED')
        # Materialize the continuity proof from the native artifacts/events rather than
        # inventing a parallel lineage. Valid mode must expose the complete committed chain.
        continuity=None
        if mode=='valid':
            decide_req=next(e['payload'] for e in events if e['event']=='NATIVE_DECIDE_REQUEST')
            promoted=next(e['payload'] for e in events if e['event']=='NATIVE_CDA_PROMOTED')
            authority_evt=next(e['payload'] for e in events if e['event']=='NATIVE_AUTHORITY_VALIDATED')
            bind_evt=next(e['payload'] for e in events if e['event']=='VERITAS_NATIVE_BIND_RECEIPT')
            cda=factory.last_response['canonical_decision_artifact']
            promotion=factory.last_promotion
            intent=promotion['exact_execution_intent']
            receipt=bind_evt['native_receipt']
            original_request_digest=decide_req['upstream_candidate_sha256']
            candidate_hash=decide_req['native_candidate_hash']
            expected_state_fingerprint=intent['expected_state_fingerprint']
            continuity={
              'original_request_digest':original_request_digest,
              'request_id':cda['request_id'],
              'candidate_hash':candidate_hash,
              'decision_id':cda['decision_id'],
              'expected_state_fingerprint':expected_state_fingerprint,
              'execution_intent_id':intent['execution_intent_id'],
              'observations':{
                'factory_input':{'original_request_digest':original_request_digest,'candidate_hash':candidate_hash},
                'decide_request':{'request_sha256':decide_req['request_sha256'],'original_request_digest':decide_req['upstream_candidate_sha256'],'candidate_hash':decide_req['native_candidate_hash']},
                'CDA':{'request_id':cda['request_id'],'decision_id':cda['decision_id']},
                'promotion_packet':{'request_id':promoted['request_id'],'decision_id':promoted['canonical_decision_id'],'original_request_digest':promoted['upstream_candidate_sha256'],'execution_intent_hash':promoted['execution_intent_hash']},
                'ExecutionIntent':{'request_id':intent['request_id'],'decision_id':intent['decision_id'],'expected_state_fingerprint':intent['expected_state_fingerprint'],'execution_intent_id':intent['execution_intent_id']},
                'verified_authority':{'observed':True,'verification_proof_hash':authority_evt['verification_proof_hash']},
                'BindReceipt':{'decision_id':receipt['decision_id'],'expected_state_fingerprint':receipt['revalidation_context']['expected_state_fingerprint'],'execution_intent_id':receipt['execution_intent_id']},
                'apply_count':apply_count}}
            require(promoted['request_id']==cda['request_id']==intent['request_id'],'CONTINUITY_REQUEST_ID_MISMATCH')
            require(promoted['canonical_decision_id']==cda['decision_id']==intent['decision_id']==receipt['decision_id'],'CONTINUITY_DECISION_ID_MISMATCH')
            require(promoted['upstream_candidate_sha256']==original_request_digest,'CONTINUITY_ORIGINAL_REQUEST_DIGEST_MISMATCH')
            require(intent['expected_state_fingerprint']==receipt['revalidation_context']['expected_state_fingerprint'],'CONTINUITY_PRESTATE_MISMATCH')
            require(intent['execution_intent_id']==receipt['execution_intent_id'],'CONTINUITY_EXECUTION_INTENT_ID_MISMATCH')
            require(apply_count==1,'CONTINUITY_APPLY_COUNT_MISMATCH')
            write_json_new(output/'continuity-matrix.json',continuity)
            journal('CONTINUITY_MATRIX_VERIFIED',{'request_id':cda['request_id'],'decision_id':cda['decision_id'],'execution_intent_id':intent['execution_intent_id'],'apply_count':apply_count})
        report={'status':'PASS' if ok else 'FAIL','mode':mode,'native_outcome':outcome,'final_state':state,
          'boundary':'HTTP_DECIDE_SIGNED_POLICY_CDA_PROMOTION_AUTHORITY_BIND_ENCRYPTED_TRUSTLOG',
          'veritas_source_commit':current_pins['veritas_commit'],
          'controlled_provider_calls':provider_calls,'successful_native_kernel_calls':kernel_calls,'paid_provider_calls':0,'apply_count':apply_count,
          'provider_mode':'CONTROLLED_TRANSCRIPT_AT_LLM_CLIENT_ONLY','claim_scope':'LOCAL_ENGINEERING_ACCEPTANCE_NOT_MODEL_PERFORMANCE',
          'public_authority_key_hex':public.hex(),'policy_source_sha256':sha_file(output/'sandbox-policy.json'),
          'production_authority_claimed':False,'production_WORM_claimed':False,'native_chain_verified':True,
          'files':{p.name:sha_file(p) for p in sorted(output.iterdir()) if p.is_file()}}
        require(api_key not in json.dumps(report) and enc not in json.dumps(report),'SECRET_IN_REPORT')
        write_json_new(output/'report.json',report);print(json.dumps(report,indent=2));return 0 if ok else 2

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);p.add_argument('--veritas-root',type=Path,required=True)
    p.add_argument('--mode',choices=['valid','tampered','revoked','candidate_substitution','request_id_substitution','prestate_drift','scorer_gold_authority'],default='valid');a=p.parse_args()
    raise SystemExit(run(a.output.resolve(),a.veritas_root.resolve(),mode=a.mode))
