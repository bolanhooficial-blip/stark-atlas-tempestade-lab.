from __future__ import annotations
import json, os, sqlite3, sys, tempfile, unittest
from dataclasses import replace
from hashlib import sha256
from pathlib import Path
from contextlib import contextmanager
import fitz

sys.path.insert(0,str(Path(__file__).parents[1]/'runtime'))
from phase3_broker import MandatoryBroker,Blocked,DurableLedger,PHASE2

H=lambda b: sha256(b).hexdigest()

class Phase3Fixture:
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.work=Path(self.temp.name)
        self.src=self.work/'synthetic.pdf'
        doc=fitz.open();pg=doc.new_page(width=320,height=200)
        pg.insert_text((20,60),'SYNTHETIC DOCUMENT — NEVER CLIENT DATA');doc.save(self.src);doc.close()
        self.env={
            'project_id':'P001','service_id':'S1','scope_id':'SPDA','revision':'V01','engine':'STARK',
            'normative_standard':'ABNT_NBR_5419','normative_edition':'2026',
            'normative_profile_hash':'1'*64,'ruleset_hash':'2'*64,
            'engine_version':'F3-PILOT',
            'sources':[{'doc_id':'DOC1','revision':'V01','sha256':H(self.src.read_bytes()),'discipline':'SPDA'}],
            'output_id':'PENDING','output_sha256':'0'*64,'required_controls':['document','review']}
        self.broker=MandatoryBroker(self.work/'state',test_probes=True)
        self.addCleanup(self.broker.ledger.close)
    def execute(self,operation='CLASSIFY_STARK',env=None,params=None,src=None):
        e=dict(self.env) if env is None else env
        return self.broker.execute(operation,e,{'DOC1':self.src} if src is None else src,
            {'doc_id':'DOC1'} if params is None else params,timeout=20)
    def assertBlocked(self,fun,contains=None):
        with self.assertRaises(Blocked) as cm:fun()
        if contains:self.assertIn(contains,str(cm.exception))

class Phase3Tests(Phase3Fixture, unittest.TestCase):
    def test_01_real_classification_in_namespace(self):
        r=self.execute();self.assertEqual(r.state,'EVIDENCE_ONLY')
        self.assertEqual(r.details['payload']['data']['project_id'],'P001')
    def test_02_namespace_isolation(self):
        r=self.execute('ISOLATION_PROBE',params={})
        d=r.details['payload'];self.assertFalse(d['host_file_visible'])
        self.assertFalse(d['root_visible']);self.assertEqual(d['network_loopback'],'BLOCKED')
    def test_03_atlas_render_in_namespace(self):
        e=dict(self.env,engine='ATLAS')
        r=self.execute('EXPORT_ATLAS_DRAFT',env=e,params={'doc_id':'DOC1','geometry_payload':{'bbox':[0,0,320,200]},'dimension_payload':{'synthetic':True}})
        self.assertEqual(r.state,'DRAFT_REVIEW_REQUIRED')
        self.assertTrue(r.artifact_pdf.startswith(b'%PDF-'))
    def test_04_duplicate_run_blocked(self):
        self.execute();self.assertBlocked(lambda:self.execute(),'DUPLICATE')
    def test_05_change_project_new_run(self):
        self.execute();r=self.execute(env=dict(self.env,project_id='P002'))
        self.assertEqual(r.state,'EVIDENCE_ONLY')
    def test_06_change_revision_new_run(self):
        self.execute();r=self.execute(env=dict(self.env,revision='V02'))
        self.assertEqual(r.state,'EVIDENCE_ONLY')
    def test_07_change_normative_edition_new_run(self):
        self.execute();r=self.execute(env=dict(self.env,normative_edition='2015'))
        self.assertEqual(r.state,'EVIDENCE_ONLY')
    def test_08_change_ruleset_new_run(self):
        self.execute();r=self.execute(env=dict(self.env,ruleset_hash='3'*64))
        self.assertEqual(r.state,'EVIDENCE_ONLY')
    def test_09_source_changed_blocks_before_worker(self):
        self.src.write_bytes(b'WRONG');self.assertBlocked(self.execute)
    def test_10_source_symlink_rejected(self):
        target=self.work/'symlink.pdf';target.symlink_to(self.src)
        self.assertBlocked(lambda:self.execute(src={'DOC1':target}))
    def test_11_path_traversal_docid_rejected(self):
        e=dict(self.env,sources=[dict(self.env['sources'][0],doc_id='../bad')])
        self.assertBlocked(lambda:self.execute(env=e))
    def test_12_abs_path_docid_rejected(self):
        e=dict(self.env,sources=[dict(self.env['sources'][0],doc_id='/tmp/bad')])
        self.assertBlocked(lambda:self.execute(env=e))
    def test_13_engine_route_STARK(self):
        self.assertBlocked(lambda:self.execute(env=dict(self.env,engine='ATLAS')))
    def test_14_engine_route_ATLAS(self):
        self.assertBlocked(lambda:self.execute('EXPORT_ATLAS_DRAFT'))
    def test_15_spda_execution_forbidden(self):
        self.assertBlocked(lambda:self.execute('SPDA_CALCULATE',params={}))
    def test_16_release_forbidden(self):
        self.assertBlocked(lambda:self.execute('EXECUTIVE_RELEASE',params={}))
    def test_17_arbitrary_operation_forbidden(self):
        self.assertBlocked(lambda:self.execute('python_eval',params={'script':'pass'}))
    def test_18_probe_disabled_by_default(self):
        b=MandatoryBroker(self.work/'state2',test_probes=False);self.addCleanup(b.ledger.close)
        self.assertBlocked(lambda:b.execute('ISOLATION_PROBE',self.env,{'DOC1':self.src},{}))
    def test_19_param_path_injection_rejected(self):
        self.assertBlocked(lambda:self.execute(params={'doc_id':'DOC1','script':'malicious'}))
    def test_20_source_set_mismatch(self):
        self.assertBlocked(lambda:self.execute(src={}))
    def test_21_unsupported_source(self):
        alt=self.work/'d.bin';alt.write_bytes(self.src.read_bytes())
        self.assertBlocked(lambda:self.execute(src={'DOC1':alt}))
    def test_22_pdf_output_hash(self):
        e=dict(self.env,engine='ATLAS')
        r=self.execute('EXPORT_ATLAS_DRAFT',env=e,params={'doc_id':'DOC1','geometry_payload':{},'dimension_payload':{}})
        self.assertEqual(H(r.artifact_pdf),r.details['payload']['pdf_sha256'])
        self.assertEqual(H(r.artifact_png),r.details['payload']['png_sha256'])
    def test_23_ledger_hmac_detects_modified_record(self):
        r=self.execute()
        self.broker.ledger.cx.execute('UPDATE runs SET details=? WHERE run_key=?',('"not-real"',r.run_key))
        # Event MAC only protects event journal; run record alteration is a separate gap.
        # This test documents the missing binding and must be strengthened by broker.
        self.assertBlocked(lambda:self.broker.ledger.report(r.run_key),'AUDIT')
    def test_24_event_hmac_detects_mutation(self):
        self.execute()
        self.broker.ledger.cx.execute("UPDATE events SET event='altered' WHERE id=1")
        self.assertBlocked(self.broker.ledger.validate,'AUDIT_CHAIN')
    def test_25_anchor_detects_deletion(self):
        self.execute();self.broker.ledger.cx.execute('DELETE FROM events WHERE id=2')
        self.assertBlocked(self.broker.ledger.validate)
    def test_26_key_file_permissions(self):
        self.assertEqual(self.broker.ledger.key_file.stat().st_mode & 0o777,0o600)
    def test_27_namespace_dependency_fail_closed(self):
        old=self.broker._spawn_isolated
        def missing(*a,**kw):raise Blocked('NAMESPACE_UNAVAILABLE')
        self.broker._spawn_isolated=missing
        self.assertBlocked(self.execute)
        self.assertEqual(self.broker.ledger.cx.execute('SELECT state FROM runs').fetchone()[0],'BLOCKED')
    def test_28_attempt_state_is_durable(self):
        r=self.execute();self.assertEqual(self.broker.ledger.report(r.run_key)['state'],'EVIDENCE_ONLY')
        other=DurableLedger(self.work/'state')
        self.assertEqual(other.report(r.run_key)['state'],'EVIDENCE_ONLY')
        other.close()
    def test_29_no_external_client_project(self):
        self.assertFalse((self.work/'state'/'draft.pdf').exists())
    def test_30_bad_params_bbox(self):
        e=dict(self.env,engine='ATLAS')
        self.assertBlocked(lambda:self.execute('EXPORT_ATLAS_DRAFT',env=e,params={'doc_id':'DOC1','geometry_payload':{},'dimension_payload':{},'bbox':[1,2,3,float('nan')]}))

class ExpandedPhase3Tests(Phase3Fixture, unittest.TestCase):
    """Additional adversarial and concurrency tests; no duplicate base test counting."""
    def test_31_private_workdir_has_nonshared_uid(self):
        import subprocess
        orig=subprocess.run
        observations=[]
        def spy(cmd,**kw):
            stage=Path(cmd[-1]); parent=stage.parent
            observations.append((parent.stat().st_mode&0o777,parent.stat().st_uid,
                                 stage.stat().st_mode&0o777,stage.stat().st_uid,
                                 (stage/'out').stat().st_mode&0o777))
            return orig(cmd,**kw)
        import unittest.mock as mock
        with mock.patch('phase3_broker.subprocess.run',side_effect=spy):
            self.execute()
        self.assertEqual(len(observations),1)
        pmod,puid,rmod,ruid,outmod=observations[0]
        self.assertEqual(pmod,0o700);self.assertEqual(rmod,0o700)
        self.assertEqual(outmod,0o700);self.assertEqual(puid,ruid)
        self.assertGreaterEqual(puid,200000)
    def test_32_document_hash_change_new_context_key(self):
        self.execute()
        before=self.src.read_bytes()
        self.src.write_bytes(before+b' NEW REVISION')
        e=dict(self.env,revision='V02',sources=[dict(self.env['sources'][0],revision='V02',sha256=H(self.src.read_bytes()))])
        r=self.execute(env=e)
        self.assertEqual(r.state,'EVIDENCE_ONLY')
    def test_33_output_no_project_leak(self):
        r=self.execute();alltext=json.dumps(r.details)
        self.assertNotIn(self.temp.name,alltext)
    def test_34_ledger_rejects_changed_state(self):
        r=self.execute()
        self.broker.ledger.cx.execute('UPDATE runs SET state=? WHERE run_key=?',('DRAFT_REVIEW_REQUIRED',r.run_key))
        self.assertBlocked(self.broker.ledger.validate)
    def test_35_ledger_rejects_deleted_run(self):
        r=self.execute();self.broker.ledger.cx.execute('DELETE FROM runs WHERE run_key=?',(r.run_key,))
        self.assertBlocked(self.broker.ledger.validate)
    def test_36_ledger_rejects_changed_project(self):
        r=self.execute();self.broker.ledger.cx.execute('UPDATE runs SET project_id=? WHERE run_key=?',('P-WRONG',r.run_key))
        self.assertBlocked(self.broker.ledger.validate)
    def test_37_failure_state_rejects_retry(self):
        # Inject failure after durable CLAIM; status must remain BLOCKED.
        self.broker._spawn_isolated=lambda *a: (_ for _ in ()).throw(Blocked('SBOX_UNAVAILABLE'))
        self.assertBlocked(self.execute)
        self.assertBlocked(self.execute,'DUPLICATE')
    def test_38_incomplete_previous_run_is_not_auto_promoted(self):
        key='f'*64
        self.broker.ledger.claim(key,'P001','V01','CLASSIFY_STARK')
        self.assertEqual(self.broker.ledger.report(key)['state'],'RUNNING')
        self.assertFalse(self.broker.ledger.claim(key,'P001','V01','CLASSIFY_STARK'))
    def test_39_context_isolated_across_normative_profiles(self):
        self.execute()
        r=self.execute(env=dict(self.env,normative_profile_hash='4'*64))
        self.assertEqual(r.state,'EVIDENCE_ONLY')
    def test_40_no_script_execution_parameter(self):
        self.assertBlocked(lambda:self.execute(params={'doc_id':'DOC1','source_code':'print(1)'}))
    def test_41_manifest_version_untouched(self):
        from pathlib import Path
        import json
        phase=PHASE2
        manifest=json.loads((phase/'VENDOR_BASELINE_HASHES.json').read_text())
        self.assertEqual(len(manifest),18)
        for n,x in manifest.items():self.assertEqual(H((phase/'vendor_snapshots'/n).read_bytes()),x['sha256'])
    def test_42_audit_atomic_duplicate_two_connections(self):
        import threading
        b2=MandatoryBroker(self.work/'state',test_probes=True)
        self.addCleanup(b2.ledger.close)
        errors=[];ok=[]
        def task(b):
            try:r=b.execute('CLASSIFY_STARK',self.env,{'DOC1':self.src},{'doc_id':'DOC1'});ok.append(r.state)
            except Blocked as exc:errors.append(str(exc))
        t=threading.Thread(target=task,args=(b2,));t.start()
        task(self.broker);t.join(timeout=20)
        self.assertFalse(t.is_alive())
        self.assertEqual(len(ok),1)
        self.assertEqual(len(errors),1)
        self.assertIn('DUPLICATE',errors[0])
    def test_43_private_installation_directory_can_launch_sandbox(self):
        import shutil
        from unittest.mock import patch
        from pathlib import Path
        private=self.work/'private-install'
        private.mkdir(mode=0o700)
        src=Path(__file__).resolve().parents[1]/'runtime'
        for name in ('worker.py','namespace_entry.sh'):
            shutil.copyfile(src/name,private/name)
        private.chmod(0o700)
        with patch('phase3_broker.ROOT',private):
            result=self.execute()
        self.assertEqual(result.state,'EVIDENCE_ONLY')
