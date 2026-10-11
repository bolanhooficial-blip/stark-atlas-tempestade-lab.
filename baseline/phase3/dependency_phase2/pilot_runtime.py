"""ECO Phase 2 -- mandatory *pilot host pathway* for copied reference modules.

NOT an engine patch, NOT an operating-system sandbox, NOT production assurance.
A caller retaining access to raw vendored modules can bypass this host. For this
reason no client/executive release is supported. Only DRAFT_REVIEW_REQUIRED.
"""
from __future__ import annotations
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Callable, Mapping
from hashlib import sha256
import json
import os
import sys

_VENDOR = Path(__file__).parent / 'vendor_snapshots'
if str(_VENDOR) not in sys.path:
    sys.path.insert(0, str(_VENDOR))

import fitz
from security_boundary import (Envelope, Source, GateBlocked, sha_bytes,
    read_bound_bytes, verify_source_set, processing_key, verify_review,
    SignedReview, TrustedReviewer)
from stark_teil import build_default_teil, ToolOutputIntegrityError, TEILError
from stark_orchestrator import classify_document
from atlas_visual_layer import AtlasVisualEngineeringLayer, DetailFrame
from acg_guard import ACG


@dataclass(frozen=True)
class EvidenceResult:
    output_bytes: bytes
    output_sha256: str
    tool_run_id: str
    status: str = 'EVIDENCE_ONLY_NO_EXECUTIVE_RELEASE'


@dataclass(frozen=True)
class DraftArtifact:
    pdf: bytes
    png: bytes
    manifest: Mapping[str, Any]
    output_sha256: str
    status: str = 'DRAFT_REVIEW_REQUIRED'


class PilotRuntime:
    """Test-only, single-instance gate. Does not confer production security."""

    def __init__(self, envelope: Envelope, source_paths: Mapping[str, Path]):
        envelope.validate()
        self.envelope = envelope
        self._paths = {k: Path(v) for k,v in source_paths.items()}
        self._source_bytes = verify_source_set(envelope, self._paths)
        self._workspace = TemporaryDirectory(prefix='eco-f2-',ignore_cleanup_errors=False)
        self.workspace = Path(self._workspace.name)
        self._snapshots: dict[str, Path] = {}
        self._teil = build_default_teil()
        self._acg = ACG()
        self._closed = False
        self._audit = []
        self._atlas = AtlasVisualEngineeringLayer(library_version='PILOT-REFERENCE-ONLY')
        self._registered_bindings = {}
        self._draft_review_envelope = None
        for src in envelope.sources:
            original = self._paths[src.doc_id]
            suffix = original.suffix.lower()
            if suffix not in {'.pdf','.txt','.json','.csv','.dxf','.xlsx','.png'}:
                raise GateBlocked('UNSUPPORTED_PILOT_SOURCE_FORMAT')
            safe_name = f'{src.doc_id}-{src.sha256[:16]}{suffix}'
            snapshot = self.workspace / safe_name
            fd = os.open(str(snapshot), os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o400)
            try:
                with os.fdopen(fd,'wb') as f:
                    f.write(self._source_bytes[src.doc_id])
                    f.flush();os.fsync(f.fileno())
            finally:
                os.chmod(snapshot,0o400)
            self._snapshots[src.doc_id] = snapshot
        self._audit.append({'event':'INPUTS_PINNED','count':len(self._snapshots)})

    def __enter__(self):return self
    def __exit__(self,*exc):self.close()
    def close(self):
        if not self._closed:
            self._workspace.cleanup(); self._closed = True

    def _assert_bound(self):
        if self._closed:raise GateBlocked('PILOT_CLOSED')
        # Recheck both source paths and pinned snapshots before each execution.
        verify_source_set(self.envelope,self._paths)
        for src in self.envelope.sources:
            data = read_bound_bytes(self._snapshots[src.doc_id],src.sha256)
            if data != self._source_bytes[src.doc_id]:
                raise GateBlocked('SNAPSHOT_CHANGED')

    def _assert_scope(self, project_id:str, revision:str):
        if (project_id,revision)!=(self.envelope.project_id,self.envelope.revision):
            raise GateBlocked('CROSS_PROJECT_OR_REVISION_ACCESS')

    def create_project_cell(self):
        self._assert_bound()
        e=self.envelope
        value=self._acg.cells.get((e.project_id,e.revision))
        actual=(e.scope_id, f'{e.normative_standard}:{e.normative_edition}:{e.normative_profile_hash}',
                sha_bytes(b''.join(self._source_bytes[s.doc_id] for s in e.sources)))
        if value is not None and (value.domain,value.normative_profile,value.raw_hash)!=actual:
            raise GateBlocked('CELL_REUSE_CONTEXT_MISMATCH')
        cell=self._acg.create_cell(e.project_id,e.revision,*actual)
        self._audit.append({'event':'CELL_BOUND','project_id':e.project_id})
        return cell

    def process_once(self, payload:bytes)->str:
        self._assert_bound()
        if not isinstance(payload,bytes) or not payload:raise GateBlocked('UNQUALIFIED_PROCESS_PAYLOAD')
        k=processing_key(self.envelope,sha_bytes(payload))
        result=self._acg.process_once({'phase2_full_context_key':k})
        self._audit.append({'event':'IDEMPOTENCY','status':result['status']})
        return result['status']

    def classify_stark_source(self, doc_id:str)->dict:
        self._assert_bound()
        if doc_id not in self._snapshots: raise GateBlocked('UNKNOWN_SOURCE_DOCUMENT')
        src=next(s for s in self.envelope.sources if s.doc_id==doc_id)
        if src.discipline.upper() not in {'SPDA','ELECTRICAL','ARCHITECTURAL_REFERENCE'}:
            raise GateBlocked('UNAUTHORIZED_SOURCE_DISCIPLINE')
        # Real STARK intake/classification, but only on sealed copy, never on raw path.
        doc=classify_document(self._snapshots[doc_id],project_id=self.envelope.project_id,teil=self._teil)
        self._assert_bound()
        if doc.sha256!=src.sha256:raise GateBlocked('STARK_CLASSIFICATION_SHA_MISMATCH')
        result={'source_doc_id':doc_id, 'sha256':doc.sha256,'media_class':doc.media_class,
                'semantic_roles':list(doc.semantic_roles),'classification':'DOCUMENT_ONLY_NOT_VERIFIED_GEOMETRY',
                'project_id':self.envelope.project_id,'revision':self.envelope.revision}
        self._audit.append({'event':'STARK_CLASSIFIED','document':doc_id})
        return result

    @staticmethod
    def _json_snapshot(obj:Any)->bytes:
        if obj is None or obj=={} or obj==[] or obj=='' or obj==b'':
            raise GateBlocked('EMPTY_TOOL_OUTPUT')
        try:
            snapshot=json.dumps(obj,ensure_ascii=False,sort_keys=True,
                separators=(',', ':'),allow_nan=False).encode('utf-8')
            roundtrip=json.loads(snapshot)
        except (TypeError,ValueError,OverflowError) as exc:
            raise GateBlocked('NON_CANONICAL_TOOL_RESULT') from exc
        if not isinstance(roundtrip,dict) or not roundtrip:
            raise GateBlocked('TOOL_RESULT_SCHEMA_REQUIRED')
        if roundtrip.get('warnings') or roundtrip.get('error'):
            raise GateBlocked('UNRESOLVED_TOOL_WARNING_OR_ERROR')
        return snapshot

    def execute_teil(self, *, tool_id:str,operation:str,input_payload:dict,
                     producer:Callable[[],dict],schema_validator:Callable[[dict],bool]|None) -> EvidenceResult:
        self._assert_bound()
        if schema_validator is None or not callable(schema_validator):
            raise GateBlocked('SCHEMA_VALIDATOR_REQUIRED')
        captured=[]
        def call():
            raw=producer()
            data=self._json_snapshot(raw)
            captured.append(data)
            return json.loads(data)
        def check(obj):
            try:
                data=self._json_snapshot(obj)
                if schema_validator(obj) is not True:
                    return False,'EXTERNAL_SCHEMA_REJECTED'
                return data==captured[0],'TOOL_OUTPUT_NOT_PINNED'
            except Exception:
                return False,'INVALID_CANONICAL_OUTPUT'
        try:
            version=self._teil.spec(tool_id).version
            result=self._teil.execute(tool_id=tool_id,tool_version=version,
                operation=operation,project_id=self.envelope.project_id,
                input_payload={'envelope':self.envelope.fingerprint(),'input':input_payload},
                call=call,output_validator=check)
        except TEILError as exc:
            raise GateBlocked('TEIL_CONTROL_REJECTED') from exc
        frozen=captured[0]
        if self._teil.fingerprint(json.loads(frozen))!=result.receipt.output_fingerprint:
            raise GateBlocked('RECEIPT_OUTPUT_MISMATCH')
        self._assert_bound()
        self._audit.append({'event':'TEIL_EVIDENCE','tool':tool_id,'sha256':sha_bytes(frozen)})
        return EvidenceResult(frozen,sha_bytes(frozen),result.receipt.tool_run_id)

    def bind_atlas(self, doc_id:str,*, geometry_payload:dict,dimension_payload:dict):
        self._assert_bound()
        src=next((s for s in self.envelope.sources if s.doc_id==doc_id),None)
        if src is None or self._snapshots[doc_id].suffix != '.pdf':
            raise GateBlocked('ATLAS_REQUIRES_BOUND_PDF')
        binding=self._atlas.bind_project(project_id=self.envelope.project_id,
            revision_id=self.envelope.revision,source_file=self._snapshots[doc_id],
            geometry_payload=geometry_payload,dimension_payload=dimension_payload,
            scale_mode='NO_SCALE',technical_state='CHECKED')
        if binding.source_sha256!=src.sha256:raise GateBlocked('ATLAS_SOURCE_MISMATCH')
        self._registered_bindings[doc_id]=(binding,geometry_payload,dimension_payload)
        self._audit.append({'event':'ATLAS_BOUND','document':doc_id})
        return binding

    def export_atlas_draft(self,doc_id:str,*,page_number:int=1,
                           bbox:tuple[float,float,float,float]|None=None,
                           dpi:int=100)->DraftArtifact:
        self._assert_bound()
        if doc_id not in self._registered_bindings:raise GateBlocked('ATLAS_DOCUMENT_UNBOUND')
        binding,geometry_payload,dimension_payload=self._registered_bindings[doc_id]
        src=next(s for s in self.envelope.sources if s.doc_id==doc_id)
        if binding.source_sha256!=src.sha256: raise GateBlocked('ATLAS_BINDING_STALE')
        doc=fitz.open(stream=self._source_bytes[doc_id],filetype='pdf')
        try:
            if page_number<1 or page_number>len(doc):raise GateBlocked('PDF_PAGE_INVALID')
            bounds=doc[page_number-1].rect
            rect=bbox or (float(bounds.x0),float(bounds.y0),float(bounds.x1),float(bounds.y1))
            clip=fitz.Rect(*rect)
            if clip.is_empty or clip.is_infinite or clip not in bounds:
                raise GateBlocked('INVALID_PDF_BBOX')
        finally:doc.close()
        sess=self._atlas.start_session(project_id=self.envelope.project_id,
            revision_id=self.envelope.revision,output_profile='TECHNICAL_EXACT')
        detail=DetailFrame('PILOT-PDF-PAGE',page_number,tuple(rect),self.envelope.project_id,self.envelope.revision,True)
        out_pdf=self.workspace/'pilot_result.pdf';out_png=self.workspace/'pilot_result.png'
        try:
            manifest=self._atlas.export_technical_exact(project_id=self.envelope.project_id,
                revision_id=self.envelope.revision,session_id=sess.session_id,detail=detail,
                out_pdf=out_pdf,out_png=out_png,dpi=dpi,
                geometry_fingerprint=binding.geometry_fingerprint,
                dimension_fingerprint=binding.dimension_fingerprint,
                annotation_complete=True,clipping_detected=False)
            self._assert_bound()   # blocks changed original or snapshot during rendering
            pdf_bytes=out_pdf.read_bytes();png_bytes=out_png.read_bytes()
            if not pdf_bytes.startswith(b'%PDF-') or not png_bytes.startswith(b'\x89PNG\r\n\x1a\n'):
                raise GateBlocked('INVALID_DERIVATIVE_FORMAT')
            pdoc=fitz.open(stream=pdf_bytes,filetype='pdf')
            if len(pdoc)!=1:raise GateBlocked('INVALID_DERIVATIVE_PAGES')
            pdoc.close()
            metadata=asdict(manifest)
            metadata.update({'output_pdf_sha256':sha_bytes(pdf_bytes),'output_png_sha256':sha_bytes(png_bytes),
                             'phase2_release_status':'DRAFT_REVIEW_REQUIRED'})
            self._draft_review_envelope = replace(self.envelope, output_id=manifest.output_id, output_sha256=sha_bytes(pdf_bytes))
            self._audit.append({'event':'ATLAS_DRAFT','sha256':sha_bytes(pdf_bytes)})
            return DraftArtifact(pdf_bytes,png_bytes,metadata,sha_bytes(pdf_bytes))
        except Exception:
            # Never leave rejected files available as a deliverable.
            for p in (out_pdf,out_png):
                p.unlink(missing_ok=True)
            raise

    def verify_external_review(self, signed:SignedReview|None,
                               trusted_registry:Mapping[str,TrustedReviewer],
                               credential_verifier:Callable|None,evidence_verifier:Callable|None,
                               *,prepared_by:str,independent_audit:bool)->str:
        self._assert_bound()
        if self._draft_review_envelope is None:
            raise GateBlocked('NO_BOUND_DRAFT_TO_REVIEW')
        result=verify_review(self._draft_review_envelope,signed,trusted_registry,
            credential_verifier,evidence_verifier,prepared_by,independent_audit)
        self._audit.append({'event':'EXTERNALLY_ATTESTED_REVIEW',
                            'state':'REVIEW_ELIGIBLE_NOT_RELEASED'})
        return result

    def review_envelope(self)->Envelope:
        if self._draft_review_envelope is None:raise GateBlocked('NO_BOUND_DRAFT_TO_REVIEW')
        return self._draft_review_envelope

    def require_spda_execution(self):
        raise GateBlocked('TEMPESTADE_SPDA_EXECUTION_NOT_QUALIFIED')

    def require_executive_release(self):
        raise GateBlocked('NO_PRODUCTION_RELEASE_IN_PHASE2')

    def audit_events(self)->tuple[dict,...]:
        return tuple(json.loads(json.dumps(e)) for e in self._audit)
