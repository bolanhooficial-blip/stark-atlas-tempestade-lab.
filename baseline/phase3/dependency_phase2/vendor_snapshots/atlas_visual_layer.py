
from __future__ import annotations
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Iterable
import hashlib, json, math, re
import fitz

LAYER_VERSION = "1.0.0"

ALLOWED_OUTPUT_PROFILES = {"TECHNICAL_EXACT", "ENGINEERING_PREMIUM", "DETAIL_INSPECTION"}
TECHNICAL_STATES = {"VALIDATED", "CHECKED", "AUDITED", "AUDITED_STRICT", "APPROVED"}

class AtlasVisualError(RuntimeError): pass
class ProjectIsolationError(AtlasVisualError): pass
class FidelityError(AtlasVisualError): pass
class DimensionAuthorityError(AtlasVisualError): pass
class OutputEligibilityError(AtlasVisualError): pass
class CrossProjectContaminationError(AtlasVisualError): pass

def canon_hash(value: Any) -> str:
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()

def file_sha256(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

@dataclass(frozen=True)
class ProjectBinding:
    project_id: str
    revision_id: str
    source_file: str
    source_sha256: str
    library_version: str
    geometry_fingerprint: str
    dimension_fingerprint: str
    scale_mode: str
    technical_state: str

@dataclass(frozen=True)
class VisualSession:
    session_id: str
    project_id: str
    revision_id: str
    output_profile: str
    binding_fingerprint: str

@dataclass(frozen=True)
class DetailFrame:
    detail_id: str
    page: int
    bbox: tuple[float, float, float, float]
    source_project_id: str
    source_revision_id: str
    vector_source: bool = True

@dataclass(frozen=True)
class OutputManifest:
    output_id: str
    project_id: str
    revision_id: str
    session_id: str
    source_sha256: str
    geometry_fingerprint: str
    dimension_fingerprint: str
    detail_id: str
    output_profile: str
    source_bbox: tuple[float, float, float, float]
    fidelity_status: str
    technical_state: str
    generated_from_read_only_source: bool = True

class AtlasVisualEngineeringLayer:
    """Read-only visual derivation layer.
    It can crop/export/represent validated source geometry, but cannot mutate technical truth.
    """
    def __init__(self, library_version: str = "AEL-UNSPECIFIED"):
        self.library_version = library_version
        self._bindings: dict[tuple[str,str], ProjectBinding] = {}
        self._sessions: dict[str, VisualSession] = {}
        self._output_manifests: list[dict[str,Any]] = []

    def bind_project(
        self, *, project_id: str, revision_id: str, source_file: str | Path,
        geometry_payload: Any, dimension_payload: Any, scale_mode: str,
        technical_state: str
    ) -> ProjectBinding:
        if not project_id or not revision_id:
            raise ProjectIsolationError("PROJECT_ID_AND_REVISION_REQUIRED")
        key = (project_id, revision_id)
        src = Path(source_file)
        if not src.exists():
            raise OutputEligibilityError("SOURCE_UNAVAILABLE")
        if technical_state not in TECHNICAL_STATES:
            raise OutputEligibilityError("TECHNICAL_STATE_NOT_ELIGIBLE")
        b = ProjectBinding(
            project_id=project_id,
            revision_id=revision_id,
            source_file=str(src),
            source_sha256=file_sha256(src),
            library_version=self.library_version,
            geometry_fingerprint=canon_hash(geometry_payload),
            dimension_fingerprint=canon_hash(dimension_payload),
            scale_mode=scale_mode.upper().strip(),
            technical_state=technical_state,
        )
        if key in self._bindings and self._bindings[key] != b:
            raise ProjectIsolationError("PROJECT_REVISION_REBIND_BLOCKED")
        self._bindings[key] = b
        return b

    def binding(self, project_id: str, revision_id: str) -> ProjectBinding:
        try:
            return self._bindings[(project_id, revision_id)]
        except KeyError as exc:
            raise ProjectIsolationError("UNBOUND_PROJECT_REVISION") from exc

    def start_session(self, *, project_id: str, revision_id: str, output_profile: str) -> VisualSession:
        b = self.binding(project_id, revision_id)
        if output_profile not in ALLOWED_OUTPUT_PROFILES:
            raise OutputEligibilityError("UNKNOWN_OUTPUT_PROFILE")
        sid = "VIS-" + canon_hash({
            "project_id":project_id, "revision_id":revision_id,
            "source_sha256":b.source_sha256, "output_profile":output_profile
        })[:16].upper()
        s = VisualSession(
            session_id=sid, project_id=project_id, revision_id=revision_id,
            output_profile=output_profile, binding_fingerprint=canon_hash(asdict(b))
        )
        self._sessions[sid] = s
        return s

    def assert_session_binding(self, session_id: str, project_id: str, revision_id: str) -> None:
        s = self._sessions.get(session_id)
        if not s:
            raise ProjectIsolationError("UNKNOWN_VISUAL_SESSION")
        if (s.project_id, s.revision_id) != (project_id, revision_id):
            raise CrossProjectContaminationError("VISUAL_SESSION_PROJECT_MISMATCH")

    def assert_dimension_authority(self, project_id: str, revision_id: str, *, infer_from_graphic: bool=False) -> None:
        b = self.binding(project_id, revision_id)
        if infer_from_graphic:
            raise DimensionAuthorityError("DIMENSION_INFERENCE_FROM_GRAPHIC_PROHIBITED")
        if b.scale_mode in {"S/ESC", "NO_SCALE", "NTS"} and infer_from_graphic:
            raise DimensionAuthorityError("NO_DIMENSION_INFERENCE_FROM_GRAPHIC_SCALE")

    @staticmethod
    def _dedupe_rects(rects: Iterable[fitz.Rect], tol: float = 1.0) -> list[fitz.Rect]:
        out=[]
        for r in rects:
            if any(abs(r.x0-u.x0)<=tol and abs(r.y0-u.y0)<=tol and abs(r.x1-u.x1)<=tol and abs(r.y1-u.y1)<=tol for u in out):
                continue
            out.append(r)
        return out

    def detect_detail_frames(self, project_id: str, revision_id: str, page_number: int=1) -> list[DetailFrame]:
        b = self.binding(project_id, revision_id)
        doc = fitz.open(b.source_file)
        if page_number < 1 or page_number > len(doc):
            raise OutputEligibilityError("PAGE_OUT_OF_RANGE")
        page = doc[page_number-1]
        parea = page.rect.width * page.rect.height
        rects=[]
        for d in page.get_drawings():
            r=d.get("rect")
            if not r:
                continue
            w,h=r.width,r.height
            area=w*h
            # Candidate detail panels: rectangular technical regions, excluding outer sheet border and micro geometry.
            if w >= 70 and h >= 65 and area <= parea*0.09 and area >= parea*0.012:
                rects.append(fitz.Rect(r))
        rects=self._dedupe_rects(rects)
        # Remove obvious title-block zone: low-left compact panels intersecting the last ~17% of page height.
        clean=[]
        for r in rects:
            if r.y0 > page.rect.height*0.82 and r.x0 < page.rect.width*0.23:
                continue
            clean.append(r)
        clean=sorted(clean, key=lambda r:(r.y0,r.x0))
        return [
            DetailFrame(
                detail_id=f"P{page_number:02d}-D{i+1:02d}",
                page=page_number,
                bbox=(float(r.x0),float(r.y0),float(r.x1),float(r.y1)),
                source_project_id=project_id,
                source_revision_id=revision_id,
                vector_source=True
            )
            for i,r in enumerate(clean)
        ]

    def fidelity_gate(
        self, *, project_id: str, revision_id: str, session_id: str, detail: DetailFrame,
        geometry_fingerprint: str, dimension_fingerprint: str,
        annotation_complete: bool, clipping_detected: bool, stale: bool=False,
        cross_project_refs: list[str] | None=None
    ) -> dict[str,Any]:
        self.assert_session_binding(session_id, project_id, revision_id)
        b=self.binding(project_id, revision_id)
        blockers=[]
        if detail.source_project_id != project_id or detail.source_revision_id != revision_id:
            blockers.append("DETAIL_PROJECT_BINDING_MISMATCH")
        if geometry_fingerprint != b.geometry_fingerprint:
            blockers.append("GEOMETRY_FINGERPRINT_MISMATCH")
        if dimension_fingerprint != b.dimension_fingerprint:
            blockers.append("DIMENSION_FINGERPRINT_MISMATCH")
        if not annotation_complete:
            blockers.append("ANNOTATION_INCOMPLETE")
        if clipping_detected:
            blockers.append("OUTPUT_CLIPPING_DETECTED")
        if stale:
            blockers.append("STALE_DEPENDENCY")
        if cross_project_refs:
            blockers.append("CROSS_PROJECT_REFERENCE_DETECTED")
        return {"eligible":not blockers,"blockers":blockers}

    def export_technical_exact(
        self, *, project_id: str, revision_id: str, session_id: str, detail: DetailFrame,
        out_pdf: str | Path, out_png: str | Path, dpi: int=600,
        geometry_fingerprint: str, dimension_fingerprint: str,
        annotation_complete: bool=True, clipping_detected: bool=False, stale: bool=False,
        cross_project_refs: list[str] | None=None
    ) -> OutputManifest:
        s=self._sessions.get(session_id)
        if not s or s.output_profile != "TECHNICAL_EXACT":
            raise OutputEligibilityError("TECHNICAL_EXACT_SESSION_REQUIRED")
        gate=self.fidelity_gate(
            project_id=project_id, revision_id=revision_id, session_id=session_id, detail=detail,
            geometry_fingerprint=geometry_fingerprint, dimension_fingerprint=dimension_fingerprint,
            annotation_complete=annotation_complete, clipping_detected=clipping_detected,
            stale=stale, cross_project_refs=cross_project_refs
        )
        if not gate["eligible"]:
            raise FidelityError("OUTPUT_BLOCKED:" + ",".join(gate["blockers"]))
        b=self.binding(project_id, revision_id)
        doc=fitz.open(b.source_file)
        page=doc[detail.page-1]
        clip=fitz.Rect(*detail.bbox)
        # Vector PDF crop: no generative redraw.
        odoc=fitz.open()
        opage=odoc.new_page(width=clip.width,height=clip.height)
        opage.show_pdf_page(opage.rect, doc, detail.page-1, clip=clip, keep_proportion=True)
        out_pdf=Path(out_pdf); out_pdf.parent.mkdir(parents=True,exist_ok=True)
        odoc.save(out_pdf)
        odoc.close()
        # High resolution raster companion.
        zoom=dpi/72.0
        pix=page.get_pixmap(matrix=fitz.Matrix(zoom,zoom), clip=clip, alpha=False)
        out_png=Path(out_png); out_png.parent.mkdir(parents=True,exist_ok=True)
        pix.save(out_png)
        manifest=OutputManifest(
            output_id="OUT-"+canon_hash({
                "session":session_id,"detail":detail.detail_id,
                "source":b.source_sha256,"bbox":detail.bbox,"profile":s.output_profile
            })[:18].upper(),
            project_id=project_id, revision_id=revision_id, session_id=session_id,
            source_sha256=b.source_sha256,
            geometry_fingerprint=b.geometry_fingerprint,
            dimension_fingerprint=b.dimension_fingerprint,
            detail_id=detail.detail_id, output_profile=s.output_profile,
            source_bbox=detail.bbox, fidelity_status="PASS",
            technical_state=b.technical_state, generated_from_read_only_source=True
        )
        self._output_manifests.append(asdict(manifest))
        return manifest

    def premium_eligibility(
        self, *, project_id: str, revision_id: str,
        validated_3d_geometry: bool, validated_dimensions: bool,
        allow_invented_depth: bool=False
    ) -> dict[str,Any]:
        self.binding(project_id, revision_id)
        blockers=[]
        if not validated_dimensions:
            blockers.append("UNVERIFIED_DIMENSIONS")
        if allow_invented_depth:
            blockers.append("INVENTED_DEPTH_PROHIBITED")
        if not validated_3d_geometry:
            blockers.append("NO_VALIDATED_3D_GEOMETRY_FOR_TRUE_3D")
        return {"eligible":not blockers,"blockers":blockers,
                "fallback":"HIGH_FIDELITY_2D_ONLY" if "NO_VALIDATED_3D_GEOMETRY_FOR_TRUE_3D" in blockers else None}

    def manifests(self) -> list[dict[str,Any]]:
        return list(self._output_manifests)
