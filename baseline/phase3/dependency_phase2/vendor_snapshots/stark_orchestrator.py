from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any, Iterable, Mapping
import json
import re

from stark_provenance import WorkbookCellIndex
from stark_cad_reconstruct import (
    reconstruct_building_from_cad,
    audit_cad_reconstruction,
    run_cad_to_rolling_sphere,
    export_reconstruction_dxf,
    build_cad_handoff,
)
from stark_geometry_3d import export_3d_dxf
from stark_teil import ToolExecutionIntegrityLayer, build_default_teil
from ecosystem_eicf import EcosystemIntegrityFabric, build_reference_fabric

try:
    import ezdxf
except Exception:  # pragma: no cover
    ezdxf = None

ORCHESTRATOR_VERSION = "1.2.0-TEIL-EICF"
SCHEMA_VERSION = "1.0"

WORKFLOW = {
    "operator": {
        "name": "Bolanho",
        "role": "Operador STARK / prestador de serviços",
        "authority": "OPERATE_AND_PREPARE",
    },
    "engineer": {
        "name": "Régis",
        "role": "Engenheiro eletricista / validador técnico",
        "authority": "TECHNICAL_VALIDATE_OR_REJECT",
    },
    "flow": [
        "REGIS_PROVIDES_INPUTS",
        "BOLANHO_OPERATES_STARK",
        "STARK_CLASSIFIES_ROUTES_EXECUTES_AND_AUDITS",
        "BOLANHO_REVIEWS_HANDOFF_PACKAGE",
        "BOLANHO_SENDS_TO_REGIS",
        "REGIS_VALIDATES_TECHNICALLY",
    ],
    "maximum_automated_state": "READY_FOR_REGIS_VALIDATION",
}

FACT_STATUSES = {
    "CONFIRMED", "EXTRACTED", "CALCULATED", "OBSERVED", "PENDING", "CONFLICTING", "PROPOSED"
}

MODULE_ORDER = [
    "INPUT_INGESTION",
    "RISK_INGESTION",
    "RISK_RECONCILIATION",
    "CAD_RECONSTRUCTION",
    "GEOMETRY_3D",
    "SPDA_ARRANGEMENT",
    "INDEPENDENT_AUDIT",
    "TOOL_EXECUTION_INTEGRITY",
    "ECOSYSTEM_INTERNAL_CONTAINMENT",
    "HANDOFF",
]


class OrchestratorError(ValueError):
    pass


@dataclass(frozen=True)
class InputDocument:
    document_id: str
    filename: str
    extension: str
    sha256: str
    size_bytes: int
    media_class: str
    semantic_roles: list[str]
    status: str


def _canon(obj: Any) -> bytes:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def digest(obj: Any) -> str:
    return sha256(_canon(obj)).hexdigest()


def file_sha256(path: str | Path) -> str:
    h = sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _revision_number(revision: str) -> int:
    m = re.fullmatch(r"V(\d+)", revision or "")
    if not m:
        raise OrchestratorError("INVALID_REVISION")
    return int(m.group(1))


def next_revision(previous_manifest: Mapping[str, Any] | None) -> str:
    if not previous_manifest:
        return "V01"
    return f"V{_revision_number(str(previous_manifest.get('revision', 'V00'))) + 1:02d}"


def _project_id(paths: list[Path], previous_manifest: Mapping[str, Any] | None, explicit: str | None) -> str:
    if explicit:
        return explicit
    if previous_manifest and previous_manifest.get("project_id"):
        return str(previous_manifest["project_id"])
    seed = [(p.name, file_sha256(p)) for p in sorted(paths, key=lambda x: x.name.lower())]
    return "STK-PRJ-" + digest(seed)[:10].upper()


def _media_class(ext: str) -> str:
    return {
        ".xlsx": "SPREADSHEET",
        ".xlsm": "SPREADSHEET",
        ".dxf": "CAD",
        ".dwg": "CAD",
        ".pdf": "DOCUMENT",
        ".png": "IMAGE",
        ".jpg": "IMAGE",
        ".jpeg": "IMAGE",
        ".webp": "IMAGE",
        ".json": "STRUCTURED_DATA",
        ".csv": "STRUCTURED_DATA",
        ".txt": "TEXT",
        ".md": "TEXT",
    }.get(ext, "OTHER")


def _xlsx_roles(path: Path, *, teil: ToolExecutionIntegrityLayer, project_id: str) -> list[str]:
    roles = ["SPREADSHEET"]
    try:
        env = teil.execute(
            tool_id="RISK_WORKBOOK_PARSER", tool_version="1.0.0", operation="CLASSIFY",
            project_id=project_id,
            input_payload={"path": str(path), "sha256": file_sha256(path)},
            call=lambda: WorkbookCellIndex(path),
            output_validator=lambda x: (bool(getattr(x, "sheet_names", None)) and bool(getattr(x, "sha256", None)), "WORKBOOK_INDEX_INCOMPLETE"),
            output_fingerprint_fn=lambda x: {"sheet_names": list(x.sheet_names), "sha256": x.sha256},
        )
        idx = env.output
        names = " | ".join(idx.sheet_names).lower()
        if "gerenciamento" in names or "memorial de cálculo" in names or "memorial de calculo" in names:
            roles.append("RISK_WORKBOOK")
        if any("antes prot" in n.lower() for n in idx.sheet_names):
            roles.append("RISK_BEFORE_SCENARIO")
        if any("após prot" in n.lower() or "apos prot" in n.lower() for n in idx.sheet_names):
            roles.append("RISK_AFTER_SCENARIO")
    except Exception:
        roles.append("SPREADSHEET_UNPARSED")
    return roles


def classify_document(path: str | Path, index: int = 1, *, teil: ToolExecutionIntegrityLayer | None = None, project_id: str = "UNBOUND") -> InputDocument:
    p = Path(path)
    if not p.exists() or not p.is_file():
        raise OrchestratorError(f"INPUT_NOT_FOUND:{p}")
    ext = p.suffix.lower()
    teil = teil or build_default_teil()
    roles: list[str] = []
    if ext in {".xlsx", ".xlsm"}:
        roles = _xlsx_roles(p, teil=teil, project_id=project_id)
    elif ext == ".dxf":
        roles = ["CAD_GEOMETRY", "DXF_DIRECT_READ"]
    elif ext == ".dwg":
        roles = ["CAD_GEOMETRY", "DWG_CONVERSION_REQUIRED"]
    elif ext == ".pdf":
        roles = ["TECHNICAL_DOCUMENT"]
    elif ext in {".png", ".jpg", ".jpeg", ".webp"}:
        roles = ["VISUAL_EVIDENCE"]
        if "memorial" in p.name.lower():
            roles.append("MEMORIAL_VISUAL_REFERENCE")
    elif ext in {".json", ".csv"}:
        roles = ["STRUCTURED_INPUT"]
    elif ext in {".txt", ".md"}:
        roles = ["TEXTUAL_INPUT"]
    else:
        roles = ["UNCLASSIFIED_INPUT"]
    return InputDocument(
        document_id=f"DOC-{index:03d}",
        filename=p.name,
        extension=ext,
        sha256=file_sha256(p),
        size_bytes=p.stat().st_size,
        media_class=_media_class(ext),
        semantic_roles=roles,
        status="EXTRACTED",
    )


def _to_number(v: Any) -> float | None:
    if v is None:
        return None
    if isinstance(v, (int, float)):
        return float(v)
    s = str(v).strip().replace(" ", "")
    if not s or s.startswith("#"):
        return None
    try:
        return float(s.replace(",", "."))
    except Exception:
        return None


def _risk_sheet(idx: WorkbookCellIndex, needle: str) -> str | None:
    for name in idx.sheet_names:
        s = name.lower().replace("ó", "o").replace("á", "a").replace("ã", "a")
        if needle in s:
            return name
    return None


def _first_numeric(idx: WorkbookCellIndex, sheet: str, cells: Iterable[str]) -> tuple[float | None, str | None]:
    for cell in cells:
        rec = idx.get(sheet, cell)
        value = _to_number(rec.value)
        if value is not None:
            return value, cell
    return None, None


def _first_text(idx: WorkbookCellIndex, sheet: str, cells: Iterable[str], pattern: str | None = None) -> tuple[str | None, str | None]:
    rx = re.compile(pattern, re.I) if pattern else None
    for cell in cells:
        rec = idx.get(sheet, cell)
        if rec.value is None:
            continue
        text = str(rec.value)
        if not rx or rx.search(text):
            return text, cell
    return None, None


def extract_risk_workbook(path: str | Path, *, teil: ToolExecutionIntegrityLayer, project_id: str) -> dict[str, Any]:
    p = Path(path)
    env = teil.execute(
        tool_id="RISK_WORKBOOK_PARSER", tool_version="1.0.0", operation="EXTRACT",
        project_id=project_id,
        input_payload={"path": str(p), "sha256": file_sha256(p)},
        call=lambda: WorkbookCellIndex(p),
        output_validator=lambda x: (bool(getattr(x, "sheet_names", None)) and bool(getattr(x, "sha256", None)), "WORKBOOK_INDEX_INCOMPLETE"),
        output_fingerprint_fn=lambda x: {"sheet_names": list(x.sheet_names), "sha256": x.sha256},
    )
    idx = env.output
    before = _risk_sheet(idx, "antes prot")
    after = _risk_sheet(idx, "apos prot")
    if not before:
        return {
            "status": "BLOCKED_UNRECOGNIZED_RISK_LAYOUT",
            "facts": [],
            "findings": [{"severity": "HIGH", "code": "RISK_BEFORE_SHEET_NOT_FOUND"}],
            "source_sha256": idx.sha256,
        }

    def fact(fid: str, value: Any, source: str, status: str = "EXTRACTED", unit: str | None = None) -> dict:
        return {"fact_id": fid, "value": value, "unit": unit, "status": status, "source": source}

    facts: list[dict] = []
    findings: list[dict] = []
    bindings = {
        "NG_BEFORE": (before, ("N49",), "descargas/km²/ano"),
        "L_BEFORE": (before, ("N52",), "m"),
        "W_BEFORE": (before, ("N53",), "m"),
        "H_BEFORE": (before, ("N54",), "m"),
        # Legacy Golden Case used O298; reconciled/current ALUSIL layout uses O331.
        "R1_BEFORE_X1E5": (before, ("O331", "O298"), "×10^-5"),
    }
    for fid, (sh, cells, unit) in bindings.items():
        value, cell = _first_numeric(idx, sh, cells)
        facts.append(fact(fid, value, f"{sh}!{cell or '/'.join(cells)}", status="EXTRACTED" if value is not None else "PENDING", unit=unit))

    rt = 1.0
    facts.append(fact("RT_X1E5", rt, f"{before}!N299/B301", unit="×10^-5"))
    r1 = next((f["value"] for f in facts if f["fact_id"] == "R1_BEFORE_X1E5"), None)
    if r1 is not None:
        facts.append(fact("PROTECTION_REQUIRED", bool(r1 > rt), f"{before}!G299/B301", status="CALCULATED"))

    selection_text, selection_cell = _first_text(idx, before, ("B342", "B310"), r"SPDA\s+de\s+classe|SPDA.*N[ií]vel")
    selection = None
    if selection_text:
        m = re.search(r"classe\s+([IVX]+)\s*/\s*NP\s*([IVX]+)", str(selection_text), flags=re.I)
        if m:
            selection = {"spda_class": m.group(1).upper(), "np": m.group(2).upper()}
            facts.append(fact("SPDA_SELECTION", selection, f"{before}!{selection_cell}"))

    after_payload = None
    if after:
        after_r1, after_r1_cell = _first_numeric(idx, after, ("O311", "O283"))
        after_narrative, after_narrative_cell = _first_text(idx, after, ("B319", "B291"), r"R1\s*=")
        after_payload = {
            "sheet": after,
            "NG": _to_number(idx.get(after, "N32").value),
            "L_m": _to_number(idx.get(after, "N35").value),
            "W_m": _to_number(idx.get(after, "N36").value),
            "H_m": _to_number(idx.get(after, "N37").value),
            "R1_cached_x1e5": after_r1,
            "R1_cached_cell": after_r1_cell,
            "R1_narrative": after_narrative,
            "R1_narrative_cell": after_narrative_cell,
        }
        before_signature = tuple(next((f["value"] for f in facts if f["fact_id"] == k), None) for k in ["NG_BEFORE", "L_BEFORE", "W_BEFORE", "H_BEFORE"])
        after_signature = (after_payload["NG"], after_payload["L_m"], after_payload["W_m"], after_payload["H_m"])
        if before_signature != after_signature:
            findings.append({
                "severity": "CRITICAL",
                "code": "BEFORE_AFTER_PROJECT_SIGNATURE_MISMATCH",
                "before": before_signature,
                "after": after_signature,
                "blocks": ["RISK_RECONCILIATION"],
            })
        narrative = str(after_payload.get("R1_narrative") or "")
        m = re.search(r"R1\s*=\s*([0-9]+(?:[\.,][0-9]+)?)\s*(?:[×x]\s*10[⁻^-]?5|E-?05)", narrative, flags=re.I)
        narrative_x1e5 = float(m.group(1).replace(",", ".")) if m else None
        if after_payload["R1_cached_x1e5"] is not None and narrative_x1e5 is not None:
            if abs(float(after_payload["R1_cached_x1e5"]) - narrative_x1e5) > 5e-6:
                findings.append({
                    "severity": "CRITICAL",
                    "code": "AFTER_R1_CACHED_VS_NARRATIVE_CONFLICT",
                    "cached_x1e5": after_payload["R1_cached_x1e5"],
                    "cached_cell": after_payload.get("R1_cached_cell"),
                    "narrative_x1e5": narrative_x1e5,
                    "narrative_cell": after_payload.get("R1_narrative_cell"),
                    "blocks": ["RISK_RECONCILIATION"],
                })

    status = "PASS_RISK_BEFORE_WITH_AFTER_REVIEW_REQUIRED" if findings else "PASS_RISK_INGESTION"
    result = {
        "status": status,
        "source_file": Path(path).name,
        "source_sha256": idx.sha256,
        "sheets": idx.sheet_names,
        "facts": facts,
        "findings": findings,
        "after": after_payload,
    }
    result["digest"] = digest(result)
    return result


def _auto_cad_config(path: Path, project_id: str, revision: str, *, teil: ToolExecutionIntegrityLayer) -> tuple[dict | None, list[dict]]:
    findings: list[dict] = []
    if ezdxf is None:
        return None, [{"severity": "CRITICAL", "code": "EZDXF_NOT_AVAILABLE"}]
    try:
        env = teil.execute(
            tool_id="CAD_DXF_PARSER", tool_version="1.0.0", operation="READ",
            project_id=project_id,
            input_payload={"path": str(path), "sha256": file_sha256(path)},
            call=lambda: ezdxf.readfile(path),
            output_validator=lambda x: (hasattr(x, "modelspace"), "DXF_DOCUMENT_INCOMPLETE"),
            output_fingerprint_fn=lambda x: {"source_sha256": file_sha256(path), "entity_count": sum(1 for _ in x.modelspace())},
        )
        doc = env.output
    except Exception as exc:
        return None, [{"severity": "CRITICAL", "code": "DXF_READ_FAILED", "detail": str(exc)}]
    msp = doc.modelspace()
    outline_layers = set()
    annotation_layers = set()
    geometry_counts: dict[str, int] = {}
    text_counts: dict[str, int] = {}
    for e in msp:
        layer = str(e.dxf.layer)
        typ = e.dxftype()
        if typ in {"LWPOLYLINE", "POLYLINE", "LINE"}:
            geometry_counts[layer] = geometry_counts.get(layer, 0) + 1
        if typ in {"TEXT", "MTEXT"}:
            text_counts[layer] = text_counts.get(layer, 0) + 1
    for layer, count in geometry_counts.items():
        lname = layer.lower()
        if any(x in lname for x in ["cota", "dim", "texto", "anot", "aux", "eixo", "grid"]):
            continue
        if count > 0:
            outline_layers.add(layer)
    for layer, count in text_counts.items():
        if count > 0:
            annotation_layers.add(layer)
    if not outline_layers:
        findings.append({"severity": "CRITICAL", "code": "NO_SAFE_OUTLINE_LAYER_CANDIDATE"})
        return None, findings
    if len(outline_layers) > 8:
        findings.append({"severity": "HIGH", "code": "TOO_MANY_OUTLINE_LAYER_CANDIDATES", "layers": sorted(outline_layers)})
        return None, findings
    cfg = {
        "project_id": project_id,
        "version": revision,
        "workflow": WORKFLOW,
        "outline_layers": sorted(outline_layers),
        "annotation_layers": sorted(annotation_layers),
        "line_join_tolerance_m": 0.002,
        "annotation_capture_buffer_m": 0.05,
        "height_semantics": "LOCAL_HEIGHT",
        "nested_footprints_mode": "STACKED_IF_ANNOTATED",
        "default_base_elevation_m": 0,
        "elevation_conflict_tolerance_m": 0.01,
        "layer_height_rules": {},
        "require_all_candidates_supported": True,
        "allow_oda_dwg_conversion": False,
        "cad_z_semantics": "IGNORE",
        "block_unsupported_entities_on_outline_layers": True,
        "config_origin": "STARK_AUTO_CLASSIFICATION_V1_0",
    }
    return cfg, findings


def _module(module_id: str, status: str, *, inputs=None, outputs=None, findings=None, blocks=None, notes=None) -> dict:
    return {
        "module_id": module_id,
        "status": status,
        "inputs": inputs or [],
        "outputs": outputs or [],
        "findings": findings or [],
        "blocks": blocks or [],
        "notes": notes or [],
    }


def _pending(owner: str, code: str, question: str, blocks: list[str], severity: str = "HIGH") -> dict:
    return {"owner": owner, "code": code, "severity": severity, "question": question, "blocks": blocks, "status": "OPEN"}


def _write_json(path: Path, obj: Any) -> None:
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2, default=str), encoding="utf-8")


def _project_summary_md(manifest: Mapping[str, Any]) -> str:
    lines = [
        f"# STARK Project Orchestrator 1.0 — {manifest['project_id']} {manifest['revision']}",
        "",
        "## Fluxo operacional",
        "Régis fornece os arquivos → Bolanho opera o Stark → Stark classifica, executa e audita → Bolanho revisa o pacote → Régis valida tecnicamente.",
        "",
        f"**Status geral:** `{manifest['overall_status']}`",
        "",
        "## Módulos",
    ]
    for m in manifest["modules"]:
        lines.append(f"- **{m['module_id']}** — `{m['status']}`")
    lines += ["", "## Pendências abertas"]
    if manifest["pending_actions"]:
        for p in manifest["pending_actions"]:
            lines.append(f"- **{p['owner']} / {p['severity']} / {p['code']}**: {p['question']}")
    else:
        lines.append("- Nenhuma pendência aberta.")
    lines += ["", "## Regra de liberação", "O Stark não aprova o projeto. O estado automatizado máximo é **READY_FOR_REGIS_VALIDATION**."]
    return "\n".join(lines) + "\n"


def run_project(
    input_paths: Iterable[str | Path],
    output_dir: str | Path,
    *,
    project_id: str | None = None,
    previous_manifest: Mapping[str, Any] | None = None,
    cad_config: Mapping[str, Any] | None = None,
    protection_context: Mapping[str, Any] | None = None,
    allow_test_policy: bool = False,
    teil: ToolExecutionIntegrityLayer | None = None,
    eicf: EcosystemIntegrityFabric | None = None,
    eicf_mode: str = "ENFORCE",
) -> dict[str, Any]:
    paths = [Path(p) for p in input_paths]
    if not paths:
        raise OrchestratorError("AT_LEAST_ONE_INPUT_REQUIRED")
    for p in paths:
        if not p.exists():
            raise OrchestratorError(f"INPUT_NOT_FOUND:{p}")
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    pid = _project_id(paths, previous_manifest, project_id)
    rev = next_revision(previous_manifest)
    teil = teil or build_default_teil()
    eicf = eicf or build_reference_fabric(project_id=pid, revision=rev, mode=eicf_mode)
    eicf.create_cell(pid, rev)
    docs = [classify_document(p, i + 1, teil=teil, project_id=pid) for i, p in enumerate(paths)]
    eicf.register_input_set(pid, rev, {d.filename: d.sha256 for d in docs})
    modules: list[dict] = []
    pending: list[dict] = []
    facts: list[dict] = []
    deliverables: list[dict] = []

    if allow_test_policy:
        eicf.raise_block("STARK", pid, rev, "TEST_ONLY_POLICY_ACTIVE", "Synthetic/test-only protection policy may be used for internal regression but can never authorize a client delivery.")
        pending.append(_pending("BOLANHO", "TEST_ONLY_POLICY_ACTIVE", "Desativar a política sintética/test-only e usar somente contexto de proteção qualificado antes de qualquer entrega ao engenheiro/cliente.", ["SPDA_ARRANGEMENT", "HANDOFF"], "CRITICAL"))

    modules.append(_module("INPUT_INGESTION", "PASS", inputs=[d.document_id for d in docs], outputs=["classified_inputs"]))

    risk_docs = [(p, d) for p, d in zip(paths, docs) if "RISK_WORKBOOK" in d.semantic_roles]
    risk_result = None
    if len(risk_docs) == 1:
        p, d = risk_docs[0]
        try:
            risk_result = extract_risk_workbook(p, teil=teil, project_id=pid)
            facts.extend(risk_result["facts"])
            risk_file = out / "risk_ingestion_output.json"
            _write_json(risk_file, risk_result)
            eicf.propose_state(
                source_engine="STARK", project_id=pid, revision=rev,
                message_type="ENGINE_OUTPUT", capability="PROPOSE_TECHNICAL_STATE",
                payload={"output_id": risk_file.name, "status": risk_result["status"], "digest": risk_result.get("digest")},
                dependency_fingerprint=risk_result.get("source_sha256", "NONE"),
            )
            deliverables.append({"type": "RISK_ANALYSIS", "path": risk_file.name, "status": risk_result["status"]})
            modules.append(_module("RISK_INGESTION", risk_result["status"], inputs=[d.document_id], outputs=[risk_file.name], findings=risk_result["findings"]))
            if risk_result["findings"]:
                eicf.raise_block("STARK", pid, rev, "RISK_SOURCE_CONFLICT", ";".join(str(f.get("code")) for f in risk_result["findings"]))
                modules.append(_module("RISK_RECONCILIATION", "BLOCKED_ENGINEER_CONFIRMATION_REQUIRED", inputs=[risk_file.name], blocks=[f["code"] for f in risk_result["findings"]]))
                pending.append(_pending("REGIS", "RISK_SOURCE_CONFLICT", "Confirmar as divergências do cenário Após Prot antes de usar esse cenário como base técnica.", ["RISK_RECONCILIATION"], "CRITICAL"))
            else:
                modules.append(_module("RISK_RECONCILIATION", "PASS_NO_DIVERGENCE_DETECTED", inputs=[risk_file.name]))
        except Exception as exc:
            modules.append(_module("RISK_INGESTION", "BLOCKED_PARSE_ERROR", inputs=[d.document_id], findings=[{"severity": "CRITICAL", "code": "RISK_PARSE_ERROR", "detail": str(exc)}]))
            modules.append(_module("RISK_RECONCILIATION", "NOT_RUN_UPSTREAM_BLOCK"))
    elif len(risk_docs) > 1:
        modules.append(_module("RISK_INGESTION", "BLOCKED_MULTIPLE_RISK_WORKBOOKS", inputs=[d.document_id for _, d in risk_docs]))
        modules.append(_module("RISK_RECONCILIATION", "NOT_RUN_UPSTREAM_BLOCK"))
        pending.append(_pending("BOLANHO", "SELECT_RISK_WORKBOOK", "Selecionar qual planilha de gerenciamento de risco pertence a esta revisão do projeto.", ["RISK_INGESTION"], "HIGH"))
    else:
        modules.append(_module("RISK_INGESTION", "NOT_APPLICABLE_NO_RISK_WORKBOOK"))
        modules.append(_module("RISK_RECONCILIATION", "NOT_APPLICABLE"))

    dxf_docs = [(p, d) for p, d in zip(paths, docs) if d.extension == ".dxf"]
    dwg_docs = [(p, d) for p, d in zip(paths, docs) if d.extension == ".dwg"]
    cad_rec = None
    cad_audit = None
    geom_bundle = None
    selected_dxf = None
    effective_cfg = None

    if len(dxf_docs) == 1:
        selected_dxf, ddoc = dxf_docs[0]
        if cad_config is None:
            effective_cfg, auto_findings = _auto_cad_config(selected_dxf, pid, rev, teil=teil)
        else:
            effective_cfg = dict(cad_config)
            effective_cfg["project_id"] = pid
            effective_cfg["version"] = rev
            effective_cfg["workflow"] = WORKFLOW
            auto_findings = []
        if effective_cfg is None:
            modules.append(_module("CAD_RECONSTRUCTION", "BLOCKED_CAD_CONFIG_AMBIGUOUS", inputs=[ddoc.document_id], findings=auto_findings))
            pending.append(_pending("BOLANHO", "CAD_LAYER_CLASSIFICATION_REQUIRED", "Confirmar quais layers representam os contornos reais da edificação e quais contêm anotações de altura.", ["CAD_RECONSTRUCTION", "GEOMETRY_3D", "SPDA_ARRANGEMENT"], "HIGH"))
        else:
            try:
                cad_rec = teil.execute(
                    tool_id="CAD_RECONSTRUCTOR", tool_version="1.0.0", operation="RECONSTRUCT",
                    project_id=pid,
                    input_payload={"source_sha256": file_sha256(selected_dxf), "config": effective_cfg},
                    call=lambda: reconstruct_building_from_cad(selected_dxf, effective_cfg),
                    output_validator=lambda x: (isinstance(x, Mapping) and bool(x), "CAD_RECONSTRUCTION_EMPTY"),
                ).output
                cad_audit = teil.execute(
                    tool_id="CAD_RECONSTRUCTOR", tool_version="1.0.0", operation="AUDIT",
                    project_id=pid, input_payload={"cad_reconstruction_digest": digest(cad_rec)},
                    call=lambda: audit_cad_reconstruction(cad_rec),
                    output_validator=lambda x: (isinstance(x, Mapping) and bool(x.get("status")), "CAD_AUDIT_STATUS_MISSING"),
                ).output
                rec_file = out / "cad_reconstruction_output.json"
                audit_file = out / "cad_reconstruction_audit.json"
                cfg_file = out / "cad_effective_config.json"
                _write_json(rec_file, cad_rec); _write_json(audit_file, cad_audit); _write_json(cfg_file, effective_cfg)
                outputs = [rec_file.name, audit_file.name, cfg_file.name]
                if cad_audit["status"] == "PASS_INTERNAL_CAD_RECONSTRUCTION_READY_FOR_GEOMETRY_ENGINE":
                    final_model_dxf = out / "cad_reconstructed_model.dxf"
                    temp_model_dxf = out / "cad_reconstructed_model.teil.tmp.dxf"
                    model_dxf = teil.execute(
                        tool_id="CAD_RECONSTRUCTOR", tool_version="1.0.0", operation="EXPORT",
                        project_id=pid, input_payload={"cad_reconstruction_digest": digest(cad_rec), "audit_digest": digest(cad_audit)},
                        call=lambda: export_reconstruction_dxf(cad_rec, cad_audit, temp_model_dxf),
                        output_validator=lambda x: (Path(x).exists() and Path(x).stat().st_size > 0, "CAD_EXPORT_MISSING_OR_EMPTY"),
                        output_fingerprint_fn=lambda x: {"path": Path(x).name, "sha256": file_sha256(Path(x))},
                    ).output
                    Path(model_dxf).replace(final_model_dxf)
                    outputs.append(final_model_dxf.name)
                    deliverables.append({"type": "CAD_RECONSTRUCTED_MODEL", "path": final_model_dxf.name, "status": "PRELIMINARY"})
                modules.append(_module("CAD_RECONSTRUCTION", cad_audit["status"], inputs=[ddoc.document_id], outputs=outputs, findings=auto_findings))
            except Exception as exc:
                modules.append(_module("CAD_RECONSTRUCTION", "BLOCKED_CAD_RECONSTRUCTION_ERROR", inputs=[ddoc.document_id], findings=[{"severity": "CRITICAL", "code": "CAD_RECONSTRUCTION_ERROR", "detail": str(exc)}]))
    elif len(dxf_docs) > 1:
        modules.append(_module("CAD_RECONSTRUCTION", "BLOCKED_MULTIPLE_DXF_FILES", inputs=[d.document_id for _, d in dxf_docs]))
        pending.append(_pending("BOLANHO", "SELECT_CAD_SOURCE", "Selecionar qual DXF é a geometria-base desta revisão; o Stark não escolhe silenciosamente entre arquivos concorrentes.", ["CAD_RECONSTRUCTION", "GEOMETRY_3D", "SPDA_ARRANGEMENT"], "HIGH"))
    elif dwg_docs:
        modules.append(_module("CAD_RECONSTRUCTION", "BLOCKED_DWG_CONVERSION_REQUIRED", inputs=[d.document_id for _, d in dwg_docs]))
        pending.append(_pending("BOLANHO", "DWG_TO_DXF_REQUIRED", "Converter/exportar o DWG para DXF preservando unidades, layers e geometria antes da reconstrução automática.", ["CAD_RECONSTRUCTION", "GEOMETRY_3D", "SPDA_ARRANGEMENT"], "HIGH"))
    else:
        modules.append(_module("CAD_RECONSTRUCTION", "BLOCKED_NO_CAD_GEOMETRY"))
        pending.append(_pending("REGIS", "CAD_GEOMETRY_REQUIRED", "Fornecer planta/arquivo CAD com a geometria real da estrutura para posicionamento físico do SPDA.", ["CAD_RECONSTRUCTION", "GEOMETRY_3D", "SPDA_ARRANGEMENT"], "CRITICAL"))

    if cad_audit and cad_audit.get("status") == "PASS_INTERNAL_CAD_RECONSTRUCTION_READY_FOR_GEOMETRY_ENGINE":
        modules.append(_module("GEOMETRY_3D", "PASS_RECONSTRUCTED_3D_MODEL", inputs=["cad_reconstruction_output.json"], outputs=["cad_reconstructed_model.dxf"]))
    else:
        modules.append(_module("GEOMETRY_3D", "NOT_RUN_UPSTREAM_CAD_BLOCK"))

    if cad_audit and cad_audit.get("status") == "PASS_INTERNAL_CAD_RECONSTRUCTION_READY_FOR_GEOMETRY_ENGINE":
        if protection_context is None:
            modules.append(_module("SPDA_ARRANGEMENT", "BLOCKED_VALIDATED_PROTECTION_POLICY_REQUIRED"))
            pending.append(_pending("REGIS", "VALIDATED_PROTECTION_POLICY_REQUIRED", "Confirmar/fornecer o contexto de proteção validado (incluindo parâmetros normativos aplicáveis ao método selecionado) antes do arranjo automático.", ["SPDA_ARRANGEMENT"], "CRITICAL"))
        else:
            try:
                geom_bundle = teil.execute(
                    tool_id="GEOMETRY_ENGINE", tool_version="1.0.0", operation="ROLLING_SPHERE",
                    project_id=pid,
                    input_payload={"source_sha256": file_sha256(selected_dxf), "config": effective_cfg, "protection_context": dict(protection_context), "allow_test_policy": allow_test_policy},
                    call=lambda: run_cad_to_rolling_sphere(selected_dxf, effective_cfg, dict(protection_context), allow_test_policy=allow_test_policy),
                    output_validator=lambda x: (isinstance(x, Mapping) and isinstance(x.get("geometry_audit"), Mapping), "GEOMETRY_BUNDLE_INCOMPLETE"),
                ).output
                bundle_file = out / "spda_geometry_bundle.json"
                _write_json(bundle_file, geom_bundle)
                ga = geom_bundle["geometry_audit"]
                outputs = [bundle_file.name]
                if ga["status"] == "PASS_INTERNAL_3D_ROLLING_SPHERE_AUDIT_AWAITING_REGIS":
                    final_arr_dxf = out / "spda_arrangement_preliminary.dxf"
                    temp_arr_dxf = out / "spda_arrangement_preliminary.teil.tmp.dxf"
                    arr_dxf = teil.execute(
                        tool_id="GEOMETRY_ENGINE", tool_version="1.0.0", operation="EXPORT_3D",
                        project_id=pid, input_payload={"arrangement_digest": digest(geom_bundle["arrangement"]), "audit_digest": digest(ga)},
                        call=lambda: export_3d_dxf(geom_bundle["arrangement"], ga, temp_arr_dxf),
                        output_validator=lambda x: (Path(x).exists() and Path(x).stat().st_size > 0, "GEOMETRY_EXPORT_MISSING_OR_EMPTY"),
                        output_fingerprint_fn=lambda x: {"path": Path(x).name, "sha256": file_sha256(Path(x))},
                    ).output
                    Path(arr_dxf).replace(final_arr_dxf)
                    outputs.append(final_arr_dxf.name)
                    deliverables.append({"type": "SPDA_ARRANGEMENT_DXF", "path": final_arr_dxf.name, "status": "PRELIMINARY_AWAITING_REGIS_VALIDATION"})
                modules.append(_module("SPDA_ARRANGEMENT", ga["status"], inputs=["cad_reconstruction_output.json"], outputs=outputs))
            except Exception as exc:
                modules.append(_module("SPDA_ARRANGEMENT", "BLOCKED_PROTECTION_ENGINE_ERROR", findings=[{"severity": "CRITICAL", "code": "SPDA_ENGINE_ERROR", "detail": str(exc)}]))
    else:
        modules.append(_module("SPDA_ARRANGEMENT", "NOT_RUN_UPSTREAM_GEOMETRY_BLOCK"))

    arrangement_module = next(m for m in modules if m["module_id"] == "SPDA_ARRANGEMENT")
    if arrangement_module["status"] == "PASS_INTERNAL_3D_ROLLING_SPHERE_AUDIT_AWAITING_REGIS":
        modules.append(_module("INDEPENDENT_AUDIT", "PASS_INTERNAL_AUDIT_AWAITING_REGIS", inputs=arrangement_module["outputs"]))
    elif arrangement_module["status"].startswith("BLOCKED"):
        modules.append(_module("INDEPENDENT_AUDIT", "NOT_RUN_ARRANGEMENT_BLOCKED"))
    else:
        modules.append(_module("INDEPENDENT_AUDIT", "NOT_RUN_NO_ARRANGEMENT"))

    teil_snapshot = teil.snapshot()
    teil_failures = list(teil_snapshot.get("failure_ledger", []))
    modules.append(_module(
        "TOOL_EXECUTION_INTEGRITY",
        "PASS" if not teil_failures else "BLOCKED_TOOL_FAILURES_PRESENT",
        outputs=["teil_integrity_snapshot.json"],
        findings=[{"severity": "CRITICAL", "code": x.get("failure_code"), "tool_id": x.get("tool_id"), "operation": x.get("operation"), "detail": x.get("detail")} for x in teil_failures],
    ))
    _write_json(out / "teil_integrity_snapshot.json", teil_snapshot)

    eicf_pre_snapshot = eicf.snapshot(pid)
    eicf_failures = [x for x in eicf_pre_snapshot.get("findings", []) if x.get("severity") == "CRITICAL"]
    eicf_integrity_ok = (
        bool(eicf_pre_snapshot.get("ledger_valid"))
        and bool(eicf_pre_snapshot.get("checkpoint_valid"))
        and not eicf_pre_snapshot.get("safe_freeze")
        and not eicf_failures
        and eicf_pre_snapshot.get("mode") == "ENFORCE"
    )

    critical_open = any(p["severity"] == "CRITICAL" for p in pending) or bool(teil_failures) or not eicf_integrity_ok
    arrangement_ready = arrangement_module["status"] == "PASS_INTERNAL_3D_ROLLING_SPHERE_AUDIT_AWAITING_REGIS"
    if arrangement_ready and not critical_open:
        overall = "READY_FOR_REGIS_VALIDATION"
        handoff_status = "READY_FOR_BOLANHO_TO_SEND_TO_REGIS_FOR_VALIDATION"
    elif deliverables:
        overall = "PARTIAL_RESULTS_READY_WITH_LOCAL_BLOCKS"
        handoff_status = "PARTIAL_PACKAGE_READY_FOR_BOLANHO_REVIEW"
    else:
        overall = "BLOCKED_INPUT_OR_ENGINEERING_DEPENDENCIES"
        handoff_status = "NOT_READY_FOR_REGIS_HANDOFF"

    delivery_integrity = eicf.delivery_precheck(
        pid, rev, overall_status=overall, unresolved_critical=critical_open
    )
    eicf_snapshot = eicf.snapshot(pid)
    _write_json(out / "eicf_integrity_snapshot.json", eicf_snapshot)
    modules.append(_module(
        "ECOSYSTEM_INTERNAL_CONTAINMENT",
        "PASS" if (eicf_snapshot.get("ledger_valid") and eicf_snapshot.get("checkpoint_valid") and not eicf_snapshot.get("safe_freeze") and not eicf_snapshot.get("findings")) else "BLOCKED_EICF_INTEGRITY",
        outputs=["eicf_integrity_snapshot.json"],
        findings=eicf_snapshot.get("findings", []),
        notes=[
            "STARK runtime is bound to the unified control plane.",
            "TEMPESTADE and ATLAS remain independent logical adapters until dedicated executable runtimes are bound.",
            "LocalKeyProvider is reference/test key custody only; production requires KMS/HSM-backed persistent keys.",
        ],
    ))
    if not delivery_integrity["eligible"] and handoff_status == "READY_FOR_BOLANHO_TO_SEND_TO_REGIS_FOR_VALIDATION":
        handoff_status = "NOT_READY_FOR_REGIS_HANDOFF"
        overall = "BLOCKED_ECOSYSTEM_INTEGRITY_GATE"
    modules.append(_module("HANDOFF", handoff_status, outputs=[d["path"] for d in deliverables]))

    previous_digest = previous_manifest.get("manifest_digest") if previous_manifest else None
    input_hashes = {d.filename: d.sha256 for d in docs}
    prior_hashes = {d["filename"]: d["sha256"] for d in previous_manifest.get("inputs", [])} if previous_manifest else {}
    changes = {
        "added": sorted([k for k in input_hashes if k not in prior_hashes]),
        "removed": sorted([k for k in prior_hashes if k not in input_hashes]),
        "changed": sorted([k for k in input_hashes if k in prior_hashes and input_hashes[k] != prior_hashes[k]]),
        "unchanged": sorted([k for k in input_hashes if k in prior_hashes and input_hashes[k] == prior_hashes[k]]),
    }

    manifest = {
        "schema_version": SCHEMA_VERSION,
        "engine": f"STARK_PROJECT_ORCHESTRATOR_{ORCHESTRATOR_VERSION}",
        "project_id": pid,
        "revision": rev,
        "created_at_utc": _utc_now(),
        "workflow": WORKFLOW,
        "parent_manifest_digest": previous_digest,
        "revision_changes": changes,
        "inputs": [asdict(d) for d in docs],
        "facts": facts,
        "modules": modules,
        "pending_actions": pending,
        "deliverables": deliverables,
        "tool_execution_integrity": {
            "teil_version": teil_snapshot["teil_version"],
            "snapshot_fingerprint": teil_snapshot["snapshot_fingerprint"],
            "successful_run_count": len(teil_snapshot.get("successful_receipts", [])),
            "failure_count": len(teil_snapshot.get("failure_ledger", [])),
            "status": "PASS" if not teil_failures else "BLOCKED",
        },
        "ecosystem_integrity": {
            "eicf_version": eicf_snapshot["eicf_version"],
            "ecl_version": eicf_snapshot["ecl_version"],
            "mode": eicf_snapshot["mode"],
            "ledger_valid": eicf_snapshot["ledger_valid"],
            "checkpoint_valid": eicf_snapshot["checkpoint_valid"],
            "safe_freeze": eicf_snapshot["safe_freeze"],
            "event_count": eicf_snapshot["event_count"],
            "snapshot_digest": eicf_snapshot["snapshot_digest"],
            "delivery_precheck": delivery_integrity,
            "key_custody": "REFERENCE_LOCAL_ONLY_NOT_PRODUCTION_KMS_HSM",
            "status": "PASS" if (eicf_snapshot["ledger_valid"] and eicf_snapshot["checkpoint_valid"] and not eicf_snapshot["safe_freeze"] and not eicf_snapshot["findings"]) else "BLOCKED",
        },
        "overall_status": overall,
        "release_rule": "STARK_DOES_NOT_TECHNICALLY_APPROVE; REGIS_VALIDATES_FINAL_OUTPUT; NO_VERIFIED_TOOL_EXECUTION_NO_EVIDENCE; NO_UNVERIFIED_INTER_ENGINE_STATE_CHANGE; NO_EICF_GATE_BYPASS",
    }
    manifest["manifest_digest"] = digest(manifest)

    manifest_file = out / "project_manifest.json"
    _write_json(manifest_file, manifest)
    summary_file = out / "STARK_PROJECT_SUMMARY.md"
    summary_file.write_text(_project_summary_md(manifest), encoding="utf-8")

    handoff = {
        "project_id": pid,
        "revision": rev,
        "status": handoff_status,
        "operator": "Bolanho",
        "technical_validator": "Régis",
        "overall_status": overall,
        "deliverables": deliverables,
        "pending_actions": pending,
        "manifest_digest": manifest["manifest_digest"],
        "instruction": "Bolanho revisa o pacote e envia ao Régis apenas quando o status do trabalho e as pendências estiverem claramente indicados.",
    }
    handoff["handoff_digest"] = digest(handoff)
    handoff_file = out / "handoff_bolanho_regis.json"
    _write_json(handoff_file, handoff)

    return {"manifest": manifest, "handoff": handoff, "output_dir": str(out)}


def verify_manifest(manifest: Mapping[str, Any]) -> dict[str, Any]:
    supplied = manifest.get("manifest_digest")
    payload = dict(manifest)
    payload.pop("manifest_digest", None)
    expected = digest(payload)
    return {"valid": supplied == expected, "supplied": supplied, "expected": expected}


def save_revision_snapshot(manifest: Mapping[str, Any], history_dir: str | Path) -> Path:
    check = verify_manifest(manifest)
    if not check["valid"]:
        raise OrchestratorError("MANIFEST_INTEGRITY_FAILURE")
    hdir = Path(history_dir)
    hdir.mkdir(parents=True, exist_ok=True)
    path = hdir / f"{manifest['project_id']}_{manifest['revision']}_{manifest['manifest_digest'][:12]}.json"
    if path.exists():
        if json.loads(path.read_text(encoding="utf-8")) != dict(manifest):
            raise OrchestratorError("IMMUTABLE_REVISION_COLLISION")
        return path
    path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    return path
