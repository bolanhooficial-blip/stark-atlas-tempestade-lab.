"""STARK SPDA Core 0.4.0 — validated risk-component engine.

Risk components are executed only from engineer-validated formulas and a
validated risk-model definition. The engine has no hard-coded ABNT coefficients.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, asdict
from decimal import Decimal
from typing import Any, Dict, List, Mapping, Sequence

from stark_core import D, Finding, StarkValidationError, canonical_hash, decimal_str, evaluate_risk
from stark_normative import (
    build_binding_receipts, dual_validate_normative_formula, evaluate_validated_formula,
    formula_findings, get_validated_parameter,
)

RISK_ENGINE_VERSION = "0.4.0"
CANONICAL_COMPONENT_IDS = {"RA","RB","RC","RM","RU","RV","RW","RZ"}


def _source_index(library: Mapping[str, Any]) -> Dict[str, Mapping[str, Any]]:
    return {x.get("source_id"): x for x in (library.get("authorized_sources", []) or []) if x.get("source_id")}


def risk_model_payload(model: Mapping[str, Any]) -> Dict[str, Any]:
    source = model.get("source", {}) or {}
    return {
        "risk_model_id": model.get("risk_model_id"),
        "risk_id": model.get("risk_id"),
        "components": [
            {"component_id": x.get("component_id"), "formula_ref": x.get("formula_ref"), "required": bool(x.get("required", True))}
            for x in (model.get("components", []) or [])
        ],
        "aggregation": model.get("aggregation", {"op":"sum"}),
        "tolerable_risk_parameter_ref": model.get("tolerable_risk_parameter_ref"),
        "source": {
            "source_id": source.get("source_id"), "standard": source.get("standard"),
            "edition": source.get("edition"), "part": source.get("part"),
            "locator": source.get("locator"), "evidence_hash": source.get("evidence_hash"),
        },
    }


def risk_model_approval_digest(model: Mapping[str, Any]) -> str:
    return canonical_hash(risk_model_payload(model))


def _find_risk_model(library: Mapping[str, Any], risk_model_id: str) -> Mapping[str, Any]:
    matches = [x for x in (library.get("risk_models", []) or []) if x.get("risk_model_id") == risk_model_id]
    if not matches: raise StarkValidationError(f"Unknown risk model: {risk_model_id}")
    if len(matches) > 1: raise StarkValidationError(f"Duplicate risk model: {risk_model_id}")
    return matches[0]


def risk_model_findings(library: Mapping[str, Any], risk_model_id: str) -> List[Finding]:
    try: model = _find_risk_model(library, risk_model_id)
    except StarkValidationError as exc: return [Finding("UNKNOWN_RISK_MODEL","CRITICAL",str(exc),True)]
    findings: List[Finding] = []
    if model.get("status") != "ENGINEER_VALIDATED":
        findings.append(Finding("RISK_MODEL_NOT_ENGINEER_VALIDATED","CRITICAL",f"{risk_model_id}: status is {model.get('status')}",True))
    source = model.get("source", {}) or {}
    sid = source.get("source_id")
    src = _source_index(library).get(sid)
    if not sid or src is None or src.get("status") != "AUTHORIZED":
        findings.append(Finding("RISK_MODEL_SOURCE_NOT_AUTHORIZED","CRITICAL",f"{risk_model_id}: source is not authorized",True))
    else:
        for field in ("standard","edition"):
            if str(source.get(field)) != str(src.get(field)):
                findings.append(Finding("RISK_MODEL_SOURCE_BINDING_MISMATCH","CRITICAL",f"{risk_model_id}: source {field} mismatch",True))
    val = model.get("validation", {}) or {}
    if model.get("status") == "ENGINEER_VALIDATED":
        if val.get("status") != "VALIDATED" or not val.get("engineer") or not val.get("validated_at") or not val.get("approved_digest"):
            findings.append(Finding("RISK_MODEL_VALIDATION_RECORD_MISSING","CRITICAL",f"{risk_model_id}: incomplete engineer validation record",True))
        elif val.get("approved_digest") != risk_model_approval_digest(model):
            findings.append(Finding("RISK_MODEL_TAMPERED_AFTER_APPROVAL","CRITICAL",f"{risk_model_id}: definition differs from engineer-approved digest",True))
    components = model.get("components", []) or []
    ids = [x.get("component_id") for x in components]
    if len(ids) != len(set(ids)):
        findings.append(Finding("RISK_MODEL_DUPLICATE_COMPONENT","CRITICAL",f"{risk_model_id}: duplicate component ID",True))
    for c in components:
        cid, fid = c.get("component_id"), c.get("formula_ref")
        if not cid or not fid:
            findings.append(Finding("RISK_MODEL_COMPONENT_INCOMPLETE","CRITICAL",f"{risk_model_id}: component mapping incomplete",True)); continue
        ff = formula_findings(library, str(fid)); findings.extend(ff)
    rt = model.get("tolerable_risk_parameter_ref")
    if not rt:
        findings.append(Finding("RISK_MODEL_RT_MISSING","CRITICAL",f"{risk_model_id}: tolerable-risk parameter reference missing",True))
    else:
        try: get_validated_parameter(library, str(rt))
        except Exception as exc: findings.append(Finding("RISK_MODEL_RT_NOT_READY","CRITICAL",f"{risk_model_id}: {exc}",True))
    if (model.get("aggregation", {}) or {}).get("op") != "sum":
        findings.append(Finding("RISK_MODEL_AGGREGATION_UNSUPPORTED","CRITICAL",f"{risk_model_id}: only deterministic sum is supported in 0.4",True))
    return findings


def validate_risk_model(library: Mapping[str, Any], risk_model_id: str, engineer: str, validated_at: str, notes: str | None=None) -> Dict[str, Any]:
    if not engineer.strip() or not validated_at.strip(): raise StarkValidationError("Engineer and validation timestamp are required")
    lib = deepcopy(library); model = _find_risk_model(lib, risk_model_id)
    source = model.get("source", {}) or {}
    src = _source_index(lib).get(source.get("source_id"))
    if src is None or src.get("status") != "AUTHORIZED":
        raise StarkValidationError("Risk model source is not authorized")
    for field in ("standard", "edition", "evidence_hash"):
        if source.get(field) and src.get(field) and str(source.get(field)) != str(src.get(field)):
            raise StarkValidationError(f"Risk model source {field} differs from authorized-source registry")
    auth = src.get("authorization", {}) or {}
    if auth:
        payload = {"source_id":src.get("source_id"),"kind":src.get("kind"),"title":src.get("title"),"standard":src.get("standard"),"edition":src.get("edition"),"location":src.get("location"),"evidence_hash":src.get("evidence_hash")}
        if auth.get("status") != "AUTHORIZED" or auth.get("approved_digest") != canonical_hash(payload):
            raise StarkValidationError("Risk model authorized source metadata has been altered")
    # Validate dependencies before signing the model.
    temp = deepcopy(model); temp["status"] = "ENGINEER_VALIDATED"; temp["validation"] = {"status":"VALIDATED","engineer":engineer,"validated_at":validated_at,"approved_digest":"TEMP"}
    # explicit dependency checks
    for c in temp.get("components", []) or []:
        ff = formula_findings(lib, str(c.get("formula_ref")))
        if any(f.blocking for f in ff): raise StarkValidationError(f"Risk model dependency {c.get('formula_ref')} is not ready")
    get_validated_parameter(lib, str(temp.get("tolerable_risk_parameter_ref")))
    for target in lib.get("risk_models", []):
        if target.get("risk_model_id") == risk_model_id:
            target["status"] = "ENGINEER_VALIDATED"
            target["validation"] = {"status":"VALIDATED","engineer":engineer,"validated_at":validated_at,"approved_digest":risk_model_approval_digest(target),"notes":notes}
            break
    return lib


def build_risk_model_receipt(library: Mapping[str, Any], risk_model_id: str) -> Dict[str, Any]:
    findings = risk_model_findings(library, risk_model_id)
    if any(f.blocking for f in findings):
        raise StarkValidationError("; ".join(f.message for f in findings if f.blocking))
    model = _find_risk_model(library, risk_model_id)
    source = model["source"]
    return {
        "item_type": "RISK_MODEL",
        "item_id": risk_model_id,
        "library_version": str(library.get("library_version")),
        "approved_digest": str(model["validation"]["approved_digest"]),
        "source_ref": str(source["source_id"]),
        "standard": str(source["standard"]),
        "edition": str(source["edition"]),
        "locator": str(source["locator"]),
    }


@dataclass(frozen=True)
class RiskComponentRun:
    component_id: str
    formula_id: str
    value: Decimal
    contribution_pct: Decimal
    formula_trace_hash: str
    dual_check_trace_hash: str
    dual_check_passed: bool
    normative_receipts: Sequence[Mapping[str, Any]]
    def to_dict(self) -> Dict[str, Any]:
        return {"component_id":self.component_id,"formula_id":self.formula_id,"value":decimal_str(self.value),"contribution_pct":decimal_str(self.contribution_pct),"formula_trace_hash":self.formula_trace_hash,"dual_check_trace_hash":self.dual_check_trace_hash,"dual_check_passed":self.dual_check_passed,"normative_receipts":list(self.normative_receipts)}

@dataclass(frozen=True)
class RiskModelRun:
    risk_model_id: str
    risk_id: str
    total: Decimal
    tolerable: Decimal
    relation: str
    status: str
    components: Sequence[RiskComponentRun]
    aggregate_delta: Decimal
    aggregate_tolerance: Decimal
    aggregate_dual_check_passed: bool
    trace_hash: str
    def to_dict(self) -> Dict[str, Any]:
        return {"risk_model_id":self.risk_model_id,"risk_id":self.risk_id,"total":decimal_str(self.total),"tolerable":decimal_str(self.tolerable),"relation":self.relation,"status":self.status,"components":[x.to_dict() for x in self.components],"aggregate_delta":decimal_str(self.aggregate_delta),"aggregate_tolerance":decimal_str(self.aggregate_tolerance),"aggregate_dual_check_passed":self.aggregate_dual_check_passed,"trace_hash":self.trace_hash}


def evaluate_validated_risk_model(library: Mapping[str, Any], risk_model_id: str, component_inputs: Mapping[str, Mapping[str, Any]], tolerance: Any="1e-24") -> RiskModelRun:
    findings = risk_model_findings(library, risk_model_id)
    if any(f.blocking for f in findings): raise StarkValidationError("; ".join(f.message for f in findings if f.blocking))
    model = _find_risk_model(library, risk_model_id)
    tol = D(tolerance)
    raw = []
    primary_total = Decimal(0); independent_total = Decimal(0)
    for spec in model.get("components", []) or []:
        cid, fid = str(spec["component_id"]), str(spec["formula_ref"])
        if cid not in component_inputs:
            if spec.get("required", True): raise StarkValidationError(f"Missing inputs for required component {cid}")
            inputs = {}
        else: inputs = component_inputs[cid]
        calc = evaluate_validated_formula(library, fid, inputs)
        dual = dual_validate_normative_formula(library, fid, inputs, tol)
        if not dual.passed: raise StarkValidationError(f"Independent arithmetic check failed for component {cid}")
        primary_total += calc.result; independent_total += dual.fraction_result
        receipts = [calc.formula_receipt.to_dict(), *[x.to_dict() for x in calc.parameter_receipts]]
        raw.append((cid,fid,calc,dual,receipts))
    delta = abs(primary_total-independent_total)
    aggregate_ok = delta <= tol
    if not aggregate_ok: raise StarkValidationError("Aggregate independent arithmetic check failed")
    rt = get_validated_parameter(library, str(model["tolerable_risk_parameter_ref"]))
    decision = evaluate_risk(primary_total, rt.value)
    components: List[RiskComponentRun] = []
    for cid,fid,calc,dual,receipts in raw:
        pct = Decimal(0) if primary_total == 0 else (calc.result/primary_total)*Decimal(100)
        components.append(RiskComponentRun(cid,fid,calc.result,pct,calc.trace_hash,dual.trace_hash,dual.passed,tuple(receipts)))
    trace = canonical_hash({
        "engine": f"STARK_RISK_{RISK_ENGINE_VERSION}", "library_version": library.get("library_version"),
        "risk_model_digest": model.get("validation",{}).get("approved_digest"),
        "risk_model_id":risk_model_id,"components":[x.to_dict() for x in components],
        "total":decimal_str(primary_total),"rt_receipt":build_binding_receipts(library,[str(model["tolerable_risk_parameter_ref"])],[]),
        "decision":decision.to_dict(),"aggregate_delta":decimal_str(delta),"tolerance":decimal_str(tol),
    })
    return RiskModelRun(risk_model_id,str(model.get("risk_id")),primary_total,rt.value,decision.relation,decision.status,tuple(components),delta,tol,aggregate_ok,trace)
