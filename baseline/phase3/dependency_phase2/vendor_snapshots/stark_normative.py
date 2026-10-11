"""STARK SPDA Core 0.4.0 — Validatable normative engine.

This module deliberately does not embed copyrighted tables or coefficients from
technical standards. It provides the machinery to ingest authorized values and
formula definitions, bind them to exact source metadata, require explicit
engineer validation, detect post-approval tampering, and execute deterministic
calculations only from validated normative content.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, asdict
from decimal import Decimal
from fractions import Fraction
import json
from typing import Any, Dict, List, Mapping, MutableMapping, Sequence, Set, Tuple

from stark_core import D, Finding, StarkValidationError, canonical_hash, decimal_str

ALLOWED_LIBRARY_STATES = {
    "METADATA_ONLY",
    "PARAMETERS_PENDING_VALIDATION",
    "VALIDATED_FOR_SCOPED_USE",
    "VALIDATED_FOR_ENGINE_USE",
    "RETIRED",
}
ALLOWED_ITEM_STATES = {
    "DRAFT",
    "PENDING_ENGINEER_VALIDATION",
    "ENGINEER_VALIDATED",
    "REJECTED",
    "RETIRED",
    "HISTORICAL_REFERENCE",
}
ALLOWED_SOURCE_STATES = {"AUTHORIZED", "PENDING", "RETIRED"}
ALLOWED_VALIDATION_STATES = {"PENDING", "VALIDATED", "REJECTED"}
ALLOWED_OPS = {"add", "sub", "mul", "div", "sum", "product", "neg", "min", "max"}


@dataclass(frozen=True)
class NormativeParameter:
    parameter_id: str
    value: Decimal
    unit: str
    status: str
    source_ref: str
    standard: str
    edition: str
    locator: str
    approved_digest: str
    notes: str | None = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["value"] = decimal_str(self.value)
        return d


@dataclass(frozen=True)
class NormativeUseReceipt:
    item_type: str
    item_id: str
    library_version: str
    approved_digest: str
    source_ref: str
    standard: str
    edition: str
    locator: str
    value: str | None = None
    unit: str | None = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class NormativeCalculationResult:
    formula_id: str
    result: Decimal
    trace_hash: str
    formula_receipt: NormativeUseReceipt
    parameter_receipts: Sequence[NormativeUseReceipt]
    normalized_inputs: Mapping[str, Decimal]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "formula_id": self.formula_id,
            "result": decimal_str(self.result),
            "trace_hash": self.trace_hash,
            "formula_receipt": self.formula_receipt.to_dict(),
            "parameter_receipts": [x.to_dict() for x in self.parameter_receipts],
            "normalized_inputs": {k: decimal_str(v) for k, v in self.normalized_inputs.items()},
        }


@dataclass(frozen=True)
class NormativeDualCheckResult:
    decimal_result: Decimal
    fraction_result: Decimal
    delta: Decimal
    tolerance: Decimal
    passed: bool
    trace_hash: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "decimal_result": decimal_str(self.decimal_result),
            "fraction_result": decimal_str(self.fraction_result),
            "delta": decimal_str(self.delta),
            "tolerance": decimal_str(self.tolerance),
            "passed": self.passed,
            "trace_hash": self.trace_hash,
        }


def load_library(path: str) -> Dict[str, Any]:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def save_library(path: str, library: Mapping[str, Any]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(library, f, indent=2, ensure_ascii=False, sort_keys=False)
        f.write("\n")


def _source_index(library: Mapping[str, Any]) -> Dict[str, Mapping[str, Any]]:
    return {x.get("source_id"): x for x in (library.get("authorized_sources", []) or []) if x.get("source_id")}


def _standard_pairs(library: Mapping[str, Any]) -> Set[Tuple[str, str]]:
    return {
        (str(x.get("standard")), str(x.get("edition")))
        for x in (library.get("standards", []) or [])
        if x.get("standard") and x.get("edition") and x.get("metadata_status") == "VERIFIED"
    }


def _parameter_payload(parameter: Mapping[str, Any]) -> Dict[str, Any]:
    source = parameter.get("source", {}) or {}
    return {
        "parameter_id": parameter.get("parameter_id"),
        "value": str(parameter.get("value")),
        "unit": parameter.get("unit", ""),
        "source": {
            "source_id": source.get("source_id"),
            "standard": source.get("standard"),
            "edition": source.get("edition"),
            "part": source.get("part"),
            "locator": source.get("locator"),
            "evidence_hash": source.get("evidence_hash"),
        },
    }


def _formula_payload(formula: Mapping[str, Any]) -> Dict[str, Any]:
    source = formula.get("source", {}) or {}
    return {
        "formula_id": formula.get("formula_id"),
        "expression": formula.get("expression"),
        "required_inputs": sorted(formula.get("required_inputs", []) or []),
        "parameter_refs": sorted(formula.get("parameter_refs", []) or []),
        "result_unit": formula.get("result_unit", ""),
        "source": {
            "source_id": source.get("source_id"),
            "standard": source.get("standard"),
            "edition": source.get("edition"),
            "part": source.get("part"),
            "locator": source.get("locator"),
            "evidence_hash": source.get("evidence_hash"),
        },
    }


def approval_digest(item: Mapping[str, Any], item_type: str) -> str:
    if item_type == "PARAMETER":
        return canonical_hash(_parameter_payload(item))
    if item_type == "FORMULA":
        return canonical_hash(_formula_payload(item))
    raise StarkValidationError(f"Unsupported normative item type: {item_type}")


def _validate_source_binding(library: Mapping[str, Any], item: Mapping[str, Any], item_id: str) -> List[Finding]:
    findings: List[Finding] = []
    source = item.get("source", {}) or {}
    for field in ("source_id", "standard", "edition", "locator"):
        if not source.get(field):
            findings.append(Finding("NORMATIVE_SOURCE_FIELD_MISSING", "CRITICAL", f"{item_id}: source.{field} is required", True))

    source_id = source.get("source_id")
    source_record = _source_index(library).get(source_id)
    if source_id and source_record is None:
        findings.append(Finding("NORMATIVE_SOURCE_UNKNOWN", "CRITICAL", f"{item_id}: unknown authorized source {source_id}", True))
    elif source_record is not None and source_record.get("status") != "AUTHORIZED":
        findings.append(Finding("NORMATIVE_SOURCE_NOT_AUTHORIZED", "CRITICAL", f"{item_id}: source {source_id} is not AUTHORIZED", True))

    pair = (str(source.get("standard")), str(source.get("edition")))
    if all(pair) and pair not in _standard_pairs(library):
        findings.append(Finding("NORMATIVE_EDITION_NOT_VERIFIED", "CRITICAL", f"{item_id}: {pair[0]} / {pair[1]} is not a verified standard edition in this library", True))

    if source_record:
        for field in ("standard", "edition", "evidence_hash"):
            if source.get(field) and source_record.get(field) and str(source.get(field)) != str(source_record.get(field)):
                findings.append(Finding("NORMATIVE_SOURCE_BINDING_MISMATCH", "CRITICAL", f"{item_id}: source {field} differs from authorized-source registry", True))
        auth = source_record.get("authorization", {}) or {}
        if auth:
            auth_payload = {
                "source_id": source_record.get("source_id"), "kind": source_record.get("kind"),
                "title": source_record.get("title"), "standard": source_record.get("standard"),
                "edition": source_record.get("edition"), "location": source_record.get("location"),
                "evidence_hash": source_record.get("evidence_hash"),
            }
            if auth.get("status") != "AUTHORIZED" or auth.get("approved_digest") != canonical_hash(auth_payload):
                findings.append(Finding("NORMATIVE_AUTHORIZED_SOURCE_TAMPERED", "CRITICAL", f"{item_id}: authorized source metadata differs from approved source digest", True))
    return findings


def _validation_integrity_findings(item: Mapping[str, Any], item_type: str, item_id: str) -> List[Finding]:
    findings: List[Finding] = []
    validation = item.get("validation", {}) or {}
    if item.get("status") == "ENGINEER_VALIDATED":
        if validation.get("status") != "VALIDATED":
            findings.append(Finding("ENGINEER_VALIDATION_RECORD_MISSING", "CRITICAL", f"{item_id}: validated status without validation record", True))
        for field in ("engineer", "validated_at", "approved_digest"):
            if not validation.get(field):
                findings.append(Finding("ENGINEER_VALIDATION_FIELD_MISSING", "CRITICAL", f"{item_id}: validation.{field} is required", True))
        approved = validation.get("approved_digest")
        if approved and approved != approval_digest(item, item_type):
            findings.append(Finding("NORMATIVE_ITEM_TAMPERED_AFTER_APPROVAL", "CRITICAL", f"{item_id}: technical content differs from engineer-approved digest", True))
    return findings


def _walk_expression(expr: Any, parameter_refs: Set[str], input_refs: Set[str], errors: List[str], path: str = "expression") -> None:
    if not isinstance(expr, Mapping):
        errors.append(f"{path}: expression node must be an object")
        return
    keys = {k for k in ("input", "param", "const", "op") if k in expr}
    if len(keys) != 1:
        errors.append(f"{path}: node must contain exactly one of input/param/const/op")
        return
    if "input" in expr:
        if not isinstance(expr["input"], str) or not expr["input"]:
            errors.append(f"{path}.input: invalid input name")
        else:
            input_refs.add(expr["input"])
        return
    if "param" in expr:
        if not isinstance(expr["param"], str) or not expr["param"]:
            errors.append(f"{path}.param: invalid parameter reference")
        else:
            parameter_refs.add(expr["param"])
        return
    if "const" in expr:
        try:
            D(expr["const"])
        except Exception:
            errors.append(f"{path}.const: invalid numeric constant")
        return
    op = expr.get("op")
    if op not in ALLOWED_OPS:
        errors.append(f"{path}.op: unsupported operation {op}")
        return
    args = expr.get("args")
    if not isinstance(args, list) or not args:
        errors.append(f"{path}.args: non-empty array required")
        return
    if op in {"sub", "div"} and len(args) != 2:
        errors.append(f"{path}: {op} requires exactly 2 args")
    if op == "neg" and len(args) != 1:
        errors.append(f"{path}: neg requires exactly 1 arg")
    for i, arg in enumerate(args):
        _walk_expression(arg, parameter_refs, input_refs, errors, f"{path}.args[{i}]")


def validate_library(library: Mapping[str, Any]) -> List[Finding]:
    findings: List[Finding] = []
    for key in ("library_id", "library_version", "state", "standards", "authorized_sources", "parameters", "formulas"):
        if key not in library:
            findings.append(Finding("LIBRARY_MISSING_FIELD", "CRITICAL", f"Missing library field: {key}", True))

    if library.get("state") not in ALLOWED_LIBRARY_STATES:
        findings.append(Finding("LIBRARY_BAD_STATE", "CRITICAL", f"Invalid library state: {library.get('state')}", True))

    source_ids: List[str] = []
    for source in library.get("authorized_sources", []) or []:
        sid = source.get("source_id")
        if not sid:
            findings.append(Finding("SOURCE_NO_ID", "CRITICAL", "Authorized source without source_id", True))
            continue
        source_ids.append(sid)
        if source.get("status") not in ALLOWED_SOURCE_STATES:
            findings.append(Finding("SOURCE_BAD_STATE", "HIGH", f"{sid}: invalid source status", True))
    for sid in sorted({x for x in source_ids if source_ids.count(x) > 1}):
        findings.append(Finding("DUPLICATE_SOURCE_ID", "CRITICAL", f"Duplicate authorized source: {sid}", True))

    params = library.get("parameters", []) or []
    pids = [p.get("parameter_id") for p in params if p.get("parameter_id")]
    for pid in sorted({x for x in pids if pids.count(x) > 1}):
        findings.append(Finding("DUPLICATE_NORMATIVE_PARAMETER", "CRITICAL", f"Duplicate parameter: {pid}", True))
    for p in params:
        pid = p.get("parameter_id", "<missing>")
        if p.get("status") not in ALLOWED_ITEM_STATES:
            findings.append(Finding("PARAMETER_BAD_STATE", "HIGH", f"{pid}: invalid status {p.get('status')}", True))
        try:
            D(p.get("value"))
        except Exception:
            findings.append(Finding("PARAMETER_BAD_VALUE", "CRITICAL", f"{pid}: invalid numeric value", True))
        findings.extend(_validate_source_binding(library, p, pid))
        findings.extend(_validation_integrity_findings(p, "PARAMETER", pid))

    formulas = library.get("formulas", []) or []
    fids = [f.get("formula_id") for f in formulas if f.get("formula_id")]
    for fid in sorted({x for x in fids if fids.count(x) > 1}):
        findings.append(Finding("DUPLICATE_NORMATIVE_FORMULA", "CRITICAL", f"Duplicate formula: {fid}", True))
    param_id_set = set(pids)
    for formula in formulas:
        fid = formula.get("formula_id", "<missing>")
        if formula.get("status") not in ALLOWED_ITEM_STATES:
            findings.append(Finding("FORMULA_BAD_STATE", "HIGH", f"{fid}: invalid status {formula.get('status')}", True))
        findings.extend(_validate_source_binding(library, formula, fid))
        findings.extend(_validation_integrity_findings(formula, "FORMULA", fid))
        expr_params: Set[str] = set()
        expr_inputs: Set[str] = set()
        errors: List[str] = []
        _walk_expression(formula.get("expression"), expr_params, expr_inputs, errors)
        for msg in errors:
            findings.append(Finding("FORMULA_EXPRESSION_INVALID", "CRITICAL", f"{fid}: {msg}", True))
        declared_params = set(formula.get("parameter_refs", []) or [])
        declared_inputs = set(formula.get("required_inputs", []) or [])
        if expr_params != declared_params:
            findings.append(Finding("FORMULA_PARAMETER_DECLARATION_MISMATCH", "CRITICAL", f"{fid}: expression params {sorted(expr_params)} != declared {sorted(declared_params)}", True))
        if expr_inputs != declared_inputs:
            findings.append(Finding("FORMULA_INPUT_DECLARATION_MISMATCH", "CRITICAL", f"{fid}: expression inputs {sorted(expr_inputs)} != declared {sorted(declared_inputs)}", True))
        for pid in declared_params:
            if pid not in param_id_set:
                findings.append(Finding("FORMULA_UNKNOWN_PARAMETER", "CRITICAL", f"{fid}: unknown parameter {pid}", True))

    return findings


def _find_item(library: Mapping[str, Any], collection: str, id_field: str, item_id: str) -> Mapping[str, Any]:
    matches = [x for x in (library.get(collection, []) or []) if x.get(id_field) == item_id]
    if not matches:
        raise StarkValidationError(f"Unknown normative item: {item_id}")
    if len(matches) > 1:
        raise StarkValidationError(f"Duplicate normative item: {item_id}")
    return matches[0]


def parameter_findings(library: Mapping[str, Any], parameter_id: str) -> List[Finding]:
    try:
        p = _find_item(library, "parameters", "parameter_id", parameter_id)
    except StarkValidationError as exc:
        return [Finding("UNKNOWN_NORMATIVE_PARAMETER", "CRITICAL", str(exc), True)]
    findings = _validate_source_binding(library, p, parameter_id)
    findings.extend(_validation_integrity_findings(p, "PARAMETER", parameter_id))
    if p.get("status") != "ENGINEER_VALIDATED":
        findings.append(Finding("PARAMETER_NOT_ENGINEER_VALIDATED", "CRITICAL", f"{parameter_id}: status is {p.get('status')}", True))
    return findings


def formula_findings(library: Mapping[str, Any], formula_id: str) -> List[Finding]:
    try:
        f = _find_item(library, "formulas", "formula_id", formula_id)
    except StarkValidationError as exc:
        return [Finding("UNKNOWN_NORMATIVE_FORMULA", "CRITICAL", str(exc), True)]
    findings = _validate_source_binding(library, f, formula_id)
    findings.extend(_validation_integrity_findings(f, "FORMULA", formula_id))
    if f.get("status") != "ENGINEER_VALIDATED":
        findings.append(Finding("FORMULA_NOT_ENGINEER_VALIDATED", "CRITICAL", f"{formula_id}: status is {f.get('status')}", True))
    for pid in f.get("parameter_refs", []) or []:
        findings.extend(parameter_findings(library, pid))
    return findings


def library_is_engine_ready(
    library: Mapping[str, Any],
    required_parameter_ids: Sequence[str] | None = None,
    required_formula_ids: Sequence[str] | None = None,
) -> Tuple[bool, List[Finding]]:
    findings = validate_library(library)
    if library.get("state") not in {"VALIDATED_FOR_SCOPED_USE", "VALIDATED_FOR_ENGINE_USE"}:
        findings.append(Finding("LIBRARY_NOT_ENGINE_VALIDATED", "CRITICAL", f"Library state is {library.get('state')}; scoped or full engineer validation is required", True))

    if required_parameter_ids is None and required_formula_ids is None:
        required_parameter_ids = [p.get("parameter_id") for p in (library.get("parameters", []) or []) if p.get("parameter_id")]
        required_formula_ids = [f.get("formula_id") for f in (library.get("formulas", []) or []) if f.get("formula_id")]
    for pid in required_parameter_ids or []:
        findings.extend(parameter_findings(library, pid))
    for fid in required_formula_ids or []:
        findings.extend(formula_findings(library, fid))
    return (not any(f.blocking for f in findings), findings)


def get_validated_parameter(library: Mapping[str, Any], parameter_id: str) -> NormativeParameter:
    findings = parameter_findings(library, parameter_id)
    if any(f.blocking for f in findings):
        raise StarkValidationError("; ".join(f.message for f in findings if f.blocking))
    p = _find_item(library, "parameters", "parameter_id", parameter_id)
    source = p["source"]
    validation = p["validation"]
    return NormativeParameter(
        parameter_id=parameter_id,
        value=D(p["value"]),
        unit=str(p.get("unit", "")),
        status=p["status"],
        source_ref=str(source["source_id"]),
        standard=str(source["standard"]),
        edition=str(source["edition"]),
        locator=str(source["locator"]),
        approved_digest=str(validation["approved_digest"]),
        notes=p.get("notes"),
    )


def validate_parameter(
    library: Mapping[str, Any], parameter_id: str, engineer: str, validated_at: str, notes: str | None = None
) -> Dict[str, Any]:
    if not engineer.strip():
        raise StarkValidationError("Engineer name is required for normative validation")
    if not validated_at.strip():
        raise StarkValidationError("Validation timestamp is required")
    lib = deepcopy(library)
    p = _find_item(lib, "parameters", "parameter_id", parameter_id)
    source_findings = _validate_source_binding(lib, p, parameter_id)
    if any(f.blocking for f in source_findings):
        raise StarkValidationError("; ".join(f.message for f in source_findings if f.blocking))
    for target in lib.get("parameters", []):
        if target.get("parameter_id") == parameter_id:
            target["status"] = "ENGINEER_VALIDATED"
            target["validation"] = {
                "status": "VALIDATED",
                "engineer": engineer,
                "validated_at": validated_at,
                "approved_digest": approval_digest(target, "PARAMETER"),
                "notes": notes,
            }
            break
    return lib


def validate_formula(
    library: Mapping[str, Any], formula_id: str, engineer: str, validated_at: str, notes: str | None = None
) -> Dict[str, Any]:
    if not engineer.strip():
        raise StarkValidationError("Engineer name is required for normative validation")
    lib = deepcopy(library)
    f = _find_item(lib, "formulas", "formula_id", formula_id)
    source_findings = _validate_source_binding(lib, f, formula_id)
    if any(x.blocking for x in source_findings):
        raise StarkValidationError("; ".join(x.message for x in source_findings if x.blocking))
    for pid in f.get("parameter_refs", []) or []:
        pf = parameter_findings(lib, pid)
        if any(x.blocking for x in pf):
            raise StarkValidationError(f"Formula dependency {pid} is not ready: " + "; ".join(x.message for x in pf if x.blocking))
    for target in lib.get("formulas", []):
        if target.get("formula_id") == formula_id:
            target["status"] = "ENGINEER_VALIDATED"
            target["validation"] = {
                "status": "VALIDATED",
                "engineer": engineer,
                "validated_at": validated_at,
                "approved_digest": approval_digest(target, "FORMULA"),
                "notes": notes,
            }
            break
    return lib


def reject_item(
    library: Mapping[str, Any], item_id: str, item_type: str, engineer: str, rejected_at: str, reason: str
) -> Dict[str, Any]:
    lib = deepcopy(library)
    collection, id_field = ("parameters", "parameter_id") if item_type == "PARAMETER" else ("formulas", "formula_id")
    _find_item(lib, collection, id_field, item_id)
    for target in lib.get(collection, []):
        if target.get(id_field) == item_id:
            target["status"] = "REJECTED"
            target["validation"] = {
                "status": "REJECTED",
                "engineer": engineer,
                "validated_at": rejected_at,
                "approved_digest": None,
                "notes": reason,
            }
            break
    return lib


def _receipt_for_parameter(library: Mapping[str, Any], p: NormativeParameter) -> NormativeUseReceipt:
    return NormativeUseReceipt(
        item_type="PARAMETER", item_id=p.parameter_id, library_version=str(library.get("library_version")),
        approved_digest=p.approved_digest, source_ref=p.source_ref, standard=p.standard,
        edition=p.edition, locator=p.locator, value=decimal_str(p.value), unit=p.unit,
    )


def _receipt_for_formula(library: Mapping[str, Any], formula: Mapping[str, Any]) -> NormativeUseReceipt:
    source = formula["source"]
    return NormativeUseReceipt(
        item_type="FORMULA", item_id=str(formula["formula_id"]), library_version=str(library.get("library_version")),
        approved_digest=str(formula["validation"]["approved_digest"]), source_ref=str(source["source_id"]),
        standard=str(source["standard"]), edition=str(source["edition"]), locator=str(source["locator"]),
    )


def _eval_decimal(expr: Mapping[str, Any], inputs: Mapping[str, Decimal], params: Mapping[str, Decimal]) -> Decimal:
    if "input" in expr:
        key = expr["input"]
        if key not in inputs:
            raise StarkValidationError(f"Missing project input: {key}")
        return inputs[key]
    if "param" in expr:
        key = expr["param"]
        if key not in params:
            raise StarkValidationError(f"Missing validated normative parameter: {key}")
        return params[key]
    if "const" in expr:
        return D(expr["const"])
    op = expr["op"]
    values = [_eval_decimal(x, inputs, params) for x in expr["args"]]
    if op in {"add", "sum"}:
        return sum(values, Decimal(0))
    if op in {"mul", "product"}:
        out = Decimal(1)
        for v in values:
            out *= v
        return out
    if op == "sub":
        return values[0] - values[1]
    if op == "div":
        if values[1] == 0:
            raise StarkValidationError("Division by zero in normative formula")
        return values[0] / values[1]
    if op == "neg":
        return -values[0]
    if op == "min":
        return min(values)
    if op == "max":
        return max(values)
    raise StarkValidationError(f"Unsupported operation: {op}")


def _F(value: Any) -> Fraction:
    return Fraction(D(value))


def _eval_fraction(expr: Mapping[str, Any], inputs: Mapping[str, Fraction], params: Mapping[str, Fraction]) -> Fraction:
    if "input" in expr:
        if expr["input"] not in inputs:
            raise StarkValidationError(f"Missing project input: {expr['input']}")
        return inputs[expr["input"]]
    if "param" in expr:
        if expr["param"] not in params:
            raise StarkValidationError(f"Missing validated normative parameter: {expr['param']}")
        return params[expr["param"]]
    if "const" in expr:
        return _F(expr["const"])
    op = expr["op"]
    values = [_eval_fraction(x, inputs, params) for x in expr["args"]]
    if op in {"add", "sum"}:
        return sum(values, Fraction(0, 1))
    if op in {"mul", "product"}:
        out = Fraction(1, 1)
        for v in values:
            out *= v
        return out
    if op == "sub":
        return values[0] - values[1]
    if op == "div":
        if values[1] == 0:
            raise StarkValidationError("Division by zero in normative formula")
        return values[0] / values[1]
    if op == "neg":
        return -values[0]
    if op == "min":
        return min(values)
    if op == "max":
        return max(values)
    raise StarkValidationError(f"Unsupported operation: {op}")


def evaluate_validated_formula(
    library: Mapping[str, Any], formula_id: str, project_inputs: Mapping[str, Any],
    expected_standard: str | None = None, expected_edition: str | None = None,
) -> NormativeCalculationResult:
    ff = formula_findings(library, formula_id)
    if any(x.blocking for x in ff):
        raise StarkValidationError("; ".join(x.message for x in ff if x.blocking))
    formula = _find_item(library, "formulas", "formula_id", formula_id)
    source = formula["source"]
    if expected_standard and source.get("standard") != expected_standard:
        raise StarkValidationError(f"Formula {formula_id} belongs to {source.get('standard')}, expected {expected_standard}")
    if expected_edition and source.get("edition") != expected_edition:
        raise StarkValidationError(f"Formula {formula_id} edition {source.get('edition')}, expected {expected_edition}")

    normalized_inputs: Dict[str, Decimal] = {}
    for name in formula.get("required_inputs", []) or []:
        if name not in project_inputs:
            raise StarkValidationError(f"Missing required project input: {name}")
        normalized_inputs[name] = D(project_inputs[name])

    pvalues: Dict[str, Decimal] = {}
    receipts: List[NormativeUseReceipt] = []
    for pid in formula.get("parameter_refs", []) or []:
        p = get_validated_parameter(library, pid)
        if p.standard != source.get("standard") or p.edition != source.get("edition"):
            raise StarkValidationError(f"Parameter {pid} normative context differs from formula {formula_id}")
        pvalues[pid] = p.value
        receipts.append(_receipt_for_parameter(library, p))

    result = _eval_decimal(formula["expression"], normalized_inputs, pvalues)
    formula_receipt = _receipt_for_formula(library, formula)
    trace = {
        "engine": "STARK_NORMATIVE_0.4.0",
        "library_version": library.get("library_version"),
        "formula": formula_receipt.to_dict(),
        "parameters": [x.to_dict() for x in receipts],
        "inputs": {k: decimal_str(v) for k, v in normalized_inputs.items()},
        "result": decimal_str(result),
    }
    return NormativeCalculationResult(formula_id, result, canonical_hash(trace), formula_receipt, tuple(receipts), normalized_inputs)


def dual_validate_normative_formula(
    library: Mapping[str, Any], formula_id: str, project_inputs: Mapping[str, Any], tolerance: Any = "1e-24",
) -> NormativeDualCheckResult:
    primary = evaluate_validated_formula(library, formula_id, project_inputs)
    formula = _find_item(library, "formulas", "formula_id", formula_id)
    inputs_f = {k: _F(v) for k, v in project_inputs.items()}
    params_f = {pid: _F(get_validated_parameter(library, pid).value) for pid in (formula.get("parameter_refs", []) or [])}
    frac = _eval_fraction(formula["expression"], inputs_f, params_f)
    independent = Decimal(frac.numerator) / Decimal(frac.denominator)
    tol = D(tolerance)
    delta = abs(primary.result - independent)
    trace = canonical_hash({
        "formula_id": formula_id,
        "primary": decimal_str(primary.result),
        "independent": decimal_str(independent),
        "tolerance": decimal_str(tol),
        "primary_trace": primary.trace_hash,
    })
    return NormativeDualCheckResult(primary.result, independent, delta, tol, delta <= tol, trace)


def build_binding_receipts(
    library: Mapping[str, Any], parameter_ids: Sequence[str], formula_ids: Sequence[str]
) -> List[Dict[str, Any]]:
    receipts: List[Dict[str, Any]] = []
    for pid in parameter_ids:
        receipts.append(_receipt_for_parameter(library, get_validated_parameter(library, pid)).to_dict())
    for fid in formula_ids:
        ff = formula_findings(library, fid)
        if any(x.blocking for x in ff):
            raise StarkValidationError("; ".join(x.message for x in ff if x.blocking))
        receipts.append(_receipt_for_formula(library, _find_item(library, "formulas", "formula_id", fid)).to_dict())
    return receipts
