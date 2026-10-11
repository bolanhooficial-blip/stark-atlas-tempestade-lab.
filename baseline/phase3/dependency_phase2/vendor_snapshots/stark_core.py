"""STARK SPDA Core 0.4.0 (experimental)

Deterministic nucleus for the STARK SPDA architecture.

This module intentionally does NOT embed copyrighted normative tables. Normative
parameters are supplied by a separately versioned library and are accepted only
when marked as engineer-validated.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
from decimal import Decimal, getcontext
from fractions import Fraction
from hashlib import sha256
import json
import math
from typing import Any, Dict, Iterable, List, Mapping, Sequence, Set, Tuple

getcontext().prec = 34

ENGINE_VERSION = "0.4.0"
SCHEMA_VERSION = "0.4.0"

ALLOWED_OBJECT_STATES = {
    "EXTRAIDO", "CONFIRMADO", "CALCULADO", "PROPOSTO", "VERIFICADO_INTERNAMENTE",
    "VALIDADO_PELO_ENGENHEIRO", "REJEITADO", "SUBSTITUIDO", "OBSOLETO",
    "PENDENTE", "CONFLITANTE"
}
ALLOWED_RELATIONS = {
    "CONECTADO_A", "PROTEGE", "PERTENCE_A", "DEPENDE_DE", "INTERFERE_COM",
    "DERIVADO_DE", "VALIDADO_POR", "SUBSTITUI", "LOCALIZADO_EM"
}
ALLOWED_PROJECT_STATES = {
    "EM_ESTRUTURACAO", "DADOS_INCOMPLETOS", "EM_CALCULO", "ARRANJO_EM_DESENVOLVIMENTO",
    "EM_AUDITORIA", "AGUARDANDO_ENGENHEIRO", "VALIDADO_PARA_DOCUMENTACAO",
    "DOCUMENTACAO_GERADA", "REVISAO_NECESSARIA", "ENCERRADO", "OBSOLETO"
}


class StarkValidationError(ValueError):
    pass


@dataclass(frozen=True)
class Finding:
    code: str
    severity: str
    message: str
    blocking: bool = False
    object_id: str | None = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class RiskResult:
    total: Decimal
    tolerable: Decimal
    relation: str
    status: str

    def to_dict(self) -> Dict[str, str]:
        return {
            "total": decimal_str(self.total),
            "tolerable": decimal_str(self.tolerable),
            "relation": self.relation,
            "status": self.status,
        }


@dataclass(frozen=True)
class ComponentResult:
    component_id: str
    factors: Mapping[str, Decimal]
    result: Decimal
    trace_hash: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "component_id": self.component_id,
            "factors": {k: decimal_str(v) for k, v in self.factors.items()},
            "result": decimal_str(self.result),
            "trace_hash": self.trace_hash,
        }


@dataclass(frozen=True)
class DualCheckResult:
    decimal_value: Decimal
    fraction_value: Decimal
    delta: Decimal
    tolerance: Decimal
    passed: bool

    def to_dict(self) -> Dict[str, Any]:
        return {
            "decimal_value": decimal_str(self.decimal_value),
            "fraction_value": decimal_str(self.fraction_value),
            "delta": decimal_str(self.delta),
            "tolerance": decimal_str(self.tolerance),
            "passed": self.passed,
        }


def D(value: Any) -> Decimal:
    """Deterministic Decimal conversion through string representation."""
    if isinstance(value, Decimal):
        return value
    if isinstance(value, float) and not math.isfinite(value):
        raise StarkValidationError(f"Non-finite numeric value not allowed: {value!r}")
    try:
        return Decimal(str(value))
    except Exception as exc:  # pragma: no cover - defensive
        raise StarkValidationError(f"Invalid decimal value: {value!r}") from exc


def decimal_str(value: Decimal) -> str:
    """Plain decimal string, avoiding scientific notation in audit outputs."""
    return format(value, "f")


def scaled_to_absolute(value: Any, exponent: int = -5) -> Decimal:
    return D(value) * (Decimal(10) ** exponent)


def sum_risk_components(components: Mapping[str, Any]) -> Decimal:
    """Sum already-normalized absolute risk components deterministically."""
    total = Decimal(0)
    for key in sorted(components):
        value = D(components[key])
        if value < 0:
            raise StarkValidationError(f"Negative risk component not allowed: {key}={value}")
        total += value
    return total


def compute_component_product(component_id: str, factors: Mapping[str, Any]) -> ComponentResult:
    """Generic deterministic multiplicative component engine.

    This implements only the arithmetic pattern `product(factors)`. It does not
    assert which factors or coefficients are required by any specific standard.
    Those definitions belong to the validated normative library.
    """
    if not component_id:
        raise StarkValidationError("component_id is required")
    if not factors:
        raise StarkValidationError(f"{component_id}: at least one factor is required")

    normalized: Dict[str, Decimal] = {}
    result = Decimal(1)
    for key in sorted(factors):
        value = D(factors[key])
        if value < 0:
            raise StarkValidationError(f"{component_id}: negative factor {key}={value}")
        normalized[key] = value
        result *= value

    trace = {
        "engine": ENGINE_VERSION,
        "component_id": component_id,
        "factors": {k: decimal_str(v) for k, v in normalized.items()},
        "operation": "PRODUCT"
    }
    return ComponentResult(component_id, normalized, result, canonical_hash(trace))


def evaluate_risk(total: Any, tolerable: Any) -> RiskResult:
    total_d, rt = D(total), D(tolerable)
    if total_d < 0 or rt <= 0:
        raise StarkValidationError("Risk must be >= 0 and tolerable risk must be > 0")
    if total_d > rt:
        return RiskResult(total_d, rt, ">", "PROTECTION_REQUIRED")
    if total_d < rt:
        return RiskResult(total_d, rt, "<", "CRITERION_MET")
    return RiskResult(total_d, rt, "=", "AT_TOLERABLE_LIMIT")


def evaluate_scaled_components(
    components_x10n: Mapping[str, Any], tolerable: Any, exponent: int = -5
) -> RiskResult:
    absolute = {k: scaled_to_absolute(v, exponent) for k, v in components_x10n.items()}
    return evaluate_risk(sum_risk_components(absolute), tolerable)


def evaluate_component_products(
    definitions: Mapping[str, Mapping[str, Any]], tolerable: Any
) -> Tuple[RiskResult, Dict[str, ComponentResult]]:
    results: Dict[str, ComponentResult] = {}
    totals: Dict[str, Decimal] = {}
    for component_id in sorted(definitions):
        result = compute_component_product(component_id, definitions[component_id])
        results[component_id] = result
        totals[component_id] = result.result
    return evaluate_risk(sum_risk_components(totals), tolerable), results


def _fraction_from_decimal_like(value: Any) -> Fraction:
    text = str(value)
    d = Decimal(text)
    return Fraction(d)


def independent_product_sum(definitions: Mapping[str, Mapping[str, Any]]) -> Decimal:
    """Independent arithmetic path using Fraction, not Decimal multiplication."""
    total = Fraction(0, 1)
    for component_id in sorted(definitions):
        product = Fraction(1, 1)
        for key in sorted(definitions[component_id]):
            factor = _fraction_from_decimal_like(definitions[component_id][key])
            if factor < 0:
                raise StarkValidationError(f"{component_id}: negative factor {key}")
            product *= factor
        total += product
    return Decimal(total.numerator) / Decimal(total.denominator)


def dual_validate_component_products(
    definitions: Mapping[str, Mapping[str, Any]], tolerance: Any = "1e-24"
) -> DualCheckResult:
    decimal_total = sum(
        (compute_component_product(cid, factors).result for cid, factors in sorted(definitions.items())),
        Decimal(0),
    )
    fraction_total = independent_product_sum(definitions)
    tol = D(tolerance)
    delta = abs(decimal_total - fraction_total)
    return DualCheckResult(decimal_total, fraction_total, delta, tol, delta <= tol)


def compare_scenarios(before: Any, after: Any, tolerance: Any = "0") -> List[Finding]:
    """Consistency checks between before/after risk values.

    A higher post-measure risk is not declared impossible; it is flagged because
    it is unexpected for a scenario explicitly described as risk-reduction.
    """
    b, a, tol = D(before), D(after), D(tolerance)
    findings: List[Finding] = []
    if b < 0 or a < 0:
        findings.append(Finding("NEGATIVE_RISK", "CRITICAL", "Risk values cannot be negative", True))
        return findings
    if a > b + tol:
        findings.append(Finding(
            "AFTER_RISK_HIGHER_THAN_BEFORE", "HIGH",
            f"After-measure risk {decimal_str(a)} is higher than before {decimal_str(b)}",
            True,
        ))
    elif abs(a - b) <= tol and b != 0:
        findings.append(Finding(
            "NO_RISK_REDUCTION_DETECTED", "MEDIUM",
            "Before and after risk values are effectively unchanged", False,
        ))
    return findings


def validate_model(model: Mapping[str, Any]) -> List[Finding]:
    findings: List[Finding] = []
    required = [
        "schema_version", "engine_manifest", "project", "normative_context",
        "coordinate_system", "sources", "objects", "relations", "calculations",
        "validations", "engineer_review", "history"
    ]
    for key in required:
        if key not in model:
            findings.append(Finding("MODEL_MISSING_FIELD", "CRITICAL", f"Missing top-level field: {key}", True))

    if model.get("schema_version") != SCHEMA_VERSION:
        findings.append(Finding(
            "SCHEMA_VERSION_MISMATCH", "CRITICAL",
            f"Expected schema {SCHEMA_VERSION}, got {model.get('schema_version')!r}", True,
        ))

    project = model.get("project", {}) or {}
    if project.get("state") not in ALLOWED_PROJECT_STATES:
        findings.append(Finding("PROJECT_BAD_STATE", "HIGH", f"Invalid project state: {project.get('state')}", True))

    _validate_coordinate_system(model.get("coordinate_system", {}) or {}, findings)

    objects = model.get("objects", []) or []
    ids: List[str] = []
    object_by_id: Dict[str, Mapping[str, Any]] = {}
    for obj in objects:
        oid = obj.get("id")
        if not oid:
            findings.append(Finding("OBJECT_NO_ID", "CRITICAL", "Object without ID", True))
            continue
        ids.append(oid)
        object_by_id[oid] = obj
        state = obj.get("status")
        if state not in ALLOWED_OBJECT_STATES:
            findings.append(Finding("OBJECT_BAD_STATE", "HIGH", f"{oid}: invalid state {state}", True, oid))
        geom = obj.get("geometry")
        if geom:
            _validate_geometry(oid, geom, findings)

    duplicates = sorted({oid for oid in ids if ids.count(oid) > 1})
    for oid in duplicates:
        findings.append(Finding("DUPLICATE_OBJECT_ID", "CRITICAL", f"Duplicate object ID: {oid}", True, oid))

    idset = set(ids)
    for rel in model.get("relations", []) or []:
        src, dst, kind = rel.get("from"), rel.get("to"), rel.get("relation")
        if kind not in ALLOWED_RELATIONS:
            findings.append(Finding("INVALID_RELATION_TYPE", "HIGH", f"Invalid relation type: {kind}", True))
        if src not in idset:
            findings.append(Finding("ORPHAN_RELATION_SOURCE", "CRITICAL", f"Unknown relation source: {src}", True))
        if dst not in idset:
            findings.append(Finding("ORPHAN_RELATION_TARGET", "CRITICAL", f"Unknown relation target: {dst}", True))

    _validate_calculations(model, findings, idset)
    _validate_normative_refs(model, findings)

    norm = model.get("normative_context", {}) or {}
    if norm.get("status") == "CONFLICT":
        findings.append(Finding("NORMATIVE_CONTEXT_CONFLICT", "CRITICAL", "Normative context is marked CONFLICT", True))
    elif norm.get("status") != "VALIDATED":
        findings.append(Finding(
            "NORMATIVE_CONTEXT_NOT_VALIDATED", "HIGH",
            "Normative context awaits engineer validation", True,
        ))

    return findings


def _validate_coordinate_system(cs: Mapping[str, Any], findings: List[Finding]) -> None:
    unit = cs.get("length_unit")
    if unit not in {"mm", "cm", "m"}:
        findings.append(Finding("INVALID_LENGTH_UNIT", "CRITICAL", f"Invalid length unit: {unit}", True))
    origin = cs.get("origin", {}) or {}
    for axis in ("x", "y", "z"):
        if axis not in origin:
            findings.append(Finding("MISSING_ORIGIN_AXIS", "CRITICAL", f"Origin missing {axis}", True))
        else:
            _validate_finite_number(origin[axis], f"origin.{axis}", findings)


def _validate_finite_number(value: Any, label: str, findings: List[Finding], oid: str | None = None) -> None:
    try:
        d = D(value)
        if not d.is_finite():
            raise StarkValidationError("non-finite")
    except Exception:
        findings.append(Finding("INVALID_NUMERIC_VALUE", "CRITICAL", f"{label}: invalid numeric value {value!r}", True, oid))


def _validate_geometry(oid: str, geom: Mapping[str, Any], findings: List[Finding]) -> None:
    coords = geom.get("coordinates")
    if coords is None:
        return

    def walk(v: Any, path: str = "coordinates") -> None:
        if isinstance(v, (list, tuple)):
            for idx, x in enumerate(v):
                walk(x, f"{path}[{idx}]")
        else:
            _validate_finite_number(v, f"{oid}.{path}", findings, oid)

    walk(coords)


def _validate_calculations(model: Mapping[str, Any], findings: List[Finding], object_ids: Set[str]) -> None:
    calculations = model.get("calculations", []) or []
    calc_ids = [c.get("id") for c in calculations if c.get("id")]
    for cid in sorted({x for x in calc_ids if calc_ids.count(x) > 1}):
        findings.append(Finding("DUPLICATE_CALCULATION_ID", "CRITICAL", f"Duplicate calculation ID: {cid}", True))

    calcset = set(calc_ids)
    for obj in model.get("objects", []) or []:
        oid = obj.get("id")
        for cref in obj.get("calculation_refs", []) or []:
            if cref not in calcset:
                findings.append(Finding(
                    "DANGLING_CALCULATION_REF", "CRITICAL",
                    f"{oid}: unknown calculation ref {cref}", True, oid,
                ))

    for calc in calculations:
        for oid in calc.get("object_refs", []) or []:
            if oid not in object_ids:
                findings.append(Finding(
                    "CALCULATION_UNKNOWN_OBJECT", "CRITICAL",
                    f"{calc.get('id')}: unknown object ref {oid}", True,
                ))


def _validate_normative_refs(model: Mapping[str, Any], findings: List[Finding]) -> None:
    norm = model.get("normative_context", {}) or {}
    param_refs = norm.get("parameter_refs", []) or []
    formula_refs = norm.get("formula_refs", []) or []
    risk_model_refs = norm.get("risk_model_refs", []) or []
    binding_receipts = norm.get("binding_receipts", []) or []

    param_ids = {x.get("parameter_id") for x in param_refs if x.get("parameter_id")}
    formula_ids = {x.get("formula_id") for x in formula_refs if x.get("formula_id")}
    risk_model_ids = {x.get("risk_model_id") for x in risk_model_refs if x.get("risk_model_id")}
    receipt_ids = {x.get("item_id") for x in binding_receipts if x.get("item_id")}

    for obj in model.get("objects", []) or []:
        oid = obj.get("id")
        for nref in obj.get("normative_refs", []) or []:
            if nref not in param_ids and nref not in formula_ids and nref not in risk_model_ids:
                findings.append(Finding(
                    "DANGLING_NORMATIVE_REF", "CRITICAL",
                    f"{oid}: unknown normative ref {nref}", True, oid,
                ))

    for calc in model.get("calculations", []) or []:
        cid = calc.get("id")
        formula_ref = calc.get("formula_ref")
        if formula_ref and formula_ref not in formula_ids:
            findings.append(Finding(
                "CALCULATION_DANGLING_FORMULA_REF", "CRITICAL",
                f"{cid}: unknown formula ref {formula_ref}", True,
            ))
        for pid in calc.get("parameter_refs", []) or []:
            if pid not in param_ids:
                findings.append(Finding(
                    "CALCULATION_DANGLING_PARAMETER_REF", "CRITICAL",
                    f"{cid}: unknown parameter ref {pid}", True,
                ))

    if norm.get("status") == "VALIDATED":
        expected = param_ids | formula_ids | risk_model_ids
        missing_receipts = sorted(expected - receipt_ids)
        if missing_receipts:
            findings.append(Finding(
                "NORMATIVE_BINDING_RECEIPTS_MISSING", "CRITICAL",
                "Validated normative context is missing binding receipts for: " + ", ".join(missing_receipts), True,
            ))


def model_is_releasable(model: Mapping[str, Any]) -> Tuple[bool, List[Finding]]:
    findings = validate_model(model)
    blocked = any(f.blocking for f in findings)
    return (not blocked, findings)


def canonical_hash(model: Mapping[str, Any]) -> str:
    payload = json.dumps(model, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str)
    return sha256(payload.encode("utf-8")).hexdigest()


def affected_objects(model: Mapping[str, Any], changed_ids: Iterable[str]) -> Set[str]:
    """Return transitive dependents through DEPENDE_DE / DERIVADO_DE relations."""
    changed = set(changed_ids)
    reverse: Dict[str, Set[str]] = {}
    for rel in model.get("relations", []) or []:
        if rel.get("relation") not in {"DEPENDE_DE", "DERIVADO_DE"}:
            continue
        reverse.setdefault(rel.get("to"), set()).add(rel.get("from"))
    queue = list(changed)
    impacted = set(changed)
    while queue:
        current = queue.pop(0)
        for dep in reverse.get(current, ()):
            if dep not in impacted:
                impacted.add(dep)
                queue.append(dep)
    return impacted


def findings_summary(findings: Sequence[Finding]) -> Dict[str, Any]:
    severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    return {
        "count": len(findings),
        "blocking": sum(1 for f in findings if f.blocking),
        "by_severity": {s: sum(1 for f in findings if f.severity == s) for s in severities},
        "findings": [f.to_dict() for f in findings],
    }
