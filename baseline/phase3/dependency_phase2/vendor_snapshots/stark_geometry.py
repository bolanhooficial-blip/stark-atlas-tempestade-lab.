from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from decimal import Decimal, getcontext
from hashlib import sha256
from math import ceil
from pathlib import Path
import json

getcontext().prec = 28

try:
    import ezdxf
except Exception:  # pragma: no cover
    ezdxf = None


class GeometryValidationError(ValueError):
    pass


def _canon(obj) -> bytes:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def digest(obj) -> str:
    return sha256(_canon(obj)).hexdigest()


def D(v) -> Decimal:
    return v if isinstance(v, Decimal) else Decimal(str(v))


def _fmt(v: Decimal) -> str:
    s = format(v.normalize(), 'f')
    return '0' if s == '-0' else s


def default_workflow(operator_name: str = "Bolanho", engineer_name: str = "Régis") -> dict:
    return {
        "operator": {
            "name": operator_name,
            "role": "Operador STARK / prestador de serviços",
            "authority": "OPERATE_AND_PREPARE",
        },
        "engineer": {
            "name": engineer_name,
            "role": "Engenheiro eletricista / validador técnico",
            "authority": "TECHNICAL_VALIDATE_OR_REJECT",
        },
        "flow": [
            "REGIS_PROVIDES_INPUTS",
            "BOLANHO_OPERATES_STARK",
            "STARK_GENERATES_AND_AUDITS",
            "BOLANHO_SENDS_TO_REGIS",
            "REGIS_VALIDATES_TECHNICALLY",
        ],
    }


def validate_workflow(workflow: dict) -> None:
    if not isinstance(workflow, dict):
        raise GeometryValidationError("WORKFLOW_MISSING")
    op = workflow.get("operator", {})
    eng = workflow.get("engineer", {})
    if op.get("name") != "Bolanho":
        raise GeometryValidationError("OPERATOR_MUST_BE_BOLANHO")
    if eng.get("name") != "Régis":
        raise GeometryValidationError("ENGINEER_VALIDATOR_MUST_BE_REGIS")
    if op.get("authority") == "TECHNICAL_VALIDATE_OR_REJECT":
        raise GeometryValidationError("OPERATOR_CANNOT_TECHNICALLY_VALIDATE")
    if eng.get("authority") != "TECHNICAL_VALIDATE_OR_REJECT":
        raise GeometryValidationError("ENGINEER_VALIDATION_AUTHORITY_REQUIRED")


def validate_geometry_input(data: dict, *, allow_test_policy: bool = False) -> None:
    validate_workflow(data.get("workflow", {}))
    g = data.get("geometry", {})
    if g.get("type") != "RECTANGULAR_PRISM":
        raise GeometryValidationError("GEOMETRY_TYPE_NOT_SUPPORTED_V0_1")
    for key in ("length_m", "width_m", "height_m"):
        try:
            if D(g.get(key)) <= 0:
                raise GeometryValidationError(f"INVALID_{key.upper()}")
        except Exception as exc:
            if isinstance(exc, GeometryValidationError):
                raise
            raise GeometryValidationError(f"INVALID_{key.upper()}") from exc
    origin = g.get("origin_m", [0, 0, 0])
    if not isinstance(origin, list) or len(origin) != 3:
        raise GeometryValidationError("INVALID_ORIGIN")
    for v in origin:
        D(v)

    pc = data.get("protection_context", {})
    policy = pc.get("policy")
    if not policy:
        raise GeometryValidationError("VALIDATED_GEOMETRY_POLICY_REQUIRED")
    if policy.get("validated") is not True:
        raise GeometryValidationError("GEOMETRY_POLICY_NOT_VALIDATED")
    if policy.get("source_type") == "SYNTHETIC_TEST_ONLY" and not allow_test_policy:
        raise GeometryValidationError("SYNTHETIC_POLICY_FORBIDDEN_FOR_PRODUCTION")
    if policy.get("source_type") != "SYNTHETIC_TEST_ONLY":
        if not policy.get("source_ref") or not policy.get("approval_digest"):
            raise GeometryValidationError("NORMATIVE_POLICY_PROVENANCE_REQUIRED")
    for key in ("max_mesh_x_m", "max_mesh_y_m", "max_down_spacing_m"):
        if D(policy.get(key)) <= 0:
            raise GeometryValidationError(f"INVALID_POLICY_{key.upper()}")


def _axis_positions(total: Decimal, max_spacing: Decimal) -> list[Decimal]:
    n = max(1, int(ceil(float(total / max_spacing))))
    spacing = total / Decimal(n)
    return [spacing * Decimal(i) for i in range(n + 1)]


def _perimeter_point(distance: Decimal, length: Decimal, width: Decimal) -> tuple[Decimal, Decimal]:
    p = Decimal(2) * (length + width)
    d = distance % p
    if d <= length:
        return d, Decimal(0)
    d -= length
    if d <= width:
        return length, d
    d -= width
    if d <= length:
        return length - d, width
    d -= length
    return Decimal(0), width - d


def _down_points(length: Decimal, width: Decimal, max_spacing: Decimal) -> tuple[list[tuple[Decimal, Decimal]], Decimal]:
    perimeter = Decimal(2) * (length + width)
    count = max(4, int(ceil(float(perimeter / max_spacing))))
    actual = perimeter / Decimal(count)
    pts = [_perimeter_point(actual * Decimal(i), length, width) for i in range(count)]
    return pts, actual


def build_rectangular_arrangement(data: dict, *, allow_test_policy: bool = False) -> dict:
    validate_geometry_input(data, allow_test_policy=allow_test_policy)
    src = deepcopy(data)
    g = src["geometry"]
    pc = src["protection_context"]
    policy = pc["policy"]
    L, W, H = D(g["length_m"]), D(g["width_m"]), D(g["height_m"])
    ox, oy, oz = (D(x) for x in g.get("origin_m", [0, 0, 0]))
    zroof = oz + H
    xs = _axis_positions(L, D(policy["max_mesh_x_m"]))
    ys = _axis_positions(W, D(policy["max_mesh_y_m"]))

    objects = []
    # Volume
    objects.append({
        "id": "VOL-001", "type": "VOLUME", "subtype": "RECTANGULAR_PRISM",
        "origin_m": [_fmt(ox), _fmt(oy), _fmt(oz)],
        "dimensions_m": {"length": _fmt(L), "width": _fmt(W), "height": _fmt(H)},
        "status": "CONFIRMED_FROM_INPUT",
    })

    # perimeter mesh
    perimeter_pts = [
        [ox, oy, zroof], [ox + L, oy, zroof], [ox + L, oy + W, zroof],
        [ox, oy + W, zroof], [ox, oy, zroof],
    ]
    objects.append({
        "id": "MAL-PERIM-001", "type": "MESH_CONDUCTOR", "subtype": "PERIMETER",
        "points_m": [[_fmt(a), _fmt(b), _fmt(c)] for a, b, c in perimeter_pts],
        "layer": "STARK-SPDA-MALHA", "status": "PROPOSED_PRELIMINARY",
    })

    # Interior mesh lines: exclude boundary, already perimeter.
    mal_idx = 1
    for x in xs[1:-1]:
        mal_idx += 1
        objects.append({
            "id": f"MAL-X-{mal_idx:03d}", "type": "MESH_CONDUCTOR", "subtype": "INTERIOR_X",
            "points_m": [[_fmt(ox+x), _fmt(oy), _fmt(zroof)], [_fmt(ox+x), _fmt(oy+W), _fmt(zroof)]],
            "layer": "STARK-SPDA-MALHA", "status": "PROPOSED_PRELIMINARY",
        })
    mal_y_idx = 0
    for y in ys[1:-1]:
        mal_y_idx += 1
        objects.append({
            "id": f"MAL-Y-{mal_y_idx:03d}", "type": "MESH_CONDUCTOR", "subtype": "INTERIOR_Y",
            "points_m": [[_fmt(ox), _fmt(oy+y), _fmt(zroof)], [_fmt(ox+L), _fmt(oy+y), _fmt(zroof)]],
            "layer": "STARK-SPDA-MALHA", "status": "PROPOSED_PRELIMINARY",
        })

    downs, actual_down_spacing = _down_points(L, W, D(policy["max_down_spacing_m"]))
    for i, (x, y) in enumerate(downs, 1):
        objects.append({
            "id": f"DES-{i:03d}", "type": "DOWN_CONDUCTOR", "subtype": "PERIMETER_DISTRIBUTED",
            "points_m": [[_fmt(ox+x), _fmt(oy+y), _fmt(zroof)], [_fmt(ox+x), _fmt(oy+y), _fmt(oz)]],
            "layer": "STARK-SPDA-DESCIDAS", "status": "PROPOSED_PRELIMINARY",
        })

    # Grid junctions, useful as technical anchors.
    cap_idx = 0
    for x in xs:
        for y in ys:
            cap_idx += 1
            objects.append({
                "id": f"JUN-{cap_idx:03d}", "type": "MESH_JUNCTION", "subtype": "GRID_INTERSECTION",
                "point_m": [_fmt(ox+x), _fmt(oy+y), _fmt(zroof)],
                "layer": "STARK-SPDA-CAPTACAO", "status": "PROPOSED_PRELIMINARY",
            })

    relations = []
    for o in objects:
        if o["type"] == "DOWN_CONDUCTOR":
            relations.append({"from": o["id"], "type": "CONNECTED_TO", "to": "MAL-PERIM-001"})
            relations.append({"from": o["id"], "type": "TERMINATES_AT", "to": "GROUNDING_INTERFACE_PENDING"})
    for o in objects:
        if o["type"] == "MESH_CONDUCTOR" and o["id"] != "MAL-PERIM-001":
            relations.append({"from": o["id"], "type": "CONNECTED_TO", "to": "MAL-PERIM-001"})

    arrangement = {
        "geometry_core_version": "0.1.0",
        "project_id": src.get("project_id", "STK-SPDA-UNASSIGNED"),
        "version": src.get("version", "V01"),
        "workflow": src["workflow"],
        "input_digest": digest(src),
        "geometry": deepcopy(g),
        "protection_context": deepcopy(pc),
        "method": {
            "type": "MESH_RECTANGULAR_PRISM_V0_1",
            "scope": "RECTANGULAR_HORIZONTAL_ROOF_ONLY",
            "limitations": [
                "NO_ROLLING_SPHERE_ENGINE_IN_V0_1",
                "NO_PROTECTION_ANGLE_ENGINE_IN_V0_1",
                "NO_COMPLEX_ROOF_VOLUMES_IN_V0_1",
                "GROUNDING_INTERFACE_NOT_DESIGNED_IN_V0_1",
            ],
        },
        "derived": {
            "grid_x_positions_m": [_fmt(ox+x) for x in xs],
            "grid_y_positions_m": [_fmt(oy+y) for y in ys],
            "max_actual_mesh_x_m": _fmt(max(xs[i+1]-xs[i] for i in range(len(xs)-1))),
            "max_actual_mesh_y_m": _fmt(max(ys[i+1]-ys[i] for i in range(len(ys)-1))),
            "down_conductor_count": len(downs),
            "actual_down_spacing_m": _fmt(actual_down_spacing),
        },
        "objects": objects,
        "relations": relations,
        "status": "PRELIMINARY_AWAITING_REGIS_VALIDATION",
        "prepared_by": "Bolanho",
        "technical_validator": "Régis",
    }
    arrangement["arrangement_digest"] = digest(arrangement)
    return arrangement


def audit_arrangement(arrangement: dict) -> dict:
    issues = []
    pc = arrangement.get("protection_context", {})
    policy = pc.get("policy", {})
    d = arrangement.get("derived", {})
    if arrangement.get("prepared_by") != "Bolanho":
        issues.append({"severity": "CRITICAL", "code": "INVALID_OPERATOR"})
    if arrangement.get("technical_validator") != "Régis":
        issues.append({"severity": "CRITICAL", "code": "INVALID_TECHNICAL_VALIDATOR"})
    if arrangement.get("status") != "PRELIMINARY_AWAITING_REGIS_VALIDATION":
        issues.append({"severity": "CRITICAL", "code": "INVALID_RELEASE_STATUS"})
    try:
        if D(d["max_actual_mesh_x_m"]) > D(policy["max_mesh_x_m"]):
            issues.append({"severity": "CRITICAL", "code": "MESH_X_EXCEEDS_POLICY"})
        if D(d["max_actual_mesh_y_m"]) > D(policy["max_mesh_y_m"]):
            issues.append({"severity": "CRITICAL", "code": "MESH_Y_EXCEEDS_POLICY"})
        if D(d["actual_down_spacing_m"]) > D(policy["max_down_spacing_m"]):
            issues.append({"severity": "CRITICAL", "code": "DOWN_SPACING_EXCEEDS_POLICY"})
    except Exception:
        issues.append({"severity": "CRITICAL", "code": "POLICY_COMPARISON_FAILED"})

    ids = [o.get("id") for o in arrangement.get("objects", [])]
    if len(ids) != len(set(ids)):
        issues.append({"severity": "CRITICAL", "code": "DUPLICATE_OBJECT_ID"})
    idset = set(ids)
    for rel in arrangement.get("relations", []):
        if rel.get("from") not in idset:
            issues.append({"severity": "CRITICAL", "code": "RELATION_FROM_MISSING", "relation": rel})
        if rel.get("to") not in idset and rel.get("to") != "GROUNDING_INTERFACE_PENDING":
            issues.append({"severity": "CRITICAL", "code": "RELATION_TO_MISSING", "relation": rel})

    # Every descent must have two 3D points and terminate at z=origin_z.
    oz = D(arrangement["geometry"].get("origin_m", [0, 0, 0])[2])
    for o in arrangement.get("objects", []):
        if o.get("type") == "DOWN_CONDUCTOR":
            pts = o.get("points_m", [])
            if len(pts) != 2 or any(len(p) != 3 for p in pts):
                issues.append({"severity": "CRITICAL", "code": "INVALID_DOWN_GEOMETRY", "object_id": o.get("id")})
            elif D(pts[-1][2]) != oz:
                issues.append({"severity": "CRITICAL", "code": "DOWN_NOT_TERMINATED_AT_REFERENCE", "object_id": o.get("id")})

    critical = [i for i in issues if i["severity"] == "CRITICAL"]
    report = {
        "geometry_core_version": "0.1.0",
        "project_id": arrangement.get("project_id"),
        "arrangement_digest": arrangement.get("arrangement_digest"),
        "checks": {
            "object_count": len(arrangement.get("objects", [])),
            "relation_count": len(arrangement.get("relations", [])),
            "unique_ids": len(ids) == len(set(ids)),
            "mesh_within_policy": not any(i["code"].startswith("MESH_") for i in critical),
            "down_spacing_within_policy": not any(i["code"] == "DOWN_SPACING_EXCEEDS_POLICY" for i in critical),
        },
        "issues": issues,
        "status": "PASS_INTERNAL_GEOMETRY_AUDIT_AWAITING_REGIS" if not critical else "BLOCKED_GEOMETRY_AUDIT",
    }
    report["audit_digest"] = digest(report)
    return report


def export_dxf(arrangement: dict, audit: dict, path: str | Path) -> Path:
    if ezdxf is None:
        raise GeometryValidationError("EZDXF_NOT_AVAILABLE")
    if audit.get("status") != "PASS_INTERNAL_GEOMETRY_AUDIT_AWAITING_REGIS":
        raise GeometryValidationError("DXF_EXPORT_REQUIRES_PASSED_INTERNAL_AUDIT")
    path = Path(path)
    doc = ezdxf.new("R2018")
    for name in [
        "STARK-SPDA-CAPTACAO", "STARK-SPDA-MALHA", "STARK-SPDA-DESCIDAS",
        "STARK-SPDA-TEXTOS", "STARK-SPDA-PENDENCIAS", "STARK-SPDA-REFERENCIAS",
    ]:
        if name not in doc.layers:
            doc.layers.add(name)
    msp = doc.modelspace()
    for o in arrangement["objects"]:
        typ = o["type"]
        layer = o.get("layer", "STARK-SPDA-REFERENCIAS")
        if typ == "MESH_CONDUCTOR":
            pts = [(float(D(p[0])), float(D(p[1])), float(D(p[2]))) for p in o["points_m"]]
            msp.add_polyline3d(pts, dxfattribs={"layer": layer})
        elif typ == "DOWN_CONDUCTOR":
            pts = [(float(D(p[0])), float(D(p[1])), float(D(p[2]))) for p in o["points_m"]]
            msp.add_polyline3d(pts, dxfattribs={"layer": layer})
        elif typ == "MESH_JUNCTION":
            p = o["point_m"]
            pt = (float(D(p[0])), float(D(p[1])), float(D(p[2])))
            msp.add_point(pt, dxfattribs={"layer": layer})
    # Header text in modelspace for traceability.
    g = arrangement["geometry"]
    ox, oy, _ = [float(D(v)) for v in g.get("origin_m", [0, 0, 0])]
    W = float(D(g["width_m"]))
    text = msp.add_text(
        f"STARK PRELIMINAR | {arrangement['project_id']} {arrangement['version']} | Operador: Bolanho | Validacao tecnica: Regis",
        dxfattribs={"height": max(0.2, min(float(D(g["length_m"])), W) / 50.0), "layer": "STARK-SPDA-TEXTOS"},
    )
    text.dxf.insert = (ox, oy + W + 1.0, 0.0)
    msp.add_text(
        "NAO LIBERADO PARA EXECUCAO — AGUARDANDO VALIDACAO DO ENGENHEIRO",
        dxfattribs={"height": max(0.2, min(float(D(g["length_m"])), W) / 55.0), "layer": "STARK-SPDA-PENDENCIAS"},
    ).dxf.insert = (ox, oy - 1.0, 0.0)
    doc.header["$INSUNITS"] = 6  # meters
    doc.saveas(path)
    return path


def build_handoff(arrangement: dict, audit: dict, files: list[str] | None = None) -> dict:
    if audit.get("status") != "PASS_INTERNAL_GEOMETRY_AUDIT_AWAITING_REGIS":
        status = "BLOCKED_NOT_READY_FOR_REGIS"
    else:
        status = "READY_FOR_BOLANHO_TO_SEND_TO_REGIS_FOR_VALIDATION"
    out = {
        "project_id": arrangement.get("project_id"),
        "version": arrangement.get("version"),
        "status": status,
        "prepared_by": "Bolanho",
        "technical_validator": "Régis",
        "engineering_status": "PRELIMINARY_NOT_RELEASED_FOR_EXECUTION",
        "arrangement_digest": arrangement.get("arrangement_digest"),
        "audit_digest": audit.get("audit_digest"),
        "files": files or [],
        "required_regis_actions": [
            "CONFIRM_GEOMETRY_AND_INPUTS",
            "CONFIRM_PROTECTION_CLASS_LEVEL_AND_NORMATIVE_POLICY",
            "REVIEW_MESH_AND_DOWN_CONDUCTOR_ARRANGEMENT",
            "APPROVE_REQUEST_CHANGES_OR_REJECT",
        ],
    }
    out["handoff_digest"] = digest(out)
    return out


def production_gate(data: dict) -> dict:
    blockers = []
    try:
        validate_workflow(data.get("workflow", {}))
    except GeometryValidationError as e:
        blockers.append(str(e))

    g = data.get("geometry", {})
    if g.get("type") != "RECTANGULAR_PRISM":
        blockers.append("GEOMETRY_TYPE_NOT_SUPPORTED_V0_1")
    for key in ("length_m", "width_m", "height_m"):
        try:
            if g.get(key) is None or D(g.get(key)) <= 0:
                blockers.append(f"INVALID_{key.upper()}")
        except Exception:
            blockers.append(f"INVALID_{key.upper()}")

    p = data.get("protection_context", {}).get("policy")
    if not p:
        blockers.append("VALIDATED_GEOMETRY_POLICY_REQUIRED")
    else:
        if p.get("validated") is not True:
            blockers.append("GEOMETRY_POLICY_NOT_VALIDATED")
        if p.get("source_type") == "SYNTHETIC_TEST_ONLY":
            blockers.append("SYNTHETIC_POLICY_FORBIDDEN_FOR_PRODUCTION")
        if p.get("source_type") != "SYNTHETIC_TEST_ONLY":
            if not p.get("source_ref") or not p.get("approval_digest"):
                blockers.append("NORMATIVE_POLICY_PROVENANCE_REQUIRED")
        for key in ("max_mesh_x_m", "max_mesh_y_m", "max_down_spacing_m"):
            try:
                if p.get(key) is None or D(p.get(key)) <= 0:
                    blockers.append(f"INVALID_POLICY_{key.upper()}")
            except Exception:
                blockers.append(f"INVALID_POLICY_{key.upper()}")

    out = {
        "geometry_core_version": "0.1.0",
        "status": "PASS_READY_FOR_PRELIMINARY_ARRANGEMENT" if not blockers else "BLOCKED",
        "blockers": sorted(set(blockers)),
        "note": "PASS only authorizes preliminary arrangement generation; Regis validation remains mandatory.",
    }
    out["gate_digest"] = digest(out)
    return out
