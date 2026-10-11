from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from decimal import Decimal, getcontext
from hashlib import sha256
from pathlib import Path
import json
import math
import re
from collections import defaultdict

getcontext().prec = 28

try:
    import ezdxf
    from ezdxf.addons import odafc
except Exception:  # pragma: no cover
    ezdxf = None
    odafc = None

try:
    from shapely.geometry import Polygon, Point
except Exception:  # pragma: no cover
    Polygon = None
    Point = None

from stark_geometry import GeometryValidationError, D, digest, default_workflow, validate_workflow
from stark_geometry_3d import (
    build_rolling_sphere_arrangement,
    audit_rolling_sphere_arrangement,
    export_3d_dxf,
    build_3d_handoff,
)

CORE_VERSION = "0.3.0"
EPS = Decimal("0.000001")


class CadReconstructionError(GeometryValidationError):
    pass


def _fmt(v: Decimal) -> str:
    s = format(D(v).normalize(), "f")
    return "0" if s == "-0" else s


def _file_sha256(path: Path) -> str:
    h = sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


# Common AutoCAD INSUNITS values converted to meters.
_INSUNITS_TO_M = {
    1: Decimal("0.0254"),      # inches
    2: Decimal("0.3048"),      # feet
    4: Decimal("0.001"),       # millimeters
    5: Decimal("0.01"),        # centimeters
    6: Decimal("1"),           # meters
    7: Decimal("1000"),        # kilometers
}


def unit_factor_to_m(insunits: int, *, explicit_override: str | None = None) -> tuple[Decimal, str]:
    if explicit_override:
        key = explicit_override.strip().lower()
        mapping = {
            "mm": (Decimal("0.001"), "EXPLICIT_MM"),
            "cm": (Decimal("0.01"), "EXPLICIT_CM"),
            "m": (Decimal("1"), "EXPLICIT_M"),
            "in": (Decimal("0.0254"), "EXPLICIT_IN"),
            "ft": (Decimal("0.3048"), "EXPLICIT_FT"),
        }
        if key not in mapping:
            raise CadReconstructionError("UNSUPPORTED_EXPLICIT_CAD_UNIT")
        return mapping[key]
    if insunits in _INSUNITS_TO_M:
        return _INSUNITS_TO_M[insunits], f"INSUNITS_{insunits}"
    raise CadReconstructionError("CAD_UNITS_UNRESOLVED")


def _convert_xy(p, factor: Decimal) -> tuple[Decimal, Decimal]:
    return D(p[0]) * factor, D(p[1]) * factor


def _convert_xyz(p, factor: Decimal) -> tuple[Decimal, Decimal, Decimal]:
    return D(p[0]) * factor, D(p[1]) * factor, D(p[2]) * factor


def _layer_allowed(layer: str, config: dict) -> bool:
    ignore = set(config.get("ignore_layers", []))
    if layer in ignore:
        return False
    exact = config.get("outline_layers")
    if exact:
        return layer in set(exact)
    pats = config.get("outline_layer_patterns") or []
    if pats:
        return any(re.search(p, layer, flags=re.I) for p in pats)
    # Safe-ish fallback for reconstruction preview: all geometry layers except obvious annotation layers.
    if re.search(r"TEXT|ANOT|COTA|DIM|HATCH", layer, re.I):
        return False
    return True


def _text_layer_allowed(layer: str, config: dict) -> bool:
    exact = config.get("annotation_layers")
    if exact:
        return layer in set(exact)
    pats = config.get("annotation_layer_patterns") or []
    if pats:
        return any(re.search(p, layer, flags=re.I) for p in pats)
    return True


def _clean_vertices(points: list[tuple[Decimal, Decimal]]) -> list[tuple[Decimal, Decimal]]:
    out = []
    for p in points:
        if not out or abs(p[0] - out[-1][0]) > EPS or abs(p[1] - out[-1][1]) > EPS:
            out.append(p)
    if len(out) >= 2 and abs(out[0][0] - out[-1][0]) <= EPS and abs(out[0][1] - out[-1][1]) <= EPS:
        out.pop()
    return out


def _polygon_payload(points: list[tuple[Decimal, Decimal]], source: dict) -> dict | None:
    if Polygon is None:
        raise CadReconstructionError("SHAPELY_NOT_AVAILABLE")
    pts = _clean_vertices(points)
    if len(pts) < 3:
        return None
    poly = Polygon([(float(x), float(y)) for x, y in pts])
    if poly.is_empty or poly.area <= 0:
        return None
    if not poly.is_valid:
        repaired = poly.buffer(0)
        if repaired.is_empty or repaired.geom_type != "Polygon":
            return {
                "source": source,
                "vertices_m": [[_fmt(x), _fmt(y)] for x, y in pts],
                "valid": False,
                "issue": "INVALID_POLYGON",
            }
        poly = repaired
        pts = [(D(x), D(y)) for x, y in list(poly.exterior.coords)[:-1]]
    minx, miny, maxx, maxy = poly.bounds
    bbox_area = max(0.0, (maxx - minx) * (maxy - miny))
    unique = pts
    axis_aligned = True
    if len(unique) != 4:
        axis_aligned = False
    else:
        for i, a in enumerate(unique):
            b = unique[(i + 1) % len(unique)]
            dx = abs(b[0] - a[0]); dy = abs(b[1] - a[1])
            if dx > EPS and dy > EPS:
                axis_aligned = False
                break
    is_rect = axis_aligned and bbox_area > 0 and abs(poly.area - bbox_area) <= max(1e-9, bbox_area * 1e-9)
    return {
        "source": source,
        "vertices_m": [[_fmt(x), _fmt(y)] for x, y in pts],
        "area_m2": _fmt(D(str(poly.area))),
        "bbox_m": [_fmt(D(str(minx))), _fmt(D(str(miny))), _fmt(D(str(maxx))), _fmt(D(str(maxy)))],
        "valid": True,
        "axis_aligned_rectangle": bool(is_rect),
        "_shape": poly,
    }


def _entity_lines_and_polylines(doc, factor: Decimal, config: dict) -> tuple[list[dict], list[dict], list[dict]]:
    closed = []
    lines = []
    ignored = []
    msp = doc.modelspace()
    for idx, e in enumerate(msp, 1):
        typ = e.dxftype()
        layer = getattr(e.dxf, "layer", "0") or "0"
        if not _layer_allowed(layer, config):
            continue
        source = {"entity_type": typ, "handle": getattr(e.dxf, "handle", None), "layer": layer, "entity_index": idx}
        try:
            if typ == "LWPOLYLINE":
                elev = D(getattr(e.dxf, "elevation", 0) or 0) * factor
                source["entity_elevation_m"] = _fmt(elev)
                pts = [_convert_xy((p[0], p[1]), factor) for p in e.get_points("xy")]
                if bool(e.closed):
                    rec = _polygon_payload(pts, source)
                    if rec: closed.append(rec)
                else:
                    ignored.append({**source, "reason": "OPEN_LWPOLYLINE"})
            elif typ == "POLYLINE":
                pts = []; zs=[]
                for v in e.vertices:
                    loc = v.dxf.location
                    pts.append(_convert_xy((loc.x, loc.y), factor)); zs.append(D(loc.z)*factor)
                if zs and all(abs(z-zs[0]) <= EPS for z in zs): source["entity_elevation_m"]=_fmt(zs[0])
                if bool(e.is_closed):
                    rec = _polygon_payload(pts, source)
                    if rec: closed.append(rec)
                else:
                    ignored.append({**source, "reason": "OPEN_POLYLINE"})
            elif typ == "LINE":
                a = _convert_xy(e.dxf.start, factor)
                b = _convert_xy(e.dxf.end, factor)
                za=D(e.dxf.start.z)*factor; zb=D(e.dxf.end.z)*factor
                if abs(za-zb)<=EPS: source["entity_elevation_m"]=_fmt(za)
                lines.append({"a": a, "b": b, "source": source})
            else:
                ignored.append({**source, "reason": "UNSUPPORTED_ENTITY_ON_OUTLINE_LAYER"})
        except Exception as exc:
            ignored.append({**source, "reason": "ENTITY_PARSE_ERROR", "detail": str(exc)})
    return closed, lines, ignored


def _node_key(p: tuple[Decimal, Decimal], tol: Decimal) -> tuple[int, int]:
    return (int((p[0] / tol).to_integral_value()), int((p[1] / tol).to_integral_value()))


def _closed_polygons_from_lines(lines: list[dict], tol: Decimal) -> tuple[list[dict], list[dict]]:
    # Reconstruct only simple closed line chains. Ambiguous junctions are not guessed.
    by_layer = defaultdict(list)
    for ln in lines:
        by_layer[ln["source"]["layer"]].append(ln)
    polygons = []
    issues = []
    for layer, group in by_layer.items():
        node_edges = defaultdict(list)
        node_coord = {}
        for i, ln in enumerate(group):
            ka = _node_key(ln["a"], tol); kb = _node_key(ln["b"], tol)
            node_coord.setdefault(ka, ln["a"]); node_coord.setdefault(kb, ln["b"])
            node_edges[ka].append((i, kb)); node_edges[kb].append((i, ka))
        used = set()
        # Components with degree != 2 are ambiguous/open and not reconstructed automatically.
        seen_nodes = set()
        for start in list(node_edges):
            if start in seen_nodes:
                continue
            stack = [start]; comp_nodes = set(); comp_edges = set()
            while stack:
                n = stack.pop()
                if n in comp_nodes: continue
                comp_nodes.add(n); seen_nodes.add(n)
                for ei, nb in node_edges[n]:
                    comp_edges.add(ei)
                    if nb not in comp_nodes: stack.append(nb)
            if any(len(node_edges[n]) != 2 for n in comp_nodes):
                issues.append({"layer": layer, "reason": "LINE_CHAIN_NOT_SIMPLE_CLOSED_LOOP", "edge_count": len(comp_edges)})
                continue
            # Traverse cycle.
            cur = min(comp_nodes); prev_edge = None; verts = []
            for _ in range(len(comp_edges) + 2):
                verts.append(node_coord[cur])
                choices = [(ei, nb) for ei, nb in node_edges[cur] if ei != prev_edge]
                if not choices: break
                ei, nb = choices[0]
                used.add(ei); prev_edge = ei; cur = nb
                if cur == min(comp_nodes):
                    break
            if cur != min(comp_nodes) or len(verts) < 3:
                issues.append({"layer": layer, "reason": "LINE_CHAIN_TRAVERSAL_FAILED", "edge_count": len(comp_edges)})
                continue
            rec = _polygon_payload(verts, {"entity_type": "LINE_LOOP", "handle": None, "layer": layer, "entity_index": None})
            if rec:
                polygons.append(rec)
    return polygons, issues


_HEIGHT_RE = re.compile(r"(?:^|\b)(?:H|ALTURA|HEIGHT)\s*[:=]\s*([0-9]+(?:[\.,][0-9]+)?)\s*(MM|CM|M)?\b", re.I)
_TOP_RE = re.compile(r"(?:^|\b)(?:TOP|TOPO|ZTOP|COTA\s*TOPO)\s*[:=]\s*([0-9]+(?:[\.,][0-9]+)?)\s*(MM|CM|M)?\b", re.I)
_BASE_RE = re.compile(r"(?:^|\b)(?:BASE|ZBASE|COTA\s*BASE)\s*[:=]\s*([0-9]+(?:[\.,][0-9]+)?)\s*(MM|CM|M)?\b", re.I)


def _annotation_value(raw: str, unit: str | None, cad_factor: Decimal) -> Decimal:
    v = D(raw.replace(",", "."))
    if unit:
        u = unit.upper()
        return v * {"MM": Decimal("0.001"), "CM": Decimal("0.01"), "M": Decimal("1")}[u]
    return v * cad_factor


def _extract_annotations(doc, factor: Decimal, config: dict) -> list[dict]:
    out = []
    for idx, e in enumerate(doc.modelspace(), 1):
        typ = e.dxftype(); layer = getattr(e.dxf, "layer", "0") or "0"
        if typ not in {"TEXT", "MTEXT"} or not _text_layer_allowed(layer, config):
            continue
        try:
            text = e.dxf.text if typ == "TEXT" else e.plain_text()
            ins = e.dxf.insert
            x, y = _convert_xy((ins.x, ins.y), factor)
        except Exception:
            continue
        vals = []
        for kind, rx in (("LOCAL_HEIGHT", _HEIGHT_RE), ("TOP_ELEVATION", _TOP_RE), ("BASE_ELEVATION", _BASE_RE)):
            for m in rx.finditer(text or ""):
                vals.append({"kind": kind, "value_m": _fmt(_annotation_value(m.group(1), m.group(2), factor)), "matched": m.group(0)})
        if vals:
            out.append({
                "entity_type": typ, "handle": getattr(e.dxf, "handle", None), "layer": layer, "entity_index": idx,
                "text": text, "point_m": [_fmt(x), _fmt(y)], "values": vals,
            })
    return out


def _attach_annotations(polys: list[dict], annotations: list[dict], config: dict) -> None:
    if Point is None:
        raise CadReconstructionError("SHAPELY_NOT_AVAILABLE")
    buffer_m = float(D(config.get("annotation_capture_buffer_m", "0.05")))
    for p in polys:
        p["annotations"] = []
    for ann in annotations:
        pt = Point(float(D(ann["point_m"][0])), float(D(ann["point_m"][1])))
        candidates = []
        for i, p in enumerate(polys):
            if not p.get("valid"): continue
            shape = p["_shape"]
            if shape.buffer(buffer_m).covers(pt):
                candidates.append((shape.area, i))
        if candidates:
            _, i = min(candidates)
            polys[i]["annotations"].append(ann)


def _unique_decimal(values: list[Decimal], tol: Decimal = Decimal("0.000001")) -> list[Decimal]:
    out = []
    for v in values:
        if not any(abs(v - x) <= tol for x in out): out.append(v)
    return out


def _concept_values(poly: dict, kind: str) -> list[Decimal]:
    vals = []
    for ann in poly.get("annotations", []):
        for v in ann.get("values", []):
            if v["kind"] == kind:
                vals.append(D(v["value_m"]))
    return _unique_decimal(vals)


def _find_parent_indices(polys: list[dict]) -> dict[int, int | None]:
    parents = {}
    for i, p in enumerate(polys):
        if not p.get("valid"): parents[i] = None; continue
        candidates = []
        shape = p["_shape"]
        for j, q in enumerate(polys):
            if i == j or not q.get("valid"): continue
            qshape = q["_shape"]
            # require q to contain p with meaningful area difference
            if qshape.area > shape.area * (1 + 1e-9) and qshape.covers(shape):
                candidates.append((qshape.area, j))
        parents[i] = min(candidates)[1] if candidates else None
    return parents


def _layer_rule(layer: str, config: dict) -> dict:
    rules = config.get("layer_height_rules") or {}
    return deepcopy(rules.get(layer, {}))


def _resolve_volume_heights(polys: list[dict], config: dict) -> list[dict]:
    parents = _find_parent_indices(polys)
    result = []
    resolved_top = {}
    unresolved = set(range(len(polys)))
    default_base = D(config.get("default_base_elevation_m", "0"))
    semantics = config.get("height_semantics", "LOCAL_HEIGHT").upper()
    nested_mode = config.get("nested_footprints_mode", "STACKED_IF_ANNOTATED").upper()

    # Iterate until no more can resolve (parent-first).
    progress = True
    while unresolved and progress:
        progress = False
        for i in list(unresolved):
            p = polys[i]
            parent = parents[i]
            if parent is not None and parent not in resolved_top:
                continue
            layer = p["source"]["layer"]
            rule = _layer_rule(layer, config)
            hvals = _concept_values(p, "LOCAL_HEIGHT")
            tvals = _concept_values(p, "TOP_ELEVATION")
            bvals = _concept_values(p, "BASE_ELEVATION")
            issues = []
            if len(hvals) > 1: issues.append("CONFLICTING_HEIGHT_ANNOTATIONS")
            if len(tvals) > 1: issues.append("CONFLICTING_TOP_ANNOTATIONS")
            if len(bvals) > 1: issues.append("CONFLICTING_BASE_ANNOTATIONS")

            explicit_base = bvals[0] if len(bvals) == 1 else (D(rule["base_m"]) if rule.get("base_m") is not None else None)
            if explicit_base is not None:
                base = explicit_base; base_source = "ANNOTATION_OR_LAYER_RULE"
            elif parent is None:
                base = default_base; base_source = "DEFAULT_BASE"
            else:
                base = resolved_top[parent]; base_source = f"PARENT_TOP:{parent}"

            local_h = hvals[0] if len(hvals) == 1 else (D(rule["height_m"]) if rule.get("height_m") is not None else None)
            top = tvals[0] if len(tvals) == 1 else (D(rule["top_m"]) if rule.get("top_m") is not None else None)
            if top is None and str(config.get("cad_z_semantics", "IGNORE")).upper() == "TOP_ELEVATION":
                ez = p.get("source", {}).get("entity_elevation_m")
                if ez is not None and D(ez) != 0:
                    top = D(ez)

            if parent is not None and nested_mode == "STACKED_IF_ANNOTATED" and local_h is None and top is None and explicit_base is None:
                issues.append("NESTED_FOOTPRINT_WITHOUT_OWN_ELEVATION")

            if top is not None and local_h is not None:
                expected = base + local_h
                if abs(expected - top) > D(config.get("elevation_conflict_tolerance_m", "0.01")):
                    issues.append("HEIGHT_TOP_CONFLICT")
            if top is None and local_h is not None:
                top = base + local_h
            elif top is not None and local_h is None:
                local_h = top - base
            elif top is None and local_h is None:
                # If configured globally as absolute top but only a generic H annotation should have been parsed as height,
                # keep unresolved instead of guessing.
                issues.append("HEIGHT_UNRESOLVED")

            if local_h is not None and local_h <= 0:
                issues.append("NONPOSITIVE_VOLUME_HEIGHT")
            if top is not None and top <= base:
                issues.append("TOP_NOT_ABOVE_BASE")

            rec = {
                "candidate_index": i,
                "source": deepcopy(p["source"]),
                "vertices_m": deepcopy(p["vertices_m"]),
                "bbox_m": deepcopy(p.get("bbox_m")),
                "area_m2": p.get("area_m2"),
                "axis_aligned_rectangle": p.get("axis_aligned_rectangle", False),
                "parent_candidate_index": parent,
                "base_elevation_m": _fmt(base) if base is not None else None,
                "top_elevation_m": _fmt(top) if top is not None else None,
                "height_m": _fmt(local_h) if local_h is not None else None,
                "base_source": base_source,
                "height_sources": [a for a in p.get("annotations", [])],
                "layer_rule": rule,
                "issues": sorted(set(issues)),
            }
            result.append(rec)
            if top is not None:
                resolved_top[i] = top
            unresolved.remove(i); progress = True
    # Any cycles / impossible parent chains.
    for i in unresolved:
        p = polys[i]
        result.append({
            "candidate_index": i, "source": deepcopy(p["source"]), "vertices_m": deepcopy(p["vertices_m"]),
            "bbox_m": deepcopy(p.get("bbox_m")), "area_m2": p.get("area_m2"),
            "axis_aligned_rectangle": p.get("axis_aligned_rectangle", False), "parent_candidate_index": parents[i],
            "base_elevation_m": None, "top_elevation_m": None, "height_m": None,
            "base_source": None, "height_sources": deepcopy(p.get("annotations", [])), "layer_rule": _layer_rule(p["source"]["layer"], config),
            "issues": ["CONTAINMENT_RESOLUTION_FAILED"],
        })
    result.sort(key=lambda x: x["candidate_index"])
    return result


def _detect_overlap_issues(polys: list[dict]) -> list[dict]:
    issues = []
    for i in range(len(polys)):
        a = polys[i]
        if not a.get("valid"): continue
        for j in range(i + 1, len(polys)):
            b = polys[j]
            if not b.get("valid"): continue
            sa, sb = a["_shape"], b["_shape"]
            inter = sa.intersection(sb)
            if inter.is_empty or inter.area <= 1e-9:
                continue
            if sa.covers(sb) or sb.covers(sa):
                continue
            issues.append({"severity": "CRITICAL", "code": "OVERLAPPING_NON_NESTED_FOOTPRINTS", "candidate_a": i, "candidate_b": j, "intersection_area_m2": str(inter.area)})
    return issues


def _strip_shapes(polys: list[dict]) -> list[dict]:
    out=[]
    for p in polys:
        q={k:deepcopy(v) for k,v in p.items() if k != "_shape"}
        out.append(q)
    return out


def validate_cad_config(config: dict) -> None:
    if not isinstance(config, dict): raise CadReconstructionError("CAD_RECONSTRUCTION_CONFIG_REQUIRED")
    workflow=config.get("workflow") or default_workflow()
    validate_workflow(workflow)
    if D(config.get("line_join_tolerance_m", "0.002")) <= 0: raise CadReconstructionError("INVALID_LINE_JOIN_TOLERANCE")
    if config.get("height_semantics", "LOCAL_HEIGHT").upper() not in {"LOCAL_HEIGHT"}:
        raise CadReconstructionError("UNSUPPORTED_HEIGHT_SEMANTICS_V0_3")


def _load_dxf(path: Path, config: dict):
    if ezdxf is None: raise CadReconstructionError("EZDXF_NOT_AVAILABLE")
    ext=path.suffix.lower()
    if ext == ".dwg":
        if odafc is not None and odafc.is_installed() and config.get("allow_oda_dwg_conversion", False):
            # readfile() handles conversion via ODA in this path.
            return odafc.readfile(str(path)), "DWG_VIA_ODA"
        raise CadReconstructionError("DWG_CONVERSION_REQUIRED_ODAFILECONVERTER_NOT_AVAILABLE")
    if ext != ".dxf": raise CadReconstructionError("UNSUPPORTED_CAD_FORMAT")
    try:
        return ezdxf.readfile(path), "DXF_NATIVE"
    except Exception as exc:
        raise CadReconstructionError(f"DXF_READ_FAILED:{exc}") from exc


def reconstruct_building_from_cad(path: str | Path, config: dict) -> dict:
    validate_cad_config(config)
    path=Path(path)
    if not path.exists(): raise CadReconstructionError("CAD_SOURCE_NOT_FOUND")
    doc, reader_mode = _load_dxf(path, config)
    insunits=int(doc.header.get("$INSUNITS", 0) or 0)
    factor, unit_source = unit_factor_to_m(insunits, explicit_override=config.get("cad_unit_override"))
    closed, lines, ignored = _entity_lines_and_polylines(doc, factor, config)
    line_polys, line_issues = _closed_polygons_from_lines(lines, D(config.get("line_join_tolerance_m", "0.002")))
    polys = closed + line_polys
    # dedupe exact/same polygons by normalized WKT-ish rounded coordinate set / symmetric area equality.
    dedup=[]; duplicate_issues=[]
    for p in polys:
        if not p.get("valid"):
            dedup.append(p); continue
        found=None
        for q in dedup:
            if q.get("valid") and p["_shape"].equals_exact(q["_shape"], float(D(config.get("line_join_tolerance_m", "0.002")))):
                found=q; break
        if found:
            duplicate_issues.append({"severity":"MEDIUM","code":"DUPLICATE_FOOTPRINT_GEOMETRY","source":p["source"],"same_as":found["source"]})
        else: dedup.append(p)
    polys=dedup
    annotations=_extract_annotations(doc,factor,config)
    _attach_annotations(polys,annotations,config)
    candidates=_resolve_volume_heights(polys,config)
    overlap_issues=_detect_overlap_issues(polys)

    supported=[]; unsupported=[]; unresolved=[]
    for i,c in enumerate(candidates,1):
        cid=f"VOL-CAD-{i:03d}"
        c["volume_id"]=cid
        if c["issues"]:
            unresolved.append(cid)
        if c.get("axis_aligned_rectangle") and c.get("height_m") is not None and c.get("base_elevation_m") is not None and not any(x in c["issues"] for x in ["HEIGHT_UNRESOLVED","CONFLICTING_HEIGHT_ANNOTATIONS","CONFLICTING_TOP_ANNOTATIONS","CONFLICTING_BASE_ANNOTATIONS","HEIGHT_TOP_CONFLICT","NONPOSITIVE_VOLUME_HEIGHT","TOP_NOT_ABOVE_BASE","CONTAINMENT_RESOLUTION_FAILED"]):
            minx,miny,maxx,maxy=[D(x) for x in c["bbox_m"]]
            supported.append({
                "id":cid,
                "origin_m":[_fmt(minx),_fmt(miny),c["base_elevation_m"]],
                "dimensions_m":{"length":_fmt(maxx-minx),"width":_fmt(maxy-miny),"height":c["height_m"]},
                "source_candidate_index":c["candidate_index"],
                "source_layer":c["source"]["layer"],
            })
        else:
            unsupported.append({"volume_id":cid,"reason":"NON_RECTANGULAR_OR_UNRESOLVED","issues":c["issues"],"axis_aligned_rectangle":c.get("axis_aligned_rectangle")})

    issue_list=[]
    issue_list.extend(line_issues)
    issue_list.extend(duplicate_issues)
    issue_list.extend(overlap_issues)
    if config.get("block_unsupported_entities_on_outline_layers", True):
        unsupported_entities=[e for e in ignored if e.get("reason")=="UNSUPPORTED_ENTITY_ON_OUTLINE_LAYER"]
        for e in unsupported_entities:
            issue_list.append({"severity":"CRITICAL","code":"UNSUPPORTED_CAD_ENTITY_ON_OUTLINE_LAYER","entity_type":e.get("entity_type"),"layer":e.get("layer"),"handle":e.get("handle")})
    for c in candidates:
        for code in c["issues"]:
            sev="CRITICAL" if code in {"HEIGHT_UNRESOLVED","CONFLICTING_HEIGHT_ANNOTATIONS","CONFLICTING_TOP_ANNOTATIONS","CONFLICTING_BASE_ANNOTATIONS","HEIGHT_TOP_CONFLICT","NONPOSITIVE_VOLUME_HEIGHT","TOP_NOT_ABOVE_BASE","CONTAINMENT_RESOLUTION_FAILED"} else "HIGH"
            issue_list.append({"severity":sev,"code":code,"volume_id":c["volume_id"]})
        if not c.get("axis_aligned_rectangle"):
            issue_list.append({"severity":"HIGH","code":"FOOTPRINT_NOT_SUPPORTED_BY_3D_V0_2_ENGINE","volume_id":c["volume_id"]})
    if not candidates:
        issue_list.append({"severity":"CRITICAL","code":"NO_CLOSED_FOOTPRINTS_FOUND"})
    if not supported:
        issue_list.append({"severity":"CRITICAL","code":"NO_SUPPORTED_3D_VOLUMES_RECONSTRUCTED"})
    if config.get("require_all_candidates_supported", True) and unsupported:
        issue_list.append({"severity":"CRITICAL","code":"UNSUPPORTED_CANDIDATES_PRESENT","count":len(unsupported)})

    rec={
        "geometry_core_version":CORE_VERSION,
        "project_id":config.get("project_id","STK-SPDA-UNASSIGNED"),
        "version":config.get("version","V01"),
        "workflow":config.get("workflow") or default_workflow(),
        "source":{
            "path_name":path.name,"extension":path.suffix.lower(),"sha256":_file_sha256(path),"reader_mode":reader_mode,
            "dxf_version":getattr(doc,"dxfversion",None),"insunits":insunits,"unit_factor_to_m":_fmt(factor),"unit_source":unit_source,
        },
        "config_digest":digest(config),
        "entity_inventory":{
            "closed_polylines":len(closed),"line_entities":len(lines),"line_loops_reconstructed":len(line_polys),"annotations":len(annotations),"ignored_entities":len(ignored),
        },
        "footprints":_strip_shapes(polys),
        "annotations":annotations,
        "volume_candidates":candidates,
        "geometry_3d":{"type":"MULTI_RECTANGULAR_PRISMS","volumes":supported},
        "unsupported_candidates":unsupported,
        "ignored_entities":ignored,
        "issues":issue_list,
        "status":"RECONSTRUCTION_COMPLETED",
        "prepared_by":"Bolanho","technical_validator":"Régis",
    }
    rec["reconstruction_digest"]=digest(rec)
    return rec


def audit_cad_reconstruction(rec: dict) -> dict:
    issues=deepcopy(rec.get("issues",[]))
    if rec.get("prepared_by")!="Bolanho": issues.append({"severity":"CRITICAL","code":"INVALID_OPERATOR"})
    if rec.get("technical_validator")!="Régis": issues.append({"severity":"CRITICAL","code":"INVALID_TECHNICAL_VALIDATOR"})
    tmp=deepcopy(rec); expected=tmp.pop("reconstruction_digest",None); computed=digest(tmp)
    if expected != computed: issues.append({"severity":"CRITICAL","code":"RECONSTRUCTION_DIGEST_MISMATCH"})
    if len(rec.get("geometry_3d",{}).get("volumes",[])) == 0: issues.append({"severity":"CRITICAL","code":"NO_VOLUMES_READY_FOR_ENGINE"})
    critical=[i for i in issues if i.get("severity")=="CRITICAL"]
    high=[i for i in issues if i.get("severity")=="HIGH"]
    status="PASS_INTERNAL_CAD_RECONSTRUCTION_READY_FOR_GEOMETRY_ENGINE" if not critical else "BLOCKED_CAD_RECONSTRUCTION"
    out={
        "geometry_core_version":CORE_VERSION,"project_id":rec.get("project_id"),"version":rec.get("version"),
        "reconstruction_digest":rec.get("reconstruction_digest"),"status":status,
        "checks":{
            "source_hashed":bool(rec.get("source",{}).get("sha256")),
            "units_resolved":bool(rec.get("source",{}).get("unit_source")),
            "candidate_count":len(rec.get("volume_candidates",[])),
            "ready_volume_count":len(rec.get("geometry_3d",{}).get("volumes",[])),
            "unsupported_candidate_count":len(rec.get("unsupported_candidates",[])),
            "critical_issue_count":len(critical),"high_issue_count":len(high),
        },
        "issues":issues,
    }
    out["audit_digest"]=digest(out)
    return out


def build_geometry_engine_input(rec: dict, audit: dict, protection_context: dict, *, explicit_air_terminals: list | None = None) -> dict:
    if audit.get("status") != "PASS_INTERNAL_CAD_RECONSTRUCTION_READY_FOR_GEOMETRY_ENGINE":
        raise CadReconstructionError("GEOMETRY_ENGINE_INPUT_REQUIRES_PASSED_CAD_RECONSTRUCTION")
    return {
        "project_id":rec.get("project_id"),"version":rec.get("version"),"workflow":deepcopy(rec.get("workflow")),
        "geometry_3d":deepcopy(rec["geometry_3d"]),"protection_context":deepcopy(protection_context),
        "explicit_air_terminals":deepcopy(explicit_air_terminals or []),
        "cad_reconstruction_ref":{
            "source_sha256":rec["source"]["sha256"],"reconstruction_digest":rec["reconstruction_digest"],"audit_digest":audit["audit_digest"]
        }
    }


def run_cad_to_rolling_sphere(path: str | Path, config: dict, protection_context: dict, *, allow_test_policy: bool=False, explicit_air_terminals: list | None=None) -> dict:
    rec=reconstruct_building_from_cad(path,config)
    cad_audit=audit_cad_reconstruction(rec)
    if cad_audit["status"] != "PASS_INTERNAL_CAD_RECONSTRUCTION_READY_FOR_GEOMETRY_ENGINE":
        return {"reconstruction":rec,"cad_audit":cad_audit,"status":"BLOCKED_BEFORE_3D_ANALYSIS"}
    inp=build_geometry_engine_input(rec,cad_audit,protection_context,explicit_air_terminals=explicit_air_terminals)
    arrangement=build_rolling_sphere_arrangement(inp,allow_test_policy=allow_test_policy)
    geom_audit=audit_rolling_sphere_arrangement(arrangement)
    return {"reconstruction":rec,"cad_audit":cad_audit,"geometry_input":inp,"arrangement":arrangement,"geometry_audit":geom_audit,"status":"CAD_TO_3D_PIPELINE_COMPLETED"}


def export_reconstruction_dxf(rec: dict, audit: dict, path: str | Path) -> Path:
    if ezdxf is None: raise CadReconstructionError("EZDXF_NOT_AVAILABLE")
    if audit.get("status") != "PASS_INTERNAL_CAD_RECONSTRUCTION_READY_FOR_GEOMETRY_ENGINE":
        raise CadReconstructionError("RECONSTRUCTION_DXF_REQUIRES_PASSED_AUDIT")
    path=Path(path); doc=ezdxf.new("R2018"); doc.header["$INSUNITS"]=6
    for layer in ["STARK-CAD-FOOTPRINT","STARK-CAD-VOLUME","STARK-CAD-TEXT","STARK-CAD-PENDING"]:
        if layer not in doc.layers: doc.layers.add(layer)
    msp=doc.modelspace()
    for v in rec["geometry_3d"]["volumes"]:
        ox,oy,oz=[float(D(x)) for x in v["origin_m"]]
        L=float(D(v["dimensions_m"]["length"])); W=float(D(v["dimensions_m"]["width"])); H=float(D(v["dimensions_m"]["height"])); z1=oz+H
        bot=[(ox,oy,oz),(ox+L,oy,oz),(ox+L,oy+W,oz),(ox,oy+W,oz),(ox,oy,oz)]
        top=[(x,y,z1) for x,y,_ in bot]
        msp.add_polyline3d(bot,dxfattribs={"layer":"STARK-CAD-VOLUME"}); msp.add_polyline3d(top,dxfattribs={"layer":"STARK-CAD-VOLUME"})
        for a,b in zip(bot[:4],top[:4]): msp.add_line(a,b,dxfattribs={"layer":"STARK-CAD-VOLUME"})
        txt=msp.add_text(f"{v['id']} H={H:g}m",dxfattribs={"height":0.25,"layer":"STARK-CAD-TEXT"}); txt.dxf.insert=(ox,oy,z1)
    txt=msp.add_text(f"STARK CAD RECONSTRUCTION 0.3 | {rec['project_id']} {rec['version']} | BOLANHO -> REGIS",dxfattribs={"height":0.3,"layer":"STARK-CAD-TEXT"}); txt.dxf.insert=(0,0,0)
    doc.saveas(path); return path


def build_cad_handoff(rec: dict, cad_audit: dict, geom_bundle: dict | None=None, files: list[str] | None=None) -> dict:
    ready=cad_audit.get("status")=="PASS_INTERNAL_CAD_RECONSTRUCTION_READY_FOR_GEOMETRY_ENGINE"
    geom_status=None
    if geom_bundle and geom_bundle.get("geometry_audit"):
        geom_status=geom_bundle["geometry_audit"].get("status")
        ready=ready and geom_status=="PASS_INTERNAL_3D_ROLLING_SPHERE_AUDIT_AWAITING_REGIS"
    out={
        "geometry_core_version":CORE_VERSION,"project_id":rec.get("project_id"),"version":rec.get("version"),
        "prepared_by":"Bolanho","technical_validator":"Régis",
        "status":"READY_FOR_BOLANHO_TO_SEND_TO_REGIS_FOR_VALIDATION" if ready else "BLOCKED_NOT_READY_FOR_REGIS",
        "engineering_status":"PRELIMINARY_NOT_RELEASED_FOR_EXECUTION",
        "source_sha256":rec.get("source",{}).get("sha256"),"reconstruction_digest":rec.get("reconstruction_digest"),"cad_audit_digest":cad_audit.get("audit_digest"),
        "geometry_audit_status":geom_status,"files":files or [],
        "required_regis_actions":[
            "CONFIRM_RECONSTRUCTED_FOOTPRINTS_AND_VOLUMES",
            "CONFIRM_HEIGHTS_LEVELS_AND_NESTED_VOLUME_INTERPRETATION",
            "CONFIRM_NO_RELEVANT_CAD_GEOMETRY_WAS_EXCLUDED",
            "REVIEW_SPDA_ARRANGEMENT_IF_GEOMETRY_ANALYSIS_WAS_RUN",
            "APPROVE_REQUEST_CHANGES_OR_REJECT",
        ],
    }
    out["handoff_digest"]=digest(out); return out


def production_gate_cad(path: str | Path, config: dict) -> dict:
    blockers=[]
    try:
        rec=reconstruct_building_from_cad(path,config)
        aud=audit_cad_reconstruction(rec)
        if aud["status"]!="PASS_INTERNAL_CAD_RECONSTRUCTION_READY_FOR_GEOMETRY_ENGINE":
            blockers.extend(sorted(set(i.get("code","UNKNOWN") for i in aud.get("issues",[]) if i.get("severity")=="CRITICAL")))
    except CadReconstructionError as e:
        blockers.append(str(e))
    out={
        "geometry_core_version":CORE_VERSION,
        "status":"PASS_READY_FOR_PRELIMINARY_CAD_RECONSTRUCTION" if not blockers else "BLOCKED",
        "blockers":sorted(set(blockers)),
        "note":"PASS authorizes CAD reconstruction only. SPDA technical validation by Régis remains mandatory; rolling-sphere production analysis separately requires validated normative parameters.",
    }
    out["gate_digest"]=digest(out); return out
