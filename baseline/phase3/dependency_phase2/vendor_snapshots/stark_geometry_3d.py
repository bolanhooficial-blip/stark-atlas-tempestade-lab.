from __future__ import annotations

from copy import deepcopy
from decimal import Decimal, getcontext
from hashlib import sha256
from pathlib import Path
import json

from stark_geometry import GeometryValidationError, D, _fmt, digest, default_workflow, validate_workflow

getcontext().prec = 28

try:
    import ezdxf
except Exception:  # pragma: no cover
    ezdxf = None


CORE_VERSION = "0.2.0"
EPS = Decimal("0.000000001")


def _d3(p):
    if not isinstance(p, (list, tuple)) or len(p) != 3:
        raise GeometryValidationError("INVALID_3D_POINT")
    return tuple(D(v) for v in p)


def _positive(data: dict, key: str, prefix: str = "INVALID_POLICY_") -> Decimal:
    try:
        v = D(data.get(key))
    except Exception as exc:
        raise GeometryValidationError(prefix + key.upper()) from exc
    if v <= 0:
        raise GeometryValidationError(prefix + key.upper())
    return v


def validate_3d_input(data: dict, *, allow_test_policy: bool = False) -> None:
    validate_workflow(data.get("workflow", {}))
    geom = data.get("geometry_3d", {})
    if geom.get("type") != "MULTI_RECTANGULAR_PRISMS":
        raise GeometryValidationError("GEOMETRY_3D_TYPE_NOT_SUPPORTED_V0_2")
    vols = geom.get("volumes")
    if not isinstance(vols, list) or not vols:
        raise GeometryValidationError("VOLUMES_REQUIRED")
    ids = []
    for i, v in enumerate(vols, 1):
        vid = v.get("id")
        if not vid:
            raise GeometryValidationError(f"VOLUME_ID_REQUIRED_{i}")
        ids.append(vid)
        _d3(v.get("origin_m", [0, 0, 0]))
        dims = v.get("dimensions_m", {})
        for key in ("length", "width", "height"):
            try:
                val = D(dims.get(key))
            except Exception as exc:
                raise GeometryValidationError(f"INVALID_VOLUME_{vid}_{key.upper()}") from exc
            if val <= 0:
                raise GeometryValidationError(f"INVALID_VOLUME_{vid}_{key.upper()}")
    if len(ids) != len(set(ids)):
        raise GeometryValidationError("DUPLICATE_VOLUME_ID")

    pc = data.get("protection_context", {})
    policy = pc.get("rolling_sphere_policy")
    if not policy:
        raise GeometryValidationError("VALIDATED_ROLLING_SPHERE_POLICY_REQUIRED")
    if policy.get("validated") is not True:
        raise GeometryValidationError("ROLLING_SPHERE_POLICY_NOT_VALIDATED")
    if policy.get("source_type") == "SYNTHETIC_TEST_ONLY" and not allow_test_policy:
        raise GeometryValidationError("SYNTHETIC_POLICY_FORBIDDEN_FOR_PRODUCTION")
    if policy.get("source_type") != "SYNTHETIC_TEST_ONLY":
        if not policy.get("source_ref") or not policy.get("approval_digest"):
            raise GeometryValidationError("NORMATIVE_POLICY_PROVENANCE_REQUIRED")
    _positive(policy, "rolling_sphere_radius_m")
    _positive(policy, "terminal_height_m")
    _positive(policy, "surface_sample_spacing_m")
    max_auto = policy.get("max_auto_terminals", 0)
    if not isinstance(max_auto, int) or max_auto < 0:
        raise GeometryValidationError("INVALID_POLICY_MAX_AUTO_TERMINALS")
    if policy.get("height_difference_rule", "REQUIRE_DH_LE_RADIUS") not in {"REQUIRE_DH_LE_RADIUS"}:
        raise GeometryValidationError("UNSUPPORTED_HEIGHT_DIFFERENCE_RULE")

    exp = data.get("explicit_air_terminals", [])
    if exp is not None:
        if not isinstance(exp, list):
            raise GeometryValidationError("INVALID_EXPLICIT_AIR_TERMINALS")
        tids = []
        for t in exp:
            if not t.get("id"):
                raise GeometryValidationError("AIR_TERMINAL_ID_REQUIRED")
            tids.append(t["id"])
            _d3(t.get("base_point_m"))
            _positive(t, "height_m", prefix="INVALID_TERMINAL_")
        if len(tids) != len(set(tids)):
            raise GeometryValidationError("DUPLICATE_AIR_TERMINAL_ID")


def _box(v: dict):
    x0, y0, z0 = _d3(v["origin_m"])
    d = v["dimensions_m"]
    L, W, H = D(d["length"]), D(d["width"]), D(d["height"])
    return x0, y0, z0, x0+L, y0+W, z0+H


def _linspace(a: Decimal, b: Decimal, max_step: Decimal) -> list[Decimal]:
    length = b-a
    if length <= 0:
        return [a]
    n = max(1, int((length/max_step).to_integral_value(rounding="ROUND_CEILING")))
    step = length/Decimal(n)
    return [a + step*Decimal(i) for i in range(n+1)]


def _point_in_solid(p, v: dict, *, include_boundary: bool = True) -> bool:
    x,y,z = p
    x0,y0,z0,x1,y1,z1 = _box(v)
    if include_boundary:
        return x0-EPS <= x <= x1+EPS and y0-EPS <= y <= y1+EPS and z0-EPS <= z <= z1+EPS
    return x0+EPS < x < x1-EPS and y0+EPS < y < y1-EPS and z0+EPS < z < z1-EPS


def _occluded_by_other(p, owner_id: str, volumes: list[dict]) -> bool:
    # Point on/inside another solid is considered hidden when the other solid extends above it,
    # or when it is strictly inside the other solid. This removes base-roof points covered by rooftop volumes.
    x,y,z = p
    for v in volumes:
        if v["id"] == owner_id:
            continue
        x0,y0,z0,x1,y1,z1 = _box(v)
        xy = x0-EPS <= x <= x1+EPS and y0-EPS <= y <= y1+EPS
        if xy and z0-EPS <= z < z1-EPS:
            return True
        if _point_in_solid(p, v, include_boundary=False):
            return True
    return False


def sample_external_surfaces(volumes: list[dict], spacing: Decimal, *, include_sides: bool = True) -> list[dict]:
    points = {}
    def add(owner, face, p):
        if _occluded_by_other(p, owner, volumes):
            return
        key = tuple(_fmt(v) for v in p)
        rec = points.setdefault(key, {"point_m": list(key), "owners": [], "faces": []})
        if owner not in rec["owners"]: rec["owners"].append(owner)
        tag=f"{owner}:{face}"
        if tag not in rec["faces"]: rec["faces"].append(tag)

    for v in volumes:
        x0,y0,z0,x1,y1,z1 = _box(v)
        xs=_linspace(x0,x1,spacing); ys=_linspace(y0,y1,spacing); zs=_linspace(z0,z1,spacing)
        for x in xs:
            for y in ys:
                add(v["id"], "TOP", (x,y,z1))
        if include_sides:
            for y in ys:
                for z in zs:
                    add(v["id"], "XMIN", (x0,y,z)); add(v["id"], "XMAX", (x1,y,z))
            for x in xs:
                for z in zs:
                    add(v["id"], "YMIN", (x,y0,z)); add(v["id"], "YMAX", (x,y1,z))
    out=[]
    for i, rec in enumerate(sorted(points.values(), key=lambda r: tuple(D(x) for x in r["point_m"])),1):
        rec={"id":f"SMP-{i:05d}", **rec}
        out.append(rec)
    return out


def top_candidate_points(volumes: list[dict]) -> list[tuple[Decimal,Decimal,Decimal,str,str]]:
    pts=[]
    for v in volumes:
        x0,y0,z0,x1,y1,z1=_box(v)
        candidates=[
            (x0,y0,z1,"CORNER_SW"),(x1,y0,z1,"CORNER_SE"),(x1,y1,z1,"CORNER_NE"),(x0,y1,z1,"CORNER_NW"),
            ((x0+x1)/2,(y0+y1)/2,z1,"CENTER"),
        ]
        for x,y,z,label in candidates:
            if not _occluded_by_other((x,y,z),v["id"],volumes):
                pts.append((x,y,z,v["id"],label))
    # dedupe same xyz, retain first owner/label
    seen=set(); out=[]
    for item in sorted(pts, key=lambda q:(q[2],q[0],q[1],q[3],q[4]), reverse=True):
        k=tuple(_fmt(x) for x in item[:3])
        if k not in seen:
            seen.add(k); out.append(item)
    return out


def rolling_sphere_horizontal_radius(radius: Decimal, delta_h: Decimal) -> Decimal | None:
    R, dh=D(radius),D(delta_h)
    if R <= 0:
        raise GeometryValidationError("INVALID_ROLLING_SPHERE_RADIUS")
    if dh <= 0:
        return Decimal(0)
    # v0.2 deliberately limits the analytic envelope to dh <= R.
    if dh > R:
        return None
    q=Decimal(2)*R*dh-dh*dh
    if q < 0:
        return None
    return q.sqrt()


def terminal_record(tid: str, base, height: Decimal, origin: str, *, source_volume=None, source_label=None) -> dict:
    x,y,z=base; h=D(height)
    return {
        "id":tid,"type":"AIR_TERMINAL","subtype":"VERTICAL_ROD",
        "base_point_m":[_fmt(x),_fmt(y),_fmt(z)],
        "tip_point_m":[_fmt(x),_fmt(y),_fmt(z+h)],
        "height_m":_fmt(h),"layer":"STARK-SPDA-CAPTACAO",
        "status":"PROPOSED_PRELIMINARY" if origin!="EXPLICIT_INPUT" else "CONFIRMED_FROM_INPUT",
        "origin":origin,"source_volume":source_volume,"source_label":source_label,
    }


def _initial_terminals(data: dict, volumes: list[dict], policy: dict) -> list[dict]:
    out=[]
    explicit=data.get("explicit_air_terminals") or []
    for t in explicit:
        out.append(terminal_record(t["id"],_d3(t["base_point_m"]),D(t["height_m"]),"EXPLICIT_INPUT"))
    if not out and policy.get("initial_terminal_strategy","TOP_CORNERS_AND_CENTER") == "TOP_CORNERS_AND_CENTER":
        h=D(policy["terminal_height_m"])
        for i,(x,y,z,vid,label) in enumerate(top_candidate_points(volumes),1):
            out.append(terminal_record(f"CAP-{i:03d}",(x,y,z),h,"AUTO_INITIAL",source_volume=vid,source_label=label))
    return out


def assess_point(point: tuple[Decimal,Decimal,Decimal], terminals: list[dict], radius: Decimal) -> dict:
    px,py,pz=point
    best=None
    unsupported=[]
    for t in terminals:
        tx,ty,tz=(_d3(t["tip_point_m"]))
        dh=tz-pz
        pr=rolling_sphere_horizontal_radius(radius,dh)
        if pr is None:
            unsupported.append(t["id"]); continue
        if dh <= 0:
            continue
        dist=((tx-px)*(tx-px)+(ty-py)*(ty-py)).sqrt()
        margin=pr-dist
        rec={
            "terminal_id":t["id"],"delta_h_m":_fmt(dh),"horizontal_distance_m":_fmt(dist),
            "protection_radius_m":_fmt(pr),"margin_m":_fmt(margin),
        }
        if best is None or D(rec["margin_m"]) > D(best["margin_m"]): best=rec
    if best is not None and D(best["margin_m"]) >= -EPS:
        return {"status":"PROTECTED","best":best,"unsupported_terminals":unsupported}
    return {"status":"EXPOSED","best":best,"unsupported_terminals":unsupported}


def assess_samples(samples: list[dict], terminals: list[dict], radius: Decimal) -> list[dict]:
    out=[]
    for s in samples:
        p=_d3(s["point_m"])
        a=assess_point(p,terminals,radius)
        out.append({**s,"coverage":a})
    return out


def _pick_exposed_for_terminal(assessed: list[dict]) -> dict | None:
    exposed=[s for s in assessed if s["coverage"]["status"]=="EXPOSED"]
    if not exposed: return None
    # Highest first, then largest XY; deterministic.
    exposed.sort(key=lambda s:(D(s["point_m"][2]),D(s["point_m"][0]),D(s["point_m"][1])),reverse=True)
    return exposed[0]


def _surface_base_for_point(sample: dict):
    # For refinement, place rod on the exact sampled external point. For side-face points, use same XYZ.
    # This is preliminary geometry only; constructability is left to Regis validation.
    return _d3(sample["point_m"])


def build_rolling_sphere_arrangement(data: dict, *, allow_test_policy: bool = False) -> dict:
    validate_3d_input(data,allow_test_policy=allow_test_policy)
    src=deepcopy(data)
    geom=src["geometry_3d"]; vols=geom["volumes"]
    policy=src["protection_context"]["rolling_sphere_policy"]
    R=D(policy["rolling_sphere_radius_m"]); h=D(policy["terminal_height_m"]); spacing=D(policy["surface_sample_spacing_m"])
    include_sides=policy.get("surface_scope","TOP_AND_SIDES") == "TOP_AND_SIDES"
    samples=sample_external_surfaces(vols,spacing,include_sides=include_sides)
    terminals=_initial_terminals(src,vols,policy)
    if not terminals:
        raise GeometryValidationError("NO_AIR_TERMINALS_AVAILABLE")

    assessed=assess_samples(samples,terminals,R)
    added=0; max_auto=int(policy.get("max_auto_terminals",0))
    if policy.get("auto_refine_exposed_points",True):
        while any(s["coverage"]["status"]=="EXPOSED" for s in assessed) and added < max_auto:
            target=_pick_exposed_for_terminal(assessed)
            if target is None: break
            base=_surface_base_for_point(target)
            tid=f"CAP-AUTO-{added+1:03d}"
            terminals.append(terminal_record(tid,base,h,"AUTO_REFINEMENT",source_volume="/".join(target["owners"]),source_label="EXPOSED_SAMPLE"))
            added += 1
            assessed=assess_samples(samples,terminals,R)

    protected=sum(1 for s in assessed if s["coverage"]["status"]=="PROTECTED")
    exposed=len(assessed)-protected
    unsupported=sum(1 for s in assessed if s["coverage"].get("unsupported_terminals"))

    objects=[]
    for v in vols:
        x0,y0,z0,x1,y1,z1=_box(v)
        objects.append({
            "id":v["id"],"type":"VOLUME","subtype":"AXIS_ALIGNED_RECTANGULAR_PRISM",
            "origin_m":[_fmt(x0),_fmt(y0),_fmt(z0)],
            "dimensions_m":{"length":_fmt(x1-x0),"width":_fmt(y1-y0),"height":_fmt(z1-z0)},
            "status":"CONFIRMED_FROM_INPUT","layer":"STARK-SPDA-REFERENCIAS",
        })
    objects.extend(terminals)
    # Only exposed samples become CAD objects; all samples remain in analysis payload.
    for s in assessed:
        if s["coverage"]["status"]=="EXPOSED":
            objects.append({
                "id":f"EXP-{s['id'][4:]}","type":"EXPOSED_SAMPLE","point_m":s["point_m"],
                "owners":s["owners"],"faces":s["faces"],"layer":"STARK-SPDA-ALERTAS","status":"REQUIRES_REVIEW",
            })

    relations=[]
    for t in terminals:
        if t.get("source_volume"):
            for vid in str(t["source_volume"]).split("/"):
                if vid:
                    relations.append({"from":t["id"],"type":"INSTALLED_ON_OR_DERIVED_FROM","to":vid})
    arrangement={
        "geometry_core_version":CORE_VERSION,
        "project_id":src.get("project_id","STK-SPDA-UNASSIGNED"),"version":src.get("version","V01"),
        "workflow":src["workflow"],"input_digest":digest(src),
        "geometry_3d":deepcopy(geom),"protection_context":deepcopy(src["protection_context"]),
        "method":{
            "type":"ROLLING_SPHERE_POINT_SCREENING_V0_2",
            "scope":"AXIS_ALIGNED_RECTANGULAR_VOLUMES_WITH_VERTICAL_AIR_TERMINALS",
            "equation":"r_p = sqrt(2*R*dh - dh^2), evaluated per sampled surface point with 0 < dh <= R",
            "limitations":[
                "NOT_FULL_CONTINUOUS_SPHERE_COLLISION_SOLVER",
                "NO_SLOPED_OR_CURVED_ROOFS_V0_2",
                "NO_HORIZONTAL_WIRE_PROTECTION_CONTRIBUTION_V0_2",
                "NO_PROTECTION_ANGLE_ENGINE_V0_2",
                "NO_SEPARATION_DISTANCE_ENGINE_V0_2",
                "CONSTRUCTABILITY_OF_AUTO_TERMINALS_REQUIRES_REGIS_VALIDATION",
            ],
        },
        "derived":{
            "rolling_sphere_radius_m":_fmt(R),"surface_sample_spacing_m":_fmt(spacing),
            "sample_count":len(assessed),"protected_sample_count":protected,"exposed_sample_count":exposed,
            "coverage_percent":_fmt((Decimal(protected)*Decimal(100)/Decimal(len(assessed))) if assessed else Decimal(0)),
            "terminal_count":len(terminals),"auto_refinement_terminal_count":added,
            "samples_with_unsupported_height_relation":unsupported,
        },
        "objects":objects,"relations":relations,"surface_assessment":assessed,
        "status":"PRELIMINARY_AWAITING_REGIS_VALIDATION","prepared_by":"Bolanho","technical_validator":"Régis",
    }
    arrangement["arrangement_digest"]=digest(arrangement)
    return arrangement


def audit_rolling_sphere_arrangement(arrangement: dict) -> dict:
    issues=[]
    if arrangement.get("prepared_by")!="Bolanho": issues.append({"severity":"CRITICAL","code":"INVALID_OPERATOR"})
    if arrangement.get("technical_validator")!="Régis": issues.append({"severity":"CRITICAL","code":"INVALID_TECHNICAL_VALIDATOR"})
    if arrangement.get("status")!="PRELIMINARY_AWAITING_REGIS_VALIDATION": issues.append({"severity":"CRITICAL","code":"INVALID_RELEASE_STATUS"})
    ids=[o.get("id") for o in arrangement.get("objects",[])]
    if len(ids)!=len(set(ids)): issues.append({"severity":"CRITICAL","code":"DUPLICATE_OBJECT_ID"})
    idset=set(ids)
    for rel in arrangement.get("relations",[]):
        if rel.get("from") not in idset: issues.append({"severity":"CRITICAL","code":"RELATION_FROM_MISSING","relation":rel})
        if rel.get("to") not in idset: issues.append({"severity":"CRITICAL","code":"RELATION_TO_MISSING","relation":rel})
    d=arrangement.get("derived",{})
    if d.get("sample_count",0) <= 0: issues.append({"severity":"CRITICAL","code":"NO_SURFACE_SAMPLES"})
    if d.get("exposed_sample_count",0) > 0:
        issues.append({"severity":"CRITICAL","code":"EXPOSED_SURFACE_POINTS_REMAIN","count":d.get("exposed_sample_count")})
    if d.get("samples_with_unsupported_height_relation",0) > 0:
        issues.append({"severity":"HIGH","code":"HEIGHT_RELATION_OUTSIDE_V0_2_ANALYTIC_SCOPE","count":d.get("samples_with_unsupported_height_relation")})
    # Tamper/integrity: rebuild digest excluding current digest and compare.
    temp=deepcopy(arrangement); expected=temp.pop("arrangement_digest",None); computed=digest(temp)
    if expected != computed: issues.append({"severity":"CRITICAL","code":"ARRANGEMENT_DIGEST_MISMATCH"})

    critical=[i for i in issues if i["severity"]=="CRITICAL"]
    out={
        "geometry_core_version":CORE_VERSION,"project_id":arrangement.get("project_id"),
        "arrangement_digest":arrangement.get("arrangement_digest"),
        "checks":{
            "object_ids_unique":len(ids)==len(set(ids)),
            "all_sample_points_covered":d.get("exposed_sample_count",0)==0,
            "sample_count":d.get("sample_count",0),"terminal_count":d.get("terminal_count",0),
            "coverage_percent":d.get("coverage_percent"),
        },
        "issues":issues,
        "status":"PASS_INTERNAL_3D_ROLLING_SPHERE_AUDIT_AWAITING_REGIS" if not critical else "BLOCKED_3D_GEOMETRY_AUDIT",
    }
    out["audit_digest"]=digest(out)
    return out


def _box_edges(vobj: dict):
    x0,y0,z0=_d3(vobj["origin_m"]); d=vobj["dimensions_m"]
    x1=x0+D(d["length"]); y1=y0+D(d["width"]); z1=z0+D(d["height"])
    p=[(x0,y0,z0),(x1,y0,z0),(x1,y1,z0),(x0,y1,z0),(x0,y0,z1),(x1,y0,z1),(x1,y1,z1),(x0,y1,z1)]
    e=[(0,1),(1,2),(2,3),(3,0),(4,5),(5,6),(6,7),(7,4),(0,4),(1,5),(2,6),(3,7)]
    return [(p[a],p[b]) for a,b in e]


def export_3d_dxf(arrangement: dict, audit: dict, path: str|Path) -> Path:
    if ezdxf is None: raise GeometryValidationError("EZDXF_NOT_AVAILABLE")
    if audit.get("status")!="PASS_INTERNAL_3D_ROLLING_SPHERE_AUDIT_AWAITING_REGIS":
        raise GeometryValidationError("DXF_EXPORT_REQUIRES_PASSED_3D_AUDIT")
    path=Path(path); doc=ezdxf.new("R2018")
    layers=["STARK-SPDA-CAPTACAO","STARK-SPDA-REFERENCIAS","STARK-SPDA-ALERTAS","STARK-SPDA-TEXTOS","STARK-SPDA-PENDENCIAS"]
    for name in layers:
        if name not in doc.layers: doc.layers.add(name)
    msp=doc.modelspace()
    for o in arrangement.get("objects",[]):
        typ=o.get("type"); layer=o.get("layer","STARK-SPDA-REFERENCIAS")
        if typ=="VOLUME":
            for a,b in _box_edges(o):
                msp.add_line(tuple(float(x) for x in a),tuple(float(x) for x in b),dxfattribs={"layer":layer})
        elif typ=="AIR_TERMINAL":
            a=_d3(o["base_point_m"]); b=_d3(o["tip_point_m"])
            msp.add_line(tuple(float(x) for x in a),tuple(float(x) for x in b),dxfattribs={"layer":layer})
            msp.add_point(tuple(float(x) for x in b),dxfattribs={"layer":layer})
        elif typ=="EXPOSED_SAMPLE":
            p=_d3(o["point_m"]); msp.add_point(tuple(float(x) for x in p),dxfattribs={"layer":layer})
    # text near origin, intentionally simple.
    all_vol=[o for o in arrangement.get("objects",[]) if o.get("type")=="VOLUME"]
    if all_vol:
        x0,y0,z0=_d3(all_vol[0]["origin_m"])
    else: x0=y0=z0=Decimal(0)
    msp.add_text(
        f"STARK 3D PRELIMINAR | {arrangement['project_id']} {arrangement['version']} | Bolanho -> Regis",
        dxfattribs={"height":0.3,"layer":"STARK-SPDA-TEXTOS"}
    ).dxf.insert=(float(x0),float(y0),float(z0))
    msp.add_text(
        "NAO LIBERADO PARA EXECUCAO - AGUARDANDO VALIDACAO DO ENGENHEIRO",
        dxfattribs={"height":0.3,"layer":"STARK-SPDA-PENDENCIAS"}
    ).dxf.insert=(float(x0),float(y0)-1.0,float(z0))
    doc.header["$INSUNITS"]=6
    doc.saveas(path); return path


def build_3d_handoff(arrangement: dict, audit: dict, files: list[str]|None=None) -> dict:
    ready=audit.get("status")=="PASS_INTERNAL_3D_ROLLING_SPHERE_AUDIT_AWAITING_REGIS"
    out={
        "geometry_core_version":CORE_VERSION,"project_id":arrangement.get("project_id"),"version":arrangement.get("version"),
        "status":"READY_FOR_BOLANHO_TO_SEND_TO_REGIS_FOR_VALIDATION" if ready else "BLOCKED_NOT_READY_FOR_REGIS",
        "prepared_by":"Bolanho","technical_validator":"Régis","engineering_status":"PRELIMINARY_NOT_RELEASED_FOR_EXECUTION",
        "arrangement_digest":arrangement.get("arrangement_digest"),"audit_digest":audit.get("audit_digest"),"files":files or [],
        "required_regis_actions":[
            "CONFIRM_ALL_3D_VOLUMES_AND_HEIGHTS",
            "CONFIRM_ROLLING_SPHERE_RADIUS_FROM_VALIDATED_NORMATIVE_LIBRARY",
            "REVIEW_AIR_TERMINAL_LOCATIONS_AND_CONSTRUCTABILITY",
            "REVIEW_EXPOSED_POINT_RESULT_AND_ENGINE_LIMITATIONS",
            "APPROVE_REQUEST_CHANGES_OR_REJECT",
        ],
    }
    out["handoff_digest"]=digest(out); return out


def production_gate_3d(data: dict) -> dict:
    blockers=[]
    try: validate_3d_input(data,allow_test_policy=False)
    except GeometryValidationError as e: blockers.append(str(e))
    out={
        "geometry_core_version":CORE_VERSION,
        "status":"PASS_READY_FOR_PRELIMINARY_3D_ROLLING_SPHERE_ANALYSIS" if not blockers else "BLOCKED",
        "blockers":sorted(set(blockers)),
        "note":"PASS authorizes only preliminary 3D analysis. Regis technical validation remains mandatory; v0.2 limitations still apply.",
    }
    out["gate_digest"]=digest(out); return out
