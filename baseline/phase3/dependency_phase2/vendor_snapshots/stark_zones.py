"""STARK SPDA Core 0.6.0 — deterministic zone and parametric Golden Case engine.

This module reconstructs a historical engineering workbook from a captured,
hash-bound snapshot. It is NOT a normative implementation of ABNT NBR 5419.
The formulas here reproduce/audit the historical source logic only.
"""
from __future__ import annotations
from dataclasses import dataclass, asdict
from decimal import Decimal, ROUND_HALF_UP, getcontext
from pathlib import Path
from typing import Any, Dict, Mapping, Iterable, Tuple
import hashlib, json

from stark_core import D, canonical_hash, decimal_str, StarkValidationError

getcontext().prec = 40
PI = Decimal("3.141592653589793238462643383279502884197")
ZONE_ENGINE_VERSION = "0.6.0"
COMPONENT_ORDER = ("RA","RB","RC","RM","RU","RV","RW","RZ")


def file_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def load_zone_snapshot(path: str | Path) -> Dict[str, Any]:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def verify_snapshot_source(snapshot: Mapping[str, Any], workbook_path: str) -> Dict[str, Any]:
    actual = file_sha256(workbook_path)
    expected = snapshot["source"]["sha256"]
    ok = actual == expected
    return {
        "expected_sha256": expected,
        "actual_sha256": actual,
        "passed": ok,
        "status": "SOURCE_HASH_MATCH" if ok else "SOURCE_HASH_MISMATCH",
    }


def q(value: Any, quantum: str) -> Decimal:
    return D(value).quantize(D(quantum), rounding=ROUND_HALF_UP)


@dataclass(frozen=True)
class ZoneLossResult:
    zone_id: str
    person_factor: Decimal
    LA: Decimal
    LU: Decimal
    LB: Decimal
    LV: Decimal
    LCMWZ: Decimal
    trace_hash: str


@dataclass(frozen=True)
class ZoneComponentResult:
    zone_id: str
    RA_x1e5: Decimal
    RU_x1e5: Decimal
    RB_x1e5: Decimal
    RV_x1e5: Decimal
    trace_hash: str


@dataclass(frozen=True)
class RelevantQuantities:
    ADmin_m2: Decimal
    ADprime_m2: Decimal
    AD_m2: Decimal
    AM_m2: Decimal
    AL_P_m2: Decimal
    AI_P_m2: Decimal
    ADJ_P_m2: Decimal
    AL_T_m2: Decimal
    AI_T_m2: Decimal
    ADJ_T_m2: Decimal
    ND: Decimal
    NM: Decimal
    NL_P: Decimal
    NI_P: Decimal
    NDJ_P: Decimal
    NL_T: Decimal
    NI_T: Decimal
    NDJ_T: Decimal
    trace_hash: str


def compute_zone_loss(zone_id: str, z: Mapping[str, Any]) -> ZoneLossResult:
    if z.get("external"):
        payload = {"zone_id": zone_id, "person_factor": "0", "LA":"0", "LU":"0", "LB":"0", "LV":"0", "LCMWZ":"0"}
        return ZoneLossResult(zone_id, Decimal(0), Decimal(0), Decimal(0), Decimal(0), Decimal(0), Decimal(0), canonical_hash(payload))
    nz, nt, tz = D(z["nz"]), D(z["nt"]), D(z["tz"])
    if nt <= 0 or tz < 0:
        raise StarkValidationError(f"Invalid zone population/time values for {zone_id}")
    f = (nz / nt) * (tz / D("8760"))
    LA = D(z["rt"]) * D(z["LT"]) * f
    LU = LA
    LB = D(z["rp"]) * D(z["rf"]) * D(z["hz"]) * D(z["LF"]) * f
    LV = LB
    LCMWZ = D(z["LO"]) * f
    payload = {"zone_id":zone_id,"person_factor":decimal_str(f),"LA":decimal_str(LA),"LU":decimal_str(LU),"LB":decimal_str(LB),"LV":decimal_str(LV),"LCMWZ":decimal_str(LCMWZ)}
    return ZoneLossResult(zone_id, f, LA, LU, LB, LV, LCMWZ, canonical_hash(payload))


def compute_relevant_quantities(before: Mapping[str, Any]) -> RelevantQuantities:
    s = before["structure"]; ep = before["energy_line"]; tp = before["signal_line"]
    NG,L,W,H,CD = D(s["NG"]),D(s["L"]),D(s["W"]),D(s["H"]),D(s["CD"])
    ADmin = L*W + D("2")*(D("3")*H)*(L+W) + PI*(D("3")*H)**2
    ADprime = PI*(D("3")*H)**2
    AD = max(ADmin, ADprime)
    AM = D("2")*D("500")*(L+W) + PI*(D("500")**2)
    AL_P = D("40")*D(ep["LL"]); AI_P = D("4000")*D(ep["LL"])
    AL_T = D("40")*D(tp["LL"]); AI_T = D("4000")*D(tp["LL"])

    def adj_area(line: Mapping[str, Any]) -> Decimal:
        a=line["adjacent"]; lj,wj,hj=D(a["L"]),D(a["W"]),D(a["H"])
        return lj*wj + D("2")*(D("3")*hj)*(lj+wj) + PI*(D("3")*hj)**2
    ADJ_P=adj_area(ep); ADJ_T=adj_area(tp)
    ND=NG*AD*CD*D("0.000001")
    NM=NG*AM*D("0.000001")
    NL_P=NG*AL_P*D(ep["CI"])*D(ep["CE"])*D(ep["CT"])*D("0.000001")
    NI_P=NG*AI_P*D(ep["CI"])*D(ep["CE"])*D(ep["CT"])*D("0.000001")
    NDJ_P=NG*ADJ_P*D(ep["adjacent"]["CDJ"])*D(ep["CT"])*D("0.000001")
    NL_T=NG*AL_T*D(tp["CI"])*D(tp["CE"])*D(tp["CT"])*D("0.000001")
    NI_T=NG*AI_T*D(tp["CI"])*D(tp["CE"])*D(tp["CT"])*D("0.000001")
    NDJ_T=NG*ADJ_T*D(tp["adjacent"]["CDJ"])*D(tp["CT"])*D("0.000001")
    payload={k:decimal_str(v) for k,v in locals().copy().items() if isinstance(v,Decimal)}
    return RelevantQuantities(ADmin,ADprime,AD,AM,AL_P,AI_P,ADJ_P,AL_T,AI_T,ADJ_T,ND,NM,NL_P,NI_P,NDJ_P,NL_T,NI_T,NDJ_T,canonical_hash(payload))


def source_quantity_audit(before: Mapping[str, Any]) -> Dict[str, Any]:
    calc=compute_relevant_quantities(before)
    src={k:D(v) for k,v in before["source_quantities"].items()}
    # Display-level tolerances mirror the precision visible in the historical workbook.
    rules={
      "ADmin_m2":("10","10"),"ADprime_m2":("10","10"),"AD_m2":("10","10"),"AM_m2":("1000","1000"),
      "AL_P_m2":("1","1"),"AI_P_m2":("1","1"),"ADJ_P_m2":("10","10"),"AL_T_m2":("1","1"),"AI_T_m2":("1","1"),"ADJ_T_m2":("10","10"),
      "ND":("0.0001","0.0001"),"NM":("0.01","0.02"),"NL_P":("0.0001","0.0001"),"NI_P":("0.01","0.01"),"NDJ_P":("0.0001","0.0001"),
      "NL_T":("0.0001","0.0001"),"NI_T":("0.01","0.01"),"NDJ_T":("0.0001","0.0001")
    }
    checks=[]; blockers=[]
    for field,(quantum,tol) in rules.items():
        c=getattr(calc,field); s=src[field]
        cdisp=q(c,quantum); delta=abs(cdisp-s); passed=delta<=D(tol)
        rec={"field":field,"calculated_raw":decimal_str(c),"calculated_display":decimal_str(cdisp),"source_display":decimal_str(s),"delta":decimal_str(delta),"passed":passed}
        checks.append(rec)
        if not passed: blockers.append({"code":"SOURCE_EQUATION_MISMATCH","field":field,"calculated":decimal_str(cdisp),"source":decimal_str(s)})
    result={"engine":f"STARK_ZONE_{ZONE_ENGINE_VERSION}","checks":checks,"blocking_findings":blockers,"status":"PASS" if not blockers else "REVIEW_REQUIRED"}
    result["trace_hash"]=canonical_hash(result)
    return result


def compute_zone_components(zone_id: str, z: Mapping[str, Any], loss: ZoneLossResult, before: Mapping[str, Any], use_source_events: bool=True) -> ZoneComponentResult:
    if z.get("external"):
        payload={"zone_id":zone_id,"RA_x1e5":"0","RU_x1e5":"0","RB_x1e5":"0","RV_x1e5":"0"}
        return ZoneComponentResult(zone_id,Decimal(0),Decimal(0),Decimal(0),Decimal(0),canonical_hash(payload))
    s=before["structure"]; ep=before["energy_line"]; tp=before["signal_line"]
    if use_source_events:
        ev={k:D(v) for k,v in before["source_quantities"].items()}
        ND,NL_P,NDJ_P,NL_T,NDJ_T=ev["ND"],ev["NL_P"],ev["NDJ_P"],ev["NL_T"],ev["NDJ_T"]
    else:
        r=compute_relevant_quantities(before); ND,NL_P,NDJ_P,NL_T,NDJ_T=r.ND,r.NL_P,r.NDJ_P,r.NL_T,r.NDJ_T
    PB,PEB=D(s["PB"]),D(s["PEB"])
    RA = ND * D(z["PTA"]) * PB * loss.LA / D("0.00001")
    RB = ND * PB * loss.LB / D("0.00001")
    energy_ru=(NL_P+NDJ_P)*D(z["PTU"])*PEB*D(ep["PLD"])*D(ep["CLD"])*loss.LU
    signal_ru=(NL_T+NDJ_T)*D(z["PTU"])*PEB*D(tp["PLD"])*D(tp["CLD"])*loss.LU
    RU=(energy_ru+signal_ru)/D("0.00001")
    energy_rv=(NL_P+NDJ_P)*PEB*D(ep["PLD"])*D(ep["CLD"])*loss.LV
    signal_rv=(NL_T+NDJ_T)*PEB*D(tp["PLD"])*D(tp["CLD"])*loss.LV
    RV=(energy_rv+signal_rv)/D("0.00001")
    # Workbook tables display zone risks to 0.001 in x1e-5 units.
    RAq,RUq,RBq,RVq=(q(RA,"0.001"),q(RU,"0.001"),q(RB,"0.001"),q(RV,"0.001"))
    payload={"zone_id":zone_id,"RA_x1e5":decimal_str(RAq),"RU_x1e5":decimal_str(RUq),"RB_x1e5":decimal_str(RBq),"RV_x1e5":decimal_str(RVq),"source_events":use_source_events}
    return ZoneComponentResult(zone_id,RAq,RUq,RBq,RVq,canonical_hash(payload))


def reconstruct_before(snapshot: Mapping[str, Any], use_source_events: bool=True) -> Dict[str, Any]:
    before=snapshot["before"]
    losses={}; comps={}; zone_checks=[]
    for zid,z in before["zones"].items():
        loss=compute_zone_loss(zid,z); comp=compute_zone_components(zid,z,loss,before,use_source_events=use_source_events)
        losses[zid]=loss; comps[zid]=comp
        if not z.get("external"):
            exp=z["expected"]
            for key in ("person_factor","LA","LU","LB","LV","LCMWZ"):
                actual=getattr(loss,key)
                zone_checks.append({"zone":zid,"kind":"loss","field":key,"actual":decimal_str(actual),"expected":str(exp[key]),"passed":actual==D(exp[key])})
        expc=z.get("expected_components_x1e5",{})
        for key in ("RA","RU","RB","RV"):
            actual=getattr(comp,f"{key}_x1e5")
            expected=D(expc.get(key,"0"))
            zone_checks.append({"zone":zid,"kind":"component","field":key,"actual":decimal_str(actual),"expected":decimal_str(expected),"passed":actual==expected})
    totals={k:Decimal(0) for k in COMPONENT_ORDER}
    for c in comps.values():
        totals["RA"]+=c.RA_x1e5; totals["RU"]+=c.RU_x1e5; totals["RB"]+=c.RB_x1e5; totals["RV"]+=c.RV_x1e5
    expected=before["expected_component_totals_x1e5"]
    total_checks=[]
    for k in COMPONENT_ORDER:
        e=D(expected[k]); a=totals[k]
        total_checks.append({"component":k,"actual_x1e5":decimal_str(a),"expected_x1e5":decimal_str(e),"passed":a==e})
    r1=sum(totals.values(),Decimal(0)); r1_expected=D(expected["R1"])
    total_checks.append({"component":"R1","actual_x1e5":decimal_str(r1),"expected_x1e5":decimal_str(r1_expected),"passed":r1==r1_expected})
    actual=r1*D("0.00001"); rt=D(before["RT_actual"])
    status="PROTECTION_REQUIRED" if actual>rt else ("CRITERION_MET" if actual<rt else "AT_TOLERABLE_LIMIT")
    result={
      "engine":f"STARK_ZONE_{ZONE_ENGINE_VERSION}","mode":"SOURCE_REPRODUCTION" if use_source_events else "EQUATION_RECOMPUTE",
      "normative_authority":False,
      "zone_losses":{k:{kk:decimal_str(vv) if isinstance(vv,Decimal) else vv for kk,vv in asdict(v).items()} for k,v in losses.items()},
      "zone_components":{k:{kk:decimal_str(vv) if isinstance(vv,Decimal) else vv for kk,vv in asdict(v).items()} for k,v in comps.items()},
      "component_totals_x1e5":{k:decimal_str(v) for k,v in totals.items()},"R1_x1e5":decimal_str(r1),"R1_actual":decimal_str(actual),"RT_actual":decimal_str(rt),"status":status,
      "zone_checks":zone_checks,"total_checks":total_checks,
      "passed":all(x["passed"] for x in zone_checks+total_checks)
    }
    result["trace_hash"]=canonical_hash(result)
    return result


def compare_project_signatures(snapshot: Mapping[str, Any]) -> Dict[str, Any]:
    b=snapshot["before"]["project_signature"]; a=snapshot["after"]["project_signature"]
    findings=[]
    if D(b["ng"]) != D(a["ng"]): findings.append({"code":"CROSS_SHEET_NG_MISMATCH","before":b["ng"],"after":a["ng"],"blocking":True})
    for dim in ("L","W","H"):
        if D(b["dimensions_m"][dim]) != D(a["dimensions_m"][dim]):
            findings.append({"code":"CROSS_SHEET_DIMENSION_MISMATCH","dimension":dim,"before":b["dimensions_m"][dim],"after":a["dimensions_m"][dim],"blocking":True})
    bz={z["id"]:z["name"] for z in b["zones"]}; az={z["id"]:z["name"] for z in a["zones"]}
    if set(bz)!=set(az): findings.append({"code":"CROSS_SHEET_ZONE_SET_MISMATCH","before_ids":sorted(bz),"after_ids":sorted(az),"blocking":True})
    for zid in sorted(set(bz)&set(az)):
        if bz[zid].strip()!=az[zid].strip(): findings.append({"code":"CROSS_SHEET_ZONE_NAME_MISMATCH","zone":zid,"before":bz[zid],"after":az[zid],"blocking":True})
    result={"status":"BLOCKED_PROJECT_SIGNATURE_MISMATCH" if findings else "SIGNATURES_MATCH","findings":findings}
    result["trace_hash"]=canonical_hash(result)
    return result


def build_zone_golden_report(snapshot: Mapping[str, Any], workbook_path: str) -> Dict[str, Any]:
    source=verify_snapshot_source(snapshot,workbook_path)
    if not source["passed"]:
        raise StarkValidationError("Golden Case workbook hash differs from captured 0.6 snapshot")
    before=reconstruct_before(snapshot,True)
    eq_audit=source_quantity_audit(snapshot["before"])
    signatures=compare_project_signatures(snapshot)
    after=snapshot["after"]
    after_findings=[]
    if after.get("known_formula_errors"): after_findings.append({"code":"AFTER_FORMULA_ERRORS_PRESENT","cells":after["known_formula_errors"],"blocking":True})
    if D(after["cached_component_totals_x1e5"]["R1"]) != D(after["narrative_R1_x1e5"]):
        after_findings.append({"code":"AFTER_CACHED_TOTAL_DIFFERS_FROM_NARRATIVE","cached":after["cached_component_totals_x1e5"]["R1"],"narrative":after["narrative_R1_x1e5"],"blocking":True})
    report={
      "core":"STARK_SPDA_Core_0.6","golden_case_id":"REGIS-ALUSIL-2017-R1-ZONES","scope":"HISTORICAL_PARAMETRIC_REPRODUCTION_ONLY","normative_authority":False,
      "source_integrity":source,"before_parametric":before,"source_equation_audit":eq_audit,"cross_sheet_signature_audit":signatures,
      "after_audit":{"status":"BLOCKED_SOURCE_INCONSISTENCY" if after_findings or signatures["findings"] else "CONSISTENT","findings":after_findings+signatures["findings"]},
    }
    report["overall_status"]="PASS_BEFORE_PARAMETRIC_WITH_AFTER_BLOCKED" if before["passed"] and report["after_audit"]["status"].startswith("BLOCKED") else "REVIEW_REQUIRED"
    report["trace_hash"]=canonical_hash(report)
    return report
