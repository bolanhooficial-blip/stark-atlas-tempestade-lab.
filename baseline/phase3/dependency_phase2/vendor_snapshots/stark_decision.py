"""STARK SPDA Core 0.9.0 — supervised decision and pending-closure engine.

This module NEVER rewrites historical evidence. It records append-only human
engineering decisions, validates dependencies, reprocesses only affected
calculation chains, and emits immutable decision receipts.

Historical Golden Case only. It is not normative ABNT content and it does not
replace professional engineering responsibility.
"""
from __future__ import annotations
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional
import json

from stark_core import canonical_hash, D, decimal_str, StarkValidationError
from stark_zones import load_zone_snapshot, reconstruct_before

DECISION_ENGINE_VERSION = "0.9.0"
SUPPORTED_CONFIRMATIONS = ("REGIS-001", "REGIS-002", "REGIS-003")


def _hash_payload(payload: Mapping[str, Any]) -> str:
    return canonical_hash(payload)


def _queue_map(report: Mapping[str, Any]) -> Dict[str, Mapping[str, Any]]:
    return {q["confirmation_id"]: q for q in report.get("engineer_confirmation_queue", [])}


def _issue_map(report: Mapping[str, Any]) -> Dict[str, Mapping[str, Any]]:
    return {x["issue_id"]: x for x in report.get("issues", [])}


def create_decision_packet(report: Mapping[str, Any], *, project_id: str, model_version: str = "0.9") -> Dict[str, Any]:
    """Create an unsigned/pending intake packet bound to one reconciliation report."""
    questions=[]
    for q in report.get("engineer_confirmation_queue", []):
        questions.append({
            "confirmation_id": q["confirmation_id"],
            "priority": q.get("priority"),
            "blocks": list(q.get("blocks", [])),
            "depends_on": list(q.get("depends_on", [])),
            "question": q.get("question"),
            "required_answer": q.get("required_answer"),
            "why_needed": q.get("why_needed"),
            "question_hash": canonical_hash({
                "confirmation_id": q["confirmation_id"],
                "question": q.get("question"),
                "evidence": q.get("evidence"),
                "required_answer": q.get("required_answer"),
            }),
        })
    packet={
        "engine": f"STARK_DECISION_{DECISION_ENGINE_VERSION}",
        "project_id": project_id,
        "model_version": model_version,
        "bound_reconciliation_hash": report.get("trace_hash"),
        "status": "AWAITING_ENGINEER_DECISIONS" if questions else "NO_DECISIONS_REQUIRED",
        "questions": questions,
        "receipts": [],
        "policy": {
            "append_only": True,
            "historical_evidence_is_immutable": True,
            "technical_change_requires_reprocessing": True,
            "missing_corrected_source_keeps_affected_chain_blocked": True,
        },
    }
    packet["packet_hash"]=canonical_hash(packet)
    return packet


def _latest_receipts(receipts: Iterable[Mapping[str, Any]]) -> Dict[str, Mapping[str, Any]]:
    out={}
    for r in receipts:
        out[r["confirmation_id"]]=r
    return out


def _validate_answer(confirmation_id: str, answer: Mapping[str, Any]) -> None:
    if confirmation_id == "REGIS-001":
        relation=answer.get("sheet_relationship")
        if relation not in {"SAME_PROJECT", "DIFFERENT_PROJECTS"}:
            raise StarkValidationError("REGIS-001 requires sheet_relationship SAME_PROJECT or DIFFERENT_PROJECTS")
        if relation == "SAME_PROJECT":
            if answer.get("authoritative_signature") not in {"BEFORE", "AFTER", "CORRECTED_SOURCE"}:
                raise StarkValidationError("SAME_PROJECT requires authoritative_signature")
            # A verbal choice cannot repair contradictory source geometry. A corrected source is required
            # before the cross-sheet comparison can become computationally releasable.
            if answer.get("authoritative_signature") == "CORRECTED_SOURCE" and not answer.get("corrected_source_sha256"):
                raise StarkValidationError("CORRECTED_SOURCE requires corrected_source_sha256")
        else:
            if not answer.get("before_project_id") or not answer.get("after_project_id"):
                raise StarkValidationError("DIFFERENT_PROJECTS requires before_project_id and after_project_id")
    elif confirmation_id == "REGIS-002":
        resolution=answer.get("resolution")
        if resolution not in {"STORED_MANUAL", "EQUATION_RECOMPUTE", "CORRECTED_SOURCE"}:
            raise StarkValidationError("REGIS-002 invalid resolution")
        if resolution == "STORED_MANUAL":
            for k in ("NDJ_P", "NDJ_T", "justification"):
                if answer.get(k) in (None, ""):
                    raise StarkValidationError(f"STORED_MANUAL requires {k}")
        if resolution == "CORRECTED_SOURCE":
            for k in ("NDJ_P", "NDJ_T", "corrected_source_sha256"):
                if answer.get(k) in (None, ""):
                    raise StarkValidationError(f"CORRECTED_SOURCE requires {k}")
    elif confirmation_id == "REGIS-003":
        resolution=answer.get("resolution")
        if resolution not in {"CACHED_O283", "NARRATIVE_B291", "CORRECTED_SOURCE"}:
            raise StarkValidationError("REGIS-003 invalid resolution")
        if resolution == "CORRECTED_SOURCE":
            if answer.get("R1_after_x1e5") in (None, "") or not answer.get("corrected_source_sha256"):
                raise StarkValidationError("CORRECTED_SOURCE requires R1_after_x1e5 and corrected_source_sha256")
    else:
        raise StarkValidationError(f"Unsupported confirmation_id {confirmation_id}")


def record_decision(packet: Mapping[str, Any], report: Mapping[str, Any], *, confirmation_id: str,
                    answer: Mapping[str, Any], engineer_name: str, engineer_role: str,
                    decided_at: str, rationale: str = "") -> Dict[str, Any]:
    """Append one decision receipt. Does not mutate packet or historical report."""
    if confirmation_id not in SUPPORTED_CONFIRMATIONS:
        raise StarkValidationError("Unsupported confirmation")
    if packet.get("bound_reconciliation_hash") != report.get("trace_hash"):
        raise StarkValidationError("Decision packet is not bound to this reconciliation report")
    qmap=_queue_map(report)
    if confirmation_id not in qmap:
        raise StarkValidationError("Confirmation is not open in the bound report")
    if not engineer_name.strip() or not engineer_role.strip() or not decided_at.strip():
        raise StarkValidationError("Engineer identity/role and decided_at are required")
    _validate_answer(confirmation_id, answer)

    latest=_latest_receipts(packet.get("receipts", []))
    deps=qmap[confirmation_id].get("depends_on", [])
    missing=[x for x in deps if x not in latest or latest[x].get("decision_status") != "RECORDED"]
    if missing:
        raise StarkValidationError(f"Unresolved decision dependencies: {missing}")

    previous_hash=packet.get("receipts", [])[-1].get("receipt_hash") if packet.get("receipts") else None
    qhash=next(x["question_hash"] for x in packet.get("questions", []) if x["confirmation_id"]==confirmation_id)
    body={
        "engine": f"STARK_DECISION_{DECISION_ENGINE_VERSION}",
        "confirmation_id": confirmation_id,
        "question_hash": qhash,
        "bound_reconciliation_hash": report.get("trace_hash"),
        "answer": deepcopy(dict(answer)),
        "answer_hash": canonical_hash(dict(answer)),
        "engineer": {"name": engineer_name, "role": engineer_role},
        "decided_at": decided_at,
        "rationale": rationale,
        "decision_status": "RECORDED",
        "previous_receipt_hash": previous_hash,
    }
    body["receipt_hash"]=canonical_hash(body)
    out=deepcopy(dict(packet))
    out["receipts"]=list(packet.get("receipts", []))+[body]
    answered=set(_latest_receipts(out["receipts"]))
    open_ids=[q["confirmation_id"] for q in report.get("engineer_confirmation_queue", []) if q["confirmation_id"] not in answered]
    out["status"]="DECISIONS_RECORDED_PENDING_REPROCESSING" if not open_ids else "PARTIALLY_ANSWERED"
    out["open_confirmation_ids"]=open_ids
    out["previous_packet_hash"]=packet.get("packet_hash")
    out.pop("packet_hash",None)
    out["packet_hash"]=canonical_hash(out)
    return out


def verify_receipt_chain(packet: Mapping[str, Any]) -> Dict[str, Any]:
    prev=None; errors=[]
    for i,r in enumerate(packet.get("receipts", [])):
        if r.get("previous_receipt_hash") != prev:
            errors.append({"index":i,"code":"RECEIPT_CHAIN_PREVIOUS_HASH_MISMATCH"})
        body=dict(r); stored=body.pop("receipt_hash",None)
        calc=canonical_hash(body)
        if stored != calc:
            errors.append({"index":i,"code":"RECEIPT_HASH_MISMATCH","stored":stored,"calculated":calc})
        prev=stored
    out={"passed":not errors,"errors":errors,"receipt_count":len(packet.get("receipts", [])),"last_receipt_hash":prev}
    out["trace_hash"]=canonical_hash(out)
    return out


def _apply_ndj_decision(snapshot: Mapping[str, Any], answer: Mapping[str, Any]) -> Dict[str, Any]:
    resolution=answer["resolution"]
    if resolution == "EQUATION_RECOMPUTE":
        r=reconstruct_before(snapshot, False)
        return {"mode":"EQUATION_RECOMPUTE","result":r,"source_correction_required":False}
    s=deepcopy(snapshot)
    if resolution in {"STORED_MANUAL", "CORRECTED_SOURCE"}:
        s["before"]["source_quantities"]["NDJ_P"]=str(answer["NDJ_P"])
        s["before"]["source_quantities"]["NDJ_T"]=str(answer["NDJ_T"])
        r=reconstruct_before(s, True)
        return {
            "mode":resolution,
            "result":r,
            "source_correction_required": resolution=="STORED_MANUAL",
            "corrected_source_sha256": answer.get("corrected_source_sha256"),
        }
    raise StarkValidationError("Unsupported NDJ decision")


def _after_value(answer: Mapping[str, Any], issue: Mapping[str, Any]) -> Dict[str, Any]:
    by_label={c["label"]:c for c in issue.get("candidates",[])}
    if answer["resolution"]=="CACHED_O283":
        value=by_label["Workbook cached O283"]["value"]
    elif answer["resolution"]=="NARRATIVE_B291":
        value=by_label["Narrative B291"]["value"]
    else:
        value=str(answer["R1_after_x1e5"])
    return {"R1_after_x1e5":str(value),"resolution":answer["resolution"],"corrected_source_sha256":answer.get("corrected_source_sha256")}


def reprocess_decisions(report: Mapping[str, Any], packet: Mapping[str, Any], snapshot_path: str|Path) -> Dict[str, Any]:
    """Apply latest decisions without rewriting report. Produces a new derived decision state."""
    chain=verify_receipt_chain(packet)
    if not chain["passed"]:
        raise StarkValidationError("Decision receipt chain is invalid")
    latest=_latest_receipts(packet.get("receipts", []))
    issues=_issue_map(report)
    snapshot=load_zone_snapshot(snapshot_path)
    outcomes={}; affected=[]; blockers=[]

    # REGIS-001: establishes whether cross-sheet comparison itself is meaningful.
    r1=latest.get("REGIS-001")
    if r1:
        ans=r1["answer"]
        if ans["sheet_relationship"]=="DIFFERENT_PROJECTS":
            outcomes["REGIS-001"]={
                "status":"RESOLVED_DIFFERENT_PROJECTS",
                "before_project_id":ans["before_project_id"],"after_project_id":ans["after_project_id"],
                "cross_sheet_before_after_comparison":"NOT_APPLICABLE",
                "receipt_hash":r1["receipt_hash"],
            }
        else:
            corrected=ans.get("authoritative_signature")=="CORRECTED_SOURCE" and ans.get("corrected_source_sha256")
            outcomes["REGIS-001"]={
                "status":"RESOLVED_WITH_CORRECTED_SOURCE" if corrected else "DECISION_RECORDED_SOURCE_CORRECTION_PENDING",
                "authoritative_signature":ans.get("authoritative_signature"),
                "corrected_source_sha256":ans.get("corrected_source_sha256"),
                "receipt_hash":r1["receipt_hash"],
            }
            if not corrected:
                blockers.append({"code":"PROJECT_SIGNATURE_CORRECTED_SOURCE_REQUIRED","confirmation_id":"REGIS-001"})
        affected.append("RC-008")

    # REGIS-002: recompute only the Before risk chain affected by NDJ/P and NDJ/T.
    r2=latest.get("REGIS-002")
    if r2:
        ndj=_apply_ndj_decision(snapshot,r2["answer"])
        rr=ndj["result"]
        outcomes["REGIS-002"]={
            "status":"REPROCESSED",
            "resolution":r2["answer"]["resolution"],
            "affected_issues":["RC-006","RC-007"],
            "affected_components":["RU","RV","R1"],
            "reprocessed_R1_x1e5":rr["R1_x1e5"],
            "reprocessed_component_totals_x1e5":rr["component_totals_x1e5"],
            "calculation_status":rr["status"],
            "historical_golden_match":rr["passed"],
            "source_correction_required":ndj["source_correction_required"],
            "receipt_hash":r2["receipt_hash"],
        }
        if ndj["source_correction_required"]:
            blockers.append({"code":"MANUAL_NDJ_DECISION_REQUIRES_SOURCE_DOCUMENTATION","confirmation_id":"REGIS-002"})
        affected.extend(["RC-006","RC-007"])

    # REGIS-003: select authoritative After R1 evidence after dependency REGIS-001 has been recorded.
    r3=latest.get("REGIS-003")
    if r3:
        after=_after_value(r3["answer"],issues["RC-008"])
        relation=outcomes.get("REGIS-001",{}).get("status")
        if not r1:
            blockers.append({"code":"REGIS_003_DEPENDS_ON_REGIS_001","confirmation_id":"REGIS-003"})
            status="DEPENDENCY_MISSING"
        elif relation=="RESOLVED_DIFFERENT_PROJECTS":
            status="AFTER_VALUE_RESOLVED_CROSS_PROJECT_COMPARISON_NOT_APPLICABLE"
        elif relation=="RESOLVED_WITH_CORRECTED_SOURCE":
            status="AFTER_VALUE_RESOLVED"
        else:
            status="AFTER_VALUE_SELECTED_SOURCE_CORRECTION_PENDING"
            blockers.append({"code":"AFTER_PROJECT_SIGNATURE_SOURCE_CORRECTION_PENDING","confirmation_id":"REGIS-003"})
        if after["resolution"] in {"CACHED_O283","NARRATIVE_B291"}:
            blockers.append({"code":"AFTER_R1_SELECTED_FROM_CONFLICTING_HISTORICAL_SOURCE","confirmation_id":"REGIS-003","selected":after["resolution"]})
        outcomes["REGIS-003"]={**after,"status":status,"receipt_hash":r3["receipt_hash"]}
        affected.append("RC-008")

    answered=set(latest)
    still_open=[q["confirmation_id"] for q in report.get("engineer_confirmation_queue",[]) if q["confirmation_id"] not in answered]
    unique_affected=[]
    for x in affected:
        if x not in unique_affected: unique_affected.append(x)
    if still_open:
        status="BLOCKED_PENDING_ENGINEER_DECISIONS"
    elif blockers:
        status="DECISIONS_COMPLETE_WITH_SOURCE_BLOCKERS"
    else:
        status="DECISIONS_CLOSED_REPROCESSING_COMPLETE"
    out={
        "engine":f"STARK_DECISION_{DECISION_ENGINE_VERSION}",
        "bound_reconciliation_hash":report.get("trace_hash"),
        "decision_packet_hash":packet.get("packet_hash"),
        "receipt_chain":chain,
        "decision_outcomes":outcomes,
        "affected_issue_ids":unique_affected,
        "still_open_confirmation_ids":still_open,
        "source_or_process_blockers":blockers,
        "status":status,
        "history_policy":"ORIGINAL_RECONCILIATION_AND_EVIDENCE_REMAIN_IMMUTABLE",
    }
    out["trace_hash"]=canonical_hash(out)
    return out


def decision_gate(reprocessed: Mapping[str, Any]) -> Dict[str, Any]:
    if reprocessed.get("still_open_confirmation_ids"):
        status="BLOCKED_PENDING_ENGINEER_DECISIONS"
    elif reprocessed.get("source_or_process_blockers"):
        status="BLOCKED_SOURCE_OR_PROCESS_CLOSURE"
    else:
        status="PASS_SUPERVISED_DECISIONS_CLOSED"
    out={
        "gate":"GOLDEN_CASE_SUPERVISED_DECISION_0_9",
        "status":status,
        "open_confirmation_ids":list(reprocessed.get("still_open_confirmation_ids",[])),
        "blocker_codes":[b["code"] for b in reprocessed.get("source_or_process_blockers",[])],
        "reprocessed_trace_hash":reprocessed.get("trace_hash"),
    }
    out["trace_hash"]=canonical_hash(out)
    return out


def save_json(path: str|Path, obj: Mapping[str, Any]) -> None:
    Path(path).write_text(json.dumps(obj,ensure_ascii=False,indent=2),encoding="utf-8")
