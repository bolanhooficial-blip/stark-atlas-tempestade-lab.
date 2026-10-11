"""STARK SPDA Core 0.4.0 — controlled normative ingestion pipeline.

This module does not scrape or embed standards. It ingests engineer-provided,
authorized evidence into a staged normative library. New technical items always
enter as PENDING_ENGINEER_VALIDATION and cannot be used by the calculation
engine until separately approved.
"""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
from pathlib import Path
from typing import Any, Dict, List, Mapping, Sequence

from stark_core import Finding, StarkValidationError, canonical_hash

INGESTION_VERSION = "0.4.0"
ALLOWED_ITEM_TYPES = {"PARAMETER", "FORMULA", "RISK_MODEL"}


def file_sha256(path: str) -> str:
    h = sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _standard_verified(library: Mapping[str, Any], standard: str, edition: str) -> bool:
    return any(
        str(x.get("standard")) == standard
        and str(x.get("edition")) == edition
        and x.get("metadata_status") == "VERIFIED"
        for x in (library.get("standards", []) or [])
    )


def source_authorization_payload(source: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        "source_id": source.get("source_id"),
        "kind": source.get("kind"),
        "title": source.get("title"),
        "standard": source.get("standard"),
        "edition": source.get("edition"),
        "location": source.get("location"),
        "evidence_hash": source.get("evidence_hash"),
    }


def authorize_source(
    library: Mapping[str, Any],
    source: Mapping[str, Any],
    engineer: str,
    authorized_at: str,
    evidence_path: str,
    notes: str | None = None,
) -> Dict[str, Any]:
    if not engineer.strip() or not authorized_at.strip():
        raise StarkValidationError("Engineer and authorization timestamp are required")
    for field in ("source_id", "kind", "standard", "edition", "location"):
        if not source.get(field):
            raise StarkValidationError(f"Authorized source missing {field}")
    if not _standard_verified(library, str(source["standard"]), str(source["edition"])):
        raise StarkValidationError("Source standard/edition is not VERIFIED in library metadata")
    actual = file_sha256(evidence_path)
    declared = source.get("evidence_hash")
    if declared and str(declared) != actual:
        raise StarkValidationError("Evidence hash mismatch during source authorization")

    lib = deepcopy(library)
    sources = lib.setdefault("authorized_sources", [])
    sid = str(source["source_id"])
    existing = [x for x in sources if x.get("source_id") == sid]
    if existing and existing[0].get("status") == "AUTHORIZED":
        raise StarkValidationError(f"Source {sid} is already authorized; use a new source revision")
    record = dict(source)
    record["evidence_hash"] = actual
    record["status"] = "AUTHORIZED"
    record["authorization"] = {
        "status": "AUTHORIZED",
        "engineer": engineer,
        "authorized_at": authorized_at,
        "approved_digest": canonical_hash(source_authorization_payload(record)),
        "notes": notes,
    }
    if existing:
        idx = sources.index(existing[0]); sources[idx] = record
    else:
        sources.append(record)
    return lib


def source_integrity_findings(library: Mapping[str, Any], source_id: str, evidence_path: str | None = None) -> List[Finding]:
    matches = [x for x in (library.get("authorized_sources", []) or []) if x.get("source_id") == source_id]
    if not matches:
        return [Finding("INGEST_SOURCE_UNKNOWN", "CRITICAL", f"Unknown source {source_id}", True)]
    if len(matches) > 1:
        return [Finding("INGEST_SOURCE_DUPLICATE", "CRITICAL", f"Duplicate source {source_id}", True)]
    source = matches[0]
    findings: List[Finding] = []
    if source.get("status") != "AUTHORIZED":
        findings.append(Finding("INGEST_SOURCE_NOT_AUTHORIZED", "CRITICAL", f"Source {source_id} is not AUTHORIZED", True))
    auth = source.get("authorization", {}) or {}
    if auth:
        expected = canonical_hash(source_authorization_payload(source))
        if auth.get("approved_digest") != expected:
            findings.append(Finding("INGEST_SOURCE_TAMPERED_AFTER_AUTHORIZATION", "CRITICAL", f"Source {source_id} metadata differs from approved digest", True))
    if evidence_path:
        actual = file_sha256(evidence_path)
        if source.get("evidence_hash") != actual:
            findings.append(Finding("INGEST_EVIDENCE_HASH_MISMATCH", "CRITICAL", f"Source {source_id} evidence file hash mismatch", True))
    return findings


def _collection_for(item_type: str) -> tuple[str, str]:
    if item_type == "PARAMETER": return "parameters", "parameter_id"
    if item_type == "FORMULA": return "formulas", "formula_id"
    if item_type == "RISK_MODEL": return "risk_models", "risk_model_id"
    raise StarkValidationError(f"Unsupported item type: {item_type}")


def _prepare_item(item_type: str, item: Mapping[str, Any], source: Mapping[str, Any]) -> Dict[str, Any]:
    collection, id_field = _collection_for(item_type)
    if not item.get(id_field):
        raise StarkValidationError(f"{item_type} missing {id_field}")
    if not item.get("locator"):
        raise StarkValidationError(f"{item[id_field]}: exact source locator is required")
    out = {k: v for k, v in item.items() if k != "locator"}
    out["status"] = "PENDING_ENGINEER_VALIDATION"
    out["source"] = {
        "source_id": source["source_id"],
        "standard": source["standard"],
        "edition": source["edition"],
        "part": item.get("part"),
        "locator": item["locator"],
        "evidence_hash": source.get("evidence_hash"),
    }
    out["validation"] = {
        "status": "PENDING", "engineer": None, "validated_at": None,
        "approved_digest": None, "notes": None,
    }
    return out


def ingest_package(
    library: Mapping[str, Any], package: Mapping[str, Any], evidence_path: str | None = None
) -> tuple[Dict[str, Any], Dict[str, Any]]:
    """Stage a controlled intake package. No technical item is auto-approved."""
    for field in ("package_id", "source_id", "standard", "edition", "items"):
        if field not in package:
            raise StarkValidationError(f"Ingestion package missing {field}")
    source_id = str(package["source_id"])
    findings = source_integrity_findings(library, source_id, evidence_path)
    if any(f.blocking for f in findings):
        raise StarkValidationError("; ".join(f.message for f in findings if f.blocking))
    source = next(x for x in library.get("authorized_sources", []) if x.get("source_id") == source_id)
    if str(package["standard"]) != str(source.get("standard")) or str(package["edition"]) != str(source.get("edition")):
        raise StarkValidationError("Package standard/edition differs from authorized source")

    lib = deepcopy(library)
    staged: List[Dict[str, str]] = []
    for entry in package.get("items", []):
        item_type = str(entry.get("item_type", ""))
        if item_type not in ALLOWED_ITEM_TYPES:
            raise StarkValidationError(f"Unsupported item_type {item_type}")
        collection, id_field = _collection_for(item_type)
        prepared = _prepare_item(item_type, entry.get("item", {}) or {}, source)
        item_id = str(prepared[id_field])
        if any(x.get(id_field) == item_id for x in (lib.get(collection, []) or [])):
            raise StarkValidationError(f"Duplicate normative identifier {item_id}; create an explicit revision instead of overwriting")
        lib.setdefault(collection, []).append(prepared)
        staged.append({"item_type": item_type, "item_id": item_id, "status": "PENDING_ENGINEER_VALIDATION"})

    lib["state"] = "PARAMETERS_PENDING_VALIDATION"
    report = {
        "pipeline": f"STARK_CONTROLLED_INGESTION_{INGESTION_VERSION}",
        "package_id": package["package_id"],
        "source_id": source_id,
        "evidence_hash": source.get("evidence_hash"),
        "staged_items": staged,
        "auto_validated_items": 0,
        "status": "STAGED_PENDING_ENGINEER_VALIDATION",
        "trace_hash": canonical_hash({"package": package, "source_digest": source.get("authorization", {}).get("approved_digest"), "staged": staged}),
    }
    return lib, report
