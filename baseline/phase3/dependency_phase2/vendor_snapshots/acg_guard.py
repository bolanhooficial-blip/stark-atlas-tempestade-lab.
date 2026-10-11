
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, Set, Tuple
import hashlib, json, copy

PROTECTED = {
    "NORMATIVE_CORE","TEIL_CORE","EICF_CORE","STARK_GOVERNANCE",
    "ATLAS_LIBRARY","APPROVED_BASELINES","EXISTING_LOCKS",
    "QUALIFIED_FORMULAS","IMMUTABLE_AUDIT_HISTORY"
}

VALID_MEMORY_TYPES = {"NORMATIVE_MEMORY","PROJECT_MEMORY","EXPERIENCE_MEMORY","OPERATIONAL_MEMORY"}

def fingerprint(obj: Any) -> str:
    return hashlib.sha256(json.dumps(obj,sort_keys=True,ensure_ascii=False,separators=(",",":")).encode()).hexdigest()

@dataclass
class ProjectCell:
    project_id: str
    revision: str
    domain: str
    normative_profile: str
    raw_hash: str
    state: Dict[str,Any] = field(default_factory=dict)
    audit: list = field(default_factory=list)

class ACG:
    def __init__(self):
        self.cells: Dict[Tuple[str,str], ProjectCell] = {}
        self.knowledge: Dict[str,Dict[str,Any]] = {}
        self.checkpoints: Dict[str,Any] = {}
        self.processed: Set[str] = set()

    def create_cell(self, project_id, revision, domain, normative_profile, raw_hash):
        key=(project_id,revision)
        if key in self.cells:
            return self.cells[key]
        c=ProjectCell(project_id,revision,domain,normative_profile,raw_hash)
        self.cells[key]=c
        return c

    def deny_protected_write(self, target):
        if target in PROTECTED:
            raise PermissionError("NO_LEARNING_TO_CORE_WRITE")

    def assert_memory_type(self, memory_type):
        if memory_type not in VALID_MEMORY_TYPES:
            raise ValueError("MEMORY_TYPE_INTEGRITY")

    def context_match(self, candidate, target):
        return all(candidate.get(k)==target.get(k) for k in ("domain","normative_profile"))

    def begin_tx(self, cell):
        return copy.deepcopy(cell.state)

    def rollback(self, cell, snapshot):
        cell.state = snapshot
        cell.audit.append({"event":"ROLLBACK"})

    def commit(self, cell):
        cell.audit.append({"event":"COMMIT","state_fingerprint":fingerprint(cell.state)})

    def process_once(self, payload):
        fp=fingerprint(payload)
        if fp in self.processed:
            return {"status":"ALREADY_PROCESSED","fingerprint":fp}
        self.processed.add(fp)
        return {"status":"ACCEPTED","fingerprint":fp}

    def promote_candidate(self, candidate, target_context):
        if candidate.get("lineage") in (None,[],{}):
            return {"status":"BLOCKED","reason":"NO_LINEAGE"}
        if candidate.get("state") in {"REVOKED","STALE","QUARANTINED","REJECTED_KNOWLEDGE"}:
            return {"status":"BLOCKED","reason":"INVALID_KNOWLEDGE_STATE"}
        if not self.context_match(candidate, target_context):
            return {"status":"BLOCKED","reason":"NO_CONTEXT_MATCH"}
        if candidate.get("memory_type")!="EXPERIENCE_MEMORY":
            return {"status":"BLOCKED","reason":"MEMORY_TYPE_MISMATCH"}
        kid=candidate["knowledge_id"]
        self.knowledge[kid]=copy.deepcopy(candidate)
        return {"status":"VALIDATED_EXPERIENCE","knowledge_id":kid}
