from __future__ import annotations

"""EICF — Ecosystem Internal Containment Fabric.

Reference executable security/containment core for the STARK–TEMPESTADE–ATLAS
unified ecosystem. This module is intentionally orthogonal to engineering logic:
it authenticates, isolates, versions and gates inter-engine state changes, but it
does not decide engineering correctness.

Security posture:
- zero trust between engines;
- project-cell isolation;
- least-privilege capabilities;
- signed immutable envelopes (Ed25519);
- encrypted project-state snapshots (AES-256-GCM);
- append-only hash-chained event ledger;
- replay protection and semantic fingerprinting;
- local engine firewalls / bulkheads;
- SAFE_FREEZE on integrity failure;
- independent checkpoint signatures;
- no critical-gate bypass.

The included LocalKeyProvider is a reference/test provider only. Production use
must replace it with a persistent KMS/HSM-backed provider and durable storage.
"""

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from hashlib import sha256
from typing import Any, Callable, Iterable, Mapping, MutableMapping
import base64
import json
import os
import secrets

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

EICF_VERSION = "1.0.0"
ECL_VERSION = "1.0"


class EICFError(RuntimeError):
    pass


class IntegrityViolation(EICFError):
    pass


class AuthorizationViolation(EICFError):
    pass


class ProjectIsolationViolation(EICFError):
    pass


class ReplayViolation(EICFError):
    pass


class SafeFreezeError(EICFError):
    pass


class StateTransitionViolation(EICFError):
    pass


class CheckpointViolation(EICFError):
    pass


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def digest(value: Any) -> str:
    return sha256(_canonical(value)).hexdigest()


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


@dataclass(frozen=True)
class EnginePolicy:
    engine_id: str
    version: str
    capabilities: tuple[str, ...]
    accepted_sources: tuple[str, ...]
    accepted_message_types: tuple[str, ...]
    runtime_binding: str = "LOGICAL_ADAPTER_ONLY"


@dataclass(frozen=True)
class SignedEnvelope:
    eicf_version: str
    ecl_version: str
    message_id: str
    source_engine: str
    source_version: str
    destination_engine: str
    project_id: str
    revision: str
    message_type: str
    capability: str
    payload: Mapping[str, Any]
    dependency_fingerprint: str
    semantic_fingerprint: str
    payload_hash: str
    timestamp_utc: str
    signature_b64: str

    def signing_payload(self) -> dict[str, Any]:
        d = asdict(self)
        d.pop("signature_b64", None)
        return d

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class LedgerEvent:
    event_index: int
    event_id: str
    project_id: str
    revision: str
    source_engine: str
    message_type: str
    capability: str
    payload_hash: str
    envelope_fingerprint: str
    previous_event_hash: str | None
    event_hash: str
    timestamp_utc: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class Checkpoint:
    checkpoint_id: str
    project_id: str
    revision: str
    ledger_head_hash: str | None
    state_digest: str
    signer_id: str
    timestamp_utc: str
    signature_b64: str

    def signing_payload(self) -> dict[str, Any]:
        d = asdict(self)
        d.pop("signature_b64", None)
        return d

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class LocalKeyProvider:
    """Reference key provider. Not a production KMS/HSM.

    Keys live only in the current process. It is suitable for tests, shadow mode
    and executable architecture qualification. It is intentionally explicit so
    nobody can mistake it for production key custody.
    """

    def __init__(self) -> None:
        self._signing: dict[str, Ed25519PrivateKey] = {}
        self._data_keys: dict[str, bytes] = {}

    def ensure_identity(self, identity: str) -> None:
        if identity not in self._signing:
            self._signing[identity] = Ed25519PrivateKey.generate()

    def public_key_bytes(self, identity: str) -> bytes:
        self.ensure_identity(identity)
        return self._signing[identity].public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    def public_key_fingerprint(self, identity: str) -> str:
        return sha256(self.public_key_bytes(identity)).hexdigest()

    def sign(self, identity: str, payload: bytes) -> bytes:
        self.ensure_identity(identity)
        return self._signing[identity].sign(payload)

    def verify(self, identity: str, payload: bytes, signature: bytes) -> bool:
        self.ensure_identity(identity)
        try:
            self._signing[identity].public_key().verify(signature, payload)
            return True
        except InvalidSignature:
            return False

    def project_data_key(self, project_id: str) -> bytes:
        if project_id not in self._data_keys:
            self._data_keys[project_id] = AESGCM.generate_key(bit_length=256)
        return self._data_keys[project_id]


class ProjectCell:
    """Isolation boundary for one project.

    The cell owns its ledger, replay cache and encrypted state snapshot. It does
    not expose mutable cross-project state.
    """

    def __init__(self, project_id: str, revision: str, key_provider: LocalKeyProvider) -> None:
        if not project_id or not revision:
            raise ValueError("PROJECT_ID_AND_REVISION_REQUIRED")
        self.project_id = project_id
        self.revision = revision
        self._keys = key_provider
        self._ledger: list[LedgerEvent] = []
        self._seen_message_ids: set[str] = set()
        self._state: dict[str, Any] = {
            "project_id": project_id,
            "revision": revision,
            "status": "ACTIVE",
            "facts": {},
            "engine_outputs": {},
            "blocks": [],
            "dependencies": {},
            "stale_objects": [],
            "delivery_state": "NOT_RELEASED",
        }
        self.safe_freeze = False
        self.freeze_reason: str | None = None

    @property
    def ledger(self) -> tuple[LedgerEvent, ...]:
        return tuple(self._ledger)

    @property
    def state(self) -> Mapping[str, Any]:
        # deep copy through canonical JSON prevents caller mutation.
        return json.loads(json.dumps(self._state, ensure_ascii=False, default=str))

    @property
    def head_hash(self) -> str | None:
        return self._ledger[-1].event_hash if self._ledger else None

    def assert_message_unused(self, message_id: str) -> None:
        if message_id in self._seen_message_ids:
            raise ReplayViolation(f"REPLAY_DETECTED:{message_id}")

    def mark_message_used(self, message_id: str) -> None:
        self.assert_message_unused(message_id)
        self._seen_message_ids.add(message_id)

    def freeze(self, reason: str) -> None:
        self.safe_freeze = True
        self.freeze_reason = reason
        self._state["status"] = "SAFE_FREEZE"

    def unfreeze(self, reason: str) -> None:
        # Recovery itself is explicit and auditable at fabric level.
        self.safe_freeze = False
        self.freeze_reason = None
        self._state["status"] = "ACTIVE"
        self._state.setdefault("recovery_notes", []).append(reason)

    def append_event(self, envelope: SignedEnvelope) -> LedgerEvent:
        if self.safe_freeze and envelope.message_type not in {"RECOVERY", "CHECKPOINT", "FREEZE"}:
            raise SafeFreezeError(f"PROJECT_SAFE_FREEZE:{self.project_id}:{self.freeze_reason}")
        self.mark_message_used(envelope.message_id)
        previous = self.head_hash
        base = {
            "event_index": len(self._ledger) + 1,
            "event_id": "EVT-" + digest({"message_id": envelope.message_id, "ordinal": len(self._ledger) + 1})[:20].upper(),
            "project_id": self.project_id,
            "revision": self.revision,
            "source_engine": envelope.source_engine,
            "message_type": envelope.message_type,
            "capability": envelope.capability,
            "payload_hash": envelope.payload_hash,
            "envelope_fingerprint": digest(envelope.to_dict()),
            "previous_event_hash": previous,
            "timestamp_utc": _utc_now(),
        }
        event_hash = digest(base)
        event = LedgerEvent(**base, event_hash=event_hash)
        self._ledger.append(event)
        return event

    def mutate_state_from_committed_event(self, envelope: SignedEnvelope) -> None:
        """Apply only a small canonical state schema after gateway approval."""
        p = dict(envelope.payload)
        mt = envelope.message_type
        if mt == "REGISTER_INPUT_SET":
            self._state["input_set_fingerprint"] = p.get("input_set_fingerprint")
            self._state["input_count"] = p.get("input_count")
        elif mt == "ENGINE_OUTPUT":
            self._state.setdefault("engine_outputs", {})[envelope.source_engine] = {
                "output_id": p.get("output_id"),
                "status": p.get("status"),
                "payload_hash": envelope.payload_hash,
                "semantic_fingerprint": envelope.semantic_fingerprint,
            }
        elif mt == "BLOCK":
            block = {
                "code": p.get("code"),
                "source": envelope.source_engine,
                "detail": p.get("detail"),
                "payload_hash": envelope.payload_hash,
            }
            if block not in self._state.setdefault("blocks", []):
                self._state["blocks"].append(block)
        elif mt == "STALE":
            self.mark_stale_transitively(p.get("object_ids", []))
        elif mt == "DELIVERY_CANDIDATE":
            self._state["delivery_state"] = str(p.get("status", "PENDING"))
        elif mt == "RECOVERY":
            self._state.setdefault("recovery_notes", []).append(p.get("note"))
        elif mt == "FREEZE":
            self.freeze(str(p.get("reason") or "UNSPECIFIED_INTEGRITY_FAILURE"))

    def register_dependencies(self, object_id: str, depends_on: Iterable[str]) -> None:
        if not object_id:
            raise ValueError("OBJECT_ID_REQUIRED")
        deps = sorted({str(x) for x in depends_on if str(x)})
        if object_id in deps:
            raise IntegrityViolation("SELF_DEPENDENCY_BLOCKED")
        self._state.setdefault("dependencies", {})[object_id] = deps

    def transitive_dependents(self, changed_ids: Iterable[str]) -> set[str]:
        changed = {str(x) for x in changed_ids}
        reverse: dict[str, set[str]] = {}
        for obj, deps in self._state.get("dependencies", {}).items():
            for dep in deps:
                reverse.setdefault(dep, set()).add(obj)
        impacted = set(changed)
        queue = list(changed)
        while queue:
            cur = queue.pop(0)
            for dep in reverse.get(cur, set()):
                if dep not in impacted:
                    impacted.add(dep); queue.append(dep)
        return impacted

    def mark_stale_transitively(self, changed_ids: Iterable[str]) -> list[str]:
        impacted = sorted(self.transitive_dependents(changed_ids))
        current = set(self._state.setdefault("stale_objects", []))
        current.update(impacted)
        self._state["stale_objects"] = sorted(current)
        return impacted

    def encrypted_state_snapshot(self) -> dict[str, Any]:
        key = self._keys.project_data_key(self.project_id)
        nonce = os.urandom(12)
        aad = _canonical({"project_id": self.project_id, "revision": self.revision, "eicf_version": EICF_VERSION})
        plaintext = _canonical(self._state)
        ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
        return {
            "algorithm": "AES-256-GCM",
            "project_id": self.project_id,
            "revision": self.revision,
            "aad_hash": sha256(aad).hexdigest(),
            "nonce_b64": _b64(nonce),
            "ciphertext_b64": _b64(ciphertext),
            "plaintext_digest": sha256(plaintext).hexdigest(),
        }

    def decrypt_state_snapshot(self, snapshot: Mapping[str, Any]) -> Mapping[str, Any]:
        if snapshot.get("project_id") != self.project_id or snapshot.get("revision") != self.revision:
            raise ProjectIsolationViolation("SNAPSHOT_PROJECT_OR_REVISION_MISMATCH")
        key = self._keys.project_data_key(self.project_id)
        aad = _canonical({"project_id": self.project_id, "revision": self.revision, "eicf_version": EICF_VERSION})
        if sha256(aad).hexdigest() != snapshot.get("aad_hash"):
            raise IntegrityViolation("SNAPSHOT_AAD_HASH_MISMATCH")
        try:
            plain = AESGCM(key).decrypt(_unb64(str(snapshot["nonce_b64"])), _unb64(str(snapshot["ciphertext_b64"])), aad)
        except Exception as exc:
            raise IntegrityViolation("SNAPSHOT_DECRYPT_OR_AUTH_FAILURE") from exc
        if sha256(plain).hexdigest() != snapshot.get("plaintext_digest"):
            raise IntegrityViolation("SNAPSHOT_PLAINTEXT_DIGEST_MISMATCH")
        return json.loads(plain.decode("utf-8"))

    def verify_ledger(self) -> bool:
        prev = None
        for i, ev in enumerate(self._ledger, 1):
            if ev.event_index != i or ev.previous_event_hash != prev:
                return False
            base = ev.to_dict()
            supplied = base.pop("event_hash")
            if digest(base) != supplied:
                return False
            prev = supplied
        return True


class EngineFirewall:
    """Local firewall/bulkhead protecting one engine boundary."""

    def __init__(self, policy: EnginePolicy, keys: LocalKeyProvider) -> None:
        self.policy = policy
        self._keys = keys
        self.rejected: list[dict[str, Any]] = []
        self.accepted: list[str] = []
        self.circuit_open = False

    def open_circuit(self, reason: str) -> None:
        self.circuit_open = True
        self.rejected.append({"code": "ENGINE_CIRCUIT_OPEN", "reason": reason, "timestamp_utc": _utc_now()})

    def reset_circuit(self) -> None:
        self.circuit_open = False

    def validate(self, envelope: SignedEnvelope, *, project_id: str, revision: str) -> None:
        if self.circuit_open:
            raise SafeFreezeError(f"ENGINE_CIRCUIT_OPEN:{self.policy.engine_id}")
        if envelope.destination_engine != self.policy.engine_id:
            raise AuthorizationViolation("DESTINATION_ENGINE_MISMATCH")
        if envelope.project_id != project_id:
            raise ProjectIsolationViolation("CROSS_PROJECT_MESSAGE_BLOCKED")
        if envelope.revision != revision:
            raise ProjectIsolationViolation("REVISION_MISMATCH_BLOCKED")
        if envelope.source_engine not in self.policy.accepted_sources:
            raise AuthorizationViolation(f"SOURCE_NOT_ALLOWED:{envelope.source_engine}->{self.policy.engine_id}")
        if envelope.message_type not in self.policy.accepted_message_types:
            raise AuthorizationViolation(f"MESSAGE_TYPE_NOT_ALLOWED:{envelope.message_type}")
        if envelope.payload_hash != digest(envelope.payload):
            raise IntegrityViolation("PAYLOAD_HASH_MISMATCH")
        expected_semantic = digest({
            "project_id": envelope.project_id,
            "revision": envelope.revision,
            "source_engine": envelope.source_engine,
            "destination_engine": envelope.destination_engine,
            "message_type": envelope.message_type,
            "capability": envelope.capability,
            "dependency_fingerprint": envelope.dependency_fingerprint,
            "payload_hash": envelope.payload_hash,
        })
        if expected_semantic != envelope.semantic_fingerprint:
            raise IntegrityViolation("SEMANTIC_FINGERPRINT_MISMATCH")
        if not self._keys.verify(envelope.source_engine, _canonical(envelope.signing_payload()), _unb64(envelope.signature_b64)):
            raise IntegrityViolation("INVALID_ENGINE_SIGNATURE")
        self.accepted.append(envelope.message_id)


class StateChangeGateway:
    """Sole writer of canonical project state.

    Engines can propose changes, never write state directly. The gateway checks
    source capability, signature, project/revision, replay, allowed transitions
    and SAFE_FREEZE before committing to the append-only ledger.
    """

    _MESSAGE_CAPABILITIES: dict[str, tuple[str, ...]] = {
        "REGISTER_INPUT_SET": ("REGISTER_INPUT",),
        "ENGINE_OUTPUT": ("PROPOSE_TECHNICAL_STATE", "PROPOSE_GRAPHICAL_STATE", "PROPOSE_RISK_STATE"),
        "BLOCK": ("RAISE_BLOCK",),
        "STALE": ("MARK_STALE",),
        "DELIVERY_CANDIDATE": ("PROPOSE_DELIVERY",),
        "FREEZE": ("FREEZE",),
        "RECOVERY": ("RECOVER",),
        "CHECKPOINT": ("CHECKPOINT",),
    }

    def __init__(self, keys: LocalKeyProvider, policies: Mapping[str, EnginePolicy]) -> None:
        self._keys = keys
        self._policies = dict(policies)
        self.audit: list[dict[str, Any]] = []

    def _verify_source_authority(self, envelope: SignedEnvelope) -> None:
        pol = self._policies.get(envelope.source_engine)
        if pol is None:
            raise AuthorizationViolation(f"UNKNOWN_SOURCE_ENGINE:{envelope.source_engine}")
        if envelope.source_version != pol.version:
            raise IntegrityViolation(f"SOURCE_VERSION_MISMATCH:{envelope.source_engine}")
        allowed_for_type = self._MESSAGE_CAPABILITIES.get(envelope.message_type, ())
        if envelope.capability not in allowed_for_type:
            raise AuthorizationViolation(f"CAPABILITY_NOT_VALID_FOR_MESSAGE:{envelope.capability}:{envelope.message_type}")
        if envelope.capability not in pol.capabilities:
            raise AuthorizationViolation(f"SOURCE_LACKS_CAPABILITY:{envelope.source_engine}:{envelope.capability}")

    def commit(self, cell: ProjectCell, envelope: SignedEnvelope) -> LedgerEvent:
        if envelope.destination_engine != "STATE_GATEWAY":
            raise AuthorizationViolation("STATE_CHANGE_MUST_TARGET_GATEWAY")
        if envelope.project_id != cell.project_id or envelope.revision != cell.revision:
            raise ProjectIsolationViolation("STATE_GATEWAY_PROJECT_OR_REVISION_MISMATCH")
        self._verify_source_authority(envelope)
        if envelope.payload_hash != digest(envelope.payload):
            raise IntegrityViolation("STATE_GATEWAY_PAYLOAD_HASH_MISMATCH")
        expected_semantic = digest({
            "project_id": envelope.project_id,
            "revision": envelope.revision,
            "source_engine": envelope.source_engine,
            "destination_engine": envelope.destination_engine,
            "message_type": envelope.message_type,
            "capability": envelope.capability,
            "dependency_fingerprint": envelope.dependency_fingerprint,
            "payload_hash": envelope.payload_hash,
        })
        if envelope.semantic_fingerprint != expected_semantic:
            raise IntegrityViolation("STATE_GATEWAY_SEMANTIC_FINGERPRINT_MISMATCH")
        if not self._keys.verify(envelope.source_engine, _canonical(envelope.signing_payload()), _unb64(envelope.signature_b64)):
            raise IntegrityViolation("STATE_GATEWAY_SIGNATURE_INVALID")
        cell.assert_message_unused(envelope.message_id)
        if cell.safe_freeze and envelope.message_type not in {"RECOVERY", "CHECKPOINT", "FREEZE"}:
            raise SafeFreezeError("STATE_GATEWAY_PROJECT_FROZEN")
        event = cell.append_event(envelope)
        cell.mutate_state_from_committed_event(envelope)
        self.audit.append({
            "decision": "COMMIT",
            "event_id": event.event_id,
            "message_id": envelope.message_id,
            "project_id": cell.project_id,
            "source_engine": envelope.source_engine,
            "message_type": envelope.message_type,
            "timestamp_utc": _utc_now(),
        })
        return event


class EcosystemIntegrityFabric:
    """Unified containment fabric; engines remain independent bounded contexts."""

    def __init__(self, *, keys: LocalKeyProvider | None = None, mode: str = "ENFORCE") -> None:
        if mode not in {"ENFORCE", "SHADOW"}:
            raise ValueError("EICF_MODE_MUST_BE_ENFORCE_OR_SHADOW")
        self.mode = mode
        self.keys = keys or LocalKeyProvider()
        self.checkpoint_keys = LocalKeyProvider()
        self.checkpoint_keys.ensure_identity("CHECKPOINT_AUTHORITY")
        self.policies: dict[str, EnginePolicy] = {}
        self.firewalls: dict[str, EngineFirewall] = {}
        self.cells: dict[str, ProjectCell] = {}
        self.gateway: StateChangeGateway | None = None
        self.findings: list[dict[str, Any]] = []
        self.checkpoints: dict[str, list[Checkpoint]] = {}
        self._install_default_policies()

    def _install_default_policies(self) -> None:
        all_sources = ("CONTROL_PLANE", "STARK", "TEMPESTADE", "ATLAS", "C9_AUDITOR", "DELIVERY_GATE", "CHECKPOINT_AUTHORITY")
        self.register_engine(EnginePolicy(
            "CONTROL_PLANE", "1.0", ("ROUTE", "REGISTER_INPUT", "FREEZE", "RECOVER"),
            accepted_sources=all_sources,
            accepted_message_types=("ACK", "NACK", "STATUS"),
            runtime_binding="BOUND_TO_UNIFIED_ORCHESTRATOR",
        ))
        self.register_engine(EnginePolicy(
            "STARK", "1.0", ("PROPOSE_TECHNICAL_STATE", "RAISE_BLOCK", "MARK_STALE"),
            accepted_sources=("CONTROL_PLANE", "TEMPESTADE", "ATLAS", "C9_AUDITOR"),
            accepted_message_types=("COMMAND", "ENGINE_OUTPUT", "BLOCK", "STALE", "STATUS"),
            runtime_binding="BOUND_TO_STARK_ORCHESTRATOR",
        ))
        self.register_engine(EnginePolicy(
            "TEMPESTADE", "1.0", ("PROPOSE_RISK_STATE", "RAISE_BLOCK", "MARK_STALE"),
            accepted_sources=("CONTROL_PLANE", "STARK", "C9_AUDITOR"),
            accepted_message_types=("COMMAND", "ENGINE_OUTPUT", "BLOCK", "STALE", "STATUS"),
            runtime_binding="LOGICAL_ADAPTER_ONLY",
        ))
        self.register_engine(EnginePolicy(
            "ATLAS", "1.0", ("PROPOSE_GRAPHICAL_STATE", "RAISE_BLOCK", "MARK_STALE"),
            accepted_sources=("CONTROL_PLANE", "STARK", "TEMPESTADE", "C9_AUDITOR"),
            accepted_message_types=("COMMAND", "ENGINE_OUTPUT", "BLOCK", "STALE", "STATUS"),
            runtime_binding="LOGICAL_ADAPTER_ONLY",
        ))
        self.register_engine(EnginePolicy(
            "C9_AUDITOR", "1.0", ("RAISE_BLOCK", "MARK_STALE"),
            accepted_sources=("CONTROL_PLANE", "STARK", "TEMPESTADE", "ATLAS"),
            accepted_message_types=("ENGINE_OUTPUT", "STATUS", "COMMAND"),
            runtime_binding="LOGICAL_AUDIT_BOUNDARY",
        ))
        self.register_engine(EnginePolicy(
            "DELIVERY_GATE", "1.0", ("PROPOSE_DELIVERY", "RAISE_BLOCK"),
            accepted_sources=("CONTROL_PLANE", "STARK", "TEMPESTADE", "ATLAS", "C9_AUDITOR"),
            accepted_message_types=("ENGINE_OUTPUT", "STATUS", "COMMAND"),
            runtime_binding="BOUND_TO_UNIFIED_ORCHESTRATOR",
        ))
        self.register_engine(EnginePolicy(
            "CHECKPOINT_AUTHORITY", "1.0", ("CHECKPOINT",),
            accepted_sources=all_sources,
            accepted_message_types=("STATUS",),
            runtime_binding="INDEPENDENT_REFERENCE_CHECKPOINT",
        ))
        self.gateway = StateChangeGateway(self.keys, self.policies)

    def register_engine(self, policy: EnginePolicy) -> None:
        if not policy.engine_id or not policy.version:
            raise ValueError("INVALID_ENGINE_POLICY")
        self.keys.ensure_identity(policy.engine_id)
        self.policies[policy.engine_id] = policy
        self.firewalls[policy.engine_id] = EngineFirewall(policy, self.keys)

    def create_cell(self, project_id: str, revision: str) -> ProjectCell:
        if project_id in self.cells:
            cell = self.cells[project_id]
            if cell.revision != revision:
                raise ProjectIsolationViolation("PROJECT_CELL_REVISION_ALREADY_BOUND")
            return cell
        cell = ProjectCell(project_id, revision, self.keys)
        self.cells[project_id] = cell
        return cell

    def cell(self, project_id: str) -> ProjectCell:
        try:
            return self.cells[project_id]
        except KeyError as exc:
            raise ProjectIsolationViolation(f"UNKNOWN_PROJECT_CELL:{project_id}") from exc

    def sign_envelope(
        self,
        *,
        source_engine: str,
        destination_engine: str,
        project_id: str,
        revision: str,
        message_type: str,
        capability: str,
        payload: Mapping[str, Any],
        dependency_fingerprint: str = "NONE",
        message_id: str | None = None,
    ) -> SignedEnvelope:
        if source_engine not in self.policies or destination_engine not in {*self.policies, "STATE_GATEWAY"}:
            raise AuthorizationViolation("UNKNOWN_SOURCE_OR_DESTINATION")
        pol = self.policies[source_engine]
        if capability not in pol.capabilities:
            raise AuthorizationViolation(f"SOURCE_LACKS_CAPABILITY:{source_engine}:{capability}")
        payload_hash = digest(payload)
        semantic = digest({
            "project_id": project_id,
            "revision": revision,
            "source_engine": source_engine,
            "destination_engine": destination_engine,
            "message_type": message_type,
            "capability": capability,
            "dependency_fingerprint": dependency_fingerprint,
            "payload_hash": payload_hash,
        })
        msg_id = message_id or "MSG-" + secrets.token_hex(12).upper()
        unsigned = {
            "eicf_version": EICF_VERSION,
            "ecl_version": ECL_VERSION,
            "message_id": msg_id,
            "source_engine": source_engine,
            "source_version": pol.version,
            "destination_engine": destination_engine,
            "project_id": project_id,
            "revision": revision,
            "message_type": message_type,
            "capability": capability,
            "payload": dict(payload),
            "dependency_fingerprint": dependency_fingerprint,
            "semantic_fingerprint": semantic,
            "payload_hash": payload_hash,
            "timestamp_utc": _utc_now(),
        }
        signature = self.keys.sign(source_engine, _canonical(unsigned))
        return SignedEnvelope(**unsigned, signature_b64=_b64(signature))

    def route(self, envelope: SignedEnvelope) -> str:
        if envelope.destination_engine == "STATE_GATEWAY":
            raise AuthorizationViolation("USE_COMMIT_FOR_STATE_GATEWAY")
        cell = self.cell(envelope.project_id)
        if cell.safe_freeze:
            raise SafeFreezeError("PROJECT_SAFE_FREEZE")
        src_policy = self.policies.get(envelope.source_engine)
        if src_policy is None or envelope.source_version != src_policy.version:
            exc = IntegrityViolation(f"SOURCE_VERSION_MISMATCH:{envelope.source_engine}")
            self.findings.append({"severity":"CRITICAL","code":type(exc).__name__,"detail":str(exc),"project_id":envelope.project_id,"message_id":envelope.message_id,"source":envelope.source_engine,"destination":envelope.destination_engine})
            if self.mode == "ENFORCE": raise exc
            return "SHADOW_REJECTED"
        fw = self.firewalls[envelope.destination_engine]
        try:
            cell.assert_message_unused(envelope.message_id)
            fw.validate(envelope, project_id=cell.project_id, revision=cell.revision)
        except EICFError as exc:
            self.findings.append({
                "severity": "CRITICAL", "code": type(exc).__name__, "detail": str(exc),
                "project_id": envelope.project_id, "message_id": envelope.message_id,
                "source": envelope.source_engine, "destination": envelope.destination_engine,
            })
            if self.mode == "ENFORCE":
                raise
            return "SHADOW_REJECTED"
        cell.mark_message_used(envelope.message_id)
        return "ACCEPTED"

    def commit(self, envelope: SignedEnvelope) -> LedgerEvent | None:
        assert self.gateway is not None
        cell = self.cell(envelope.project_id)
        try:
            return self.gateway.commit(cell, envelope)
        except EICFError as exc:
            self.findings.append({
                "severity": "CRITICAL", "code": type(exc).__name__, "detail": str(exc),
                "project_id": envelope.project_id, "message_id": envelope.message_id,
                "source": envelope.source_engine, "destination": "STATE_GATEWAY",
            })
            if self.mode == "ENFORCE":
                raise
            return None

    def propose_state(
        self,
        *, source_engine: str, project_id: str, revision: str, message_type: str,
        capability: str, payload: Mapping[str, Any], dependency_fingerprint: str = "NONE",
    ) -> LedgerEvent | None:
        env = self.sign_envelope(
            source_engine=source_engine, destination_engine="STATE_GATEWAY",
            project_id=project_id, revision=revision, message_type=message_type,
            capability=capability, payload=payload, dependency_fingerprint=dependency_fingerprint,
        )
        return self.commit(env)

    def register_input_set(self, project_id: str, revision: str, input_hashes: Mapping[str, str]) -> LedgerEvent | None:
        return self.propose_state(
            source_engine="CONTROL_PLANE", project_id=project_id, revision=revision,
            message_type="REGISTER_INPUT_SET", capability="REGISTER_INPUT",
            payload={"input_count": len(input_hashes), "input_set_fingerprint": digest(dict(sorted(input_hashes.items())))},
            dependency_fingerprint=digest(dict(sorted(input_hashes.items()))),
        )

    def raise_block(self, source_engine: str, project_id: str, revision: str, code: str, detail: str) -> LedgerEvent | None:
        return self.propose_state(
            source_engine=source_engine, project_id=project_id, revision=revision,
            message_type="BLOCK", capability="RAISE_BLOCK", payload={"code": code, "detail": detail},
        )

    def register_dependencies(self, project_id: str, object_id: str, depends_on: Iterable[str]) -> None:
        self.cell(project_id).register_dependencies(object_id, depends_on)

    def invalidate_dependency(self, source_engine: str, project_id: str, revision: str, object_ids: Iterable[str], reason: str) -> LedgerEvent | None:
        ids = sorted({str(x) for x in object_ids if str(x)})
        impacted = sorted(self.cell(project_id).transitive_dependents(ids))
        return self.propose_state(
            source_engine=source_engine, project_id=project_id, revision=revision,
            message_type="STALE", capability="MARK_STALE",
            payload={"object_ids": ids, "impacted_objects": impacted, "reason": reason},
            dependency_fingerprint=digest({"changed": ids, "impacted": impacted}),
        )

    def freeze_project(self, project_id: str, revision: str, reason: str) -> LedgerEvent | None:
        return self.propose_state(
            source_engine="CONTROL_PLANE", project_id=project_id, revision=revision,
            message_type="FREEZE", capability="FREEZE", payload={"reason": reason},
        )

    def recover_project(self, project_id: str, revision: str, note: str) -> LedgerEvent | None:
        cell = self.cell(project_id)
        # Recovery is intentionally two-phase: signed event while frozen, then unfreeze.
        event = self.propose_state(
            source_engine="CONTROL_PLANE", project_id=project_id, revision=revision,
            message_type="RECOVERY", capability="RECOVER", payload={"note": note},
        )
        cell.unfreeze(note)
        return event

    def create_checkpoint(self, project_id: str) -> Checkpoint:
        cell = self.cell(project_id)
        payload = {
            "checkpoint_id": "CP-" + secrets.token_hex(10).upper(),
            "project_id": cell.project_id,
            "revision": cell.revision,
            "ledger_head_hash": cell.head_hash,
            "state_digest": digest(cell.state),
            "signer_id": "CHECKPOINT_AUTHORITY",
            "timestamp_utc": _utc_now(),
        }
        sig = self.checkpoint_keys.sign("CHECKPOINT_AUTHORITY", _canonical(payload))
        cp = Checkpoint(**payload, signature_b64=_b64(sig))
        self.checkpoints.setdefault(project_id, []).append(cp)
        return cp

    def verify_checkpoint(self, checkpoint: Checkpoint) -> bool:
        cell = self.cell(checkpoint.project_id)
        if checkpoint.revision != cell.revision:
            return False
        if not self.checkpoint_keys.verify(checkpoint.signer_id, _canonical(checkpoint.signing_payload()), _unb64(checkpoint.signature_b64)):
            return False
        return checkpoint.ledger_head_hash == cell.head_hash and checkpoint.state_digest == digest(cell.state)

    def delivery_precheck(self, project_id: str, revision: str, *, overall_status: str, unresolved_critical: bool) -> dict[str, Any]:
        cell = self.cell(project_id)
        blockers: list[str] = []
        if cell.safe_freeze:
            blockers.append("PROJECT_SAFE_FREEZE")
        if not cell.verify_ledger():
            blockers.append("LEDGER_INTEGRITY_FAILURE")
        if unresolved_critical:
            blockers.append("UNRESOLVED_CRITICAL_BLOCK")
        if cell.state.get("blocks"):
            blockers.append("CANONICAL_STATE_BLOCK_PRESENT")
        if cell.state.get("stale_objects"):
            blockers.append("STALE_DEPENDENCY_PRESENT")
        if any(x.get("severity") == "CRITICAL" for x in self.findings):
            blockers.append("EICF_CRITICAL_FINDING")
        eligible = not blockers and overall_status == "READY_FOR_REGIS_VALIDATION"
        status = "EICF_RELEASE_ELIGIBLE" if eligible else "EICF_DELIVERY_BLOCKED"
        payload = {"status": status, "overall_status": overall_status, "blockers": blockers}
        # SAFE_FREEZE is itself a hard stop: do not mutate canonical state merely
        # to record a delivery attempt while the project is frozen.
        if not cell.safe_freeze:
            self.propose_state(
                source_engine="DELIVERY_GATE", project_id=project_id, revision=revision,
                message_type="DELIVERY_CANDIDATE", capability="PROPOSE_DELIVERY", payload=payload,
                dependency_fingerprint=cell.head_hash or "EMPTY",
            )
        return {"eligible": eligible, **payload}

    def shadow_compare(self, left: Mapping[str, Any], right: Mapping[str, Any], *, ignore_keys: Iterable[str] = ()) -> dict[str, Any]:
        ignore = set(ignore_keys)
        def clean(obj: Any) -> Any:
            if isinstance(obj, Mapping):
                return {k: clean(v) for k, v in obj.items() if k not in ignore}
            if isinstance(obj, list):
                return [clean(x) for x in obj]
            return obj
        a, b = clean(left), clean(right)
        return {
            "equivalent": a == b,
            "left_digest": digest(a),
            "right_digest": digest(b),
            "status": "SHADOW_EQUIVALENT" if a == b else "MIGRATION_DIVERGENCE",
        }

    def snapshot(self, project_id: str) -> dict[str, Any]:
        cell = self.cell(project_id)
        cp = self.create_checkpoint(project_id)
        payload = {
            "eicf_version": EICF_VERSION,
            "ecl_version": ECL_VERSION,
            "mode": self.mode,
            "project_id": cell.project_id,
            "revision": cell.revision,
            "safe_freeze": cell.safe_freeze,
            "freeze_reason": cell.freeze_reason,
            "ledger_valid": cell.verify_ledger(),
            "ledger_head_hash": cell.head_hash,
            "event_count": len(cell.ledger),
            "state_digest": digest(cell.state),
            "encrypted_state_snapshot": cell.encrypted_state_snapshot(),
            "checkpoint": cp.to_dict(),
            "checkpoint_valid": self.verify_checkpoint(cp),
            "checkpoint_public_key_fingerprint": self.checkpoint_keys.public_key_fingerprint("CHECKPOINT_AUTHORITY"),
            "engine_policies": [asdict(self.policies[k]) for k in sorted(self.policies)],
            "engine_public_key_fingerprints": {k: self.keys.public_key_fingerprint(k) for k in sorted(self.policies)},
            "firewall_status": {
                k: {"circuit_open": fw.circuit_open, "accepted_count": len(fw.accepted), "rejected_count": len(fw.rejected)}
                for k, fw in sorted(self.firewalls.items())
            },
            "findings": list(self.findings),
            "policy": {
                "zero_trust_inter_engine": True,
                "project_cell_isolation": True,
                "least_privilege": True,
                "state_gateway_only_writer": True,
                "append_only_hash_chain": True,
                "signed_envelopes_ed25519": True,
                "encrypted_state_aes_256_gcm": True,
                "no_critical_gate_bypass": True,
                "central_failure_safe_freeze": True,
                "local_failure_local_containment": True,
                "local_key_provider_production_qualified": False,
            },
        }
        payload["snapshot_digest"] = digest(payload)
        return payload


def build_reference_fabric(*, project_id: str, revision: str, mode: str = "ENFORCE") -> EcosystemIntegrityFabric:
    fabric = EcosystemIntegrityFabric(mode=mode)
    fabric.create_cell(project_id, revision)
    return fabric
