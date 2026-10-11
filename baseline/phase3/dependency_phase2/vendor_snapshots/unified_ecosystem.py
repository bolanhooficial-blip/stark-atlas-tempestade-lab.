from __future__ import annotations

"""Unified STARK–TEMPESTADE–ATLAS control plane with preserved engine autonomy."""

from dataclasses import dataclass
from typing import Any, Callable, Mapping

from ecosystem_eicf import EcosystemIntegrityFabric, SignedEnvelope


@dataclass
class EngineAdapter:
    engine_id: str
    handler: Callable[[Mapping[str, Any]], Mapping[str, Any]] | None = None

    @property
    def bound(self) -> bool:
        return self.handler is not None

    def execute(self, command: Mapping[str, Any]) -> Mapping[str, Any]:
        if self.handler is None:
            raise RuntimeError(f"ENGINE_RUNTIME_NOT_BOUND:{self.engine_id}")
        return self.handler(command)


class UnifiedEcosystem:
    """One operational ecosystem, three independently bounded engines.

    This object does not merge engine logic. It centralizes routing and canonical
    state while each engine remains behind its own firewall and capability set.
    """

    def __init__(self, fabric: EcosystemIntegrityFabric) -> None:
        self.fabric = fabric
        self.adapters: dict[str, EngineAdapter] = {
            "STARK": EngineAdapter("STARK"),
            "TEMPESTADE": EngineAdapter("TEMPESTADE"),
            "ATLAS": EngineAdapter("ATLAS"),
        }

    def bind(self, engine_id: str, handler: Callable[[Mapping[str, Any]], Mapping[str, Any]]) -> None:
        if engine_id not in self.adapters:
            raise KeyError(f"UNKNOWN_ENGINE:{engine_id}")
        self.adapters[engine_id].handler = handler

    def send_command(
        self, *, source_engine: str, destination_engine: str, project_id: str, revision: str,
        payload: Mapping[str, Any], dependency_fingerprint: str = "NONE"
    ) -> Mapping[str, Any]:
        envelope = self.fabric.sign_envelope(
            source_engine=source_engine,
            destination_engine=destination_engine,
            project_id=project_id,
            revision=revision,
            message_type="COMMAND",
            capability="ROUTE" if source_engine == "CONTROL_PLANE" else "PROPOSE_TECHNICAL_STATE",
            payload=payload,
            dependency_fingerprint=dependency_fingerprint,
        )
        self.fabric.route(envelope)
        adapter = self.adapters.get(destination_engine)
        if adapter is None:
            raise RuntimeError(f"DESTINATION_NOT_EXECUTABLE_ENGINE:{destination_engine}")
        return adapter.execute(payload)

    def runtime_status(self) -> dict[str, str]:
        return {k: ("BOUND" if a.bound else "LOGICAL_ADAPTER_ONLY") for k, a in self.adapters.items()}
