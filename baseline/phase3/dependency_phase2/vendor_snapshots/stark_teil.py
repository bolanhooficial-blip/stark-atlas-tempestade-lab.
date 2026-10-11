from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from hashlib import sha256
from typing import Any, Callable, Mapping, MutableMapping
import json

TEIL_VERSION = "1.0.0"


class TEILError(RuntimeError):
    """Base exception for fail-closed tool execution integrity failures."""


class ToolContractError(TEILError):
    pass


class ToolExecutionError(TEILError):
    pass


class ToolOutputIntegrityError(TEILError):
    pass


class ToolCircuitOpenError(TEILError):
    pass


@dataclass(frozen=True)
class ToolSpec:
    tool_id: str
    version: str
    operations: tuple[str, ...]
    critical: bool = True
    failure_threshold: int = 3


@dataclass(frozen=True)
class ToolExecutionReceipt:
    teil_version: str
    tool_run_id: str
    tool_id: str
    tool_version: str
    project_id: str
    operation: str
    input_fingerprint: str
    contract_validation: str
    execution_status: str
    output_completeness: str
    critical_warnings: tuple[str, ...]
    output_fingerprint: str | None
    evidence_eligibility: bool
    committed: bool
    timestamp_utc: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ToolExecutionEnvelope:
    output: Any
    receipt: ToolExecutionReceipt


class ToolExecutionIntegrityLayer:
    """Fail-closed guard around parsers, converters and technical engines.

    Invariants:
    - no registered/qualified tool + operation => no execution;
    - any exception/incomplete output/critical warning => no evidence promotion;
    - failed runs never return an output to the caller;
    - repeated failures open a circuit and force explicit recovery/requalification.
    """

    def __init__(self, specs: list[ToolSpec] | None = None) -> None:
        self._registry: dict[str, ToolSpec] = {}
        self._failure_counts: dict[tuple[str, str], int] = {}
        self._open_circuits: set[tuple[str, str]] = set()
        self.receipts: list[dict[str, Any]] = []
        self.failure_ledger: list[dict[str, Any]] = []
        for spec in specs or []:
            self.register(spec)

    @staticmethod
    def _utc_now() -> str:
        return datetime.now(timezone.utc).replace(microsecond=0).isoformat()

    @staticmethod
    def _canonical(value: Any) -> bytes:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")

    @classmethod
    def fingerprint(cls, value: Any) -> str:
        return sha256(cls._canonical(value)).hexdigest()

    def register(self, spec: ToolSpec) -> None:
        if not spec.tool_id or not spec.version or not spec.operations:
            raise ToolContractError("INVALID_TOOL_SPEC")
        if len(set(spec.operations)) != len(spec.operations):
            raise ToolContractError("DUPLICATE_OPERATION_IN_TOOL_SPEC")
        self._registry[spec.tool_id] = spec

    def spec(self, tool_id: str) -> ToolSpec:
        try:
            return self._registry[tool_id]
        except KeyError as exc:
            raise ToolContractError(f"UNREGISTERED_TOOL:{tool_id}") from exc

    def is_circuit_open(self, tool_id: str, version: str) -> bool:
        return (tool_id, version) in self._open_circuits

    def reset_circuit(self, tool_id: str, version: str) -> None:
        key = (tool_id, version)
        self._open_circuits.discard(key)
        self._failure_counts[key] = 0

    def _contract_gate(self, *, tool_id: str, tool_version: str, operation: str, project_id: str) -> ToolSpec:
        if not project_id or not str(project_id).strip():
            raise ToolContractError("PROJECT_ID_REQUIRED")
        spec = self.spec(tool_id)
        if tool_version != spec.version:
            raise ToolContractError(
                f"TOOL_VERSION_MISMATCH:{tool_id}:expected={spec.version}:received={tool_version}"
            )
        if operation not in spec.operations:
            raise ToolContractError(f"UNSUPPORTED_TOOL_OPERATION:{tool_id}:{operation}")
        if self.is_circuit_open(tool_id, tool_version):
            raise ToolCircuitOpenError(f"TOOL_CIRCUIT_OPEN:{tool_id}:{tool_version}")
        return spec

    @staticmethod
    def _critical_warnings(output: Any) -> list[str]:
        if not isinstance(output, Mapping):
            return []
        warnings = output.get("warnings")
        if not isinstance(warnings, list):
            return []
        critical: list[str] = []
        for item in warnings:
            if isinstance(item, Mapping):
                sev = str(item.get("severity", "")).upper()
                if sev in {"CRITICAL", "BLOCKING", "FATAL"}:
                    critical.append(str(item.get("code") or item.get("message") or item))
            elif isinstance(item, str) and item.upper().startswith(("CRITICAL", "FATAL", "BLOCKING")):
                critical.append(item)
        return critical

    def _record_failure(
        self,
        *,
        tool_id: str,
        tool_version: str,
        project_id: str,
        operation: str,
        input_fingerprint: str,
        code: str,
        detail: str,
        spec: ToolSpec | None,
    ) -> None:
        key = (tool_id, tool_version)
        count = self._failure_counts.get(key, 0) + 1
        self._failure_counts[key] = count
        threshold = spec.failure_threshold if spec else 1
        circuit_opened = count >= threshold
        if circuit_opened:
            self._open_circuits.add(key)
        self.failure_ledger.append({
            "teil_version": TEIL_VERSION,
            "tool_id": tool_id,
            "tool_version": tool_version,
            "project_id": project_id,
            "operation": operation,
            "input_fingerprint": input_fingerprint,
            "failure_code": code,
            "detail": detail,
            "failure_count": count,
            "circuit_opened": circuit_opened,
            "technical_state_change": False,
            "evidence_created": False,
            "timestamp_utc": self._utc_now(),
        })

    def execute(
        self,
        *,
        tool_id: str,
        tool_version: str,
        operation: str,
        project_id: str,
        input_payload: Any,
        call: Callable[[], Any],
        output_validator: Callable[[Any], tuple[bool, str | None]] | None = None,
        output_fingerprint_fn: Callable[[Any], Any] | None = None,
    ) -> ToolExecutionEnvelope:
        input_fingerprint = self.fingerprint(input_payload)
        spec: ToolSpec | None = None
        try:
            spec = self._contract_gate(
                tool_id=tool_id,
                tool_version=tool_version,
                operation=operation,
                project_id=project_id,
            )
        except TEILError as exc:
            self._record_failure(
                tool_id=tool_id, tool_version=tool_version, project_id=project_id,
                operation=operation, input_fingerprint=input_fingerprint,
                code="TOOL_CALL_REJECTED_BEFORE_EXECUTION", detail=str(exc), spec=spec,
            )
            raise

        try:
            output = call()
        except Exception as exc:
            self._record_failure(
                tool_id=tool_id, tool_version=tool_version, project_id=project_id,
                operation=operation, input_fingerprint=input_fingerprint,
                code="TOOL_EXECUTION_EXCEPTION", detail=f"{type(exc).__name__}:{exc}", spec=spec,
            )
            raise ToolExecutionError(f"TOOL_EXECUTION_FAILED:{tool_id}:{operation}:{exc}") from exc

        if output is None:
            self._record_failure(
                tool_id=tool_id, tool_version=tool_version, project_id=project_id,
                operation=operation, input_fingerprint=input_fingerprint,
                code="TOOL_OUTPUT_INCOMPLETE", detail="Tool returned None", spec=spec,
            )
            raise ToolOutputIntegrityError(f"TOOL_OUTPUT_INCOMPLETE:{tool_id}:{operation}")

        critical_warnings = self._critical_warnings(output)
        if critical_warnings:
            self._record_failure(
                tool_id=tool_id, tool_version=tool_version, project_id=project_id,
                operation=operation, input_fingerprint=input_fingerprint,
                code="TOOL_OUTPUT_CRITICAL_WARNING", detail=";".join(critical_warnings), spec=spec,
            )
            raise ToolOutputIntegrityError(f"TOOL_OUTPUT_CRITICAL_WARNING:{tool_id}:{operation}")

        if output_validator is not None:
            ok, reason = output_validator(output)
            if not ok:
                self._record_failure(
                    tool_id=tool_id, tool_version=tool_version, project_id=project_id,
                    operation=operation, input_fingerprint=input_fingerprint,
                    code="TOOL_OUTPUT_VALIDATION_FAILED", detail=reason or "validator rejected output", spec=spec,
                )
                raise ToolOutputIntegrityError(f"TOOL_OUTPUT_VALIDATION_FAILED:{tool_id}:{operation}:{reason or ''}")

        fingerprint_payload = output_fingerprint_fn(output) if output_fingerprint_fn is not None else output
        output_fingerprint = self.fingerprint(fingerprint_payload)
        tool_run_id = "TEIL-RUN-" + self.fingerprint({
            "tool_id": tool_id,
            "tool_version": tool_version,
            "project_id": project_id,
            "operation": operation,
            "input": input_fingerprint,
            "output": output_fingerprint,
            "ordinal": len(self.receipts) + 1,
        })[:16].upper()
        receipt = ToolExecutionReceipt(
            teil_version=TEIL_VERSION,
            tool_run_id=tool_run_id,
            tool_id=tool_id,
            tool_version=tool_version,
            project_id=project_id,
            operation=operation,
            input_fingerprint=input_fingerprint,
            contract_validation="PASS",
            execution_status="SUCCESS",
            output_completeness="PASS",
            critical_warnings=tuple(),
            output_fingerprint=output_fingerprint,
            evidence_eligibility=True,
            committed=True,
            timestamp_utc=self._utc_now(),
        )
        record = receipt.to_dict()
        self.receipts.append(record)
        self._failure_counts[(tool_id, tool_version)] = 0
        return ToolExecutionEnvelope(output=output, receipt=receipt)

    def snapshot(self) -> dict[str, Any]:
        payload = {
            "teil_version": TEIL_VERSION,
            "policy": {
                "no_verified_tool_execution_no_evidence": True,
                "tool_failure_zero_technical_state_change": True,
                "fail_closed": True,
            },
            "registered_tools": [asdict(x) for x in sorted(self._registry.values(), key=lambda s: s.tool_id)],
            "successful_receipts": list(self.receipts),
            "failure_ledger": list(self.failure_ledger),
            "open_circuits": [
                {"tool_id": tool_id, "tool_version": version}
                for tool_id, version in sorted(self._open_circuits)
            ],
        }
        payload["snapshot_fingerprint"] = self.fingerprint(payload)
        return payload


def build_default_teil() -> ToolExecutionIntegrityLayer:
    return ToolExecutionIntegrityLayer([
        ToolSpec("RISK_WORKBOOK_PARSER", "1.0.0", ("CLASSIFY", "EXTRACT")),
        ToolSpec("PDF_PAGE_READER", "1.0.0", ("READ_PAGES", "RENDER_PAGE")),
        ToolSpec("FILE_INTEGRITY_SCANNER", "1.0.0", ("IDENTIFY", "HASH", "COVERAGE")),
        ToolSpec("CAD_DXF_PARSER", "1.0.0", ("READ",)),
        ToolSpec("CAD_RECONSTRUCTOR", "1.0.0", ("RECONSTRUCT", "AUDIT", "EXPORT")),
        ToolSpec("GEOMETRY_ENGINE", "1.0.0", ("ROLLING_SPHERE", "EXPORT_3D")),
    ])
