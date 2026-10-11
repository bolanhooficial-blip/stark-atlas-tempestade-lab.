"""ECO controlled hardening candidate v0.1: detached gate, NOT production wired.

Never calls or edits STARK/ATLAS/TEMPESTADE engines. It is a provisional
host-side integrity control: it neither certifies engineer credentials nor
proves the normative source text, which require independent external services.
"""
from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import stat
from dataclasses import asdict, dataclass
from decimal import Decimal, InvalidOperation, localcontext
from pathlib import Path
from typing import Callable, Mapping, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

VALID_SHA = re.compile(r"^[0-9a-f]{64}$")
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}$")
ALLOWED_ENGINES = frozenset({"STARK", "ATLAS", "TEMPESTADE"})

class GateBlocked(RuntimeError):
    pass


def canonical(obj: object) -> bytes:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def digest(obj: object) -> str:
    return hashlib.sha256(canonical(obj)).hexdigest()


def sha_bytes(contents: bytes) -> str:
    return hashlib.sha256(contents).hexdigest()


def _valid_id(item: str) -> bool:
    return isinstance(item, str) and bool(SAFE_ID.fullmatch(item))


@dataclass(frozen=True)
class Source:
    doc_id: str
    revision: str
    sha256: str
    discipline: str


@dataclass(frozen=True)
class Envelope:
    project_id: str
    service_id: str
    scope_id: str
    revision: str
    engine: str
    normative_standard: str
    normative_edition: str
    normative_profile_hash: str
    ruleset_hash: str
    engine_version: str
    sources: tuple[Source, ...]
    output_id: str
    output_sha256: str
    required_controls: tuple[str, ...]

    def validate(self) -> None:
        identities=(self.project_id,self.service_id,self.scope_id,self.revision,
                    self.engine,self.normative_standard,self.normative_edition,
                    self.engine_version,self.output_id)
        if not all(_valid_id(v) for v in identities):
            raise GateBlocked('MISSING_OR_INVALID_CONTEXT')
        if self.engine not in ALLOWED_ENGINES:
            raise GateBlocked('UNAUTHORIZED_ENGINE')
        if not all(VALID_SHA.fullmatch(v or '') for v in
                   (self.normative_profile_hash,self.ruleset_hash,self.output_sha256)):
            raise GateBlocked('INVALID_HASH_BINDING')
        if not self.sources or not self.required_controls:
            raise GateBlocked('INCOMPLETE_EVIDENCE_OR_REVIEW_CONTROLS')
        source_ids=[s.doc_id for s in self.sources]
        if len(set(source_ids)) != len(source_ids):
            raise GateBlocked('DUPLICATE_DOCUMENT_ID')
        for s in self.sources:
            if not all(_valid_id(v) for v in (s.doc_id,s.revision,s.discipline)):
                raise GateBlocked('INVALID_DOCUMENT_IDENTITY')
            if not VALID_SHA.fullmatch(s.sha256 or ''):
                raise GateBlocked('INVALID_DOCUMENT_HASH')
        if len(set(self.required_controls)) != len(self.required_controls) or not all(_valid_id(x) for x in self.required_controls):
            raise GateBlocked('INVALID_REVIEW_CONTROLS')

    def content(self) -> dict:
        self.validate()
        return asdict(self)

    def fingerprint(self) -> str:
        return digest(self.content())


def read_bound_bytes(path: Path, expected_sha: str, max_bytes: int=25_000_000) -> bytes:
    """Read exactly one opened fd, verify hash and return immutable bytes.

    Downstream must operate on these bytes, never reopen an unaudited path.
    """
    if not VALID_SHA.fullmatch(expected_sha or ''):
        raise GateBlocked('INVALID_EXPECTED_DOCUMENT_SHA')
    if not isinstance(path, Path):
        raise GateBlocked('PATH_TYPE_INVALID')
    try:
        flags=os.O_RDONLY | getattr(os,'O_NOFOLLOW',0) | getattr(os,'O_CLOEXEC',0)
        fd=os.open(str(path), flags)
        try:
            first=os.fstat(fd)
            if not stat.S_ISREG(first.st_mode) or first.st_size > max_bytes:
                raise GateBlocked('SOURCE_NOT_REGULAR_OR_OVERSIZE')
            with os.fdopen(fd, 'rb', closefd=False) as stream:
                contents=stream.read(max_bytes+1)
            second=os.fstat(fd)
            if (first.st_dev,first.st_ino,first.st_size,first.st_mtime_ns)!=(
                second.st_dev,second.st_ino,second.st_size,second.st_mtime_ns):
                raise GateBlocked('SOURCE_CHANGED_DURING_READ')
            if len(contents)>max_bytes or len(contents)!=first.st_size:
                raise GateBlocked('SOURCE_SIZE_MISMATCH')
        finally:
            os.close(fd)
    except (OSError, ValueError) as exc:
        raise GateBlocked('SOURCE_UNREADABLE') from exc
    if sha_bytes(contents)!=expected_sha:
        raise GateBlocked('SOURCE_HASH_MISMATCH')
    return contents


def verify_source_set(envelope: Envelope, paths: Mapping[str,Path]) -> dict[str,bytes]:
    envelope.validate()
    if set(paths) != {s.doc_id for s in envelope.sources}:
        raise GateBlocked('SOURCE_SET_MISMATCH')
    return {s.doc_id:read_bound_bytes(paths[s.doc_id],s.sha256) for s in envelope.sources}


@dataclass(frozen=True)
class SignedReview:
    reviewer_id: str
    professional_registration: str
    role: str
    approval_id: str
    envelope_hash: str
    reviewed_control_ids: tuple[str,...]
    review_evidence_hashes: tuple[str,...]
    approved_at_utc: str
    signature_hex: str

    def signing_data(self) -> bytes:
        data=asdict(self)
        data.pop('signature_hex')
        return canonical(data)


@dataclass(frozen=True)
class TrustedReviewer:
    reviewer_id: str
    public_key_raw: bytes
    allowed_roles: tuple[str,...]


def verify_review(envelope: Envelope, attestation: SignedReview | None,
                  registry: Mapping[str,TrustedReviewer],
                  credential_verifier: Callable[[str,str,str],bool] | None,
                  evidence_verifier: Callable[[tuple[str,...],str],bool] | None,
                  prepared_by: str, independent_audit: bool) -> str:
    """Reference-only approval check, never an autonomous work authorization.

    Registry and callbacks must be provisioned by an external trusted service.
    Without them, fail closed. Review must cover all specified controls.
    """
    envelope.validate()
    if attestation is None or credential_verifier is None or evidence_verifier is None:
        raise GateBlocked('EXTERNAL_AUTHORITY_MISSING')
    if not _valid_id(prepared_by) or not _valid_id(attestation.reviewer_id):
        raise GateBlocked('INVALID_REVIEW_IDENTITY')
    if attestation.role not in {'TECHNICAL_REVIEWER','INDEPENDENT_AUDITOR'}:
        raise GateBlocked('INVALID_REVIEW_ROLE')
    if independent_audit and (attestation.role!='INDEPENDENT_AUDITOR' or prepared_by==attestation.reviewer_id):
        raise GateBlocked('AUDITOR_INDEPENDENCE_VIOLATION')
    if attestation.envelope_hash != envelope.fingerprint():
        raise GateBlocked('REVIEW_CONTEXT_CHANGED')
    if not _valid_id(attestation.approval_id) or not attestation.professional_registration.strip():
        raise GateBlocked('INVALID_APPROVAL_METADATA')
    if set(attestation.reviewed_control_ids)!=set(envelope.required_controls) or len(set(attestation.reviewed_control_ids))!=len(attestation.reviewed_control_ids):
        raise GateBlocked('REVIEW_COVERAGE_MISMATCH')
    if not attestation.review_evidence_hashes or not all(VALID_SHA.fullmatch(x or '') for x in attestation.review_evidence_hashes):
        raise GateBlocked('NO_REVIEW_EVIDENCE')
    try:
        from datetime import datetime,timezone
        ts=datetime.fromisoformat(attestation.approved_at_utc.replace('Z','+00:00'))
        if ts.tzinfo is None or ts.astimezone(timezone.utc)>datetime.now(timezone.utc):
            raise GateBlocked('INVALID_APPROVAL_TIMESTAMP')
    except (ValueError,AttributeError):
        raise GateBlocked('INVALID_APPROVAL_TIMESTAMP')
    reviewer=registry.get(attestation.reviewer_id)
    if reviewer is None or reviewer.reviewer_id!=attestation.reviewer_id or attestation.role not in reviewer.allowed_roles:
        raise GateBlocked('UNTRUSTED_REVIEWER')
    try:
        signature=bytes.fromhex(attestation.signature_hex)
        Ed25519PublicKey.from_public_bytes(reviewer.public_key_raw).verify(signature,attestation.signing_data())
    except (ValueError,InvalidSignature):
        raise GateBlocked('REVIEW_SIGNATURE_INVALID')
    try:
        credential_ok=credential_verifier(attestation.reviewer_id,attestation.professional_registration,attestation.role)
        evidence_ok=evidence_verifier(attestation.review_evidence_hashes,attestation.envelope_hash)
    except Exception as exc:
        raise GateBlocked('EXTERNAL_VERIFIER_UNAVAILABLE') from exc
    if credential_ok is not True:
        raise GateBlocked('PROFESSIONAL_CREDENTIAL_REJECTED')
    if evidence_ok is not True:
        raise GateBlocked('REVIEW_EVIDENCE_UNVERIFIED')
    return 'POLICY_ELIGIBLE_FOR_PROFESSIONAL_REVIEW_ONLY'


def processing_key(envelope: Envelope, payload_sha256: str) -> str:
    envelope.validate()
    if not VALID_SHA.fullmatch(payload_sha256 or ''):
        raise GateBlocked('INVALID_PAYLOAD_HASH')
    return digest({'binding':envelope.content(),'payload_sha256':payload_sha256})


class IsolatedReplayLedger:
    """Test-only idempotency store. Production needs atomic durable storage."""
    def __init__(self):
        self._keys=set()

    def accept(self, envelope:Envelope, payload_sha256:str) -> str:
        key=processing_key(envelope,payload_sha256)
        if key in self._keys:
            return 'DUPLICATE_SAME_CONTEXT'
        self._keys.add(key)
        return 'NEW_CONTEXT_OR_PAYLOAD'


@dataclass(frozen=True)
class IndependentNormativeReference:
    standard: str
    edition: str
    source_doc_id: str
    source_sha256: str
    source_locator: str
    expression: str
    review_evidence_hash: str


def _eval_reference_expression(expr: str, inputs: Mapping[str,Decimal]) -> Decimal:
    """Different expression parser from STARK's formula-tree evaluator.

    Strict AST subset, no eval/exec/functions/imports.
    """
    try:
        tree=ast.parse(expr,mode='eval')
    except SyntaxError as exc:
        raise GateBlocked('INVALID_REFERENCE_EXPRESSION') from exc
    def walk(n):
        if isinstance(n,ast.Expression):return walk(n.body)
        if isinstance(n,ast.Name):
            if n.id not in inputs:raise GateBlocked('UNKNOWN_REFERENCE_VARIABLE')
            return inputs[n.id]
        if isinstance(n,ast.Constant) and isinstance(n.value,(int,float)) and not isinstance(n.value,bool):
            return Decimal(str(n.value))
        if isinstance(n,ast.UnaryOp) and isinstance(n.op,(ast.UAdd,ast.USub)):
            a=walk(n.operand);return a if isinstance(n.op,ast.UAdd) else -a
        if isinstance(n,ast.BinOp) and isinstance(n.op,(ast.Add,ast.Sub,ast.Mult,ast.Div)):
            a=walk(n.left);b=walk(n.right)
            if isinstance(n.op,ast.Add):return a+b
            if isinstance(n.op,ast.Sub):return a-b
            if isinstance(n.op,ast.Mult):return a*b
            if b==0:raise GateBlocked('ZERO_DIVISION_REFERENCE')
            return a/b
        raise GateBlocked('FORBIDDEN_REFERENCE_EXPRESSION_NODE')
    with localcontext() as ctx:
        ctx.prec=32
        try:
            value=walk(tree)
        except (InvalidOperation,OverflowError) as exc:
            raise GateBlocked('REFERENCE_EVALUATION_ERROR') from exc
    if not value.is_finite():raise GateBlocked('NONFINITE_REFERENCE_RESULT')
    return value



@dataclass(frozen=True)
class NormativeReferenceAttestation:
    reviewer_id: str
    reference_hash: str
    signed_at_utc: str
    signature_hex: str

    def signing_data(self) -> bytes:
        data=asdict(self)
        data.pop('signature_hex')
        return canonical(data)


def verify_independent_normative_reference(reference: IndependentNormativeReference,
        proof: NormativeReferenceAttestation | None,
        registry: Mapping[str,TrustedReviewer],
        source_locator_verifier: Callable[[IndependentNormativeReference],bool] | None,
        formula_author_id: str) -> None:
    """Checks independent review provenance, not mathematical correctness.

    External verifier must check document accessibility, licensed source locator,
    and the professional reviewer authorization outside this process.
    """
    if proof is None or source_locator_verifier is None:
        raise GateBlocked('UNATTESTED_NORMATIVE_REFERENCE')
    if proof.reviewer_id==formula_author_id:
        raise GateBlocked('CORRELATED_NORMATIVE_REVIEWER')
    if proof.reference_hash!=digest(asdict(reference)):
        raise GateBlocked('NORMATIVE_REFERENCE_ALTERED')
    if not _valid_id(proof.reviewer_id):
        raise GateBlocked('INVALID_NORMATIVE_REVIEWER_ID')
    reviewer=registry.get(proof.reviewer_id)
    if not reviewer or reviewer.reviewer_id!=proof.reviewer_id or 'NORMATIVE_REVIEWER' not in reviewer.allowed_roles:
        raise GateBlocked('UNTRUSTED_NORMATIVE_REVIEWER')
    try:
        from datetime import datetime, timezone
        signed=datetime.fromisoformat(proof.signed_at_utc.replace('Z','+00:00'))
        if signed.tzinfo is None or signed.astimezone(timezone.utc)>datetime.now(timezone.utc):
            raise GateBlocked('INVALID_NORMATIVE_REVIEW_DATE')
    except (ValueError,AttributeError) as exc:
        raise GateBlocked('INVALID_NORMATIVE_REVIEW_DATE') from exc
    try:
        Ed25519PublicKey.from_public_bytes(reviewer.public_key_raw).verify(
            bytes.fromhex(proof.signature_hex),proof.signing_data())
    except (ValueError,InvalidSignature) as exc:
        raise GateBlocked('INVALID_NORMATIVE_REFERENCE_SIGNATURE') from exc
    try:
        if source_locator_verifier(reference) is not True:
            raise GateBlocked('NORMATIVE_LOCATOR_UNVERIFIED')
    except GateBlocked:
        raise
    except Exception as exc:
        raise GateBlocked('NORMATIVE_LOCATOR_VERIFIER_FAILED') from exc

def compare_normative_calculation(envelope:Envelope,
             reference:IndependentNormativeReference,
             verified_reference_bytes:bytes,
             reference_attestation:NormativeReferenceAttestation | None,
             normative_reviewer_registry:Mapping[str,TrustedReviewer],
             source_locator_verifier:Callable[[IndependentNormativeReference],bool] | None,
             candidate_formula_author_id:str,
             candidate:Callable[[Mapping[str,Decimal]],Decimal],
             vectors:Sequence[Mapping[str,Decimal]],
             absolute_tolerance:Decimal=Decimal('0.000001')) -> dict:
    """Challenge supplied candidate against independently transcribed values.

    Reference review must have valid signature from an independent reviewer.
    This function deliberately DOES NOT parse protected ABNT normative PDFs.
    """
    envelope.validate()
    verify_independent_normative_reference(
        reference, reference_attestation, normative_reviewer_registry,
        source_locator_verifier, candidate_formula_author_id)
    if (reference.standard,reference.edition)!=(envelope.normative_standard,envelope.normative_edition):
        raise GateBlocked('NORMATIVE_EDITION_MISMATCH')
    if not reference.source_doc_id or reference.source_doc_id not in [s.doc_id for s in envelope.sources]:
        raise GateBlocked('NORMATIVE_SOURCE_NOT_BOUND')
    if reference.source_sha256!=sha_bytes(verified_reference_bytes):
        raise GateBlocked('NORMATIVE_SOURCE_HASH_MISMATCH')
    if reference.source_sha256 != next(s.sha256 for s in envelope.sources if s.doc_id==reference.source_doc_id):
        raise GateBlocked('NORMATIVE_SOURCE_CONTEXT_MISMATCH')
    if not reference.source_locator.strip() or not VALID_SHA.fullmatch(reference.review_evidence_hash or ''):
        raise GateBlocked('NORMATIVE_LOCATOR_OR_ATTESTATION_MISSING')
    if len(vectors)<3 or absolute_tolerance<0:
        raise GateBlocked('INADEQUATE_REFERENCE_CHALLENGE')
    cases=[]
    for i,v in enumerate(vectors):
        if not v or not all(isinstance(k,str) and isinstance(val,Decimal) and val.is_finite() for k,val in v.items()):
            raise GateBlocked('INVALID_TEST_VECTOR')
        ref=_eval_reference_expression(reference.expression,v)
        try: actual=candidate(v)
        except Exception as exc:raise GateBlocked('CANDIDATE_EVALUATION_FAILED') from exc
        if not isinstance(actual,Decimal) or not actual.is_finite():
            raise GateBlocked('INVALID_CANDIDATE_RESULT')
        d=abs(ref-actual)
        cases.append({'index':i, 'match':d<=absolute_tolerance, 'delta':str(d),
                      'reference':str(ref),'candidate':str(actual)})
    return {'status':'REFERENCE_MATCH_FOR_TEST_VECTORS_ONLY' if all(x['match'] for x in cases) else 'DIVERGENCE_BLOCKED',
            'scope':'SYNTHETIC_OR_EXTERNALLY_AUTHENTICATED_REFERENCE_ONLY',
            'cases':cases,
            'normative_edition':reference.edition}


def qualify_immutable_derivative(envelope: Envelope,
         paths: Mapping[str,Path],
         producer: Callable[[Mapping[str,bytes]],bytes],
         output_validator: Callable[[bytes],bool] | None) -> bytes:
    """Guard for new external integration, not installed in existing engine paths.

    Enforces content-addressed inputs, explicit output validator, no empty output,
    and checks output SHA binding. Downstream must consume returned immutable
    bytes. A production supervisor must additionally sandbox/attest the producer
    to prevent it from opening another source path on its own.
    """
    envelope.validate()
    if output_validator is None or not callable(output_validator):
        raise GateBlocked('OUTPUT_VALIDATOR_MISSING')
    sources=verify_source_set(envelope,paths)
    try:
        output=producer(dict(sources))
    except Exception as exc:
        raise GateBlocked('PRODUCER_FAILED') from exc
    if not isinstance(output,bytes) or not output:
        raise GateBlocked('EMPTY_OR_MUTABLE_OUTPUT')
    if sha_bytes(output)!=envelope.output_sha256:
        raise GateBlocked('DERIVED_OUTPUT_HASH_MISMATCH')
    try:
        if output_validator(output) is not True:
            raise GateBlocked('OUTPUT_VALIDATOR_REJECTED')
    except GateBlocked:
        raise
    except Exception as exc:
        raise GateBlocked('OUTPUT_VALIDATOR_ERROR') from exc
    return output
