"""Shared authorization types and checks."""

import asyncio
import base64
from dataclasses import dataclass, field
import math
import re
from typing import Mapping, Protocol
from uuid import UUID


NONCE_BYTES = 24
PUBLIC_KEY_BYTES = 32
CHALLENGE_BYTES = 32
AUTHORIZATION_BYTES = 116


class AuthorizationError(Exception):
    """Base for classified failures; none of these causes automatic retry."""


class ContractError(AuthorizationError):
    """Input, response shape, encoding, length or local binding is invalid."""


class BackendRejected(AuthorizationError):
    """Provider explicitly rejected the request; not proof of pump key expiry."""


class BackendUnavailable(AuthorizationError):
    """Provider transport/service failed; not proof of pump key expiry."""


class AttestationRejected(AuthorizationError):
    """Attestation could not be issued or verified for this request."""


class AuthorizationTimedOut(AuthorizationError):
    """The overall budget, including waiting for serialization, expired."""


def exact_bytes(value: bytes, size: int, name: str) -> None:
    if type(value) is not bytes or len(value) != size:
        raise ContractError(f"{name} must be exactly {size} immutable bytes")


def nonempty_text(value: str, name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ContractError(f"{name} must be nonempty text")


def decode_hex_response(response: Mapping[str, object], name: str, size: int) -> bytes:
    """Read a fixed-length hex response."""
    if not isinstance(response, Mapping):
        raise ContractError("Backend response must be a field mapping")
    value = response.get(name)
    if not isinstance(value, str) or len(value) != size * 2:
        raise ContractError(f"{name} must encode exactly {size} bytes")
    if re.fullmatch(r"[0-9a-fA-F]+", value) is None:
        raise ContractError(f"{name} must be hexadecimal without whitespace")
    return bytes.fromhex(value)


@dataclass(frozen=True)
class Metrics:
    platform: str
    model: str
    os_type: str
    os_version: str
    manufacturer: str
    device_serial: str
    application_name: str
    application_package: str
    library_version: str
    xamarin: bool

    def __post_init__(self):
        for name in self.__dataclass_fields__:
            if name != "xamarin":
                nonempty_text(getattr(self, name), name)
        if type(self.xamarin) is not bool:
            raise ContractError("xamarin must be boolean")

    def to_proto_fields(self) -> dict[int, object]:
        """Field-number mapping, NOT a protobuf wire encoder."""
        return {
            1: self.platform, 2: self.model, 3: self.os_type,
            4: self.os_version, 5: self.manufacturer, 6: self.device_serial,
            7: self.application_name, 8: self.application_package,
            9: self.library_version, 10: self.xamarin,
        }


@dataclass(frozen=True)
class PumpIdentity:
    bt_address: bytes = field(repr=False)
    public_key: bytes = field(repr=False)

    def __post_init__(self):
        exact_bytes(self.bt_address, 6, "Bluetooth address")
        exact_bytes(self.public_key, PUBLIC_KEY_BYTES, "pump public key")


@dataclass(frozen=True)
class AuthorizationContext:
    pump: PumpIdentity
    device_id: UUID
    metrics: Metrics
    challenge: bytes = field(repr=False)
    app_public_key: bytes = field(repr=False)

    def __post_init__(self):
        if not isinstance(self.pump, PumpIdentity):
            raise ContractError("pump must be a PumpIdentity")
        if not isinstance(self.device_id, UUID):
            raise ContractError("device_id must be an explicit UUID")
        if not isinstance(self.metrics, Metrics):
            raise ContractError("metrics must be explicit")
        exact_bytes(self.challenge, CHALLENGE_BYTES, "challenge")
        exact_bytes(self.app_public_key, PUBLIC_KEY_BYTES, "app public key")


@dataclass(frozen=True)
class NonceRequest:
    context: AuthorizationContext

    def __post_init__(self):
        if not isinstance(self.context, AuthorizationContext):
            raise ContractError("Nonce request context is missing")

    def to_proto_fields(self) -> dict[int, object]:
        c = self.context
        return {1: str(c.device_id), 2: c.pump.bt_address.hex().upper(),
                3: c.metrics.to_proto_fields()}


@dataclass(frozen=True)
class AttestationRequest:
    nonce_base64: str
    application_package: str

    def __post_init__(self):
        if (not isinstance(self.nonce_base64, str)
                or re.fullmatch(r"[A-Za-z0-9_-]{32}", self.nonce_base64) is None):
            raise ContractError("Attestation nonce must encode 24 bytes in URL-safe Base64")
        nonempty_text(self.application_package, "attestation application package")


@dataclass(frozen=True)
class BoundAttestation:
    """Token metadata still needs a real verifier."""
    token: str = field(repr=False)
    binding: AttestationRequest

    def __post_init__(self):
        nonempty_text(self.token, "attestation token")
        if not isinstance(self.binding, AttestationRequest):
            raise ContractError("Attestation binding is missing")


@dataclass(frozen=True)
class EncryptKeyRequest:
    context: AuthorizationContext
    nonce: bytes = field(repr=False)
    attestation: BoundAttestation

    def __post_init__(self):
        if not isinstance(self.context, AuthorizationContext):
            raise ContractError("Authorization request context is missing")
        exact_bytes(self.nonce, NONCE_BYTES, "server nonce")
        expected = AttestationRequest(
            base64.urlsafe_b64encode(self.nonce).decode("ascii"),
            self.context.metrics.application_package,
        )
        if not isinstance(self.attestation, BoundAttestation) or self.attestation.binding != expected:
            raise ContractError("Attestation metadata does not match nonce/application")

    def to_proto_fields(self) -> dict[int, object]:
        c = self.context
        return {
            1: c.challenge.hex().upper(),
            2: c.pump.public_key.hex().upper(),
            3: c.app_public_key.hex().upper(),
            4: c.pump.bt_address.hex().upper(),
            5: self.attestation.token,
            6: self.nonce.hex().upper(),
            7: c.metrics.to_proto_fields(),
            8: str(c.device_id),
        }


@dataclass(frozen=True)
class AuthorizationCandidate:
    """A response whose size is checked; pump acceptance is still required."""
    context: AuthorizationContext
    nonce: bytes = field(repr=False)
    payload: bytes = field(repr=False)

    def __post_init__(self):
        if not isinstance(self.context, AuthorizationContext):
            raise ContractError("Candidate context is missing")
        exact_bytes(self.nonce, NONCE_BYTES, "candidate nonce")
        exact_bytes(self.payload, AUTHORIZATION_BYTES, "authorization payload")


class AuthorizationBackend(Protocol):
    """Future transport seam. Must honor asyncio cancellation and avoid retries."""

    async def get_nonce(self, request: NonceRequest) -> Mapping[str, object]: ...

    async def encrypt_key(self, request: EncryptKeyRequest) -> Mapping[str, object]: ...


class AttestationProvider(Protocol):
    async def attest(self, request: AttestationRequest) -> BoundAttestation: ...


class AuthorizationProvider(Protocol):
    async def authorize(
        self, context: AuthorizationContext, *, timeout_seconds: float = 5.0,
    ) -> AuthorizationCandidate: ...


class NonceBoundAuthorizationProvider:
    """Fetch a fresh nonce and serialize requests for one pump."""

    def __init__(self, backend: AuthorizationBackend, attestation: AttestationProvider):
        self._backend = backend
        self._attestation = attestation
        self._pump_locks: dict[bytes, asyncio.Lock] = {}

    async def authorize(
        self, context: AuthorizationContext, *, timeout_seconds: float = 5.0,
    ) -> AuthorizationCandidate:
        if not isinstance(context, AuthorizationContext):
            raise ContractError("context must be an AuthorizationContext")
        if (type(timeout_seconds) not in (int, float)
                or not math.isfinite(timeout_seconds) or timeout_seconds <= 0):
            raise ContractError("timeout_seconds must be finite and positive")
        lock = self._pump_locks.setdefault(context.pump.bt_address, asyncio.Lock())
        budget = asyncio.timeout(timeout_seconds)
        try:
            async with budget:
                async with lock:
                    raw_nonce = await self._backend.get_nonce(NonceRequest(context))
                    nonce = decode_hex_response(raw_nonce, "server_nonce", NONCE_BYTES)
                    binding = AttestationRequest(
                        base64.urlsafe_b64encode(nonce).decode("ascii"),
                        context.metrics.application_package,
                    )
                    attestation = await self._attestation.attest(binding)
                    request = EncryptKeyRequest(context, nonce, attestation)
                    raw_payload = await self._backend.encrypt_key(request)
                    payload = decode_hex_response(raw_payload, "encrypted_bytes", AUTHORIZATION_BYTES)
                    return AuthorizationCandidate(context, nonce, payload)
        except TimeoutError:
            if budget.expired():
                raise AuthorizationTimedOut("Authorization transaction deadline expired") from None
            raise
