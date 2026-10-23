"""Authorize once and check pump status."""
import asyncio
from dataclasses import dataclass, field
import math
import secrets
from typing import Protocol
from uuid import UUID

from authorization_provider import (
    AuthorizationCandidate, AuthorizationContext, AuthorizationProvider,
    ContractError, Metrics, PumpIdentity,
)
from .protocol import (
    AUTHORIZATION, NEW_KEY, PASSWORD, STATUS, ProtocolFailure,
    decode_status, digest, fragments, public_key, read_message, shared_key,
)


class Transport(Protocol):
    """A single explicitly selected peer, with acknowledged writes and no retry."""
    async def connect(self) -> None: ...
    async def read(self, characteristic: str) -> bytes: ...
    async def write(self, characteristic: str, value: bytes) -> None: ...
    async def disconnect(self) -> None: ...


class ClientTimedOut(Exception):
    pass


class ClientBusy(Exception):
    pass


@dataclass(frozen=True)
class StatusObservation:
    """Proof for this peer/test only; contains no persisted session credential."""
    payload: bytes = field(repr=False)
    reboot_counter: int
    numeric_counter: int
    context_sha256: str


def context_digest(context: AuthorizationContext) -> str:
    # Bind the result to this pump and request.
    import json
    return digest(json.dumps({
        "bt": context.pump.bt_address.hex(), "pump_key": context.pump.public_key.hex(),
        "challenge": context.challenge.hex(), "app_key": context.app_public_key.hex(),
        "device": str(context.device_id), "metrics": context.metrics.to_proto_fields(),
    }, sort_keys=True, separators=(",", ":")).encode())


class MinimalClient:
    """Run once without delivery commands or automatic retries; disconnecting does not restore CamAPS."""
    def __init__(self, transport: Transport, provider: AuthorizationProvider,
                 *, bt_address: bytes, password: bytes, device_id: UUID,
                 metrics: Metrics, private_key: bytes | None = None,
                 captured_context: AuthorizationContext | None = None):
        if type(bt_address) is not bytes or len(bt_address) != 6:
            raise ContractError("Explicit six-byte peer identity required")
        if type(password) is not bytes or len(password) != 16:
            raise ContractError("Explicit sixteen-byte access password required")
        if not isinstance(device_id, UUID) or not isinstance(metrics, Metrics):
            raise ContractError("Explicit device UUID and metrics required")
        self.transport, self.provider = transport, provider
        self.bt_address, self._password = bt_address, password
        self.device_id, self.metrics = device_id, metrics
        self._private = secrets.token_bytes(32) if private_key is None else private_key
        self.public_key = public_key(self._private)
        if captured_context is not None:
            if not isinstance(captured_context, AuthorizationContext) or (
                captured_context.pump.bt_address != bt_address or
                captured_context.device_id != device_id or
                captured_context.metrics != metrics or
                captured_context.app_public_key != self.public_key):
                raise ContractError("Captured context does not bind this client/identity/metadata")
            # Check the key before connecting.
            shared_key(self._private, captured_context.pump.public_key)
        self._captured_context = captured_context
        self.state = "new"
        self.events: list[str] = []
        # A captured request may already have changed the pump keys.
        self.recovery_required = captured_context is not None
        self.challenge_request_attempted = False
        self.authorization_write_attempted = False
        self.cleanup_failed = False
        self._started = False
        self.context: AuthorizationContext | None = None

    def _event(self, state):
        self.state = state
        self.events.append(state)

    async def run(self, *, timeout_seconds: float = 20, cleanup_seconds: float = 2) -> StatusObservation:
        for value in [timeout_seconds, cleanup_seconds]:
            if type(value) not in (float, int) or not math.isfinite(value) or value <= 0:
                raise ContractError("Deadlines must be finite positive numbers")
        if self._started:
            raise ClientBusy("Client is single-use; no implicit retry/reconnect")
        self._started = True
        budget = asyncio.timeout(timeout_seconds)
        try:
            async with budget:
                self._event("connecting")
                await self.transport.connect()
                self._event("access")
                await self.transport.write(PASSWORD, self._password)
                self._event("challenge")
                if self._captured_context is None:
                    # Record a possible key change before sending the request.
                    self.recovery_required = True
                    self.challenge_request_attempted = True
                    data = await read_message(self.transport, NEW_KEY, 64)
                    self.context = AuthorizationContext(
                        PumpIdentity(self.bt_address, data[32:]), self.device_id,
                        self.metrics, data[:32], self.public_key)
                else:
                    self.context = self._captured_context
                # Reject invalid keys before asking the server.
                key = shared_key(self._private, self.context.pump.public_key)
                self._event("authorizing")
                candidate = await self.provider.authorize(
                    self.context, timeout_seconds=timeout_seconds)
                if not isinstance(candidate, AuthorizationCandidate) or candidate.context != self.context:
                    raise ProtocolFailure("Authorization candidate context mismatch")
                self._event("installing")
                # Record the attempt before writing; a lost reply does not mean nothing changed.
                self.authorization_write_attempted = True
                for frame in fragments(candidate.payload):
                    await self.transport.write(AUTHORIZATION, frame)
                self._event("status")
                payload, reboot, counter = decode_status(
                    await read_message(self.transport, STATUS), key)
                observation = StatusObservation(payload, reboot, counter,
                                                context_digest(self.context))
                self._event("verified")
                return observation
        except TimeoutError:
            self._event("failed")
            if budget.expired():
                raise ClientTimedOut("Overall client deadline expired") from None
            raise
        except asyncio.CancelledError:
            self._event("cancelled")
            raise
        except Exception:
            self._event("failed")
            raise
        finally:
            try:
                try:
                    async with asyncio.timeout(cleanup_seconds):
                        await self.transport.disconnect()
                except asyncio.CancelledError:
                    self.cleanup_failed = True
                    self._event("cancelled")
                    raise
                except Exception:
                    self.cleanup_failed = True
            finally:
                # Drop the key reference; Python cannot guarantee erasure.
                self._private = bytes(32)

    def report(self):
        return {"state": self.state, "events": list(self.events),
                "controller_restoration_required": self.recovery_required,
                "challenge_request_attempted": self.challenge_request_attempted,
                "captured_context_used": self._captured_context is not None,
                "authorization_write_attempted": self.authorization_write_attempted,
                "disconnect_failed": self.cleanup_failed,
                "credentials_persisted": False,
                "delivery_commands_supported": False}
