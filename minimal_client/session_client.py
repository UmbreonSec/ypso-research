"""Check pump status with the saved session."""
import asyncio

from .core import ClientBusy, StatusObservation
from .protocol import PASSWORD, STATUS, digest, read_message
from .relay import context_digest, decode_context


class ResumeStatusClient:
    def __init__(self, transport, lease, *, peer_sha256, firmware, password, reconcile=False):
        lease.assert_target(peer_sha256, firmware)
        self.reconcile = reconcile
        self.credential = lease.recovery_credential() if reconcile else lease.credential()
        if type(password) is not bytes or len(password) != 16:
            raise ValueError('Explicit access password required')
        self.transport, self.lease, self.password = transport, lease, password
        self.started = False
        self.disconnect_failed = False

    async def run(self, *, timeout_seconds=50, cleanup_seconds=10):
        if self.started:
            raise ClientBusy('Resume client is single-use; no implicit retry')
        if any(type(x) not in (int, float) or not 0 < x <= 120
               for x in [timeout_seconds, cleanup_seconds]):
            raise ValueError('Bounded positive deadlines required')
        self.started = True
        self.lease.begin_read(reconcile=self.reconcile)
        try:
            async with asyncio.timeout(timeout_seconds):
                await self.transport.connect()
                await self.transport.write(PASSWORD, self.password)
                packet = await read_message(self.transport, STATUS)
                payload, reboot, counter = self.lease.accept_status(packet,reconcile=self.reconcile)
                return StatusObservation(payload, reboot, counter,
                    context_digest(decode_context(self.credential['context'])))
        finally:
            try:
                try:
                    async with asyncio.timeout(cleanup_seconds):
                        await self.transport.disconnect()
                except asyncio.CancelledError:
                    self.disconnect_failed = True
                    raise
                except Exception:
                    self.disconnect_failed = True
            finally:
                self.lease.end_read()
