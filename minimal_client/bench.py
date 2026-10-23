"""Check the selected pump and its authorization."""
import hashlib
import math
import re
import time

from authorization_provider import (AuthorizationCandidate, AuthorizationContext,
    AuthorizationTimedOut, ContractError, PumpIdentity)
from .relay import RelayRun
from .relay_wire import fields, hex_bytes, nonce_context, unframe


class BenchRelayRun(RelayRun):
    scope = 'physical-bench'


def logical_address(name):
    if not isinstance(name, str) or re.fullmatch(r'YpsoPump_[0-9]{8}', name) is None:
        raise ContractError('Exact observed pump name required')
    number = int(name.split('_')[1])
    if number <= 10000000:
        raise ContractError('A physical observed pump serial is required, not a fixture')
    # Address mapping checked against the official app.
    return bytes.fromhex('EC2AF0') + (number % 10000000).to_bytes(3, 'big')


def settings_password(address):
    if type(address) is not bytes or len(address) != 6:
        raise ContractError('Explicit six-byte connected peer required')
    # Access password used by the official app.
    return hashlib.md5(address + bytes([79,194,69,77,155,129,89,164,147,187])).digest()


def validate_target(target):
    if not isinstance(target, dict) or target.get('scope') != 'paired-pump':
        raise ContractError('An explicitly selected paired pump is required')
    address = target.get('peer_address', '')
    if re.fullmatch(r'(?:[0-9A-F]{2}:){5}[0-9A-F]{2}', address) is None:
        raise ContractError('Observed peer address required')
    peer = bytes.fromhex(address.replace(':', ''))
    logical = logical_address(target.get('name'))
    if (hashlib.sha256(peer).hexdigest() != target.get('peer_sha256') or
        logical.hex() != target.get('rpc_identity_hex') or logical != peer):
        raise ContractError('Physical identity mapping is not established')
    return peer


def captured_key_context(packet, native_nonce_packet, independent_public_key, target_address):
    if type(independent_public_key) is not bytes or len(independent_public_key) != 32:
        raise ContractError('Independent public key required')
    device, address, metrics, _ = nonce_context(native_nonce_packet)
    values = fields(unframe(packet))
    if address != target_address or hex_bytes(values, 4, 6) != address:
        raise ContractError('Genuine request targets another pump')
    return AuthorizationContext(PumpIdentity(address, hex_bytes(values, 2, 32)),
        device, metrics, hex_bytes(values, 1, 32), independent_public_key)


class CandidateOnce:
    """Use a fresh authorization once."""
    def __init__(self, candidate, *, lifetime_seconds=45):
        if not isinstance(candidate, AuthorizationCandidate):
            raise ContractError('Validated relay candidate object required')
        if type(lifetime_seconds) not in (int, float) or not math.isfinite(lifetime_seconds) or not 0 < lifetime_seconds <= 60:
            raise ContractError('Bounded fresh handoff lifetime required')
        self._candidate = candidate
        self._deadline = time.monotonic() + lifetime_seconds
        self._used = False

    async def authorize(self, context, *, timeout_seconds=20):
        if self._used:
            raise ContractError('Captured candidate handoff already used')
        self._used = True
        if time.monotonic() >= self._deadline:
            raise AuthorizationTimedOut('Captured candidate handoff expired')
        if type(timeout_seconds) not in (int, float) or not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
            raise ContractError('Positive provider timeout required')
        if context != self._candidate.context:
            raise ContractError('Captured candidate belongs to another context')
        return self._candidate
