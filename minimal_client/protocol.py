"""Read and check encrypted pump messages."""
import hashlib
import hmac
import struct
import ctypes
from functools import lru_cache

from nacl.bindings import crypto_scalarmult, crypto_scalarmult_base, crypto_aead_xchacha20poly1305_ietf_decrypt as decrypt
from nacl.exceptions import CryptoError

def read_frame(frame, key):
    """Authenticate and parse bytes; no counter-state/reconnect policy is assumed."""
    if len(frame) < 52:
        raise ValueError("Frame cannot contain tag, nonce and counter trailer")
    plaintext = decrypt(frame[:-24], None, frame[-24:], key)
    if len(plaintext) < 12:
        raise ValueError("Authenticated plaintext has no full counter trailer")
    reboot, counter = struct.unpack("<iq", plaintext[-12:])
    if reboot < 0 or counter < 0:
        raise ValueError("Negative counter")
    return plaintext[:-12], reboot, counter


PASSWORD = "669a0c20-0008-969e-e211-fcbeb2147bc5"
NEW_KEY = "669a0c20-0008-969e-e211-fcff0000000a"
AUTHORIZATION = "669a0c20-0008-969e-e211-fcff0000000b"
EXTENDED = "669a0c20-0008-969e-e211-fcff000000ff"
STATUS = "669a0c20-0008-969e-e211-fcbee48b7bc5"
MAX_PAYLOAD = 19 * 15


class ProtocolFailure(Exception):
    """Malformed, unauthenticated or unexpected protocol data."""


def fragments(payload: bytes) -> list[bytes]:
    if type(payload) is not bytes or not 1 <= len(payload) <= MAX_PAYLOAD:
        raise ProtocolFailure("Payload outside bounded framing contract")
    count = (len(payload) + 18) // 19
    return [bytes([((i + 1) << 4) | count]) + payload[i * 19:(i + 1) * 19]
            for i in range(count)]


def validate_fragment(frame: bytes, index: int, count: int | None = None) -> int:
    if type(frame) is not bytes or not 2 <= len(frame) <= 20:
        raise ProtocolFailure("Empty or oversized GATT fragment")
    actual_index, actual_count = frame[0] >> 4, frame[0] & 15
    if not 1 <= actual_count <= 15 or actual_index != index:
        raise ProtocolFailure("Invalid fragment order/count")
    if count is not None and actual_count != count:
        raise ProtocolFailure("Fragment count changed mid-message")
    if actual_index > actual_count or (actual_index < actual_count and len(frame) != 20):
        raise ProtocolFailure("Truncated intermediate fragment")
    return actual_count


async def read_message(transport, characteristic: str, expected_size: int | None = None) -> bytes:
    first = await transport.read(characteristic)
    count = validate_fragment(first, 1)
    if expected_size is not None and count != (expected_size + 18) // 19:
        raise ProtocolFailure("Unexpected message length/fragments")
    parts = [first[1:]]
    for index in range(2, count + 1):
        frame = await transport.read(EXTENDED)
        validate_fragment(frame, index, count)
        parts.append(frame[1:])
    result = b"".join(parts)
    if expected_size is not None and len(result) != expected_size:
        raise ProtocolFailure("Message has unexpected decoded length")
    return result


def crc16(payload: bytes) -> bytes:
    """Compute the CRC used by the tested pump messages."""
    crc = 0xFFFFFFFF
    for offset in range(0, len(payload), 4):
        for byte in payload[offset:offset + 4].ljust(4, b"\0")[::-1]:
            crc ^= byte << 24
            for _ in range(8):
                crc = ((crc << 1) ^ (0x04C11DB7 if crc & 0x80000000 else 0)) & 0xFFFFFFFF
    return struct.pack("<H", crc & 0xFFFF)


def public_key(private: bytes) -> bytes:
    if type(private) is not bytes or len(private) != 32:
        raise ProtocolFailure("Independent private key must be 32 bytes")
    return crypto_scalarmult_base(private)


def shared_key(private: bytes, pump_public: bytes) -> bytes:
    if type(pump_public) is not bytes or len(pump_public) != 32:
        raise ProtocolFailure("Pump public key must be 32 bytes")
    public_key(private)
    try:
        raw = crypto_scalarmult(private, pump_public)
    except (CryptoError, RuntimeError, ValueError):
        raise ProtocolFailure("Invalid/low-order pump public key") from None
    return hchacha(raw, bytes(16))


@lru_cache(maxsize=1)
def _sodium():
    # Load libsodium directly without running another program.
    library = ctypes.CDLL("libsodium.so.23")
    library.sodium_init.restype = ctypes.c_int
    if library.sodium_init() < 0:
        raise RuntimeError("libsodium initialization failed")
    library.crypto_core_hchacha20.argtypes = [ctypes.c_void_p] * 4
    library.crypto_core_hchacha20.restype = ctypes.c_int
    return library


def hchacha(key: bytes, nonce: bytes) -> bytes:
    if len(key) != 32 or len(nonce) != 16:
        raise ProtocolFailure("Invalid HChaCha20 input length")
    output = ctypes.create_string_buffer(32)
    if _sodium().crypto_core_hchacha20(output, ctypes.create_string_buffer(nonce, 16),
                                    ctypes.create_string_buffer(key, 32), None):
        raise ProtocolFailure("HChaCha20 failed")
    return output.raw


def decode_status(packet: bytes, key: bytes) -> tuple[bytes, int, int]:
    try:
        payload, reboot, counter = read_frame(packet, key)
    except (CryptoError, ValueError):
        raise ProtocolFailure("Status authentication/framing failed") from None
    if len(payload) < 3 or not hmac.compare_digest(crc16(payload[:-2]), payload[-2:]):
        raise ProtocolFailure("Authenticated status CRC/length failed")
    # Return status bytes without guessing their meaning.
    return payload[:-2], reboot, counter


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()
