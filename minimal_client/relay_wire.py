"""Read mylife requests and change only public-key field 3."""
import re
import struct
from uuid import UUID

from authorization_provider import ContractError, Metrics


HOST = "connect.mland.pr.sec01.proregia.io"
NONCE_PATH = "/Proregia.Bluetooth.Contracts.Proto.NonceRequest/Send"
KEY_PATH = "/Proregia.Bluetooth.Contracts.Proto.EncryptKey/Send"
APP = "net.sinovo.mylife.app"
LIMIT = 1024 * 1024


def varint(data, position):
    value = 0
    for index in range(10):
        if position >= len(data):
            raise ContractError("Truncated protobuf varint")
        byte = data[position]; position += 1
        if index == 9 and byte > 1:
            raise ContractError("Protobuf varint overflow")
        value |= (byte & 127) << (7 * index)
        if byte < 128:
            return value, position
    raise ContractError("Overlong protobuf varint")


def fields(data):
    if not isinstance(data, (bytes, bytearray)) or len(data) > LIMIT:
        raise ContractError("Unbounded protobuf input")
    result = {}; position = 0
    while position < len(data):
        tag, position = varint(data, position)
        number, wire = tag >> 3, tag & 7
        if not 0 < number < (1 << 29) or number in result:
            raise ContractError("Invalid or duplicate protobuf field")
        if wire == 2:
            length, position = varint(data, position); end = position + length
        elif wire == 0:
            _, end = varint(data, position)
        elif wire in (1, 5):
            end = position + (8 if wire == 1 else 4)
        else:
            raise ContractError("Unsupported protobuf wire type")
        if end > len(data):
            raise ContractError("Truncated protobuf field")
        result[number] = (wire, position, end, bytes(data[position:end]))
        position = end
        if len(result) > 128:
            raise ContractError("Too many protobuf fields")
    return result


def unframe(data):
    if type(data) is not bytes or not 5 <= len(data) <= LIMIT or data[0] != 0:
        raise ContractError("Expected one bounded uncompressed unary gRPC frame")
    if struct.unpack(">I", data[1:5])[0] != len(data) - 5:
        raise ContractError("Invalid or multiple gRPC frames")
    return data[5:]


def raw(mapping, number):
    if number not in mapping or mapping[number][0] != 2:
        raise ContractError("Missing length-delimited protobuf field")
    return mapping[number][3]


def text(mapping, number, limit=4096):
    value = raw(mapping, number)
    if not 0 < len(value) <= limit:
        raise ContractError("Missing or unbounded protobuf text")
    try:
        return value.decode("utf-8")
    except UnicodeError:
        raise ContractError("Invalid protobuf text") from None


def hex_bytes(mapping, number, size):
    value = raw(mapping, number)
    if len(value) != size * 2 or re.fullmatch(rb"[0-9A-Fa-f]+", value) is None:
        raise ContractError("Invalid hexadecimal protobuf field")
    return bytes.fromhex(value.decode("ascii"))


def metrics_from_wire(data):
    mapping = fields(data)
    names = list(Metrics.__dataclass_fields__)
    values = {name: text(mapping, n, 1024) for n, name in enumerate(names[:9], 1)}
    if 10 not in mapping:
        xamarin = False
    else:
        if mapping[10][0] != 0:
            raise ContractError("Invalid Xamarin wire type")
        xamarin, end = varint(mapping[10][3], 0)
        if xamarin not in (0, 1) or end != len(mapping[10][3]):
            raise ContractError("Invalid Xamarin boolean")
    values['xamarin'] = bool(xamarin)
    metrics = Metrics(**values)
    if metrics.application_package != APP:
        raise ContractError("Not the configured genuine mylife application")
    return metrics


def nonce_context(packet):
    mapping = fields(unframe(packet))
    try:
        device = UUID(text(mapping, 1, 36))
    except (ValueError, AttributeError):
        raise ContractError("Invalid genuine-app device UUID") from None
    return device, hex_bytes(mapping, 2, 6), metrics_from_wire(raw(mapping, 3)), raw(mapping, 3)


def substitute_key(packet, context, nonce, metrics_wire):
    body = unframe(packet); mapping = fields(body)
    # Keep unknown fields and use the mylife request format.
    if 8 in mapping:
        raise ContractError("Unexpected CamAPS-profile field in mylife request")
    expected = {1: context.challenge, 2: context.pump.public_key,
                4: context.pump.bt_address, 6: nonce}
    for number, value in expected.items():
        if hex_bytes(mapping, number, len(value)) != value:
            raise ContractError("Genuine request context does not match pending client")
    if raw(mapping, 7) != metrics_wire or metrics_from_wire(raw(mapping, 7)) != context.metrics:
        raise ContractError("Genuine request metrics changed")
    text(mapping, 5, 128 * 1024)  # genuine opaque attestation; never synthesized
    old = hex_bytes(mapping, 3, 32)
    if old == context.app_public_key:
        raise ContractError("Independent key must differ from genuine app key")
    _, start, end, encoded = mapping[3]
    replacement = context.app_public_key.hex()
    if encoded.isupper(): replacement = replacement.upper()
    changed = body[:start] + replacement.encode("ascii") + body[end:]
    result = packet[:5] + changed
    if len(result) != len(packet) or fields(changed).keys() != mapping.keys():
        raise ContractError("Unexpected wire shape change")
    if any(fields(changed)[n] != value for n, value in mapping.items() if n != 3):
        raise ContractError("Unexpected change outside client public key")
    return result


def response_bytes(packet, size):
    return hex_bytes(fields(unframe(packet)), 1, size)
