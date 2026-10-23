"""Pass one fresh server response from the proxy to the client."""
import asyncio
from dataclasses import asdict
import hashlib
import json
import math
import os
from pathlib import Path
import stat
import time
from uuid import UUID, uuid4

from authorization_provider import (AuthorizationCandidate, AuthorizationContext,
    AuthorizationTimedOut, BackendRejected, ContractError, Metrics, PumpIdentity)
from .relay_wire import LIMIT, nonce_context, response_bytes, substitute_key


def digest(data):
    return hashlib.sha256(data).hexdigest()


def context_digest(context):
    # Use the same request fingerprint as the client.
    return digest(json.dumps({'bt':context.pump.bt_address.hex(),
        'pump_key':context.pump.public_key.hex(),'challenge':context.challenge.hex(),
        'app_key':context.app_public_key.hex(),'device':str(context.device_id),
        'metrics':context.metrics.to_proto_fields()},sort_keys=True,separators=(',',':')).encode())


def private_write(path, data):
    """Publish a fully written immutable file atomically, never replace evidence."""
    path = Path(path)
    temporary = path.parent / ('.' + path.name + '.' + str(uuid4()))
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(data); stream.flush(); os.fsync(stream.fileno())
        os.link(temporary, path)  # exclusive destination, no partial readers
    finally:
        temporary.unlink(missing_ok=True)


def write_json(path, value):
    private_write(path, (json.dumps(value, indent=2) + '\n').encode())


def read_private(path, limit=1024 * 1024):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077 or info.st_size > limit:
            raise ContractError("Untrusted local relay file")
        data = stream.read(limit + 1)
        if len(data) > limit: raise ContractError("Unbounded local relay file")
        return data


def read_json(path):
    try:
        result = json.loads(read_private(path))
    except (ValueError, UnicodeError):
        raise ContractError("Invalid relay JSON") from None
    if not isinstance(result, dict): raise ContractError("Relay record must be an object")
    return result


def encode_context(context):
    return {'bt_address_hex': context.pump.bt_address.hex(),
        'pump_public_key_hex': context.pump.public_key.hex(),
        'challenge_hex': context.challenge.hex(), 'app_public_key_hex': context.app_public_key.hex(),
        'device_id': str(context.device_id), 'metrics': asdict(context.metrics)}


def decode_context(value):
    try:
        return AuthorizationContext(PumpIdentity(bytes.fromhex(value['bt_address_hex']),
            bytes.fromhex(value['pump_public_key_hex'])), UUID(value['device_id']),
            Metrics(**value['metrics']), bytes.fromhex(value['challenge_hex']),
            bytes.fromhex(value['app_public_key_hex']))
    except (KeyError, TypeError, ValueError):
        raise ContractError("Invalid relay authorization context") from None


class RelayRun:
    scope = 'synthetic-phones-only'

    def __init__(self, directory):
        self.directory = Path(directory).resolve()
        info = self.directory.stat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ContractError("Private owned relay directory required")
        self.manifest = read_json(self.directory / 'manifest.json')
        UUID(self.manifest['run_id'])
        if self.manifest.get('scope') != self.scope:
            raise ContractError("Relay run scope does not match this explicit implementation")
        created, expires = self.manifest['created_ms'], self.manifest['expires_ms']
        if type(created) is not int or type(expires) is not int or not 0 < expires - created <= 300000:
            raise ContractError("Invalid relay lifetime")
        for name in ['challenge_hex', 'pump_public_key_hex', 'app_public_key_hex', 'peer_sha256']:
            value = self.manifest[name]
            if not isinstance(value, str) or len(value) != 64 or any(c not in '0123456789abcdef' for c in value):
                raise ContractError("Invalid synthetic manifest binding")

    @classmethod
    def create(cls, directory, *, challenge, pump_public_key, app_public_key, peer_sha256, lifetime_seconds=240):
        directory = Path(directory).resolve()
        original = Path(__file__).resolve().parent.parent / 'analysis/backend-public-key'
        if directory == original or original in directory.parents:
            raise ContractError("Original backend evidence tree cannot hold relay runs")
        if not math.isfinite(lifetime_seconds) or not 0 < lifetime_seconds <= 300:
            raise ContractError("Relay lifetime must be at most five minutes")
        for value in [challenge, pump_public_key, app_public_key]:
            if type(value) is not bytes or len(value) != 32:
                raise ContractError("Exact public fixture context required")
        directory.mkdir(parents=True, exist_ok=False, mode=0o700)
        created = int(time.time() * 1000)
        write_json(directory / 'manifest.json', {'scope':cls.scope,
            'run_id':str(uuid4()), 'created_ms':created,
            'expires_ms':created + int(lifetime_seconds * 1000),
            'challenge_hex':challenge.hex(), 'pump_public_key_hex':pump_public_key.hex(),
            'app_public_key_hex':app_public_key.hex(), 'peer_sha256':peer_sha256,
            'wire_profile':'mylife-android-seven-fields'})
        return cls(directory)

    def path(self, name):
        if '/' in name or name in {'.','..'}: raise ContractError("Invalid relay filename")
        return self.directory / name

    def check_live(self):
        now = int(time.time() * 1000)
        if not self.manifest['created_ms'] - 1000 <= now < self.manifest['expires_ms']:
            raise AuthorizationTimedOut("Relay session expired or clock moved backwards")
        if self.path('cancelled.json').exists() or self.path('consumed.json').exists():
            raise ContractError("Relay session is terminal")

    def bind(self, context):
        self.check_live()
        for name, value in [('challenge_hex',context.challenge),
                            ('pump_public_key_hex',context.pump.public_key),
                            ('app_public_key_hex',context.app_public_key)]:
            if self.manifest[name] != value.hex():
                raise ContractError("Client does not match this synthetic session")

    def fail(self, reason):
        if not self.path('cancelled.json').exists():
            try: write_json(self.path('cancelled.json'), {'reason':reason})
            except FileExistsError: pass


class RelayAuthorizationProvider:
    """Check the proxy records and use the response once."""
    def __init__(self, run):
        self.run = run
        self.started = False

    async def authorize(self, context, *, timeout_seconds=120):
        if not isinstance(context, AuthorizationContext):
            raise ContractError("AuthorizationContext required")
        if type(timeout_seconds) not in (int,float) or not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
            raise ContractError("Positive finite provider deadline required")
        if self.started: raise ContractError("Relay provider is single-use")
        self.started = True; self.run.bind(context)
        request = {'run_id':self.run.manifest['run_id'], 'request_id':str(uuid4()),
            'context':encode_context(context), 'context_sha256':context_digest(context)}
        write_json(self.run.path('request.json'), request)
        try:
            async with asyncio.timeout(timeout_seconds):
                while not self.run.path('response.json').exists():
                    self.run.check_live()
                    if self.run.path('failure.json').exists():
                        raise BackendRejected("Relay backend transaction failed; inspect private run")
                    await asyncio.sleep(0.05)
                self.run.check_live()
                response = read_json(self.run.path('response.json'))
                if any(response.get(k) != request[k] for k in ['run_id','request_id','context_sha256']):
                    raise ContractError("Relay response correlation mismatch")
                if response.get('http_status') != 200 or response.get('grpc_status') != '0':
                    raise BackendRejected("Backend did not issue authorization")
                native = read_private(self.run.path('nonce-request.grpc'))
                device, address, metrics, metrics_wire = nonce_context(native)
                if (device,address,metrics) != (context.device_id,context.pump.bt_address,context.metrics):
                    raise ContractError("Client context does not match genuine nonce request")
                nonce = response_bytes(read_private(self.run.path('nonce-response.grpc')),24)
                original = read_private(self.run.path('request-original.grpc'))
                forwarded = read_private(self.run.path('request-forwarded.grpc'))
                if forwarded != substitute_key(original,context,nonce,metrics_wire):
                    raise ContractError("Forwarded request does not match client context")
                payload = response_bytes(read_private(self.run.path('response-upstream.grpc')),116)
                if response.get('authorization_sha256') != digest(payload):
                    raise ContractError("Recorded authorization digest mismatch")
                candidate = AuthorizationCandidate(context,nonce,payload)
                write_json(self.run.path('consumed.json'), {'request_id':request['request_id'],
                    'context_sha256':request['context_sha256'], 'authorization_sha256':digest(payload),
                    'manufacturer_signature_verified':False, 'pump_acceptance_tested':False})
                return candidate
        except BaseException as error:
            self.run.fail(type(error).__name__)
            if isinstance(error,TimeoutError):
                raise AuthorizationTimedOut("Genuine-app relay deadline expired") from None
            raise


class RelayExchange:
    """Synchronous transaction checks used by the separately loaded proxy addon."""
    def __init__(self, run):
        self.run = run; self.nonce = None; self.native = None; self.pending = None
        run.check_live()
        private_write(run.path('proxy-started.marker'),b'one proxy process\n')

    def nonce_request(self, packet):
        self.run.check_live()
        if self.run.path('authorization-request.marker').exists():
            raise ContractError("Authorization already attempted")
        device,address,metrics,wire = nonce_context(packet)
        private_write(self.run.path('nonce-request.marker'),b'one fresh nonce\n')
        private_write(self.run.path('nonce-request.grpc'),packet)
        self.native = (device,address,metrics,wire)
        write_json(self.run.path('native-context.json'), {'device_id':str(device),
            'bt_address_hex':address.hex(),'metrics':asdict(metrics)})

    def nonce_response(self, packet, http_status, grpc_status):
        self.run.check_live()
        if self.native is None or self.nonce is not None:
            raise ContractError("Unexpected nonce response")
        if http_status != 200 or grpc_status != '0':
            raise BackendRejected("Nonce RPC rejected")
        self.nonce = response_bytes(packet,24)
        private_write(self.run.path('nonce-response.grpc'),packet)

    def authorization_request(self, packet):
        self.run.check_live()
        if self.native is None or self.nonce is None:
            raise ContractError("No fresh successful genuine-app nonce")
        request = read_json(self.run.path('request.json'))
        context = decode_context(request['context']); self.run.bind(context)
        if request['run_id'] != self.run.manifest['run_id'] or request['context_sha256'] != context_digest(context):
            raise ContractError("Pending client request does not match run")
        UUID(request['request_id'])
        device,address,metrics,wire = self.native
        if (device,address,metrics) != (context.device_id,context.pump.bt_address,context.metrics):
            raise ContractError("Genuine-app/client nonce metadata differ")
        forwarded = substitute_key(packet,context,self.nonce,wire)
        private_write(self.run.path('authorization-request.marker'),b'one EncryptKey\n')
        private_write(self.run.path('request-original.grpc'),packet)
        private_write(self.run.path('request-forwarded.grpc'),forwarded)
        self.pending = request
        return forwarded

    def authorization_response(self, packet, http_status, grpc_status):
        self.run.check_live()
        if self.pending is None: raise ContractError("No forwarded authorization request")
        if type(packet) is not bytes or len(packet)>LIMIT:
            raise ContractError("Unbounded backend response")
        private_write(self.run.path('response-upstream.grpc'),packet)
        if http_status != 200 or grpc_status != '0':
            raise BackendRejected("EncryptKey RPC rejected")
        payload = response_bytes(packet,116)
        response = {k:self.pending[k] for k in ['run_id','request_id','context_sha256']}
        response.update(http_status=http_status,grpc_status=grpc_status,
            authorization_sha256=digest(payload),response_forwarded_to_app=False,
            pump_acceptance_tested=False)
        write_json(self.run.path('response.json'),response)
        return response
