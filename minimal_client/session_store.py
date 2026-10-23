"""Save session keys securely using the host keyring."""
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
import time
from uuid import uuid4

from nacl.bindings import (crypto_aead_xchacha20poly1305_ietf_decrypt,
                          crypto_aead_xchacha20poly1305_ietf_encrypt)

from .protocol import decode_status, digest, public_key, shared_key
from .relay import context_digest, decode_context, encode_context


class SessionError(Exception):
    pass


class RecoveryRequired(SessionError):
    pass


class SessionBusy(SessionError):
    pass


class SecretServiceVault:
    """Explicit OS keyring only: no plaintext backend or key-file fallback."""
    service = 'ypso-research-bench-session-v1'

    def _backend(self):
        from keyring.backends.SecretService import Keyring
        backend = Keyring()
        if backend.priority <= 0:
            raise SessionError('OS Secret Service unavailable')
        return backend

    def get(self, name):
        value = self._backend().get_password(self.service, name)
        return None if value is None else json.loads(value)

    def set(self, name, value):
        self._backend().set_password(self.service, name, json.dumps(value, sort_keys=True))


def _private_file(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 262144):
            raise SessionError('Untrusted session file')
        return stream.read(262145)


class SessionStore:
    def __init__(self, directory, *, vault=None, fault=None):
        self.directory = Path(directory).absolute()
        self.vault = SecretServiceVault() if vault is None else vault
        self.name = digest(str(self.directory).encode())
        self.path = self.directory / 'session.enc'
        self.fault = fault or (lambda stage: None)

    @contextmanager
    def lease(self):
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = self.directory.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o700):
            raise SessionError('Owned private session directory required')
        fd = os.open(self.directory / '.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o600):
                raise SessionError('Untrusted session lock')
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise SessionBusy('Session already leased') from None
            lease = SessionLease(self)
            try:
                yield lease
            finally:
                lease.closed = True
                lease.anchor = None
                lease.state = None
        finally:
            os.close(fd)


class SessionLease:
    def __init__(self, store):
        self.store = store
        self.anchor = self.state = None
        self.closed = False
        self.poisoned = False
        self.read_in_flight = False

    def _check(self):
        if self.closed or self.poisoned:
            raise RecoveryRequired('Session lease closed or interrupted')

    def load(self):
        self._check()
        try:
            anchor = self.store.vault.get(self.store.name)
            if anchor is None:
                raise RecoveryRequired('Session has no trusted keyring anchor')
            packet = _private_file(self.store.path)
            if digest(packet) != anchor['sha256']:
                raise RecoveryRequired('Session rollback or interrupted commit detected')
            key = bytes.fromhex(anchor['key_hex'])
            plain = crypto_aead_xchacha20poly1305_ietf_decrypt(
                packet[24:], self.store.name.encode(), packet[:24], key)
            state = json.loads(plain)
            self._validate(state)
            if state['revision'] != anchor['revision']:
                raise RecoveryRequired('Session revision anchor mismatch')
            self.anchor, self.state = anchor, state
            return state
        except SessionError:
            raise
        except Exception:
            raise RecoveryRequired('Session cannot be authenticated or loaded') from None

    @staticmethod
    def _validate(state):
        if (not isinstance(state, dict) or state.get('version') != 1
                or type(state.get('revision')) is not int or state['revision'] < 1
                or state.get('controller') not in {'unprovisioned', 'verified', 'changing', 'uncertain', 'handed_back'}
                or not isinstance(state.get('firmware'), str)
                or len(state.get('peer_sha256', '')) != 64
                or state.get('profile') != 'mylife-physical-status-v1'):
            raise RecoveryRequired('Invalid session schema')
        for name in ['active', 'pending']:
            entry = state.get(name)
            if entry is None:
                continue
            if not isinstance(entry, dict) or len(bytes.fromhex(entry['private_hex'])) != 32:
                raise RecoveryRequired('Invalid session credential')
            if entry.get('context') is not None:
                context = decode_context(entry['context'])
                if (public_key(bytes.fromhex(entry['private_hex'])) != context.app_public_key
                        or digest(context.pump.bt_address) != state['peer_sha256']):
                    raise RecoveryRequired('Stored credential identity mismatch')
                shared_key(bytes.fromhex(entry['private_hex']), context.pump.public_key)
        active = state.get('active')
        if active is not None:
            counters = active['counters']
            if (active.get('context') is None or
                    any(type(counters.get(n)) is not int or not 0 <= counters[n] <= bound
                        for n, bound in [('reboot', 2**31-1), ('read', 2**63-1), ('write', 2**63-1)])
                    or not 1 <= len(active['seen_packets']) <= 128
                    or len(set(active['seen_packets'])) != len(active['seen_packets'])):
                raise RecoveryRequired('Invalid persisted counter/replay state')
        if state['controller'] == 'verified' and active is None:
            raise RecoveryRequired('Verified session has no active key')

    def create(self, *, peer_sha256, firmware):
        self._check()
        if self.store.path.exists() or self.store.vault.get(self.store.name) is not None:
            raise SessionError('Session already exists; refusing replacement')
        if len(peer_sha256) != 64 or not firmware:
            raise SessionError('Explicit pump identity and firmware required')
        self.anchor = {'key_hex': secrets.token_hex(32), 'revision': 0, 'sha256': None}
        self.state = {'version': 1, 'revision': 0, 'peer_sha256': peer_sha256,
                      'firmware': firmware, 'profile': 'mylife-physical-status-v1',
                      'controller': 'unprovisioned', 'active': None, 'pending': None}
        self.store.vault.set(self.store.name, self.anchor)
        self._commit()

    def _commit(self):
        self._check()
        if self.state is None or self.anchor is None:
            raise SessionError('Session not loaded')
        self.state['revision'] += 1
        self._validate(self.state)
        nonce = secrets.token_bytes(24)
        packet = nonce + crypto_aead_xchacha20poly1305_ietf_encrypt(
            json.dumps(self.state, sort_keys=True, separators=(',', ':')).encode(),
            self.store.name.encode(), nonce, bytes.fromhex(self.anchor['key_hex']))
        temporary = self.store.directory / ('.session-' + str(uuid4()))
        try:
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(packet); stream.flush(); os.fsync(stream.fileno())
            self.store.fault('after_file_fsync')
            os.replace(temporary, self.store.path)
            directory_fd = os.open(self.store.directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
            self.store.fault('after_replace')
            anchor = dict(self.anchor, revision=self.state['revision'], sha256=digest(packet))
            self.store.vault.set(self.store.name, anchor)
            self.anchor = anchor
            self.store.fault('after_anchor')
        except BaseException:
            self.poisoned = True
            raise
        finally:
            temporary.unlink(missing_ok=True)

    def assert_target(self, peer_sha256, firmware):
        self._check()
        if self.state is None:
            self.load()
        if (self.state['peer_sha256'], self.state['firmware']) != (peer_sha256, firmware):
            raise SessionError('Saved session targets another pump or firmware')

    def prepare(self):
        self._check()
        if self.read_in_flight:
            raise SessionBusy('Status read already in progress')
        if self.state is None:
            self.load()
        if self.state['pending'] is not None or self.state['controller'] in {'changing', 'uncertain'}:
            raise RecoveryRequired('Earlier controller change unresolved')
        self.state['pending'] = {'generation': str(uuid4()), 'private_hex': secrets.token_hex(32),
                                 'context': None, 'authorization_attempted': False}
        self._commit()
        return bytes.fromhex(self.state['pending']['private_hex'])

    def changing(self):
        self._check()
        if self.state['pending'] is None:
            raise SessionError('Prepare persistent key before requesting pump keys')
        self.state['controller'] = 'changing'
        self._commit()

    def abort_prepared(self):
        self._check()
        if self.read_in_flight or self.state['controller'] in {'changing', 'uncertain'}:
            raise RecoveryRequired('Cannot discard an ambiguous controller change')
        self.state['pending'] = None
        self._commit()

    def bind(self, context):
        self._check()
        pending = self.state['pending']
        if (self.state['controller'] != 'changing' or pending is None
                or context.app_public_key != public_key(bytes.fromhex(pending['private_hex']))
                or digest(context.pump.bt_address) != self.state['peer_sha256']):
            raise SessionError('Fresh context does not bind pending key/target')
        pending['context'] = encode_context(context)
        self._commit()

    def authorization_attempt(self):
        self._check()
        pending = self.state['pending']
        if self.state['controller'] != 'changing' or pending is None or pending['context'] is None:
            raise SessionError('Bound pending context required')
        pending['authorization_attempted'] = True
        self._commit()

    def activate(self, packet):
        self._check()
        pending = self.state['pending']
        if self.state['controller'] != 'changing' or pending is None or not pending['authorization_attempted']:
            raise SessionError('No pending authorization attempt')
        context = decode_context(pending['context'])
        key = shared_key(bytes.fromhex(pending['private_hex']), context.pump.public_key)
        payload, reboot, counter = decode_status(packet, key)
        active = dict(pending, counters={'reboot': reboot, 'read': counter, 'write': 0},
                      seen_packets=[digest(packet)], verified_ms=int(time.time()*1000))
        self.state.update(active=active, pending=None, controller='verified')
        self._commit()
        return payload, reboot, counter

    def credential(self):
        self._check()
        if self.state is None:
            self.load()
        if self.state['controller'] != 'verified' or self.state['pending'] is not None:
            raise RecoveryRequired('No resumable verified credential')
        return self.state['active']

    def recovery_credential(self):
        """Allow an explicit status check only after a failure before authorization."""
        self._check()
        if self.state is None:
            self.load()
        pending = self.state['pending']
        if (self.state['controller'] != 'uncertain' or self.state['active'] is None
                or pending is None or pending['context'] is not None
                or pending['authorization_attempted']):
            raise RecoveryRequired('Explicit reconciliation requires an unbound pre-authorization failure')
        return self.state['active']

    def accept_status(self, packet, *, reconcile=False):
        active = self.recovery_credential() if reconcile else self.credential()
        context = decode_context(active['context'])
        payload, reboot, counter = decode_status(packet, shared_key(
            bytes.fromhex(active['private_hex']), context.pump.public_key))
        previous = active['counters']
        if reboot != previous['reboot']:
            self.uncertain()
            raise RecoveryRequired('Authenticated reboot counter changed; explicit resynchronization required')
        if counter < previous['read'] or digest(packet) in active['seen_packets']:
            raise SessionError('Stale or replayed authenticated status')
        if len(active['seen_packets']) >= 128:
            raise SessionError('Bounded bench replay ledger full')
        # A fresh packet can have the same numeric counter.
        active['counters']['read'] = counter
        active['seen_packets'].append(digest(packet))
        if reconcile:
            self.state.update(controller='verified', pending=None,
                              last_explicit_reconciliation_ms=int(time.time()*1000))
        self._commit()
        return payload, reboot, counter

    def reserve_write_counter(self):
        """Offline state-model exercise only; no command builder or send path."""
        if self.read_in_flight:
            raise SessionBusy('Status read already in progress')
        active = self.credential()
        value = active['counters']['write']
        if value >= 2**63-1:
            raise SessionError('Write counter exhausted')
        active['counters']['write'] = value + 1
        self._commit()  # durable reservation before any hypothetical send
        return value + 1

    def uncertain(self):
        self._check()
        self.state['controller'] = 'uncertain'
        self._commit()

    def handed_back(self):
        self._check()
        if self.read_in_flight:
            raise SessionBusy('Status read already in progress')
        self.state['controller'] = 'handed_back'
        self.state['pending'] = None
        self._commit()

    def begin_read(self, *, reconcile=False):
        if reconcile:self.recovery_credential()
        else:self.credential()
        if self.read_in_flight:
            raise SessionBusy('Session status read already in progress')
        self.read_in_flight = True

    def end_read(self):
        self.read_in_flight = False

    def summary(self):
        self._check()
        active = self.state['active']
        return {'version': 1, 'revision': self.state['revision'],
                'controller': self.state['controller'], 'pending': self.state['pending'] is not None,
                'generation': active['generation'] if active else None,
                'counters': dict(active['counters']) if active else None,
                'private_keys_in_report': False,
                'protection': 'XChaCha20-Poly1305; wrapping key and revision anchor supplied by vault'}
