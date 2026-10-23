"""Pass Bluetooth commands through the Android bridge."""
import asyncio
import os
import json
import re
import shlex
from uuid import uuid4

from .protocol import AUTHORIZATION, EXTENDED, NEW_KEY, PASSWORD, STATUS


PACKAGE = "org.ypso.research.minimalclient"


class AdbTransport:
    package = PACKAGE

    def __init__(self, *, serial: str, adb_port: int, peer_address: str,
                 peer_sha256: str, command_timeout: float = 20,
                 scan_service_uuid: str | None = None):
        if not serial or adb_port not in (5037, 5047):
            raise ValueError("Explicit ADB serial and server port required")
        if not re.fullmatch(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", peer_address):
            raise ValueError("Explicit Bluetooth address required")
        if not re.fullmatch(r"[0-9a-f]{64}", peer_sha256):
            raise ValueError("Explicit peer identity pin required")
        from .protocol import digest
        if digest(bytes.fromhex(peer_address.replace(":", ""))) != peer_sha256:
            raise ValueError("Peer address does not match pin")
        if not 0 < command_timeout <= 30:
            raise ValueError("Command deadline must be 0-30 seconds")
        self._prefix = [os.environ.get("YPSO_ADB", "/usr/bin/adb"), "-P", str(adb_port), "-s", serial]
        self._config = {"session": str(uuid4()), "peer": peer_address.upper(),
                        "peer_sha256": peer_sha256, "mode": "simulator"}
        if scan_service_uuid is not None:
            from uuid import UUID
            service = UUID(scan_service_uuid)
            if service.version != 4:
                raise ValueError("A fresh random simulator service UUID is required")
            self._config["scan_service_uuid"] = str(service)
        self._sequence = 0
        self._timeout = command_timeout
        self._lock = asyncio.Lock()
        self._launched = False

    @classmethod
    async def discover(cls, *, serial: str, adb_port: int, service_uuid: str) -> bytes:
        """Find a test peripheral by its private service ID."""
        from .protocol import digest
        placeholder = bytes.fromhex("020000000001")
        adapter = cls(serial=serial, adb_port=adb_port,
            peer_address="02:00:00:00:00:01", peer_sha256=digest(placeholder),
            scan_service_uuid=service_uuid)
        await adapter._put("config", adapter._config)
        await adapter._adb("shell", shlex.join(["run-as", adapter.package, "sh", "-c",
            "mkdir -p files && printf '{}' > files/reply.json"]))
        try:
            result = await adapter._operation("scan")
            if len(result) != 6:
                raise ConnectionError("Simulator discovery returned invalid address")
            return result
        finally:
            await adapter.disconnect()

    async def _adb(self, *args, data=None):
        process = await asyncio.create_subprocess_exec(
            *self._prefix, *args, stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        try:
            stdout, _ = await asyncio.wait_for(process.communicate(data), self._timeout)
        except BaseException:
            if process.returncode is None:
                process.kill()
                await process.wait()
            raise
        if process.returncode:
            raise ConnectionError("Explicitly selected Android bridge command failed")
        return stdout

    async def _put(self, name, value):
        if name not in {"config", "command"}:
            raise ValueError("Unknown bridge input")
        command = f"mkdir -p files && cat > files/{name}.tmp && mv files/{name}.tmp files/{name}.json"
        await self._adb("shell", shlex.join(["run-as", self.package, "sh", "-c", command]),
                        data=json.dumps(value).encode())

    async def _operation(self, operation, *, characteristic=None, value=None):
        async with self._lock:
            self._sequence += 1
            command = {"session": self._config["session"], "id": self._sequence,
                       "op": operation}
            if characteristic is not None: command["uuid"] = characteristic
            if value is not None: command["hex"] = value.hex()
            await self._put("command", command)
            self._launched = True
            await self._adb("shell", shlex.join([
                "am", "start", "--activity-single-top", "-n", self.package + "/.MainActivity",
                "--es", "session", self._config["session"]]))
            async with asyncio.timeout(self._timeout):
                while True:
                    raw = await self._adb("shell", shlex.join([
                        "run-as", self.package, "cat", "files/reply.json"]))
                    if len(raw) > 65536: raise ConnectionError("Unbounded bridge reply")
                    reply = json.loads(raw)
                    if reply.get("session") == command["session"] and reply.get("id") == command["id"]:
                        if reply.get("ok") is not True:
                            raise ConnectionError("Android bridge operation failed")
                        return bytes.fromhex(reply.get("hex", ""))
                    await asyncio.sleep(0.025)

    async def connect(self):
        await self._put("config", self._config)
        # Wait for this command’s reply, not an older reply.
        await self._adb("shell", shlex.join(["run-as", self.package, "sh", "-c",
            "mkdir -p files && printf '{}' > files/reply.json"]))
        await self._operation("connect")

    async def read(self, characteristic):
        if characteristic not in {NEW_KEY, EXTENDED, STATUS}:
            raise ValueError("Only key-input/extended/status reads permitted")
        return await self._operation("read", characteristic=characteristic)

    async def write(self, characteristic, value):
        if characteristic not in {PASSWORD, AUTHORIZATION}:
            raise ValueError("Only access/authorization writes permitted")
        if type(value) is not bytes or not 1 <= len(value) <= 20:
            raise ValueError("Bounded acknowledged GATT write required")
        await self._operation("write", characteristic=characteristic, value=value)

    async def disconnect(self):
        if self._launched:
            await self._operation("disconnect")
