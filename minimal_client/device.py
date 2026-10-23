"""Run commands on the selected phone."""
import asyncio
import os
import shlex
from dataclasses import dataclass, field

@dataclass
class Device:
    role: str
    identity: str
    port: int
    serial: str = field(repr=False)

    async def adb(self, *args, data=None, check=True, timeout=30):
        process = await asyncio.create_subprocess_exec(
            os.environ.get("YPSO_ADB", "/usr/bin/adb"), "-P", str(self.port), "-s", self.serial, *map(str, args),
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE)
        try:
            out, err = await asyncio.wait_for(process.communicate(data), timeout)
        except BaseException:
            if process.returncode is None:
                process.kill(); await process.wait()
            raise
        if check and process.returncode:
            detail=(out+err).decode(errors='replace').replace(self.serial,'<redacted>')[:2000]
            raise RuntimeError("Lab phone command failed for recorded " + self.role +
                               " ("+str(args[0])+"): "+detail)
        return out, process.returncode

    async def shell(self, *args, **kwargs):
        return await self.adb("shell", shlex.join(list(map(str, args))), **kwargs)

