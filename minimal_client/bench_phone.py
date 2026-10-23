"""Connect only to the recorded phone and paired pump."""
import argparse
import asyncio
import os
import hashlib
import json
import re
import time
from pathlib import Path

from authorization_provider import AuthorizationCandidate, ContractError
from .adb_transport import AdbTransport
from .bench import settings_password, validate_target
from .device import Device
from .protocol import AUTHORIZATION, EXTENDED, NEW_KEY, PASSWORD, STATUS, fragments
from .relay import private_write, read_json, write_json
from .ui import UI

ROOT=Path(__file__).resolve().parent.parent
PACKAGE='org.ypso.research.benchclient'
FW='669a0c20-0008-969e-e211-fcbeb0147bc5'
METADATA=[FW]+['669a0c20-0008-969e-e211-'+s for s in ['fcbee23b7bc5','fcbee33b7bc5','fcbee43b7bc5']]
CAMAPS='com.camdiab.fx_alert.mmoll'


async def resolve_usual():
    saved=json.loads((Path(os.environ.get('YPSO_RIG', str(ROOT/'private/connected-rig.json')))).read_text())
    wanted=next(d['identity_sha256'] for d in saved['devices'] if d['role']=='usual_phone')
    for port in [5037,5047]:
        process=await asyncio.create_subprocess_exec(os.environ.get("YPSO_ADB", "/usr/bin/adb"),'-P',str(port),'devices',
            stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE)
        raw,_=await asyncio.wait_for(process.communicate(),15)
        matching=[]
        for line in raw.decode(errors='replace').splitlines()[1:]:
            fields=line.split()
            if len(fields)>1 and fields[1]=='device' and hashlib.sha256(fields[0].encode()).hexdigest()==wanted:
                matching.append(fields[0])
        if len(matching)==1:return Device('usual_phone',wanted,port,matching[0])
        if matching:raise RuntimeError('Ambiguous recorded phone')
    raise RuntimeError('Recorded usual phone is not connected/authorized')


def ascii_version(value):
    if type(value) is not bytes or not 2<=len(value)<=20 or b'\0' not in value:
        raise ContractError('Expected bounded NUL-terminated version metadata')
    text=value.split(b'\0',1)[0].decode('ascii')
    if not text or re.fullmatch(r'[A-Za-z0-9.]+',text) is None:
        raise ContractError('Invalid version text')
    return text


class BenchTransport(AdbTransport):
    package=PACKAGE

    def __init__(self, *, serial, adb_port, target, mode, candidate=None, resume_generation=None):
        self._peer=validate_target(target)
        if mode not in {'bench-metadata','bench-status','bench-resume'}:
            raise ContractError('Explicit bench operation mode required')
        if mode=='bench-status':
            if not isinstance(candidate,AuthorizationCandidate) or candidate.context.pump.bt_address!=self._peer:
                raise ContractError('Fresh exact-target candidate required')
            if not isinstance(target.get('firmware'),str) or not target['firmware']:
                raise ContractError('Actual preflight firmware required')
        elif candidate is not None:
            raise ContractError('Metadata preflight cannot carry an authorization')
        if mode=='bench-resume':
            from uuid import UUID
            if not isinstance(resume_generation,str) or str(UUID(resume_generation))!=resume_generation:
                raise ContractError('Explicit saved credential generation required')
            if not isinstance(target.get('firmware'),str) or not target['firmware']:
                raise ContractError('Actual preflight firmware required')
        elif resume_generation is not None:
            raise ContractError('Saved credential generation belongs only to resume mode')
        super().__init__(serial=serial,adb_port=adb_port,peer_address=target['peer_address'],
            peer_sha256=target['peer_sha256'])
        self._mode=mode;self.events=[];self.status_frames=[]
        self._config.update(scope='physical-bench',mode=mode,expected_name=target['name'],
            expires_ms=int(time.time()*1000)+110000,expected_firmware=target.get('firmware'))
        if candidate is not None:self._config['authorization_hex']=candidate.payload.hex()
        if resume_generation is not None:self._config['resume_generation']=resume_generation

    @classmethod
    async def discover(cls, **kwargs):
        raise ContractError('Physical bench has no discovery interface; exact existing bond required')

    async def _operation(self,operation,*,characteristic=None,value=None):
        event={'op':operation,'uuid':characteristic,'write_bytes':len(value) if value is not None else 0}
        self.events.append(event)
        try:
            result=await super()._operation(operation,characteristic=characteristic,value=value)
            event.update(ok=True,read_bytes=len(result))
            if operation=='read' and characteristic in {STATUS,EXTENDED}:self.status_frames.append(result)
            return result
        except BaseException as error:
            event.update(ok=False,error_type=type(error).__name__)
            try:
                import shlex
                raw=await self._adb('shell',shlex.join(['run-as',self.package,'cat','files/reply.json']))
                reply=json.loads(raw)
                if reply.get('session')==self._config['session'] and reply.get('id')==self._sequence:
                    event['bridge_result']={k:reply.get(k) for k in ['gatt_status','operation','bridge_error']}
            except Exception:pass
            raise

    async def read(self,characteristic):
        allowed=set(METADATA) if self._mode=='bench-metadata' else {STATUS,EXTENDED}
        if characteristic not in allowed or characteristic==NEW_KEY:
            raise ContractError('Bench adapter never requests new key material')
        return await self._operation('read',characteristic=characteristic)

    async def write(self,characteristic,value):
        allowed={PASSWORD,AUTHORIZATION} if self._mode=='bench-status' else {PASSWORD}
        if characteristic not in allowed:
            raise ContractError('Bench write is outside the explicit operation scope')
        if type(value) is not bytes or not 1<=len(value)<=20:
            raise ContractError('Bounded acknowledged bench write required')
        if characteristic==PASSWORD and value!=settings_password(self._peer):
            raise ContractError('Access password does not match recorded peer')
        await self._operation('write',characteristic=characteristic,value=value)
        if characteristic==PASSWORD and self._mode in {'bench-status','bench-resume'}:
            actual=ascii_version(await self._operation('read',characteristic=FW))
            if actual!=self._config['expected_firmware']:
                raise ContractError('Pump firmware differs from captured baseline')

    async def catalog(self):
        if self._mode!='bench-metadata':raise ContractError('Catalog belongs to metadata preflight')
        value=json.loads((await self._operation('catalog')).decode())
        if not isinstance(value,list) or not 1<=len(value)<=200:
            raise ContractError('Unbounded physical catalog')
        return value


async def permissions(device):
    await device.shell('am','start','-n',PACKAGE+'/.MainActivity','--ez','permissions_only','true')
    async with asyncio.timeout(45):
        while True:
            raw,status=await device.shell('run-as',PACKAGE,'cat','files/permissions.json',check=False)
            if status==0:
                if json.loads(raw).get('granted') is not True:raise RuntimeError('Nearby permission denied')
                return
            ns=await UI(device).nodes()
            if any('Bench status bridge' in n.get('text','') for n in ns):
                buttons=[n for n in ns if n.get('resource-id','').endswith(':id/permission_allow_button')
                    and n.get('package') in {'com.google.android.permissioncontroller','com.android.permissioncontroller'}]
                if len(buttons)==1:await UI(device).tap(buttons[0],{buttons[0].get('package')})
            await asyncio.sleep(.2)


async def metadata(args):
    device=await resolve_usual();target=read_json(args.target);validate_target(target)
    args.out.mkdir(parents=True,exist_ok=False,mode=0o700)
    raw,_=await device.shell('pm','path',PACKAGE,check=False)
    if raw.startswith(b'package:'):raise RuntimeError('Preexisting bench package; refusing overwrite')
    write_json(args.out/'target.json',target)
    transport=None;installed=False;result=None;failure=None;clean={}
    try:
        await device.adb('install',str(args.apk),timeout=60);installed=True
        await permissions(device)
        transport=BenchTransport(serial=device.serial,adb_port=device.port,target=target,mode='bench-metadata')
        await transport.connect();await transport.write(PASSWORD,settings_password(validate_target(target)))
        catalog=await transport.catalog();versions={}
        for characteristic in METADATA:
            versions[characteristic]=ascii_version(await transport.read(characteristic))
        result={'scope':'Physical existing-bond metadata/access preflight only; no NEW_KEY/auth installation/delivery/clock',
            'firmware':versions[FW],'versions':versions,'catalog':catalog,'events':transport.events,
            'logical_identity_matches_actual_bond':True,'new_key_requested':False,
            'authorization_written':False,'camaps_operated':False}
        write_json(args.out/'result.json',result)
    except Exception as error:
        failure=type(error).__name__;write_json(args.out/'failure.json',{'error_type':failure,'detail':str(error)[:1000]})
    finally:
        if transport is not None:
            try:await transport.disconnect();clean['gatt_closed']=True
            except Exception:clean['gatt_closed']=False
            write_json(args.out/'transport-events.json',{'events':transport.events})
        if installed:
            raw,_=await device.adb('uninstall',PACKAGE);clean['own_bench_app_removed']=b'Success' in raw
        await device.shell('input','keyevent','HOME')
        write_json(args.out/'cleanup.json',{'checks':clean,'passed':all(clean.values())})
    passed=result is not None and failure is None and all(clean.values())
    write_json(args.out/'summary.json',{'passed':passed,'failure_type':failure,'physical_metadata_only':True,
        'new_key_requested':False,'authorization_written':False,'apk_sha256':hashlib.sha256(args.apk.read_bytes()).hexdigest()})
    print(json.dumps({'passed':passed,'failure_type':failure,'firmware':result['firmware'] if result else None,'out':str(args.out)}),flush=True)
    return 0 if passed else 1


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target',type=Path,required=True);parser.add_argument('--apk',type=Path,required=True)
    parser.add_argument('--out',type=Path,required=True);args=parser.parse_args()
    return asyncio.run(metadata(args))

if __name__=='__main__':raise SystemExit(main())
