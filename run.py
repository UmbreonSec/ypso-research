"""Run the existing authorization test after the one-time setup in SETUP.md."""
import asyncio
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
from types import SimpleNamespace

from minimal_client.bench import logical_address, validate_target
from minimal_client.bench_phone import CAMAPS, metadata
from minimal_client.bench_run import experiment, pcap_vpn_active, vpn_ranges
from minimal_client.device import Device
from minimal_client.relay import read_json, write_json
from minimal_client.relay_wire import APP

ROOT = Path(__file__).resolve().parent


def phone(adb):
    result = subprocess.run([adb, '-P', '5037', 'devices'], capture_output=True, text=True, check=True, timeout=20)
    devices = [line.split()[0] for line in result.stdout.splitlines()[1:]
               if len(line.split()) >= 2 and line.split()[1] == 'device']
    if not devices:
        raise RuntimeError('Connect and unlock the phone, enable USB debugging and approve this computer.')
    if len(devices) == 1:
        serial = devices[0]
    else:
        for index, serial in enumerate(devices, 1):
            print(f'{index}. {serial}')
        choice = input('Phone number: ')
        if not choice.isdigit() or not 1 <= int(choice) <= len(devices):
            raise RuntimeError('Choose one of the listed phones.')
        serial = devices[int(choice) - 1]
    return Device('usual_phone', hashlib.sha256(serial.encode()).hexdigest(), 5037, serial)


def pump(identity):
    saved = ROOT / 'private/pump.json'
    if saved.exists():
        record = read_json(saved)
        if record.get('phone_identity') == identity:
            validate_target(record['target'])
            return record['target']
    name = input('Paired pump name (YpsoPump_ followed by eight digits): ').strip()
    address = input('Paired Bluetooth address: ').strip().upper()
    peer = bytes.fromhex(address.replace(':', ''))
    target = {'scope': 'paired-pump', 'name': name, 'peer_address': address,
        'peer_sha256': hashlib.sha256(peer).hexdigest(), 'rpc_identity_hex': logical_address(name).hex()}
    validate_target(target)
    temporary = saved.with_name('pump-' + secrets.token_hex(4) + '.tmp')
    write_json(temporary, {'phone_identity': identity, 'target': target})
    os.replace(temporary, saved)
    return target


async def run():
    os.umask(0o077)
    private = ROOT / 'private'
    private.mkdir(mode=0o700, exist_ok=True)
    apk = ROOT / 'build/bridge-01/bench-client.apk'
    proxy = Path(os.environ.get('YPSO_MITMDUMP', str(ROOT/'.venv-proxy/bin/mitmdump')))
    adb = os.environ.get('YPSO_ADB') or shutil.which('adb')
    if not adb or not apk.is_file() or not proxy.is_file():
        raise RuntimeError('Finish the one-time setup in SETUP.md first (adb, bridge build and proxy).')
    os.environ['YPSO_ADB'], os.environ['YPSO_MITMDUMP'] = adb, str(proxy.resolve())
    os.environ.setdefault('YPSO_MITM_CONFDIR', str(private/'mitmproxy'))
    device = phone(adb)
    raw, _ = await device.shell('dumpsys', 'vpn_management')
    package, _ = await device.shell('cmd', 'package', 'list', 'packages', '-U', APP)
    uid = re.search(rb'uid:(\d+)', package)
    if uid is None or not pcap_vpn_active(raw) or vpn_ranges(raw) != {(int(uid.group(1)), int(uid.group(1)))}:
        raise RuntimeError('Start the mylife-only PCAPdroid connection described in SETUP.md.')
    target = pump(device.identity)
    folder = private / (datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S-') + secrets.token_hex(4))
    folder.mkdir(mode=0o700)
    write_json(folder/'target.json', target)
    write_json(folder/'phone.json', {'devices': [{'role': 'usual_phone', 'identity_sha256': device.identity}]})
    write_json(folder/'vpn.json', {'vpn_lines': [line for line in raw.decode().splitlines() if 'sessionId=PCAPdroid VPN' in line]})
    os.environ['YPSO_RIG'], os.environ['YPSO_VPN_SCOPE'] = str(folder/'phone.json'), str(folder/'vpn.json')
    for app in [APP, CAMAPS]:
        await device.shell('am', 'force-stop', app)
    print('Reading firmware…', flush=True)
    if await metadata(SimpleNamespace(target=folder/'target.json', apk=apk, out=folder/'metadata')):
        raise RuntimeError('Firmware check failed; see ' + str(folder/'metadata'))
    target['firmware'] = read_json(folder/'metadata/result.json')['firmware']
    write_json(folder/'measured-target.json', target)
    print('Authorizing and reading encrypted status…', flush=True)
    status = await experiment(SimpleNamespace(target=folder/'measured-target.json', apk=apk,
        out=folder/'authorization', renewal_baseline=None))
    print('Authorization passed.' if status == 0 else 'Authorization failed. No retry was made.')
    print('Results: ' + str(folder))
    print('Finish the cleanup steps in SETUP.md before returning to CamAPS.')
    return status


if __name__ == '__main__':
    try:
        raise SystemExit(asyncio.run(run()))
    except Exception as error:
        raise SystemExit(str(error))
