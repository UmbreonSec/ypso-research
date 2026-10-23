"""Read status using a saved key while both official apps are stopped."""
import argparse
import asyncio
from datetime import datetime, timezone
from pathlib import Path

from .bench import settings_password, validate_target
from .bench_phone import BenchTransport, CAMAPS, PACKAGE, permissions, resolve_usual
from .protocol import digest
from .relay import read_json, write_json
from .relay_wire import APP
from .session_client import ResumeStatusClient
from .session_store import SessionStore

ROOT=Path(__file__).resolve().parent.parent


async def experiment(args, lease):
    target=read_json(args.target);peer=validate_target(target)
    lease.assert_target(target['peer_sha256'],target['firmware'])
    credential=lease.recovery_credential() if args.reconcile_uncertain else lease.credential()
    usual=await resolve_usual()
    for package in [CAMAPS,APP]:
        raw,_=await usual.shell('pidof',package,check=False)
        if raw.strip():raise RuntimeError('Genuine controllers must already be stopped for independent resume')
    raw,_=await usual.shell('pm','path',PACKAGE,check=False)
    if raw.startswith(b'package:'):raise RuntimeError('Preexisting bridge package; refusing overwrite')
    args.out.mkdir(mode=0o700,parents=True,exist_ok=False)
    write_json(args.out/'inputs.json',{'scope':'physical-bench-saved-session-status',
        'target':target,'session_before':lease.summary(),'apk_sha256':digest(args.apk.read_bytes()),
        'source_sha256':{str(p.relative_to(ROOT)):digest(p.read_bytes()) for p in
            (ROOT/'minimal_client').rglob('*') if p.suffix in {'.py','.java','.xml'}},
        'backend_requests_permitted':False,'new_key_permitted':False,'authorization_write_permitted':False})
    if args.reconcile_uncertain:
        write_json(args.out/'explicit-reconciliation.json',{'pre_authorization_failure_only':True,
            'purpose':'Determine whether the prior active key is still accepted using a fresh status only',
            'new_key_or_authorization_write_permitted':False})
    transport=None;client=None;installed=False;result=None;failure=None;cleanup={}
    try:
        await usual.adb('install',str(args.apk),timeout=60);installed=True
        await permissions(usual)
        transport=BenchTransport(serial=usual.serial,adb_port=usual.port,target=target,
            mode='bench-resume',resume_generation=credential['generation'])
        client=ResumeStatusClient(transport,lease,peer_sha256=target['peer_sha256'],
            firmware=target['firmware'],password=settings_password(peer),reconcile=args.reconcile_uncertain)
        observation=await client.run(timeout_seconds=60,cleanup_seconds=12)
        result={'utc':datetime.now(timezone.utc).isoformat(),'physical_pump_used':True,
            'independent_status_authenticated':True,'saved_session_used':True,
            'status_payload_bytes':len(observation.payload),'status_payload_sha256':digest(observation.payload),
            'reboot_counter':observation.reboot_counter,'numeric_counter':observation.numeric_counter,
            'peer_sha256':target['peer_sha256'],'context_sha256':observation.context_sha256,
            'status_packet_sha256':digest(b''.join(f[1:] for f in transport.status_frames)),
            'session_after':lease.summary(),'backend_requests':0,'new_key_requests':0,
            'authorization_writes':0,'delivery_commands_sent':False,'clock_commands_sent':False}
        result['uncertain_session_reconciled']=args.reconcile_uncertain
        write_json(args.out/'result.json',result)
    except Exception as error:
        failure=type(error).__name__
        write_json(args.out/'failure.json',{'error_type':failure,'detail':str(error)[:1000]})
    finally:
        if transport is not None:
            write_json(args.out/'transport-events.json',{'events':transport.events,
                'encrypted_status_frames_hex':[f.hex() for f in transport.status_frames]})
            cleanup['gatt_closed']=bool(client and not client.disconnect_failed)
        if installed:
            raw,_=await usual.adb('uninstall',PACKAGE);cleanup['own_bridge_removed']=b'Success' in raw
        await usual.shell('input','keyevent','HOME')
        write_json(args.out/'cleanup.json',{'checks':cleanup,'passed':all(cleanup.values()),
            'normal_camaps_handback_still_required':True})
    passed=result is not None and failure is None and all(cleanup.values())
    write_json(args.out/'summary.json',{'passed':passed,'failure_type':failure,'saved_session_test_only':True})
    print(__import__('json').dumps({'passed':passed,'failure_type':failure,'out':str(args.out)}),flush=True)
    return 0 if passed else 1


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ['target','apk','session-store','out']:parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--reconcile-uncertain',action='store_true',
        help='Explicit status-only recovery after an unbound pre-authorization failure')
    args=parser.parse_args()
    with SessionStore(args.session_store).lease() as lease:
        lease.load()
        return asyncio.run(experiment(args,lease))


if __name__=='__main__':raise SystemExit(main())
