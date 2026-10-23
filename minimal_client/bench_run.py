"""Authorize the selected bench pump and read its encrypted status."""
import argparse
import asyncio
from datetime import datetime,timezone
import json
import os
from pathlib import Path
import re
import secrets
import time

from .bench import BenchRelayRun,CandidateOnce,settings_password,validate_target
from .bench_phone import BenchTransport,CAMAPS,PACKAGE,permissions,resolve_usual
from .bench_ui import BenchNativeUI
from .core import MinimalClient
from .protocol import crc16,digest,public_key,shared_key,validate_fragment
from .relay import RelayAuthorizationProvider,context_digest,decode_context,private_write,read_json,write_json
from .relay_wire import APP

ROOT=Path(__file__).resolve().parent.parent


def observed_crypto_diagnostic(frames,context,private):
    """Inspect already received bytes only; never issues another pump request."""
    import struct
    from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_decrypt
    if not frames:return {'status_bytes_received':False}
    try:
        count=validate_fragment(frames[0],1)
        if len(frames)!=count:raise ValueError('Incomplete observed status')
        for i,frame in enumerate(frames,1):validate_fragment(frame,i,count)
        packet=b''.join(x[1:] for x in frames)
        if len(packet)<40:raise ValueError('Observed AEAD packet too short')
        plain=crypto_aead_xchacha20poly1305_ietf_decrypt(packet[:-24],None,packet[-24:],shared_key(private,context.pump.public_key))
        result={'status_bytes_received':True,'aead_authenticated':True,'authenticated_bytes':len(plain),
            'authenticated_payload_sha256':digest(plain),'contains_counter_tail':len(plain)>=12,'additional_pump_requests':0}
        if len(plain)>=12:
            payload=plain[:-12];reboot,counter=struct.unpack('<iq',plain[-12:])
            result.update(crc_matches_client_policy=len(payload)>=2 and crc16(payload[:-2])==payload[-2:],
                reboot_counter=reboot,numeric_counter=counter,counters_match_client_policy=reboot>=0 and counter>=0)
        return result
    except Exception as error:
        return {'status_bytes_received':True,'aead_authenticated':False,'error_type':type(error).__name__,
            'additional_pump_requests':0}


def vpn_ranges(data):
    lines=[line for line in data.splitlines() if b'sessionId=PCAPdroid VPN' in line]
    scopes=[s for line in lines for s in re.findall(rb'Uids: <([^>]+)>',line)]
    return {(int(a),int(b)) for scope in scopes for a,b in re.findall(rb'(\d+)-(\d+)',scope)}


def pcap_vpn_active(data):
    """The prepared package name alone does not establish a connected VPN."""
    names=re.findall(rb'(?m)^[ \t]*Active package name:[ \t]*([^\r\n]*)',data)
    kinds=re.findall(rb'(?m)^[ \t]*Active vpn type:[ \t]*(-?\d+)[ \t]*$',data)
    return [name.strip() for name in names]==[b'com.emanuelef.remote_capture'] and kinds==[b'1']


def validate_renewal_confirmation(target,resumed,lease,*,now_ms):
    """Require fresh saved-key status before replacing the key."""
    validate_target(target)
    lease.assert_target(target['peer_sha256'],target['firmware'])
    active=lease.credential()
    try:observed=int(datetime.fromisoformat(resumed['utc']).timestamp()*1000)
    except (KeyError,ValueError,TypeError):raise ValueError('Dated independent status required') from None
    freshness_limit=300000
    if (not 0<=now_ms-observed<=freshness_limit or resumed.get('physical_pump_used') is not True or
        resumed.get('independent_status_authenticated') is not True or resumed.get('saved_session_used') is not True or
        resumed.get('peer_sha256')!=target['peer_sha256'] or
        resumed.get('context_sha256')!=context_digest(decode_context(active['context'])) or
        resumed.get('session_after',{}).get('generation')!=active['generation'] or
        resumed.get('session_after',{}).get('revision')!=lease.summary()['revision'] or
        resumed.get('status_packet_sha256')!=active['seen_packets'][-1] or
        any(resumed.get(k)!=0 for k in ['backend_requests','new_key_requests','authorization_writes'])):
        raise ValueError('Fresh authenticated saved-session proof does not match the active credential')


async def experiment(args):
    target=read_json(args.target);peer=validate_target(target)
    lease=getattr(args,'session_lease',None)
    renewal=getattr(args,'renewal_baseline',None)
    if renewal is not None:
        if lease is None:raise ValueError('Renewal requires an encrypted persistent session')
        validate_renewal_confirmation(target,read_json(renewal),lease,now_ms=int(time.time()*1000))
    usual=await resolve_usual()
    ui=BenchNativeUI(usual,target)
    raw,_=await usual.shell('pm','path',PACKAGE,check=False)
    if raw.startswith(b'package:'):raise RuntimeError('Preexisting connection helper; no overwrite')
    vpn,_=await usual.shell('dumpsys','vpn_management')
    uid_raw,_=await usual.shell('cmd','package','list','packages','-U',APP)
    uid=re.search(rb'uid:(\d+)',uid_raw)
    # Check that the VPN still covers only mylife.
    approved=json.loads((Path(os.environ.get('YPSO_VPN_SCOPE', str(ROOT/'private/scoped-vpn-state.json')))).read_text())
    expected=vpn_ranges('\n'.join(approved['vpn_lines']).encode())
    if (not pcap_vpn_active(vpn) or not expected or
        vpn_ranges(vpn)!=expected or uid is None or (int(uid.group(1)),int(uid.group(1))) not in expected):
        raise RuntimeError('Verified mylife-only scoped VPN required')
    reverse,_=await usual.adb('reverse','--list')
    if b'tcp:18520' in reverse:raise RuntimeError('Preexisting USB reverse; no overwrite')
    args.out.mkdir(parents=True,exist_ok=False,mode=0o700)
    write_json(args.out/'target.json',target)
    write_json(args.out/'inputs.json',{'metadata_target':str(args.target),'apk_sha256':digest(args.apk.read_bytes()),
        'source_sha256':{str(p.relative_to(ROOT)):digest(p.read_bytes()) for p in
            list((ROOT/'minimal_client').rglob('*'))+[ROOT/'authorization_provider.py']
            if p.suffix in {'.py','.java','.xml'}}})
    pins=read_json(args.out/'inputs.json')['source_sha256']
    for name,expected in pins.items():
        data=(ROOT/name).read_bytes()
        if digest(data)!=expected:raise RuntimeError('Source changed while recording execution archive')
        archived=args.out/'source'/name
        archived.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        private_write(archived,data)
    write_json(args.out/'source-archive.json',{'scope':'Exact pre-run source copies',
        'sha256':pins,'reconstructed_sources':[]})
    if lease is not None:
        write_json(args.out/'session-input.json',{'session_before':lease.summary(),
            'encrypted_store':str(lease.store.directory),'renewal_baseline':str(renewal) if renewal else None,
            'client_key_persisted_encrypted':True,'wrapping_key_stored_in':'host OS Secret Service'})
    proxy=None;proxy_log=None;forward=False;installed=False;client=None;transport=None
    run=None;result=None;failure=None;cleanup={};selected=False
    previous_generation=lease.summary()['generation'] if lease is not None else None
    private=lease.prepare() if lease is not None else secrets.token_bytes(32)
    try:
        await usual.adb('install',str(args.apk),timeout=60);installed=True
        await permissions(usual)
        # Stop CamAPS before the independent test.
        await usual.shell('am','force-stop',CAMAPS)
        await ui.find()
        created=int(time.time()*1000)
        write_json(args.out/'preflight.json',{'scope':'physical-bench','created_ms':created,
            'expires_ms':created+240000,'target':target,'app_public_key_hex':public_key(private).hex()})
        proxy_log=(args.out/'proxy.log').open('xb');os.chmod(args.out/'proxy.log',0o600)
        proxy=await asyncio.create_subprocess_exec(str(Path(os.environ.get('YPSO_MITMDUMP', str(ROOT/'.venv/bin/mitmdump')))),
            '--mode','socks5','--listen-host','127.0.0.1','--listen-port','18520',
            '--set','confdir='+str(Path(os.environ.get('YPSO_MITM_CONFDIR', str(ROOT/'private/mitmproxy')))),
            '--set','connection_strategy=lazy','--set','upstream_cert=false','--set','ssl_insecure=false',
            '-s',str(ROOT/'minimal_client/bench_proxy.py'),stdout=proxy_log,stderr=asyncio.subprocess.STDOUT,
            env=dict(os.environ,YPSO_BENCH_RUN=str(args.out.resolve())))
        async with asyncio.timeout(10):
            while not (args.out/'proxy-started.marker').exists():
                if proxy.returncode is not None:raise RuntimeError('Bench proxy did not load')
                await asyncio.sleep(.05)
        await usual.adb('reverse','tcp:18520','tcp:18520');forward=True
        # Record possible key changes before mylife starts.
        write_json(args.out/'controller-recovery-required.json',{'utc':datetime.now(timezone.utc).isoformat(),
            'possible_key_change':True,'delivery_authorized':False,'automatic_retry_allowed':False,
            'reason':'Genuine app is about to request physical challenge; lost responses cannot imply rollback'})
        if lease is not None:lease.changing()
        selected=True
        await ui.add()
        print(json.dumps({'phase':'waiting-for-fresh-physical-context','out':str(args.out)}),flush=True)
        async with asyncio.timeout(150):
            while not (args.out/'captured-context.json').exists():
                if (args.out/'failure.json').exists():raise RuntimeError('Physical relay guard failed')
                if proxy.returncode is not None:raise RuntimeError('Bench proxy exited')
                await asyncio.sleep(.05)
        context=decode_context(read_json(args.out/'captured-context.json'))
        if context.pump.bt_address!=peer or context.app_public_key!=public_key(private):
            raise RuntimeError('Captured physical context does not bind this client')
        shared_key(private,context.pump.public_key)  # reject low-order key before issuance
        if lease is not None:lease.bind(context)
        run=BenchRelayRun(args.out/'relay')
        candidate=await RelayAuthorizationProvider(run).authorize(context,timeout_seconds=35)
        # Stop mylife before our client connects.
        await usual.shell('am','force-stop',APP)
        await asyncio.sleep(.25)
        transport=BenchTransport(serial=usual.serial,adb_port=usual.port,target=target,
            mode='bench-status',candidate=candidate)
        client=MinimalClient(transport,CandidateOnce(candidate),bt_address=peer,password=settings_password(peer),
            device_id=context.device_id,metrics=context.metrics,private_key=private,captured_context=context)
        print(json.dumps({'phase':'physical-authorization-and-encrypted-status'}),flush=True)
        if lease is not None:lease.authorization_attempt()
        observation=await client.run(timeout_seconds=65,cleanup_seconds=12)
        if lease is not None:
            packet=b''.join(frame[1:] for frame in transport.status_frames)
            persisted=lease.activate(packet)
            if persisted!=(observation.payload,observation.reboot_counter,observation.numeric_counter):
                raise RuntimeError('Persisted candidate verification differs from runtime status')
        result={'utc':datetime.now(timezone.utc).isoformat(),'physical_pump_used':True,
            'firmware':target['firmware'],'independent_status_authenticated':True,
            'status_payload_bytes':len(observation.payload),'status_payload_sha256':digest(observation.payload),
            'reboot_counter':observation.reboot_counter,'numeric_counter':observation.numeric_counter,
            'context_sha256':observation.context_sha256,'authorization_sha256':digest(candidate.payload),
            'client':client.report(),'delivery_commands_sent':False,'clock_commands_sent':False,
            'camaps_restoration_verified':False,'renewal_tested':renewal is not None,'credentials_persisted':lease is not None}
        if lease is not None:result['session_store']=lease.summary()
        if renewal is not None:result['previous_generation']=previous_generation
        write_json(args.out/'result.json',result)
    except Exception as error:
        failure=type(error).__name__
        if lease is not None and selected and not lease.poisoned:
            try:lease.uncertain()
            except Exception as state_error:
                write_json(args.out/'session-journal-failure.json',{'error_type':type(state_error).__name__,
                    'session_requires_recovery':True,'original_failure_type':failure})
        elif lease is not None and not lease.poisoned:
            lease.abort_prepared()
        write_json(args.out/'failure-detail.json',{'error_type':failure,'detail':str(error)[:1200]})
        write_json(args.out/'partial-result.json',{'client':client.report() if client else None,
            'controller_recovery_required':selected,'backend_candidate_received':bool(run and run.path('consumed.json').exists()),
            'physical_authorization_write_attempted':bool(client and client.authorization_write_attempted)})
        if transport is not None and client is not None and client.context is not None:
            write_json(args.out/'status-crypto-diagnostic.json',
                observed_crypto_diagnostic(transport.status_frames,client.context,private))
    finally:
        private=bytes(32)
        if transport is not None:
            write_json(args.out/'transport-events.json',{'events':transport.events,
                'encrypted_status_frames_hex':[x.hex() for x in transport.status_frames]})
        if run is not None and not run.path('consumed.json').exists():run.fail('physical experiment ended')
        # Stop mylife before removing the proxy.
        await usual.shell('am','force-stop',APP)
        if proxy is not None:
            if proxy.returncode is None:
                proxy.terminate()
                try:await asyncio.wait_for(proxy.wait(),5)
                except TimeoutError:proxy.kill();await proxy.wait()
            cleanup['proxy_stopped']=proxy.returncode is not None
        if proxy_log is not None:proxy_log.close()
        if forward:
            await usual.adb('reverse','--remove','tcp:18520');cleanup['own_usb_reverse_removed']=True
        if installed:
            raw,_=await usual.adb('uninstall',PACKAGE);cleanup['own_bridge_removed']=b'Success' in raw
        await usual.shell('input','keyevent','HOME')
        write_json(args.out/'cleanup.json',{'checks':cleanup,'passed':all(cleanup.values()),
            'scope':'own bridge/proxy/reverse; genuine test entry, network and CamAPS restoration are separate',
            'test_entry_may_exist':selected,'camaps_restoration_required':selected,
            'normal_app_restart_deferred_until_native_entry_and_network_cleanup':True})
    passed=result is not None and failure is None and all(cleanup.values())
    write_json(args.out/'summary.json',{'utc':datetime.now(timezone.utc).isoformat(),'passed':passed,
        'failure_type':failure,'physical_status_test_only':True,'camaps_restoration_verified':False,
        'controller_recovery_required':selected})
    print(json.dumps({'passed':passed,'failure_type':failure,'out':str(args.out),
        'camaps_restoration_still_required':selected}),flush=True)
    return 0 if passed else 1


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ['target','apk','out']:parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--session-store',type=Path,
        help='Explicit encrypted persistent bench session; OS Secret Service required')
    parser.add_argument('--renewal-baseline',type=Path,
        help='Fresh matching saved-session status result for the A-to-B renewal test')
    args=parser.parse_args()
    if args.session_store is None:return asyncio.run(experiment(args))
    from .session_store import SessionStore
    target=read_json(args.target)
    with SessionStore(args.session_store).lease() as lease:
        if lease.store.path.exists():lease.load()
        else:lease.create(peer_sha256=target['peer_sha256'],firmware=target['firmware'])
        lease.assert_target(target['peer_sha256'],target['firmware'])
        args.session_lease=lease
        return asyncio.run(experiment(args))

if __name__=='__main__':raise SystemExit(main())
