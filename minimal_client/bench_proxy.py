"""Replace the client public key in one genuine mylife request."""
import asyncio
import os
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from minimal_client.bench import BenchRelayRun, captured_key_context, validate_target
from minimal_client.relay import RelayExchange, encode_context, private_write, read_json, write_json
from minimal_client.relay_wire import HOST, KEY_PATH, NONCE_PATH, nonce_context, response_bytes


class BenchAddon:
    def __init__(self, directory=None):
        self.directory = directory
        self.run = None
        self.exchange = None
        self.http = None
        self.root = None
        self.preflight = None
        self.nonce_packet = None
        self.nonce_response_packet = None

    def load(self, loader):
        from mitmproxy import http
        self.http = http
        if not self.directory:
            raise RuntimeError('YPSO_BENCH_RUN must name one fresh private bench directory')
        self.root = Path(self.directory).resolve()
        if self.root.stat().st_mode & 0o077:
            raise ValueError('Private bench run directory required')
        self.preflight = read_json(self.root/'preflight.json')
        if self.preflight.get('scope') != 'physical-bench':
            raise ValueError('Explicit bench scope required')
        validate_target(self.preflight['target'])
        self.check_live()
        private_write(self.root/'proxy-started.marker', b'one explicit bench proxy\n')

    def check_live(self):
        now = int(time.time()*1000)
        if (type(self.preflight['created_ms']) is not int or type(self.preflight['expires_ms']) is not int or
            not 0 < self.preflight['expires_ms'] - self.preflight['created_ms'] <= 300000 or
            not self.preflight['created_ms'] - 1000 <= now < self.preflight['expires_ms'] or
            (self.root/'cancelled.json').exists()):
            raise TimeoutError('Bench transaction is expired or cancelled')

    def fail(self, flow, error):
        try:
            write_json(self.root/'failure.json', {'error_type':type(error).__name__,
                'stage':flow.metadata.get('relay_stage', 'guard')})
        except FileExistsError:
            pass
        try:
            write_json(self.root/'cancelled.json', {'reason':type(error).__name__})
        except FileExistsError:
            pass
        if self.run is not None:
            self.run.fail(type(error).__name__)
        self.withhold(flow)

    async def request(self, flow):
        try:
            self.check_live()
            if (flow.client_conn.sni != HOST or flow.request.path not in {NONCE_PATH, KEY_PATH} or
                not flow.server_conn.address or flow.server_conn.address[1] != 443):
                raise ValueError('Unexpected host or RPC')
            flow.request.host = HOST; flow.request.port = 443; flow.request.authority = HOST
            target_address = bytes.fromhex(self.preflight['target']['rpc_identity_hex'])
            if flow.request.path == NONCE_PATH:
                flow.metadata['relay_stage'] = 'bench-nonce'
                _, address, _, _ = nonce_context(flow.request.raw_content)
                if address != target_address:
                    raise ValueError('Native nonce targets a different pump')
                private_write(self.root/'nonce-request.marker', b'one fresh physical nonce\n')
                self.nonce_packet = flow.request.raw_content
                private_write(self.root/'nonce-request.grpc', self.nonce_packet)
            else:
                flow.metadata['relay_stage'] = 'authorization'
                if self.nonce_packet is None or self.nonce_response_packet is None:
                    raise ValueError('No fresh successful Native nonce')
                private_write(self.root/'key-arrived.marker', b'one actual Native key context\n')
                context = captured_key_context(flow.request.raw_content, self.nonce_packet,
                    bytes.fromhex(self.preflight['app_public_key_hex']), target_address)
                self.run = BenchRelayRun.create(self.root/'relay', challenge=context.challenge,
                    pump_public_key=context.pump.public_key, app_public_key=context.app_public_key,
                    peer_sha256=self.preflight['target']['peer_sha256'],
                    lifetime_seconds=min(120, (self.preflight['expires_ms']-int(time.time()*1000))/1000))
                self.exchange = RelayExchange(self.run)
                self.exchange.nonce_request(self.nonce_packet)
                self.exchange.nonce_response(self.nonce_response_packet, 200, '0')
                write_json(self.root/'captured-context.json', encode_context(context))
                async with asyncio.timeout(20):
                    while not self.run.path('request.json').exists():
                        self.check_live(); await asyncio.sleep(.05)
                flow.request.raw_content = self.exchange.authorization_request(flow.request.raw_content)
        except Exception as error:
            self.fail(flow, error)

    def response(self, flow):
        stage = flow.metadata.get('relay_stage')
        if not stage or flow.response is None or (self.root/'failure.json').exists():
            return
        try:
            self.check_live()
            response = flow.response
            status = (response.trailers or {}).get('grpc-status') or response.headers.get('grpc-status')
            if stage == 'bench-nonce':
                if response.status_code != 200 or status != '0':
                    raise ValueError('Genuine nonce RPC rejected')
                response_bytes(response.raw_content, 24)
                private_write(self.root/'nonce-response.grpc', response.raw_content)
                self.nonce_response_packet = response.raw_content
            else:
                self.exchange.authorization_response(response.raw_content, response.status_code, status)
        except Exception as error:
            self.fail(flow, error)
        finally:
            if stage == 'authorization':
                self.withhold(flow)


    def withhold(self, flow):
        flow.response = self.http.Response.make(200,b'',{'content-type':'application/grpc'})
        flow.response.trailers = self.http.Headers([(b'grpc-status',b'14'),
            (b'grpc-message',b'Local authorization relay withheld response')])

    def server_connect(self, data):
        address = data.server.address; name = data.server.sni or data.client.sni
        if address is None or address[1] != 443 or not (name == HOST or address[0] == HOST):
            data.server.error = 'Only the fixed authorization backend is permitted'; return
        data.server.address = (HOST,443); data.server.sni = HOST

    def error(self, flow):
        if flow.metadata.get('relay_stage'):
            self.fail(flow,ConnectionError('Backend transport failed'))


addons = [BenchAddon(os.environ.get('YPSO_BENCH_RUN'))]
