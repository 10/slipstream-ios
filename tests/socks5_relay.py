#!/usr/bin/env python3
"""Minimal SOCKS5 relay for repeatable device checks: CONNECT, UDP ASSOCIATE, optional
username/password (RFC 1928, RFC 1929). Not hardened; run only on a trusted LAN during a test.

  python3 tests/socks5_relay.py --bind 192.168.86.29 --port 1080 --user u --password p [--no-udp]

--no-udp answers UDP ASSOCIATE with "command not supported" to exercise the app's
"not relayed" result. Prints one line per session; never prints payloads or credentials."""
import argparse, asyncio, ipaddress, socket, struct, sys, time

def log(*parts): print(time.strftime('%H:%M:%S'), *parts, flush=True)

async def read_address(reader):
    kind = (await reader.readexactly(1))[0]
    if kind == 1: host = str(ipaddress.IPv4Address(await reader.readexactly(4)))
    elif kind == 4: host = str(ipaddress.IPv6Address(await reader.readexactly(16)))
    elif kind == 3: host = (await reader.readexactly((await reader.readexactly(1))[0])).decode()
    else: raise ValueError('address type')
    port = struct.unpack('!H', await reader.readexactly(2))[0]
    return host, port

def encode_address(host, port):
    try: return b'\x01' + ipaddress.IPv4Address(host).packed + struct.pack('!H', port)
    except ValueError: return b'\x03' + bytes([len(host)]) + host.encode() + struct.pack('!H', port)

def parse_udp(datagram):
    """Returns (destination host, port, payload) from a SOCKS5 UDP request header."""
    if len(datagram) < 4 or datagram[2] != 0: raise ValueError('fragmented or malformed')
    kind = datagram[3]
    if kind == 1: host, offset = str(ipaddress.IPv4Address(datagram[4:8])), 8
    elif kind == 3: n = datagram[4]; host, offset = datagram[5:5 + n].decode(), 5 + n
    elif kind == 4: host, offset = str(ipaddress.IPv6Address(datagram[4:20])), 20
    else: raise ValueError('address type')
    port = struct.unpack('!H', datagram[offset:offset + 2])[0]
    return host, port, datagram[offset + 2:]

class Relay(asyncio.DatagramProtocol):
    """One UDP ASSOCIATE session: relay between the client and any destination."""
    def __init__(self, client_ip):
        self.client_ip, self.client, self.transport, self.count = client_ip, None, None, 0
        self.upstream = {}
    def connection_made(self, transport): self.transport = transport
    def datagram_received(self, data, addr):
        if addr[0] == self.client_ip:
            self.client = addr
            try: host, port, payload = parse_udp(data)
            except ValueError: return
            key = (host, port)
            if key not in self.upstream:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); sock.setblocking(False); sock.bind(('0.0.0.0', 0))
                asyncio.get_running_loop().create_task(self.upstream_socket(sock, key))
                self.upstream[key] = sock
            self.upstream[key].sendto(payload, key); self.count += 1
    async def upstream_socket(self, sock, key):
        loop = asyncio.get_running_loop()
        while self.transport and not self.transport.is_closing():
            try: data = await asyncio.wait_for(loop.sock_recv(sock, 65535), 60)
            except (asyncio.TimeoutError, OSError): break
            if self.client: self.transport.sendto(b'\x00\x00\x00' + encode_address(*key) + data, self.client)
        sock.close()

async def pipe(reader, writer):
    try:
        while data := await reader.read(65536): writer.write(data); await writer.drain()
    except (ConnectionError, asyncio.CancelledError, OSError): pass
    finally:
        try: writer.close()
        except OSError: pass

async def session(reader, writer, args):
    peer = writer.get_extra_info('peername')
    try:
        version, count = await reader.readexactly(2)
        methods = await reader.readexactly(count)
        wanted = 2 if args.user else 0
        if version != 5 or wanted not in methods:
            writer.write(b'\x05\xff'); await writer.drain(); return
        writer.write(bytes([5, wanted])); await writer.drain()
        if wanted == 2:
            v, n = await reader.readexactly(2); user = await reader.readexactly(n)
            n = (await reader.readexactly(1))[0]; password = await reader.readexactly(n)
            ok = v == 1 and user.decode(errors='replace') == args.user and password.decode(errors='replace') == args.password
            writer.write(bytes([1, 0 if ok else 1])); await writer.drain()
            if not ok: log('rejected credentials from', peer[0]); return
        v, command, _ = await reader.readexactly(3)
        host, port = await read_address(reader)
        if command == 1:
            try: up_reader, up_writer = await asyncio.wait_for(asyncio.open_connection(host, port), 10)
            except (OSError, asyncio.TimeoutError):
                writer.write(b'\x05\x05\x00' + encode_address('0.0.0.0', 0)); await writer.drain(); log('CONNECT failed', peer[0], '->', host, port); return
            writer.write(b'\x05\x00\x00' + encode_address(*up_writer.get_extra_info('sockname')[:2])); await writer.drain()
            log('CONNECT', peer[0], '->', host, port)
            await asyncio.gather(pipe(reader, up_writer), pipe(up_reader, writer))
        elif command == 3:
            if args.no_udp:
                writer.write(b'\x05\x07\x00' + encode_address('0.0.0.0', 0)); await writer.drain(); log('UDP ASSOCIATE refused (--no-udp)', peer[0]); return
            transport, relay = await asyncio.get_running_loop().create_datagram_endpoint(lambda: Relay(peer[0]), local_addr=(args.bind, 0))
            bound = transport.get_extra_info('sockname')
            writer.write(b'\x05\x00\x00' + encode_address(bound[0], bound[1])); await writer.drain()
            log('UDP ASSOCIATE', peer[0], 'relay port', bound[1])
            try:
                while await reader.read(1024): pass
            finally:
                transport.close(); log('UDP session ended', peer[0], 'datagrams relayed', relay.count)
        else:
            writer.write(b'\x05\x07\x00' + encode_address('0.0.0.0', 0)); await writer.drain()
    except (asyncio.IncompleteReadError, ConnectionError, OSError, ValueError):
        pass
    finally:
        writer.close()

async def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--bind', required=True, help='LAN address the phone can reach')
    p.add_argument('--port', type=int, default=1080)
    p.add_argument('--user'); p.add_argument('--password')
    p.add_argument('--no-udp', action='store_true', help='refuse UDP ASSOCIATE')
    args = p.parse_args()
    if bool(args.user) != bool(args.password): sys.exit('use --user and --password together')
    server = await asyncio.start_server(lambda r, w: session(r, w, args), args.bind, args.port)
    log('listening on', args.bind, args.port, 'auth' if args.user else 'no auth', 'udp refused' if args.no_udp else 'udp relayed')
    async with server: await server.serve_forever()

if __name__ == '__main__':
    try: asyncio.run(main())
    except KeyboardInterrupt: pass
