#!/usr/bin/env python3
"""Audit XS DLT_PKTAP v1 captures without printing packet payloads or credentials."""
import argparse
import collections
import ipaddress
import json
import struct
import uuid


def audit(path, selected, names, tunnel=(), provider=(), proxy=()):
    """With an app proxy there is no tunnel: selected apps' flows are diverted before any packet
    exists, so every selected packet is direct, and the provider may only reach the proxy."""
    tunnels = {tunnel} if isinstance(tunnel, str) else set(tunnel)
    providers = set(provider)
    # A proxy switch may legitimately use the previous or the new endpoint.
    proxies = {(host, int(port)) for host, port in (p.rsplit(':', 1) for p in ([proxy] if isinstance(proxy, str) else proxy))}
    counts = collections.Counter()
    destinations = set()
    with open(path, 'rb') as stream:
        header = stream.read(24)
        if len(header) != 24 or struct.unpack('<IHHIIII', header)[0] != 0xA1B2C3D4 or struct.unpack_from('<I', header, 20)[0] != 258:
            raise ValueError('Expected little-endian pcap with DLT_PKTAP')
        while record := stream.read(16):
            if len(record) != 16:
                raise ValueError('Truncated record header')
            _, _, captured, original = struct.unpack('<IIII', record)
            packet = stream.read(captured)
            if len(packet) != captured or captured < 156:
                raise ValueError('Truncated PKTAP header')
            length, next_type = struct.unpack_from('<II', packet)
            flags = struct.unpack_from('<I', packet, 36)[0]
            if flags & 0x80000 or length != 156 or next_type != 1:
                raise ValueError('Unsupported PKTAP header version')
            counts['packets'] += 1
            if not flags & 2:
                continue
            interface = packet[12:36].split(b'\0')[0].decode()
            process = packet[56:73].split(b'\0')[0].decode(errors='replace')
            effective = packet[88:105].split(b'\0')[0].decode(errors='replace')
            ids = {str(uuid.UUID(bytes=packet[124:140])), str(uuid.UUID(bytes=packet[140:156]))}
            prefix = struct.unpack_from('<I', packet, 44)[0]
            ip = packet[length + prefix:]
            source = None
            if len(ip) >= 20 and ip[0] >> 4 == 4:
                source = str(ipaddress.ip_address(ip[12:16]))
            elif len(ip) >= 40 and ip[0] >> 4 == 6:
                source = str(ipaddress.ip_address(ip[8:24]))
            if source in ('198.18.0.1', 'fd00:51:1::1') and interface not in tunnels:
                counts['tunnel_source_outside_tunnel'] += 1
            if providers and {process, effective} & providers:
                destination, proto, port = endpoint(ip)
                # A SOCKS5 UDP relay port is chosen per association; only its host is fixed.
                if (destination, port) in proxies and proto == 6 or proto == 17 and destination in {host for host, _ in proxies}:
                    counts['provider_to_proxy'] += 1
                else:
                    counts['provider_elsewhere'] += 1
                continue
            if not (ids & selected or {process, effective} & names):
                counts['other_outbound'] += 1
                continue
            address, proto, port = endpoint(ip)
            if address is None:
                raise ValueError('Selected packet has unsupported or truncated IP header')
            counts['selected_outbound'] += 1
            counts[f'selected_ipv{ip[0] >> 4}'] += 1
            counts[f'selected_protocol_{proto}'] += 1
            if port == 53:
                counts['selected_dns'] += 1
            destinations.add(address)
            if interface in tunnels:
                counts['selected_tunnel'] += 1
            else:
                counts['selected_outside_tunnel'] += 1
    if providers:
        passed = counts['provider_to_proxy'] > 0 and counts['provider_elsewhere'] == 0 and counts['selected_outbound'] == 0
    else:
        passed = counts['selected_outbound'] > 0 and counts['selected_outside_tunnel'] == 0
    return {'counts': dict(counts), 'selected_destination_count': len(destinations),
            'passed': passed and counts['tunnel_source_outside_tunnel'] == 0}


def endpoint(ip):
    """Destination address, protocol and destination port of an IP packet."""
    if len(ip) >= 20 and ip[0] >> 4 == 4:
        proto, offset, address = ip[9], (ip[0] & 15) * 4, ipaddress.ip_address(ip[16:20])
    elif len(ip) >= 40 and ip[0] >> 4 == 6:
        proto, offset, address = ip[6], 40, ipaddress.ip_address(ip[24:40])
    else:
        return None, None, None
    port = struct.unpack_from('>H', ip, offset + 2)[0] if proto in (6, 17) and len(ip) >= offset + 4 else None
    return str(address), proto, port


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture')
    parser.add_argument('--uuid', action='append', default=[])
    parser.add_argument('--process', action='append', default=[])
    parser.add_argument('--tunnel', action='append', default=[], help='packet tunnel interface')
    parser.add_argument('--provider', action='append', default=[], help='app proxy provider process name')
    parser.add_argument('--proxy', action='append', default=[], help='IP:PORT of an upstream proxy, with --provider')
    args = parser.parse_args()
    if bool(args.tunnel) == bool(args.provider) or bool(args.provider) != bool(args.proxy):
        parser.error('use --tunnel for a packet tunnel, or --provider with --proxy for an app proxy')
    result = audit(args.capture, {str(uuid.UUID(s)) for s in args.uuid}, set(args.process), args.tunnel, args.provider, args.proxy)
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result['passed'] else 1)
