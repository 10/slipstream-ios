#!/usr/bin/env python3
"""Audit a classic Ethernet pcap without printing payloads or proxy credentials."""
import argparse, collections, ipaddress, json, struct

def packets(path):
    with open(path,'rb') as f:
        header=f.read(24)
        endian={b'\xd4\xc3\xb2\xa1':'<',b'\xa1\xb2\xc3\xd4':'>',b'\x4d\x3c\xb2\xa1':'<',b'\xa1\xb2\x3c\x4d':'>'}[header[:4]]
        if struct.unpack(endian+'I',header[20:24])[0] != 1: raise ValueError('capture must use Ethernet link type')
        while h:=f.read(16):
            sec,subsec,caplen,wirelen=struct.unpack(endian+'IIII',h)
            p=f.read(caplen)
            if len(p)!=caplen:raise ValueError('truncated pcap')
            yield p,wirelen,sec

def classify(p,mac,proxy,port,management,local_subnets=(),proxy_udp=False):
    if len(p)<14:return 'VIOLATION truncated Ethernet header'
    if p[6:12]!=mac:return 'other host or inbound'
    kind=int.from_bytes(p[12:14],'big');b=p[14:]
    if kind==0x0806:return 'ARP'
    if kind==0x0800 and len(b)>=20:
        size=(b[0]&15)*4;proto=b[9];dst=str(ipaddress.IPv4Address(b[16:20]));payload=b[size:]
        if any(ipaddress.ip_address(dst) in subnet for subnet in local_subnets):return 'local network'
        # Only the first fragment can prove an allowlisted transport endpoint.
        if int.from_bytes(b[6:8],'big') & 0x1fff:return 'VIOLATION IPv4 fragment'
        if proto in (6,17) and len(payload)>=4:
            srcport,dstport=struct.unpack('!HH',payload[:4])
            if proto==6 and dst==proxy and dstport==port:return 'proxy TCP'
            # A SOCKS5 relay port is chosen by the proxy per session; only the host is fixed.
            if proto==17 and dst==proxy and proxy_udp:return 'proxy UDP'
            if proto==6 and dst==management and srcport==22:return 'recovery SSH'
            if proto==17 and srcport==68 and dstport==67 and dst=='255.255.255.255':return 'DHCP'
        return f'VIOLATION IPv4 {dst} protocol {proto}'
    if kind==0x86dd and len(b)>=40:
        dst=str(ipaddress.IPv6Address(b[24:40]))
        if any(ipaddress.ip_address(dst) in subnet for subnet in local_subnets):return 'local network'
        # Darwin emits local neighbor discovery independently of normal PF rules.
        if b[6]==58 and b[7]==255 and len(b)>40 and b[40] in (133,134,135,136):return 'IPv6 neighbor discovery'
        return f'VIOLATION IPv6 {ipaddress.IPv6Address(b[24:40])} next-header {b[6]}'
    if kind==0x888e:return 'EAPOL'
    return f'VIOLATION unknown or truncated Ethernet protocol {kind:#x}'

def audit(path,mac,config,local_subnets=()):
    counts=collections.Counter();sizes=collections.Counter();times=[]
    mac=bytes.fromhex(mac.replace(':',''))
    for p,n,t in packets(path):
        key=classify(p,mac,config['proxy_ip'],config['proxy_port'],config.get('management_ip'),local_subnets,config.get('proxy','').startswith('socks5://'))
        counts[key]+=1;sizes[key]+=n;times.append(t)
    return {'packets':dict(counts),'wire_bytes':dict(sizes),'duration_seconds':max(times)-min(times) if times else 0,'pass':not any(k.startswith('VIOLATION') for k in counts),'total_packets':sum(counts.values())}

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('pcap');p.add_argument('--mac',required=True);p.add_argument('--config',required=True);p.add_argument('--local-subnet',action='append',default=[]);a=p.parse_args()
    result=audit(a.pcap,a.mac,json.load(open(a.config)),tuple(ipaddress.ip_network(n) for n in a.local_subnet));print(json.dumps(result,indent=2));raise SystemExit(0 if result['pass'] else 1)
