#!/usr/bin/env python3
"""Convert one host:port:username:password entry into a private Slipstream config."""
import argparse, ipaddress, json, os, pathlib, urllib.parse
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('proxy_file');p.add_argument('output');p.add_argument('--line',type=int,default=1)
a=p.parse_args()
rows=pathlib.Path(a.proxy_file).read_text().splitlines()
if not 1<=a.line<=len(rows):raise SystemExit('line out of range')
try:
 host,port,user,password=rows[a.line-1].strip().split(':',3)
 ipaddress.IPv4Address(host);number=int(port)
 if not 1<=number<=65535:raise ValueError()
except ValueError:raise SystemExit('expected host:port:username:password')
q=lambda s:urllib.parse.quote(s,safe='')
d={'proxy':f'http://{q(user)}:{q(password)}@{host}:{number}','proxy_ip':host,'proxy_port':number}
fd=os.open(a.output,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
with os.fdopen(fd,'w') as f:json.dump(d,f,indent=2);f.write('\n')
print('Private configuration written. Transfer it securely and set root ownership/mode 600 on the phone.')
