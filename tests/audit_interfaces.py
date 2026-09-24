#!/usr/bin/env python3
"""Compare tests/interfaces.c snapshots taken before and while protected. Protection must not add
a tunnel-like interface (utun, tun, tap, ppp, ipsec) to any list apps' VPN checks read: the
scoped proxy settings, the interface names or the default path. Earlier ones, such as iOS's own
utun interfaces or another VPN's, are not Slipstream's."""
import argparse, json, re

TUNNEL = re.compile(r'(utun|tun|tap|ppp|ipsec)[0-9]*')


def audit(before, during):
    added = {key: sorted(name for name in during[key] if TUNNEL.fullmatch(name) and name not in before[key])
             for key in ('scoped', 'interfaces', 'path')}
    return {'added_tunnel_interfaces': added, 'passed': not any(added.values())}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('before')
    parser.add_argument('during')
    args = parser.parse_args()
    result = audit(json.load(open(args.before)), json.load(open(args.during)))
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result['passed'] else 1)
