"""The transport is an app proxy: iOS diverts selected apps' flows to the provider without the
tunnel interface a packet tunnel creates, which apps' VPN checks can see."""
import unittest

from audit_interfaces import audit


class InterfaceAuditTests(unittest.TestCase):
    # Shapes recorded on the XS: iOS keeps utun0-utun3 of its own at baseline.
    before = {'scoped': ['en0'], 'interfaces': ['lo0', 'en0', 'utun0', 'utun1', 'utun2', 'utun3'], 'path': ['en0']}

    def test_a_packet_tunnel_interface_fails(self):
        during = {'scoped': ['en0', 'utun4'], 'interfaces': self.before['interfaces'] + ['utun4'], 'path': ['utun4', 'en0']}
        result = audit(self.before, during)
        self.assertFalse(result['passed'])
        self.assertEqual(result['added_tunnel_interfaces'], {'scoped': ['utun4'], 'interfaces': ['utun4'], 'path': ['utun4']})
        for name in ('ipsec0', 'ppp0', 'tap1', 'tun0'):
            self.assertFalse(audit(self.before, dict(self.before, scoped=['en0', name]))['passed'], name)


if __name__ == '__main__':
    unittest.main()
