import struct
import tempfile
import unittest
from audit_per_app_capture import audit


class PerAppCaptureTests(unittest.TestCase):
    def capture(self, interface, process=b'MobileSafari', destination=(1, 1, 1, 1), port=443):
        h = bytearray(156)
        struct.pack_into('<III', h, 0, 156, 1, 0)
        h[12:12+len(interface)] = interface.encode()
        struct.pack_into('<I', h, 36, 2)
        h[88:88+len(process)] = process
        ip = bytearray(24)
        ip[0], ip[9], ip[16:20] = 0x45, 6, bytes(destination)
        struct.pack_into('>HH', ip, 20, 50000, port)
        data = h + ip
        return struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 256, 258) + struct.pack('<IIII', 0, 0, len(data), len(data)) + data

    def app_proxy(self, *packets):
        with tempfile.NamedTemporaryFile() as f:
            f.write(packets[0] + b''.join(p[24:] for p in packets[1:])); f.flush()
            return audit(f.name, set(), {'MobileSafari'}, provider=['AppProxyProvider'], proxy='203.0.113.2:3128')

    def test_app_proxy_requires_provider_traffic_only_to_the_proxy(self):
        to_proxy = self.capture('en0', b'AppProxyProvider', (203, 0, 113, 2), 3128)
        self.assertTrue(self.app_proxy(to_proxy)['passed'])
        elsewhere = self.capture('en0', b'AppProxyProvider', (1, 1, 1, 1), 443)
        result = self.app_proxy(to_proxy, elsewhere)
        self.assertFalse(result['passed'])
        self.assertEqual(result['counts']['provider_elsewhere'], 1)

    def test_app_proxy_rejects_any_selected_packet_and_an_idle_provider(self):
        to_proxy = self.capture('en0', b'AppProxyProvider', (203, 0, 113, 2), 3128)
        result = self.app_proxy(to_proxy, self.capture('en0'))
        self.assertFalse(result['passed'])
        self.assertEqual(result['counts']['selected_outbound'], 1)
        self.assertFalse(self.app_proxy(self.capture('en0', b'SpringBoard'))['passed'])


if __name__ == '__main__':
    unittest.main()
