import struct
import tempfile
import unittest
from pathlib import Path
from packet_inspector import parse_ipv4, read_pcap


def packet(fragment=0):
    return struct.pack('!BBHHHBBH4s4sHH', 0x45, 0, 24, 0, fragment, 64, 17, 0,
                       bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]), 1234, 53)


class PacketTests(unittest.TestCase):
    def test_udp(self):
        p = parse_ipv4(packet())
        self.assertEqual((p['source'], p['destination_port']), ('10.0.0.1', 53))
    def test_fragment_does_not_infer_ports(self):
        self.assertNotIn('source_port', parse_ipv4(packet(1)))
    def test_short_packet(self):
        with self.assertRaises(ValueError): parse_ipv4(b'\x45')
    def test_pcap(self):
        frame = bytes(12) + b'\x08\x00' + packet()
        data = b'\xd4\xc3\xb2\xa1' + struct.pack('<HHiIII', 2, 4, 0, 0, 65535, 1)
        data += struct.pack('<IIII', 1, 500000, len(frame), len(frame)) + frame
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / 'capture.pcap'; p.write_bytes(data)
            result = list(read_pcap(p))
        self.assertEqual(result[0]['timestamp'], 1.5)
        self.assertEqual(result[0]['destination'], '10.0.0.2')
    def test_truncated_record(self):
        data = b'\xd4\xc3\xb2\xa1' + struct.pack('<HHiIII', 2, 4, 0, 0, 65535, 1) + b'x'
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / 'bad.pcap'; p.write_bytes(data)
            with self.assertRaises(ValueError): list(read_pcap(p))

if __name__ == '__main__': unittest.main()
