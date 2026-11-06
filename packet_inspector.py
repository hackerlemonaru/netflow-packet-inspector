"""Inspect IPv4 packets and classic PCAP captures without external packages."""
import argparse
import ipaddress
import json
import struct
from pathlib import Path


def parse_ipv4(packet: bytes) -> dict:
    if len(packet) < 20:
        raise ValueError('truncated IPv4 header')
    version, ihl = packet[0] >> 4, (packet[0] & 15) * 4
    if version != 4 or ihl < 20 or len(packet) < ihl:
        raise ValueError('invalid IPv4 header')
    total = int.from_bytes(packet[2:4], 'big')
    if total < ihl or total > len(packet):
        raise ValueError('invalid or truncated IPv4 packet length')
    proto = packet[9]
    result = {'source': str(ipaddress.IPv4Address(packet[12:16])),
              'destination': str(ipaddress.IPv4Address(packet[16:20])),
              'protocol': proto, 'length': total, 'ttl': packet[8]}
    flags_offset = int.from_bytes(packet[6:8], 'big')
    if proto in (6, 17) and flags_offset & 0x1fff == 0 and total >= ihl + 4:
        result['source_port'], result['destination_port'] = struct.unpack('!HH', packet[ihl:ihl+4])
    return result


def read_pcap(path: Path):
    with path.open('rb') as stream:
        header = stream.read(24)
        if len(header) != 24:
            raise ValueError('truncated PCAP header')
        magic = header[:4]
        formats = {b'\xd4\xc3\xb2\xa1': ('<', 1_000_000), b'\xa1\xb2\xc3\xd4': ('>', 1_000_000),
                   b'\x4d\x3c\xb2\xa1': ('<', 1_000_000_000), b'\xa1\xb2\x3c\x4d': ('>', 1_000_000_000)}
        if magic not in formats:
            raise ValueError('unsupported PCAP magic (PCAPNG is not supported)')
        endian, scale = formats[magic]
        major, minor, _, _, snaplen, linktype = struct.unpack(endian + 'HHiIII', header[4:])
        if (major, minor) != (2, 4) or linktype != 1 or not snaplen:
            raise ValueError('only PCAP 2.4 Ethernet captures are supported')
        while True:
            record = stream.read(16)
            if not record:
                break
            if len(record) != 16:
                raise ValueError('truncated packet record header')
            sec, frac, captured, original = struct.unpack(endian + 'IIII', record)
            if captured > snaplen or captured > original or captured > 16 * 1024 * 1024 or frac >= scale:
                raise ValueError('invalid packet record')
            frame = stream.read(captured)
            if len(frame) != captured:
                raise ValueError('truncated packet record data')
            if len(frame) < 14:
                continue
            offset, ethertype = 14, int.from_bytes(frame[12:14], 'big')
            while ethertype in (0x8100, 0x88a8):
                if len(frame) < offset + 4:
                    raise ValueError('truncated VLAN header')
                ethertype = int.from_bytes(frame[offset+2:offset+4], 'big')
                offset += 4
            if ethertype == 0x0800:
                item = parse_ipv4(frame[offset:])
                item['timestamp'] = sec + frac / scale
                yield item


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture', type=Path, help='classic Ethernet PCAP file')
    args = parser.parse_args()
    for packet in read_pcap(args.capture):
        print(json.dumps(packet, sort_keys=True))


if __name__ == '__main__':
    main()
