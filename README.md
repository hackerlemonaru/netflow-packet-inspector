# Netflow Packet Inspector

A small, dependency-free Python tool for inspecting IPv4 packets in classic Ethernet PCAP captures. It emits one JSON object per packet with addresses, protocol, TTL, timestamp and, when present, TCP/UDP ports. VLAN-tagged frames are supported.

```sh
python3 packet_inspector.py capture.pcap
python3 -m unittest discover -s tests
```

Requires Python 3.9+. Only classic PCAP 2.4 with Ethernet link type is supported; PCAPNG and IPv6 are not supported. Truncated IPv4 packets are rejected; non-IPv4 frames are skipped. No live traffic capture is performed. Use only captures you are authorized to inspect.
