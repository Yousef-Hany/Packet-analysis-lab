#!/usr/bin/env python3
"""Build a synthetic ICMP training pcap: normal behaviour + SOC-relevant anomalies.
Pure standard library. All addresses are private or documentation ranges."""
import base64
import os
import random
import socket
import struct
import sys

random.seed(7)
out = sys.argv[1]

pkts = []       # (timestamp, bytes)
sections = []   # [label, first_frame, last_frame]
t = 1_790_000_000.0

GW_MAC = "aa:bb:cc:00:00:01"
MACS = {
    "10.0.0.15": "aa:bb:cc:00:00:15", "10.0.0.1": GW_MAC,
    "10.0.0.99": "aa:bb:cc:00:00:99", "10.0.0.77": "aa:bb:cc:00:00:77",
    "10.0.0.66": "aa:bb:cc:00:00:66", "10.0.0.5": "aa:bb:cc:00:00:05",
}


def mac_bytes(ip):
    return bytes(int(x, 16) for x in MACS.get(ip, GW_MAC).split(":"))


def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def icmp(typ, code=0, rest=b"\x00\x00\x00\x00", payload=b""):
    hdr = struct.pack("!BBH", typ, code, 0) + rest
    cs = checksum(hdr + payload)
    return struct.pack("!BBH", typ, code, cs) + rest + payload


def echo(typ, ident, seq, payload):
    return icmp(typ, 0, struct.pack("!HH", ident, seq), payload)


def ip(src, dst, payload, ttl=64, ident=None, df=False, mf=False, frag_off=0):
    ident = random.randint(1, 65000) if ident is None else ident
    flags = (0x4000 if df else 0) | (0x2000 if mf else 0) | (frag_off // 8)
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident, flags, ttl, 1, 0,
                      socket.inet_aton(src), socket.inet_aton(dst))
    cs = checksum(hdr)
    hdr = hdr[:10] + struct.pack("!H", cs) + hdr[12:]
    return hdr + payload


def add(ts, src, dst, ip_bytes):
    frame = mac_bytes(dst) + mac_bytes(src) + b"\x08\x00" + ip_bytes
    pkts.append((ts, frame))


def begin(label):
    sections.append([label, len(pkts) + 1, None])


def end():
    sections[-1][2] = len(pkts)


def echo_pair(ts, src, dst, ident, seq, payload, rtt, ttl_req=64, ttl_rep=117, df=False, drop_reply=False):
    add(ts, src, dst, ip(src, dst, echo(8, ident, seq, payload), ttl=ttl_req, df=df))
    if not drop_reply:
        add(ts + rtt, dst, src, ip(dst, src, echo(0, ident, seq, payload), ttl=ttl_rep))


std_payload = bytes(8) + bytes(range(0x10, 0x38))  # Linux-style 56-byte ping data

# 1 NORMAL ping
begin("1. NORMAL      user ping 10.0.0.15 -> 8.8.8.8: 4 x, 1s apart, fixed 48B payload, stable RTT")
for i in range(1, 5):
    echo_pair(t, "10.0.0.15", "8.8.8.8", 0x1A2B, i, std_payload, 0.018 + random.random() * 0.004)
    t += 1.0
t += 5
end()

# 2 NORMAL traceroute
begin("2. NORMAL      ICMP traceroute 10.0.0.15 -> 8.8.8.8: TTL 1..5 get Time Exceeded (type 11), TTL 6 gets echo reply")
hops = ["10.0.0.1", "100.64.0.1", "172.16.4.1", "172.16.9.2", "192.0.2.77"]
for ttl, hop in enumerate(hops, start=1):
    probe = ip("10.0.0.15", "8.8.8.8", echo(8, 0x4444, ttl, b"\x00" * 32), ttl=ttl, ident=3000 + ttl)
    add(t, "10.0.0.15", "8.8.8.8", probe)
    add(t + 0.004 * ttl, hop, "10.0.0.15", ip(hop, "10.0.0.15", icmp(11, 0, payload=probe[:28]), ttl=250))
    t += 0.3
echo_pair(t, "10.0.0.15", "8.8.8.8", 0x4444, 6, b"\x00" * 32, 0.021, ttl_req=6)
t += 8
end()

# 3 NORMAL PMTUD
begin("3. NORMAL      Path MTU discovery: DF + 1472B payload -> type 3 code 4 (next-hop MTU 1400) -> retry with 1372B works")
big = ip("10.0.0.15", "8.8.8.8", echo(8, 0x5555, 1, b"A" * 1472), df=True, ident=4001)
add(t, "10.0.0.15", "8.8.8.8", big)
add(t + 0.006, "172.16.4.1", "10.0.0.15",
    ip("172.16.4.1", "10.0.0.15", icmp(3, 4, struct.pack("!HH", 0, 1400), big[:28]), ttl=250))
t += 1.0
echo_pair(t, "10.0.0.15", "8.8.8.8", 0x5555, 2, b"A" * 1372, 0.02, df=True)
t += 8
end()

# 4 NORMAL host unreachable
begin("4. NORMAL      gateway returns Host Unreachable (type 3 code 1) for a dead internal host")
req = ip("10.0.0.15", "10.0.0.200", echo(8, 0x6666, 1, std_payload), ident=5001)
add(t, "10.0.0.15", "10.0.0.200", req)
add(t + 3.0, "10.0.0.1", "10.0.0.15", ip("10.0.0.1", "10.0.0.15", icmp(3, 1, payload=req[:28])))
t += 10
end()

# 5 SUSPICIOUS ping sweep
begin("5. SUSPICIOUS  ping sweep: 10.0.0.99 -> 10.0.0.1..60, one request per host every 50ms, only 3 hosts answer (.1, .5, .15)")
live = {1, 5, 15, 77}
for host in range(1, 61):
    echo_pair(t, "10.0.0.99", f"10.0.0.{host}", 0x7777, host, bytes(range(0x61, 0x81)), 0.001,
              ttl_rep=64, drop_reply=host not in live)
    t += 0.05
t += 10
end()

# 6 SUSPICIOUS tunnel
begin("6. SUSPICIOUS  ICMP tunnel: 10.0.0.77 <-> 203.0.113.50, fixed 5s beacon, ~480B high-entropy payloads, base64 blobs")
for i in range(1, 13):
    if i % 4 == 0:
        data = base64.b64encode(b"user=admin;host=FIN-DB01;note=training-data;" + os.urandom(180))[:480]
    else:
        data = os.urandom(480)
    ts = t
    add(ts, "10.0.0.77", "203.0.113.50", ip("10.0.0.77", "203.0.113.50", echo(8, 0x1337, i, data), ttl=64))
    add(ts + 0.045, "203.0.113.50", "10.0.0.77",
        ip("203.0.113.50", "10.0.0.77", echo(0, 0x1337, i, os.urandom(480)), ttl=52))  # reply data != request data
    t += 5.0
t += 10
end()

# 7 SUSPICIOUS flood
begin("7. SUSPICIOUS  ICMP flood: 198.51.100.23 -> 10.0.0.5, 300 x 1000B echo requests in ~1s, no replies")
for i in range(300):
    add(t, "198.51.100.23", "10.0.0.5",
        ip("198.51.100.23", "10.0.0.5", echo(8, 0x9999, i, b"X" * 1000), ttl=240))
    t += 0.0033
t += 10
end()

# 8 SUSPICIOUS fragments
begin("8. SUSPICIOUS  fragmented echo request: 4000B payload split across MF fragments (same IP ID 0xBEEF)")
whole = echo(8, 0xAAAA, 1, b"Z" * 4000)
off = 0
while off < len(whole):
    chunk = whole[off:off + 1480]
    more = off + len(chunk) < len(whole)
    add(t, "198.51.100.77", "10.0.0.5",
        ip("198.51.100.77", "10.0.0.5", chunk, ttl=55, ident=0xBEEF, mf=more, frag_off=off))
    off += len(chunk)
    t += 0.0005
t += 10
end()

# 9 SUSPICIOUS redirect
begin("9. SUSPICIOUS  ICMP redirect (type 5) from 10.0.0.66, which is not the gateway, pointing 8.8.8.8 traffic at itself")
orig = ip("10.0.0.15", "8.8.8.8", echo(8, 0xBBBB, 1, b""), ident=7001)
add(t, "10.0.0.66", "10.0.0.15",
    ip("10.0.0.66", "10.0.0.15", icmp(5, 1, socket.inet_aton("10.0.0.66"), orig[:28])))
end()

# write classic pcap (LINKTYPE_ETHERNET)
with open(out, "wb") as f:
    f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for ts, frame in pkts:
        sec = int(ts)
        usec = int((ts - sec) * 1_000_000)
        f.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)))
        f.write(frame)

print(f"wrote {len(pkts)} packets to {out}")
for label, a, b in sections:
    print(f"frames {a:>3}-{b:<3} {label}")
