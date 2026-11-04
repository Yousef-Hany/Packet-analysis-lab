# Screenshot and Filter Guide

Open `pcap/icmp_soc_lab.pcap` in Wireshark. For every screenshot, make sure the **display filter bar**, the **packet list** and the **status bar** (packets displayed) are visible, so a reader can see what you did.

> Field names can differ slightly between Wireshark versions. If a filter turns red, click the filter bar, type the field prefix (for example `icmp.`) and pick from the autocomplete list.

## 0. One-time setup

Add these as columns (right-click a field in packet details > Apply as Column):

| Column | Field |
|---|---|
| ICMP type | `icmp.type` |
| ICMP code | `icmp.code` |
| TTL | `ip.ttl` |
| Payload length | `data.len` |
| Delta displayed | `frame.time_delta_displayed` |
| Response time | `icmp.resptime` |

## 1. Whole-capture overview (take these first)

| Screenshot | Where | Show |
|---|---|---|
| Capture properties | Statistics > Capture File Properties | 417 packets, duration, link type |
| Protocol hierarchy | Statistics > Protocol Hierarchy | 100% ICMP over IPv4 |
| Conversations | Statistics > Conversations > IPv4 | Which pairs talk most: 198.51.100.23 to 10.0.0.5 dominates |
| Type/code breakdown | filter `icmp`, sort by the type column | Mix of 8, 0, 11, 3, 5 |

Expected totals: 386 echo requests, 21 echo replies, 5 time-exceeded, 1 type 3 code 4, 1 type 3 code 1, 1 redirect.

## 2. Normal traffic

### 2.1 Ping (frames 1-8)
- Filter: `frame.number >= 1 && frame.number <= 8`
- Screenshot: packet list showing 4 requests and 4 replies, then packet details of one reply with "Request frame" and "Response time" expanded.
- Annotate: same identifier and sequence, 48-byte payload (data.len == 48), about 1 s spacing, RTT about 20 ms, reply TTL 117.

### 2.2 Traceroute (frames 9-20)
- Filter: `frame.number >= 9 && frame.number <= 20`
- Screenshot: list showing TTL rising 1 to 6 with the TTL column visible, and type 11 replies from 10.0.0.1, 100.64.0.1, 172.16.4.1, 172.16.9.2, 192.0.2.77.
- Also: expand one type 11 packet to show the quoted original IP header inside ICMP.
- Annotate: hop-by-hop path, final echo reply when TTL is high enough.

### 2.3 Path MTU discovery (frames 21-24)
- Filter: `icmp.type == 3 && icmp.code == 4`
- Screenshot: the type 3 code 4 packet with "MTU of next hop: 1400" expanded.
- Second screenshot: `frame.number >= 21 && frame.number <= 24` showing the DF packet (`ip.flags.df == 1`, 1472 B payload), the error, then the retry at 1372 B that gets a reply.
- Annotate: DF bit set, too big, sender adapts.

### 2.4 Host unreachable (frames 25-26)
- Filter: `icmp.type == 3 && icmp.code == 1`
- Screenshot: request to 10.0.0.200 followed by the gateway's type 3 code 1 about 3 seconds later.
- Annotate: sender is the gateway 10.0.0.1, a normal result for a dead host.

## 3. Suspicious traffic

### 3.1 Ping sweep (frames 27-89)
- Filters:
  - `icmp.type == 8 && ip.src == 10.0.0.99` (60 requests)
  - `icmp.type == 0 && ip.dst == 10.0.0.99` (only 3 replies: .1, .5, .15)
  - `icmp.no_resp` (requests with no response)
- Screenshots:
  1. First filter with destination addresses incrementing, and the delta column near 0.05 s.
  2. Statistics > Endpoints > IPv4, showing 10.0.0.99 sending far more than it receives.
  3. Second filter showing the 3 live hosts.
- Annotate: one source, many sequential targets, tiny constant interval, mostly unanswered.

### 3.2 ICMP tunnel (frames 90-113)
- Filters:
  - `ip.addr == 203.0.113.50 && icmp` (12 requests, 12 replies)
  - `icmp.type == 8 && data.len > 100`
- Screenshots:
  1. List with the payload-length column showing 480 bytes and the delta column showing 5 s steps.
  2. Packet bytes pane of a request next to its reply. They should differ (a normal echo reply repeats the request data).
  3. Packet bytes of the fourth beacon, which contains a readable base64 blob.
  4. Statistics > I/O Graph with filter `ip.addr == 203.0.113.50`, 1 s interval, showing evenly spaced spikes.
- Annotate: payload far above the 48-byte payload of the lab's normal pings, high entropy, fixed 5 s beacon, reply data differs from request, reply TTL 52 compared with 64 for the sender.

### 3.3 ICMP flood (frames 114-413)
- Filter: `ip.src == 198.51.100.23 && icmp`
- Screenshots:
  1. Statistics > Conversations showing 300 packets from 198.51.100.23 to 10.0.0.5.
  2. Statistics > I/O Graph, filter `ip.src == 198.51.100.23`, interval 100 ms, a burst of about 1 s.
  3. Packet list with `icmp.no_resp` applied to show no replies, and the TTL column at 240.
- Annotate: 300 packets in about 1 s, 1000-byte payloads, no replies, unusual TTL (check for spoofing).

### 3.4 Fragmented echo (frames 414-416)
- Filters:
  - `ip.flags.mf == 1 || ip.frag_offset > 0`
  - `ip.id == 0xbeef`
- Screenshots:
  1. The three fragments with More Fragments set on the first two.
  2. The last fragment's details, where Wireshark shows "Reassembled IPv4 in frame" and "Reassembled IPv4 (4008 bytes)".
  3. Expand the Fragment offset and Flags fields in packet details.
- Annotate: one 4000-byte echo split into fragments with one shared IP ID, from 198.51.100.77 (an unusual size for ICMP).

### 3.5 ICMP redirect (frame 417)
- Filter: `icmp.type == 5`
- Screenshot: packet details with the ICMP section expanded, showing "Gateway address: 10.0.0.66" and the quoted original header (10.0.0.15 to 8.8.8.8).
- Second screenshot: the Ethernet and IP source (10.0.0.66, MAC aa:bb:cc:00:00:66), next to the real gateway (10.0.0.1, MAC aa:bb:cc:00:00:01).
- Annotate: sender is not the default gateway and names itself as the better next hop.


