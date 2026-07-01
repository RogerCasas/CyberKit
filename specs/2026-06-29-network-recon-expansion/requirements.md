# v4.2 — Network Recon Expansion: Requirements

## Problem statement

CyberKit's Network / Recon category currently has only two tools: Port Scanner and ARP Scanner.
Students progressing beyond basic port scanning need hands-on exposure to routing topology
(Traceroute), service identification via raw banners (Banner Grabber), and passive traffic
observation (Packet Sniffer). These are staple recon techniques taught in every network-security
curriculum; the absence of them creates a visible gap in the category.

## In scope

### Traceroute
- Send probes with incrementing TTL (1 → max_hops, default 30) towards a target host.
- Support both ICMP Echo and UDP probes (platform-adaptive: ICMP on Windows, UDP on Linux/macOS
  by default; user can override via a dropdown).
- For each hop: display hop index, IP address, reverse-DNS hostname (if available), and RTT (ms).
- Live Treeview — each hop row appears as its reply arrives, not after the full trace finishes.
- Star `*` for hops that time out (no reply within timeout window).
- Stop button halts mid-trace.
- Uses Scapy (already a project dependency from ARP Scanner).

### Banner Grabber
- Raw TCP connect to a user-supplied host:port.
- Send a minimal probe string (configurable, defaults to `\r\n`) and read the banner.
- Display banner text in a scrollable text box.
- Optional: attempt a TLS handshake if the port is well-known for TLS (443, 8443) or if
  "Use TLS" checkbox is ticked.
- No third-party libraries beyond the stdlib `ssl` module.

### Packet Sniffer
- Passive Scapy capture on a user-selected network interface (dropdown populated at startup).
- Live Treeview: src IP, dst IP, protocol, src port, dst port, payload preview (first 40 chars).
- Protocol filter: all / TCP / UDP / ICMP / ARP.
- Capture stops when the Stop button is pressed or the row limit (default 500) is reached.
- Read-only — no packet injection or modification.
- ⚠ Requires administrator / root privileges (same constraint as ARP Scanner; UI warns if
  insufficient).

## Out of scope

- Path MTU discovery or advanced traceroute modes (Paris traceroute, TCP SYN probes).
- Banner Grabber TLS certificate inspection (covered by SSL Analyser).
- Packet Sniffer pcap file save/load (future phase).
- Packet Sniffer deep-packet inspection or protocol decoding beyond basic header fields.
- Automated exploit delivery or payload injection in any of the three tools.

## Key decisions and constraints

- **Scapy** is already declared as a project dependency (ARP Scanner). Traceroute and Packet
  Sniffer extend it; no new C-extension dependencies are introduced.
- **Admin privilege warning** — both Traceroute (raw sockets) and Packet Sniffer require elevated
  privileges on most OSes. The UI displays a clear warning banner if the process is not running
  as admin/root, matching the ARP Scanner behaviour.
- **Thread + queue pattern** — all network I/O runs in a background thread; results arrive via
  `queue.Queue`; UI polls with `widget.after()`. No Tk widget is touched from a worker thread.
  This is identical to every other scan engine in the project.
- **Module structure** follows v4.1 conventions: `app/modules/<name>.py` for the engine,
  `app/ui/pages/<name>.py` for the UI page.
- **Sidebar category** for all three tools: `Network / Recon` (existing category).
- **Home page tags**: all three cards use `"tag": "Active"` with green tag colour once implemented.
- **No new external libraries** beyond Scapy and stdlib.

## Open questions

None — all scoping decisions resolved in the pre-spec interview.
