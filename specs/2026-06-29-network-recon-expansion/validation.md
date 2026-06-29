# v4.2 — Network Recon Expansion: Validation Checklist

---

## Group 1 — Traceroute Engine

- [ ] `TraceHop` dataclass importable from `app.modules.traceroute`
- [ ] `scan()` calls `on_hop` once per TTL increment
- [ ] Timed-out hop produces `TraceHop(timed_out=True, ip=None, rtt_ms=None)`
- [ ] `stop_event` set before call → no hops emitted, function returns immediately
- [ ] Trace terminates when ICMP Echo-Reply received (not always at max_hops)
- [ ] All `test_traceroute.py` tests pass with no network access (mocked Scapy)

---

## Group 2 — Banner Grabber Engine

- [ ] `BannerResult` dataclass importable from `app.modules.banner_grabber`
- [ ] Clean banner captured and returned in `BannerResult.banner`
- [ ] Connection timeout → `BannerResult.error` populated; no uncaught exception
- [ ] Probe bytes sent to socket before reading (verified in test)
- [ ] TLS path: `ssl.wrap_socket` called when `use_tls=True`
- [ ] Banner truncated at 4096 characters
- [ ] All `test_banner_grabber.py` tests pass with mocked sockets

---

## Group 3 — Packet Sniffer Engine

- [ ] `PacketRow` dataclass importable from `app.modules.packet_sniffer`
- [ ] TCP packet: `proto="TCP"`, src/dst ports populated
- [ ] UDP packet: `proto="UDP"`, src/dst ports populated
- [ ] ICMP packet: `proto="ICMP"`, ports are `None`
- [ ] ARP packet: `proto="ARP"`, ports are `None`
- [ ] `stop_event` set → sniffer loop exits on next packet check
- [ ] `row_limit` enforced: `on_packet` called at most `row_limit` times
- [ ] All `test_packet_sniffer.py` tests pass with mocked Scapy packets

---

## Group 4 — UI Pages

### Traceroute Page
- [ ] Page renders without exception on app startup
- [ ] Target entry accepts hostname or IP
- [ ] ICMP / UDP method dropdown present and selectable
- [ ] Scan button starts trace; rows appear live (one per hop)
- [ ] `*` displayed for timed-out hops
- [ ] Stop button halts ongoing trace
- [ ] Admin warning banner visible when running without elevated privileges
- [ ] Results table fills available vertical space (no fixed-height squish)

### Banner Grabber Page
- [ ] Page renders without exception
- [ ] Host + port entry accepts input
- [ ] Grab button connects and displays banner in text box
- [ ] TLS checkbox forces TLS wrap; TLS status shown in label
- [ ] Connection error (bad host/port) shown in status label, no crash

### Packet Sniffer Page
- [ ] Page renders without exception
- [ ] Interface dropdown populated with at least one interface
- [ ] Protocol filter dropdown present (All / TCP / UDP / ICMP / ARP)
- [ ] Start capture populates Treeview with live rows
- [ ] Stop button halts capture
- [ ] Row limit respected (no more than 500 rows by default)
- [ ] Admin warning banner visible when running without elevated privileges

---

## Group 5 — Wiring & Integration

- [ ] All three tools appear in sidebar under `Network / Recon`
- [ ] All three tools appear on home page with `Active` (green) tag
- [ ] Clicking sidebar entry navigates to the correct page
- [ ] Clicking home page card navigates to the correct page
- [ ] Version label reads `v4.2.0` in sidebar footer
- [ ] `roadmap.md` shows v4.2 ✅ Complete
- [ ] All existing tests still pass (`tests/test_*.py`)

---

## Documentation

- [ ] `specs/2026-06-29-network-recon-expansion/requirements.md` committed
- [ ] `specs/2026-06-29-network-recon-expansion/plan.md` committed
- [ ] `specs/2026-06-29-network-recon-expansion/validation.md` committed (this file)
- [ ] `CHANGELOG.md` updated with v4.2 entry after implementation
