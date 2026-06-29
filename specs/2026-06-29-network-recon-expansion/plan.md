# v4.2 — Network Recon Expansion: Plan

Each group can be tested independently before the next begins.

---

## Group 1 — Traceroute Engine & Tests

### 1.1 — Create `app/modules/traceroute.py`
- `TraceHop` dataclass: `hop: int`, `ip: str | None`, `hostname: str | None`, `rtt_ms: float | None`, `timed_out: bool`
- `scan(host, max_hops, timeout, method, stop_event, on_hop)` — calls `on_hop(TraceHop)` for each TTL increment
- Use Scapy `sr1()` with `IP(dst=host, ttl=n)/ICMP()` (or `UDP()` depending on method)
- Reverse-DNS via `socket.gethostbyaddr()` with timeout guard
- Returns when ICMP Echo Reply received, max_hops reached, or `stop_event` set

### 1.2 — Create `tests/test_traceroute.py`
- Test `TraceHop` construction
- Test timeout detection (mock `sr1` returning `None`)
- Test stop_event abort before first hop
- Test hop sequence 1..N (mock sr1 returning synthetic ICMP Time-Exceeded then Echo-Reply)

---

## Group 2 — Banner Grabber Engine & Tests

### 2.1 — Create `app/modules/banner_grabber.py`
- `BannerResult` dataclass: `host: str`, `port: int`, `banner: str`, `tls: bool`, `error: str | None`
- `grab(host, port, probe, use_tls, timeout)` → `BannerResult`
- Raw TCP via `socket.create_connection()`
- TLS wrap via `ssl.create_default_context().wrap_socket()` (verify disabled for test servers)
- Strip null bytes; truncate banner at 4096 chars

### 2.2 — Create `tests/test_banner_grabber.py`
- Test clean banner capture (mock socket returning a banner string)
- Test TLS path branching (mock `ssl.wrap_socket`)
- Test connection timeout → `error` field populated, no exception raised
- Test probe sent before read (verify `sendall` called with probe bytes)
- Test banner truncation at 4096 chars

---

## Group 3 — Packet Sniffer Engine & Tests

### 3.1 — Create `app/modules/packet_sniffer.py`
- `PacketRow` dataclass: `src: str`, `dst: str`, `proto: str`, `sport: int | None`, `dport: int | None`, `preview: str`
- `list_interfaces()` → `list[str]` via Scapy `get_if_list()`
- `sniff(iface, proto_filter, row_limit, stop_event, on_packet)` — calls `on_packet(PacketRow)` per captured frame
- Scapy `sniff()` with `store=False`, `stop_filter=lambda _: stop_event.is_set() or count[0] >= row_limit`
- Protocol extraction: check for `TCP`, `UDP`, `ICMP`, `ARP` layers; fallback to `"OTHER"`
- Payload preview: first 40 printable ASCII chars of `Raw` layer if present

### 3.2 — Create `tests/test_packet_sniffer.py`
- Test `PacketRow` construction
- Test TCP packet parsing (mock Scapy packet object with TCP layer)
- Test UDP packet parsing
- Test ICMP packet parsing (no ports → `None`)
- Test ARP packet parsing
- Test stop_event halts iteration
- Test row_limit enforced

---

## Group 4 — UI Pages

### 4.1 — Create `app/ui/pages/traceroute.py`
- `TraceRoutePage(CTkFrame)` — target entry, max_hops spinbox, method dropdown (ICMP/UDP), timeout spinbox
- Admin/privilege warning banner (visible when `os.getuid() != 0` on Linux; `ctypes.windll` check on Windows)
- Scan / Stop button
- Treeview columns: Hop, IP, Hostname, RTT (ms)
- Live update via `queue.Queue` + `after()` poll
- Layout: `grid_rowconfigure` weight on table row; wrapper `sticky="nsew"`; Treeview `height=6`

### 4.2 — Create `app/ui/pages/banner_grabber.py`
- `BannerGrabberPage(CTkFrame)` — host entry, port entry, probe entry (default `\r\n`), TLS checkbox
- Grab / Stop button
- `CTkTextbox` (read-only) for banner output; scrollable
- Status label (Connected / TLS / Error)

### 4.3 — Create `app/ui/pages/packet_sniffer.py`
- `PacketSnifferPage(CTkFrame)` — interface dropdown (populated from `list_interfaces()`), protocol filter dropdown, row limit entry
- Admin/privilege warning banner
- Start / Stop button
- Treeview columns: #, Src IP, Dst IP, Proto, Src Port, Dst Port, Payload Preview
- Live update via `queue.Queue` + `after()` poll
- Row auto-scroll to latest packet

---

## Group 5 — Wiring & Documentation

### 5.1 — Update `app/data/categories.py`
- Add `ToolEntry("Traceroute", "🗺", "traceroute")` to `network_recon` list
- Add `ToolEntry("Banner Grabber", "📡", "banner_grabber")` to `network_recon`
- Add `ToolEntry("Packet Sniffer", "🔍", "packet_sniffer")` to `network_recon`

### 5.2 — Update `app/ui/pages/home.py`
- Add card data for all three tools (tag: Active, tag_color: "#22c55e")

### 5.3 — Update `app/ui/app_window.py`
- Import and `_add_page()` for all three new page classes

### 5.4 — Update `app/ui/sidebar.py`
- Version label: `"v4.2.0"`

### 5.5 — Update `roadmap.md`
- Mark v4.2 ✅ Complete; add Status column to table

### 5.6 — Commit spec files on branch
- Commit `specs/2026-06-29-network-recon-expansion/` as first branch commit
