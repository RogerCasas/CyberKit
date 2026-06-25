"""
CyberKit — Port Scanner engine tests

Run: python tests/test_port_scanner.py
"""

import io
import socket
import threading
import time
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

from app.modules.port_scanner import PortScanEngine, STATUS_OPEN, STATUS_CLOSED, STATUS_FILTERED


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_open_port_detected():
    port = _free_port()
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", port))
    server.listen(5)

    results = []
    done_event = threading.Event()

    engine = PortScanEngine("127.0.0.1", [port], threads=1, timeout_s=2.0, grab_banner=False)
    engine.start(
        on_result=lambda r: results.append(r),
        on_done=lambda s: done_event.set(),
    )

    done_event.wait(timeout=5)
    server.close()

    assert len(results) == 1, f"Expected 1 result, got {len(results)}"
    assert results[0].status == STATUS_OPEN, f"Expected OPEN, got {results[0].status}"
    print("✓ Open port detected")


def test_closed_port_not_open():
    port = _free_port()
    # Nothing listening on this port
    results = []
    done_event = threading.Event()

    engine = PortScanEngine("127.0.0.1", [port], threads=1, timeout_s=2.0)
    engine.start(
        on_result=lambda r: results.append(r),
        on_done=lambda s: done_event.set(),
    )

    done_event.wait(timeout=5)
    assert len(results) == 1
    assert results[0].status != STATUS_OPEN, f"Should not be OPEN on unused port"
    print("✓ Unused port is not OPEN")


def test_stop_halts_scan():
    ports = list(range(10000, 10200))  # 200 filtered ports
    results = []
    done_event = threading.Event()

    engine = PortScanEngine("127.0.0.1", ports, threads=10, timeout_s=0.5)
    engine.start(
        on_result=lambda r: results.append(r),
        on_done=lambda s: done_event.set(),
    )

    time.sleep(0.3)
    engine.stop()
    done_event.wait(timeout=5)

    assert done_event.is_set(), "on_done was not called after stop()"
    print(f"✓ Stop halted scan (got {len(results)} results before stop)")


def test_banner_grab():
    port = _free_port()
    banner_msg = b"HELLO CyberKit\r\n"

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", port))
    server.listen(1)
    server_ready = threading.Event()

    def _serve():
        server_ready.set()
        try:
            conn, _ = server.accept()
            conn.sendall(banner_msg)
            conn.close()
        except Exception:
            pass
        finally:
            server.close()

    threading.Thread(target=_serve, daemon=True).start()
    server_ready.wait(timeout=2)

    results = []
    done_event = threading.Event()
    engine = PortScanEngine("127.0.0.1", [port], threads=1,
                            timeout_s=2.0, grab_banner=True)
    engine.start(
        on_result=lambda r: results.append(r),
        on_done=lambda s: done_event.set(),
    )
    done_event.wait(timeout=5)

    assert len(results) == 1
    assert results[0].status == STATUS_OPEN
    assert results[0].banner, "Banner should be non-empty"
    assert "HELLO" in results[0].banner, f"Expected 'HELLO' in banner, got: {results[0].banner}"
    print(f"✓ Banner grab works: '{results[0].banner}'")


def test_host_normalisation():
    e = PortScanEngine("https://example.com/path/to/page", [80])
    assert e.host == "example.com", f"Expected 'example.com', got '{e.host}'"
    e2 = PortScanEngine("http://192.168.1.1:8080/", [80])
    assert e2.host == "192.168.1.1", f"Expected '192.168.1.1', got '{e2.host}'"
    print("✓ Host normalisation strips scheme, path, and port")


def test_unreachable_host_no_exception():
    results = []
    done_event = threading.Event()

    engine = PortScanEngine("192.0.2.1", [80, 443], threads=2, timeout_s=0.5)
    try:
        engine.start(
            on_result=lambda r: results.append(r),
            on_done=lambda s: done_event.set(),
        )
        done_event.wait(timeout=6)
    except Exception as exc:
        assert False, f"Engine raised unexpected exception: {exc}"

    for r in results:
        assert r.status in (STATUS_FILTERED, "ERROR"), \
            f"Unreachable host should give FILTERED/ERROR, got {r.status}"
    print("✓ Unreachable host raises no exception")


if __name__ == "__main__":
    tests = [
        test_host_normalisation,
        test_open_port_detected,
        test_closed_port_not_open,
        test_stop_halts_scan,
        test_banner_grab,
        test_unreachable_host_no_exception,
    ]
    passed = 0
    for t in tests:
        try:
            t()
            passed += 1
        except AssertionError as e:
            print(f"✗ {t.__name__}: {e}")
        except Exception as e:
            print(f"✗ {t.__name__}: unexpected error — {e}")

    print(f"\n{passed}/{len(tests)} tests passed")
    sys.exit(0 if passed == len(tests) else 1)
