"""
CyberKit — Email Header Analyser engine tests

Run: python tests/test_email_header.py
All tests use fixture data — no network calls.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from app.modules.email_header import parse, AuthResult, HopEntry, HeaderSummary

# ── Fixtures ──────────────────────────────────────────────────────────────────

# Three-hop header: oldest → newest (headers stored newest-first so reversed)
THREE_HOP_HEADER = """\
Received: from mx.destination.com (mx.destination.com [203.0.113.50])
        by mail.example.net with ESMTP id abc123
        for <alice@destination.com>;
        Mon, 01 Jul 2024 12:35:00 +0000 (UTC)
Received: from relay.isp.net (relay.isp.net [198.51.100.25])
        by mx.destination.com with ESMTPS id def456
        ; Mon, 01 Jul 2024 12:34:00 +0000 (UTC)
Received: from mail.sender.org (mail.sender.org [192.0.2.10])
        by relay.isp.net with ESMTP id ghi789
        ; Mon, 01 Jul 2024 12:33:00 +0000 (UTC)
From: Bob <bob@sender.org>
To: Alice <alice@destination.com>
Subject: Test Email
Date: Mon, 01 Jul 2024 12:33:00 +0000
Message-ID: <unique-id@sender.org>
"""

AUTH_HEADER = """\
Received: from mail.example.com (mail.example.com [192.0.2.1])
        by mx.google.com with ESMTP id x1
        ; Mon, 01 Jul 2024 10:00:00 +0000 (UTC)
Authentication-Results: mx.google.com;
       spf=pass (google.com: domain of bob@example.com) smtp.mailfrom=bob@example.com;
       dkim=fail header.i=@example.com header.s=key1;
       dmarc=none (p=NONE sp=NONE dis=NONE) header.from=example.com
From: Bob <bob@example.com>
To: Alice <alice@gmail.com>
Subject: Auth Test
Date: Mon, 01 Jul 2024 10:00:00 +0000
"""

GAP_HEADER = """\
Received: from relay.example.com (relay.example.com [198.51.100.1])
        by mx.destination.com with ESMTP id xyz
        ; Mon, 01 Jul 2024 15:00:00 +0000 (UTC)
Received: from mail.sender.org (mail.sender.org [192.0.2.5])
        by relay.example.com with ESMTP id abc
        ; Mon, 01 Jul 2024 12:00:00 +0000
From: Sender <sender@sender.org>
To: Receiver <receiver@destination.com>
Subject: Gap Test
Date: Mon, 01 Jul 2024 12:00:00 +0000
"""

SPF_FAIL_HEADER = """\
Received: from mail.evil.com (mail.evil.com [10.0.0.1])
        by mx.victim.com with ESMTP id zzz
        ; Mon, 01 Jul 2024 09:00:00 +0000
Authentication-Results: mx.victim.com;
       spf=fail (domain of attacker@evil.com does not designate)
From: Attacker <attacker@evil.com>
To: Victim <victim@victim.com>
Subject: SPF Fail
Date: Mon, 01 Jul 2024 09:00:00 +0000
"""


# ── Tests ─────────────────────────────────────────────────────────────────────

def test_parse_hops():
    """Three-hop fixture produces 3 HopEntry objects with correct fields."""
    result = parse(THREE_HOP_HEADER)
    assert len(result.hops) == 3, f"Expected 3 hops, got {len(result.hops)}"

    # Oldest hop (index 1) should be from mail.sender.org
    hop1 = result.hops[0]
    assert "sender.org" in hop1.from_ or "sender.org" in hop1.by, (
        f"Hop 1 from/by should reference sender.org: {hop1}"
    )
    assert hop1.delta_s is None, "First hop should have no delta"

    # Hops 2 and 3 should have non-None delta_s
    assert result.hops[1].delta_s is not None, "Hop 2 should have a delta"
    assert result.hops[2].delta_s is not None, "Hop 3 should have a delta"

    # Deltas should be positive (timestamps are in ascending order)
    assert result.hops[1].delta_s >= 0, f"Hop 2 delta should be non-negative: {result.hops[1].delta_s}"
    assert result.hops[2].delta_s >= 0, f"Hop 3 delta should be non-negative: {result.hops[2].delta_s}"
    print(f"  parse_hops: {len(result.hops)} hops, deltas={[h.delta_s for h in result.hops]}: OK")


def test_auth_results_extracted():
    """Authentication-Results header produces correct AuthResult."""
    result = parse(AUTH_HEADER)
    assert result.auth.spf  == "pass", f"Expected spf=pass, got '{result.auth.spf}'"
    assert result.auth.dkim == "fail", f"Expected dkim=fail, got '{result.auth.dkim}'"
    assert result.auth.dmarc == "none", f"Expected dmarc=none, got '{result.auth.dmarc}'"
    print(f"  auth_results_extracted: spf={result.auth.spf} dkim={result.auth.dkim} dmarc={result.auth.dmarc}: OK")


def test_flags_gap():
    """Two hops > 1 hour apart produce a time-gap flag."""
    result = parse(GAP_HEADER)
    gap_flags = [f for f in result.flags if "gap" in f.lower() or "time" in f.lower()]
    assert gap_flags, (
        f"Expected a time-gap flag for 3h delay, flags were: {result.flags}"
    )
    print(f"  flags_gap: gap flag found — '{gap_flags[0][:60]}…': OK")


def test_flags_spf_fail():
    """SPF fail result produces a failure flag."""
    result = parse(SPF_FAIL_HEADER)
    spf_flags = [f for f in result.flags if "spf" in f.lower() or "SPF" in f]
    assert spf_flags, (
        f"Expected an SPF failure flag, flags were: {result.flags}"
    )
    print(f"  flags_spf_fail: SPF flag found — '{spf_flags[0][:60]}…': OK")


def test_empty_input():
    """parse('') returns a HeaderSummary without raising."""
    result = parse("")
    assert isinstance(result, HeaderSummary), "Expected HeaderSummary for empty input"
    assert result.hops == [], "Empty input should have no hops"
    assert result.flags == [], "Empty input should have no flags"
    print("  empty_input: OK")


# ── Runner ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    tests = [
        test_parse_hops,
        test_auth_results_extracted,
        test_flags_gap,
        test_flags_spf_fail,
        test_empty_input,
    ]
    passed = 0
    print(f"Running {len(tests)} Email Header Analyser tests…\n")
    for t in tests:
        try:
            t()
            passed += 1
        except AssertionError as e:
            print(f"  FAIL {t.__name__}: {e}")
        except Exception as e:
            import traceback
            print(f"  ERROR {t.__name__}: {e}")
            traceback.print_exc()
    print(f"\n{passed}/{len(tests)} tests passed")
    sys.exit(0 if passed == len(tests) else 1)
