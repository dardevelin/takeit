import math

import pytest

from takeit._dilation.connector import Connector
from takeit._dilation.manager import Manager
from takeit._hints import DirectTCPV1Hint, TorTCPV1Hint, parse_hint, parse_tcp_v1_hint


def _direct(hostname="192.168.1.20", port=1234, priority=0.0):
    return {
        "type": "direct-tcp-v1",
        "hostname": hostname,
        "port": port,
        "priority": priority,
    }


def _tor(hostname="example.onion", port=1234, priority=0.0):
    return {
        "type": "tor-tcp-v1",
        "hostname": hostname,
        "port": port,
        "priority": priority,
    }


def test_parse_direct_hint_rejects_private_ip_literal_by_default():
    assert parse_tcp_v1_hint(_direct()) is None


def test_parse_direct_hint_accepts_private_ip_literal_when_opted_in():
    hint = parse_tcp_v1_hint(_direct(), allow_private=True)
    assert hint == DirectTCPV1Hint("192.168.1.20", 1234, 0.0)


def test_parse_direct_hint_accepts_public_ip_literal_by_default():
    hint = parse_tcp_v1_hint(_direct("8.8.8.8"))
    assert hint == DirectTCPV1Hint("8.8.8.8", 1234, 0.0)


# Post-review additions: ipaddress.is_private misses these but they're
# routable inside ISPs / private dual-stack networks and so should be
# gated by --allow-private-hints.


@pytest.mark.parametrize(
    "host",
    [
        "100.64.0.1",  # CGNAT (RFC 6598)
        "100.127.255.254",  # CGNAT upper edge
    ],
)
def test_parse_direct_hint_rejects_cgnat_by_default(host):
    assert parse_tcp_v1_hint(_direct(host)) is None


@pytest.mark.parametrize(
    "host",
    [
        "100.64.0.1",
        "100.127.255.254",
    ],
)
def test_parse_direct_hint_accepts_cgnat_with_opt_in(host):
    hint = parse_tcp_v1_hint(_direct(host), allow_private=True)
    assert hint == DirectTCPV1Hint(host, 1234, 0.0)


def test_parse_direct_hint_rejects_6to4_by_default():
    assert parse_tcp_v1_hint(_direct("2002::1")) is None


def test_parse_direct_hint_accepts_6to4_with_opt_in():
    hint = parse_tcp_v1_hint(_direct("2002::1"), allow_private=True)
    assert hint == DirectTCPV1Hint("2002::1", 1234, 0.0)


def test_parse_direct_hint_accepts_ipv4_mapped_public_ipv6_by_default():
    """`::ffff:8.8.8.8` is the IPv4-mapped form of a PUBLIC IPv4. Without
    normalization, ipaddress.is_private returns True for these — which
    would falsely reject legitimate dual-stack peers. We unwrap the
    mapping before the private check."""
    hint = parse_tcp_v1_hint(_direct("::ffff:8.8.8.8"))
    assert hint == DirectTCPV1Hint("::ffff:8.8.8.8", 1234, 0.0)


def test_parse_direct_hint_rejects_ipv4_mapped_private_ipv6():
    """`::ffff:192.168.1.1` is the IPv4-mapped form of a PRIVATE IPv4;
    must still be gated by allow_private."""
    assert parse_tcp_v1_hint(_direct("::ffff:192.168.1.1")) is None
    hint = parse_tcp_v1_hint(_direct("::ffff:192.168.1.1"), allow_private=True)
    assert hint is not None


def test_parse_tor_hint_allows_hostname():
    hint = parse_tcp_v1_hint(_tor("example.com", priority=2))
    assert hint == TorTCPV1Hint("example.com", 1234, 2.0)


@pytest.mark.parametrize("port", [0, -1, 65536, True, "1234"])
def test_parse_hint_rejects_invalid_ports(port):
    assert parse_tcp_v1_hint(_direct(port=port)) is None
    assert parse_tcp_v1_hint(_tor(port=port)) is None


@pytest.mark.parametrize("priority", [True, "high", math.inf, -math.inf, math.nan])
def test_parse_hint_rejects_invalid_priority(priority):
    assert parse_tcp_v1_hint(_direct(priority=priority)) is None
    assert parse_tcp_v1_hint(_tor(priority=priority)) is None


@pytest.mark.parametrize(
    "hostname",
    [
        "localhost",
        "example.com",
        "127.0.0.1",
        "::1",
        "0.0.0.0",
        "::",
        "224.0.0.1",
        "ff02::1",
    ],
)
def test_parse_direct_hint_rejects_nonliteral_or_unsafe_addresses(hostname):
    assert parse_tcp_v1_hint(_direct(hostname=hostname)) is None


@pytest.mark.parametrize("hostname", ["169.254.1.2", "fe80::1"])
def test_parse_direct_hint_rejects_link_local_even_when_private_opted_in(hostname):
    assert parse_tcp_v1_hint(_direct(hostname=hostname), allow_private=True) is None


def test_parse_relay_hint_rejects_non_list_hints():
    assert parse_hint({"type": "relay-v1", "hints": "not a list"}) is None


def test_parse_relay_hint_honors_private_opt_in():
    relay = {"type": "relay-v1", "hints": [_direct()]}
    assert parse_hint(relay).hints == []
    assert parse_hint(relay, allow_private=True).hints == [
        DirectTCPV1Hint("192.168.1.20", 1234, 0.0)
    ]


class _FakeManager:
    def __init__(self):
        self.statuses = []

    def _hint_status(self, statuses):
        self.statuses.append(statuses)


class _FakeConnector:
    MAX_DIRECT_HINTS = Connector.MAX_DIRECT_HINTS

    def __init__(self):
        self._tor = None
        self._manager = _FakeManager()
        self.scheduled = []

    def _schedule_connection(self, delay, hint):
        self.scheduled.append((delay, hint))
        return True


class _HintsSink:
    def __init__(self):
        self.hints = None

    def got_hints(self, hints):
        self.hints = hints


class _FakeManagerForParsing:
    def __init__(self, allow_private_hints):
        self._allow_private_hints = allow_private_hints
        self._connector = _HintsSink()


def test_manager_filters_private_peer_hints_by_default():
    fake = _FakeManagerForParsing(allow_private_hints=False)
    Manager._use_hints(fake, {"hints": [_direct(), _direct("8.8.8.8")]})
    assert fake._connector.hints == [DirectTCPV1Hint("8.8.8.8", 1234, 0.0)]


def test_manager_allows_private_peer_hints_when_opted_in():
    fake = _FakeManagerForParsing(allow_private_hints=True)
    Manager._use_hints(fake, {"hints": [_direct()]})
    assert fake._connector.hints == [DirectTCPV1Hint("192.168.1.20", 1234, 0.0)]


def test_connector_caps_scheduled_peer_hints():
    fake = _FakeConnector()
    hints = [
        DirectTCPV1Hint(f"192.168.1.{i}", 10000 + i, 0.0)
        for i in range(1, Connector.MAX_DIRECT_HINTS + 10)
    ]
    Connector._use_hints(fake, hints)
    assert len(fake.scheduled) == Connector.MAX_DIRECT_HINTS
    assert len(fake._manager.statuses) == 1
    assert len(fake._manager.statuses[0]) == Connector.MAX_DIRECT_HINTS


class _NoStunConnector:
    _stun_servers = ()


def test_connector_skips_stun_when_no_servers_configured():
    # Should return before importing/using the STUN implementation.
    assert Connector._gather_stun_hints(_NoStunConnector(), 1234) is None
