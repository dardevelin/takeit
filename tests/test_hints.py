import math

import pytest

from takeit._dilation.connector import Connector
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


def test_parse_direct_hint_accepts_private_ip_literal():
    hint = parse_tcp_v1_hint(_direct())
    assert hint == DirectTCPV1Hint("192.168.1.20", 1234, 0.0)


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
        "169.254.1.2",
        "fe80::1",
    ],
)
def test_parse_direct_hint_rejects_nonliteral_or_unsafe_addresses(hostname):
    assert parse_tcp_v1_hint(_direct(hostname=hostname)) is None


def test_parse_relay_hint_rejects_non_list_hints():
    assert parse_hint({"type": "relay-v1", "hints": "not a list"}) is None


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
