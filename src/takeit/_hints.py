# Originally from magic-wormhole (MIT, (c) 2015 Brian Warner).
# Lifted into takeit; see NOTICE for the full list.
import ipaddress
import math
import numbers
from collections import namedtuple

from twisted.internet.abstract import isIPAddress, isIPv6Address
from twisted.internet.endpoints import (
    HostnameEndpoint,
    TCP4ClientEndpoint,
    TCP6ClientEndpoint,
)
from twisted.python import log

# These namedtuples are "hint objects". The JSON-serializable dictionaries
# are "hint dicts".

# DirectTCPV1Hint and TorTCPV1Hint mean the following protocol:
# * make a TCP connection (possibly via Tor)
# * send the sender/receiver handshake bytes first
# * expect to see the receiver/sender handshake bytes from the other side
# * the sender writes "go\n", the receiver waits for "go\n"
# * the rest of the connection contains transit data
DirectTCPV1Hint = namedtuple("DirectTCPV1Hint", ["hostname", "port", "priority"])
TorTCPV1Hint = namedtuple("TorTCPV1Hint", ["hostname", "port", "priority"])
# RelayV1Hint contains a tuple of DirectTCPV1Hint and TorTCPV1Hint hints (we
# use a tuple rather than a list so they'll be hashable into a set). For each
# one, make the TCP connection, send the relay handshake, then complete the
# rest of the V1 protocol. Only one hint per relay is useful.
RelayV1Hint = namedtuple("RelayV1Hint", ["hints"])


def describe_hint_obj(hint, relay, tor):
    prefix = "tor->" if tor else "->"
    if relay:
        prefix = prefix + "relay:"
    if isinstance(hint, DirectTCPV1Hint):
        return prefix + "tcp:%s:%d" % (hint.hostname, hint.port)
    elif isinstance(hint, TorTCPV1Hint):
        return prefix + "tor:%s:%d" % (hint.hostname, hint.port)
    else:
        return prefix + str(hint)


def endpoint_from_hint_obj(hint, tor, reactor):
    if tor:
        if isinstance(hint, (DirectTCPV1Hint, TorTCPV1Hint)):
            # this Tor object will throw ValueError for non-public IPv4
            # addresses and any IPv6 address
            try:
                return tor.stream_via(hint.hostname, hint.port)
            except ValueError:
                return None
        return None
    if isinstance(hint, DirectTCPV1Hint):
        # avoid DNS lookup unless necessary
        if isIPAddress(hint.hostname):
            return TCP4ClientEndpoint(reactor, hint.hostname, hint.port)
        if isIPv6Address(hint.hostname):
            return TCP6ClientEndpoint(reactor, hint.hostname, hint.port)
        return HostnameEndpoint(reactor, hint.hostname, hint.port)
    return None


# Carrier-grade NAT (RFC 6598) — routable inside an ISP, not flagged as
# private by `ipaddress`. Treat as private for the opt-in gate.
_CGNAT_NET = ipaddress.ip_network("100.64.0.0/10")
# 6to4 (RFC 3056) — public-routable but commonly bridges to internal IPv4
# space; require opt-in to avoid SSRF-via-IPv6-tunnel surprises.
_SIXTOFOUR_NET = ipaddress.ip_network("2002::/16")


def is_private_or_carrier_grade(ip):
    """Return True if `ip` should be gated by `--allow-private-hints`.

    Catches what `ipaddress.is_private` misses: CGNAT (100.64/10) routes
    inside ISPs without being marked private, and 6to4 (2002::/16) is
    `is_global=True` but bridges to potentially-internal IPv4. IPv4-mapped
    IPv6 is normalized to its IPv4 form before the check so that a
    public address wrapped as `::ffff:8.8.8.8` is not falsely rejected.
    """
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip.is_private:
        return True
    if isinstance(ip, ipaddress.IPv4Address) and ip in _CGNAT_NET:
        return True
    if isinstance(ip, ipaddress.IPv6Address) and ip in _SIXTOFOUR_NET:
        return True
    return False


def parse_tcp_v1_hint(hint, *, allow_private=False):  # hint_struct -> hint_obj
    hint_type = hint.get("type", "")
    if hint_type not in ["direct-tcp-v1", "tor-tcp-v1"]:
        log.msg(f"unknown hint type: {hint!r}")
        return None
    if not ("hostname" in hint and isinstance(hint["hostname"], str)):
        log.msg(f"invalid hostname in hint: {hint!r}")
        return None
    if not (
        "port" in hint
        and isinstance(hint["port"], int)
        and not isinstance(hint["port"], bool)
        and 1 <= hint["port"] <= 65535
    ):
        log.msg(f"invalid port in hint: {hint!r}")
        return None
    priority = hint.get("priority", 0.0)
    if (
        not isinstance(priority, numbers.Real)
        or isinstance(priority, bool)
        or not math.isfinite(priority)
    ):
        log.msg(f"invalid priority in hint: {hint!r}")
        return None
    if hint_type == "direct-tcp-v1":
        try:
            ip = ipaddress.ip_address(hint["hostname"])
        except ValueError:
            log.msg(f"direct hint hostname is not an IP literal: {hint!r}")
            return None
        if ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_link_local:
            log.msg(f"unsafe direct hint address: {hint!r}")
            return None
        if not allow_private and is_private_or_carrier_grade(ip):
            log.msg(f"private direct hint address requires opt-in: {hint!r}")
            return None
        return DirectTCPV1Hint(str(ip), hint["port"], float(priority))
    else:
        return TorTCPV1Hint(hint["hostname"], hint["port"], float(priority))


def parse_hint(hint_struct, *, allow_private=False):
    hint_type = hint_struct.get("type", "")
    if hint_type == "relay-v1":
        # the struct can include multiple ways to reach the same relay
        if not isinstance(hint_struct.get("hints"), list):
            log.msg(f"invalid relay-v1 hints: {hint_struct!r}")
            return None
        rhints = filter(
            lambda h: h,  # drop None (unrecognized)
            [
                parse_tcp_v1_hint(rh, allow_private=allow_private)
                for rh in hint_struct["hints"]
            ],
        )
        return RelayV1Hint(list(rhints))
    return parse_tcp_v1_hint(hint_struct, allow_private=allow_private)


def encode_hint(h):
    if isinstance(h, DirectTCPV1Hint):
        return {
            "type": "direct-tcp-v1",
            "priority": h.priority,
            "hostname": h.hostname,
            "port": h.port,  # integer
        }
    elif isinstance(h, RelayV1Hint):
        rhint = {"type": "relay-v1", "hints": []}
        for rh in h.hints:
            rhint["hints"].append(
                {
                    "type": "direct-tcp-v1",
                    "priority": rh.priority,
                    "hostname": rh.hostname,
                    "port": rh.port,
                }
            )
        return rhint
    elif isinstance(h, TorTCPV1Hint):
        return {
            "type": "tor-tcp-v1",
            "priority": h.priority,
            "hostname": h.hostname,
            "port": h.port,  # integer
        }
    raise ValueError("unknown hint type", h)
