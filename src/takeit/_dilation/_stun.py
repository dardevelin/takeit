"""
Minimal STUN client for discovering a reflexive address (RFC 5389).

We only need the Binding Request and the XOR-MAPPED-ADDRESS attribute from
the response. No authentication, no fingerprint, no TURN. Implementation
is ~120 lines and avoids pulling in `pystun3` / `aioice` for what amounts
to "send 20 bytes of UDP, parse 32 bytes back."

Used by `Connector.start()` to gather candidate `(reflexive_ip, port)`
addresses to advertise as DirectTCPV1Hint to the peer.
"""
import os
import socket
import struct

from twisted.internet.defer import Deferred
from twisted.internet.protocol import DatagramProtocol


# RFC 5389: every STUN message includes a fixed 4-byte magic cookie.
MAGIC_COOKIE = 0x2112A442

# Message types we care about.
_MSG_BINDING_REQUEST = 0x0001
_MSG_BINDING_SUCCESS = 0x0101

# Attribute type for the XORed reflexive address.
_ATTR_XOR_MAPPED_ADDRESS = 0x0020


class StunError(Exception):
    """Raised by parse_binding_response on malformed or unexpected data."""


def build_binding_request(transaction_id: bytes) -> bytes:
    """Construct a 20-byte STUN Binding Request.

    The transaction_id (12 bytes) MUST be unique per request — the response
    echoes it, and we use it to match responses to requests over a shared
    UDP socket.
    """
    if len(transaction_id) != 12:
        raise ValueError("transaction_id must be 12 bytes")
    return struct.pack(">HHI12s",
                       _MSG_BINDING_REQUEST, 0, MAGIC_COOKIE, transaction_id)


def parse_binding_response(packet: bytes, expected_tx_id: bytes
                           ) -> tuple[str, int]:
    """Parse a STUN Binding Success Response and return (addr, port).

    Raises :class:`StunError` if the message is malformed, has the wrong
    transaction id, isn't a success class, or doesn't contain a
    XOR-MAPPED-ADDRESS attribute.
    """
    if len(packet) < 20:
        raise StunError("STUN packet too short for a header")

    msg_type, msg_length, cookie, tx_id = struct.unpack(">HHI12s", packet[:20])

    if cookie != MAGIC_COOKIE:
        raise StunError(f"bad magic cookie: {cookie:#x}")
    if tx_id != expected_tx_id:
        raise StunError("transaction id mismatch")
    if msg_type != _MSG_BINDING_SUCCESS:
        raise StunError(f"not a success response: type={msg_type:#06x}")
    if len(packet) - 20 < msg_length:
        raise StunError("STUN body shorter than declared length")

    body = packet[20:20 + msg_length]
    pos = 0
    while pos + 4 <= len(body):
        attr_type, attr_len = struct.unpack(">HH", body[pos:pos + 4])
        pos += 4
        if pos + attr_len > len(body):
            raise StunError("attribute length overruns body")
        value = body[pos:pos + attr_len]
        # Attributes are padded to 4-byte boundaries on the wire, but the
        # length field reports unpadded length.
        padded = (attr_len + 3) & ~3
        pos += padded

        if attr_type == _ATTR_XOR_MAPPED_ADDRESS:
            if len(value) < 4:
                raise StunError("XOR-MAPPED-ADDRESS too short")
            _reserved, family, x_port = struct.unpack(">BBH", value[:4])
            port = x_port ^ (MAGIC_COOKIE >> 16)
            if family == 0x01:  # IPv4
                if len(value) < 8:
                    raise StunError("XOR-MAPPED-ADDRESS IPv4 too short")
                x_addr = struct.unpack(">I", value[4:8])[0]
                addr_int = x_addr ^ MAGIC_COOKIE
                addr = "{}.{}.{}.{}".format(
                    (addr_int >> 24) & 0xFF,
                    (addr_int >> 16) & 0xFF,
                    (addr_int >> 8) & 0xFF,
                    addr_int & 0xFF,
                )
                return addr, port
            elif family == 0x02:  # IPv6
                if len(value) < 20:
                    raise StunError("XOR-MAPPED-ADDRESS IPv6 too short")
                # IPv6 address is XOR'd with MAGIC_COOKIE || transaction_id.
                xor_key = struct.pack(">I12s", MAGIC_COOKIE, expected_tx_id)
                addr_bytes = bytes(a ^ b for a, b in zip(value[4:20], xor_key))
                addr = socket.inet_ntop(socket.AF_INET6, addr_bytes)
                return addr, port
            else:
                raise StunError(f"unknown address family {family:#x}")

    raise StunError("response had no XOR-MAPPED-ADDRESS attribute")


class _StunDatagramProtocol(DatagramProtocol):
    """One-shot datagram protocol: send a Binding Request, fire a
    Deferred with the parsed response or an errback on timeout / error."""

    def __init__(self, server_host, server_port, deferred, transaction_id):
        self._server = (server_host, server_port)
        self._d = deferred
        self._tx_id = transaction_id
        self._fired = False

    def startProtocol(self):
        self.transport.write(build_binding_request(self._tx_id), self._server)

    def datagramReceived(self, data, addr):
        if self._fired:
            return
        self._fired = True
        try:
            result = parse_binding_response(data, self._tx_id)
        except StunError as e:
            self._d.errback(e)
        else:
            self._d.callback(result)
        finally:
            try:
                self.transport.stopListening()
            except Exception:  # pragma: no cover
                pass


def discover_reflexive_address(reactor, server_host, server_port,
                               timeout=2.0):
    """Async STUN binding via the Twisted reactor.

    Returns a Deferred firing with ``(reflexive_addr, reflexive_port)`` or
    erroring with :class:`StunError` / a timeout.
    """
    d = Deferred()
    tx_id = os.urandom(12)
    proto = _StunDatagramProtocol(server_host, server_port, d, tx_id)
    listening_port = reactor.listenUDP(0, proto)

    def _cancel():  # pragma: no cover (covered by integration test)
        if not proto._fired:
            proto._fired = True
            try:
                listening_port.stopListening()
            except Exception:
                pass
            d.errback(StunError(f"STUN timeout after {timeout}s"))

    delayed = reactor.callLater(timeout, _cancel)

    def _cancel_timeout(result):
        if delayed.active():
            delayed.cancel()
        return result

    d.addBoth(_cancel_timeout)
    return d


def discover_reflexive_address_blocking(server_host, server_port,
                                        timeout=2.0):
    """Synchronous helper for tests / scripting only.

    Sends a single UDP Binding Request and parses the response. Not for
    use inside the reactor — use :func:`discover_reflexive_address`.
    """
    tx_id = os.urandom(12)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        sock.sendto(build_binding_request(tx_id), (server_host, server_port))
        data, _ = sock.recvfrom(1024)
        return parse_binding_response(data, tx_id)
    finally:
        sock.close()
