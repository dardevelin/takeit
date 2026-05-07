"""
Tests for the minimal STUN client used to discover a reflexive address.

Wire format covered: RFC 5389 Binding Request / Binding Success Response,
including XOR-MAPPED-ADDRESS (the only attribute we need).
"""
import os
import struct

import pytest

from takeit._dilation._stun import (
    MAGIC_COOKIE, build_binding_request, parse_binding_response,
    StunError,
)


def test_binding_request_format():
    """Binding Request: type=0x0001, length=0, MAGIC_COOKIE, 12-byte tx_id."""
    tx_id = b"\x11" * 12
    req = build_binding_request(tx_id)
    assert len(req) == 20  # header only, no attributes
    msg_type, msg_length, cookie, returned_tx = struct.unpack(">HHI12s", req)
    assert msg_type == 0x0001  # Binding Request
    assert msg_length == 0
    assert cookie == MAGIC_COOKIE
    assert returned_tx == tx_id


def test_parse_response_with_xor_mapped_address_ipv4():
    """A valid Binding Success Response with IPv4 XOR-MAPPED-ADDRESS."""
    tx_id = b"\x22" * 12
    # Build a synthetic response: Success (0x0101) with XOR-MAPPED-ADDRESS
    # attribute. Attribute layout: type (2) | len (2) | value...
    # XOR-MAPPED-ADDRESS value: 0 (1) | family (1) | x_port (2) | x_addr (4)
    # Family 0x01 = IPv4. Port and addr are XORed with MAGIC_COOKIE / its
    # high 16 bits respectively.
    real_port = 54321
    real_addr = (203, 0, 113, 99)  # 203.0.113.99 (TEST-NET-3)

    x_port = real_port ^ (MAGIC_COOKIE >> 16)
    addr_int = (real_addr[0] << 24) | (real_addr[1] << 16) \
        | (real_addr[2] << 8) | real_addr[3]
    x_addr = addr_int ^ MAGIC_COOKIE

    attr_value = struct.pack(">BBHI", 0, 0x01, x_port, x_addr)
    attr = struct.pack(">HH", 0x0020, len(attr_value)) + attr_value  # XOR-MAPPED-ADDRESS

    header = struct.pack(">HHI12s", 0x0101, len(attr), MAGIC_COOKIE, tx_id)
    response = header + attr

    addr, port = parse_binding_response(response, tx_id)
    assert addr == "203.0.113.99"
    assert port == real_port


def test_parse_response_rejects_wrong_transaction_id():
    """A response whose tx_id doesn't match the request must be rejected.

    This catches misrouted responses (e.g. on a shared UDP socket)."""
    sent_tx = b"\xAA" * 12
    other_tx = b"\xBB" * 12
    header = struct.pack(">HHI12s", 0x0101, 0, MAGIC_COOKIE, other_tx)
    with pytest.raises(StunError, match="transaction"):
        parse_binding_response(header, sent_tx)


def test_parse_response_rejects_non_success_class():
    """STUN error responses (class=0x0111) are not parsed as binding success."""
    tx_id = b"\xCC" * 12
    header = struct.pack(">HHI12s", 0x0111, 0, MAGIC_COOKIE, tx_id)
    with pytest.raises(StunError, match="not.*success"):
        parse_binding_response(header, tx_id)


def test_parse_response_rejects_short_packet():
    """Anything under 20 bytes can't even be a STUN header."""
    with pytest.raises(StunError, match="too short"):
        parse_binding_response(b"x" * 10, b"\x00" * 12)


def test_parse_response_rejects_bad_magic_cookie():
    """Wrong MAGIC_COOKIE means this isn't a STUN message at all."""
    tx_id = b"\xDD" * 12
    header = struct.pack(">HHI12s", 0x0101, 0, 0xDEADBEEF, tx_id)
    with pytest.raises(StunError, match="cookie"):
        parse_binding_response(header, tx_id)


def test_parse_response_ignores_unknown_attributes():
    """Unknown attributes (comprehension-optional, type >= 0x8000) must
    not cause parse failures — we just look for XOR-MAPPED-ADDRESS."""
    tx_id = b"\xEE" * 12
    real_port = 8080
    real_addr = (192, 0, 2, 1)

    # Unknown comprehension-optional attribute (type 0x8023 = SOFTWARE)
    soft_value = b"unit-test\x00\x00\x00"  # padded to 4 bytes
    soft_attr = struct.pack(">HH", 0x8022, len(soft_value)) + soft_value

    # XOR-MAPPED-ADDRESS
    x_port = real_port ^ (MAGIC_COOKIE >> 16)
    addr_int = (real_addr[0] << 24) | (real_addr[1] << 16) \
        | (real_addr[2] << 8) | real_addr[3]
    x_addr = addr_int ^ MAGIC_COOKIE
    xma_value = struct.pack(">BBHI", 0, 0x01, x_port, x_addr)
    xma_attr = struct.pack(">HH", 0x0020, len(xma_value)) + xma_value

    body = soft_attr + xma_attr
    header = struct.pack(">HHI12s", 0x0101, len(body), MAGIC_COOKIE, tx_id)
    response = header + body

    addr, port = parse_binding_response(response, tx_id)
    assert addr == "192.0.2.1"
    assert port == real_port


# --- live integration (skipped without env opt-in) ---


@pytest.mark.skipif(
    not os.environ.get("TAKEIT_TEST_STUN"),
    reason="set TAKEIT_TEST_STUN=stun.l.google.com:19302 to run",
)
def test_integration_against_real_stun_server():  # pragma: no cover
    from takeit._dilation._stun import discover_reflexive_address_blocking
    host, port = os.environ["TAKEIT_TEST_STUN"].split(":")
    addr, port_out = discover_reflexive_address_blocking(host, int(port))
    assert addr.count(".") == 3 or ":" in addr
    assert 1 <= port_out <= 65535
