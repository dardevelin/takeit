import pytest

from takeit._dilation.connection import (
    KCM,
    MAX_SUBPROTOCOL_NAME_BYTES,
    T_ACK,
    T_CLOSE,
    T_DATA,
    T_KCM,
    T_OPEN,
    T_PING,
    T_PONG,
    Ack,
    Close,
    Data,
    Open,
    Ping,
    Pong,
    parse_record,
)
from takeit._dilation.encode import to_be4


def test_parse_record_accepts_valid_records():
    assert parse_record(T_KCM) == KCM()
    assert parse_record(T_PING + b"ping") == Ping(b"ping")
    assert parse_record(T_PONG + b"pong") == Pong(b"pong")
    assert parse_record(T_OPEN + to_be4(7) + to_be4(8) + b"xfer") == Open(8, 7, "xfer")
    assert parse_record(T_DATA + to_be4(7) + to_be4(8) + b"payload") == Data(
        8, 7, b"payload"
    )
    assert parse_record(T_CLOSE + to_be4(7) + to_be4(8)) == Close(8, 7)
    assert parse_record(T_ACK + to_be4(9)) == Ack(9)


@pytest.mark.parametrize(
    "record",
    [
        b"",
        T_KCM + b"x",
        T_PING + b"abc",
        T_PING + b"abcde",
        T_PONG + b"abc",
        T_PONG + b"abcde",
        T_ACK + b"abc",
        T_ACK + b"abcde",
        T_OPEN + b"\x00" * 7,
        T_DATA + b"\x00" * 7,
        T_CLOSE + b"\x00" * 7,
        T_CLOSE + b"\x00" * 9,
        b"\xff",
    ],
)
def test_parse_record_rejects_malformed_lengths_and_unknown_types(record):
    with pytest.raises(ValueError):
        parse_record(record)


def test_parse_record_rejects_invalid_open_subprotocol_utf8():
    with pytest.raises(ValueError, match="UTF-8"):
        parse_record(T_OPEN + to_be4(7) + to_be4(8) + b"\xff")


def test_parse_record_rejects_oversized_open_subprotocol():
    payload = b"a" * (MAX_SUBPROTOCOL_NAME_BYTES + 1)
    with pytest.raises(ValueError, match="too long"):
        parse_record(T_OPEN + to_be4(7) + to_be4(8) + payload)
