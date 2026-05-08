"""
Tests for dilation framing hardening (HYP-422).
"""

import pytest
from twisted.internet.interfaces import ITransport
from zope.interface import implementer

from takeit._dilation.connection import (
    MAX_PRE_AUTH_FRAME_LENGTH,
    Disconnect,
    Frame,
    _Framer,
)
from takeit._dilation.encode import to_be4


@implementer(ITransport)
class _FakeTransport:
    def __init__(self):
        self.writes = []

    def write(self, data):
        self.writes.append(data)

    def writeSequence(self, data):
        for chunk in data:
            self.writes.append(chunk)

    def loseConnection(self):
        pass

    def getPeer(self):
        return None

    def getHost(self):
        return None


def _make_framer(prologue=b"takeit-prologue\n\n"):
    transport = _FakeTransport()
    framer = _Framer(transport, b"outbound", prologue)
    framer.connectionMade()
    list(framer.add_and_parse(prologue))
    return framer


def test_framer_rejects_oversized_length_prefix():
    framer = _make_framer()
    with pytest.raises(Disconnect):
        list(
            framer.add_and_parse(
                to_be4(MAX_PRE_AUTH_FRAME_LENGTH + 1) + b"partial-payload"
            )
        )


def test_framer_accepts_frame_at_cap_and_parses_body():
    framer = _make_framer()
    frame = b"x" * 1024
    body = to_be4(len(frame)) + frame
    tokens = list(framer.add_and_parse(body))
    assert len(tokens) == 1
    assert isinstance(tokens[0], Frame)
    assert tokens[0].frame == frame


def test_framer_allows_frame_of_exact_cap_size():
    framer = _make_framer()
    frame = b"x" * MAX_PRE_AUTH_FRAME_LENGTH
    tokens = list(framer.add_and_parse(to_be4(len(frame)) + frame))
    assert len(tokens) == 1
    assert tokens[0].frame == frame
