"""
Tests for dilation framing hardening (HYP-422 + HYP-430).

HYP-422 added a hard frame-length cap to defend against unauthenticated
LAN attackers buffering huge frames pre-Noise-handshake. HYP-430 split
that cap into a tight pre-auth bound (handshake messages are ~100 bytes)
and a looser post-auth bound that accommodates legitimate file-transfer
records with default 1 MiB chunks (~1.001 MiB after Noise overhead).
"""

import pytest
from twisted.internet.interfaces import ITransport
from zope.interface import implementer

from takeit._dilation.connection import (
    MAX_POST_AUTH_FRAME_LENGTH,
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


# ---- HYP-430: post-auth cap accommodates legitimate file-transfer
# records with the default 1 MiB chunk size + Noise overhead.


def test_framer_post_auth_accepts_full_chunk_record_above_pre_auth_cap():
    """Regression for HYP-430: a 1 MiB plaintext chunk becomes a
    ~1,048,857-byte frame after Noise envelopes (1 MiB + 9-byte record
    header / NOISE_MAX_PAYLOAD = 17 Noise messages × per-message tag =
    16 × 65535 + 297 = 1,048,857 bytes). Pre-HYP-430 this hit the
    1-MiB pre-auth cap and disconnected mid-transfer. After
    mark_handshake_complete the post-auth cap accepts it."""
    framer = _make_framer()
    framer.mark_handshake_complete()
    # 1,048,857 bytes — a default-size chunk record after Noise envelope
    frame_len = (1 << 20) + 281
    assert frame_len > MAX_PRE_AUTH_FRAME_LENGTH
    assert frame_len <= MAX_POST_AUTH_FRAME_LENGTH
    frame = b"x" * frame_len
    tokens = list(framer.add_and_parse(to_be4(len(frame)) + frame))
    assert len(tokens) == 1
    assert isinstance(tokens[0], Frame)
    assert tokens[0].frame == frame


def test_framer_post_auth_still_rejects_oversized_frame():
    """The post-auth cap is loosened, not removed. An authenticated
    peer claiming a 64 MiB frame is still hostile / misbehaving and
    we drop the connection."""
    framer = _make_framer()
    framer.mark_handshake_complete()
    with pytest.raises(Disconnect):
        list(
            framer.add_and_parse(
                to_be4(MAX_POST_AUTH_FRAME_LENGTH + 1) + b"partial-payload"
            )
        )


def test_framer_pre_auth_cap_still_rejects_post_auth_size_frame():
    """Before mark_handshake_complete, a frame above the pre-auth cap
    is rejected even if it's within the post-auth cap. This is the
    HYP-422 invariant: a LAN attacker who reaches our listener but
    hasn't completed Noise can't buffer arbitrary memory."""
    framer = _make_framer()
    # Don't call mark_handshake_complete — still in pre-auth posture.
    above_pre = MAX_PRE_AUTH_FRAME_LENGTH + 1
    assert above_pre <= MAX_POST_AUTH_FRAME_LENGTH
    with pytest.raises(Disconnect):
        list(framer.add_and_parse(to_be4(above_pre) + b"partial"))


def test_post_auth_cap_accommodates_default_chunk_size():
    """Pin the relationship: MAX_POST_AUTH_FRAME_LENGTH must be large
    enough to hold a frame containing a default-chunk-size data record
    (chunk + 9-byte record header) split across Noise messages with
    16-byte auth tags each."""
    from takeit._dilation._noise import NOISE_MAX_PAYLOAD
    from takeit.cli._protocol import DEFAULT_CHUNK_SIZE

    record_plaintext = 9 + DEFAULT_CHUNK_SIZE  # T_DATA + scid + seqnum + data
    full_noise_messages = record_plaintext // NOISE_MAX_PAYLOAD
    tail_plaintext = record_plaintext % NOISE_MAX_PAYLOAD
    # Each full Noise message: NOISE_MAX_PAYLOAD + 16 (tag) bytes; tail
    # message: tail_plaintext + 16 bytes.
    frame_len = full_noise_messages * (NOISE_MAX_PAYLOAD + 16)
    if tail_plaintext:
        frame_len += tail_plaintext + 16
    assert MAX_POST_AUTH_FRAME_LENGTH >= frame_len, (
        f"post-auth cap ({MAX_POST_AUTH_FRAME_LENGTH}) is too small for "
        f"a default-chunk-size frame ({frame_len} bytes). Bumping the "
        f"cap or shrinking DEFAULT_CHUNK_SIZE would fix it; the current "
        f"combination causes default file transfers to disconnect."
    )
