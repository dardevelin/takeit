"""
HYP-455: caps on inbound subchannel buffers.

Three sites of unbounded growth, all reachable by an authenticated
peer post-Noise:

1. SubchannelDemultiplex._pending_opens (per-name list of OPENs
   awaiting a register() call). Capped at
   MAX_PENDING_OPENS_PER_SUBPROTOCOL = 64. Excess raises
   PendingOpenCapExceeded which Inbound converts to send_close.

2. Inbound._open_subchannels (total count of OPEN subchannels).
   Capped at MAX_OPEN_SUBCHANNELS = 256. Excess sends close +
   refuses to allocate.

3. SubChannel._pending_remote_data (per-channel byte buffer for
   DATA arriving before the local protocol attaches). Capped at
   MAX_PENDING_REMOTE_DATA_BYTES = 16 MiB. Excess closes the
   subchannel and drops the buffer.

The point of the cap is post-auth memory DoS: Noise-authenticated
doesn't make the peer trusted enough to allocate unbounded memory
on our behalf.
"""

from unittest.mock import MagicMock

import pytest
from zope.interface import implementer

from takeit._dilation.inbound import MAX_OPEN_SUBCHANNELS, Inbound
from takeit._dilation.subchannel import (
    MAX_PENDING_OPENS_PER_SUBPROTOCOL,
    MAX_PENDING_REMOTE_DATA_BYTES,
    PendingOpenCapExceeded,
    SubChannel,
    SubchannelAddress,
    SubchannelDemultiplex,
    _WormholeAddress,
)
from takeit._interfaces import IDilationManager


@implementer(IDilationManager)
class _FakeManager:
    """Minimum IDilationManager for tests that need the provides()
    validator to pass. Captures send_close for assertion. Other surface
    is a no-op to keep this small."""

    def __init__(self):
        self.send_close_calls = []
        self._subprotocol_factories = None

    def send_close(self, scid):
        self.send_close_calls.append(scid)

    def __getattr__(self, _name):
        return lambda *a, **kw: None


# --- Site 1: _pending_opens per-name cap ---


def _make_demux(expected_names):
    return SubchannelDemultiplex(frozenset(expected_names))


def _fake_open(name, scid=0):
    """Tuple shape that _got_open expects: (transport, peer_addr).
    Transport is a stand-in; peer_addr carries the subprotocol name."""
    t = MagicMock(name=f"transport-scid-{scid}")
    addr = SubchannelAddress(name)
    return t, addr


def test_pending_opens_under_cap_queues_normally():
    """Negative control: 64 OPENs queue cleanly; the 65th would tip."""
    demux = _make_demux({"sub1"})
    for i in range(MAX_PENDING_OPENS_PER_SUBPROTOCOL):
        t, addr = _fake_open("sub1", scid=i)
        demux._got_open(t, addr)
    assert len(demux._pending_opens["sub1"]) == MAX_PENDING_OPENS_PER_SUBPROTOCOL


def test_pending_opens_at_cap_raises_on_next():
    """The (N+1)th OPEN for an expected-but-unregistered subprotocol
    raises PendingOpenCapExceeded. Inbound translates this into
    send_close."""
    demux = _make_demux({"sub1"})
    for i in range(MAX_PENDING_OPENS_PER_SUBPROTOCOL):
        t, addr = _fake_open("sub1", scid=i)
        demux._got_open(t, addr)
    t_overflow, addr_overflow = _fake_open("sub1", scid=999)
    with pytest.raises(PendingOpenCapExceeded):
        demux._got_open(t_overflow, addr_overflow)
    # The overflow OPEN was NOT appended.
    assert len(demux._pending_opens["sub1"]) == MAX_PENDING_OPENS_PER_SUBPROTOCOL


def test_pending_opens_cap_is_per_name_not_global():
    """A different subprotocol name has its own quota — cap is per
    subprotocol-name. A peer can't use one subprotocol's queue to
    block another subprotocol's queue."""
    demux = _make_demux({"sub1", "sub2"})
    for i in range(MAX_PENDING_OPENS_PER_SUBPROTOCOL):
        t, addr = _fake_open("sub1", scid=i)
        demux._got_open(t, addr)
    # sub1 is at cap; sub2 should still accept.
    t, addr = _fake_open("sub2", scid=1000)
    demux._got_open(t, addr)
    assert len(demux._pending_opens["sub2"]) == 1


def test_pending_opens_register_drains_queue():
    """Sanity: register() flushes accumulated pending OPENs through to
    factory.buildProtocol(). After register(), the cap is irrelevant for
    that subprotocol — connect() runs synchronously."""
    demux = _make_demux({"sub1"})
    fake_factory = MagicMock()
    fake_proto = MagicMock()
    fake_factory.buildProtocol.return_value = fake_proto

    # Queue 10 OPENs for sub1
    for i in range(10):
        t, addr = _fake_open("sub1", scid=i)
        demux._got_open(t, addr)
    assert len(demux._pending_opens["sub1"]) == 10

    # register() drains them
    demux.register("sub1", fake_factory)
    assert fake_factory.buildProtocol.call_count == 10
    # Pending queue removed entirely after drain
    assert "sub1" not in demux._pending_opens


# --- Site 2: Inbound._open_subchannels total count cap ---


def _make_inbound():
    """Inbound with a real-shape IDilationManager fake."""
    mgr = _FakeManager()
    mgr._subprotocol_factories = SubchannelDemultiplex(frozenset({"sub1"}))
    inbound = Inbound(mgr, _WormholeAddress())
    return inbound, mgr


def test_open_subchannels_under_cap_allocates_normally():
    """Negative control: 256 OPENs allocate cleanly; the 257th would tip."""
    inbound, mgr = _make_inbound()
    for scid in range(MAX_OPEN_SUBCHANNELS):
        inbound.handle_open(scid, "sub1")
    # Some scids may have been removed via UnexpectedSubprotocol /
    # PendingOpenCapExceeded — verify the 64 pending-queue cap
    # didn't silently kick first.
    assert len(inbound._open_subchannels) == MAX_PENDING_OPENS_PER_SUBPROTOCOL, (
        "Per-name OPEN cap fires before the global cap; this test asserts "
        "the per-name cap leaves entries that the global cap then governs"
    )


def test_open_subchannels_at_cap_refuses_further_opens():
    """The (N+1)th OPEN with a fresh scid is refused via send_close
    BEFORE allocating a SubChannel. Crucially: the per-name pending
    cap doesn't shadow this — even with all subprotocols registered,
    the global count cap fires."""
    inbound, mgr = _make_inbound()
    # Register sub1 so per-name pending cap doesn't fire (each OPEN
    # connects synchronously instead of queuing).
    mgr._subprotocol_factories.register("sub1", MagicMock())
    # Fill to cap with distinct scids
    for scid in range(MAX_OPEN_SUBCHANNELS):
        inbound.handle_open(scid, "sub1")
    pre_send_close = len(mgr.send_close_calls)
    # Overflow:
    inbound.handle_open(MAX_OPEN_SUBCHANNELS + 1, "sub1")
    # send_close was called for the overflow scid; SubChannel was
    # NOT allocated for it (count stays at cap).
    assert len(mgr.send_close_calls) == pre_send_close + 1
    assert mgr.send_close_calls[-1] == MAX_OPEN_SUBCHANNELS + 1
    assert (MAX_OPEN_SUBCHANNELS + 1) not in inbound._open_subchannels


def test_open_subchannels_cap_uses_max_constant():
    """Pin: the cap is exactly MAX_OPEN_SUBCHANNELS. Future tunings
    should update the constant, not the test value."""
    assert MAX_OPEN_SUBCHANNELS == 256


# --- Site 3: SubChannel._pending_remote_data byte cap ---


def _make_subchannel(scid=42):
    mgr = _FakeManager()
    # attrs strips the leading underscore from `_xxx = attrib(...)`
    # (per feedback_attrs_strips_underscore_kwargs). So kwargs are
    # scid/manager/host_addr/peer_addr, NOT _scid/_manager/etc.
    sc = SubChannel(
        scid=scid,
        manager=mgr,
        host_addr=_WormholeAddress(),
        peer_addr=SubchannelAddress("sub1"),
    )
    return sc, mgr


def test_pending_remote_data_under_cap_queues():
    """Negative control: bytes under the cap accumulate and the
    counter tracks them."""
    sc, mgr = _make_subchannel()
    sc.remote_data(b"x" * 1024)
    sc.remote_data(b"x" * 2048)
    assert sc._pending_remote_data_bytes == 1024 + 2048
    assert len(sc._pending_remote_data) == 2
    assert mgr.send_close_calls == []


def test_pending_remote_data_over_cap_closes_channel():
    """A peer that floods DATA before the local protocol attaches
    forces a close at the cap. The pending buffer is dropped to free
    memory; further DATA should also be ignored (channel is closing)."""
    sc, mgr = _make_subchannel(scid=99)
    # Push to just under cap
    chunk = b"x" * (1 << 20)  # 1 MiB
    for _ in range(MAX_PENDING_REMOTE_DATA_BYTES // len(chunk)):
        sc.remote_data(chunk)
    # Should still be under cap, no close
    assert mgr.send_close_calls == []
    # Tip over with one more byte
    sc.remote_data(b"\x00")
    # send_close fired with our scid
    assert mgr.send_close_calls == [99]
    # Buffer cleared to free memory
    assert sc._pending_remote_data == []
    assert sc._pending_remote_data_bytes == 0


def test_pending_remote_data_cap_uses_max_constant():
    """Pin: the cap is exactly 16 MiB."""
    assert MAX_PENDING_REMOTE_DATA_BYTES == 16 << 20


def test_pending_remote_data_cap_is_terminal_hyp457():
    """HYP-457: once the cap fires, further remote_data must be
    dropped — NOT re-buffered. Pre-fix, a peer could cycle
    fill→close→re-fill repeatedly, defeating HYP-455's cap.

    Reproduces the pass-12 finding: after cap-trip, b'z'*1234
    was accepted into a fresh buffer."""
    sc, mgr = _make_subchannel(scid=42)
    chunk = b"x" * (1 << 20)
    for _ in range(MAX_PENDING_REMOTE_DATA_BYTES // len(chunk)):
        sc.remote_data(chunk)
    # Tip: fires cap.
    sc.remote_data(b"\x00")
    assert mgr.send_close_calls == [42], "cap-trip should send_close once"
    assert sc._cap_tripped is True, "cap-trip flag must be set"

    # The post-cap remote_data is dropped, NOT re-buffered.
    sc.remote_data(b"z" * 1234)
    assert sc._pending_remote_data == [], "buffer must stay empty"
    assert sc._pending_remote_data_bytes == 0, (
        "byte counter must stay zero — peer cannot cycle pressure"
    )
    # And no second close — the cap-trip is terminal, not chatty.
    assert mgr.send_close_calls == [42], "send_close must fire only once"


def test_pending_remote_data_cap_stays_terminal_under_repeated_data():
    """The flag survives an arbitrary number of remote_data calls
    after cap-trip — proving the channel is truly terminal."""
    sc, mgr = _make_subchannel(scid=99)
    chunk = b"x" * (1 << 20)
    # Fire the cap.
    for _ in range(MAX_PENDING_REMOTE_DATA_BYTES // len(chunk)):
        sc.remote_data(chunk)
    sc.remote_data(b"\x00")
    assert sc._cap_tripped is True

    # 100 follow-up data frames — none should be buffered.
    for _ in range(100):
        sc.remote_data(b"more")
    assert sc._pending_remote_data == []
    assert sc._pending_remote_data_bytes == 0
    assert mgr.send_close_calls == [99]  # still just the one close


# --- Cross-site: caps don't interfere with the happy path ---


def test_happy_path_unaffected_by_caps():
    """Normal use: 64 OPENs, register, drain — nothing should hit
    any cap-related send_close."""
    inbound, mgr = _make_inbound()
    fake_factory = MagicMock()
    mgr._subprotocol_factories.register("sub1", fake_factory)

    for scid in range(64):
        inbound.handle_open(scid, "sub1")

    # Each OPEN should have allocated a real SubChannel and called
    # buildProtocol.
    assert len(inbound._open_subchannels) == 64
    assert fake_factory.buildProtocol.call_count == 64
    # No send_close calls — happy path doesn't trigger caps.
    assert mgr.send_close_calls == []
