"""
HYP-440: cap outbound queue at MAX_UNACKED_BYTES + ACK heartbeat watchdog.

Threat model: an authenticated peer (passed SPAKE2) reads chunks but
withholds ACKs. Under upstream wormhole's Outbound, _outbound_queue
grows linearly with bytes-sent until ACKed -- 10 GiB transfer = 10 GiB
resident on the sender. takeit's dilation-default architecture
inherits this.

The cap (~16 MiB) bounds memory regardless of peer behavior. The
watchdog severs the connection if the peer goes silent for too long.
Legitimate slow peers see TCP-level backpressure first, then queue-cap
backpressure -- never a false-positive abort.

Tests drive Outbound directly via a fake Manager + fake Connection.
"""

from twisted.internet.task import Clock
from zope.interface import implementer

from takeit._dilation.connection import Close, Data, Open
from takeit._dilation.outbound import (
    MAX_UNACKED_BYTES,
    NO_ACK_TIMEOUT_SECONDS,
    Outbound,
)
from takeit._interfaces import IDilationManager


@implementer(IDilationManager)
class _FakeManager:
    """Minimum-viable IDilationManager so Outbound's `_manager` attrib
    validator passes. Outbound only calls back into the manager for
    one path -- peer_stopped_acking on watchdog fire."""

    def __init__(self, reactor):
        self._reactor = reactor
        self.peer_stopped_acking_called = False

    def peer_stopped_acking(self):
        self.peer_stopped_acking_called = True

    # IDilationManager surface that Outbound doesn't actually call;
    # implement the rest as no-ops just to satisfy provides() if it
    # checks coarsely.
    def __getattr__(self, _name):
        return lambda *a, **kw: None


class _FakeConnection:
    """A connection stub that captures sent records without doing
    any real wire work."""

    def __init__(self):
        self.transport = _FakeTransport()
        self.sent = []

    def send_record(self, r):
        self.sent.append(r)


class _FakeTransport:
    def __init__(self):
        self.producer = None
        self.streaming = None

    def registerProducer(self, producer, streaming):
        self.producer = producer
        self.streaming = streaming

    def unregisterProducer(self):
        self.producer = None


def _make_outbound(reactor):
    """Construct an Outbound with a fake manager + dummy cooperator.

    The Cooperator is only used by PullToPush wrappers, which we
    don't exercise in these tests."""
    mgr = _FakeManager(reactor)
    # `attrs` strips the leading underscore from constructor kwargs;
    # _manager / _cooperator / _reactor become manager / cooperator /
    # reactor in __init__.
    out = Outbound(mgr, cooperator=None, reactor=reactor)
    conn = _FakeConnection()
    out.use_connection(conn)
    return out, mgr, conn


def _data_record(seqnum, scid, payload_bytes):
    return Data(seqnum=seqnum, scid=scid, data=payload_bytes)


# --- HYP-440: outbound queue is byte-bounded ---


def test_max_unacked_bytes_constant_is_reasonable():
    """The cap is the load-bearing memory bound. 16 MiB is the takeit
    default: high enough that legitimate transfers over fast LANs
    aren't artificially throttled, low enough that worst-case
    sender memory is hard-bounded."""
    assert MAX_UNACKED_BYTES == 16 << 20  # 16 MiB


def test_no_ack_timeout_constant_is_reasonable():
    """60 seconds is generous enough that TCP pauses + slow links
    don't trip false positives, tight enough that an actively
    abusive peer is severed promptly."""
    assert NO_ACK_TIMEOUT_SECONDS == 60.0


def test_outbound_queue_byte_count_starts_at_zero():
    reactor = Clock()
    out, _mgr, _conn = _make_outbound(reactor)
    assert out.unacked_bytes() == 0


def test_outbound_queue_byte_count_grows_with_data_records():
    reactor = Clock()
    out, _mgr, _conn = _make_outbound(reactor)
    out.queue_and_send_record(_data_record(0, 1, b"x" * 1000))
    assert out.unacked_bytes() == 1000
    out.queue_and_send_record(_data_record(1, 1, b"y" * 2500))
    assert out.unacked_bytes() == 3500


def test_outbound_queue_byte_count_shrinks_on_ack():
    reactor = Clock()
    out, _mgr, _conn = _make_outbound(reactor)
    out.queue_and_send_record(_data_record(0, 1, b"x" * 1000))
    out.queue_and_send_record(_data_record(1, 1, b"y" * 2500))
    assert out.unacked_bytes() == 3500
    out.handle_ack(0)  # retire seqnum 0 only
    assert out.unacked_bytes() == 2500
    out.handle_ack(1)
    assert out.unacked_bytes() == 0


def test_outbound_pauses_producers_when_cap_exceeded():
    """When _outbound_queue size in bytes exceeds MAX_UNACKED_BYTES,
    Outbound calls pauseProducing on itself so upstream producers
    stop generating new records. This is the core memory-bound
    defense: a malicious peer can't grow the queue past the cap
    no matter how long they withhold ACKs."""
    reactor = Clock()
    out, _mgr, _conn = _make_outbound(reactor)
    # Outbound starts paused (it pauses until use_connection's
    # resumeProducing fires). Force it to the unpaused state so the
    # cap-induced pause is observable as a state change.
    out.resumeProducing()
    assert not out._paused

    # Send records totaling exactly MAX_UNACKED_BYTES. Cap not yet
    # exceeded; producer remains active.
    half = MAX_UNACKED_BYTES // 2
    out.queue_and_send_record(_data_record(0, 1, b"x" * half))
    assert not out._paused
    out.queue_and_send_record(_data_record(1, 1, b"y" * half))
    # We've hit but not exceeded the cap; either pause-now or
    # pause-on-next-record is acceptable. Document the behavior:
    # we pause at OR exceeding the cap to be defensive.
    if out._paused:
        cap_paused_already = True
    else:
        # Send one more byte to push us strictly over.
        out.queue_and_send_record(_data_record(2, 1, b"z"))
        cap_paused_already = False
    assert out._paused, (
        "Outbound must pause when _outbound_queue byte count meets "
        "or exceeds MAX_UNACKED_BYTES"
    )
    # And remain paused until ACKs drain past the low-water mark.
    _ = cap_paused_already


def test_outbound_resumes_producers_when_cap_drains():
    """After the cap pauses producers, an inbound ACK that drops the
    queue below the low-water threshold MUST resume them. Without
    this, a single cap hit would freeze the transfer permanently."""
    reactor = Clock()
    out, _mgr, _conn = _make_outbound(reactor)
    out.resumeProducing()
    # Push past the cap.
    chunk = b"x" * (MAX_UNACKED_BYTES // 2 + 1)
    out.queue_and_send_record(_data_record(0, 1, chunk))
    out.queue_and_send_record(_data_record(1, 1, chunk))
    assert out._paused, "expected cap-induced pause"
    # ACK both records. Queue drains to 0 < low-water; producer resumes.
    out.handle_ack(1)
    assert not out._paused, (
        "expected ACK that drained the queue past low-water to resume producers"
    )


# --- HYP-440: ACK heartbeat watchdog ---


def test_ack_watchdog_fires_when_unacked_bytes_persist():
    """If the queue is non-empty for NO_ACK_TIMEOUT_SECONDS without a
    single retiring ACK, Outbound calls manager.peer_stopped_acking()
    so the connection can be torn down and the user gets a clear
    'peer stopped acknowledging' error.

    Legitimate slow ACKs reset the watchdog -- only true ACK-silence
    fires it."""
    reactor = Clock()
    out, mgr, _conn = _make_outbound(reactor)
    # Send a record. Watchdog arms.
    out.queue_and_send_record(_data_record(0, 1, b"hello"))
    assert not mgr.peer_stopped_acking_called
    # Almost timeout; not yet.
    reactor.advance(NO_ACK_TIMEOUT_SECONDS - 0.1)
    assert not mgr.peer_stopped_acking_called
    # Cross the threshold.
    reactor.advance(0.2)
    assert mgr.peer_stopped_acking_called


def test_ack_watchdog_resets_on_each_ack():
    """An ACK that retires a record resets the watchdog timer to a
    fresh NO_ACK_TIMEOUT_SECONDS window. A peer ACKing every 59s
    can hold the connection open indefinitely -- that's the
    expected upper bound on adversarial stretching, well-bounded
    against the cap that limits worst-case memory."""
    reactor = Clock()
    out, mgr, _conn = _make_outbound(reactor)
    out.queue_and_send_record(_data_record(0, 1, b"hello"))
    reactor.advance(NO_ACK_TIMEOUT_SECONDS - 0.5)
    out.handle_ack(0)  # retire; watchdog resets
    out.queue_and_send_record(_data_record(1, 1, b"world"))
    reactor.advance(NO_ACK_TIMEOUT_SECONDS - 0.5)
    # Total elapsed wall time is ~2*timeout, but the second window
    # restarted from the ack -- so we have NOT crossed.
    assert not mgr.peer_stopped_acking_called
    reactor.advance(1.0)
    assert mgr.peer_stopped_acking_called


def test_ack_watchdog_inactive_when_queue_empty():
    """No unacked records -> no watchdog. A fully-idle connection
    must not trip the timer (we're not sending pings here, and
    pings have their own separate keepalive)."""
    reactor = Clock()
    out, mgr, _conn = _make_outbound(reactor)
    # Never send anything. Advance well past the timeout.
    reactor.advance(NO_ACK_TIMEOUT_SECONDS * 5)
    assert not mgr.peer_stopped_acking_called


def test_ack_watchdog_inactive_after_full_drain():
    """All records ACKed -> queue empty -> no live watchdog. The next
    record send re-arms it from a fresh start."""
    reactor = Clock()
    out, mgr, _conn = _make_outbound(reactor)
    out.queue_and_send_record(_data_record(0, 1, b"hello"))
    out.handle_ack(0)
    reactor.advance(NO_ACK_TIMEOUT_SECONDS * 5)
    assert not mgr.peer_stopped_acking_called


# --- non-Data records don't count against the cap ---


def test_non_data_records_do_not_count_against_cap():
    """Open / Close / Ack / KCM / Ping / Pong are tiny protocol
    records, not user payload. Counting them against the cap would
    confuse the abstraction -- the cap exists to bound user data,
    not protocol overhead."""
    reactor = Clock()
    out, _mgr, _conn = _make_outbound(reactor)
    out.queue_and_send_record(Open(seqnum=0, scid=1, subprotocol="x"))
    assert out.unacked_bytes() == 0
    out.queue_and_send_record(Close(seqnum=1, scid=1))
    assert out.unacked_bytes() == 0
    out.queue_and_send_record(_data_record(2, 1, b"real"))
    assert out.unacked_bytes() == 4
