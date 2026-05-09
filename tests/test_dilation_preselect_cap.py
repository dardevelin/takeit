"""
HYP-460: cap the pre-select inbound record queue.

Connector.consider takes an eventual-turn to decide whether to accept
a candidate connection (.select()). During that turn, every inbound
record arriving on the candidate appends to _inbound_record_queue.
Without a cap, an authenticated peer can pack KCM + arbitrary records
into one TCP turn and grow memory.

Fix: count + byte cap, terminal flag (mirror HYP-457). Excess records
trigger transport.loseConnection() and subsequent records drop.
"""

from unittest.mock import MagicMock

from twisted.internet.interfaces import ITransport
from zope.interface import implementer

from takeit._dilation.connection import (
    MAX_PRESELECT_RECORD_BYTES,
    MAX_PRESELECT_RECORDS,
    Data,
    DilatedConnectionProtocol,
    Open,
)
from takeit._interfaces import IDilationConnector


@implementer(IDilationConnector)
class _FakeConnector:
    """Minimum surface for the DilatedConnectionProtocol attrs validator."""

    def __getattr__(self, _name):
        return lambda *a, **kw: None


@implementer(ITransport)
class _FakeTransport:
    def __init__(self):
        self.writes = []
        self.lost = False

    def write(self, data):
        self.writes.append(data)

    def writeSequence(self, data):
        for chunk in data:
            self.writes.append(chunk)

    def loseConnection(self):
        self.lost = True

    def getPeer(self):
        return None

    def getHost(self):
        return None


def _make_protocol():
    """Build a DilatedConnectionProtocol in the `selecting` state so
    `got_record` dispatches to `queue_inbound_record`. Per
    `feedback_automat_output_not_callable.md`, we can't call the @m.output
    directly — we have to drive the @m.input that triggers it.

    Path: unselected --got_kcm--> selecting --got_record--> queue_inbound_record.
    """
    eq = MagicMock()
    proto = DilatedConnectionProtocol(
        eventual_queue=eq,
        role="leader",
        description="test",
        connector=_FakeConnector(),
        noise=MagicMock(),
        outbound_prologue=b"",
        inbound_prologue=b"",
    )
    proto.transport = _FakeTransport()
    # Move to `selecting` state so subsequent `got_record` calls fire
    # the cap-checked queue_inbound_record output.
    proto.got_kcm()
    return proto


def _open_record(scid):
    """An Open record (control-class, ~no bytes from cap perspective)."""
    return Open(seqnum=0, scid=scid, subprotocol="sub1")


def _data_record(payload):
    """A Data record carries a payload counted against the byte cap."""
    return Data(seqnum=0, scid=1, data=payload)


# --- count cap ---


def test_preselect_count_cap_under_limit_queues():
    """Negative control: 64 records queue cleanly."""
    proto = _make_protocol()
    for i in range(MAX_PRESELECT_RECORDS):
        proto.got_record(_open_record(scid=i))
    assert len(proto._inbound_record_queue) == MAX_PRESELECT_RECORDS
    assert proto.transport.lost is False
    assert proto._preselect_cap_tripped is False


def test_preselect_count_cap_at_limit_closes_connection():
    """The (N+1)th record fires the cap, closes the transport."""
    proto = _make_protocol()
    for i in range(MAX_PRESELECT_RECORDS):
        proto.got_record(_open_record(scid=i))
    proto.got_record(_open_record(scid=999))
    assert proto.transport.lost is True
    assert proto._preselect_cap_tripped is True
    # Overflow record was NOT appended.
    assert len(proto._inbound_record_queue) == MAX_PRESELECT_RECORDS


def test_preselect_count_cap_constant_pinned():
    """Cap is exactly 64."""
    assert MAX_PRESELECT_RECORDS == 64


# --- byte cap ---


def test_preselect_byte_cap_under_limit_queues():
    """Negative control: under-cap bytes accumulate, no close."""
    proto = _make_protocol()
    chunk = b"x" * (256 * 1024)  # 256 KiB each
    # 3 chunks = 768 KiB, under 1 MiB cap
    for _ in range(3):
        proto.got_record(_data_record(chunk))
    assert proto._preselect_byte_total == 3 * len(chunk)
    assert proto.transport.lost is False


def test_preselect_byte_cap_at_limit_closes():
    """Tipping past 1 MiB byte cap fires close."""
    proto = _make_protocol()
    chunk = b"x" * (256 * 1024)  # 256 KiB
    # Push to exactly 1 MiB (4 chunks)
    for _ in range(MAX_PRESELECT_RECORD_BYTES // len(chunk)):
        proto.got_record(_data_record(chunk))
    pre_lost = proto.transport.lost
    assert pre_lost is False, "should still be under cap"

    # One more chunk pushes past — fires.
    proto.got_record(_data_record(chunk))
    assert proto.transport.lost is True
    assert proto._preselect_cap_tripped is True


def test_preselect_byte_cap_constant_pinned():
    """Cap is exactly 1 MiB."""
    assert MAX_PRESELECT_RECORD_BYTES == 1 << 20


# --- terminal behavior (HYP-457 lesson applied) ---


def test_preselect_cap_is_terminal():
    """Per `feedback_caps_must_be_terminal.md`: once tripped, the cap
    must drop further records, not re-arm."""
    proto = _make_protocol()
    # Trip the count cap
    for i in range(MAX_PRESELECT_RECORDS + 1):
        proto.got_record(_open_record(scid=i))
    assert proto._preselect_cap_tripped is True
    pre_trip_len = len(proto._inbound_record_queue)
    pre_trip_bytes = proto._preselect_byte_total

    # 100 follow-up records — none should grow queue or counter.
    for _ in range(100):
        proto.got_record(_data_record(b"more"))
    assert len(proto._inbound_record_queue) == pre_trip_len, (
        "post-trip records must not be queued"
    )
    assert proto._preselect_byte_total == pre_trip_bytes, (
        "byte counter must not grow after cap-trip"
    )
    # And only ONE close — not chatty.
    # (We don't track close-count on the fake; testing transport.lost
    # stays True is sufficient for the protocol contract.)
    assert proto.transport.lost is True


def test_preselect_byte_cap_stays_terminal():
    """Symmetric of the count-cap terminal test, for the byte path."""
    proto = _make_protocol()
    chunk = b"x" * (1 << 20)  # exactly 1 MiB
    proto.got_record(_data_record(chunk))  # at cap (=, not >)
    proto.got_record(_data_record(b"\x00"))  # tips past cap
    assert proto._preselect_cap_tripped is True

    # Many follow-ups — all dropped.
    for _ in range(50):
        proto.got_record(_data_record(b"hello"))
    assert proto._preselect_byte_total == len(chunk), (
        "post-cap-trip bytes must not accumulate"
    )
