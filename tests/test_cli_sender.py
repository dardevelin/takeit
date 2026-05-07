"""
Tests for the takeit sender's two-phase subchannel flow (HYP-392).

Phase 1 (header): connectionMade writes the chunk_hashes header; protocol
buffers inbound bytes until the receiver's chunks_have reply arrives.
Phase 2 (stream): pull-producer streams chunk frames.

Verified:
- The sender writes the subchannel header on connection.
- After the chunks_have reply, registers as a non-streaming producer.
- Each `resumeProducing` advances by exactly one chunk.
- Disk reads happen off the reactor thread (mocked deferToThread).
- `stopProducing` halts further work.
- An out-of-range chunk index errbacks the factory's `done`.
- After all chunks are sent, the producer is unregistered and closed.
"""

import hashlib

from twisted.internet.defer import Deferred
from twisted.internet.interfaces import IPullProducer
from zope.interface import implementer

from takeit.cli import _protocol as P
from takeit.cli import cli as cli_mod


@implementer(IPullProducer)  # we'll verify this via the protocol's behavior
class _FakeTransport:
    """A pull-producer-aware transport stand-in."""

    def __init__(self):
        self.writes = []
        self.producer = None
        self.streaming = None
        self.unregistered = False
        self.connection_lost = False

    def registerProducer(self, producer, streaming):
        assert self.producer is None
        self.producer = producer
        self.streaming = streaming

    def unregisterProducer(self):
        self.unregistered = True

    def write(self, data):
        self.writes.append(data)

    def loseConnection(self):
        self.connection_lost = True


class _FakeReason:
    def __init__(self, msg):
        self._msg = msg

    def getErrorMessage(self):
        return self._msg


def _sync_defer(fn, *args, **kwargs):
    """Run fn(*args, **kwargs) synchronously and return a fired Deferred."""
    d = Deferred()
    try:
        result = fn(*args, **kwargs)
    except Exception as e:
        d.errback(e)
    else:
        d.callback(result)
    return d


def _hashes_for(payload, chunk_size):
    """Compute per-chunk BLAKE2b-256 hashes for a byte string."""
    hashes = []
    for i in range(0, len(payload), chunk_size):
        hashes.append(
            hashlib.blake2b(payload[i : i + chunk_size], digest_size=32).digest()
        )
    return hashes


def _make_factory(path, chunk_size, chunk_hashes):
    return cli_mod._SenderFactory(path, chunk_size, chunk_hashes)


def _setup_proto(tmp_path, payload, chunk_size, chunk_hashes, monkeypatch):
    """Build a wired-up sender protocol on a fake transport, with
    deferToThread monkeypatched to run synchronously."""
    src = tmp_path / "f.bin"
    src.write_bytes(payload)
    f = _make_factory(str(src), chunk_size, chunk_hashes)
    proto = cli_mod._SenderProtocol(f)
    transport = _FakeTransport()
    proto.transport = transport
    monkeypatch.setattr(
        cli_mod, "deferToThread", lambda fn, *a, **kw: _sync_defer(fn, *a, **kw)
    )
    proto.connectionMade()
    return proto, transport, f


def _enter_stream_phase(proto, chunks_have):
    """Feed a chunks_have reply into the protocol, transitioning it from
    header phase to stream phase."""
    framed = P.build_chunks_have(chunks_have)
    proto.dataReceived(framed)


def test_connection_made_writes_subchannel_header(tmp_path, monkeypatch):
    """Phase 1: connectionMade writes the length-prefixed chunk_hashes
    header. No producer is registered yet — that happens after the
    receiver's chunks_have reply arrives."""
    payload = b"x" * 100
    chunk_hashes = _hashes_for(payload, 50)
    proto, transport, _f = _setup_proto(
        tmp_path, payload, 50, chunk_hashes, monkeypatch
    )
    # Exactly one write so far: the subchannel header.
    assert len(transport.writes) == 1
    assert transport.producer is None
    # Header round-trips through the LengthPrefixedDecoder + parser.
    decoder = P.LengthPrefixedDecoder()
    bodies = list(decoder.feed(transport.writes[0]))
    assert len(bodies) == 1
    parsed = P.parse_subchannel_header(bodies[0])
    assert parsed == chunk_hashes


def test_registers_as_pull_producer_after_reply(tmp_path, monkeypatch):
    payload = b"x" * 100
    chunk_hashes = _hashes_for(payload, 50)
    proto, transport, _f = _setup_proto(
        tmp_path, payload, 50, chunk_hashes, monkeypatch
    )
    _enter_stream_phase(proto, chunks_have=[])
    assert transport.producer is proto
    assert transport.streaming is False  # pull producer


def test_resume_producing_advances_one_chunk_at_a_time(tmp_path, monkeypatch):
    payload = b"".join(bytes([i % 256]) * 50 for i in range(4))
    chunk_hashes = _hashes_for(payload, 50)
    proto, transport, f = _setup_proto(tmp_path, payload, 50, chunk_hashes, monkeypatch)
    _enter_stream_phase(proto, chunks_have=[])
    # Header write counts as one. Drop it from "frame count" math by
    # tracking the writes after entering stream phase.
    pre_stream_writes = len(transport.writes)

    proto.resumeProducing()
    assert len(transport.writes) - pre_stream_writes == 1
    proto.resumeProducing()
    assert len(transport.writes) - pre_stream_writes == 2
    proto.resumeProducing()
    proto.resumeProducing()
    assert len(transport.writes) - pre_stream_writes == 4

    # One more call: no more chunks, producer should unregister + close.
    proto.resumeProducing()
    assert transport.unregistered
    assert transport.connection_lost
    proto.connectionLost(_FakeReason("Connection closed"))
    assert f.done.called


def test_disk_reads_go_through_deferToThread(tmp_path, monkeypatch):
    payload = b"x" * 100
    chunk_hashes = _hashes_for(payload, 50)
    src = tmp_path / "f.bin"
    src.write_bytes(payload)
    f = _make_factory(str(src), 50, chunk_hashes)
    proto = cli_mod._SenderProtocol(f)
    transport = _FakeTransport()
    proto.transport = transport

    deferToThread_calls = []

    def fake_deferToThread(fn, *args, **kwargs):
        deferToThread_calls.append((fn, args, kwargs))
        return _sync_defer(fn, *args, **kwargs)

    monkeypatch.setattr(cli_mod, "deferToThread", fake_deferToThread)
    proto.connectionMade()
    _enter_stream_phase(proto, chunks_have=[])
    proto.resumeProducing()

    # First call should be _read_chunk for chunk index 0.
    assert len(deferToThread_calls) == 1
    fn, args, _ = deferToThread_calls[0]
    assert fn is cli_mod._read_chunk
    assert args[1] == 0
    assert args[2] == 50


def test_out_of_range_chunk_errbacks(tmp_path, monkeypatch):
    """If the protocol is asked to send a chunk beyond the file's end
    (file shorter than chunk_hashes implies), the factory's done
    Deferred errbacks."""
    payload = b"x" * 50  # only 1 chunk's worth on disk
    # But we hand 6 chunk_hashes — pretend the file should be 6 chunks.
    chunk_hashes = [b"\x00" * 32] * 6
    proto, transport, f = _setup_proto(tmp_path, payload, 50, chunk_hashes, monkeypatch)
    _enter_stream_phase(proto, chunks_have=[0, 1, 2, 3, 4])  # only idx 5 left
    proto.resumeProducing()

    failures = []
    f.done.addErrback(lambda f_: failures.append(f_))
    assert len(failures) == 1
    assert "past end of file" in str(failures[0].value)
    assert transport.connection_lost


def test_stop_producing_halts_writes(tmp_path, monkeypatch):
    payload = b"x" * 200
    chunk_hashes = _hashes_for(payload, 50)
    proto, transport, _f = _setup_proto(
        tmp_path, payload, 50, chunk_hashes, monkeypatch
    )
    _enter_stream_phase(proto, chunks_have=[])
    pre_stream_writes = len(transport.writes)

    proto.resumeProducing()
    proto.resumeProducing()
    proto.stopProducing()
    proto.resumeProducing()  # no-op after stop
    assert len(transport.writes) - pre_stream_writes == 2


def test_resume_skips_chunks_have(tmp_path, monkeypatch):
    """Receiver tells us 'I already have chunks 0 and 2'; we should send
    only chunks 1 and 3."""
    payload = b"".join(bytes([i]) * 4 for i in range(4))
    chunk_hashes = _hashes_for(payload, 4)
    proto, transport, _f = _setup_proto(tmp_path, payload, 4, chunk_hashes, monkeypatch)
    _enter_stream_phase(proto, chunks_have=[0, 2])
    pre_stream_writes = len(transport.writes)

    for _ in range(3):  # 2 chunks + final call to trigger close
        proto.resumeProducing()

    frames = transport.writes[pre_stream_writes:]
    assert len(frames) == 2
    decoder = P.FrameDecoder()
    indices = []
    for frame in frames:
        for idx, _data in decoder.feed(frame):
            indices.append(idx)
    assert indices == [1, 3]


def test_unexpected_data_after_reply_errbacks(tmp_path, monkeypatch):
    """The receiver sends one reply during the header phase; any
    further bytes from them are a protocol error."""
    payload = b"x" * 100
    chunk_hashes = _hashes_for(payload, 50)
    proto, transport, f = _setup_proto(tmp_path, payload, 50, chunk_hashes, monkeypatch)
    _enter_stream_phase(proto, chunks_have=[])
    # Now feed extra bytes — sender should treat this as misbehavior.
    proto.dataReceived(b"unexpected")
    failures = []
    f.done.addErrback(lambda f_: failures.append(f_))
    assert len(failures) == 1
    assert "unexpected bytes" in str(failures[0].value)
