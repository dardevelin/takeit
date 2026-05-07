"""
Tests for the takeit sender's pull-producer flow control.

Verifies:
- The protocol registers itself as a (non-streaming) producer on the transport.
- Each `resumeProducing` call advances by one chunk.
- Disk reads happen off the reactor thread (mocked deferToThread proves this).
- `stopProducing` halts further work.
- An out-of-range chunk index errbacks the factory's `done` Deferred.
- After all chunks are sent, the producer is unregistered and the
  connection is closed.
"""
import os
from io import BytesIO

import pytest
from twisted.internet.defer import Deferred
from zope.interface import implementer
from zope.interface.verify import verifyObject
from twisted.internet.interfaces import IPullProducer

from takeit.cli import cli as cli_mod
from takeit.cli import _protocol as P


@implementer(IPullProducer)  # we'll verify this via the protocol's behavior
class _FakeTransport:
    """A pull-producer-aware transport stand-in.

    Records writes; lets the test drive resumeProducing manually rather
    than the reactor doing it. The producer registers itself here; we
    record that and then crank resumeProducing as many times as we need.
    """

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


def _make_factory(path, chunk_size, chunks_to_send):
    return cli_mod._SenderFactory(path, chunk_size, chunks_to_send)


def test_registers_as_pull_producer(tmp_path, monkeypatch):
    src = tmp_path / "f.bin"
    src.write_bytes(b"x" * 100)
    f = _make_factory(str(src), 50, [0, 1])
    proto = cli_mod._SenderProtocol(f)
    transport = _FakeTransport()
    proto.transport = transport
    # Patch deferToThread to run synchronously, returning a fired Deferred,
    # so we don't need a real reactor.
    monkeypatch.setattr(cli_mod, "deferToThread",
                        lambda fn, *a, **kw: _sync_defer(fn, *a, **kw))
    proto.connectionMade()
    assert transport.producer is proto
    # Pull-producer registration: streaming=False
    assert transport.streaming is False


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


def test_resume_producing_advances_one_chunk_at_a_time(tmp_path, monkeypatch):
    src = tmp_path / "f.bin"
    payload = b"".join(bytes([i % 256]) * 50 for i in range(4))
    src.write_bytes(payload)
    f = _make_factory(str(src), 50, [0, 1, 2, 3])
    proto = cli_mod._SenderProtocol(f)
    transport = _FakeTransport()
    proto.transport = transport
    monkeypatch.setattr(cli_mod, "deferToThread",
                        lambda fn, *a, **kw: _sync_defer(fn, *a, **kw))
    proto.connectionMade()

    # Each resumeProducing should produce exactly one frame.
    proto.resumeProducing()
    assert len(transport.writes) == 1
    proto.resumeProducing()
    assert len(transport.writes) == 2
    proto.resumeProducing()
    proto.resumeProducing()
    assert len(transport.writes) == 4

    # One more call: no more chunks, producer should unregister + close.
    proto.resumeProducing()
    assert transport.unregistered
    assert transport.connection_lost
    # done Deferred won't fire until connectionLost is called by transport
    proto.connectionLost(_FakeReason("Connection closed"))
    assert f.done.called


def test_disk_reads_go_through_deferToThread(tmp_path, monkeypatch):
    src = tmp_path / "f.bin"
    src.write_bytes(b"x" * 100)
    f = _make_factory(str(src), 50, [0, 1])
    proto = cli_mod._SenderProtocol(f)
    transport = _FakeTransport()
    proto.transport = transport

    deferToThread_calls = []

    def fake_deferToThread(fn, *args, **kwargs):
        deferToThread_calls.append((fn, args, kwargs))
        return _sync_defer(fn, *args, **kwargs)

    monkeypatch.setattr(cli_mod, "deferToThread", fake_deferToThread)
    proto.connectionMade()
    proto.resumeProducing()

    assert len(deferToThread_calls) == 1
    fn, args, _ = deferToThread_calls[0]
    # The thread-target is _read_chunk(fh, idx, chunk_size)
    assert fn is cli_mod._read_chunk
    assert args[1] == 0  # first chunk index
    assert args[2] == 50  # chunk_size


def test_out_of_range_chunk_errbacks(tmp_path, monkeypatch):
    src = tmp_path / "f.bin"
    src.write_bytes(b"x" * 50)  # only one chunk's worth of data
    f = _make_factory(str(src), 50, [5])  # but we ask for chunk index 5
    proto = cli_mod._SenderProtocol(f)
    transport = _FakeTransport()
    proto.transport = transport
    monkeypatch.setattr(cli_mod, "deferToThread",
                        lambda fn, *a, **kw: _sync_defer(fn, *a, **kw))

    proto.connectionMade()
    proto.resumeProducing()

    # done should have errbacked. We need to add an errback to inspect.
    failures = []
    f.done.addErrback(lambda f_: failures.append(f_))
    assert len(failures) == 1
    assert "past end of file" in str(failures[0].value)
    assert transport.connection_lost


def test_stop_producing_halts_writes(tmp_path, monkeypatch):
    src = tmp_path / "f.bin"
    src.write_bytes(b"x" * 200)
    f = _make_factory(str(src), 50, [0, 1, 2, 3])
    proto = cli_mod._SenderProtocol(f)
    transport = _FakeTransport()
    proto.transport = transport
    monkeypatch.setattr(cli_mod, "deferToThread",
                        lambda fn, *a, **kw: _sync_defer(fn, *a, **kw))
    proto.connectionMade()

    proto.resumeProducing()
    proto.resumeProducing()
    proto.stopProducing()
    # Subsequent resumeProducing should be a no-op
    proto.resumeProducing()
    assert len(transport.writes) == 2  # only the two before stopProducing


def test_only_chunks_to_send_are_sent_in_order(tmp_path, monkeypatch):
    """Resume scenario: we send a non-contiguous, possibly-reordered set."""
    src = tmp_path / "f.bin"
    payload = b"".join(bytes([i]) * 4 for i in range(10))  # 10 chunks of 4 bytes each
    src.write_bytes(payload)
    f = _make_factory(str(src), 4, [3, 7, 1])  # only these three, in this order
    proto = cli_mod._SenderProtocol(f)
    transport = _FakeTransport()
    proto.transport = transport
    monkeypatch.setattr(cli_mod, "deferToThread",
                        lambda fn, *a, **kw: _sync_defer(fn, *a, **kw))

    proto.connectionMade()
    for _ in range(4):  # one extra to trigger the close
        proto.resumeProducing()

    assert len(transport.writes) == 3
    # Decode the frames and check indices are 3, 7, 1 in order
    decoder = P.FrameDecoder()
    indices = []
    for frame in transport.writes:
        for idx, _data in decoder.feed(frame):
            indices.append(idx)
    assert indices == [3, 7, 1]


class _FakeReason:
    def __init__(self, msg):
        self._msg = msg

    def getErrorMessage(self):
        return self._msg
