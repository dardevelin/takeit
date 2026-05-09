"""
HYP-459: receiver-side `_fail()` must close the transport.

Sender's `_fail()` (cli.py:1068) calls `transport.loseConnection()`.
Receiver's `_fail()` (cli.py:1768) didn't — leaving a misbehaving
peer's subchannel alive while we unwind.

This is asymmetry hygiene; the practical impact is bounded because
CLI flow upstream usually closes the transport via process exit.
But per `feedback_symmetric_privacy_filters.md`: every send-side
defense should have a receive-side mirror.
"""

from takeit.cli import cli as cli_mod


class _FakeTransport:
    def __init__(self):
        self.lost = False

    def loseConnection(self):
        self.lost = True


class _FakeFactory:
    """Minimal _ReceiverFactory stand-in for `_fail` tests."""

    def __init__(self):
        from twisted.internet.defer import Deferred

        self.done = Deferred()
        # _ReceiverProtocol __init__ reads these:
        self._offer = {
            "chunk_size": 50,
            "size": 100,
            "_content_hash_bytes": b"\x00" * 32,
            "transfer_id": "AAAAAAAAAAAAAAAAAAAAAA==",
        }
        self._progress = None
        self._partial_path = "/tmp/unused"
        self._meta_path = "/tmp/unused.meta"
        self._prior_matches = False


def _make_proto():
    factory = _FakeFactory()
    proto = cli_mod._ReceiverProtocol(factory)
    proto.transport = _FakeTransport()
    # Don't call connectionMade — `_fail` doesn't depend on it.
    return proto, factory


def test_fail_closes_transport():
    """Pre-fix: receiver `_fail` left the transport open. Post-fix:
    `loseConnection` is called so the misbehaving peer's subchannel
    doesn't stay alive while we unwind."""
    proto, factory = _make_proto()
    factory.done.addErrback(lambda f: None)  # consume errback

    proto._fail(ValueError("test"))

    assert proto.transport.lost, "_fail should have closed the transport"
    assert proto._stopped is True
    assert factory.done.called


def test_fail_idempotent_on_second_call():
    """`_fail` may run more than once if multiple errors race. The
    second call must NOT errback the Deferred again (already-called
    guard works), and must still leave the transport closed."""
    proto, factory = _make_proto()
    factory.done.addErrback(lambda f: None)

    proto._fail(ValueError("first"))
    assert factory.done.called
    pre_lost = proto.transport.lost

    # Second fail — Deferred guard prevents re-errback; transport stays closed.
    proto._fail(ValueError("second"))
    assert proto.transport.lost == pre_lost  # still closed (already was)
