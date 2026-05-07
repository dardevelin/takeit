"""
End-to-end test for Boss: two paired Boss instances complete a real
SPAKE2 handshake over FakeRendezvous and exchange application messages.

This is the integration test that proves the takeit wire graph is correct.
If it passes, every state machine is wired right and outputs fire in the
expected order during a real protocol exchange.
"""

import pytest
from twisted.internet.task import Clock, Cooperator
from zope.interface import implementer

from takeit import _interfaces
from takeit._boss import Boss
from takeit.eventual import EventualQueue
from tests._fake_rendezvous import FakeRendezvous, pair


@implementer(_interfaces.IWormhole)
class WormholeSpy:
    """A test double for the public delegate user code would see."""

    def __init__(self):
        self.welcome = None
        self.code = None
        self.key = None
        self.verifier = None
        self.versions = None
        self.messages = []
        self.closed_with = None

    def got_welcome(self, welcome):
        self.welcome = welcome

    def got_code(self, code):
        self.code = code

    def got_key(self, key):
        self.key = key

    def got_verifier(self, verifier):
        self.verifier = verifier

    def got_versions(self, versions):
        self.versions = versions

    def received(self, plaintext):
        self.messages.append(plaintext)

    def closed(self, result):
        self.closed_with = result


def _new_clock():
    """Twisted's Clock implements IReactorTime, sufficient for Boss/Dilator
    instantiation in the absence of a real reactor."""
    return Clock()


@implementer(_interfaces.ITiming)
class _FakeTiming:
    def add(self, *a, **kw):
        class _Ctx:
            def __enter__(self_):
                return self_

            def __exit__(self_, *a):
                return False

        return _Ctx()


def _make_boss(side, eq, rendezvous_factory, wormhole=None):
    return Boss(
        wormhole=wormhole or WormholeSpy(),
        side=side,
        appid="takeit/test",
        versions={},
        reactor=_new_clock(),
        eventual_queue=eq,
        cooperator=Cooperator(scheduler=lambda f: eq.eventually(f)),
        timing=_FakeTiming(),
        rendezvous_factory=rendezvous_factory,
    )


def _flush(eq):
    eq.flush_sync()


def _make_paired_bosses():
    """Build two paired Boss instances ready for set_code/allocate_code."""
    eq = EventualQueue(_new_clock())
    rv_a = FakeRendezvous("aaaa")
    rv_b = FakeRendezvous("bbbb")
    pair(rv_a, rv_b)

    def factory_a(boss, mailbox, terminator):
        rv_a.wire(boss, mailbox, terminator)
        return rv_a

    def factory_b(boss, mailbox, terminator):
        rv_b.wire(boss, mailbox, terminator)
        return rv_b

    boss_a = _make_boss("aaaa", eq, factory_a)
    boss_b = _make_boss("bbbb", eq, factory_b)
    return eq, boss_a, boss_b, rv_a, rv_b


def test_boss_constructs_with_factory():
    """The factory pattern injects the rendezvous without Boss knowing
    about Nostr."""
    eq = EventualQueue(_new_clock())

    def factory(boss, mailbox, terminator):
        rv = FakeRendezvous("aaaa")
        rv.wire(boss, mailbox, terminator)
        return rv

    boss = _make_boss("aaaa", eq, factory)
    assert boss is not None


def test_full_handshake_and_message_exchange():
    """Golden path: A allocates, B set_codes the same code, both connect,
    SPAKE2 runs, app messages flow both ways, both close happy."""
    eq, boss_a, boss_b, _, _ = _make_paired_bosses()

    boss_a.start()
    boss_b.start()
    _flush(eq)

    # A: allocate a fresh code; both sides set_code with the same one.
    boss_a.allocate_code(3)
    _flush(eq)
    code = boss_a._wormhole.code
    assert code is not None
    assert code.count("-") == 2  # 3 words

    boss_b.set_code(code)
    _flush(eq)

    # SPAKE2 should now have run; both sides have the same key.
    assert boss_a._wormhole.key is not None
    assert boss_b._wormhole.key is not None
    assert boss_a._wormhole.key == boss_b._wormhole.key

    # The "versions" message follows automatically.
    assert boss_a._wormhole.versions == {}
    assert boss_b._wormhole.versions == {}

    # Both sides should be in S2_happy now and can exchange app messages.
    boss_a.send(b"hello from a")
    boss_b.send(b"hello from b")
    _flush(eq)

    assert b"hello from a" in boss_b._wormhole.messages
    assert b"hello from b" in boss_a._wormhole.messages

    # Close both sides happily
    boss_a.close()
    boss_b.close()
    _flush(eq)

    assert boss_a._wormhole.closed_with == "happy"
    assert boss_b._wormhole.closed_with == "happy"


def test_close_before_peer_arrives_is_lonely():
    """Closing while still in S0_empty (no got_code) yields 'lonely'."""
    eq, boss_a, _, _, _ = _make_paired_bosses()
    boss_a.start()
    _flush(eq)
    boss_a.close()
    _flush(eq)
    from takeit.errors import LonelyError

    assert isinstance(boss_a._wormhole.closed_with, LonelyError)


def test_set_code_twice_raises():
    eq, boss_a, _, _, _ = _make_paired_bosses()
    boss_a.start()
    _flush(eq)
    boss_a.set_code("purple-sausages-mocha")
    from takeit.errors import OnlyOneCodeError

    with pytest.raises(OnlyOneCodeError):
        boss_a.set_code("yarn-loafer-stockman")


def test_invalid_code_format_raises():
    eq, boss_a, _, _, _ = _make_paired_bosses()
    boss_a.start()
    _flush(eq)
    from takeit.errors import KeyFormatError

    with pytest.raises(KeyFormatError):
        boss_a.set_code("bad code with spaces")


def test_status_progresses_through_handshake():
    """Boss should fire on_status_update at AllegedSharedKey then
    ConfirmedKey as the handshake progresses."""
    eq = EventualQueue(_new_clock())
    rv_a = FakeRendezvous("aaaa")
    rv_b = FakeRendezvous("bbbb")
    pair(rv_a, rv_b)

    def factory_a(boss, mailbox, terminator):
        rv_a.wire(boss, mailbox, terminator)
        return rv_a

    def factory_b(boss, mailbox, terminator):
        rv_b.wire(boss, mailbox, terminator)
        return rv_b

    statuses = []
    boss_a = Boss(
        wormhole=WormholeSpy(),
        side="aaaa",
        appid="takeit/test",
        versions={},
        reactor=_new_clock(),
        eventual_queue=eq,
        cooperator=Cooperator(scheduler=lambda f: eq.eventually(f)),
        timing=_FakeTiming(),
        rendezvous_factory=factory_a,
        on_status_update=lambda s: statuses.append(s),
    )
    boss_b = _make_boss("bbbb", eq, factory_b)

    boss_a.start()
    boss_b.start()
    boss_a.allocate_code(3)
    _flush(eq)
    boss_b.set_code(boss_a._wormhole.code)
    _flush(eq)

    # Confirm we saw both the alleged-key and confirmed-key statuses.
    from takeit._status import AllegedSharedKey, ConfirmedKey

    peer_keys = [s.peer_key for s in statuses if s.peer_key is not None]
    assert any(isinstance(k, AllegedSharedKey) for k in peer_keys)
    assert any(isinstance(k, ConfirmedKey) for k in peer_keys)
