"""
Re-entrancy regression test for Key.compute_key.

Upstream wormhole had two TODOs at `_key.py:201` and `_key.py:210` flagging
that `B.got_key(key)` and `R.got_key(key)` are fired synchronously from
inside the `compute_key` output, and that their downstream firing of
user-level Deferreds could re-enter wormhole APIs and confuse the state
machine. takeit fixes this by routing both calls through the eventual
queue so they run on a fresh reactor turn.

The test pins the fix by asserting that got_key is NOT observable until
the eventual queue is flushed.
"""
from twisted.internet.task import Clock, Cooperator
from zope.interface import implementer

from takeit import _interfaces
from takeit._boss import Boss
from takeit.eventual import EventualQueue

from tests._fake_rendezvous import FakeRendezvous, pair


@implementer(_interfaces.IWormhole)
class _Wormhole:
    def __init__(self):
        self.welcome = None
        self.code = None
        self.key = None
        self.verifier = None
        self.versions = None
        self.messages = []
        self.closed_with = None

    def got_welcome(self, w): self.welcome = w
    def got_code(self, c): self.code = c
    def got_key(self, k): self.key = k
    def got_verifier(self, v): self.verifier = v
    def got_versions(self, vs): self.versions = vs
    def received(self, p): self.messages.append(p)
    def closed(self, r): self.closed_with = r


@implementer(_interfaces.ITiming)
class _Timing:
    def add(self, *a, **kw):
        class _Ctx:
            def __enter__(self_): return self_
            def __exit__(self_, *a): return False
        return _Ctx()


def _build_pair():
    eq = EventualQueue(Clock())
    rv_a = FakeRendezvous("aaaaaa")
    rv_b = FakeRendezvous("bbbbbb")
    pair(rv_a, rv_b)

    def fa(boss, mailbox, terminator):
        rv_a.wire(boss, mailbox, terminator)
        return rv_a

    def fb(boss, mailbox, terminator):
        rv_b.wire(boss, mailbox, terminator)
        return rv_b

    def make(side, factory):
        return Boss(
            wormhole=_Wormhole(),
            side=side,
            appid="takeit/test",
            versions={},
            reactor=Clock(),
            eventual_queue=eq,
            cooperator=Cooperator(scheduler=lambda f: eq.eventually(f)),
            timing=_Timing(),
            rendezvous_factory=factory,
        )
    return eq, make("aaaaaa", fa), make("bbbbbb", fb)


def test_got_key_does_not_fire_synchronously_from_compute_key():
    """If got_key were called synchronously inside compute_key, the user's
    handler could re-enter wormhole APIs while the Key state machine was
    still mid-transition. The fix routes the call through the eventual
    queue: got_key fires only after eq.flush_sync() runs.
    """
    eq, a, b = _build_pair()
    a.start()
    b.start()
    eq.flush_sync()

    a.allocate_code(3)
    eq.flush_sync()
    code = a._wormhole.code
    b.set_code(code)

    # Important: do NOT flush yet. FakeRendezvous delivers messages
    # synchronously, so compute_key has already executed inside b.set_code.
    # If got_key were called synchronously from compute_key, the
    # wormhole.key would already be set. With eventual-queue gating, it
    # must remain None until we flush.
    a_key_synchronous = a._wormhole.key
    b_key_synchronous = b._wormhole.key
    eq.flush_sync()

    # Now both wormholes must have got_key fired.
    assert a._wormhole.key is not None
    assert b._wormhole.key is not None

    # Pin the eventual-queue contract: both got_key calls were deferred,
    # not synchronous. This is what `_key.py:201,210` TODOs warned about
    # before the fix.
    assert a_key_synchronous is None, (
        "Boss._wormhole.got_key fired synchronously from compute_key "
        "(re-entrancy bug): _key.py needs eventual-queue gating")
    assert b_key_synchronous is None, (
        "Boss._wormhole.got_key fired synchronously from compute_key "
        "(re-entrancy bug): _key.py needs eventual-queue gating")
