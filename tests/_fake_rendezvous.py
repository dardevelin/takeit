"""
Synchronous in-memory IRendezvous for state-machine and integration tests.

Two FakeRendezvous instances can be paired with `pair(a, b)` so that events
published on one are delivered as `rx_message` on the other (and vice versa),
modelling two takeit clients meeting on a Nostr relay without any actual
network. All deliveries are synchronous — no reactor, no Deferreds.

The fake reads its own `side` from `boss._side` during wire(), so the side
seen at the rendezvous layer always matches the side embedded in SPAKE2
payloads. Tests do not pass `side` to the constructor.
"""

from zope.interface import implementer

from takeit import _interfaces


@implementer(_interfaces.IRendezvousConnector)
class FakeRendezvous:
    """A test double for IRendezvous.

    Implements the *outbound* surface (start/stop/tx_open/tx_add/tx_close)
    and exposes the wired Boss/Mailbox/Terminator so tests can drive
    rx_message, rx_closed, connection events, etc. directly. Pairing two
    FakeRendezvous instances bridges their tx/rx so they exchange events.
    """

    def __init__(self, side=None):
        # Tests may pass `side=` for fake Bosses that lack a real `_side`
        # attribute (e.g. contract tests). When wired to a real Boss, the
        # boss's actual side is preferred so that values seen at the
        # rendezvous layer match those embedded in SPAKE2 payloads.
        self.side = side
        self._peer = None
        self._tag = None
        self._started = False
        self._stopped = False
        self._connected = False
        self._subscribed_tag = None

        # Wired-in peers (filled by .wire())
        self._B = None
        self._M = None
        self._T = None

        # Recorded outbound traffic (for assertions)
        self.opened = []  # list[tag]
        self.added = []  # list[(phase, body)]
        self.closed = []  # list[(tag, mood)]

    # ---- IRendezvous outbound surface ----

    def wire(self, boss, mailbox, terminator):
        self._B = _interfaces.IBoss(boss)
        self._M = _interfaces.IMailbox(mailbox)
        self._T = _interfaces.ITerminator(terminator)
        # Read the boss's side so any rx_message we deliver carries the
        # actual side embedded in SPAKE2 payloads. Falls back to the
        # constructor-supplied side for fake Bosses that lack `_side`.
        boss_side = getattr(boss, "_side", None)
        if boss_side is not None:
            self.side = boss_side

    def start(self):
        assert not self._started, "start() called twice"
        self._started = True
        self._connected = True
        # Synthesize a welcome to mirror upstream's behavior.
        self._B.rx_welcome({})
        self._M.connected()

    def stop(self):
        assert self._started, "stop() before start()"
        if self._connected:
            self._connected = False
            self._M.lost()
        self._stopped = True
        self._T.stoppedRC()

    def tx_open(self, tag):
        assert self._connected, "tx_open while disconnected"
        self.opened.append(tag)
        self._subscribed_tag = tag

    def tx_add(self, phase, body):
        assert self._connected, "tx_add while disconnected"
        assert self._subscribed_tag, "tx_add before tx_open"
        self.added.append((phase, body))
        # Echo to ourselves (relays do this) and forward to peer if paired.
        self._M.rx_message(self.side, phase, body)
        if self._peer and self._peer._subscribed_tag == self._subscribed_tag:
            self._peer._M.rx_message(self.side, phase, body)

    def tx_close(self, tag, mood):
        assert self._connected, "tx_close while disconnected"
        self.closed.append((tag, mood))
        # Nostr has no close ack; synthesize one immediately.
        self._M.rx_closed()

    # ---- Test affordances ----

    def drop_connection(self):
        """Simulate the relay dropping us."""
        assert self._connected
        self._connected = False
        self._subscribed_tag = None
        self._M.lost()

    def restore_connection(self):
        """Simulate the relay coming back."""
        assert not self._connected
        self._connected = True
        self._M.connected()


def pair(a: FakeRendezvous, b: FakeRendezvous) -> None:
    """Wire two FakeRendezvous so they deliver each other's tx_add events.

    They will only deliver when both have called tx_open with the same tag.
    """
    a._peer = b
    b._peer = a
