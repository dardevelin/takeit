from attr import attrib, attrs
from attr.validators import instance_of
from automat import MethodicalMachine
from zope.interface import implementer

from . import _interfaces


@attrs
@implementer(_interfaces.IMailbox)
class Mailbox:
    """
    Drives publish/subscribe over IRendezvous keyed by a takeit tag.

    Compared to upstream wormhole's Mailbox, the state shape is unchanged:
    the A/B suffix tracks rendezvous-connection state, which is real on
    Nostr because relays can drop. What is gone is the nameplate-claim
    round-trip — the tag is derived synchronously from the code, so
    `got_tag` only records the tag and (if connected) immediately
    subscribes. There is no Nameplate state machine to inform on
    peer-message receipt.
    """

    # Cap on the number of distinct peer phases we'll redrain on. The
    # legitimate set is small (`pake`, `version`, plus a handful of app
    # phases over the wormhole-control channel), so 64 is generous. A
    # malicious peer flooding distinct phase strings to amplify our PoW-
    # mined outbound is bounded to MAX_PROCESSED_PHASES redrains per
    # session regardless of how many events they post.
    MAX_PROCESSED_PHASES = 64

    _side = attrib(validator=instance_of(str))
    m = MethodicalMachine()
    set_trace = getattr(m, "_setTrace", lambda self, f: None)  # pragma: no cover

    def __attrs_post_init__(self):
        self._tag = None
        self._mood = None
        self._pending_outbound = {}
        self._processed = set()

    def wire(self, rendezvous_connector, ordering, terminator):
        self._RC = _interfaces.IRendezvousConnector(rendezvous_connector)
        self._O = _interfaces.IOrder(ordering)
        self._T = _interfaces.ITerminator(terminator)

    # all -A states: not connected
    # all -B states: yes connected

    # S0: know nothing
    @m.state(initial=True)
    def S0A(self):
        pass  # pragma: no cover

    @m.state()
    def S0B(self):
        pass  # pragma: no cover

    # S1: tag known, not yet subscribed (we lack a connection)
    @m.state()
    def S1A(self):
        pass  # pragma: no cover

    # S2: tag known, subscription requested. Subscribe must be re-sent each
    # connection because Nostr subscriptions don't survive a relay reconnect.
    @m.state()
    def S2A(self):
        pass  # pragma: no cover

    @m.state()
    def S2B(self):
        pass  # pragma: no cover

    # S3: closing
    @m.state()
    def S3A(self):
        pass  # pragma: no cover

    @m.state()
    def S3B(self):
        pass  # pragma: no cover

    # S4: closed (we no longer care about connection state)
    @m.state(terminal=True)
    def S4(self):
        pass  # pragma: no cover

    S4A = S4
    S4B = S4

    # from Terminator
    @m.input()
    def close(self, mood):
        pass

    # from Boss / Code (was got_mailbox in upstream)
    @m.input()
    def got_tag(self, tag):
        pass

    # from RendezvousConnector
    @m.input()
    def connected(self):
        pass

    @m.input()
    def lost(self):
        pass

    def rx_message(self, side, phase, body):
        assert isinstance(side, str), type(side)
        assert isinstance(phase, str), type(phase)
        assert isinstance(body, bytes), type(body)
        if side == self._side:
            self.rx_message_ours(phase, body)
        else:
            self.rx_message_theirs(side, phase, body)

    @m.input()
    def rx_message_ours(self, phase, body):
        pass

    @m.input()
    def rx_message_theirs(self, side, phase, body):
        pass

    @m.input()
    def rx_closed(self):
        pass

    # from Send or Key
    @m.input()
    def add_message(self, phase, body):
        pass

    @m.output()
    def record_tag(self, tag):
        self._tag = tag

    @m.output()
    def RC_tx_open(self):
        assert self._tag
        self._RC.tx_open(self._tag)

    @m.output()
    def queue(self, phase, body):
        assert isinstance(phase, str), type(phase)
        assert isinstance(body, bytes), (type(body), phase, body)
        self._pending_outbound[phase] = body

    @m.output()
    def record_tag_and_RC_tx_open_and_drain(self, tag):
        self._tag = tag
        self._RC.tx_open(tag)
        self._drain()

    @m.output()
    def drain(self):
        self._drain()

    def _drain(self):
        for phase, body in self._pending_outbound.items():
            self._RC.tx_add(phase, body)

    @m.output()
    def RC_tx_add(self, phase, body):
        assert isinstance(phase, str), type(phase)
        assert isinstance(body, bytes), type(body)
        self._RC.tx_add(phase, body)

    @m.output()
    def accept_peer_message_and_redrain(self, side, phase, body):
        # On Nostr the relay does not buffer ephemeral events — if a peer
        # subscribes after we publish, they never see our message. So when
        # we *first* hear from the peer (one event per phase), we redrain
        # the outbound queue so any of our pending messages get a fresh
        # chance to land while the peer is demonstrably subscribed.
        # Subsequent duplicates of the same peer phase are ignored by the
        # `_processed` dedup, which also stops the redrain feedback loop.
        # Cap `_processed` so a malicious peer flooding distinct phases
        # cannot grow our memory or amplify our PoW-mined outbound past
        # MAX_PROCESSED_PHASES redrains per session. Past the cap we still
        # forward unseen messages to Order (they're legitimate-looking),
        # but we do NOT redrain or grow `_processed`.
        if len(self._processed) >= self.MAX_PROCESSED_PHASES:
            if phase not in self._processed:
                self._O.got_message(side, phase, body)
            return
        if phase not in self._processed:
            self._processed.add(phase)
            self._drain()
            self._O.got_message(side, phase, body)

    @m.output()
    def RC_tx_close(self):
        assert self._mood
        self._RC_tx_close()

    def _RC_tx_close(self):
        self._RC.tx_close(self._tag, self._mood)

    @m.output()
    def noop_on_self_echo(self, phase, body):
        # Upstream wormhole dequeued our outbound on rx_message_ours
        # (relay echo) because the mailbox server's queue would keep
        # delivering our message to the peer until the peer reads it.
        # Nostr relays don't queue ephemeral events, so we must keep our
        # outbound around in case the peer subscribes after we publish.
        # `redrain_on_peer` will re-publish on the next peer event.
        pass

    @m.output()
    def record_mood(self, mood):
        self._mood = mood

    @m.output()
    def record_mood_and_RC_tx_close(self, mood):
        self._mood = mood
        self._RC_tx_close()

    @m.output()
    def ignore_mood_and_T_mailbox_done(self, mood):
        self._T.mailbox_done()

    @m.output()
    def T_mailbox_done(self):
        self._T.mailbox_done()

    S0A.upon(connected, enter=S0B, outputs=[])
    S0A.upon(got_tag, enter=S1A, outputs=[record_tag])
    S0A.upon(add_message, enter=S0A, outputs=[queue])
    S0A.upon(close, enter=S4A, outputs=[ignore_mood_and_T_mailbox_done])
    S0B.upon(lost, enter=S0A, outputs=[])
    S0B.upon(add_message, enter=S0B, outputs=[queue])
    S0B.upon(close, enter=S4B, outputs=[ignore_mood_and_T_mailbox_done])
    S0B.upon(got_tag, enter=S2B, outputs=[record_tag_and_RC_tx_open_and_drain])

    S1A.upon(connected, enter=S2B, outputs=[RC_tx_open, drain])
    S1A.upon(add_message, enter=S1A, outputs=[queue])
    S1A.upon(close, enter=S4A, outputs=[ignore_mood_and_T_mailbox_done])

    S2A.upon(connected, enter=S2B, outputs=[RC_tx_open, drain])
    S2A.upon(add_message, enter=S2A, outputs=[queue])
    S2A.upon(close, enter=S3A, outputs=[record_mood])
    S2B.upon(lost, enter=S2A, outputs=[])
    S2B.upon(add_message, enter=S2B, outputs=[queue, RC_tx_add])
    S2B.upon(rx_message_theirs, enter=S2B, outputs=[accept_peer_message_and_redrain])
    S2B.upon(rx_message_ours, enter=S2B, outputs=[noop_on_self_echo])
    S2B.upon(close, enter=S3B, outputs=[record_mood_and_RC_tx_close])

    S3A.upon(connected, enter=S3B, outputs=[RC_tx_close])
    S3B.upon(lost, enter=S3A, outputs=[])
    S3B.upon(rx_closed, enter=S4B, outputs=[T_mailbox_done])
    S3B.upon(add_message, enter=S3B, outputs=[])
    S3B.upon(rx_message_theirs, enter=S3B, outputs=[])
    S3B.upon(rx_message_ours, enter=S3B, outputs=[])
    S3B.upon(close, enter=S3B, outputs=[])

    S4A.upon(connected, enter=S4B, outputs=[])
    S4B.upon(lost, enter=S4A, outputs=[])
    S4.upon(add_message, enter=S4, outputs=[])
    S4.upon(rx_message_theirs, enter=S4, outputs=[])
    S4.upon(rx_message_ours, enter=S4, outputs=[])
    S4.upon(close, enter=S4, outputs=[])
