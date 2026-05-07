"""
Tests for the takeit Mailbox state machine.

The state shape mirrors upstream's because the connection lifecycle (the A/B
suffix encoding "rendezvous connected" vs "disconnected") is still real on
Nostr — relays can drop. What is *gone* is the nameplate-claim round-trip:
the tag is derived synchronously from the code, so `got_tag` only sets the
tag, it does not initiate a server claim.

Inputs:
- got_tag(tag)               — Boss/Code calls this once the code is known
- connected() / lost()       — IRendezvous notifies of relay connectivity
- add_message(phase, body)   — Send/Key wants to publish a phase
- rx_message(side, phase, body) — IRendezvous delivers a peer event
- rx_closed()                — IRendezvous confirms close (may be synthetic)
- close(mood)                — Terminator initiates teardown

Outputs of interest:
- _RC.tx_open(tag)           — subscribe + drain queued outbound
- _RC.tx_add(phase, body)    — publish one phase
- _RC.tx_close(tag, mood)    — unsubscribe (no-op on Nostr but kept for
                               symmetry with Terminator's expectations)
- _O.got_message(side, phase, body) — forward peer messages (deduped)
- _T.mailbox_done()          — final ack to Terminator
"""

import pytest
from zope.interface import implementer

from takeit import _interfaces
from takeit._mailbox import Mailbox


@implementer(_interfaces.IRendezvousConnector)
class FakeRC:
    def __init__(self):
        self.opened = []
        self.added = []
        self.closed = []

    def tx_open(self, tag):
        self.opened.append(tag)

    def tx_add(self, phase, body):
        self.added.append((phase, body))

    def tx_close(self, tag, mood):
        self.closed.append((tag, mood))


@implementer(_interfaces.IOrder)
class FakeOrder:
    def __init__(self):
        self.received = []

    def got_message(self, side, phase, body):
        self.received.append((side, phase, body))


@implementer(_interfaces.ITerminator)
class FakeTerminator:
    def __init__(self):
        self.done = False

    def mailbox_done(self):
        self.done = True


@pytest.fixture
def mailbox_setup():
    rc = FakeRC()
    order = FakeOrder()
    term = FakeTerminator()
    mb = Mailbox(side="aaaa")
    mb.wire(rc, order, term)
    return mb, rc, order, term


# --- happy path ---


def test_message_published_after_tag_and_connect(mailbox_setup):
    mb, rc, _, _ = mailbox_setup
    mb.got_tag("xyz")
    mb.connected()
    mb.add_message("pake", b"payload")
    assert rc.added == [("pake", b"payload")]


def test_outbound_queued_until_connected(mailbox_setup):
    mb, rc, _, _ = mailbox_setup
    mb.got_tag("xyz")
    mb.add_message("pake", b"payload")
    assert rc.added == []  # not yet
    mb.connected()
    assert rc.added == [("pake", b"payload")]


def test_outbound_queued_until_tag_known(mailbox_setup):
    mb, rc, _, _ = mailbox_setup
    mb.connected()
    mb.add_message("pake", b"payload")
    assert rc.added == []
    mb.got_tag("xyz")
    assert rc.added == [("pake", b"payload")]


def test_open_command_sent_on_each_reconnect(mailbox_setup):
    """Subscriptions don't survive Nostr disconnects; we must re-subscribe."""
    mb, rc, _, _ = mailbox_setup
    mb.got_tag("xyz")
    mb.connected()
    assert rc.opened == ["xyz"]
    mb.lost()
    mb.connected()
    assert rc.opened == ["xyz", "xyz"]


# --- inbound message handling ---


def test_peer_message_forwarded_to_order(mailbox_setup):
    mb, _, order, _ = mailbox_setup
    mb.got_tag("xyz")
    mb.connected()
    mb.rx_message("bbbb", "pake", b"peer-payload")
    assert order.received == [("bbbb", "pake", b"peer-payload")]


def test_own_message_does_not_loop_back(mailbox_setup):
    """Self-events from the relay (we publish, we also subscribe) must not
    loop into the Order pipeline."""
    mb, _, order, _ = mailbox_setup
    mb.got_tag("xyz")
    mb.connected()
    mb.rx_message("aaaa", "pake", b"my-own")  # side == self._side
    assert order.received == []


def test_peer_phase_delivered_only_once(mailbox_setup):
    """Relays may deliver duplicates; Mailbox must dedupe by phase."""
    mb, _, order, _ = mailbox_setup
    mb.got_tag("xyz")
    mb.connected()
    mb.rx_message("bbbb", "pake", b"peer-payload")
    mb.rx_message("bbbb", "pake", b"peer-payload")  # duplicate
    assert len(order.received) == 1


# --- close path ---


def test_close_with_no_tag_yet_completes_immediately(mailbox_setup):
    """If the user closes before a code is set, there's nothing to clean up."""
    mb, rc, _, term = mailbox_setup
    mb.close("lonely")
    assert term.done is True
    assert rc.closed == []  # nothing to close


def test_close_after_open_sends_close_then_completes_on_ack(mailbox_setup):
    mb, rc, _, term = mailbox_setup
    mb.got_tag("xyz")
    mb.connected()
    mb.close("happy")
    assert rc.closed == [("xyz", "happy")]
    assert term.done is False  # waiting for rx_closed
    mb.rx_closed()
    assert term.done is True


def test_messages_after_close_are_ignored(mailbox_setup):
    mb, _, order, _ = mailbox_setup
    mb.got_tag("xyz")
    mb.connected()
    mb.close("happy")
    mb.rx_closed()  # fully closed
    mb.rx_message("bbbb", "pake", b"too-late")
    assert order.received == []


def test_outbound_persists_after_self_echo(mailbox_setup):
    """takeit semantic: outbound messages must stay queued even after the
    relay echoes them back to us. Nostr does not buffer ephemeral events,
    so a peer who subscribes after we publish would never see our message
    unless we retransmit."""
    mb, rc, _, _ = mailbox_setup
    mb.got_tag("xyz")
    mb.connected()
    mb.add_message("pake", b"my-pake")
    # Self-echo (relay reflects our publish to our own subscription)
    mb.rx_message("aaaa", "pake", b"my-pake")
    # Queue should still hold "pake" — assert by triggering a redrain
    # via a peer message and verifying tx_add fires again.
    mb.rx_message("bbbb", "pake", b"peer-pake")
    # First publish + redrain on peer-pake = 2 publishes.
    assert rc.added == [("pake", b"my-pake"), ("pake", b"my-pake")]


def test_redrain_on_peer_only_fires_once_per_phase(mailbox_setup):
    """A peer that retransmits the same phase (because they hadn't seen our
    response yet) must not cause us to retransmit unboundedly. The
    `_processed` dedup guards against this feedback loop."""
    mb, rc, _, _ = mailbox_setup
    mb.got_tag("xyz")
    mb.connected()
    mb.add_message("pake", b"my-pake")
    rc.added.clear()  # forget the initial publish
    # Peer sends pake; we redrain (one extra publish)
    mb.rx_message("bbbb", "pake", b"peer-pake")
    assert rc.added == [("pake", b"my-pake")]
    # Peer retransmits pake; we must NOT redrain again
    mb.rx_message("bbbb", "pake", b"peer-pake")
    assert rc.added == [("pake", b"my-pake")]


def test_redrain_capped_at_max_processed_phases(mailbox_setup):
    """A malicious peer flooding distinct phase strings cannot grow our
    memory or amplify our outbound past MAX_PROCESSED_PHASES redrains."""
    from takeit._mailbox import Mailbox

    mb, rc, order, _ = mailbox_setup
    mb.got_tag("xyz")
    mb.connected()
    mb.add_message("pake", b"my-pake")
    rc.added.clear()  # forget the initial publish

    cap = Mailbox.MAX_PROCESSED_PHASES
    # Send `cap + 50` distinct peer phases; expect exactly `cap` redrains.
    for i in range(cap + 50):
        mb.rx_message("bbbb", f"p{i}", b"peer-payload")

    assert len(rc.added) == cap
    # All payloads still reach Order — the peer's messages aren't dropped,
    # just the redrain side-effect is capped.
    assert len(order.received) == cap + 50
    # `_processed` is bounded.
    assert len(mb._processed) == cap


def test_disconnect_during_close_still_completes_on_reconnect(mailbox_setup):
    """If we lose the relay during close, we must re-send tx_close on reconnect
    so the receiver of rx_closed (or our local synthesis of it) will fire."""
    mb, rc, _, term = mailbox_setup
    mb.got_tag("xyz")
    mb.connected()
    mb.close("happy")
    assert rc.closed == [("xyz", "happy")]
    mb.lost()
    mb.connected()  # reconnected mid-close
    assert rc.closed == [("xyz", "happy"), ("xyz", "happy")]
    mb.rx_closed()
    assert term.done is True
