"""
Contract tests for IRendezvous.

These tests pin the shape of the Mailbox<->IRendezvous boundary. The
takeit Mailbox makes calls of these forms:
    rendezvous.start()
    rendezvous.stop()
    rendezvous.tx_open(tag)
    rendezvous.tx_add(phase, body)
    rendezvous.tx_close(tag, mood)

In response, IRendezvous fires events back into the wired Boss/Mailbox/
Terminator. Any production implementation (today: NostrRendezvous) must
satisfy the same contract. The FakeRendezvous test double is verified
here to act as a credible reference; production implementations should
pass these same tests (parametrized by fixture).
"""
import pytest
from zope.interface import implementer

from takeit import _interfaces
from tests._fake_rendezvous import FakeRendezvous, pair


@implementer(_interfaces.IBoss)
class _BossSpy:
    def __init__(self):
        self.welcomes = []
        self.errors = []

    def rx_welcome(self, welcome):
        self.welcomes.append(welcome)

    def error(self, exc):
        self.errors.append(exc)


@implementer(_interfaces.IMailbox)
class _MailboxSpy:
    def __init__(self):
        self.events = []

    def connected(self):
        self.events.append(("connected",))

    def lost(self):
        self.events.append(("lost",))

    def rx_message(self, side, phase, body):
        self.events.append(("rx_message", side, phase, body))

    def rx_closed(self):
        self.events.append(("rx_closed",))


@implementer(_interfaces.ITerminator)
class _TerminatorSpy:
    def __init__(self):
        self.stopped = False

    def stoppedRC(self):
        self.stopped = True


@pytest.fixture
def rendezvous_factory():
    """Returns (rendezvous, boss, mailbox, terminator) for a single side.

    Production implementations should provide a fixture with the same
    signature, swapping FakeRendezvous for their own constructor.
    """
    def factory(side="aaaa"):
        rv = FakeRendezvous(side)
        boss = _BossSpy()
        mailbox = _MailboxSpy()
        term = _TerminatorSpy()
        rv.wire(boss, mailbox, term)
        return rv, boss, mailbox, term
    return factory


# --- start/stop lifecycle ---


def test_start_emits_welcome_and_connected(rendezvous_factory):
    rv, boss, mailbox, _ = rendezvous_factory()
    rv.start()
    assert boss.welcomes == [{}]
    assert ("connected",) in mailbox.events


def test_stop_emits_lost_then_stoppedRC(rendezvous_factory):
    rv, _, mailbox, term = rendezvous_factory()
    rv.start()
    rv.stop()
    # lost must come before stoppedRC so Terminator's RC stop is the final
    # signal, with mailbox-disconnect already observed.
    lost_idx = mailbox.events.index(("lost",))
    assert lost_idx >= 0
    assert term.stopped is True


def test_stop_without_start_is_invalid(rendezvous_factory):
    rv, _, _, _ = rendezvous_factory()
    with pytest.raises(AssertionError):
        rv.stop()


def test_double_start_is_invalid(rendezvous_factory):
    rv, _, _, _ = rendezvous_factory()
    rv.start()
    with pytest.raises(AssertionError):
        rv.start()


# --- tx_open / tx_add ---


def test_tx_open_requires_connection(rendezvous_factory):
    rv, _, _, _ = rendezvous_factory()
    with pytest.raises(AssertionError):
        rv.tx_open("some-tag")


def test_tx_add_requires_subscription(rendezvous_factory):
    rv, _, _, _ = rendezvous_factory()
    rv.start()
    with pytest.raises(AssertionError):
        rv.tx_add("pake", b"body")


def test_tx_add_echoes_to_self(rendezvous_factory):
    """The relay echoes our publishes back as subscription events. The
    contract preserves this behavior so Mailbox can rely on rx_message_ours
    to dequeue."""
    rv, _, mailbox, _ = rendezvous_factory("aaaa")
    rv.start()
    rv.tx_open("tag")
    rv.tx_add("pake", b"body")
    assert ("rx_message", "aaaa", "pake", b"body") in mailbox.events


# --- pairing two sides ---


def test_paired_sides_deliver_each_others_messages():
    a = FakeRendezvous("aaaa")
    b = FakeRendezvous("bbbb")
    pair(a, b)

    boss_a, mailbox_a, term_a = _BossSpy(), _MailboxSpy(), _TerminatorSpy()
    boss_b, mailbox_b, term_b = _BossSpy(), _MailboxSpy(), _TerminatorSpy()
    a.wire(boss_a, mailbox_a, term_a)
    b.wire(boss_b, mailbox_b, term_b)

    a.start()
    b.start()
    a.tx_open("shared-tag")
    b.tx_open("shared-tag")

    a.tx_add("pake", b"hello-from-a")
    # b should have received it
    assert ("rx_message", "aaaa", "pake", b"hello-from-a") in mailbox_b.events
    # and a echoed to itself
    assert ("rx_message", "aaaa", "pake", b"hello-from-a") in mailbox_a.events


def test_paired_sides_with_different_tags_do_not_cross():
    a = FakeRendezvous("aaaa")
    b = FakeRendezvous("bbbb")
    pair(a, b)

    boss_a, mailbox_a, term_a = _BossSpy(), _MailboxSpy(), _TerminatorSpy()
    boss_b, mailbox_b, term_b = _BossSpy(), _MailboxSpy(), _TerminatorSpy()
    a.wire(boss_a, mailbox_a, term_a)
    b.wire(boss_b, mailbox_b, term_b)

    a.start()
    b.start()
    a.tx_open("a-tag")
    b.tx_open("b-tag")

    a.tx_add("pake", b"hello")
    # b is on a different tag — must not see this
    assert not any(
        ev[0] == "rx_message" and ev[1] == "aaaa" for ev in mailbox_b.events)


# --- disconnection ---


def test_drop_emits_lost(rendezvous_factory):
    rv, _, mailbox, _ = rendezvous_factory()
    rv.start()
    rv.tx_open("tag")
    rv.drop_connection()
    assert ("lost",) in mailbox.events


def test_restore_emits_connected(rendezvous_factory):
    rv, _, mailbox, _ = rendezvous_factory()
    rv.start()
    rv.tx_open("tag")
    rv.drop_connection()
    rv.restore_connection()
    # After restore, mailbox sees connected. (Mailbox's state machine then
    # decides to re-issue tx_open; that's not the rendezvous's job.)
    assert mailbox.events.count(("connected",)) == 2


# --- tx_close synthesizes rx_closed ---


def test_tx_close_synthesizes_rx_closed(rendezvous_factory):
    """Nostr has no close-ack message; the rendezvous synthesizes one
    immediately so Mailbox's state machine can complete."""
    rv, _, mailbox, _ = rendezvous_factory()
    rv.start()
    rv.tx_open("tag")
    rv.tx_close("tag", "happy")
    assert ("rx_closed",) in mailbox.events
