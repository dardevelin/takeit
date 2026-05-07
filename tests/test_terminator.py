"""
Tests for the takeit Terminator state machine.

Without Nameplate the 2D product (nameplate-done × mailbox-done) collapses
to a 1D problem: just track whether the mailbox is done. The state machine
becomes tiny:

    S_running ──close──▶ S_closing_mailbox
    S_closing_mailbox ──mailbox_done──▶ S_stopping_RC  (with RC_stop)
    S_stopping_RC ──stoppedRC──▶ S_stopping_D  (with stop_dilator)
    S_stopping_D ──stoppedD──▶ S_stopped  (with B_closed)
"""

from zope.interface import implementer

from takeit import _interfaces
from takeit._terminator import Terminator


@implementer(_interfaces.IBoss)
class FakeBoss:
    def __init__(self):
        self.closed_called = False

    def closed(self):
        self.closed_called = True


@implementer(_interfaces.IRendezvousConnector)
class FakeRC:
    def __init__(self):
        self.stopped = False

    def stop(self):
        self.stopped = True


@implementer(_interfaces.IMailbox)
class FakeMailbox:
    def __init__(self):
        self.close_calls = []

    def close(self, mood):
        self.close_calls.append(mood)


@implementer(_interfaces.IDilator)
class FakeDilator:
    def __init__(self):
        self.stopped = False

    def stop(self):
        self.stopped = True


def _wired_terminator():
    boss = FakeBoss()
    rc = FakeRC()
    mailbox = FakeMailbox()
    dilator = FakeDilator()
    t = Terminator()
    t.wire(boss, rc, mailbox, dilator)
    return t, boss, rc, mailbox, dilator


def test_close_propagates_mood_to_mailbox():
    t, _, _, mailbox, _ = _wired_terminator()
    t.close("happy")
    assert mailbox.close_calls == ["happy"]


def test_full_shutdown_sequence():
    t, boss, rc, mailbox, dilator = _wired_terminator()
    t.close("happy")
    assert mailbox.close_calls == ["happy"]
    assert rc.stopped is False
    t.mailbox_done()
    assert rc.stopped is True
    assert dilator.stopped is False
    t.stoppedRC()
    assert dilator.stopped is True
    assert boss.closed_called is False
    t.stoppedD()
    assert boss.closed_called is True


def test_mailbox_done_before_close_holds():
    """If mailbox closes itself for unrelated reasons before our close call,
    we still wait for the user's close before tearing down RC and Dilator."""
    t, boss, rc, _, dilator = _wired_terminator()
    t.mailbox_done()
    assert rc.stopped is False
    assert dilator.stopped is False
    assert boss.closed_called is False
    t.close("happy")
    # mailbox is already done, so RC stop fires immediately
    assert rc.stopped is True


def test_mood_required_on_close():
    """close() must take a mood — no mood-less terminations."""
    t, _, _, _, _ = _wired_terminator()
    import pytest

    with pytest.raises(TypeError):
        t.close()  # missing mood
