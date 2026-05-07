from automat import MethodicalMachine
from zope.interface import implementer

from . import _interfaces


@implementer(_interfaces.ITerminator)
class Terminator:
    """
    Drives the takeit shutdown sequence.

    Without a Nameplate state machine the upstream 2-by-2 product
    (nameplate-done × mailbox-done × closing) collapses to a 1-D problem.
    The sequence is:

        S_running ──close──▶ S_closing  (forwards close+mood to Mailbox)
        S_closing ──mailbox_done──▶ S_stopping_RC  (calls RC.stop())
        S_stopping_RC ──stoppedRC──▶ S_stopping_D  (calls Dilator.stop())
        S_stopping_D ──stoppedD──▶ S_stopped       (calls Boss.closed())

    `mailbox_done` may also fire before `close` (e.g. relay error tore the
    mailbox down). In that case we hold in S_running_mailbox_done and
    short-circuit the next close to skip Mailbox.
    """

    m = MethodicalMachine()
    set_trace = getattr(m, "_setTrace",
                        lambda self, f: None)  # pragma: no cover

    def __init__(self):
        self._mood = None

    def wire(self, boss, rendezvous_connector, mailbox, dilator):
        self._B = _interfaces.IBoss(boss)
        self._RC = _interfaces.IRendezvousConnector(rendezvous_connector)
        self._M = _interfaces.IMailbox(mailbox)
        self._D = _interfaces.IDilator(dilator)

    @m.state(initial=True)
    def S_running(self):
        pass  # pragma: no cover

    @m.state()
    def S_running_mailbox_done(self):
        pass  # pragma: no cover

    @m.state()
    def S_closing(self):
        pass  # pragma: no cover

    @m.state()
    def S_stopping_RC(self):
        pass  # pragma: no cover

    @m.state()
    def S_stopping_D(self):
        pass  # pragma: no cover

    @m.state(terminal=True)
    def S_stopped(self):
        pass  # pragma: no cover

    @m.input()
    def close(self, mood):
        pass

    @m.input()
    def mailbox_done(self):
        pass

    @m.input()
    def stoppedRC(self):
        pass

    @m.input()
    def stoppedD(self):
        pass

    @m.output()
    def close_mailbox(self, mood):
        self._M.close(mood)

    @m.output()
    def ignore_mood_and_RC_stop(self, mood):
        self._RC.stop()

    @m.output()
    def RC_stop(self):
        self._RC.stop()

    @m.output()
    def stop_dilator(self):
        self._D.stop()

    @m.output()
    def B_closed(self):
        self._B.closed()

    S_running.upon(close, enter=S_closing, outputs=[close_mailbox])
    S_running.upon(mailbox_done, enter=S_running_mailbox_done, outputs=[])

    S_running_mailbox_done.upon(
        close, enter=S_stopping_RC, outputs=[ignore_mood_and_RC_stop])

    S_closing.upon(mailbox_done, enter=S_stopping_RC, outputs=[RC_stop])

    S_stopping_RC.upon(stoppedRC, enter=S_stopping_D, outputs=[stop_dilator])
    S_stopping_D.upon(stoppedD, enter=S_stopped, outputs=[B_closed])
