# Originally from magic-wormhole (MIT, (c) 2015 Brian Warner).
# Lifted into takeit; see NOTICE for the full list.
from attr import attrib, attrs
from attr.validators import instance_of
from automat import MethodicalMachine
from zope.interface import implementer

from . import _interfaces
from .util import provides


@attrs
@implementer(_interfaces.IOrder)
class Order:
    _side = attrib(validator=instance_of(str))
    _timing = attrib(validator=provides(_interfaces.ITiming))
    m = MethodicalMachine()
    set_trace = getattr(m, "_setTrace", lambda self, f: None)  # pragma: no cover

    def __attrs_post_init__(self):
        self._key = None
        self._queue = []

    def wire(self, key, receive):
        self._K = _interfaces.IKey(key)
        self._R = _interfaces.IReceive(receive)

    @m.state(initial=True)
    def S0_no_pake(self):
        pass  # pragma: no cover

    # HYP-423: under a hostile relay, a got_pake may be a forged event
    # that Key cannot finish SPAKE2 against. We stay in S0_no_pake
    # (queueing non-pake events) and only transition once Key signals
    # pake_confirmed. That way a forged pake does not let a later
    # encrypted message be delivered to a key-less Receive.
    @m.state()
    def S1_yes_pake(self):
        pass  # pragma: no cover

    def got_message(self, side, phase, body):
        # print("ORDER[%s].got_message(%s)" % (self._side, phase))
        assert isinstance(side, str), type(phase)
        assert isinstance(phase, str), type(phase)
        assert isinstance(body, bytes), type(body)
        if phase == "pake":
            self.got_pake(side, phase, body)
        else:
            self.got_non_pake(side, phase, body)

    @m.input()
    def got_pake(self, side, phase, body):
        pass

    @m.input()
    def got_non_pake(self, side, phase, body):
        pass

    @m.input()
    def pake_confirmed(self):
        # Called by Key after a successful SPAKE2.finish. Transitions
        # us to S1_yes_pake and drains queued non-pake events.
        pass

    @m.output()
    def queue(self, side, phase, body):
        assert isinstance(side, str), type(phase)
        assert isinstance(phase, str), type(phase)
        assert isinstance(body, bytes), type(body)
        self._queue.append((side, phase, body))

    @m.output()
    def notify_key(self, side, phase, body):
        self._K.got_pake(body)

    @m.output()
    def drain(self):
        for side, phase, body in self._queue:
            self._deliver(side, phase, body)
        self._queue[:] = []

    @m.output()
    def deliver(self, side, phase, body):
        self._deliver(side, phase, body)

    def _deliver(self, side, phase, body):
        self._R.got_message(side, phase, body)

    S0_no_pake.upon(got_non_pake, enter=S0_no_pake, outputs=[queue])
    # HYP-423: feeding Key on every got_pake is safe (Key handles
    # forged-pake parsing internally). What's NOT safe is transitioning
    # Order's state and draining on a got_pake that may be forged —
    # that's why we stay in S0_no_pake until Key confirms via
    # pake_confirmed.
    S0_no_pake.upon(got_pake, enter=S0_no_pake, outputs=[notify_key])
    S0_no_pake.upon(pake_confirmed, enter=S1_yes_pake, outputs=[drain])
    S1_yes_pake.upon(got_non_pake, enter=S1_yes_pake, outputs=[deliver])
    # Subsequent pakes after auth (e.g. peer self-echo) are no-ops at
    # the order layer; Key's S11.got_pake handles them.
    S1_yes_pake.upon(got_pake, enter=S1_yes_pake, outputs=[notify_key])
    S1_yes_pake.upon(pake_confirmed, enter=S1_yes_pake, outputs=[])
