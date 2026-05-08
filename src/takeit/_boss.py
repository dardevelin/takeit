import re

from attr import attrib, attrs, evolve
from attr.validators import instance_of
from automat import MethodicalMachine
from twisted.python import log
from zope.interface import implementer

from . import _interfaces
from ._code import Code, validate_code
from ._code_format import encode_locator, generate_locator, parse_code
from ._dilation.manager import Dilator
from ._input import Input
from ._key import Key
from ._mailbox import Mailbox
from ._order import Order
from ._receive import Receive
from ._send import Send
from ._status import AllegedSharedKey, Closed, ConfirmedKey, WormholeStatus
from ._tag import derive_tag, derive_tag_legacy_words
from ._terminator import Terminator
from ._wordlist import PGPWordList
from .errors import (
    LonelyError,
    OnlyOneCodeError,
    WelcomeError,
    WrongPasswordError,
    _UnknownPhaseError,
)
from .util import bytes_to_dict, provides


@attrs
@implementer(_interfaces.IBoss)
class Boss:
    """
    Orchestrates the per-wormhole state machines.

    Compared to upstream wormhole's Boss:
    - The mailbox-server URL (`_url`), the journal (`_journal`), and the
      Tor manager (`_tor`) are gone. takeit has no central mailbox URL,
      and Tor support is now self-contained inside `_dilation/`.
    - A `rendezvous_factory(boss, mailbox, terminator) -> IRendezvous`
      callable is supplied at construction time. Tests pass FakeRendezvous;
      production passes a NostrRendezvous-builder closure. Boss does not
      know about Nostr.
    - On `got_code`, Boss derives the routing tag via
      `_tag.derive_tag(code)` and hands it to Mailbox.
    """

    _wormhole = attrib()
    _side = attrib(validator=instance_of(str))
    _appid = attrib(validator=instance_of(str))
    _versions = attrib(validator=instance_of(dict))
    _reactor = attrib()
    _eventual_queue = attrib()
    _cooperator = attrib()
    _timing = attrib(validator=provides(_interfaces.ITiming))
    _rendezvous_factory = attrib()
    _on_status_update = attrib(default=None)

    m = MethodicalMachine()
    set_trace = getattr(m, "_setTrace", lambda self, f: None)  # pragma: no cover

    def __attrs_post_init__(self):
        # Initialize bookkeeping state *first* so that workers built next
        # can see consistent values (status, phase counters) during their
        # own __attrs_post_init__/wire calls.
        self._init_other_state()
        self._current_wormhole_status = WormholeStatus()
        self._build_workers()
        # Make sure our listener gets the "initial" state; normally we only
        # send updates when we evolve() away from this initial state.
        if self._on_status_update is not None:
            self._on_status_update(self._current_wormhole_status)

    def _build_workers(self):
        self._M = Mailbox(self._side)
        self._S = Send(self._side, self._timing)
        self._O = Order(self._side, self._timing)
        self._K = Key(self._appid, self._versions, self._side, self._timing)
        self._R = Receive(self._side, self._timing)
        self._I = Input(self._timing)
        self._C = Code(self._timing)
        self._T = Terminator()
        self._D = Dilator(
            self._reactor,
            self._eventual_queue,
            self._cooperator,
            self._versions.get("can-dilate", []),
        )

        # Build the rendezvous via the supplied factory. The factory is
        # responsible for calling rv.wire(boss, mailbox, terminator) before
        # returning, so by this line the inbound side of IRendezvous is wired.
        self._RC = self._rendezvous_factory(self, self._M, self._T)

        # Wire the rest of the graph.
        self._M.wire(self._RC, self._O, self._T)
        self._S.wire(self._M)
        self._O.wire(self._K, self._R)
        self._K.wire(self, self._M, self._R, self._O)
        self._R.wire(self, self._S, self._M)
        self._I.wire(self._C)
        self._C.wire(self, self._K, self._I)
        self._T.wire(self, self._RC, self._M, self._D)
        self._D.wire(self._S, self._T)

    def _init_other_state(self):
        self._did_start_code = False
        self._next_tx_phase = 0
        self._next_rx_phase = 0
        self._rx_phases = {}  # phase -> plaintext

        self._next_rx_dilate_seqnum = 0
        self._rx_dilate_seqnums = {}  # seqnum -> plaintext

        self._result = "empty"

    def _evolve_wormhole_status(self, **kwargs):
        # Track the wormhole status here because we may be connected to the
        # rendezvous (and even the peer) before the application asks for
        # Dilation.
        status = evolve(self._current_wormhole_status, **kwargs)
        if self._on_status_update is not None:
            self._on_status_update(status)
        if hasattr(self, "_D") and self._D._manager is not None:
            self._D._manager._wormhole_status(status)
        self._current_wormhole_status = status

    # ---- called from outside ----

    def start(self):
        self._RC.start()

    def _print_trace(
        self, old_state, input, new_state, client_name, machine, file
    ):  # pragma: no cover
        if new_state:
            print(
                f"{client_name}.{machine}[{old_state}].{input} -> [{new_state}]",
                file=file,
            )
        else:
            # IRendezvous emits message events as if they were state
            # transitions, except that old_state and new_state are empty.
            print(f"{client_name}.{machine}.{input}", file=file)
        file.flush()

        def output_tracer(output):
            print(f" {client_name}.{machine}.{output}()", file=file)
            file.flush()

        return output_tracer

    def _set_trace(self, client_name, which, file):  # pragma: no cover
        names = {
            "B": self,
            "M": self._M,
            "S": self._S,
            "O": self._O,
            "K": self._K,
            "SK": self._K._SK,
            "R": self._R,
            "RC": self._RC,
            "I": self._I,
            "C": self._C,
            "T": self._T,
        }
        for machine in which.split():

            def tracer(old_state, input, new_state, machine=machine):
                self._print_trace(
                    old_state,
                    input,
                    new_state,
                    client_name=client_name,
                    machine=machine,
                    file=file,
                )

            names[machine].set_trace(tracer)
            if machine == "I":
                self._I.set_debug(tracer)

    # input/allocate/set_code are regular methods, not state-transition
    # inputs. They must be called while we're in S0_empty, and exactly one
    # of them must be called.
    def input_code(self):
        if self._did_start_code:
            raise OnlyOneCodeError()
        self._did_start_code = True
        return self._C.input_code()

    def allocate_code(self, code_length):
        if self._did_start_code:
            raise OnlyOneCodeError()
        self._did_start_code = True
        # Mint a fresh 16-byte locator. The user-facing code becomes
        # `<base32-locator>:<words>` (HYP-406): locator carries the
        # public Nostr routing tag, the FULL code is the SPAKE2 password
        # (~152 bits vs ~24 from words-only).
        locator_b32 = encode_locator(generate_locator())
        self._C.allocate_code(code_length, PGPWordList(), locator_b32=locator_b32)

    def set_code(self, code):
        """Set a CANONICAL `<base32-locator>:<words>` code (HYP-443).

        Bare-words codes are refused with ValueError; library callers
        wanting the legacy oracle-vulnerable path must use
        set_code_legacy_words() so that path is syntactically
        conspicuous (per the standing 'no easy paths' mandate). The
        CLI's words-only flow goes through the legacy entrypoint
        only after --verify validation in cli.py.
        """
        validate_code(code)  # raises KeyFormatError on bad format
        if ":" not in code:
            raise ValueError(
                "set_code requires a canonical '<locator>:<words>' code. "
                "For legacy words-only handoff (vulnerable to relay "
                "MITM without out-of-band SAS comparison), use "
                "set_code_legacy_words()."
            )
        if self._did_start_code:
            raise OnlyOneCodeError()
        self._did_start_code = True
        self._C.set_code(code)

    def set_code_legacy_words(self, words):
        """Set a legacy words-only code (HYP-443).

        Used by the CLI's words-only path AFTER --verify has gated it,
        and by library callers explicitly bridging to upstream
        wormhole's words-only protocol shape. The rendezvous tag is
        derived from the words alone via derive_tag_legacy_words,
        which means a hostile Nostr relay can pre-compute every
        wordlist^N → tag mapping and mount an active MITM. Out-of-band
        SAS comparison is the ONLY mitigation; callers MUST display
        the verifier and have both peers compare it before exchanging
        sensitive data.

        Symmetrically refuses canonical-shape codes — those should
        flow through set_code so the canonical HKDF salt is used.
        """
        validate_code(words)  # raises KeyFormatError on bad format
        if ":" in words:
            raise ValueError(
                "set_code_legacy_words refuses canonical-shape codes. "
                "Pass the canonical '<locator>:<words>' code to "
                "set_code instead — it routes through a different "
                "(non-oracle-vulnerable) HKDF path."
            )
        if self._did_start_code:
            raise OnlyOneCodeError()
        self._did_start_code = True
        self._C.set_code(words)

    def dilate(
        self,
        *,
        expected_subprotocols,
        transit_relay_location=None,
        no_listen=False,
        on_status_update=None,
        ping_interval=None,
    ):
        # HYP-442: forward keyword-only-required expected_subprotocols
        # straight through to the Dilator. The TypeError check fires
        # there; we don't pre-empt it here because that would bury the
        # actual call site in a stack of indirection.
        return self._D.dilate(
            transit_relay_location=transit_relay_location,
            no_listen=no_listen,
            wormhole_status=self._current_wormhole_status,
            status_update=on_status_update,
            ping_interval=ping_interval,
            expected_subprotocols=expected_subprotocols,
        )

    @m.input()
    def send(self, plaintext):
        pass

    @m.input()
    def close(self):
        pass

    # ---- from IRendezvous ----

    def rx_welcome(self, welcome):
        try:
            if "error" in welcome:
                raise WelcomeError(welcome["error"])
            self._wormhole.got_welcome(welcome)
        except WelcomeError as welcome_error:
            self.rx_unwelcome(welcome_error)

    @m.input()
    def rx_unwelcome(self, welcome_error):
        pass

    @m.input()
    def error(self, err):
        pass

    # ---- from Code ----

    @m.input()
    def got_code(self, code):
        pass

    # ---- from Key ----

    @m.input()
    def happy(self):
        pass

    @m.input()
    def scared(self):
        pass

    def got_message(self, phase, plaintext):
        assert isinstance(phase, str), type(phase)
        assert isinstance(plaintext, bytes), type(plaintext)
        d_mo = re.search(r"^dilate-(\d+)$", phase)
        if phase == "version":
            self._got_version(plaintext)
        elif d_mo:
            self._got_dilate(int(d_mo.group(1)), plaintext)
        elif re.search(r"^\d+$", phase):
            self._got_phase(int(phase), plaintext)
        else:
            # Ignore unrecognized phases for forward-compatibility, but log
            # them so tests catch surprises.
            log.err(_UnknownPhaseError(f"received unknown phase '{phase}'"))

    @m.input()
    def _got_version(self, plaintext):
        pass

    @m.input()
    def _got_phase(self, phase, plaintext):
        pass

    @m.input()
    def _got_dilate(self, seqnum, plaintext):
        pass

    @m.input()
    def got_key(self, key):
        pass

    @m.input()
    def got_verifier(self, verifier):
        pass

    # ---- from Terminator ----

    @m.input()
    def closed(self):
        pass

    # ---- outputs ----

    @m.output()
    def do_got_code(self, code):
        # Boss is the orchestrator that knows about routing tags. State
        # machines below it (Code, Key) only know the user-visible code.
        #
        # Post-HYP-406, the code is one of two shapes:
        # - canonical `<base32-locator>:<words>` → tag from locator
        #   (canonical path, no oracle).
        # - words-only → tag from words via legacy domain-separated
        #   path. Words-only handoff is vulnerable to relay-mediated
        #   MITM unless --verify is used; the CLI is responsible for
        #   warning the user. Boss just routes the bytes.
        self._wormhole.got_code(code)
        locator, words = parse_code(code)
        if locator is not None:
            tag = derive_tag(locator)
        else:
            tag = derive_tag_legacy_words(words)
        self._M.got_tag(tag)

    @m.output()
    def process_version(self, plaintext):
        self._their_versions = bytes_to_dict(plaintext)
        self._D.got_wormhole_versions(self._their_versions)
        app_versions = self._their_versions.get("app_versions", {})
        self._wormhole.got_versions(app_versions)

    @m.output()
    def S_send(self, plaintext):
        assert isinstance(plaintext, bytes), type(plaintext)
        phase = self._next_tx_phase
        self._next_tx_phase += 1
        self._S.send("%d" % phase, plaintext)

    @m.output()
    def close_unwelcome(self, welcome_error):
        self._result = welcome_error
        self._T.close("unwelcome")

    @m.output()
    def close_scared(self):
        self._result = WrongPasswordError()
        self._T.close("scary")

    @m.output()
    def close_lonely(self):
        self._result = LonelyError()
        self._T.close("lonely")

    @m.output()
    def close_happy(self):
        self._result = "happy"
        self._T.close("happy")

    @m.output()
    def W_got_key(self, key):
        # Route the user-facing notification through the eventual queue:
        # the application's got_key handler may re-enter wormhole APIs
        # (e.g. derive_key, send_message) and that re-entry must not
        # observe a state-machine that's still mid-transition. This
        # addresses the upstream `_key.py` TODO at line 201; we keep the
        # internal `Boss.got_key` input synchronous (so transitions stay
        # ordered) but defer the user callback to a fresh reactor turn.
        self._eventual_queue.eventually(self._wormhole.got_key, key)

    @m.output()
    def D_got_key(self, key):
        self._D.got_key(key)

    @m.output()
    def send_status_peer_key(self, key):
        self._evolve_wormhole_status(peer_key=AllegedSharedKey())

    @m.output()
    def send_status_confirmed_key(self, plaintext):
        self._evolve_wormhole_status(peer_key=ConfirmedKey())

    @m.output()
    def send_status_closed(self):
        self._evolve_wormhole_status(mailbox_connection=Closed())

    @m.output()
    def W_got_verifier(self, verifier):
        self._wormhole.got_verifier(verifier)

    @m.output()
    def W_received(self, phase, plaintext):
        assert isinstance(phase, int), type(phase)
        # We call wormhole.received() in strict phase order, with no gaps.
        self._rx_phases[phase] = plaintext
        while self._next_rx_phase in self._rx_phases:
            self._wormhole.received(self._rx_phases.pop(self._next_rx_phase))
            self._next_rx_phase += 1

    @m.output()
    def D_received_dilate(self, seqnum, plaintext):
        assert isinstance(seqnum, int), type(seqnum)
        self._rx_dilate_seqnums[seqnum] = plaintext
        while self._next_rx_dilate_seqnum in self._rx_dilate_seqnums:
            payload = self._rx_dilate_seqnums.pop(self._next_rx_dilate_seqnum)
            self._D.received_dilate(payload)
            self._next_rx_dilate_seqnum += 1

    @m.output()
    def W_close_with_error(self, err):
        self._result = err
        self._wormhole.closed(self._result)

    @m.output()
    def W_closed(self):
        # result is either "happy" or a WormholeError of some sort
        self._wormhole.closed(self._result)

    # ---- states ----

    @m.state(initial=True)
    def S0_empty(self):
        pass  # pragma: no cover

    @m.state()
    def S1_lonely(self):
        pass  # pragma: no cover

    @m.state()
    def S2_happy(self):
        pass  # pragma: no cover

    @m.state()
    def S3_closing(self):
        pass  # pragma: no cover

    @m.state(terminal=True)
    def S4_closed(self):
        pass  # pragma: no cover

    # ---- transitions ----

    S0_empty.upon(close, enter=S3_closing, outputs=[close_lonely])
    S0_empty.upon(send, enter=S0_empty, outputs=[S_send])
    S0_empty.upon(rx_unwelcome, enter=S3_closing, outputs=[close_unwelcome])
    S0_empty.upon(got_code, enter=S1_lonely, outputs=[do_got_code])
    S0_empty.upon(
        error, enter=S4_closed, outputs=[W_close_with_error, send_status_closed]
    )

    S1_lonely.upon(rx_unwelcome, enter=S3_closing, outputs=[close_unwelcome])
    S1_lonely.upon(happy, enter=S2_happy, outputs=[])
    S1_lonely.upon(scared, enter=S3_closing, outputs=[close_scared])
    S1_lonely.upon(close, enter=S3_closing, outputs=[close_lonely])
    S1_lonely.upon(send, enter=S1_lonely, outputs=[S_send])
    S1_lonely.upon(
        got_key, enter=S1_lonely, outputs=[W_got_key, D_got_key, send_status_peer_key]
    )
    S1_lonely.upon(
        error, enter=S4_closed, outputs=[W_close_with_error, send_status_closed]
    )

    S2_happy.upon(rx_unwelcome, enter=S3_closing, outputs=[close_unwelcome])
    S2_happy.upon(got_verifier, enter=S2_happy, outputs=[W_got_verifier])
    S2_happy.upon(_got_phase, enter=S2_happy, outputs=[W_received])
    S2_happy.upon(
        _got_version,
        enter=S2_happy,
        outputs=[process_version, send_status_confirmed_key],
    )
    S2_happy.upon(_got_dilate, enter=S2_happy, outputs=[D_received_dilate])
    S2_happy.upon(scared, enter=S3_closing, outputs=[close_scared])
    S2_happy.upon(close, enter=S3_closing, outputs=[close_happy])
    S2_happy.upon(send, enter=S2_happy, outputs=[S_send])
    S2_happy.upon(
        error, enter=S4_closed, outputs=[W_close_with_error, send_status_closed]
    )

    S3_closing.upon(rx_unwelcome, enter=S3_closing, outputs=[])
    S3_closing.upon(got_verifier, enter=S3_closing, outputs=[])
    S3_closing.upon(_got_phase, enter=S3_closing, outputs=[])
    S3_closing.upon(_got_version, enter=S3_closing, outputs=[])
    S3_closing.upon(_got_dilate, enter=S3_closing, outputs=[])
    S3_closing.upon(happy, enter=S3_closing, outputs=[])
    S3_closing.upon(scared, enter=S3_closing, outputs=[])
    S3_closing.upon(close, enter=S3_closing, outputs=[])
    S3_closing.upon(send, enter=S3_closing, outputs=[])
    S3_closing.upon(closed, enter=S4_closed, outputs=[W_closed, send_status_closed])
    S3_closing.upon(
        error, enter=S4_closed, outputs=[W_close_with_error, send_status_closed]
    )

    S4_closed.upon(rx_unwelcome, enter=S4_closed, outputs=[])
    S4_closed.upon(got_verifier, enter=S4_closed, outputs=[])
    S4_closed.upon(_got_phase, enter=S4_closed, outputs=[])
    S4_closed.upon(_got_version, enter=S4_closed, outputs=[])
    S4_closed.upon(_got_dilate, enter=S4_closed, outputs=[])
    S4_closed.upon(happy, enter=S4_closed, outputs=[])
    S4_closed.upon(scared, enter=S4_closed, outputs=[])
    S4_closed.upon(close, enter=S4_closed, outputs=[])
    S4_closed.upon(send, enter=S4_closed, outputs=[])
    S4_closed.upon(error, enter=S4_closed, outputs=[])
