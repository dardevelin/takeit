from hashlib import sha256

from attr import attrib, attrs
from attr.validators import instance_of
from automat import MethodicalMachine
from nacl import utils
from nacl.exceptions import CryptoError
from nacl.secret import SecretBox
from spake2 import SPAKE2_Symmetric
from zope.interface import implementer

from . import _interfaces
from .util import (
    HKDF,
    bytes_to_dict,
    bytes_to_hexstr,
    dict_to_bytes,
    hexstr_to_bytes,
    provides,
    to_bytes,
)

CryptoError
__all__ = ["derive_key", "derive_phase_key", "CryptoError", "Key"]


def derive_key(key, purpose, length=SecretBox.KEY_SIZE):
    if not isinstance(key, bytes):
        raise TypeError(type(key))
    if not isinstance(purpose, bytes):
        raise TypeError(type(purpose))
    if not isinstance(length, int):
        raise TypeError(type(length))
    return HKDF(key, length, CTXinfo=purpose)


def derive_phase_key(key, side, phase):
    assert isinstance(side, str), type(side)
    assert isinstance(phase, str), type(phase)
    side_bytes = side.encode("ascii")
    phase_bytes = phase.encode("ascii")
    purpose = (
        b"wormhole:phase:" + sha256(side_bytes).digest() + sha256(phase_bytes).digest()
    )
    return derive_key(key, purpose)


def decrypt_data(key, encrypted):
    assert isinstance(key, bytes), type(key)
    assert isinstance(encrypted, bytes), type(encrypted)
    assert len(key) == SecretBox.KEY_SIZE, len(key)
    box = SecretBox(key)
    data = box.decrypt(encrypted)
    return data


def encrypt_data(key, plaintext):
    assert isinstance(key, bytes), type(key)
    assert isinstance(plaintext, bytes), type(plaintext)
    assert len(key) == SecretBox.KEY_SIZE, len(key)
    box = SecretBox(key)
    nonce = utils.random(SecretBox.NONCE_SIZE)
    return box.encrypt(plaintext, nonce)


# the Key we expose to callers (Boss, Ordering) is responsible for sorting
# the two messages (got_code and got_pake), then delivering them to
# _SortedKey in the right order.


@attrs
@implementer(_interfaces.IKey)
class Key:
    _appid = attrib(validator=instance_of(str))
    _versions = attrib(validator=instance_of(dict))
    _side = attrib(validator=instance_of(str))
    _timing = attrib(validator=provides(_interfaces.ITiming))
    m = MethodicalMachine()
    set_trace = getattr(m, "_setTrace", lambda self, f: None)  # pragma: no cover

    def __attrs_post_init__(self):
        self._SK = _SortedKey(self._appid, self._versions, self._side, self._timing)
        self._debug_pake_stashed = False  # for tests

    def wire(self, boss, mailbox, receive, order):
        self._SK.wire(boss, mailbox, receive, order)

    @m.state(initial=True)
    def S00(self):
        pass  # pragma: no cover

    @m.state()
    def S01(self):
        pass  # pragma: no cover

    @m.state()
    def S10(self):
        pass  # pragma: no cover

    @m.state()
    def S11(self):
        pass  # pragma: no cover

    @m.input()
    def got_code(self, code):
        pass

    @m.input()
    def got_pake(self, body):
        pass

    @m.output()
    def stash_pake(self, body):
        self._pake = body
        self._debug_pake_stashed = True

    @m.output()
    def deliver_code(self, code):
        self._SK.got_code(code)

    @m.output()
    def deliver_pake(self, body):
        self._SK.got_pake(body)

    @m.output()
    def deliver_code_and_stashed_pake(self, code):
        self._SK.got_code(code)
        self._SK.got_pake(self._pake)

    S00.upon(got_code, enter=S10, outputs=[deliver_code])
    S10.upon(got_pake, enter=S11, outputs=[deliver_pake])
    S00.upon(got_pake, enter=S01, outputs=[stash_pake])
    S01.upon(got_code, enter=S11, outputs=[deliver_code_and_stashed_pake])
    S11.upon(got_pake, enter=S11, outputs=[deliver_pake])


@attrs
class _SortedKey:
    _appid = attrib(validator=instance_of(str))
    _versions = attrib(validator=instance_of(dict))
    _side = attrib(validator=instance_of(str))
    _timing = attrib(validator=provides(_interfaces.ITiming))
    m = MethodicalMachine()
    set_trace = getattr(m, "_setTrace", lambda self, f: None)  # pragma: no cover

    def wire(self, boss, mailbox, receive, order):
        self._B = _interfaces.IBoss(boss)
        self._M = _interfaces.IMailbox(mailbox)
        self._R = _interfaces.IReceive(receive)
        self._O = _interfaces.IOrder(order)

    @m.state(initial=True)
    def S0_know_nothing(self):
        pass  # pragma: no cover

    @m.state()
    def S1_know_code(self):
        pass  # pragma: no cover

    @m.state()
    def S2_know_key(self):
        pass  # pragma: no cover

    @m.state(terminal=True)
    def S3_scared(self):
        pass  # pragma: no cover

    # from Boss
    @m.input()
    def got_code(self, code):
        pass

    # from Ordering
    def got_pake(self, body):
        # HYP-423: a hostile relay can forward forged events on the
        # `pake` phase. Anything that fails to parse, fails to find the
        # `pake_v1` key, OR fails SPAKE2.finish() must be reported as
        # not-authenticated to Mailbox so the slot is cleared and the
        # NEXT inbound on this phase is forwarded. Real peer's pake
        # eventually lands.
        assert isinstance(body, bytes), type(body)
        try:
            payload = bytes_to_dict(body)
        except Exception:
            self._on_bad_pake()
            return
        if not isinstance(payload, dict) or "pake_v1" not in payload:
            self._on_bad_pake()
            return
        try:
            msg2 = hexstr_to_bytes(payload["pake_v1"])
        except Exception:
            self._on_bad_pake()
            return
        try:
            with self._timing.add("pake2", waiting="crypto"):
                key = self._sp.finish(msg2)
        except Exception:
            # SPAKE2 instances are single-use even on failure; rebuild
            # from the remembered code so the real peer's later pake can
            # still complete.
            self._sp = SPAKE2_Symmetric(
                to_bytes(self._code), idSymmetric=to_bytes(self._appid)
            )
            self._sp.start()
            self._on_bad_pake()
            return
        self.got_pake_good(key)

    def _on_bad_pake(self):
        self._M.peer_message_not_authenticated("pake")
        self.got_pake_bad()

    @m.input()
    def got_pake_good(self, key):
        pass

    @m.input()
    def got_pake_bad(self):
        pass

    @m.output()
    def build_pake(self, code):
        with self._timing.add("pake1", waiting="crypto"):
            self._sp = SPAKE2_Symmetric(
                to_bytes(code), idSymmetric=to_bytes(self._appid)
            )
            msg1 = self._sp.start()
        body = dict_to_bytes({"pake_v1": bytes_to_hexstr(msg1)})
        self._M.add_message("pake", body)

    @m.output()
    def scared(self):
        self._B.scared()

    @m.output()
    def compute_key(self, key):
        assert isinstance(key, bytes)
        # HYP-423 ordering: set R.got_key BEFORE peer_message_authenticated
        # so that any incoming non-pake events triggered by the auth
        # callback's redrain (the drain re-publishes our pake, which the
        # peer may answer with a `version` event in the same synchronous
        # chain) find R already keyed. If we called peer_message_*
        # first, A's redrain would chain through to B which would
        # publish version, and that version would land at B's R (still
        # keyless) before this compute_key finished setting B.R.got_key.
        # B.got_key transitions Boss's state machine and stays synchronous
        # so ordering with downstream `happy`/`got_verifier`/`got_message`
        # transitions is preserved. The *user-facing* notification
        # (`self._wormhole.got_key(key)`) is what's re-entrancy-prone, and
        # Boss routes it through the eventual queue (see _boss.W_got_key).
        self._B.got_key(key)
        phase = "version"
        data_key = derive_phase_key(key, self._side, phase)
        plaintext = dict_to_bytes(self._versions)
        encrypted = encrypt_data(data_key, plaintext)
        # R.got_key only records the key on Receive — no user Deferreds
        # fire from it directly, and the peer's reply or our self-echo of
        # the version message may arrive immediately, so Receive must
        # already have the key to decrypt.
        self._R.got_key(key)
        # HYP-423: now Order can transition S0_no_pake → S1_yes_pake
        # and drain queued non-pake events. Doing this AFTER R.got_key
        # ensures any drained events find R keyed.
        self._O.pake_confirmed()
        # And tell Mailbox the auth verdict so the phase slot is moved
        # from pending → processed and the redrain side-effect fires.
        self._M.peer_message_authenticated("pake")
        self._M.add_message(phase, encrypted)

    @m.output()
    def remember_code(self, code):
        # HYP-423: stash the code so we can rebuild the SPAKE2 instance
        # if SPAKE2.finish() raises on a forged msg2 (one-shot instance).
        self._code = code

    S0_know_nothing.upon(
        got_code, enter=S1_know_code, outputs=[remember_code, build_pake]
    )
    S1_know_code.upon(got_pake_good, enter=S2_know_key, outputs=[compute_key])
    # HYP-423: a single bad pake does NOT poison the wormhole. We stay
    # in S1_know_code so the next pake (likely the real peer's) gets a
    # chance.
    S1_know_code.upon(got_pake_bad, enter=S1_know_code, outputs=[])
    S2_know_key.upon(got_pake_good, enter=S2_know_key, outputs=[])
    S2_know_key.upon(got_pake_bad, enter=S2_know_key, outputs=[])
