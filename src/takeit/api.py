"""
Public takeit API: `takeit.create(...)` and the two wormhole modes.

Two modes match upstream wormhole:
- **Deferred mode** (default): `w.get_code()`, `w.get_message()`, etc.
  return Twisted Deferreds that fire when the corresponding event arrives.
- **Delegate mode**: pass `delegate=app`; the app's `wormhole_got_code`,
  `wormhole_got_message`, etc. are called as events occur. Better for
  journaled or event-driven application architectures.

Construction goes through `takeit.create(...)`; both modes plumb identical
state through `Boss` and only differ in how inbound events are surfaced.
"""

import os
import sys

from attr import attrib, attrs
from twisted.internet.task import Cooperator
from twisted.python import failure
from zope.interface import implementer

from . import _interfaces
from ._boss import Boss
from ._dilation.connector import Connector
from ._dilation.manager import DILATION_VERSIONS
from ._key import derive_key
from .errors import (
    LegacyVerifierNotChecked,
    LegacyWordsRequiresAcknowledgement,
    NoKeyError,
    WormholeClosed,
)
from .eventual import EventualQueue
from .observer import OneShotObserver, SequenceObserver
from .timing import DebugTiming
from .util import SIDE_BYTE_LENGTH, bytes_to_hexstr, to_bytes

# Hardcoded shortlist of well-known public Nostr relays. Override via
# `relays=[...]` to takeit.create(), or via `--relay` on the CLI. These are
# only contacted for introduction; they never carry file bytes.
DEFAULT_RELAYS = (
    "wss://relay.damus.io",
    "wss://nos.lol",
    "wss://relay.nostr.band",
    "wss://relay.snort.social",
)


@attrs
@implementer(_interfaces.IWormhole)
class _DelegatedWormhole:
    _delegate = attrib()

    def __attrs_post_init__(self):
        self._key = None
        # HYP-461: track legacy + verifier-observed for the unsafe-words gate.
        self._is_legacy_words = False
        self._verifier_observed = False

    def _set_boss(self, boss):
        self._boss = boss

    # ---- application-facing methods ----

    def allocate_code(self, code_length=3):
        self._boss.allocate_code(code_length)

    def input_code(self):
        return self._boss.input_code()

    def set_code(self, code):
        """Set a canonical '<locator>:<words>' code. See Boss.set_code
        for the full HYP-443 contract; bare-words callers must use
        set_code_legacy_words explicitly."""
        self._boss.set_code(code)

    def set_code_legacy_words(self, words, *, unsafe_relay_mitm_acknowledged=False):
        """Set a legacy words-only code.

        The rendezvous path is vulnerable to active relay MITM (the tag
        is derived from words alone so a hostile relay can pre-compute
        wordlist^N → tag mappings). HYP-461 requires:

        1. ``unsafe_relay_mitm_acknowledged=True`` — explicit opt-in,
           ensures callers grep-find this dangerous path.
        2. The delegate MUST receive ``wormhole_got_verifier`` and
           verify it out-of-band before this wormhole will accept
           ``send_message()`` or ``dilate()`` calls.

        See Boss.set_code_legacy_words.
        """
        if not unsafe_relay_mitm_acknowledged:
            raise LegacyWordsRequiresAcknowledgement(
                "set_code_legacy_words is vulnerable to active relay "
                "MITM. Pass unsafe_relay_mitm_acknowledged=True to "
                "acknowledge the risk, AND verify the SAS via the "
                "wormhole_got_verifier delegate callback before "
                "exchanging sensitive data. Use set_code(<locator>:<words>) "
                "for MITM-resistant codes instead."
            )
        self._is_legacy_words = True
        self._boss.set_code_legacy_words(words)

    def _check_legacy_verifier_gate(self, op):
        # HYP-461: legacy session must observe the verifier before send/dilate.
        if self._is_legacy_words and not self._verifier_observed:
            raise LegacyVerifierNotChecked(
                f"{op}() refused on legacy words-only session before "
                "the verifier (SAS) was delivered. Wait for the "
                "wormhole_got_verifier delegate callback and verify "
                "the SAS out-of-band first."
            )

    def send_message(self, plaintext):
        self._check_legacy_verifier_gate("send_message")
        self._boss.send(plaintext)

    def derive_key(self, purpose, length):
        """Derive a deterministic purpose-specific key from the master
        SPAKE2 key. Both wormhole peers calling derive_key with the same
        purpose and length get the same bytes. Cannot be called before the
        master key is established (got_key) or after close.
        """
        if not isinstance(purpose, str):
            raise TypeError(type(purpose))
        if not self._key:
            raise NoKeyError()
        return derive_key(self._key, to_bytes(purpose), length)

    def dilate(self, **kwargs):
        self._check_legacy_verifier_gate("dilate")
        return self._boss.dilate(**kwargs)

    def close(self):
        self._boss.close()

    def debug_set_trace(
        self, client_name, which="B M S O K SK R RC I C T", file=sys.stderr
    ):
        self._boss._set_trace(client_name, which, file)

    # ---- inbound (called by Boss) ----

    def got_welcome(self, welcome):
        self._delegate.wormhole_got_welcome(welcome)

    def got_code(self, code):
        self._delegate.wormhole_got_code(code)

    def got_key(self, key):
        self._delegate.wormhole_got_unverified_key(key)
        self._key = key

    def got_verifier(self, verifier):
        # HYP-461: delivering the verifier to the delegate trips the
        # gate. Delegates that don't display/compare the verifier are
        # in the same boat as Deferred-mode callers who don't await
        # get_verifier — both are wrong, but at least we've done our
        # part by surfacing the verifier.
        self._verifier_observed = True
        self._delegate.wormhole_got_verifier(verifier)

    def got_versions(self, versions):
        self._delegate.wormhole_got_versions(versions)

    def received(self, plaintext):
        self._delegate.wormhole_got_message(plaintext)

    def closed(self, result):
        self._delegate.wormhole_closed(result)


@implementer(_interfaces.IWormhole, _interfaces.IDeferredWormhole)
class _DeferredWormhole:
    def __init__(self, reactor, eq):
        self._reactor = reactor
        self._welcome_observer = OneShotObserver(eq)
        self._code_observer = OneShotObserver(eq)
        self._key = None
        self._key_observer = OneShotObserver(eq)
        self._verifier_observer = OneShotObserver(eq)
        self._version_observer = OneShotObserver(eq)
        self._received_observer = SequenceObserver(eq)
        self._closed = False
        self._closed_observer = OneShotObserver(eq)
        # HYP-461: legacy-words gate. set_code_legacy_words sets the
        # first flag; awaiting get_verifier() sets the second; send/
        # dilate require both before proceeding on legacy sessions.
        self._is_legacy_words = False
        self._verifier_observed = False

    def _set_boss(self, boss):
        self._boss = boss

    # ---- application-facing methods ----

    def get_welcome(self):
        return self._welcome_observer.when_fired()

    def get_code(self):
        return self._code_observer.when_fired()

    def get_unverified_key(self):
        return self._key_observer.when_fired()

    def get_verifier(self):
        # HYP-461: the act of asking for the verifier trips the legacy
        # gate. A caller that calls get_verifier() then displays the
        # SAS to the user has done what the gate requires; the gate
        # cannot tell the difference between "displayed and compared"
        # and "displayed and ignored" — the unsafe-flag opt-in already
        # signaled the caller accepts that responsibility.
        self._verifier_observed = True
        return self._verifier_observer.when_fired()

    def get_versions(self):
        return self._version_observer.when_fired()

    def get_message(self):
        return self._received_observer.when_next_event()

    def allocate_code(self, code_length=3):
        self._boss.allocate_code(code_length)

    def input_code(self):
        return self._boss.input_code()

    def set_code(self, code):
        """Set a canonical '<locator>:<words>' code. See Boss.set_code
        for the full HYP-443 contract; bare-words callers must use
        set_code_legacy_words explicitly."""
        self._boss.set_code(code)

    def set_code_legacy_words(self, words, *, unsafe_relay_mitm_acknowledged=False):
        """Set a legacy words-only code.

        The rendezvous path is vulnerable to active relay MITM (the tag
        is derived from words alone so a hostile relay can pre-compute
        wordlist^N → tag mappings). HYP-461 requires:

        1. ``unsafe_relay_mitm_acknowledged=True`` — explicit opt-in,
           ensures callers grep-find this dangerous path.
        2. The caller MUST ``await get_verifier()`` and verify the SAS
           out-of-band before this wormhole will accept
           ``send_message()`` or ``dilate()`` calls.

        See Boss.set_code_legacy_words.
        """
        if not unsafe_relay_mitm_acknowledged:
            raise LegacyWordsRequiresAcknowledgement(
                "set_code_legacy_words is vulnerable to active relay "
                "MITM. Pass unsafe_relay_mitm_acknowledged=True to "
                "acknowledge the risk, AND verify the SAS via "
                "await get_verifier() before exchanging sensitive "
                "data. Use set_code(<locator>:<words>) for "
                "MITM-resistant codes instead."
            )
        self._is_legacy_words = True
        self._boss.set_code_legacy_words(words)

    def _check_legacy_verifier_gate(self, op):
        # HYP-461: legacy session must observe the verifier before send/dilate.
        if self._is_legacy_words and not self._verifier_observed:
            raise LegacyVerifierNotChecked(
                f"{op}() refused on legacy words-only session before "
                "the verifier (SAS) was observed. Await get_verifier() "
                "and compare the SAS out-of-band first."
            )

    def send_message(self, plaintext):
        self._check_legacy_verifier_gate("send_message")
        self._boss.send(plaintext)

    def derive_key(self, purpose, length):
        """See _DelegatedWormhole.derive_key."""
        if not isinstance(purpose, str):
            raise TypeError(type(purpose))
        if not self._key:
            raise NoKeyError()
        return derive_key(self._key, to_bytes(purpose), length)

    def dilate(self, **kwargs):
        self._check_legacy_verifier_gate("dilate")
        return self._boss.dilate(**kwargs)

    def close(self):
        d = self._closed_observer.when_fired()
        if not self._closed:
            self._boss.close()
        return d

    def debug_set_trace(
        self, client_name, which="B M S O K SK R RC I C T", file=sys.stderr
    ):
        self._boss._set_trace(client_name, which, file)

    # ---- inbound (called by Boss) ----

    def got_welcome(self, welcome):
        self._welcome_observer.fire_if_not_fired(welcome)

    def got_code(self, code):
        self._code_observer.fire_if_not_fired(code)

    def got_key(self, key):
        self._key = key
        self._key_observer.fire_if_not_fired(key)

    def got_verifier(self, verifier):
        self._verifier_observer.fire_if_not_fired(verifier)

    def got_versions(self, versions):
        self._version_observer.fire_if_not_fired(versions)

    def received(self, plaintext):
        self._received_observer.fire(plaintext)

    def closed(self, result):
        self._closed = True
        if isinstance(result, Exception):
            f = failure.Failure(result)
            self._closed_observer.error(f)
        else:
            f = failure.Failure(WormholeClosed(result))
            self._closed_observer.fire_if_not_fired(result)
        self._welcome_observer.error(f)
        self._code_observer.error(f)
        self._key_observer.error(f)
        self._verifier_observer.error(f)
        self._version_observer.error(f)
        self._received_observer.fire(f)


def _build_nostr_rendezvous_factory(side, relays):
    """Returns a `rendezvous_factory(boss, mailbox, terminator)` closure
    that constructs a NostrRendezvous bound to the given relays.

    Lives behind a deferred import so that test code passing a custom
    `_rendezvous_factory` doesn't pay the cost of importing nostr-sdk.
    """

    def factory(boss, mailbox, terminator):
        from ._rendezvous_nostr import NostrRendezvous

        rv = NostrRendezvous(side=side, relays=relays)
        rv.wire(boss, mailbox, terminator)
        return rv

    return factory


def create(
    appid,
    reactor,
    *,
    relays=None,
    versions=None,
    delegate=None,
    timing=None,
    on_status_update=None,
    _eventual_queue=None,
    _rendezvous_factory=None,
):
    """Create a takeit Wormhole.

    :param str appid: an application identifier (e.g. ``"takeit/file-xfer"``).
        Both peers must use the same appid; it scopes the SPAKE2 derivation
        so two unrelated apps using the same code don't accidentally meet.
    :param reactor: a Twisted reactor (production: ``twisted.internet.reactor``;
        tests: ``twisted.internet.task.Clock``).
    :param list[str] | None relays: Nostr relay URLs (``wss://...``) for
        introduction. ``None`` uses :data:`DEFAULT_RELAYS`.
    :param dict versions: per-application capabilities sent during the
        wormhole-versions handshake.
    :param delegate: if given, an object whose ``wormhole_*`` methods will
        be called on events; switches the returned wormhole to Delegate mode.
    :param timing: optional ``DebugTiming`` for instrumentation.
    :param on_status_update: optional callback invoked on
        ``WormholeStatus`` changes.

    :returns: a Wormhole. Deferred-mode unless ``delegate`` is given.
    """
    timing = timing or DebugTiming()
    side = bytes_to_hexstr(os.urandom(SIDE_BYTE_LENGTH))
    eq = _eventual_queue or EventualQueue(reactor)
    cooperator = Cooperator(scheduler=eq.eventually)

    if delegate is not None:
        w = _DelegatedWormhole(delegate)
    else:
        w = _DeferredWormhole(reactor, eq)

    wormhole_versions = {
        "can-dilate": DILATION_VERSIONS,
        "dilation-abilities": Connector.get_connection_abilities(),
        "app_versions": versions or {},
    }

    if _rendezvous_factory is None:
        _rendezvous_factory = _build_nostr_rendezvous_factory(
            side, tuple(relays) if relays is not None else DEFAULT_RELAYS
        )

    boss = Boss(
        wormhole=w,
        side=side,
        appid=appid,
        versions=wormhole_versions,
        reactor=reactor,
        eventual_queue=eq,
        cooperator=cooperator,
        timing=timing,
        rendezvous_factory=_rendezvous_factory,
        on_status_update=on_status_update,
    )
    w._set_boss(boss)
    boss.start()
    return w
