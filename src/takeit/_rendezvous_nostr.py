"""
Nostr-backed IRendezvous implementation.

Bridges Twisted (Boss / Mailbox / Terminator) to nostr-sdk's asyncio API.

Wire format (kind 21420, ephemeral range 20000-29999):
    tags = [
        ["t", <derived_tag>],   # NIP-01 single-letter tag for filter routing
        ["s", <our_side>],      # the takeit side string (hex)
        ["p", <phase>],         # the wormhole phase ("pake" / "version" / "0" / ...)
    ]
    content = base64.b64encode(body).decode("ascii")

The Nostr event signature provides authenticity for the *publisher* (a fresh
ephemeral keypair per session — no long-term identity), but real authentication
of the wormhole peer is provided by SPAKE2 over the body. The relay operator
sees only encrypted phase payloads keyed on the blinded tag.

Concurrency model:
- The Twisted reactor and asyncio event loop are unified via
  `twisted.internet.asyncioreactor` in production; setup is the caller's
  responsibility (takeit.api.create() expects a reactor that has already
  been installed).
- Outbound IRendezvous calls (start/stop/tx_*) are synchronous; each
  schedules an `ensureDeferred(coroutine)` that runs the underlying
  nostr-sdk async work and errbacks via `_B.error` on failure.
- Inbound notifications come from `client.handle_notifications(...)`,
  whose handlers run on the asyncio loop (= the Twisted reactor) and can
  call into `_M.rx_message` directly.
"""
import base64
import re

from twisted.internet import defer
from twisted.python import log
from zope.interface import implementer

from . import _interfaces


# Whitelist of valid phase strings on the wormhole control channel. The
# rendezvous drops events with anything else BEFORE they reach Mailbox —
# defense-in-depth against a malicious peer flooding distinct phase
# values to amplify the Mailbox redrain.
_PHASE_RE = re.compile(r"^(pake|version|\d{1,10}|dilate-\d{1,10})$")


def _is_valid_phase(phase):
    """True iff `phase` is one of the wormhole's known control phases."""
    return isinstance(phase, str) and bool(_PHASE_RE.fullmatch(phase))


# Nostr ephemeral kind: relays must NOT persist these. NIP-16.
TAKEIT_KIND = 21420

# NIP-13 proof-of-work difficulty. 16 is cheap (~ms to mine on a laptop)
# and deters incidental spam without burdening real users.
DEFAULT_POW_DIFFICULTY = 16


@implementer(_interfaces.IRendezvousConnector)
class NostrRendezvous:
    """
    Production Nostr-based rendezvous. Constructed by
    `takeit.api._build_nostr_rendezvous_factory`; users never see this class.

    Parameters
    ----------
    side : str
        The takeit side string for this client (hex, set by Boss).
    relays : tuple[str, ...]
        Nostr relay URLs (`wss://...`) for introduction.
    pow_difficulty : int
        NIP-13 proof-of-work difficulty for outbound events. Default 16.
    """

    def __init__(self, side, relays, pow_difficulty=DEFAULT_POW_DIFFICULTY):
        if not relays:
            raise ValueError("at least one relay URL required")
        self._side = side
        self._relays = tuple(relays)
        self._pow_difficulty = pow_difficulty

        self._client = None  # lazily built in start()
        self._tag = None
        self._subscription_id = None
        self._notification_task = None
        self._started = False
        self._connected = False

        # Wired-in peers (filled by .wire())
        self._B = None
        self._M = None
        self._T = None

    # ---- IRendezvous outbound surface ----

    def wire(self, boss, mailbox, terminator):
        self._B = _interfaces.IBoss(boss)
        self._M = _interfaces.IMailbox(mailbox)
        self._T = _interfaces.ITerminator(terminator)

    def start(self):
        assert not self._started, "start() called twice"
        self._started = True
        d = defer.ensureDeferred(self._async_start())
        d.addErrback(self._on_async_error, "start")

    def stop(self):
        assert self._started, "stop() before start()"
        d = defer.ensureDeferred(self._async_stop())
        d.addErrback(self._on_async_error, "stop")
        d.addBoth(lambda _: self._T.stoppedRC())

    def tx_open(self, tag):
        assert self._connected, "tx_open while disconnected"
        d = defer.ensureDeferred(self._async_subscribe(tag))
        d.addErrback(self._on_async_error, "tx_open")

    def tx_add(self, phase, body):
        assert self._connected, "tx_add while disconnected"
        assert self._tag, "tx_add before tx_open"
        d = defer.ensureDeferred(self._async_publish(phase, body))
        d.addErrback(self._on_async_error, "tx_add")

    def tx_close(self, tag, mood):
        assert self._connected, "tx_close while disconnected"
        d = defer.ensureDeferred(self._async_unsubscribe())
        d.addErrback(self._on_async_error, "tx_close")
        # Nostr has no close-ack; synthesize one immediately so Mailbox's
        # state machine completes. Fire on the next reactor turn so we don't
        # re-enter the state machine that's still processing tx_close.
        from twisted.internet import reactor
        reactor.callLater(0, self._M.rx_closed)

    # ---- async helpers (run on the asyncio/Twisted loop) ----

    async def _async_start(self):
        # Imports are deferred so a test that bypasses NostrRendezvous via
        # `_rendezvous_factory=` doesn't pay the cost of loading nostr-sdk.
        from nostr_sdk import Client, Keys, NostrSigner

        # Fresh ephemeral keypair per session — no on-disk persistence,
        # no long-term identity. Authenticity of the wormhole peer comes
        # from SPAKE2 over the body, not the Nostr signature.
        signer_keys = Keys.generate()
        signer = NostrSigner.keys(signer_keys)
        self._client = Client(signer)

        for url in self._relays:
            await self._client.add_relay(url)
        await self._client.connect()

        self._connected = True
        # Synthesize a welcome dict so Boss's state machine progresses.
        self._B.rx_welcome({})
        self._M.connected()

    async def _async_stop(self):
        if self._connected:
            self._connected = False
            try:
                self._M.lost()
            except Exception as e:  # pragma: no cover
                log.err(e)
        if self._client is not None:
            try:
                await self._client.shutdown()
            except Exception as e:  # pragma: no cover
                log.err(e)

    async def _async_subscribe(self, tag):
        from nostr_sdk import Filter, Kind, Timestamp

        self._tag = tag
        filt = (
            Filter()
            .kind(Kind(TAKEIT_KIND))
            .hashtag(tag)
            .since(Timestamp.now())
        )
        # Subscribe; nostr-sdk returns an Output with subscription id.
        output = await self._client.subscribe([filt], None)
        self._subscription_id = output.id

        # Spawn the notification handler if not already running. It runs
        # forever until shutdown.
        if self._notification_task is None:
            handler = _Handler(self)
            self._notification_task = defer.ensureDeferred(
                self._client.handle_notifications(handler))
            self._notification_task.addErrback(
                self._on_async_error, "handle_notifications")

    async def _async_unsubscribe(self):
        if self._subscription_id is not None:
            try:
                await self._client.unsubscribe(self._subscription_id)
            except Exception as e:  # pragma: no cover
                log.err(e)
            self._subscription_id = None

    async def _async_publish(self, phase, body):
        from nostr_sdk import EventBuilder, Kind, Tag

        content = base64.b64encode(body).decode("ascii")
        builder = EventBuilder(Kind(TAKEIT_KIND), content).tags([
            Tag.parse(["t", self._tag]),
            Tag.parse(["s", self._side]),
            Tag.parse(["p", phase]),
        ])
        if self._pow_difficulty > 0:
            builder = builder.pow(self._pow_difficulty)
        await self._client.send_event_builder(builder)

    # ---- inbound from Nostr (called from _Handler) ----

    def _deliver_inbound(self, event):
        """Route a received Nostr event to Mailbox.rx_message.

        Drops events with malformed/unknown phase strings before they
        reach Mailbox — defense against a peer (or attacker) sending
        events with arbitrarily-many distinct ``p`` tag values to
        amplify the Mailbox redrain.
        """
        side = None
        phase = None
        for tag in event.tags().to_vec():
            vec = tag.as_vec()
            if len(vec) >= 2 and vec[0] == "s":
                side = vec[1]
            elif len(vec) >= 2 and vec[0] == "p":
                phase = vec[1]
        if side is None or phase is None:
            log.err(ValueError(
                "takeit: received Nostr event missing s/p tags; ignoring"))
            return
        if not _is_valid_phase(phase):
            log.msg(
                f"takeit: dropping inbound event with invalid phase: {phase!r}")
            return
        try:
            body = base64.b64decode(event.content())
        except Exception as e:
            log.err(e)
            return
        self._M.rx_message(side, phase, body)

    # ---- error sink ----

    def _on_async_error(self, failure_, where):
        log.err(failure_, f"NostrRendezvous async error in {where}")
        try:
            self._B.error(failure_.value)
        except Exception as e:  # pragma: no cover
            log.err(e)


class _Handler:
    """Adapter from nostr-sdk's HandleNotification to NostrRendezvous.

    Cannot subclass `nostr_sdk.HandleNotification` directly with arbitrary
    Python state because the binding wants UniFFI subclassing semantics; the
    safer pattern is a duck-typed handler matching the protocol.
    """

    def __init__(self, rv):
        self._rv = rv

    async def handle(self, relay_url, subscription_id, event):
        try:
            self._rv._deliver_inbound(event)
        except Exception as e:  # pragma: no cover
            log.err(e)

    async def handle_msg(self, relay_url, msg):  # pragma: no cover
        # We don't currently need raw RelayMessage inspection.
        return None
