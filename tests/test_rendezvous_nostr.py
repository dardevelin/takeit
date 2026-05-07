"""
Unit tests for NostrRendezvous bridge logic.

These tests mock `nostr_sdk.Client` to verify the bridge issues the right
async calls in the right order. They do NOT exercise a real Nostr relay —
that is the responsibility of the integration tests further down (skipped
unless a real relay is configured via TAKEIT_TEST_RELAY env var).
"""

import asyncio
import base64
import os
from unittest.mock import MagicMock

import pytest
from zope.interface import implementer

from takeit import _interfaces
from takeit._rendezvous_nostr import (
    DEFAULT_POW_DIFFICULTY,
    TAKEIT_KIND,
    NostrRendezvous,
)


@implementer(_interfaces.IBoss)
class _Boss:
    def __init__(self):
        self.welcomes = []
        self.errors = []
        self._side = "sssssssss"

    def rx_welcome(self, w):
        self.welcomes.append(w)

    def error(self, e):
        self.errors.append(e)


@implementer(_interfaces.IMailbox)
class _Mailbox:
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
class _Terminator:
    def __init__(self):
        self.stopped = False

    def stoppedRC(self):
        self.stopped = True


def _wired(side="sssssssss", relays=("wss://example.invalid",)):
    boss = _Boss()
    boss._side = side
    mailbox = _Mailbox()
    term = _Terminator()
    rv = NostrRendezvous(side=side, relays=relays, pow_difficulty=0)
    rv.wire(boss, mailbox, term)
    return rv, boss, mailbox, term


# --- construction-time validation ---


def test_requires_at_least_one_relay():
    with pytest.raises(ValueError):
        NostrRendezvous(side="x", relays=())


def test_pow_difficulty_defaults_to_16_when_unspecified():
    rv = NostrRendezvous(side="x", relays=("wss://r",))
    assert rv._pow_difficulty == DEFAULT_POW_DIFFICULTY


# --- bridge logic with mocked nostr-sdk Client ---


class _AsyncMockClient:
    """Stand-in for nostr_sdk.Client recording the calls we make."""

    def __init__(self):
        self.added_relays = []
        self.connected = False
        self.shutdown_called = False
        self.subscribe_calls = []
        self.unsubscribe_calls = []
        self.published_builders = []
        self.handle_notifications_started = False
        self._handler = None

    async def add_relay(self, url):
        self.added_relays.append(url)

    async def connect(self):
        self.connected = True

    async def shutdown(self):
        self.shutdown_called = True

    async def subscribe(self, filters, opts):
        sub_id = f"sub-{len(self.subscribe_calls)}"
        self.subscribe_calls.append((filters, opts))
        out = MagicMock()
        out.id = sub_id
        return out

    async def unsubscribe(self, sub_id):
        self.unsubscribe_calls.append(sub_id)

    async def send_event_builder(self, builder):
        self.published_builders.append(builder)
        out = MagicMock()
        return out

    async def handle_notifications(self, handler):
        self.handle_notifications_started = True
        self._handler = handler
        # Block forever (mimics real behavior). The test will trigger
        # specific callbacks via the recorded handler reference.
        await asyncio.Event().wait()


@pytest.fixture
def mock_client(monkeypatch):
    """Patch nostr_sdk.Client so it returns an _AsyncMockClient.

    Keys/NostrSigner/EventBuilder/Filter still come from the real library —
    we only swap the network-touching Client.
    """
    inst = _AsyncMockClient()

    class _ClientFactory:
        def __call__(self, signer):
            return inst

    monkeypatch.setattr("takeit._rendezvous_nostr.NostrRendezvous", NostrRendezvous)
    # Patch the deferred import inside _async_start.
    import nostr_sdk

    monkeypatch.setattr(nostr_sdk, "Client", _ClientFactory())
    return inst


@pytest.mark.asyncio
async def test_start_connects_to_all_relays_and_emits_welcome(mock_client):
    relays = ("wss://r1", "wss://r2", "wss://r3")
    rv, boss, mailbox, _ = _wired(relays=relays)

    # Drive the async-start coroutine directly (in a real reactor it would
    # be scheduled via ensureDeferred from rv.start()).
    await rv._async_start()

    assert sorted(mock_client.added_relays) == sorted(relays)
    assert mock_client.connected
    assert boss.welcomes == [{}]
    assert ("connected",) in mailbox.events


@pytest.mark.asyncio
async def test_subscribe_uses_kind_and_t_tag_filter(mock_client):
    rv, _, _, _ = _wired()
    await rv._async_start()
    await rv._async_subscribe("the-tag-here-here")

    assert len(mock_client.subscribe_calls) == 1
    filters, _opts = mock_client.subscribe_calls[0]
    assert len(filters) == 1
    # The filter should be JSON-serializable to verify shape.
    f = filters[0]
    serialized = f.as_json()
    assert "21420" in serialized  # kind
    assert "the-tag-here-here" in serialized  # tag value
    assert '"#t"' in serialized  # filter on `t` tag


@pytest.mark.asyncio
async def test_publish_includes_t_s_p_tags_and_content(mock_client):
    rv, _, _, _ = _wired(side="myhexside")
    await rv._async_start()
    await rv._async_subscribe("tag123")
    await rv._async_publish("pake", b"binary-payload")

    assert len(mock_client.published_builders) == 1
    builder = mock_client.published_builders[0]
    # Build the event so we can inspect the tags structurally.
    from nostr_sdk import Keys

    event = builder.sign_with_keys(Keys.generate())
    tag_kvs = [t.as_vec()[:2] for t in event.tags().to_vec() if len(t.as_vec()) >= 2]
    assert ["t", "tag123"] in tag_kvs
    assert ["s", "myhexside"] in tag_kvs
    assert ["p", "pake"] in tag_kvs

    # Content is base64 of body.
    assert event.content() == base64.b64encode(b"binary-payload").decode()
    # Kind is takeit's ephemeral kind.
    assert event.kind().as_u16() == TAKEIT_KIND


@pytest.mark.asyncio
async def test_unsubscribe_calls_client(mock_client):
    rv, _, _, _ = _wired()
    await rv._async_start()
    await rv._async_subscribe("tag")
    await rv._async_unsubscribe()
    assert mock_client.unsubscribe_calls == ["sub-0"]


@pytest.mark.asyncio
async def test_stop_shuts_down_client_and_emits_lost(mock_client):
    rv, _, mailbox, _ = _wired()
    await rv._async_start()
    await rv._async_stop()
    assert mock_client.shutdown_called
    assert ("lost",) in mailbox.events


# --- inbound delivery from a Nostr event ---


def _build_event(side, phase, body, our_signer_keys=None):
    """Build a real Nostr Event object for inbound-delivery tests."""
    from nostr_sdk import EventBuilder, Keys, Kind, Tag

    keys = our_signer_keys or Keys.generate()
    builder = EventBuilder(
        Kind(TAKEIT_KIND), base64.b64encode(body).decode("ascii")
    ).tags(
        [
            Tag.parse(["t", "tagX"]),
            Tag.parse(["s", side]),
            Tag.parse(["p", phase]),
        ]
    )
    return builder.sign_with_keys(keys)


def test_deliver_inbound_passes_through_to_mailbox():
    rv, _, mailbox, _ = _wired()
    event = _build_event("their-side", "pake", b"some-body")
    rv._deliver_inbound(event)
    assert ("rx_message", "their-side", "pake", b"some-body") in mailbox.events


def test_deliver_inbound_accepts_known_phases():
    """All wormhole control-channel phase strings are accepted."""
    rv, _, mailbox, _ = _wired()
    for phase in (
        "pake",
        "version",
        "0",
        "42",
        "1234567890",
        "dilate-0",
        "dilate-3",
        "dilate-9999",
    ):
        event = _build_event("their-side", phase, b"x")
        rv._deliver_inbound(event)
    assert sum(1 for e in mailbox.events if e[0] == "rx_message") == 8


def test_deliver_inbound_drops_invalid_phases():
    """Malformed phase strings are dropped before reaching Mailbox; this
    is the defense-in-depth layer for the Mailbox redrain DoS."""
    rv, _, mailbox, _ = _wired()
    # All invalid: not in {pake, version}, not numeric, not dilate-N.
    for bad_phase in (
        "../etc/passwd",
        "abcde",
        "PAKE",
        "Pake",
        "pake-version",
        "1.0",
        "0x123",
        "phase " * 100,
        "p" * 1000,
        "dilate-",
        "dilate-x",
        "X" * 100,
    ):
        event = _build_event("their-side", bad_phase, b"x")
        rv._deliver_inbound(event)
    # No rx_message events delivered for any of those invalid phases.
    assert not any(e[0] == "rx_message" for e in mailbox.events)


def test_is_valid_phase_unit():
    """Pin the regex shape directly, not just through the event flow."""
    from takeit._rendezvous_nostr import _is_valid_phase

    for ok in ("pake", "version", "0", "1234567890", "dilate-0", "dilate-9999"):
        assert _is_valid_phase(ok), f"{ok!r} should be valid"
    for bad in (
        "",
        "PAKE",
        "pake ",
        " pake",
        "pake\n",
        "abc",
        "12345678901",
        "dilate-",
        "dilate-12345678901",
        "dilate",
        "dilate-x",
        "../bad",
    ):
        assert not _is_valid_phase(bad), f"{bad!r} should be invalid"


def test_deliver_inbound_drops_event_missing_tags():
    """Defense in depth: an event without our s/p tags is logged-and-ignored
    rather than raising."""
    from nostr_sdk import EventBuilder, Keys, Kind

    rv, _, mailbox, _ = _wired()
    # No s/p tags
    event = EventBuilder(Kind(TAKEIT_KIND), "ZGF0YQ==").sign_with_keys(Keys.generate())
    rv._deliver_inbound(event)
    assert mailbox.events == []  # nothing delivered


# --- integration test (skipped without a real relay) ---


@pytest.mark.skipif(
    not os.environ.get("TAKEIT_TEST_RELAY"),
    reason="set TAKEIT_TEST_RELAY=wss://... to run real-relay integration",
)
@pytest.mark.asyncio
async def test_integration_two_nostr_rendezvous_meet():  # pragma: no cover
    """Two NostrRendezvous instances using the same tag exchange events.

    Skipped by default. Set TAKEIT_TEST_RELAY=wss://relay.example to run.
    """
    relay = os.environ["TAKEIT_TEST_RELAY"]
    rv_a, _, mb_a, _ = _wired(side="sideAAAA", relays=(relay,))
    rv_b, _, mb_b, _ = _wired(side="sideBBBB", relays=(relay,))
    await rv_a._async_start()
    await rv_b._async_start()
    await rv_a._async_subscribe("integration-test-tag-xyz")
    await rv_b._async_subscribe("integration-test-tag-xyz")
    rv_a._tag = "integration-test-tag-xyz"  # would normally be set by tx_open
    rv_b._tag = "integration-test-tag-xyz"
    await rv_a._async_publish("hello", b"from-a")
    # Give the relay a moment to deliver
    await asyncio.sleep(2.0)
    received = [e for e in mb_b.events if e[0] == "rx_message"]
    assert any(
        ev[1] == "sideAAAA" and ev[2] == "hello" and ev[3] == b"from-a"
        for ev in received
    ), f"expected rx_message in {mb_b.events}"
    await rv_a._async_stop()
    await rv_b._async_stop()
