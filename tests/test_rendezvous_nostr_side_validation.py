"""
HYP-454: validate the inbound 's' tag at rendezvous ingress.

A malicious relay can craft an event with a non-ASCII or otherwise
malformed `s` (side) tag. Without ingress validation, the tag flows
through to `_receive.py` → `derive_phase_key`, which calls
`side.encode("ascii")` and raises UnicodeEncodeError BEFORE the
auth-failure handler `peer_message_not_authenticated()` runs. The
phase remains in Mailbox._pending_phases; the real peer's later
authenticated message is silently dropped as "already pending."

The fix: validate the side at the rendezvous-ingress boundary.
The locally-generated side is `os.urandom(5)` hex (10 lowercase
hex chars per `bytes_to_hexstr`), so the regex `^[0-9a-f]{10}$`
matches the local format exactly. Any non-conforming side is
either a non-conforming peer or a malicious relay; either way
drop before reaching the key-derivation site.
"""

import base64

import pytest

from takeit._rendezvous_nostr import (
    TAKEIT_KIND,
    _is_valid_side,
)

from .test_rendezvous_nostr import _set_active_subscription, _wired

# --- Unit pin: regex shape ---


def test_is_valid_side_accepts_local_format():
    """The locally-generated side format must validate."""
    for ok in (
        "0123456789",
        "abcdef0123",
        "ffffffffff",
        "0000000000",
        "deadbeef00",
    ):
        assert _is_valid_side(ok), f"{ok!r} should be valid"


def test_is_valid_side_rejects_non_conforming():
    """Anything that doesn't match the local format must be rejected:
    uppercase, non-hex, wrong length, non-string types, non-ASCII."""
    for bad in (
        # Length wrong
        "",
        "0",
        "012345678",  # 9 chars
        "01234567890",  # 11 chars
        # Case wrong
        "ABCDEF0123",
        "AaBbCcDdEe",
        # Non-hex
        "thisistext",
        "their-side",
        "0123456789abcdef",
        # Whitespace
        "0123 56789",
        "0123456789 ",
        " 123456789",
        "0123456789\n",
        # Non-ASCII (the canonical wedge attack)
        "\xff\xff\xff\xff\xff",
        "ÿÿÿÿÿÿÿÿÿÿ",
        "0123456789‮",  # right-to-left override
        # Wrong type
        None,
        42,
        b"0123456789",  # bytes, not str
        ["0123456789"],
    ):
        assert not _is_valid_side(bad), f"{bad!r} should be invalid"


# --- Integration: malformed side at ingress dropped ---


def _build_event_with_side(side, phase="pake"):
    """Build a real Nostr event with the given side. We bypass any
    helper that might pre-validate so we can test the ingress."""
    from nostr_sdk import EventBuilder, Keys, Kind, Tag

    body = b"some-body"
    content = base64.b64encode(body).decode("ascii")
    builder = EventBuilder(Kind(TAKEIT_KIND), content).tags(
        [
            Tag.parse(["t", "tagX"]),
            Tag.parse(["s", side]),
            Tag.parse(["p", phase]),
        ]
    )
    keys = Keys.generate()
    return builder.sign_with_keys(keys)


@pytest.mark.parametrize(
    "bad_side",
    [
        "ÿÿÿÿÿÿÿÿÿÿ",  # 10 chars but non-ASCII
        "their-side",  # contains hyphen, common testing string
        "ABCDEF0123",  # uppercase
        "0123456789abcdef",  # 16 chars
        "012345678",  # 9 chars (off by one)
        "0123 56789",  # contains space
        "01234567z9",  # contains non-hex 'z'
    ],
)
def test_inbound_with_invalid_side_dropped_before_mailbox(bad_side):
    """The whole point of HYP-454: a malformed side at ingress must NOT
    reach Mailbox.rx_message. Pre-fix, the event would be forwarded
    and crash downstream in derive_phase_key."""
    rv, _boss, mailbox, _t = _wired()
    sub_id = _set_active_subscription(rv)
    event = _build_event_with_side(bad_side)
    rv._deliver_inbound(event, sub_id)
    assert not any(e[0] == "rx_message" for e in mailbox.events), (
        f"event with side={bad_side!r} should not have reached mailbox"
    )


def test_inbound_with_valid_side_reaches_mailbox():
    """Negative control: a well-formed side proceeds through to
    Mailbox.rx_message, exercising the happy path."""
    rv, _boss, mailbox, _t = _wired()
    sub_id = _set_active_subscription(rv)
    event = _build_event_with_side("0123456789")
    rv._deliver_inbound(event, sub_id)
    rx_messages = [e for e in mailbox.events if e[0] == "rx_message"]
    assert len(rx_messages) == 1
    assert rx_messages[0][1] == "0123456789"  # side value preserved
    assert rx_messages[0][2] == "pake"  # phase preserved


def test_invalid_side_does_not_wedge_phase():
    """Specific scenario the finding describes: a malicious relay
    sends a non-ASCII s tag. Pre-fix this would raise UnicodeEncodeError
    in derive_phase_key, leaving the phase entry pending. Post-fix
    the event is dropped at ingress, so a subsequent VALID event for
    the same phase from the real peer is delivered normally."""
    rv, _boss, mailbox, _t = _wired()
    sub_id = _set_active_subscription(rv)

    # Step 1: malicious event with non-ASCII side
    bad_event = _build_event_with_side("ÿÿÿÿÿÿÿÿÿÿ")
    rv._deliver_inbound(bad_event, sub_id)

    # Step 2: legitimate event from real peer for the same phase
    good_event = _build_event_with_side("0123456789", phase="pake")
    rv._deliver_inbound(good_event, sub_id)

    # The good message reached the mailbox; the wedge attack failed.
    rx_messages = [e for e in mailbox.events if e[0] == "rx_message"]
    assert len(rx_messages) == 1, (
        f"expected only the legitimate rx_message; got {mailbox.events}"
    )
    assert rx_messages[0][1] == "0123456789"
