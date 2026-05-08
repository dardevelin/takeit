"""
Tests for takeit.api — the public create() entry point and its two
wormhole modes (Deferred and Delegated).
"""

import pytest
from twisted.internet.task import Clock
from zope.interface import implementer

import takeit
from takeit import _interfaces
from takeit.eventual import EventualQueue
from tests._fake_rendezvous import FakeRendezvous, pair

# --- shared fixtures ---


def _make_wormhole_pair(*, delegate_a=None, delegate_b=None, code_length=3, **kwargs):
    """Build two paired wormholes via FakeRendezvous, ready for handshake."""
    eq = EventualQueue(Clock())
    rv_a = FakeRendezvous("aaaaaa")
    rv_b = FakeRendezvous("bbbbbb")
    pair(rv_a, rv_b)

    def factory_a(boss, mailbox, terminator):
        rv_a.wire(boss, mailbox, terminator)
        return rv_a

    def factory_b(boss, mailbox, terminator):
        rv_b.wire(boss, mailbox, terminator)
        return rv_b

    a = takeit.create(
        appid="takeit/test",
        reactor=Clock(),
        relays=None,
        delegate=delegate_a,
        _eventual_queue=eq,
        _rendezvous_factory=factory_a,
        **kwargs,
    )
    b = takeit.create(
        appid="takeit/test",
        reactor=Clock(),
        relays=None,
        delegate=delegate_b,
        _eventual_queue=eq,
        _rendezvous_factory=factory_b,
        **kwargs,
    )
    return eq, a, b


def _flush(eq):
    eq.flush_sync()


# --- create() basics ---


def test_create_returns_a_deferred_wormhole_by_default():
    """No delegate -> Deferred-mode wormhole supporting get_code() etc."""
    eq, a, _ = _make_wormhole_pair()
    assert hasattr(a, "get_code")
    assert hasattr(a, "send_message")


def test_create_returns_delegated_wormhole_when_delegate_given():
    """delegate=app -> Delegated-mode wormhole; no get_*() methods."""

    @implementer(_interfaces.IWormholeDelegate)
    class Delegate:
        def wormhole_got_welcome(self, w):
            pass

        def wormhole_got_code(self, c):
            pass

        def wormhole_got_unverified_key(self, k):
            pass

        def wormhole_got_verifier(self, v):
            pass

        def wormhole_got_versions(self, vs):
            pass

        def wormhole_got_message(self, p):
            pass

        def wormhole_closed(self, r):
            pass

    eq, a, _ = _make_wormhole_pair(delegate_a=Delegate())
    assert not hasattr(a, "get_code")
    assert hasattr(a, "send_message")


# --- Deferred mode end-to-end ---


def _resolve(eq, d):
    """Flush the queue and return a Deferred's result, asserting it fired."""
    eq.flush_sync()
    assert d.called, "expected Deferred to have fired"
    return d.result


def test_deferred_mode_full_handshake_and_message_exchange():
    """Two Deferred wormholes meet, exchange a message, and close happy."""
    eq, a, b = _make_wormhole_pair()

    a.allocate_code()
    code_d = a.get_code()
    code = _resolve(eq, code_d)
    assert isinstance(code, str)
    # Post-HYP-406 shape: <26-base32-locator>:<word1-word2-word3>
    assert code.count(":") == 1
    assert code.split(":", 1)[1].count("-") == 2

    b.set_code(code)
    _flush(eq)

    # Both should have keys.
    key_a = _resolve(eq, a.get_unverified_key())
    key_b = _resolve(eq, b.get_unverified_key())
    assert key_a == key_b

    # versions arrive
    assert _resolve(eq, a.get_versions()) == {}
    assert _resolve(eq, b.get_versions()) == {}

    # exchange messages
    a.send_message(b"hello from a")
    b.send_message(b"hello from b")
    _flush(eq)

    assert _resolve(eq, b.get_message()) == b"hello from a"
    assert _resolve(eq, a.get_message()) == b"hello from b"

    # Close both
    close_a_d = a.close()
    close_b_d = b.close()
    assert _resolve(eq, close_a_d) == "happy"
    assert _resolve(eq, close_b_d) == "happy"


def test_deferred_get_code_can_be_grabbed_before_allocate():
    """The Deferred returned by get_code() before allocate_code() should
    fire as soon as the code is established."""
    eq, a, _ = _make_wormhole_pair()
    d = a.get_code()
    assert not d.called
    a.allocate_code()
    _flush(eq)
    assert d.called
    assert isinstance(d.result, str)


def test_set_code_canonical_path():
    """set_code with a CANONICAL `<locator>:<words>` code should fire
    get_code() immediately. This is the path library callers should
    use; bare-words callers must use set_code_legacy_words explicitly
    (HYP-443)."""
    eq, a, _ = _make_wormhole_pair()
    canonical = "abcdefghijklmnopqrstuvwxyz:purple-sausages-mocha"
    a.set_code(canonical)
    assert _resolve(eq, a.get_code()) == canonical


def test_set_code_refuses_bare_words(_recorded=[]):
    """HYP-443: passing a bare-words code (no `:` separator) to
    set_code raises ValueError. The CLI's words-only flow must
    explicitly route through set_code_legacy_words to make the
    relay-MITM-vulnerable path syntactically conspicuous (per the
    standing 'no easy paths' mandate). Library callers using
    canonical codes see zero change."""
    eq, a, _ = _make_wormhole_pair()
    with pytest.raises(ValueError, match="canonical|legacy_words"):
        a.set_code("purple-sausages-mocha")
    # The session is still alive — the refusal happens BEFORE any
    # state-machine commit, so the caller can still call
    # set_code_legacy_words or set_code(canonical).
    canonical = "abcdefghijklmnopqrstuvwxyz:purple-sausages-mocha"
    a.set_code(canonical)
    assert _resolve(eq, a.get_code()) == canonical


def test_set_code_legacy_words_path():
    """HYP-443: set_code_legacy_words exists and accepts bare words.
    Used by the CLI's words-only-with-verify flow and by library
    callers that explicitly want to bridge to upstream wormhole's
    words-only protocol shape. The function name mirrors
    derive_tag_legacy_words to keep "legacy" loud."""
    eq, a, _ = _make_wormhole_pair()
    a.set_code_legacy_words("purple-sausages-mocha")
    assert _resolve(eq, a.get_code()) == "purple-sausages-mocha"


def test_set_code_legacy_words_refuses_canonical():
    """Symmetric refusal: canonical-shape codes must NOT enter the
    legacy entrypoint. Otherwise a caller could accidentally route a
    canonical code through derive_tag_legacy_words (which uses a
    DIFFERENT HKDF salt domain), and the resulting tag would not match
    what the peer derives via the canonical path."""
    eq, a, _ = _make_wormhole_pair()
    canonical = "abcdefghijklmnopqrstuvwxyz:purple-sausages-mocha"
    with pytest.raises(ValueError, match="canonical|set_code"):
        a.set_code_legacy_words(canonical)


# --- Delegated mode end-to-end ---


def test_delegated_mode_full_handshake_and_message_exchange():
    """Two Delegated wormholes meet, exchange a message, and close happy."""

    @implementer(_interfaces.IWormholeDelegate)
    class Delegate:
        def __init__(self, name):
            self.name = name
            self.welcome = None
            self.code = None
            self.key = None
            self.verifier = None
            self.versions = None
            self.messages = []
            self.closed = None

        def wormhole_got_welcome(self, w):
            self.welcome = w

        def wormhole_got_code(self, c):
            self.code = c

        def wormhole_got_unverified_key(self, k):
            self.key = k

        def wormhole_got_verifier(self, v):
            self.verifier = v

        def wormhole_got_versions(self, vs):
            self.versions = vs

        def wormhole_got_message(self, p):
            self.messages.append(p)

        def wormhole_closed(self, r):
            self.closed = r

    da = Delegate("a")
    db = Delegate("b")
    eq, a, b = _make_wormhole_pair(delegate_a=da, delegate_b=db)

    a.allocate_code()
    _flush(eq)
    assert da.code is not None
    b.set_code(da.code)
    _flush(eq)

    assert da.key == db.key

    a.send_message(b"hi")
    _flush(eq)
    assert db.messages == [b"hi"]

    a.close()
    b.close()
    _flush(eq)
    assert da.closed == "happy"
    assert db.closed == "happy"


# --- derive_key ---


def test_derive_key_after_handshake():
    """derive_key returns deterministic bytes once the master key is known."""
    eq, a, b = _make_wormhole_pair()
    a.allocate_code()
    code = _resolve(eq, a.get_code())
    b.set_code(code)
    _flush(eq)

    k1 = a.derive_key("for-test", 32)
    k2 = b.derive_key("for-test", 32)
    assert k1 == k2
    assert len(k1) == 32

    k3 = a.derive_key("different-purpose", 32)
    assert k3 != k1


def test_derive_key_before_key_raises():
    """derive_key before the master key is set raises NoKeyError."""
    eq, a, _ = _make_wormhole_pair()
    from takeit.errors import NoKeyError

    with pytest.raises(NoKeyError):
        a.derive_key("anything", 32)


def test_derive_key_rejects_non_string_purpose():
    """Type safety on derive_key inputs."""
    eq, a, b = _make_wormhole_pair()
    a.allocate_code()
    code = _resolve(eq, a.get_code())
    b.set_code(code)
    _flush(eq)
    with pytest.raises(TypeError):
        a.derive_key(b"bytes-not-str", 32)


# --- code_length default ---


def test_default_code_length_is_three():
    """takeit's default code is 3 words.

    Post-HYP-406 the full code shape is `<26-base32-locator>:<words>`.
    We assert the SHAPE here: one colon, words section has 3 words
    (2 hyphens), locator section is 26 base32 chars.
    """
    eq, a, _ = _make_wormhole_pair()
    a.allocate_code()  # no length argument
    code = _resolve(eq, a.get_code())
    assert code.count(":") == 1  # locator:words separator
    locator_b32, words = code.split(":", 1)
    assert len(locator_b32) == 26  # 16 bytes → 26 base32 chars
    assert words.count("-") == 2  # 3 words


def test_code_length_can_be_overridden():
    eq, a, _ = _make_wormhole_pair()
    a.allocate_code(code_length=4)
    code = _resolve(eq, a.get_code())
    _, words = code.split(":", 1)
    assert words.count("-") == 3  # 4 words


def test_allocated_code_uses_canonical_locator_words_shape():
    """Sender-allocated codes always have the locator prefix; words-only
    handoff is opt-in by the receiver typing only words."""
    from takeit._code_format import parse_code

    eq, a, _ = _make_wormhole_pair()
    a.allocate_code()
    code = _resolve(eq, a.get_code())
    locator, words = parse_code(code)
    assert locator is not None
    assert len(locator) == 16  # full 128-bit locator
    assert words  # non-empty words section


# --- relays argument ---


def test_relays_default_to_takeit_defaults():
    """When relays=None (or omitted), takeit uses its hardcoded defaults."""
    from takeit.api import DEFAULT_RELAYS

    assert isinstance(DEFAULT_RELAYS, tuple)
    assert len(DEFAULT_RELAYS) >= 3
    for r in DEFAULT_RELAYS:
        assert r.startswith("wss://")
