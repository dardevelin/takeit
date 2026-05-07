"""
Tests for the takeit Code state machine.

Three branches, all leading to the same terminal state S2_known:
- set_code(code)              — caller already knows the code
- input_code()                — interactive entry; helper drives finished_input
- allocate_code(length, wl)   — locally generates a fresh code, synchronous

The S2_known transition fires `B.got_code(code)` and `K.got_code(code)` so
that downstream state machines (Boss, Key) start their work.
"""
import pytest
from zope.interface import implementer

from takeit import _interfaces
from takeit._code import Code, validate_code
from takeit._wordlist import PGPWordList
from takeit.errors import KeyFormatError


@implementer(_interfaces.IBoss)
class FakeBoss:
    def __init__(self):
        self.codes = []

    def got_code(self, code):
        self.codes.append(code)


@implementer(_interfaces.IKey)
class FakeKey:
    def __init__(self):
        self.codes = []

    def got_code(self, code):
        self.codes.append(code)


@implementer(_interfaces.IInput)
class FakeInput:
    """Returns a sentinel from start(); finished_input is driven by tests."""

    def __init__(self):
        self.start_called = 0

    def start(self):
        self.start_called += 1
        return "input-helper-sentinel"


@implementer(_interfaces.ITiming)
class FakeTiming:
    def add(self, *a, **kw):
        class _Ctx:
            def __enter__(self_): return self_
            def __exit__(self_, *a): return False
        return _Ctx()


def _wired_code():
    boss = FakeBoss()
    key = FakeKey()
    inp = FakeInput()
    c = Code(FakeTiming())
    c.wire(boss, key, inp)
    return c, boss, key, inp


# --- validate_code (already partly tested in test_tag — repeat the boundaries
#     here so a Code-only refactor doesn't lose them) ---


def test_validate_code_accepts_typical():
    validate_code("purple-sausages-mocha")  # no raise


def test_validate_code_rejects_empty():
    with pytest.raises(KeyFormatError):
        validate_code("")


def test_validate_code_rejects_whitespace():
    with pytest.raises(KeyFormatError):
        validate_code("purple sausages mocha")
    with pytest.raises(KeyFormatError):
        validate_code("purple-sausages-mocha\n")


def test_validate_code_rejects_no_hyphen():
    with pytest.raises(KeyFormatError):
        validate_code("loneword")


def test_validate_code_rejects_non_string():
    with pytest.raises(KeyFormatError):
        validate_code(b"purple-sausages-mocha")


# --- set_code path ---


def test_set_code_notifies_boss_and_key():
    c, boss, key, _ = _wired_code()
    c.set_code("purple-sausages-mocha")
    assert boss.codes == ["purple-sausages-mocha"]
    assert key.codes == ["purple-sausages-mocha"]


def test_set_code_validates():
    c, _, _, _ = _wired_code()
    with pytest.raises(KeyFormatError):
        c.set_code("invalid code")


# --- input_code path ---


def test_input_code_returns_input_helper():
    c, _, _, inp = _wired_code()
    helper = c.input_code()
    assert helper == "input-helper-sentinel"
    assert inp.start_called == 1


def test_input_code_then_finished_notifies_boss_and_key():
    c, boss, key, _ = _wired_code()
    c.input_code()
    c.finished_input("purple-sausages-mocha")
    assert boss.codes == ["purple-sausages-mocha"]
    assert key.codes == ["purple-sausages-mocha"]


def test_finished_input_before_start_is_invalid():
    """The Code state machine should reject finished_input from S0_idle."""
    from automat import NoTransition
    c, _, _, _ = _wired_code()
    with pytest.raises(NoTransition):
        c.finished_input("purple-sausages-mocha")


# --- allocate_code path: synchronous local generation ---


def test_allocate_code_generates_locally_and_notifies():
    c, boss, key, _ = _wired_code()
    wl = PGPWordList()
    c.allocate_code(3, wl)
    assert len(boss.codes) == 1
    code = boss.codes[0]
    assert code.count("-") == 2  # 3 words = 2 hyphens
    assert key.codes == [code]


def test_allocate_code_uses_caller_provided_wordlist():
    """The wordlist must be respected so a future i18n wordlist works."""
    class StubWordlist:
        def choose_words(self, length):
            return "alpha-beta-gamma"
    c, boss, _, _ = _wired_code()
    c.allocate_code(3, StubWordlist())
    assert boss.codes == ["alpha-beta-gamma"]


# --- terminal state ---


def test_cannot_set_code_twice():
    from automat import NoTransition
    c, _, _, _ = _wired_code()
    c.set_code("purple-sausages-mocha")
    with pytest.raises(NoTransition):
        c.set_code("yarn-loafer-stockman")


def test_cannot_mix_paths():
    from automat import NoTransition
    c, _, _, _ = _wired_code()
    c.set_code("purple-sausages-mocha")
    with pytest.raises(NoTransition):
        c.input_code()
    with pytest.raises(NoTransition):
        c.allocate_code(3, PGPWordList())
