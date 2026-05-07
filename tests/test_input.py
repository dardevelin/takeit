"""
Tests for the takeit Input state machine and Helper.

takeit's Input drives single-phase interactive code entry. There is no
nameplate prefix; every word in the code comes from the local PGPWordList,
so completion is purely local and synchronous.

State machine:
    S0_idle ── start ──▶ S1_typing_words ── choose_words ──▶ S2_done
"""

import pytest
from automat import NoTransition
from zope.interface import implementer

from takeit import _interfaces
from takeit._input import Helper, Input
from takeit.errors import AlreadyChoseWordsError


@implementer(_interfaces.ICode)
class FakeCode:
    def __init__(self):
        self.finished = []

    def finished_input(self, code):
        self.finished.append(code)


@implementer(_interfaces.ITiming)
class FakeTiming:
    def add(self, *a, **kw):
        class _Ctx:
            def __enter__(self_):
                return self_

            def __exit__(self_, *a):
                return False

        return _Ctx()


def _wired_input():
    code = FakeCode()
    inp = Input(FakeTiming())
    inp.wire(code)
    return inp, code


# --- start returns a Helper ---


def test_start_returns_helper():
    inp, _ = _wired_input()
    helper = inp.start()
    assert isinstance(helper, Helper)


def test_start_can_only_be_called_once():
    inp, _ = _wired_input()
    inp.start()
    with pytest.raises(NoTransition):
        inp.start()


# --- word completion ---


def test_completion_uses_local_wordlist():
    """Completion is synchronous and works as soon as Input is started."""
    inp, _ = _wired_input()
    inp.start()
    # 0 hyphens -> odd-list parity. "ad" prefix in odd list: adroitness,
    # adviser. Each is returned with a trailing hyphen because we expect more
    # words to follow.
    completions = inp.get_word_completions("ad")
    assert "adroitness-" in completions
    assert "adviser-" in completions


def test_completion_alternates_parity_by_hyphen_count():
    """First-word completion uses odd list; second-word uses even list."""
    inp, _ = _wired_input()
    inp.start()
    # 0 hyphens -> odd parity. "adviser" is odd, "adrift" is even.
    first = inp.get_word_completions("ad")
    assert "adviser-" in first
    assert "adrift-" not in first
    # 1 hyphen -> even parity.
    second = inp.get_word_completions("adviser-ad")
    assert "adviser-adrift-" in second
    assert "adviser-adviser-" not in second


def test_completion_returns_full_strings_including_prefix():
    """Completions include the full code-so-far, suitable for readline."""
    inp, _ = _wired_input()
    inp.start()
    completions = inp.get_word_completions("adviser-ad")
    for s in completions:
        assert s.startswith("adviser-ad")


def test_last_word_completion_omits_trailing_hyphen():
    """For an N-word code, the Nth word completion has no trailing hyphen
    because the code is complete after that word."""
    code = FakeCode()
    inp = Input(FakeTiming(), expected_code_length=3)
    inp.wire(code)
    inp.start()
    # 2 hyphens -> third word, parity odd, last word.
    completions = inp.get_word_completions("adviser-adrift-ad")
    assert "adviser-adrift-adviser" in completions
    # No trailing hyphen on the last word.
    assert not any(
        s.endswith("-") for s in completions if s.startswith("adviser-adrift-ad")
    )


def test_expected_code_length_is_configurable():
    """Sender's intended length can be configured (e.g. for 4-word codes)."""
    code = FakeCode()
    inp = Input(FakeTiming(), expected_code_length=4)
    inp.wire(code)
    inp.start()
    # 2 hyphens -> third of four; should still have trailing hyphen.
    completions = inp.get_word_completions("adviser-adrift-ad")
    assert all(s.endswith("-") for s in completions)


# --- choose_words ---


def test_choose_words_submits_full_code_to_code_state_machine():
    inp, code = _wired_input()
    inp.start()
    inp.choose_words("purple-sausages-mocha")
    assert code.finished == ["purple-sausages-mocha"]


def test_choose_words_validates_format():
    """A code with whitespace or no hyphen must be rejected with KeyFormatError
    rather than silently submitted."""
    from takeit.errors import KeyFormatError

    inp, _ = _wired_input()
    inp.start()
    with pytest.raises(KeyFormatError):
        inp.choose_words("loneword")
    with pytest.raises(KeyFormatError):
        inp.choose_words("purple sausages mocha")


def test_choose_words_can_only_be_called_once():
    inp, _ = _wired_input()
    inp.start()
    inp.choose_words("purple-sausages-mocha")
    with pytest.raises(AlreadyChoseWordsError):
        inp.choose_words("yarn-loafer-stockman")


def test_get_word_completions_after_choose_words_raises():
    """After choose_words the helper is consumed — completions are no
    longer meaningful."""
    inp, _ = _wired_input()
    inp.start()
    inp.choose_words("purple-sausages-mocha")
    with pytest.raises(AlreadyChoseWordsError):
        inp.get_word_completions("any")


# --- Helper thread affinity ---


def test_helper_enforces_main_thread():
    """All Helper methods must be called from the construction thread.

    The helper is a thread-affine wrapper so that the readline thread can't
    accidentally re-enter the reactor's state machines."""
    import threading

    inp, _ = _wired_input()
    helper = inp.start()
    errors = []

    def call_from_other_thread():
        try:
            helper.choose_words("purple-sausages-mocha")
        except AssertionError as e:
            errors.append(str(e))

    t = threading.Thread(target=call_from_other_thread)
    t.start()
    t.join()
    assert errors  # the assertion fired
