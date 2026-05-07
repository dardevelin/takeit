# We use 'threading' defensively here, to detect if we're being called from a
# non-main thread. _rlcompleter.py is the only internal takeit code that
# deliberately creates a new thread.
import threading

from attr import attrib, attrs
from automat import MethodicalMachine
from zope.interface import implementer

from . import _interfaces
from ._automat import first as _first
from ._code import validate_code
from ._wordlist import PGPWordList
from .errors import AlreadyChoseWordsError
from .util import provides


@attrs
@implementer(_interfaces.IInput)
class Input:
    """
    Drives interactive single-phase code entry.

    Compared to upstream wormhole's Input:
    - The two-phase entry (`S1_typing_nameplate` then
      `S2_typing_code_no_wordlist`/`S3_typing_code_yes_wordlist`) collapses
      to a single `S1_typing_words` state. There is no nameplate prefix.
    - The wordlist is local (`PGPWordList()`) and known at construction;
      `got_wordlist`, `when_wordlist_is_available`, and the wordlist-waiter
      machinery are gone.
    - Lister, `refresh_nameplates`, `get_nameplate_completions`,
      `choose_nameplate` are gone.
    """

    _timing = attrib(validator=provides(_interfaces.ITiming))
    # The receiver doesn't know the sender's intended code length unless told.
    # 3 is the takeit default. Out-of-range lengths still complete usefully —
    # the user just won't get a trailing hyphen on the wrong word.
    _expected_code_length = attrib(default=3)
    m = MethodicalMachine()
    set_trace = getattr(m, "_setTrace",
                        lambda self, f: None)  # pragma: no cover

    def __attrs_post_init__(self):
        self._wordlist = PGPWordList()
        self._trace = None

    def set_debug(self, f):
        self._trace = f

    def _debug(self, what):  # pragma: no cover
        if self._trace:
            self._trace(old_state="", input=what, new_state="")

    def wire(self, code):
        self._C = _interfaces.ICode(code)

    @m.state(initial=True)
    def S0_idle(self):
        pass  # pragma: no cover

    @m.state()
    def S1_typing_words(self):
        pass  # pragma: no cover

    @m.state(terminal=True)
    def S2_done(self):
        pass  # pragma: no cover

    # from Code
    @m.input()
    def start(self):
        pass

    # API provided to app via Helper
    @m.input()
    def get_word_completions(self, prefix):
        pass

    def choose_words(self, code):
        validate_code(code)  # raises KeyFormatError on bad input
        self._choose_words(code)

    @m.input()
    def _choose_words(self, code):
        pass

    @m.output()
    def do_start(self):
        return Helper(self)

    @m.output()
    def do_word_completions(self, prefix):
        return self._wordlist.get_completions(
            prefix, num_words=self._expected_code_length)

    @m.output()
    def do_finish(self, code):
        self._C.finished_input(code)

    @m.output()
    def raise_already_chose_words_completions(self, prefix):
        raise AlreadyChoseWordsError()

    @m.output()
    def raise_already_chose_words_choose(self, code):
        raise AlreadyChoseWordsError()

    S0_idle.upon(
        start, enter=S1_typing_words, outputs=[do_start], collector=_first)

    S1_typing_words.upon(
        get_word_completions,
        enter=S1_typing_words,
        outputs=[do_word_completions],
        collector=_first,
    )
    S1_typing_words.upon(_choose_words, enter=S2_done, outputs=[do_finish])

    S2_done.upon(
        get_word_completions,
        enter=S2_done,
        outputs=[raise_already_chose_words_completions],
    )
    S2_done.upon(
        _choose_words,
        enter=S2_done,
        outputs=[raise_already_chose_words_choose],
    )


@attrs
@implementer(_interfaces.IInputHelper)
class Helper:
    """
    Thread-affine wrapper exposed to application code (the readline thread
    in the CLI). All methods must be called from the construction thread.
    """

    _input = attrib()

    def __attrs_post_init__(self):
        self._main_thread = threading.current_thread().ident

    def get_word_completions(self, prefix):
        assert threading.current_thread().ident == self._main_thread
        return self._input.get_word_completions(prefix)

    def choose_words(self, code):
        assert threading.current_thread().ident == self._main_thread
        self._input._debug("I.choose_words")
        self._input.choose_words(code)
        self._input._debug("I.choose_words finished")
