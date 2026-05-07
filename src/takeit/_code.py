from zope.interface import implementer
from attr import attrs, attrib
from automat import MethodicalMachine
from . import _interfaces
from ._automat import first as _first
from .errors import KeyFormatError
from .util import provides


def validate_code(code):
    """A takeit code is a hyphen-separated sequence of words, e.g.
    `purple-sausages-mocha`. It must contain no whitespace and at least
    one hyphen (i.e. at least two words). Word-by-word membership in the
    PGP wordlist is not enforced here — that gives users some freedom to
    use custom codes via `set_code` while still catching obvious typos.
    """
    if not isinstance(code, str):
        raise KeyFormatError(f"Code must be str, got {type(code).__name__}.")
    if not code:
        raise KeyFormatError("Code must not be empty.")
    if any(ch.isspace() for ch in code):
        raise KeyFormatError(f"Code '{code}' contains whitespace.")
    if "-" not in code:
        raise KeyFormatError(
            f"Code '{code}' must contain at least one hyphen.")


@attrs
@implementer(_interfaces.ICode)
class Code:
    """
    Drives the three ways a takeit code is established.

    Compared to upstream wormhole's Code:
    - The `S1_inputting_nameplate` / `S2_inputting_words` two-phase entry
      is collapsed to a single `S1_inputting`, because takeit codes have
      no nameplate prefix.
    - The `S3_allocating` waiting state is gone: `allocate_code` is a
      synchronous local generation against the caller-supplied wordlist.
    - `Allocator` and `Nameplate` references are gone from `wire()`.
    """

    _timing = attrib(validator=provides(_interfaces.ITiming))
    m = MethodicalMachine()
    set_trace = getattr(m, "_setTrace",
                        lambda self, f: None)  # pragma: no cover

    def wire(self, boss, key, input):
        self._B = _interfaces.IBoss(boss)
        self._K = _interfaces.IKey(key)
        self._I = _interfaces.IInput(input)

    @m.state(initial=True)
    def S0_idle(self):
        pass  # pragma: no cover

    @m.state()
    def S1_inputting(self):
        pass  # pragma: no cover

    @m.state()
    def S2_known(self):
        pass  # pragma: no cover

    # from App
    @m.input()
    def input_code(self):
        pass

    def set_code(self, code):
        validate_code(code)  # can raise KeyFormatError
        self._set_code(code)

    @m.input()
    def _set_code(self, code):
        pass

    def allocate_code(self, length, wordlist):
        """Locally generate a code from `wordlist` and commit it.

        Synchronous: by the time this returns, `B.got_code` and `K.got_code`
        have been called.
        """
        if length < 1:
            raise ValueError("length must be >= 1")
        code = wordlist.choose_words(length)
        self._set_code(code)

    # from Input
    @m.input()
    def finished_input(self, code):
        pass

    @m.output()
    def do_set_code(self, code):
        self._B.got_code(code)
        self._K.got_code(code)

    @m.output()
    def do_start_input(self):
        return self._I.start()

    @m.output()
    def do_finish_input(self, code):
        validate_code(code)  # the helper-driven path also goes through
        self._B.got_code(code)
        self._K.got_code(code)

    S0_idle.upon(_set_code, enter=S2_known, outputs=[do_set_code])
    S0_idle.upon(
        input_code,
        enter=S1_inputting,
        outputs=[do_start_input],
        collector=_first,
    )
    S1_inputting.upon(
        finished_input, enter=S2_known, outputs=[do_finish_input])
