"""
readline-based interactive code entry for the takeit CLI.

This runs in a worker thread (so the reactor isn't blocked while the user
types). Every call into the IInputHelper goes through
`blockingCallFromThread` to hop back to the reactor thread.

Compared to upstream wormhole's _rlcompleter:
- The two-phase nameplate-then-words completion is gone. Every press of TAB
  completes against the local wordlist for whatever word the user is on.
- No `choose_nameplate`, no `when_wordlist_is_available`, no `refresh_*`.
"""
import traceback
from sys import stderr

from attr import attrib, attrs
from twisted.internet.defer import inlineCallbacks
from twisted.internet.threads import blockingCallFromThread, deferToThread

from .errors import KeyFormatError

try:
    import readline
except ImportError:
    readline = None

errf = None


# uncomment this to enable tab-completion debugging
# import os ; errf = open("err", "w") if os.path.exists("err") else None
def debug(*args, **kwargs):  # pragma: no cover
    if errf:
        print(*args, file=errf, **kwargs)
        errf.flush()


@attrs
class CodeInputter:
    """
    Drives readline tab-completion for a takeit code.

    Lives in the readline thread. All `IInputHelper` calls go through
    `blockingCallFromThread` to reach the reactor.
    """

    _input_helper = attrib()
    _reactor = attrib()

    def __attrs_post_init__(self):
        self.used_completion = False
        self._matches = None

    def _bcft(self, f, *a, **kw):
        return blockingCallFromThread(self._reactor, f, *a, **kw)

    def completer(self, text, state):
        try:
            return self._wrapped_completer(text, state)
        except Exception as e:  # pragma: no cover
            # readline silently discards completer exceptions; surface them
            # so debugging is possible.
            print(f"completer exception: {e}")
            traceback.print_exc()
            raise

    def _wrapped_completer(self, text, state):
        self.used_completion = True
        if state == 0:
            debug(f"completer starting ({text!r})")
            completions = self._bcft(
                self._input_helper.get_word_completions, text)
            self._matches = sorted(completions)
            debug(" matches:", " ".join(f"'{m}'" for m in self._matches))
        if state >= len(self._matches):
            return None
        return self._matches[state]

    def finish(self, code):
        if "-" not in code:
            raise KeyFormatError("incomplete takeit code")
        self._bcft(self._input_helper.choose_words, code)


def _input_code_with_completion(prompt, input_helper, reactor):
    # reminder: this all occurs in a separate thread. All calls to input_helper
    # must go through blockingCallFromThread()
    c = CodeInputter(input_helper, reactor)
    if readline is not None:
        if readline.__doc__ and "libedit" in readline.__doc__:
            readline.parse_and_bind("bind ^I rl_complete")
        else:
            readline.parse_and_bind("tab: complete")
        readline.set_completer(c.completer)
        readline.set_completer_delims("")
        debug("==== readline-based completion is prepared")
    else:
        debug("==== unable to import readline, disabling completion")
    code = input(prompt)
    if isinstance(code, bytes):
        code = code.decode("utf-8")
    c.finish(code)
    return c.used_completion


def warn_readline():  # pragma: no cover
    # When our process receives a SIGINT, Twisted's SIGINT handler will
    # stop the reactor and wait for all threads to terminate before the
    # process exits. However, if we were waiting for
    # input_code_with_completion() when SIGINT happened, the readline
    # thread will be blocked waiting for something on stdin. Trick the
    # user into satisfying the blocking read so we can exit.
    print("\nCommand interrupted: please press Return to quit", file=stderr)


@inlineCallbacks
def input_with_completion(prompt, input_helper, reactor):
    t = reactor.addSystemEventTrigger("before", "shutdown", warn_readline)
    used_completion = yield deferToThread(
        _input_code_with_completion, prompt, input_helper, reactor)
    reactor.removeSystemEventTrigger(t)
    return used_completion
