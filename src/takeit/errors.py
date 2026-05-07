class WormholeError(Exception):
    """Parent class for all wormhole-related errors"""


class WelcomeError(WormholeError):
    """
    The relay server told us to signal an error, probably because our version
    is too old to possibly work. The server said:"""

    pass


class LonelyError(WormholeError):
    """wormhole.close() was called before the peer connection could be
    established"""


class WrongPasswordError(WormholeError):
    """
    Key confirmation failed. Either you or your correspondent typed the code
    wrong, or a would-be man-in-the-middle attacker guessed incorrectly. Try
    sending the file again.
    """

    # or the data blob was corrupted, and that's why decrypt failed
    pass


class KeyFormatError(WormholeError):
    """
    The takeit code is malformed: contains whitespace, is empty, or has
    no hyphen separating the words.
    """


class NoKeyError(WormholeError):
    """w.derive_key() was called before got_verifier() fired"""


class OnlyOneCodeError(WormholeError):
    """Only one w.generate_code/w.set_code/w.input_code may be called"""


class AlreadyChoseWordsError(WormholeError):
    """The InputHelper was asked to do get_word_completions() after
    choose_words() was called, or choose_words() was called a second time."""


class WormholeClosed(Exception):
    """Deferred-returning API calls errback with WormholeClosed if the
    wormhole was already closed, or if it closes before a real result can be
    obtained."""


class _UnknownPhaseError(Exception):
    """internal exception type, for tests."""
