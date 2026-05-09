"""
HYP-450: inner-shape validation for authenticated dilation control
messages.

HYP-447 closed the top-level shape (validate `type` is a string).
HYP-450 closes the next layer down: even with a string `type`, the
required inner fields can be missing or wrong-typed:

- `please` without `side` → KeyError in choose_role(message["side"]).
- `please` with non-string `side` → TypeError in `>` comparison.
- `connection-hints` without `hints` → KeyError in _use_hints.
- `connection-hints` with non-list `hints` → TypeError iterating.
- `connection-hints` with list of non-dict elements → AttributeError
  in parse_hint(hs).get("type", "").

All of these are reachable post-Noise-auth and turn a hostile
authenticated peer into a guaranteed local crash. The fix: validate
inner shape in `received_dilation_message`; pre-filter non-dict
elements in `_use_hints`; defensive Mapping check in `parse_hint`.
"""

from takeit._dilation import manager as manager_mod
from takeit._hints import parse_hint

from ._dilation_helpers import FakeDilationDispatcher as _FakeManager
from ._dilation_helpers import bytes_for as _bytes

# --- HYP-450: please.side shape validation ---


def test_please_without_side_drops():
    """`please` missing `side` would crash choose_role at message['side']."""
    fake = _FakeManager()
    manager_mod.Manager.received_dilation_message(fake, _bytes({"type": "please"}))
    assert fake.rx_PLEASE_called_with is None


def test_please_with_non_string_side_drops():
    """`side` must be a string. None / list / number all reach
    choose_role's comparison and crash with TypeError."""
    fake = _FakeManager()
    for bad_side in (None, 42, ["abc"], {"a": 1}, True):
        manager_mod.Manager.received_dilation_message(
            fake, _bytes({"type": "please", "side": bad_side})
        )
    assert fake.rx_PLEASE_called_with is None


def test_please_with_string_side_dispatches():
    """Negative control: a well-shaped please dispatches."""
    fake = _FakeManager()
    msg = {"type": "please", "side": "abc"}
    manager_mod.Manager.received_dilation_message(fake, _bytes(msg))
    assert fake.rx_PLEASE_called_with == msg


# --- HYP-450: connection-hints.hints shape validation ---


def test_hints_without_hints_field_drops():
    """`connection-hints` missing `hints` would crash use_hints at
    hint_message['hints']."""
    fake = _FakeManager()
    manager_mod.Manager.received_dilation_message(
        fake, _bytes({"type": "connection-hints"})
    )
    assert fake.rx_HINTS_called_with is None


def test_hints_with_non_list_hints_drops():
    """`hints` must be a list. Non-list shapes reach the `for` loop
    in use_hints and crash."""
    fake = _FakeManager()
    for bad in (42, "a string", {"a": 1}, None, True):
        manager_mod.Manager.received_dilation_message(
            fake, _bytes({"type": "connection-hints", "hints": bad})
        )
    assert fake.rx_HINTS_called_with is None


def test_hints_with_empty_list_dispatches():
    """Empty hints list is well-formed (no hints to merge)."""
    fake = _FakeManager()
    msg = {"type": "connection-hints", "hints": []}
    manager_mod.Manager.received_dilation_message(fake, _bytes(msg))
    assert fake.rx_HINTS_called_with == msg


# --- HYP-450: parse_hint defensive Mapping check ---


def test_parse_hint_returns_none_for_non_mapping():
    """Even if `_use_hints` forgets to filter, parse_hint must defend."""
    assert parse_hint(42) is None
    assert parse_hint("abc") is None
    assert parse_hint([1, 2, 3]) is None
    assert parse_hint(None) is None


def test_parse_hint_accepts_mapping():
    """Negative control: a real hint dict still parses."""
    h = {
        "type": "direct-tcp-v1",
        "hostname": "8.8.8.8",
        "port": 1234,
        "priority": 1.0,
    }
    result = parse_hint(h)
    assert result is not None


# --- HYP-450: _use_hints filters non-dict elements ---


class _FakeConnectorForUseHints:
    def __init__(self):
        self.got_hints_calls = []

    def got_hints(self, hint_objs):
        self.got_hints_calls.append(hint_objs)


class _FakeManagerForUseHints:
    """Just enough surface for _use_hints to run."""

    def __init__(self, allow_private=False):
        self._allow_private_hints = allow_private
        self._connector = _FakeConnectorForUseHints()


def test_use_hints_filters_non_dict_elements():
    """A hostile hints array can mix valid hint dicts with garbage:
    [42, "abc", {"valid": ...}, None]. _use_hints must filter the
    junk before passing to parse_hint, not crash with AttributeError."""
    fake = _FakeManagerForUseHints()
    msg = {
        "type": "connection-hints",
        "hints": [
            42,
            "abc",
            None,
            [1, 2, 3],
            {
                "type": "direct-tcp-v1",
                "hostname": "8.8.8.8",
                "port": 1234,
                "priority": 1.0,
            },
        ],
    }
    # Should NOT raise, even with non-dict garbage in the list.
    manager_mod.Manager._use_hints(fake, msg)
    # The valid hint reached got_hints.
    assert len(fake._connector.got_hints_calls) == 1
    parsed = fake._connector.got_hints_calls[0]
    assert len(parsed) == 1


def test_use_hints_all_garbage_passes_empty_to_connector():
    """All-garbage hints array → connector sees empty list, no crash."""
    fake = _FakeManagerForUseHints()
    msg = {"type": "connection-hints", "hints": [42, "abc", None]}
    manager_mod.Manager._use_hints(fake, msg)
    assert fake._connector.got_hints_calls == [[]]
