"""
HYP-447: malformed authenticated dilation records / messages must be
caught and converted to clean disconnection, NOT bubble up as Twisted
unhandled-callback errors.

Two sites, two related bugs:

1. `connection.py:_Record.decrypt_message` calls `parse_record(message)`
   after Noise auth succeeds. parse_record raises ValueError on bad
   record shapes; only Disconnect is caught in dataReceived.

2. `manager.py:Manager.received_dilation_message` calls
   `bytes_to_dict(plaintext)` and then `message["type"]` without
   shape validation. Bad JSON or missing "type" raises various
   exceptions uncaught.

Both surface as authenticated-peer log noise. Fix is to catch
ValueError alongside Disconnect at the dataReceived layer, and to
shape-validate the dilation message before key access.
"""

from takeit._dilation import manager as manager_mod
from takeit._dilation.connection import DilatedConnectionProtocol

from ._dilation_helpers import FakeDilationDispatcher, bytes_for

# --- HYP-447 (Site A): dataReceived catches ValueError ---


def test_dataReceived_catches_value_error():
    """ValueError from parse_record (malformed authenticated record)
    must be caught alongside Disconnect and converted into a clean
    transport.loseConnection. Today only Disconnect is caught — a
    ValueError bubbles up uncaught into Twisted's logger.

    We assert this structurally via inspect: the except clause in
    dataReceived must list both Disconnect and ValueError. The
    end-to-end behavior is covered by an existing exercise of the
    Disconnect path; the structural pin catches a regression where
    a future refactor narrows the except back to just Disconnect."""
    import inspect
    import re

    src = inspect.getsource(DilatedConnectionProtocol.dataReceived)
    flat = re.sub(r"\s+", " ", src)
    # The except clause must reference both names.
    assert (
        "except (Disconnect, ValueError)" in flat
        or "except (ValueError, Disconnect)" in flat
    ), (
        "expected dataReceived to catch (Disconnect, ValueError) so "
        "malformed authenticated records produce clean loseConnection"
    )


# --- HYP-447 (Site B): received_dilation_message shape-validates ---


_FakeManagerForReceivedDilation = FakeDilationDispatcher
_bytes_to_dict_via_module = bytes_for


def test_received_dilation_message_drops_invalid_json():
    """An authenticated peer can send a record whose plaintext isn't
    valid JSON. Today bytes_to_dict raises uncaught; HYP-447 makes
    Manager log+drop instead.

    We verify by binding the un-bound method to a fake manager.
    """
    fake = _FakeManagerForReceivedDilation()
    # Should NOT raise
    manager_mod.Manager.received_dilation_message(fake, b"not-json")
    # No dispatch fired.
    assert fake.rx_PLEASE_called_with is None
    assert fake.rx_HINTS_called_with is None
    assert not fake.rx_RECONNECT_called
    assert not fake.rx_RECONNECTING_called


def test_received_dilation_message_drops_non_dict_json():
    """JSON parses but isn't an object (e.g. bare list, string)."""
    fake = _FakeManagerForReceivedDilation()
    manager_mod.Manager.received_dilation_message(fake, b"[]")
    manager_mod.Manager.received_dilation_message(fake, b'"a string"')
    manager_mod.Manager.received_dilation_message(fake, b"42")
    assert fake.rx_PLEASE_called_with is None


def test_received_dilation_message_drops_dict_without_type():
    """Object missing the 'type' field: today raises KeyError uncaught."""
    fake = _FakeManagerForReceivedDilation()
    manager_mod.Manager.received_dilation_message(
        fake, _bytes_to_dict_via_module({"oops": "no type"})
    )
    assert fake.rx_PLEASE_called_with is None


def test_received_dilation_message_drops_non_string_type():
    """type field exists but isn't a string."""
    fake = _FakeManagerForReceivedDilation()
    manager_mod.Manager.received_dilation_message(
        fake, _bytes_to_dict_via_module({"type": 42})
    )
    manager_mod.Manager.received_dilation_message(
        fake, _bytes_to_dict_via_module({"type": None})
    )
    assert fake.rx_PLEASE_called_with is None


def test_received_dilation_message_routes_valid_please():
    """Sanity check: a well-formed 'please' message still dispatches."""
    fake = _FakeManagerForReceivedDilation()
    msg = {"type": "please", "side": "abc"}
    manager_mod.Manager.received_dilation_message(fake, _bytes_to_dict_via_module(msg))
    assert fake.rx_PLEASE_called_with == msg


def test_received_dilation_message_routes_valid_hints():
    fake = _FakeManagerForReceivedDilation()
    msg = {"type": "connection-hints", "hints": []}
    manager_mod.Manager.received_dilation_message(fake, _bytes_to_dict_via_module(msg))
    assert fake.rx_HINTS_called_with == msg


def test_received_dilation_message_routes_reconnect():
    fake = _FakeManagerForReceivedDilation()
    msg = {"type": "reconnect"}
    manager_mod.Manager.received_dilation_message(fake, _bytes_to_dict_via_module(msg))
    assert fake.rx_RECONNECT_called


def test_received_dilation_message_routes_reconnecting():
    fake = _FakeManagerForReceivedDilation()
    msg = {"type": "reconnecting"}
    manager_mod.Manager.received_dilation_message(fake, _bytes_to_dict_via_module(msg))
    assert fake.rx_RECONNECTING_called


def test_received_dilation_message_unknown_type_does_not_raise():
    """Unknown type strings (forward-compat or attacker-chosen) drop
    cleanly with a log line, no exception."""
    fake = _FakeManagerForReceivedDilation()
    msg = {"type": "future-takeit-thing"}
    manager_mod.Manager.received_dilation_message(fake, _bytes_to_dict_via_module(msg))
    # No dispatch fired.
    assert fake.rx_PLEASE_called_with is None
