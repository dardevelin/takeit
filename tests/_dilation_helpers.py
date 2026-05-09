"""
Shared helpers for dilation-message tests (HYP-447, HYP-450, ...).

A `Manager.received_dilation_message` test can build a stripped-down
fake Manager that captures dispatch calls without spinning up the
full Automat machinery. Two passes (HYP-447 and HYP-450) duplicated
this helper; consolidating here.
"""

import json


def bytes_for(payload_dict):
    """Encode a dict to bytes the same way Manager decodes its
    plaintext input. Wire-format-aligned with `bytes_to_dict`."""
    return json.dumps(payload_dict).encode("utf-8")


class FakeDilationDispatcher:
    """Just enough Manager surface to exercise
    `received_dilation_message` without spinning up the real state
    machines. The unbound method is bound against an instance of this
    class via `Manager.received_dilation_message(fake, payload)`.

    Captures:
    - `rx_PLEASE_called_with`: the last `please` dispatch payload, or None
    - `rx_HINTS_called_with`: the last `connection-hints` dispatch payload, or None
    - `rx_RECONNECT_called`: bool
    - `rx_RECONNECTING_called`: bool
    """

    def __init__(self):
        self.rx_PLEASE_called_with = None
        self.rx_HINTS_called_with = None
        self.rx_RECONNECT_called = False
        self.rx_RECONNECTING_called = False

    def rx_PLEASE(self, message):
        self.rx_PLEASE_called_with = message

    def rx_HINTS(self, message):
        self.rx_HINTS_called_with = message

    def rx_RECONNECT(self):
        self.rx_RECONNECT_called = True

    def rx_RECONNECTING(self):
        self.rx_RECONNECTING_called = True
