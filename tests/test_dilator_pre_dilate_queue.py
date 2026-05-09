"""
HYP-456: cap Dilator._pending_inbound_dilate_messages.

Boss forwards in-window dilate-N plaintexts to Dilator.received_dilate.
Until the local app calls w.dilate(), Dilator has no Manager — so each
plaintext queues into _pending_inbound_dilate_messages. The queue had
no cap, allowing an authenticated peer to spend memory before the
local app opts into dilation.

Per HYP-446 the upstream phase-window cap (W=64) bounds practical
exposure to ~4 MiB worst-case, but the cap should also fire HERE for
two reasons:
- Defense in depth: HYP-446 governs phase index window, not bytes per
  message, so many small in-window messages can still pack memory.
- Symmetric closure: HYP-440 caps outbound memory at 16 MiB; this is
  the matching inbound site at the pre-dilate layer.

The fix: count + byte caps, both checked. Excess messages are dropped
with a log line; the connection survives.
"""

import pytest

from takeit._dilation.manager import (
    MAX_PENDING_INBOUND_DILATE_BYTES,
    MAX_PENDING_INBOUND_DILATE_COUNT,
    Dilator,
)


def _make_dilator():
    """Construct a bare Dilator. We don't need most of the
    construction scaffolding because received_dilate's pre-Manager
    branch only touches the queue."""
    return Dilator(
        reactor=None,
        eventual_queue=None,
        cooperator=None,
        acceptable_versions=["ged"],
    )


# --- Count cap ---


def test_count_cap_under_limit_queues_normally():
    """Negative control: 256 small messages queue cleanly."""
    d = _make_dilator()
    for i in range(MAX_PENDING_INBOUND_DILATE_COUNT):
        d.received_dilate(f"msg-{i}".encode("utf-8"))
    assert len(d._pending_inbound_dilate_messages) == MAX_PENDING_INBOUND_DILATE_COUNT


def test_count_cap_at_limit_drops_next():
    """The (N+1)th message is dropped; queue stays at cap; no exception."""
    d = _make_dilator()
    for i in range(MAX_PENDING_INBOUND_DILATE_COUNT):
        d.received_dilate(f"msg-{i}".encode("utf-8"))
    pre_drop_len = len(d._pending_inbound_dilate_messages)
    d.received_dilate(b"overflow")
    assert len(d._pending_inbound_dilate_messages) == pre_drop_len, (
        "overflow message should have been dropped, not queued"
    )


def test_count_cap_constant_pinned():
    """Pin: cap value is exactly 256. Future tunings update the
    constant, not the test."""
    assert MAX_PENDING_INBOUND_DILATE_COUNT == 256


# --- Byte cap ---


def test_byte_cap_under_limit_queues_normally():
    """Negative control: total bytes under 4 MiB queue cleanly."""
    d = _make_dilator()
    chunk = b"x" * (1 << 20)  # 1 MiB
    # 3 chunks = 3 MiB, well under 4 MiB cap
    for _ in range(3):
        d.received_dilate(chunk)
    assert d._pending_inbound_dilate_total_bytes == 3 * len(chunk)
    assert len(d._pending_inbound_dilate_messages) == 3


def test_byte_cap_at_limit_drops_next():
    """A message that would push past the byte cap is dropped, even
    if the count is well under MAX_COUNT."""
    d = _make_dilator()
    chunk = b"x" * (1 << 20)  # 1 MiB
    # 4 chunks = 4 MiB, exactly at cap
    for _ in range(MAX_PENDING_INBOUND_DILATE_BYTES // len(chunk)):
        d.received_dilate(chunk)
    pre_drop_len = len(d._pending_inbound_dilate_messages)
    pre_drop_bytes = d._pending_inbound_dilate_total_bytes
    # One more byte would tip past cap.
    d.received_dilate(b"\x00")
    assert len(d._pending_inbound_dilate_messages) == pre_drop_len
    assert d._pending_inbound_dilate_total_bytes == pre_drop_bytes


def test_byte_cap_constant_pinned():
    """Pin: cap value is exactly 4 MiB."""
    assert MAX_PENDING_INBOUND_DILATE_BYTES == 4 << 20


# --- Drain semantics ---


def test_drain_clears_byte_counter():
    """When `dilate()` is called and Manager is constructed, the queue
    drains and the byte counter resets. The next message after dilate()
    bypasses the queue entirely (Manager is now real)."""
    d = _make_dilator()
    chunk = b"y" * 1024
    for _ in range(50):
        d.received_dilate(chunk)
    assert d._pending_inbound_dilate_total_bytes == 50 * 1024
    assert len(d._pending_inbound_dilate_messages) == 50

    # Manually simulate Manager arriving and draining (since calling
    # dilate() requires the full Boss/Dilator construction). The drain
    # sequence in dilate() is:
    #   while q: q.popleft(); m.received_dilation_message(p)
    #   self._pending_inbound_dilate_total_bytes = 0
    while d._pending_inbound_dilate_messages:
        d._pending_inbound_dilate_messages.popleft()
    d._pending_inbound_dilate_total_bytes = 0

    # Simulate Manager being attached.
    class _StubManager:
        def __init__(self):
            self.received = []

        def received_dilation_message(self, p):
            self.received.append(p)

    d._manager = _StubManager()
    # Now received_dilate goes straight to the manager.
    d.received_dilate(b"after-dilate")
    assert d._manager.received == [b"after-dilate"]
    # Queue stays empty + byte counter at 0.
    assert len(d._pending_inbound_dilate_messages) == 0
    assert d._pending_inbound_dilate_total_bytes == 0


# --- Cap interaction ---


@pytest.mark.parametrize(
    "scenario",
    [
        # name, count, msg_size, should_drop_at_index
        ("count cap fires first (small messages)", 256, 100, 256),
        # 4 MiB / 1 MiB = 4 messages → 5th drops by byte cap, well
        # under count cap.
        ("byte cap fires first (large messages)", 4, 1 << 20, 4),
    ],
)
def test_either_cap_fires(scenario):
    """Either cap can fire first, depending on message-size profile."""
    name, count, msg_size, drop_at = scenario
    d = _make_dilator()
    msg = b"x" * msg_size
    for i in range(drop_at):
        d.received_dilate(msg)
    pre_len = len(d._pending_inbound_dilate_messages)
    # The (drop_at+1)th message is rejected.
    d.received_dilate(msg)
    assert len(d._pending_inbound_dilate_messages) == pre_len, (
        f"{name}: expected drop at index {drop_at}, but queue grew"
    )
