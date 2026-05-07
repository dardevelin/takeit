"""Tests for the CLI spinner module.

Covers the pure-function rotate_glyph and the TossSpinner lifecycle. The
visible animation is a UI affordance and not directly tested for pixels;
we test that the right number of frames advance, that NO_COLOR strips
ANSI, and that start/stop is safe to call multiple times.
"""

import sys

from twisted.internet.task import Clock

from takeit.cli import _spinner as S

# --- rotate_glyph ---


def test_rotate_glyph_advances_with_byte_count(monkeypatch):
    """Each ROTATION_STEP bytes advances by one rotation index."""
    monkeypatch.setattr(S, "use_color", lambda: False)
    step = S._BYTES_PER_ROTATION_STEP
    assert S.rotate_glyph(0) == S.ROT[0]
    assert S.rotate_glyph(step - 1) == S.ROT[0]
    assert S.rotate_glyph(step) == S.ROT[1]
    assert S.rotate_glyph(step * 2) == S.ROT[2]
    assert S.rotate_glyph(step * 3) == S.ROT[3]
    # Wraps after a full cycle.
    assert S.rotate_glyph(step * 4) == S.ROT[0]


def test_rotate_glyph_colorizes_when_color_available(monkeypatch):
    monkeypatch.setattr(S, "use_color", lambda: True)
    glyph = S.rotate_glyph(0)
    assert S.PALE_VIOLET in glyph
    assert S.RESET in glyph
    assert S.ROT[0] in glyph


def test_rotate_glyph_strips_color_under_no_color(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    glyph = S.rotate_glyph(0)
    assert glyph == S.ROT[0]
    assert S.PALE_VIOLET not in glyph


def test_rotate_glyph_strips_color_when_not_tty(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: False)
    glyph = S.rotate_glyph(0)
    assert glyph == S.ROT[0]


# --- TossSpinner ---


def _make_spinner_for_tty(monkeypatch):
    """Force the spinner to think stdout is a TTY (it isn't under pytest)
    so the start/stop logic actually runs."""
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    clock = Clock()
    return S.TossSpinner(clock), clock


def test_toss_spinner_no_op_when_not_tty(monkeypatch):
    """When stdout isn't a TTY (e.g. piped, in a CI log), start() is a
    no-op — we don't paint ANSI escapes into a non-TTY."""
    monkeypatch.setattr(sys.stdout, "isatty", lambda: False)
    clock = Clock()
    spinner = S.TossSpinner(clock)
    spinner.start()
    # Nothing scheduled.
    assert clock.calls == []
    assert spinner._active is False
    spinner.stop()  # safe to stop after no-op start


def test_toss_spinner_schedules_next_frame(monkeypatch):
    spinner, clock = _make_spinner_for_tty(monkeypatch)
    spinner.start()
    assert spinner._active is True
    # First frame's delay is 0.10 (the rest pose).
    assert len(clock.calls) == 1
    delay = clock.calls[0].time - clock.seconds()
    assert 0.05 < delay < 0.15
    spinner.stop()
    assert spinner._active is False


def test_toss_spinner_advances_through_frames(monkeypatch):
    spinner, clock = _make_spinner_for_tty(monkeypatch)
    spinner.start()
    # Advance through several frames; each tick should schedule the next.
    for _ in range(len(S._TOSS_FRAMES)):
        clock.advance(0.5)  # generous, exceeds any per-frame delay
    # After a full cycle of frames, frame_idx wraps to 0 (the rest pose).
    assert spinner._frame_idx == 0
    spinner.stop()


def test_toss_spinner_stop_cancels_pending_call(monkeypatch):
    spinner, clock = _make_spinner_for_tty(monkeypatch)
    spinner.start()
    # One pending callLater is scheduled.
    assert len(clock.calls) == 1
    pending = clock.calls[0]
    assert pending.active() is True
    spinner.stop()
    assert pending.active() is False


def test_toss_spinner_double_start_is_safe(monkeypatch):
    spinner, clock = _make_spinner_for_tty(monkeypatch)
    spinner.start()
    spinner.start()  # should NOT schedule a second concurrent loop
    # Only one pending callLater.
    active_calls = [c for c in clock.calls if c.active()]
    assert len(active_calls) == 1
    spinner.stop()


def test_toss_spinner_double_stop_is_safe(monkeypatch):
    spinner, clock = _make_spinner_for_tty(monkeypatch)
    spinner.start()
    spinner.stop()
    spinner.stop()  # idempotent
    assert spinner._active is False


# --- visual smoke (integration) ---


def test_rot_states_use_three_distinct_shapes():
    """4 rotation states cycle through 3 distinct shapes — the diamond
    (45°) is reused on the way up and on the way down, which is right:
    a parcel viewed edge-on at +45° and -45° looks the same."""
    assert len(set(S.ROT)) == 3
    assert "■" in S.ROT  # square
    assert "◆" in S.ROT  # diamond (used twice)
    assert "▮" in S.ROT  # vertical
