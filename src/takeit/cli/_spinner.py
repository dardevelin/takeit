"""
Tiny tumbling-parcel spinner.

Two display modes:

- :class:`TossSpinner` — the full 2-line toss-and-rotate animation, used
  while Yobi is waiting (pre-transfer, between commands). It owns its
  own scheduling via the reactor.

- :func:`rotate_glyph(byte_count)` — pure function returning a single
  rotation glyph for use as a tqdm bar prefix. The receiver/sender wires
  byte_count → glyph so the rotation tracks transfer speed.

Pure-ASCII glyphs are not used — Unicode block shapes look like a tumbling
parcel; pure ASCII attempts looked off. Color is takeit's pale violet
(``#A78BFF``); honors ``NO_COLOR`` and downgrades when stdout isn't a TTY.
"""
import os
import sys


# 4-state rotation, viewed edge-on. Square -> 45° -> vertical -> 45° -> square.
ROT = ("■", "◆", "▮", "◆")

# Pale violet — same hue as the brand body color (#5B3FD9) but lifted in
# luminance so the glyph reads against dark and light terminals. Brand
# body is too dark for terminal contrast; this is the animation accent.
PALE_VIOLET = "\033[38;2;167;139;255m"
RESET = "\033[0m"


def use_color():
    """Color iff stdout is a TTY and NO_COLOR is unset."""
    if os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


def colorize(glyph):
    """Wrap a glyph in pale-violet ANSI codes if color is available."""
    if not use_color():
        return glyph
    return f"{PALE_VIOLET}{glyph}{RESET}"


# Pacing: 2-line toss with full revolution mid-air. Indices into ROT.
# Each entry is (height, rot_idx, frame_delay_seconds).
# Heights: 0 = baseline, 1 = apex.
_TOSS_FRAMES = [
    (0, 0, 0.10),  # rest
    (1, 1, 0.06),  # apex, diamond
    (1, 2, 0.06),  # apex, vertical
    (1, 3, 0.06),  # apex, diamond
    (1, 0, 0.06),  # apex, square (full revolution)
    (0, 0, 0.10),  # land
]
_TOSS_HEIGHT_MAX = max(h for h, _, _ in _TOSS_FRAMES)
_TOSS_TOTAL_LINES = _TOSS_HEIGHT_MAX + 1


# ---- Toss animation (idle / waiting) ----


class TossSpinner:
    """The 2-line toss-and-rotate animation, used during idle waits.

    Drives itself via the Twisted reactor. Owns the lines it draws. Call
    :meth:`start` once and :meth:`stop` to clear and yield the area.
    Safe to start/stop multiple times. Honors NO_COLOR / non-TTY.
    """

    def __init__(self, reactor):
        self._reactor = reactor
        self._loop = None
        self._frame_idx = 0
        self._active = False

    def start(self):
        if self._active or not sys.stdout.isatty():
            # On non-TTYs the animation is a no-op.
            return
        self._active = True
        self._frame_idx = 0
        # Reserve the lines we'll draw into so the first clear_lines() call
        # has somewhere to move up to.
        sys.stdout.write("\n" * _TOSS_TOTAL_LINES)
        sys.stdout.flush()
        self._draw_current()
        self._schedule_next()

    def stop(self):
        if not self._active:
            return
        self._active = False
        if self._loop and self._loop.active():
            self._loop.cancel()
        self._loop = None
        # Clear the toss area so subsequent output starts on a clean line.
        if sys.stdout.isatty():
            sys.stdout.write(f"\033[{_TOSS_TOTAL_LINES}A\033[J")
            sys.stdout.flush()

    def _schedule_next(self):
        if not self._active:
            return
        _, _, delay = _TOSS_FRAMES[self._frame_idx]
        self._loop = self._reactor.callLater(delay, self._tick)

    def _tick(self):
        if not self._active:
            return
        self._frame_idx = (self._frame_idx + 1) % len(_TOSS_FRAMES)
        self._draw_current()
        self._schedule_next()

    def _draw_current(self):
        sys.stdout.write(f"\033[{_TOSS_TOTAL_LINES}A\033[J")
        height, rot_idx, _ = _TOSS_FRAMES[self._frame_idx]
        glyph = colorize(ROT[rot_idx])
        blanks = _TOSS_HEIGHT_MAX - height
        for _ in range(blanks):
            sys.stdout.write("\n")
        sys.stdout.write(f"  {glyph}\n")
        for _ in range(height):
            sys.stdout.write("\n")
        sys.stdout.flush()


# ---- Bar prefix (active transfer) ----

# How many bytes per rotation step. Tuned so a 100 MB/s LAN ticks roughly
# 10 times per second (visually fast but readable), and a 1 MB/s mobile
# tether ticks ~10 times per second too — because the rotation rate maps
# to *throughput* nonlinearly: chunks per step, not bytes per second.
# Chunk size is 1 MiB by default in takeit, so 1 step per ~1 MiB feels
# right across multiple orders of magnitude.
_BYTES_PER_ROTATION_STEP = 1 << 19  # 512 KiB


def rotate_glyph(bytes_seen):
    """Return the rotation glyph for the current byte count.

    Wire this on each ``progress.update(n)`` callback: the bar's prefix
    becomes a slowly-spinning block that visibly speeds up with throughput.
    Always returns a colored glyph if color is available.
    """
    step = bytes_seen // _BYTES_PER_ROTATION_STEP
    return colorize(ROT[step % len(ROT)])
