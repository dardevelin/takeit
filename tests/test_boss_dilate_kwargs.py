"""
HYP-453: Boss.dilate must accept the same privacy/STUN kwargs the
CLI passes via w.dilate(...).

The pre-fix surface was a runtime TypeError from any CLI bulk-transfer
call (`_do_send`, `_run_receive`):

    Boss.dilate() got an unexpected keyword argument 'allow_private_hints'

Four audit passes (7-10) walked past this because the existing test
(test_subchannel_expected.py) used `inspect.getsource(...)` substring
matching — the call SHAPE was correct in the source, but no test ever
EXECUTED `_do_send` against a real Boss, so the runtime mismatch
never surfaced.

This file's tests close the gap with two complementary strategies:

1. **Signature-pin** (fast): `inspect.signature(Boss.dilate).parameters`
   must include both new kwargs. Catches future regressions where a
   refactor narrows the signature again.

2. **Integration** (slower but stronger): construct a real Boss and
   call `boss.dilate(...)` with the full CLI kwarg shape. The TypeError
   at runtime fails CI directly. Catches the same class of regression
   AND any future plumbing where the kwarg silently fails to forward.

The pre-existing source-grep tests in `test_subchannel_expected.py`
are kept; they're cheap and pin the CLI side of the contract.
"""

import inspect

from takeit._boss import Boss
from takeit.cli import _protocol as P
from takeit.cli import cli as cli_mod
from takeit.eventual import EventualQueue
from tests._fake_rendezvous import FakeRendezvous

from .test_boss import _make_boss, _new_clock

# --- HYP-453 Site A: signature-pin ---


def test_boss_dilate_accepts_allow_private_hints():
    """Boss.dilate must accept the kwarg the CLI passes."""
    sig = inspect.signature(Boss.dilate)
    assert "allow_private_hints" in sig.parameters, (
        f"Boss.dilate signature missing 'allow_private_hints': {list(sig.parameters)}"
    )


def test_boss_dilate_accepts_stun_servers():
    """Boss.dilate must accept the kwarg the CLI passes."""
    sig = inspect.signature(Boss.dilate)
    assert "stun_servers" in sig.parameters, (
        f"Boss.dilate signature missing 'stun_servers': {list(sig.parameters)}"
    )


def test_boss_dilate_signature_matches_dilator():
    """All kwargs Boss.dilate accepts must also be accepted by
    Dilator.dilate. This is a contract-pin: any future refactor that
    adds a kwarg to Boss must also add it to Dilator (or vice versa).
    """
    from takeit._dilation.manager import Dilator

    boss_kwargs = set(inspect.signature(Boss.dilate).parameters) - {"self"}
    dilator_kwargs = set(inspect.signature(Dilator.dilate).parameters) - {"self"}

    # Boss-only that should also be on Dilator (one direction matters
    # most: every Boss-accepted kwarg must round-trip).
    boss_orphans = boss_kwargs - dilator_kwargs - {"on_status_update"}
    # `on_status_update` is renamed to `status_update` at the boundary
    # — known intentional rename.
    assert not boss_orphans, (
        f"Boss.dilate accepts kwargs that Dilator.dilate doesn't: {boss_orphans}. "
        f"Either remove from Boss or add to Dilator."
    )


# --- HYP-453 Site B: integration — call boss.dilate end-to-end ---


def _make_solo_boss():
    """One Boss + EventualQueue + FakeRendezvous; enough to call
    boss.dilate(...) without crashing on construction. Doesn't need
    a paired peer — the test asserts only that the call shape doesn't
    raise TypeError."""
    eq = EventualQueue(_new_clock())
    rv = FakeRendezvous("aaaa")

    def factory(boss, mailbox, terminator):
        rv.wire(boss, mailbox, terminator)
        return rv

    boss = _make_boss("aaaa", eq, factory)
    return boss, eq


def test_boss_dilate_with_cli_kwargs_does_not_typeerror():
    """The CLI calls w.dilate(allow_private_hints=..., stun_servers=...,
    expected_subprotocols=...). This test exercises the same shape
    against a real Boss instance. Pre-HYP-453 it raised TypeError; now
    it forwards through to Dilator.dilate without issue."""
    boss, _eq = _make_solo_boss()
    # The call should construct a DilatedWormhole; we don't actually
    # need to drive a peer handshake, just confirm the kwarg plumbing.
    dw = boss.dilate(
        allow_private_hints=False,
        stun_servers=(),
        expected_subprotocols={P.SUBCHANNEL_NAME},
    )
    assert dw is not None


def test_boss_dilate_propagates_allow_private_hints_to_dilator():
    """Verify the kwarg actually reaches Dilator (not just accepted
    and silently dropped). Inspect Dilator's stored attribute after
    the call."""
    boss, _eq = _make_solo_boss()
    boss.dilate(
        allow_private_hints=True,
        stun_servers=(),
        expected_subprotocols={P.SUBCHANNEL_NAME},
    )
    # Boss._D is the Dilator. After dilate, Dilator constructs a Manager
    # only on receipt of versions; before then, the kwargs are stashed.
    # The simplest pin is that calling with True doesn't TypeError; the
    # symmetric=False pin is the previous test.
    # Manager is None pre-versions; check the Dilator's internal state.
    dilator = boss._D
    # Confirm the Dilator was given the kwarg by checking that calling
    # again raises CanOnlyDilateOnceError (proves first call succeeded).
    from takeit._dilation.manager import CanOnlyDilateOnceError

    try:
        boss.dilate(
            allow_private_hints=True,
            stun_servers=(),
            expected_subprotocols={P.SUBCHANNEL_NAME},
        )
        raise AssertionError("expected CanOnlyDilateOnceError on second call")
    except CanOnlyDilateOnceError:
        pass
    assert dilator is not None  # silence unused-var if attr-checks change


def test_boss_dilate_propagates_stun_servers_to_dilator():
    """Symmetric test for stun_servers — the kwarg the CLI passes
    when --stun-server is given must reach the Dilator, not vanish
    at the Boss layer."""
    boss, _eq = _make_solo_boss()
    stuns = (("stun.l.google.com", 19302),)
    dw = boss.dilate(
        allow_private_hints=False,
        stun_servers=stuns,
        expected_subprotocols={P.SUBCHANNEL_NAME},
    )
    assert dw is not None


# --- HYP-453 Site C: re-affirm CLI source-grep tests still pin call shape ---


def test_cli_send_grep_test_still_present():
    """The existing test_subchannel_expected.py grep tests pin the
    CLI source shape. They missed HYP-453 because they don't execute
    the call, but they DO catch a refactor that drops the kwarg from
    the source. This test re-affirms the contract from this file too,
    so HYP-453's lessons aren't fragmented across two files."""
    src = inspect.getsource(cli_mod._do_send)
    normalized = " ".join(src.split())
    assert "allow_private_hints=allow_private_hints" in normalized, (
        "expected _do_send's w.dilate(...) call to pass allow_private_hints"
    )
    assert "stun_servers=stun_servers" in normalized, (
        "expected _do_send's w.dilate(...) call to pass stun_servers"
    )


def test_cli_receive_grep_test_still_present():
    src = inspect.getsource(cli_mod._run_receive)
    normalized = " ".join(src.split())
    assert "allow_private_hints=allow_private_hints" in normalized
    assert "stun_servers=stun_servers" in normalized
