import inspect
from types import SimpleNamespace

import pytest

from takeit._dilation import manager as manager_mod
from takeit._dilation.subchannel import (
    SubchannelDemultiplex,
    UnexpectedSubprotocol,
)


def test_subchannel_demux_rejects_unexpected_subprotocol():
    demux = SubchannelDemultiplex(expected_subprotocols={"takeit-xfer-v1"})
    with pytest.raises(UnexpectedSubprotocol):
        demux._got_open(object(), SimpleNamespace(subprotocol="other"))


def test_manager_wires_expected_subprotocols_into_demux():
    # Whitespace-insensitive check so a ruff/black reformat doesn't break the
    # contract — what we care about is that Manager passes the allowlist into
    # SubchannelDemultiplex's constructor, not how that call line wraps.
    src = inspect.getsource(manager_mod.Manager.__attrs_post_init__)
    normalized = " ".join(src.split())
    assert (
        "SubchannelDemultiplex( self._expected_subprotocols )" in normalized
        or "SubchannelDemultiplex(self._expected_subprotocols)" in normalized
    )


# --- HYP-437: CLI passes expected_subprotocols so the allowlist is enforced ---


def test_cli_send_passes_expected_subprotocols_to_dilate():
    """HYP-413 wired SubchannelDemultiplex to enforce an allowlist when
    expected_subprotocols is non-None. HYP-437 ensures the CLI WIRES
    that allowlist on the send path; without this, HYP-413's defense
    is dormant and any authenticated peer can OPEN arbitrary
    subchannel names."""
    from takeit.cli import cli as cli_mod

    src = inspect.getsource(cli_mod._do_send)
    normalized = " ".join(src.split())
    assert "expected_subprotocols={P.SUBCHANNEL_NAME}" in normalized, (
        "expected _do_send's w.dilate(...) call to pass "
        "expected_subprotocols={P.SUBCHANNEL_NAME} so HYP-413's "
        "allowlist actually fires in production"
    )


def test_cli_receive_passes_expected_subprotocols_to_dilate():
    """Same wiring on the receive path."""
    from takeit.cli import cli as cli_mod

    src = inspect.getsource(cli_mod._run_receive)
    normalized = " ".join(src.split())
    assert "expected_subprotocols={P.SUBCHANNEL_NAME}" in normalized, (
        "expected _run_receive's w.dilate(...) call to pass "
        "expected_subprotocols={P.SUBCHANNEL_NAME} so HYP-413's "
        "allowlist actually fires in production"
    )


# --- HYP-442: expected_subprotocols is required keyword-only on Dilator.dilate ---


def test_dilator_dilate_expected_subprotocols_is_keyword_only_no_default():
    """HYP-442: making expected_subprotocols keyword-only with no default
    surfaces missing-arg as a loud TypeError at every library callsite.
    HYP-437 fixed the CLI; this fixes the library default. Symmetric
    closure to feedback_pin_defense_activation: an opt-in defense
    should be hard to forget at the outermost layer."""
    from takeit._dilation.manager import Dilator

    sig = inspect.signature(Dilator.dilate)
    param = sig.parameters.get("expected_subprotocols")
    assert param is not None, "Dilator.dilate must declare expected_subprotocols"
    assert param.kind is inspect.Parameter.KEYWORD_ONLY, (
        "expected_subprotocols must be keyword-only so callers can't "
        "rely on positional argument order silently filling it in"
    )
    assert param.default is inspect.Parameter.empty, (
        "expected_subprotocols must have NO default so callers MUST "
        "name an allowlist (use an empty set for 'reject all')"
    )


def test_subchannel_demux_requires_expected_subprotocols():
    """HYP-442 paired change: SubchannelDemultiplex no longer accepts
    None. Library callers building dilation by hand can't stumble
    into the legacy 'queue everything' behavior anymore."""
    with pytest.raises((TypeError, ValueError)):
        SubchannelDemultiplex(expected_subprotocols=None)


def test_subchannel_demux_empty_set_rejects_all_unknown():
    """expected_subprotocols=frozenset() is the explicit 'reject all'
    posture — every OPEN with an unregistered name raises."""
    demux = SubchannelDemultiplex(expected_subprotocols=frozenset())
    with pytest.raises(UnexpectedSubprotocol):
        demux._got_open(object(), SimpleNamespace(subprotocol="anything"))


def test_dilator_dilate_without_expected_subprotocols_raises():
    """End-to-end signature pin: calling Dilator.dilate() without the
    kwarg is a TypeError (because it's keyword-only-no-default).
    Bound-method check via inspect; we don't need a real Dilator
    instance to verify this — Python's binding machinery enforces
    the signature."""
    from takeit._dilation.manager import Dilator

    # Dilator.dilate is a regular method; pretend `self` is a sentinel
    # and call through the unbound function. Python evaluates the
    # signature BEFORE the body, so we never reach any code that needs
    # a real instance.
    sentinel = object()
    with pytest.raises(TypeError, match="expected_subprotocols"):
        Dilator.dilate(sentinel)
