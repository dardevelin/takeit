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
