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
