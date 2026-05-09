"""
Tests for receiver-side resume races (HYP-451, HYP-452).

HYP-452: the sidecar can disappear between `_run_receive`'s
match-check and `_on_header_received`'s reload (concurrent rm,
chmod, fs hiccup, etc.). When that happens, `R.load_receiver_state`
returns None and the old code hit `prior.get(...)` → AttributeError.
The fix: detect None and fall back to fresh-transfer (strictly safer
than the resume path).

HYP-451: pipelined chunk frames received during async resume
verification used to be processed before _header_phase=False, then
overwritten when _on_chunks_have_verified seeded the canonical
chunks_have set. Either ProtocolError or buffered-flush is correct;
this test suite pins the chosen ProtocolError shape.
"""

import hashlib

from twisted.internet.defer import Deferred

from takeit.cli import _protocol as P
from takeit.cli import _resume as R
from takeit.cli import cli as cli_mod


class _FakeTransport:
    def __init__(self):
        self.writes = []
        self.connection_lost = False

    def write(self, data):
        self.writes.append(data)

    def loseConnection(self):
        self.connection_lost = True


def _hashes_for(payload, chunk_size):
    hashes = []
    for i in range(0, len(payload), chunk_size):
        hashes.append(
            hashlib.blake2b(payload[i : i + chunk_size], digest_size=32).digest()
        )
    return hashes


def _build_offer_for(payload, chunk_size, filename="incoming.bin"):
    """Mirror what `build_offer_file` produces, plus the cli-side
    `_content_hash_bytes` / `_transfer_id_bytes` decorations the
    receiver protocol expects."""
    content_hash = hashlib.blake2b(payload, digest_size=32).digest()
    transfer_id = P.compute_transfer_id(
        P.KIND_FILE, len(payload), filename, content_hash
    )
    return {
        "kind": "file",
        "filename": filename,
        "size": len(payload),
        "chunk_size": chunk_size,
        "content_hash": content_hash.hex(),
        "transfer_id": transfer_id.hex(),  # b64/hex doesn't matter for the
        # internal fields; the receiver protocol only reads kind/size/
        # chunk_size/_content_hash_bytes/_transfer_id_bytes.
        "_content_hash_bytes": content_hash,
        "_transfer_id_bytes": transfer_id,
    }


def _make_proto_with_partial(tmp_path, payload, chunk_size, prior_matches):
    """Build a wired-up _ReceiverProtocol with partial file pre-staged
    so connectionMade can open it. Returns (proto, factory, transport).
    The chunks_have async verify deferred is NOT fired automatically —
    callers can inspect deferToThread args.
    """
    partial_path = tmp_path / "incoming.bin.takeit-partial"
    meta_path = tmp_path / "incoming.bin.takeit-partial.meta"
    # Pre-stage the partial; resume needs it to exist.
    partial_path.write_bytes(payload if prior_matches else b"")
    offer = _build_offer_for(payload, chunk_size)
    factory = cli_mod._ReceiverFactory(
        partial_path=str(partial_path),
        meta_path=str(meta_path),
        offer=offer,
        prior_matches=prior_matches,
        progress=None,
    )
    proto = factory.buildProtocol(addr=None)
    proto.transport = _FakeTransport()
    proto.connectionMade()
    return proto, factory, proto.transport


# --- HYP-452: sidecar disappears between match-check and reload ---


def test_hyp452_sidecar_missing_falls_back_to_fresh_transfer(tmp_path):
    """Match-check at _run_receive set _prior_matches=True, but by
    the time _on_header_received runs, the sidecar is gone. Old code
    raised AttributeError on prior.get(...). New code falls back to
    fresh-transfer (chunks_have = []).
    """
    payload = b"x" * 100
    chunk_size = 50
    proto, factory, transport = _make_proto_with_partial(
        tmp_path, payload, chunk_size, prior_matches=True
    )
    # Sidecar was never written — load_receiver_state will return None.
    # (In a real race, _run_receive saw it and it disappeared. Same
    # observable effect here.)
    assert not (tmp_path / "incoming.bin.takeit-partial.meta").exists()

    # Drive the protocol with a valid header; _on_header_received
    # reloads the sidecar, finds None, and must NOT raise.
    chunk_hashes = _hashes_for(payload, chunk_size)
    header = P.build_subchannel_header(chunk_hashes)
    proto.dataReceived(header)

    # Receiver should have sent a chunks_have reply with empty list
    # (fresh transfer). Header phase flipped off.
    assert proto._header_phase is False
    assert proto._chunks_have == set()
    # The reply is the most recent write.
    assert len(transport.writes) >= 1
    decoder = P.LengthPrefixedDecoder()
    bodies = list(decoder.feed(transport.writes[-1]))
    assert len(bodies) == 1
    parsed = P.parse_chunks_have(bodies[0], total_chunks=len(chunk_hashes))
    assert parsed == []


def test_hyp452_sidecar_corrupt_json_falls_back_to_fresh_transfer(tmp_path):
    """Sidecar exists but is unparseable. load_receiver_state returns
    None; receiver falls back to fresh-transfer, no AttributeError."""
    payload = b"x" * 100
    chunk_size = 50
    proto, factory, transport = _make_proto_with_partial(
        tmp_path, payload, chunk_size, prior_matches=True
    )
    # Write a corrupt sidecar AFTER connectionMade so the partial open
    # already succeeded; _on_header_received will be the one to reload.
    (tmp_path / "incoming.bin.takeit-partial.meta").write_text("not json{")

    chunk_hashes = _hashes_for(payload, chunk_size)
    header = P.build_subchannel_header(chunk_hashes)
    proto.dataReceived(header)

    assert proto._header_phase is False
    assert proto._chunks_have == set()


def test_hyp452_sidecar_present_and_valid_takes_resume_path(tmp_path):
    """Negative control: when the sidecar IS present and valid,
    the resume path runs and verify_chunks_have is dispatched.
    """
    payload = b"x" * 100
    chunk_size = 50
    proto, factory, transport = _make_proto_with_partial(
        tmp_path, payload, chunk_size, prior_matches=True
    )
    # Pre-write a valid sidecar matching the partial.
    chunk_hashes = _hashes_for(payload, chunk_size)
    transfer_id_bytes = _build_offer_for(payload, chunk_size)["_transfer_id_bytes"]
    R.save_receiver_state(
        str(tmp_path / "incoming.bin.takeit-partial.meta"),
        transfer_id_b64=R.b64(transfer_id_bytes),
        size=len(payload),
        chunk_size=chunk_size,
        chunk_hashes_b64=[R.b64(h) for h in chunk_hashes],
        chunks_have=[0],
    )
    # Capture deferToThread to confirm verify path runs.
    calls = []

    def fake_deferToThread(fn, *args, **kwargs):
        calls.append((fn, args, kwargs))
        d = Deferred()
        # Don't auto-fire; just confirm dispatch happened.
        return d

    import takeit.cli.cli as cli_mod_local

    orig = cli_mod_local.deferToThread
    cli_mod_local.deferToThread = fake_deferToThread
    try:
        header = P.build_subchannel_header(chunk_hashes)
        proto.dataReceived(header)
    finally:
        cli_mod_local.deferToThread = orig

    # verify_chunks_have should have been dispatched.
    assert len(calls) == 1
    fn, args, _ = calls[0]
    assert fn is R.verify_chunks_have
    # Header phase still True until the verify deferred fires.
    assert proto._header_phase is True


# --- HYP-451 tests will be added in the HYP-451 commit ---
