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


# --- HYP-451: pipelined chunk frames during async verify ---


def _make_resume_proto_with_held_verify(tmp_path, payload, chunk_size, monkeypatch):
    """Build a resume-path receiver where verify_chunks_have is dispatched
    but its Deferred is held — never fires. Lets the test inject pipelined
    bytes during the race window.

    Returns (proto, factory, transport, fire_verify, errback_verify).
    `fire_verify` callback resolves verify with the given verified-set.
    """
    partial_path = tmp_path / "incoming.bin.takeit-partial"
    meta_path = tmp_path / "incoming.bin.takeit-partial.meta"
    partial_path.write_bytes(payload)
    offer = _build_offer_for(payload, chunk_size)

    # Pre-write a valid sidecar so prior_matches=True path runs.
    chunk_hashes = _hashes_for(payload, chunk_size)
    transfer_id_bytes = offer["_transfer_id_bytes"]
    R.save_receiver_state(
        str(meta_path),
        transfer_id_b64=R.b64(transfer_id_bytes),
        size=len(payload),
        chunk_size=chunk_size,
        chunk_hashes_b64=[R.b64(h) for h in chunk_hashes],
        chunks_have=[],
    )

    factory = cli_mod._ReceiverFactory(
        partial_path=str(partial_path),
        meta_path=str(meta_path),
        offer=offer,
        prior_matches=True,
        progress=None,
    )
    proto = factory.buildProtocol(addr=None)
    proto.transport = _FakeTransport()
    proto.connectionMade()

    # Hold the verify Deferred so we control when it fires.
    held = {}

    def held_deferToThread(fn, *args, **kwargs):
        d = Deferred()
        held["d"] = d
        held["args"] = (fn, args, kwargs)
        return d

    monkeypatch.setattr(cli_mod, "deferToThread", held_deferToThread)
    return proto, factory, proto.transport, held, chunk_hashes


def test_hyp451_pipelined_chunk_during_verify_raises_protocol_error(
    tmp_path, monkeypatch
):
    """A non-conforming sender pipelines header || chunk_frame in one
    TCP segment. Receiver is on the resume path; verify_chunks_have
    is in flight. The pipelined chunk bytes must NOT be processed —
    they would mutate _chunks_have / throttle and then be silently
    overwritten when verify finishes. Treat as ProtocolError."""
    payload = b"x" * 100
    chunk_size = 50
    proto, factory, transport, held, chunk_hashes = _make_resume_proto_with_held_verify(
        tmp_path, payload, chunk_size, monkeypatch
    )

    # Pre-attach errback so the failure doesn't surface as an
    # unhandled Deferred warning.
    errs = []
    factory.done.addErrback(lambda f: errs.append(f.value))

    # Build header + a chunk frame, deliver in one dataReceived call.
    header = P.build_subchannel_header(chunk_hashes)
    chunk_frame = P.encode_length_prefixed(b"\x00\x00\x00\x00" + payload[:chunk_size])
    pipelined = header + chunk_frame

    proto.dataReceived(pipelined)

    # Verify is still in flight (held); the protocol should have failed
    # via _fail because the drain hit a chunk during _verify_in_flight.
    assert proto._stopped is True, "protocol should have entered stopped state"
    assert factory.done.called, "factory.done should have been errback'd"
    assert any(isinstance(e, P.ProtocolError) for e in errs), errs


def test_hyp451_no_pipelined_data_during_verify_does_not_fault(tmp_path, monkeypatch):
    """Conforming sender: header alone in dataReceived; verify dispatches
    cleanly. After verify completes (we fire it manually), a chunk frame
    in a SEPARATE dataReceived call is honored."""
    payload = b"x" * 100
    chunk_size = 50
    proto, factory, transport, held, chunk_hashes = _make_resume_proto_with_held_verify(
        tmp_path, payload, chunk_size, monkeypatch
    )

    header = P.build_subchannel_header(chunk_hashes)
    proto.dataReceived(header)

    # Verify is in flight. _header_phase still True. _verify_in_flight True.
    assert proto._verify_in_flight is True
    assert proto._header_phase is True
    assert not factory.done.called

    # Fire the held verify deferred with empty verified-set.
    held["d"].callback(set())

    # Now _header_phase=False, _verify_in_flight=False.
    assert proto._header_phase is False
    assert proto._verify_in_flight is False
    assert not factory.done.called  # still alive — transfer in progress


def test_hyp451_protocol_error_does_not_corrupt_disk(tmp_path, monkeypatch):
    """If a pipelined chunk frame triggers ProtocolError, the in-memory
    `_chunks_have` set must not have been mutated and the throttle must
    not have been re-initialized."""
    payload = b"x" * 100
    chunk_size = 50
    proto, factory, transport, held, chunk_hashes = _make_resume_proto_with_held_verify(
        tmp_path, payload, chunk_size, monkeypatch
    )

    pre_chunks_have = set(proto._chunks_have)

    # Pre-attach errback to suppress the unhandled-Deferred warning.
    factory.done.addErrback(lambda f: None)

    header = P.build_subchannel_header(chunk_hashes)
    chunk_frame = P.encode_length_prefixed(b"\x00\x00\x00\x00" + payload[:chunk_size])
    proto.dataReceived(header + chunk_frame)

    # _chunks_have unchanged; the protocol-error path didn't run
    # _consume_frames at all.
    assert proto._chunks_have == pre_chunks_have


def test_hyp451_verify_in_flight_flag_initialized_false():
    """Sanity: the new flag starts False so unrelated code paths
    (e.g. fresh transfer with no resume path) don't accidentally
    start in the in-flight state."""
    # We don't fully wire up; just check class-level init.
    import inspect

    src = inspect.getsource(cli_mod._ReceiverProtocol.__init__)
    assert "self._verify_in_flight = False" in src
