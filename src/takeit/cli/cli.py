"""
takeit command-line interface.

Two subcommands: ``send`` and ``receive``. Aliases ``tx`` / ``rx``. The
protocol shape (offer with chunk hashes → answer with chunks_have → bulk
chunked stream → complete → done) is defined in `takeit.cli._protocol`,
and resume sidecar files in `takeit.cli._resume`. This module is the
Twisted + Click glue that wires it to a real wormhole + dilation transport.
"""
import os
import sys

import click
import tqdm as tqdm_module
from twisted.internet.defer import Deferred, inlineCallbacks
from twisted.internet.protocol import ClientFactory, Factory, Protocol
from twisted.internet.task import react
from twisted.internet.threads import deferToThread
from twisted.python import log

import takeit
from takeit.cli import _protocol as P
from takeit.cli import _resume as R
from takeit.errors import KeyFormatError, WrongPasswordError


def _make_progress_bar(total_bytes, initial_bytes=0, desc="transfer"):
    """Build a tqdm progress bar configured for byte-rate display.

    Returns a no-op shim if stdout isn't a TTY so tqdm doesn't paint
    progress lines into log files / pipes / CI runs. The shim has the
    same `update`, `close`, `__enter__`, and `__exit__` surface.
    """
    if not sys.stdout.isatty():
        class _Noop:
            def update(self, n): pass
            def close(self): pass
            def __enter__(self): return self
            def __exit__(self, *a): return False
        return _Noop()
    return tqdm_module.tqdm(
        total=total_bytes,
        initial=initial_bytes,
        unit="B",
        unit_scale=True,
        unit_divisor=1024,
        desc=desc,
        leave=False,
    )


APPID = "takeit/file-xfer"


def _default_output_dir():
    """Pick a sensible default destination directory.

    Prefer ``~/Downloads`` if it exists and is writable; otherwise fall
    back to the current directory. Avoids the surprise of running
    ``takeit receive`` from ``~`` and finding files dumped into the home
    folder.
    """
    downloads = os.path.expanduser("~/Downloads")
    try:
        if os.path.isdir(downloads) and os.access(downloads, os.W_OK):
            return downloads
    except OSError:
        pass
    return "."


# ---- Click commands ----


@click.group(invoke_without_command=False)
@click.version_option(takeit.__version__, prog_name="takeit")
@click.option("--debug", is_flag=True, default=False,
              help="Print Twisted tracebacks on errors (verbose).")
@click.pass_context
def main(ctx, debug):
    """takeit — securely transfer files between computers, peer-to-peer."""
    ctx.ensure_object(dict)
    ctx.obj["debug"] = debug


@main.command("send")
@click.argument("path", type=click.Path(exists=True, dir_okay=False,
                                        readable=True, resolve_path=True))
@click.option("--code-length", type=int, default=3,
              help="Number of words in the generated code (default: 3).")
@click.option("--relay", "relays", multiple=True,
              help="Override Nostr relay URLs (may be repeated).")
@click.option("--code", "explicit_code", default=None,
              help="Use this code instead of allocating a fresh one.")
@click.option("--no-cache", is_flag=True, default=False,
              help="Don't read or write the per-file chunk-hash cache.")
@click.option("--qr", is_flag=True, default=False,
              help="Also render the code as a terminal QR code "
                   "(useful for hand-off to a phone).")
@click.pass_context
def cmd_send(ctx, path, code_length, relays, explicit_code, no_cache, qr):
    """Send a file."""
    relay_list = list(relays) if relays else None
    react(_run_send, (path, code_length, relay_list, explicit_code,
                      not no_cache, qr, ctx.obj.get("debug", False)))


@main.command("receive")
@click.argument("code", required=False, default=None)
@click.option("--accept/--no-accept", "-y/", "auto_accept", default=False,
              help="Skip the y/N accept prompt (alias: -y).")
@click.option("--relay", "relays", multiple=True,
              help="Override Nostr relay URLs (may be repeated).")
@click.option("--output-dir", "output_dir", type=click.Path(file_okay=False),
              default=None,
              help="Where to save the received file "
                   "(default: ~/Downloads if it exists, else current dir).")
@click.pass_context
def cmd_receive(ctx, code, auto_accept, relays, output_dir):
    """Receive a file using a code.

    If no CODE is given, you'll be prompted to type one with tab-completion
    against the wordlist.
    """
    relay_list = list(relays) if relays else None
    if output_dir is None:
        output_dir = _default_output_dir()
    react(_run_receive,
          (code, auto_accept, relay_list, output_dir,
           ctx.obj.get("debug", False)))


@main.command("completion")
@click.argument("shell", type=click.Choice(["bash", "zsh", "fish"]))
def cmd_completion(shell):
    """Print the shell-completion script for the given shell.

    Install for zsh:  ``eval "$(takeit completion zsh)"`` in ``.zshrc``.
    Install for bash: ``eval "$(takeit completion bash)"`` in ``.bashrc``.
    Install for fish: ``takeit completion fish > ~/.config/fish/completions/takeit.fish``.
    """
    from click.shell_completion import shell_complete
    # shell_complete prints to stdout and returns an exit code.
    code = shell_complete(
        cli=main, ctx_args={}, prog_name="takeit",
        complete_var="_TAKEIT_COMPLETE", instruction=f"{shell}_source")
    sys.exit(code)


# Aliases — Click groups don't support aliasing directly, so register again.
main.add_command(cmd_send, name="tx")
main.add_command(cmd_receive, name="rx")


# ---- shared error handling ----


def _handle_cli_error(exc, debug):
    """Render an exception as a friendly user-facing error.

    Common protocol errors get tailored messages; unknown errors fall
    through to a generic "Error: ...". Twisted tracebacks via `log.err()`
    are gated behind the ``--debug`` flag so plain users never see them.
    Returns the exit code.
    """
    if isinstance(exc, WrongPasswordError):
        click.echo("Error: wrong code (decryption failed)", err=True)
        return 1
    if isinstance(exc, KeyFormatError):
        click.echo(f"Error: {exc}", err=True)
        return 2
    if isinstance(exc, P.ProtocolError):
        click.echo(f"Error: protocol violation by sender: {exc}", err=True)
        return 1
    click.echo(f"Error: {exc}", err=True)
    if debug:
        log.err()
    return 1


# ---- Send flow ----


@inlineCallbacks
def _run_send(reactor, path, code_length, relays, explicit_code,
              use_cache, qr, debug):
    filename = os.path.basename(path)
    cache_path = R.sender_cache_path(path)
    chunk_size = P.DEFAULT_CHUNK_SIZE

    # Load cached hashes if the file is unchanged; otherwise compute fresh.
    cache = R.load_sender_cache(cache_path, path) if use_cache else None
    if cache and cache["chunk_size"] == chunk_size:
        click.echo(f"Using cached chunk hashes for {filename}")
        size = cache["size"]
        content_hash = R.b64d(cache["content_hash"])
        chunk_hashes = [R.b64d(h) for h in cache["chunk_hashes"]]
    else:
        click.echo(f"Hashing {filename}...")
        # Hashing a multi-GiB file at ~500 MB/s BLAKE2b is ~20 s of work; do
        # it on a worker thread so the reactor stays responsive (Nostr
        # keepalives, dilation pings, UI). The save_sender_cache write is
        # tiny (one fsync) and runs on the reactor thread post-hash.
        size, content_hash, chunk_hashes = yield deferToThread(
            P.chunk_hashes_for_file, path, chunk_size)
        if use_cache:
            R.save_sender_cache(
                cache_path, path, chunk_size,
                content_hash_b64=R.b64(content_hash),
                chunk_hashes_b64=[R.b64(h) for h in chunk_hashes])

    w = takeit.create(appid=APPID, reactor=reactor, relays=relays)
    try:
        if explicit_code:
            w.set_code(explicit_code)
        else:
            w.allocate_code(code_length=code_length)
        code = yield w.get_code()
        click.echo(f"Wormhole code: {code}")
        click.echo("On the receiving machine, run:")
        click.echo(f"    takeit receive {code}")
        if qr:
            _print_qr(code)

        # Send the offer
        offer_msg = P.build_offer(
            filename, size, content_hash, chunk_hashes, chunk_size=chunk_size)
        w.send_message(P.encode_message(offer_msg))

        # Wait for the answer (which may include resumed chunk indices)
        answer_payload = yield w.get_message()
        accepted, reason, chunks_have = P.parse_answer(answer_payload)
        if not accepted:
            click.echo(f"Receiver declined: {reason}", err=True)
            yield w.close()
            sys.exit(1)

        chunks_to_send = sorted(
            set(range(len(chunk_hashes))) - set(chunks_have))
        skipped = len(chunks_have)
        if skipped:
            click.echo(f"Resuming: receiver already has {skipped} chunk(s); "
                       f"sending {len(chunks_to_send)}")

        # Dilate and stream the file body over a subchannel
        dw = w.dilate()
        yield dw.when_dilated()
        ep = dw.connector_for(P.SUBCHANNEL_NAME)
        click.echo(f"Sending {filename} ({_pretty_size(size)})...")
        # Bytes to send = sum of remaining chunk sizes. The last chunk may
        # be short — compute against actual sizes, not chunk_size * count.
        bytes_to_send = sum(
            min(chunk_size, size - i * chunk_size) for i in chunks_to_send)
        progress = _make_progress_bar(bytes_to_send, desc="sending")
        try:
            yield _send_chunks_over_subchannel(
                reactor, ep, path, chunk_size, chunks_to_send,
                progress=progress)
        finally:
            progress.close()

        w.send_message(P.encode_message(P.build_complete()))
        done_payload = yield w.get_message()
        P.parse_simple_flag(done_payload, "done")
        click.echo("Transfer complete.")
        yield w.close()
    except Exception as exc:
        sys.exit(_handle_cli_error(exc, debug))


@inlineCallbacks
def _send_chunks_over_subchannel(reactor, endpoint, path, chunk_size,
                                 chunks_to_send, progress=None):
    factory = _SenderFactory(path, chunk_size, chunks_to_send, progress)
    yield endpoint.connect(factory)
    yield factory.done


class _SenderFactory(ClientFactory):
    def __init__(self, path, chunk_size, chunks_to_send, progress=None):
        self._path = path
        self._chunk_size = chunk_size
        self._chunks_to_send = chunks_to_send
        self._progress = progress  # tqdm-like, or None
        self.done = Deferred()

    def buildProtocol(self, addr):
        return _SenderProtocol(self)


class _SenderProtocol(Protocol):
    """Streams chunks to the dilation subchannel using a pull producer.

    Registers as a non-streaming (pull) producer on the transport so that
    `resumeProducing` is called only when the transport has buffer room —
    this gives proper backpressure and bounds memory to roughly the size
    of one chunk in flight, regardless of how big the file is. Disk reads
    happen on a worker thread so the reactor isn't blocked on slow disks.
    """

    def __init__(self, factory):
        self._factory = factory
        self._fh = None
        self._chunks_iter = None
        self._read_in_flight = False
        self._stopped = False
        self._finished = False
        self._progress = factory._progress

    def connectionMade(self):
        try:
            self._fh = open(self._factory._path, "rb")
        except Exception as e:
            self._factory.done.errback(e)
            self.transport.loseConnection()
            return
        self._chunks_iter = iter(self._factory._chunks_to_send)
        # streaming=False -> resumeProducing called repeatedly until we
        # unregister; pauseProducing is a no-op for pull producers.
        self.transport.registerProducer(self, False)

    def resumeProducing(self):
        if self._stopped or self._read_in_flight:
            return
        try:
            idx = next(self._chunks_iter)
        except StopIteration:
            self._finished = True
            self.transport.unregisterProducer()
            self.transport.loseConnection()
            return

        # Read off the reactor thread so a slow disk doesn't block other
        # reactor work (Nostr keepalives, dilation pings, etc.).
        self._read_in_flight = True
        d = deferToThread(_read_chunk,
                          self._fh, idx, self._factory._chunk_size)
        d.addCallback(self._chunk_read, idx)
        d.addErrback(self._read_failed)

    def _chunk_read(self, data, idx):
        self._read_in_flight = False
        if self._stopped:
            return
        if not data:
            self._fail(IOError(f"chunk index {idx} past end of file"))
            return
        self.transport.write(P.frame(idx, data))
        if self._progress is not None:
            self._progress.update(len(data))
        # The transport will call resumeProducing again when ready.

    def _read_failed(self, failure):
        self._read_in_flight = False
        self._fail(failure.value)

    def _fail(self, exc):
        self._stopped = True
        try:
            self.transport.unregisterProducer()
        except Exception:
            pass
        if not self._factory.done.called:
            self._factory.done.errback(exc)
        self.transport.loseConnection()

    def pauseProducing(self):
        # Pull producer: nothing to do. resumeProducing is called when ready.
        pass

    def stopProducing(self):
        self._stopped = True

    def connectionLost(self, reason):
        if self._fh is not None:
            try:
                self._fh.close()
            except Exception:
                pass
            self._fh = None
        if self._factory.done.called:
            return
        if self._finished:
            self._factory.done.callback(None)
        else:
            self._factory.done.errback(
                IOError(f"subchannel closed before transfer finished: "
                        f"{reason.getErrorMessage()}"))


def _read_chunk(fh, idx, chunk_size):
    """Worker-thread helper: seek + read one chunk."""
    fh.seek(idx * chunk_size)
    return fh.read(chunk_size)


# ---- Receive flow ----


@inlineCallbacks
def _run_receive(reactor, code, auto_accept, relays, output_dir, debug):
    w = takeit.create(appid=APPID, reactor=reactor, relays=relays)
    try:
        # B2: resolve output_dir via realpath so a symlinked output_dir
        # can't direct writes to an unintended location, and verify it's
        # actually a directory we can use.
        try:
            output_dir_real = os.path.realpath(output_dir)
            if not os.path.isdir(output_dir_real):
                click.echo(
                    f"Error: --output-dir {output_dir!r} is not a directory",
                    err=True)
                sys.exit(1)
        except OSError as e:
            click.echo(f"Error: cannot resolve --output-dir: {e}", err=True)
            sys.exit(1)

        # B4: sweep any orphan .tmp meta files left from prior crashes,
        # so they don't accumulate over time.
        R.cleanup_orphan_tmp_files(output_dir_real)

        # C2: interactive code entry. If `code` is None (positional
        # omitted), drop into a readline-driven prompt with tab completion
        # against the local PGP wordlist. The helper runs in a worker
        # thread; `input_with_completion` returns whether completion was
        # used (we discard that — the helper has already submitted the
        # code via choose_words, which fires Code.finished_input which
        # fires Boss.got_code and Key.got_code).
        if code is None:
            from .. import _rlcompleter
            helper = w.input_code()
            yield _rlcompleter.input_with_completion(
                "takeit code: ", helper, reactor)
            code = yield w.get_code()
        else:
            w.set_code(code)
        offer_payload = yield w.get_message()
        offer = P.parse_offer(offer_payload)
        click.echo(
            f"Offered: {offer['filename']} ({_pretty_size(offer['size'])})")

        dest_path = os.path.join(output_dir_real, offer["filename"])
        partial_path, meta_path = R.receiver_paths(dest_path)

        # A4: refuse if anything already exists at dest_path. lstat (not
        # exists) so we catch dangling symlinks too — those return False
        # from os.path.exists but would be followed by os.rename.
        try:
            os.lstat(dest_path)
            click.echo(f"Error: {dest_path} already exists; refusing to "
                       "overwrite", err=True)
            w.send_message(P.encode_message(
                P.build_answer(False, "destination exists")))
            yield w.close()
            sys.exit(1)
        except FileNotFoundError:
            pass  # good — destination is clear

        # Defense in depth: even after realpath on output_dir, ensure the
        # resolved dest stays inside it. The filename validator already
        # forbids separators in the offer's filename, so this is a
        # belt-and-suspenders check.
        if os.path.dirname(os.path.realpath(dest_path)) != output_dir_real:
            click.echo("Error: refusing to write outside --output-dir",
                       err=True)
            w.send_message(P.encode_message(
                P.build_answer(False, "destination escapes output_dir")))
            yield w.close()
            sys.exit(1)

        # Check for resumable state. Compute chunks_have silently here;
        # surface it to the user as part of the "Receiving into …"
        # message AFTER they accept, so a "Resuming: N chunks" line
        # before the prompt doesn't imply the transfer has started.
        offer_chunk_hashes_b64 = offer["chunk_hashes"]
        prior = R.load_receiver_state(meta_path)
        chunks_have = []
        dropped_chunks = 0
        stale_partial = False
        if prior is not None and R.can_resume_with(
                prior, offer["transfer_id"], offer["size"],
                offer["chunk_size"], offer_chunk_hashes_b64):
            # A5: do NOT trust the sidecar's chunks_have. A same-user
            # attacker could pre-stage a malicious sidecar that matches
            # the offer's deterministic transfer_id but claims indices
            # the receiver doesn't actually have. Re-hash each claimed
            # index from disk before agreeing to skip it.
            claimed = list(prior["chunks_have"])
            verified = yield deferToThread(
                R.verify_chunks_have,
                partial_path,
                offer["size"],
                offer["chunk_size"],
                offer["_chunk_hashes_bytes"],
                claimed)
            chunks_have = sorted(verified)
            dropped_chunks = len(claimed) - len(chunks_have)
        elif prior is not None:
            stale_partial = True

        if not auto_accept:
            if not click.confirm("Accept?", default=False):
                w.send_message(P.encode_message(
                    P.build_answer(False, "user declined")))
                yield w.close()
                return

        # Now that the user has consented, surface the resume state and
        # clean up any stale partial.
        if stale_partial:
            click.echo("Discarding stale partial (offer doesn't match)")
            R.cleanup_receiver(partial_path, meta_path)
        if dropped_chunks:
            click.echo(
                f"Resume: dropped {dropped_chunks} chunk(s) that failed "
                "verification")
        if chunks_have:
            click.echo(
                f"Resuming: {len(chunks_have)} chunk(s) already on disk")

        w.send_message(P.encode_message(
            P.build_answer(True, chunks_have=chunks_have)))

        dw = w.dilate()
        yield dw.when_dilated()
        listener_ep = dw.listener_for(P.SUBCHANNEL_NAME)
        click.echo(f"Receiving into {dest_path}...")
        # Initial bytes already on disk (resumed) shown as "starting at"
        # so the bar reaches 100% at the offer's full size.
        bytes_already = sum(
            min(offer["chunk_size"], offer["size"] - i * offer["chunk_size"])
            for i in chunks_have)
        progress = _make_progress_bar(
            offer["size"], initial_bytes=bytes_already, desc="receiving")
        try:
            yield _receive_chunks_over_subchannel(
                reactor, listener_ep, partial_path, meta_path, offer,
                chunks_have, progress=progress)
        finally:
            progress.close()

        # Whole-file integrity check before atomic rename. Run off the
        # reactor thread — for a 10 GB file this is ~20 s of BLAKE2b.
        actual_size, actual_hash = yield deferToThread(
            P.hash_file, partial_path)
        if actual_size != offer["size"] \
                or actual_hash != offer["_content_hash_bytes"]:
            click.echo("Error: integrity check failed; received bytes "
                       "do not match the sender's hash", err=True)
            R.cleanup_receiver(partial_path, meta_path)
            yield w.close()
            sys.exit(1)

        # A4: atomic finalize that fails closed if dest_path appeared
        # between the lstat check and now (TOCTOU). os.link refuses with
        # FileExistsError; we keep the partial in place and surface the
        # race so the user can investigate rather than silently overwrite.
        try:
            os.link(partial_path, dest_path)
        except FileExistsError:
            click.echo(
                f"Error: {dest_path} appeared during transfer; refusing to "
                "overwrite. The verified bytes are at "
                f"{partial_path}; rename manually if desired.", err=True)
            yield w.close()
            sys.exit(1)
        os.unlink(partial_path)
        try:
            os.unlink(meta_path)
        except FileNotFoundError:
            pass

        complete_payload = yield w.get_message()
        P.parse_simple_flag(complete_payload, "complete")
        w.send_message(P.encode_message(P.build_done()))
        click.echo(f"Saved {dest_path}.")
        yield w.close()
    except Exception as exc:
        sys.exit(_handle_cli_error(exc, debug))


@inlineCallbacks
def _receive_chunks_over_subchannel(reactor, listener_ep, partial_path,
                                    meta_path, offer, chunks_have,
                                    progress=None):
    factory = _ReceiverFactory(partial_path, meta_path, offer, chunks_have,
                               progress)
    yield listener_ep.listen(factory)
    yield factory.done


class _ReceiverFactory(Factory):
    def __init__(self, partial_path, meta_path, offer, chunks_have,
                 progress=None):
        self._partial_path = partial_path
        self._meta_path = meta_path
        self._offer = offer
        self._chunks_have = set(chunks_have)
        self._progress = progress  # tqdm-like, or None
        self.done = Deferred()

    def buildProtocol(self, addr):
        return _ReceiverProtocol(self)


class _ReceiverProtocol(Protocol):
    """Receives chunks at arbitrary indices, verifies each, sparse-writes
    them to the partial file, and persists progress through a throttle
    so a 10K-chunk transfer doesn't fsync 10K times."""

    def __init__(self, factory):
        self._factory = factory
        self._decoder = P.FrameDecoder()
        self._fh = None
        # Factory already stored chunks_have as a set; share it directly
        # so writes here mutate one canonical set rather than diverging.
        self._chunks_have = factory._chunks_have
        self._offer = factory._offer
        self._chunk_size = self._offer["chunk_size"]
        self._chunk_hashes = self._offer["_chunk_hashes_bytes"]
        self._total_chunks = len(self._chunk_hashes)
        self._progress = factory._progress
        self._throttle = R.ReceiverStateThrottle(
            factory._meta_path,
            transfer_id_b64=self._offer["transfer_id"],
            size=self._offer["size"],
            chunk_size=self._chunk_size,
            chunk_hashes_b64=self._offer["chunk_hashes"],
        )

    def connectionMade(self):
        # Open the partial file in r+b. If it doesn't exist (fresh
        # transfer), create it via O_CREAT|O_EXCL|O_NOFOLLOW so we don't
        # follow a same-user-attacker symlink and we set 0600 perms from
        # the start (no umask 022 → world-readable window).
        partial = self._factory._partial_path
        if not os.path.exists(partial):
            fd = os.open(partial,
                         os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600)
            os.close(fd)
        self._fh = open(partial, "r+b")
        # Persist initial state so a kill before any chunks arrive still
        # writes a usable sidecar matching the offer.
        self._throttle.initialize(self._chunks_have)

    def dataReceived(self, data):
        try:
            for idx, chunk in self._decoder.feed(data):
                if idx >= self._total_chunks:
                    raise P.ProtocolError(
                        f"chunk index {idx} >= total {self._total_chunks}")
                if idx in self._chunks_have:
                    continue  # duplicate; ignore (sender bug or retransmit)
                if not P.verify_chunk(chunk, self._chunk_hashes[idx]):
                    raise P.ProtocolError(
                        f"chunk {idx} hash mismatch")
                self._fh.seek(idx * self._chunk_size)
                self._fh.write(chunk)
                self._chunks_have.add(idx)
                self._throttle.update(self._chunks_have)
                if self._progress is not None:
                    self._progress.update(len(chunk))
        except P.ProtocolError as e:
            if not self._factory.done.called:
                self._factory.done.errback(e)

    def connectionLost(self, reason):
        # Flush whatever progress we have before closing — don't lose the
        # last `interval` seconds of chunks_have just because the peer
        # dropped the connection.
        try:
            self._throttle.flush()
        except Exception as e:  # pragma: no cover
            log.err(e)
        if self._fh is not None:
            self._fh.close()
            self._fh = None
        if self._factory.done.called:
            return
        if self._chunks_have == set(range(self._total_chunks)):
            self._factory.done.callback(None)
        else:
            missing = sorted(set(range(self._total_chunks))
                             - self._chunks_have)
            self._factory.done.errback(P.ProtocolError(
                f"subchannel closed with {len(missing)} chunks missing "
                f"(first missing: {missing[:5]})"))


# ---- helpers ----


def _print_qr(text):
    """Render `text` as a terminal QR code on stdout.

    Uses ``qrcode``'s ASCII renderer so it works without a graphics
    backend. Convenient for handing the code off to a phone camera.
    """
    import qrcode
    qr = qrcode.QRCode(border=1)
    qr.add_data(text)
    qr.make(fit=True)
    qr.print_ascii(tty=sys.stdout.isatty())


def _pretty_size(n):
    units = ("B", "KiB", "MiB", "GiB", "TiB")
    f = float(n)
    for u in units:
        if f < 1024 or u == units[-1]:
            return f"{f:.1f} {u}" if u != "B" else f"{int(n)} B"
        f /= 1024


if __name__ == "__main__":
    main()
