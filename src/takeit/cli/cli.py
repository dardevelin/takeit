"""
takeit command-line interface.

Two subcommands: ``send`` and ``receive``. Aliases ``tx`` / ``rx``. The
protocol shape (offer → answer → subchannel header carrying chunk_hashes
→ chunks_have reply → chunk frames → complete → done) is defined in
`takeit.cli._protocol`, and resume sidecar files in `takeit.cli._resume`.
This module is the Twisted + Click glue that wires it to a real wormhole
+ dilation transport.
"""
import base64
import os
import shutil
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
from takeit.cli import _spinner as Sp
from takeit.cli import _zipstream as Z
from takeit.errors import KeyFormatError, WrongPasswordError


def _make_progress_bar(total_bytes, initial_bytes=0, desc="transfer"):
    """Build a tqdm progress bar configured for byte-rate display, with
    a tumbling-block prefix (Yobi) whose rotation rate tracks throughput.

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
    bar = tqdm_module.tqdm(
        total=total_bytes,
        initial=initial_bytes,
        unit="B",
        unit_scale=True,
        unit_divisor=1024,
        desc=f"{Sp.rotate_glyph(initial_bytes)} {desc}",
        leave=False,
    )
    return _SpinningBar(bar, desc, initial_bytes)


class _SpinningBar:
    """Wraps a tqdm bar and rotates a small block-glyph prefix on each
    update, so the bar visibly speeds up with throughput.

    The rotation step is byte-count-driven (one step per ~512 KiB by
    default), so a faster transfer ticks the glyph faster — the spinner
    tracks bytes/sec without us computing rates.
    """

    def __init__(self, bar, label, initial_bytes):
        self._bar = bar
        self._label = label
        self._seen = initial_bytes
        self._last_glyph_step = self._seen // Sp._BYTES_PER_ROTATION_STEP

    def update(self, n):
        self._bar.update(n)
        self._seen += n
        step = self._seen // Sp._BYTES_PER_ROTATION_STEP
        if step != self._last_glyph_step:
            self._last_glyph_step = step
            # set_description_str avoids appending ": " (set_description does).
            self._bar.set_description_str(
                f"{Sp.rotate_glyph(self._seen)} {self._label}",
                refresh=False,
            )

    def close(self):
        self._bar.close()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()
        return False


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
@click.argument("path", required=False,
                type=click.Path(dir_okay=True, resolve_path=True))
@click.option("--text", "text_input", default=None,
              help="Send a short text message instead of a file. "
                   "Use '-' to read the text from stdin.")
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
def cmd_send(ctx, path, text_input, code_length, relays,
             explicit_code, no_cache, qr):
    """Send a file, directory, or text.

    Directories are streamed as a deterministic zip — the receiver
    expands them on arrival. Resume works for files and directories.
    Use ``--text`` to send a short text message inline.
    """
    if text_input is not None and path is not None:
        raise click.UsageError(
            "--text and a file path are mutually exclusive")
    if text_input is None and path is None:
        raise click.UsageError("Provide a path or --text")
    relay_list = list(relays) if relays else None
    debug = ctx.obj.get("debug", False)
    if text_input is not None:
        # Read from stdin if the value is "-".
        text = sys.stdin.read() if text_input == "-" else text_input
        react(_run_send_text,
              (text, code_length, relay_list, explicit_code, qr, debug))
        return
    # Path validation runs here (not in the Click annotation) so that
    # --text vs path mutual-exclusion can fire first with a clear
    # error, regardless of whether `path` exists on disk.
    if not os.path.exists(path):
        raise click.UsageError(f"Path {path!r} does not exist")
    if not os.access(path, os.R_OK):
        raise click.UsageError(f"Path {path!r} is not readable")
    react(_run_send, (path, code_length, relay_list, explicit_code,
                      not no_cache, qr, debug))


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
    chunk_size = P.DEFAULT_CHUNK_SIZE
    is_dir = os.path.isdir(path)

    if is_dir:
        # Directory transfer: stream the source through a deterministic
        # zip into a temp file, hashing as we go. The temp file then
        # plays the role of "the file" for the rest of the send flow:
        # chunk-indexed reads, resume, etc. Sender cache is skipped —
        # zipping is fast enough relative to the transfer that re-doing
        # it on retry is cheaper than persisting a sidecar that may
        # disagree with the source tree the user has since edited.
        dir_name = os.path.basename(os.path.normpath(path))
        click.echo(f"Preparing {dir_name}/ ...")
        _files, num_files, num_bytes = Z.walk_directory(path)
        # Hold the temp zip alongside the source dir so it's on the same
        # filesystem (avoids ENOSPC surprises in /tmp on small partitions).
        tmp_zip_path = os.path.join(
            os.path.dirname(os.path.abspath(path)),
            f".{dir_name}.takeit-zip-{os.getpid()}")
        try:
            size, content_hash, chunk_hashes = yield deferToThread(
                Z.materialize_and_hash, path, tmp_zip_path, chunk_size)
            yield _do_send(
                reactor, tmp_zip_path, dir_name, size, content_hash,
                chunk_hashes, chunk_size, code_length, relays,
                explicit_code, qr, debug,
                kind=P.KIND_DIRECTORY,
                num_files=num_files, num_bytes=num_bytes)
        finally:
            try:
                os.unlink(tmp_zip_path)
            except FileNotFoundError:
                pass
        return

    # File transfer: original path.
    filename = os.path.basename(path)
    cache_path = R.sender_cache_path(path)

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

    yield _do_send(
        reactor, path, filename, size, content_hash, chunk_hashes,
        chunk_size, code_length, relays, explicit_code, qr, debug,
        kind=P.KIND_FILE)


@inlineCallbacks
def _run_send_text(reactor, text, code_length, relays, explicit_code,
                   qr, debug):
    """Send a text message inline. The offer IS the payload — no
    chunked stream, no dilation. Same accept/decline gate as files
    so the receiver still gets to consent before the text appears."""
    w = takeit.create(appid=APPID, reactor=reactor, relays=relays)
    try:
        if explicit_code:
            w.set_code(explicit_code)
        else:
            w.allocate_code(code_length=code_length)
        code = yield w.get_code()
        click.echo(f"takeit code: {code}")
        click.echo("On the receiving machine, run:")
        click.echo(f"    takeit receive {code}")
        if qr:
            _print_qr(code)

        offer_msg = P.build_offer_text(text)
        w.send_message(P.encode_message(offer_msg))

        # Wait for receiver's accept/decline.
        spinner = Sp.TossSpinner(reactor)
        spinner.start()
        try:
            answer_payload = yield w.get_message()
        finally:
            spinner.stop()
        accepted, reason = P.parse_answer(answer_payload)
        if not accepted:
            click.echo(f"Receiver declined: {reason}", err=True)
            yield w.close()
            sys.exit(1)

        # Same complete/done handshake as file/directory transfers.
        # Keeps the close protocol uniform across kinds.
        w.send_message(P.encode_message(P.build_complete()))
        done_payload = yield w.get_message()
        P.parse_simple_flag(done_payload, "done")
        click.echo("Text delivered.")
        yield w.close()
    except Exception as exc:
        sys.exit(_handle_cli_error(exc, debug))


@inlineCallbacks
def _do_send(reactor, payload_path, name, size, content_hash, chunk_hashes,
             chunk_size, code_length, relays, explicit_code, qr, debug,
             *, kind, num_files=None, num_bytes=None):
    """Common send flow once the payload is hashed. `payload_path` is the
    file on disk to chunk-stream (the source file for KIND_FILE, the
    materialized temp zip for KIND_DIRECTORY). `name` is the user-facing
    name (filename or dir_name) embedded in the offer."""
    w = takeit.create(appid=APPID, reactor=reactor, relays=relays)
    try:
        if explicit_code:
            w.set_code(explicit_code)
        else:
            w.allocate_code(code_length=code_length)
        code = yield w.get_code()
        click.echo(f"takeit code: {code}")
        click.echo("On the receiving machine, run:")
        click.echo(f"    takeit receive {code}")
        if qr:
            _print_qr(code)

        # Send the offer (per-kind shape). Post-HYP-392, chunk_hashes
        # do NOT ride the offer — they go on the dilation subchannel
        # so the relay can't infer file size from offer ciphertext length.
        if kind == P.KIND_FILE:
            offer_msg = P.build_offer_file(
                name, size, content_hash, chunk_size=chunk_size)
        elif kind == P.KIND_DIRECTORY:
            offer_msg = P.build_offer_directory(
                name, size, content_hash,
                num_files=num_files, num_bytes=num_bytes,
                chunk_size=chunk_size)
        else:
            raise AssertionError(f"unsupported send kind: {kind!r}")
        w.send_message(P.encode_message(offer_msg))

        # Wait for the receiver's accept/decline.
        spinner = Sp.TossSpinner(reactor)
        spinner.start()
        try:
            answer_payload = yield w.get_message()
        finally:
            spinner.stop()
        accepted, reason = P.parse_answer(answer_payload)
        if not accepted:
            click.echo(f"Receiver declined: {reason}", err=True)
            yield w.close()
            sys.exit(1)

        # Dilate and open the bulk subchannel. Spin during the handshake —
        # STUN candidates racing, Noise prologue, KCM selection.
        spinner = Sp.TossSpinner(reactor)
        spinner.start()
        try:
            dw = w.dilate()
            yield dw.when_dilated()
            ep = dw.connector_for(P.SUBCHANNEL_NAME)
        finally:
            spinner.stop()
        if kind == P.KIND_DIRECTORY:
            click.echo(
                f"Sending {name}/ ({num_files} files, "
                f"{_pretty_size(num_bytes)} → {_pretty_size(size)} zipped)...")
        else:
            click.echo(f"Sending {name} ({_pretty_size(size)})...")
        # Maximum bytes that could be sent (full transfer). The actual
        # number is reduced by chunks_have which we don't know yet — the
        # progress bar's total updates after the receiver replies.
        progress = _make_progress_bar(size, desc="sending")
        try:
            yield _send_chunks_over_subchannel(
                reactor, ep, payload_path, chunk_size, chunk_hashes,
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
                                 chunk_hashes, progress=None):
    factory = _SenderFactory(path, chunk_size, chunk_hashes, progress)
    yield endpoint.connect(factory)
    yield factory.done


class _SenderFactory(ClientFactory):
    def __init__(self, path, chunk_size, chunk_hashes, progress=None):
        self._path = path
        self._chunk_size = chunk_size
        self._chunk_hashes = chunk_hashes
        self._progress = progress  # tqdm-like, or None
        self.done = Deferred()

    def buildProtocol(self, addr):
        return _SenderProtocol(self)


class _SenderProtocol(Protocol):
    """Streams chunks to the dilation subchannel using a pull producer.

    Two phases (HYP-392):
    1. Header phase: write build_subchannel_header(chunk_hashes), then
       buffer incoming bytes through a LengthPrefixedDecoder until the
       receiver's chunks_have reply arrives.
    2. Stream phase: register as a pull producer; `resumeProducing` is
       called when the transport has buffer room. Disk reads happen on
       a worker thread so the reactor isn't blocked on slow disks.

    Memory is bounded to roughly one chunk in flight regardless of file
    size — pull producer + chunked reads keep us flat under any pressure.
    """

    def __init__(self, factory):
        self._factory = factory
        self._fh = None
        self._chunks_iter = None
        self._read_in_flight = False
        self._stopped = False
        self._finished = False
        self._progress = factory._progress
        # Header-phase state
        self._reply_decoder = P.LengthPrefixedDecoder()
        self._header_phase = True

    def connectionMade(self):
        try:
            self._fh = open(self._factory._path, "rb")
        except Exception as e:
            self._factory.done.errback(e)
            self.transport.loseConnection()
            return
        # Send the chunk_hashes header (HYP-392) — receiver needs it
        # before it can compute chunks_have.
        self.transport.write(
            P.build_subchannel_header(self._factory._chunk_hashes))
        # Wait for chunks_have reply on dataReceived; the pull producer
        # is registered only after we know which chunks to send.

    def dataReceived(self, data):
        if not self._header_phase:
            # No further inbound bytes are expected on the sender side
            # post-header; if any arrive, the peer is misbehaving.
            self._fail(P.ProtocolError(
                "unexpected bytes from receiver after chunks_have reply"))
            return
        try:
            for body in self._reply_decoder.feed(data):
                chunks_have = P.parse_chunks_have(body)
                self._enter_stream_phase(chunks_have)
                return
        except P.ProtocolError as e:
            self._fail(e)

    def _enter_stream_phase(self, chunks_have):
        self._header_phase = False
        total = len(self._factory._chunk_hashes)
        chunks_to_send = sorted(set(range(total)) - set(chunks_have))
        if chunks_have:
            click.echo(
                f"Resuming: receiver already has {len(chunks_have)} "
                f"chunk(s); sending {len(chunks_to_send)}")
        # Update the progress bar's total to reflect skipped chunks.
        if self._progress is not None:
            chunk_size = self._factory._chunk_size
            # Each chunk is chunk_size except possibly the last.
            # We don't know `size` here; leave the bar's total as-is
            # (it was set by _do_send to size, which is the upper bound).
            # Mark the skipped bytes as already-progressed.
            skipped_bytes = 0
            # Reuse the offer's per-chunk size estimation: full chunks
            # except the last. We don't have `size`, so estimate as
            # chunk_size for each — slightly off for the last chunk if
            # it's in chunks_have, but the overall bar is accurate
            # within one chunk_size which is already the case.
            for idx in chunks_have:
                skipped_bytes += chunk_size
            try:
                self._progress.update(skipped_bytes)
            except Exception:
                pass
        self._chunks_iter = iter(chunks_to_send)
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


def _rmtree_quiet(path):
    """Best-effort recursive remove. Used when a directory transfer is
    aborted mid-extract — leaving a half-populated tempdir behind would
    confuse the user, but propagating the cleanup error would mask the
    real failure that triggered cleanup."""
    try:
        shutil.rmtree(path)
    except OSError:
        pass


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

        # Wait for the sender's offer. The sender may be hashing a large
        # file before they can publish — for a 10 GB source this is ~20 s.
        # Spinner makes the wait feel intentional rather than hung.
        spinner = Sp.TossSpinner(reactor)
        spinner.start()
        try:
            offer_payload = yield w.get_message()
        finally:
            spinner.stop()
        offer = P.parse_offer(offer_payload)
        if offer["kind"] not in (
                P.KIND_FILE, P.KIND_DIRECTORY, P.KIND_TEXT):
            reason = f"{offer['kind']} transfer not yet supported by this client"
            w.send_message(P.encode_message(P.build_answer(False, reason)))
            click.echo(f"Error: {reason}", err=True)
            yield w.close()
            sys.exit(1)

        if offer["kind"] == P.KIND_TEXT:
            # Typing the code IS the consent for text — wormhole's
            # behavior. No filesystem side effect, nothing to "accept";
            # just print the message and close.
            text = offer["text"]
            w.send_message(P.encode_message(P.build_answer(True)))
            # Print the text exactly as sent — no quoting, no extra
            # newline beyond what the sender included.
            click.echo(text, nl=False)
            # If the sender's text didn't end with a newline, finish
            # the line so the user's prompt isn't glued to the message.
            if not text.endswith("\n"):
                click.echo()
            # Same close handshake as file/dir for protocol uniformity.
            complete_payload = yield w.get_message()
            P.parse_simple_flag(complete_payload, "complete")
            w.send_message(P.encode_message(P.build_done()))
            yield w.close()
            return

        if offer["kind"] == P.KIND_FILE:
            display_name = offer["filename"]
            click.echo(
                f"Offered: {display_name} ({_pretty_size(offer['size'])})")
            dest_path = os.path.join(output_dir_real, display_name)
            partial_path, meta_path = R.receiver_paths(dest_path)
        else:  # KIND_DIRECTORY
            display_name = offer["dir_name"]
            click.echo(
                f"Offered: {display_name}/ "
                f"({offer['num_files']} files, "
                f"{_pretty_size(offer['num_bytes'])} → "
                f"{_pretty_size(offer['size'])} zipped)")
            # The "dest path" for finalization is the directory itself.
            # The partial-and-meta sidecars hang off a sibling .zip path
            # so they don't collide with anything inside the final dir.
            dest_path = os.path.join(output_dir_real, display_name)
            zip_marker = os.path.join(
                output_dir_real, f"{display_name}.zip")
            partial_path, meta_path = R.receiver_paths(zip_marker)

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

        # Resume-state probe: knowing whether a prior sidecar exists for
        # this transfer_id lets us hint the user before the prompt. The
        # actual chunks_have computation now happens AFTER the dilation
        # subchannel delivers chunk_hashes (HYP-392) — we don't have
        # them at offer-parse time.
        prior = R.load_receiver_state(meta_path)
        prior_matches_offer = (
            prior is not None
            and prior.get("transfer_id") == offer["transfer_id"]
            and prior.get("size") == offer["size"]
            and prior.get("chunk_size") == offer["chunk_size"]
        )
        stale_partial = prior is not None and not prior_matches_offer

        if not auto_accept:
            if prior_matches_offer:
                click.echo(
                    "(Partial transfer found on disk — resuming if accepted.)")
            if not click.confirm("Accept?", default=False):
                w.send_message(P.encode_message(
                    P.build_answer(False, "user declined")))
                yield w.close()
                return

        if stale_partial:
            click.echo("Discarding stale partial (offer doesn't match)")
            R.cleanup_receiver(partial_path, meta_path)

        # Post-HYP-392 the answer is just accept/reject — chunks_have
        # moves onto the dilation subchannel reply.
        w.send_message(P.encode_message(P.build_answer(True)))

        # Spinner during the dilation handshake — the peer is finishing
        # the SPAKE2 confirmation and we're racing connection candidates.
        spinner = Sp.TossSpinner(reactor)
        spinner.start()
        try:
            dw = w.dilate()
            yield dw.when_dilated()
            listener_ep = dw.listener_for(P.SUBCHANNEL_NAME)
        finally:
            spinner.stop()
        click.echo(f"Receiving into {dest_path}...")
        progress = _make_progress_bar(offer["size"], desc="receiving")
        try:
            yield _receive_chunks_over_subchannel(
                reactor, listener_ep, partial_path, meta_path, offer,
                prior_matches=prior_matches_offer, progress=progress)
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

        # Finalize differs by kind. File: atomic-link the verified
        # partial into place. Directory: extract the verified zip into
        # a sibling tempdir, then atomic-rename the tempdir to dest.
        if offer["kind"] == P.KIND_FILE:
            try:
                os.link(partial_path, dest_path)
            except FileExistsError:
                click.echo(
                    f"Error: {dest_path} appeared during transfer; "
                    "refusing to overwrite. The verified bytes are at "
                    f"{partial_path}; rename manually if desired.",
                    err=True)
                yield w.close()
                sys.exit(1)
            os.unlink(partial_path)
        else:  # KIND_DIRECTORY: extract zip into a tempdir, atomic-rename
            extract_tmp = (
                f"{dest_path}.takeit-extract-{os.getpid()}")
            os.makedirs(extract_tmp, exist_ok=False)
            try:
                yield deferToThread(
                    Z.extract_zip_safely, partial_path, extract_tmp)
                # TOCTOU-safe atomic rename. os.rename refuses on Linux
                # if dest_path is a non-empty directory, but on macOS it
                # may overwrite — the lstat pre-check + this re-check
                # cover both.
                try:
                    os.lstat(dest_path)
                    click.echo(
                        f"Error: {dest_path} appeared during transfer; "
                        f"refusing to overwrite. Extracted bytes are at "
                        f"{extract_tmp}.", err=True)
                    yield w.close()
                    sys.exit(1)
                except FileNotFoundError:
                    pass
                os.rename(extract_tmp, dest_path)
                os.unlink(partial_path)
            except Exception:
                # Best-effort cleanup of the half-extracted tempdir.
                _rmtree_quiet(extract_tmp)
                raise
        try:
            os.unlink(meta_path)
        except FileNotFoundError:
            pass

        complete_payload = yield w.get_message()
        P.parse_simple_flag(complete_payload, "complete")
        w.send_message(P.encode_message(P.build_done()))
        click.echo(f"Saved {dest_path}{'/' if offer['kind'] == P.KIND_DIRECTORY else ''}.")
        yield w.close()
    except Exception as exc:
        sys.exit(_handle_cli_error(exc, debug))


@inlineCallbacks
def _receive_chunks_over_subchannel(reactor, listener_ep, partial_path,
                                    meta_path, offer, prior_matches,
                                    progress=None):
    factory = _ReceiverFactory(
        partial_path, meta_path, offer, prior_matches, progress)
    yield listener_ep.listen(factory)
    yield factory.done


class _ReceiverFactory(Factory):
    def __init__(self, partial_path, meta_path, offer, prior_matches,
                 progress=None):
        self._partial_path = partial_path
        self._meta_path = meta_path
        self._offer = offer
        self._prior_matches = prior_matches
        self._progress = progress  # tqdm-like, or None
        self.done = Deferred()

    def buildProtocol(self, addr):
        return _ReceiverProtocol(self)


class _ReceiverProtocol(Protocol):
    """Receives the subchannel header (chunk_hashes), then chunks (HYP-392).

    Two phases:
    1. Header phase: feed bytes to a LengthPrefixedDecoder; on parse,
       compute chunks_have by re-hashing the partial file off-thread,
       send the chunks_have reply, switch to chunk phase.
    2. Chunk phase: feed bytes to FrameDecoder; for each frame, verify
       hash, sparse-write to partial, throttle-persist sidecar.

    Memory bounded — chunks_have computation reads the partial chunk-
    by-chunk on a worker thread; the protocol itself only holds one
    chunk in flight.
    """

    def __init__(self, factory):
        self._factory = factory
        self._offer = factory._offer
        self._chunk_size = self._offer["chunk_size"]
        self._size = self._offer["size"]
        self._content_hash = self._offer["_content_hash_bytes"]
        self._progress = factory._progress
        # Header-phase state
        self._header_decoder = P.LengthPrefixedDecoder()
        self._header_phase = True
        # Chunk-phase state, populated when header arrives
        self._frame_decoder = P.FrameDecoder()
        self._fh = None
        self._chunks_have = set()
        self._chunk_hashes = None  # list[bytes], from header
        self._total_chunks = None
        self._throttle = None
        self._stopped = False

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

    def dataReceived(self, data):
        if self._stopped:
            return
        if self._header_phase:
            try:
                for body in self._header_decoder.feed(data):
                    # Got the full header. Any bytes remaining in the
                    # current `data` after the header are chunk-phase
                    # frames — but the decoder consumes them one body
                    # at a time, so subsequent dataReceived calls will
                    # carry the chunk frames cleanly.
                    self._on_header_received(body)
                    return
            except P.ProtocolError as e:
                self._fail(e)
            return
        # Chunk phase
        self._consume_frames(data)

    def _on_header_received(self, body):
        try:
            chunk_hashes = P.parse_subchannel_header(body)
        except P.ProtocolError as e:
            self._fail(e)
            return
        # Sanity-check: the header's chunk count must match what the
        # offer's size + chunk_size implies.
        expected_count = P.expected_chunk_count(self._size, self._chunk_size)
        if len(chunk_hashes) != expected_count:
            self._fail(P.ProtocolError(
                f"subchannel header has {len(chunk_hashes)} chunk_hashes "
                f"but offer implies {expected_count}"))
            return
        self._chunk_hashes = chunk_hashes
        self._total_chunks = len(chunk_hashes)
        # Reconstruct the b64 list for the throttle/sidecar (sidecar
        # format hasn't changed — it stores chunk_hashes_b64 to match
        # against on resume).
        chunk_hashes_b64 = [
            base64.b64encode(h).decode("ascii") for h in chunk_hashes]
        self._throttle = R.ReceiverStateThrottle(
            self._factory._meta_path,
            transfer_id_b64=self._offer["transfer_id"],
            size=self._size,
            chunk_size=self._chunk_size,
            chunk_hashes_b64=chunk_hashes_b64,
        )
        # Compute chunks_have by re-hashing the partial off-thread.
        # Skip if no prior sidecar matched (fresh transfer).
        if self._factory._prior_matches:
            prior = R.load_receiver_state(self._factory._meta_path)
            claimed = list(prior.get("chunks_have", []))
            d = deferToThread(
                R.verify_chunks_have,
                self._factory._partial_path,
                self._size, self._chunk_size,
                chunk_hashes, claimed)
            d.addCallback(self._on_chunks_have_verified, claimed)
            d.addErrback(self._on_verify_failed)
        else:
            self._on_chunks_have_verified(set(), [])

    def _on_chunks_have_verified(self, verified, claimed):
        if self._stopped:
            return
        chunks_have = sorted(verified)
        dropped = len(claimed) - len(chunks_have)
        if dropped:
            click.echo(
                f"Resume: dropped {dropped} chunk(s) that failed "
                "verification")
        if chunks_have:
            click.echo(
                f"Resuming: {len(chunks_have)} chunk(s) already on disk")
            # Mark resumed bytes as already-progressed.
            if self._progress is not None:
                bytes_already = sum(
                    min(self._chunk_size,
                        self._size - i * self._chunk_size)
                    for i in chunks_have)
                try:
                    self._progress.update(bytes_already)
                except Exception:
                    pass
        self._chunks_have = set(chunks_have)
        self._throttle.initialize(self._chunks_have)
        # Send the chunks_have reply to the sender.
        self.transport.write(P.build_chunks_have(chunks_have))
        self._header_phase = False
        # Any chunk-phase bytes that arrived while we were verifying are
        # in the dilation transport's input buffer; Twisted will deliver
        # them via subsequent dataReceived calls.

    def _on_verify_failed(self, failure):
        self._fail(failure.value)

    def _consume_frames(self, data):
        try:
            for idx, chunk in self._frame_decoder.feed(data):
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
            self._fail(e)

    def _fail(self, exc):
        self._stopped = True
        if not self._factory.done.called:
            self._factory.done.errback(exc)

    def connectionLost(self, reason):
        # Flush whatever progress we have before closing.
        if self._throttle is not None:
            try:
                self._throttle.flush()
            except Exception as e:  # pragma: no cover
                log.err(e)
        if self._fh is not None:
            self._fh.close()
            self._fh = None
        if self._factory.done.called:
            return
        if self._stopped:
            return  # _fail already errbacked
        if self._total_chunks is None:
            self._factory.done.errback(P.ProtocolError(
                "subchannel closed before header arrived"))
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
