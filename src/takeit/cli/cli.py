"""
takeit command-line interface.

Two subcommands: ``send`` and ``receive``. Aliases ``tx`` / ``rx``. The
protocol shape (offer → answer → subchannel header carrying chunk_hashes
→ chunks_have reply → chunk frames → complete → done) is defined in
`takeit.cli._protocol`, and resume sidecar files in `takeit.cli._resume`.
This module is the Twisted + Click glue that wires it to a real takeit
+ dilation transport.
"""

import base64
import os
import shutil
import sys
import tempfile

import click
import tqdm as tqdm_module
from twisted.internet.defer import Deferred, inlineCallbacks
from twisted.internet.protocol import ClientFactory, Factory, Protocol
from twisted.internet.task import react
from twisted.internet.threads import deferToThread
from twisted.python import log

import takeit
from takeit._code import MIN_CODE_WORDS, validate_code
from takeit._code_format import parse_code
from takeit.cli import _protocol as P
from takeit.cli import _resume as R
from takeit.cli import _spinner as Sp
from takeit.cli import _zipstream as Z
from takeit.errors import KeyFormatError, WrongPasswordError


class _Noop:
    """No-op progress shim with the same surface as tqdm + _SpinningBar.

    Returned from `_make_progress_bar` when output is suppressed (either
    `--hide-progress` or stdout isn't a TTY). The methods deliberately do
    nothing so call sites don't need to special-case the missing bar.
    """

    def update(self, n):
        pass

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class _NoopSpinner:
    """No-op spinner shim with the same surface as TossSpinner. Returned
    from `_make_spinner` when output is suppressed."""

    def start(self):
        pass

    def stop(self):
        pass


def _make_progress_bar(total_bytes, initial_bytes=0, desc="transfer", hide=False):
    """Build a tqdm progress bar configured for byte-rate display, with
    a tumbling-block prefix (Yobi) whose rotation rate tracks throughput.

    Returns a no-op shim when `hide=True` or stdout isn't a TTY so tqdm
    doesn't paint progress lines into log files / pipes / CI runs.
    """
    if hide or not sys.stdout.isatty():
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


def _make_spinner(reactor, hide=False):
    """Build a TossSpinner, or a no-op shim when output is suppressed
    (`--hide-progress` or non-TTY). The toss-spinner is purely visual,
    so suppress it on the same conditions as the progress bar."""
    if hide or not sys.stdout.isatty():
        return _NoopSpinner()
    return Sp.TossSpinner(reactor)


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


def _resolve_output_target(output_file, sender_name):
    """Resolve --output-file into a (parent_dir, final_name) pair.

    takeit-compatible semantics:
    - None → (default_output_dir, sender_name).
    - existing directory → (that_directory, sender_name).
    - non-existing path with existing parent → (parent, basename)
      (rename-on-receive).
    - non-existing path with missing parent → ValueError early
      (we refuse to silently mkdir -p; almost always a typo).
    - existing file → ValueError (collision; refuse rather than
      silently overwrite at resolve-time, even though the
      final-write code has its own atomic-rename guard).

    The returned `parent_dir` is realpath-resolved at this point, so
    later TOCTOU races on the parent are caught by lstat at write time.
    """
    if output_file is None:
        return _default_output_dir(), sender_name
    target = os.path.abspath(output_file)
    if os.path.isdir(target):
        return target, sender_name
    if os.path.exists(target):
        # Existing non-directory (file, symlink to file, fifo, etc.).
        # Refuse — the user likely meant to rename to a NEW path.
        raise ValueError(
            f"{output_file!r} already exists; refusing to overwrite. "
            "Pick a different path or remove it first."
        )
    parent = os.path.dirname(target) or "."
    if not os.path.isdir(parent):
        raise ValueError(
            f"parent directory of {output_file!r} does not exist "
            f"({parent!r}). Create it first or pick a different path."
        )
    return parent, os.path.basename(target)


def _parse_stun_servers(values):
    servers = []
    for value in values:
        host, sep, port_s = value.rpartition(":")
        if not sep or not host:
            raise click.UsageError("--stun-server must be HOST:PORT")
        try:
            port = int(port_s)
        except ValueError:
            raise click.UsageError("--stun-server port must be an integer")
        if not (1 <= port <= 65535):
            raise click.UsageError("--stun-server port must be between 1 and 65535")
        servers.append((host, port))
    return tuple(servers)


# ---- Click commands ----


@click.group(invoke_without_command=False)
@click.version_option(takeit.__version__, prog_name="takeit")
@click.option(
    "--debug",
    is_flag=True,
    default=False,
    help="Print Twisted tracebacks on errors (verbose).",
)
@click.pass_context
def main(ctx, debug):
    """takeit — securely transfer files between computers, peer-to-peer."""
    ctx.ensure_object(dict)
    ctx.obj["debug"] = debug


@main.command("send")
@click.argument(
    "path", required=False, type=click.Path(dir_okay=True, resolve_path=True)
)
@click.option(
    "--text",
    "text_input",
    default=None,
    help="Send a short text message instead of a file. "
    "Use '-' to read the text from stdin.",
)
@click.option(
    "--code-length",
    type=click.IntRange(min=MIN_CODE_WORDS),
    default=3,
    help="Number of words in the generated code (default: 3).",
)
@click.option(
    "--relay",
    "relays",
    multiple=True,
    help="Override Nostr relay URLs (may be repeated).",
)
@click.option(
    "--allow-private-hints",
    is_flag=True,
    default=False,
    help="Allow dilation to connect to peer-advertised private LAN IP hints.",
)
@click.option(
    "--stun-server",
    "stun_servers",
    multiple=True,
    help="Opt into a STUN server for public-IP hints, as HOST:PORT.",
)
@click.option(
    "--code",
    "explicit_code",
    default=None,
    help="Use this code instead of allocating a fresh one.",
)
@click.option(
    "--no-cache",
    is_flag=True,
    default=False,
    help="Don't read or write the per-file chunk-hash cache.",
)
@click.option(
    "--qr",
    is_flag=True,
    default=False,
    help="Also render the code as a terminal QR code (useful for hand-off to a phone).",
)
@click.option(
    "--verify",
    "verify",
    is_flag=True,
    default=False,
    help="Show the short authentication string (SAS) and pause for "
    "out-of-band comparison before any payload moves.",
)
@click.option(
    "--hide-progress",
    "hide_progress",
    is_flag=True,
    default=False,
    help="Suppress the progress bar and spinner. Auto-suppressed when "
    "stdout is not a terminal.",
)
@click.option(
    "--ignore-unsendable-files",
    "ignore_unsendable",
    is_flag=True,
    default=False,
    help="When sending a directory, skip entries that can't be read "
    "(permission denied, broken symlinks, etc.) instead of erroring "
    "out. Out-of-root symlinks are STILL refused — that's a privacy "
    "concern, not an IO concern.",
)
@click.pass_context
def cmd_send(
    ctx,
    path,
    text_input,
    code_length,
    relays,
    allow_private_hints,
    stun_servers,
    explicit_code,
    no_cache,
    qr,
    verify,
    hide_progress,
    ignore_unsendable,
):
    """Send a file, directory, or text.

    Directories are streamed as a deterministic zip — the receiver
    expands them on arrival. Resume works for files and directories.
    Use ``--text`` to send a short text message inline.
    """
    if text_input is not None and path is not None:
        raise click.UsageError("--text and a file path are mutually exclusive")
    if text_input is None and path is None:
        raise click.UsageError("Provide a path or --text")
    relay_list = list(relays) if relays else None
    stun_server_list = _parse_stun_servers(stun_servers)
    debug = ctx.obj.get("debug", False)
    if text_input is not None:
        # Read from stdin if the value is "-".
        text = sys.stdin.read() if text_input == "-" else text_input
        react(
            _run_send_text,
            (
                text,
                code_length,
                relay_list,
                explicit_code,
                qr,
                verify,
                hide_progress,
                debug,
            ),
        )
        return
    # Path validation runs here (not in the Click annotation) so that
    # --text vs path mutual-exclusion can fire first with a clear
    # error, regardless of whether `path` exists on disk.
    if not os.path.exists(path):
        raise click.UsageError(f"Path {path!r} does not exist")
    if not os.access(path, os.R_OK):
        raise click.UsageError(f"Path {path!r} is not readable")
    react(
        _run_send,
        (
            path,
            code_length,
            relay_list,
            allow_private_hints,
            stun_server_list,
            explicit_code,
            not no_cache,
            qr,
            verify,
            hide_progress,
            ignore_unsendable,
            debug,
        ),
    )


@main.command("receive")
@click.argument("code", required=False, default=None)
@click.option(
    "--accept/--no-accept",
    "-y/",
    "auto_accept",
    default=False,
    help="Skip the y/N accept prompt (alias: -y).",
)
@click.option(
    "--relay",
    "relays",
    multiple=True,
    help="Override Nostr relay URLs (may be repeated).",
)
@click.option(
    "--allow-private-hints",
    is_flag=True,
    default=False,
    help="Allow dilation to connect to peer-advertised private LAN IP hints.",
)
@click.option(
    "--stun-server",
    "stun_servers",
    multiple=True,
    help="Opt into a STUN server for public-IP hints, as HOST:PORT.",
)
@click.option(
    "-o",
    "--output-file",
    "output_file",
    type=click.Path(),
    default=None,
    help="Where to save the received file. If PATH is an existing "
    "directory, save into it using the sender's filename. Otherwise "
    "treat PATH as the full target path (rename-on-receive). Default: "
    "~/Downloads if it exists, else the current directory.",
)
@click.option(
    "--verify",
    "verify",
    is_flag=True,
    default=False,
    help="Show the short authentication string (SAS) and pause for "
    "out-of-band comparison before accepting any payload.",
)
@click.option(
    "--hide-progress",
    "hide_progress",
    is_flag=True,
    default=False,
    help="Suppress the progress bar and spinner. Auto-suppressed when "
    "stdout is not a terminal.",
)
@click.option(
    "-a",
    "--allocate",
    "allocate",
    is_flag=True,
    default=False,
    help="Allocate a fresh code on the receive side and wait for the "
    "sender to type it (the inverse of the default direction).",
)
@click.option(
    "-t",
    "--only-text",
    "only_text",
    is_flag=True,
    default=False,
    help="Refuse any incoming file or directory transfer; only accept "
    "inline text offers. Useful for scripted use where the receiver "
    "knows it's expecting a chat message.",
)
@click.option(
    "--code-length",
    "code_length",
    type=click.IntRange(min=MIN_CODE_WORDS),
    default=None,
    help="Number of words in the code (only meaningful with --allocate; default 3).",
)
@click.pass_context
def cmd_receive(
    ctx,
    code,
    auto_accept,
    relays,
    allow_private_hints,
    stun_servers,
    output_file,
    verify,
    hide_progress,
    allocate,
    only_text,
    code_length,
):
    """Receive a file using a code.

    If no CODE is given, you'll be prompted to type one with tab-completion
    against the wordlist. Pass ``--allocate`` to invert the direction:
    takeit will pick a code, you read it to the sender, and the sender
    types it via ``takeit send --code <code> file.pdf``.
    """
    if allocate and code is not None:
        raise click.UsageError(
            "--allocate and a positional CODE are mutually exclusive: "
            "either takeit allocates the code (--allocate) or you "
            "provide one (positional)."
        )
    if code_length is not None and not allocate:
        raise click.UsageError(
            "--code-length is only meaningful with --allocate (the "
            "code length is fixed by the sender otherwise)."
        )
    if code_length is None:
        code_length = 3  # match cmd_send's default
    relay_list = list(relays) if relays else None
    stun_server_list = _parse_stun_servers(stun_servers)
    react(
        _run_receive,
        (
            code,
            auto_accept,
            relay_list,
            allow_private_hints,
            stun_server_list,
            output_file,
            verify,
            hide_progress,
            allocate,
            only_text,
            code_length,
            ctx.obj.get("debug", False),
        ),
    )


@main.command("completion")
@click.argument("shell", type=click.Choice(["bash", "zsh", "fish"]))
def cmd_completion(shell):
    """Print the shell-completion script for the given shell.

    Install for zsh:  ``eval "$(takeit completion zsh)"`` in ``.zshrc``.
    Install for bash: ``eval "$(takeit completion bash)"`` in ``.bashrc``.
    Install for fish: write ``takeit completion fish`` output to
    ``~/.config/fish/completions/takeit.fish``.
    """
    from click.shell_completion import shell_complete

    # shell_complete prints to stdout and returns an exit code.
    code = shell_complete(
        cli=main,
        ctx_args={},
        prog_name="takeit",
        complete_var="_TAKEIT_COMPLETE",
        instruction=f"{shell}_source",
    )
    sys.exit(code)


# Aliases — Click groups don't support aliasing directly, so register again.
main.add_command(cmd_send, name="tx")
main.add_command(cmd_receive, name="rx")
# `recv` is shell-muscle-memory; `recieve` is the typo-tolerant alias
# inherited from the upstream project. Both route to cmd_receive.
main.add_command(cmd_receive, name="recv")
main.add_command(cmd_receive, name="recieve")


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
def _run_send(
    reactor,
    path,
    code_length,
    relays,
    allow_private_hints,
    stun_servers,
    explicit_code,
    use_cache,
    qr,
    verify,
    hide_progress,
    ignore_unsendable,
    debug,
):
    chunk_size = P.DEFAULT_CHUNK_SIZE
    is_dir = os.path.isdir(path)

    try:
        if explicit_code:
            _validate_code_before_takeit(explicit_code, verify)
    except Exception as exc:
        sys.exit(_handle_cli_error(exc, debug))

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
        _files, num_files, num_bytes = Z.walk_directory(
            path, ignore_unsendable=ignore_unsendable
        )
        # Hold the temp zip alongside the source dir so it's on the same
        # filesystem (avoids ENOSPC surprises in /tmp on small partitions).
        tmp_zip_path = os.path.join(
            os.path.dirname(os.path.abspath(path)),
            f".{dir_name}.takeit-zip-{os.getpid()}",
        )
        # tmp_zip cleanup ownership:
        # - HYP-433: if `materialize_and_hash` raises (e.g. attacker
        #   pre-created the predictable path → O_EXCL fires), the flag
        #   stays False, the finally below skips, and we don't unlink
        #   a path we didn't create.
        # - HYP-441: if `materialize_and_hash` fails MID-WRITE (after
        #   it created the tmp via O_EXCL), it unlinks its own partial
        #   itself before re-raising. Same flag-False outcome here.
        # - If `_do_send` raises after `materialize_and_hash` returned,
        #   the flag is True and finally unlinks the now-fully-written
        #   tmp zip.
        # - Happy path: flag True, finally unlinks.
        tmp_zip_created = False
        try:
            size, content_hash, chunk_hashes = yield deferToThread(
                Z.materialize_and_hash,
                path,
                tmp_zip_path,
                chunk_size,
                ignore_unsendable=ignore_unsendable,
            )
            tmp_zip_created = True
            yield _do_send(
                reactor,
                tmp_zip_path,
                dir_name,
                size,
                content_hash,
                chunk_hashes,
                chunk_size,
                code_length,
                relays,
                allow_private_hints,
                stun_servers,
                explicit_code,
                qr,
                verify,
                hide_progress,
                debug,
                kind=P.KIND_DIRECTORY,
                num_files=num_files,
                num_bytes=num_bytes,
                explicit_code_prevalidated=True,
            )
        finally:
            if tmp_zip_created:
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
            P.chunk_hashes_for_file, path, chunk_size
        )
        if use_cache:
            R.save_sender_cache(
                cache_path,
                path,
                chunk_size,
                content_hash_b64=R.b64(content_hash),
                chunk_hashes_b64=[R.b64(h) for h in chunk_hashes],
            )

    yield _do_send(
        reactor,
        path,
        filename,
        size,
        content_hash,
        chunk_hashes,
        chunk_size,
        code_length,
        relays,
        allow_private_hints,
        stun_servers,
        explicit_code,
        qr,
        verify,
        hide_progress,
        debug,
        kind=P.KIND_FILE,
        explicit_code_prevalidated=True,
    )


@inlineCallbacks
def _run_send_text(
    reactor,
    text,
    code_length,
    relays,
    explicit_code,
    qr,
    verify,
    hide_progress,
    debug,
):
    """Send a text message inline. The offer IS the payload — no
    chunked stream, no dilation. Per takeit's typing-is-consent rule
    (the receiver's KIND_TEXT branch in `_run_receive` accepts as
    soon as the offer parses, mirroring upstream wormhole), there is
    NO y/N prompt for text: typing the code is the consent.
    Terminal control characters in the received text are sanitized
    by `_escape_terminal_text` (HYP-414) so an authenticated peer
    cannot move the cursor, clear the screen, or spoof shell
    output. Text payload size is capped at MAX_TEXT_BYTES."""
    try:
        if explicit_code:
            _validate_code_before_takeit(explicit_code, verify)
        w = takeit.create(appid=APPID, reactor=reactor, relays=relays)
        if explicit_code:
            _set_code_routed(w, explicit_code)
        else:
            # allocate_code always produces a canonical <locator>:<words>
            # code post-HYP-406, so no validation needed here.
            w.allocate_code(code_length=code_length)
        code = yield w.get_code()
        click.echo(f"takeit code: {code}")
        click.echo("On the receiving machine, run:")
        click.echo(f"    takeit receive {code}")
        if qr:
            _print_qr(code)
        if verify:
            yield _confirm_verifier(w)

        offer_msg = P.build_offer_text(text)
        w.send_message(P.encode_message(offer_msg))

        # Wait for receiver's accept/decline.
        spinner = _make_spinner(reactor, hide=hide_progress)
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
def _do_send(
    reactor,
    payload_path,
    name,
    size,
    content_hash,
    chunk_hashes,
    chunk_size,
    code_length,
    relays,
    allow_private_hints,
    stun_servers,
    explicit_code,
    qr,
    verify,
    hide_progress,
    debug,
    *,
    kind,
    num_files=None,
    num_bytes=None,
    explicit_code_prevalidated=False,
):
    """Common send flow once the payload is hashed. `payload_path` is the
    file on disk to chunk-stream (the source file for KIND_FILE, the
    materialized temp zip for KIND_DIRECTORY). `name` is the user-facing
    name (filename or dir_name) embedded in the offer."""
    try:
        if explicit_code and not explicit_code_prevalidated:
            _validate_code_before_takeit(explicit_code, verify)
        w = takeit.create(appid=APPID, reactor=reactor, relays=relays)
        if explicit_code:
            _set_code_routed(w, explicit_code)
        else:
            # allocate_code always produces a canonical <locator>:<words>
            # code post-HYP-406, so no validation needed here.
            w.allocate_code(code_length=code_length)
        code = yield w.get_code()
        click.echo(f"takeit code: {code}")
        click.echo("On the receiving machine, run:")
        click.echo(f"    takeit receive {code}")
        if qr:
            _print_qr(code)
        if verify:
            yield _confirm_verifier(w)

        # Send the offer (per-kind shape). Post-HYP-392, chunk_hashes
        # do NOT ride the offer — they go on the dilation subchannel
        # so the relay can't infer file size from offer ciphertext length.
        if kind == P.KIND_FILE:
            offer_msg = P.build_offer_file(
                name, size, content_hash, chunk_size=chunk_size
            )
        elif kind == P.KIND_DIRECTORY:
            offer_msg = P.build_offer_directory(
                name,
                size,
                content_hash,
                num_files=num_files,
                num_bytes=num_bytes,
                chunk_size=chunk_size,
            )
        else:
            raise AssertionError(f"unsupported send kind: {kind!r}")
        w.send_message(P.encode_message(offer_msg))

        # Wait for the receiver's accept/decline.
        spinner = _make_spinner(reactor, hide=hide_progress)
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
        spinner = _make_spinner(reactor, hide=hide_progress)
        spinner.start()
        try:
            # HYP-437: pass the subprotocol allowlist so SubchannelDemultiplex
            # rejects opens for unknown subprotocol names (HYP-413's defense
            # was dormant without this — a malicious authenticated peer
            # could OPEN any name and have it accepted).
            dw = w.dilate(
                allow_private_hints=allow_private_hints,
                stun_servers=stun_servers,
                expected_subprotocols={P.SUBCHANNEL_NAME},
            )
            yield dw.when_dilated()
            ep = dw.connector_for(P.SUBCHANNEL_NAME)
        finally:
            spinner.stop()
        if kind == P.KIND_DIRECTORY:
            click.echo(
                f"Sending {name}/ ({num_files} files, "
                f"{_pretty_size(num_bytes)} → {_pretty_size(size)} zipped)..."
            )
        else:
            click.echo(f"Sending {name} ({_pretty_size(size)})...")
        # Maximum bytes that could be sent (full transfer). The actual
        # number is reduced by chunks_have which we don't know yet — the
        # progress bar's total updates after the receiver replies.
        progress = _make_progress_bar(size, desc="sending", hide=hide_progress)
        try:
            yield _send_chunks_over_subchannel(
                reactor, ep, payload_path, chunk_size, chunk_hashes, progress=progress
            )
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
def _send_chunks_over_subchannel(
    reactor, endpoint, path, chunk_size, chunk_hashes, progress=None
):
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
        self.transport.write(P.build_subchannel_header(self._factory._chunk_hashes))
        # Wait for chunks_have reply on dataReceived; the pull producer
        # is registered only after we know which chunks to send.

    def dataReceived(self, data):
        if not self._header_phase:
            # No further inbound bytes are expected on the sender side
            # post-header; if any arrive, the peer is misbehaving.
            self._fail(
                P.ProtocolError(
                    "unexpected bytes from receiver after chunks_have reply"
                )
            )
            return
        try:
            for body in self._reply_decoder.feed(data):
                # HYP-410: bound the receiver's reply against the
                # sender-known chunk count so a malicious peer can't
                # pack the 64 MiB header cap with millions of indices
                # to burn our memory/CPU on `set(chunks_have)`.
                chunks_have = P.parse_chunks_have(
                    body,
                    total_chunks=len(self._factory._chunk_hashes),
                )
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
                f"chunk(s); sending {len(chunks_to_send)}"
            )
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
        d = deferToThread(_read_chunk, self._fh, idx, self._factory._chunk_size)
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
                IOError(
                    f"subchannel closed before transfer finished: "
                    f"{reason.getErrorMessage()}"
                )
            )


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


def _validate_code_before_takeit(code, verify):
    """Validate user-provided code before constructing a takeit session."""
    validate_code(code)
    parse_code(code)
    _validate_words_only_handoff(code, verify)


def _set_code_routed(w, code):
    """Route a validated code to the right takeit entrypoint based on
    its shape (HYP-443).

    Canonical `<locator>:<words>` codes go to `w.set_code`. Bare-words
    codes go to `w.set_code_legacy_words` so the relay-MITM-vulnerable
    path is syntactically conspicuous. Callers MUST have already run
    `_validate_words_only_handoff` (so a bare-words code reaching here
    implies `--verify` was passed).

    HYP-461: the legacy path now requires explicit
    unsafe_relay_mitm_acknowledged=True at the API boundary. The CLI
    has already checked --verify upstream, so passing the flag here
    expresses "we know this is unsafe AND we're going to display the
    SAS via --verify"."""
    if ":" in code:
        w.set_code(code)
    else:
        w.set_code_legacy_words(code, unsafe_relay_mitm_acknowledged=True)


# ---- Receive flow ----


@inlineCallbacks
def _run_receive(
    reactor,
    code,
    auto_accept,
    relays,
    allow_private_hints,
    stun_servers,
    output_file,
    verify,
    hide_progress,
    allocate,
    only_text,
    code_length,
    debug,
):
    try:
        # Validate --output-file shape up front so a typo'd path errors
        # BEFORE the user types a code. We can't fully resolve yet —
        # rename mode needs the sender's basename to know whether the
        # final target collides — so defer the (parent, final_name)
        # split until after parse_offer.
        if output_file is not None:
            try:
                # In directory-or-rename mode, ask the resolver with a
                # placeholder filename. It'll error on missing parents
                # or existing-non-dir collisions; for collision detection
                # against the actual sender name we re-run after parse.
                _resolve_output_target(output_file, "_probe")
            except ValueError as e:
                click.echo(f"Error: {e}", err=True)
                sys.exit(1)

        # Resolve any user-provided code before constructing the takeit session.
        # HYP-421's earlier fix validated before set_code/choose_words, but
        # still created the rendezvous object first. A refused words-only
        # handoff must not even start the relay connector.
        if not allocate:
            if code is None:
                from .. import _rlcompleter

                code = yield _rlcompleter.prompt_code_with_completion(
                    "takeit code: ",
                    reactor,
                    validate=lambda c: _validate_code_before_takeit(c, verify),
                    expected_code_length=code_length,
                )
            else:
                _validate_code_before_takeit(code, verify)

        w = takeit.create(appid=APPID, reactor=reactor, relays=relays)

        # Three code-resolution paths:
        # 1. --allocate: takeit picks a code, prints it; sender types it
        #    in via `takeit send --code ...`. Inverts the direction.
        # 2. positional code given: caller already has the code; set it.
        # 3. neither: we already prompted with local tab-completion above,
        #    before the takeit session existed; now commit the validated code.
        if allocate:
            # allocate_code always produces a canonical <locator>:<words>
            # code post-HYP-406, so no validation needed here.
            w.allocate_code(code_length=code_length)
            code = yield w.get_code()
            click.echo(f"takeit code: {code}")
            click.echo("On the sending machine, run:")
            click.echo(f"    takeit send --code {code} <file>")
        else:
            _set_code_routed(w, code)

        if verify:
            yield _confirm_verifier(w)

        # Wait for the sender's offer. The sender may be hashing a large
        # file before they can publish — for a 10 GB source this is ~20 s.
        # Spinner makes the wait feel intentional rather than hung.
        spinner = _make_spinner(reactor, hide=hide_progress)
        spinner.start()
        try:
            offer_payload = yield w.get_message()
        finally:
            spinner.stop()
        offer = P.parse_offer(offer_payload)
        if offer["kind"] not in (P.KIND_FILE, P.KIND_DIRECTORY, P.KIND_TEXT):
            reason = f"{offer['kind']} transfer not yet supported by this client"
            w.send_message(P.encode_message(P.build_answer(False, reason)))
            click.echo(f"Error: {reason}", err=True)
            yield w.close()
            sys.exit(1)

        if only_text and offer["kind"] != P.KIND_TEXT:
            reason = f"--only-text refuses {offer['kind']} transfers"
            w.send_message(P.encode_message(P.build_answer(False, reason)))
            click.echo(f"Error: {reason}", err=True)
            yield w.close()
            sys.exit(1)

        if offer["kind"] == P.KIND_TEXT:
            # Typing the code IS the consent for text — takeit's
            # behavior. No filesystem side effect, nothing to "accept";
            # just print the message and close.
            text = offer["text"]
            w.send_message(P.encode_message(P.build_answer(True)))
            # Print the text without adding framing. Terminal control
            # bytes are escaped so an authenticated peer cannot move the
            # cursor, clear the screen, or spoof shell output.
            terminal_text = _escape_terminal_text(text)
            click.echo(terminal_text, nl=False)
            # If the sender's text didn't end with a newline, finish
            # the line so the user's prompt isn't glued to the message.
            if not terminal_text.endswith("\n"):
                click.echo()
            # Same close handshake as file/dir for protocol uniformity.
            complete_payload = yield w.get_message()
            P.parse_simple_flag(complete_payload, "complete")
            w.send_message(P.encode_message(P.build_done()))
            yield w.close()
            return

        if offer["kind"] == P.KIND_FILE:
            sender_name = offer["filename"]
            try:
                parent_real, final_name = _resolve_output_target(
                    output_file, sender_name
                )
                parent_real = os.path.realpath(parent_real)
            except ValueError as e:
                click.echo(f"Error: {e}", err=True)
                w.send_message(
                    P.encode_message(P.build_answer(False, "bad output target"))
                )
                yield w.close()
                sys.exit(1)
            display_name = sender_name
            offered = f"Offered: {display_name} ({_pretty_size(offer['size'])})"
            if final_name != sender_name:
                offered += f" → saving as {final_name}"
            click.echo(offered)
            dest_path = os.path.join(parent_real, final_name)
            partial_path, meta_path = R.receiver_paths(dest_path)
        else:  # KIND_DIRECTORY
            sender_name = offer["dir_name"]
            try:
                parent_real, final_name = _resolve_output_target(
                    output_file, sender_name
                )
                parent_real = os.path.realpath(parent_real)
            except ValueError as e:
                click.echo(f"Error: {e}", err=True)
                w.send_message(
                    P.encode_message(P.build_answer(False, "bad output target"))
                )
                yield w.close()
                sys.exit(1)
            display_name = sender_name
            offered = (
                f"Offered: {display_name}/ "
                f"({offer['num_files']} files, "
                f"{_pretty_size(offer['num_bytes'])} → "
                f"{_pretty_size(offer['size'])} zipped)"
            )
            if final_name != sender_name:
                offered += f" → extracting as {final_name}/"
            click.echo(offered)
            # The "dest path" for finalization is the directory itself.
            # The partial-and-meta sidecars hang off a sibling .zip path
            # so they don't collide with anything inside the final dir.
            dest_path = os.path.join(parent_real, final_name)
            zip_marker = os.path.join(parent_real, f"{final_name}.zip")
            partial_path, meta_path = R.receiver_paths(zip_marker)
        # Sweep any orphan .tmp meta files in the resolved parent.
        R.cleanup_orphan_tmp_files(parent_real)

        # A4: refuse if anything already exists at dest_path. lstat (not
        # exists) so we catch dangling symlinks too — those return False
        # from os.path.exists but would be followed by os.rename.
        try:
            os.lstat(dest_path)
            click.echo(
                f"Error: {dest_path} already exists; refusing to overwrite", err=True
            )
            w.send_message(
                P.encode_message(P.build_answer(False, "destination exists"))
            )
            yield w.close()
            sys.exit(1)
        except FileNotFoundError:
            pass  # good — destination is clear

        # Defense in depth: even after realpath on the parent, ensure the
        # resolved dest stays inside it. The filename validator already
        # forbids separators in the offer's name, so this is a
        # belt-and-suspenders check against weird interactions with
        # symlinked parents or oddly-shaped final-name strings.
        if os.path.dirname(os.path.realpath(dest_path)) != parent_real:
            click.echo(
                "Error: refusing to write outside --output-file's parent",
                err=True,
            )
            w.send_message(
                P.encode_message(P.build_answer(False, "destination escapes parent"))
            )
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
                click.echo("(Partial transfer found on disk — resuming if accepted.)")
            if not click.confirm("Accept?", default=False):
                w.send_message(P.encode_message(P.build_answer(False, "user declined")))
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
        spinner = _make_spinner(reactor, hide=hide_progress)
        spinner.start()
        try:
            # HYP-437: pass the subprotocol allowlist so SubchannelDemultiplex
            # rejects opens for unknown subprotocol names (HYP-413's defense
            # was dormant without this).
            dw = w.dilate(
                allow_private_hints=allow_private_hints,
                stun_servers=stun_servers,
                expected_subprotocols={P.SUBCHANNEL_NAME},
            )
            yield dw.when_dilated()
            listener_ep = dw.listener_for(P.SUBCHANNEL_NAME)
        finally:
            spinner.stop()
        click.echo(f"Receiving into {dest_path}...")
        progress = _make_progress_bar(
            offer["size"],
            desc="receiving",
            hide=hide_progress,
        )
        try:
            yield _receive_chunks_over_subchannel(
                reactor,
                listener_ep,
                partial_path,
                meta_path,
                offer,
                prior_matches=prior_matches_offer,
                progress=progress,
            )
        finally:
            progress.close()

        # Whole-file integrity check before atomic rename. Run off the
        # reactor thread — for a 10 GB file this is ~20 s of BLAKE2b.
        actual_size, actual_hash = yield deferToThread(P.hash_file, partial_path)
        if actual_size != offer["size"] or actual_hash != offer["_content_hash_bytes"]:
            click.echo(
                "Error: integrity check failed; received bytes "
                "do not match the sender's hash",
                err=True,
            )
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
                    err=True,
                )
                yield w.close()
                sys.exit(1)
            os.unlink(partial_path)
        else:  # KIND_DIRECTORY: extract zip into a tempdir, atomic-rename
            extract_tmp = tempfile.mkdtemp(
                prefix=f".{final_name[:48]}.takeit-extract-",
                dir=parent_real,
            )
            try:
                # HYP-438: thread the offer's num_files/num_bytes into
                # the extractor so the central directory's totals are
                # bound by the consent prompt, not just advisory.
                yield deferToThread(
                    Z.extract_zip_safely,
                    partial_path,
                    extract_tmp,
                    num_files=offer["num_files"],
                    num_bytes=offer["num_bytes"],
                )
                # TOCTOU-safe atomic rename. os.rename refuses on Linux
                # if dest_path is a non-empty directory, but on macOS it
                # may overwrite — the lstat pre-check + this re-check
                # cover both.
                try:
                    os.lstat(dest_path)
                    click.echo(
                        f"Error: {dest_path} appeared during transfer; "
                        f"refusing to overwrite. Extracted bytes are at "
                        f"{extract_tmp}.",
                        err=True,
                    )
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
        suffix = "/" if offer["kind"] == P.KIND_DIRECTORY else ""
        click.echo(f"Saved {dest_path}{suffix}.")
        yield w.close()
    except Exception as exc:
        sys.exit(_handle_cli_error(exc, debug))


@inlineCallbacks
def _receive_chunks_over_subchannel(
    reactor, listener_ep, partial_path, meta_path, offer, prior_matches, progress=None
):
    factory = _ReceiverFactory(partial_path, meta_path, offer, prior_matches, progress)
    yield listener_ep.listen(factory)
    yield factory.done


class _ReceiverFactory(Factory):
    def __init__(self, partial_path, meta_path, offer, prior_matches, progress=None):
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
        # Chunk-phase state, populated when header arrives. FrameDecoder
        # construction is deferred to _on_header_received so it can be
        # given chunk_size / total_chunks / total_size for length caps
        # (HYP-409); constructing it here pre-header would force a
        # bypass of those caps until total_chunks lands.
        self._frame_decoder = None
        self._fh = None
        self._chunks_have = set()
        self._chunk_hashes = None  # list[bytes], from header
        self._total_chunks = None
        self._throttle = None
        self._stopped = False
        # HYP-451: True while verify_chunks_have runs off-thread. A
        # conforming sender must wait for chunks_have before sending
        # chunk frames, so any chunk-phase bytes in this window indicate
        # a non-conforming or hostile peer. Treated as ProtocolError.
        self._verify_in_flight = False

    def connectionMade(self):
        # Open the partial file safely. The audit (HYP-408) found two
        # symlink/race holes here: closing the fd and reopening by path
        # lost the O_NOFOLLOW guarantee, and the resume path had no
        # symlink protection at all. Fix: keep the original fd via
        # os.fdopen, and on the resume branch lstat+fstat cross-check
        # so a swap-after-stat can't slip through.
        partial = self._factory._partial_path
        if self._factory._prior_matches:
            # Resume: partial should already exist. O_NOFOLLOW refuses
            # if a symlink got pre-staged in our slot; the cross-check
            # catches a real-file swap that happened between the
            # caller's resume-state probe and now.
            fd = os.open(partial, os.O_RDWR | os.O_NOFOLLOW)
            try:
                lst = os.lstat(partial)
                fst = os.fstat(fd)
                if lst.st_ino != fst.st_ino or lst.st_dev != fst.st_dev:
                    raise OSError(
                        f"partial file {partial!r} was swapped between "
                        f"lstat and open (inode {lst.st_ino} vs {fst.st_ino})"
                    )
            except BaseException:
                os.close(fd)
                raise
        else:
            # Fresh: create with O_EXCL|O_NOFOLLOW + 0o600. If the path
            # already exists OR is a symlink, fail loud — upstream code
            # is responsible for the "stale partial" cleanup before we
            # get here.
            fd = os.open(
                partial,
                os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
            )
        self._fh = os.fdopen(fd, "r+b")

    def dataReceived(self, data):
        if self._stopped:
            return
        if self._header_phase:
            try:
                for body in self._header_decoder.feed(data):
                    # Got the full header.
                    self._on_header_received(body)
                    # HYP-434 / HYP-451: drain any pipelined post-header
                    # bytes the decoder buffered with the header. The
                    # CHUNK-protocol spec says senders MUST wait for
                    # `chunks_have` before sending chunk frames — any
                    # bytes here are non-conforming.
                    #
                    # If verify_chunks_have is in flight (resume path),
                    # we cannot process pipelined chunk bytes — they'd
                    # mutate `_chunks_have` and `_throttle`, then get
                    # silently overwritten when verify finishes,
                    # discarding the in-memory bookkeeping for those
                    # chunks. Treat as ProtocolError. For fresh
                    # transfers (no resume), verify is synchronous via
                    # _on_chunks_have_verified(set(), []), so the flag
                    # is False here and we honor HYP-434's drain-
                    # passthrough behavior.
                    remaining = self._header_decoder.drain_remaining()
                    if remaining:
                        if self._verify_in_flight:
                            raise P.ProtocolError(
                                "chunk frames received before chunks_have ack"
                            )
                        self._consume_frames(remaining)
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
            self._fail(
                P.ProtocolError(
                    f"subchannel header has {len(chunk_hashes)} chunk_hashes "
                    f"but offer implies {expected_count}"
                )
            )
            return
        self._chunk_hashes = chunk_hashes
        self._total_chunks = len(chunk_hashes)
        # Now that we know chunk_size + total_chunks + total_size, we
        # can construct the FrameDecoder with proper length caps.
        # Pre-header bytes can't reach _consume_frames because
        # _header_phase guards dataReceived; the deferred construction
        # is therefore safe.
        self._frame_decoder = P.FrameDecoder(
            chunk_size=self._chunk_size,
            total_chunks=self._total_chunks,
            total_size=self._size,
        )
        # Reconstruct the b64 list for the throttle/sidecar (sidecar
        # format hasn't changed — it stores chunk_hashes_b64 to match
        # against on resume).
        chunk_hashes_b64 = [base64.b64encode(h).decode("ascii") for h in chunk_hashes]
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
            # HYP-452: the sidecar passed prior_matches_offer in
            # _run_receive, but it can disappear or become unreadable
            # between then and now (concurrent rm, chmod, fs hiccup).
            # `load_receiver_state` returns None for any of those.
            # Fall back to fresh-transfer rather than raising
            # AttributeError — it's strictly safer (a fresh transfer
            # never exposes more than the resume path would).
            if prior is None:
                self._on_chunks_have_verified(set(), [])
                return
            claimed = list(prior.get("chunks_have", []))
            # HYP-451: pipelined chunk frames received before
            # _on_chunks_have_verified runs must be rejected; the flag
            # gates dataReceived's drain-passthrough.
            self._verify_in_flight = True
            d = deferToThread(
                R.verify_chunks_have,
                self._factory._partial_path,
                self._size,
                self._chunk_size,
                chunk_hashes,
                claimed,
            )
            d.addCallback(self._on_chunks_have_verified, claimed)
            d.addErrback(self._on_verify_failed)
        else:
            self._on_chunks_have_verified(set(), [])

    def _on_chunks_have_verified(self, verified, claimed):
        if self._stopped:
            return
        # HYP-451: verify finished; chunk-phase bytes are now legitimate.
        self._verify_in_flight = False
        chunks_have = sorted(verified)
        dropped = len(claimed) - len(chunks_have)
        if dropped:
            click.echo(f"Resume: dropped {dropped} chunk(s) that failed verification")
        if chunks_have:
            click.echo(f"Resuming: {len(chunks_have)} chunk(s) already on disk")
            # Mark resumed bytes as already-progressed.
            if self._progress is not None:
                bytes_already = sum(
                    min(self._chunk_size, self._size - i * self._chunk_size)
                    for i in chunks_have
                )
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
        # HYP-451: `_verify_in_flight` is intentionally NOT cleared here;
        # `_fail` sets `_stopped=True`, which `dataReceived` short-circuits
        # on before any further flag reads. If a future refactor decouples
        # `_stopped` from `_fail`, also clear `_verify_in_flight` here.
        self._fail(failure.value)

    def _consume_frames(self, data):
        try:
            for idx, chunk in self._frame_decoder.feed(data):
                if idx >= self._total_chunks:
                    raise P.ProtocolError(
                        f"chunk index {idx} >= total {self._total_chunks}"
                    )
                if idx in self._chunks_have:
                    continue  # duplicate; ignore (sender bug or retransmit)
                if not P.verify_chunk(chunk, self._chunk_hashes[idx]):
                    raise P.ProtocolError(f"chunk {idx} hash mismatch")
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
        # HYP-459: mirror sender's `_fail` — close the transport so a
        # misbehaving peer's subchannel doesn't stay alive while we
        # unwind. Symmetric to cli.py:1068's sender `_fail`.
        self.transport.loseConnection()

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
            self._factory.done.errback(
                P.ProtocolError("subchannel closed before header arrived")
            )
            return
        if self._chunks_have == set(range(self._total_chunks)):
            self._factory.done.callback(None)
        else:
            missing = sorted(set(range(self._total_chunks)) - self._chunks_have)
            self._factory.done.errback(
                P.ProtocolError(
                    f"subchannel closed with {len(missing)} chunks missing "
                    f"(first missing: {missing[:5]})"
                )
            )


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


def _escape_terminal_text(text):
    """Escape terminal control bytes in received inline text."""
    out = []
    for ch in text:
        cp = ord(ch)
        if ch in ("\n", "\t"):
            out.append(ch)
        elif cp < 0x20 or cp == 0x7F or 0x80 <= cp <= 0x9F:
            if cp <= 0xFF:
                out.append(f"\\x{cp:02x}")
            else:
                out.append(f"\\u{cp:04x}")
        else:
            out.append(ch)
    return "".join(out)


def _validate_words_only_handoff(code, verify):
    """Refuse a words-only `code` unless `--verify` was passed (HYP-416).

    Background: HYP-406 closed the canonical-code oracle by adding a
    128-bit locator to the on-the-wire code shape (``<base32>:<words>``).
    With a locator present, a hostile Nostr relay can no longer
    precompute every 3-word → tag mapping. Words-only handoff is
    preserved as a legacy ergonomic, but in that mode the relay CAN
    still mount an active MITM — the audit's wording is that words-only
    "cannot honestly claim relay-level anonymity or active-relay MITM
    resistance." Out-of-band SAS comparison via ``--verify`` is the
    only mitigation, so we REFUSE to proceed without it.

    Three branches, all four (shape, verify) combinations covered:

    * canonical full-shape code (contains ``:``) → silent return; the
      locator already authenticates the channel.
    * words-only + ``verify=False`` → ``click.UsageError`` with a
      message that names BOTH escapes (rerun with --verify, or paste
      the full ``<locator>:<words>`` form). The user must NOT see a
      vague "warning" they can shrug off.
    * words-only + ``verify=True`` → soft stderr note. The user has
      already opted into the SAS prompt; we just remind them that
      THIS comparison is the load-bearing security check.
    """
    if ":" in code:
        return
    if not verify:
        raise click.UsageError(
            "Words-only code handoff requires --verify on both sides "
            "(a hostile Nostr relay could otherwise intercept this "
            "transfer). Either:\n"
            "  - rerun with --verify and compare the SAS out-of-band, OR\n"
            "  - paste the full <locator>:<words> code (e.g. via QR)."
        )
    click.echo(
        "Note: words-only code handoff. The verifier comparison you're "
        "about to do is what makes this transfer MITM-resistant.",
        err=True,
    )


def format_verifier(verifier):
    """Render the protocol's verifier bytes as four 4-char hex groups
    separated by dashes (takeit's convention).

    Only the first 8 bytes are displayed — that's 64 bits of SAS, plenty
    for visual comparison and matching takeit's UX exactly. Comparing
    longer strings out-of-band is error-prone, and the underlying SPAKE2
    transcript already binds the full key.
    """
    hex16 = verifier[:8].hex()
    return "-".join(hex16[i : i + 4] for i in range(0, 16, 4))


@inlineCallbacks
def _confirm_verifier(w):
    """If --verify was set, surface the SAS and block until the user
    presses Enter. Ctrl-C aborts: callers should treat the raised
    KeyboardInterrupt as user-declined and close the takeit session."""
    verifier = yield w.get_verifier()
    click.echo(f"Verifier: {format_verifier(verifier)}")
    click.echo(
        "Compare with the other side and press Enter to continue, or Ctrl-C to abort.",
    )
    # click.prompt with default="" + show_default=False is the cleanest
    # blocking line read; an empty Enter returns "" and we proceed.
    click.prompt("", default="", show_default=False, prompt_suffix="")


if __name__ == "__main__":
    main()
