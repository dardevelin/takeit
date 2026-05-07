# takeit

**Securely transfer files between computers, peer-to-peer. No central server.**

Two short commands, a three-word code, and the file flows directly between the
two machines over an encrypted connection.

```sh
# on the sending machine
$ takeit send report.pdf
Wormhole code: purple-sausages-mocha
On the receiving machine, run:
    takeit receive purple-sausages-mocha

# on the receiving machine
$ takeit receive purple-sausages-mocha
Offered: report.pdf (3.2 MiB)
Accept? [y/N]: y
Receiving into /Users/you/Downloads/report.pdf...
receiving: 100%|████████████████| 3.20M/3.20M [00:00<00:00, 12.8MB/s]
Saved /Users/you/Downloads/report.pdf.
```

That's it. No accounts, no upload to anyone's cloud, no waiting for a relay
to forward your bytes. The two computers find each other through a public
[Nostr](https://github.com/nostr-protocol/nostr) relay (introduction only —
the relay never sees your file) and then talk directly.

## Why

Existing peer-to-peer file tools either route your bytes through a central
relay (so the operator sees your traffic), require accounts and clients
(Dropbox, WeTransfer), or are tricky to set up (rsync over SSH, NAT
configuration). `takeit` is in the same family as
[magic-wormhole](https://github.com/magic-wormhole/magic-wormhole) — short
human-readable code, strong PAKE, peer-to-peer transport — but with no
project-run infrastructure: introduction happens over public Nostr relays
that anyone can host, swap, or run themselves.

## Install

```sh
pip install takeit
```

Requires Python 3.10 or newer. The console script `takeit` is installed,
along with the shorter aliases `tx` and `rx`.

## Quickstart

Send a file:

```sh
takeit send <path>            # generates a 3-word code
takeit send <path> --qr       # also prints a QR code for the receiver's phone
takeit send <path> --code-length 4  # longer code, more entropy
```

Receive a file:

```sh
takeit receive <code>                    # one-shot
takeit receive                           # interactive: tab-completes against the wordlist
takeit receive <code> --output-dir ~/inbox
takeit receive <code> -y                 # auto-accept, no prompt
```

If a transfer is interrupted (Ctrl-C, network drop, dead battery), just rerun
both commands. The receiver keeps a small `<filename>.takeit-partial` and a
sidecar metadata file; the next run picks up where it left off, after
re-verifying the bytes already on disk to defend against a tampered
sidecar.

## How it works

1. The sender generates a three-word code (e.g. `purple-sausages-mocha`).
2. Both clients derive the same routing tag from the code via
   `HKDF-SHA256` and subscribe to it on a public Nostr relay.
3. They run **SPAKE2** over a small handful of ephemeral Nostr events,
   producing a shared secret. The wormhole code is the only password —
   SPAKE2's online-only-one-guess property makes it resistant to brute
   force.
4. They exchange direct connection candidates (LAN addresses + STUN-derived
   public IPs) and open a direct, **Noise**-encrypted, dilated TCP
   connection.
5. The file streams chunk-by-chunk over that direct connection. Every chunk
   is hash-verified on arrival; the whole file is hash-verified before the
   atomic rename into place.

Nostr relays only ever see the SPAKE2 PAKE messages and a few small
encrypted control messages — the file itself never touches them. The
sender's IP and the receiver's IP only see each other (not the relay
operator), and only after both peers consent to the transfer.

For users behind symmetric NATs without a port-forward the direct
connection may fail — there is no transit-relay fallback. Try from a
different network in that case.

## All flags

```
takeit [--version] [--debug] {send,receive,tx,rx,completion} ...
```

**`takeit send <path>`** (alias `tx`)

| Flag | Default | Description |
|------|---------|-------------|
| `--code-length N` | 3 | Number of words in the generated code. |
| `--code <code>` | — | Use a specific code instead of allocating a fresh one. |
| `--no-cache` | off | Don't read or write the per-file chunk-hash cache. |
| `--qr` | off | Also render the code as a terminal QR code. |
| `--relay wss://...` | takeit defaults | Override Nostr relay URLs (repeatable). |

**`takeit receive [code]`** (alias `rx`)

| Flag | Default | Description |
|------|---------|-------------|
| `code` (positional) | prompt | If omitted, takeit prompts with tab-completion. |
| `-y` / `--accept` | off | Skip the y/N accept prompt. |
| `--output-dir DIR` | `~/Downloads` if it exists, else `.` | Where to save the received file. |
| `--relay wss://...` | takeit defaults | Override Nostr relay URLs (repeatable). |

**`takeit completion <shell>`** prints a completion script. Install with:

```sh
# zsh
eval "$(takeit completion zsh)"
# bash
eval "$(takeit completion bash)"
# fish
takeit completion fish > ~/.config/fish/completions/takeit.fish
```

## Library use

The CLI is a thin layer over a Python library. To embed takeit in your own
application:

```python
import takeit
from twisted.internet import asyncioreactor
asyncioreactor.install()
from twisted.internet import reactor

w = takeit.create("myapp/v1", reactor)
w.allocate_code()
code = await w.get_code()
print(f"share this: {code}")

w.send_message(b"hello")
msg = await w.get_message()
await w.close()
```

See `src/takeit/api.py` for the full surface (Deferred-mode and Delegate-mode
wormholes, `dilate()` for bulk-data subchannels, `derive_key()` for
purpose-keyed derivation, etc.).

## v0.1 known limitations

- **Single file at a time.** No multi-file (`takeit send a b c`) or directory
  transfer yet. Tracked for a future release.
- **No text mode.** No `takeit send --text "msg"` yet (file transfer only).
- **No verifier (SAS) display.** The wormhole computes a verifier but the
  CLI doesn't surface it for paranoid out-of-band comparison.
- **Privacy: encrypted-offer size leaks file size to the relay (±1 MiB).**
  The offer's encrypted `chunk_hashes` list ciphertext length is roughly
  proportional to chunk count.
- **Privacy: the routing tag is HKDF-deterministic.** A relay operator can
  precompute every possible `(code → tag)` mapping and detect specific
  codes in use. Doesn't enable a man-in-the-middle (SPAKE2 still defends),
  but it's an observation channel.
- **NAT traversal is direct-only.** Symmetric NATs without a port-forward
  will fail. There's no transit-relay fallback.

## Status

Pre-alpha. Wire protocol and CLI surface may change. The in-process test
suite has 203 tests covering the SPAKE2 + offer/answer/chunk-streaming +
resume protocol; full network integration testing is opt-in via the
`TAKEIT_TEST_RELAY=wss://...` and `TAKEIT_TEST_STUN=stun.l.google.com:19302`
environment variables.

## Contributing

Issues and PRs welcome at <https://github.com/dardevelin/takeit>. The
codebase is small (~9 KLOC), MIT-licensed, and tests-heavy.

## Acknowledgements

`takeit` would not exist without [magic-wormhole][mw] by Brian Warner —
the SPAKE2-over-mailbox design and the dilation transport machinery are
his work. takeit reuses several modules verbatim with attribution; see
`NOTICE` for the full list.

[mw]: https://github.com/magic-wormhole/magic-wormhole

## License

MIT. See `LICENSE` for the text and `NOTICE` for upstream attribution.
