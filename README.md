<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/lockup-dark.svg">
    <img src="assets/lockup-light.svg" alt="takeit" width="360">
  </picture>
</p>

<p align="center">
  <a href="https://github.com/dardevelin/takeit/actions/workflows/test.yml"><img alt="tests" src="https://github.com/dardevelin/takeit/actions/workflows/test.yml/badge.svg"></a>
  <a href="https://pypi.org/project/takeit/"><img alt="PyPI" src="https://img.shields.io/pypi/v/takeit.svg"></a>
  <a href="https://pypi.org/project/takeit/"><img alt="Python" src="https://img.shields.io/pypi/pyversions/takeit.svg"></a>
  <a href="https://github.com/dardevelin/takeit/blob/main/LICENSE"><img alt="MIT" src="https://img.shields.io/badge/license-MIT-blue.svg"></a>
</p>

# takeit

**Send a file, folder, or message to someone. No accounts, no upload to a cloud, no fuss.**

```sh
# you, the sender
$ takeit send report.pdf
takeit code: purple-sausages-mocha

# them, the receiver — type the code
$ takeit receive purple-sausages-mocha
Offered: report.pdf (3.2 MiB)
Accept? [y/N]: y
Saved /Users/them/Downloads/report.pdf.
```

The file goes from your computer to theirs, **directly**. Nothing in
between gets a copy.

## Install

```sh
pip install takeit
```

That's it. You now have a `takeit` command. (Python 3.10 or newer.)

## Use it

### Send a file, directory, or text

```sh
takeit send report.pdf
takeit send my_project/
takeit send --text "the meeting is at 3pm"
```

You'll see a three-word code. Tell it to the other person — say it,
text it, paste it, scan it. Directories are streamed as a single
deterministic zip — the receiver expands them on arrival. Text is
inline — the receiver prints it to their terminal.

```sh
takeit send report.pdf --qr
```

…also prints a QR code for the receiver's phone.

### Receive a file

```sh
takeit receive purple-sausages-mocha
```

Or, if you don't want to type the whole code at once:

```sh
takeit receive
```

…then type words and press TAB to autocomplete.

The file lands in `~/Downloads` by default. Use `--output-dir` to save
it elsewhere.

### Got cut off mid-transfer?

Just rerun both commands. takeit picks up where it stopped. You don't
need to do anything special — the partial file and a tiny notebook
file (`<filename>.takeit-partial`, `.takeit-partial.meta`) sit next to
where the file is going, and the next attempt resumes from them.

### Common flags

| Flag | What it does |
|------|--------------|
| `--qr` (sender) | Show a QR code for the takeit code. |
| `--code-length 4` (sender) | Use a 4-word code instead of 3. |
| `-y` / `--accept` (receiver) | Skip the "accept this?" prompt. |
| `--output-dir DIR` (receiver) | Save somewhere other than `~/Downloads`. |
| `--debug` | Show full error details if something goes wrong. |

`takeit --help`, `takeit send --help`, `takeit receive --help` give
you the rest.

### Tab completion in your shell

```sh
# zsh
eval "$(takeit completion zsh)"

# bash
eval "$(takeit completion bash)"

# fish
takeit completion fish > ~/.config/fish/completions/takeit.fish
```

## Is it safe?

**For typical use, yes.** A short summary in plain language:

- **The file goes directly between you and the receiver.** It does not
  pass through any server we (or anyone) operate.
- **The connection is encrypted** with a password derived from the
  three-word code. Someone watching the network sees ciphertext.
- **Wrong code → no transfer.** A bad guess fails immediately and
  closes the connection. Brute-force isn't practical.
- **Your filename and file size are also encrypted** — the relays we
  use to find each other never see them.

A few honest limits:

- The relay can tell *that* a transfer is happening (someone is using a
  takeit-style code on this relay) but not *what* is being transferred,
  *who* is involved, or *where* the file is going.
- If both you and the receiver are behind tricky network setups
  (corporate firewalls, mobile carrier-grade NAT), the direct connection
  may fail — there's no fallback to "send through us." Try from a
  different network.
- Pre-alpha software. Use it for things that are nice to send privately,
  not for things that ruin your day if delivery fails.

The deep dive is below in *How it works under the hood* if you're
curious.

---

## For developers

### Library use

The CLI is a thin layer over a Python library. Embed takeit in your
own application:

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

See `src/takeit/api.py` for the full surface (Deferred-mode and
Delegate-mode wormholes, `dilate()` for bulk-data subchannels,
`derive_key()` for purpose-keyed derivation, etc.).

### How it works under the hood

1. The sender generates a three-word code (e.g. `purple-sausages-mocha`).
2. Both clients derive the same routing tag from the code via
   `HKDF-SHA256` and subscribe to it on a public Nostr relay.
3. They run **SPAKE2** over a small handful of ephemeral Nostr events,
   producing a shared secret. The takeit code is the only password —
   SPAKE2's online-only-one-guess property makes it resistant to brute
   force.
4. They exchange direct connection candidates (LAN addresses +
   STUN-derived public IPs) and open a direct, **Noise**-encrypted,
   multiplexed TCP connection.
5. The file streams chunk-by-chunk over that direct connection. Every
   chunk is hash-verified on arrival; the whole file is hash-verified
   before the atomic rename into place.

### Hacking on takeit

```sh
git clone https://github.com/dardevelin/takeit
cd takeit
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/python -m pytest tests/
```

Two opt-in integration tests run only when env vars are set:
`TAKEIT_TEST_RELAY=wss://...` (real Nostr relay) and
`TAKEIT_TEST_STUN=stun.l.google.com:19302` (real STUN server).

### Status

Pre-alpha. The wire protocol and the CLI surface may change before
v0.1. The in-process test suite (~210 tests) covers the protocol,
resume logic, security defenses, and CLI behavior. See
[CHANGELOG.md](CHANGELOG.md) for the per-release notes and
[v0.1 known limitations][limits] for the current rough edges.

[limits]: #v01-known-limitations

### v0.1 known limitations

- **Multi-file send is one-shot.** `takeit send a b c` (multiple
  positionals) is not supported — pass a directory instead.
- **No verifier (SAS) display.** takeit computes a short verification
  string but the CLI doesn't surface it for paranoid out-of-band
  comparison.
- **Privacy: encrypted-offer ciphertext length leaks file size to the
  relay (±1 MiB).** The encrypted offer's `chunk_hashes` list is
  ~32 bytes per chunk; a relay operator can divide ciphertext length
  to estimate file size to within one chunk.
- **Privacy: the routing tag is HKDF-deterministic.** A relay operator
  can precompute every possible `(code → tag)` mapping and detect
  specific codes in use. Doesn't enable a man-in-the-middle, but it's
  an observation channel.
- **NAT traversal is direct-only.** Symmetric NATs without a
  port-forward will fail; no transit-relay fallback.

### Contributing

Issues and PRs welcome. The codebase is small (~9 KLOC), MIT-licensed,
tests-heavy. The brand and voice rules live in
[docs/brand.md](docs/brand.md) — keep them honest in any UI work.

### Acknowledgements

Some core protocol modules (the multiplexed Noise transport, parts of
the state-machine plumbing) are reused with attribution from prior art;
the full list and copyright lines are in [NOTICE](NOTICE).

### License

MIT. See [LICENSE](LICENSE).
