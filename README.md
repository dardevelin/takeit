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
takeit code: nbswy3dpo5xxe3deebsxe5dpor4q:purple-sausages-mocha

# them, the receiver — paste the code (or scan a QR)
$ takeit receive nbswy3dpo5xxe3deebsxe5dpor4q:purple-sausages-mocha
Offered: report.pdf (3.2 MiB)
Accept? [y/N]: y
Saved /Users/them/Downloads/report.pdf.
```

The code's two parts are: a long random locator (carries the routing
tag) and a short three-word human handoff half. Paste the full string,
or use `--qr` and scan it.

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

You'll see a full code ending in three words. Tell it to the other
person — paste it or scan it when you can. Directories are streamed as
a single deterministic zip — the receiver expands them on arrival. Text
is inline — the receiver prints it to their terminal.

```sh
takeit send report.pdf --qr
```

…also prints a QR code for the receiver's phone.

### Receive a file

```sh
takeit receive nbswy3dpo5xxe3deebsxe5dpor4q:purple-sausages-mocha
```

Or, if you don't want to type the whole code at once:

```sh
takeit receive
```

…then type words and press TAB to autocomplete.

The file lands in `~/Downloads` by default. Pass `--output-file PATH`
(or `-o PATH`) to save somewhere else. If `PATH` is an existing
directory, the file goes inside with the sender's name. If `PATH`
doesn't exist, it's used as the full target — `takeit receive -o
~/notes/today.md` saves to that path even if the sender called the
file something else.

### Receiver speaks first

Sometimes it's the *receiver* who initiates the transfer ("hey, can
you send me your config?"). takeit can flip the direction so the
receiver allocates the code:

```sh
# you, the receiver
$ takeit receive --allocate
takeit code: jbswy3dpo5xxe3deebsxe5dpor4q:copper-orbit-staircase
On the sending machine, run:
    takeit send --code jbswy3dpo5xxe3deebsxe5dpor4q:copper-orbit-staircase <file>

# them, the sender — type or paste the code
$ takeit send --code jbswy3dpo5xxe3deebsxe5dpor4q:copper-orbit-staircase report.pdf
```

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
| `--ignore-unsendable-files` (sender) | Skip unreadable entries during a directory transfer instead of erroring. |
| `--verify` (both) | Show a short authentication string and pause to compare out-of-band. |
| `--allow-private-hints` (both) | Allow direct connection attempts to peer-advertised private LAN IPs. Off by default. |
| `--stun-server HOST:PORT` (both) | Opt into STUN-derived public-IP hints. May be repeated. |
| `-y` / `--accept` (receiver) | Skip the "accept this?" prompt. |
| `-o` / `--output-file PATH` (receiver) | Save somewhere else. Existing dir → save into it; non-existing path → rename-on-receive. |
| `-a` / `--allocate` (receiver) | Receiver picks the code; sender uses `--code <code>`. |
| `-t` / `--only-text` (receiver) | Refuse incoming files/directories; only accept `--text` messages. |
| `--hide-progress` (both) | Suppress the progress bar and spinner. Auto-suppressed when stdout isn't a terminal. |
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
- **The connection is encrypted** with a key derived from the full
  takeit code. Someone watching the network sees ciphertext.
- **Wrong code → no transfer.** A bad guess fails immediately and
  closes the connection. Brute-force isn't practical.
- **Your filename, file size, and inline text are plaintext-confidential** —
  relays do not get the decrypted values. Ciphertext is padded to a
  small set of size buckets, so relays only learn which bucket — short,
  medium, large — the plaintext fell into. They can still see phase
  tags, event count, and timing.
- **Want to be extra sure?** Pass `--verify` on both sides. takeit
  shows a short authentication string after the code is exchanged;
  read it out loud and the receiver checks it matches before any
  bytes move. Catches even a determined attacker.

A few honest limits:

- This is private transfer, not anonymous transfer. Public Nostr relays
  see client IPs, timing, subscriptions, phase tags, event counts, and
  ciphertext size buckets on a takeit-style tag. They do not see decrypted
  file bytes, filenames, file sizes, or inline text.
- Peers can see direct connection hints you choose to advertise. Private
  LAN hint connections require `--allow-private-hints`; STUN-derived
  public-IP hints require explicit `--stun-server HOST:PORT`.
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
Delegate-mode sessions, `dilate()` for bulk-data subchannels,
`derive_key()` for purpose-keyed derivation, etc.).

### How it works under the hood

1. The sender generates a fresh 128-bit random *locator* and a short
   three-word handoff half from a wordlist. The full code shown to the
   user is `<base32-locator>:<words>` (e.g.
   `nbswy3dpo5xxe3deebsxe5dpor4q:purple-sausages-mocha`).
2. The locator (NOT the words) is fed through `HKDF-SHA256` to produce
   the public Nostr routing tag. Both clients subscribe to that tag on
   a public Nostr relay to find each other. Since the locator is 128
   random bits, a relay cannot brute-force it the way it could with
   short words alone.
3. The peers run **SPAKE2** over a small handful of ephemeral Nostr
   events, using the full code as the PAKE input, producing a shared
   secret. In legacy words-only mode, the words-only string is the PAKE
   input and `--verify` is mandatory.
4. They exchange direct connection candidates and open a direct,
   **Noise**-encrypted, multiplexed TCP connection. Private LAN
   candidates and STUN-derived public-IP candidates are opt-in because
   they reveal network location to the peer and, for STUN, to the STUN
   operator.
5. The file streams chunk-by-chunk over that direct connection. Every
   chunk is hash-verified on arrival; the whole file is hash-verified
   before the atomic rename into place.

### Hacking on takeit

```sh
git clone https://github.com/dardevelin/takeit
cd takeit
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pre-commit install        # ruff lint + format + pytest on every commit
pytest tests/
```

The pre-commit hooks call `pytest` from `PATH`; activate the venv before
committing so they find the project's deps. CI runs the same checks via
`.github/workflows/test.yml`.

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
- **Words-only handoff requires `--verify`.** Default takeit codes are
  `<long-random-locator>:<short-words>` and are MITM-resistant out of
  the box. If you handed off ONLY the words (no QR / no full code),
  takeit refuses to proceed unless you use `--verify` on both sides
  and compare the authentication string out-of-band. Without that, a
  hostile Nostr relay could intercept the transfer.
- **NAT traversal is direct-only.** Symmetric NATs without a
  port-forward will fail; no transit-relay fallback. STUN-derived
  public-IP hints are opt-in via `--stun-server HOST:PORT`.

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
