# Changelog

All notable changes to takeit will be documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
follows [Semantic Versioning](https://semver.org/) once it leaves alpha.

## [Unreleased]

## [0.0.1] — 2026-05-07

First public release. Pre-alpha; wire protocol and CLI surface may change.

### What works

- Send and receive files over the wormhole using a three-word code.
- Peer introduction via public Nostr relays (no project-run server,
  no transit relay). Default relays are bundled; override with `--relay`.
- SPAKE2 password-authenticated key exchange over a few ephemeral
  Nostr events. NaCl-secretbox encryption per phase.
- Direct, dilated, Noise-encrypted TCP transport for bulk data.
  STUN-derived reflexive addresses gathered alongside LAN candidates.
- Resumable transfers via on-disk sidecars. The receiver re-hashes any
  bytes already on disk before trusting them, defending against a
  same-user attacker pre-staging a malicious sidecar.
- Per-chunk integrity (BLAKE2b-256) plus a whole-file hash check before
  the atomic rename into place.
- Symlink-safe destination handling (`O_CREAT|O_EXCL|O_NOFOLLOW`, 0600
  permissions, `os.link` finalize that fails closed on race).
- Click CLI with `send` / `receive` (aliases `tx` / `rx`), `--qr`,
  `--debug`, `--version`, `completion <shell>`, interactive code prompt
  with tab-completion against the wordlist.
- Tumbling-block progress indicator that tracks throughput automatically
  (rotation tied to bytes received, freezes on stall).
- Library API: `takeit.create(appid, reactor, ...)` returning either a
  Deferred-mode or Delegate-mode wormhole.

### Known limitations (see README)

- Single file at a time (no multi-file or directory transfer yet).
- No text-only mode.
- No verifier/SAS display.
- Encrypted-offer ciphertext length leaks file size to the relay
  (±1 MiB).
- Routing tag is HKDF-deterministic (relay can detect specific
  in-use codes; doesn't enable MitM).
- NAT traversal is direct-only (no transit-relay fallback).

### Acknowledgements

`takeit` builds on [magic-wormhole](https://github.com/magic-wormhole/magic-wormhole)
by Brian Warner. Several modules are reused verbatim with attribution;
see `NOTICE` for the full list.

[Unreleased]: https://github.com/dardevelin/takeit/compare/v0.0.1...HEAD
[0.0.1]: https://github.com/dardevelin/takeit/releases/tag/v0.0.1
