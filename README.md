# takeit

Securely transfer files between computers, peer-to-peer, with no central server.

`takeit` is a fork of [magic-wormhole](https://github.com/magic-wormhole/magic-wormhole) that:

- replaces the mailbox server with **Nostr relays** for peer introduction;
- makes **dilation** (multiplexed, reconnecting Noise transport) the default for bulk transfer;
- adds **resume** for interrupted transfers via on-disk sidecar files;
- uses three phonetic words as the transfer code (no numeric nameplate).

## Usage

```sh
# sender
takeit send report.pdf
# -> code: purple-sausages-mocha

# receiver
takeit receive purple-sausages-mocha
```

If the transfer is interrupted, re-running the send command picks up where it left off.

## Status

Pre-alpha. Wire protocol and CLI surface may change.

## How it works

Two clients meet on a public Nostr relay using a tag derived from the shared code, run SPAKE2 over a few ephemeral Nostr events, exchange direct connection candidates (LAN addresses, STUN-derived reflexive addresses), and then stream the file directly over a Noise-encrypted dilated connection. The Nostr relays only see encrypted PAKE messages and address hints; they never carry file bytes.

See `docs/` for the protocol details (forthcoming).

## License

MIT. See `LICENSE`. Substantial portions of the code derive from magic-wormhole, also MIT-licensed.
