# Mail

A decentralized email client that runs on [Freenet](https://freenet.org) —
no servers, no accounts, end-to-end encrypted, and rate-limited by
Anti-Flood Tokens instead of a central authority.

Messages are stored in per-user inbox contracts on the Freenet network,
encrypted with post-quantum ML-KEM-768 (NIST FIPS 203) and authenticated
with ML-DSA-65 (NIST FIPS 204). The UI is a Dioxus web app served from
a signed web-container contract under a deterministic, reproducible
contract id.

> **Status**: pre-alpha. The protocol and contract ids will change.
> Don't use this for anything you'd mind losing.

## Try it

1. **Install Freenet.** Follow the
   [Freenet quickstart](https://freenet.org/quickstart/) to get a
   network-connected node running.

2. **Open the webapp** in a browser at the published contract id:

   ```
   http://127.0.0.1:7509/v1/contract/web/<contract-id>/
   ```

   The latest committed contract id lives at
   [`published-contract/contract-id.txt`](published-contract/contract-id.txt)
   in this repo. The `7509` port and `/v1/contract/web/` path are the
   defaults for the Freenet HTTP/WebSocket gateway in current builds —
   adjust for your setup.

3. **Create an identity** in the app. Your private keys are held by the
   identity delegate inside the Freenet node sandbox, never in browser
   storage.

4. **Send a message.** The first send burns one Anti-Flood Token,
   minted automatically by your local node.

## How it works

Three contracts and a delegate make up the full system:

- **Web container contract** — hosts the compiled Dioxus UI. Signed
  with an ed25519 key committed to
  [`test-contract/`](test-contract/) for sandbox builds, and with an
  offline-generated production key for real releases.
- **Inbox contract** — one per user. Stores ML-KEM-encapsulated,
  ChaCha20-Poly1305-encrypted messages, with ML-DSA-65 signatures
  on every state delta for ownership verification.
- **Anti-Flood Token contracts** — mint/burn tokens that gate each
  message send, preventing spam without a central authority.
- **Identity delegate** — holds the user's private keys inside the
  Freenet delegate sandbox, never exposed to the webapp.

## Contributing

See [`AGENTS.md`](AGENTS.md) for the developer guide: build setup,
feature-flag matrix, publishing pipeline, Playwright tests, and the
manual E2E checklist.

See [`RELEASING.md`](RELEASING.md) for the release runbook.

## License

TBD (see Cargo.toml).
