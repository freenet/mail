# Freenet Mail

A decentralized email client that runs on [Freenet](https://freenet.org) —
no servers, no accounts, end-to-end encrypted, and rate-limited by
Anti-Flood Tokens instead of a central authority.

Messages live in per-user inbox contracts on the Freenet network,
encrypted with post-quantum ML-KEM-768 (NIST FIPS 203) and
authenticated with ML-DSA-65 (NIST FIPS 204). The UI is a Dioxus
web app served from a signed web-container contract, fronted by a
stable **facade contract** so the bookmarkable URL never changes
between releases.

> **Status**: pre-alpha. The protocol may still change. Don't store
> anything you'd mind losing.

## Try it

1. **Install Freenet.** Follow the
   [Freenet quickstart](https://freenet.org/quickstart/) to get a
   network-connected node running on `127.0.0.1:7509`.

2. **Open the app at the stable URL:**

   ```
   http://127.0.0.1:7509/v1/contract/web/122f6AR7PyF8d8mhczuNQM4xrLtBf5t8g2iB7PEVT7KC/
   ```

   That contract id is the **facade** — a thin pointer contract that
   serves a tiny HTML+JS loader. The loader forwards the browser to
   whichever web-container release is current. The facade id is
   byte-stable across every release (see [#198](https://github.com/iduartgomez/freenet-email/issues/198),
   [#200](https://github.com/iduartgomez/freenet-email/issues/200),
   [#206](https://github.com/iduartgomez/freenet-email/issues/206)),
   so once you bookmark it, future releases land automatically without
   the URL changing.

   The current canonical id is also committed at
   [`published-contract/facade-id.txt`](published-contract/facade-id.txt).

3. **Create an identity** in the app. Your private keys live inside
   the identity delegate, in the Freenet node sandbox — never in
   browser storage.

4. **Send a message.** The first send burns one Anti-Flood Token,
   minted automatically by your local node.

## How it works

Three on-chain contracts and one delegate make up the system:

- **Facade contract** ([`contracts/facade/`](contracts/facade/)) —
  stable bookmarkable entry point. Its state is a signed
  `FacadePointer { current_app_id, prev_app_ids }`; the served
  payload is a static HTML+JS shell that `postMessage`s the gateway
  shell to navigate to the current web-container. Per release the
  facade wasm is unchanged — only the pointer state is updated, via
  `fdev execute update --as-state` signed with the production key.
- **Web container contract** ([`contracts/web-container/`](contracts/web-container/)) —
  hosts the compiled Dioxus UI. Its contract id is
  `hash(wasm, ed25519_pubkey)` and rotates whenever the wasm bytes
  change. The facade pointer absorbs the rotation so users never see
  it.
- **Inbox contract** ([`contracts/inbox/`](contracts/inbox/)) —
  one per user. Stores ML-KEM-encapsulated, ChaCha20-Poly1305
  encrypted messages, with ML-DSA-65 signatures on every state delta
  for ownership verification. Lockfile-isolated
  ([#199](https://github.com/iduartgomez/freenet-email/issues/199))
  so workspace dep bumps can't rotate the contract id and orphan
  stored mail; a per-identity migration path
  ([#213](https://github.com/iduartgomez/freenet-email/issues/213),
  [#223](https://github.com/iduartgomez/freenet-email/issues/223))
  re-signs and re-PUTs when deliberate rotation is needed.
- **Anti-Flood Token contracts + delegate**
  ([`modules/antiflood-tokens/`](modules/antiflood-tokens/)) —
  mint/burn tokens that gate each message send. Prevents spam
  without a central authority.
- **Identity delegate**
  ([`modules/identity-management/`](modules/identity-management/)) —
  holds the user's private keys inside the Freenet delegate sandbox,
  never exposed to the webapp.

### Why two contracts in front of the UI?

A Freenet contract id is `hash(wasm, parameters)`. Any change to the
UI rebuilds the wasm and rotates the id. Without a stable pointer,
every release would orphan every bookmark. The facade is a tiny
wasm contract that's deliberately frozen — its lockfile is isolated
from the workspace, its rustc version is pinned in
`rust-toolchain.toml`, and CI byte-checks every PR against the
committed `published-contract/facade.wasm`. Releases flip the
pointer state inside the facade rather than re-deploying it.

## Contributing

See [`AGENTS.md`](AGENTS.md) for the developer guide: build setup,
feature-flag matrix, publishing pipeline, Playwright tests, and the
manual E2E checklist.

See [`RELEASING.md`](RELEASING.md) for the production release
runbook, including facade pointer flips and recovery.

## License

Licensed under the GNU Lesser General Public License v3.0 or later
(LGPL-3.0-or-later). See [`COPYING.LESSER`](COPYING.LESSER) and
[`COPYING`](COPYING) for the full license text.
