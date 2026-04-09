# Committed Test Keypairs — DO NOT USE IN PRODUCTION

This directory contains **test-only** cryptographic material that is
intentionally committed to the repository so that builds and contract
IDs are reproducible across machines and CI.

## Contents

```
test-contract/
├── README.md                               (this file)
├── web-container-keys.toml                 ed25519 key pair for the
│                                           web-container signing flow
│                                           (see below)
└── identity/
    ├── README.md                           details on the EC P-384 key
    ├── identity-manager-key.private.pem    secret key for the
    │                                       identity-management delegate
    └── identity-manager-key.public.pem     public key
```

Neither keypair has any bearing on production deployments — see the
security notes below.

---

## `web-container-keys.toml` — webapp signing key

Used by `cargo make publish-email-test` to sign the compressed webapp
archive so that the on-chain `web-container` contract accepts it at
validation time. Produced by:

```bash
cargo run -p web-container-sign -- generate \
  --output test-contract/web-container-keys.toml
```

(or equivalently `cargo make generate-web-container-keys`).

### Why this key is committed

The web-container contract's on-chain ID is derived from its code hash
**plus** its parameters. The parameters blob is the 32-byte ed25519
verifying key. If every contributor generated their own keypair, the
derived contract ID would be different on every machine, making the
committed `published-contract/` directory impossible to keep in sync.

A single committed test key guarantees that two developers building
from the same commit produce the **same** test contract ID — which is
exactly the reproducibility property Phase 2 (#6) is trying to
establish. `freenet-river` uses the same pattern at
`test-contract/test-keys.toml`.

### Security implications

**Anyone with read access to this repository can sign a webapp with
this test key and publish it under the test contract ID.** That is
acceptable because:

1. This key is only used for the `publish-email-test` flow against a
   local `freenet local` node.
2. Production publishes (`cargo make publish-email`) use a separate,
   **uncommitted** key file — by convention at
   `~/.config/freenet-email/web-container-keys.toml` — that each
   release manager generates and keeps out of band.
3. The key grants no access to any user data. The email application's
   message encryption uses per-user RSA keys generated in the browser
   at identity-creation time, unrelated to this signing key.

**Never copy this key to a production deployment. Never reuse it for
any purpose other than testing `freenet-email`'s own publish
pipeline.**

### Rotating

```bash
rm test-contract/web-container-keys.toml \
   published-contract/contract-id.txt \
   published-contract/webapp.parameters \
   published-contract/web_container_contract.wasm
cargo make generate-web-container-keys
cargo make update-published-contract
git add test-contract/web-container-keys.toml published-contract/
git commit -m "chore: rotate web-container test keypair"
```

Rotating the key **changes the test contract ID**. Any user with a
bookmark to the old ID will see it as a dead contract.

---

## `identity/` — identity-management delegate key

EC P-384 keypair used by the `identity-management` delegate. See
`identity/README.md` for details, including the same reproducibility
and security caveats (and the fact that the secret PEM is committed
for the same reason this file is).
