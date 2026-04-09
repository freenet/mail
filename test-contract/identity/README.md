# Test Identity Keypair — DO NOT USE IN PRODUCTION

This directory contains a fixed EC P-384 keypair used by the
`identity-management` delegate during local development and CI builds.
It exists so that `cargo make build-contracts` is deterministic and
reproducible across machines and clones.

## What is here

- `identity-manager-key.private.pem` — **secret key, committed intentionally**
- `identity-manager-key.public.pem` — public key

## Why a test secret is in git

The `identity-management` delegate needs a serialized `IdentityParams`
(containing this secret key) embedded into the UI via `include_bytes!`.
Without a committed keypair, every fresh clone would produce a different
delegate identity, breaking reproducible builds and CI.

The same pattern is used by `freenet-river`'s `test-contract/test-keys.toml`.

## Security implications

**Anyone with read access to this repository can impersonate this test
identity.** That is acceptable because:

1. This key is only used to sign/identify the **test build** of the
   identity delegate — it has no bearing on any production deployment.
2. A real production deployment must generate its own keypair and
   supply the resulting `identity-manager-params` via a non-committed
   build pipeline (see Phase 4: publishing pipeline).
3. The test key gives no access to any user data, mailbox, or
   inbox — the email contract's message encryption uses per-user RSA
   keys generated client-side, unrelated to this delegate key.

**Never copy this key to a production deployment. Never reuse it for
any purpose other than testing `freenet-email`'s own build.**

## Regenerating the keypair

```bash
rm -rf test-contract/identity modules/identity-management/build/identity-manager-params
cargo make generate-identity-params
```
