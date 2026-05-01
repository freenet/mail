# Test mail-local-state Keypair — DO NOT USE IN PRODUCTION

This directory contains a fixed EC P-384 keypair used by the
`mail-local-state` delegate (drafts + read-state, issue #47/47a) during
local development and CI builds. It exists so that
`cargo make build-contracts` is deterministic and reproducible across
machines and clones.

## What is here

- `mail-local-state-key.private.pem` — **secret key, committed intentionally**
- `mail-local-state-key.public.pem` — public key

## Why a test secret is in git

Same rationale as `test-contract/identity/README.md`. The delegate needs
a serialized `LocalStateParams` (containing this secret key) embedded
into the UI via `include_bytes!`. Without a committed keypair, every
fresh clone would produce a different delegate identity, breaking
reproducible builds.

## Security implications

The delegate stash is **per-device**, encrypted by the Freenet runtime
under this params blob. Anyone with read access to this repository can
read/write **their own local stash** for the test build, but the stash
of any other user is on their device and not exposed by this key. No
network propagation, no cross-user leakage.

**Never copy this key to a production deployment.** A real production
deployment must generate its own keypair via a non-committed build
pipeline.

## Regenerating the keypair

```bash
rm -rf test-contract/mail-local-state modules/mail-local-state/build/mail-local-state-params
cargo make generate-mail-local-state-params
```
