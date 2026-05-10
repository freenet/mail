# facade-loader

Static HTML+JS shell served by the facade contract. Issue #200 / Phase 1.

## Role

The facade contract has a **stable contract ID** (its wasm + parameters
never change). Its state carries a signed pointer to the *current*
freenet-email webapp contract ID. The loader is the webapp content the
facade serves; its job is to redirect the browser to the real app at
`/v1/contract/web/<current_app_id>/`.

## Phase 1 mechanism (this directory)

The loader is built per-release with `<current_app_id>` baked in by the
publish pipeline (`scripts/build-loader.sh`). The pipeline writes
`dist/index.html` from `src/index.html.tmpl`, substituting the placeholder
`__CURRENT_APP_ID__` with the real ID, then `cargo make build-facade`
embeds `dist/` as the facade webapp content.

Pros: no in-browser binary-WS-protocol parsing; loader is ~50 lines of
vanilla JS. Cons: rotating `current_app_id` requires a new facade-state
UPDATE *and* the new loader bytes go into the new state. Both the
on-chain contract and the signer compute the signature over
`(pointer, loader_bytes)`, so the swap is atomic.

The facade-state pointer remains the source of truth and is what tools /
future smarter loaders should read; the baked redirect is a convenience
for browsers without a freenet-stdlib-aware client.

## Phase 2 (deferred)

Replace the static redirect with a small WASM-backed loader that subscribes
to facade state via the gateway WS API and supports automatic rollback to
`prev_app_ids` on load failure. Out of scope for Phase 1.
