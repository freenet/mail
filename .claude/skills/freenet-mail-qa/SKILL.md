---
name: freenet-mail-qa
description: QA inventory for the freenet-email project. Use this skill before merging feature PRs, after fixing bugs, or when asked "what's tested" / "what's manual". Source of truth is docs/qa/manual-test-inventory.md.
---

# Freenet Mail QA

## When to invoke

- User asks: "what's tested?", "what's manual?", "what bugs are we missing?",
  "did we test X?", "QA inventory", "what should I test before merging?".
- About to merge a non-trivial UI/contract/delegate PR.
- After a bug fix — the row needs to flip from `manual` to `auto`, or a new
  row needs to be added.
- Before a release — walk `manual` rows for the touched areas.

## How to use

1. **Read** `docs/qa/manual-test-inventory.md` first. The matrix is keyed by
   feature area (Identity, Contacts, Inbox, Compose, Drafts, Sent, Archive,
   Settings, Layout, Network).
2. **Filter** to the area the PR / bug touches. Each row has a `Status`
   column: `auto` / `manual` / `automatable` / `blocked`.
3. **For `auto` rows**: confirm the linked test still exists and still
   exercises the behavior (search ui/tests for the title).
4. **For `manual` rows**: do the recipe; report what passed / failed.
5. **For `automatable` rows**: if you're already touching that area, write
   the test in the matching spec file. Then flip the row to `auto`.
6. **For `blocked` rows**: cite the blocking issue; don't try to automate.

## Updating the inventory

When you add a test:

```
| <Behavior> | auto | <suite>: `<test title>` |
```

Suites: `offline` (`ui/tests/email-app.spec.ts`), `iso`
(`ui/tests/live-node.spec.ts`), `liveness`
(`ui/tests/production-liveness.spec.ts`), `rust` (`cargo test`).

When you remove a test, flip the row back to `manual` (with recipe) or
delete the row if the behavior is gone.

## Running the suites

| Suite | Command |
|---|---|
| offline | `cargo make test-ui-playwright` |
| iso (cross-node gated) | `FREENET_LIVE_E2E_SEND=1 cargo make test-e2e-real-node` |
| liveness | `scripts/smoke-test-production.sh <url>` |
| rust | `cargo test --workspace` |

Iso harness is heavy (~5–10 min, full freenet net + dx build + headed
browser). Don't run on every change — gate to tags / nightly.

## WIP settings gating

Settings controls whose backend isn't fully wired live behind the
`wip-settings` cargo feature (off by default). When you add or modify
a Settings control:

1. **Has a real consumer in non-Settings code?** Ship it ungated. Verify
   by grepping the persisted field name across `ui/src/` excluding
   `settings.rs` — if zero hits, it's WIP.
2. **No consumer yet?** Gate with `#[cfg(feature = "wip-settings")]` on
   the enum variant / route / nav entry / locals / SettingRow rsx
   block. Cite the blocking issue (#69, #85, etc.) in the surrounding
   comment.
3. **Backend just landed?** Drop the gate, add row to the matrix as
   `manual` (with recipe) or `auto` (with test link).

Verify all three configs build clean before pushing:

```bash
cargo check -p freenet-email-ui
cargo check -p freenet-email-ui --features wip-settings
cargo check -p freenet-email-ui --no-default-features --features example-data,no-sync
```

The matrix's "Settings" section flags WIP rows with `(gated behind
\`wip-settings\`)` and status `blocked` + the issue link.

## Anti-patterns

- **Don't** add a test that requires `--features example-data,no-sync` for
  cross-node behavior. Mock data lives in offline; real protocol behavior
  belongs in iso.
- **Don't** flip a row to `auto` without linking the spec + title. Future
  agents need to verify the link.
- **Don't** automate `blocked` rows. Cite the issue and move on.
- **Don't** delete rows just because they're tedious to test. Mark them
  `automatable` and add to the gap-conversion list at the bottom of the
  matrix.
