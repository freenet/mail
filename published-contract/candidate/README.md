# Candidate artifacts

The mail delegate's and inbox v2's WASM between releases. Unlike `../wasm/`,
these files change: each PR that changes either's source rebuilds them, and CI
(`scripts/check-delegate-candidate.sh`, `scripts/check-inbox-candidate.sh`)
fails if the committed bytes are not what the source builds.

The release that ships them moves them into `../wasm/v2/`, pins them in
`../frozen.sha256` and adds their registry rows. From then on they never change.

| File | What |
|---|---|
| `mail_delegate` | The unified mail delegate (`delegates/mail-delegate`), built with the `v1-transition` feature. Its parameters are empty, so its delegate key is `blake3(code hash)`. |
| `mail_delegate_code_hash` | `fdev inspect` code hash of `mail_delegate`. |
| `inbox_v2` | The inbox v2 contract (`contracts/inbox-v2`). Nothing embeds it yet. Each inbox's parameters are its address and the Ghost Key master, so its contract id is per inbox. |
| `inbox_v2_code_hash` | `fdev inspect` code hash of `inbox_v2`. |

Rebuild after changing the delegate, its lockfile or anything it depends on
(`protocol/`, `wire-v1/`). That includes test-only edits: a change confined
to a `#[cfg(test)]` module of a delegate source file has been seen to change
the built bytes, so do not assume a test change leaves the candidate alone.

```bash
scripts/build-wasm.sh delegates/mail-delegate delegate freenet-main-delegate,v1-transition \
    published-contract/candidate/mail_delegate \
  | sed -n 's/^code hash: *//p' > published-contract/candidate/mail_delegate_code_hash
```

Build on linux/amd64 with the toolchain `rust-toolchain.toml` selects, as CI
does. CI is the canonical builder: if its rebuild differs from yours, the
`check-drift` run uploads its bytes as the artifact
`mail-delegate-candidate-<sha>`. Commit those:

```bash
gh run download <run-id> -n mail-delegate-candidate-<sha> -D published-contract/candidate/
```

Inbox v2 the same way, after changing `contracts/inbox-v2`:

```bash
scripts/build-wasm.sh contracts/inbox-v2 contract contract \
    published-contract/candidate/inbox_v2 \
  | sed -n 's/^code hash: *//p' > published-contract/candidate/inbox_v2_code_hash
```

Its CI artifact is `inbox-v2-candidate-<sha>`.
