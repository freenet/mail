# Candidate artifacts

WASM for the next generation, committed while that generation is still being
built. Unlike `../wasm/`, these files may change: each PR that changes the
source rebuilds them, and CI (`scripts/check-delegate-candidate.sh`) fails if
the committed bytes are not what the source builds.

The release that ships them moves them into `../wasm/v2/`, pins them in
`../frozen.sha256` and adds their registry rows. From then on they never change.

| File | What |
|---|---|
| `mail_delegate` | The unified mail delegate (`delegates/mail-delegate`), built with the default features (`v1-transition` on). Its parameters are empty, so its delegate key is `blake3(code hash)`. |
| `mail_delegate_code_hash` | `fdev inspect` code hash of `mail_delegate`. |

Rebuild after changing the delegate, its lockfile or anything it depends on
(`protocol/`, `wire-v1/`):

```bash
scripts/build-wasm.sh delegates/mail-delegate delegate freenet-main-delegate \
    published-contract/candidate/mail_delegate \
  | sed -n 's/^code hash: *//p' > published-contract/candidate/mail_delegate_code_hash
```

Build on linux/amd64 with the toolchain `rust-toolchain.toml` selects, as CI does.
