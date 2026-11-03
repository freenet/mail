# cargo-mutants on inbox v2: what survives, and why

`cargo mutants` (config in `.cargo/mutants.toml`) rewrites each operator, return
value and match arm in `src/merge.rs`, `src/sync.rs`, `src/lib.rs` and
`src/types.rs` in turn and runs the crate's tests. A mutant that no test fails
is a survivor, and one that makes the tests hang is a timeout. Neither is a
pass, so each has a line below. `scripts/check-mutants-triage.sh` fails on a
survivor with no line, and, on a run of every shard, on a line with no
survivor. A line is the mutant as cargo-mutants names it, without its position.

Last full run, after fix round 4 (review r4, which added the nothing-lost
oracle to the fuzzer and changed no rule): the same 245, 211 caught, 6
survived, 2 timed out. After fix round 3 (review r3): 245 mutants, 211 caught, 26
unviable (they do not compile, so no test could be run), 6 survived, 2 timed
out. The 6 survivors and the 2 timeouts below are the whole list. Each was
applied by hand at the position cargo-mutants gave, built, and run against every
test: the survivors passed all of them, and the two timeouts did not finish in
240 seconds. (After fix round 2: 241 mutants, 207 caught, the same 6 and 2. After fix round 1: 204 mutants, 176 caught, 6 survived of which 2
were test gaps, now tested. The run that added this file: 168 mutants, the
first five below.)

None of the eight is a test gap. Each is a mutant that does not change what the
function returns, or one that cannot fail faster than a hang.

## Survivors

- `src/merge.rs: replace > with >= in join_owner` Equivalent. The mutant is
  `rank > *b` becoming `>=`. A tie in `(version, digest)` needs the same digest,
  and the loop has already skipped a digest it has seen (`seen.insert`), so a
  tie is never compared.
- `src/merge.rs: replace > with >= in join_entry` Equivalent. The mutant is
  `rank(&value) > rank(held)` becoming `>=`. It could only matter when the new
  value has the same rank as the held one but is not equal to it. The rank of a
  revocation is `(epoch, expiry, sig)` and of a usage entry `(used, expiry,
  sig)`; the one field left out is `pass_id`, and `genuine` requires it to equal
  the map key, as the held entry's does. A value that passes `genuine` and
  matches the rank is therefore equal to the held one, and `*held != value`
  already excludes it. A value that does not pass `genuine` is not inserted
  whichever way the comparison goes.
- `src/merge.rs: replace < with <= in merge` Equivalent. This is the
  `(encoding.len(), &encoding) < (held.0.len(), &held.0)` that picks the
  smallest encoding of one id. Equal means the same bytes, which is the same
  message, and the copies collected for one id are distinct (`at_id.contains`;
  dropping that `!` is a mutant the tests do catch), so a tie never arises, and
  if it did the two values would be equal.

- `src/merge.rs: replace > with >= in Filter<'_>::admit_quarantine` See the
  next line.
- `src/merge.rs: replace > with == in Filter<'_>::admit_quarantine` Both are
  equivalent since decision 19. The mutant is the certificate's size cap,
  `proof.cert.len() > ghostkey_verify::MAX_CERTIFICATE_BYTES`, which saves the
  cost of reading an oversized certificate. `GhostkeyCertificate::from_cbor`
  refuses the same sizes itself (over `MAX_CERTIFICATE_BYTES` as given, and over
  it once armored, which a certificate of exactly that many bytes is), and it
  runs before the certificate can admit anything. So neither `==` nor `>=`
  changes what is admitted. Until decision 19 an Open inbox held a proof
  without reading it, and the cap alone decided there, which a test pinned; an
  Open inbox now refuses every proof, so nothing reaches the cap but a proof in
  RequireGhost, which `from_cbor` also reads.

- `src/types.rs: replace bounded::<impl serde::de::Visitor<'de> for Visit<K, V, N>>::expecting -> std::fmt::Result with Ok(Default::default())`
  Equivalent. `expecting` only writes the text of a type error. `decode` maps
  every error except the count bound's to one fixed reason, so the text is never
  read.

## Timeouts

- `src/merge.rs: replace > with < in merge` Two mutants: the loops that trim the
  revocations and the usage entries to their caps (`while revoked.len() > cap`,
  `while usage.len() > cap`). With `<` the loop keeps popping an emptied map and
  never ends, so the test run hangs and cargo-mutants stops it at its timeout.
  A test cannot fail sooner than a hang. They are detected, and a rewrite that
  would make them fail fast (`truncate`-style trimming) would change the
  candidate's bytes, which this change leaves alone.

## What the first runs found, and what changed

- The first run, before the seam's logic moved out of `src/merge.rs`, left 14
  survivors: the 3 above and 11 in the test seam's own call sites. Some were
  real gaps in `tests/plausible_mutants.rs`: it took the first law a mutant
  broke, so a seam that broke a different one passed (for example,
  `bytes.len() - 64` becoming `/ 64` in the by-pass-id memo refused a genuine
  certificate, and the test accepted that as the mutant doing its job). Others
  sat in a copy of the requestor check that is compiled out when the feature is
  on. Each scenario now lists every law it sees broken, and the mutant must
  break exactly the list in `fingerprint`; the seam's logic moved into
  `src/mutant.rs`, so the rules hold one-line calls and no copy of a rule.
- Branch coverage found one unvisited arm, the revocation count in a summary,
  which no mutant run reached either. `tests/rules.rs` now has a test for it; it
  fails with that arm removed (`|| state.revoked.len() as u32 != theirs.revoked_count`
  replaced by `|| false`).
- Fix round 1 left two survivors that were test gaps. `replace && with || in
  merge`, in the seam's `note_revocation` call, let a forged revocation into the
  union the `FilterUnprunedRevocations` and `OverflowReadsUnion` mutants read;
  that scenario now has a forged-revocation control, which fails under the
  mutant applied by hand. `replace match guard why == OVER_A_BOUND with true in
  decode` reported every semantic decode error as a count bound;
  `tests/bounds.rs` `other_decode_errors_are_not_a_bound` fails under it,
  applied by hand.
