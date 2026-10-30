//! Typed operations over [`super::call`]: one function per thing the UI asks
//! the mail delegate, each matching the replies that operation can return
//! and nothing else (a reply of another kind is a protocol mismatch, not a
//! result).
//!
//! These must be awaited from a spawned task, never from inside the node
//! loop (`api::node_comms`): that loop is what delivers the delegate's
//! answers, so awaiting one there would wait forever.

use freenet_mail_protocol::{
    Addr, Entropy, FailureCode, Hash32, IdentityInfo, ImportKind, ImportSource, Item, ItemKind,
    ItemRef, MAX_DECRYPT_BATCH, Op, Reply,
};
use serde_bytes::ByteBuf;

use super::{CallError, call, call_ack, unexpected};

// ── Identities ─────────────────────────────────────────────────────────────

pub(crate) async fn list_identities() -> Result<Vec<IdentityInfo>, CallError> {
    match call(Op::ListIdentities).await? {
        Reply::Identities(ids) => Ok(ids),
        other => Err(unexpected(&other)),
    }
}

/// Create an identity. Its recovery key comes back this once, so it can be
/// backed up as it is made; later reveals are consented exports.
pub(crate) async fn create_identity(
    alias: String,
    description: String,
) -> Result<(IdentityInfo, SecretString), CallError> {
    let op = Op::CreateIdentity {
        alias,
        description,
        ui_entropy: Entropy(nonzero_entropy()),
    };
    match call(op).await? {
        Reply::CreatedIdentity {
            identity,
            recovery_key,
        } => Ok((identity, SecretString::new(recovery_key))),
        other => Err(unexpected(&other)),
    }
}

/// The pause before a lost create that is not listed is looked for again.
const LOST_CREATE_RECHECK_MS: u32 = 3_000;

/// What happened to a create whose answer never came.
#[derive(Debug)]
pub(crate) enum LostCreate {
    /// It was created: here it is, with its recovery key from a consented
    /// export (the one returned at creation was lost with the answer).
    Created(IdentityInfo, SecretString),
    /// It is not there: creating it again is safe.
    NotCreated,
    /// It is there, but its recovery key could not be shown now.
    CreatedKeyUnavailable(IdentityInfo, CallError),
    /// Nothing could be checked either.
    Unknown(CallError),
}

/// After a create with no answer ([`CallError::Unknown`]): the identity may
/// exist. Look for it by `alias` and, if it is there, fetch its recovery
/// key through the consented export, so the backup step can still run.
///
/// Matching by alias is enough: the delegate refuses a second live identity
/// with the same alias, atomically. The only way the identity found is not
/// the one this create made is another tab of the same app creating that
/// same alias first (this create then got a lost `Conflict`); what is shown
/// is then the user's own identity of exactly that name, through the
/// consented export, so no other identity's key is exposed. A per-create
/// nonce in the protocol would close even that, at the cost of a delegate
/// change.
pub(crate) async fn after_lost_create(alias: &str) -> LostCreate {
    let found = match find_lost_create(alias, list_identities).await {
        Ok(found) => found,
        Err(e) => return LostCreate::Unknown(e),
    };
    let Some(info) = found else {
        return LostCreate::NotCreated;
    };
    match export_recovery_key(info.addr).await {
        Ok(key) => LostCreate::Created(info, key),
        Err(e) => LostCreate::CreatedKeyUnavailable(info, e),
    }
}

/// The identity named `alias`, per `list`. A create still queued behind
/// other work may not be listed yet, so one miss is checked again after a
/// pause before it counts as "not created" (which invites the user to
/// create it again).
async fn find_lost_create<F, Fut>(
    alias: &str,
    mut list: F,
) -> Result<Option<IdentityInfo>, CallError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<Vec<IdentityInfo>, CallError>>,
{
    for attempt in 0..2 {
        if attempt > 0 {
            pause_ms(LOST_CREATE_RECHECK_MS).await;
        }
        if let Some(info) = list().await?.into_iter().find(|i| i.alias == alias) {
            return Ok(Some(info));
        }
    }
    Ok(None)
}

/// Import an identity. Never overwrites: an address already stored comes
/// back unchanged with `already_present`.
pub(crate) async fn import_identity(
    source: ImportSource,
    kind: ImportKind,
    alias: String,
    description: String,
) -> Result<(IdentityInfo, bool), CallError> {
    let op = Op::ImportIdentity {
        source,
        kind,
        alias,
        description,
    };
    match call(op).await? {
        Reply::Imported {
            identity,
            already_present,
        } => Ok((identity, already_present)),
        other => Err(unexpected(&other)),
    }
}

pub(crate) async fn update_identity(
    addr: Addr,
    alias: String,
    description: String,
    expected_gen: u64,
) -> Result<u64, CallError> {
    // The delegate acknowledges with the record's new generation.
    call_ack(Op::UpdateIdentity {
        addr,
        alias,
        description,
        expected_gen,
    })
    .await
}

// Used by the confirm-identity prompt, which lands with the migration that
// can import unconfirmed identities (step B3 of the v0.3.0 chain, the next
// PR after this one). Remove this allow there.
#[allow(dead_code)]
pub(crate) async fn confirm_identity(addr: Addr, expected_gen: u64) -> Result<u64, CallError> {
    call_ack(Op::ConfirmIdentity { addr, expected_gen }).await
}

/// Delete an identity and everything it owns. The delegate asks the user
/// once, then deletes in bounded pages: repeat the same request on
/// `Continue` (without asking again) until `Deleted`. `progress` hears how
/// much is left after each page.
pub(crate) async fn delete_identity(
    addr: Addr,
    expected_gen: u64,
    mut progress: impl FnMut(u32),
) -> Result<(), CallError> {
    // A full identity is about 17k items at 256 per page; the bound only
    // stops a delegate that never finishes from looping forever.
    for _ in 0..1_000 {
        match call(Op::DeleteIdentity { addr, expected_gen }).await? {
            Reply::Deleted => return Ok(()),
            Reply::Continue { remaining } => progress(remaining),
            other => return Err(unexpected(&other)),
        }
    }
    Err(CallError::Unknown(
        "identity deletion did not finish".into(),
    ))
}

/// Identities whose approved deletion was interrupted; finish one with
/// [`delete_identity`], which does not ask again.
pub(crate) async fn list_deleting_identities() -> Result<Vec<IdentityInfo>, CallError> {
    match call(Op::ListDeletingIdentities).await? {
        Reply::Identities(list) => Ok(list),
        other => Err(unexpected(&other)),
    }
}

// ── Stored items ───────────────────────────────────────────────────────────

/// Whether `e` says the item is listed but its stored bytes cannot be read
/// (the host reports a file it cannot read or decrypt as absent, every
/// time). Writing it with no expected generation replaces it.
pub(crate) fn is_unreadable(e: &CallError) -> bool {
    matches!(e.code(), Some(FailureCode::Unreadable))
}

/// Tell the user, once per page, that something stored could not be read
/// and was replaced (or that defaults stand in for it).
pub(crate) fn notice_unreadable() {
    thread_local! {
        static SHOWN: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }
    if !SHOWN.with(|s| s.replace(true)) {
        crate::toast::push_toast_detached(
            "Some of Mail's saved data on this node could not be read. \
             Defaults are used in its place, and saving replaces it.",
            crate::toast::ToastLevel::Warning,
        );
    }
}

pub(crate) async fn get_item(item: ItemRef) -> Result<Option<Item>, CallError> {
    match call(Op::GetItem { item }).await? {
        Reply::Item(item) => Ok(item),
        other => Err(unexpected(&other)),
    }
}

/// Every item of one kind (and owner), paging until the delegate has no
/// more.
pub(crate) async fn list_all_items(
    kind: ItemKind,
    owner: Option<Addr>,
) -> Result<Vec<Item>, CallError> {
    let mut out: Vec<Item> = Vec::new();
    let mut after = None;
    loop {
        let op = Op::ListItems {
            kind,
            owner,
            after: after.clone(),
            limit: 256,
        };
        let (items, more) = match call(op).await? {
            Reply::Items { items, more } => (items, more),
            other => return Err(unexpected(&other)),
        };
        let last = items.last().map(|i| ByteBuf::from(i.item.id.clone()));
        out.extend(items);
        match (more, last) {
            (true, Some(last)) => after = Some(last),
            _ => return Ok(out),
        }
    }
}

/// Write `body`: `expected_gen` `None` creates only, `Some(g)` is a
/// compare-and-swap against generation `g`. Returns the new generation.
pub(crate) async fn put_item(
    item: ItemRef,
    body: Vec<u8>,
    expected_gen: Option<u64>,
) -> Result<u64, CallError> {
    // Counted until answered, so the page knows a reload would lose it.
    let _in_flight = crate::pending_saves::begin();
    call_ack(Op::PutItem {
        item,
        body: ByteBuf::from(body),
        expected_gen,
    })
    .await
}

pub(crate) async fn delete_item(item: ItemRef, expected_gen: u64) -> Result<(), CallError> {
    let _in_flight = crate::pending_saves::begin();
    match call(Op::DeleteItem { item, expected_gen }).await? {
        Reply::Deleted | Reply::Ack { .. } => Ok(()),
        other => Err(unexpected(&other)),
    }
}

/// How many times a merged write retries after losing a compare-and-swap.
pub(crate) const MERGE_RETRIES: u32 = 3;

/// Read-merge-write one item: `merge` gets the stored body (`None` when
/// absent) and returns the body to store, or `None` to leave it as it is.
/// On a lost compare-and-swap (another tab wrote first) the item is read
/// again and merged again, up to [`MERGE_RETRIES`] times with a growing
/// pause, then the conflict is returned to the caller.
///
/// An item that existed when first read and is gone on a retry was deleted
/// meanwhile: the write is dropped (`Ok(None)`) rather than recreating it,
/// so a delete is never undone by a write that raced it.
pub(crate) async fn put_item_merged(
    item: ItemRef,
    mut merge: impl FnMut(Option<&[u8]>) -> Option<Vec<u8>>,
) -> Result<Option<u64>, CallError> {
    let _in_flight = crate::pending_saves::begin();
    let mut attempt = 0;
    let mut existed = false;
    loop {
        let current = match get_item(item.clone()).await {
            Ok(current) => current,
            // Listed but unreadable: merge onto nothing and replace it (a
            // create, so the delegate keeps its index entry). Never a
            // resurrection: the item is still listed, not deleted.
            Err(e) if is_unreadable(&e) => {
                let Some(body) = merge(None) else {
                    return Ok(None);
                };
                notice_unreadable();
                return put_item(item.clone(), body, None).await.map(Some);
            }
            Err(e) => return Err(e),
        };
        let (stored, generation) = match &current {
            Some(i) => (Some(i.body.as_slice()), i.generation),
            None if existed => return Ok(None),
            None => (None, 0),
        };
        existed |= current.is_some();
        let Some(body) = merge(stored) else {
            return Ok(None);
        };
        match put_item(item.clone(), body, Some(generation)).await {
            Ok(generation) => return Ok(Some(generation)),
            Err(e)
                if matches!(e.code(), Some(FailureCode::Conflict { .. }))
                    && attempt < MERGE_RETRIES =>
            {
                attempt += 1;
                pause_ms(50 * 2u32.pow(attempt)).await;
            }
            Err(e) => return Err(e),
        }
    }
}

// ── v1 inbox crypto (transitional) ─────────────────────────────────────────

/// Decrypt v1 ciphertexts addressed to `addr`, in batches the delegate
/// accepts. Each entry is the plaintext, or `None` for a ciphertext that is
/// not this identity's (or is malformed): such a message is skipped, never
/// fatal.
///
/// A batch whose plaintexts would exceed the reply budget comes back with
/// `CapReached` for the entries that did not fit; those are asked for again
/// in later calls until each has been answered alone. Each entry keeps the
/// delegate's answer: `BadInput` for a ciphertext this identity cannot
/// decrypt, `CapReached` for a plaintext too large to fit any reply on its
/// own. A call that fails as a whole is the error.
pub(crate) async fn decrypt_v1(
    addr: Addr,
    ciphertexts: Vec<Vec<u8>>,
) -> Result<Vec<Result<Vec<u8>, FailureCode>>, CallError> {
    let mut out: Vec<Result<Vec<u8>, FailureCode>> =
        vec![Err(FailureCode::Internal); ciphertexts.len()];
    let mut pending: std::collections::VecDeque<usize> = (0..ciphertexts.len()).collect();
    while !pending.is_empty() {
        let batch: Vec<usize> = pending
            .drain(..pending.len().min(MAX_DECRYPT_BATCH))
            .collect();
        let op = Op::DecryptV1 {
            addr,
            ciphertexts: batch
                .iter()
                .map(|&i| ByteBuf::from(ciphertexts[i].clone()))
                .collect(),
        };
        let results = match call(op).await? {
            Reply::Decrypted(results) => results,
            other => return Err(unexpected(&other)),
        };
        if results.len() != batch.len() {
            return Err(CallError::Unknown(format!(
                "decrypted {} of {} ciphertexts",
                results.len(),
                batch.len()
            )));
        }
        let mut retry = Vec::new();
        for (&i, result) in batch.iter().zip(results) {
            match result {
                Ok(plain) => out[i] = Ok(plain.into_vec()),
                Err(FailureCode::CapReached) => {
                    out[i] = Err(FailureCode::CapReached);
                    retry.push(i);
                }
                Err(code) => out[i] = Err(code),
            }
        }
        // Nothing in the batch fitted: its first entry does not fit a reply
        // even on its own, and keeps its `CapReached`.
        if retry.len() == batch.len() {
            retry.remove(0);
        }
        for i in retry.into_iter().rev() {
            pending.push_front(i);
        }
    }
    Ok(out)
}

/// A v1 message sealed by the delegate: the ciphertext for the recipient,
/// the sender's ML-DSA signature over it, and the sender's verifying key.
#[derive(Clone, Debug)]
pub(crate) struct SealedV1 {
    pub content: Vec<u8>,
    pub signature: Vec<u8>,
    pub sender_vk: Vec<u8>,
}

pub(crate) async fn seal_v1(
    addr: Addr,
    recipient_ek: Vec<u8>,
    plaintext: Vec<u8>,
) -> Result<SealedV1, CallError> {
    let op = Op::SealV1Message {
        addr,
        recipient_ek: ByteBuf::from(recipient_ek),
        plaintext: ByteBuf::from(plaintext),
        ui_entropy: Entropy(nonzero_entropy()),
    };
    match call(op).await? {
        Reply::SealedV1 {
            content,
            signature,
            sender_vk,
        } => Ok(SealedV1 {
            content: content.into_vec(),
            signature: signature.into_vec(),
            sender_vk: sender_vk.into_vec(),
        }),
        other => Err(unexpected(&other)),
    }
}

/// Sign a v1 inbox authority payload (a new inbox state or a settings
/// change).
pub(crate) async fn sign_v1_authority(
    addr: Addr,
    settings_json: Vec<u8>,
    last_update_micros: i64,
) -> Result<Vec<u8>, CallError> {
    let op = Op::SignV1Authority {
        addr,
        settings_json: ByteBuf::from(settings_json),
        last_update_micros,
    };
    signature(op).await
}

/// The removal payload order the delegate signs: strictly ascending,
/// without duplicates.
pub(crate) fn removal_order(mut hashes: Vec<[u8; 32]>) -> Vec<[u8; 32]> {
    hashes.sort_unstable();
    hashes.dedup();
    hashes
}

/// Sign a v1 `RemoveMessages` payload. The delegate signs only hashes in
/// ascending order, so the hashes are sorted here; send the removal with
/// [`removal_order`]'s order, which is what the signature covers.
pub(crate) async fn sign_v1_removal(
    addr: Addr,
    hashes: Vec<[u8; 32]>,
) -> Result<Vec<u8>, CallError> {
    let op = Op::SignV1Removal {
        addr,
        assignment_hashes: removal_order(hashes).into_iter().map(Hash32).collect(),
    };
    signature(op).await
}

async fn signature(op: Op) -> Result<Vec<u8>, CallError> {
    match call(op).await? {
        Reply::Signature(sig) => Ok(sig.into_vec()),
        other => Err(unexpected(&other)),
    }
}

/// The v1 token-generator delegate's parameters for `addr`.
/// Secret bytes held by the page: zeroized on drop, and `Debug` prints only
/// their length, so a logged action or panic message never shows them.
#[derive(Clone)]
pub(crate) struct SecretBytes(pub(crate) zeroize::Zeroizing<Vec<u8>>);

impl std::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretBytes(<{} bytes redacted>)", self.0.len())
    }
}

/// A secret string held by the page, such as a recovery key. Clones share
/// one allocation, which is zeroized when the last clone drops, and `Debug`
/// prints nothing of it. (Text handed to the browser, for display, the
/// clipboard or a download, is outside the page's control.)
#[derive(Clone)]
pub(crate) struct SecretString(std::rc::Rc<zeroize::Zeroizing<String>>);

impl SecretString {
    pub(crate) fn new(s: String) -> Self {
        Self(std::rc::Rc::new(zeroize::Zeroizing::new(s)))
    }

    pub(crate) fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl AsRef<str> for SecretString {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl PartialEq for SecretString {
    fn eq(&self, other: &Self) -> bool {
        std::rc::Rc::ptr_eq(&self.0, &other.0) || self.as_str() == other.as_str()
    }
}

impl std::fmt::Debug for SecretString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretString(<redacted>)")
    }
}

/// The v1 token-generator delegate's parameters, which carry the identity's
/// ML-DSA signing seed (transitional; removed with the anti-flood tokens).
/// Fetch them only where they are used, and let them drop promptly.
///
/// Only the buffer returned here is zeroized. Using the parameters means
/// decoding them into stdlib `DelegateParameters`/`Parameters` (plain
/// `Vec<u8>` inside) and handing them to the node's client API, and those
/// copies are not zeroized: they live across the awaits of the send path
/// and are freed, not wiped. That holds only until the anti-flood tokens
/// go; the release guard refuses a delegate that still serves this.
pub(crate) async fn v1_aft_params(addr: Addr) -> Result<zeroize::Zeroizing<Vec<u8>>, CallError> {
    match call(Op::V1AftParams { addr }).await? {
        Reply::AftParams(params) => Ok(zeroize::Zeroizing::new(params.into_vec())),
        other => Err(unexpected(&other)),
    }
}

// ── Exports (the delegate asks the user) ───────────────────────────────────

pub(crate) async fn export_recovery_key(addr: Addr) -> Result<SecretString, CallError> {
    match call(Op::ExportRecoveryKey { addr }).await? {
        Reply::RecoveryKey(key) => Ok(SecretString::new(key)),
        other => Err(unexpected(&other)),
    }
}

// The JSON profile export has no UI yet (the recovery key covers backups).
#[allow(dead_code)]
pub(crate) async fn export_profile(addr: Addr) -> Result<zeroize::Zeroizing<Vec<u8>>, CallError> {
    match call(Op::ExportProfile { addr }).await? {
        Reply::Profile(profile) => Ok(zeroize::Zeroizing::new(profile.into_vec())),
        other => Err(unexpected(&other)),
    }
}

/// Reset a list the node can no longer read: the identity list
/// (`kind: None`) or one kind's list for its owner. The delegate asks the
/// user first, and refuses while the list reads fine. Stored records stay;
/// identities come back by restoring them from their recovery keys.
pub(crate) async fn repair_index(
    kind: Option<freenet_mail_protocol::ItemKind>,
    owner: Option<Addr>,
) -> Result<(), CallError> {
    match call(Op::RepairIndex { kind, owner }).await? {
        Reply::Ack { .. } => Ok(()),
        other => Err(unexpected(&other)),
    }
}

/// Withdraw a remembered "Always allow" for exports.
pub(crate) async fn revoke_export_grant() -> Result<(), CallError> {
    match call(Op::RevokeExportGrant).await? {
        Reply::Ack { .. } | Reply::Deleted => Ok(()),
        other => Err(unexpected(&other)),
    }
}

// ── Helpers ────────────────────────────────────────────────────────────────

/// 32 random bytes that are not all zero (the delegate refuses all-zero
/// entropy, the signature of a platform generator that wrote nothing).
fn nonzero_entropy() -> [u8; 32] {
    loop {
        let bytes: [u8; 32] = crate::rng::random_bytes();
        if bytes != [0; 32] {
            return bytes;
        }
    }
}

pub(crate) async fn pause_ms(ms: u32) {
    #[cfg(target_family = "wasm")]
    gloo_timers::future::TimeoutFuture::new(ms).await;
    #[cfg(not(target_family = "wasm"))]
    let _ = ms;
}

#[cfg(all(test, feature = "local-delegate", not(feature = "use-node")))]
mod tests {
    //! Run against the real delegate code (the offline backend), so these
    //! pin the UI's side of the protocol to what the delegate does, and the
    //! delegate's v1 crypto to the UI's own v1 implementation.

    use super::*;
    use freenet_mail_protocol::{DsaSeed, KemSeed};

    fn block_on<F: std::future::Future>(f: F) -> F::Output {
        futures::executor::block_on(f)
    }

    /// After a create whose answer was lost, an identity that was created is
    /// found with its recovery key (through the consented export), and one
    /// that was not is reported as safe to create again.
    #[test]
    fn a_lost_create_finds_the_identity_and_its_key() {
        let (info, key) = block_on(create_identity("lost-made".into(), String::new())).unwrap();
        match block_on(after_lost_create("lost-made")) {
            LostCreate::Created(found, k) => {
                assert_eq!(found.addr, info.addr);
                assert_eq!(k.as_str(), key.as_str());
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            block_on(after_lost_create("lost-never-made")),
            LostCreate::NotCreated
        ));
    }

    /// A lost create that is not listed at first (still queued behind other
    /// work) is found on the re-check, not reported as "not created".
    #[test]
    fn a_lost_create_listed_late_is_still_found() {
        let (info, _) = block_on(create_identity("lost-late".into(), String::new())).unwrap();
        let mut calls = 0;
        let found = block_on(find_lost_create("lost-late", || {
            calls += 1;
            let listed = if calls == 1 {
                Vec::new()
            } else {
                vec![info.clone()]
            };
            async move { Ok(listed) }
        }))
        .unwrap();
        assert_eq!(found.map(|i| i.addr), Some(info.addr));
        assert_eq!(calls, 2);
    }

    /// An identity imported from known seeds, with the UI-side keys for the
    /// same seeds.
    fn imported(alias: &str, seed: u8) -> (IdentityInfo, crate::app::login::StoredIdentityKeys) {
        let dsa = [seed; 32];
        let kem = [seed.wrapping_add(1); 64];
        let (info, _) = block_on(import_identity(
            ImportSource::Seeds {
                dsa: DsaSeed(dsa),
                kem: KemSeed(kem),
            },
            ImportKind::UserRestore,
            alias.into(),
            String::new(),
        ))
        .unwrap();
        let keys = crate::app::login::StoredIdentityKeys {
            ml_dsa_seed: dsa.to_vec(),
            ml_kem_seed: kem.to_vec(),
        };
        (info, keys)
    }

    /// Every item write (the Sent copy, archive, delete, settings, contacts,
    /// not only drafts) counts as pending until the delegate answers, so a
    /// reload just after it can be held off (#286: a reload right after Send
    /// lost the Sent copy whose write was still in flight).
    #[test]
    fn an_item_write_is_counted_as_pending_until_answered() {
        let (owner, _) = imported("pending-write", 62);
        let item = ItemRef {
            kind: ItemKind::Sent,
            owner: Some(owner.addr),
            id: vec![7; 16],
        };
        let before = crate::pending_saves::pending();
        let mut seen = None;
        block_on(put_item_merged(item.clone(), |_| {
            seen = Some(crate::pending_saves::pending());
            Some(b"sent".to_vec())
        }))
        .unwrap();
        assert_eq!(
            seen,
            Some(before + 1),
            "counted while the write is in flight"
        );
        assert_eq!(
            crate::pending_saves::pending(),
            before,
            "released once answered"
        );
        let stored = block_on(get_item(item.clone())).unwrap().unwrap();
        block_on(delete_item(item, stored.generation)).unwrap();
        assert_eq!(crate::pending_saves::pending(), before);
    }

    #[test]
    fn a_merged_write_does_not_resurrect_an_item_deleted_meanwhile() {
        let (owner, _) = imported("no-resurrect", 61);
        let item = ItemRef {
            kind: ItemKind::Draft,
            owner: Some(owner.addr),
            id: vec![9; 16],
        };
        let created = block_on(put_item(item.clone(), b"draft".to_vec(), Some(0))).unwrap();
        let mut first = true;
        let outcome = block_on(put_item_merged(item.clone(), |stored| {
            if first {
                first = false;
                // Another tab deletes the item between this read and the
                // write below (the in-page delegate runs synchronously).
                let request = crate::mail_delegate::new_request(Op::DeleteItem {
                    item: item.clone(),
                    expected_gen: created,
                });
                crate::mail_delegate::local::process(
                    &freenet_mail_protocol::to_cbor(&request).unwrap(),
                );
            }
            stored.map(|_| b"autosaved".to_vec())
        }))
        .unwrap();
        assert_eq!(outcome, None);
        assert!(
            block_on(get_item(item)).unwrap().is_none(),
            "the delete stands"
        );
    }

    #[test]
    fn a_batch_over_the_reply_budget_is_decrypted_in_full() {
        let (sender, _) = imported("budget-sender", 41);
        let (recipient, _) = imported("budget-recipient", 51);
        // Four 200 KB plaintexts: together over the 512 KiB reply budget,
        // each well under it.
        let plaintexts: Vec<Vec<u8>> = (0..4u8).map(|n| vec![n; 200 * 1024]).collect();
        let ciphertexts: Vec<Vec<u8>> = plaintexts
            .iter()
            .map(|p| {
                block_on(seal_v1(sender.addr, recipient.ek.to_vec(), p.clone()))
                    .unwrap()
                    .content
            })
            .collect();
        let out = block_on(decrypt_v1(recipient.addr, ciphertexts)).unwrap();
        let got: Vec<Result<Vec<u8>, FailureCode>> = plaintexts.into_iter().map(Ok).collect();
        assert!(out == got, "every message must come back readable");
    }

    #[test]
    fn a_rename_is_acknowledged_with_the_new_generation() {
        let (info, _) = imported("before-rename", 31);
        let generation = block_on(update_identity(
            info.addr,
            "after-rename".into(),
            String::new(),
            info.generation,
        ))
        .unwrap();
        assert!(generation > info.generation);
        let listed = block_on(list_identities()).unwrap();
        let renamed = listed.iter().find(|i| i.addr == info.addr).unwrap();
        assert_eq!(renamed.alias, "after-rename");
        assert_eq!(renamed.generation, generation);
    }

    #[test]
    fn loading_an_identity_does_not_fetch_its_signing_seed() {
        let (info, _) = imported("no-seed-on-load", 23);
        let before = crate::mail_delegate::V1_AFT_PARAMS_CALLS.with(std::cell::Cell::get);
        let loaded = block_on(crate::app::identity_store::prepare(info));
        let after = crate::mail_delegate::V1_AFT_PARAMS_CALLS.with(std::cell::Cell::get);
        assert_eq!(loaded.info.alias, "no-seed-on-load");
        assert_eq!(
            after, before,
            "loading must not ask for the token-generator parameters"
        );
    }

    #[test]
    fn the_delegate_decrypts_what_the_v1_client_encrypts() {
        use ml_kem::kem::KeyExport;
        let (info, keys) = imported("decrypt-interop", 11);
        let ek = keys.ml_kem_dk().encapsulation_key().clone();
        assert_eq!(ek.to_bytes().to_vec(), info.ek.to_vec());
        let ct = crate::inbox::ml_kem_encrypt(&ek, b"hello from v0.2").unwrap();
        let out = block_on(decrypt_v1(
            info.addr,
            vec![ct, b"not a ciphertext".to_vec()],
        ))
        .unwrap();
        assert_eq!(out[0].as_deref(), Ok(&b"hello from v0.2"[..]));
        assert_eq!(
            out[1],
            Err(FailureCode::BadInput),
            "a ciphertext this identity can't read is told apart from a failed call"
        );
    }

    #[test]
    fn the_v1_client_opens_and_verifies_what_the_delegate_seals() {
        let (sender, _) = imported("seal-sender", 21);
        let (recipient, recipient_keys) = imported("seal-recipient", 31);
        let sealed = block_on(seal_v1(
            sender.addr,
            recipient.ek.to_vec(),
            b"hello to v0.2".to_vec(),
        ))
        .unwrap();
        assert_eq!(sealed.sender_vk, sender.vk.to_vec());
        let plain =
            crate::inbox::ml_kem_decrypt(&recipient_keys.ml_kem_dk(), sealed.content.clone())
                .unwrap();
        assert_eq!(plain, b"hello to v0.2");
        assert!(crate::inbox::verify_message_signature(
            &sealed.content,
            &sealed.sender_vk,
            &sealed.signature
        ));
    }

    #[test]
    fn a_merged_write_creates_then_merges() {
        let item = ItemRef {
            kind: ItemKind::GlobalSettings,
            owner: None,
            id: Vec::new(),
        };
        let first = block_on(put_item_merged(item.clone(), |stored| {
            assert!(stored.is_none());
            Some(b"a".to_vec())
        }))
        .unwrap();
        let second = block_on(put_item_merged(item.clone(), |stored| {
            let mut body = stored.unwrap().to_vec();
            body.extend_from_slice(b"b");
            Some(body)
        }))
        .unwrap();
        assert!(second > first);
        let stored = block_on(get_item(item.clone())).unwrap().unwrap();
        assert_eq!(stored.body.as_slice(), b"ab");
        // A merge with nothing to change writes nothing.
        assert_eq!(block_on(put_item_merged(item, |_| None)).unwrap(), None);
    }

    #[test]
    fn a_stale_write_loses_its_compare_and_swap() {
        let item = ItemRef {
            kind: ItemKind::GlobalSettings,
            owner: None,
            id: Vec::new(),
        };
        let generation = block_on(put_item_merged(item.clone(), |_| Some(b"x".to_vec())))
            .unwrap()
            .unwrap();
        let stale = block_on(put_item(
            item,
            b"y".to_vec(),
            Some(generation.saturating_sub(1)),
        ));
        assert!(matches!(
            stale.unwrap_err().code(),
            Some(FailureCode::Conflict { .. })
        ));
    }

    #[test]
    fn removal_hashes_go_out_ascending_and_distinct() {
        assert_eq!(
            removal_order(vec![[3; 32], [1; 32], [3; 32], [2; 32]]),
            vec![[1; 32], [2; 32], [3; 32]]
        );
    }

    #[test]
    fn deleting_an_identity_finishes_and_it_is_gone() {
        let (info, _) = imported("delete-me", 41);
        let mut pages = 0;
        block_on(delete_identity(info.addr, info.generation, |_| pages += 1)).unwrap();
        let ids = block_on(list_identities()).unwrap();
        assert!(ids.iter().all(|i| i.addr != info.addr));
    }

    /// The offline build runs the delegate with `v1-transition`, so the
    /// transitional token-generator parameters are exercised there too: they
    /// must be exactly what the v0.2 client derived from the identity's
    /// signing seed, or token signing would use the wrong generator.
    #[test]
    fn v1_aft_params_are_the_v0_2_token_generator_parameters() {
        let (info, keys) = imported("aft-params", 61);
        let params = block_on(v1_aft_params(info.addr)).unwrap();
        let decoded: freenet_mail_wire_v1::aft::DelegateParameters =
            serde_json::from_slice(&params).unwrap();
        let seed: [u8; 32] = keys.ml_dsa_seed.as_slice().try_into().unwrap();
        assert_eq!(decoded.generator_seed, seed);
        assert_eq!(
            &params[..],
            serde_json::to_vec(&freenet_mail_wire_v1::aft::DelegateParameters::new(seed))
                .unwrap()
                .as_slice(),
            "byte-identical to the v0.2 client's encoding",
        );
    }

    #[test]
    fn importing_twice_never_overwrites() {
        let (first, _) = imported("import-once", 51);
        let (again, already) = block_on(import_identity(
            ImportSource::Seeds {
                dsa: DsaSeed([51; 32]),
                kem: KemSeed([52; 64]),
            },
            ImportKind::UserRestore,
            "a different alias".into(),
            String::new(),
        ))
        .unwrap();
        assert!(already);
        assert_eq!(again.alias, first.alias);
    }
}

#[cfg(test)]
mod secret_bytes_tests {
    #[test]
    fn debug_never_shows_the_bytes() {
        let s = super::SecretBytes(zeroize::Zeroizing::new(vec![0xab; 4]));
        let shown = format!("{s:?}");
        assert_eq!(shown, "SecretBytes(<4 bytes redacted>)");
        assert!(!shown.contains("171") && !shown.to_lowercase().contains("ab"));
    }
}
