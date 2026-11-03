//! Inbox v2: the owner's records, passes and drain, and the sender's side.
//!
//! **Keys.** The issuer key is Ed25519, derived from the identity's ML-DSA
//! seed under its own domain, so it is never stored and leaves only inside
//! the recovery key's existing material. A pass key is derived from the seed,
//! the contact it was issued for and a random nonce kept in the pass ledger.
//!
//! **What the delegate keeps** (`ItemKind`s the page can read but not write):
//! the inbox record (the highest owner version and `owner_time` it signed, its
//! epoch, filters, and contact to pass id), one ledger entry per issued pass,
//! the passes it holds for other inboxes (never readable by a page) and the
//! drained mail. Every version and time is recorded before the update that
//! carries it is returned, so a lost answer never makes the delegate sign one
//! version twice.
//!
//! **Drain first.** Every owner change drains the state it is given: each
//! message is stored, then tombstoned in the same update as the change. A
//! message is tombstoned only once it is stored (or can never be read by
//! anyone), and any failure before the update is returned leaves every
//! message in the inbox, so a retry stores it again (stores are create-only
//! and idempotent).
//!
//! **Linkability** (decisions 17 and 20). Pass, revocation and usage expiries
//! are whole days, and a contact pass's lifetime is drawn from 335 to 395
//! days, so an expiry does not give the issue time. Renewal falls at a random
//! 40 to 60% of the lifetime, and reissue after an epoch bump at a random
//! point of the 14-day grace, per pass.

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use freenet_mail_protocol::address::address_of;
use freenet_mail_protocol::inbox_v2::{
    self as w, Admission, B16, B24, B32, EnvelopeKind, InboxDelta, InboxState, PassClass,
    QuarantineMode, SealedBody, SystemMsg,
};
use freenet_mail_protocol::{
    Addr, ChangeOutcome, DsaSeed, Entropy, Failure, FailureCode, Hash32, InboxV2Update, ItemKind,
    ItemRef, OwnerChange, PassId, Reply, SealContent, SealedV2, SendAdmission, SendNotice,
    from_cbor, to_cbor,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_bytes::{ByteArray, ByteBuf};

use crate::crypto::{self, Keys, MixRng};
use crate::handlers::{OpResult, put_item, require_identity};
use crate::sealing;
use crate::store::{Space, fail, item_rel};

const DAY: u64 = 86_400;
/// A contact pass's lifetime is drawn from this range (decision 17).
pub const LIFETIME_MIN: u64 = 335 * DAY;
pub const LIFETIME_MAX: u64 = 395 * DAY;
pub const INVITE_LIFETIME: u64 = 14 * DAY;
/// The `owner_time` guard: never past `min(prev + 7 d, node time + 1 d)`.
pub const TIME_STEP_MAX: u64 = 7 * DAY;
pub const TIME_LEAD_MAX: u64 = DAY;
/// A routine epoch bump's grace, over which passes are reissued (decision 18).
pub const EPOCH_GRACE: u64 = 14 * DAY;
/// Live revocations of the current epoch at which it is bumped (decision 23).
pub const BUMP_AT_REVOCATIONS: usize = 2048;
/// Messages one call drains: decrypting and verifying one costs a KEM
/// decapsulation and an ML-DSA check.
pub const DRAIN_BATCH: usize = 32;
/// Drained stranger (quarantine) messages kept per inbox, their stored copies
/// and their tombstones both (decision 21). Past it the earliest drained give
/// way, so strangers can hold at most this many of the 4096 tombstones and
/// never fill this identity's storage. Contact mail is never removed.
pub const STRANGERS_KEPT: usize = 1024;
/// How long a certificate may go unseen in the contact's inbox before the
/// renew job sends it again.
pub const RESEND_AFTER: u64 = 6 * 3600;
/// With no live pass to the contact, a renewal waits this long: it is sent
/// only through the contact's pass, never through quarantine.
pub const NO_PASS_RETRY: u64 = DAY;
/// The clock job moves `owner_time` once it trails the node's clock by this.
pub const CLOCK_LAG: u64 = 12 * 3600;
/// Live invites per identity. They have their own cap so they never fill the
/// pass ledger, which contact passes need.
pub const MAX_INVITES: usize = 1024;
/// Ledger entries one time advance looks at for pruning.
pub const PRUNE_PER_CALL: usize = 64;
/// What a send's `reseal_at` keeps in hand for clock skew and propagation.
pub const RESEAL_MARGIN: u64 = 6 * 3600;

// ── Keys ────────────────────────────────────────────────────────────────────

pub fn issuer_key(dsa: &DsaSeed) -> SigningKey {
    SigningKey::from_bytes(&blake3::derive_key("freenet-mail issuer key v1", &dsa.0))
}

fn pass_id_of(dsa: &DsaSeed, nonce: &B32) -> B16 {
    let mut h = blake3::Hasher::new_derive_key("freenet-mail pass id v1");
    h.update(&dsa.0);
    h.update(nonce.as_slice());
    let mut id = [0u8; 16];
    id.copy_from_slice(&h.finalize().as_bytes()[..16]);
    ByteArray::new(id)
}

fn pass_key(dsa: &DsaSeed, issued_for: Option<&B24>, nonce: &B32) -> SigningKey {
    let mut h = blake3::Hasher::new_derive_key("freenet-mail pass key v1");
    h.update(&dsa.0);
    match issued_for {
        Some(contact) => h.update(&[1]).update(contact.as_slice()),
        None => h.update(&[0]),
    };
    h.update(nonce.as_slice());
    SigningKey::from_bytes(h.finalize().as_bytes())
}

pub(crate) struct Me {
    pub(crate) addr: Addr,
    dsa: DsaSeed,
    keys: Keys,
    issuer: SigningKey,
}

/// Randomness for a run no page started: the host's, mixed with a value
/// only this identity can derive in place of a page's entropy. `context`
/// names what it is for, so a host whose RNG fails repeats randomness only
/// for the same message (the same ciphertext), never for two.
pub(crate) fn background_rng(
    s: &mut Space<'_>,
    me: &Me,
    purpose: &str,
    now: u64,
    context: &[u8],
) -> MixRng {
    let host = s.env.host_random();
    let mut h = blake3::Hasher::new_derive_key("freenet-mail background entropy v1");
    h.update(&me.dsa.0);
    h.update(&now.to_le_bytes());
    h.update(context);
    MixRng::new(purpose, &host, &Entropy(*h.finalize().as_bytes()))
}

/// Randomness for a page's call: the host's, mixed with the page's entropy,
/// which must not be zero (as `seal_v1` requires), and with `bind`, so a host
/// whose RNG fails and a page that repeats its entropy repeat randomness only
/// for the same request.
fn page_rng(
    s: &mut Space<'_>,
    purpose: &str,
    entropy: &Entropy,
    bind: &[u8],
) -> Result<MixRng, Failure> {
    if entropy.0 == [0; 32] {
        return Err(fail(
            FailureCode::BadInput,
            "ui_entropy must be random bytes",
        ));
    }
    let mut h = blake3::Hasher::new_derive_key("freenet-mail page entropy v1");
    h.update(&entropy.0);
    h.update(bind);
    let host = s.env.host_random();
    Ok(MixRng::new(
        purpose,
        &host,
        &Entropy(*h.finalize().as_bytes()),
    ))
}

pub(crate) fn me(s: &Space<'_>, addr: &Addr) -> Result<Me, Failure> {
    let (_, record) = require_identity(s, addr)?;
    Ok(Me {
        addr: *addr,
        keys: Keys::from_seeds(&record.dsa, &record.kem),
        issuer: issuer_key(&record.dsa),
        dsa: record.dsa,
    })
}

// ── Records ─────────────────────────────────────────────────────────────────

/// The owner's bookkeeping for one inbox (`ItemKind::InboxV2`).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct InboxRecord {
    pub v: u8,
    pub ghost_master: B32,
    /// The highest owner version this delegate signed.
    pub max_version: u64,
    /// The highest `owner_time` it signed.
    pub max_owner_time: u64,
    pub pass_epoch: u32,
    pub prev_epoch_until: u64,
    pub quarantine: QuarantineMode,
    /// When the current epoch began (node time), and what spreads the
    /// reissue of each pass over its grace.
    pub epoch_began: u64,
    pub reissue_grace: u64,
    pub reissue_seed: B32,
    /// The contact pass issued to each contact.
    pub issued: BTreeMap<B24, B16>,
    /// When the renew job next looks at each contact's pass.
    pub due: BTreeMap<B24, u64>,
    /// Drained stranger messages, by drain order (decision 21), with their
    /// sender when it could be read.
    pub strangers: BTreeMap<u64, (B32, Option<B24>)>,
    pub stranger_seq: u64,
    /// Stranger messages removed to keep the newest, all told: what the
    /// quarantine view says was dropped.
    pub strangers_dropped: u64,
    /// Senders whose held passes came only from stranger (quarantine) mail,
    /// with the `stranger_seq` they last wrote at. They share the stranger
    /// budget: past `STRANGERS_KEPT` the earliest's passes go, so strangers
    /// never fill the held passes. Writing to one, or a pass from it that is
    /// not stranger mail, makes it a contact.
    #[serde(default)]
    pub stranger_held: BTreeMap<B24, u64>,
    /// The tombstones of the latest owner record this delegate signed or was
    /// given: every owner change is built on them, so a page's older state
    /// never signs a version without what a job tombstoned.
    #[serde(default)]
    pub tombstones: BTreeMap<B32, u64>,
    /// Invites not yet pruned ([`MAX_INVITES`]).
    #[serde(default)]
    pub invites: BTreeSet<B16>,
    /// The last ledger entry the prune looked at.
    #[serde(default)]
    pub pruned_to: Option<B16>,
}

/// A message that carries a pass's newest certificate to its contact.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Pending {
    pub id: B32,
    pub expiry: u64,
    /// Node time it was sealed.
    pub at: u64,
}

/// One issued pass (`ItemKind::PassLedger`, id the pass id).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct LedgerEntry {
    pub v: u8,
    /// Who it was issued for; part of its key, so it never changes.
    pub issued_for: Option<B24>,
    /// Who has written with it (an invite learns this on first use).
    pub contact: Option<B24>,
    pub nonce: B32,
    pub class: PassClass,
    pub epoch: u32,
    pub expiry: u64,
    /// The largest expiry any of its certificates had: what a revocation
    /// signs (decision 23).
    pub max_expiry: u64,
    pub renew_at: u64,
    pub revoked: bool,
    /// Invite mail drained under it, by id: `used` is its size, which only
    /// grows, so no usage entry ever signs a lower `used` (decision 23).
    pub drained: BTreeSet<B32>,
    /// The largest expiry of a certificate seen to reach the contact.
    pub delivered: u64,
    pub pending: Option<Pending>,
    /// The epoch its revocation was signed with.
    #[serde(default)]
    pub revoked_epoch: u32,
    /// Renewal looks in a row that found the contact's inbox missing or
    /// failed: the next waits twice as long, up to a day.
    #[serde(default)]
    pub misses: u32,
}

pub(crate) fn item(kind: ItemKind, owner: &Addr, id: &[u8]) -> ItemRef {
    ItemRef {
        kind,
        owner: Some(*owner),
        id: id.to_vec(),
    }
}

pub(crate) fn load<T: DeserializeOwned>(
    s: &Space<'_>,
    item: &ItemRef,
) -> Result<Option<(u64, T)>, Failure> {
    match s.read(&item_rel(item))? {
        None => Ok(None),
        Some((generation, body)) => from_cbor(&body)
            .map(|v| Some((generation, v)))
            .map_err(|_| {
                fail(
                    FailureCode::Internal,
                    "a stored inbox record does not decode",
                )
            }),
    }
}

/// Write `value`, compare-and-swap against `generation` (0: absent).
pub(crate) fn save<T: Serialize>(
    s: &mut Space<'_>,
    item: ItemRef,
    value: &T,
    generation: u64,
) -> Result<(), Failure> {
    let body = to_cbor(value).map_err(|e| fail(FailureCode::Internal, e))?;
    put_item(s, item, body, Some(generation)).map(|_| ())
}

pub(crate) fn record(s: &Space<'_>, addr: &Addr) -> Result<(u64, InboxRecord), Failure> {
    load(s, &item(ItemKind::InboxV2, addr, &[]))?
        .ok_or_else(|| fail(FailureCode::NotFound, "this identity has no v2 inbox"))
}

fn clock(s: &Space<'_>) -> Result<u64, Failure> {
    s.env
        .now_secs()
        .ok_or_else(|| fail(FailureCode::Busy, "the node gave no time"))
}

/// The `owner_time` to sign: the node's clock, but never past
/// `min(prev + 7 d, now + 1 d)` and never back.
pub fn guarded_time(prev: u64, now: u64) -> u64 {
    let ceiling = prev
        .saturating_add(TIME_STEP_MAX)
        .min(now.saturating_add(TIME_LEAD_MAX));
    now.min(ceiling).max(prev)
}

fn ceil_day(t: u64) -> u64 {
    t.div_ceil(DAY) * DAY
}

fn below(rng: &mut MixRng, n: u64) -> u64 {
    if n == 0 {
        return 0;
    }
    u64::from_le_bytes(rng.bytes()) % n
}

fn sign_owner(
    me: &Me,
    rec: &InboxRecord,
    version: u64,
    tombstones: BTreeMap<B32, u64>,
) -> w::OwnerRecord {
    let mut owner = w::OwnerRecord {
        owner_vk: ByteBuf::from(me.keys.vk_bytes()),
        kem_ek: ByteBuf::from(me.keys.ek_bytes()),
        issuer_vk: ByteArray::new(me.issuer.verifying_key().to_bytes()),
        pass_epoch: rec.pass_epoch,
        prev_epoch_until: rec.prev_epoch_until,
        version,
        quarantine: rec.quarantine,
        tombstones,
        sig: ByteBuf::new(),
    };
    owner.sig = ByteBuf::from(
        me.keys
            .sign_v2(w::OWNER_SIG_CONTEXT, &w::owner_bytes(&me.addr.0, &owner)),
    );
    owner
}

fn sign_time(me: &Me, owner_time: u64) -> w::TimeAttestation {
    let sig = me.issuer.sign(&w::time_bytes(&me.addr.0, owner_time));
    w::TimeAttestation {
        owner_time,
        sig: ByteArray::new(sig.to_bytes()),
    }
}

/// The owner version after `v`. An inbox at the last version can take no
/// owner change: wrapping would sign a version every merge discards.
fn next_version(v: u64) -> Result<u64, Failure> {
    v.checked_add(1).ok_or_else(|| {
        fail(
            FailureCode::Refused,
            "this inbox's owner version is at its limit",
        )
    })
}

/// `bytes` as this identity's own inbox. The owner record and the time must
/// verify, as for anyone's inbox: a page's state is not trusted to carry an
/// unsigned time (which the time guard would never move back from).
pub(crate) fn own_state(me: &Me, bytes: &[u8]) -> Result<InboxState, Failure> {
    let state = their_state(&me.addr, bytes)?;
    if state.owner.owner_vk.as_slice() != me.keys.vk_bytes().as_slice() {
        return Err(fail(FailureCode::BadInput, "not this identity's inbox"));
    }
    // Decision 6: the issuer key never changes, so a record naming another
    // one was not signed here.
    if *state.owner.issuer_vk != me.issuer.verifying_key().to_bytes() {
        return Err(fail(
            FailureCode::Refused,
            "this inbox names another issuer key",
        ));
    }
    Ok(state)
}

/// Start an identity's inbox, or take over one already on the network.
pub fn create_inbox(
    s: &mut Space<'_>,
    addr: &Addr,
    ghost_master: &Hash32,
    existing: Option<&[u8]>,
) -> OpResult {
    let me = me(s, addr)?;
    let rec_item = item(ItemKind::InboxV2, addr, &[]);
    if let Some((generation, _)) = load::<InboxRecord>(s, &rec_item)? {
        return Err(fail(
            FailureCode::Conflict {
                current_gen: generation,
            },
            "this identity has a v2 inbox",
        ));
    }
    let now = clock(s)?;
    let mut rec = InboxRecord {
        v: 1,
        ghost_master: ByteArray::new(ghost_master.0),
        max_version: 1,
        max_owner_time: now,
        pass_epoch: 1,
        prev_epoch_until: 0,
        quarantine: QuarantineMode::Open,
        epoch_began: now,
        reissue_grace: 0,
        reissue_seed: ByteArray::new([0; 32]),
        issued: BTreeMap::new(),
        due: BTreeMap::new(),
        strangers: BTreeMap::new(),
        stranger_seq: 0,
        strangers_dropped: 0,
        stranger_held: BTreeMap::new(),
        tombstones: BTreeMap::new(),
        invites: BTreeSet::new(),
        pruned_to: None,
    };
    let mut state = match existing {
        None => None,
        Some(bytes) => {
            let state = own_state(&me, bytes)?;
            rec.max_version = next_version(state.owner.version)?;
            rec.max_owner_time = guarded_time(state.time.owner_time, now);
            rec.pass_epoch = state.owner.pass_epoch;
            rec.prev_epoch_until = state.owner.prev_epoch_until;
            rec.quarantine = state.owner.quarantine;
            Some(state)
        }
    };
    save(s, rec_item, &rec, 0)?;
    let tombstones = state
        .as_ref()
        .map(|st| st.owner.tombstones.clone())
        .unwrap_or_default();
    let owner = sign_owner(&me, &rec, rec.max_version, tombstones);
    let time = sign_time(&me, rec.max_owner_time);
    let full = match state.take() {
        Some(st) => InboxState { owner, time, ..st },
        None => InboxState {
            owner,
            time,
            revoked: BTreeMap::new(),
            usage: BTreeMap::new(),
            messages: BTreeMap::new(),
        },
    };
    Ok(Reply::InboxV2State(ByteBuf::from(w::encode(&full))))
}

// ── Passes ──────────────────────────────────────────────────────────────────

fn cert_of(me: &Me, pass_id: &B16, e: &LedgerEntry) -> w::PassCert {
    let mut cert = w::PassCert {
        recipient: ByteArray::new(me.addr.0),
        pass_id: *pass_id,
        pass_vk: ByteArray::new(
            pass_key(&me.dsa, e.issued_for.as_ref(), &e.nonce)
                .verifying_key()
                .to_bytes(),
        ),
        epoch: e.epoch,
        expiry: e.expiry,
        class: e.class,
        sig: ByteArray::new([0; 64]),
    };
    cert.sig = ByteArray::new(me.issuer.sign(&w::cert_bytes(&cert)).to_bytes());
    cert
}

fn pass_of(me: &Me, pass_id: &B16, e: &LedgerEntry) -> w::Pass {
    w::Pass {
        cert: cert_of(me, pass_id, e),
        pass_sk: ByteArray::new(pass_key(&me.dsa, e.issued_for.as_ref(), &e.nonce).to_bytes()),
    }
}

/// A new lifetime from `now`: expiry a whole day, renewal at 40 to 60%.
pub fn start_term(e: &mut LedgerEntry, now: u64, rng: &mut MixRng) {
    let lifetime = match e.class {
        PassClass::Contact => LIFETIME_MIN + below(rng, LIFETIME_MAX - LIFETIME_MIN + 1),
        PassClass::Invite { .. } => INVITE_LIFETIME,
    };
    e.expiry = ceil_day(now + lifetime);
    e.max_expiry = e.max_expiry.max(e.expiry);
    e.renew_at = match e.class {
        PassClass::Contact => now + lifetime * 2 / 5 + below(rng, lifetime / 5 + 1),
        PassClass::Invite { .. } => u64::MAX,
    };
}

/// When a pass of an older epoch is reissued: a point of the grace drawn
/// per pass, so reissues do not arrive together.
pub fn reissue_at(rec: &InboxRecord, pass_id: &B16) -> u64 {
    let mut h = blake3::Hasher::new();
    h.update(rec.reissue_seed.as_slice());
    h.update(pass_id.as_slice());
    let r = u64::from_le_bytes(h.finalize().as_bytes()[..8].try_into().expect("8 bytes"));
    rec.epoch_began
        + if rec.reissue_grace == 0 {
            0
        } else {
            r % rec.reissue_grace
        }
}

/// When `e` is next renewed or reissued.
pub fn refresh_at(rec: &InboxRecord, pass_id: &B16, e: &LedgerEntry) -> u64 {
    if e.epoch < rec.pass_epoch {
        e.renew_at.min(reissue_at(rec, pass_id))
    } else {
        e.renew_at
    }
}

/// Renew or reissue `e` if it is due. Returns whether it changed.
fn refresh(
    rec: &InboxRecord,
    pass_id: &B16,
    e: &mut LedgerEntry,
    now: u64,
    rng: &mut MixRng,
) -> bool {
    if e.revoked || now < refresh_at(rec, pass_id, e) {
        return false;
    }
    e.epoch = rec.pass_epoch;
    start_term(e, now, rng);
    true
}

/// When the renew job should next look at `e`: a certificate the contact
/// has not been seen to get is looked at again soon.
pub fn next_look(rec: &InboxRecord, pass_id: &B16, e: &LedgerEntry, now: u64) -> u64 {
    match &e.pending {
        _ if e.expiry <= e.delivered => refresh_at(rec, pass_id, e),
        Some(p) => p.at + RESEND_AFTER,
        None => now,
    }
}

/// Set when the renew job looks at `contact` next (`None`: never).
pub(crate) fn set_due(
    s: &mut Space<'_>,
    owner: &Addr,
    contact: &B24,
    at: Option<u64>,
) -> Result<(), Failure> {
    let (generation, mut rec) = record(s, owner)?;
    let before = rec.due.get(contact).copied();
    if before == at {
        return Ok(());
    }
    match at {
        Some(t) => rec.due.insert(*contact, t),
        None => rec.due.remove(contact),
    };
    save(s, item(ItemKind::InboxV2, owner, &[]), &rec, generation)
}

/// Message `id` carries pass `pass_id`'s current certificate to its
/// contact. Recorded when the contact has not been seen to get one that
/// late (always, with `resend`), so the renew job reads back for it.
pub(crate) fn note_sent(
    s: &mut Space<'_>,
    me: &Me,
    pass_id: &B16,
    id: &[u8; 32],
    now: u64,
    resend: bool,
) -> Result<(), Failure> {
    let at = item(ItemKind::PassLedger, &me.addr, pass_id.as_slice());
    let Some((generation, mut e)) = load::<LedgerEntry>(s, &at)? else {
        return Ok(());
    };
    // A message older than the window can no longer land: a page may never
    // have sent it, so a newer one takes its place.
    let waiting = e
        .pending
        .as_ref()
        .is_some_and(|p| p.expiry >= e.expiry && now < p.at + w::WINDOW_BACK);
    let Some(contact) = e
        .issued_for
        .filter(|_| e.expiry > e.delivered && (resend || !waiting))
    else {
        return Ok(());
    };
    e.pending = Some(Pending {
        id: ByteArray::new(*id),
        expiry: e.expiry,
        at: now,
    });
    save(s, at, &e, generation)?;
    set_due(s, &me.addr, &contact, Some(now + RESEND_AFTER))
}

fn new_entry(
    me: &Me,
    rec: &InboxRecord,
    contact: Option<B24>,
    class: PassClass,
    now: u64,
    rng: &mut MixRng,
) -> (B16, LedgerEntry) {
    let nonce = ByteArray::new(rng.bytes());
    let mut e = LedgerEntry {
        v: 1,
        issued_for: contact,
        contact,
        nonce,
        class,
        epoch: rec.pass_epoch,
        expiry: 0,
        max_expiry: 0,
        renew_at: 0,
        revoked: false,
        drained: BTreeSet::new(),
        delivered: 0,
        pending: None,
        revoked_epoch: 0,
        misses: 0,
    };
    start_term(&mut e, now, rng);
    (pass_id_of(&me.dsa, &nonce), e)
}

/// The contact pass for `contact`: the live one (renewed or reissued if
/// due), or a new one.
fn contact_pass(
    s: &mut Space<'_>,
    me: &Me,
    contact: &Addr,
    now: u64,
    rng: &mut MixRng,
) -> Result<(B16, w::Pass), Failure> {
    let (mut rec_gen, mut rec) = record(s, &me.addr)?;
    let contact = ByteArray::new(contact.0);
    // Writing to a stranger makes it a contact: its passes and its mail
    // leave the stranger budget.
    if promote(&mut rec, &contact) {
        save(s, item(ItemKind::InboxV2, &me.addr, &[]), &rec, rec_gen)?;
        rec_gen = record(s, &me.addr)?.0;
    }
    if let Some(pass_id) = rec.issued.get(&contact).copied() {
        let at = item(ItemKind::PassLedger, &me.addr, pass_id.as_slice());
        if let Some((generation, mut e)) = load::<LedgerEntry>(s, &at)?
            && !e.revoked
            && e.expiry > now
        {
            if refresh(&rec, &pass_id, &mut e, now, rng) {
                save(s, at, &e, generation)?;
            }
            return Ok((pass_id, pass_of(me, &pass_id, &e)));
        }
    }
    let (pass_id, e) = new_entry(me, &rec, Some(contact), PassClass::Contact, now, rng);
    new_ledger_entry(s, me, &mut rec, &pass_id, &e, now)?;
    rec.issued.insert(contact, pass_id);
    rec.due.insert(contact, now);
    save(s, item(ItemKind::InboxV2, &me.addr, &[]), &rec, rec_gen)?;
    Ok((pass_id, pass_of(me, &pass_id, &e)))
}

/// `sender` is a contact now: its passes and its drained mail leave the
/// stranger budget. Returns whether `rec` changed.
fn promote(rec: &mut InboxRecord, sender: &B24) -> bool {
    let before = rec.strangers.len();
    rec.strangers.retain(|_, (_, from)| *from != Some(*sender));
    rec.stranger_held.remove(sender).is_some() || rec.strangers.len() != before
}

/// Write a new ledger entry. A full ledger is pruned first; still full, the
/// cap is the caller's answer.
fn new_ledger_entry(
    s: &mut Space<'_>,
    me: &Me,
    rec: &mut InboxRecord,
    pass_id: &B16,
    e: &LedgerEntry,
    now: u64,
) -> Result<(), Failure> {
    let at = item(ItemKind::PassLedger, &me.addr, pass_id.as_slice());
    match save(s, at.clone(), e, 0) {
        Err(f) if f.code == FailureCode::CapReached => {
            let owner_time = rec.max_owner_time.max(now);
            prune_ledger(s, me, rec, owner_time, None)?;
            save(s, at, e, 0)
        }
        other => other,
    }
}

/// Whether ledger entry `e` can go: its revocation (if any) is pruned from
/// the inbox at `owner_time`, and no certificate of it is admitted there.
/// A contact's current pass stays until it is dead: the renew job reissues
/// it after a bump.
fn prunable(rec: &InboxRecord, pass_id: &B16, e: &LedgerEntry, owner_time: u64) -> bool {
    let oldest = if owner_time < rec.prev_epoch_until {
        rec.pass_epoch.saturating_sub(1)
    } else {
        rec.pass_epoch
    };
    let dead = e.max_expiry.saturating_add(w::WINDOW_BACK) <= owner_time;
    let current = e
        .issued_for
        .is_some_and(|c| rec.issued.get(&c) == Some(pass_id));
    if e.revoked {
        dead || e.revoked_epoch < oldest
    } else {
        dead || (!current && e.epoch < oldest)
    }
}

/// Delete the ledger entries that can go, looking at `limit` of them from
/// where the last prune stopped (all of them with `None`).
fn prune_ledger(
    s: &mut Space<'_>,
    me: &Me,
    rec: &mut InboxRecord,
    owner_time: u64,
    limit: Option<usize>,
) -> Result<(), Failure> {
    let (_, ids) = s.index(&crate::store::index_rel(
        ItemKind::PassLedger,
        Some(&me.addr),
    ))?;
    let ids: Vec<B16> = ids
        .iter()
        .filter_map(|id| Some(ByteArray::new(id.as_slice().try_into().ok()?)))
        .collect();
    let start = rec
        .pruned_to
        .map_or(0, |last| ids.partition_point(|id| *id <= last));
    let n = limit.unwrap_or(ids.len()).min(ids.len());
    for pass_id in ids.iter().cycle().skip(start).take(n) {
        rec.pruned_to = Some(*pass_id);
        let at = item(ItemKind::PassLedger, &me.addr, pass_id.as_slice());
        let Some((generation, e)) = load::<LedgerEntry>(s, &at)? else {
            continue;
        };
        if !prunable(rec, pass_id, &e, owner_time) {
            continue;
        }
        crate::handlers::delete_item(s, at, generation)?;
        rec.invites.remove(pass_id);
        if let Some(c) = e.issued_for
            && rec.issued.get(&c) == Some(pass_id)
        {
            rec.issued.remove(&c);
            rec.due.remove(&c);
        }
    }
    Ok(())
}

pub fn issue_pass(
    s: &mut Space<'_>,
    addr: &Addr,
    contact: Option<Addr>,
    invite: Option<u8>,
    entropy: &Entropy,
) -> OpResult {
    let me = me(s, addr)?;
    let now = clock(s)?;
    let mut rng = page_rng(s, "issue-pass", entropy, &[])?;
    match (contact, invite) {
        (Some(contact), None) => {
            // The page hands this one over itself, so the renew job takes it
            // as delivered and starts with its next renewal.
            let (pass_id, pass) = contact_pass(s, &me, &contact, now, &mut rng)?;
            let at = item(ItemKind::PassLedger, addr, pass_id.as_slice());
            if let Some((generation, mut e)) = load::<LedgerEntry>(s, &at)?
                && e.delivered < e.expiry
            {
                e.delivered = e.expiry;
                e.pending = None;
                let (_, rec) = record(s, addr)?;
                let next = refresh_at(&rec, &pass_id, &e);
                save(s, at, &e, generation)?;
                set_due(s, addr, &ByteArray::new(contact.0), Some(next))?;
            }
            Ok(Reply::PassIssued(pass))
        }
        (_, Some(max_messages)) if max_messages > 0 => {
            let (generation, mut rec) = record(s, addr)?;
            if rec.invites.len() >= MAX_INVITES {
                let owner_time = rec.max_owner_time;
                prune_ledger(s, &me, &mut rec, owner_time.max(now), None)?;
            }
            if rec.invites.len() >= MAX_INVITES {
                return Err(fail(
                    FailureCode::CapReached,
                    "this identity has as many live invites as it may",
                ));
            }
            let issued_for = contact.map(|c| ByteArray::new(c.0));
            let class = PassClass::Invite { max_messages };
            let (pass_id, e) = new_entry(&me, &rec, issued_for, class, now, &mut rng);
            new_ledger_entry(s, &me, &mut rec, &pass_id, &e, now)?;
            rec.invites.insert(pass_id);
            save(s, item(ItemKind::InboxV2, addr, &[]), &rec, generation)?;
            Ok(Reply::PassIssued(pass_of(&me, &pass_id, &e)))
        }
        _ => Err(fail(
            FailureCode::BadInput,
            "a pass is for a contact or an invite of 1 or more messages",
        )),
    }
}

/// Passes held per recipient. A send uses the best one the recipient's
/// state admits, so a revoked or forged one held beside a live one never
/// shadows it; past this many the earliest to arrive goes.
pub const HELD_PER_RECIPIENT: usize = 4;

/// The issuer key of `recipient`'s inbox, if this node holds that inbox.
/// The node's copy is what the contract accepted, so its owner record is
/// genuine.
fn held_issuer(s: &Space<'_>, ghost_master: &B32, recipient: &B24) -> Option<VerifyingKey> {
    #[derive(Deserialize)]
    struct Owner {
        issuer_vk: B32,
    }
    #[derive(Deserialize)]
    struct State {
        owner: Owner,
    }
    let id = crate::inbox_jobs::inbox_id(&Addr(**recipient), ghost_master).ok()?;
    let bytes = s.env.contract_state(&id)?;
    // Only the owner's issuer key is read; the rest is skipped, not built.
    let state: State = ciborium::from_reader(bytes.as_slice()).ok()?;
    VerifyingKey::from_bytes(&state.owner.issuer_vk).ok()
}

/// Keep `pass` to write to its cert's recipient. The same pass is replaced
/// only by a later certificate of it (a renewal); another pass id is kept
/// beside it, since which one the recipient admits is known only from its
/// state, at send time. The certificate is checked against the recipient's
/// issuer key when this node holds its inbox, and at send time always.
fn hold(
    s: &mut Space<'_>,
    owner: &Addr,
    ghost_master: Option<&B32>,
    pass: &w::Pass,
) -> Result<(), Failure> {
    let bad = |why| Err(fail(FailureCode::BadInput, why));
    let pk = SigningKey::from_bytes(&pass.pass_sk)
        .verifying_key()
        .to_bytes();
    if pk != *pass.cert.pass_vk {
        return bad("the pass key does not match its certificate");
    }
    if let Some(issuer) = ghost_master.and_then(|m| held_issuer(s, m, &pass.cert.recipient)) {
        let sig = ed25519_dalek::Signature::from_bytes(&pass.cert.sig);
        if issuer
            .verify_strict(&w::cert_bytes(&pass.cert), &sig)
            .is_err()
        {
            return bad("the pass certificate is not its recipient's");
        }
    }
    let at = item(ItemKind::HeldPass, owner, pass.cert.recipient.as_slice());
    let (generation, mut held) = load::<Vec<w::Pass>>(s, &at)?.unwrap_or_default();
    // A certificate past its expiry and the window admits nothing anywhere.
    let now = s.env.now_secs().unwrap_or(0);
    held.retain(|p| p.cert.expiry.saturating_add(w::WINDOW_BACK) > now);
    match held
        .iter_mut()
        .find(|p| p.cert.pass_id == pass.cert.pass_id)
    {
        Some(p) if (p.cert.epoch, p.cert.expiry) >= (pass.cert.epoch, pass.cert.expiry) => {
            return Ok(());
        }
        Some(p) => *p = pass.clone(),
        None => {
            held.push(pass.clone());
            if held.len() > HELD_PER_RECIPIENT {
                held.remove(0);
            }
        }
    }
    save(s, at, &held, generation)
}

/// Remove every pass held for `recipient`. Best effort, like removing a
/// stored copy: a pass left behind is one more kept.
fn forget_held(s: &mut Space<'_>, owner: &Addr, recipient: &B24) {
    let at = item(ItemKind::HeldPass, owner, recipient.as_slice());
    if let Ok(Some((generation, _))) = s.read(&item_rel(&at)) {
        let _ = crate::handlers::delete_item(s, at, generation);
    }
}

/// The page hands over a pass (an invite, or a contact's pass), which makes
/// its recipient a contact.
pub fn hold_pass(s: &mut Space<'_>, addr: &Addr, pass: &w::Pass) -> OpResult {
    require_identity(s, addr)?;
    let rec = match record(s, addr) {
        Ok(r) => Some(r),
        Err(f) if f.code == FailureCode::NotFound => None,
        Err(f) => return Err(f),
    };
    hold(s, addr, rec.as_ref().map(|(_, r)| &r.ghost_master), pass)?;
    if let Some((generation, mut rec)) = rec
        && promote(&mut rec, &pass.cert.recipient)
    {
        save(s, item(ItemKind::InboxV2, addr, &[]), &rec, generation)?;
    }
    Ok(Reply::Ack { generation: 0 })
}

/// Whether `sender` is a contact: one this identity issued a pass to, or
/// whose pass it holds from mail that was not a stranger's.
fn is_contact(s: &Space<'_>, me: &Me, rec: &InboxRecord, sender: &B24) -> Result<bool, Failure> {
    let at = item(ItemKind::HeldPass, &me.addr, sender.as_slice());
    Ok(rec.issued.contains_key(sender)
        || (!rec.stranger_held.contains_key(sender) && s.read(&item_rel(&at))?.is_some()))
}

/// Remove the held passes of every recipient whose certificates are all
/// past expiry and the window. Looked at only when the held passes are full.
fn prune_held(s: &mut Space<'_>, owner: &Addr) -> Result<usize, Failure> {
    let now = s.env.now_secs().unwrap_or(0);
    let (_, ids) = s.index(&crate::store::index_rel(ItemKind::HeldPass, Some(owner)))?;
    let mut removed = 0;
    for id in ids {
        let at = item(ItemKind::HeldPass, owner, &id);
        if let Some((generation, held)) = load::<Vec<w::Pass>>(s, &at)?
            && held
                .iter()
                .all(|p| p.cert.expiry.saturating_add(w::WINDOW_BACK) <= now)
        {
            crate::handlers::delete_item(s, at, generation)?;
            removed += 1;
        }
    }
    Ok(removed)
}

/// Keep a pass a drained message carried. A stranger's counts against the
/// stranger budget; when the held passes are full, the earliest stranger's
/// go first, then every recipient whose passes are all dead. Still full, the
/// pass is not kept and `Ok(false)` says so: the mail is stored all the same.
fn keep_drained_pass(
    s: &mut Space<'_>,
    me: &Me,
    rec: &mut InboxRecord,
    pass: &w::Pass,
    quarantine: bool,
    contact: bool,
) -> Result<bool, Failure> {
    let recipient = pass.cert.recipient;
    let stranger = quarantine;
    let mut pruned = false;
    loop {
        match hold(s, &me.addr, Some(&rec.ghost_master), pass) {
            Err(f) if f.code == FailureCode::CapReached => {
                let oldest = rec
                    .stranger_held
                    .iter()
                    .filter(|(r, _)| **r != recipient)
                    .min_by_key(|(r, seq)| (**seq, **r))
                    .map(|(r, _)| *r);
                if let Some(old) = oldest {
                    rec.stranger_held.remove(&old);
                    forget_held(s, &me.addr, &old);
                } else if pruned || prune_held(s, &me.addr)? == 0 {
                    return Ok(false);
                } else {
                    pruned = true;
                }
            }
            other => break other?,
        }
    }
    if stranger && !contact {
        rec.stranger_held.insert(recipient, rec.stranger_seq);
        while rec.stranger_held.len() > STRANGERS_KEPT {
            let (old, _) = rec
                .stranger_held
                .iter()
                .min_by_key(|(r, seq)| (**seq, **r))
                .map(|(r, s)| (*r, *s))
                .expect("over the limit");
            rec.stranger_held.remove(&old);
            forget_held(s, &me.addr, &old);
        }
    } else if !stranger {
        rec.stranger_held.remove(&recipient);
    }
    Ok(true)
}

// ── The owner's updates ─────────────────────────────────────────────────────

#[derive(Default)]
struct Drained {
    tombstones: Vec<(B32, u64)>,
    /// Invites whose drained count grew: pass id, used, expiry.
    usage: BTreeMap<B16, (u8, u64)>,
    /// Stranger messages drained, stored or not, with their sender.
    strangers: Vec<(B32, Option<B24>)>,
    /// Earlier stranger messages removed to make room in storage.
    evicted: Vec<B32>,
    /// Messages tried (each a decryption).
    tried: usize,
    stored: u32,
    remaining: u32,
    /// Tried and left in the inbox: not stored (storage full, a failed
    /// write) or a Ghost Key proof only the node's copy can confirm.
    unstored: BTreeSet<B32>,
    /// Passes drained mail carried that the full held passes did not take.
    passes_not_kept: u32,
}

/// Store what `state` holds, up to `limit` messages. Returns the tombstones
/// for what is stored (or unreadable by anyone). A message that cannot be
/// stored now stays in the inbox, untombstoned and counted, and the rest go
/// on: no one message holds the drain.
fn drain(
    s: &mut Space<'_>,
    me: &Me,
    rec: &mut InboxRecord,
    state: &InboxState,
    limit: usize,
    from_node: bool,
) -> Result<Drained, Failure> {
    let pending: Vec<_> = state
        .messages
        .iter()
        // A message a version this delegate signed tombstones is drained
        // already, even if this state is older than that version: storing
        // it again would bring back a copy the user deleted.
        .filter(|(id, _)| {
            !state.owner.tombstones.contains_key(*id) && !rec.tombstones.contains_key(*id)
        })
        .collect();
    let mut out = Drained {
        remaining: pending.len().saturating_sub(limit) as u32,
        ..Drained::default()
    };
    let batch: Vec<_> = pending.into_iter().take(limit).collect();
    let proven = proven_ghosts(s, rec, &me.addr, &batch, from_node);
    for (id, m) in batch {
        out.tried += 1;
        // The stored copy is a function of the message and what the contract
        // admitted: a Ghost Key claim the node's copy cannot confirm waits
        // for a drain that can, rather than being stored without it.
        let claimed = matches!(m.admission, Admission::Quarantine { ghost: Some(_) });
        if claimed && !proven.contains(id) {
            out.unstored.insert(*id);
            continue;
        }
        let mut stranger = matches!(m.admission, Admission::Quarantine { .. }).then_some(None);
        if let Some(opened) = sealing::open(&me.keys, &me.addr.0, id, m) {
            match store_opened(s, me, rec, id, m, opened, proven.contains(id), &mut out) {
                Ok(from) => stranger = from.map(Some),
                Err(_) => {
                    out.unstored.insert(*id);
                    continue;
                }
            }
        }
        if let Some(from) = stranger {
            out.strangers.push((*id, from));
        }
        out.tombstones.push((*id, m.sent_time));
    }
    Ok(out)
}

/// The messages of `batch` whose Ghost Key proof the contract checked. A
/// state from the node's store is what the contract accepted. A page's
/// state is not: a proof counts only if the node holds the same message
/// with the same admission (the delegate does not carry the Ghost Key chain
/// check), and otherwise the message is kept without its Ghost Key.
fn proven_ghosts(
    s: &Space<'_>,
    rec: &InboxRecord,
    addr: &Addr,
    batch: &[(&B32, &w::Message)],
    from_node: bool,
) -> BTreeSet<B32> {
    let claimed = batch
        .iter()
        .filter(|(_, m)| matches!(m.admission, Admission::Quarantine { ghost: Some(_) }));
    if from_node {
        return claimed.map(|(id, _)| **id).collect();
    }
    let node: Option<InboxState> = claimed.clone().next().and_then(|_| {
        let id = crate::inbox_jobs::inbox_id(addr, &rec.ghost_master).ok()?;
        w::decode(&s.env.contract_state(&id)?).ok()
    });
    let Some(node) = node else {
        return BTreeSet::new();
    };
    claimed
        .filter(|(id, m)| node.messages.get(*id) == Some(*m))
        .map(|(id, _)| **id)
        .collect()
}

/// Whether `cert` and `msg_sig` are a pass this identity issued, signing
/// this message: what the contract checked, checked again for a page's
/// state before an invite's use is counted.
fn issued_here(me: &Me, m: &w::Message, cert: &w::PassCert, msg_sig: &w::B64) -> bool {
    let ct_hash = *blake3::hash(&m.ciphertext).as_bytes();
    let genuine_cert = me
        .issuer
        .verifying_key()
        .verify_strict(
            &w::cert_bytes(cert),
            &ed25519_dalek::Signature::from_bytes(&cert.sig),
        )
        .is_ok();
    genuine_cert
        && *cert.recipient == me.addr.0
        && VerifyingKey::from_bytes(&cert.pass_vk).is_ok_and(|k| {
            k.verify_strict(
                &w::admit_bytes(&me.addr.0, m.sent_time, &ct_hash),
                &ed25519_dalek::Signature::from_bytes(msg_sig),
            )
            .is_ok()
        })
}

fn inbound(owner: &Addr, id: &B32) -> ItemRef {
    item(ItemKind::Inbound, owner, id.as_slice())
}

/// Remove the stored copy of drained message `id`, if there is one. Best
/// effort: a copy left behind is only one more message kept.
fn forget_inbound(s: &mut Space<'_>, owner: &Addr, id: &B32) {
    if let Ok(Some((generation, _))) = s.read(&item_rel(&inbound(owner, id))) {
        let _ = crate::handlers::delete_item(s, inbound(owner, id), generation);
    }
}

/// Whether the copy under message `id` reads back with exactly `bytes`. Anything
/// else (no copy, another content, a record that will not read) is not known
/// to be this message stored.
pub(crate) fn counts_as_stored(s: &Space<'_>, owner: &Addr, id: &B32, bytes: &[u8]) -> bool {
    matches!(
        s.read(&item_rel(&inbound(owner, id))),
        Ok(Some((_, stored))) if stored == bytes
    )
}

/// Store `bytes` as drained message `id`, making room by removing the
/// earliest drained stranger messages when storage is full. Contact mail is
/// never removed for it.
fn store_inbound(
    s: &mut Space<'_>,
    me: &Me,
    rec: &mut InboxRecord,
    id: &B32,
    bytes: Vec<u8>,
    out: &mut Drained,
) -> Result<(), Failure> {
    // A removed copy the page had deleted already frees nothing: a few tries.
    for _ in 0..8 {
        // Create-only. A copy already under this id is this message, stored
        // by an earlier drain (the id binds the ciphertext): it counts as
        // stored, whatever path stored it. A Conflict alone proves nothing (the
        // index record's own write can raise one), so the copy is read back:
        // only a readable one with this content counts. A read that finds
        // nothing may be an unreadable record, so that is Unknown: the
        // message stays in the inbox and is tried again.
        match put_item(s, inbound(&me.addr, id), bytes.clone(), None) {
            Err(f) if matches!(f.code, FailureCode::Conflict { .. }) => {
                return if counts_as_stored(s, &me.addr, id, &bytes) {
                    Ok(())
                } else {
                    Err(f)
                };
            }
            Err(f) if f.code == FailureCode::CapReached && !rec.strangers.is_empty() => {
                let (_, (old, _)) = rec.strangers.pop_first().expect("not empty");
                forget_inbound(s, &me.addr, &old);
                out.evicted.push(old);
            }
            other => return other.map(|_| ()),
        }
    }
    Err(fail(
        FailureCode::CapReached,
        "this identity's storage is full",
    ))
}

#[allow(clippy::too_many_arguments)]
fn store_opened(
    s: &mut Space<'_>,
    me: &Me,
    rec: &mut InboxRecord,
    id: &B32,
    m: &w::Message,
    opened: sealing::Opened,
    ghost_proven: bool,
    out: &mut Drained,
) -> Result<Option<B24>, Failure> {
    let body = opened.body;
    let sender = address_of(&opened.sender_vk);
    let from = ByteArray::new(sender.0);
    // Stranger mail is decided by its sender, not its admission: a contact
    // writes through quarantine whenever no pass of ours admits.
    let quarantine = matches!(m.admission, Admission::Quarantine { .. });
    let contact = is_contact(s, me, rec, &from)?;
    // The way back is kept, but a pass the sender got wrong must not hold
    // the message in the inbox for good: only a failure a retry can clear
    // does.
    let grant = body
        .pass_grant
        .as_ref()
        .filter(|g| *g.cert.recipient == sender.0);
    for pass in std::iter::once(&body.reply_pass).chain(grant) {
        match keep_drained_pass(s, me, rec, pass, quarantine, contact) {
            Ok(true) => {}
            Ok(false) => out.passes_not_kept += 1,
            Err(f) if f.code == FailureCode::BadInput => {}
            Err(f) => return Err(f),
        }
    }
    if let EnvelopeKind::Mail(text) = &body.kind {
        // A Ghost Key is the message's only when its proof was checked: in
        // any other admission the sender merely named one.
        let ghost_vk = body.ghost_vk.filter(|_| ghost_proven);
        let inbound = w::InboundMessage {
            id: *id,
            sender_vk: ByteBuf::from(opened.sender_vk.clone()),
            sent_time: m.sent_time,
            admission: sealing::kind_and_tag(&m.admission, body.ghost_vk.as_ref())
                .map_or(0, |(k, _)| k),
            ghost_vk,
            body: text.clone(),
        };
        let bytes = to_cbor(&inbound).map_err(|e| fail(FailureCode::Internal, e))?;
        store_inbound(s, me, rec, id, bytes, out)?;
        out.stored += 1;
    }
    if let Admission::Pass { cert, msg_sig } = &m.admission
        && matches!(cert.class, PassClass::Invite { .. })
        && issued_here(me, m, cert, msg_sig)
    {
        let at = item(ItemKind::PassLedger, &me.addr, cert.pass_id.as_slice());
        if let Some((generation, mut e)) = load::<LedgerEntry>(s, &at)? {
            if e.drained.insert(*id) || e.contact.is_none() {
                e.contact.get_or_insert(ByteArray::new(sender.0));
                save(s, at, &e, generation)?;
            }
            let used = u8::try_from(e.drained.len()).unwrap_or(u8::MAX);
            out.usage.insert(cert.pass_id, (used, e.max_expiry));
        }
    }
    Ok((quarantine && !contact).then_some(from))
}

fn bump(rec: &mut InboxRecord, owner_time: u64, now: u64, emergency: bool, rng: &mut MixRng) {
    rec.pass_epoch += 1;
    // Decision 18. Only a bump ever sets this: raising it alone would revive
    // the previous epoch's passes, revoked ones included (decision 23).
    rec.prev_epoch_until = if emergency {
        0
    } else {
        owner_time.max(now) + EPOCH_GRACE
    };
    rec.epoch_began = now;
    rec.reissue_grace = if emergency { 0 } else { EPOCH_GRACE };
    rec.reissue_seed = ByteArray::new(rng.bytes());
}

/// Revoke a pass: signed with the current epoch and the largest expiry its
/// certificates had (decisions 10, 23). At 2048 live revocations of the
/// epoch it is bumped first; a full set means an emergency bump.
#[allow(clippy::too_many_arguments)]
fn revoke(
    s: &mut Space<'_>,
    me: &Me,
    rec: &mut InboxRecord,
    state: &InboxState,
    pass_id: &PassId,
    now: u64,
    rng: &mut MixRng,
) -> Result<w::Revocation, Failure> {
    let at = item(ItemKind::PassLedger, &me.addr, &pass_id.0);
    let (generation, mut e) = load::<LedgerEntry>(s, &at)?
        .ok_or_else(|| fail(FailureCode::NotFound, "this identity issued no such pass"))?;
    let key = ByteArray::new(pass_id.0);
    let this_epoch = state
        .revoked
        .values()
        .filter(|r| r.epoch == rec.pass_epoch)
        .count();
    if state.revoked.len() >= w::MAX_REVOKED {
        bump(rec, state.time.owner_time, now, true, rng);
    } else if !state.revoked.contains_key(&key) && this_epoch + 1 >= BUMP_AT_REVOCATIONS {
        bump(rec, state.time.owner_time, now, false, rng);
    }
    if !e.revoked || e.revoked_epoch != rec.pass_epoch {
        e.revoked = true;
        e.revoked_epoch = rec.pass_epoch;
        save(s, at, &e, generation)?;
    }
    rec.invites.remove(&key);
    if let Some(contact) = e.issued_for
        && rec.issued.get(&contact) == Some(&key)
    {
        rec.due.remove(&contact);
    }
    rec.issued.retain(|_, id| *id != key);
    let sig = me.issuer.sign(&w::revocation_bytes(
        &me.addr.0,
        &pass_id.0,
        e.max_expiry,
        rec.pass_epoch,
    ));
    Ok(w::Revocation {
        pass_id: key,
        expiry: e.max_expiry,
        epoch: rec.pass_epoch,
        sig: ByteArray::new(sig.to_bytes()),
    })
}

pub fn update_inbox(
    s: &mut Space<'_>,
    addr: &Addr,
    state: &[u8],
    change: OwnerChange,
    entropy: &Entropy,
) -> OpResult {
    let me = me(s, addr)?;
    let state = own_state(&me, state)?;
    let now = clock(s)?;
    let mut rng = page_rng(s, "inbox-v2-update", entropy, &[])?;
    // The page's state: what the contract checked about an admission is
    // checked again before the drain trusts it.
    owner_update(s, &me, &state, change, now, &mut rng, DRAIN_BATCH, false)
        .map(|(u, _)| Reply::InboxV2Update(u))
}

/// Drain up to `limit` messages of `state`, then sign `change` unless it
/// would drop a message still in the inbox. The operation and the jobs both
/// come here. `from_node`: `state` is the node's stored copy, which the
/// contract accepted, rather than a page's. Returns the update and how many
/// messages were tried.
#[allow(clippy::too_many_arguments)]
pub(crate) fn owner_update(
    s: &mut Space<'_>,
    me: &Me,
    state: &InboxState,
    change: OwnerChange,
    now: u64,
    rng: &mut MixRng,
    limit: usize,
    from_node: bool,
) -> Result<(InboxV2Update, usize), Failure> {
    let addr = &me.addr;
    let (rec_gen, mut rec) = record(s, addr)?;
    let drained = drain(s, me, &mut rec, state, limit, from_node)?;

    // Built on the latest owner record this delegate signed or was given:
    // the tombstones of both, so a page's older state cannot sign a version
    // without what a job tombstoned. A tombstone outside the window guards
    // nothing (the filter drops the message by its time).
    let held_time = state.time.owner_time;
    let in_window = |t: &u64| t.saturating_add(w::WINDOW_BACK) >= held_time;
    let mut tombstones: BTreeMap<B32, u64> = rec
        .tombstones
        .iter()
        .chain(&state.owner.tombstones)
        .filter(|(_, t)| in_window(t))
        .map(|(id, t)| (*id, *t))
        .collect();
    if tombstones.len() > w::MAX_TOMBSTONES {
        let mut extra: Vec<(u64, B32)> = tombstones
            .iter()
            .filter(|(id, _)| !state.owner.tombstones.contains_key(*id))
            .map(|(id, t)| (*t, *id))
            .collect();
        extra.sort_unstable();
        let over = tombstones.len() - w::MAX_TOMBSTONES;
        let cut: BTreeSet<B32> = extra.iter().take(over).map(|(_, id)| *id).collect();
        tombstones.retain(|id, _| !cut.contains(id));
    }
    // Decision 21: strangers keep at most STRANGERS_KEPT, the earliest
    // drained giving way (stored copy and tombstone both), so they can never
    // fill the tombstones or this identity's storage.
    let mut dropped = drained.evicted.clone();
    for (id, from) in &drained.strangers {
        rec.stranger_seq += 1;
        rec.strangers.insert(rec.stranger_seq, (*id, *from));
    }
    while rec.strangers.len() > STRANGERS_KEPT {
        let (_, (old, _)) = rec.strangers.pop_first().expect("over the limit");
        forget_inbound(s, addr, &old);
        dropped.push(old);
    }
    for id in &dropped {
        tombstones.remove(id);
    }
    rec.strangers_dropped += dropped.len() as u64;
    // Past the cap (only contacts can get there) a stored message waits in
    // the inbox until older tombstones expire.
    let mut untombstoned = 0;
    for (id, t) in &drained.tombstones {
        if tombstones.len() < w::MAX_TOMBSTONES || tombstones.contains_key(id) {
            tombstones.insert(*id, *t);
        } else {
            untombstoned += 1;
        }
    }

    // Decision 9: nothing is signed that drops a message not yet stored.
    // What is still in the inbox: not tried yet, or tried and not stored.
    let drained_ids: BTreeSet<&B32> = drained.tombstones.iter().map(|(id, _)| id).collect();
    let left: Vec<(&B32, &w::Message)> = state
        .messages
        .iter()
        .filter(|(id, _)| {
            !state.owner.tombstones.contains_key(*id)
                && !rec.tombstones.contains_key(*id)
                && !drained_ids.contains(id)
        })
        .collect();
    // Whether a change that drops what `drops` names may be signed.
    let why = |drops: &dyn Fn(&w::Message) -> bool| {
        let hit: Vec<&B32> = left
            .iter()
            .filter(|(_, m)| drops(m))
            .map(|(id, _)| *id)
            .collect();
        if hit.iter().any(|id| drained.unstored.contains(*id)) {
            ChangeOutcome::WaitsForStorage
        } else if hit.is_empty() {
            ChangeOutcome::Signed
        } else {
            ChangeOutcome::WaitsForDrain
        }
    };
    // The last `owner_time` that keeps `m` admitted: its window, and for a
    // pass of the previous epoch the grace.
    let keeps = |m: &w::Message| {
        let old_epoch =
            matches!(&m.admission, Admission::Pass { cert, .. } if cert.epoch < rec.pass_epoch);
        let grace_end = if old_epoch {
            rec.prev_epoch_until.saturating_sub(1)
        } else {
            u64::MAX
        };
        m.sent_time.saturating_add(w::WINDOW_BACK).min(grace_end)
    };
    let time_bound = left.iter().map(|(_, m)| keeps(m)).min().unwrap_or(u64::MAX);
    let is_pass = |m: &w::Message| matches!(m.admission, Admission::Pass { .. });

    let mut delta = InboxDelta::default();
    let mut new_time = None;
    let epoch = rec.pass_epoch;
    let mut outcome = ChangeOutcome::Signed;
    match change {
        OwnerChange::Drain => {}
        // As far as keeps every message still in the inbox admitted.
        OwnerChange::AdvanceTime => {
            let want = guarded_time(held_time.max(rec.max_owner_time), now);
            let t = want.min(time_bound.max(held_time));
            if t < want {
                outcome = why(&|m| keeps(m) < want);
            }
            if t > held_time {
                new_time = Some(t);
            }
        }
        // Any other change waits for the drain to try every message.
        _ if drained.remaining > 0 => outcome = ChangeOutcome::WaitsForDrain,
        OwnerChange::SetQuarantine(mode) => {
            if mode != rec.quarantine {
                outcome = why(&|m| matches!(m.admission, Admission::Quarantine { .. }));
            }
            if outcome == ChangeOutcome::Signed {
                rec.quarantine = mode;
            }
        }
        OwnerChange::Revoke { pass_id } => {
            let emergency = state.revoked.len() >= w::MAX_REVOKED;
            outcome = why(&|m| {
                (emergency && is_pass(m))
                    || matches!(&m.admission, Admission::Pass { cert, .. } if cert.pass_id.into_array() == pass_id.0)
            });
            if outcome == ChangeOutcome::Signed {
                let r = revoke(s, me, &mut rec, state, &pass_id, now, rng)?;
                delta.revoked.insert(r.pass_id, r);
            }
        }
        OwnerChange::BumpEpoch { emergency } => {
            outcome = why(&|m| emergency && is_pass(m));
            if outcome == ChangeOutcome::Signed {
                bump(&mut rec, held_time, now, emergency, rng);
            }
        }
    }
    if rec.pass_epoch != epoch {
        // Every contact pass is reissued at its own point of the grace.
        let points: Vec<(B24, u64)> = rec
            .issued
            .iter()
            .map(|(contact, pass_id)| (*contact, reissue_at(&rec, pass_id)))
            .collect();
        for (contact, at) in points {
            let due = rec.due.entry(contact).or_insert(at);
            *due = (*due).min(at);
        }
    }
    // A time signed earlier whose update did not land goes out again, unless
    // it would now drop a message still in the inbox.
    if new_time.is_none() && rec.max_owner_time > held_time && rec.max_owner_time <= time_bound {
        new_time = Some(rec.max_owner_time);
    }
    if let Some(t) = new_time {
        // The time goes out with these tombstones, so what it moves out of
        // the window needs none.
        tombstones.retain(|_, sent| sent.saturating_add(w::WINDOW_BACK) >= t);
        // Ledger entries this time leaves with nothing to sign go.
        prune_ledger(s, me, &mut rec, t, Some(PRUNE_PER_CALL))?;
    }
    let o = &state.owner;
    let needs_owner = tombstones != o.tombstones
        || rec.pass_epoch != o.pass_epoch
        || rec.prev_epoch_until != o.prev_epoch_until
        || rec.quarantine != o.quarantine;
    let version = match needs_owner {
        true => Some(next_version(rec.max_version.max(o.version))?),
        false => None,
    };
    if let Some(v) = version {
        rec.max_version = v;
    }
    if let Some(t) = new_time {
        rec.max_owner_time = rec.max_owner_time.max(t);
    }
    rec.tombstones = tombstones.clone();
    // Recorded before anything signed leaves.
    save(s, item(ItemKind::InboxV2, addr, &[]), &rec, rec_gen)?;
    if let Some(v) = version {
        delta.owner = Some(sign_owner(me, &rec, v, tombstones));
        // C1 fix round 1, S2: a usage entry is signed with the
        // owner version that carries its tombstones, and published with it.
        for (pass_id, (used, expiry)) in &drained.usage {
            let bytes = w::usage_bytes(&addr.0, pass_id, *used, *expiry, v);
            delta.usage.insert(
                *pass_id,
                w::PassUsage {
                    pass_id: *pass_id,
                    used: *used,
                    expiry: *expiry,
                    owner_version: v,
                    sig: ByteArray::new(me.issuer.sign(&bytes).to_bytes()),
                },
            );
        }
    }
    delta.time = new_time.map(|t| sign_time(me, t));
    let update = (delta != InboxDelta::default()).then(|| ByteBuf::from(w::encode(&delta)));
    Ok((
        InboxV2Update {
            update,
            drained: drained.stored,
            remaining: drained.remaining,
            full: drained.unstored.len() as u32 + untombstoned,
            strangers_dropped: dropped.len() as u32,
            change: outcome,
            passes_not_kept: drained.passes_not_kept,
        },
        drained.tried,
    ))
}

// ── Sending ─────────────────────────────────────────────────────────────────

/// The recipient's state, with its owner record and time verified: the
/// message is encrypted to the KEM key it names.
pub(crate) fn their_state(to: &Addr, bytes: &[u8]) -> Result<InboxState, Failure> {
    let state: InboxState = w::decode(bytes).map_err(|e| fail(FailureCode::BadInput, e))?;
    let o = &state.owner;
    let issuer = VerifyingKey::from_bytes(&o.issuer_vk).ok();
    let time_ok = issuer.is_some_and(|k| {
        let sig = ed25519_dalek::Signature::from_bytes(&state.time.sig);
        k.verify_strict(&w::time_bytes(&to.0, state.time.owner_time), &sig)
            .is_ok()
    });
    if address_of(&o.owner_vk) != *to
        || !crypto::verify_v2(
            w::OWNER_SIG_CONTEXT,
            &w::owner_bytes(&to.0, o),
            &o.owner_vk,
            &o.sig,
        )
        || !time_ok
    {
        return Err(fail(
            FailureCode::BadInput,
            "not a genuine inbox of this address",
        ));
    }
    Ok(state)
}

/// `now` at hour granularity, moved into the window `owner_time` allows.
pub fn sent_time_for(now: u64, owner_time: u64, forward: u64) -> u64 {
    let hour = w::SENT_TIME_GRANULARITY;
    let lo = owner_time.saturating_sub(w::WINDOW_BACK).div_ceil(hour) * hour;
    let hi = owner_time.saturating_add(forward) / hour * hour;
    (now / hour * hour).clamp(lo, hi.max(lo))
}

/// How many messages `cert` may hold in `state` now, if it admits mail at
/// `sent_time` at all: what the contract checks, from the sender's side.
fn pass_room(state: &InboxState, to: &Addr, cert: &w::PassCert, sent_time: u64) -> Option<usize> {
    let o = &state.owner;
    let oldest = if state.time.owner_time < o.prev_epoch_until {
        o.pass_epoch.saturating_sub(1)
    } else {
        o.pass_epoch
    };
    let issuer = VerifyingKey::from_bytes(&o.issuer_vk).ok()?;
    let sig = ed25519_dalek::Signature::from_bytes(&cert.sig);
    let genuine = issuer.verify_strict(&w::cert_bytes(cert), &sig).is_ok();
    if !genuine
        || *cert.recipient != to.0
        || cert.epoch > o.pass_epoch
        || cert.epoch < oldest
        || sent_time >= cert.expiry
        || state.revoked.contains_key(&cert.pass_id)
        || state.revoked.len() >= w::MAX_REVOKED
    {
        return None;
    }
    let limit = match cert.class {
        PassClass::Contact => w::PER_PASS,
        PassClass::Invite { max_messages } => {
            let used = state.usage.get(&cert.pass_id).map_or(0, |u| u.used);
            usize::from(max_messages.saturating_sub(used)).min(w::PER_INVITE)
        }
    };
    (limit > 0).then_some(limit)
}

/// Whether quarantine message `id` would rank outside the 16 slots.
fn queue_full(state: &InboxState, id: &[u8; 32]) -> bool {
    let salt = blake3::hash(&w::encode(&state.time));
    let rank = |id: &[u8]| {
        *blake3::Hasher::new()
            .update(salt.as_bytes())
            .update(id)
            .finalize()
            .as_bytes()
    };
    let mut ranks: Vec<_> = state
        .messages
        .iter()
        .filter(|(_, m)| matches!(m.admission, Admission::Quarantine { .. }))
        .map(|(id, _)| rank(id.as_slice()))
        .collect();
    ranks.sort_unstable();
    ranks
        .get(w::QUARANTINE_SLOTS - 1)
        .is_some_and(|last| rank(id) > *last)
}

#[allow(clippy::too_many_arguments)]
pub fn seal_v2(
    s: &mut Space<'_>,
    from: &Addr,
    to: &Addr,
    to_state: &[u8],
    content: SealContent,
    ghost_vk: Option<Hash32>,
    entropy: &Entropy,
    reseals: u8,
) -> OpResult {
    if reseals > freenet_mail_protocol::MAX_RESEALS {
        return Err(fail(
            FailureCode::Refused,
            "this message was sealed again and again and never landed: it could not be delivered",
        ));
    }
    let me = me(s, from)?;
    let state = their_state(to, to_state)?;
    let now = clock(s)?;
    let bind = to_cbor(&(to, &content, ghost_vk)).map_err(|e| fail(FailureCode::Internal, e))?;
    let mut rng = page_rng(s, "seal-v2", entropy, &bind)?;
    let (sealed, reply_pass) = seal_to(s, &me, to, &state, content, ghost_vk, now, &mut rng)?;
    // A renewed certificate riding on mail: the renew job reads back for it.
    note_sent(s, &me, &reply_pass, &sealed.id.0, now, false)?;
    Ok(Reply::SealedV2(sealed))
}

/// Seal `content` from `me` to the inbox `to` holding `state`. Returns the
/// sealed message and the id of the reply pass it carries.
#[allow(clippy::too_many_arguments)]
pub(crate) fn seal_to(
    s: &mut Space<'_>,
    me: &Me,
    to: &Addr,
    state: &InboxState,
    content: SealContent,
    ghost_vk: Option<Hash32>,
    now: u64,
    rng: &mut MixRng,
) -> Result<(SealedV2, B16), Failure> {
    let from = &me.addr;
    let owner_time = state.time.owner_time;
    let mut notice = None;

    let held = if to == from {
        Vec::new()
    } else {
        load::<Vec<w::Pass>>(s, &item(ItemKind::HeldPass, from, &to.0))?
            .map(|(_, p)| p)
            .unwrap_or_default()
    };
    let pass_time = sent_time_for(now, owner_time, w::WINDOW_FORWARD);
    // Of the passes held, the one the recipient's state admits: after a
    // revoke and a new pass, the new one, whichever arrived last.
    let any_held = !held.is_empty();
    let pass = held
        .into_iter()
        .filter_map(|p| pass_room(state, to, &p.cert, pass_time).map(|room| (p, room)))
        .max_by_key(|(p, room)| (p.cert.epoch, p.cert.expiry, *room));
    if any_held && pass.is_none() {
        notice = Some(SendNotice::PassLapsed);
    }
    let (admission, sent_time) = match (&pass, to == from) {
        (Some(_), _) => (SendAdmission::Pass, pass_time),
        (None, true) => (SendAdmission::Owner, pass_time),
        (None, false) => (
            SendAdmission::Quarantine,
            sent_time_for(now, owner_time, w::QUARANTINE_FORWARD),
        ),
    };
    let ghost_vk = match (admission, state.owner.quarantine) {
        (SendAdmission::Quarantine, QuarantineMode::RequireGhost { .. }) => Some(ByteArray::new(
            ghost_vk
                .ok_or_else(|| fail(FailureCode::Refused, "this inbox requires a Ghost Key"))?
                .0,
        )),
        // Decision 19: an Open inbox refuses a proof, so none is bound.
        _ => None,
    };
    let (reply_pass_id, reply_pass) = contact_pass(s, me, to, now, rng)?;
    let body = SealedBody {
        kind: match content {
            SealContent::Mail(text) => EnvelopeKind::Mail(text),
            SealContent::PassUpdate => EnvelopeKind::System(SystemMsg::PassUpdate),
        },
        reply_pass: reply_pass.clone(),
        pass_grant: None,
        ghost_vk,
    };
    let (kind, tag) = match (&pass, admission) {
        (Some((p, _)), _) => (w::KIND_PASS, p.cert.pass_id.to_vec()),
        (None, SendAdmission::Owner) => (w::KIND_OWNER, Vec::new()),
        _ => (
            w::KIND_QUARANTINE,
            ghost_vk.map(|k| k.to_vec()).unwrap_or_default(),
        ),
    };
    let ciphertext = sealing::seal(
        &me.keys,
        &to.0,
        &state.owner.kem_ek,
        sent_time,
        kind,
        &tag,
        &body,
        rng,
    )?;
    let ct_hash = *blake3::hash(&ciphertext).as_bytes();
    let id = w::message_id(&to.0, &ct_hash, sent_time, kind, &tag);
    let mut ghost_payload = None;
    let admission_value = match &pass {
        Some((p, room)) => {
            let held_now = state
                .messages
                .values()
                .filter(|m| matches!(&m.admission, Admission::Pass { cert, .. } if cert.pass_id == p.cert.pass_id))
                .count();
            if held_now >= *room {
                notice = Some(SendNotice::PassFull);
            }
            let sig = SigningKey::from_bytes(&p.pass_sk)
                .sign(&w::admit_bytes(&to.0, sent_time, &ct_hash));
            Admission::Pass {
                cert: p.cert.clone(),
                msg_sig: ByteArray::new(sig.to_bytes()),
            }
        }
        None if admission == SendAdmission::Owner => {
            let sig = me
                .issuer
                .sign(&w::owner_msg_bytes(&to.0, sent_time, &ct_hash));
            Admission::Owner {
                sig: ByteArray::new(sig.to_bytes()),
            }
        }
        None => {
            if ghost_vk.is_some() {
                ghost_payload = Some(ByteBuf::from(w::ghost_admit_bytes(
                    &to.0, sent_time, &ct_hash,
                )));
            }
            if queue_full(state, &id) {
                notice = Some(SendNotice::QueueFull);
            }
            Admission::Quarantine { ghost: None }
        }
    };
    let message = w::Message {
        ciphertext: ByteBuf::from(ciphertext),
        sent_time,
        admission: admission_value,
    };
    // Decision 9. The recipient drops this message once its `owner_time`
    // passes `sent_time + WINDOW_BACK`. Its time never runs more than
    // TIME_LEAD_MAX ahead of its clock, which the `owner_time` read shows to
    // be at least `owner_time - now` ahead of ours, so that is not before the
    // point below; RESEAL_MARGIN covers propagation and skew. A message at the
    // edge already is looked at again after the margin, when a fresh read may
    // allow a later `sent_time`, never at once.
    let skew = owner_time.saturating_sub(now);
    let reseal_at = sent_time
        .saturating_add(w::WINDOW_BACK)
        .saturating_sub(TIME_LEAD_MAX + skew + RESEAL_MARGIN)
        .max(now + RESEAL_MARGIN);
    let sealed = SealedV2 {
        message: ByteBuf::from(w::encode(&message)),
        id: Hash32(id),
        sent_time,
        admission,
        ghost_payload,
        notice,
        reseal_at,
    };
    Ok((sealed, reply_pass_id))
}
