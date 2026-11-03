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
    Addr, DsaSeed, Entropy, Failure, FailureCode, Hash32, InboxV2Update, ItemKind, ItemRef,
    OwnerChange, PassId, Reply, SealContent, SealedV2, SendAdmission, SendNotice, from_cbor,
    to_cbor,
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

struct Me {
    addr: Addr,
    dsa: DsaSeed,
    keys: Keys,
    issuer: SigningKey,
}

fn me(s: &Space<'_>, addr: &Addr) -> Result<Me, Failure> {
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
}

fn item(kind: ItemKind, owner: &Addr, id: &[u8]) -> ItemRef {
    ItemRef {
        kind,
        owner: Some(*owner),
        id: id.to_vec(),
    }
}

fn load<T: DeserializeOwned>(s: &Space<'_>, item: &ItemRef) -> Result<Option<(u64, T)>, Failure> {
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
fn save<T: Serialize>(
    s: &mut Space<'_>,
    item: ItemRef,
    value: &T,
    generation: u64,
) -> Result<(), Failure> {
    let body = to_cbor(value).map_err(|e| fail(FailureCode::Internal, e))?;
    put_item(s, item, body, Some(generation)).map(|_| ())
}

fn record(s: &Space<'_>, addr: &Addr) -> Result<(u64, InboxRecord), Failure> {
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
    owner.sig = ByteBuf::from(me.keys.sign(&w::owner_bytes(&me.addr.0, &owner)));
    owner
}

fn sign_time(me: &Me, owner_time: u64) -> w::TimeAttestation {
    let sig = me.issuer.sign(&w::time_bytes(&me.addr.0, owner_time));
    w::TimeAttestation {
        owner_time,
        sig: ByteArray::new(sig.to_bytes()),
    }
}

/// `bytes` as this identity's own inbox.
fn own_state(me: &Me, bytes: &[u8]) -> Result<InboxState, Failure> {
    let state: InboxState = w::decode(bytes).map_err(|e| fail(FailureCode::BadInput, e))?;
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
    };
    let mut state = match existing {
        None => None,
        Some(bytes) => {
            let state = own_state(&me, bytes)?;
            rec.max_version = state.owner.version + 1;
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

/// Renew or reissue `e` if it is due. Returns whether it changed.
fn refresh(
    rec: &InboxRecord,
    pass_id: &B16,
    e: &mut LedgerEntry,
    now: u64,
    rng: &mut MixRng,
) -> bool {
    if e.revoked {
        return false;
    }
    if e.epoch < rec.pass_epoch && now >= reissue_at(rec, pass_id) {
        e.epoch = rec.pass_epoch;
        start_term(e, now, rng);
        return true;
    }
    if now >= e.renew_at {
        start_term(e, now, rng);
        return true;
    }
    false
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
) -> Result<w::Pass, Failure> {
    let (rec_gen, mut rec) = record(s, &me.addr)?;
    let contact = ByteArray::new(contact.0);
    if let Some(pass_id) = rec.issued.get(&contact).copied() {
        let at = item(ItemKind::PassLedger, &me.addr, pass_id.as_slice());
        if let Some((generation, mut e)) = load::<LedgerEntry>(s, &at)?
            && !e.revoked
            && e.expiry > now
        {
            if refresh(&rec, &pass_id, &mut e, now, rng) {
                save(s, at, &e, generation)?;
            }
            return Ok(pass_of(me, &pass_id, &e));
        }
    }
    let (pass_id, e) = new_entry(me, &rec, Some(contact), PassClass::Contact, now, rng);
    save(
        s,
        item(ItemKind::PassLedger, &me.addr, pass_id.as_slice()),
        &e,
        0,
    )?;
    rec.issued.insert(contact, pass_id);
    save(s, item(ItemKind::InboxV2, &me.addr, &[]), &rec, rec_gen)?;
    Ok(pass_of(me, &pass_id, &e))
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
    let host = s.env.host_random();
    let mut rng = MixRng::new("issue-pass", &host, entropy);
    match (contact, invite) {
        (Some(contact), None) => {
            contact_pass(s, &me, &contact, now, &mut rng).map(Reply::PassIssued)
        }
        (_, Some(max_messages)) if max_messages > 0 => {
            let (_, rec) = record(s, addr)?;
            let issued_for = contact.map(|c| ByteArray::new(c.0));
            let class = PassClass::Invite { max_messages };
            let (pass_id, e) = new_entry(&me, &rec, issued_for, class, now, &mut rng);
            save(
                s,
                item(ItemKind::PassLedger, addr, pass_id.as_slice()),
                &e,
                0,
            )?;
            Ok(Reply::PassIssued(pass_of(&me, &pass_id, &e)))
        }
        _ => Err(fail(
            FailureCode::BadInput,
            "a pass is for a contact or an invite of 1 or more messages",
        )),
    }
}

/// Keep `pass` to write to its cert's recipient, unless a later one is held.
fn hold(s: &mut Space<'_>, owner: &Addr, pass: &w::Pass) -> Result<(), Failure> {
    let pk = SigningKey::from_bytes(&pass.pass_sk)
        .verifying_key()
        .to_bytes();
    if pk != *pass.cert.pass_vk {
        return Err(fail(
            FailureCode::BadInput,
            "the pass key does not match its certificate",
        ));
    }
    let at = item(ItemKind::HeldPass, owner, pass.cert.recipient.as_slice());
    let generation = match load::<w::Pass>(s, &at)? {
        Some((_, held))
            if (held.cert.epoch, held.cert.expiry) >= (pass.cert.epoch, pass.cert.expiry) =>
        {
            return Ok(());
        }
        Some((generation, _)) => generation,
        None => 0,
    };
    save(s, at, pass, generation)
}

pub fn hold_pass(s: &mut Space<'_>, addr: &Addr, pass: &w::Pass) -> OpResult {
    require_identity(s, addr)?;
    hold(s, addr, pass).map(|()| Reply::Ack { generation: 0 })
}

// ── The owner's updates ─────────────────────────────────────────────────────

#[derive(Default)]
struct Drained {
    tombstones: Vec<(B32, u64)>,
    /// Invites whose drained count grew: pass id, used, expiry.
    usage: BTreeMap<B16, (u8, u64)>,
    stored: u32,
    remaining: u32,
}

/// Store what `state` holds, up to [`DRAIN_BATCH`] messages. Returns the
/// tombstones for what is stored (or unreadable by anyone). Any failure is
/// returned before a tombstone leaves, so the inbox keeps the message.
fn drain(s: &mut Space<'_>, me: &Me, state: &InboxState) -> Result<Drained, Failure> {
    let pending: Vec<_> = state
        .messages
        .iter()
        .filter(|(id, _)| !state.owner.tombstones.contains_key(*id))
        .collect();
    let mut out = Drained {
        remaining: pending.len().saturating_sub(DRAIN_BATCH) as u32,
        ..Drained::default()
    };
    for (id, m) in pending.into_iter().take(DRAIN_BATCH) {
        if let Some(opened) = sealing::open(&me.keys, &me.addr.0, id, m) {
            store_opened(s, me, id, m, opened, &mut out)?;
        }
        out.tombstones.push((*id, m.sent_time));
    }
    Ok(out)
}

fn store_opened(
    s: &mut Space<'_>,
    me: &Me,
    id: &B32,
    m: &w::Message,
    opened: sealing::Opened,
    out: &mut Drained,
) -> Result<(), Failure> {
    let body = opened.body;
    if let EnvelopeKind::Mail(text) = &body.kind {
        let inbound = w::InboundMessage {
            id: *id,
            sender_vk: ByteBuf::from(opened.sender_vk.clone()),
            sent_time: m.sent_time,
            admission: sealing::kind_and_tag(&m.admission, body.ghost_vk.as_ref())
                .map_or(0, |(k, _)| k),
            ghost_vk: body.ghost_vk,
            body: text.clone(),
        };
        let bytes = to_cbor(&inbound).map_err(|e| fail(FailureCode::Internal, e))?;
        // Create-only; storing the same message again is acknowledged.
        put_item(
            s,
            item(ItemKind::Inbound, &me.addr, id.as_slice()),
            bytes,
            None,
        )?;
        out.stored += 1;
    }
    let sender = address_of(&opened.sender_vk);
    hold(s, &me.addr, &body.reply_pass)?;
    if let Some(grant) = body
        .pass_grant
        .as_ref()
        .filter(|g| *g.cert.recipient == sender.0)
    {
        hold(s, &me.addr, grant)?;
    }
    if let Admission::Pass { cert, .. } = &m.admission
        && matches!(cert.class, PassClass::Invite { .. })
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
    Ok(())
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
    if !e.revoked {
        e.revoked = true;
        save(s, at, &e, generation)?;
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
    let host = s.env.host_random();
    let mut rng = MixRng::new("inbox-v2-update", &host, entropy);
    let drained = drain(s, &me, &state)?;
    // Read after the drain, which may have written nothing to it but must
    // not race a write of its own.
    let (rec_gen, mut rec) = record(s, addr)?;

    // A tombstone outside the window guards nothing: the filter drops the
    // message by its time. Pruned against the joined time already held.
    let held_time = state.time.owner_time;
    let mut tombstones: BTreeMap<B32, u64> = state
        .owner
        .tombstones
        .iter()
        .filter(|(_, t)| t.saturating_add(w::WINDOW_BACK) >= held_time)
        .map(|(id, t)| (*id, *t))
        .collect();
    tombstones.extend(drained.tombstones.iter().copied());
    if tombstones.len() > w::MAX_TOMBSTONES {
        return Err(fail(
            FailureCode::CapReached,
            "the inbox's tombstones are full",
        ));
    }

    let mut delta = InboxDelta::default();
    let mut new_time = None;
    if drained.remaining == 0 {
        match change {
            OwnerChange::Drain => {}
            OwnerChange::AdvanceTime => {
                let t = guarded_time(held_time.max(rec.max_owner_time), now);
                if t > held_time {
                    new_time = Some(t);
                }
            }
            OwnerChange::SetQuarantine(mode) => rec.quarantine = mode,
            OwnerChange::Revoke { pass_id } => {
                let r = revoke(s, &me, &mut rec, &state, &pass_id, now, &mut rng)?;
                delta.revoked.insert(r.pass_id, r);
            }
            OwnerChange::BumpEpoch { emergency } => {
                bump(&mut rec, held_time, now, emergency, &mut rng)
            }
        }
    }
    // A time signed earlier whose update did not land goes out again.
    if new_time.is_none() && rec.max_owner_time > held_time {
        new_time = Some(rec.max_owner_time);
    }
    let o = &state.owner;
    let needs_owner = tombstones != o.tombstones
        || rec.pass_epoch != o.pass_epoch
        || rec.prev_epoch_until != o.prev_epoch_until
        || rec.quarantine != o.quarantine;
    let version = needs_owner.then(|| rec.max_version.max(o.version) + 1);
    if let Some(v) = version {
        rec.max_version = v;
    }
    if let Some(t) = new_time {
        rec.max_owner_time = rec.max_owner_time.max(t);
    }
    // Recorded before anything signed leaves.
    save(s, item(ItemKind::InboxV2, addr, &[]), &rec, rec_gen)?;
    if let Some(v) = version {
        delta.owner = Some(sign_owner(&me, &rec, v, tombstones));
        // C1 fix round 1, S2: a usage entry is signed with the
        // owner version that carries its tombstones, and published with it.
        for (pass_id, (used, expiry)) in &drained.usage {
            let bytes = w::usage_bytes(&me.addr.0, pass_id, *used, *expiry, v);
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
    delta.time = new_time.map(|t| sign_time(&me, t));
    let update = (delta != InboxDelta::default()).then(|| ByteBuf::from(w::encode(&delta)));
    Ok(Reply::InboxV2Update(InboxV2Update {
        update,
        drained: drained.stored,
        remaining: drained.remaining,
    }))
}

// ── Sending ─────────────────────────────────────────────────────────────────

/// The recipient's state, with its owner record and time verified: the
/// message is encrypted to the KEM key it names.
fn their_state(to: &Addr, bytes: &[u8]) -> Result<InboxState, Failure> {
    let state: InboxState = w::decode(bytes).map_err(|e| fail(FailureCode::BadInput, e))?;
    let o = &state.owner;
    let issuer = VerifyingKey::from_bytes(&o.issuer_vk).ok();
    let time_ok = issuer.is_some_and(|k| {
        let sig = ed25519_dalek::Signature::from_bytes(&state.time.sig);
        k.verify_strict(&w::time_bytes(&to.0, state.time.owner_time), &sig)
            .is_ok()
    });
    if address_of(&o.owner_vk) != *to
        || !crypto::verify_v1(&w::owner_bytes(&to.0, o), &o.owner_vk, &o.sig)
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
) -> OpResult {
    let me = me(s, from)?;
    let state = their_state(to, to_state)?;
    let now = clock(s)?;
    let host = s.env.host_random();
    let mut rng = MixRng::new("seal-v2", &host, entropy);
    let owner_time = state.time.owner_time;
    let mut notice = None;

    let held = if to == from {
        None
    } else {
        load::<w::Pass>(s, &item(ItemKind::HeldPass, from, &to.0))?.map(|(_, p)| p)
    };
    let pass_time = sent_time_for(now, owner_time, w::WINDOW_FORWARD);
    let pass = held.and_then(|p| match pass_room(&state, to, &p.cert, pass_time) {
        Some(room) => Some((p, room)),
        None => {
            notice = Some(SendNotice::PassLapsed);
            None
        }
    });
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
    let body = SealedBody {
        kind: match content {
            SealContent::Mail(text) => EnvelopeKind::Mail(text),
            SealContent::PassUpdate => EnvelopeKind::System(SystemMsg::PassUpdate),
        },
        reply_pass: contact_pass(s, &me, to, now, &mut rng)?,
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
        &mut rng,
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
            if queue_full(&state, &id) {
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
    Ok(Reply::SealedV2(SealedV2 {
        message: ByteBuf::from(w::encode(&message)),
        id: Hash32(id),
        sent_time,
        admission,
        ghost_payload,
        notice,
    }))
}
