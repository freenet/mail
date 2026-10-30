//! Contacts in the mail delegate: one `ItemKind::Contact` item per contact,
//! keyed by the contact's 24-byte address (so an alias can change without
//! moving the record, and an identity and a contact can never share one).
//!
//! The address book (`address_book`) stays the in-memory view the UI reads.
//! Writes update it at once and persist in a task that outlives the view
//! that started it (`spawn_forever`: a scoped task would be cancelled when
//! that view unmounts); a write the delegate refuses or never answers is
//! reported, not silently dropped.

use freenet_mail_protocol::address::address_of;
use freenet_mail_protocol::{ItemKind, ItemRef};
use serde::{Deserialize, Serialize};

use super::address_book::{Contact, StoredContactKeys};
use crate::mail_delegate::{CallError, ops};

/// One contact as stored. `v` lets a later layout be told apart.
#[derive(Serialize, Deserialize)]
struct ContactRecord {
    v: u8,
    local_alias: String,
    description: String,
    keys: StoredContactKeys,
}

/// The item a contact with ML-DSA verifying key `vk` is stored under.
pub(crate) fn item_for(vk: &[u8]) -> ItemRef {
    ItemRef {
        kind: ItemKind::Contact,
        owner: None,
        id: address_of(vk).0.to_vec(),
    }
}

pub(crate) fn encode(contact: &Contact) -> Vec<u8> {
    let record = ContactRecord {
        v: 1,
        local_alias: contact.local_alias.to_string(),
        description: contact.description.clone(),
        keys: StoredContactKeys {
            ml_dsa_vk_bytes: contact.ml_dsa_vk_bytes.clone(),
            ml_kem_ek_bytes: contact.ml_kem_ek_bytes.clone(),
            suggested_alias: contact.suggested_alias.as_deref().map(str::to_string),
            verified: contact.verified,
            required_tier: contact.required_tier,
            max_age_secs: contact.max_age_secs,
            inbox_wasm_hash: contact.inbox_wasm_hash.clone(),
        },
    };
    serde_json::to_vec(&record).expect("a contact record always encodes")
}

/// A stored contact, or `None` for a record this build cannot read, or one
/// whose keys do not match the address it is stored under.
pub(crate) fn decode(item: &ItemRef, body: &[u8]) -> Option<Contact> {
    let record: ContactRecord = serde_json::from_slice(body).ok()?;
    if item_for(&record.keys.ml_dsa_vk_bytes) != *item {
        return None;
    }
    Some(
        record
            .keys
            .into_contact(record.local_alias.into(), record.description),
    )
}

/// Every stored contact.
pub(crate) async fn load_all() -> Result<Vec<Contact>, CallError> {
    let items = ops::list_all_items(ItemKind::Contact, None).await?;
    Ok(items
        .iter()
        .filter_map(|item| {
            let contact = decode(&item.item, &item.body);
            if contact.is_none() {
                crate::log::error("skipping an unreadable stored contact", None);
            }
            contact
        })
        .collect())
}

/// Store `contact`, replacing what is stored for its address.
///
/// Saving a contact is the user asking for it to exist, so it is created
/// even if a deletion lands between this write's read and its put (another
/// tab removing it, or this page's own remove of a contact it is re-adding).
/// That is why this does not use `put_item_merged`, whose "existed, then
/// gone" rule is right for drafts and wrong here.
pub(crate) async fn save(contact: &Contact) -> Result<(), CallError> {
    let item = item_for(&contact.ml_dsa_vk_bytes);
    store_replacing(
        encode(contact),
        || ops::get_item(item.clone()),
        |body, generation| ops::put_item(item.clone(), body, Some(generation)),
    )
    .await
}

/// Write `body`, replacing whatever is stored, retrying a lost
/// compare-and-swap from a fresh read. An item deleted meanwhile reads as
/// absent and is created again (generation 0), never dropped.
async fn store_replacing<G, GF, P, PF>(body: Vec<u8>, mut get: G, mut put: P) -> Result<(), CallError>
where
    G: FnMut() -> GF,
    GF: std::future::Future<Output = Result<Option<freenet_mail_protocol::Item>, CallError>>,
    P: FnMut(Vec<u8>, u64) -> PF,
    PF: std::future::Future<Output = Result<u64, CallError>>,
{
    let mut attempt = 0;
    loop {
        let generation = match get().await? {
            Some(stored) if stored.body.as_slice() == body.as_slice() => return Ok(()),
            Some(stored) => stored.generation,
            None => 0,
        };
        match put(body.clone(), generation).await {
            Ok(_) => return Ok(()),
            Err(e)
                if matches!(
                    e.code(),
                    Some(freenet_mail_protocol::FailureCode::Conflict { .. })
                ) && attempt < ops::MERGE_RETRIES =>
            {
                attempt += 1;
                ops::pause_ms(50 * 2u32.pow(attempt)).await;
            }
            Err(e) => return Err(e),
        }
    }
}

/// Remove the contact with verifying key `vk`. Absent is success.
pub(crate) async fn remove(vk: &[u8]) -> Result<(), CallError> {
    let item = item_for(vk);
    match ops::get_item(item.clone()).await? {
        Some(stored) => ops::delete_item(item, stored.generation).await,
        None => Ok(()),
    }
}

/// Add `contact` to the address book and, only if it is accepted there,
/// persist it. The address book is what refuses a clash (an alias taken by
/// another contact or by one of your identities); persisting first stored a
/// contact the user was told was rejected, which a later load could let
/// claim the alias.
pub(crate) fn accept(contact: Contact) -> Result<(), String> {
    accept_with(contact, save_in_background)
}

fn accept_with(contact: Contact, persist: impl FnOnce(Contact)) -> Result<(), String> {
    super::address_book::insert_contact(contact.clone())?;
    persist(contact);
    Ok(())
}

/// The label a stored contact is shown under when its alias clashes:
/// the alias plus the start of its address, which is what tells the
/// contacts apart.
pub(crate) fn clash_label(contact: &Contact) -> std::rc::Rc<str> {
    let addr = address_of(&contact.ml_dsa_vk_bytes);
    let prefix: String = addr.0[..3].iter().map(|b| format!("{b:02x}")).collect();
    format!("{}~{prefix}", contact.local_alias).into()
}

/// Stored contacts, made safe to load into the address book. A contact is
/// its address; its alias is a label, and stored contacts can share one
/// (stored before the address book's check ran, or carried over from older
/// data), or share one with your own identity (`taken`). Whichever loaded
/// first would take the alias, and mail addressed to it would go there, so
/// none of them keeps the bare alias: each is shown as `alias~<address>`
/// until the user renames it. Returns the contacts, in address order, and
/// the aliases that clashed.
pub(crate) fn disambiguate(
    mut contacts: Vec<Contact>,
    taken: impl Fn(&str) -> bool,
) -> (Vec<Contact>, Vec<String>) {
    contacts.sort_by_key(|c| address_of(&c.ml_dsa_vk_bytes).0);
    let mut uses: std::collections::HashMap<std::rc::Rc<str>, usize> =
        std::collections::HashMap::new();
    for c in &contacts {
        *uses.entry(c.local_alias.clone()).or_default() += 1;
    }
    let mut clashed: Vec<String> = Vec::new();
    // A clash label must not land on a name another contact keeps, on an
    // identity's name, or on a label already given out here: inserting it
    // would then fail and the contact would be dropped.
    let mut assigned: std::collections::HashSet<std::rc::Rc<str>> =
        std::collections::HashSet::new();
    for c in &mut contacts {
        if uses[&c.local_alias] > 1 || taken(&c.local_alias) {
            if !clashed.iter().any(|a| **a == *c.local_alias) {
                clashed.push(c.local_alias.to_string());
            }
            let original = c.local_alias.clone();
            c.local_alias = super::address_book::free_label_by(clash_label(c), |label| {
                uses.contains_key(label) || taken(label) || assigned.contains(label)
            });
            assigned.insert(c.local_alias.clone());
            super::address_book::note_relabelled(&c.local_alias, &original);
        }
    }
    (contacts, clashed)
}

/// A contact write waiting its turn.
enum Write {
    Save(Contact),
    Remove { alias: String },
}

/// Writes for one contact, run strictly in the order the user made them.
/// Independent tasks could interleave: a remove landing after the save that
/// re-added the contact would delete what the user just added back.
struct KeyQueue<T> {
    pending: std::collections::HashMap<Vec<u8>, std::collections::VecDeque<T>>,
}

impl<T> KeyQueue<T> {
    fn new() -> Self {
        Self {
            pending: std::collections::HashMap::new(),
        }
    }

    /// Queue `op` for `key`. True when no writer is running for `key`, so
    /// the caller must start one.
    fn push(&mut self, key: Vec<u8>, op: T) -> bool {
        let queue = self.pending.entry(key).or_default();
        queue.push_back(op);
        queue.len() == 1
    }

    /// The next write for `key` once the current one (at the front) is done,
    /// or `None` when the queue is empty and the writer must stop.
    fn finish_and_next(&mut self, key: &[u8]) -> Option<&T> {
        let queue = self.pending.get_mut(key)?;
        queue.pop_front();
        if queue.is_empty() {
            self.pending.remove(key);
            return None;
        }
        self.pending.get(key).and_then(|q| q.front())
    }

    fn front(&self, key: &[u8]) -> Option<&T> {
        self.pending.get(key).and_then(|q| q.front())
    }
}

thread_local! {
    static WRITES: std::cell::RefCell<KeyQueue<Write>> = std::cell::RefCell::new(KeyQueue::new());
}

fn enqueue(vk: Vec<u8>, write: Write) {
    let start = WRITES.with(|w| w.borrow_mut().push(vk.clone(), write));
    if !start {
        return;
    }
    let _task = dioxus::core::spawn_forever(async move {
        loop {
            // Take what to do without holding the borrow across an await.
            let op = WRITES.with(|w| {
                w.borrow().front(&vk).map(|op| match op {
                    Write::Save(contact) => Write::Save(contact.clone()),
                    Write::Remove { alias } => Write::Remove {
                        alias: alias.clone(),
                    },
                })
            });
            match op {
                Some(Write::Save(contact)) => {
                    if let Err(e) = save(&contact).await {
                        report(
                            &format!("Couldn't save contact {}", contact.local_alias),
                            &e,
                        );
                    }
                }
                Some(Write::Remove { alias }) => {
                    if let Err(e) = remove(&vk).await {
                        report(&format!("Couldn't remove contact {alias}"), &e);
                    }
                }
                None => return,
            }
            if WRITES.with(|w| w.borrow_mut().finish_and_next(&vk).is_none()) {
                return;
            }
        }
    });
}

/// Persist `contact` in the background, after any earlier write for the
/// same contact, reporting a failure.
pub(crate) fn save_in_background(contact: Contact) {
    enqueue(contact.ml_dsa_vk_bytes.clone(), Write::Save(contact));
}

/// Remove a contact in the background, after any earlier write for the same
/// contact, reporting a failure.
pub(crate) fn remove_in_background(alias: String, vk: Vec<u8>) {
    enqueue(vk, Write::Remove { alias });
}

fn report(what: &str, e: &CallError) {
    crate::log::error(format!("{what}: {e}"), None);
    crate::toast::push_toast_detached(report_text(what, e), crate::toast::ToastLevel::Error);
}

/// The user-facing text for a failed contact write: a reached storage limit
/// says so rather than hiding behind a bare "couldn't save".
fn report_text(what: &str, e: &CallError) -> String {
    match e {
        CallError::Unknown(_) => format!("{what}: no answer from your node"),
        CallError::Failed(_) => match crate::mail_delegate::cap_reached_text(&e.to_string()) {
            Some(cap) => format!("{what}: {cap}"),
            None => what.to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contact(vk: Vec<u8>) -> Contact {
        StoredContactKeys {
            ml_dsa_vk_bytes: vk,
            ml_kem_ek_bytes: vec![2; 1184],
            suggested_alias: Some("bob".into()),
            verified: true,
            required_tier: freenet_mail_wire_v1::aft::Tier::Min10,
            max_age_secs: 7,
            inbox_wasm_hash: Some("hash".into()),
        }
        .into_contact("Bob".into(), "from work".into())
    }

    /// Writes for one contact run in the order they were made; a writer is
    /// started only for the first, and stops when the queue drains.
    #[test]
    fn contact_writes_run_in_the_order_they_were_made() {
        let mut q: KeyQueue<&str> = KeyQueue::new();
        let k = b"bob".to_vec();
        assert!(q.push(k.clone(), "remove"), "the first write starts a writer");
        assert!(!q.push(k.clone(), "save"), "a later one waits its turn");
        assert!(q.push(b"carol".to_vec(), "save"), "other contacts are independent");
        assert_eq!(q.front(&k), Some(&"remove"));
        assert_eq!(q.finish_and_next(&k), Some(&"save"));
        assert_eq!(q.finish_and_next(&k), None, "drained: the writer stops");
        assert!(q.push(k.clone(), "save"), "and the next write starts a new one");
    }

    /// A contact deleted between a save's read and its put (another tab's
    /// remove, or this page's remove of a contact it re-adds) is created
    /// again. The earlier merged-write path took "existed, then gone" as a
    /// reason to stop, so the re-added contact was silently not stored.
    #[test]
    fn a_save_racing_a_delete_still_stores_the_contact() {
        use freenet_mail_protocol::{Failure, FailureCode, Item};
        use futures::executor::block_on;
        use std::cell::RefCell;
        let item = item_for(&[7; 1952]);
        let stored: RefCell<Option<Item>> = RefCell::new(Some(Item {
            item: item.clone(),
            body: serde_bytes::ByteBuf::from(b"old".to_vec()),
            generation: 4,
        }));
        let reads = RefCell::new(0);
        let get = || {
            *reads.borrow_mut() += 1;
            let now = stored.borrow().clone();
            // Right after the first read, the contact is deleted.
            if *reads.borrow() == 1 {
                *stored.borrow_mut() = None;
            }
            async move { Ok(now) }
        };
        let put = |body: Vec<u8>, expected: u64| {
            let current = stored.borrow().as_ref().map_or(0, |i| i.generation);
            let result = if current == expected {
                *stored.borrow_mut() = Some(Item {
                    item: item.clone(),
                    body: serde_bytes::ByteBuf::from(body),
                    generation: expected + 1,
                });
                Ok(expected + 1)
            } else {
                Err(CallError::Failed(Failure {
                    code: FailureCode::Conflict { current_gen: current },
                    detail: String::new(),
                }))
            };
            async move { result }
        };
        block_on(store_replacing(b"new".to_vec(), get, put)).unwrap();
        assert_eq!(
            stored.borrow().as_ref().map(|i| i.body.to_vec()),
            Some(b"new".to_vec()),
            "the contact is stored, not dropped"
        );
    }

    /// A contact write refused at the contact cap says the limit was reached
    /// (it used to be a bare "couldn't save"), and other failures stay bare.
    /// Also pins that `CallError`'s text starts a failure with its code,
    /// which `cap_reached_text` reads.
    #[test]
    fn a_full_address_book_is_reported_as_a_reached_limit() {
        use freenet_mail_protocol::{Failure, FailureCode};
        let cap = CallError::Failed(Failure {
            code: FailureCode::CapReached,
            detail: "too many items of this kind".into(),
        });
        assert!(cap.to_string().starts_with("CapReached:"), "{cap}");
        let text = report_text("Couldn't save the contact", &cap);
        assert!(text.contains("storage limit"), "{text}");
        let other = CallError::Failed(Failure {
            code: FailureCode::BadInput,
            detail: "x".into(),
        });
        assert_eq!(
            report_text("Couldn't save the contact", &other),
            "Couldn't save the contact"
        );
    }

    #[test]
    fn a_contact_round_trips_through_its_record() {
        let c = contact(vec![1; 1952]);
        let item = item_for(&c.ml_dsa_vk_bytes);
        let back = decode(&item, &encode(&c)).unwrap();
        assert_eq!(back.local_alias, c.local_alias);
        assert_eq!(back.description, c.description);
        assert_eq!(back.ml_dsa_vk_bytes, c.ml_dsa_vk_bytes);
        assert_eq!(back.ml_kem_ek_bytes, c.ml_kem_ek_bytes);
        assert_eq!(back.suggested_alias, c.suggested_alias);
        assert!(back.verified);
        assert_eq!(back.max_age_secs, 7);
        assert_eq!(back.inbox_wasm_hash.as_deref(), Some("hash"));
    }

    /// A contact the address book refuses is never persisted.
    #[test]
    fn a_rejected_contact_is_not_persisted() {
        let mut persisted = Vec::new();
        let mut first = contact(vec![11; 1952]);
        first.local_alias = "acc-bob".into();
        accept_with(first, |c| persisted.push(c)).unwrap();
        let mut clash = contact(vec![12; 1952]);
        clash.local_alias = "acc-bob".into();
        assert!(accept_with(clash, |c| persisted.push(c)).is_err());
        assert_eq!(persisted.len(), 1, "only the accepted contact is saved");
        assert_eq!(persisted[0].ml_dsa_vk_bytes, vec![11; 1952]);
    }

    #[test]
    fn clashing_stored_contacts_are_all_relabelled_never_routed_by_load_order() {
        let mut a = contact(vec![21; 1952]);
        a.local_alias = "bob".into();
        let mut b = contact(vec![22; 1952]);
        b.local_alias = "bob".into();
        let mut own = contact(vec![23; 1952]);
        own.local_alias = "me".into();
        let mut fine = contact(vec![24; 1952]);
        fine.local_alias = "carol".into();
        for order in [
            vec![a.clone(), b.clone(), own.clone(), fine.clone()],
            vec![fine.clone(), own.clone(), b.clone(), a.clone()],
        ] {
            let (out, clashed) = disambiguate(order, |alias| alias == "me");
            let labels: Vec<String> = out.iter().map(|c| c.local_alias.to_string()).collect();
            assert!(
                !labels.iter().any(|l| l == "bob" || l == "me"),
                "{labels:?}"
            );
            assert!(labels.contains(&"carol".to_string()));
            assert_eq!(clashed, vec!["bob".to_string(), "me".to_string()]);
            // The same contact gets the same label whatever the load order.
            let label_of = |vk: &[u8]| {
                out.iter()
                    .find(|c| c.ml_dsa_vk_bytes == vk)
                    .map(|c| c.local_alias.to_string())
                    .unwrap()
            };
            assert_eq!(label_of(&a.ml_dsa_vk_bytes), clash_label(&a).to_string());
            assert_ne!(label_of(&a.ml_dsa_vk_bytes), label_of(&b.ml_dsa_vk_bytes));
        }
    }

    #[test]
    fn a_record_under_another_address_is_refused() {
        let c = contact(vec![1; 1952]);
        let elsewhere = item_for(&[3; 1952]);
        assert!(decode(&elsewhere, &encode(&c)).is_none());
    }

    #[test]
    fn the_item_id_is_the_contacts_address() {
        let vk = vec![5; 1952];
        let item = item_for(&vk);
        assert_eq!(item.kind, ItemKind::Contact);
        assert_eq!(item.owner, None);
        assert_eq!(item.id, address_of(&vk).0.to_vec());
    }

    #[cfg(all(feature = "local-delegate", not(feature = "use-node")))]
    #[test]
    fn contacts_save_load_and_remove_through_the_delegate() {
        use futures::executor::block_on;
        let c = contact(vec![6; 1952]);
        block_on(save(&c)).unwrap();
        // Saving the same contact again writes nothing new.
        block_on(save(&c)).unwrap();
        let loaded = block_on(load_all()).unwrap();
        assert!(
            loaded
                .iter()
                .any(|l| l.ml_dsa_vk_bytes == c.ml_dsa_vk_bytes)
        );
        block_on(remove(&c.ml_dsa_vk_bytes)).unwrap();
        block_on(remove(&c.ml_dsa_vk_bytes)).unwrap();
        let loaded = block_on(load_all()).unwrap();
        assert!(
            loaded
                .iter()
                .all(|l| l.ml_dsa_vk_bytes != c.ml_dsa_vk_bytes)
        );
    }
}
