//! Sending to a v2 inbox: read it, have the delegate seal the message (it
//! picks the pass, the owner's key or the new-contacts queue), send it, and
//! read the inbox back, since the contract drops a message it does not admit
//! without an error. What happened is said plainly.

use freenet_mail_protocol::inbox_v2::{self as w, InboxDelta, Message};
use freenet_mail_protocol::{
    Addr, MAX_RESEALS, Op, Reply, SealContent, SealedV2, SendAdmission, SendNotice,
};
use serde_bytes::ByteArray;

use super::MailBody;
use super::net::{self, Got};
use crate::mail_delegate::{CallError, call, unexpected};

/// How a send ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// In their inbox (or already drained).
    Delivered {
        admission: SendAdmission,
        notice: Option<SendNotice>,
    },
    /// Not in their inbox, and why.
    NotDelivered(NotDelivered),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum NotDelivered {
    /// Their new-contacts queue is full and this message did not get in.
    QueueFull,
    /// The pass already holds as many messages as it may.
    PassFull,
    /// Their inbox takes strangers' mail only with a Ghost Key proof.
    NeedsGhostKey,
    /// Sealed again and again, and never in the inbox.
    AfterReseals,
    /// No inbox at that address, or no answer: never sent.
    Unreachable(String),
    /// Ghost Key had no key to sign with.
    NoGhostKey,
    /// The user declined Ghost Key's prompt.
    GhostDeclined,
    /// The key that signed is below the tier their inbox requires.
    BelowTier { have: u64, need: u32 },
}

/// The key the compose sheet chose with "Use Ghost Key", and the recipient
/// it was chosen and disclosed for. Read at send, for that recipient only.
pub(crate) static GHOST_CHOICE: dioxus::prelude::GlobalSignal<Option<(Addr, GhostChoice)>> =
    dioxus::prelude::Signal::global(|| None);

/// The Ghost Key to send to `to` with: the one chosen for `to`, never one
/// chosen (and disclosed) for another recipient.
pub(crate) fn ghost_for(choice: Option<(Addr, GhostChoice)>, to: &Addr) -> Option<GhostChoice> {
    choice
        .filter(|(chosen_for, _)| chosen_for == to)
        .map(|(_, g)| g)
}

/// The Ghost Key to prove with, for a RequireGhost recipient.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct GhostChoice {
    pub key: crate::ghostkeys::Key,
    /// The user's default key: signed with `SignWithDefault`.
    pub default: bool,
}

impl Outcome {
    /// What to tell the user, naming the recipient.
    pub(crate) fn text(&self, to: &str) -> String {
        match self {
            Outcome::Delivered {
                notice: Some(SendNotice::PassLapsed),
                ..
            } => format!(
                "Delivered to {to}'s new-contacts queue: the pass you held for them has lapsed. \
                 When they accept you, you get a new one."
            ),
            Outcome::Delivered {
                admission: SendAdmission::Quarantine,
                ..
            } => format!(
                "Delivered to {to}'s new-contacts queue. Once they accept you, your mail goes \
                 straight to their inbox."
            ),
            Outcome::Delivered { .. } => format!("Delivered to {to}."),
            Outcome::NotDelivered(why) => match why {
                NotDelivered::QueueFull => format!(
                    "Not delivered: {to}'s new-contacts queue is full. A Ghost Key, or an invite \
                     from them, gets you in."
                ),
                NotDelivered::PassFull => format!(
                    "Not delivered: {to} has not read your earlier messages yet, and their inbox \
                     holds no more from you until they do."
                ),
                NotDelivered::NeedsGhostKey => format!(
                    "Not delivered: {to} accepts mail from new contacts only with a Ghost Key."
                ),
                NotDelivered::AfterReseals => format!(
                    "Could not be delivered to {to}: the message never landed in their inbox, \
                     although it was sent again {MAX_RESEALS} times."
                ),
                NotDelivered::Unreachable(e) => format!("Not sent to {to}: {e}"),
                NotDelivered::NoGhostKey => format!(
                    "Not sent to {to}: you have no Ghost Key that can sign. Get one with \
                     \"Get a Ghost Key\" and send again."
                ),
                NotDelivered::GhostDeclined => format!(
                    "Not sent to {to}: Ghost Key access was declined. Send again to be asked again."
                ),
                NotDelivered::BelowTier { have, need } => format!(
                    "Not sent to {to}: your Ghost Key is ${have}, and {to} accepts new contacts \
                     only with ${need} or more."
                ),
            },
        }
    }

    pub(crate) fn delivered(&self) -> bool {
        matches!(self, Outcome::Delivered { .. })
    }
}

/// The last send's outcome on this page, shown with the compose button so a
/// test can wait for it.
/// The number counts the page's v2 sends, so the outcome of one is told from
/// the one before.
pub(crate) static LAST_OUTCOME: dioxus::prelude::GlobalSignal<Option<(u32, String, Outcome)>> =
    dioxus::prelude::Signal::global(|| None);

thread_local! {
    static SENDS: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
    /// Tests: when each seal happened (page ms) and its `reseal_at`.
    #[cfg(test)]
    pub(crate) static SEALS: std::cell::RefCell<Vec<(i64, u64)>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// How many times the inbox is read back after one update before the message
/// is sealed again, and the pause between reads.
const READ_BACKS: u32 = 4;
const READ_BACK_PAUSE_MS: u32 = 1_500;

/// Send `body` from `from` to `to`.
#[cfg(all(test, feature = "local-delegate", not(feature = "use-node")))]
pub(crate) async fn send(from: Addr, to: Addr, body: &MailBody) -> Outcome {
    send_content(from, to, SealContent::Mail(body.encode().into())).await
}

/// Send `content` from `from` to `to`: a mail, or a system message that only
/// hands over a pass (accepting a stranger).
pub(crate) async fn send_content(from: Addr, to: Addr, content: SealContent) -> Outcome {
    send_ghost(from, to, content, None).await
}

/// [`send_content`], proving with `ghost` if their inbox requires a Ghost Key
/// and the delegate seals the message for its queue. A proof is attached
/// only then (decisions 2 and 19).
pub(crate) async fn send_ghost(
    from: Addr,
    to: Addr,
    content: SealContent,
    ghost: Option<GhostChoice>,
) -> Outcome {
    send_waiting(from, to, content, ghost, || {}).await
}

/// [`send_ghost`], calling `waiting` once if the message is not in their
/// inbox after the first read-backs and the page keeps looking for it.
async fn send_waiting(
    from: Addr,
    to: Addr,
    content: SealContent,
    mut ghost: Option<GhostChoice>,
    waiting: impl Fn(),
) -> Outcome {
    let mut told = false;
    for reseals in 0..=MAX_RESEALS {
        let state = match net::get(&to, super::contacts::follows(&to)).await {
            Ok(Got::State(s)) => s,
            Ok(Got::Missing) => {
                return Outcome::NotDelivered(NotDelivered::Unreachable(
                    "there is no inbox at this address on the network".into(),
                ));
            }
            Err(e) => return Outcome::NotDelivered(NotDelivered::Unreachable(e)),
        };
        let need = match w::decode::<w::InboxState>(&state).map(|s| s.owner.quarantine) {
            Ok(w::QuarantineMode::RequireGhost { min_usd }) => Some(min_usd.unwrap_or(0)),
            _ => None,
        };
        let ghost_vk = match (&ghost, need) {
            (Some(g), Some(_)) => match crate::ghostkeys::verifying_key(&g.key).await {
                Ok(vk) => Some(vk),
                Err(e) => return refused(e),
            },
            _ => None,
        };
        let sealed = match seal(from, to, state, content.clone(), ghost_vk, reseals).await {
            Ok(s) => s,
            Err(CallError::Failed(f)) if f.detail.contains("requires a Ghost Key") => {
                return Outcome::NotDelivered(NotDelivered::NeedsGhostKey);
            }
            Err(e) => {
                return Outcome::NotDelivered(NotDelivered::Unreachable(format!(
                    "the message could not be sealed: {e}"
                )));
            }
        };
        #[cfg(test)]
        SEALS.with(|s| {
            s.borrow_mut()
                .push((crate::mail_delegate::ops::now_ms(), sealed.reseal_at))
        });
        let mut message: Message = match w::decode(&sealed.message) {
            Ok(m) => m,
            Err(e) => return Outcome::NotDelivered(NotDelivered::Unreachable(e)),
        };
        if let (Some(payload), Some(g), Some(vk)) = (&sealed.ghost_payload, &ghost, ghost_vk) {
            let signed = match crate::ghostkeys::sign(&g.key, g.default, payload.to_vec()).await {
                Ok(s) => s,
                Err(e) => return refused(e),
            };
            if signed.vk != vk {
                // The vault signed with another key (the user picked one at
                // its prompt): the message names its key, so seal it again.
                ghost = Some(GhostChoice {
                    key: crate::ghostkeys::Key {
                        fingerprint: signed.fingerprint,
                        label: None,
                        usd: Some(signed.usd),
                        vk: Some(signed.vk),
                    },
                    default: false,
                });
                continue;
            }
            let need = need.unwrap_or(0);
            if signed.usd < u64::from(need) {
                return Outcome::NotDelivered(NotDelivered::BelowTier {
                    have: signed.usd,
                    need,
                });
            }
            message.admission = w::Admission::Quarantine {
                ghost: Some(signed.proof),
            };
        }
        let delta = w::encode(&InboxDelta {
            messages: [(ByteArray::new(sealed.id.0), message)].into(),
            ..Default::default()
        });
        if let Err(e) = net::update(&to, delta.clone()).await {
            crate::log::error(format!("inbox v2: the update was refused: {e}"), None);
        }
        let delivered = Outcome::Delivered {
            admission: sealed.admission,
            notice: sealed.notice,
        };
        if read_back(&to, &sealed.id.0).await {
            super::contacts::note_send(from, to, sealed.admission, sealed.notice);
            return delivered;
        }
        super::contacts::note_send(from, to, sealed.admission, sealed.notice);
        // Sealing again cannot make room in a full queue or a full pass.
        match sealed.notice {
            Some(SendNotice::QueueFull) => return Outcome::NotDelivered(NotDelivered::QueueFull),
            Some(SendNotice::PassFull) => return Outcome::NotDelivered(NotDelivered::PassFull),
            _ => {}
        }
        // Decision 9: the update may still land, so this message is looked
        // for (and sent again, the same message) until its `reseal_at`, and
        // only then sealed anew. Sealing earlier could land both.
        if !told {
            told = true;
            waiting();
        }
        if wait_for(&to, &sealed.id.0, &delta, sealed.reseal_at).await {
            return delivered;
        }
    }
    Outcome::NotDelivered(NotDelivered::AfterReseals)
}

/// The first pause while waiting for a message, and the longest.
const WAIT_FIRST_MS: u32 = 5_000;
const WAIT_MAX_MS: u32 = 600_000;

/// Look for message `id` in `to`'s inbox until `reseal_at` (seconds), sending
/// `delta` (the same message) again before each look in case an update was
/// lost. Whether it landed.
async fn wait_for(to: &Addr, id: &[u8; 32], delta: &[u8], reseal_at: u64) -> bool {
    let until_ms = i64::try_from(reseal_at.saturating_mul(1_000)).unwrap_or(i64::MAX);
    let mut pause = WAIT_FIRST_MS;
    while crate::mail_delegate::ops::now_ms() < until_ms {
        crate::mail_delegate::ops::pause_ms(pause).await;
        pause = pause.saturating_mul(2).min(WAIT_MAX_MS);
        let _ = net::update(to, delta.to_vec()).await;
        if let Ok(Got::State(bytes)) = net::get(to, super::contacts::follows(to)).await
            && let Ok(state) = w::decode(&bytes)
            && w::delivered(&state, id)
        {
            return true;
        }
    }
    false
}

fn refused(e: crate::ghostkeys::Refusal) -> Outcome {
    use crate::ghostkeys::Refusal;
    Outcome::NotDelivered(match e {
        Refusal::NoKey => NotDelivered::NoGhostKey,
        Refusal::Denied => NotDelivered::GhostDeclined,
        Refusal::Failed(_) => NotDelivered::Unreachable(e.to_string()),
    })
}

async fn seal(
    from: Addr,
    to: Addr,
    state: Vec<u8>,
    content: SealContent,
    ghost_vk: Option<[u8; 32]>,
    reseals: u8,
) -> Result<SealedV2, CallError> {
    match call(Op::SealV2 {
        from,
        to,
        to_state: state.into(),
        content,
        ghost_vk: ghost_vk.map(freenet_mail_protocol::Hash32),
        ui_entropy: super::entropy(),
        reseals,
    })
    .await?
    {
        Reply::SealedV2(s) => Ok(s),
        other => Err(unexpected(&other)),
    }
}

/// Whether message `id` is in `to`'s inbox, held or drained.
async fn read_back(to: &Addr, id: &[u8; 32]) -> bool {
    for attempt in 0..READ_BACKS {
        if attempt > 0 {
            crate::mail_delegate::ops::pause_ms(READ_BACK_PAUSE_MS).await;
        }
        if let Ok(Got::State(bytes)) = net::get(to, super::contacts::follows(to)).await
            && let Ok(state) = w::decode(&bytes)
            && w::delivered(&state, id)
        {
            return true;
        }
    }
    false
}

/// Send `body` and record it in Sent, its delivery state set by the outcome,
/// which is also told to the user.
pub(crate) fn send_and_record(
    from: Addr,
    from_alias: String,
    to: Addr,
    to_name: String,
    to_text: String,
    body: MailBody,
    ghost: Option<GhostChoice>,
) {
    use freenet_mail_wire_v1::local_state::{DeliveryState, SentMessage};
    let seq = SENDS.with(|n| {
        n.set(n.get() + 1);
        n.get()
    });
    let sent_id = crate::local_state::new_sent_id();
    let sent = SentMessage {
        to: to_text,
        recipient_fingerprint: crate::address::display(&to.0)[..8].to_string(),
        recipient_fingerprint_full: crate::address::display(&to.0),
        subject: body.title.clone(),
        body: body.content.clone(),
        sent_at: body.time_ms,
        delivery_state: DeliveryState::Pending,
        thread_id: body.thread_id.clone(),
        in_reply_to: body.in_reply_to.clone(),
        quoted_excerpt: body.quoted_excerpt.clone(),
    };
    crate::local_state::local_save_sent(&from_alias, &sent_id, sent.clone());
    let in_flight = crate::pending_saves::begin();
    let _task = dioxus::core::spawn_forever(async move {
        let _in_flight = in_flight;
        if let Err(e) =
            crate::local_state::save_sent(from_alias.clone(), sent_id.clone(), sent).await
        {
            crate::log::local_state_failure("save sent message", e);
        }
        let content = SealContent::Mail(body.encode().into());
        let waiting_name = to_name.clone();
        let outcome = send_waiting(from, to, content, ghost, move || {
            crate::toast::push_toast_detached(
                format!(
                    "Sent to {waiting_name}, but not in their inbox yet. This page keeps \
                     checking while it is open; Sent shows it as pending until then."
                ),
                crate::toast::ToastLevel::Warning,
            );
        })
        .await;
        let state = if outcome.delivered() {
            DeliveryState::Delivered
        } else {
            DeliveryState::Failed
        };
        let _ = crate::local_state::local_set_sent_delivery_state(&from_alias, &sent_id, state);
        if let Err(e) =
            crate::local_state::set_sent_delivery_state(from_alias, sent_id, state).await
        {
            crate::log::local_state_failure("update delivery state", e);
        }
        let level = match &outcome {
            Outcome::Delivered { notice: None, .. } => crate::toast::ToastLevel::Success,
            Outcome::Delivered { .. } => crate::toast::ToastLevel::Warning,
            Outcome::NotDelivered(_) => crate::toast::ToastLevel::Error,
        };
        let text = outcome.text(&to_name);
        crate::toast::push_toast_detached(text.clone(), level);
        if dioxus::core::Runtime::try_current().is_some() {
            *LAST_OUTCOME.write() = Some((seq, text, outcome));
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// S2: a key chosen (and disclosed) for one recipient is not used for
    /// another the To field names later.
    #[test]
    fn a_ghost_key_chosen_for_one_recipient_is_not_used_for_another() {
        let (a, b) = (Addr([1; 24]), Addr([2; 24]));
        let choice = GhostChoice {
            key: crate::ghostkeys::Key {
                fingerprint: "k".into(),
                label: None,
                usd: Some(5),
                vk: None,
            },
            default: true,
        };
        assert_eq!(
            ghost_for(Some((a, choice.clone())), &a),
            Some(choice.clone())
        );
        assert_eq!(ghost_for(Some((a, choice)), &b), None);
        assert_eq!(ghost_for(None, &a), None);
    }

    #[test]
    fn every_outcome_says_plainly_what_happened() {
        let lapsed = Outcome::Delivered {
            admission: SendAdmission::Quarantine,
            notice: Some(SendNotice::PassLapsed),
        };
        assert!(lapsed.text("bob").contains("lapsed"));
        assert!(lapsed.text("bob").contains("new-contacts queue"));
        assert_eq!(
            Outcome::Delivered {
                admission: SendAdmission::Pass,
                notice: None
            }
            .text("bob"),
            "Delivered to bob."
        );
        let full = Outcome::NotDelivered(NotDelivered::QueueFull).text("bob");
        assert!(full.starts_with("Not delivered") && full.contains("queue is full"));
        assert!(
            Outcome::NotDelivered(NotDelivered::AfterReseals)
                .text("bob")
                .contains("Could not be delivered")
        );
    }
}
