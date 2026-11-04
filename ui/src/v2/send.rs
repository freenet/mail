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
            },
        }
    }

    pub(crate) fn delivered(&self) -> bool {
        matches!(self, Outcome::Delivered { .. })
    }
}

/// The last send's outcome on this page, shown with the compose button so a
/// test can wait for it.
pub(crate) static LAST_OUTCOME: dioxus::prelude::GlobalSignal<Option<(String, Outcome)>> =
    dioxus::prelude::Signal::global(|| None);

/// How many times the inbox is read back after one update before the message
/// is sealed again, and the pause between reads.
const READ_BACKS: u32 = 4;
const READ_BACK_PAUSE_MS: u32 = 1_500;

/// Send `body` from `from` to `to`.
pub(crate) async fn send(from: Addr, to: Addr, body: &MailBody) -> Outcome {
    send_content(from, to, SealContent::Mail(body.encode().into())).await
}

/// Send `content` from `from` to `to`: a mail, or a system message that only
/// hands over a pass (accepting a stranger).
pub(crate) async fn send_content(from: Addr, to: Addr, content: SealContent) -> Outcome {
    for reseals in 0..=MAX_RESEALS {
        let state = match net::get(&to, true).await {
            Ok(Got::State(s)) => s,
            Ok(Got::Missing) => {
                return Outcome::NotDelivered(NotDelivered::Unreachable(
                    "there is no inbox at this address on the network".into(),
                ));
            }
            Err(e) => return Outcome::NotDelivered(NotDelivered::Unreachable(e)),
        };
        let sealed = match seal(from, to, state, content.clone(), reseals).await {
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
        let message: Message = match w::decode(&sealed.message) {
            Ok(m) => m,
            Err(e) => return Outcome::NotDelivered(NotDelivered::Unreachable(e)),
        };
        let delta = InboxDelta {
            messages: [(ByteArray::new(sealed.id.0), message)].into(),
            ..Default::default()
        };
        if let Err(e) = net::update(&to, w::encode(&delta)).await {
            crate::log::error(format!("inbox v2: the update was refused: {e}"), None);
        }
        if read_back(&to, &sealed.id.0).await {
            super::contacts::note_send(from, to, sealed.admission, sealed.notice);
            return Outcome::Delivered {
                admission: sealed.admission,
                notice: sealed.notice,
            };
        }
        super::contacts::note_send(from, to, sealed.admission, sealed.notice);
        // Sealing again cannot make room in a full queue or a full pass.
        match sealed.notice {
            Some(SendNotice::QueueFull) => return Outcome::NotDelivered(NotDelivered::QueueFull),
            Some(SendNotice::PassFull) => return Outcome::NotDelivered(NotDelivered::PassFull),
            _ => {}
        }
    }
    Outcome::NotDelivered(NotDelivered::AfterReseals)
}

async fn seal(
    from: Addr,
    to: Addr,
    state: Vec<u8>,
    content: SealContent,
    reseals: u8,
) -> Result<SealedV2, CallError> {
    match call(Op::SealV2 {
        from,
        to,
        to_state: state.into(),
        content,
        ghost_vk: None,
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
        if let Ok(Got::State(bytes)) = net::get(to, true).await
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
) {
    use freenet_mail_wire_v1::local_state::{DeliveryState, SentMessage};
    if dioxus::core::Runtime::try_current().is_some() {
        *LAST_OUTCOME.write() = None;
    }
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
        let outcome = send(from, to, &body).await;
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
            *LAST_OUTCOME.write() = Some((text, outcome));
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

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
