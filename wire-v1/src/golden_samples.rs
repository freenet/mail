// Golden wire samples for the v0.2.x message and state formats.
//
// This file is `include!`d in two places, each with the four module names
// `inbox`, `aft`, `identity` and `local_state` in scope plus a
// `dsa_signing_key([u8; 32])` function (ml-dsa's seed API differs between
// rc.8 and 0.1.1):
//   * wire-v1/capture, against the frozen crates the shipped WASM was built
//     from, to produce golden_v1.txt:
//       cargo run --locked --manifest-path wire-v1/capture/Cargo.toml -- golden \
//         > wire-v1/src/golden_v1.txt
//   * this crate's tests, against the copies, to prove they still produce
//     and accept those bytes.
// Every sample is deterministic: fixed seeds, fixed timestamps, and maps with
// at most one entry.

fn golden_sample_bytes() -> Vec<(&'static str, Vec<u8>)> {
    use chrono::{TimeZone, Utc};
    use freenet_stdlib::prelude::{ContractInstanceId, Parameters, SecretsId, StateSummary};
    use ml_dsa::signature::Keypair;
    use std::collections::{BTreeSet, HashMap};

    let ts = Utc.timestamp_opt(1_761_000_000, 0).unwrap();
    let sk = dsa_signing_key([7u8; 32]);
    let vk = sk.verifying_key();
    let ek = vec![0xEE; 16];
    let mut out: Vec<(&'static str, Vec<u8>)> = Vec::new();

    // ---- AFT interface ----
    let tiers = [
        aft::Tier::Min1,
        aft::Tier::Min5,
        aft::Tier::Min10,
        aft::Tier::Min30,
        aft::Tier::Hour1,
        aft::Tier::Hour3,
        aft::Tier::Hour6,
        aft::Tier::Hour12,
        aft::Tier::Day1,
        aft::Tier::Day7,
        aft::Tier::Day15,
        aft::Tier::Day30,
        aft::Tier::Day90,
        aft::Tier::Day180,
        aft::Tier::Day365,
    ];
    out.push(("aft_tiers_json", serde_json::to_vec(&tiers).unwrap()));
    out.push((
        "aft_tiers_display",
        tiers
            .iter()
            .map(|t| t.to_string())
            .collect::<Vec<_>>()
            .join(",")
            .into_bytes(),
    ));
    let hash = [3u8; 32];
    let content = aft::TokenAssignment::signature_content(&ts, aft::Tier::Hour1, &hash);
    out.push(("aft_signature_content", content.to_vec()));
    let assignment = aft::TokenAssignment {
        tier: aft::Tier::Hour1,
        time_slot: ts,
        generator: vk.encode().to_vec(),
        signature: vec![9, 8, 7],
        assignment_hash: hash,
        token_record: ContractInstanceId::new([5; 32]),
    };
    out.push(("aft_assignment_json", serde_json::to_vec(&assignment).unwrap()));
    let record = aft::TokenAllocationRecord::new(HashMap::from([(
        aft::Tier::Hour1,
        vec![assignment.clone()],
    )]));
    out.push(("aft_record_json", record.serialized().unwrap()));
    let summary: StateSummary<'static> = record.summarize().try_into().unwrap();
    out.push(("aft_summary", summary.as_ref().to_vec()));
    let delegate_id = SecretsId::new(b"freenet-mail golden".to_vec());
    let criteria = aft::AllocationCriteria::new(
        aft::Tier::Min10,
        std::time::Duration::from_secs(86_400),
        ContractInstanceId::new([6; 32]),
    )
    .unwrap();
    out.push((
        "aft_msg_request",
        aft::TokenDelegateMessage::RequestNewToken(aft::RequestNewToken {
            request_id: 42,
            delegate_id: delegate_id.clone(),
            criteria: criteria.clone(),
            records: record.clone(),
            assignment_hash: hash,
        })
        .serialize()
        .unwrap(),
    ));
    out.push((
        "aft_msg_allocated",
        aft::TokenDelegateMessage::AllocatedToken {
            delegate_id: delegate_id.clone(),
            assignment: assignment.clone(),
            records: record.clone(),
        }
        .serialize()
        .unwrap(),
    ));
    out.push((
        "aft_msg_denied",
        aft::TokenDelegateMessage::Failure(aft::FailureReason::UserPermissionDenied)
            .serialize()
            .unwrap(),
    ));
    out.push((
        "aft_msg_no_slot",
        aft::TokenDelegateMessage::Failure(aft::FailureReason::NoFreeSlot {
            delegate_id,
            criteria,
        })
        .serialize()
        .unwrap(),
    ));
    let p: Parameters<'static> = aft::TokenDelegateParameters::new(&vk).try_into().unwrap();
    out.push(("aft_record_params", p.as_ref().to_vec()));
    let p: Parameters<'static> = aft::DelegateParameters::new([7; 32]).try_into().unwrap();
    out.push(("aft_generator_params", p.as_ref().to_vec()));

    // ---- Inbox contract ----
    let p: Parameters<'static> = inbox::InboxParams::from_verifying_key(&vk)
        .try_into()
        .unwrap();
    out.push(("inbox_params", p.as_ref().to_vec()));
    let settings = inbox::InboxSettings {
        minimum_tier: aft::Tier::Day1,
        max_age_secs: 3600,
        allow_verified_skip_token: true,
        verified_senders: BTreeSet::from([vec![1, 2, 3]]),
        private: vec![4, 5, 6],
    };
    out.push(("inbox_settings", serde_json::to_vec(&settings).unwrap()));
    out.push((
        "inbox_settings_default",
        serde_json::to_vec(&inbox::InboxSettings::default()).unwrap(),
    ));
    out.push(("inbox_sign_payload", inbox::sign_payload(&ek, &settings, ts)));
    let sig = inbox::Inbox::sign(&sk, &ek, &settings, ts);
    out.push(("inbox_settings_signature", sig.to_vec()));
    let message = inbox::Message {
        content: vec![1; 8],
        token_assignment: assignment,
        sender_vk: vec![2; 4],
        signature: vec![3; 4],
    };
    out.push((
        "inbox_update_add",
        serde_json::to_vec(&inbox::UpdateInbox::AddMessages {
            messages: vec![message.clone()],
        })
        .unwrap(),
    ));
    out.push((
        "inbox_update_remove",
        serde_json::to_vec(&inbox::UpdateInbox::RemoveMessages {
            signature: vec![7; 5].into_boxed_slice(),
            ids: vec![hash],
        })
        .unwrap(),
    ));
    out.push((
        "inbox_update_settings",
        serde_json::to_vec(&inbox::UpdateInbox::ModifySettings {
            inbox_signature: sig,
            settings: settings.clone(),
            last_update: ts,
        })
        .unwrap(),
    ));
    let state: inbox::Inbox = serde_json::from_value(serde_json::json!({
        "messages": [serde_json::to_value(&message).unwrap()],
        "last_update": ts,
        "settings": serde_json::to_value(&settings).unwrap(),
        "owner_ek_bytes": ek,
        "inbox_signature": [1, 2, 3],
    }))
    .unwrap();
    out.push(("inbox_state", state.serialize().unwrap()));

    // ---- identity-management delegate ----
    use identity::{EntryKind, IdentityMsg};
    let msgs = [
        IdentityMsg::Init,
        IdentityMsg::CreateIdentity {
            alias: "alice".into(),
            key: vec![1, 2],
            extra: Some("extra".into()),
            kind: Some(EntryKind::Contact),
        },
        IdentityMsg::DeleteIdentity {
            alias: "alice".into(),
        },
        IdentityMsg::UpdateInboxWasmHash {
            alias: "alice".into(),
            wasm_hash: "h1".into(),
        },
        IdentityMsg::SetPendingMigrationFrom {
            alias: "alice".into(),
            prior_hash: Some("h0".into()),
        },
        IdentityMsg::UpdateAftRecordWasmHash {
            alias: "alice".into(),
            wasm_hash: "h2".into(),
        },
        IdentityMsg::SetPendingAftMigrationFrom {
            alias: "alice".into(),
            prior_hash: None,
        },
        IdentityMsg::GetIdentities,
    ];
    let names = [
        "identity_msg_init",
        "identity_msg_create",
        "identity_msg_delete",
        "identity_msg_inbox_hash",
        "identity_msg_pending",
        "identity_msg_aft_hash",
        "identity_msg_aft_pending",
        "identity_msg_get",
    ];
    for (name, msg) in names.into_iter().zip(msgs.iter()) {
        out.push((name, Vec::<u8>::try_from(msg).unwrap()));
    }
    let ids = identity::IdentityManagement::try_from(
        br#"{"identities":{"alice":{"key":[1,2],"extra":"x","kind":"contact","inbox_wasm_hash":"a","pending_migration_from":"b","aft_record_wasm_hash":"c","pending_aft_migration_from":"d"}}}"#
            .as_slice(),
    )
    .unwrap();
    out.push(("identity_state", serde_json::to_vec(&ids).unwrap()));
    let ids = identity::IdentityManagement::try_from(
        br#"{"identities":{"bob":{"key":[3],"extra":null}}}"#.as_slice(),
    )
    .unwrap();
    out.push(("identity_state_legacy", serde_json::to_vec(&ids).unwrap()));

    // ---- mail-local-state delegate ----
    use local_state as ls;
    let draft = ls::Draft {
        to: "bob".into(),
        subject: "s".into(),
        body: "b".into(),
        updated_at: 5,
        thread_id: Some("t".into()),
        in_reply_to: Some("r".into()),
        quoted_excerpt: Some("q".into()),
    };
    let kept = ls::KeptMessage {
        from: "bob".into(),
        title: "t".into(),
        content: "c".into(),
        kept_at: 6,
        sent_at: Some(4),
        sender_vk: vec![1],
        signature_valid: true,
    };
    let sent = ls::SentMessage {
        to: "bob".into(),
        recipient_fingerprint: "f".into(),
        recipient_fingerprint_full: "ff".into(),
        subject: "s".into(),
        body: "b".into(),
        sent_at: 7,
        delivery_state: ls::DeliveryState::Failed,
        thread_id: None,
        in_reply_to: Some("r".into()),
        quoted_excerpt: None,
    };
    let archived = ls::ArchivedMessage {
        from: "bob".into(),
        title: "t".into(),
        content: "c".into(),
        archived_at: 8,
        thread_id: Some("t".into()),
        in_reply_to: None,
        quoted_excerpt: Some("q".into()),
    };
    let mut identity_settings = ls::IdentitySettings {
        display_name: "Alice".into(),
        signature: "--a".into(),
        auto_sign: false,
        last_backup_at: Some(9),
        ..Default::default()
    };
    identity_settings.aft.allow_verified_skip_token = true;
    identity_settings
        .aft
        .permission_decisions
        .insert("app".into(), ls::PermissionDecision::Deny);
    identity_settings.privacy.read_receipts = true;
    let mut global = ls::GlobalSettings::default();
    global.appearance.theme = ls::Theme::Dark;
    global.appearance.density = ls::Density::Compact;
    global.appearance.font_size = ls::FontSize::Larger;
    global.inbox.thread_view = ls::ThreadView::Compact;
    global.inbox.quarantine_unknown = true;
    global.advanced.custom_relay_url = "ws://x".into();
    let alice = || "alice".to_string();
    let msgs = [
        ("ls_msg_init", ls::LocalStateMsg::Init),
        (
            "ls_msg_save_draft",
            ls::LocalStateMsg::SaveDraft {
                alias: alice(),
                id: "d1".into(),
                draft: draft.clone(),
            },
        ),
        (
            "ls_msg_delete_draft",
            ls::LocalStateMsg::DeleteDraft {
                alias: alice(),
                id: "d1".into(),
            },
        ),
        (
            "ls_msg_mark_read",
            ls::LocalStateMsg::MarkRead {
                alias: alice(),
                msg_id: 3,
                kept: kept.clone(),
            },
        ),
        (
            "ls_msg_save_sent",
            ls::LocalStateMsg::SaveSent {
                alias: alice(),
                id: "s1".into(),
                sent: sent.clone(),
            },
        ),
        (
            "ls_msg_delete_sent",
            ls::LocalStateMsg::DeleteSent {
                alias: alice(),
                id: "s1".into(),
            },
        ),
        (
            "ls_msg_delivery",
            ls::LocalStateMsg::SetSentDeliveryState {
                alias: alice(),
                id: "s1".into(),
                state: ls::DeliveryState::Delivered,
            },
        ),
        (
            "ls_msg_archive",
            ls::LocalStateMsg::ArchiveMessage {
                alias: alice(),
                msg_id: 4,
                archived: archived.clone(),
            },
        ),
        (
            "ls_msg_unarchive",
            ls::LocalStateMsg::UnarchiveMessage {
                alias: alice(),
                msg_id: 4,
            },
        ),
        (
            "ls_msg_delete",
            ls::LocalStateMsg::DeleteMessage {
                alias: alice(),
                msg_id: 5,
            },
        ),
        (
            "ls_msg_identity_settings",
            ls::LocalStateMsg::SetIdentitySettings {
                alias: alice(),
                settings: identity_settings.clone(),
            },
        ),
        (
            "ls_msg_global_settings",
            ls::LocalStateMsg::SetGlobalSettings {
                settings: global.clone(),
            },
        ),
        ("ls_msg_get_all", ls::LocalStateMsg::GetAll),
    ];
    for (name, msg) in &msgs {
        out.push((*name, Vec::<u8>::try_from(msg).unwrap()));
    }
    let mut state = ls::LocalState::default();
    *state.global_settings_mut() = global;
    state.aliases_mut().insert(
        alice(),
        ls::AliasState {
            drafts: HashMap::from([("d1".to_string(), draft)]),
            read: vec![1, 2],
            kept: HashMap::from([("3".to_string(), kept)]),
            sent: HashMap::from([("s1".to_string(), sent)]),
            archived: HashMap::from([("4".to_string(), archived)]),
            deleted: vec![5],
            settings: identity_settings,
        },
    );
    out.push(("ls_state", serde_json::to_vec(&state).unwrap()));
    let state = ls::LocalState::try_from(br#"{"aliases":{"bob":{}}}"#.as_slice()).unwrap();
    out.push(("ls_state_sparse", serde_json::to_vec(&state).unwrap()));

    // Every variant of every serde-renamed enum, so a rename cannot hide
    // behind a variant no other sample happens to use.
    use ls::{Density, DeliveryState, FontSize, PermissionDecision, Theme, ThreadView};
    let enums: [(&'static str, Vec<u8>); 7] = [
        (
            "ls_enum_delivery_state",
            serde_json::to_vec(&[
                DeliveryState::Pending,
                DeliveryState::Delivered,
                DeliveryState::Failed,
            ])
            .unwrap(),
        ),
        (
            "ls_enum_theme",
            serde_json::to_vec(&[Theme::System, Theme::Light, Theme::Dark]).unwrap(),
        ),
        (
            "ls_enum_density",
            serde_json::to_vec(&[Density::Comfortable, Density::Compact]).unwrap(),
        ),
        (
            "ls_enum_font_size",
            serde_json::to_vec(&[
                FontSize::Small,
                FontSize::Default,
                FontSize::Large,
                FontSize::Larger,
            ])
            .unwrap(),
        ),
        (
            "ls_enum_thread_view",
            serde_json::to_vec(&[ThreadView::Nested, ThreadView::Compact]).unwrap(),
        ),
        (
            "ls_enum_permission",
            serde_json::to_vec(&[PermissionDecision::Accept, PermissionDecision::Deny]).unwrap(),
        ),
        (
            "identity_enum_kind",
            serde_json::to_vec(&[EntryKind::Identity, EntryKind::Contact]).unwrap(),
        ),
    ];
    out.extend(enums);
    out
}

/// Re-encodes `bytes` after decoding them as `T` with serde_json.
fn json_rt<T: serde::Serialize + serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let value = serde_json::from_slice::<T>(bytes).map_err(|e| format!("decode: {e}"))?;
    serde_json::to_vec(&value).map_err(|e| format!("encode: {e}"))
}

/// Re-encodes `bytes` after decoding them as `T` with bincode 1.
fn bincode_rt<T: serde::Serialize + serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let value = bincode::deserialize::<T>(bytes).map_err(|e| format!("decode: {e}"))?;
    bincode::serialize(&value).map_err(|e| format!("encode: {e}"))
}

/// A golden sample: its name, its bytes, and how to decode and re-encode
/// them (`None` for raw byte strings with no decoder: signing payloads,
/// signatures, `Display` output).
type Codec = fn(&[u8]) -> Result<Vec<u8>, String>;
type GoldenSample = (&'static str, Vec<u8>, Option<Codec>);

fn golden_samples() -> Vec<GoldenSample> {
    use aft::{
        DelegateParameters, Tier, TokenAllocationRecord, TokenAllocationSummary, TokenAssignment,
        TokenDelegateMessage, TokenDelegateParameters,
    };
    use local_state::{
        Density, DeliveryState, FontSize, LocalState, LocalStateMsg, PermissionDecision, Theme,
        ThreadView,
    };
    let codec = |name: &str| -> Option<Codec> {
        let f: Codec = match name {
            "aft_tiers_display" | "aft_signature_content" | "inbox_sign_payload"
            | "inbox_settings_signature" => return None,
            "aft_tiers_json" => json_rt::<Vec<Tier>>,
            "aft_assignment_json" => json_rt::<TokenAssignment>,
            "aft_record_json" => json_rt::<TokenAllocationRecord>,
            "aft_summary" => json_rt::<TokenAllocationSummary>,
            "aft_record_params" => json_rt::<TokenDelegateParameters>,
            "aft_generator_params" => json_rt::<DelegateParameters>,
            n if n.starts_with("aft_msg_") => bincode_rt::<TokenDelegateMessage>,
            "inbox_params" => json_rt::<inbox::InboxParams>,
            "inbox_settings" | "inbox_settings_default" => json_rt::<inbox::InboxSettings>,
            n if n.starts_with("inbox_update_") => json_rt::<inbox::UpdateInbox>,
            "inbox_state" => json_rt::<inbox::Inbox>,
            n if n.starts_with("identity_msg_") => json_rt::<identity::IdentityMsg>,
            "identity_state" | "identity_state_legacy" => {
                json_rt::<identity::IdentityManagement>
            }
            "identity_enum_kind" => json_rt::<Vec<identity::EntryKind>>,
            n if n.starts_with("ls_msg_") => json_rt::<LocalStateMsg>,
            "ls_state" | "ls_state_sparse" => json_rt::<LocalState>,
            "ls_enum_delivery_state" => json_rt::<Vec<DeliveryState>>,
            "ls_enum_theme" => json_rt::<Vec<Theme>>,
            "ls_enum_density" => json_rt::<Vec<Density>>,
            "ls_enum_font_size" => json_rt::<Vec<FontSize>>,
            "ls_enum_thread_view" => json_rt::<Vec<ThreadView>>,
            "ls_enum_permission" => json_rt::<Vec<PermissionDecision>>,
            other => panic!("golden sample {other} has no codec"),
        };
        Some(f)
    };
    golden_sample_bytes()
        .into_iter()
        .map(|(name, bytes)| (name, bytes, codec(name)))
        .collect()
}
