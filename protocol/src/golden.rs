//! Golden CBOR bytes for every protocol variant.
//!
//! The UI and the delegate are released separately, so this encoding is a
//! wire format: renaming, reordering or retyping a variant breaks whichever
//! side was not rebuilt. `golden_v1.txt` pins one encoding per variant and
//! is append-only (scripts/check-frozen-immutable.sh): add a line for a new
//! variant, never change one.
//!
//! The `*_name` functions match without a wildcard, so a new variant does
//! not compile until it is named here, and the test then fails until it has
//! a sample and a golden line. Regenerate the file with
//! `GOLDEN_PRINT=1 cargo test -p freenet-mail-protocol golden -- --nocapture`
//! and append only the new lines.

use serde_bytes::ByteBuf;

use crate::*;

fn op_name(op: &Op) -> &'static str {
    match op {
        Op::GetStatus => "op_get_status",
        Op::ListIdentities => "op_list_identities",
        Op::CreateIdentity { .. } => "op_create_identity",
        Op::ImportIdentity { .. } => "op_import_identity",
        Op::UpdateIdentity { .. } => "op_update_identity",
        Op::DeleteIdentity { .. } => "op_delete_identity",
        Op::ConfirmIdentity { .. } => "op_confirm_identity",
        Op::ListItems { .. } => "op_list_items",
        Op::GetItem { .. } => "op_get_item",
        Op::PutItem { .. } => "op_put_item",
        Op::DeleteItem { .. } => "op_delete_item",
        Op::DecryptV1 { .. } => "op_decrypt_v1",
        Op::SealV1Message { .. } => "op_seal_v1_message",
        Op::SignV1Authority { .. } => "op_sign_v1_authority",
        Op::SignV1Removal { .. } => "op_sign_v1_removal",
        Op::V1AftParams { .. } => "op_v1_aft_params",
        Op::ExportRecoveryKey { .. } => "op_export_recovery_key",
        Op::ExportProfile { .. } => "op_export_profile",
        Op::ExportForSuccessor { .. } => "op_export_for_successor",
        Op::RevokeExportGrant => "op_revoke_export_grant",
        Op::ListDeletingIdentities => "op_list_deleting_identities",
        Op::RepairIndex { .. } => "op_repair_index",
        Op::RunJobs => "op_run_jobs",
        Op::CreateInboxV2 { .. } => "op_create_inbox_v2",
        Op::UpdateInboxV2 { .. } => "op_update_inbox_v2",
        Op::IssuePass { .. } => "op_issue_pass",
        Op::HoldPass { .. } => "op_hold_pass",
        Op::SealV2 { .. } => "op_seal_v2",
    }
}

fn reply_name(reply: &Reply) -> &'static str {
    match reply {
        Reply::Status(_) => "reply_status",
        Reply::Identities(_) => "reply_identities",
        Reply::Identity(_) => "reply_identity",
        Reply::Imported { .. } => "reply_imported",
        Reply::Items { .. } => "reply_items",
        Reply::Item(_) => "reply_item",
        Reply::Ack { .. } => "reply_ack",
        Reply::Deleted => "reply_deleted",
        Reply::Decrypted(_) => "reply_decrypted",
        Reply::SealedV1 { .. } => "reply_sealed_v1",
        Reply::Signature(_) => "reply_signature",
        Reply::AftParams(_) => "reply_aft_params",
        Reply::RecoveryKey(_) => "reply_recovery_key",
        Reply::Profile(_) => "reply_profile",
        Reply::ExportedSecrets { .. } => "reply_exported_secrets",
        Reply::Continue { .. } => "reply_continue",
        Reply::CreatedIdentity { .. } => "reply_created_identity",
        Reply::JobsRun(_) => "reply_jobs_run",
        Reply::InboxV2State(_) => "reply_inbox_v2_state",
        Reply::InboxV2Update(_) => "reply_inbox_v2_update",
        Reply::PassIssued(_) => "reply_pass_issued",
        Reply::SealedV2(_) => "reply_sealed_v2",
    }
}

fn failure_name(code: &FailureCode) -> &'static str {
    match code {
        FailureCode::NotFound => "failure_not_found",
        FailureCode::Conflict { .. } => "failure_conflict",
        FailureCode::CapReached => "failure_cap_reached",
        FailureCode::Refused => "failure_refused",
        FailureCode::BadInput => "failure_bad_input",
        FailureCode::Busy => "failure_busy",
        FailureCode::Internal => "failure_internal",
        FailureCode::UnsupportedVersion => "failure_unsupported_version",
        FailureCode::UnknownOperation => "failure_unknown_operation",
        FailureCode::Unreadable => "failure_unreadable",
    }
}

fn kind_name(kind: &ItemKind) -> &'static str {
    match kind {
        ItemKind::Contact => "kind_contact",
        ItemKind::Draft => "kind_draft",
        ItemKind::Sent => "kind_sent",
        ItemKind::Kept => "kind_kept",
        ItemKind::Archived => "kind_archived",
        ItemKind::Flags => "kind_flags",
        ItemKind::IdentitySettings => "kind_identity_settings",
        ItemKind::GlobalSettings => "kind_global_settings",
        ItemKind::MigrationJournal => "kind_migration_journal",
        ItemKind::MigrationMarker => "kind_migration_marker",
        ItemKind::LegacyOrphan => "kind_legacy_orphan",
        ItemKind::InboxV2 => "kind_inbox_v2",
        ItemKind::PassLedger => "kind_pass_ledger",
        ItemKind::HeldPass => "kind_held_pass",
        ItemKind::Inbound => "kind_inbound",
    }
}

fn source_name(source: &ImportSource) -> &'static str {
    match source {
        ImportSource::RecoveryKey(_) => "source_recovery_key",
        ImportSource::LegacyJson(_) => "source_legacy_json",
        ImportSource::Seeds { .. } => "source_seeds",
    }
}

fn import_kind_name(kind: &ImportKind) -> &'static str {
    match kind {
        ImportKind::UserRestore => "import_user_restore",
        ImportKind::Migration => "import_migration",
    }
}

fn b(v: &[u8]) -> ByteBuf {
    ByteBuf::from(v.to_vec())
}

fn addr() -> Addr {
    Addr([0xA1; 24])
}

fn item() -> ItemRef {
    ItemRef {
        kind: ItemKind::Draft,
        owner: Some(addr()),
        id: vec![0xB2; 16],
    }
}

fn identity() -> IdentityInfo {
    IdentityInfo {
        addr: addr(),
        vk: b(&[1, 2]),
        ek: b(&[3, 4]),
        alias: "alice".into(),
        description: "d".into(),
        confirmed: true,
        generation: 7,
    }
}

fn pass() -> inbox_v2::Pass {
    use serde_bytes::ByteArray;
    inbox_v2::Pass {
        cert: inbox_v2::PassCert {
            recipient: ByteArray::new([0xA1; 24]),
            pass_id: ByteArray::new([0x22; 16]),
            pass_vk: ByteArray::new([0x33; 32]),
            epoch: 1,
            expiry: 86_400,
            class: inbox_v2::PassClass::Invite { max_messages: 3 },
            sig: ByteArray::new([0x44; 64]),
        },
        pass_sk: ByteArray::new([0x55; 32]),
    }
}

fn ops() -> Vec<Op> {
    let a = addr();
    vec![
        Op::GetStatus,
        Op::ListIdentities,
        Op::CreateIdentity {
            alias: "alice".into(),
            description: "d".into(),
            ui_entropy: Entropy([0xC3; 32]),
        },
        Op::ImportIdentity {
            source: ImportSource::RecoveryKey("fmail-key-1:x".into()),
            kind: ImportKind::UserRestore,
            alias: "a".into(),
            description: String::new(),
        },
        Op::UpdateIdentity {
            addr: a,
            alias: "a".into(),
            description: "d".into(),
            expected_gen: 3,
        },
        Op::DeleteIdentity {
            addr: a,
            expected_gen: 4,
        },
        Op::ConfirmIdentity {
            addr: a,
            expected_gen: 5,
        },
        Op::ListItems {
            kind: ItemKind::Archived,
            owner: Some(a),
            after: Some(b(&[9])),
            limit: 50,
        },
        Op::GetItem { item: item() },
        Op::PutItem {
            item: item(),
            body: b(b"body"),
            expected_gen: Some(2),
        },
        Op::DeleteItem {
            item: item(),
            expected_gen: 6,
        },
        Op::DecryptV1 {
            addr: a,
            ciphertexts: vec![b(&[1]), b(&[2])],
        },
        Op::SealV1Message {
            addr: a,
            recipient_ek: b(&[5]),
            plaintext: b(b"hi"),
            ui_entropy: Entropy([0xD4; 32]),
        },
        Op::SignV1Authority {
            addr: a,
            settings_json: b(b"{}"),
            last_update_micros: -1,
        },
        Op::SignV1Removal {
            addr: a,
            assignment_hashes: vec![Hash32([0xE5; 32])],
        },
        Op::V1AftParams { addr: a },
        Op::ExportRecoveryKey { addr: a },
        Op::ExportProfile { addr: a },
        Op::ExportForSuccessor {
            source_generation: 2,
            after: None,
            session: None,
        },
        Op::RevokeExportGrant,
        Op::ListDeletingIdentities,
        Op::RunJobs,
        Op::RepairIndex {
            kind: Some(ItemKind::Draft),
            owner: Some(a),
        },
        Op::CreateInboxV2 {
            addr: a,
            ghost_master: Hash32([0x88; 32]),
            existing: Some(b(&[0])),
        },
        Op::UpdateInboxV2 {
            addr: a,
            state: b(&[1]),
            change: OwnerChange::Revoke {
                pass_id: PassId([0x22; 16]),
            },
            ui_entropy: Entropy([0xC3; 32]),
        },
        Op::IssuePass {
            addr: a,
            contact: Some(Addr([0xB1; 24])),
            invite: Some(3),
            ui_entropy: Entropy([0xC3; 32]),
        },
        Op::HoldPass {
            addr: a,
            pass: pass(),
        },
        Op::SealV2 {
            from: a,
            to: Addr([0xB1; 24]),
            to_state: b(&[2]),
            content: SealContent::Mail(b(b"hi")),
            ghost_vk: Some(Hash32([0x33; 32])),
            ui_entropy: Entropy([0xD4; 32]),
        },
    ]
}

fn replies() -> Vec<Reply> {
    vec![
        Reply::Status(Status {
            protocol_version: 1,
            identities: 2,
            stored_keys: 3,
            stored_bytes: 4,
            key_budget: 5,
            byte_budget: 6,
            v1_transition: true,
            unreadable_identities: 0,
        }),
        Reply::Identities(vec![identity()]),
        Reply::Identity(identity()),
        Reply::Imported {
            identity: identity(),
            already_present: false,
        },
        Reply::Items {
            items: vec![Item {
                item: item(),
                body: b(b"x"),
                generation: 8,
            }],
            more: true,
        },
        Reply::Item(None),
        Reply::Ack { generation: 9 },
        Reply::Deleted,
        Reply::Decrypted(vec![Ok(b(b"pt")), Err(FailureCode::BadInput)]),
        Reply::SealedV1 {
            content: b(&[1]),
            signature: b(&[2]),
            sender_vk: b(&[3]),
        },
        Reply::Signature(b(&[4])),
        Reply::AftParams(b(b"{}")),
        Reply::RecoveryKey("fmail-key-1:x".into()),
        Reply::Profile(b(b"{}")),
        Reply::ExportedSecrets {
            payload: b(&[5]),
            next: Some(b(b"ix/id")),
            session: None,
        },
        Reply::Continue { remaining: 12 },
        Reply::JobsRun(JobsRun {
            scanned: 1,
            imported: 2,
            unknown: 3,
            remaining: 4,
        }),
        Reply::CreatedIdentity {
            identity: identity(),
            recovery_key: "fmail-key-1:x".into(),
        },
        Reply::InboxV2State(b(&[6])),
        Reply::InboxV2Update(InboxV2Update {
            update: Some(b(&[7])),
            drained: 1,
            remaining: 2,
            full: 3,
            strangers_dropped: 4,
        }),
        Reply::PassIssued(pass()),
        Reply::SealedV2(SealedV2 {
            message: b(&[8]),
            id: Hash32([0x99; 32]),
            sent_time: 3600,
            admission: SendAdmission::Quarantine,
            ghost_payload: Some(b(&[9])),
            notice: Some(SendNotice::QueueFull),
            reseal_at: 7200,
        }),
    ]
}

fn samples() -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    let enc = |v: &dyn erased::Enc| v.cbor();
    for op in ops() {
        out.push((op_name(&op).to_string(), enc(&op)));
    }
    for reply in replies() {
        out.push((reply_name(&reply).to_string(), enc(&reply)));
    }
    for code in [
        FailureCode::NotFound,
        FailureCode::Conflict { current_gen: 11 },
        FailureCode::CapReached,
        FailureCode::Refused,
        FailureCode::BadInput,
        FailureCode::Busy,
        FailureCode::Internal,
        FailureCode::UnsupportedVersion,
        FailureCode::UnknownOperation,
        FailureCode::Unreadable,
    ] {
        let f = Failure {
            code,
            detail: "why".into(),
        };
        out.push((failure_name(&code).to_string(), enc(&f)));
    }
    for kind in [
        ItemKind::Contact,
        ItemKind::Draft,
        ItemKind::Sent,
        ItemKind::Kept,
        ItemKind::Archived,
        ItemKind::Flags,
        ItemKind::IdentitySettings,
        ItemKind::GlobalSettings,
        ItemKind::MigrationJournal,
        ItemKind::MigrationMarker,
        ItemKind::LegacyOrphan,
        ItemKind::InboxV2,
        ItemKind::PassLedger,
        ItemKind::HeldPass,
        ItemKind::Inbound,
    ] {
        out.push((kind_name(&kind).to_string(), enc(&kind)));
    }
    for source in [
        ImportSource::RecoveryKey("k".into()),
        ImportSource::LegacyJson(b(b"{}")),
        ImportSource::Seeds {
            dsa: DsaSeed([0x11; 32]),
            kem: KemSeed([0x22; 64]),
        },
    ] {
        out.push((source_name(&source).to_string(), enc(&source)));
    }
    for kind in [ImportKind::UserRestore, ImportKind::Migration] {
        out.push((import_kind_name(&kind).to_string(), enc(&kind)));
    }
    let request = Request {
        version: PROTOCOL_VERSION,
        request_id: RequestId([0x33; 16]),
        op: Op::GetStatus,
    };
    out.push(("request".into(), enc(&request)));
    // Optional fields added later, present.
    let with_session = Op::ExportForSuccessor {
        source_generation: 2,
        after: Some(b(b"it/x")),
        session: Some(b(&[0x55; 32])),
    };
    out.push(("op_export_for_successor_session".into(), enc(&with_session)));
    let reply_session = Reply::ExportedSecrets {
        payload: b(&[5]),
        next: Some(b(b"ix/id")),
        session: Some(b(&[0x66; 32])),
    };
    out.push(("reply_exported_secrets_session".into(), enc(&reply_session)));
    let status_unreadable = Reply::Status(Status {
        protocol_version: 1,
        identities: 2,
        stored_keys: 3,
        stored_bytes: 4,
        key_budget: 5,
        byte_budget: 6,
        v1_transition: true,
        unreadable_identities: 1,
    });
    out.push(("reply_status_unreadable".into(), enc(&status_unreadable)));
    let response = Response {
        request_id: RequestId([0x44; 16]),
        result: Err(Failure {
            code: FailureCode::Busy,
            detail: String::new(),
        }),
    };
    out.push(("response".into(), enc(&response)));
    for change in [
        OwnerChange::Drain,
        OwnerChange::AdvanceTime,
        OwnerChange::SetQuarantine(inbox_v2::QuarantineMode::RequireGhost { min_usd: Some(5) }),
        OwnerChange::BumpEpoch { emergency: true },
    ] {
        out.push((change_name(&change).into(), enc(&change)));
    }
    out.push(("seal_pass_update".into(), enc(&SealContent::PassUpdate)));
    out.push(("admission_pass".into(), enc(&SendAdmission::Pass)));
    out.push(("admission_owner".into(), enc(&SendAdmission::Owner)));
    out.push(("notice_pass_lapsed".into(), enc(&SendNotice::PassLapsed)));
    out.push(("notice_pass_full".into(), enc(&SendNotice::PassFull)));
    out
}

fn change_name(change: &OwnerChange) -> &'static str {
    match change {
        OwnerChange::Drain => "change_drain",
        OwnerChange::AdvanceTime => "change_advance_time",
        OwnerChange::SetQuarantine(_) => "change_set_quarantine",
        OwnerChange::Revoke { .. } => "change_revoke",
        OwnerChange::BumpEpoch { .. } => "change_bump_epoch",
    }
}

mod erased {
    pub trait Enc {
        fn cbor(&self) -> Vec<u8>;
    }
    impl<T: serde::Serialize> Enc for T {
        fn cbor(&self) -> Vec<u8> {
            crate::to_cbor(self).expect("samples encode")
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

const GOLDEN: &str = include_str!("golden_v1.txt");

fn golden(name: &str) -> Option<&'static str> {
    GOLDEN
        .lines()
        .find_map(|l| l.strip_prefix(name)?.strip_prefix(' '))
}

#[test]
fn golden_every_variant_encodes_to_its_pinned_bytes() {
    if std::env::var_os("GOLDEN_PRINT").is_some() {
        for (name, bytes) in samples() {
            println!("{name} {}", hex(&bytes));
        }
    }
    let mut missing = Vec::new();
    for (name, bytes) in samples() {
        match golden(&name) {
            Some(want) => assert_eq!(hex(&bytes), want, "{name} changed encoding"),
            None => missing.push(name),
        }
    }
    assert!(missing.is_empty(), "no golden line for {missing:?}");
}

#[test]
fn golden_bytes_decode_and_re_encode_unchanged() {
    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
    for op in ops() {
        let bytes = unhex(golden(op_name(&op)).unwrap());
        assert_eq!(from_cbor::<Op>(&bytes).unwrap(), op);
    }
    for reply in replies() {
        let bytes = unhex(golden(reply_name(&reply)).unwrap());
        assert_eq!(from_cbor::<Reply>(&bytes).unwrap(), reply);
    }
}

#[test]
fn a_request_with_an_unknown_operation_still_yields_its_id() {
    // A future UI's request: same envelope, an operation this build lacks.
    #[derive(serde::Serialize)]
    enum FutureOp {
        Teleport { to: u8 },
    }
    #[derive(serde::Serialize)]
    struct FutureRequest {
        version: u16,
        request_id: RequestId,
        op: FutureOp,
    }
    let bytes = to_cbor(&FutureRequest {
        version: PROTOCOL_VERSION,
        request_id: RequestId([9; 16]),
        op: FutureOp::Teleport { to: 1 },
    })
    .unwrap();
    assert!(from_cbor::<Request>(&bytes).is_err());
    let env: RequestEnvelope = from_cbor(&bytes).unwrap();
    assert_eq!(
        (env.version, env.request_id),
        (PROTOCOL_VERSION, RequestId([9; 16]))
    );
    assert!(env.op().is_err());
    // A current request decodes the same either way.
    let req = Request {
        version: PROTOCOL_VERSION,
        request_id: RequestId([1; 16]),
        op: Op::GetStatus,
    };
    let env: RequestEnvelope = from_cbor(&to_cbor(&req).unwrap()).unwrap();
    assert_eq!(env.op().unwrap(), Op::GetStatus);
}

#[test]
fn golden_a_changed_byte_is_caught() {
    let (name, bytes) = samples().remove(0);
    let mut tampered = bytes.clone();
    tampered[0] ^= 1;
    assert_ne!(hex(&tampered), golden(&name).unwrap());
}
