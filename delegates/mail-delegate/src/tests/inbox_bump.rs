//! The epoch bumps a revocation causes: the routine one at 2048 live
//! revocations of an epoch (decision 18, with its 14 day grace) and the
//! emergency one when the set is full (no grace). The states here are the
//! owner's, with the earlier revocations signed by the issuer key as the
//! delegate signs them, so the delegate's choice at the edge is the only
//! thing under test; every update it returns goes through the contract.

use freenet_mail_protocol::inbox_v2::{self as w, InboxState};
use freenet_mail_protocol::{Addr, OwnerChange, PassId};
use serde_bytes::ByteArray;

use super::PROD;
use super::inbox_v2::{DAY, START, World};
use crate::inbox_v2::{BUMP_AT_REVOCATIONS, EPOCH_GRACE, issuer_key};
use crate::store::{Origin, Space};

/// `addr`'s state with `n` more live revocations of its current epoch, each
/// for a pass that does not exist, signed by its issuer key.
fn with_revocations(world: &mut World, addr: &Addr, n: usize) -> InboxState {
    let dsa = {
        let s = Space::new(&mut world.env, Origin([PROD; 32]));
        crate::handlers::require_identity(&s, addr).unwrap().1.dsa
    };
    let issuer = issuer_key(&dsa);
    let mut state = world.state(addr);
    let epoch = state.owner.pass_epoch;
    let expiry = (START / DAY + 300) * DAY;
    for i in 0..n {
        let mut id = [0xEE; 16];
        id[..8].copy_from_slice(&(i as u64).to_be_bytes());
        let sig = {
            use ed25519_dalek::Signer;
            issuer.sign(&w::revocation_bytes(&addr.0, &id, expiry, epoch))
        };
        state.revoked.insert(
            ByteArray::new(id),
            w::Revocation {
                pass_id: ByteArray::new(id),
                expiry,
                epoch,
                sig: ByteArray::new(sig.to_bytes()),
            },
        );
    }
    state
}

/// Revoke one more real pass of `addr`'s, as the page would; returns what the
/// delegate sent, after the contract has accepted it.
fn revoke_one(world: &mut World, addr: &Addr) -> w::InboxDelta {
    let pass = world.issue(addr, None, Some(1));
    let u = world
        .update(
            addr,
            OwnerChange::Revoke {
                pass_id: PassId(pass.cert.pass_id.into_array()),
            },
        )
        .expect("the revocation is signed");
    assert_eq!(u.remaining, 0);
    let delta = u.update.expect("an update");
    world.publish(addr, &delta);
    let delta: w::InboxDelta = w::decode(&delta).unwrap();
    assert!(delta.revoked.contains_key(&pass.cert.pass_id));
    delta
}

#[test]
fn the_2048th_live_revocation_bumps_the_epoch_and_the_2047th_does_not() {
    let mut world = World::new();
    let a = world.identity("alice");
    let st = with_revocations(&mut world, &a, BUMP_AT_REVOCATIONS - 2);
    world.inboxes.insert(a, w::encode(&st));
    assert_eq!(world.state(&a).revoked.len(), BUMP_AT_REVOCATIONS - 2);

    // The 2047th: no bump, signed with the epoch the inbox is in.
    let before = world.state(&a);
    let delta = revoke_one(&mut world, &a);
    let after = world.state(&a);
    assert_eq!(after.revoked.len(), BUMP_AT_REVOCATIONS - 1);
    assert_eq!(after.owner.pass_epoch, before.owner.pass_epoch);
    assert_eq!(after.owner.prev_epoch_until, before.owner.prev_epoch_until);
    assert!(
        delta
            .revoked
            .values()
            .all(|r| r.epoch == before.owner.pass_epoch)
    );

    // The 2048th: the epoch moves on, the old one keeps its 14 day grace, and
    // the revocation is signed with the new epoch.
    let now = world.env.now.unwrap();
    let held = after.time.owner_time;
    let delta = revoke_one(&mut world, &a);
    let bumped = world.state(&a);
    assert_eq!(bumped.owner.pass_epoch, after.owner.pass_epoch + 1);
    assert_eq!(bumped.owner.prev_epoch_until, held.max(now) + EPOCH_GRACE);
    assert!(delta.revoked.values().all(|r| r.epoch == bumped.owner.pass_epoch));
    let rec = world.record(&a);
    assert_eq!(rec.pass_epoch, bumped.owner.pass_epoch);
    assert_eq!(rec.reissue_grace, EPOCH_GRACE);
}

#[test]
fn a_full_revoked_set_bumps_the_epoch_with_no_grace() {
    let mut world = World::new();
    let a = world.identity("alice");
    let st = with_revocations(&mut world, &a, w::MAX_REVOKED);
    world.inboxes.insert(a, w::encode(&st));
    assert_eq!(world.state(&a).revoked.len(), w::MAX_REVOKED);
    let before = world.state(&a).owner.pass_epoch;

    // Issue the pass first: the revocation of a full set is the one that has
    // to bump, and it must still be accepted.
    let delta = revoke_one(&mut world, &a);
    let after = world.state(&a);
    assert_eq!(after.owner.pass_epoch, before + 1);
    assert_eq!(after.owner.prev_epoch_until, 0, "no grace on an emergency");
    assert!(delta.revoked.values().all(|r| r.epoch == before + 1));
    let rec = world.record(&a);
    assert_eq!(rec.reissue_grace, 0);
}
