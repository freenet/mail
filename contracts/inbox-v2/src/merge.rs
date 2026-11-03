//! STUB, replaced once the merge-law run has been seen to fail on it.

use crate::Params;
use crate::types::{InboxDelta, InboxState, Malformed};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rules {
    pub per_pass: usize,
    pub per_invite: usize,
    pub pass_pool: usize,
    pub owner_pool: usize,
    pub quarantine: usize,
    pub per_ghost: usize,
    pub revoked: usize,
    pub usage: usize,
    pub tombstones: usize,
}

impl Rules {
    pub const V1: Rules = Rules {
        per_pass: 8,
        per_invite: 2,
        pass_pool: 64,
        owner_pool: 8,
        quarantine: 16,
        per_ghost: 2,
        revoked: 4096,
        usage: 1024,
        tombstones: 4096,
    };
}

pub fn merge(
    _rules: &Rules,
    _params: &Params,
    parts: Vec<InboxDelta>,
) -> Result<InboxState, Malformed> {
    let mut out: Option<InboxState> = None;
    for part in parts {
        let mut base = match out.take() {
            Some(base) => base,
            None => InboxState {
                owner: part.owner.clone().ok_or(Malformed("no owner"))?,
                time: part.time.clone().ok_or(Malformed("no time"))?,
                revoked: Default::default(),
                usage: Default::default(),
                messages: Default::default(),
            },
        };
        if let Some(owner) = part.owner
            && owner.version > base.owner.version
        {
            base.owner = owner;
        }
        if let Some(time) = part.time
            && time.owner_time > base.time.owner_time
        {
            base.time = time;
        }
        base.revoked.extend(part.revoked);
        base.usage.extend(part.usage);
        base.messages.extend(part.messages);
        out = Some(base);
    }
    out.ok_or(Malformed("nothing to merge"))
}

pub const WEBAPP_REQUESTOR: [u8; 32] = [0; 32];
