//! Serde for `[u8; N]` as a byte string of exactly N bytes.
//!
//! Serde's own array impl encodes a sequence of integers (about twice the
//! size in CBOR) and stops at N = 32.

use serde::de::Error;
use serde::{Deserialize, Deserializer, Serializer};
use serde_bytes::ByteBuf;

pub fn serialize<S: Serializer, const N: usize>(value: &[u8; N], s: S) -> Result<S::Ok, S::Error> {
    s.serialize_bytes(value)
}

pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(d: D) -> Result<[u8; N], D::Error> {
    let buf = ByteBuf::deserialize(d)?;
    let len = buf.len();
    buf.into_vec()
        .try_into()
        .map_err(|_| D::Error::invalid_length(len, &"a fixed-length byte string"))
}
