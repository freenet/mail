#!/usr/bin/env python3
"""A second implementation of the inbox's byte layouts, written from the spec
without reading the Rust. It writes vectors.txt, which tests/vectors.rs compares
the contract against. Needs cbor2 and b3sum.

Run from this directory: python3 vectors.py > vectors.txt
"""
import subprocess

import cbor2


def b3(data, context=None):
    cmd = ["b3sum", "--no-names", "--raw"]
    if context:
        cmd += ["--derive-key", context]
    return subprocess.run(cmd, input=data, capture_output=True, check=True).stdout


def u32(n):
    return n.to_bytes(4, "big")


def u64(n):
    return n.to_bytes(8, "big")


ADDR = b"\x11" * 24
PASS_ID = b"\x22" * 16
KEY = b"\x33" * 32
SIG = b"\x44" * 64
HASH = b"\x55" * 32
TOMB = b"\x66" * 32
VK = b"\x77" * 1952
MASTER = b"\x88" * 32
KEM = bytes.fromhex("aabbccdd")
T = 0x0102030405060708
SENT = 0x68000000 // 3600 * 3600


def quarantine(mode):
    return {
        "open": b"\x00",
        "require": b"\x01\x00",
        "require5": b"\x01\x01" + u32(5),
    }[mode]


def owner_layout(mode):
    return (
        b"fmail/owner/v1" + ADDR + u64(7) + u32(3) + KEY + quarantine(mode)
        + u32(len(KEM)) + KEM + u32(1) + TOMB + u64(0x1000)
    )


def cert_layout(klass):
    return b"fmail/pass/v1" + ADDR + PASS_ID + KEY + u32(3) + u64(T) + klass


def stamped(domain):
    return domain + ADDR + u64(SENT) + HASH


def sealed(kind, tag):
    return b"fmail/sealed/v1" + ADDR + HASH + u64(SENT) + bytes([kind]) + tag


def msgid(kind, tag):
    return b3(b"fmail/msgid/v1" + ADDR + HASH + u64(SENT) + bytes([kind]) + tag)


address = b3(VK, "freenet-mail address v1")[:24]
vectors = [
    ("address", address),
    ("address_check", b3(address, "freenet-mail address check v1")[:2]),
    ("params", b"\x02" + ADDR + MASTER),
    ("owner_open", owner_layout("open")),
    ("owner_require", owner_layout("require")),
    ("owner_require5", owner_layout("require5")),
    ("time", b"fmail/time/v1" + ADDR + u64(T)),
    ("cert_contact", cert_layout(b"\x00")),
    ("cert_invite", cert_layout(b"\x01\x03")),
    ("revocation", b"fmail/revoke/v1" + ADDR + PASS_ID + u64(T) + u32(3)),
    ("usage", b"fmail/usage/v1" + ADDR + PASS_ID + b"\x02" + u64(T)),
    ("admit", stamped(b"fmail/admit/v1")),
    ("owner_msg", stamped(b"fmail/owner-msg/v1")),
    ("ghost_admit", stamped(b"fmail/ghost-admit/v1")),
    ("sealed_pass", sealed(0, PASS_ID)),
    ("sealed_owner", sealed(1, b"")),
    ("sealed_quarantine", sealed(2, KEY)),
    ("id_pass", msgid(0, PASS_ID)),
    ("id_owner", msgid(1, b"")),
    ("id_quarantine", msgid(2, b"")),
    # With a Ghost Key proof, the key its certificate claims; zeros when the
    # certificate does not decode.
    ("id_quarantine_proven", msgid(2, KEY)),
    ("id_quarantine_undecodable", msgid(2, b"\x00" * 32)),
]

# Wire: structs are maps in field order, fixed bytes are byte strings, enums are
# externally tagged, a unit variant is its name.
owner = {
    "owner_vk": b"\x77" * 4,
    "kem_ek": KEM,
    "issuer_vk": KEY,
    "pass_epoch": 3,
    "version": 7,
    "quarantine": {"RequireGhost": {"min_usd": 5}},
    "tombstones": {TOMB: 0x1000},
    "sig": b"\x99" * 4,
}
time = {"owner_time": T, "sig": SIG}
revocation = {"pass_id": PASS_ID, "expiry": T, "epoch": 3, "sig": SIG}
usage = {"pass_id": PASS_ID, "used": 2, "expiry": T, "sig": SIG}
cert = {
    "recipient": ADDR,
    "pass_id": PASS_ID,
    "pass_vk": KEY,
    "epoch": 3,
    "expiry": T,
    "class": {"Invite": {"max_messages": 3}},
    "sig": SIG,
}
pass_msg = {
    "ciphertext": b"\xcc" * 3,
    "sent_time": SENT,
    "admission": {"Pass": {"cert": cert, "msg_sig": SIG}},
}
owner_msg = {
    "ciphertext": b"\xcc" * 3,
    "sent_time": SENT,
    "admission": {"Owner": {"sig": SIG}},
}
proof = {"cert": b"\xc1\xc2", "scoped_payload": b"\xd1", "ghost_sig": SIG}
quarantine_msg = {
    "ciphertext": b"\xcc" * 3,
    "sent_time": SENT,
    "admission": {"Quarantine": {"ghost": proof}},
}
bare_msg = {
    "ciphertext": b"\xcc" * 3,
    "sent_time": SENT,
    "admission": {"Quarantine": {"ghost": None}},
}
state = {
    "owner": owner,
    "time": time,
    "revoked": {PASS_ID: revocation},
    "usage": {PASS_ID: usage},
    "messages": {HASH: bare_msg},
}
delta_some = {
    "owner": None,
    "time": time,
    "revoked": {},
    "usage": {},
    "messages": {HASH: owner_msg},
}


def enc(value):
    return cbor2.dumps(value)


vectors += [
    ("cbor_owner_open_mode", enc("Open")),
    ("cbor_owner", enc(owner)),
    ("cbor_time", enc(time)),
    ("cbor_revocation", enc(revocation)),
    ("cbor_usage", enc(usage)),
    ("cbor_cert", enc(cert)),
    ("cbor_pass_message", enc(pass_msg)),
    ("cbor_owner_message", enc(owner_msg)),
    ("cbor_quarantine_message", enc(quarantine_msg)),
    ("cbor_state", enc(state)),
    ("cbor_delta", enc(delta_some)),
]

# 16 bytes of the id, 16 of the encoding's digest (decision 13).
entry = HASH[:16] + b3(enc(bare_msg))[:16]
summary = {
    "owner": b3(enc(owner))[:16],
    "time": b3(enc(time))[:16],
    "revoked": b3(enc({PASS_ID: revocation}))[:16],
    "revoked_count": 1,
    "usage": b3(enc({PASS_ID: usage}))[:16],
    "messages": entry,
}
vectors.append(("cbor_summary", enc(summary)))

for name, value in vectors:
    print(name, value.hex())
