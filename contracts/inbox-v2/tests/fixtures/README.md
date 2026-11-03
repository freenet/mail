# Test fixtures

`ghost-keys.txt` holds a throwaway test master's verifying key and ten Ghost
Key certificates under it: four at $1, four at $5, two at $20, each from a
notary whose `info` is current-format JSON. Each `cert` line is
`cert <usd> <ghost signing key> <certificate CBOR> <unused>`, in hex.

None of these keys is used anywhere else. They were made once with
`ghostkey_lib` 0.2's `NotaryCertificateV1::new` and
`GhostkeyCertificateV1::new`, because RSA key generation is too slow to repeat
per test and `ghostkey_lib` is too large a dev-dependency for one use.
