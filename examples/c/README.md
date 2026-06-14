# C example

Pure C99. No external dependencies beyond `signal_ffi.h` and a C compiler.

## Prerequisites

- C compiler (`cc` / `clang` / `gcc`)
- Library built from repo root: `zig build`

## Run

```sh
make run
```

## What it covers

| Section | API exercised |
|---------|---------------|
| EC + XEdDSA | `signal_privatekey_generate`, `signal_privatekey_agree`, `signal_privatekey_sign`, `signal_publickey_verify` |
| ML-KEM-1024 | `signal_kyber_key_pair_generate`, `signal_kyber_public_key_serialize`, `signal_kyber_secret_key_serialize` |
| X3DH + PQXDH + Double Ratchet | `signal_pre_key_bundle_new`, `signal_process_prekey_bundle`, `signal_encrypt_message`, `signal_decrypt_pre_key_message`, `signal_decrypt_message` |
| Sender Keys | `signal_sender_key_distribution_message_create`, `signal_process_sender_key_distribution_message`, `signal_group_encrypt_message`, `signal_group_decrypt_message` |
| Fingerprints | `signal_fingerprint_new`, `signal_fingerprint_scannable_encoding`, `signal_fingerprint_compare` |
| Username ZK proof | `signal_username_hash`, `signal_username_proof`, `signal_username_verify` |
| Account entropy pool | `signal_account_entropy_pool_generate`, `signal_account_entropy_pool_derive_svr_key`, `signal_account_entropy_pool_derive_backup_key`, `signal_backup_key_derive_media_encryption_key` |

## Notes

**Error handling.** Every `signal_*` function returns `NULL` on success or a
caller-owned `SignalFfiError*` on failure. Errors must be freed with
`signal_error_free()`. The example wraps this in a `MUST()` macro that calls
`signal_error_get_message()` and aborts on any failure.

**Store callbacks.** The six store structs (`SignalSessionStore`,
`SignalIdentityKeyStore`, `SignalPreKeyStore`, `SignalSignedPreKeyStore`,
`SignalKyberPreKeyStore`, `SignalSenderKeyStore`) are passed by pointer to
session functions. Each holds a `void *ud` user-data pointer plus function
pointer fields. Callbacks return `SignalFfiError*` (NULL = success).

**Serialization.** Store callbacks use `signal_session_record_serialize` /
`signal_session_record_deserialize` (and their per-type equivalents) to
convert opaque handles to bytes for storage and back. Output bytes arrive
in `SignalOwnedBuffer` structs and must be freed with `signal_free_buffer`.

**In-memory stores.** All stores use a simple fixed-array key-value map
(`kv_t`) with linear search — sufficient for a test harness and easy to
follow.
