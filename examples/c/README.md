# C example

Pure C99. No external dependencies beyond `libsignal.h` and a C compiler.

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
| EC + XEdDSA | `libsignal_ec_keypair_generate`, `libsignal_ec_dh`, `libsignal_xeddsa_sign/verify` |
| ML-KEM-1024 | `libsignal_kyber1024_keypair_generate`, `_encaps`, `_decaps` |
| X3DH + Double Ratchet | `libsignal_ctx_new`, `libsignal_process_prekey_bundle`, `libsignal_encrypt`, `libsignal_decrypt_prekey`, `libsignal_decrypt` |
| Sender Keys | `libsignal_group_create_session`, `_process_session`, `_encrypt`, `_decrypt` |
| Sealed Sender V1 | `libsignal_server_cert_serialize`, `libsignal_sender_cert_serialize`, `libsignal_sealed_sender_encrypt/decrypt` |
| Sealed Sender V2 | `libsignal_sealed_sender_encrypt_v2`, `_v2_dispatch`, `_decrypt_v2` |
| Fingerprints | `libsignal_fingerprint_compute`, `libsignal_fingerprint_compare` |
| Username ZK proof | `libsignal_username_hash`, `libsignal_username_proof`, `libsignal_username_verify` |
| Account entropy pool | `libsignal_account_entropy_pool_generate`, `_parse`, `_derive_svr_key`, `_derive_backup_key`, `libsignal_backup_key_derive_media_key` |

## Notes

**Store callbacks.** The five store structs (`libsignal_session_store_t`,
`libsignal_identity_store_t`, `libsignal_pre_key_store_t`,
`libsignal_signed_pre_key_store_t`, `libsignal_sender_key_store_t`) are passed
**by value** to `libsignal_ctx_new`. Each holds a `void *ud` user-data pointer
plus function pointer fields.

**malloc contract.** The `load` callbacks for session and sender key stores must
write a `malloc`'d buffer to `*out`. The library calls `free()` on it after use.
This example demonstrates the pattern:

```c
static int sess_load(void *ud, const char *name, uint32_t dev,
                     uint8_t **out, size_t *out_len) {
    /* ... find entry ... */
    *out     = (uint8_t *)malloc(entry->len);
    *out_len = entry->len;
    memcpy(*out, entry->data, entry->len);
    return LIBSIGNAL_OK;
}
```

**In-memory stores.** Identity, pre-key, and signed pre-key stores are simple
stack-allocated structs. Session and sender key stores are fixed-size arrays
with linear search — sufficient for a test harness and easy to follow.
