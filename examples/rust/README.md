# Rust example

Pure Rust with `unsafe` FFI. No bindgen — all bindings are hand-written
`#[repr(C)]` structs and `extern "C"` declarations against `signal_ffi.h`.

## Prerequisites

- Rust toolchain (`cargo`)
- Library built from repo root: `zig build`

## Run

```sh
cargo run
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

**Signal{Mut,Const}Pointer<T> ABI.** These single-field wrapper structs are
ABI-equivalent to a bare pointer on 64-bit platforms. All opaque handles are
declared as `*mut c_void` in Rust; mutable pointer out-parameters are
`*mut *mut c_void`.

**Store struct layout.** Each store struct is `#[repr(C)]` and matches the
field order in `signal_ffi.h` exactly. Store callbacks serialize/deserialize
opaque handles using library functions (e.g. `signal_session_record_serialize`,
`signal_pre_key_record_deserialize`), keeping serialized bytes in Rust
`HashMap<String, Vec<u8>>` backing stores.

**Store callbacks calling back into the library.** Rust `unsafe extern "C"`
callbacks can call any `extern "C"` function. The C→Rust→C call chain is
synchronous and safe as long as no Rust panics cross the FFI boundary.

**`ud` pointer lifetime.** Store structs hold a `*mut c_void` pointing to
stack-allocated Rust data. The data is declared at the start of each test
function and remains live for its entire duration — the store structs never
outlive their backing data.

**Error handling.** Every `signal_*` function returns `NULL` on success or a
caller-owned `*mut c_void` (`SignalFfiError*`) on failure. The `must!` macro
calls `signal_error_get_message`, panics with the message, and frees the error.

**Memory.** `OwnedBuffer` values are freed with `signal_free_buffer`. Opaque
handles are freed with `signal_*_destroy`. C strings are freed with
`signal_free_string`.
