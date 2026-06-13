# Rust example

Pure Rust with `unsafe` FFI. No bindgen — all bindings are hand-written
`#[repr(C)]` structs and `extern "C"` declarations. The only external crate is
`libc` for `malloc`/`free`.

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

**Struct-by-value.** The five store structs (`SessionStore`, `IdentityStore`,
`PreKeyStore`, `SignedPreKeyStore`, `SenderKeyStore`) are declared `#[repr(C)]`
and passed **by value** to `libsignal_ctx_new` and the group functions — exactly
as in the C ABI. No boxing or indirection is needed.

**malloc contract.** The `load` callbacks for session and sender key stores must
write a `libc::malloc`'d buffer to `*out`. The library calls `free()` on it
after use. Using the Rust global allocator here would be wrong because it is not
guaranteed to back onto `malloc`. The example uses `libc::malloc` explicitly:

```rust
let buf = libc::malloc(data.len()) as *mut u8;
ptr::copy_nonoverlapping(data.as_ptr(), buf, data.len());
*out = buf;
*out_len = data.len();
```

**`ud` pointer lifetime.** Each store struct holds a `*mut c_void` pointing to
heap-allocated store data (a Rust struct on the stack). The data must outlive
every call into the library that uses those stores. In this example all store
data is declared at the top of each test function and dropped only after the
corresponding ctx is freed.

**No bindgen.** All bindings are written by hand against `include/libsignal.h`.
`Option<unsafe extern "C" fn(...)>` is the correct FFI-safe representation of a
nullable C function pointer.
