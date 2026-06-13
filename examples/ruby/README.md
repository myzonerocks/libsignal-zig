# Ruby example

Exercises the full C API via the [`ffi`](https://github.com/ffi/ffi) gem.
Store structs are `FFI::Struct` subclasses passed with `.by_value`. Store
callbacks are `FFI::Function` objects. In-memory stores use Ruby hashes.

## Prerequisites

- Ruby 3.0+
- Bundler (`gem install bundler`)
- Library built: `zig build` from the repo root

## Run

```sh
bundle install
bundle exec ruby main.rb
```

## What it tests

Each section prints `PASS` on success or raises with the section name and
error code on failure.

| Section | API exercised |
|---------|--------------|
| EC + XEdDSA | `ec_keypair_generate`, `ec_dh`, `xeddsa_sign`, `xeddsa_verify` |
| ML-KEM-1024 | `kyber1024_keypair_generate`, `kyber1024_encaps`, `kyber1024_decaps` |
| X3DH + Double Ratchet | `ctx_new`, `process_prekey_bundle`, `encrypt`, `decrypt_prekey`, `decrypt` |
| Sender Keys | `group_create_session`, `group_process_session`, `group_encrypt`, `group_decrypt` |
| Sealed Sender V1 | `server_cert_serialize`, `sender_cert_serialize`, `sealed_sender_encrypt`, `sealed_sender_decrypt` |
| Sealed Sender V2 | `sealed_sender_encrypt_v2`, `sealed_sender_v2_dispatch`, `sealed_sender_decrypt_v2` |
| Fingerprints | `fingerprint_compute`, `fingerprint_compare` |
| Username ZK proof | `username_hash`, `username_proof`, `username_verify` |
| Account entropy pool | `account_entropy_pool_generate`, `account_entropy_derive_svr_key`, `account_entropy_derive_backup_key`, `backup_key_derive_media_key` |

## Memory contract

The session store and sender key store `load` callbacks allocate output
buffers with `FFI::MemoryPointer` and set `autorelease = false` so that
Ruby's GC does not free them — the library does, via `free()` after use.
All other output pointers returned by the library are freed via
`FFI::LibC.free` before the calling function returns.

## Notes

- `FFI::MemoryPointer#put` requires an explicit byte offset: `put(:uint32, 0, value)`.
  Omitting the offset raises `ArgumentError: wrong number of arguments`.
- `libsignal_ctx_new` and the group functions take store structs **by value**,
  not by pointer. Pass them as `StoreClass.by_value` instances.
