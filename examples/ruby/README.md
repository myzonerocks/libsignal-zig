# Ruby example

Exercises the full C API via the [`ffi`](https://github.com/ffi/ffi) gem.
`Signal{Mut,Const}Pointer<T>` wrappers are treated as bare `:pointer` values
(ABI-equivalent on 64-bit). `SignalBorrowedBuffer` and `SignalOwnedBuffer` are
declared as `FFI::Struct` subclasses passed `.by_value`. Store callbacks are
`FFI::Function` objects kept alive as instance variables. In-memory stores use
Ruby hashes.

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
error message on failure.

| Section | API exercised |
|---------|--------------|
| EC + XEdDSA | `signal_privatekey_generate`, `signal_privatekey_agree`, `signal_privatekey_sign`, `signal_publickey_verify` |
| ML-KEM-1024 | `signal_kyber_key_pair_generate`, `signal_kyber_public_key_serialize`, `signal_kyber_secret_key_serialize` |
| X3DH + PQXDH + Double Ratchet | `signal_pre_key_bundle_new`, `signal_process_prekey_bundle`, `signal_encrypt_message`, `signal_decrypt_pre_key_message`, `signal_decrypt_message` |
| Sender Keys | `signal_sender_key_distribution_message_create`, `signal_process_sender_key_distribution_message`, `signal_group_encrypt_message`, `signal_group_decrypt_message` |
| Fingerprints | `signal_fingerprint_new`, `signal_fingerprint_scannable_encoding`, `signal_fingerprint_compare` |
| Username ZK proof | `signal_username_hash`, `signal_username_proof`, `signal_username_verify` |
| Account entropy pool | `signal_account_entropy_pool_generate`, `signal_account_entropy_pool_derive_svr_key`, `signal_account_entropy_pool_derive_backup_key`, `signal_backup_key_derive_media_encryption_key` |

## Memory contract

`SignalOwnedBuffer` values returned by the library are read into Ruby strings
and freed with `signal_free_buffer` before the calling method returns. Opaque
handles are destroyed with `signal_*_destroy`. Store callbacks call back into
the library to serialize/deserialize opaque handles; the resulting byte strings
are stored as Ruby `String` objects in plain hashes — no manual memory
management needed for the store backing data.

## Notes

- Store structs are modelled as raw `FFI::MemoryPointer.new(:pointer, N)`
  arrays rather than `FFI::Struct` subclasses; callback function pointers are
  filled in directly and the array pointer is passed to session functions.
- Calling back into `Sig.*` library functions from within an `FFI::Function`
  callback is safe — the C→Ruby→C call chain is synchronous.
