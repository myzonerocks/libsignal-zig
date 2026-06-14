# Go example

Exercises the full C API via CGo. All store callback structs, in-memory store
implementations, and test logic are written in C inside the CGo preamble. The
Go `main()` simply calls the C test functions in sequence. This avoids the CGo
restriction on calling Go functions from C callbacks while keeping all signal
protocol logic in one file.

## Prerequisites

- Go 1.18+
- A C compiler on `PATH` (CGo requirement — `clang` on macOS, `gcc` on Linux)
- Library built: `zig build` from the repo root

## Run

```sh
go run .
```

CGo locates the library and header using `${SRCDIR}`, which expands to the
directory containing `main.go` at compile time. No environment variables or
install steps are needed.

## What it tests

Each section prints `PASS` on success or calls `abort()` on failure.

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

`SignalOwnedBuffer` values returned by the library are freed with
`signal_free_buffer(buf.base, buf.length)` after use. Opaque handles are
destroyed with their matching `signal_*_destroy()` call. Store callbacks
serialize/deserialize opaque handles using library functions; the resulting
byte buffers are managed by the `kv_t` map and freed on cleanup.
