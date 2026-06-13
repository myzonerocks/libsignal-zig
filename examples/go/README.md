# Go example

Exercises the full C API via CGo. The store callback structs and in-memory
store implementations are written in C inside the CGo preamble; the test
logic is in Go. This mirrors production usage where store implementations
live close to the application's persistence layer.

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

Each section prints `PASS` on success or calls `log.Fatalf` on failure.

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

The session store and sender key store `load` callbacks allocate output buffers
with `malloc`. The library calls `free()` on those pointers after use. All
other output pointers returned by the library are also `malloc`'d and freed
by the caller via `C.free`.
