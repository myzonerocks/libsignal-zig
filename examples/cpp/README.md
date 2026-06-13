# C++ example

Exercises the full C API via a direct `#include` of `libsignal.h`. No
generated bindings, no wrapper library — just C++ calling C. In-memory stores
are implemented with `std::map`.

## Prerequisites

- C++17 compiler (`clang++` or `g++`)
- `make`
- Library built: `zig build` from the repo root

## Run

```sh
make run
```

`make` compiles `main.cpp` and links against `../../zig-out/lib/libsignal.dylib`
(`.so` on Linux). The `rpath` is set at link time so the binary finds the
library without any environment variables.

## What it tests

Each function in the test suite prints `PASS` on success or aborts with the
error code and section name on failure.

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
