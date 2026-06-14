# C++ example

Exercises the full C API via a direct `#include` of `signal_ffi.h`. No
generated bindings, no wrapper library — just C++ calling C. In-memory stores
are implemented with `std::map<std::string, std::vector<uint8_t>>`.

## Prerequisites

- C++17 compiler (`clang++` or `g++`)
- `make`
- Library built: `zig build` from the repo root

## Run

```sh
make run
```

`make` compiles `main.cpp` and links against `../../zig-out/lib/libsignal_ffi.dylib`
(`.so` on Linux). The `rpath` is set at link time so the binary finds the
library without any environment variables.

## What it tests

Each function in the test suite prints `PASS` on success or aborts with the
error message and section name on failure.

| Section | API exercised |
|---------|--------------|
| EC + XEdDSA | `signal_privatekey_generate`, `signal_privatekey_agree`, `signal_privatekey_sign`, `signal_publickey_verify` |
| ML-KEM-1024 | `signal_kyber_key_pair_generate`, `signal_kyber_public_key_serialize`, `signal_kyber_secret_key_serialize` |
| X3DH + PQXDH + Double Ratchet | `signal_pre_key_bundle_new`, `signal_process_prekey_bundle`, `signal_encrypt_message`, `signal_decrypt_pre_key_message`, `signal_decrypt_message` |
| Sender Keys | `signal_sender_key_distribution_message_create`, `signal_process_sender_key_distribution_message`, `signal_group_encrypt_message`, `signal_group_decrypt_message` |
| Fingerprints | `signal_fingerprint_new`, `signal_fingerprint_scannable_encoding`, `signal_fingerprint_compare` |
| Username ZK proof | `signal_username_hash`, `signal_username_proof`, `signal_username_verify` |
| Account entropy pool | `signal_account_entropy_pool_generate`, `signal_account_entropy_pool_derive_svr_key`, `signal_account_entropy_pool_derive_backup_key`, `signal_backup_key_derive_media_encryption_key` |
