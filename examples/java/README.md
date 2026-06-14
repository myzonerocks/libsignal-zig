# Java example

Exercises the full C API via [JNA](https://github.com/java-native-access/jna)
(Java Native Access). `Signal{Mut,Const}Pointer<T>` wrappers are declared as
bare `Pointer` (ABI-equivalent on 64-bit). `SignalBorrowedBuffer` and
`SignalOwnedBuffer` are modelled as `Structure.ByValue` subclasses.
Store structs are raw `Memory` pointer arrays filled with JNA callback function
pointers obtained via `CallbackReference.getFunctionPointer()`. In-memory
stores use `HashMap<String, byte[]>`.

## Prerequisites

- Java 17 or later
- `curl` (used by `run.sh` to download JNA on first run)
- Library built: `zig build` from the repo root

## Run

```sh
./run.sh
```

On first run, `run.sh` downloads `jna-5.14.0.jar` into `lib/` and compiles
`Main.java` into `out/`. Subsequent runs skip the download and recompile.

## What it tests

Each section prints `PASS` on success or throws `RuntimeException` with the
section name and error message on failure.

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

`SignalOwnedBuffer.ByRef` values returned by the library are read into Java
`byte[]` and freed with `signal_free_buffer` before the calling method returns.
Opaque handles (returned as `Pointer` out-parameters) are destroyed with
`signal_*_destroy`. Store callbacks call back into the library to
serialize/deserialize opaque handles; JNA callbacks can call other library
methods synchronously without restriction.
