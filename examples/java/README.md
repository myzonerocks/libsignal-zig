# Java example

Exercises the full C API via [JNA](https://github.com/java-native-access/jna)
(Java Native Access). Store structs are modelled as `Structure.ByValue`
subclasses with `Callback` fields for each function pointer. In-memory stores
use `HashMap<String, byte[]>`.

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
section name and error code on failure.

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

JNA `Memory` objects are managed by JNA's garbage collector and must not be
freed by C. The session store and sender key store `load` callbacks therefore
use `Native.malloc` to allocate output buffers, which the library frees with
the system `free()` after use. All other output pointers returned by the
library are read into Java `byte[]` and freed via `Native.free` before the
calling function returns.
