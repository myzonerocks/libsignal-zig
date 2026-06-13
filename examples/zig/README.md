# Zig example

Exercises the native Zig API — not the C FFI layer. Store implementations
follow the vtable pattern used by `SessionBuilder` and `SessionCipher`:
a concrete struct with function pointer fields cast through `*anyopaque`.

## Prerequisites

- Zig 0.16.0 (exactly — the API changes between minor versions)

No separate library build step is required. The example declares a path
dependency on `../..` in `build.zig.zon`, so `zig build` compiles both the
library and the example in one step.

## Run

```sh
zig build run
```

## What it tests

Each section prints `PASS` on success or returns an error that propagates
to `main`, which prints the error name and exits non-zero.

| Section | API exercised |
|---------|--------------|
| EC + XEdDSA | `KeyPair.generate`, `ecDH`, `xeddsa.sign`, `xeddsa.verify` |
| ML-KEM-1024 | `KyberKeyPair.generate`, `KyberKeyPair.encapsulate`, `KyberKeyPair.decapsulate` |
| X3DH + Double Ratchet | `SessionBuilder.processPreKeyBundle`, `SessionCipher.encrypt`, `SessionCipher.decryptPreKeyMessage`, `SessionCipher.decryptMessage` |
| Sender Keys | `GroupSessionBuilder.createSession`, `GroupSessionBuilder.processSession`, `GroupCipher.encrypt`, `GroupCipher.decrypt` |
| Sealed Sender V1 | `ServerCertificate`, `SenderCertificate`, `sealedSenderEncrypt`, `sealedSenderDecrypt` |
| Sealed Sender V2 | `sealedSenderEncryptV2`, `v2Dispatch`, `sealedSenderDecryptV2` |
| Fingerprints | `Fingerprint.compute`, `ScannableFingerprint.compare` |
| Username ZK proof | `username.hash`, `username.generateProof`, `username.verifyProof` |
| Account entropy pool | `AccountEntropyPool.generate`, `AccountEntropyPool.deriveSvrKey`, `AccountEntropyPool.deriveBackupKey`, `BackupKey.deriveMediaKey` |

## Notes

- Uses `std.heap.DebugAllocator` (renamed from `GeneralPurposeAllocator` in Zig 0.16).
- Sealed Sender V2 calls `v2Dispatch` from `src/sealed_sender.zig` directly,
  which models the server-side per-device dispatch step.
- `errdefer` is used instead of `defer` at ownership-transfer points (e.g.,
  where a struct is passed into another struct's constructor) to avoid
  double-free on error paths.
