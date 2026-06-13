# libsignal-zig

libsignal-zig is a Zig implementation of the Signal Protocol. It exports a C-compatible API, which makes it usable from any language that can communicate with C APIs: Go, Swift, Rust, Python, Ruby, and others.

**Zig version**: 0.16.0
**Status**: All core protocol operations are implemented and battle-tested end-to-end via a Go CGo test suite ([`proc/`](proc/)). Suitable for production use in projects that need Signal Protocol primitives without pulling in the official Rust/Java libsignal.

## Why?

The official Signal client library ([libsignal](https://github.com/signalapp/libsignal)) is written in Rust. It is large, has a significant build toolchain, and its C API surface is tied to the Rust ecosystem.

libsignal-zig is a clean-room Zig implementation. It has zero runtime dependencies beyond the OS, cross-compiles to any target Zig supports, and builds with a single `zig build`. If you are building in Zig or want a portable, auditable Signal Protocol library without a Rust toolchain, this is that option.

## What's implemented

- **X3DH** — Extended Triple Diffie-Hellman key agreement
- **PQXDH** — Post-quantum X3DH with ML-KEM-1024 (Kyber), post-quantum forward secrecy
- **Double Ratchet** — Full session cipher with chain and DH ratchet
- **XEdDSA** — Signal's signing scheme over X25519 keys
- **Sender Keys** — Group messaging with sender key distribution and ratcheting
- **Sealed Sender V1** — Anonymous sender envelopes (AES-256-CBC, HMAC-SHA256)
- **Sealed Sender V2** — Multi-recipient anonymous sender (AES-256-GCM-SIV, per-recipient ECDH)
- **Pre-key bundles** — One-time pre-keys, signed pre-keys, Kyber pre-keys
- **Fingerprints** — 60-digit displayable safety numbers and serializable scannable fingerprints
- **Username hashes and ZK proofs** — Ristretto255-based username commitment scheme
- **Account entropy pool** — Signal's backup key derivation (SVR key, backup key, media key)

## Build

```sh
zig build                           # debug
```

Or a more optimized one

```sh
zig build -Doptimize=ReleaseFast     # optimized
```

Pick one.

Build outputs:

- `zig-out/lib/libsignal.dylib` (`.so` on Linux) — shared library for C FFI consumers
- `zig-out/lib/libsignal_zig.a` — static library for Zig consumers
- `include/libsignal.h` — C header

No build dependencies beyond Zig itself.

## Example (C)

The example below establishes a Signal session, encrypts a message, and decrypts it.

```c
#include "libsignal.h"
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    // Bob generates identity and signed pre-key.
    uint8_t bob_id_pub[33], bob_id_priv[32];
    libsignal_ec_keypair_generate(bob_id_pub, bob_id_priv);

    uint8_t spk_pub[33], spk_priv[32], spk_sig[64];
    libsignal_ec_keypair_generate(spk_pub, spk_priv);
    libsignal_xeddsa_sign(bob_id_priv, spk_pub, 33, spk_sig);

    // Alice creates a context targeting Bob and processes his pre-key bundle.
    libsignal_ctx_t *alice = libsignal_ctx_new(
        "bob", 1, alice_session_store, alice_identity_store,
        alice_pre_key_store, alice_signed_pre_key_store, NULL);

    libsignal_process_prekey_bundle(alice, bob_reg_id,
        0, NULL,               // no one-time pre-key
        1, spk_pub, spk_sig,   // signed pre-key id=1
        bob_id_pub,
        0, NULL, NULL);        // no Kyber

    // Alice encrypts. msg_type == LIBSIGNAL_MSG_PREKEY for the first message.
    uint8_t *ct; size_t ct_len; int msg_type;
    libsignal_encrypt(alice, (uint8_t *)"hello", 5, &ct, &ct_len, &msg_type);

    // Bob decrypts.
    libsignal_ctx_t *bob = libsignal_ctx_new(
        "alice", 1, bob_session_store, bob_identity_store,
        bob_pre_key_store, bob_signed_pre_key_store, NULL);

    uint8_t *pt; size_t pt_len;
    libsignal_decrypt_prekey(bob, ct, ct_len, &pt, &pt_len);
    printf("%.*s\n", (int)pt_len, pt);  // "hello"

    free(ct); free(pt);
    libsignal_ctx_free(alice);
    libsignal_ctx_free(bob);
    return 0;
}
```

Store callbacks (session, identity, pre-key, signed pre-key) are plain function pointer structs. The library imposes no storage mechanism — use SQLite, a hash map, or anything else. See `include/libsignal.h` for the full callback signatures and all other API functions.

## Example (Zig)

```zig
const signal = @import("libsignal_zig");

// Bob prepares a signed pre-key.
const bob_ikp = try signal.KeyPair.generate();
const spk = try signal.KeyPair.generate();
const spk_sig = try bob_ikp.private_key.calculateSignature(&spk.public_key.serialize());

const bundle = signal.PreKeyBundle.new(
    bob_reg_id, device_id,
    null, null,                                              // no one-time pre-key
    1, spk.public_key, spk_sig,
    signal.IdentityKey.fromPublicKey(bob_ikp.public_key),
    null, null, null,                                        // no Kyber
);

// Alice processes the bundle and encrypts.
var builder = signal.SessionBuilder.init(allocator, bob_address, ...stores...);
try builder.processPreKeyBundle(bundle);

var cipher = signal.SessionCipher.init(allocator, bob_address, ...stores...);
var ct = try cipher.encrypt("hello bob!");
defer ct.deinit();

// Bob decrypts.
var bob_cipher = signal.SessionCipher.init(allocator, alice_address, ...stores...);
const plaintext = try bob_cipher.decryptPreKeyMessage(ct.serialized);
defer allocator.free(plaintext);
```

## Installation (Zig)

Find the commit SHA you want to pin on GitHub (e.g. `a1b2c3d`), then run:

```sh
zig fetch --save https://github.com/myzonerocks/libsignal-zig/archive/a1b2c3d.tar.gz
```

`zig fetch` downloads the archive, computes the content hash, and writes both into `build.zig.zon` automatically. The result looks like:

```zig
// build.zig.zon
.dependencies = .{
    .libsignal_zig = .{
        .url = "https://github.com/myzonerocks/libsignal-zig/archive/a1b2c3d.tar.gz",
        .hash = "122099f7d5b02e2ee5c38b0a55a85c1b3f99db80e7e9c3e1c2e2b0e9b5d4a1f3c8",
    },
},
```

Then wire it up in `build.zig`:

```zig
const libsignal = b.dependency("libsignal_zig", .{ .target = target, .optimize = optimize });
exe.root_module.addImport("libsignal_zig", libsignal.module("libsignal_zig"));
```

## Documentation

The C API is fully documented in [`include/libsignal.h`](include/libsignal.h) — every function, struct, and constant has a doc comment covering parameters, return values, and memory ownership.

The Zig API is documented in source comments. Entry points worth reading:

- `src/root.zig` — public Zig API surface
- `src/session_builder.zig` — X3DH and PQXDH session establishment
- `src/session_cipher.zig` — Double Ratchet encrypt/decrypt
- `src/group_session_builder.zig`, `src/group_cipher.zig` — Sender Key group messaging
- `src/sealed_sender.zig` — anonymous sender envelopes (V1 and V2)
- `src/fingerprint.zig` — safety number fingerprints
- `src/username.zig` — username hash and ZK proof
- `src/account_keys.zig` — account entropy pool and backup key derivation

## Tests

```sh
# Zig unit and integration tests
zig test src/integration_test.zig
```

```sh
# Go CGo battle-test — links against the compiled .dylib and exercises every 
# exported C function with real encrypt/decrypt roundtrips.
cd proc && go run .
```

## Memory contract

All output buffers written by the C API are allocated with `malloc` and must be freed by the caller with `free()`. The library never retains output pointers after returning.

Store callbacks that return heap-allocated data (session load, sender key load) must allocate with `malloc`. The library calls `free()` on them after use.

## License

MIT
