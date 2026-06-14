# libsignal-zig

libsignal-zig is a Zig implementation of the Signal Protocol. It exports a C-compatible API, which makes it usable from any language that can communicate with C APIs: Go, Swift, Rust, Python, Ruby, and others.

**Zig version**: 0.16.0

**Status**: Implemented. End-to-end coverage across multiple languages in [`examples/`](examples/).

## Why?

[libsignal](https://github.com/signalapp/libsignal) is a complete, production-proven implementation. If you are building a Signal client and already have a Rust toolchain, use it.

libsignal-zig exists for a different set of constraints:

- **No Rust toolchain.** `zig build` is the only build step. No cargo, no rustup, no cross-compilation wrappers.
- **Cross-compilation is first-class.** Zig targets any supported platform from any host in a single command, with no additional toolchain configuration.
- **Native Zig integration.** Add it as a standard `b.dependency()` — no FFI boundary, no generated bindings, no cgo.
- **Auditable.** The entire implementation is pure Zig against the standard library. No vendored crates, no generated code.

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

Pick one.

```sh
zig build                         # debug
```

```sh
zig build -Doptimize=ReleaseFast  # optimized
```

Build outputs:

- `zig-out/lib/libsignal_ffi.dylib` (`.so` on Linux) — shared library for C FFI consumers
- `zig-out/lib/libsignal_zig.a` — static library for Zig consumers
- `include/signal_ffi.h` — C header

No build dependencies beyond Zig itself.

## Example (C)

The example below establishes a Signal session, encrypts a message, and decrypts it.

```c
#include "signal_ffi.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* NULL return = success; non-NULL = caller-owned error, must be freed. */
#define MUST(call) do { SignalFfiError *_e = (call); \
    if (_e) { const char *m = NULL; signal_error_get_message(&m, _e); \
               fprintf(stderr, "FAIL: %s\n", m); signal_error_free(_e); abort(); } \
} while(0)

int main(void) {
    /* ── Bob: generate identity key pair ─────────────────────────────────── */
    SignalMutPointerSignalPrivateKey bob_id_priv = {NULL};
    SignalMutPointerSignalPublicKey  bob_id_pub  = {NULL};
    MUST(signal_privatekey_generate(&bob_id_priv));
    MUST(signal_privatekey_get_public_key(&bob_id_pub,
             (SignalConstPointerSignalPrivateKey){bob_id_priv.raw}));

    /* ── Bob: generate signed pre-key and sign it with his identity key ───── */
    SignalMutPointerSignalPrivateKey spk_priv = {NULL};
    SignalMutPointerSignalPublicKey  spk_pub  = {NULL};
    MUST(signal_privatekey_generate(&spk_priv));
    MUST(signal_privatekey_get_public_key(&spk_pub,
             (SignalConstPointerSignalPrivateKey){spk_priv.raw}));

    SignalOwnedBuffer spk_pub_bytes = {0};
    MUST(signal_publickey_serialize(&spk_pub_bytes,
             (SignalConstPointerSignalPublicKey){spk_pub.raw}));
    SignalOwnedBuffer spk_sig = {0};
    MUST(signal_privatekey_sign(&spk_sig,
             (SignalConstPointerSignalPrivateKey){bob_id_priv.raw},
             (SignalBorrowedBuffer){spk_pub_bytes.base, spk_pub_bytes.length}));

    /* ── Build Bob's pre-key bundle (no one-time pre-key, no Kyber here) ─── */
    SignalMutPointerSignalPreKeyBundle bundle = {NULL};
    MUST(signal_pre_key_bundle_new(
        &bundle,
        /*reg_id*/1, /*device_id*/1,
        /*opk_id*/0, /*opk*/NULL,                      /* no one-time pre-key */
        /*spk_id*/1, (SignalConstPointerSignalPublicKey){spk_pub.raw},
        (SignalBorrowedBuffer){spk_sig.base, spk_sig.length},
        (SignalConstPointerSignalPublicKey){bob_id_pub.raw},
        /*kpk_id*/0, /*kpk*/NULL, /*kpk_sig*/{NULL,0}  /* no Kyber */
    ));

    /* ── Alice: process bundle → session established in alice's stores ───── */
    SignalProtocolAddress *bob_addr = NULL;
    MUST(signal_address_new(&bob_addr, "bob", 3, 1));

    /* (alice_sess, alice_id, alice_pk, alice_spk are SignalXxxStore structs
     *  backed by your storage; see examples/c/main.c for a full implementation) */
    MUST(signal_process_prekey_bundle(
        (SignalConstPointerSignalPreKeyBundle){bundle.raw},
        bob_addr, alice_sess, alice_id, alice_pk, alice_spk, NULL));

    /* ── Alice encrypts (first message is a PreKey message, type 3) ────────── */
    SignalMutPointerCiphertextMessage ct = {NULL};
    uint8_t plaintext[] = "hello bob!";
    MUST(signal_encrypt_message(
        &ct, (SignalBorrowedBuffer){plaintext, sizeof plaintext - 1},
        bob_addr, alice_sess, alice_id));

    SignalOwnedBuffer ct_bytes = {0};
    MUST(signal_ciphertext_message_serialize(&ct_bytes,
             (SignalConstPointerCiphertextMessage){ct.raw}));

    /* ── Bob decrypts ─────────────────────────────────────────────────────── */
    SignalMutPointerPreKeySignalMessage pkmsg = {NULL};
    MUST(signal_pre_key_signal_message_deserialize(
        &pkmsg, (SignalBorrowedBuffer){ct_bytes.base, ct_bytes.length}));

    SignalProtocolAddress *alice_addr = NULL;
    MUST(signal_address_new(&alice_addr, "alice", 5, 1));

    SignalOwnedBuffer pt = {0};
    MUST(signal_decrypt_pre_key_message(
        &pt, (SignalConstPointerPreKeySignalMessage){pkmsg.raw},
        alice_addr, bob_sess, bob_id, bob_pk, bob_spk, NULL));

    printf("%.*s\n", (int)pt.length, pt.base);  /* "hello bob!" */

    /* ── Cleanup ──────────────────────────────────────────────────────────── */
    signal_free_buffer(pt.base, pt.length);
    signal_free_buffer(ct_bytes.base, ct_bytes.length);
    signal_free_buffer(spk_pub_bytes.base, spk_pub_bytes.length);
    signal_free_buffer(spk_sig.base, spk_sig.length);
    signal_pre_key_signal_message_destroy(pkmsg);
    signal_ciphertext_message_destroy(ct);
    signal_pre_key_bundle_destroy(bundle);
    signal_publickey_destroy(spk_pub);
    signal_privatekey_destroy(spk_priv);
    signal_publickey_destroy(bob_id_pub);
    signal_privatekey_destroy(bob_id_priv);
    signal_address_free(bob_addr);
    signal_address_free(alice_addr);
    return 0;
}
```

Every `signal_*` function returns `NULL` on success or a caller-owned `SignalFfiError*` on failure. Opaque handles are destroyed with their matching `signal_*_destroy()` call. Store callbacks (session, identity, pre-key, signed pre-key, Kyber pre-key, sender key) are plain C function-pointer structs — the library imposes no storage mechanism. See `include/signal_ffi.h` for the full API and `examples/c/main.c` for a complete working implementation with all store callbacks.

## Example (Zig)

```zig
const signal = @import("libsignal_zig");

// Bob prepares a signed pre-key.
const bob_ikp = try signal.KeyPair.generate();
const spk = try signal.KeyPair.generate();
const spk_pub_bytes = spk.public_key.serialize();
const spk_sig = try bob_ikp.private_key.calculateSignature(&spk_pub_bytes);

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

**From a tag** — no SHA needed, just the tag name:

```sh
zig fetch --save https://github.com/myzonerocks/libsignal-zig/archive/refs/tags/v1.1.0.tar.gz
```

`zig fetch` downloads the archive, computes the content hash, and writes both fields into `build.zig.zon` automatically.

**From a local checkout** — no fetch at all, just point at the path:

```zig
// build.zig.zon
.dependencies = .{
    .libsignal_zig = .{
        .path = "../libsignal-zig",
    },
},
```

Either way, wire it up in `build.zig` the same:

```zig
const libsignal = b.dependency("libsignal_zig", .{ .target = target, .optimize = optimize });
exe.root_module.addImport("libsignal_zig", libsignal.module("libsignal_zig"));
```

## Documentation

The C API is fully documented in [`include/signal_ffi.h`](include/signal_ffi.h) — every function, struct, and constant has a doc comment covering parameters, return values, and memory ownership.

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

[`examples/`](examples/) contains end-to-end test suites for C, C++, Go, Java, Ruby, Rust, and Zig, each exercising every protocol operation. See [`examples/README.md`](examples/README.md) for prerequisites and run instructions per language.

## Memory contract

- **Opaque handles** returned through `Signal{Mut,Const}Pointer<T>` out-parameters are owned by the caller and must be destroyed with the matching `signal_*_destroy()` function.
- **`SignalOwnedBuffer`** values returned by the library are owned by the caller and must be freed with `signal_free_buffer(buf.base, buf.length)`.
- **`SignalBorrowedBuffer`** values passed _into_ the library are borrowed — the library does not retain or free them.
- **`SignalFfiError*`** returned on failure is owned by the caller and must be freed with `signal_error_free()` after inspecting the message.
- The library never retains any pointer after a function returns.

## License

MIT
