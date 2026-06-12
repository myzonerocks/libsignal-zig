# libsignal-zig

Libsignal-zig is written in Zig but exports a C-compatible API, which makes it usable from any language that can communicate with C APIs: Python, Swift, Rust, Go, Ruby, JavaScript (via WASM), and others.

**Zig version**: 0.16.0  
**Algorithms**: X3DH, PQXDH (ML-KEM-1024), Double Ratchet, XEdDSA, Sender Keys, Sealed Sender

---

## What's implemented

- **X3DH** key agreement (classic EC)
- **PQXDH** key agreement (EC + ML-KEM-1024 / Kyber), post-quantum forward secrecy
- **Double Ratchet** with full chain ratchet and DH ratchet
- **XEdDSA** signatures over X25519 keys (Signal's signing scheme)
- **Sender Keys** for group messaging
- **Sealed Sender** — anonymous sender envelopes
- **Pre-key bundles** — one-time and signed pre-keys, Kyber pre-keys
- **Fingerprints** — displayable (60-digit) and scannable (QR-code-ready protobuf)
- **Username hashes and proofs** — ZK-style username commitment scheme
- **AES-256-CBC / GCM / GCM-SIV** encryption utilities

---

## Build

```sh
zig build                  # produces zig-out/lib/libsignal.dylib and zig-out/include/libsignal.h
zig build -Doptimize=ReleaseFast
zig test src/integration_test.zig   
```

Build outputs:
- `zig-out/lib/libsignal.dylib` (or `.so` on Linux) — C-compatible shared library
- `zig-out/lib/libsignal_zig.a` — static library for Zig consumers
- `zig-out/include/libsignal.h` — C header

---

## Using from Zig

Add to `build.zig.zon`:

```zig
.dependencies = .{
    .libsignal_zig = .{ .path = "path/to/libsignal-zig" },
},
```

Import in `build.zig`:

```zig
const libsignal = b.dependency("libsignal_zig", .{});
exe.root_module.addImport("libsignal", libsignal.module("libsignal_zig"));
```

---

## Using from C (and any language with C FFI)

```c
#include "libsignal.h"
```

Link against `libsignal.dylib` / `libsignal.so`. All outputs allocated by the library use `malloc` and must be freed by the caller with `free()`.

---

## API

### Error codes

Every function returns `int`. Zero is success; negative values are errors:

| Code | Meaning |
|------|---------|
| 0    | OK |
| -1   | Invalid key |
| -2   | Invalid signature |
| -3   | Invalid message |
| -4   | Untrusted identity |
| -5   | Duplicate message |
| -6   | Not found |
| -7   | Internal error |

---

### EC keys and XEdDSA (C API)

```c
// Generate an X25519 key pair.
// pub_out: 33 bytes (0x05 prefix || 32-byte key)
// priv_out: 32 bytes
int libsignal_ec_keypair_generate(uint8_t pub_out[33], uint8_t priv_out[32]);

// X25519 Diffie-Hellman.
int libsignal_ec_dh(
    const uint8_t their_pub[33],
    const uint8_t our_priv[32],
    uint8_t shared_out[32]);

// XEdDSA sign and verify.
int libsignal_xeddsa_sign(
    const uint8_t priv[32],
    const uint8_t *msg, size_t msg_len,
    uint8_t sig_out[64]);

int libsignal_xeddsa_verify(
    const uint8_t pub[33],
    const uint8_t *msg, size_t msg_len,
    const uint8_t sig[64]);
```

### ML-KEM-1024 / Kyber (C API)

```c
int libsignal_kyber1024_keypair_generate(
    uint8_t pub_out[1568], uint8_t sec_out[3168]);

int libsignal_kyber1024_encaps(
    const uint8_t pub[1568],
    uint8_t ct_out[1568],   // send to key holder
    uint8_t ss_out[32]);    // shared secret

int libsignal_kyber1024_decaps(
    const uint8_t sec[3168],
    const uint8_t ct[1568],
    uint8_t ss_out[32]);
```

---

### Session protocol (C API)

Sessions are managed through an opaque context handle. Stores are provided as callback structs so the library imposes no storage requirements — use SQLite, a file, an in-memory map, or anything else.

#### 1. Implement the store callbacks

```c
// Example: in-memory session store backed by a hash map.
int my_load_session(void *ud, const char *name, uint32_t device_id,
                    uint8_t **out, size_t *out_len) {
    MyStore *s = ud;
    Bytes *b = hashmap_get(s->sessions, name, device_id);
    if (!b) return -6;  // not found
    *out = malloc(b->len);
    memcpy(*out, b->data, b->len);
    *out_len = b->len;
    return 0;
}

int my_store_session(void *ud, const char *name, uint32_t device_id,
                     const uint8_t *data, size_t len) {
    MyStore *s = ud;
    hashmap_put(s->sessions, name, device_id, data, len);
    return 0;
}

libsignal_session_store_t session_store = {
    .ud    = &my_store,
    .load  = my_load_session,
    .store = my_store_session,
};
```

#### 2. Create a context

```c
// One context per (local identity, remote peer) pair.
// Pass NULL for kyber_store to use X3DH only (no post-quantum ratchet).
libsignal_ctx_t *ctx = libsignal_ctx_new(
    "bob",          // remote peer name
    1,              // remote device id
    session_store,
    identity_store,
    pre_key_store,
    signed_pre_key_store,
    NULL            // or &kyber_store for PQXDH
);
```

#### 3. Process a pre-key bundle (Alice's side)

```c
// Pass pre_key_id=0 and pre_key_pub=NULL if the bundle has no one-time pre-key.
// Pass kyber_pre_key_id=0 and NULL pointers for X3DH only.
int rc = libsignal_process_prekey_bundle(
    ctx,
    bob_registration_id,
    pre_key_id, pre_key_pub,
    signed_pre_key_id, signed_pre_key_pub, signed_pre_key_sig,
    bob_identity_pub,
    0, NULL, NULL   // no Kyber
);
```

#### 4. Encrypt

```c
uint8_t *ct;
size_t ct_len;
int msg_type;

int rc = libsignal_encrypt(ctx,
    (uint8_t *)"hello", 5,
    &ct, &ct_len, &msg_type);

// msg_type == 3 (LIBSIGNAL_MSG_PREKEY) for the first message;
// msg_type == 2 (LIBSIGNAL_MSG_WHISPER) for subsequent messages.
// ...send ct[0..ct_len] to Bob...
free(ct);
```

#### 5. Decrypt (Bob's side)

```c
uint8_t *pt;
size_t pt_len;

// First message from a new session:
int rc = libsignal_decrypt_prekey(ctx, ct, ct_len, &pt, &pt_len);

// Subsequent messages:
// int rc = libsignal_decrypt(ctx, ct, ct_len, &pt, &pt_len);

printf("%.*s\n", (int)pt_len, pt);
free(pt);
```

#### 6. Free the context

```c
libsignal_ctx_free(ctx);
```

---

### Session protocol (Zig API)

```zig
const signal = @import("libsignal");

// Bob prepares keys and builds a bundle.
const spk = try signal.KeyPair.generate();
const spk_sig = try bob_ikp.private_key.calculateSignature(&spk.public_key.serialize());
const bundle = signal.PreKeyBundle.new(
    reg_id, device_id,
    @as(?u32, opk_id), @as(?signal.PublicKey, opk_pub),
    spk_id, spk.public_key, spk_sig,
    bob_identity_key,
    null, null, null,  // no Kyber for classic X3DH
);

// Alice processes the bundle.
var builder = signal.SessionBuilder.init(
    allocator, bob_address,
    alice_session_store, alice_pre_key_store,
    alice_signed_pre_key_store, alice_identity_store, null,
);
try builder.processPreKeyBundle(bundle);

// Alice encrypts.
var cipher = signal.SessionCipher.init(
    allocator, bob_address,
    alice_session_store, alice_pre_key_store,
    alice_signed_pre_key_store, alice_identity_store, null,
);
var ct = try cipher.encrypt("hello bob!");
defer ct.deinit();
// ct.message_type == .pre_key for the first message

// Bob decrypts.
var bob_cipher = signal.SessionCipher.init(
    allocator, alice_address,
    bob_session_store, bob_pre_key_store,
    bob_signed_pre_key_store, bob_identity_store, null,
);
const plaintext = try bob_cipher.decryptPreKeyMessage(ct.serialized);
defer allocator.free(plaintext);
```

---

### PQXDH (post-quantum sessions)

Add a Kyber pre-key to Bob's bundle and pass a non-null `kyber_store` to `libsignal_ctx_new`:

```zig
// Zig: generate and sign a Kyber pre-key.
const kpk = try signal.KyberKeyPair.generate();
const kpk_sig = try bob_ikp.private_key.calculateSignature(&kpk.public_key_bytes);

const bundle = signal.PreKeyBundle.new(
    reg_id, device_id,
    opk_id, opk_pub,
    spk_id, spk_pub, spk_sig,
    bob_identity_key,
    @as(?u32, kyber_id),
    @as(?[signal.KyberKeyPair.KYBER_PUBLIC_KEY_LENGTH]u8, kpk.public_key_bytes),
    @as(?[signal.SIGNATURE_LENGTH]u8, kpk_sig),
);
```

Everything else is identical to X3DH. The Kyber encapsulation and ML-KEM shared secret are folded into the session key derivation automatically.

---

### Stores (Zig)

Each store is a `{ ptr: *anyopaque, vtable: *const VTable }` pair. Implement the vtable functions for your storage backend and wrap them:

```zig
const MySessionStore = struct {
    fn loadSession(ptr: *anyopaque, addr: *const signal.ProtocolAddress) anyerror!?signal.SessionRecord {
        const self: *MySessionStore = @ptrCast(@alignCast(ptr));
        const bytes = self.db.get(addr) orelse return null;
        return signal.SessionRecord.deserialize(allocator, bytes);
    }
    fn storeSession(ptr: *anyopaque, addr: *const signal.ProtocolAddress, record: *const signal.SessionRecord) anyerror!void {
        const self: *MySessionStore = @ptrCast(@alignCast(ptr));
        const bytes = try record.serialize();
        try self.db.put(addr, bytes);
    }
    const vtable = signal.SessionStore.VTable{
        .loadSession = loadSession,
        .storeSession = storeSession,
    };
    fn store(self: *MySessionStore) signal.SessionStore {
        return .{ .ptr = self, .vtable = &vtable };
    }
};
```

Required stores: `IdentityKeyStore`, `SessionStore`, `PreKeyStore`, `SignedPreKeyStore`.  
Optional: `KyberPreKeyStore` (PQXDH), `SenderKeyStore` (group messaging).

---

### Group messaging (Zig)

```zig
const skn = signal.SenderKeyName{
    .group_id = "my-group",
    .sender   = signal.ProtocolAddress{ .name = "alice", .device_id = 1 },
};

// Alice creates the distribution message once per group.
var builder = signal.GroupSessionBuilder.init(allocator, sender_key_store);
const dist_msg = try builder.createSession(&skn);
defer allocator.free(dist_msg.serialized);

// Each member processes it (once per member).
var member_builder = signal.GroupSessionBuilder.init(allocator, member_key_store);
try member_builder.processSession(&skn, &dist_msg);

// Alice encrypts to the group.
var group_cipher = signal.GroupCipher.init(allocator, sender_key_store);
const encrypted = try group_cipher.encrypt(&skn, "hello group!");
defer allocator.free(encrypted);

// Each member decrypts.
var member_cipher = signal.GroupCipher.init(allocator, member_key_store);
const plaintext = try member_cipher.decrypt(&skn, encrypted);
defer allocator.free(plaintext);
```

---

### Fingerprints

```zig
// Displayable: 60 decimal digits, shown to users for out-of-band comparison.
const display = try signal.computeDisplayableFingerprint(
    allocator,
    local_identity_key,  "+15551234567",
    remote_identity_key, "+15559876543",
);
defer allocator.free(display); // 60 ASCII digit characters

// Scannable: protobuf bytes, compare via QR code.
const sf = try signal.ScannableFingerprint.compute(
    allocator,
    local_identity_key,  local_stable_id,
    remote_identity_key, remote_stable_id,
);
const sf_bytes = try sf.serialize();
defer allocator.free(sf_bytes);
const matches = try sf.compareTo(their_sf_bytes);
```

---
MIT