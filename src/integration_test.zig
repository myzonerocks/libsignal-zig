// Integration tests that prove the full Signal Protocol flows work end-to-end.
// Run with: zig test src/integration_test.zig
const std = @import("std");
const mem = std.mem;
const ally = std.heap.smp_allocator;

const curve = @import("curve.zig");
const identity = @import("identity.zig");
const address = @import("address.zig");
const storage = @import("storage.zig");
const bundle_mod = @import("state/bundle.zig");
const session_record_mod = @import("state/session_record.zig");
const pre_key_record_mod = @import("state/pre_key_record.zig");
const signed_pre_key_record_mod = @import("state/signed_pre_key_record.zig");
const kyber_pre_key_record_mod = @import("state/kyber_pre_key_record.zig");
const session_builder_mod = @import("session_builder.zig");
const session_cipher_mod = @import("session_cipher.zig");
const group_session_builder_mod = @import("group_session_builder.zig");
const group_cipher_mod = @import("group_cipher.zig");
const username_mod = @import("username.zig");
const fingerprint_mod = @import("fingerprint.zig");
const aes_mod = @import("aes.zig");
const xeddsa = @import("xeddsa.zig");
const rnd = @import("random.zig");
const err = @import("error.zig");

// ---- In-Memory Store Implementations ----

const MemIdentityStore = struct {
    key_pair: identity.IdentityKeyPair,
    reg_id: u32,
    trusted: std.StringHashMap(identity.IdentityKey),
    allocator: mem.Allocator,

    fn init(allocator: mem.Allocator) !MemIdentityStore {
        return .{
            .key_pair = try identity.IdentityKeyPair.generate(),
            .reg_id = 12345,
            .trusted = std.StringHashMap(identity.IdentityKey).init(allocator),
            .allocator = allocator,
        };
    }

    fn deinit(self: *MemIdentityStore) void {
        self.trusted.deinit();
    }

    fn getIdentityKeyPair(ptr: *anyopaque) anyerror!identity.IdentityKeyPair {
        const self: *MemIdentityStore = @ptrCast(@alignCast(ptr));
        return self.key_pair;
    }
    fn getLocalRegistrationId(ptr: *anyopaque) anyerror!u32 {
        const self: *MemIdentityStore = @ptrCast(@alignCast(ptr));
        return self.reg_id;
    }
    fn saveIdentity(ptr: *anyopaque, addr: *const address.ProtocolAddress, key: identity.IdentityKey) anyerror!bool {
        const self: *MemIdentityStore = @ptrCast(@alignCast(ptr));
        const key_str = try std.fmt.allocPrint(self.allocator, "{s}:{d}", .{ addr.name, addr.device_id });
        defer self.allocator.free(key_str);
        try self.trusted.put(try self.allocator.dupe(u8, key_str), key);
        return true;
    }
    fn isTrustedIdentity(_: *anyopaque, _: *const address.ProtocolAddress, _: identity.IdentityKey, _: storage.Direction) anyerror!bool {
        return true; // trust all for tests
    }
    fn getIdentity(ptr: *anyopaque, addr: *const address.ProtocolAddress) anyerror!?identity.IdentityKey {
        const self: *MemIdentityStore = @ptrCast(@alignCast(ptr));
        const key_str = try std.fmt.allocPrint(self.allocator, "{s}:{d}", .{ addr.name, addr.device_id });
        defer self.allocator.free(key_str);
        return self.trusted.get(key_str);
    }

    const vtable = storage.IdentityKeyStore.VTable{
        .getIdentityKeyPair = getIdentityKeyPair,
        .getLocalRegistrationId = getLocalRegistrationId,
        .saveIdentity = saveIdentity,
        .isTrustedIdentity = isTrustedIdentity,
        .getIdentity = getIdentity,
    };

    fn store(self: *MemIdentityStore) storage.IdentityKeyStore {
        return .{ .ptr = self, .vtable = &vtable };
    }
};

const MemSessionStore = struct {
    sessions: std.StringHashMap([]u8),
    allocator: mem.Allocator,

    fn init(allocator: mem.Allocator) MemSessionStore {
        return .{ .sessions = std.StringHashMap([]u8).init(allocator), .allocator = allocator };
    }
    fn deinit(self: *MemSessionStore) void {
        var it = self.sessions.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.sessions.deinit();
    }

    fn loadSession(ptr: *anyopaque, addr: *const address.ProtocolAddress) anyerror!?session_record_mod.SessionRecord {
        const self: *MemSessionStore = @ptrCast(@alignCast(ptr));
        const k = try std.fmt.allocPrint(self.allocator, "{s}:{d}", .{ addr.name, addr.device_id });
        defer self.allocator.free(k);
        const bytes = self.sessions.get(k) orelse return null;
        return try session_record_mod.SessionRecord.deserialize(self.allocator, bytes);
    }
    fn storeSession(ptr: *anyopaque, addr: *const address.ProtocolAddress, record: *const session_record_mod.SessionRecord) anyerror!void {
        const self: *MemSessionStore = @ptrCast(@alignCast(ptr));
        const k = try std.fmt.allocPrint(self.allocator, "{s}:{d}", .{ addr.name, addr.device_id });
        const bytes = try record.serialize();
        const res = try self.sessions.getOrPut(try self.allocator.dupe(u8, k));
        if (res.found_existing) {
            self.allocator.free(res.value_ptr.*);
        }
        res.value_ptr.* = bytes;
        self.allocator.free(k);
    }

    const vtable = storage.SessionStore.VTable{
        .loadSession = loadSession,
        .storeSession = storeSession,
    };
    fn store(self: *MemSessionStore) storage.SessionStore {
        return .{ .ptr = self, .vtable = &vtable };
    }
};

const MemPreKeyStore = struct {
    keys: std.AutoHashMap(u32, pre_key_record_mod.PreKeyRecord),
    allocator: mem.Allocator,

    fn init(allocator: mem.Allocator) MemPreKeyStore {
        return .{ .keys = std.AutoHashMap(u32, pre_key_record_mod.PreKeyRecord).init(allocator), .allocator = allocator };
    }
    fn deinit(self: *MemPreKeyStore) void {
        self.keys.deinit();
    }

    fn loadPreKey(ptr: *anyopaque, id: u32) anyerror!pre_key_record_mod.PreKeyRecord {
        const self: *MemPreKeyStore = @ptrCast(@alignCast(ptr));
        return self.keys.get(id) orelse err.SignalError.InvalidKeyIdentifier;
    }
    fn storePreKey(ptr: *anyopaque, id: u32, record: *const pre_key_record_mod.PreKeyRecord) anyerror!void {
        const self: *MemPreKeyStore = @ptrCast(@alignCast(ptr));
        try self.keys.put(id, record.*);
    }
    fn removePreKey(ptr: *anyopaque, id: u32) anyerror!void {
        const self: *MemPreKeyStore = @ptrCast(@alignCast(ptr));
        _ = self.keys.remove(id);
    }

    const vtable = storage.PreKeyStore.VTable{
        .loadPreKey = loadPreKey,
        .storePreKey = storePreKey,
        .removePreKey = removePreKey,
    };
    fn store(self: *MemPreKeyStore) storage.PreKeyStore {
        return .{ .ptr = self, .vtable = &vtable };
    }
};

const MemSignedPreKeyStore = struct {
    keys: std.AutoHashMap(u32, signed_pre_key_record_mod.SignedPreKeyRecord),
    allocator: mem.Allocator,

    fn init(allocator: mem.Allocator) MemSignedPreKeyStore {
        return .{ .keys = std.AutoHashMap(u32, signed_pre_key_record_mod.SignedPreKeyRecord).init(allocator), .allocator = allocator };
    }
    fn deinit(self: *MemSignedPreKeyStore) void {
        self.keys.deinit();
    }

    fn loadSignedPreKey(ptr: *anyopaque, id: u32) anyerror!signed_pre_key_record_mod.SignedPreKeyRecord {
        const self: *MemSignedPreKeyStore = @ptrCast(@alignCast(ptr));
        return self.keys.get(id) orelse err.SignalError.InvalidKeyIdentifier;
    }
    fn storeSignedPreKey(ptr: *anyopaque, id: u32, record: *const signed_pre_key_record_mod.SignedPreKeyRecord) anyerror!void {
        const self: *MemSignedPreKeyStore = @ptrCast(@alignCast(ptr));
        try self.keys.put(id, record.*);
    }

    const vtable = storage.SignedPreKeyStore.VTable{
        .loadSignedPreKey = loadSignedPreKey,
        .storeSignedPreKey = storeSignedPreKey,
    };
    fn store(self: *MemSignedPreKeyStore) storage.SignedPreKeyStore {
        return .{ .ptr = self, .vtable = &vtable };
    }
};

const MemKyberPreKeyStore = struct {
    keys: std.AutoHashMap(u32, kyber_pre_key_record_mod.KyberPreKeyRecord),
    allocator: mem.Allocator,

    fn init(allocator: mem.Allocator) MemKyberPreKeyStore {
        return .{ .keys = std.AutoHashMap(u32, kyber_pre_key_record_mod.KyberPreKeyRecord).init(allocator), .allocator = allocator };
    }
    fn deinit(self: *MemKyberPreKeyStore) void {
        self.keys.deinit();
    }

    fn loadKyberPreKey(ptr: *anyopaque, id: u32) anyerror!kyber_pre_key_record_mod.KyberPreKeyRecord {
        const self: *MemKyberPreKeyStore = @ptrCast(@alignCast(ptr));
        return self.keys.get(id) orelse err.SignalError.InvalidKeyIdentifier;
    }
    fn storeKyberPreKey(ptr: *anyopaque, id: u32, record: *const kyber_pre_key_record_mod.KyberPreKeyRecord) anyerror!void {
        const self: *MemKyberPreKeyStore = @ptrCast(@alignCast(ptr));
        try self.keys.put(id, record.*);
    }
    fn markKyberPreKeyUsed(_: *anyopaque, _: u32) anyerror!void {}

    const vtable = storage.KyberPreKeyStore.VTable{
        .loadKyberPreKey = loadKyberPreKey,
        .storeKyberPreKey = storeKyberPreKey,
        .markKyberPreKeyUsed = markKyberPreKeyUsed,
    };
    fn store(self: *MemKyberPreKeyStore) storage.KyberPreKeyStore {
        return .{ .ptr = self, .vtable = &vtable };
    }
};

const MemSenderKeyStore = struct {
    keys: std.StringHashMap([]u8),
    allocator: mem.Allocator,

    fn init(allocator: mem.Allocator) MemSenderKeyStore {
        return .{ .keys = std.StringHashMap([]u8).init(allocator), .allocator = allocator };
    }
    fn deinit(self: *MemSenderKeyStore) void {
        var it = self.keys.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.keys.deinit();
    }

    fn storeSenderKey(ptr: *anyopaque, name: *const address.SenderKeyName, record: []const u8) anyerror!void {
        const self: *MemSenderKeyStore = @ptrCast(@alignCast(ptr));
        const k = try std.fmt.allocPrint(self.allocator, "{s}:{s}", .{ name.group_id, name.sender.name });
        const v = try self.allocator.dupe(u8, record);
        const res = try self.keys.getOrPut(try self.allocator.dupe(u8, k));
        if (res.found_existing) self.allocator.free(res.value_ptr.*);
        res.value_ptr.* = v;
        self.allocator.free(k);
    }
    fn loadSenderKey(ptr: *anyopaque, name: *const address.SenderKeyName) anyerror!?[]u8 {
        const self: *MemSenderKeyStore = @ptrCast(@alignCast(ptr));
        const k = try std.fmt.allocPrint(self.allocator, "{s}:{s}", .{ name.group_id, name.sender.name });
        defer self.allocator.free(k);
        const v = self.keys.get(k) orelse return null;
        return try self.allocator.dupe(u8, v);
    }

    const vtable = storage.SenderKeyStore.VTable{
        .storeSenderKey = storeSenderKey,
        .loadSenderKey = loadSenderKey,
    };
    fn store(self: *MemSenderKeyStore) storage.SenderKeyStore {
        return .{ .ptr = self, .vtable = &vtable };
    }
};

// ---- Tests ----

test "key generation" {
    const kp = try curve.KeyPair.generate();
    // Public key serializes to 33 bytes (0x05 prefix + 32-byte key)
    const pk_bytes = kp.public_key.serialize();
    try std.testing.expectEqual(@as(usize, 33), pk_bytes.len);
    try std.testing.expectEqual(@as(u8, 0x05), pk_bytes[0]);
}

test "public key serialize/deserialize roundtrip" {
    const kp = try curve.KeyPair.generate();
    const serialized = kp.public_key.serialize();
    const deserialized = try curve.PublicKey.deserialize(&serialized);
    try std.testing.expectEqualSlices(u8, &kp.public_key.key_bytes, &deserialized.key_bytes);
}

test "ECDH key agreement" {
    const kp_a = try curve.KeyPair.generate();
    const kp_b = try curve.KeyPair.generate();
    const shared_a = try kp_a.private_key.calculateAgreement(kp_b.public_key);
    const shared_b = try kp_b.private_key.calculateAgreement(kp_a.public_key);
    try std.testing.expectEqualSlices(u8, &shared_a, &shared_b);
}

test "XEdDSA sign and verify" {
    const kp = try curve.KeyPair.generate();
    const msg = "hello signal protocol";
    const sig = try kp.private_key.calculateSignature(msg);
    const ok = try kp.public_key.verifySignature(msg, sig);
    try std.testing.expect(ok);
    // Wrong message fails
    var bad_sig = sig;
    bad_sig[0] ^= 0x01;
    const bad = try kp.public_key.verifySignature(msg, bad_sig);
    try std.testing.expect(!bad);
}

test "ML-KEM-1024 (Kyber) key encapsulation" {
    const kp = try curve.KyberKeyPair.generate();
    const pk = try kp.publicKey();
    const sk = try kp.secretKey();

    var seed: [32]u8 = undefined;
    rnd.bytes(&seed);
    const encap = pk.encapsDeterministic(&seed); // no error return
    const ss_dec = try sk.decaps(&encap.ciphertext);
    try std.testing.expectEqualSlices(u8, &encap.shared_secret, &ss_dec);
}

test "identity key pair generate and serialize" {
    const ikp = try identity.IdentityKeyPair.generate();
    const serialized = try ikp.serialize(ally);
    defer ally.free(serialized);
    const restored = try identity.IdentityKeyPair.deserialize(ally, serialized);
    try std.testing.expectEqualSlices(u8, &ikp.identity_key.public_key.key_bytes, &restored.identity_key.public_key.key_bytes);
}

test "pre-key record serialize/deserialize" {
    const record = try pre_key_record_mod.PreKeyRecord.generate(42);
    const bytes = try record.serialize(ally);
    defer ally.free(bytes);
    const restored = try pre_key_record_mod.PreKeyRecord.deserialize(bytes);
    try std.testing.expectEqual(record.id, restored.id);
    try std.testing.expectEqualSlices(u8, &record.key_pair.public_key.key_bytes, &restored.key_pair.public_key.key_bytes);
}

test "signed pre-key record serialize/deserialize" {
    const ikp = try identity.IdentityKeyPair.generate();
    const spk_kp = try curve.KeyPair.generate();
    const spk_pk_bytes = spk_kp.public_key.serialize();
    const sig = try ikp.private_key.calculateSignature(&spk_pk_bytes);
    const record = signed_pre_key_record_mod.SignedPreKeyRecord{
        .id = 1,
        .timestamp = 1700000000,
        .key_pair = spk_kp,
        .signature = sig,
    };
    const bytes = try record.serialize(ally);
    defer ally.free(bytes);
    const restored = try signed_pre_key_record_mod.SignedPreKeyRecord.deserialize(bytes);
    try std.testing.expectEqual(record.id, restored.id);
    try std.testing.expectEqualSlices(u8, &record.signature, &restored.signature);
}

test "kyber pre-key record serialize/deserialize" {
    const ikp = try identity.IdentityKeyPair.generate();
    const kpk = try curve.KyberKeyPair.generate();
    const sig = try ikp.private_key.calculateSignature(&kpk.public_key_bytes);
    const record = kyber_pre_key_record_mod.KyberPreKeyRecord{
        .id = 7,
        .timestamp = 1700000000,
        .key_pair = kpk,
        .signature = sig,
    };
    const bytes = try record.serialize(ally);
    defer ally.free(bytes);
    const restored = try kyber_pre_key_record_mod.KyberPreKeyRecord.deserialize(bytes);
    try std.testing.expectEqual(record.id, restored.id);
    try std.testing.expectEqualSlices(u8, &record.key_pair.public_key_bytes, &restored.key_pair.public_key_bytes);
}

test "AES-256-CBC encrypt/decrypt" {
    const key: [32]u8 = [_]u8{0xAB} ** 32;
    const iv: [16]u8 = [_]u8{0x00} ** 16;
    const plaintext = "the signal protocol rocks!";

    const ct = try aes_mod.cbc_encrypt(ally, key, iv, plaintext);
    defer ally.free(ct);
    const pt = try aes_mod.cbc_decrypt(ally, key, iv, ct);
    defer ally.free(pt);
    try std.testing.expectEqualSlices(u8, plaintext, pt);
}

test "AES-256-GCM encrypt/decrypt" {
    const key: [32]u8 = [_]u8{0x42} ** 32;
    const nonce: [12]u8 = [_]u8{0x01} ** 12;
    const plaintext = "sealed sender message";
    const aad = "additional authenticated data";

    const ct = try aes_mod.gcm_encrypt(ally, key, nonce, plaintext, aad);
    defer ally.free(ct);
    const pt = try aes_mod.gcm_decrypt(ally, key, nonce, ct, aad);
    defer ally.free(pt);
    try std.testing.expectEqualSlices(u8, plaintext, pt);
}

test "AES-256-GCM-SIV encrypt/decrypt" {
    const key: [32]u8 = [_]u8{0x77} ** 32;
    const nonce: [12]u8 = [_]u8{0x02} ** 12;
    const plaintext = "post-quantum safe message";
    const aad = "context";

    const ct = try aes_mod.gcm_siv_encrypt(ally, key, nonce, plaintext, aad);
    defer ally.free(ct);
    const pt = try aes_mod.gcm_siv_decrypt(ally, key, nonce, ct, aad);
    defer ally.free(pt);
    try std.testing.expectEqualSlices(u8, plaintext, pt);
}

test "username hash" {
    const hash1 = try username_mod.UsernameHash.compute("alice");
    const hash2 = try username_mod.UsernameHash.compute("alice");
    const hash3 = try username_mod.UsernameHash.compute("bob");
    // Same username → same hash
    try std.testing.expectEqualSlices(u8, &hash1.hash, &hash2.hash);
    // Different usernames → different hashes
    try std.testing.expect(!mem.eql(u8, &hash1.hash, &hash3.hash));
    // Invalid usernames rejected
    try std.testing.expectError(err.SignalError.InvalidArgument, username_mod.UsernameHash.compute("ab")); // too short
    try std.testing.expectError(err.SignalError.InvalidArgument, username_mod.UsernameHash.compute("1alice")); // starts with digit
}

test "username proof and verify" {
    const randomness = rnd.fillArray(32);
    const proof = try username_mod.usernameProof(ally, "alice_42", randomness);
    defer ally.free(proof);
    const valid = try username_mod.usernameVerify("alice_42", proof);
    try std.testing.expect(valid);
    const invalid = try username_mod.usernameVerify("bob", proof);
    try std.testing.expect(!invalid);
}

test "scannable fingerprint compute and compare" {
    const ikp_local = try identity.IdentityKeyPair.generate();
    const ikp_remote = try identity.IdentityKeyPair.generate();

    const fp_local = try fingerprint_mod.ScannableFingerprint.compute(
        ally,
        ikp_local.identity_key,
        "+15551234567",
        ikp_remote.identity_key,
        "+15559876543",
    );
    const fp_remote = try fingerprint_mod.ScannableFingerprint.compute(
        ally,
        ikp_remote.identity_key,
        "+15559876543",
        ikp_local.identity_key,
        "+15551234567",
    );

    const local_bytes = try fp_local.serialize();
    defer ally.free(local_bytes);
    const remote_bytes = try fp_remote.serialize();
    defer ally.free(remote_bytes);

    const match = try fp_local.compareTo(remote_bytes);
    try std.testing.expect(match);
    const rev_match = try fp_remote.compareTo(local_bytes);
    try std.testing.expect(rev_match);
}

test "displayable fingerprint" {
    const ikp_a = try identity.IdentityKeyPair.generate();
    const ikp_b = try identity.IdentityKeyPair.generate();
    const display = try fingerprint_mod.computeDisplayableFingerprint(
        ally,
        ikp_a.identity_key,
        "+15551234567",
        ikp_b.identity_key,
        "+15559876543",
    );
    defer ally.free(display);
    // 6 groups of 5 digits per side × 2 sides = 60 decimal digits
    try std.testing.expectEqual(@as(usize, 60), display.len);
    for (display) |c| try std.testing.expect(std.ascii.isDigit(c));
}

test "full session: X3DH + Double Ratchet (classic EC only)" {
    // Bob prepares his keys
    var bob_identity = try MemIdentityStore.init(ally);
    defer bob_identity.deinit();
    var bob_sessions = MemSessionStore.init(ally);
    defer bob_sessions.deinit();
    var bob_prekeys = MemPreKeyStore.init(ally);
    defer bob_prekeys.deinit();
    var bob_signed_prekeys = MemSignedPreKeyStore.init(ally);
    defer bob_signed_prekeys.deinit();

    const bob_ikp = bob_identity.key_pair;

    // Bob creates a signed pre-key
    const spk_kp = try curve.KeyPair.generate();
    const spk_pk_bytes = spk_kp.public_key.serialize();
    const spk_sig = try bob_ikp.private_key.calculateSignature(&spk_pk_bytes);
    const spk_record = signed_pre_key_record_mod.SignedPreKeyRecord{
        .id = 1,
        .timestamp = 1700000000,
        .key_pair = spk_kp,
        .signature = spk_sig,
    };
    try bob_signed_prekeys.keys.put(1, spk_record);

    // Bob creates a one-time pre-key
    const opk = try pre_key_record_mod.PreKeyRecord.generate(100);
    try bob_prekeys.keys.put(100, opk);

    // Bob publishes his pre-key bundle (no Kyber for this test)
    const bob_bundle = bundle_mod.PreKeyBundle.new(
        bob_identity.reg_id,
        1, // device_id
        @as(?u32, 100),
        @as(?curve.PublicKey, opk.key_pair.public_key),
        1,
        spk_kp.public_key,
        spk_sig,
        bob_ikp.identity_key,
        null,
        null,
        null,
    );

    // Alice sets up her stores
    var alice_identity = try MemIdentityStore.init(ally);
    defer alice_identity.deinit();
    var alice_sessions = MemSessionStore.init(ally);
    defer alice_sessions.deinit();
    var alice_prekeys = MemPreKeyStore.init(ally);
    defer alice_prekeys.deinit();
    var alice_signed_prekeys = MemSignedPreKeyStore.init(ally);
    defer alice_signed_prekeys.deinit();

    const bob_addr = address.ProtocolAddress{ .name = "bob", .device_id = 1 };

    // Alice processes Bob's bundle to establish a session
    var alice_builder = session_builder_mod.SessionBuilder.init(
        ally,
        bob_addr,
        alice_sessions.store(),
        alice_prekeys.store(),
        alice_signed_prekeys.store(),
        alice_identity.store(),
        null,
    );
    try alice_builder.processPreKeyBundle(bob_bundle);

    // Alice encrypts a message to Bob
    var alice_cipher = session_cipher_mod.SessionCipher.init(
        ally,
        bob_addr,
        alice_sessions.store(),
        alice_prekeys.store(),
        alice_signed_prekeys.store(),
        alice_identity.store(),
        null,
    );
    var ct_msg = try alice_cipher.encrypt("hello bob!");
    defer ct_msg.deinit();

    try std.testing.expectEqual(session_cipher_mod.CiphertextType.pre_key, ct_msg.message_type);

    // Bob decrypts Alice's message
    const alice_addr = address.ProtocolAddress{ .name = "alice", .device_id = 1 };
    var bob_cipher = session_cipher_mod.SessionCipher.init(
        ally,
        alice_addr,
        bob_sessions.store(),
        bob_prekeys.store(),
        bob_signed_prekeys.store(),
        bob_identity.store(),
        null,
    );
    const plaintext = try bob_cipher.decryptPreKeyMessage(ct_msg.serialized);
    defer ally.free(plaintext);
    try std.testing.expectEqualSlices(u8, "hello bob!", plaintext);
}

test "full session: PQXDH (EC + Kyber)" {
    var bob_identity = try MemIdentityStore.init(ally);
    defer bob_identity.deinit();
    var bob_sessions = MemSessionStore.init(ally);
    defer bob_sessions.deinit();
    var bob_prekeys = MemPreKeyStore.init(ally);
    defer bob_prekeys.deinit();
    var bob_signed_prekeys = MemSignedPreKeyStore.init(ally);
    defer bob_signed_prekeys.deinit();
    var bob_kyber_prekeys = MemKyberPreKeyStore.init(ally);
    defer bob_kyber_prekeys.deinit();

    const bob_ikp = bob_identity.key_pair;

    // Signed pre-key
    const spk_kp = try curve.KeyPair.generate();
    const spk_pk_bytes = spk_kp.public_key.serialize();
    const spk_sig = try bob_ikp.private_key.calculateSignature(&spk_pk_bytes);
    const spk_record = signed_pre_key_record_mod.SignedPreKeyRecord{
        .id = 1,
        .timestamp = 1700000000,
        .key_pair = spk_kp,
        .signature = spk_sig,
    };
    try bob_signed_prekeys.keys.put(1, spk_record);

    // Kyber pre-key
    const kpk = try curve.KyberKeyPair.generate();
    const kpk_sig = try bob_ikp.private_key.calculateSignature(&kpk.public_key_bytes);
    const kpk_record = kyber_pre_key_record_mod.KyberPreKeyRecord{
        .id = 200,
        .timestamp = 1700000000,
        .key_pair = kpk,
        .signature = kpk_sig,
    };
    try bob_kyber_prekeys.keys.put(200, kpk_record);

    // One-time pre-key
    const opk = try pre_key_record_mod.PreKeyRecord.generate(100);
    try bob_prekeys.keys.put(100, opk);

    const bob_bundle = bundle_mod.PreKeyBundle.new(
        bob_identity.reg_id,
        1,
        @as(?u32, 100),
        @as(?curve.PublicKey, opk.key_pair.public_key),
        1,
        spk_kp.public_key,
        spk_sig,
        bob_ikp.identity_key,
        @as(?u32, 200),
        @as(?[curve.KyberKeyPair.KYBER_PUBLIC_KEY_LENGTH]u8, kpk.public_key_bytes),
        @as(?[curve.SIGNATURE_LENGTH]u8, kpk_sig),
    );

    var alice_identity = try MemIdentityStore.init(ally);
    defer alice_identity.deinit();
    var alice_sessions = MemSessionStore.init(ally);
    defer alice_sessions.deinit();
    var alice_prekeys = MemPreKeyStore.init(ally);
    defer alice_prekeys.deinit();
    var alice_signed_prekeys = MemSignedPreKeyStore.init(ally);
    defer alice_signed_prekeys.deinit();

    const bob_addr = address.ProtocolAddress{ .name = "bob_pq", .device_id = 1 };

    var alice_builder = session_builder_mod.SessionBuilder.init(
        ally,
        bob_addr,
        alice_sessions.store(),
        alice_prekeys.store(),
        alice_signed_prekeys.store(),
        alice_identity.store(),
        null,
    );
    try alice_builder.processPreKeyBundle(bob_bundle);

    var alice_cipher = session_cipher_mod.SessionCipher.init(
        ally,
        bob_addr,
        alice_sessions.store(),
        alice_prekeys.store(),
        alice_signed_prekeys.store(),
        alice_identity.store(),
        null,
    );
    var ct = try alice_cipher.encrypt("hello pqxdh!");
    defer ct.deinit();

    const alice_addr = address.ProtocolAddress{ .name = "alice_pq", .device_id = 1 };
    var bob_cipher = session_cipher_mod.SessionCipher.init(
        ally,
        alice_addr,
        bob_sessions.store(),
        bob_prekeys.store(),
        bob_signed_prekeys.store(),
        bob_identity.store(),
        bob_kyber_prekeys.store(),
    );
    const pt = try bob_cipher.decryptPreKeyMessage(ct.serialized);
    defer ally.free(pt);
    try std.testing.expectEqualSlices(u8, "hello pqxdh!", pt);
}

test "group messaging" {
    var sender_key_store = MemSenderKeyStore.init(ally);
    defer sender_key_store.deinit();

    const group_id = "group-abc-123";
    const sender_addr = address.ProtocolAddress{ .name = "alice", .device_id = 1 };
    const skn = address.SenderKeyName{ .group_id = group_id, .sender = sender_addr };

    // Create a group session (sender side)
    var builder = group_session_builder_mod.GroupSessionBuilder.init(ally, sender_key_store.store());
    const dist_msg = try builder.createSession(&skn);
    defer {
        var m = dist_msg;
        m.deinit();
    }

    // Simulate a second member processing the distribution
    var member_key_store = MemSenderKeyStore.init(ally);
    defer member_key_store.deinit();
    var member_builder = group_session_builder_mod.GroupSessionBuilder.init(ally, member_key_store.store());
    try member_builder.processSession(&skn, &dist_msg);

    // Sender encrypts
    var sender_cipher = group_cipher_mod.GroupCipher.init(ally, sender_key_store.store(), skn);
    const encrypted = try sender_cipher.encrypt("hello group!");
    defer ally.free(encrypted);

    // Member decrypts
    var member_cipher = group_cipher_mod.GroupCipher.init(ally, member_key_store.store(), skn);
    const decrypted = try member_cipher.decrypt(encrypted);
    defer ally.free(decrypted);
    try std.testing.expectEqualSlices(u8, "hello group!", decrypted);
}

// ---- SPQR Tests ----

const spqr_state_mod = @import("spqr/state.zig");
const spqr_msg_mod = @import("spqr/msg.zig");
const spqr_chain_mod = @import("spqr/chain.zig");
const spqr_auth_mod = @import("spqr/authenticator.zig");
const spqr_poly_mod = @import("spqr/poly_codec.zig");
const spqr_mlkem_mod = @import("spqr/mlkem768_incremental.zig");

// Run one full bidirectional step of the SPQR exchange:
//   - each side produces one chunk
//   - each side consumes the oldest pending chunk from the other
// Returns true once both sides have advanced to epoch >= 1.
fn spqrStep(
    a: mem.Allocator,
    alice: *spqr_state_mod.SpqrState,
    bob: *spqr_state_mod.SpqrState,
    alice_inbox: *std.ArrayListUnmanaged([]u8),
    bob_inbox: *std.ArrayListUnmanaged([]u8),
) !bool {
    {
        const r = try spqr_state_mod.send(a, alice);
        try bob_inbox.append(a, r.msg_bytes);
    }
    {
        const r = try spqr_state_mod.send(a, bob);
        try alice_inbox.append(a, r.msg_bytes);
    }
    if (bob_inbox.items.len > 0) {
        const msg = bob_inbox.orderedRemove(0);
        _ = try spqr_state_mod.recv(a, bob, msg);
    }
    if (alice_inbox.items.len > 0) {
        const msg = alice_inbox.orderedRemove(0);
        _ = try spqr_state_mod.recv(a, alice, msg);
    }
    return alice.chain.current_epoch >= 1 and bob.chain.current_epoch >= 1;
}

test "SPQR: epoch advancement and chain key symmetry" {
    // Drive a full ML-KEM-768 epoch exchange and verify:
    //   (1) both sides advance to epoch 1,
    //   (2) send-chain key produced by the new epoch sender equals
    //       the recv-chain key produced by the new epoch receiver.
    var arena = std.heap.ArenaAllocator.init(ally);
    defer arena.deinit();
    const a = arena.allocator();

    var initial_key: [32]u8 = undefined;
    rnd.bytes(&initial_key);

    var alice = spqr_state_mod.SpqrState{
        .chain = try spqr_chain_mod.Chain.init(a, initial_key, .a2b),
        .auth = spqr_auth_mod.Authenticator.init(initial_key, 0),
        .sm = .unsampled,
    };
    var bob = spqr_state_mod.SpqrState{
        .chain = try spqr_chain_mod.Chain.init(a, initial_key, .b2a),
        .auth = spqr_auth_mod.Authenticator.init(initial_key, 0),
        .sm = .{ .waiting_hdr = .{
            .hdr_dec = try spqr_poly_mod.PolyDecoder.init(spqr_mlkem_mod.HEADER_SIZE),
        } },
    };

    var alice_inbox: std.ArrayListUnmanaged([]u8) = .empty;
    var bob_inbox: std.ArrayListUnmanaged([]u8) = .empty;

    // Drive the exchange. The exchange needs ~72 minimum chunks each way;
    // 400 iterations with the round-robin delivery policy is more than enough.
    for (0..400) |_| {
        if (try spqrStep(a, &alice, &bob, &alice_inbox, &bob_inbox)) break;
    }

    try std.testing.expect(alice.chain.current_epoch >= 1);
    try std.testing.expect(bob.chain.current_epoch >= 1);
    try std.testing.expectEqual(alice.chain.current_epoch, bob.chain.current_epoch);

    // After epoch 0 exchange: Alice is now waiting_hdr (receiver), Bob is unsampled (sender).
    // Drain any in-flight messages so state machines are idle.
    for (0..400) |_| {
        if (try spqrStep(a, &alice, &bob, &alice_inbox, &bob_inbox)) break;
    }

    // Bob now sends in epoch 1. Capture his send chain key.
    const b_send = try spqr_state_mod.send(a, &bob);
    const parsed = try spqr_msg_mod.parse(b_send.msg_bytes);

    // Alice receives that exact message. Her recv chain key must match Bob's send chain key.
    const a_recv = try spqr_state_mod.recv(a, &alice, b_send.msg_bytes);

    // Both sides must produce a non-null key for the epoch-1 message.
    const key_bob = b_send.chain_key orelse return error.NullSendKey;
    const key_alice = a_recv.chain_key orelse return error.NullRecvKey;
    _ = parsed;
    try std.testing.expectEqualSlices(u8, &key_bob, &key_alice);
}

test "SPQR: state serialization round-trip" {
    // Serialize SpqrState mid-exchange, deserialize, and verify the exchange
    // still completes correctly from the restored state.
    var arena = std.heap.ArenaAllocator.init(ally);
    defer arena.deinit();
    const a = arena.allocator();

    var initial_key: [32]u8 = undefined;
    rnd.bytes(&initial_key);

    var alice = spqr_state_mod.SpqrState{
        .chain = try spqr_chain_mod.Chain.init(a, initial_key, .a2b),
        .auth = spqr_auth_mod.Authenticator.init(initial_key, 0),
        .sm = .unsampled,
    };
    var bob = spqr_state_mod.SpqrState{
        .chain = try spqr_chain_mod.Chain.init(a, initial_key, .b2a),
        .auth = spqr_auth_mod.Authenticator.init(initial_key, 0),
        .sm = .{ .waiting_hdr = .{
            .hdr_dec = try spqr_poly_mod.PolyDecoder.init(spqr_mlkem_mod.HEADER_SIZE),
        } },
    };

    var alice_inbox: std.ArrayListUnmanaged([]u8) = .empty;
    var bob_inbox: std.ArrayListUnmanaged([]u8) = .empty;

    // Advance Alice far enough to be mid-EK-sending (after HDR is fully sent, ~4 steps).
    for (0..4) |_| {
        _ = try spqrStep(a, &alice, &bob, &alice_inbox, &bob_inbox);
    }

    // Snapshot Alice's state via serialize → deserialize round-trip.
    const snapshot = try alice.serialize(a);
    var alice_restored = try spqr_state_mod.SpqrState.deserialize(a, snapshot);

    // Re-serialize the restored state and confirm it is byte-for-byte identical.
    const snapshot2 = try alice_restored.serialize(a);
    try std.testing.expectEqualSlices(u8, snapshot, snapshot2);

    // Continue the exchange from the restored Alice until epoch 1 is reached.
    for (0..400) |_| {
        if (try spqrStep(a, &alice_restored, &bob, &alice_inbox, &bob_inbox)) break;
    }

    try std.testing.expect(alice_restored.chain.current_epoch >= 1);
    try std.testing.expect(bob.chain.current_epoch >= 1);
}

test "SPQR: MAC rejection on tampered header" {
    // Verify that a receiver detects a forged or corrupted MAC and returns InvalidMac.
    // Alice sends two HDR chunks (the minimum needed for the 64-byte header).
    // We corrupt the MAC carried in chunk 0; the error fires when chunk 1 completes
    // the header and MAC verification runs.
    var arena = std.heap.ArenaAllocator.init(ally);
    defer arena.deinit();
    const a = arena.allocator();

    var initial_key: [32]u8 = undefined;
    rnd.bytes(&initial_key);

    var alice = spqr_state_mod.SpqrState{
        .chain = try spqr_chain_mod.Chain.init(a, initial_key, .a2b),
        .auth = spqr_auth_mod.Authenticator.init(initial_key, 0),
        .sm = .unsampled,
    };
    var bob = spqr_state_mod.SpqrState{
        .chain = try spqr_chain_mod.Chain.init(a, initial_key, .b2a),
        .auth = spqr_auth_mod.Authenticator.init(initial_key, 0),
        .sm = .{ .waiting_hdr = .{
            .hdr_dec = try spqr_poly_mod.PolyDecoder.init(spqr_mlkem_mod.HEADER_SIZE),
        } },
    };

    // HDR has 64 bytes → 2 chunks of 32 bytes each.
    // Chunk 0 carries the MAC; chunk 1 completes the header and triggers verification.

    // Alice sends HDR chunk 0 (carries MAC).
    const chunk0_send = try spqr_state_mod.send(a, &alice);
    var msg0 = try spqr_msg_mod.parse(chunk0_send.msg_bytes);
    try std.testing.expect(msg0.mac != null); // chunk 0 must have a MAC

    // Corrupt the MAC.
    msg0.mac.?[0] ^= 0xFF;
    const tampered0 = try spqr_msg_mod.serialize(a, msg0);

    // Deliver tampered chunk 0 to Bob. Bob stores the (bad) MAC; no verification yet.
    _ = try spqr_state_mod.recv(a, &bob, tampered0);

    // Alice sends HDR chunk 1 (no MAC).
    const chunk1_send = try spqr_state_mod.send(a, &alice);
    try std.testing.expect((try spqr_msg_mod.parse(chunk1_send.msg_bytes)).mac == null);

    // Deliver chunk 1 to Bob. Header is now complete → MAC verification fires → InvalidMac.
    try std.testing.expectError(
        error.InvalidMac,
        spqr_state_mod.recv(a, &bob, chunk1_send.msg_bytes),
    );
}
