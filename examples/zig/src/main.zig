const std = @import("std");
const signal = @import("libsignal_zig");

const storage = signal.storage;
const curve = signal.curve;
const identity = signal.identity;
const address = signal.address;

// ---- in-memory IdentityKeyStore ----

const MemIdentityStore = struct {
    allocator: std.mem.Allocator,
    key_pair: signal.IdentityKeyPair,
    reg_id: u32,
    known: std.StringHashMap(signal.IdentityKey),

    const vtable = storage.IdentityKeyStore.VTable{
        .getIdentityKeyPair = getIdentityKeyPair,
        .getLocalRegistrationId = getLocalRegistrationId,
        .saveIdentity = saveIdentity,
        .isTrustedIdentity = isTrustedIdentity,
        .getIdentity = getIdentity,
    };

    fn init(allocator: std.mem.Allocator, reg_id: u32) !MemIdentityStore {
        return .{
            .allocator = allocator,
            .key_pair = try signal.IdentityKeyPair.generate(),
            .reg_id = reg_id,
            .known = std.StringHashMap(signal.IdentityKey).init(allocator),
        };
    }

    fn deinit(self: *MemIdentityStore) void {
        var it = self.known.keyIterator();
        while (it.next()) |k| self.allocator.free(k.*);
        self.known.deinit();
    }

    fn store(self: *MemIdentityStore) storage.IdentityKeyStore {
        return .{ .ptr = self, .vtable = &vtable };
    }

    fn addrKey(allocator: std.mem.Allocator, addr: *const address.ProtocolAddress) ![]u8 {
        return std.fmt.allocPrint(allocator, "{s}:{d}", .{ addr.name, addr.device_id });
    }

    fn getIdentityKeyPair(ptr: *anyopaque) anyerror!signal.IdentityKeyPair {
        return cast(ptr).key_pair;
    }

    fn getLocalRegistrationId(ptr: *anyopaque) anyerror!u32 {
        return cast(ptr).reg_id;
    }

    fn saveIdentity(ptr: *anyopaque, addr: *const address.ProtocolAddress, key: signal.IdentityKey) anyerror!storage.IdentityChange {
        const self = cast(ptr);
        const k = try addrKey(self.allocator, addr);
        const r = try self.known.getOrPut(k);
        if (r.found_existing) {
            self.allocator.free(k);
            const changed = !r.value_ptr.eql(key);
            r.value_ptr.* = key;
            return if (changed) .replaced_existing else .new_or_unchanged;
        }
        r.key_ptr.* = k;
        r.value_ptr.* = key;
        return .new_or_unchanged;
    }

    fn isTrustedIdentity(ptr: *anyopaque, addr: *const address.ProtocolAddress, key: signal.IdentityKey, _: storage.Direction) anyerror!bool {
        const self = cast(ptr);
        const k = try addrKey(self.allocator, addr);
        defer self.allocator.free(k);
        const existing = self.known.get(k) orelse return true;
        return existing.eql(key);
    }

    fn getIdentity(ptr: *anyopaque, addr: *const address.ProtocolAddress) anyerror!?signal.IdentityKey {
        const self = cast(ptr);
        const k = try addrKey(self.allocator, addr);
        defer self.allocator.free(k);
        return self.known.get(k);
    }

    fn cast(ptr: *anyopaque) *MemIdentityStore {
        return @ptrCast(@alignCast(ptr));
    }
};

// ---- in-memory SessionStore ----

const MemSessionStore = struct {
    allocator: std.mem.Allocator,
    sessions: std.StringHashMap([]u8),

    const vtable = storage.SessionStore.VTable{
        .loadSession = loadSession,
        .storeSession = storeSession,
    };

    fn init(allocator: std.mem.Allocator) MemSessionStore {
        return .{ .allocator = allocator, .sessions = std.StringHashMap([]u8).init(allocator) };
    }

    fn deinit(self: *MemSessionStore) void {
        var it = self.sessions.iterator();
        while (it.next()) |e| {
            self.allocator.free(e.key_ptr.*);
            self.allocator.free(e.value_ptr.*);
        }
        self.sessions.deinit();
    }

    fn store(self: *MemSessionStore) storage.SessionStore {
        return .{ .ptr = self, .vtable = &vtable };
    }

    fn addrKey(allocator: std.mem.Allocator, addr: *const address.ProtocolAddress) ![]u8 {
        return std.fmt.allocPrint(allocator, "{s}:{d}", .{ addr.name, addr.device_id });
    }

    fn loadSession(ptr: *anyopaque, addr: *const address.ProtocolAddress) anyerror!?signal.SessionRecord {
        const self = cast(ptr);
        const k = try addrKey(self.allocator, addr);
        defer self.allocator.free(k);
        const bytes = self.sessions.get(k) orelse return null;
        return try signal.SessionRecord.deserialize(self.allocator, bytes);
    }

    fn storeSession(ptr: *anyopaque, addr: *const address.ProtocolAddress, record: *const signal.SessionRecord) anyerror!void {
        const self = cast(ptr);
        const k = try addrKey(self.allocator, addr);
        errdefer self.allocator.free(k);
        const bytes = try record.serialize();
        errdefer self.allocator.free(bytes);
        const r = try self.sessions.getOrPut(k);
        if (r.found_existing) {
            self.allocator.free(k);
            self.allocator.free(r.value_ptr.*);
        } else {
            r.key_ptr.* = k;
        }
        r.value_ptr.* = bytes;
    }

    fn cast(ptr: *anyopaque) *MemSessionStore {
        return @ptrCast(@alignCast(ptr));
    }
};

// ---- in-memory PreKeyStore ----

const MemPreKeyStore = struct {
    allocator: std.mem.Allocator,
    keys: std.AutoHashMap(u32, []u8),

    const vtable = storage.PreKeyStore.VTable{
        .loadPreKey = loadPreKey,
        .storePreKey = storePreKey,
        .removePreKey = removePreKey,
    };

    fn init(allocator: std.mem.Allocator) MemPreKeyStore {
        return .{ .allocator = allocator, .keys = std.AutoHashMap(u32, []u8).init(allocator) };
    }

    fn deinit(self: *MemPreKeyStore) void {
        var it = self.keys.valueIterator();
        while (it.next()) |v| self.allocator.free(v.*);
        self.keys.deinit();
    }

    fn store(self: *MemPreKeyStore) storage.PreKeyStore {
        return .{ .ptr = self, .vtable = &vtable };
    }

    fn loadPreKey(ptr: *anyopaque, id: u32) anyerror!signal.PreKeyRecord {
        const self = cast(ptr);
        const bytes = self.keys.get(id) orelse return signal.SignalError.InvalidKeyIdentifier;
        return signal.PreKeyRecord.deserialize(bytes);
    }

    fn storePreKey(ptr: *anyopaque, id: u32, record: *const signal.PreKeyRecord) anyerror!void {
        const self = cast(ptr);
        const bytes = try record.serialize(self.allocator);
        errdefer self.allocator.free(bytes);
        const r = try self.keys.getOrPut(id);
        if (r.found_existing) self.allocator.free(r.value_ptr.*);
        r.value_ptr.* = bytes;
    }

    fn removePreKey(ptr: *anyopaque, id: u32) anyerror!void {
        const self = cast(ptr);
        if (self.keys.fetchRemove(id)) |kv| self.allocator.free(kv.value);
    }

    fn cast(ptr: *anyopaque) *MemPreKeyStore {
        return @ptrCast(@alignCast(ptr));
    }
};

// ---- in-memory SignedPreKeyStore ----

const MemSignedPreKeyStore = struct {
    allocator: std.mem.Allocator,
    keys: std.AutoHashMap(u32, []u8),

    const vtable = storage.SignedPreKeyStore.VTable{
        .loadSignedPreKey = loadSignedPreKey,
        .storeSignedPreKey = storeSignedPreKey,
    };

    fn init(allocator: std.mem.Allocator) MemSignedPreKeyStore {
        return .{ .allocator = allocator, .keys = std.AutoHashMap(u32, []u8).init(allocator) };
    }

    fn deinit(self: *MemSignedPreKeyStore) void {
        var it = self.keys.valueIterator();
        while (it.next()) |v| self.allocator.free(v.*);
        self.keys.deinit();
    }

    fn store(self: *MemSignedPreKeyStore) storage.SignedPreKeyStore {
        return .{ .ptr = self, .vtable = &vtable };
    }

    fn loadSignedPreKey(ptr: *anyopaque, id: u32) anyerror!signal.SignedPreKeyRecord {
        const self = cast(ptr);
        const bytes = self.keys.get(id) orelse return signal.SignalError.InvalidKeyIdentifier;
        return signal.SignedPreKeyRecord.deserialize(bytes);
    }

    fn storeSignedPreKey(ptr: *anyopaque, id: u32, record: *const signal.SignedPreKeyRecord) anyerror!void {
        const self = cast(ptr);
        const bytes = try record.serialize(self.allocator);
        errdefer self.allocator.free(bytes);
        const r = try self.keys.getOrPut(id);
        if (r.found_existing) self.allocator.free(r.value_ptr.*);
        r.value_ptr.* = bytes;
    }

    fn cast(ptr: *anyopaque) *MemSignedPreKeyStore {
        return @ptrCast(@alignCast(ptr));
    }
};

// ---- in-memory SenderKeyStore ----

const MemSenderKeyStore = struct {
    allocator: std.mem.Allocator,
    keys: std.StringHashMap([]u8),

    const vtable = storage.SenderKeyStore.VTable{
        .storeSenderKey = storeSenderKey,
        .loadSenderKey = loadSenderKey,
    };

    fn init(allocator: std.mem.Allocator) MemSenderKeyStore {
        return .{ .allocator = allocator, .keys = std.StringHashMap([]u8).init(allocator) };
    }

    fn deinit(self: *MemSenderKeyStore) void {
        var it = self.keys.iterator();
        while (it.next()) |e| {
            self.allocator.free(e.key_ptr.*);
            self.allocator.free(e.value_ptr.*);
        }
        self.keys.deinit();
    }

    fn store(self: *MemSenderKeyStore) storage.SenderKeyStore {
        return .{ .ptr = self, .vtable = &vtable };
    }

    fn makeKey(allocator: std.mem.Allocator, sender: *const address.ProtocolAddress, dist_id: [16]u8) ![]u8 {
        const hex = std.fmt.bytesToHex(&dist_id, .lower);
        return std.fmt.allocPrint(allocator, "{s}:{d}:{s}", .{ sender.name, sender.device_id, &hex });
    }

    fn storeSenderKey(ptr: *anyopaque, sender: *const address.ProtocolAddress, dist_id: [16]u8, record: []const u8) anyerror!void {
        const self = cast(ptr);
        const k = try makeKey(self.allocator, sender, dist_id);
        errdefer self.allocator.free(k);
        const copy = try self.allocator.dupe(u8, record);
        errdefer self.allocator.free(copy);
        const r = try self.keys.getOrPut(k);
        if (r.found_existing) {
            self.allocator.free(k);
            self.allocator.free(r.value_ptr.*);
        } else {
            r.key_ptr.* = k;
        }
        r.value_ptr.* = copy;
    }

    fn loadSenderKey(ptr: *anyopaque, sender: *const address.ProtocolAddress, dist_id: [16]u8) anyerror!?[]u8 {
        const self = cast(ptr);
        const k = try makeKey(self.allocator, sender, dist_id);
        defer self.allocator.free(k);
        const bytes = self.keys.get(k) orelse return null;
        return try self.allocator.dupe(u8, bytes);
    }

    fn cast(ptr: *anyopaque) *MemSenderKeyStore {
        return @ptrCast(@alignCast(ptr));
    }
};

// ---- helpers ----

fn pass(comptime label: []const u8) void {
    std.debug.print("PASS {s}\n", .{label});
}

// ---- tests ----

fn testKeyOps(allocator: std.mem.Allocator) !void {
    _ = allocator;

    // EC keypair + DH
    const alice_kp = try curve.KeyPair.generate();
    const bob_kp = try curve.KeyPair.generate();
    const dh_alice = try alice_kp.private_key.calculateAgreement(bob_kp.public_key);
    const dh_bob = try bob_kp.private_key.calculateAgreement(alice_kp.public_key);
    std.debug.assert(std.mem.eql(u8, &dh_alice, &dh_bob));

    // XEdDSA sign + verify
    const msg = "hello signal";
    var rand64: [64]u8 = undefined;
    signal.random.bytes(&rand64);
    const sig = try signal.xeddsa.sign(alice_kp.private_key.serialize(), msg, rand64);
    const ok = try signal.xeddsa.verify(alice_kp.public_key.key_bytes, msg, sig);
    std.debug.assert(ok);

    // Kyber1024 encaps + decaps
    const kyber_kp = try curve.KyberKeyPair.generate();
    const ek = try kyber_kp.encapsulate();
    const ss2 = try kyber_kp.decapsulate(ek.ciphertext);
    std.debug.assert(std.mem.eql(u8, &ek.shared_secret, &ss2));

    pass("EC keypair / DH / XEdDSA sign-verify / Kyber encaps-decaps");
}

fn testX3DH(allocator: std.mem.Allocator) !void {
    // Bob's stores
    var bob_id = try MemIdentityStore.init(allocator, 2222);
    defer bob_id.deinit();
    var bob_sess = MemSessionStore.init(allocator);
    defer bob_sess.deinit();
    var bob_pk = MemPreKeyStore.init(allocator);
    defer bob_pk.deinit();
    var bob_spk = MemSignedPreKeyStore.init(allocator);
    defer bob_spk.deinit();

    // Alice's stores
    var alice_id = try MemIdentityStore.init(allocator, 1111);
    defer alice_id.deinit();
    var alice_sess = MemSessionStore.init(allocator);
    defer alice_sess.deinit();
    var alice_pk = MemPreKeyStore.init(allocator);
    defer alice_pk.deinit();
    var alice_spk = MemSignedPreKeyStore.init(allocator);
    defer alice_spk.deinit();

    // Bob generates and stores a signed pre-key
    const bob_spk_record = try signal.SignedPreKeyRecord.generate(
        1,
        0,
        bob_id.key_pair.private_key,
    );
    try bob_spk.store().storeSignedPreKey(1, &bob_spk_record);

    // Bob generates and stores a one-time pre-key
    const bob_opk_record = try signal.PreKeyRecord.generate(42);
    try bob_pk.store().storePreKey(42, &bob_opk_record);

    // Alice builds Bob's pre-key bundle
    const bundle = signal.PreKeyBundle.new(
        2222, // Bob's reg_id
        1, // device_id
        42,
        bob_opk_record.key_pair.public_key, // one-time pre-key
        1,
        bob_spk_record.key_pair.public_key,
        bob_spk_record.signature, // signed pre-key
        bob_id.key_pair.identity_key,
        null,
        null,
        null, // no Kyber
    );

    const bob_addr = address.ProtocolAddress{ .name = "bob", .device_id = 1 };
    const alice_addr = address.ProtocolAddress{ .name = "alice", .device_id = 1 };

    // Alice processes bundle and encrypts
    var alice_builder = signal.SessionBuilder.init(
        allocator,
        bob_addr,
        alice_sess.store(),
        alice_pk.store(),
        alice_spk.store(),
        alice_id.store(),
        null,
    );
    try alice_builder.processPreKeyBundle(bundle);

    var alice_cipher = signal.SessionCipher.init(
        allocator,
        bob_addr,
        alice_sess.store(),
        alice_pk.store(),
        alice_spk.store(),
        alice_id.store(),
        null,
    );

    var ct = try alice_cipher.encrypt("hello bob, this is X3DH!");
    defer ct.deinit();
    std.debug.assert(ct.message_type == .pre_key);

    // Bob decrypts
    var bob_cipher = signal.SessionCipher.init(
        allocator,
        alice_addr,
        bob_sess.store(),
        bob_pk.store(),
        bob_spk.store(),
        bob_id.store(),
        null,
    );

    const pt = try bob_cipher.decryptPreKeyMessage(ct.serialized);
    defer allocator.free(pt);
    std.debug.assert(std.mem.eql(u8, pt, "hello bob, this is X3DH!"));

    // Bob replies — now a regular SignalMessage (double ratchet)
    var bob_reply_cipher = signal.SessionCipher.init(
        allocator,
        alice_addr,
        bob_sess.store(),
        bob_pk.store(),
        bob_spk.store(),
        bob_id.store(),
        null,
    );
    var reply_ct = try bob_reply_cipher.encrypt("hey alice!");
    defer reply_ct.deinit();
    std.debug.assert(reply_ct.message_type == .whisper);

    var alice_recv = signal.SessionCipher.init(
        allocator,
        bob_addr,
        alice_sess.store(),
        alice_pk.store(),
        alice_spk.store(),
        alice_id.store(),
        null,
    );
    const reply_pt = try alice_recv.decryptMessage(reply_ct.serialized);
    defer allocator.free(reply_pt);
    std.debug.assert(std.mem.eql(u8, reply_pt, "hey alice!"));

    pass("X3DH session establish / Double Ratchet encrypt-decrypt both directions");
}

fn testGroupMessaging(allocator: std.mem.Allocator) !void {
    // Alice and Bob each have their own sender key database
    var alice_sk = MemSenderKeyStore.init(allocator);
    defer alice_sk.deinit();
    var bob_sk = MemSenderKeyStore.init(allocator);
    defer bob_sk.deinit();

    const alice_addr = address.ProtocolAddress{ .name = "alice", .device_id = 1 };

    // Fixed distribution UUID for this group session
    const dist_id: [16]u8 = .{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };

    // Alice creates the sender key session and gets the distribution message
    var alice_gsb = signal.GroupSessionBuilder.init(allocator, alice_sk.store());
    var skdm = try alice_gsb.createSession(&alice_addr, dist_id);
    defer skdm.deinit();

    // Bob receives the distribution message
    var bob_gsb = signal.GroupSessionBuilder.init(allocator, bob_sk.store());
    try bob_gsb.processSession(&alice_addr, &skdm);

    // Alice encrypts a group message
    var alice_gc = signal.GroupCipher.init(allocator, alice_sk.store(), alice_addr, dist_id);
    const group_ct = try alice_gc.encrypt("hello group!");
    defer allocator.free(group_ct);

    // Bob decrypts it
    var bob_gc = signal.GroupCipher.init(allocator, bob_sk.store(), alice_addr, dist_id);
    const group_pt = try bob_gc.decrypt(group_ct);
    defer allocator.free(group_pt);
    std.debug.assert(std.mem.eql(u8, group_pt, "hello group!"));

    pass("Group session create / process / encrypt / decrypt (Sender Keys)");
}

fn testSealedSenderV1(allocator: std.mem.Allocator) !void {
    const ss = signal.sealed_sender;

    // Trust root keypair (server-side)
    const trust_root_kp = try curve.KeyPair.generate();

    // Server certificate: key_id=1, server's ephemeral key, signed by trust root
    const server_ephemeral_kp = try curve.KeyPair.generate();
    var server_cert = try ss.ServerCertificate.new(
        allocator,
        1,
        server_ephemeral_kp.public_key,
        trust_root_kp.private_key,
    );
    defer server_cert.deinit();

    const sc_bytes = try server_cert.serialize();
    defer allocator.free(sc_bytes);
    var server_cert2 = try ss.ServerCertificate.deserialize(allocator, sc_bytes);
    // server_cert2 is passed into SenderCertificate.new which takes ownership via .signer
    errdefer server_cert2.deinit();

    // Sender certificate: Alice's identity key + UUID, signed by server
    const alice_kp = try curve.KeyPair.generate();
    var sender_cert = try ss.SenderCertificate.new(
        allocator,
        "alice-uuid",
        null,
        1,
        alice_kp.public_key,
        std.math.maxInt(u64),
        server_cert2,
        server_ephemeral_kp.private_key,
    );
    // sender_cert is passed into UnidentifiedSenderMessageContent.new which owns it
    errdefer sender_cert.deinit();

    // Bob's identity key (the recipient)
    const bob_kp = try curve.KeyPair.generate();

    // Build UnidentifiedSenderMessageContent
    const plaintext = "sealed secret";
    var usmc = try ss.UnidentifiedSenderMessageContent.new(
        allocator,
        .prekey_message,
        sender_cert,
        .default,
        null,
        plaintext,
    );
    defer usmc.deinit();

    // Encrypt (V1)
    const envelope = try ss.sealedSenderEncrypt(allocator, bob_kp.public_key, &usmc);
    defer allocator.free(envelope);

    // Decrypt (V1) → get back the USMC
    var result = try ss.sealedSenderDecryptToUsmc(allocator, envelope, bob_kp.private_key);
    defer result.deinit();

    std.debug.assert(std.mem.eql(u8, result.contents, plaintext));
    std.debug.assert(std.mem.eql(u8, result.sender_cert.sender_uuid, "alice-uuid"));

    pass("Sealed Sender V1 encrypt / decrypt");
}

fn testSealedSenderV2(allocator: std.mem.Allocator) !void {
    const ss = signal.sealed_sender;

    const alice_kp = try curve.KeyPair.generate();
    const bob_kp = try curve.KeyPair.generate();

    // Bob's service ID: ACI with a fixed UUID
    const bob_uuid = signal.uuid.Uuid.fromBytes(.{0xbb} ** 16);
    const bob_sid = signal.ServiceId{ .aci = signal.Aci.fromUuid(bob_uuid) };

    const recipients = [_]ss.SealedSenderV2Recipient{.{
        .service_id = bob_sid,
        .device_id = 1,
        .identity_key = bob_kp.public_key,
    }};

    // Encrypt (produces 0x23 sent-message for the Signal server)
    const sent = try ss.sealedSenderEncryptV2(
        allocator,
        "hello sealed v2!",
        alice_kp,
        &recipients,
        &[_]signal.ServiceId{},
    );
    defer allocator.free(sent);
    std.debug.assert(sent[0] == 0x23);

    // Server dispatch: convert 0x23 → 0x22 for Bob's device
    const bob_sid_bin = bob_sid.toFixedWidthBinary();
    const received = try ss.v2Dispatch(allocator, sent, bob_sid_bin, 1);
    defer allocator.free(received);
    std.debug.assert(received[0] == 0x22);

    // Bob decrypts
    const plaintext = try ss.sealedSenderDecryptV2(
        allocator,
        received,
        bob_kp,
        alice_kp.public_key,
    );
    defer allocator.free(plaintext);
    std.debug.assert(std.mem.eql(u8, plaintext, "hello sealed v2!"));

    pass("Sealed Sender V2 encrypt / dispatch / decrypt");
}

fn testFingerprint(allocator: std.mem.Allocator) !void {
    const alice_ikp = try signal.IdentityKeyPair.generate();
    const bob_ikp = try signal.IdentityKeyPair.generate();

    // Both parties compute the same 60-digit safety number
    const alice_fp = try signal.fingerprint.Fingerprint.compute(
        allocator,
        alice_ikp.identity_key,
        "+15551111111",
        bob_ikp.identity_key,
        "+15552222222",
    );
    const bob_fp = try signal.fingerprint.Fingerprint.compute(
        allocator,
        bob_ikp.identity_key,
        "+15552222222",
        alice_ikp.identity_key,
        "+15551111111",
    );

    std.debug.assert(alice_fp.displayable.eql(bob_fp.displayable));

    // Scannable fingerprint cross-comparison
    const alice_scan_bytes = try alice_fp.scannable.serialize();
    defer allocator.free(alice_scan_bytes);
    const match = try bob_fp.scannable.compareTo(alice_scan_bytes);
    std.debug.assert(match);

    pass("Displayable + scannable fingerprint symmetry");
}

fn testUsername(allocator: std.mem.Allocator) !void {
    const username = "alice.42";

    const hash = try signal.UsernameHash.compute(username);

    var randomness: [32]u8 = undefined;
    signal.random.bytes(&randomness);

    const proof = try signal.username.usernameProof(allocator, username, randomness);
    defer allocator.free(proof);

    const valid = try signal.username.usernameVerify(allocator, hash.toBytes(), proof);
    std.debug.assert(valid);

    pass("Username hash + ZK proof generate / verify");
}

fn testAccountKeys(_: std.mem.Allocator) !void {
    const pool = signal.AccountEntropyPool.generate();

    // Round-trip through string
    const pool2 = try signal.AccountEntropyPool.fromString(pool.asString());
    std.debug.assert(std.mem.eql(u8, pool.asString(), pool2.asString()));

    const svr_key = pool.deriveSvrKey();
    const backup_key = pool.deriveBackupKey();
    const media_key = backup_key.deriveMediaEncryptionKey();

    // Deterministic: same pool produces same keys
    std.debug.assert(std.mem.eql(u8, &svr_key, &pool2.deriveSvrKey()));
    std.debug.assert(std.mem.eql(u8, &backup_key.bytes, &pool2.deriveBackupKey().bytes));
    std.debug.assert(std.mem.eql(u8, &media_key, &pool2.deriveBackupKey().deriveMediaEncryptionKey()));

    pass("AccountEntropyPool generate / parse / derive SVR + backup + media keys");
}

pub fn main() !void {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    try testKeyOps(allocator);
    try testX3DH(allocator);
    try testGroupMessaging(allocator);
    try testSealedSenderV1(allocator);
    try testSealedSenderV2(allocator);
    try testFingerprint(allocator);
    try testUsername(allocator);
    try testAccountKeys(allocator);

    std.debug.print("\nAll Zig API tests PASSED.\n", .{});
}
