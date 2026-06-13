//! C-compatible API for libsignal-zig.
//!
//! All output buffers marked *_out are allocated with the system allocator
//! (malloc) and must be freed by the caller using the standard free().
//! The library never retains these pointers after returning.

const std = @import("std");
const curve = @import("curve.zig");
const identity = @import("identity.zig");
const address_mod = @import("address.zig");
const storage = @import("storage.zig");
const session_builder_mod = @import("session_builder.zig");
const session_cipher_mod = @import("session_cipher.zig");
const bundle_mod = @import("state/bundle.zig");
const session_record_mod = @import("state/session_record.zig");
const pre_key_record_mod = @import("state/pre_key_record.zig");
const signed_pre_key_record_mod = @import("state/signed_pre_key_record.zig");
const kyber_pre_key_record_mod = @import("state/kyber_pre_key_record.zig");
const group_session_builder_mod = @import("group_session_builder.zig");
const group_cipher_mod = @import("group_cipher.zig");
const sealed_sender_mod = @import("sealed_sender.zig");
const fingerprint_mod = @import("fingerprint.zig");
const username_mod = @import("username.zig");
const account_keys_mod = @import("account_keys.zig");
const service_id_mod = @import("service_id.zig");
const skdm_mod = @import("messages/sender_key_distribution_message.zig");
const err = @import("error.zig");

const gpa = std.heap.c_allocator;

// ── Kyber size constants (ML-KEM-1024) ────────────────────────────────────────

const KYBER_PK_LEN = curve.KyberKeyPair.KYBER_PUBLIC_KEY_LENGTH;
const KYBER_SK_LEN = curve.KyberKeyPair.KYBER_SECRET_KEY_LENGTH;
const KYBER_CT_LEN = curve.KyberKeyPair.CIPHERTEXT_LENGTH;
const KYBER_SS_LEN = curve.KyberKeyPair.SHARED_SECRET_LENGTH;
const MlKem = std.crypto.kem.ml_kem.MLKem1024;

// ── Error mapping ──────────────────────────────────────────────────────────────

fn toErrCode(e: anyerror) c_int {
    return switch (e) {
        err.SignalError.InvalidKey,
        err.SignalError.InvalidType,
        => -1,
        err.SignalError.InvalidSignature => -2,
        err.SignalError.InvalidMessage,
        err.SignalError.InvalidArgument,
        err.SignalError.LegacyCiphertextVersion,
        err.SignalError.UnknownCiphertextVersion,
        => -3,
        err.SignalError.UntrustedIdentity => -4,
        err.SignalError.DuplicateMessage => -5,
        err.SignalError.InvalidKeyIdentifier,
        err.SignalError.SessionNotFound,
        => -6,
        else => -7,
    };
}

// ── EC key operations ──────────────────────────────────────────────────────────

export fn libsignal_ec_keypair_generate(
    pub_out: *[33]u8,
    priv_out: *[32]u8,
) c_int {
    const kp = curve.KeyPair.generate() catch return -7;
    pub_out.* = kp.public_key.serialize();
    priv_out.* = kp.private_key.key_bytes;
    return 0;
}

export fn libsignal_ec_dh(
    their_pub: *const [33]u8,
    our_priv: *const [32]u8,
    shared_out: *[32]u8,
) c_int {
    const pk = curve.PublicKey.deserialize(their_pub) catch return -1;
    const sk = curve.PrivateKey{ .key_bytes = our_priv.* };
    const shared = sk.calculateAgreement(pk) catch return -7;
    shared_out.* = shared;
    return 0;
}

export fn libsignal_xeddsa_sign(
    priv: *const [32]u8,
    msg: [*]const u8,
    msg_len: usize,
    sig_out: *[64]u8,
) c_int {
    const sk = curve.PrivateKey{ .key_bytes = priv.* };
    const sig = sk.calculateSignature(msg[0..msg_len]) catch return -7;
    sig_out.* = sig;
    return 0;
}

export fn libsignal_xeddsa_verify(
    pub_key: *const [33]u8,
    msg: [*]const u8,
    msg_len: usize,
    sig: *const [64]u8,
) c_int {
    const pk = curve.PublicKey.deserialize(pub_key) catch return -1;
    const ok = pk.verifySignature(msg[0..msg_len], sig.*) catch return -7;
    return if (ok) 0 else -2;
}

// ── ML-KEM-1024 ────────────────────────────────────────────────────────────────

export fn libsignal_kyber1024_keypair_generate(
    pub_out: *[KYBER_PK_LEN]u8,
    sec_out: *[KYBER_SK_LEN]u8,
) c_int {
    const kp = curve.KyberKeyPair.generate() catch return -7;
    pub_out.* = kp.public_key_bytes;
    sec_out.* = kp.secret_key_bytes;
    return 0;
}

export fn libsignal_kyber1024_encaps(
    pub_key: *const [KYBER_PK_LEN]u8,
    ct_out: *[KYBER_CT_LEN]u8,
    ss_out: *[KYBER_SS_LEN]u8,
) c_int {
    const rnd = @import("random.zig");
    const pk = MlKem.PublicKey.fromBytes(pub_key) catch return -1;
    const seed = rnd.fillArray(MlKem.encaps_seed_length);
    const enc = pk.encapsDeterministic(&seed);
    ct_out.* = enc.ciphertext;
    ss_out.* = enc.shared_secret;
    return 0;
}

export fn libsignal_kyber1024_decaps(
    sec_key: *const [KYBER_SK_LEN]u8,
    ct: *const [KYBER_CT_LEN]u8,
    ss_out: *[KYBER_SS_LEN]u8,
) c_int {
    const sk = MlKem.SecretKey.fromBytes(sec_key) catch return -1;
    const ss = sk.decaps(ct) catch return -7;
    ss_out.* = ss;
    return 0;
}

// ── Session protocol ───────────────────────────────────────────────────────────
//
// Stores are provided as C callback structs. Each callback receives a userdata
// pointer (ud) as its first argument. Return 0 for success, negative for error,
// and -6 specifically from load callbacks to signal "not found".
//
// Heap-allocated outputs from load callbacks are expected to have been allocated
// with malloc and are freed by the library with free().

pub const CSessionStore = extern struct {
    ud: ?*anyopaque,
    load: ?*const fn (?*anyopaque, [*:0]const u8, u32, *?[*]u8, *usize) callconv(.c) c_int,
    store: ?*const fn (?*anyopaque, [*:0]const u8, u32, [*]const u8, usize) callconv(.c) c_int,
};

pub const CIdentityStore = extern struct {
    ud: ?*anyopaque,
    get_keypair: ?*const fn (?*anyopaque, *[33]u8, *[32]u8) callconv(.c) c_int,
    get_registration_id: ?*const fn (?*anyopaque, *u32) callconv(.c) c_int,
    save_identity: ?*const fn (?*anyopaque, [*:0]const u8, u32, *const [33]u8) callconv(.c) c_int,
    is_trusted: ?*const fn (?*anyopaque, [*:0]const u8, u32, *const [33]u8, c_int) callconv(.c) c_int,
};

pub const CPreKeyStore = extern struct {
    ud: ?*anyopaque,
    load: ?*const fn (?*anyopaque, u32, *[33]u8, *[32]u8) callconv(.c) c_int,
    remove: ?*const fn (?*anyopaque, u32) callconv(.c) c_int,
};

pub const CSignedPreKeyStore = extern struct {
    ud: ?*anyopaque,
    load: ?*const fn (?*anyopaque, u32, *[33]u8, *[32]u8, *[64]u8, *u64) callconv(.c) c_int,
};

pub const CKyberPreKeyStore = extern struct {
    ud: ?*anyopaque,
    load: ?*const fn (?*anyopaque, u32, *[KYBER_PK_LEN]u8, *[KYBER_SK_LEN]u8, *[64]u8) callconv(.c) c_int,
    mark_used: ?*const fn (?*anyopaque, u32) callconv(.c) c_int,
};

// ── Store adapters (C callbacks → Zig vtable) ──────────────────────────────────

const SessionStoreAdapter = struct {
    c: CSessionStore,

    fn loadSession(ptr: *anyopaque, addr: *const address_mod.ProtocolAddress) anyerror!?session_record_mod.SessionRecord {
        const self: *SessionStoreAdapter = @ptrCast(@alignCast(ptr));
        const f = self.c.load orelse return error.NotImplemented;
        const name_z = try gpa.dupeZ(u8, addr.name);
        defer gpa.free(name_z);
        var out_ptr: ?[*]u8 = null;
        var out_len: usize = 0;
        const rc = f(self.c.ud, name_z, addr.device_id, &out_ptr, &out_len);
        if (rc == -6) return null;
        if (rc != 0) return error.StoreError;
        const data = out_ptr.?[0..out_len];
        defer std.c.free(out_ptr);
        return try session_record_mod.SessionRecord.deserialize(gpa, data);
    }

    fn storeSession(ptr: *anyopaque, addr: *const address_mod.ProtocolAddress, record: *const session_record_mod.SessionRecord) anyerror!void {
        const self: *SessionStoreAdapter = @ptrCast(@alignCast(ptr));
        const f = self.c.store orelse return error.NotImplemented;
        const name_z = try gpa.dupeZ(u8, addr.name);
        defer gpa.free(name_z);
        const bytes = try record.serialize();
        defer gpa.free(bytes);
        const rc = f(self.c.ud, name_z, addr.device_id, bytes.ptr, bytes.len);
        if (rc != 0) return error.StoreError;
    }

    const vtable = storage.SessionStore.VTable{
        .loadSession = loadSession,
        .storeSession = storeSession,
    };

    fn store(self: *SessionStoreAdapter) storage.SessionStore {
        return .{ .ptr = self, .vtable = &vtable };
    }
};

const IdentityStoreAdapter = struct {
    c: CIdentityStore,

    fn getIdentityKeyPair(ptr: *anyopaque) anyerror!identity.IdentityKeyPair {
        const self: *IdentityStoreAdapter = @ptrCast(@alignCast(ptr));
        const f = self.c.get_keypair orelse return error.NotImplemented;
        var pub_bytes: [33]u8 = undefined;
        var priv_bytes: [32]u8 = undefined;
        if (f(self.c.ud, &pub_bytes, &priv_bytes) != 0) return error.StoreError;
        const pk = try curve.PublicKey.deserialize(&pub_bytes);
        const sk = curve.PrivateKey{ .key_bytes = priv_bytes };
        return .{ .identity_key = identity.IdentityKey.fromPublicKey(pk), .private_key = sk };
    }

    fn getLocalRegistrationId(ptr: *anyopaque) anyerror!u32 {
        const self: *IdentityStoreAdapter = @ptrCast(@alignCast(ptr));
        const f = self.c.get_registration_id orelse return error.NotImplemented;
        var id: u32 = 0;
        if (f(self.c.ud, &id) != 0) return error.StoreError;
        return id;
    }

    fn saveIdentity(ptr: *anyopaque, addr: *const address_mod.ProtocolAddress, key: identity.IdentityKey) anyerror!storage.IdentityChange {
        const self: *IdentityStoreAdapter = @ptrCast(@alignCast(ptr));
        const f = self.c.save_identity orelse return .new_or_unchanged;
        const name_z = try gpa.dupeZ(u8, addr.name);
        defer gpa.free(name_z);
        const key_bytes = key.serialize();
        // C callback returns 1 if an existing identity was replaced, 0 otherwise.
        return if (f(self.c.ud, name_z, addr.device_id, &key_bytes) == 1)
            storage.IdentityChange.replaced_existing
        else
            storage.IdentityChange.new_or_unchanged;
    }

    fn isTrustedIdentity(ptr: *anyopaque, addr: *const address_mod.ProtocolAddress, key: identity.IdentityKey, dir: storage.Direction) anyerror!bool {
        const self: *IdentityStoreAdapter = @ptrCast(@alignCast(ptr));
        const f = self.c.is_trusted orelse return true;
        const name_z = try gpa.dupeZ(u8, addr.name);
        defer gpa.free(name_z);
        const key_bytes = key.serialize();
        const dir_int: c_int = if (dir == .sending) 0 else 1;
        return f(self.c.ud, name_z, addr.device_id, &key_bytes, dir_int) == 1;
    }

    fn getIdentity(_: *anyopaque, _: *const address_mod.ProtocolAddress) anyerror!?identity.IdentityKey {
        return null;
    }

    const vtable = storage.IdentityKeyStore.VTable{
        .getIdentityKeyPair = getIdentityKeyPair,
        .getLocalRegistrationId = getLocalRegistrationId,
        .saveIdentity = saveIdentity,
        .isTrustedIdentity = isTrustedIdentity,
        .getIdentity = getIdentity,
    };

    fn store(self: *IdentityStoreAdapter) storage.IdentityKeyStore {
        return .{ .ptr = self, .vtable = &vtable };
    }
};

const PreKeyStoreAdapter = struct {
    c: CPreKeyStore,

    fn loadPreKey(ptr: *anyopaque, id: u32) anyerror!pre_key_record_mod.PreKeyRecord {
        const self: *PreKeyStoreAdapter = @ptrCast(@alignCast(ptr));
        const f = self.c.load orelse return err.SignalError.InvalidKeyIdentifier;
        var pub_bytes: [33]u8 = undefined;
        var priv_bytes: [32]u8 = undefined;
        const rc = f(self.c.ud, id, &pub_bytes, &priv_bytes);
        if (rc == -6) return err.SignalError.InvalidKeyIdentifier;
        if (rc != 0) return error.StoreError;
        const pk = try curve.PublicKey.deserialize(&pub_bytes);
        const sk = curve.PrivateKey{ .key_bytes = priv_bytes };
        return .{ .id = id, .key_pair = .{ .public_key = pk, .private_key = sk } };
    }

    fn storePreKey(_: *anyopaque, _: u32, _: *const pre_key_record_mod.PreKeyRecord) anyerror!void {}

    fn removePreKey(ptr: *anyopaque, id: u32) anyerror!void {
        const self: *PreKeyStoreAdapter = @ptrCast(@alignCast(ptr));
        const f = self.c.remove orelse return;
        _ = f(self.c.ud, id);
    }

    const vtable = storage.PreKeyStore.VTable{
        .loadPreKey = loadPreKey,
        .storePreKey = storePreKey,
        .removePreKey = removePreKey,
    };

    fn store(self: *PreKeyStoreAdapter) storage.PreKeyStore {
        return .{ .ptr = self, .vtable = &vtable };
    }
};

const SignedPreKeyStoreAdapter = struct {
    c: CSignedPreKeyStore,

    fn loadSignedPreKey(ptr: *anyopaque, id: u32) anyerror!signed_pre_key_record_mod.SignedPreKeyRecord {
        const self: *SignedPreKeyStoreAdapter = @ptrCast(@alignCast(ptr));
        const f = self.c.load orelse return err.SignalError.InvalidKeyIdentifier;
        var pub_bytes: [33]u8 = undefined;
        var priv_bytes: [32]u8 = undefined;
        var sig_bytes: [64]u8 = undefined;
        var timestamp: u64 = 0;
        const rc = f(self.c.ud, id, &pub_bytes, &priv_bytes, &sig_bytes, &timestamp);
        if (rc == -6) return err.SignalError.InvalidKeyIdentifier;
        if (rc != 0) return error.StoreError;
        const pk = try curve.PublicKey.deserialize(&pub_bytes);
        const sk = curve.PrivateKey{ .key_bytes = priv_bytes };
        return .{ .id = id, .timestamp = timestamp, .key_pair = .{ .public_key = pk, .private_key = sk }, .signature = sig_bytes };
    }

    fn storeSignedPreKey(_: *anyopaque, _: u32, _: *const signed_pre_key_record_mod.SignedPreKeyRecord) anyerror!void {}

    const vtable = storage.SignedPreKeyStore.VTable{
        .loadSignedPreKey = loadSignedPreKey,
        .storeSignedPreKey = storeSignedPreKey,
    };

    fn store(self: *SignedPreKeyStoreAdapter) storage.SignedPreKeyStore {
        return .{ .ptr = self, .vtable = &vtable };
    }
};

const KyberPreKeyStoreAdapter = struct {
    c: CKyberPreKeyStore,

    fn loadKyberPreKey(ptr: *anyopaque, id: u32) anyerror!kyber_pre_key_record_mod.KyberPreKeyRecord {
        const self: *KyberPreKeyStoreAdapter = @ptrCast(@alignCast(ptr));
        const f = self.c.load orelse return err.SignalError.InvalidKeyIdentifier;
        var pub_bytes: [KYBER_PK_LEN]u8 = undefined;
        var sec_bytes: [KYBER_SK_LEN]u8 = undefined;
        var sig_bytes: [64]u8 = undefined;
        const rc = f(self.c.ud, id, &pub_bytes, &sec_bytes, &sig_bytes);
        if (rc == -6) return err.SignalError.InvalidKeyIdentifier;
        if (rc != 0) return error.StoreError;
        return .{ .id = id, .timestamp = 0, .key_pair = .{ .public_key_bytes = pub_bytes, .secret_key_bytes = sec_bytes }, .signature = sig_bytes };
    }

    fn storeKyberPreKey(_: *anyopaque, _: u32, _: *const kyber_pre_key_record_mod.KyberPreKeyRecord) anyerror!void {}

    fn markKyberPreKeyUsed(ptr: *anyopaque, id: u32) anyerror!void {
        const self: *KyberPreKeyStoreAdapter = @ptrCast(@alignCast(ptr));
        const f = self.c.mark_used orelse return;
        _ = f(self.c.ud, id);
    }

    const vtable = storage.KyberPreKeyStore.VTable{
        .loadKyberPreKey = loadKyberPreKey,
        .storeKyberPreKey = storeKyberPreKey,
        .markKyberPreKeyUsed = markKyberPreKeyUsed,
    };

    fn store(self: *KyberPreKeyStoreAdapter) storage.KyberPreKeyStore {
        return .{ .ptr = self, .vtable = &vtable };
    }
};

// ── Opaque context handle ──────────────────────────────────────────────────────

const LibsignalCtx = struct {
    // Remote address — name slice points into name_buf below.
    remote_address: address_mod.ProtocolAddress,
    name_buf: [256]u8,
    name_len: usize,

    // Store adapters; must not be moved after ctx is created (vtables hold &self).
    session_adapter: SessionStoreAdapter,
    identity_adapter: IdentityStoreAdapter,
    pre_key_adapter: PreKeyStoreAdapter,
    signed_pre_key_adapter: SignedPreKeyStoreAdapter,
    kyber_adapter: ?KyberPreKeyStoreAdapter,
};

export fn libsignal_ctx_new(
    remote_name: [*:0]const u8,
    remote_device_id: u32,
    session_store: CSessionStore,
    identity_store: CIdentityStore,
    pre_key_store: CPreKeyStore,
    signed_pre_key_store: CSignedPreKeyStore,
    kyber_store: ?*const CKyberPreKeyStore,
) ?*LibsignalCtx {
    const ctx = gpa.create(LibsignalCtx) catch return null;
    const name = std.mem.span(remote_name);
    const copy_len = @min(name.len, ctx.name_buf.len - 1);
    @memcpy(ctx.name_buf[0..copy_len], name[0..copy_len]);
    ctx.name_buf[copy_len] = 0;
    ctx.name_len = copy_len;
    ctx.remote_address = .{
        .name = ctx.name_buf[0..ctx.name_len],
        .device_id = remote_device_id,
    };
    ctx.session_adapter = .{ .c = session_store };
    ctx.identity_adapter = .{ .c = identity_store };
    ctx.pre_key_adapter = .{ .c = pre_key_store };
    ctx.signed_pre_key_adapter = .{ .c = signed_pre_key_store };
    ctx.kyber_adapter = if (kyber_store) |ks| .{ .c = ks.* } else null;
    return ctx;
}

export fn libsignal_ctx_free(ctx: ?*LibsignalCtx) void {
    if (ctx) |c| gpa.destroy(c);
}

// ── Session protocol operations ────────────────────────────────────────────────

export fn libsignal_process_prekey_bundle(
    ctx: *LibsignalCtx,
    registration_id: u32,
    pre_key_id: u32,
    pre_key_pub: ?*const [33]u8,
    signed_pre_key_id: u32,
    signed_pre_key_pub: *const [33]u8,
    signed_pre_key_sig: *const [64]u8,
    identity_pub: *const [33]u8,
    kyber_pre_key_id: u32,
    kyber_pub: ?*const [KYBER_PK_LEN]u8,
    kyber_sig: ?*const [64]u8,
) c_int {
    const result = processPreKeyBundleInner(ctx, registration_id, pre_key_id, pre_key_pub, signed_pre_key_id, signed_pre_key_pub, signed_pre_key_sig, identity_pub, kyber_pre_key_id, kyber_pub, kyber_sig) catch |e| return toErrCode(e);
    _ = result;
    return 0;
}

fn processPreKeyBundleInner(
    ctx: *LibsignalCtx,
    registration_id: u32,
    pre_key_id: u32,
    pre_key_pub: ?*const [33]u8,
    signed_pre_key_id: u32,
    signed_pre_key_pub: *const [33]u8,
    signed_pre_key_sig: *const [64]u8,
    identity_pub: *const [33]u8,
    kyber_pre_key_id: u32,
    kyber_pub: ?*const [KYBER_PK_LEN]u8,
    kyber_sig: ?*const [64]u8,
) !void {
    const their_ik_pk = try curve.PublicKey.deserialize(identity_pub);
    const their_ik = identity.IdentityKey.fromPublicKey(their_ik_pk);
    const spk_pub = try curve.PublicKey.deserialize(signed_pre_key_pub);

    const bundle = bundle_mod.PreKeyBundle.new(
        registration_id,
        ctx.remote_address.device_id,
        if (pre_key_id != 0) @as(?u32, pre_key_id) else null,
        if (pre_key_pub) |p| @as(?curve.PublicKey, try curve.PublicKey.deserialize(p)) else null,
        signed_pre_key_id,
        spk_pub,
        signed_pre_key_sig.*,
        their_ik,
        if (kyber_pre_key_id != 0) @as(?u32, kyber_pre_key_id) else null,
        if (kyber_pub) |kp| @as(?[KYBER_PK_LEN]u8, kp.*) else null,
        if (kyber_sig) |ks| @as(?[64]u8, ks.*) else null,
    );

    var builder = session_builder_mod.SessionBuilder.init(
        gpa,
        ctx.remote_address,
        ctx.session_adapter.store(),
        ctx.pre_key_adapter.store(),
        ctx.signed_pre_key_adapter.store(),
        ctx.identity_adapter.store(),
        if (ctx.kyber_adapter != null) ctx.kyber_adapter.?.store() else null,
    );
    try builder.processPreKeyBundle(bundle);
}

export fn libsignal_encrypt(
    ctx: *LibsignalCtx,
    plaintext: [*]const u8,
    plaintext_len: usize,
    ct_out: *?[*]u8,
    ct_len_out: *usize,
    msg_type_out: *c_int,
) c_int {
    const result = encryptInner(ctx, plaintext[0..plaintext_len]) catch |e| return toErrCode(e);
    ct_out.* = result.ptr;
    ct_len_out.* = result.len;
    msg_type_out.* = result.msg_type;
    return 0;
}

const EncryptResult = struct { ptr: [*]u8, len: usize, msg_type: c_int };

fn encryptInner(ctx: *LibsignalCtx, plaintext: []const u8) !EncryptResult {
    var cipher = session_cipher_mod.SessionCipher.init(
        gpa,
        ctx.remote_address,
        ctx.session_adapter.store(),
        ctx.pre_key_adapter.store(),
        ctx.signed_pre_key_adapter.store(),
        ctx.identity_adapter.store(),
        if (ctx.kyber_adapter != null) ctx.kyber_adapter.?.store() else null,
    );
    var ct = try cipher.encrypt(plaintext);
    // Transfer ownership to caller; serialized is already malloc'd via c_allocator.
    const ptr = ct.serialized.ptr;
    const len = ct.serialized.len;
    const msg_type: c_int = @intFromEnum(ct.message_type);
    ct.serialized = &.{}; // prevent double-free in deinit
    ct.deinit();
    return .{ .ptr = @constCast(ptr), .len = len, .msg_type = msg_type };
}

export fn libsignal_decrypt_prekey(
    ctx: *LibsignalCtx,
    ct: [*]const u8,
    ct_len: usize,
    pt_out: *?[*]u8,
    pt_len_out: *usize,
) c_int {
    const pt = decryptPrekeyInner(ctx, ct[0..ct_len]) catch |e| return toErrCode(e);
    pt_out.* = pt.ptr;
    pt_len_out.* = pt.len;
    return 0;
}

fn decryptPrekeyInner(ctx: *LibsignalCtx, ct: []const u8) ![]u8 {
    var cipher = session_cipher_mod.SessionCipher.init(
        gpa,
        ctx.remote_address,
        ctx.session_adapter.store(),
        ctx.pre_key_adapter.store(),
        ctx.signed_pre_key_adapter.store(),
        ctx.identity_adapter.store(),
        if (ctx.kyber_adapter != null) ctx.kyber_adapter.?.store() else null,
    );
    return cipher.decryptPreKeyMessage(ct);
}

export fn libsignal_decrypt(
    ctx: *LibsignalCtx,
    ct: [*]const u8,
    ct_len: usize,
    pt_out: *?[*]u8,
    pt_len_out: *usize,
) c_int {
    const pt = decryptInner(ctx, ct[0..ct_len]) catch |e| return toErrCode(e);
    pt_out.* = pt.ptr;
    pt_len_out.* = pt.len;
    return 0;
}

fn decryptInner(ctx: *LibsignalCtx, ct: []const u8) ![]u8 {
    var cipher = session_cipher_mod.SessionCipher.init(
        gpa,
        ctx.remote_address,
        ctx.session_adapter.store(),
        ctx.pre_key_adapter.store(),
        ctx.signed_pre_key_adapter.store(),
        ctx.identity_adapter.store(),
        if (ctx.kyber_adapter != null) ctx.kyber_adapter.?.store() else null,
    );
    return cipher.decryptMessage(ct);
}

// ── Group messaging ───────────────────────────────────────────────────────────
//
// CSenderKeyStore callbacks: store/load keyed by (name_z, device_id, dist_id[16]).
// load returns -6 when no record exists (not found), 0 on success.
// Heap-allocated output from load must have been allocated with malloc.

pub const CSenderKeyStore = extern struct {
    ud: ?*anyopaque,
    store: ?*const fn (?*anyopaque, [*:0]const u8, u32, *const [16]u8, [*]const u8, usize) callconv(.c) c_int,
    load: ?*const fn (?*anyopaque, [*:0]const u8, u32, *const [16]u8, *?[*]u8, *usize) callconv(.c) c_int,
};

const SenderKeyStoreAdapter = struct {
    c: CSenderKeyStore,

    fn storeSenderKey(ptr: *anyopaque, sender: *const address_mod.ProtocolAddress, dist_id: [16]u8, record: []const u8) anyerror!void {
        const self: *SenderKeyStoreAdapter = @ptrCast(@alignCast(ptr));
        const f = self.c.store orelse return error.NotImplemented;
        const name_z = try gpa.dupeZ(u8, sender.name);
        defer gpa.free(name_z);
        if (f(self.c.ud, name_z, sender.device_id, &dist_id, record.ptr, record.len) != 0)
            return error.StoreError;
    }

    fn loadSenderKey(ptr: *anyopaque, sender: *const address_mod.ProtocolAddress, dist_id: [16]u8) anyerror!?[]u8 {
        const self: *SenderKeyStoreAdapter = @ptrCast(@alignCast(ptr));
        const f = self.c.load orelse return null;
        const name_z = try gpa.dupeZ(u8, sender.name);
        defer gpa.free(name_z);
        var out_ptr: ?[*]u8 = null;
        var out_len: usize = 0;
        const rc = f(self.c.ud, name_z, sender.device_id, &dist_id, &out_ptr, &out_len);
        if (rc == -6) return null;
        if (rc != 0) return error.StoreError;
        const data = out_ptr.?[0..out_len];
        defer std.c.free(out_ptr);
        return try gpa.dupe(u8, data);
    }

    const vtable = storage.SenderKeyStore.VTable{
        .storeSenderKey = storeSenderKey,
        .loadSenderKey = loadSenderKey,
    };

    fn store(self: *SenderKeyStoreAdapter) storage.SenderKeyStore {
        return .{ .ptr = self, .vtable = &vtable };
    }
};

/// Create (or retrieve existing) sender key session, returning a serialized
/// SenderKeyDistributionMessage the caller must distribute to group members.
/// distribution_id: 16-byte UUID identifying this group session.
export fn libsignal_group_create_session(
    sender_name: [*:0]const u8,
    sender_device_id: u32,
    distribution_id: *const [16]u8,
    sk_store: CSenderKeyStore,
    skdm_out: *?[*]u8,
    skdm_len_out: *usize,
) c_int {
    const result = groupCreateSessionInner(sender_name, sender_device_id, distribution_id.*, sk_store) catch |e| return toErrCode(e);
    skdm_out.* = result.ptr;
    skdm_len_out.* = result.len;
    return 0;
}

fn groupCreateSessionInner(
    sender_name: [*:0]const u8,
    sender_device_id: u32,
    distribution_id: [16]u8,
    c_store: CSenderKeyStore,
) ![]u8 {
    var adapter = SenderKeyStoreAdapter{ .c = c_store };
    var builder = group_session_builder_mod.GroupSessionBuilder.init(gpa, adapter.store());
    const name_slice = std.mem.span(sender_name);
    const sender = address_mod.ProtocolAddress{ .name = name_slice, .device_id = sender_device_id };
    var skdm = try builder.createSession(&sender, distribution_id);
    defer skdm.deinit();
    return skdm.serialize();
}

/// Process a received SenderKeyDistributionMessage from a group member.
/// skdm_bytes: serialized SenderKeyDistributionMessage.
export fn libsignal_group_process_session(
    sender_name: [*:0]const u8,
    sender_device_id: u32,
    skdm_bytes: [*]const u8,
    skdm_len: usize,
    sk_store: CSenderKeyStore,
) c_int {
    groupProcessSessionInner(sender_name, sender_device_id, skdm_bytes[0..skdm_len], sk_store) catch |e| return toErrCode(e);
    return 0;
}

fn groupProcessSessionInner(
    sender_name: [*:0]const u8,
    sender_device_id: u32,
    skdm_bytes: []const u8,
    c_store: CSenderKeyStore,
) !void {
    var adapter = SenderKeyStoreAdapter{ .c = c_store };
    var builder = group_session_builder_mod.GroupSessionBuilder.init(gpa, adapter.store());
    const name_slice = std.mem.span(sender_name);
    const sender = address_mod.ProtocolAddress{ .name = name_slice, .device_id = sender_device_id };
    var skdm = try skdm_mod.SenderKeyDistributionMessage.deserialize(gpa, skdm_bytes);
    defer skdm.deinit();
    try builder.processSession(&sender, &skdm);
}

/// Encrypt a group message. Returns the serialized SenderKeyMessage.
export fn libsignal_group_encrypt(
    sender_name: [*:0]const u8,
    sender_device_id: u32,
    distribution_id: *const [16]u8,
    plaintext: [*]const u8,
    plaintext_len: usize,
    sk_store: CSenderKeyStore,
    ct_out: *?[*]u8,
    ct_len_out: *usize,
) c_int {
    const ct = groupEncryptInner(sender_name, sender_device_id, distribution_id.*, plaintext[0..plaintext_len], sk_store) catch |e| return toErrCode(e);
    ct_out.* = ct.ptr;
    ct_len_out.* = ct.len;
    return 0;
}

fn groupEncryptInner(
    sender_name: [*:0]const u8,
    sender_device_id: u32,
    distribution_id: [16]u8,
    plaintext: []const u8,
    c_store: CSenderKeyStore,
) ![]u8 {
    var adapter = SenderKeyStoreAdapter{ .c = c_store };
    const name_slice = std.mem.span(sender_name);
    const sender = address_mod.ProtocolAddress{ .name = name_slice, .device_id = sender_device_id };
    var cipher = group_cipher_mod.GroupCipher.init(gpa, adapter.store(), sender, distribution_id);
    return cipher.encrypt(plaintext);
}

/// Decrypt a group message (SenderKeyMessage). Returns the plaintext.
export fn libsignal_group_decrypt(
    sender_name: [*:0]const u8,
    sender_device_id: u32,
    distribution_id: *const [16]u8,
    ciphertext: [*]const u8,
    ciphertext_len: usize,
    sk_store: CSenderKeyStore,
    pt_out: *?[*]u8,
    pt_len_out: *usize,
) c_int {
    const pt = groupDecryptInner(sender_name, sender_device_id, distribution_id.*, ciphertext[0..ciphertext_len], sk_store) catch |e| return toErrCode(e);
    pt_out.* = pt.ptr;
    pt_len_out.* = pt.len;
    return 0;
}

fn groupDecryptInner(
    sender_name: [*:0]const u8,
    sender_device_id: u32,
    distribution_id: [16]u8,
    ciphertext: []const u8,
    c_store: CSenderKeyStore,
) ![]u8 {
    var adapter = SenderKeyStoreAdapter{ .c = c_store };
    const name_slice = std.mem.span(sender_name);
    const sender = address_mod.ProtocolAddress{ .name = name_slice, .device_id = sender_device_id };
    var cipher = group_cipher_mod.GroupCipher.init(gpa, adapter.store(), sender, distribution_id);
    return cipher.decrypt(ciphertext);
}

// ── Sealed sender ─────────────────────────────────────────────────────────────

/// Build and serialize a ServerCertificate.
/// trust_root_priv: 32-byte private key of the server's trust root.
/// Returns heap-allocated serialized bytes; caller must free().
export fn libsignal_server_cert_serialize(
    key_id: u32,
    key_pub: *const [33]u8,
    trust_root_priv: *const [32]u8,
    out: *?[*]u8,
    out_len: *usize,
) c_int {
    const result = serverCertSerializeInner(key_id, key_pub, trust_root_priv) catch |e| return toErrCode(e);
    out.* = result.ptr;
    out_len.* = result.len;
    return 0;
}

fn serverCertSerializeInner(key_id: u32, key_pub: *const [33]u8, trust_root_priv: *const [32]u8) ![]u8 {
    const pk = try curve.PublicKey.deserialize(key_pub);
    const sk = curve.PrivateKey{ .key_bytes = trust_root_priv.* };
    var sc = try sealed_sender_mod.ServerCertificate.new(gpa, key_id, pk, sk);
    defer sc.deinit();
    return sc.serialize();
}

/// Build and serialize a SenderCertificate.
/// sender_e164_z: null-terminated E.164 string, or null if absent.
/// server_key_priv: 32-byte private key used to sign the sender certificate.
/// Returns heap-allocated serialized bytes; caller must free().
export fn libsignal_sender_cert_serialize(
    sender_uuid_z: [*:0]const u8,
    sender_e164_z: ?[*:0]const u8,
    sender_device_id: u32,
    sender_key_pub: *const [33]u8,
    expiration: u64,
    server_cert_bytes: [*]const u8,
    server_cert_len: usize,
    server_key_priv: *const [32]u8,
    out: *?[*]u8,
    out_len: *usize,
) c_int {
    const result = senderCertSerializeInner(
        sender_uuid_z,
        sender_e164_z,
        sender_device_id,
        sender_key_pub,
        expiration,
        server_cert_bytes[0..server_cert_len],
        server_key_priv,
    ) catch |e| return toErrCode(e);
    out.* = result.ptr;
    out_len.* = result.len;
    return 0;
}

fn senderCertSerializeInner(
    sender_uuid_z: [*:0]const u8,
    sender_e164_z: ?[*:0]const u8,
    sender_device_id: u32,
    sender_key_pub: *const [33]u8,
    expiration: u64,
    server_cert_bytes: []const u8,
    server_key_priv: *const [32]u8,
) ![]u8 {
    const sender_key = try curve.PublicKey.deserialize(sender_key_pub);
    const server_key = curve.PrivateKey{ .key_bytes = server_key_priv.* };
    var server_cert = try sealed_sender_mod.ServerCertificate.deserialize(gpa, server_cert_bytes);
    // errdefer only: on success, ownership transfers to sc.signer; sc.deinit() handles cleanup.
    errdefer server_cert.deinit();
    var sc = try sealed_sender_mod.SenderCertificate.new(
        gpa,
        std.mem.span(sender_uuid_z),
        if (sender_e164_z) |e| std.mem.span(e) else null,
        sender_device_id,
        sender_key,
        expiration,
        server_cert,
        server_key,
    );
    defer sc.deinit();
    return sc.serialize();
}

/// V1 sealed sender encrypt.
/// group_id_z: null-terminated group ID string, or null.
/// Returns heap-allocated ciphertext; caller must free().
export fn libsignal_sealed_sender_encrypt(
    recipient_pub: *const [33]u8,
    sender_cert_bytes: [*]const u8,
    sender_cert_len: usize,
    msg_type: u8,
    content_hint: u8,
    group_id_z: ?[*:0]const u8,
    plaintext: [*]const u8,
    plaintext_len: usize,
    out: *?[*]u8,
    out_len: *usize,
) c_int {
    const result = sealedSenderEncryptInner(
        recipient_pub,
        sender_cert_bytes[0..sender_cert_len],
        msg_type,
        content_hint,
        group_id_z,
        plaintext[0..plaintext_len],
    ) catch |e| return toErrCode(e);
    out.* = result.ptr;
    out_len.* = result.len;
    return 0;
}

fn sealedSenderEncryptInner(
    recipient_pub: *const [33]u8,
    sender_cert_bytes: []const u8,
    msg_type: u8,
    content_hint: u8,
    group_id_z: ?[*:0]const u8,
    plaintext: []const u8,
) ![]u8 {
    const r_pub = try curve.PublicKey.deserialize(recipient_pub);
    var sc = try sealed_sender_mod.SenderCertificate.deserialize(gpa, sender_cert_bytes);
    // errdefer only: on success, ownership transfers to usmc.sender_cert; usmc.deinit() handles cleanup.
    errdefer sc.deinit();
    const ct: sealed_sender_mod.ContentType = @enumFromInt(msg_type);
    const ch: sealed_sender_mod.ContentHint = @enumFromInt(content_hint);
    const gid: ?[]const u8 = if (group_id_z) |g| std.mem.span(g) else null;
    var usmc = try sealed_sender_mod.UnidentifiedSenderMessageContent.new(gpa, ct, sc, ch, gid, plaintext);
    defer usmc.deinit();
    return sealed_sender_mod.sealedSenderEncrypt(gpa, r_pub, &usmc);
}

/// V1 sealed sender decrypt. Outputs sender_uuid, sender_e164 (may be null),
/// sender_device_id, content_type, and contents as separate heap-allocated values.
/// Caller must free: sender_uuid_out, sender_e164_out (if non-null), contents_out.
export fn libsignal_sealed_sender_decrypt(
    data: [*]const u8,
    data_len: usize,
    our_priv: *const [32]u8,
    sender_uuid_out: *?[*]u8,
    sender_uuid_len_out: *usize,
    sender_e164_out: *?[*]u8,
    sender_e164_len_out: *usize,
    sender_device_id_out: *u32,
    content_type_out: *u8,
    contents_out: *?[*]u8,
    contents_len_out: *usize,
) c_int {
    sealedSenderDecryptInner(
        data[0..data_len],
        our_priv,
        sender_uuid_out,
        sender_uuid_len_out,
        sender_e164_out,
        sender_e164_len_out,
        sender_device_id_out,
        content_type_out,
        contents_out,
        contents_len_out,
    ) catch |e| return toErrCode(e);
    return 0;
}

fn sealedSenderDecryptInner(
    data: []const u8,
    our_priv: *const [32]u8,
    sender_uuid_out: *?[*]u8,
    sender_uuid_len_out: *usize,
    sender_e164_out: *?[*]u8,
    sender_e164_len_out: *usize,
    sender_device_id_out: *u32,
    content_type_out: *u8,
    contents_out: *?[*]u8,
    contents_len_out: *usize,
) !void {
    const sk = curve.PrivateKey{ .key_bytes = our_priv.* };
    var usmc = try sealed_sender_mod.sealedSenderDecryptToUsmc(gpa, data, sk);
    defer usmc.deinit();

    const uuid = try gpa.dupe(u8, usmc.sender_cert.sender_uuid);
    errdefer gpa.free(uuid);
    const e164: ?[]u8 = if (usmc.sender_cert.sender_e164) |e| try gpa.dupe(u8, e) else null;
    errdefer if (e164) |e| gpa.free(e);
    const contents = try gpa.dupe(u8, usmc.contents);

    sender_uuid_out.* = uuid.ptr;
    sender_uuid_len_out.* = uuid.len;
    sender_e164_out.* = if (e164) |e| e.ptr else null;
    sender_e164_len_out.* = if (e164) |e| e.len else 0;
    sender_device_id_out.* = usmc.sender_cert.sender_device_id;
    content_type_out.* = @intFromEnum(usmc.msg_type);
    contents_out.* = contents.ptr;
    contents_len_out.* = contents.len;
}

/// V2 sealed sender recipient descriptor (C-compatible layout).
pub const CSealedSenderV2Recipient = extern struct {
    service_id_fixed: [17]u8, // ServiceId fixed-width binary (type_byte || uuid[16])
    device_id: u8,
    identity_pub: [33]u8,
};

/// V2 sealed sender encrypt (multi-recipient AES-256-GCM-SIV).
/// excluded_sids: array of fixed-width ServiceId bytes (17 bytes each), or null.
/// Returns heap-allocated sent-message bytes (version 0x23); caller must free().
export fn libsignal_sealed_sender_encrypt_v2(
    message: [*]const u8,
    message_len: usize,
    sender_priv: *const [32]u8,
    sender_pub: *const [33]u8,
    recipients: [*]const CSealedSenderV2Recipient,
    recipient_count: usize,
    excluded_sids: ?[*]const [17]u8,
    excluded_count: usize,
    out: *?[*]u8,
    out_len: *usize,
) c_int {
    const result = sealedSenderEncryptV2Inner(
        message[0..message_len],
        sender_priv,
        sender_pub,
        recipients[0..recipient_count],
        if (excluded_sids) |e| e[0..excluded_count] else &.{},
    ) catch |e| return toErrCode(e);
    out.* = result.ptr;
    out_len.* = result.len;
    return 0;
}

fn sealedSenderEncryptV2Inner(
    message: []const u8,
    sender_priv: *const [32]u8,
    sender_pub: *const [33]u8,
    c_recipients: []const CSealedSenderV2Recipient,
    c_excluded: []const [17]u8,
) ![]u8 {
    const s_priv = curve.PrivateKey{ .key_bytes = sender_priv.* };
    const s_pub = try curve.PublicKey.deserialize(sender_pub);
    const sender_kp = curve.KeyPair{ .private_key = s_priv, .public_key = s_pub };

    const recipients = try gpa.alloc(sealed_sender_mod.SealedSenderV2Recipient, c_recipients.len);
    defer gpa.free(recipients);
    for (c_recipients, 0..) |cr, i| {
        recipients[i] = .{
            .service_id = try service_id_mod.ServiceId.fromFixedWidthBinary(cr.service_id_fixed),
            .device_id = cr.device_id,
            .identity_key = try curve.PublicKey.deserialize(&cr.identity_pub),
        };
    }

    const excluded = try gpa.alloc(service_id_mod.ServiceId, c_excluded.len);
    defer gpa.free(excluded);
    for (c_excluded, 0..) |e, i| {
        excluded[i] = try service_id_mod.ServiceId.fromFixedWidthBinary(e);
    }

    return sealed_sender_mod.sealedSenderEncryptV2(gpa, message, sender_kp, recipients, excluded);
}

// Per-recipient entry sizes in the sent (0x23) format:
//   service_id[17] + device_id[1] + reg_id/has_more[2] + C[32] + AT[16] = 68 bytes
const V2_SENT_ENTRY_LEN: usize = 17 + 1 + 2 + 32 + 16;

/// Convert a V2 "sent message" (version 0x23) into the per-device "received message"
/// (version 0x22) for the first recipient whose (service_id, device_id) matches.
/// This models the Signal server's per-recipient dispatch step.
/// Returns heap-allocated received message bytes (0x22 format); caller must free().
export fn libsignal_sealed_sender_v2_dispatch(
    sent: [*]const u8,
    sent_len: usize,
    service_id_fixed: *const [17]u8,
    device_id: u8,
    out: *?[*]u8,
    out_len: *usize,
) c_int {
    const result = v2DispatchInner(sent[0..sent_len], service_id_fixed, device_id) catch |e| return toErrCode(e);
    out.* = result.ptr;
    out_len.* = result.len;
    return 0;
}

fn v2DispatchInner(sent: []const u8, service_id_fixed: *const [17]u8, target_device_id: u8) ![]u8 {
    const SSV2_SENT: u8 = 0x23;
    const SSV2_RECV: u8 = 0x22;
    if (sent.len < 2) return err.SignalError.InvalidMessage;
    if (sent[0] != SSV2_SENT) return err.SignalError.UnknownCiphertextVersion;

    // Read varint recipient count
    var pos: usize = 1;
    var recipient_count: usize = 0;
    var shift: u6 = 0;
    while (pos < sent.len) {
        const b = sent[pos];
        pos += 1;
        recipient_count |= @as(usize, b & 0x7F) << shift;
        if (b & 0x80 == 0) break;
        shift += 7;
        if (shift >= 64) return err.SignalError.InvalidMessage;
    }

    const entries_start = pos;
    const entries_end = entries_start + recipient_count * V2_SENT_ENTRY_LEN;
    if (entries_end + 32 > sent.len) return err.SignalError.InvalidMessage;

    // Scan entries for matching recipient
    var found_c: ?[32]u8 = null;
    var found_at: ?[16]u8 = null;
    for (0..recipient_count) |i| {
        const e = entries_start + i * V2_SENT_ENTRY_LEN;
        const sid = sent[e .. e + 17];
        const dev = sent[e + 17];
        // skip 2-byte reg_id/has_more
        const c_off = e + 20;
        const at_off = c_off + 32;
        if (std.mem.eql(u8, sid, service_id_fixed) and dev == target_device_id) {
            found_c = sent[c_off .. c_off + 32][0..32].*;
            found_at = sent[at_off .. at_off + 16][0..16].*;
            break;
        }
    }

    const c = found_c orelse return err.SignalError.InvalidKeyIdentifier;
    const at = found_at orelse return err.SignalError.InvalidKeyIdentifier;

    // e_pub (32 bytes) + ciphertext immediately follow the entries
    const e_pub: [32]u8 = sent[entries_end .. entries_end + 32][0..32].*;
    const ciphertext = sent[entries_end + 32 ..];

    // Build 0x22 received message: 0x22 || C[32] || AT[16] || e_pub[32] || ciphertext
    const recv = try gpa.alloc(u8, 1 + 32 + 16 + 32 + ciphertext.len);
    recv[0] = SSV2_RECV;
    @memcpy(recv[1..33], &c);
    @memcpy(recv[33..49], &at);
    @memcpy(recv[49..81], &e_pub);
    @memcpy(recv[81..], ciphertext);
    return recv;
}

/// V2 sealed sender decrypt. Returns the decrypted plaintext; caller must free().
export fn libsignal_sealed_sender_decrypt_v2(
    received: [*]const u8,
    received_len: usize,
    our_priv: *const [32]u8,
    our_pub: *const [33]u8,
    sender_pub: *const [33]u8,
    out: *?[*]u8,
    out_len: *usize,
) c_int {
    const result = sealedSenderDecryptV2Inner(received[0..received_len], our_priv, our_pub, sender_pub) catch |e| return toErrCode(e);
    out.* = result.ptr;
    out_len.* = result.len;
    return 0;
}

fn sealedSenderDecryptV2Inner(
    received: []const u8,
    our_priv: *const [32]u8,
    our_pub: *const [33]u8,
    sender_pub: *const [33]u8,
) ![]u8 {
    const r_priv = curve.PrivateKey{ .key_bytes = our_priv.* };
    const r_pub = try curve.PublicKey.deserialize(our_pub);
    const s_pub = try curve.PublicKey.deserialize(sender_pub);
    const our_kp = curve.KeyPair{ .private_key = r_priv, .public_key = r_pub };
    return sealed_sender_mod.sealedSenderDecryptV2(gpa, received, our_kp, s_pub);
}

// ── Fingerprint ───────────────────────────────────────────────────────────────

/// Compute a fingerprint for two identity keys.
/// local/remote_stable_id: phone number or other stable identifier bytes.
/// displayable_out: caller-provided [60]u8 buffer filled with the decimal digit string.
/// scannable_out / scannable_len_out: heap-allocated serialized ScannableFingerprint; caller must free().
export fn libsignal_fingerprint_compute(
    local_pub: *const [33]u8,
    local_stable_id: [*]const u8,
    local_stable_id_len: usize,
    remote_pub: *const [33]u8,
    remote_stable_id: [*]const u8,
    remote_stable_id_len: usize,
    displayable_out: *[60]u8,
    scannable_out: *?[*]u8,
    scannable_len_out: *usize,
) c_int {
    fingerprintComputeInner(
        local_pub,
        local_stable_id[0..local_stable_id_len],
        remote_pub,
        remote_stable_id[0..remote_stable_id_len],
        displayable_out,
        scannable_out,
        scannable_len_out,
    ) catch |e| return toErrCode(e);
    return 0;
}

fn fingerprintComputeInner(
    local_pub: *const [33]u8,
    local_stable_id: []const u8,
    remote_pub: *const [33]u8,
    remote_stable_id: []const u8,
    displayable_out: *[60]u8,
    scannable_out: *?[*]u8,
    scannable_len_out: *usize,
) !void {
    const lk_raw = try curve.PublicKey.deserialize(local_pub);
    const rk_raw = try curve.PublicKey.deserialize(remote_pub);
    const local_ik = identity.IdentityKey.fromPublicKey(lk_raw);
    const remote_ik = identity.IdentityKey.fromPublicKey(rk_raw);
    const fp = try fingerprint_mod.Fingerprint.compute(gpa, local_ik, local_stable_id, remote_ik, remote_stable_id);
    displayable_out.* = fp.displayable.digits();
    const scannable_bytes = try fp.scannable.serialize();
    scannable_out.* = scannable_bytes.ptr;
    scannable_len_out.* = scannable_bytes.len;
}

/// Compare two serialized ScannableFingerprints.
/// match_out: set to 1 if they match, 0 otherwise.
export fn libsignal_fingerprint_compare(
    local_scannable: [*]const u8,
    local_len: usize,
    their_scannable: [*]const u8,
    their_len: usize,
    match_out: *c_int,
) c_int {
    const fp = fingerprint_mod.ScannableFingerprint.compareTo(
        // We need to deserialize local first — build from its bytes
        blk: {
            // Parse local scannable bytes to reconstruct ScannableFingerprint
            const bytes = local_scannable[0..local_len];
            var pos: usize = 0;
            const proto_mod = @import("proto.zig");
            var local_fp: [32]u8 = std.mem.zeroes([32]u8);
            var remote_fp: [32]u8 = std.mem.zeroes([32]u8);
            while (proto_mod.nextField(bytes, &pos) catch null) |field| {
                switch (field.number) {
                    2 => {
                        if (field.wire_type == .len and field.data.len.len == 32) local_fp = field.data.len[0..32].*;
                    },
                    3 => {
                        if (field.wire_type == .len and field.data.len.len == 32) remote_fp = field.data.len[0..32].*;
                    },
                    else => {},
                }
            }
            break :blk fingerprint_mod.ScannableFingerprint{
                .version = 0,
                .local_fingerprint = local_fp,
                .remote_fingerprint = remote_fp,
                .allocator = gpa,
            };
        },
        their_scannable[0..their_len],
    ) catch |e| return toErrCode(e);
    match_out.* = if (fp) 1 else 0;
    return 0;
}

// ── Username ──────────────────────────────────────────────────────────────────

/// Compute the 32-byte hash for a username (e.g. "alice.42").
export fn libsignal_username_hash(
    username_z: [*:0]const u8,
    hash_out: *[32]u8,
) c_int {
    const h = username_mod.UsernameHash.compute(std.mem.span(username_z)) catch |e| return toErrCode(e);
    hash_out.* = h.hash;
    return 0;
}

/// Generate a 128-byte ZK proof that the caller knows the username behind hash_out.
/// randomness: 32 bytes of caller-supplied entropy (use a CSPRNG).
/// proof_out: caller-provided [128]u8 buffer.
export fn libsignal_username_proof(
    username_z: [*:0]const u8,
    randomness: *const [32]u8,
    proof_out: *[128]u8,
) c_int {
    const proof = username_mod.usernameProof(gpa, std.mem.span(username_z), randomness.*) catch |e| return toErrCode(e);
    defer gpa.free(proof);
    @memcpy(proof_out, proof[0..128]);
    return 0;
}

/// Verify a 128-byte ZK proof against a username hash.
/// valid_out: set to 1 if valid, 0 otherwise.
export fn libsignal_username_verify(
    username_hash: *const [32]u8,
    proof: *const [128]u8,
    valid_out: *c_int,
) c_int {
    const valid = username_mod.usernameVerify(gpa, username_hash.*, proof) catch |e| return toErrCode(e);
    valid_out.* = if (valid) 1 else 0;
    return 0;
}

// ── Account keys ──────────────────────────────────────────────────────────────

/// Generate a fresh 64-character AccountEntropyPool.
/// pool_out: caller-provided [64]u8 buffer (ASCII base-32 alphabet characters).
export fn libsignal_account_entropy_pool_generate(pool_out: *[64]u8) void {
    const pool = account_keys_mod.AccountEntropyPool.generate();
    @memcpy(pool_out, &pool.data);
}

/// Parse and validate a 64-character AccountEntropyPool string.
export fn libsignal_account_entropy_pool_parse(pool_str: *const [64]u8) c_int {
    _ = account_keys_mod.AccountEntropyPool.fromString(pool_str) catch return toErrCode(err.SignalError.InvalidArgument);
    return 0;
}

/// Derive the 32-byte SVR (Secure Value Recovery) master key from the entropy pool.
export fn libsignal_account_entropy_derive_svr_key(
    pool_str: *const [64]u8,
    key_out: *[32]u8,
) c_int {
    const pool = account_keys_mod.AccountEntropyPool.fromString(pool_str) catch return toErrCode(err.SignalError.InvalidArgument);
    key_out.* = pool.deriveSvrKey();
    return 0;
}

/// Derive the 32-byte backup key from the entropy pool.
export fn libsignal_account_entropy_derive_backup_key(
    pool_str: *const [64]u8,
    key_out: *[32]u8,
) c_int {
    const pool = account_keys_mod.AccountEntropyPool.fromString(pool_str) catch return toErrCode(err.SignalError.InvalidArgument);
    key_out.* = pool.deriveBackupKey().bytes;
    return 0;
}

/// Derive the 32-byte media encryption key from a backup key.
export fn libsignal_backup_key_derive_media_key(
    backup_key: *const [32]u8,
    key_out: *[32]u8,
) void {
    const bk = account_keys_mod.BackupKey{ .bytes = backup_key.* };
    key_out.* = bk.deriveMediaEncryptionKey();
}
