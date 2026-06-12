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

    fn saveIdentity(ptr: *anyopaque, addr: *const address_mod.ProtocolAddress, key: identity.IdentityKey) anyerror!bool {
        const self: *IdentityStoreAdapter = @ptrCast(@alignCast(ptr));
        const f = self.c.save_identity orelse return true;
        const name_z = try gpa.dupeZ(u8, addr.name);
        defer gpa.free(name_z);
        const key_bytes = key.serialize();
        return f(self.c.ud, name_z, addr.device_id, &key_bytes) == 1;
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
