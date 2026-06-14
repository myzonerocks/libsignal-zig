//! Store interfaces and session protocol functions.

const std = @import("std");
const err_mod = @import("error.zig");
const keys = @import("keys.zig");
const addr_ffi = @import("address.zig");
const records = @import("records.zig");
const messages = @import("messages.zig");
const bundle_ffi = @import("bundle.zig");
const curve = @import("../curve.zig");
const address_mod = @import("../address.zig");
const storage_mod = @import("../storage.zig");
const session_builder_mod = @import("../session_builder.zig");
const session_cipher_mod = @import("../session_cipher.zig");
const group_builder_mod = @import("../group_session_builder.zig");
const group_cipher_mod = @import("../group_cipher.zig");
const bundle_mod = @import("../state/bundle.zig");
const session_record_mod = @import("../state/session_record.zig");
const pre_key_record_mod = @import("../state/pre_key_record.zig");
const signed_pre_key_record_mod = @import("../state/signed_pre_key_record.zig");
const kyber_pre_key_record_mod = @import("../state/kyber_pre_key_record.zig");
const identity_mod = @import("../identity.zig");
const gpa = std.heap.c_allocator;

const SignalFfiError = err_mod.SignalFfiError;
const SignalOwnedBuffer = keys.SignalOwnedBuffer;
const SignalBorrowedBuffer = keys.SignalBorrowedBuffer;
const SignalProtocolAddress = addr_ffi.SignalProtocolAddress;
const SignalConstPointerProtocolAddress = addr_ffi.SignalConstPointerProtocolAddress;
const SignalMutPointerPreKeyRecord = records.SignalMutPointerPreKeyRecord;
const SignalMutPointerSignedPreKeyRecord = records.SignalMutPointerSignedPreKeyRecord;
const SignalMutPointerSenderKeyRecord = records.SignalMutPointerSenderKeyRecord;
const SignalConstPointerSenderKeyRecord = records.SignalConstPointerSenderKeyRecord;
const SignalMutPointerSessionRecord = records.SignalMutPointerSessionRecord;
const SignalConstPointerSessionRecord = records.SignalConstPointerSessionRecord;
const SignalMutPointerPublicKey = keys.SignalMutPointerPublicKey;
const SignalConstPointerPublicKey = keys.SignalConstPointerPublicKey;
const SignalMutPointerPrivateKey = keys.SignalMutPointerPrivateKey;
const SignalConstPointerPrivateKey = keys.SignalConstPointerPrivateKey;
const SignalPublicKey = keys.SignalPublicKey;
const SignalPrivateKey = keys.SignalPrivateKey;
const SignalMutPointerKyberPreKeyRecord = keys.SignalMutPointerKyberPreKeyRecord;
const SignalMutPointerCiphertextMessage = messages.SignalMutPointerCiphertextMessage;
const SignalConstPointerMessage = messages.SignalConstPointerMessage;
const SignalMutPointerPreKeySignalMessage = messages.SignalMutPointerPreKeySignalMessage;
const SignalConstPointerPreKeySignalMessage = messages.SignalConstPointerPreKeySignalMessage;
const SignalMutPointerSenderKeyDistributionMessage = messages.SignalMutPointerSenderKeyDistributionMessage;
const SignalConstPointerSenderKeyDistributionMessage = messages.SignalConstPointerSenderKeyDistributionMessage;
const SignalConstPointerPreKeyBundle = bundle_ffi.SignalConstPointerPreKeyBundle;

// ── Helper to convert between FFI and internal address types ─────────────────

fn toInternalAddress(ffi_addr: *const SignalProtocolAddress) address_mod.ProtocolAddress {
    return .{
        .name = std.mem.span(ffi_addr.name.ptr),
        .device_id = ffi_addr.device_id,
    };
}

fn tempFfiAddress(addr: *const address_mod.ProtocolAddress) error{OutOfMemory}!SignalProtocolAddress {
    return .{
        .name = try gpa.dupeZ(u8, addr.name),
        .device_id = addr.device_id,
    };
}

const BridgeError = error{StoreCallbackFailed};

// ── C-callable store callback types ───────────────────────────────────────────

pub const SignalSessionStore = extern struct {
    ctx: ?*anyopaque,
    load_session: ?*const fn (*SignalMutPointerSessionRecord, *const SignalProtocolAddress, ?*anyopaque) callconv(.c) ?*SignalFfiError,
    store_session: ?*const fn (*const SignalProtocolAddress, SignalConstPointerSessionRecord, ?*anyopaque) callconv(.c) ?*SignalFfiError,
    destroy: ?*const fn (?*anyopaque) callconv(.c) void,
};

pub const SignalIdentityKeyStore = extern struct {
    ctx: ?*anyopaque,
    get_identity_key_pair: ?*const fn (*SignalMutPointerPublicKey, *SignalMutPointerPrivateKey, ?*anyopaque) callconv(.c) ?*SignalFfiError,
    get_local_registration_id: ?*const fn (*u32, ?*anyopaque) callconv(.c) ?*SignalFfiError,
    save_identity: ?*const fn (*const SignalProtocolAddress, SignalConstPointerPublicKey, ?*anyopaque) callconv(.c) ?*SignalFfiError,
    is_trusted_identity: ?*const fn (*bool, *const SignalProtocolAddress, SignalConstPointerPublicKey, u32, ?*anyopaque) callconv(.c) ?*SignalFfiError,
    get_identity: ?*const fn (*SignalMutPointerPublicKey, *const SignalProtocolAddress, ?*anyopaque) callconv(.c) ?*SignalFfiError,
    destroy: ?*const fn (?*anyopaque) callconv(.c) void,
};

pub const SignalPreKeyStore = extern struct {
    ctx: ?*anyopaque,
    load_pre_key: ?*const fn (*SignalMutPointerPreKeyRecord, u32, ?*anyopaque) callconv(.c) ?*SignalFfiError,
    store_pre_key: ?*const fn (u32, SignalMutPointerPreKeyRecord, ?*anyopaque) callconv(.c) ?*SignalFfiError,
    remove_pre_key: ?*const fn (u32, ?*anyopaque) callconv(.c) ?*SignalFfiError,
    destroy: ?*const fn (?*anyopaque) callconv(.c) void,
};

pub const SignalSignedPreKeyStore = extern struct {
    ctx: ?*anyopaque,
    load_signed_pre_key: ?*const fn (*SignalMutPointerSignedPreKeyRecord, u32, ?*anyopaque) callconv(.c) ?*SignalFfiError,
    store_signed_pre_key: ?*const fn (u32, SignalMutPointerSignedPreKeyRecord, ?*anyopaque) callconv(.c) ?*SignalFfiError,
    destroy: ?*const fn (?*anyopaque) callconv(.c) void,
};

pub const SignalKyberPreKeyStore = extern struct {
    ctx: ?*anyopaque,
    load_kyber_pre_key: ?*const fn (*SignalMutPointerKyberPreKeyRecord, u32, ?*anyopaque) callconv(.c) ?*SignalFfiError,
    store_kyber_pre_key: ?*const fn (u32, SignalMutPointerKyberPreKeyRecord, ?*anyopaque) callconv(.c) ?*SignalFfiError,
    mark_kyber_pre_key_used: ?*const fn (u32, ?*anyopaque) callconv(.c) ?*SignalFfiError,
    destroy: ?*const fn (?*anyopaque) callconv(.c) void,
};

pub const SignalSenderKeyStore = extern struct {
    ctx: ?*anyopaque,
    store_sender_key: ?*const fn (*const SignalProtocolAddress, *const [16]u8, SignalConstPointerSenderKeyRecord, ?*anyopaque) callconv(.c) ?*SignalFfiError,
    load_sender_key: ?*const fn (*SignalMutPointerSenderKeyRecord, *const SignalProtocolAddress, *const [16]u8, ?*anyopaque) callconv(.c) ?*SignalFfiError,
    destroy: ?*const fn (?*anyopaque) callconv(.c) void,
};

// ── Bridge: SessionStore ──────────────────────────────────────────────────────

const SessionStoreBridge = struct {
    c: *const SignalSessionStore,

    fn loadSession(ptr: *anyopaque, addr: *const address_mod.ProtocolAddress) anyerror!?session_record_mod.SessionRecord {
        const self: *SessionStoreBridge = @ptrCast(@alignCast(ptr));
        var ffi_addr = try tempFfiAddress(addr);
        defer ffi_addr.deinit();
        var out: SignalMutPointerSessionRecord = .{ .raw = null };
        const fn_ptr = self.c.load_session orelse return BridgeError.StoreCallbackFailed;
        if (fn_ptr(&out, &ffi_addr, self.c.ctx)) |e| {
            err_mod.signal_error_free(e);
            return BridgeError.StoreCallbackFailed;
        }
        const rec = out.raw orelse return null;
        defer {
            rec.inner.deinit();
            gpa.destroy(rec);
        }
        const bytes = try rec.inner.serialize();
        defer gpa.free(bytes);
        return try session_record_mod.SessionRecord.deserialize(gpa, bytes);
    }

    fn storeSession(ptr: *anyopaque, addr: *const address_mod.ProtocolAddress, record: *const session_record_mod.SessionRecord) anyerror!void {
        const self: *SessionStoreBridge = @ptrCast(@alignCast(ptr));
        var ffi_addr = try tempFfiAddress(addr);
        defer ffi_addr.deinit();
        const bytes = try record.serialize();
        defer gpa.free(bytes);
        const inner = try session_record_mod.SessionRecord.deserialize(gpa, bytes);
        var rec_obj = records.SignalSessionRecord{ .inner = inner };
        defer rec_obj.deinit();
        const const_ptr = SignalConstPointerSessionRecord{ .raw = &rec_obj };
        const fn_ptr = self.c.store_session orelse return BridgeError.StoreCallbackFailed;
        if (fn_ptr(&ffi_addr, const_ptr, self.c.ctx)) |e| {
            err_mod.signal_error_free(e);
            return BridgeError.StoreCallbackFailed;
        }
    }

    const vtable = storage_mod.SessionStore.VTable{
        .loadSession = loadSession,
        .storeSession = storeSession,
    };
};

// ── Bridge: IdentityKeyStore ──────────────────────────────────────────────────

const IdentityStoreBridge = struct {
    c: *const SignalIdentityKeyStore,

    fn getIdentityKeyPair(ptr: *anyopaque) anyerror!identity_mod.IdentityKeyPair {
        const self: *IdentityStoreBridge = @ptrCast(@alignCast(ptr));
        var out_pub: SignalMutPointerPublicKey = .{ .raw = null };
        var out_priv: SignalMutPointerPrivateKey = .{ .raw = null };
        const fn_ptr = self.c.get_identity_key_pair orelse return BridgeError.StoreCallbackFailed;
        if (fn_ptr(&out_pub, &out_priv, self.c.ctx)) |e| {
            err_mod.signal_error_free(e);
            return BridgeError.StoreCallbackFailed;
        }
        const pk_ptr = out_pub.raw orelse return BridgeError.StoreCallbackFailed;
        const sk_ptr = out_priv.raw orelse return BridgeError.StoreCallbackFailed;
        defer {
            gpa.destroy(pk_ptr);
            gpa.destroy(sk_ptr);
        }
        return identity_mod.IdentityKeyPair{
            .identity_key = identity_mod.IdentityKey.fromPublicKey(pk_ptr.inner),
            .private_key = sk_ptr.inner,
        };
    }

    fn getLocalRegistrationId(ptr: *anyopaque) anyerror!u32 {
        const self: *IdentityStoreBridge = @ptrCast(@alignCast(ptr));
        var out: u32 = 0;
        const fn_ptr = self.c.get_local_registration_id orelse return BridgeError.StoreCallbackFailed;
        if (fn_ptr(&out, self.c.ctx)) |e| {
            err_mod.signal_error_free(e);
            return BridgeError.StoreCallbackFailed;
        }
        return out;
    }

    fn saveIdentity(ptr: *anyopaque, addr: *const address_mod.ProtocolAddress, key: identity_mod.IdentityKey) anyerror!storage_mod.IdentityChange {
        const self: *IdentityStoreBridge = @ptrCast(@alignCast(ptr));
        var ffi_addr = try tempFfiAddress(addr);
        defer ffi_addr.deinit();
        var pk_obj = SignalPublicKey{ .inner = key.public_key };
        const pk_const = SignalConstPointerPublicKey{ .raw = &pk_obj };
        const fn_ptr = self.c.save_identity orelse return BridgeError.StoreCallbackFailed;
        if (fn_ptr(&ffi_addr, pk_const, self.c.ctx)) |e| {
            err_mod.signal_error_free(e);
            return BridgeError.StoreCallbackFailed;
        }
        return .new_or_unchanged;
    }

    fn isTrustedIdentity(ptr: *anyopaque, addr: *const address_mod.ProtocolAddress, key: identity_mod.IdentityKey, dir: storage_mod.Direction) anyerror!bool {
        const self: *IdentityStoreBridge = @ptrCast(@alignCast(ptr));
        var ffi_addr = try tempFfiAddress(addr);
        defer ffi_addr.deinit();
        var pk_obj = SignalPublicKey{ .inner = key.public_key };
        const pk_const = SignalConstPointerPublicKey{ .raw = &pk_obj };
        const dir_val: u32 = if (dir == .sending) 1 else 0;
        var out: bool = false;
        const fn_ptr = self.c.is_trusted_identity orelse return BridgeError.StoreCallbackFailed;
        if (fn_ptr(&out, &ffi_addr, pk_const, dir_val, self.c.ctx)) |e| {
            err_mod.signal_error_free(e);
            return BridgeError.StoreCallbackFailed;
        }
        return out;
    }

    fn getIdentity(ptr: *anyopaque, addr: *const address_mod.ProtocolAddress) anyerror!?identity_mod.IdentityKey {
        const self: *IdentityStoreBridge = @ptrCast(@alignCast(ptr));
        var ffi_addr = try tempFfiAddress(addr);
        defer ffi_addr.deinit();
        var out: SignalMutPointerPublicKey = .{ .raw = null };
        const fn_ptr = self.c.get_identity orelse return BridgeError.StoreCallbackFailed;
        if (fn_ptr(&out, &ffi_addr, self.c.ctx)) |e| {
            err_mod.signal_error_free(e);
            return BridgeError.StoreCallbackFailed;
        }
        const pk_ptr = out.raw orelse return null;
        defer gpa.destroy(pk_ptr);
        return identity_mod.IdentityKey.fromPublicKey(pk_ptr.inner);
    }

    const vtable = storage_mod.IdentityKeyStore.VTable{
        .getIdentityKeyPair = getIdentityKeyPair,
        .getLocalRegistrationId = getLocalRegistrationId,
        .saveIdentity = saveIdentity,
        .isTrustedIdentity = isTrustedIdentity,
        .getIdentity = getIdentity,
    };
};

// ── Bridge: PreKeyStore ───────────────────────────────────────────────────────

const PreKeyStoreBridge = struct {
    c: *const SignalPreKeyStore,

    fn loadPreKey(ptr: *anyopaque, id: u32) anyerror!pre_key_record_mod.PreKeyRecord {
        const self: *PreKeyStoreBridge = @ptrCast(@alignCast(ptr));
        var out: SignalMutPointerPreKeyRecord = .{ .raw = null };
        const fn_ptr = self.c.load_pre_key orelse return BridgeError.StoreCallbackFailed;
        if (fn_ptr(&out, id, self.c.ctx)) |e| {
            err_mod.signal_error_free(e);
            return BridgeError.StoreCallbackFailed;
        }
        const rec = out.raw orelse return BridgeError.StoreCallbackFailed;
        defer gpa.destroy(rec);
        return rec.inner;
    }

    fn storePreKey(ptr: *anyopaque, id: u32, record: *const pre_key_record_mod.PreKeyRecord) anyerror!void {
        const self: *PreKeyStoreBridge = @ptrCast(@alignCast(ptr));
        var rec_obj = records.SignalPreKeyRecord{ .inner = record.* };
        const rec_mut = SignalMutPointerPreKeyRecord{ .raw = &rec_obj };
        const fn_ptr = self.c.store_pre_key orelse return BridgeError.StoreCallbackFailed;
        if (fn_ptr(id, rec_mut, self.c.ctx)) |e| {
            err_mod.signal_error_free(e);
            return BridgeError.StoreCallbackFailed;
        }
    }

    fn removePreKey(ptr: *anyopaque, id: u32) anyerror!void {
        const self: *PreKeyStoreBridge = @ptrCast(@alignCast(ptr));
        const fn_ptr = self.c.remove_pre_key orelse return BridgeError.StoreCallbackFailed;
        if (fn_ptr(id, self.c.ctx)) |e| {
            err_mod.signal_error_free(e);
            return BridgeError.StoreCallbackFailed;
        }
    }

    const vtable = storage_mod.PreKeyStore.VTable{
        .loadPreKey = loadPreKey,
        .storePreKey = storePreKey,
        .removePreKey = removePreKey,
    };
};

// ── Bridge: SignedPreKeyStore ─────────────────────────────────────────────────

const SignedPreKeyStoreBridge = struct {
    c: *const SignalSignedPreKeyStore,

    fn loadSignedPreKey(ptr: *anyopaque, id: u32) anyerror!signed_pre_key_record_mod.SignedPreKeyRecord {
        const self: *SignedPreKeyStoreBridge = @ptrCast(@alignCast(ptr));
        var out: SignalMutPointerSignedPreKeyRecord = .{ .raw = null };
        const fn_ptr = self.c.load_signed_pre_key orelse return BridgeError.StoreCallbackFailed;
        if (fn_ptr(&out, id, self.c.ctx)) |e| {
            err_mod.signal_error_free(e);
            return BridgeError.StoreCallbackFailed;
        }
        const rec = out.raw orelse return BridgeError.StoreCallbackFailed;
        defer gpa.destroy(rec);
        return rec.inner;
    }

    fn storeSignedPreKey(ptr: *anyopaque, id: u32, record: *const signed_pre_key_record_mod.SignedPreKeyRecord) anyerror!void {
        const self: *SignedPreKeyStoreBridge = @ptrCast(@alignCast(ptr));
        var rec_obj = records.SignalSignedPreKeyRecord{ .inner = record.* };
        const rec_mut = SignalMutPointerSignedPreKeyRecord{ .raw = &rec_obj };
        const fn_ptr = self.c.store_signed_pre_key orelse return BridgeError.StoreCallbackFailed;
        if (fn_ptr(id, rec_mut, self.c.ctx)) |e| {
            err_mod.signal_error_free(e);
            return BridgeError.StoreCallbackFailed;
        }
    }

    const vtable = storage_mod.SignedPreKeyStore.VTable{
        .loadSignedPreKey = loadSignedPreKey,
        .storeSignedPreKey = storeSignedPreKey,
    };
};

// ── Bridge: KyberPreKeyStore ──────────────────────────────────────────────────

const KyberPreKeyStoreBridge = struct {
    c: *const SignalKyberPreKeyStore,

    fn loadKyberPreKey(ptr: *anyopaque, id: u32) anyerror!kyber_pre_key_record_mod.KyberPreKeyRecord {
        const self: *KyberPreKeyStoreBridge = @ptrCast(@alignCast(ptr));
        var out: SignalMutPointerKyberPreKeyRecord = .{ .raw = null };
        const fn_ptr = self.c.load_kyber_pre_key orelse return BridgeError.StoreCallbackFailed;
        if (fn_ptr(&out, id, self.c.ctx)) |e| {
            err_mod.signal_error_free(e);
            return BridgeError.StoreCallbackFailed;
        }
        const rec = out.raw orelse return BridgeError.StoreCallbackFailed;
        defer gpa.destroy(rec);
        return rec.inner;
    }

    fn storeKyberPreKey(ptr: *anyopaque, id: u32, record: *const kyber_pre_key_record_mod.KyberPreKeyRecord) anyerror!void {
        const self: *KyberPreKeyStoreBridge = @ptrCast(@alignCast(ptr));
        var rec_obj = keys.SignalKyberPreKeyRecord{ .inner = record.* };
        const rec_mut = SignalMutPointerKyberPreKeyRecord{ .raw = &rec_obj };
        const fn_ptr = self.c.store_kyber_pre_key orelse return BridgeError.StoreCallbackFailed;
        if (fn_ptr(id, rec_mut, self.c.ctx)) |e| {
            err_mod.signal_error_free(e);
            return BridgeError.StoreCallbackFailed;
        }
    }

    fn markKyberPreKeyUsed(ptr: *anyopaque, id: u32) anyerror!void {
        const self: *KyberPreKeyStoreBridge = @ptrCast(@alignCast(ptr));
        const fn_ptr = self.c.mark_kyber_pre_key_used orelse return;
        if (fn_ptr(id, self.c.ctx)) |e| {
            err_mod.signal_error_free(e);
            return BridgeError.StoreCallbackFailed;
        }
    }

    const vtable = storage_mod.KyberPreKeyStore.VTable{
        .loadKyberPreKey = loadKyberPreKey,
        .storeKyberPreKey = storeKyberPreKey,
        .markKyberPreKeyUsed = markKyberPreKeyUsed,
    };
};

// ── Bridge: SenderKeyStore ────────────────────────────────────────────────────

const SenderKeyStoreBridge = struct {
    c: *const SignalSenderKeyStore,

    fn storeSenderKey(ptr: *anyopaque, sender: *const address_mod.ProtocolAddress, distribution_id: [16]u8, record: []const u8) anyerror!void {
        const self: *SenderKeyStoreBridge = @ptrCast(@alignCast(ptr));
        var ffi_addr = try tempFfiAddress(sender);
        defer ffi_addr.deinit();
        const data_copy = gpa.dupe(u8, record) catch return BridgeError.StoreCallbackFailed;
        var rec_obj = records.SignalSenderKeyRecord{ .data = data_copy };
        defer {
            rec_obj.deinit();
        }
        const const_ptr = SignalConstPointerSenderKeyRecord{ .raw = &rec_obj };
        const fn_ptr = self.c.store_sender_key orelse return BridgeError.StoreCallbackFailed;
        if (fn_ptr(&ffi_addr, &distribution_id, const_ptr, self.c.ctx)) |e| {
            err_mod.signal_error_free(e);
            return BridgeError.StoreCallbackFailed;
        }
    }

    fn loadSenderKey(ptr: *anyopaque, sender: *const address_mod.ProtocolAddress, distribution_id: [16]u8) anyerror!?[]u8 {
        const self: *SenderKeyStoreBridge = @ptrCast(@alignCast(ptr));
        var ffi_addr = try tempFfiAddress(sender);
        defer ffi_addr.deinit();
        var out: SignalMutPointerSenderKeyRecord = .{ .raw = null };
        const fn_ptr = self.c.load_sender_key orelse return BridgeError.StoreCallbackFailed;
        if (fn_ptr(&out, &ffi_addr, &distribution_id, self.c.ctx)) |e| {
            err_mod.signal_error_free(e);
            return BridgeError.StoreCallbackFailed;
        }
        const rec = out.raw orelse return null;
        defer {
            rec.deinit();
            gpa.destroy(rec);
        }
        return try gpa.dupe(u8, rec.data);
    }

    const vtable = storage_mod.SenderKeyStore.VTable{
        .storeSenderKey = storeSenderKey,
        .loadSenderKey = loadSenderKey,
    };
};

// ── Helper macros for store bridge creation ───────────────────────────────────

fn makeSessionStore(c: *const SignalSessionStore) struct { bridge: SessionStoreBridge, store: storage_mod.SessionStore } {
    var result = .{
        .bridge = SessionStoreBridge{ .c = c },
        .store = undefined,
    };
    result.store = storage_mod.SessionStore{ .ptr = &result.bridge, .vtable = &SessionStoreBridge.vtable };
    return result;
}

// ── Session protocol functions ─────────────────────────────────────────────────

pub export fn signal_process_prekey_bundle(
    bundle: SignalConstPointerPreKeyBundle,
    address: SignalConstPointerProtocolAddress,
    session_store: *const SignalSessionStore,
    identity_store: *const SignalIdentityKeyStore,
    pre_key_store: *const SignalPreKeyStore,
    signed_pre_key_store: *const SignalSignedPreKeyStore,
    kyber_pre_key_store: *const SignalKyberPreKeyStore,
) ?*SignalFfiError {
    const b = bundle.raw orelse return err_mod.alloc(.null_parameter, "bundle is null");
    const addr = address.raw orelse return err_mod.alloc(.null_parameter, "address is null");

    var ss_bridge = SessionStoreBridge{ .c = session_store };
    var id_bridge = IdentityStoreBridge{ .c = identity_store };
    var pk_bridge = PreKeyStoreBridge{ .c = pre_key_store };
    var spk_bridge = SignedPreKeyStoreBridge{ .c = signed_pre_key_store };
    var kpk_bridge = KyberPreKeyStoreBridge{ .c = kyber_pre_key_store };

    const zig_ss = storage_mod.SessionStore{ .ptr = &ss_bridge, .vtable = &SessionStoreBridge.vtable };
    const zig_id = storage_mod.IdentityKeyStore{ .ptr = &id_bridge, .vtable = &IdentityStoreBridge.vtable };
    const zig_pk = storage_mod.PreKeyStore{ .ptr = &pk_bridge, .vtable = &PreKeyStoreBridge.vtable };
    const zig_spk = storage_mod.SignedPreKeyStore{ .ptr = &spk_bridge, .vtable = &SignedPreKeyStoreBridge.vtable };
    const zig_kpk = storage_mod.KyberPreKeyStore{ .ptr = &kpk_bridge, .vtable = &KyberPreKeyStoreBridge.vtable };

    const internal_addr = toInternalAddress(addr);
    var builder = session_builder_mod.SessionBuilder.init(gpa, internal_addr, zig_ss, zig_pk, zig_spk, zig_id, zig_kpk);
    builder.processPreKeyBundle(b.inner) catch |e| return err_mod.fromZigError(e);
    return null;
}

pub export fn signal_encrypt_message(
    out: *SignalMutPointerCiphertextMessage,
    plaintext: SignalBorrowedBuffer,
    address: SignalConstPointerProtocolAddress,
    session_store: *const SignalSessionStore,
    identity_store: *const SignalIdentityKeyStore,
) ?*SignalFfiError {
    const addr = address.raw orelse return err_mod.alloc(.null_parameter, "address is null");

    var ss_bridge = SessionStoreBridge{ .c = session_store };
    var id_bridge = IdentityStoreBridge{ .c = identity_store };
    // Dummy stores for encrypt (not used internally but satisfy the init signature)
    var pk_bridge = PreKeyStoreBridge{ .c = undefined };
    var spk_bridge = SignedPreKeyStoreBridge{ .c = undefined };

    const zig_ss = storage_mod.SessionStore{ .ptr = &ss_bridge, .vtable = &SessionStoreBridge.vtable };
    const zig_id = storage_mod.IdentityKeyStore{ .ptr = &id_bridge, .vtable = &IdentityStoreBridge.vtable };
    const zig_pk = storage_mod.PreKeyStore{ .ptr = &pk_bridge, .vtable = &PreKeyStoreBridge.vtable };
    const zig_spk = storage_mod.SignedPreKeyStore{ .ptr = &spk_bridge, .vtable = &SignedPreKeyStoreBridge.vtable };

    const internal_addr = toInternalAddress(addr);
    var cipher = session_cipher_mod.SessionCipher.init(gpa, internal_addr, zig_ss, zig_pk, zig_spk, zig_id, null);
    var ct = cipher.encrypt(plaintext.slice()) catch |e| return err_mod.fromZigError(e);
    defer ct.deinit();

    const ffi_ct = gpa.create(messages.SignalCiphertextMessage) catch return err_mod.alloc(.internal_error, "OOM");
    ffi_ct.* = .{
        .msg_type = @enumFromInt(@intFromEnum(ct.message_type)),
        .serialized = gpa.dupe(u8, ct.serialized) catch {
            gpa.destroy(ffi_ct);
            return err_mod.alloc(.internal_error, "OOM");
        },
    };
    out.raw = ffi_ct;
    return null;
}

pub export fn signal_decrypt_message(
    out: *SignalOwnedBuffer,
    ciphertext: SignalConstPointerMessage,
    address: SignalConstPointerProtocolAddress,
    session_store: *const SignalSessionStore,
    identity_store: *const SignalIdentityKeyStore,
) ?*SignalFfiError {
    const msg = ciphertext.raw orelse return err_mod.alloc(.null_parameter, "ciphertext is null");
    const addr = address.raw orelse return err_mod.alloc(.null_parameter, "address is null");

    var ss_bridge = SessionStoreBridge{ .c = session_store };
    var id_bridge = IdentityStoreBridge{ .c = identity_store };
    var pk_bridge = PreKeyStoreBridge{ .c = undefined };
    var spk_bridge = SignedPreKeyStoreBridge{ .c = undefined };

    const zig_ss = storage_mod.SessionStore{ .ptr = &ss_bridge, .vtable = &SessionStoreBridge.vtable };
    const zig_id = storage_mod.IdentityKeyStore{ .ptr = &id_bridge, .vtable = &IdentityStoreBridge.vtable };
    const zig_pk = storage_mod.PreKeyStore{ .ptr = &pk_bridge, .vtable = &PreKeyStoreBridge.vtable };
    const zig_spk = storage_mod.SignedPreKeyStore{ .ptr = &spk_bridge, .vtable = &SignedPreKeyStoreBridge.vtable };

    const internal_addr = toInternalAddress(addr);
    var cipher = session_cipher_mod.SessionCipher.init(gpa, internal_addr, zig_ss, zig_pk, zig_spk, zig_id, null);
    const plaintext = cipher.decryptMessage(msg.serialized) catch |e| return err_mod.fromZigError(e);
    out.* = .{ .base = plaintext.ptr, .length = plaintext.len };
    return null;
}

pub export fn signal_decrypt_pre_key_message(
    out: *SignalOwnedBuffer,
    ciphertext: SignalConstPointerPreKeySignalMessage,
    address: SignalConstPointerProtocolAddress,
    session_store: *const SignalSessionStore,
    identity_store: *const SignalIdentityKeyStore,
    pre_key_store: *const SignalPreKeyStore,
    signed_pre_key_store: *const SignalSignedPreKeyStore,
    kyber_pre_key_store: *const SignalKyberPreKeyStore,
) ?*SignalFfiError {
    const msg = ciphertext.raw orelse return err_mod.alloc(.null_parameter, "ciphertext is null");
    const addr = address.raw orelse return err_mod.alloc(.null_parameter, "address is null");

    var ss_bridge = SessionStoreBridge{ .c = session_store };
    var id_bridge = IdentityStoreBridge{ .c = identity_store };
    var pk_bridge = PreKeyStoreBridge{ .c = pre_key_store };
    var spk_bridge = SignedPreKeyStoreBridge{ .c = signed_pre_key_store };
    var kpk_bridge = KyberPreKeyStoreBridge{ .c = kyber_pre_key_store };

    const zig_ss = storage_mod.SessionStore{ .ptr = &ss_bridge, .vtable = &SessionStoreBridge.vtable };
    const zig_id = storage_mod.IdentityKeyStore{ .ptr = &id_bridge, .vtable = &IdentityStoreBridge.vtable };
    const zig_pk = storage_mod.PreKeyStore{ .ptr = &pk_bridge, .vtable = &PreKeyStoreBridge.vtable };
    const zig_spk = storage_mod.SignedPreKeyStore{ .ptr = &spk_bridge, .vtable = &SignedPreKeyStoreBridge.vtable };
    const zig_kpk = storage_mod.KyberPreKeyStore{ .ptr = &kpk_bridge, .vtable = &KyberPreKeyStoreBridge.vtable };

    const internal_addr = toInternalAddress(addr);
    var cipher = session_cipher_mod.SessionCipher.init(gpa, internal_addr, zig_ss, zig_pk, zig_spk, zig_id, zig_kpk);

    const serialized = msg.inner.serialize() catch |e| return err_mod.fromZigError(e);
    defer gpa.free(serialized);
    const plaintext = cipher.decryptPreKeyMessage(serialized) catch |e| return err_mod.fromZigError(e);
    out.* = .{ .base = plaintext.ptr, .length = plaintext.len };
    return null;
}

pub export fn signal_sender_key_distribution_message_create(
    out: *SignalMutPointerSenderKeyDistributionMessage,
    sender: SignalConstPointerProtocolAddress,
    distribution_id: SignalBorrowedBuffer,
    store: *const SignalSenderKeyStore,
) ?*SignalFfiError {
    const addr = sender.raw orelse return err_mod.alloc(.null_parameter, "sender is null");
    if (distribution_id.length != 16) return err_mod.alloc(.invalid_argument, "distribution_id must be 16 bytes");

    var skb = SenderKeyStoreBridge{ .c = store };
    const zig_store = storage_mod.SenderKeyStore{ .ptr = &skb, .vtable = &SenderKeyStoreBridge.vtable };

    const internal_addr = toInternalAddress(addr);
    var uuid: [16]u8 = undefined;
    @memcpy(&uuid, distribution_id.slice()[0..16]);

    var builder = group_builder_mod.GroupSessionBuilder.init(gpa, zig_store);
    const msg = builder.createSession(&internal_addr, uuid) catch |e| return err_mod.fromZigError(e);

    const ffi_msg = gpa.create(messages.SignalSenderKeyDistributionMessage) catch {
        var m = msg;
        m.deinit();
        return err_mod.alloc(.internal_error, "OOM");
    };
    ffi_msg.* = .{ .inner = msg };
    out.raw = ffi_msg;
    return null;
}

pub export fn signal_process_sender_key_distribution_message(
    sender: SignalConstPointerProtocolAddress,
    msg: SignalConstPointerSenderKeyDistributionMessage,
    store: *const SignalSenderKeyStore,
) ?*SignalFfiError {
    const addr = sender.raw orelse return err_mod.alloc(.null_parameter, "sender is null");
    const m = msg.raw orelse return err_mod.alloc(.null_parameter, "msg is null");

    var skb = SenderKeyStoreBridge{ .c = store };
    const zig_store = storage_mod.SenderKeyStore{ .ptr = &skb, .vtable = &SenderKeyStoreBridge.vtable };

    const internal_addr = toInternalAddress(addr);
    var builder = group_builder_mod.GroupSessionBuilder.init(gpa, zig_store);
    builder.processSession(&internal_addr, &m.inner) catch |e| return err_mod.fromZigError(e);
    return null;
}

pub export fn signal_group_encrypt_message(
    out: *SignalOwnedBuffer,
    sender: SignalConstPointerProtocolAddress,
    distribution_id: SignalBorrowedBuffer,
    plaintext: SignalBorrowedBuffer,
    store: *const SignalSenderKeyStore,
) ?*SignalFfiError {
    const addr = sender.raw orelse return err_mod.alloc(.null_parameter, "sender is null");
    if (distribution_id.length != 16) return err_mod.alloc(.invalid_argument, "distribution_id must be 16 bytes");

    var skb = SenderKeyStoreBridge{ .c = store };
    const zig_store = storage_mod.SenderKeyStore{ .ptr = &skb, .vtable = &SenderKeyStoreBridge.vtable };

    const internal_addr = toInternalAddress(addr);
    var uuid: [16]u8 = undefined;
    @memcpy(&uuid, distribution_id.slice()[0..16]);

    var cipher = group_cipher_mod.GroupCipher.init(gpa, zig_store, internal_addr, uuid);
    const ciphertext = cipher.encrypt(plaintext.slice()) catch |e| return err_mod.fromZigError(e);
    out.* = .{ .base = ciphertext.ptr, .length = ciphertext.len };
    return null;
}

pub export fn signal_group_decrypt_message(
    out: *SignalOwnedBuffer,
    sender: SignalConstPointerProtocolAddress,
    distribution_id: SignalBorrowedBuffer,
    ciphertext: SignalBorrowedBuffer,
    store: *const SignalSenderKeyStore,
) ?*SignalFfiError {
    const addr = sender.raw orelse return err_mod.alloc(.null_parameter, "sender is null");
    if (distribution_id.length != 16) return err_mod.alloc(.invalid_argument, "distribution_id must be 16 bytes");

    var skb = SenderKeyStoreBridge{ .c = store };
    const zig_store = storage_mod.SenderKeyStore{ .ptr = &skb, .vtable = &SenderKeyStoreBridge.vtable };

    const internal_addr = toInternalAddress(addr);
    var uuid: [16]u8 = undefined;
    @memcpy(&uuid, distribution_id.slice()[0..16]);

    var cipher = group_cipher_mod.GroupCipher.init(gpa, zig_store, internal_addr, uuid);
    const plaintext = cipher.decrypt(ciphertext.slice()) catch |e| return err_mod.fromZigError(e);
    out.* = .{ .base = plaintext.ptr, .length = plaintext.len };
    return null;
}
