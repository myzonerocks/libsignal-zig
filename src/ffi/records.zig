//! Pre-key records, session record.

const std = @import("std");
const err_mod = @import("error.zig");
const keys = @import("keys.zig");
const curve = @import("../curve.zig");
const pre_key_mod = @import("../state/pre_key_record.zig");
const signed_pre_key_mod = @import("../state/signed_pre_key_record.zig");
const session_record_mod = @import("../state/session_record.zig");
const gpa = std.heap.c_allocator;

const SignalFfiError = err_mod.SignalFfiError;
const SignalOwnedBuffer = keys.SignalOwnedBuffer;
const SignalBorrowedBuffer = keys.SignalBorrowedBuffer;
const SignalMutPointerPrivateKey = keys.SignalMutPointerPrivateKey;
const SignalConstPointerPrivateKey = keys.SignalConstPointerPrivateKey;
const SignalMutPointerPublicKey = keys.SignalMutPointerPublicKey;
const SignalConstPointerPublicKey = keys.SignalConstPointerPublicKey;
const SignalPrivateKey = keys.SignalPrivateKey;
const SignalPublicKey = keys.SignalPublicKey;

// ── SignalPreKeyRecord ─────────────────────────────────────────────────────────

pub const SignalPreKeyRecord = struct { inner: pre_key_mod.PreKeyRecord };
pub const SignalMutPointerPreKeyRecord = extern struct { raw: ?*SignalPreKeyRecord };
pub const SignalConstPointerPreKeyRecord = extern struct { raw: ?*const SignalPreKeyRecord };

pub export fn signal_pre_key_record_new(out: *SignalMutPointerPreKeyRecord, id: u32, public_key: SignalConstPointerPublicKey, private_key: SignalConstPointerPrivateKey) ?*SignalFfiError {
    const pk = public_key.raw orelse return err_mod.alloc(.null_parameter, "public_key is null");
    const sk = private_key.raw orelse return err_mod.alloc(.null_parameter, "private_key is null");
    const record = gpa.create(SignalPreKeyRecord) catch return err_mod.alloc(.internal_error, "OOM");
    record.* = .{ .inner = pre_key_mod.PreKeyRecord.new(id, .{
        .public_key = pk.inner,
        .private_key = sk.inner,
    }) };
    out.raw = record;
    return null;
}

pub export fn signal_pre_key_record_clone(new_obj: *SignalMutPointerPreKeyRecord, obj: SignalConstPointerPreKeyRecord) ?*SignalFfiError {
    const src = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    const copy = gpa.create(SignalPreKeyRecord) catch return err_mod.alloc(.internal_error, "OOM");
    copy.* = src.*;
    new_obj.raw = copy;
    return null;
}

pub export fn signal_pre_key_record_destroy(p: SignalMutPointerPreKeyRecord) ?*SignalFfiError {
    if (p.raw) |r| gpa.destroy(r);
    return null;
}

pub export fn signal_pre_key_record_serialize(out: *SignalOwnedBuffer, obj: SignalConstPointerPreKeyRecord) ?*SignalFfiError {
    const r = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    const bytes = r.inner.serialize(gpa) catch |e| return err_mod.fromZigError(e);
    out.* = .{ .base = bytes.ptr, .length = bytes.len };
    return null;
}

pub export fn signal_pre_key_record_deserialize(out: *SignalMutPointerPreKeyRecord, data: SignalBorrowedBuffer) ?*SignalFfiError {
    const inner = pre_key_mod.PreKeyRecord.deserialize(data.slice()) catch |e| return err_mod.fromZigError(e);
    const record = gpa.create(SignalPreKeyRecord) catch return err_mod.alloc(.internal_error, "OOM");
    record.* = .{ .inner = inner };
    out.raw = record;
    return null;
}

pub export fn signal_pre_key_record_get_id(out: *u32, obj: SignalConstPointerPreKeyRecord) ?*SignalFfiError {
    const r = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    out.* = r.inner.id;
    return null;
}

pub export fn signal_pre_key_record_get_public_key(out: *SignalMutPointerPublicKey, obj: SignalConstPointerPreKeyRecord) ?*SignalFfiError {
    const r = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    const pk = gpa.create(SignalPublicKey) catch return err_mod.alloc(.internal_error, "OOM");
    pk.* = .{ .inner = r.inner.publicKey() };
    out.raw = pk;
    return null;
}

pub export fn signal_pre_key_record_get_private_key(out: *SignalMutPointerPrivateKey, obj: SignalConstPointerPreKeyRecord) ?*SignalFfiError {
    const r = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    const sk = gpa.create(SignalPrivateKey) catch return err_mod.alloc(.internal_error, "OOM");
    sk.* = .{ .inner = r.inner.privateKey() };
    out.raw = sk;
    return null;
}

// ── SignalSignedPreKeyRecord ───────────────────────────────────────────────────

pub const SignalSignedPreKeyRecord = struct { inner: signed_pre_key_mod.SignedPreKeyRecord };
pub const SignalMutPointerSignedPreKeyRecord = extern struct { raw: ?*SignalSignedPreKeyRecord };
pub const SignalConstPointerSignedPreKeyRecord = extern struct { raw: ?*const SignalSignedPreKeyRecord };

pub export fn signal_signed_pre_key_record_new(out: *SignalMutPointerSignedPreKeyRecord, id: u32, timestamp: u64, public_key: SignalConstPointerPublicKey, private_key: SignalConstPointerPrivateKey, signature: SignalBorrowedBuffer) ?*SignalFfiError {
    const pk = public_key.raw orelse return err_mod.alloc(.null_parameter, "public_key is null");
    const sk = private_key.raw orelse return err_mod.alloc(.null_parameter, "private_key is null");
    if (signature.length != 64) return err_mod.alloc(.invalid_signature, "signature must be 64 bytes");
    const sig: [64]u8 = signature.slice()[0..64].*;
    const record = gpa.create(SignalSignedPreKeyRecord) catch return err_mod.alloc(.internal_error, "OOM");
    record.* = .{ .inner = signed_pre_key_mod.SignedPreKeyRecord.new(id, timestamp, .{
        .public_key = pk.inner,
        .private_key = sk.inner,
    }, sig) };
    out.raw = record;
    return null;
}

pub export fn signal_signed_pre_key_record_clone(new_obj: *SignalMutPointerSignedPreKeyRecord, obj: SignalConstPointerSignedPreKeyRecord) ?*SignalFfiError {
    const src = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    const copy = gpa.create(SignalSignedPreKeyRecord) catch return err_mod.alloc(.internal_error, "OOM");
    copy.* = src.*;
    new_obj.raw = copy;
    return null;
}

pub export fn signal_signed_pre_key_record_destroy(p: SignalMutPointerSignedPreKeyRecord) ?*SignalFfiError {
    if (p.raw) |r| gpa.destroy(r);
    return null;
}

pub export fn signal_signed_pre_key_record_serialize(out: *SignalOwnedBuffer, obj: SignalConstPointerSignedPreKeyRecord) ?*SignalFfiError {
    const r = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    const bytes = r.inner.serialize(gpa) catch |e| return err_mod.fromZigError(e);
    out.* = .{ .base = bytes.ptr, .length = bytes.len };
    return null;
}

pub export fn signal_signed_pre_key_record_deserialize(out: *SignalMutPointerSignedPreKeyRecord, data: SignalBorrowedBuffer) ?*SignalFfiError {
    const inner = signed_pre_key_mod.SignedPreKeyRecord.deserialize(data.slice()) catch |e| return err_mod.fromZigError(e);
    const record = gpa.create(SignalSignedPreKeyRecord) catch return err_mod.alloc(.internal_error, "OOM");
    record.* = .{ .inner = inner };
    out.raw = record;
    return null;
}

pub export fn signal_signed_pre_key_record_get_id(out: *u32, obj: SignalConstPointerSignedPreKeyRecord) ?*SignalFfiError {
    const r = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    out.* = r.inner.id;
    return null;
}

pub export fn signal_signed_pre_key_record_get_timestamp(out: *u64, obj: SignalConstPointerSignedPreKeyRecord) ?*SignalFfiError {
    const r = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    out.* = r.inner.timestamp;
    return null;
}

pub export fn signal_signed_pre_key_record_get_public_key(out: *SignalMutPointerPublicKey, obj: SignalConstPointerSignedPreKeyRecord) ?*SignalFfiError {
    const r = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    const pk = gpa.create(SignalPublicKey) catch return err_mod.alloc(.internal_error, "OOM");
    pk.* = .{ .inner = r.inner.publicKey() };
    out.raw = pk;
    return null;
}

pub export fn signal_signed_pre_key_record_get_private_key(out: *SignalMutPointerPrivateKey, obj: SignalConstPointerSignedPreKeyRecord) ?*SignalFfiError {
    const r = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    const sk = gpa.create(SignalPrivateKey) catch return err_mod.alloc(.internal_error, "OOM");
    sk.* = .{ .inner = r.inner.privateKey() };
    out.raw = sk;
    return null;
}

pub export fn signal_signed_pre_key_record_get_signature(out: *SignalOwnedBuffer, obj: SignalConstPointerSignedPreKeyRecord) ?*SignalFfiError {
    const r = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    out.* = SignalOwnedBuffer.dupe(&r.inner.signature) catch return err_mod.alloc(.internal_error, "OOM");
    return null;
}

// ── SignalSenderKeyRecord ──────────────────────────────────────────────────────
// Stored as an opaque byte blob; the internal format is application-defined.

pub const SignalSenderKeyRecord = struct {
    data: []u8,

    pub fn deinit(self: *SignalSenderKeyRecord) void {
        gpa.free(self.data);
    }
};

pub const SignalMutPointerSenderKeyRecord = extern struct { raw: ?*SignalSenderKeyRecord };
pub const SignalConstPointerSenderKeyRecord = extern struct { raw: ?*const SignalSenderKeyRecord };

pub export fn signal_sender_key_record_clone(new_obj: *SignalMutPointerSenderKeyRecord, obj: SignalConstPointerSenderKeyRecord) ?*SignalFfiError {
    const src = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    const copy = gpa.create(SignalSenderKeyRecord) catch return err_mod.alloc(.internal_error, "OOM");
    copy.data = gpa.dupe(u8, src.data) catch {
        gpa.destroy(copy);
        return err_mod.alloc(.internal_error, "OOM");
    };
    new_obj.raw = copy;
    return null;
}

pub export fn signal_sender_key_record_destroy(p: SignalMutPointerSenderKeyRecord) ?*SignalFfiError {
    if (p.raw) |r| {
        r.deinit();
        gpa.destroy(r);
    }
    return null;
}

pub export fn signal_sender_key_record_serialize(out: *SignalOwnedBuffer, obj: SignalConstPointerSenderKeyRecord) ?*SignalFfiError {
    const r = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    out.* = SignalOwnedBuffer.dupe(r.data) catch return err_mod.alloc(.internal_error, "OOM");
    return null;
}

pub export fn signal_sender_key_record_deserialize(out: *SignalMutPointerSenderKeyRecord, data: SignalBorrowedBuffer) ?*SignalFfiError {
    const record = gpa.create(SignalSenderKeyRecord) catch return err_mod.alloc(.internal_error, "OOM");
    record.data = gpa.dupe(u8, data.slice()) catch {
        gpa.destroy(record);
        return err_mod.alloc(.internal_error, "OOM");
    };
    out.raw = record;
    return null;
}

// ── SignalSessionRecord — Phase 7 ─────────────────────────────────────────────

pub const SignalSessionRecord = struct {
    inner: session_record_mod.SessionRecord,

    pub fn deinit(self: *SignalSessionRecord) void {
        self.inner.deinit();
    }
};

pub const SignalMutPointerSessionRecord = extern struct { raw: ?*SignalSessionRecord };
pub const SignalConstPointerSessionRecord = extern struct { raw: ?*const SignalSessionRecord };

pub export fn signal_session_record_new(out: *SignalMutPointerSessionRecord) ?*SignalFfiError {
    const record = gpa.create(SignalSessionRecord) catch return err_mod.alloc(.internal_error, "OOM");
    record.* = .{ .inner = session_record_mod.SessionRecord.new(gpa) };
    out.raw = record;
    return null;
}

pub export fn signal_session_record_clone(new_obj: *SignalMutPointerSessionRecord, obj: SignalConstPointerSessionRecord) ?*SignalFfiError {
    const src = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    const bytes = src.inner.serialize() catch |e| return err_mod.fromZigError(e);
    defer gpa.free(bytes);
    const inner = session_record_mod.SessionRecord.deserialize(gpa, bytes) catch |e| return err_mod.fromZigError(e);
    const copy = gpa.create(SignalSessionRecord) catch {
        var r = inner;
        r.deinit();
        return err_mod.alloc(.internal_error, "OOM");
    };
    copy.* = .{ .inner = inner };
    new_obj.raw = copy;
    return null;
}

pub export fn signal_session_record_destroy(p: SignalMutPointerSessionRecord) ?*SignalFfiError {
    if (p.raw) |r| {
        r.deinit();
        gpa.destroy(r);
    }
    return null;
}

pub export fn signal_session_record_serialize(out: *SignalOwnedBuffer, obj: SignalConstPointerSessionRecord) ?*SignalFfiError {
    const r = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    const bytes = r.inner.serialize() catch |e| return err_mod.fromZigError(e);
    out.* = .{ .base = bytes.ptr, .length = bytes.len };
    return null;
}

pub export fn signal_session_record_deserialize(out: *SignalMutPointerSessionRecord, data: SignalBorrowedBuffer) ?*SignalFfiError {
    const inner = session_record_mod.SessionRecord.deserialize(gpa, data.slice()) catch |e| return err_mod.fromZigError(e);
    const record = gpa.create(SignalSessionRecord) catch {
        var r = inner;
        r.deinit();
        return err_mod.alloc(.internal_error, "OOM");
    };
    record.* = .{ .inner = inner };
    out.raw = record;
    return null;
}

pub export fn signal_session_record_get_local_registration_id(out: *u32, obj: SignalConstPointerSessionRecord) ?*SignalFfiError {
    const r = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    if (r.inner.current_state) |cs| {
        out.* = cs.local_registration_id;
    } else {
        out.* = 0;
    }
    return null;
}

pub export fn signal_session_record_get_remote_registration_id(out: *u32, obj: SignalConstPointerSessionRecord) ?*SignalFfiError {
    const r = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    if (r.inner.current_state) |cs| {
        out.* = cs.remote_registration_id;
    } else {
        out.* = 0;
    }
    return null;
}

pub export fn signal_session_record_has_usable_sender_chain(out: *bool, obj: SignalConstPointerSessionRecord) ?*SignalFfiError {
    const r = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    if (r.inner.current_state) |cs| {
        out.* = cs.hasUsableSenderChain();
    } else {
        out.* = false;
    }
    return null;
}

pub export fn signal_session_record_current_ratchet_key_matches(out: *bool, obj: SignalConstPointerSessionRecord, key: keys.SignalConstPointerPublicKey) ?*SignalFfiError {
    const r = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    const pk = key.raw orelse return err_mod.alloc(.null_parameter, "key is null");
    if (r.inner.current_state) |cs| {
        out.* = cs.currentRatchetKeyMatchesSenderChain(pk.inner);
    } else {
        out.* = false;
    }
    return null;
}

pub export fn signal_session_record_archive_current_state(obj: SignalMutPointerSessionRecord) ?*SignalFfiError {
    const r = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    r.inner.archiveCurrentState() catch |e| return err_mod.fromZigError(e);
    return null;
}
