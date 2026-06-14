//! Sealed Sender FFI: ServerCertificate, SenderCertificate, USMC, encrypt/decrypt.

const std = @import("std");
const err_mod = @import("error.zig");
const keys = @import("keys.zig");
const ss = @import("../sealed_sender.zig");
const curve = @import("../curve.zig");
const gpa = std.heap.c_allocator;

const SignalFfiError = err_mod.SignalFfiError;
const SignalOwnedBuffer = keys.SignalOwnedBuffer;
const SignalBorrowedBuffer = keys.SignalBorrowedBuffer;
const SignalPublicKey = keys.SignalPublicKey;
const SignalPrivateKey = keys.SignalPrivateKey;
const SignalMutPointerPublicKey = keys.SignalMutPointerPublicKey;
const SignalConstPointerPublicKey = keys.SignalConstPointerPublicKey;
const SignalConstPointerPrivateKey = keys.SignalConstPointerPrivateKey;

// ── ServerCertificate ─────────────────────────────────────────────────────────

pub const SignalServerCertificate = struct {
    inner: ss.ServerCertificate,

    pub fn deinit(self: *SignalServerCertificate) void {
        self.inner.deinit();
    }
};

pub const SignalMutPointerServerCertificate = extern struct { raw: ?*SignalServerCertificate };
pub const SignalConstPointerServerCertificate = extern struct { raw: ?*const SignalServerCertificate };

pub export fn signal_server_certificate_new(
    out: *SignalMutPointerServerCertificate,
    key_id: u32,
    server_public_key: SignalConstPointerPublicKey,
    trust_root_private_key: SignalConstPointerPrivateKey,
) ?*SignalFfiError {
    const spk = server_public_key.raw orelse return err_mod.alloc(.null_parameter, "server_public_key is null");
    const trk = trust_root_private_key.raw orelse return err_mod.alloc(.null_parameter, "trust_root_private_key is null");
    const obj = gpa.create(SignalServerCertificate) catch return err_mod.alloc(.internal_error, "OOM");
    obj.inner = ss.ServerCertificate.new(gpa, key_id, spk.inner, trk.inner) catch |e| {
        gpa.destroy(obj);
        return err_mod.fromZigError(e);
    };
    out.raw = obj;
    return null;
}

pub export fn signal_server_certificate_deserialize(out: *SignalMutPointerServerCertificate, data: SignalBorrowedBuffer) ?*SignalFfiError {
    const obj = gpa.create(SignalServerCertificate) catch return err_mod.alloc(.internal_error, "OOM");
    obj.inner = ss.ServerCertificate.deserialize(gpa, data.slice()) catch |e| {
        gpa.destroy(obj);
        return err_mod.fromZigError(e);
    };
    out.raw = obj;
    return null;
}

pub export fn signal_server_certificate_clone(new_obj: *SignalMutPointerServerCertificate, obj: SignalConstPointerServerCertificate) ?*SignalFfiError {
    const src = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    const bytes = src.inner.serialize() catch return err_mod.alloc(.internal_error, "serialize failed");
    defer gpa.free(bytes);
    const copy = gpa.create(SignalServerCertificate) catch return err_mod.alloc(.internal_error, "OOM");
    copy.inner = ss.ServerCertificate.deserialize(gpa, bytes) catch |e| {
        gpa.destroy(copy);
        return err_mod.fromZigError(e);
    };
    new_obj.raw = copy;
    return null;
}

pub export fn signal_server_certificate_destroy(p: SignalMutPointerServerCertificate) ?*SignalFfiError {
    if (p.raw) |obj| {
        obj.deinit();
        gpa.destroy(obj);
    }
    return null;
}

pub export fn signal_server_certificate_serialize(out: *SignalOwnedBuffer, obj: SignalConstPointerServerCertificate) ?*SignalFfiError {
    const sc = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    const bytes = sc.inner.serialize() catch return err_mod.alloc(.internal_error, "serialize failed");
    out.* = .{ .base = bytes.ptr, .length = bytes.len };
    return null;
}

pub export fn signal_server_certificate_get_key_id(out: *u32, obj: SignalConstPointerServerCertificate) ?*SignalFfiError {
    const sc = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    out.* = sc.inner.key_id;
    return null;
}

pub export fn signal_server_certificate_get_key(out: *SignalMutPointerPublicKey, obj: SignalConstPointerServerCertificate) ?*SignalFfiError {
    const sc = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    const pk = gpa.create(SignalPublicKey) catch return err_mod.alloc(.internal_error, "OOM");
    pk.* = .{ .inner = sc.inner.key };
    out.raw = pk;
    return null;
}

// ── SenderCertificate ─────────────────────────────────────────────────────────

pub const SignalSenderCertificate = struct {
    inner: ss.SenderCertificate,

    pub fn deinit(self: *SignalSenderCertificate) void {
        self.inner.deinit();
    }
};

pub const SignalMutPointerSenderCertificate = extern struct { raw: ?*SignalSenderCertificate };
pub const SignalConstPointerSenderCertificate = extern struct { raw: ?*const SignalSenderCertificate };

pub export fn signal_sender_certificate_new(
    out: *SignalMutPointerSenderCertificate,
    sender_uuid: [*:0]const u8,
    sender_e164: ?[*:0]const u8,
    sender_device_id: u32,
    sender_key: SignalConstPointerPublicKey,
    expiration: u64,
    server_cert: SignalConstPointerServerCertificate,
    server_private_key: SignalConstPointerPrivateKey,
) ?*SignalFfiError {
    const sk = sender_key.raw orelse return err_mod.alloc(.null_parameter, "sender_key is null");
    const sc = server_cert.raw orelse return err_mod.alloc(.null_parameter, "server_cert is null");
    const spk = server_private_key.raw orelse return err_mod.alloc(.null_parameter, "server_private_key is null");

    // Clone the server certificate so SenderCertificate can own it.
    const sc_bytes = sc.inner.serialize() catch return err_mod.alloc(.internal_error, "OOM");
    defer gpa.free(sc_bytes);
    var sc_clone = ss.ServerCertificate.deserialize(gpa, sc_bytes) catch return err_mod.alloc(.internal_error, "OOM");
    errdefer sc_clone.deinit();

    const uuid_slice = std.mem.span(sender_uuid);
    const e164_slice: ?[]const u8 = if (sender_e164) |e| std.mem.span(e) else null;

    const obj = gpa.create(SignalSenderCertificate) catch return err_mod.alloc(.internal_error, "OOM");
    obj.inner = ss.SenderCertificate.new(gpa, uuid_slice, e164_slice, sender_device_id, sk.inner, expiration, sc_clone, spk.inner) catch |e| {
        gpa.destroy(obj);
        return err_mod.fromZigError(e);
    };
    out.raw = obj;
    return null;
}

pub export fn signal_sender_certificate_deserialize(out: *SignalMutPointerSenderCertificate, data: SignalBorrowedBuffer) ?*SignalFfiError {
    const obj = gpa.create(SignalSenderCertificate) catch return err_mod.alloc(.internal_error, "OOM");
    obj.inner = ss.SenderCertificate.deserialize(gpa, data.slice()) catch |e| {
        gpa.destroy(obj);
        return err_mod.fromZigError(e);
    };
    out.raw = obj;
    return null;
}

pub export fn signal_sender_certificate_clone(new_obj: *SignalMutPointerSenderCertificate, obj: SignalConstPointerSenderCertificate) ?*SignalFfiError {
    const src = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    const bytes = src.inner.serialize() catch return err_mod.alloc(.internal_error, "serialize failed");
    defer gpa.free(bytes);
    const copy = gpa.create(SignalSenderCertificate) catch return err_mod.alloc(.internal_error, "OOM");
    copy.inner = ss.SenderCertificate.deserialize(gpa, bytes) catch |e| {
        gpa.destroy(copy);
        return err_mod.fromZigError(e);
    };
    new_obj.raw = copy;
    return null;
}

pub export fn signal_sender_certificate_destroy(p: SignalMutPointerSenderCertificate) ?*SignalFfiError {
    if (p.raw) |obj| {
        obj.deinit();
        gpa.destroy(obj);
    }
    return null;
}

pub export fn signal_sender_certificate_serialize(out: *SignalOwnedBuffer, obj: SignalConstPointerSenderCertificate) ?*SignalFfiError {
    const sc = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    const bytes = sc.inner.serialize() catch return err_mod.alloc(.internal_error, "serialize failed");
    out.* = .{ .base = bytes.ptr, .length = bytes.len };
    return null;
}

pub export fn signal_sender_certificate_validate(out: *bool, obj: SignalConstPointerSenderCertificate, trust_root: SignalConstPointerPublicKey, current_time: u64) ?*SignalFfiError {
    const sc = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    const tr = trust_root.raw orelse return err_mod.alloc(.null_parameter, "trust_root is null");
    out.* = sc.inner.validate(tr.inner, current_time) catch |e| return err_mod.fromZigError(e);
    return null;
}

pub export fn signal_sender_certificate_get_sender_uuid(out: *[*:0]const u8, obj: SignalConstPointerSenderCertificate) ?*SignalFfiError {
    const sc = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    // sender_uuid is []const u8, not necessarily null-terminated. Allocate a null-terminated copy.
    const z = gpa.dupeZ(u8, sc.inner.sender_uuid) catch return err_mod.alloc(.internal_error, "OOM");
    out.* = z.ptr;
    return null;
}

pub export fn signal_sender_certificate_get_sender_e164(out: *?[*:0]const u8, obj: SignalConstPointerSenderCertificate) ?*SignalFfiError {
    const sc = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    if (sc.inner.sender_e164) |e164| {
        const z = gpa.dupeZ(u8, e164) catch return err_mod.alloc(.internal_error, "OOM");
        out.* = z.ptr;
    } else {
        out.* = null;
    }
    return null;
}

pub export fn signal_sender_certificate_get_sender_device_id(out: *u32, obj: SignalConstPointerSenderCertificate) ?*SignalFfiError {
    const sc = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    out.* = sc.inner.sender_device_id;
    return null;
}

pub export fn signal_sender_certificate_get_expiration(out: *u64, obj: SignalConstPointerSenderCertificate) ?*SignalFfiError {
    const sc = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    out.* = sc.inner.expiration;
    return null;
}

pub export fn signal_sender_certificate_get_key(out: *SignalMutPointerPublicKey, obj: SignalConstPointerSenderCertificate) ?*SignalFfiError {
    const sc = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    const pk = gpa.create(SignalPublicKey) catch return err_mod.alloc(.internal_error, "OOM");
    pk.* = .{ .inner = sc.inner.sender_key };
    out.raw = pk;
    return null;
}

pub export fn signal_sender_certificate_get_server_certificate(out: *SignalMutPointerServerCertificate, obj: SignalConstPointerSenderCertificate) ?*SignalFfiError {
    const sc = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    const bytes = sc.inner.signer.serialize() catch return err_mod.alloc(.internal_error, "OOM");
    defer gpa.free(bytes);
    const copy = gpa.create(SignalServerCertificate) catch return err_mod.alloc(.internal_error, "OOM");
    copy.inner = ss.ServerCertificate.deserialize(gpa, bytes) catch |e| {
        gpa.destroy(copy);
        return err_mod.fromZigError(e);
    };
    out.raw = copy;
    return null;
}

// ── UnidentifiedSenderMessageContent ─────────────────────────────────────────

pub const SignalUnidentifiedSenderMessageContent = struct {
    inner: ss.UnidentifiedSenderMessageContent,

    pub fn deinit(self: *SignalUnidentifiedSenderMessageContent) void {
        self.inner.deinit();
    }
};

pub const SignalMutPointerUnidentifiedSenderMessageContent = extern struct { raw: ?*SignalUnidentifiedSenderMessageContent };
pub const SignalConstPointerUnidentifiedSenderMessageContent = extern struct { raw: ?*const SignalUnidentifiedSenderMessageContent };

pub export fn signal_unidentified_sender_message_content_new(
    out: *SignalMutPointerUnidentifiedSenderMessageContent,
    message_type: u8,
    sender_cert: SignalConstPointerSenderCertificate,
    content_hint: u8,
    group_id: SignalBorrowedBuffer,
    contents: SignalBorrowedBuffer,
) ?*SignalFfiError {
    const sc = sender_cert.raw orelse return err_mod.alloc(.null_parameter, "sender_cert is null");
    const msg_type: ss.ContentType = @enumFromInt(message_type);
    const hint: ss.ContentHint = @enumFromInt(content_hint);

    // Clone the sender cert so USMC owns it.
    const sc_bytes = sc.inner.serialize() catch return err_mod.alloc(.internal_error, "OOM");
    defer gpa.free(sc_bytes);
    var sc_clone = ss.SenderCertificate.deserialize(gpa, sc_bytes) catch return err_mod.alloc(.internal_error, "OOM");
    errdefer sc_clone.deinit();

    const gid: ?[]const u8 = if (group_id.length > 0) group_id.slice() else null;

    const obj = gpa.create(SignalUnidentifiedSenderMessageContent) catch return err_mod.alloc(.internal_error, "OOM");
    obj.inner = ss.UnidentifiedSenderMessageContent.new(gpa, msg_type, sc_clone, hint, gid, contents.slice()) catch |e| {
        gpa.destroy(obj);
        return err_mod.fromZigError(e);
    };
    out.raw = obj;
    return null;
}

pub export fn signal_unidentified_sender_message_content_deserialize(out: *SignalMutPointerUnidentifiedSenderMessageContent, data: SignalBorrowedBuffer) ?*SignalFfiError {
    const obj = gpa.create(SignalUnidentifiedSenderMessageContent) catch return err_mod.alloc(.internal_error, "OOM");
    obj.inner = ss.UnidentifiedSenderMessageContent.deserialize(gpa, data.slice()) catch |e| {
        gpa.destroy(obj);
        return err_mod.fromZigError(e);
    };
    out.raw = obj;
    return null;
}

pub export fn signal_unidentified_sender_message_content_clone(new_obj: *SignalMutPointerUnidentifiedSenderMessageContent, obj: SignalConstPointerUnidentifiedSenderMessageContent) ?*SignalFfiError {
    const src = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    const bytes = src.inner.serialize() catch return err_mod.alloc(.internal_error, "serialize failed");
    defer gpa.free(bytes);
    const copy = gpa.create(SignalUnidentifiedSenderMessageContent) catch return err_mod.alloc(.internal_error, "OOM");
    copy.inner = ss.UnidentifiedSenderMessageContent.deserialize(gpa, bytes) catch |e| {
        gpa.destroy(copy);
        return err_mod.fromZigError(e);
    };
    new_obj.raw = copy;
    return null;
}

pub export fn signal_unidentified_sender_message_content_destroy(p: SignalMutPointerUnidentifiedSenderMessageContent) ?*SignalFfiError {
    if (p.raw) |obj| {
        obj.deinit();
        gpa.destroy(obj);
    }
    return null;
}

pub export fn signal_unidentified_sender_message_content_serialize(out: *SignalOwnedBuffer, obj: SignalConstPointerUnidentifiedSenderMessageContent) ?*SignalFfiError {
    const usmc = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    const bytes = usmc.inner.serialize() catch return err_mod.alloc(.internal_error, "serialize failed");
    out.* = .{ .base = bytes.ptr, .length = bytes.len };
    return null;
}

pub export fn signal_unidentified_sender_message_content_get_msg_type(out: *u8, obj: SignalConstPointerUnidentifiedSenderMessageContent) ?*SignalFfiError {
    const usmc = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    out.* = @intFromEnum(usmc.inner.msg_type);
    return null;
}

pub export fn signal_unidentified_sender_message_content_get_content_hint(out: *u8, obj: SignalConstPointerUnidentifiedSenderMessageContent) ?*SignalFfiError {
    const usmc = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    out.* = @intFromEnum(usmc.inner.content_hint);
    return null;
}

pub export fn signal_unidentified_sender_message_content_get_group_id(out: *SignalOwnedBuffer, obj: SignalConstPointerUnidentifiedSenderMessageContent) ?*SignalFfiError {
    const usmc = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    if (usmc.inner.group_id) |g| {
        out.* = SignalOwnedBuffer.dupe(g) catch return err_mod.alloc(.internal_error, "OOM");
    } else {
        out.* = SignalOwnedBuffer.empty();
    }
    return null;
}

pub export fn signal_unidentified_sender_message_content_get_contents(out: *SignalOwnedBuffer, obj: SignalConstPointerUnidentifiedSenderMessageContent) ?*SignalFfiError {
    const usmc = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    out.* = SignalOwnedBuffer.dupe(usmc.inner.contents) catch return err_mod.alloc(.internal_error, "OOM");
    return null;
}

pub export fn signal_unidentified_sender_message_content_get_sender_cert(out: *SignalMutPointerSenderCertificate, obj: SignalConstPointerUnidentifiedSenderMessageContent) ?*SignalFfiError {
    const usmc = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    const sc_bytes = usmc.inner.sender_cert.serialize() catch return err_mod.alloc(.internal_error, "OOM");
    defer gpa.free(sc_bytes);
    const copy = gpa.create(SignalSenderCertificate) catch return err_mod.alloc(.internal_error, "OOM");
    copy.inner = ss.SenderCertificate.deserialize(gpa, sc_bytes) catch |e| {
        gpa.destroy(copy);
        return err_mod.fromZigError(e);
    };
    out.raw = copy;
    return null;
}

// ── Sealed Sender encrypt / decrypt ──────────────────────────────────────────

pub export fn signal_sealed_session_cipher_encrypt(
    out: *SignalOwnedBuffer,
    recipient_identity: SignalConstPointerPublicKey,
    usmc: SignalConstPointerUnidentifiedSenderMessageContent,
) ?*SignalFfiError {
    const ik = recipient_identity.raw orelse return err_mod.alloc(.null_parameter, "recipient_identity is null");
    const msg = usmc.raw orelse return err_mod.alloc(.null_parameter, "usmc is null");
    const bytes = ss.sealedSenderEncrypt(gpa, ik.inner, &msg.inner) catch |e| return err_mod.fromZigError(e);
    out.* = .{ .base = bytes.ptr, .length = bytes.len };
    return null;
}

pub export fn signal_sealed_session_cipher_decrypt_to_usmc(
    out: *SignalMutPointerUnidentifiedSenderMessageContent,
    ciphertext: SignalBorrowedBuffer,
    our_identity_private_key: SignalConstPointerPrivateKey,
) ?*SignalFfiError {
    const our_key = our_identity_private_key.raw orelse return err_mod.alloc(.null_parameter, "our_identity_private_key is null");
    var usmc = ss.sealedSenderDecryptToUsmc(gpa, ciphertext.slice(), our_key.inner) catch |e| return err_mod.fromZigError(e);
    const obj = gpa.create(SignalUnidentifiedSenderMessageContent) catch {
        usmc.deinit();
        return err_mod.alloc(.internal_error, "OOM");
    };
    obj.inner = usmc;
    out.raw = obj;
    return null;
}

// ── SSv2 multi-recipient encrypt / server-side dispatch ───────────────────────

/// Per-recipient info for SSv2 multi-recipient encryption.
/// Passed as an array pointer + count.
pub const SignalSealedSenderV2Recipient = extern struct {
    service_id_fixed_width: [17]u8,
    device_id: u8,
    identity_key_ptr: ?*const SignalPublicKey,
};

pub export fn signal_sealed_sender_multi_recipient_encrypt(
    out: *SignalOwnedBuffer,
    message: SignalBorrowedBuffer,
    sender_identity_private_key: SignalConstPointerPrivateKey,
    recipients_ptr: [*]const SignalSealedSenderV2Recipient,
    recipients_len: usize,
    excluded_ids_ptr: ?[*]const [17]u8,
    excluded_ids_len: usize,
) ?*SignalFfiError {
    const sk = sender_identity_private_key.raw orelse return err_mod.alloc(.null_parameter, "sender_identity_private_key is null");
    const sender_pub = sk.inner.publicKey() catch return err_mod.alloc(.internal_error, "key error");
    const sender_kp = curve.KeyPair{ .private_key = sk.inner, .public_key = sender_pub };

    const service_id_mod = @import("../service_id.zig");
    const recipients_ffi = recipients_ptr[0..recipients_len];
    var recipients = gpa.alloc(ss.SealedSenderV2Recipient, recipients_len) catch return err_mod.alloc(.internal_error, "OOM");
    defer gpa.free(recipients);

    for (recipients_ffi, 0..) |r, i| {
        const ik = r.identity_key_ptr orelse return err_mod.alloc(.null_parameter, "recipient identity_key is null");
        const sid = service_id_mod.ServiceId.fromFixedWidthBinary(r.service_id_fixed_width) catch return err_mod.alloc(.invalid_argument, "invalid service_id");
        recipients[i] = .{
            .service_id = sid,
            .device_id = r.device_id,
            .identity_key = ik.inner,
        };
    }

    const excluded_ffi: []const [17]u8 = if (excluded_ids_ptr) |p| p[0..excluded_ids_len] else &[0][17]u8{};
    var excluded = gpa.alloc(service_id_mod.ServiceId, excluded_ids_len) catch return err_mod.alloc(.internal_error, "OOM");
    defer gpa.free(excluded);

    for (excluded_ffi, 0..) |sid_bin, i| {
        excluded[i] = service_id_mod.ServiceId.fromFixedWidthBinary(sid_bin) catch return err_mod.alloc(.invalid_argument, "invalid excluded service_id");
    }

    const bytes = ss.sealedSenderEncryptV2(gpa, message.slice(), sender_kp, recipients, excluded) catch |e| return err_mod.fromZigError(e);
    out.* = .{ .base = bytes.ptr, .length = bytes.len };
    return null;
}

pub export fn signal_sealed_sender_multi_recipient_message_for_single_recipient(
    out: *SignalOwnedBuffer,
    multi_recipient_message: SignalBorrowedBuffer,
    service_id_fixed_width: *const [17]u8,
    device_id: u8,
) ?*SignalFfiError {
    const bytes = ss.v2Dispatch(gpa, multi_recipient_message.slice(), service_id_fixed_width.*, device_id) catch |e| return err_mod.fromZigError(e);
    out.* = .{ .base = bytes.ptr, .length = bytes.len };
    return null;
}

/// Decrypt a per-device SSv2 received message.
pub export fn signal_sealed_sender_decrypt_v2(
    out: *SignalOwnedBuffer,
    received: SignalBorrowedBuffer,
    our_identity_private_key: SignalConstPointerPrivateKey,
    sender_identity_key: SignalConstPointerPublicKey,
) ?*SignalFfiError {
    const our_sk = our_identity_private_key.raw orelse return err_mod.alloc(.null_parameter, "our_identity_private_key is null");
    const sender_ik = sender_identity_key.raw orelse return err_mod.alloc(.null_parameter, "sender_identity_key is null");
    const our_pub = our_sk.inner.publicKey() catch return err_mod.alloc(.internal_error, "key error");
    const our_kp = curve.KeyPair{ .private_key = our_sk.inner, .public_key = our_pub };
    const plaintext = ss.sealedSenderDecryptV2(gpa, received.slice(), our_kp, sender_ik.inner) catch |e| return err_mod.fromZigError(e);
    out.* = .{ .base = plaintext.ptr, .length = plaintext.len };
    return null;
}
