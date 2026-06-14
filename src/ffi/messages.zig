//! Signal message types.

const std = @import("std");
const err_mod = @import("error.zig");
const keys = @import("keys.zig");
const curve = @import("../curve.zig");
const proto = @import("../proto.zig");
const signal_msg = @import("../messages/signal_message.zig");
const prekey_msg = @import("../messages/pre_key_signal_message.zig");
const skm = @import("../messages/sender_key_message.zig");
const skdm = @import("../messages/sender_key_distribution_message.zig");
const plaintext_mod = @import("../messages/plaintext_content.zig");
const dec_err_mod = @import("../messages/decryption_error_message.zig");
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const gpa = std.heap.c_allocator;

const SignalFfiError = err_mod.SignalFfiError;
const SignalOwnedBuffer = keys.SignalOwnedBuffer;
const SignalBorrowedBuffer = keys.SignalBorrowedBuffer;
const SignalMutPointerPublicKey = keys.SignalMutPointerPublicKey;
const SignalConstPointerPublicKey = keys.SignalConstPointerPublicKey;
const SignalPublicKey = keys.SignalPublicKey;
const SignalConstPointerPrivateKey = keys.SignalConstPointerPrivateKey;

// ── SignalMessage ─────────────────────────────────────────────────────────────
// Stores the deserialized fields + the complete serialized wire bytes.

pub const SignalMessage = struct {
    serialized: []u8, // owned; complete wire bytes including version byte and MAC
    ratchet_key: curve.PublicKey,
    counter: u32,
    previous_counter: u32,
    ciphertext: []u8, // owned
    message_version: u8,
    pq_ratchet: []u8, // owned; empty if none

    pub fn deinit(self: *SignalMessage) void {
        gpa.free(self.serialized);
        gpa.free(self.ciphertext);
        if (self.pq_ratchet.len > 0) gpa.free(self.pq_ratchet);
    }
};

pub const SignalMutPointerMessage = extern struct { raw: ?*SignalMessage };
pub const SignalConstPointerMessage = extern struct { raw: ?*const SignalMessage };

// Parse SignalMessage fields from wire bytes (without MAC check).
fn parseSignalMessageWire(data: []const u8) !SignalMessage {
    if (data.len < 1 + signal_msg.MAC_LENGTH) return error.InvalidMessage;
    const version_byte = data[0];
    const message_version = version_byte >> 4;
    // Body is between version byte and trailing 8-byte MAC.
    const body = data[1 .. data.len - signal_msg.MAC_LENGTH];

    var pos: usize = 0;
    var ratchet_key_raw: ?[]const u8 = null;
    var counter: u32 = 0;
    var previous_counter: u32 = 0;
    var ciphertext_raw: ?[]const u8 = null;
    var pq_ratchet_raw: ?[]const u8 = null;

    while (try proto.nextField(body, &pos)) |field| {
        switch (field.number) {
            1 => if (field.wire_type == .len) {
                ratchet_key_raw = field.data.len;
            },
            2 => if (field.wire_type == .varint) {
                counter = @intCast(field.data.varint & 0xFFFF_FFFF);
            },
            3 => if (field.wire_type == .varint) {
                previous_counter = @intCast(field.data.varint & 0xFFFF_FFFF);
            },
            4 => if (field.wire_type == .len) {
                ciphertext_raw = field.data.len;
            },
            5 => if (field.wire_type == .len) {
                pq_ratchet_raw = field.data.len;
            },
            else => {},
        }
    }

    const rk_bytes = ratchet_key_raw orelse return error.InvalidMessage;
    const ct_bytes = ciphertext_raw orelse return error.InvalidMessage;

    const ratchet_key = try curve.PublicKey.deserialize(rk_bytes);
    const serialized = try gpa.dupe(u8, data);
    const ciphertext = try gpa.dupe(u8, ct_bytes);
    const pq_ratchet = if (pq_ratchet_raw) |pqr| try gpa.dupe(u8, pqr) else try gpa.dupe(u8, &[_]u8{});

    return SignalMessage{
        .serialized = serialized,
        .ratchet_key = ratchet_key,
        .counter = counter,
        .previous_counter = previous_counter,
        .ciphertext = ciphertext,
        .message_version = message_version,
        .pq_ratchet = pq_ratchet,
    };
}

pub export fn signal_message_deserialize(out: *SignalMutPointerMessage, data: SignalBorrowedBuffer) ?*SignalFfiError {
    const msg = gpa.create(SignalMessage) catch return err_mod.alloc(.internal_error, "OOM");
    msg.* = parseSignalMessageWire(data.slice()) catch |e| {
        gpa.destroy(msg);
        return err_mod.fromZigError(e);
    };
    out.raw = msg;
    return null;
}

pub export fn signal_message_new(out: *SignalMutPointerMessage, message_version: u8, mac_key: SignalBorrowedBuffer, sender_ratchet_key: SignalConstPointerPublicKey, counter: u32, previous_counter: u32, ciphertext: SignalBorrowedBuffer, sender_identity_key: SignalConstPointerPublicKey, receiver_identity_key: SignalConstPointerPublicKey) ?*SignalFfiError {
    if (mac_key.length != 32) return err_mod.alloc(.invalid_argument, "mac_key must be 32 bytes");
    const rk_ptr = sender_ratchet_key.raw orelse return err_mod.alloc(.null_parameter, "sender_ratchet_key is null");
    const sik_ptr = sender_identity_key.raw orelse return err_mod.alloc(.null_parameter, "sender_identity_key is null");
    const rik_ptr = receiver_identity_key.raw orelse return err_mod.alloc(.null_parameter, "receiver_identity_key is null");

    const mac_k: [32]u8 = mac_key.slice()[0..32].*;
    const sender_id = sik_ptr.inner.serialize();
    const receiver_id = rik_ptr.inner.serialize();

    const inner = signal_msg.SignalMessage{
        .message_version = message_version,
        .ratchet_key = rk_ptr.inner,
        .counter = counter,
        .previous_counter = previous_counter,
        .ciphertext = ciphertext.slice(),
        .pq_ratchet = null,
        .addresses = null,
        .allocator = gpa,
    };

    const serialized = inner.serialize(sender_id, receiver_id, mac_k) catch |e| return err_mod.fromZigError(e);

    const ffi_msg = gpa.create(SignalMessage) catch {
        gpa.free(serialized);
        return err_mod.alloc(.internal_error, "OOM");
    };
    ffi_msg.* = parseSignalMessageWire(serialized) catch |e| {
        gpa.free(serialized);
        gpa.destroy(ffi_msg);
        return err_mod.fromZigError(e);
    };
    // parseSignalMessageWire dupes the data, free original
    gpa.free(serialized);
    out.raw = ffi_msg;
    return null;
}

pub export fn signal_message_clone(new_obj: *SignalMutPointerMessage, obj: SignalConstPointerMessage) ?*SignalFfiError {
    const src = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    const copy = gpa.create(SignalMessage) catch return err_mod.alloc(.internal_error, "OOM");
    copy.* = parseSignalMessageWire(src.serialized) catch |e| {
        gpa.destroy(copy);
        return err_mod.fromZigError(e);
    };
    new_obj.raw = copy;
    return null;
}

pub export fn signal_message_destroy(p: SignalMutPointerMessage) ?*SignalFfiError {
    if (p.raw) |msg| {
        msg.deinit();
        gpa.destroy(msg);
    }
    return null;
}

pub export fn signal_message_serialize(out: *SignalOwnedBuffer, obj: SignalConstPointerMessage) ?*SignalFfiError {
    const msg = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    out.* = SignalOwnedBuffer.dupe(msg.serialized) catch return err_mod.alloc(.internal_error, "OOM");
    return null;
}

pub export fn signal_message_get_serialized(out: *SignalOwnedBuffer, obj: SignalConstPointerMessage) ?*SignalFfiError {
    return signal_message_serialize(out, obj);
}

pub export fn signal_message_get_sender_ratchet_key(out: *SignalMutPointerPublicKey, obj: SignalConstPointerMessage) ?*SignalFfiError {
    const msg = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    const pk = gpa.create(SignalPublicKey) catch return err_mod.alloc(.internal_error, "OOM");
    pk.* = .{ .inner = msg.ratchet_key };
    out.raw = pk;
    return null;
}

pub export fn signal_message_get_counter(out: *u32, obj: SignalConstPointerMessage) ?*SignalFfiError {
    const msg = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    out.* = msg.counter;
    return null;
}

pub export fn signal_message_get_message_version(out: *u32, obj: SignalConstPointerMessage) ?*SignalFfiError {
    const msg = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    out.* = msg.message_version;
    return null;
}

pub export fn signal_message_get_body(out: *SignalOwnedBuffer, obj: SignalConstPointerMessage) ?*SignalFfiError {
    const msg = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    out.* = SignalOwnedBuffer.dupe(msg.ciphertext) catch return err_mod.alloc(.internal_error, "OOM");
    return null;
}

pub export fn signal_message_get_pq_ratchet(out: *SignalOwnedBuffer, obj: SignalConstPointerMessage) ?*SignalFfiError {
    const msg = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    out.* = SignalOwnedBuffer.dupe(msg.pq_ratchet) catch return err_mod.alloc(.internal_error, "OOM");
    return null;
}

// ── SignalPreKeySignalMessage ─────────────────────────────────────────────────

pub const SignalPreKeySignalMessage = struct {
    inner: prekey_msg.PreKeySignalMessage,

    pub fn deinit(self: *SignalPreKeySignalMessage) void {
        self.inner.deinit();
    }
};

pub const SignalMutPointerPreKeySignalMessage = extern struct { raw: ?*SignalPreKeySignalMessage };
pub const SignalConstPointerPreKeySignalMessage = extern struct { raw: ?*const SignalPreKeySignalMessage };

pub export fn signal_pre_key_signal_message_deserialize(out: *SignalMutPointerPreKeySignalMessage, data: SignalBorrowedBuffer) ?*SignalFfiError {
    const inner = prekey_msg.PreKeySignalMessage.deserialize(gpa, data.slice()) catch |e| return err_mod.fromZigError(e);
    const msg = gpa.create(SignalPreKeySignalMessage) catch {
        var m = inner;
        m.deinit();
        return err_mod.alloc(.internal_error, "OOM");
    };
    msg.* = .{ .inner = inner };
    out.raw = msg;
    return null;
}

pub export fn signal_pre_key_signal_message_new(out: *SignalMutPointerPreKeySignalMessage, message_version: u8, registration_id: u32, pre_key_id: *const u32, pre_key_id_valid: bool, signed_pre_key_id: u32, base_key: SignalConstPointerPublicKey, identity_key: SignalConstPointerPublicKey, signal_message: SignalBorrowedBuffer) ?*SignalFfiError {
    const bk_ptr = base_key.raw orelse return err_mod.alloc(.null_parameter, "base_key is null");
    const ik_ptr = identity_key.raw orelse return err_mod.alloc(.null_parameter, "identity_key is null");

    const msg_bytes = gpa.dupe(u8, signal_message.slice()) catch return err_mod.alloc(.internal_error, "OOM");

    const inner = prekey_msg.PreKeySignalMessage{
        .message_version = message_version,
        .registration_id = registration_id,
        .pre_key_id = if (pre_key_id_valid) pre_key_id.* else null,
        .signed_pre_key_id = signed_pre_key_id,
        .kyber_pre_key_id = null,
        .base_key = bk_ptr.inner,
        .identity_key = ik_ptr.inner,
        .kyber_ciphertext = null,
        .message = msg_bytes,
        .allocator = gpa,
    };

    const wrapper = gpa.create(SignalPreKeySignalMessage) catch {
        gpa.free(msg_bytes);
        return err_mod.alloc(.internal_error, "OOM");
    };
    wrapper.* = .{ .inner = inner };
    out.raw = wrapper;
    return null;
}

pub export fn signal_pre_key_signal_message_clone(new_obj: *SignalMutPointerPreKeySignalMessage, obj: SignalConstPointerPreKeySignalMessage) ?*SignalFfiError {
    const src = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    const serialized = src.inner.serialize() catch |e| return err_mod.fromZigError(e);
    defer gpa.free(serialized);
    const inner = prekey_msg.PreKeySignalMessage.deserialize(gpa, serialized) catch |e| return err_mod.fromZigError(e);
    const copy = gpa.create(SignalPreKeySignalMessage) catch {
        var m = inner;
        m.deinit();
        return err_mod.alloc(.internal_error, "OOM");
    };
    copy.* = .{ .inner = inner };
    new_obj.raw = copy;
    return null;
}

pub export fn signal_pre_key_signal_message_destroy(p: SignalMutPointerPreKeySignalMessage) ?*SignalFfiError {
    if (p.raw) |msg| {
        msg.deinit();
        gpa.destroy(msg);
    }
    return null;
}

pub export fn signal_pre_key_signal_message_serialize(out: *SignalOwnedBuffer, obj: SignalConstPointerPreKeySignalMessage) ?*SignalFfiError {
    const msg = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    const bytes = msg.inner.serialize() catch |e| return err_mod.fromZigError(e);
    out.* = .{ .base = bytes.ptr, .length = bytes.len };
    return null;
}

pub export fn signal_pre_key_signal_message_get_version(out: *u32, obj: SignalConstPointerPreKeySignalMessage) ?*SignalFfiError {
    const msg = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    out.* = msg.inner.message_version;
    return null;
}

pub export fn signal_pre_key_signal_message_get_registration_id(out: *u32, obj: SignalConstPointerPreKeySignalMessage) ?*SignalFfiError {
    const msg = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    out.* = msg.inner.registration_id;
    return null;
}

pub export fn signal_pre_key_signal_message_get_pre_key_id(out: *u32, out_valid: *bool, obj: SignalConstPointerPreKeySignalMessage) ?*SignalFfiError {
    const msg = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    if (msg.inner.pre_key_id) |id| {
        out.* = id;
        out_valid.* = true;
    } else {
        out.* = 0;
        out_valid.* = false;
    }
    return null;
}

pub export fn signal_pre_key_signal_message_get_signed_pre_key_id(out: *u32, obj: SignalConstPointerPreKeySignalMessage) ?*SignalFfiError {
    const msg = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    out.* = msg.inner.signed_pre_key_id;
    return null;
}

pub export fn signal_pre_key_signal_message_get_base_key(out: *SignalMutPointerPublicKey, obj: SignalConstPointerPreKeySignalMessage) ?*SignalFfiError {
    const msg = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    const pk = gpa.create(SignalPublicKey) catch return err_mod.alloc(.internal_error, "OOM");
    pk.* = .{ .inner = msg.inner.base_key };
    out.raw = pk;
    return null;
}

pub export fn signal_pre_key_signal_message_get_identity_key(out: *SignalMutPointerPublicKey, obj: SignalConstPointerPreKeySignalMessage) ?*SignalFfiError {
    const msg = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    const pk = gpa.create(SignalPublicKey) catch return err_mod.alloc(.internal_error, "OOM");
    pk.* = .{ .inner = msg.inner.identity_key };
    out.raw = pk;
    return null;
}

pub export fn signal_pre_key_signal_message_get_signal_message(out: *SignalMutPointerMessage, obj: SignalConstPointerPreKeySignalMessage) ?*SignalFfiError {
    const msg = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    const inner_msg = gpa.create(SignalMessage) catch return err_mod.alloc(.internal_error, "OOM");
    inner_msg.* = parseSignalMessageWire(msg.inner.message) catch |e| {
        gpa.destroy(inner_msg);
        return err_mod.fromZigError(e);
    };
    out.raw = inner_msg;
    return null;
}

// ── SignalSenderKeyMessage ────────────────────────────────────────────────────

pub const SignalSenderKeyMessage = struct {
    serialized: []u8, // owned wire bytes
    distribution_uuid: [16]u8,
    chain_id: u32,
    iteration: u32,
    ciphertext: []u8, // owned

    pub fn deinit(self: *SignalSenderKeyMessage) void {
        gpa.free(self.serialized);
        gpa.free(self.ciphertext);
    }
};

pub const SignalMutPointerSenderKeyMessage = extern struct { raw: ?*SignalSenderKeyMessage };
pub const SignalConstPointerSenderKeyMessage = extern struct { raw: ?*const SignalSenderKeyMessage };

fn parseSenderKeyMessageWire(data: []const u8) !SignalSenderKeyMessage {
    if (data.len < 1 + skm.SIGNATURE_LENGTH) return error.InvalidMessage;
    const body = data[1 .. data.len - skm.SIGNATURE_LENGTH];
    var pos: usize = 0;
    var uuid: [16]u8 = undefined;
    var has_uuid = false;
    var chain_id: u32 = 0;
    var iteration: u32 = 0;
    var ciphertext_raw: ?[]const u8 = null;

    while (try proto.nextField(body, &pos)) |field| {
        switch (field.number) {
            1 => if (field.wire_type == .len and field.data.len.len == 16) {
                @memcpy(&uuid, field.data.len);
                has_uuid = true;
            },
            2 => if (field.wire_type == .varint) {
                chain_id = @intCast(field.data.varint & 0xFFFF_FFFF);
            },
            3 => if (field.wire_type == .varint) {
                iteration = @intCast(field.data.varint & 0xFFFF_FFFF);
            },
            4 => if (field.wire_type == .len) {
                ciphertext_raw = field.data.len;
            },
            else => {},
        }
    }

    if (!has_uuid) return error.InvalidMessage;
    const ct = ciphertext_raw orelse return error.InvalidMessage;

    return SignalSenderKeyMessage{
        .serialized = try gpa.dupe(u8, data),
        .distribution_uuid = uuid,
        .chain_id = chain_id,
        .iteration = iteration,
        .ciphertext = try gpa.dupe(u8, ct),
    };
}

pub export fn signal_sender_key_message_deserialize(out: *SignalMutPointerSenderKeyMessage, data: SignalBorrowedBuffer, sender_key: SignalConstPointerPublicKey) ?*SignalFfiError {
    const pk = sender_key.raw orelse return err_mod.alloc(.null_parameter, "sender_key is null");
    // Verify signature
    const src = data.slice();
    if (src.len < 1 + skm.SIGNATURE_LENGTH) return err_mod.alloc(.invalid_message, "sender key message too short");
    const sig_start = src.len - skm.SIGNATURE_LENGTH;
    const sig: [64]u8 = src[sig_start..][0..64].*;
    const valid = pk.inner.verifySignature(src[0..sig_start], sig) catch return err_mod.alloc(.invalid_signature, "signature verification error");
    if (!valid) return err_mod.alloc(.invalid_signature, "sender key message signature invalid");

    const msg = gpa.create(SignalSenderKeyMessage) catch return err_mod.alloc(.internal_error, "OOM");
    msg.* = parseSenderKeyMessageWire(src) catch |e| {
        gpa.destroy(msg);
        return err_mod.fromZigError(e);
    };
    out.raw = msg;
    return null;
}

pub export fn signal_sender_key_message_new(out: *SignalMutPointerSenderKeyMessage, message_version: u8, distribution_id: SignalBorrowedBuffer, chain_id: u32, iteration: u32, ciphertext: SignalBorrowedBuffer, pk: SignalConstPointerPublicKey, signing_key: SignalConstPointerPrivateKey) ?*SignalFfiError {
    _ = message_version;
    if (distribution_id.length != 16) return err_mod.alloc(.invalid_argument, "distribution_id must be 16 bytes");
    const pk_ptr = pk.raw orelse return err_mod.alloc(.null_parameter, "pk is null");
    const sk_ptr = signing_key.raw orelse return err_mod.alloc(.null_parameter, "signing_key is null");
    _ = pk_ptr;
    var uuid: [16]u8 = undefined;
    @memcpy(&uuid, distribution_id.slice()[0..16]);

    const inner = skm.SenderKeyMessage{
        .distribution_uuid = uuid,
        .chain_id = chain_id,
        .iteration = iteration,
        .ciphertext = ciphertext.slice(),
        .allocator = gpa,
    };
    const serialized = inner.serialize(sk_ptr.inner) catch |e| return err_mod.fromZigError(e);

    const ffi_msg = gpa.create(SignalSenderKeyMessage) catch {
        gpa.free(serialized);
        return err_mod.alloc(.internal_error, "OOM");
    };
    ffi_msg.* = parseSenderKeyMessageWire(serialized) catch |e| {
        gpa.free(serialized);
        gpa.destroy(ffi_msg);
        return err_mod.fromZigError(e);
    };
    gpa.free(serialized);
    out.raw = ffi_msg;
    return null;
}

pub export fn signal_sender_key_message_clone(new_obj: *SignalMutPointerSenderKeyMessage, obj: SignalConstPointerSenderKeyMessage) ?*SignalFfiError {
    const src = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    const copy = gpa.create(SignalSenderKeyMessage) catch return err_mod.alloc(.internal_error, "OOM");
    copy.* = parseSenderKeyMessageWire(src.serialized) catch |e| {
        gpa.destroy(copy);
        return err_mod.fromZigError(e);
    };
    new_obj.raw = copy;
    return null;
}

pub export fn signal_sender_key_message_destroy(p: SignalMutPointerSenderKeyMessage) ?*SignalFfiError {
    if (p.raw) |msg| {
        msg.deinit();
        gpa.destroy(msg);
    }
    return null;
}

pub export fn signal_sender_key_message_serialize(out: *SignalOwnedBuffer, obj: SignalConstPointerSenderKeyMessage) ?*SignalFfiError {
    const msg = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    out.* = SignalOwnedBuffer.dupe(msg.serialized) catch return err_mod.alloc(.internal_error, "OOM");
    return null;
}

pub export fn signal_sender_key_message_get_distribution_id(out: *SignalOwnedBuffer, obj: SignalConstPointerSenderKeyMessage) ?*SignalFfiError {
    const msg = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    out.* = SignalOwnedBuffer.dupe(&msg.distribution_uuid) catch return err_mod.alloc(.internal_error, "OOM");
    return null;
}

pub export fn signal_sender_key_message_get_chain_id(out: *u32, obj: SignalConstPointerSenderKeyMessage) ?*SignalFfiError {
    const msg = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    out.* = msg.chain_id;
    return null;
}

pub export fn signal_sender_key_message_get_iteration(out: *u32, obj: SignalConstPointerSenderKeyMessage) ?*SignalFfiError {
    const msg = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    out.* = msg.iteration;
    return null;
}

pub export fn signal_sender_key_message_get_cipher_text(out: *SignalOwnedBuffer, obj: SignalConstPointerSenderKeyMessage) ?*SignalFfiError {
    const msg = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    out.* = SignalOwnedBuffer.dupe(msg.ciphertext) catch return err_mod.alloc(.internal_error, "OOM");
    return null;
}

pub export fn signal_sender_key_message_verify_signature(out: *bool, obj: SignalConstPointerSenderKeyMessage, sender_key: SignalConstPointerPublicKey) ?*SignalFfiError {
    const msg = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    const pk = sender_key.raw orelse return err_mod.alloc(.null_parameter, "sender_key is null");
    const data = msg.serialized;
    if (data.len < 1 + skm.SIGNATURE_LENGTH) {
        out.* = false;
        return null;
    }
    const sig_start = data.len - skm.SIGNATURE_LENGTH;
    const sig: [64]u8 = data[sig_start..][0..64].*;
    out.* = pk.inner.verifySignature(data[0..sig_start], sig) catch false;
    return null;
}

// ── SignalSenderKeyDistributionMessage ────────────────────────────────────────

pub const SignalSenderKeyDistributionMessage = struct {
    inner: skdm.SenderKeyDistributionMessage,

    pub fn deinit(self: *SignalSenderKeyDistributionMessage) void {
        self.inner.deinit();
    }
};

pub const SignalMutPointerSenderKeyDistributionMessage = extern struct { raw: ?*SignalSenderKeyDistributionMessage };
pub const SignalConstPointerSenderKeyDistributionMessage = extern struct { raw: ?*const SignalSenderKeyDistributionMessage };

pub export fn signal_sender_key_distribution_message_deserialize(out: *SignalMutPointerSenderKeyDistributionMessage, data: SignalBorrowedBuffer) ?*SignalFfiError {
    const inner = skdm.SenderKeyDistributionMessage.deserialize(gpa, data.slice()) catch |e| return err_mod.fromZigError(e);
    const msg = gpa.create(SignalSenderKeyDistributionMessage) catch {
        var m = inner;
        m.deinit();
        return err_mod.alloc(.internal_error, "OOM");
    };
    msg.* = .{ .inner = inner };
    out.raw = msg;
    return null;
}

pub export fn signal_sender_key_distribution_message_new(out: *SignalMutPointerSenderKeyDistributionMessage, distribution_id: SignalBorrowedBuffer, chain_id: u32, iteration: u32, chain_key: SignalBorrowedBuffer, signature_key: SignalConstPointerPublicKey) ?*SignalFfiError {
    if (distribution_id.length != 16) return err_mod.alloc(.invalid_argument, "distribution_id must be 16 bytes");
    if (chain_key.length != 32) return err_mod.alloc(.invalid_argument, "chain_key must be 32 bytes");
    const pk_ptr = signature_key.raw orelse return err_mod.alloc(.null_parameter, "signature_key is null");
    var uuid: [16]u8 = undefined;
    @memcpy(&uuid, distribution_id.slice()[0..16]);
    const ck: [32]u8 = chain_key.slice()[0..32].*;

    const inner = skdm.SenderKeyDistributionMessage.new(gpa, uuid, chain_id, iteration, ck, pk_ptr.inner);
    const msg = gpa.create(SignalSenderKeyDistributionMessage) catch return err_mod.alloc(.internal_error, "OOM");
    msg.* = .{ .inner = inner };
    out.raw = msg;
    return null;
}

pub export fn signal_sender_key_distribution_message_clone(new_obj: *SignalMutPointerSenderKeyDistributionMessage, obj: SignalConstPointerSenderKeyDistributionMessage) ?*SignalFfiError {
    const src = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    const copy = gpa.create(SignalSenderKeyDistributionMessage) catch return err_mod.alloc(.internal_error, "OOM");
    copy.* = .{ .inner = src.inner }; // copy by value (SenderKeyDistributionMessage is value-semantic)
    new_obj.raw = copy;
    return null;
}

pub export fn signal_sender_key_distribution_message_destroy(p: SignalMutPointerSenderKeyDistributionMessage) ?*SignalFfiError {
    if (p.raw) |msg| {
        msg.deinit();
        gpa.destroy(msg);
    }
    return null;
}

pub export fn signal_sender_key_distribution_message_serialize(out: *SignalOwnedBuffer, obj: SignalConstPointerSenderKeyDistributionMessage) ?*SignalFfiError {
    const msg = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    const bytes = msg.inner.serialize() catch |e| return err_mod.fromZigError(e);
    out.* = .{ .base = bytes.ptr, .length = bytes.len };
    return null;
}

pub export fn signal_sender_key_distribution_message_get_distribution_id(out: *SignalOwnedBuffer, obj: SignalConstPointerSenderKeyDistributionMessage) ?*SignalFfiError {
    const msg = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    out.* = SignalOwnedBuffer.dupe(&msg.inner.distribution_uuid) catch return err_mod.alloc(.internal_error, "OOM");
    return null;
}

pub export fn signal_sender_key_distribution_message_get_chain_id(out: *u32, obj: SignalConstPointerSenderKeyDistributionMessage) ?*SignalFfiError {
    const msg = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    out.* = msg.inner.chain_id;
    return null;
}

pub export fn signal_sender_key_distribution_message_get_iteration(out: *u32, obj: SignalConstPointerSenderKeyDistributionMessage) ?*SignalFfiError {
    const msg = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    out.* = msg.inner.iteration;
    return null;
}

pub export fn signal_sender_key_distribution_message_get_chain_key(out: *SignalOwnedBuffer, obj: SignalConstPointerSenderKeyDistributionMessage) ?*SignalFfiError {
    const msg = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    out.* = SignalOwnedBuffer.dupe(&msg.inner.chain_key) catch return err_mod.alloc(.internal_error, "OOM");
    return null;
}

pub export fn signal_sender_key_distribution_message_get_signature_key(out: *SignalMutPointerPublicKey, obj: SignalConstPointerSenderKeyDistributionMessage) ?*SignalFfiError {
    const msg = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    const pk = gpa.create(SignalPublicKey) catch return err_mod.alloc(.internal_error, "OOM");
    pk.* = .{ .inner = msg.inner.signing_key };
    out.raw = pk;
    return null;
}

// ── CiphertextMessage ─────────────────────────────────────────────────────────
// A type-tagged wrapper around an opaque serialized message.

pub const CiphertextMessageType = enum(u8) {
    whisper = 2,
    prekey = 3,
    sender_key = 7,
    plaintext_content = 8,
};

pub const SignalCiphertextMessage = struct {
    msg_type: CiphertextMessageType,
    serialized: []u8,

    pub fn deinit(self: *SignalCiphertextMessage) void {
        gpa.free(self.serialized);
    }
};

pub const SignalMutPointerCiphertextMessage = extern struct { raw: ?*SignalCiphertextMessage };
pub const SignalConstPointerCiphertextMessage = extern struct { raw: ?*const SignalCiphertextMessage };

pub export fn signal_ciphertext_message_destroy(p: SignalMutPointerCiphertextMessage) ?*SignalFfiError {
    if (p.raw) |msg| {
        msg.deinit();
        gpa.destroy(msg);
    }
    return null;
}

pub export fn signal_ciphertext_message_serialize(out: *SignalOwnedBuffer, obj: SignalConstPointerCiphertextMessage) ?*SignalFfiError {
    const msg = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    out.* = SignalOwnedBuffer.dupe(msg.serialized) catch return err_mod.alloc(.internal_error, "OOM");
    return null;
}

pub export fn signal_ciphertext_message_type(out: *u8, obj: SignalConstPointerCiphertextMessage) ?*SignalFfiError {
    const msg = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    out.* = @intFromEnum(msg.msg_type);
    return null;
}

// ── PlaintextContent ──────────────────────────────────────────────────────────

pub const SignalPlaintextContent = struct {
    inner: plaintext_mod.PlaintextContent,

    pub fn deinit(self: *SignalPlaintextContent) void {
        self.inner.deinit();
    }
};

pub const SignalMutPointerPlaintextContent = extern struct { raw: ?*SignalPlaintextContent };
pub const SignalConstPointerPlaintextContent = extern struct { raw: ?*const SignalPlaintextContent };

pub export fn signal_plaintext_content_deserialize(out: *SignalMutPointerPlaintextContent, data: SignalBorrowedBuffer) ?*SignalFfiError {
    const inner = plaintext_mod.PlaintextContent.deserialize(gpa, data.slice()) catch |e| return err_mod.fromZigError(e);
    const msg = gpa.create(SignalPlaintextContent) catch {
        var m = inner;
        m.deinit();
        return err_mod.alloc(.internal_error, "OOM");
    };
    msg.* = .{ .inner = inner };
    out.raw = msg;
    return null;
}

pub export fn signal_plaintext_content_clone(new_obj: *SignalMutPointerPlaintextContent, obj: SignalConstPointerPlaintextContent) ?*SignalFfiError {
    const src = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    const inner = plaintext_mod.PlaintextContent.new(gpa, src.inner.body) catch |e| return err_mod.fromZigError(e);
    const copy = gpa.create(SignalPlaintextContent) catch {
        var m = inner;
        m.deinit();
        return err_mod.alloc(.internal_error, "OOM");
    };
    copy.* = .{ .inner = inner };
    new_obj.raw = copy;
    return null;
}

pub export fn signal_plaintext_content_destroy(p: SignalMutPointerPlaintextContent) ?*SignalFfiError {
    if (p.raw) |msg| {
        msg.deinit();
        gpa.destroy(msg);
    }
    return null;
}

pub export fn signal_plaintext_content_serialize(out: *SignalOwnedBuffer, obj: SignalConstPointerPlaintextContent) ?*SignalFfiError {
    const msg = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    const bytes = msg.inner.serialize() catch |e| return err_mod.fromZigError(e);
    out.* = .{ .base = bytes.ptr, .length = bytes.len };
    return null;
}

pub export fn signal_plaintext_content_get_body(out: *SignalOwnedBuffer, obj: SignalConstPointerPlaintextContent) ?*SignalFfiError {
    const msg = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    out.* = SignalOwnedBuffer.dupe(msg.inner.body) catch return err_mod.alloc(.internal_error, "OOM");
    return null;
}

// ── DecryptionErrorMessage ────────────────────────────────────────────────────

pub const SignalDecryptionErrorMessage = struct {
    inner: dec_err_mod.DecryptionErrorMessage,
    serialized: []u8, // owned

    pub fn deinit(self: *SignalDecryptionErrorMessage) void {
        gpa.free(self.serialized);
    }
};

pub const SignalMutPointerDecryptionErrorMessage = extern struct { raw: ?*SignalDecryptionErrorMessage };
pub const SignalConstPointerDecryptionErrorMessage = extern struct { raw: ?*const SignalDecryptionErrorMessage };

pub export fn signal_decryption_error_message_deserialize(out: *SignalMutPointerDecryptionErrorMessage, data: SignalBorrowedBuffer) ?*SignalFfiError {
    const inner = dec_err_mod.DecryptionErrorMessage.deserialize(data.slice()) catch |e| return err_mod.fromZigError(e);
    const serialized = gpa.dupe(u8, data.slice()) catch return err_mod.alloc(.internal_error, "OOM");
    const msg = gpa.create(SignalDecryptionErrorMessage) catch {
        gpa.free(serialized);
        return err_mod.alloc(.internal_error, "OOM");
    };
    msg.* = .{ .inner = inner, .serialized = serialized };
    out.raw = msg;
    return null;
}

pub export fn signal_decryption_error_message_for_original_message(out: *SignalMutPointerDecryptionErrorMessage, original_bytes: SignalBorrowedBuffer, original_type: u8, timestamp: u64, original_sender_device_id: u32) ?*SignalFfiError {
    _ = original_bytes;
    _ = original_type;
    const inner = dec_err_mod.DecryptionErrorMessage.new(
        std.mem.zeroes(curve.PublicKey), // ratchet key not available without session context
        timestamp,
        original_sender_device_id,
    );
    const serialized = inner.serialize(gpa) catch |e| return err_mod.fromZigError(e);
    const msg = gpa.create(SignalDecryptionErrorMessage) catch {
        gpa.free(serialized);
        return err_mod.alloc(.internal_error, "OOM");
    };
    msg.* = .{ .inner = inner, .serialized = serialized };
    out.raw = msg;
    return null;
}

pub export fn signal_decryption_error_message_clone(new_obj: *SignalMutPointerDecryptionErrorMessage, obj: SignalConstPointerDecryptionErrorMessage) ?*SignalFfiError {
    const src = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    const serialized = gpa.dupe(u8, src.serialized) catch return err_mod.alloc(.internal_error, "OOM");
    const copy = gpa.create(SignalDecryptionErrorMessage) catch {
        gpa.free(serialized);
        return err_mod.alloc(.internal_error, "OOM");
    };
    copy.* = .{ .inner = src.inner, .serialized = serialized };
    new_obj.raw = copy;
    return null;
}

pub export fn signal_decryption_error_message_destroy(p: SignalMutPointerDecryptionErrorMessage) ?*SignalFfiError {
    if (p.raw) |msg| {
        msg.deinit();
        gpa.destroy(msg);
    }
    return null;
}

pub export fn signal_decryption_error_message_serialize(out: *SignalOwnedBuffer, obj: SignalConstPointerDecryptionErrorMessage) ?*SignalFfiError {
    const msg = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    out.* = SignalOwnedBuffer.dupe(msg.serialized) catch return err_mod.alloc(.internal_error, "OOM");
    return null;
}

pub export fn signal_decryption_error_message_get_timestamp(out: *u64, obj: SignalConstPointerDecryptionErrorMessage) ?*SignalFfiError {
    const msg = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    out.* = msg.inner.timestamp;
    return null;
}

pub export fn signal_decryption_error_message_get_device_id(out: *u32, obj: SignalConstPointerDecryptionErrorMessage) ?*SignalFfiError {
    const msg = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    out.* = msg.inner.device_id;
    return null;
}

pub export fn signal_decryption_error_message_get_ratchet_key(out: *SignalMutPointerPublicKey, obj: SignalConstPointerDecryptionErrorMessage) ?*SignalFfiError {
    const msg = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    const pk = gpa.create(SignalPublicKey) catch return err_mod.alloc(.internal_error, "OOM");
    pk.* = .{ .inner = msg.inner.ratchet_key };
    out.raw = pk;
    return null;
}
