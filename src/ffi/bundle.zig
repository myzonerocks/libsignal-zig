//! SignalPreKeyBundle opaque type.

const std = @import("std");
const err_mod = @import("error.zig");
const keys = @import("keys.zig");
const curve = @import("../curve.zig");
const identity = @import("../identity.zig");
const bundle_mod = @import("../state/bundle.zig");
const gpa = std.heap.c_allocator;

const SignalFfiError = err_mod.SignalFfiError;
const SignalOwnedBuffer = keys.SignalOwnedBuffer;
const SignalBorrowedBuffer = keys.SignalBorrowedBuffer;
const SignalMutPointerPublicKey = keys.SignalMutPointerPublicKey;
const SignalConstPointerPublicKey = keys.SignalConstPointerPublicKey;
const SignalPublicKey = keys.SignalPublicKey;
const SignalMutPointerKyberPublicKey = keys.SignalMutPointerKyberPublicKey;
const SignalConstPointerKyberPublicKey = keys.SignalConstPointerKyberPublicKey;
const SignalKyberPublicKey = keys.SignalKyberPublicKey;

pub const SignalPreKeyBundle = struct { inner: bundle_mod.PreKeyBundle };
pub const SignalMutPointerPreKeyBundle = extern struct { raw: ?*SignalPreKeyBundle };
pub const SignalConstPointerPreKeyBundle = extern struct { raw: ?*const SignalPreKeyBundle };

pub export fn signal_pre_key_bundle_new(
    out: *SignalMutPointerPreKeyBundle,
    registration_id: u32,
    device_id: u32,
    pre_key_id: u32,
    pre_key_id_valid: bool,
    pre_key_public: SignalConstPointerPublicKey,
    signed_pre_key_id: u32,
    signed_pre_key_public: SignalConstPointerPublicKey,
    signed_pre_key_signature: SignalBorrowedBuffer,
    identity_key: SignalConstPointerPublicKey,
    kyber_pre_key_id: u32,
    kyber_pre_key_id_valid: bool,
    kyber_pre_key_public: SignalConstPointerKyberPublicKey,
    kyber_pre_key_signature: SignalBorrowedBuffer,
) ?*SignalFfiError {
    const spk = signed_pre_key_public.raw orelse return err_mod.alloc(.null_parameter, "signed_pre_key_public is null");
    const ik = identity_key.raw orelse return err_mod.alloc(.null_parameter, "identity_key is null");
    if (signed_pre_key_signature.length != 64) return err_mod.alloc(.invalid_signature, "signed_pre_key_signature must be 64 bytes");

    const pre_key_pub: ?curve.PublicKey = if (pre_key_id_valid)
        (if (pre_key_public.raw) |p| p.inner else return err_mod.alloc(.null_parameter, "pre_key_public is null when pre_key_id_valid"))
    else
        null;

    const spk_sig: [64]u8 = signed_pre_key_signature.slice()[0..64].*;

    const kyber_pub: ?[curve.KyberKeyPair.KYBER_PUBLIC_KEY_LENGTH]u8 = if (kyber_pre_key_id_valid)
        (if (kyber_pre_key_public.raw) |kp| kp.bytes else return err_mod.alloc(.null_parameter, "kyber_pre_key_public is null when valid"))
    else
        null;

    const kyber_sig: ?[64]u8 = if (kyber_pre_key_id_valid) blk: {
        if (kyber_pre_key_signature.length != 64) return err_mod.alloc(.invalid_signature, "kyber_pre_key_signature must be 64 bytes");
        break :blk kyber_pre_key_signature.slice()[0..64].*;
    } else null;

    const bundle = gpa.create(SignalPreKeyBundle) catch return err_mod.alloc(.internal_error, "OOM");
    bundle.* = .{ .inner = bundle_mod.PreKeyBundle.new(
        registration_id,
        device_id,
        if (pre_key_id_valid) pre_key_id else null,
        pre_key_pub,
        signed_pre_key_id,
        spk.inner,
        spk_sig,
        identity.IdentityKey.fromPublicKey(ik.inner),
        if (kyber_pre_key_id_valid) kyber_pre_key_id else null,
        kyber_pub,
        kyber_sig,
    ) };
    out.raw = bundle;
    return null;
}

pub export fn signal_pre_key_bundle_clone(new_obj: *SignalMutPointerPreKeyBundle, obj: SignalConstPointerPreKeyBundle) ?*SignalFfiError {
    const src = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    const copy = gpa.create(SignalPreKeyBundle) catch return err_mod.alloc(.internal_error, "OOM");
    copy.* = src.*;
    new_obj.raw = copy;
    return null;
}

pub export fn signal_pre_key_bundle_destroy(p: SignalMutPointerPreKeyBundle) ?*SignalFfiError {
    if (p.raw) |b| gpa.destroy(b);
    return null;
}

pub export fn signal_pre_key_bundle_get_registration_id(out: *u32, obj: SignalConstPointerPreKeyBundle) ?*SignalFfiError {
    const b = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    out.* = b.inner.registration_id;
    return null;
}

pub export fn signal_pre_key_bundle_get_device_id(out: *u32, obj: SignalConstPointerPreKeyBundle) ?*SignalFfiError {
    const b = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    out.* = b.inner.device_id;
    return null;
}

pub export fn signal_pre_key_bundle_get_pre_key_id(out: *u32, out_valid: *bool, obj: SignalConstPointerPreKeyBundle) ?*SignalFfiError {
    const b = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    if (b.inner.pre_key_id) |id| {
        out.* = id;
        out_valid.* = true;
    } else {
        out.* = 0;
        out_valid.* = false;
    }
    return null;
}

pub export fn signal_pre_key_bundle_get_pre_key_public(out: *SignalMutPointerPublicKey, obj: SignalConstPointerPreKeyBundle) ?*SignalFfiError {
    const b = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    if (b.inner.pre_key_public) |pk_val| {
        const pk = gpa.create(SignalPublicKey) catch return err_mod.alloc(.internal_error, "OOM");
        pk.* = .{ .inner = pk_val };
        out.raw = pk;
    } else {
        out.raw = null;
    }
    return null;
}

pub export fn signal_pre_key_bundle_get_signed_pre_key_id(out: *u32, obj: SignalConstPointerPreKeyBundle) ?*SignalFfiError {
    const b = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    out.* = b.inner.signed_pre_key_id;
    return null;
}

pub export fn signal_pre_key_bundle_get_signed_pre_key_public(out: *SignalMutPointerPublicKey, obj: SignalConstPointerPreKeyBundle) ?*SignalFfiError {
    const b = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    const pk = gpa.create(SignalPublicKey) catch return err_mod.alloc(.internal_error, "OOM");
    pk.* = .{ .inner = b.inner.signed_pre_key_public };
    out.raw = pk;
    return null;
}

pub export fn signal_pre_key_bundle_get_signed_pre_key_signature(out: *SignalOwnedBuffer, obj: SignalConstPointerPreKeyBundle) ?*SignalFfiError {
    const b = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    out.* = SignalOwnedBuffer.dupe(&b.inner.signed_pre_key_signature) catch return err_mod.alloc(.internal_error, "OOM");
    return null;
}

pub export fn signal_pre_key_bundle_get_identity_key(out: *SignalMutPointerPublicKey, obj: SignalConstPointerPreKeyBundle) ?*SignalFfiError {
    const b = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    const pk = gpa.create(SignalPublicKey) catch return err_mod.alloc(.internal_error, "OOM");
    pk.* = .{ .inner = b.inner.identity_key.public_key };
    out.raw = pk;
    return null;
}

pub export fn signal_pre_key_bundle_get_kyber_pre_key_id(out: *u32, out_valid: *bool, obj: SignalConstPointerPreKeyBundle) ?*SignalFfiError {
    const b = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    if (b.inner.kyber_pre_key_id) |id| {
        out.* = id;
        out_valid.* = true;
    } else {
        out.* = 0;
        out_valid.* = false;
    }
    return null;
}

pub export fn signal_pre_key_bundle_get_kyber_pre_key_public(out: *SignalMutPointerKyberPublicKey, obj: SignalConstPointerPreKeyBundle) ?*SignalFfiError {
    const b = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    if (b.inner.kyber_pre_key_public) |kpk_bytes| {
        const pk = gpa.create(SignalKyberPublicKey) catch return err_mod.alloc(.internal_error, "OOM");
        pk.* = .{ .bytes = kpk_bytes };
        out.raw = pk;
    } else {
        out.raw = null;
    }
    return null;
}

pub export fn signal_pre_key_bundle_get_kyber_pre_key_signature(out: *SignalOwnedBuffer, obj: SignalConstPointerPreKeyBundle) ?*SignalFfiError {
    const b = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    if (b.inner.kyber_pre_key_signature) |sig| {
        out.* = SignalOwnedBuffer.dupe(&sig) catch return err_mod.alloc(.internal_error, "OOM");
    } else {
        out.* = SignalOwnedBuffer.empty();
    }
    return null;
}
