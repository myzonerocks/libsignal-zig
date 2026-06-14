//! Opaque EC and Kyber key objects.
//!
//! All types are heap-allocated and returned via *Mut pointer structs.
//! Callers own the pointer and must call _destroy when done.

const std = @import("std");
const curve = @import("../curve.zig");
const xeddsa_mod = @import("../xeddsa.zig");
const err_mod = @import("error.zig");
const rnd = @import("../random.zig");
const state = @import("../state/kyber_pre_key_record.zig");
const gpa = std.heap.c_allocator;

const SignalFfiError = err_mod.SignalFfiError;

// ── Opaque heap types ──────────────────────────────────────────────────────────

pub const SignalPrivateKey = struct { inner: curve.PrivateKey };
pub const SignalPublicKey = struct { inner: curve.PublicKey };
pub const SignalKeyPair = struct { inner: curve.KeyPair };

const MlKem1024 = std.crypto.kem.ml_kem.MLKem1024;

pub const SignalKyberKeyPair = struct { inner: curve.KyberKeyPair };
pub const SignalKyberPublicKey = struct { bytes: [curve.KyberKeyPair.KYBER_PUBLIC_KEY_LENGTH]u8 };
pub const SignalKyberSecretKey = struct { bytes: [curve.KyberKeyPair.KYBER_SECRET_KEY_LENGTH]u8 };

// ── Pointer wrapper types ───────────────────────────────

pub const SignalMutPointerPrivateKey = extern struct { raw: ?*SignalPrivateKey };
pub const SignalConstPointerPrivateKey = extern struct { raw: ?*const SignalPrivateKey };
pub const SignalMutPointerPublicKey = extern struct { raw: ?*SignalPublicKey };
pub const SignalConstPointerPublicKey = extern struct { raw: ?*const SignalPublicKey };
pub const SignalMutPointerKyberKeyPair = extern struct { raw: ?*SignalKyberKeyPair };
pub const SignalConstPointerKyberKeyPair = extern struct { raw: ?*const SignalKyberKeyPair };
pub const SignalMutPointerKyberPublicKey = extern struct { raw: ?*SignalKyberPublicKey };
pub const SignalConstPointerKyberPublicKey = extern struct { raw: ?*const SignalKyberPublicKey };
pub const SignalMutPointerKyberSecretKey = extern struct { raw: ?*SignalKyberSecretKey };
pub const SignalConstPointerKyberSecretKey = extern struct { raw: ?*const SignalKyberSecretKey };

// ── SignalPrivateKey functions ─────────────────────────────────────────────────

pub export fn signal_privatekey_generate(out: *SignalMutPointerPrivateKey) ?*SignalFfiError {
    const key = gpa.create(SignalPrivateKey) catch return err_mod.alloc(.internal_error, "OOM");
    errdefer gpa.destroy(key);
    const kp = curve.KeyPair.generate() catch |e| {
        gpa.destroy(key);
        return err_mod.fromZigError(e);
    };
    key.* = .{ .inner = kp.private_key };
    out.raw = key;
    return null;
}

pub export fn signal_privatekey_deserialize(out: *SignalMutPointerPrivateKey, data: SignalBorrowedBuffer) ?*SignalFfiError {
    const key = gpa.create(SignalPrivateKey) catch return err_mod.alloc(.internal_error, "OOM");
    errdefer gpa.destroy(key);
    const sk = curve.PrivateKey.deserialize(data.slice()) catch |e| {
        gpa.destroy(key);
        return err_mod.fromZigError(e);
    };
    key.* = .{ .inner = sk };
    out.raw = key;
    return null;
}

pub export fn signal_privatekey_serialize(out: *SignalOwnedBuffer, obj: SignalConstPointerPrivateKey) ?*SignalFfiError {
    const key = obj.raw orelse return err_mod.alloc(.null_parameter, "key is null");
    const bytes = key.inner.serialize();
    out.* = SignalOwnedBuffer.dupe(&bytes) catch return err_mod.alloc(.internal_error, "OOM");
    return null;
}

pub export fn signal_privatekey_clone(new_obj: *SignalMutPointerPrivateKey, obj: SignalConstPointerPrivateKey) ?*SignalFfiError {
    const src = obj.raw orelse return err_mod.alloc(.null_parameter, "key is null");
    const copy = gpa.create(SignalPrivateKey) catch return err_mod.alloc(.internal_error, "OOM");
    copy.* = src.*;
    new_obj.raw = copy;
    return null;
}

pub export fn signal_privatekey_destroy(p: SignalMutPointerPrivateKey) ?*SignalFfiError {
    if (p.raw) |key| gpa.destroy(key);
    return null;
}

pub export fn signal_privatekey_agree(out: *SignalOwnedBuffer, private_key: SignalConstPointerPrivateKey, public_key: SignalConstPointerPublicKey) ?*SignalFfiError {
    const sk = private_key.raw orelse return err_mod.alloc(.null_parameter, "private_key is null");
    const pk = public_key.raw orelse return err_mod.alloc(.null_parameter, "public_key is null");
    const shared = sk.inner.calculateAgreement(pk.inner) catch |e| return err_mod.fromZigError(e);
    out.* = SignalOwnedBuffer.dupe(&shared) catch return err_mod.alloc(.internal_error, "OOM");
    return null;
}

pub export fn signal_privatekey_sign(out: *SignalOwnedBuffer, key: SignalConstPointerPrivateKey, message: SignalBorrowedBuffer) ?*SignalFfiError {
    const sk = key.raw orelse return err_mod.alloc(.null_parameter, "key is null");
    const sig = sk.inner.calculateSignature(message.slice()) catch |e| return err_mod.fromZigError(e);
    out.* = SignalOwnedBuffer.dupe(&sig) catch return err_mod.alloc(.internal_error, "OOM");
    return null;
}

pub export fn signal_privatekey_get_public_key(out: *SignalMutPointerPublicKey, k: SignalConstPointerPrivateKey) ?*SignalFfiError {
    const sk = k.raw orelse return err_mod.alloc(.null_parameter, "key is null");
    const pub_key = gpa.create(SignalPublicKey) catch return err_mod.alloc(.internal_error, "OOM");
    errdefer gpa.destroy(pub_key);
    pub_key.* = .{ .inner = sk.inner.publicKey() catch |e| {
        gpa.destroy(pub_key);
        return err_mod.fromZigError(e);
    } };
    out.raw = pub_key;
    return null;
}

pub export fn signal_privatekey_hpke_open(out: *SignalOwnedBuffer, sk: SignalConstPointerPrivateKey, ciphertext: SignalBorrowedBuffer, info: SignalBorrowedBuffer, associated_data: SignalBorrowedBuffer) ?*SignalFfiError {
    const key = sk.raw orelse return err_mod.alloc(.null_parameter, "sk is null");
    _ = key;
    _ = ciphertext;
    _ = info;
    _ = associated_data;
    // HPKE-X25519-HKDF-SHA256-ChaCha20Poly1305 decryption
    // TODO: implement HPKE decryption using Zig crypto
    _ = out;
    return err_mod.alloc(.internal_error, "HPKE open not yet implemented");
}

// ── SignalPublicKey functions ──────────────────────────────────────────────────

pub export fn signal_publickey_deserialize(out: *SignalMutPointerPublicKey, data: SignalBorrowedBuffer) ?*SignalFfiError {
    const key = gpa.create(SignalPublicKey) catch return err_mod.alloc(.internal_error, "OOM");
    errdefer gpa.destroy(key);
    const pk = curve.PublicKey.deserialize(data.slice()) catch |e| {
        gpa.destroy(key);
        return err_mod.fromZigError(e);
    };
    key.* = .{ .inner = pk };
    out.raw = key;
    return null;
}

pub export fn signal_publickey_serialize(out: *SignalOwnedBuffer, obj: SignalConstPointerPublicKey) ?*SignalFfiError {
    const key = obj.raw orelse return err_mod.alloc(.null_parameter, "key is null");
    const bytes = key.inner.serialize();
    out.* = SignalOwnedBuffer.dupe(&bytes) catch return err_mod.alloc(.internal_error, "OOM");
    return null;
}

pub export fn signal_publickey_get_public_key_bytes(out: *SignalOwnedBuffer, obj: SignalConstPointerPublicKey) ?*SignalFfiError {
    const key = obj.raw orelse return err_mod.alloc(.null_parameter, "key is null");
    // Raw 32-byte key (without 0x05 prefix)
    out.* = SignalOwnedBuffer.dupe(&key.inner.key_bytes) catch return err_mod.alloc(.internal_error, "OOM");
    return null;
}

pub export fn signal_publickey_clone(new_obj: *SignalMutPointerPublicKey, obj: SignalConstPointerPublicKey) ?*SignalFfiError {
    const src = obj.raw orelse return err_mod.alloc(.null_parameter, "key is null");
    const copy = gpa.create(SignalPublicKey) catch return err_mod.alloc(.internal_error, "OOM");
    copy.* = src.*;
    new_obj.raw = copy;
    return null;
}

pub export fn signal_publickey_destroy(p: SignalMutPointerPublicKey) ?*SignalFfiError {
    if (p.raw) |key| gpa.destroy(key);
    return null;
}

pub export fn signal_publickey_equals(out: *bool, lhs: SignalConstPointerPublicKey, rhs: SignalConstPointerPublicKey) ?*SignalFfiError {
    const l = lhs.raw orelse return err_mod.alloc(.null_parameter, "lhs is null");
    const r = rhs.raw orelse return err_mod.alloc(.null_parameter, "rhs is null");
    out.* = l.inner.eql(r.inner);
    return null;
}

pub export fn signal_publickey_verify(out: *bool, key: SignalConstPointerPublicKey, message: SignalBorrowedBuffer, signature: SignalBorrowedBuffer) ?*SignalFfiError {
    const pk = key.raw orelse return err_mod.alloc(.null_parameter, "key is null");
    if (signature.length != 64) return err_mod.alloc(.invalid_signature, "signature must be 64 bytes");
    const sig: [64]u8 = signature.slice()[0..64].*;
    out.* = pk.inner.verifySignature(message.slice(), sig) catch |e| return err_mod.fromZigError(e);
    return null;
}

pub export fn signal_publickey_hpke_seal(out: *SignalOwnedBuffer, pk: SignalConstPointerPublicKey, plaintext: SignalBorrowedBuffer, info: SignalBorrowedBuffer, associated_data: SignalBorrowedBuffer) ?*SignalFfiError {
    _ = pk;
    _ = plaintext;
    _ = info;
    _ = associated_data;
    _ = out;
    return err_mod.alloc(.internal_error, "HPKE seal not yet implemented");
}

// ── Identity key pair operations ───────────────────────────────────────────────

pub const SignalPairOfMutPointerPrivateKeyMutPointerPublicKey = extern struct {
    first: SignalMutPointerPrivateKey,
    second: SignalMutPointerPublicKey,
};

pub const SignalPairOfMutPointerPublicKeyMutPointerPrivateKey = extern struct {
    first: SignalMutPointerPublicKey,
    second: SignalMutPointerPrivateKey,
};

pub export fn signal_identitykeypair_deserialize(out: *SignalPairOfMutPointerPublicKeyMutPointerPrivateKey, input: SignalBorrowedBuffer) ?*SignalFfiError {
    // Identity key pair is serialized as: public_key (33 bytes) + private_key (32 bytes)
    const bytes = input.slice();
    if (bytes.len < 65) return err_mod.alloc(.invalid_key, "Identity key pair too short");
    const pub_key = gpa.create(SignalPublicKey) catch return err_mod.alloc(.internal_error, "OOM");
    errdefer gpa.destroy(pub_key);
    const priv_key = gpa.create(SignalPrivateKey) catch {
        gpa.destroy(pub_key);
        return err_mod.alloc(.internal_error, "OOM");
    };
    errdefer gpa.destroy(priv_key);
    pub_key.* = .{ .inner = curve.PublicKey.deserialize(bytes[0..33]) catch |e| {
        gpa.destroy(priv_key);
        gpa.destroy(pub_key);
        return err_mod.fromZigError(e);
    } };
    priv_key.* = .{ .inner = curve.PrivateKey.deserialize(bytes[33..65]) catch |e| {
        gpa.destroy(priv_key);
        gpa.destroy(pub_key);
        return err_mod.fromZigError(e);
    } };
    out.first.raw = pub_key;
    out.second.raw = priv_key;
    return null;
}

pub export fn signal_identitykeypair_serialize(out: *SignalOwnedBuffer, public_key: SignalConstPointerPublicKey, private_key: SignalConstPointerPrivateKey) ?*SignalFfiError {
    const pk = public_key.raw orelse return err_mod.alloc(.null_parameter, "public_key is null");
    const sk = private_key.raw orelse return err_mod.alloc(.null_parameter, "private_key is null");
    var buf: [65]u8 = undefined;
    const pub_bytes = pk.inner.serialize();
    @memcpy(buf[0..33], &pub_bytes);
    @memcpy(buf[33..65], &sk.inner.key_bytes);
    out.* = SignalOwnedBuffer.dupe(&buf) catch return err_mod.alloc(.internal_error, "OOM");
    return null;
}

pub export fn signal_identitykeypair_sign_alternate_identity(out: *SignalOwnedBuffer, public_key: SignalConstPointerPublicKey, private_key: SignalConstPointerPrivateKey, other_identity: SignalConstPointerPublicKey) ?*SignalFfiError {
    const pk = public_key.raw orelse return err_mod.alloc(.null_parameter, "public_key is null");
    const sk = private_key.raw orelse return err_mod.alloc(.null_parameter, "private_key is null");
    const other = other_identity.raw orelse return err_mod.alloc(.null_parameter, "other_identity is null");
    _ = pk;
    // Sign: sign(private_key, "Signal_PNI_Signature" || other_identity_pub_bytes)
    const label = "Signal_PNI_Signature";
    const other_bytes = other.inner.serialize();
    var msg_buf: [label.len + 33]u8 = undefined;
    @memcpy(msg_buf[0..label.len], label);
    @memcpy(msg_buf[label.len..], &other_bytes);
    const sig = sk.inner.calculateSignature(&msg_buf) catch |e| return err_mod.fromZigError(e);
    out.* = SignalOwnedBuffer.dupe(&sig) catch return err_mod.alloc(.internal_error, "OOM");
    return null;
}

pub export fn signal_identitykey_verify_alternate_identity(out: *bool, public_key: SignalConstPointerPublicKey, other_identity: SignalConstPointerPublicKey, signature: SignalBorrowedBuffer) ?*SignalFfiError {
    const pk = public_key.raw orelse return err_mod.alloc(.null_parameter, "public_key is null");
    const other = other_identity.raw orelse return err_mod.alloc(.null_parameter, "other_identity is null");
    if (signature.length != 64) return err_mod.alloc(.invalid_signature, "signature must be 64 bytes");
    const label = "Signal_PNI_Signature";
    const other_bytes = other.inner.serialize();
    var msg_buf: [label.len + 33]u8 = undefined;
    @memcpy(msg_buf[0..label.len], label);
    @memcpy(msg_buf[label.len..], &other_bytes);
    const sig: [64]u8 = signature.slice()[0..64].*;
    out.* = pk.inner.verifySignature(&msg_buf, sig) catch |e| return err_mod.fromZigError(e);
    return null;
}

// ── SignalKyberKeyPair functions ───────────────────────────────────────────────

pub export fn signal_kyber_key_pair_generate(out: *SignalMutPointerKyberKeyPair) ?*SignalFfiError {
    const kp = gpa.create(SignalKyberKeyPair) catch return err_mod.alloc(.internal_error, "OOM");
    errdefer gpa.destroy(kp);
    kp.* = .{ .inner = curve.KyberKeyPair.generate() catch |e| {
        gpa.destroy(kp);
        return err_mod.fromZigError(e);
    } };
    out.raw = kp;
    return null;
}

pub export fn signal_kyber_key_pair_clone(new_obj: *SignalMutPointerKyberKeyPair, obj: SignalConstPointerKyberKeyPair) ?*SignalFfiError {
    const src = obj.raw orelse return err_mod.alloc(.null_parameter, "key_pair is null");
    const copy = gpa.create(SignalKyberKeyPair) catch return err_mod.alloc(.internal_error, "OOM");
    copy.* = src.*;
    new_obj.raw = copy;
    return null;
}

pub export fn signal_kyber_key_pair_destroy(p: SignalMutPointerKyberKeyPair) ?*SignalFfiError {
    if (p.raw) |kp| gpa.destroy(kp);
    return null;
}

pub export fn signal_kyber_key_pair_get_public_key(out: *SignalMutPointerKyberPublicKey, key_pair: SignalConstPointerKyberKeyPair) ?*SignalFfiError {
    const kp = key_pair.raw orelse return err_mod.alloc(.null_parameter, "key_pair is null");
    const pk = gpa.create(SignalKyberPublicKey) catch return err_mod.alloc(.internal_error, "OOM");
    pk.* = .{ .bytes = kp.inner.public_key_bytes };
    out.raw = pk;
    return null;
}

pub export fn signal_kyber_key_pair_get_secret_key(out: *SignalMutPointerKyberSecretKey, key_pair: SignalConstPointerKyberKeyPair) ?*SignalFfiError {
    const kp = key_pair.raw orelse return err_mod.alloc(.null_parameter, "key_pair is null");
    const sk = gpa.create(SignalKyberSecretKey) catch return err_mod.alloc(.internal_error, "OOM");
    sk.* = .{ .bytes = kp.inner.secret_key_bytes };
    out.raw = sk;
    return null;
}

// ── SignalKyberPublicKey functions ─────────────────────────────────────────────

pub export fn signal_kyber_public_key_deserialize(out: *SignalMutPointerKyberPublicKey, data: SignalBorrowedBuffer) ?*SignalFfiError {
    const bytes = data.slice();
    if (bytes.len != curve.KyberKeyPair.KYBER_PUBLIC_KEY_LENGTH)
        return err_mod.alloc(.invalid_key, "Kyber public key wrong length");
    const pk = gpa.create(SignalKyberPublicKey) catch return err_mod.alloc(.internal_error, "OOM");
    @memcpy(&pk.bytes, bytes[0..curve.KyberKeyPair.KYBER_PUBLIC_KEY_LENGTH]);
    out.raw = pk;
    return null;
}

pub export fn signal_kyber_public_key_serialize(out: *SignalOwnedBuffer, obj: SignalConstPointerKyberPublicKey) ?*SignalFfiError {
    const pk = obj.raw orelse return err_mod.alloc(.null_parameter, "key is null");
    out.* = SignalOwnedBuffer.dupe(&pk.bytes) catch return err_mod.alloc(.internal_error, "OOM");
    return null;
}

pub export fn signal_kyber_public_key_clone(new_obj: *SignalMutPointerKyberPublicKey, obj: SignalConstPointerKyberPublicKey) ?*SignalFfiError {
    const src = obj.raw orelse return err_mod.alloc(.null_parameter, "key is null");
    const copy = gpa.create(SignalKyberPublicKey) catch return err_mod.alloc(.internal_error, "OOM");
    copy.* = src.*;
    new_obj.raw = copy;
    return null;
}

pub export fn signal_kyber_public_key_destroy(p: SignalMutPointerKyberPublicKey) ?*SignalFfiError {
    if (p.raw) |pk| gpa.destroy(pk);
    return null;
}

pub export fn signal_kyber_public_key_equals(out: *bool, lhs: SignalConstPointerKyberPublicKey, rhs: SignalConstPointerKyberPublicKey) ?*SignalFfiError {
    const l = lhs.raw orelse return err_mod.alloc(.null_parameter, "lhs is null");
    const r = rhs.raw orelse return err_mod.alloc(.null_parameter, "rhs is null");
    out.* = std.mem.eql(u8, &l.bytes, &r.bytes);
    return null;
}

// ── SignalKyberSecretKey functions ─────────────────────────────────────────────

pub export fn signal_kyber_secret_key_deserialize(out: *SignalMutPointerKyberSecretKey, data: SignalBorrowedBuffer) ?*SignalFfiError {
    const bytes = data.slice();
    if (bytes.len != curve.KyberKeyPair.KYBER_SECRET_KEY_LENGTH)
        return err_mod.alloc(.invalid_key, "Kyber secret key wrong length");
    const sk = gpa.create(SignalKyberSecretKey) catch return err_mod.alloc(.internal_error, "OOM");
    @memcpy(&sk.bytes, bytes[0..curve.KyberKeyPair.KYBER_SECRET_KEY_LENGTH]);
    out.raw = sk;
    return null;
}

pub export fn signal_kyber_secret_key_serialize(out: *SignalOwnedBuffer, obj: SignalConstPointerKyberSecretKey) ?*SignalFfiError {
    const sk = obj.raw orelse return err_mod.alloc(.null_parameter, "key is null");
    out.* = SignalOwnedBuffer.dupe(&sk.bytes) catch return err_mod.alloc(.internal_error, "OOM");
    return null;
}

pub export fn signal_kyber_secret_key_clone(new_obj: *SignalMutPointerKyberSecretKey, obj: SignalConstPointerKyberSecretKey) ?*SignalFfiError {
    const src = obj.raw orelse return err_mod.alloc(.null_parameter, "key is null");
    const copy = gpa.create(SignalKyberSecretKey) catch return err_mod.alloc(.internal_error, "OOM");
    copy.* = src.*;
    new_obj.raw = copy;
    return null;
}

pub export fn signal_kyber_secret_key_destroy(p: SignalMutPointerKyberSecretKey) ?*SignalFfiError {
    if (p.raw) |sk| gpa.destroy(sk);
    return null;
}

// ── SignalKyberPreKeyRecord functions ─────────────────────────────────────────

pub const SignalKyberPreKeyRecord = struct { inner: state.KyberPreKeyRecord };
pub const SignalMutPointerKyberPreKeyRecord = extern struct { raw: ?*SignalKyberPreKeyRecord };
pub const SignalConstPointerKyberPreKeyRecord = extern struct { raw: ?*const SignalKyberPreKeyRecord };

pub export fn signal_kyber_pre_key_record_new(out: *SignalMutPointerKyberPreKeyRecord, id: u32, timestamp: u64, key_pair: SignalConstPointerKyberKeyPair, signature: SignalBorrowedBuffer) ?*SignalFfiError {
    const kp = key_pair.raw orelse return err_mod.alloc(.null_parameter, "key_pair is null");
    if (signature.length != 64) return err_mod.alloc(.invalid_signature, "signature must be 64 bytes");
    const sig: [64]u8 = signature.slice()[0..64].*;
    const record = gpa.create(SignalKyberPreKeyRecord) catch return err_mod.alloc(.internal_error, "OOM");
    record.* = .{ .inner = state.KyberPreKeyRecord.new(id, timestamp, kp.inner, sig) };
    out.raw = record;
    return null;
}

pub export fn signal_kyber_pre_key_record_clone(new_obj: *SignalMutPointerKyberPreKeyRecord, obj: SignalConstPointerKyberPreKeyRecord) ?*SignalFfiError {
    const src = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    const copy = gpa.create(SignalKyberPreKeyRecord) catch return err_mod.alloc(.internal_error, "OOM");
    copy.* = src.*;
    new_obj.raw = copy;
    return null;
}

pub export fn signal_kyber_pre_key_record_destroy(p: SignalMutPointerKyberPreKeyRecord) ?*SignalFfiError {
    if (p.raw) |r| gpa.destroy(r);
    return null;
}

pub export fn signal_kyber_pre_key_record_serialize(out: *SignalOwnedBuffer, obj: SignalConstPointerKyberPreKeyRecord) ?*SignalFfiError {
    const r = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    const bytes = r.inner.serialize(gpa) catch |e| return err_mod.fromZigError(e);
    out.* = .{ .base = bytes.ptr, .length = bytes.len };
    return null;
}

pub export fn signal_kyber_pre_key_record_deserialize(out: *SignalMutPointerKyberPreKeyRecord, data: SignalBorrowedBuffer) ?*SignalFfiError {
    const inner = state.KyberPreKeyRecord.deserialize(data.slice()) catch |e| return err_mod.fromZigError(e);
    const record = gpa.create(SignalKyberPreKeyRecord) catch return err_mod.alloc(.internal_error, "OOM");
    record.* = .{ .inner = inner };
    out.raw = record;
    return null;
}

pub export fn signal_kyber_pre_key_record_get_id(out: *u32, obj: SignalConstPointerKyberPreKeyRecord) ?*SignalFfiError {
    const r = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    out.* = r.inner.id;
    return null;
}

pub export fn signal_kyber_pre_key_record_get_timestamp(out: *u64, obj: SignalConstPointerKyberPreKeyRecord) ?*SignalFfiError {
    const r = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    out.* = r.inner.timestamp;
    return null;
}

pub export fn signal_kyber_pre_key_record_get_public_key(out: *SignalMutPointerKyberPublicKey, obj: SignalConstPointerKyberPreKeyRecord) ?*SignalFfiError {
    const r = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    const pk = gpa.create(SignalKyberPublicKey) catch return err_mod.alloc(.internal_error, "OOM");
    pk.* = .{ .bytes = r.inner.key_pair.public_key_bytes };
    out.raw = pk;
    return null;
}

pub export fn signal_kyber_pre_key_record_get_secret_key(out: *SignalMutPointerKyberSecretKey, obj: SignalConstPointerKyberPreKeyRecord) ?*SignalFfiError {
    const r = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    const sk = gpa.create(SignalKyberSecretKey) catch return err_mod.alloc(.internal_error, "OOM");
    sk.* = .{ .bytes = r.inner.key_pair.secret_key_bytes };
    out.raw = sk;
    return null;
}

pub export fn signal_kyber_pre_key_record_get_key_pair(out: *SignalMutPointerKyberKeyPair, obj: SignalConstPointerKyberPreKeyRecord) ?*SignalFfiError {
    const r = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    const kp = gpa.create(SignalKyberKeyPair) catch return err_mod.alloc(.internal_error, "OOM");
    kp.* = .{ .inner = r.inner.key_pair };
    out.raw = kp;
    return null;
}

pub export fn signal_kyber_pre_key_record_get_signature(out: *SignalOwnedBuffer, obj: SignalConstPointerKyberPreKeyRecord) ?*SignalFfiError {
    const r = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    out.* = SignalOwnedBuffer.dupe(&r.inner.signature) catch return err_mod.alloc(.internal_error, "OOM");
    return null;
}

// ── Buffer types (shared across all FFI modules) ───────────────────────────────

pub const SignalOwnedBuffer = extern struct {
    base: ?[*]u8,
    length: usize,

    pub fn empty() SignalOwnedBuffer {
        return .{ .base = null, .length = 0 };
    }

    pub fn dupe(bytes: []const u8) !SignalOwnedBuffer {
        if (bytes.len == 0) return .{ .base = null, .length = 0 };
        const buf = try gpa.dupe(u8, bytes);
        return .{ .base = buf.ptr, .length = buf.len };
    }

    pub fn slice(self: SignalOwnedBuffer) []u8 {
        if (self.base == null or self.length == 0) return &.{};
        return self.base.?[0..self.length];
    }
};

pub const SignalBorrowedBuffer = extern struct {
    base: ?[*]const u8,
    length: usize,

    pub fn slice(self: SignalBorrowedBuffer) []const u8 {
        if (self.base == null or self.length == 0) return &.{};
        return self.base.?[0..self.length];
    }

    pub fn fromSlice(s: []const u8) SignalBorrowedBuffer {
        return .{ .base = s.ptr, .length = s.len };
    }
};

pub const SignalBorrowedMutableBuffer = extern struct {
    base: ?[*]u8,
    length: usize,

    pub fn slice(self: SignalBorrowedMutableBuffer) []u8 {
        if (self.base == null or self.length == 0) return &.{};
        return self.base.?[0..self.length];
    }
};
