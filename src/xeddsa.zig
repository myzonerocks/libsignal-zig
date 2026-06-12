// XEdDSA: Sign/verify using X25519 keys as Ed25519-compatible signatures.
// Spec: https://signal.org/docs/specifications/xeddsa/
const std = @import("std");
const Edwards25519 = std.crypto.ecc.Edwards25519;
const Fe = Edwards25519.Fe;
const scalar = Edwards25519.scalar;
const Sha512 = std.crypto.hash.sha2.Sha512;

pub const SIGNATURE_LENGTH = 64;

const NONCE_PREFIX = [_]u8{0xFE} ** 64;

fn clampScalar(s: [32]u8) [32]u8 {
    var c = s;
    c[0] &= 248;
    c[31] &= 127;
    c[31] |= 64;
    return c;
}

fn montgomeryUToEdwardsPoint(u_bytes: [32]u8, sign_bit: u1) !Edwards25519 {
    const u_fe = Fe.fromBytes(u_bytes);
    const one = Fe.one;
    const num = u_fe.sub(one);
    const den = u_fe.add(one);
    const y_fe = num.mul(den.invert());
    var y = y_fe.toBytes();
    y[31] = (y[31] & 0x7F) | (@as(u8, sign_bit) << 7);
    return Edwards25519.fromBytes(y) catch return error.InvalidKey;
}

pub fn sign(
    x25519_private_key: [32]u8,
    message: []const u8,
    random_64: [64]u8,
) ![SIGNATURE_LENGTH]u8 {
    const a = clampScalar(x25519_private_key);

    // Compute Ed25519 public key A = a * B
    const A_point = try Edwards25519.basePoint.mul(a);
    const A_bytes = A_point.toBytes();
    const sign_bit: u1 = @intCast(A_bytes[31] >> 7);

    // Compute nonce: r = SHA-512([0xFE * 64] || x25519_private_key || random_64) mod l
    var h = Sha512.init(.{});
    h.update(&NONCE_PREFIX);
    h.update(&x25519_private_key);
    h.update(&random_64);
    var nonce_hash: [64]u8 = undefined;
    h.final(&nonce_hash);
    const r = scalar.reduce64(nonce_hash);

    // R = r * B
    const R_point = try Edwards25519.basePoint.mul(r);
    const R_bytes = R_point.toBytes();

    // h = SHA-512(R || A || message) mod l
    var h2 = Sha512.init(.{});
    h2.update(&R_bytes);
    h2.update(&A_bytes);
    h2.update(message);
    var h2_hash: [64]u8 = undefined;
    h2.final(&h2_hash);
    const k = scalar.reduce64(h2_hash);

    // s = (r + k * a) mod l
    const s = scalar.mulAdd(k, a, r);

    // Encode signature: R || s, with sign_bit embedded in s[63] high bit
    var sig: [64]u8 = undefined;
    @memcpy(sig[0..32], &R_bytes);
    @memcpy(sig[32..64], &s);
    sig[63] = (sig[63] & 0x7F) | (@as(u8, sign_bit) << 7);

    return sig;
}

pub fn verify(
    x25519_public_key: [32]u8,
    message: []const u8,
    signature: [SIGNATURE_LENGTH]u8,
) !bool {
    // Extract sign bit and clean it from signature
    var sig = signature;
    const sign_bit: u1 = @intCast(sig[63] >> 7);
    sig[63] &= 0x7F;

    // Decode R from sig[0..32]
    const R_point = Edwards25519.fromBytes(sig[0..32].*) catch return false;

    // Decode s from sig[32..64]
    const s = sig[32..64].*;

    // Convert X25519 public key to Edwards point using sign_bit
    const A_point = montgomeryUToEdwardsPoint(x25519_public_key, sign_bit) catch return false;
    const A_bytes = A_point.toBytes();
    const R_bytes = sig[0..32].*;

    // h = SHA-512(R || A || message) mod l
    var h = Sha512.init(.{});
    h.update(&R_bytes);
    h.update(&A_bytes);
    h.update(message);
    var h_hash: [64]u8 = undefined;
    h.final(&h_hash);
    const k = scalar.reduce64(h_hash);

    // Verify: s*B - k*A == R  i.e. s*B + k*(-A) == R
    const neg_A = A_point.neg();
    const R_check = Edwards25519.mulDoubleBasePublic(Edwards25519.basePoint, s, neg_A, k) catch return false;
    const R_check_bytes = R_check.toBytes();

    return std.mem.eql(u8, &R_bytes, &R_check_bytes) and !rejectIdentity(R_point);
}

fn rejectIdentity(p: Edwards25519) bool {
    p.rejectIdentity() catch return true;
    return false;
}

test "xeddsa sign and verify" {
    const rnd = @import("random.zig");
    var priv_raw: [32]u8 = undefined;
    rnd.bytes(&priv_raw);

    var random_64: [64]u8 = undefined;
    rnd.bytes(&random_64);

    const message = "hello signal";

    // Derive X25519 public key
    const Curve25519 = std.crypto.dh.X25519.Curve;
    const a = clampScalar(priv_raw);
    const pub_point = try Curve25519.basePoint.clampedMul(a);
    const pub_key = pub_point.toBytes();

    const sig = try sign(priv_raw, message, random_64);
    const ok = try verify(pub_key, message, sig);
    try std.testing.expect(ok);

    // Wrong message should fail
    var bad_sig = sig;
    bad_sig[0] ^= 0x01;
    const not_ok = try verify(pub_key, message, bad_sig);
    try std.testing.expect(!not_ok);
}
