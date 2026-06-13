// Username hashing and ZK proof per Signal's username spec.
// Hash: s1*G1 + s2*G2 + s3*G3 (Ristretto255 multi-scalar-mul, compressed to 32 bytes)
// Proof: Fiat-Shamir Schnorr proof over the linear relation, using ShoHmacSha256.
//
// Three scalars encode the username:
//   s1 = SHA-512(nickname_lc || 0x00 || discriminator_be64) reduced mod l
//   s2 = base-37 polynomial of nickname characters (first char uses multiplier 27, rest 37)
//   s3 = discriminator value as little-endian scalar
//
// Proof wire format (128 bytes): challenge[32] || response[0][32] || response[1][32] || response[2][32]
const std = @import("std");
const Sha512 = std.crypto.hash.sha2.Sha512;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const Ristretto255 = std.crypto.ecc.Ristretto255;
const err = @import("error.zig");
const mem = std.mem;

const Ed25519Scalar = std.crypto.ecc.Edwards25519.scalar;

pub const USERNAME_MAX_LENGTH = 32;
pub const USERNAME_MIN_LENGTH = 3;
pub const USERNAME_HASH_LEN = 32;
pub const USERNAME_PROOF_LEN = 128; // challenge(32) + 3 responses(32 each)

// Generator points G1, G2, G3: derived at runtime from domain labels via hash-to-point.
// Using SHA-512(label) → 64 bytes → reduce mod l → scalar → scalar*basePoint.
fn generatorFromLabel(label: []const u8) Ristretto255 {
    var wide: [64]u8 = undefined;
    Sha512.hash(label, &wide, .{});
    const s = Ed25519Scalar.reduce64(wide);
    // scalar mul: mul the base point by the derived scalar
    return Ristretto255.basePoint.mul(s) catch unreachable;
}

fn g1() Ristretto255 {
    return generatorFromLabel("Signal_Username_ZKP_Generator_G1");
}
fn g2() Ristretto255 {
    return generatorFromLabel("Signal_Username_ZKP_Generator_G2");
}
fn g3() Ristretto255 {
    return generatorFromLabel("Signal_Username_ZKP_Generator_G3");
}

// ---- ShoHmacSha256 ----
// Stateful hash object based on HMAC-SHA256. Matches the poksho crate's ShoHmacSha256.
//   ratchet:  key = HMAC(key, input || 0x00); clear input
//   squeeze:  for each 32-byte block i: HMAC(key, i_be32 || input || 0x01); then ratchet
const SHO_RATCHET: u8 = 0x00;
const SHO_SQUEEZE: u8 = 0x01;

const Sho = struct {
    key: [32]u8,
    input: std.ArrayListUnmanaged(u8),

    fn init(allocator: mem.Allocator, label: []const u8) !Sho {
        var s = Sho{
            .key = [_]u8{0} ** 32,
            .input = .empty,
        };
        try s.absorbAndRatchet(allocator, label);
        return s;
    }

    fn deinit(self: *Sho, allocator: mem.Allocator) void {
        self.input.deinit(allocator);
    }

    fn clone(self: *const Sho, allocator: mem.Allocator) !Sho {
        return .{
            .key = self.key,
            .input = try self.input.clone(allocator),
        };
    }

    fn absorb(self: *Sho, allocator: mem.Allocator, data: []const u8) !void {
        try self.input.appendSlice(allocator, data);
    }

    fn ratchet(self: *Sho) void {
        var mac = HmacSha256.init(&self.key);
        mac.update(self.input.items);
        mac.update(&[1]u8{SHO_RATCHET});
        mac.final(&self.key);
        self.input.clearRetainingCapacity();
    }

    fn absorbAndRatchet(self: *Sho, allocator: mem.Allocator, data: []const u8) !void {
        try self.absorb(allocator, data);
        self.ratchet();
    }

    fn squeezeAndRatchet(self: *Sho, allocator: mem.Allocator, num_bytes: usize) ![]u8 {
        const out = try allocator.alloc(u8, num_bytes);
        var produced: usize = 0;
        var counter: u32 = 0;
        while (produced < num_bytes) {
            var mac = HmacSha256.init(&self.key);
            var ctr_be: [4]u8 = undefined;
            std.mem.writeInt(u32, &ctr_be, counter, .big);
            mac.update(&ctr_be);
            mac.update(self.input.items);
            mac.update(&[1]u8{SHO_SQUEEZE});
            var block: [32]u8 = undefined;
            mac.final(&block);
            const chunk = @min(32, num_bytes - produced);
            @memcpy(out[produced .. produced + chunk], block[0..chunk]);
            produced += chunk;
            counter += 1;
        }
        self.ratchet();
        return out;
    }
};

// ---- Scalar encoding of username components ----

fn charToByte(c: u8) u8 {
    return switch (c) {
        '_' => 1,
        'a'...'z' => c - 'a' + 2,
        '0'...'9' => c - '0' + 28,
        else => 0,
    };
}

// Reduces a 64-byte wide hash output to a Ristretto255 scalar ([32]u8 little-endian).
fn scalarFromWide(bytes: [64]u8) [32]u8 {
    return Ed25519Scalar.reduce64(bytes);
}

// Scalar multiplication that returns null for the zero scalar (P*0 = identity = additive no-op).
// Zig's Ristretto255.mul rejects identity-element output, so we guard explicitly.
fn scalarMulOpt(point: Ristretto255, scalar: [32]u8) !?Ristretto255 {
    if (std.mem.allEqual(u8, &scalar, 0)) return null;
    return try point.mul(scalar);
}

// s1: SHA-512(nickname_lc || 0x00 || discriminator_be64) reduced mod l
fn makeS1(nickname_lc: []const u8, discriminator: u64) [32]u8 {
    var h = Sha512.init(.{});
    h.update(nickname_lc);
    h.update(&[1]u8{0x00});
    var disc_be: [8]u8 = undefined;
    std.mem.writeInt(u64, &disc_be, discriminator, .big);
    h.update(&disc_be);
    var wide: [64]u8 = undefined;
    h.final(&wide);
    return scalarFromWide(wide);
}

// s2: base-37 polynomial of the nickname; first character uses multiplier 27.
// Processes bytes[1..] in reverse (with multiplier 37), then adds first byte × 27.
fn makeS2(nickname_lc: []const u8) [32]u8 {
    if (nickname_lc.len == 0) return [_]u8{0} ** 32;
    const l: u256 = Ed25519Scalar.field_order;
    var val: u256 = 0;
    var i: usize = nickname_lc.len;
    while (i > 1) {
        i -= 1;
        val = (val * 37 + charToByte(nickname_lc[i])) % l;
    }
    val = (val * 27 + charToByte(nickname_lc[0])) % l;
    var s: [32]u8 = [_]u8{0} ** 32;
    var tmp = val;
    for (0..32) |j| {
        s[j] = @intCast(tmp & 0xFF);
        tmp >>= 8;
    }
    return s;
}

// s3: discriminator as little-endian 64-bit scalar
fn makeS3(discriminator: u64) [32]u8 {
    var s: [32]u8 = [_]u8{0} ** 32;
    std.mem.writeInt(u64, s[0..8], discriminator, .little);
    return s;
}

// ---- POKSHO statement description bytes ----
// Encodes the linear relation: username_hash = s1*G1 + s2*G2 + s3*G3
// Format matches poksho Statement serialization (null-terminated labels):
//   lhs_label\0 (scalar\0point\0)... \0
const STATEMENT_BYTES =
    "username_hash\x00" ++
    "username_sha_scalar\x00G1\x00" ++
    "nickname_scalar\x00G2\x00" ++
    "discriminator_scalar\x00G3\x00" ++
    "\x00";

const SHO_DOMAIN = "POKSHO_Ristretto_SHOHMACSHA256";

// ---- Public types ----

pub const UsernameHash = struct {
    hash: [USERNAME_HASH_LEN]u8,

    /// Compute the canonical username hash from a username string "nickname" or "nickname.discriminator".
    /// Discriminator is optional; if absent, defaults to 0.
    pub fn compute(username: []const u8) !UsernameHash {
        if (username.len < USERNAME_MIN_LENGTH) return err.SignalError.InvalidArgument;
        if (username.len > USERNAME_MAX_LENGTH) return err.SignalError.InvalidArgument;

        var nickname: []const u8 = username;
        var discriminator: u64 = 0;
        if (mem.indexOfScalar(u8, username, '.')) |dot| {
            nickname = username[0..dot];
            const disc_str = username[dot + 1 ..];
            discriminator = std.fmt.parseInt(u64, disc_str, 10) catch return err.SignalError.InvalidArgument;
        }

        for (nickname) |c| {
            if (!std.ascii.isAlphanumeric(c) and c != '_') return err.SignalError.InvalidArgument;
        }
        if (nickname.len == 0) return err.SignalError.InvalidArgument;
        if (std.ascii.isDigit(nickname[0])) return err.SignalError.InvalidArgument;

        var lc_buf: [USERNAME_MAX_LENGTH]u8 = undefined;
        for (nickname, 0..) |c, i| lc_buf[i] = std.ascii.toLower(c);
        const lc = lc_buf[0..nickname.len];

        const s1 = makeS1(lc, discriminator);
        const s2 = makeS2(lc);
        const s3 = makeS3(discriminator);

        const p1 = try g1().mul(s1);
        const p2 = try g2().mul(s2);
        var hash_point = p1.add(p2);
        if (try scalarMulOpt(g3(), s3)) |p3| hash_point = hash_point.add(p3);

        return .{ .hash = hash_point.toBytes() };
    }

    pub fn fromBytes(bytes: [USERNAME_HASH_LEN]u8) UsernameHash {
        return .{ .hash = bytes };
    }

    pub fn toBytes(self: UsernameHash) [USERNAME_HASH_LEN]u8 {
        return self.hash;
    }
};

fn splitUsername(username: []const u8) !struct { lc: [USERNAME_MAX_LENGTH]u8, lc_len: usize, discriminator: u64 } {
    var nickname: []const u8 = username;
    var discriminator: u64 = 0;
    if (mem.indexOfScalar(u8, username, '.')) |dot| {
        nickname = username[0..dot];
        const disc_str = username[dot + 1 ..];
        discriminator = std.fmt.parseInt(u64, disc_str, 10) catch return err.SignalError.InvalidArgument;
    }
    for (nickname) |c| {
        if (!std.ascii.isAlphanumeric(c) and c != '_') return err.SignalError.InvalidArgument;
    }
    var lc_buf: [USERNAME_MAX_LENGTH]u8 = undefined;
    for (nickname, 0..) |c, i| lc_buf[i] = std.ascii.toLower(c);
    return .{ .lc = lc_buf, .lc_len = nickname.len, .discriminator = discriminator };
}

/// Generate a 128-byte Schnorr ZK proof that the caller knows the scalars behind a username hash.
pub fn usernameProof(
    allocator: mem.Allocator,
    username: []const u8,
    randomness: [32]u8,
) ![]u8 {
    const parsed = try splitUsername(username);
    const lc = parsed.lc[0..parsed.lc_len];

    const s1 = makeS1(lc, parsed.discriminator);
    const s2 = makeS2(lc);
    const s3 = makeS3(parsed.discriminator);
    const scalars = [3][32]u8{ s1, s2, s3 };

    const G1 = g1();
    const G2 = g2();
    const G3 = g3();

    const p1 = try G1.mul(s1);
    const p2 = try G2.mul(s2);
    var hash_point = p1.add(p2);
    if (try scalarMulOpt(G3, s3)) |p3| hash_point = hash_point.add(p3);
    const hash_bytes = hash_point.toBytes();

    var sho = try Sho.init(allocator, SHO_DOMAIN);
    defer sho.deinit(allocator);

    try sho.absorb(allocator, STATEMENT_BYTES);
    try sho.absorb(allocator, &G1.toBytes());
    try sho.absorb(allocator, &G2.toBytes());
    try sho.absorb(allocator, &G3.toBytes());
    try sho.absorb(allocator, &hash_bytes);
    sho.ratchet();

    // Synthetic nonce: clone sho, absorb randomness + scalars + message
    var sho2 = try sho.clone(allocator);
    defer sho2.deinit(allocator);

    try sho2.absorb(allocator, &randomness);
    try sho2.absorb(allocator, &s1);
    try sho2.absorb(allocator, &s2);
    try sho2.absorb(allocator, &s3);
    sho2.ratchet();
    try sho2.absorbAndRatchet(allocator, &hash_bytes);
    const nonce_bytes = try sho2.squeezeAndRatchet(allocator, 3 * 64);
    defer allocator.free(nonce_bytes);

    const nonces: [3][32]u8 = .{
        scalarFromWide(nonce_bytes[0..64].*),
        scalarFromWide(nonce_bytes[64..128].*),
        scalarFromWide(nonce_bytes[128..192].*),
    };

    // Commitment R = nonces[0]*G1 + nonces[1]*G2 + nonces[2]*G3
    var R = (try G1.mul(nonces[0])).add(try G2.mul(nonces[1]));
    if (try scalarMulOpt(G3, nonces[2])) |p| R = R.add(p);

    // Challenge via Fiat-Shamir
    try sho.absorb(allocator, &R.toBytes());
    try sho.absorbAndRatchet(allocator, &hash_bytes);
    const challenge_wide = try sho.squeezeAndRatchet(allocator, 64);
    defer allocator.free(challenge_wide);
    const challenge = scalarFromWide(challenge_wide[0..64].*);

    // Responses: response[i] = nonce[i] + scalars[i] * challenge
    const out = try allocator.alloc(u8, USERNAME_PROOF_LEN);
    @memcpy(out[0..32], &challenge);
    for (0..3) |i| {
        const sc_ch = Ed25519Scalar.mul(scalars[i], challenge);
        const resp = Ed25519Scalar.add(nonces[i], sc_ch);
        @memcpy(out[32 + i * 32 .. 32 + (i + 1) * 32], &resp);
    }
    return out;
}

/// Verify a 128-byte username proof against its hash.
pub fn usernameVerify(
    allocator: mem.Allocator,
    username_hash: [USERNAME_HASH_LEN]u8,
    proof: []const u8,
) !bool {
    if (proof.len != USERNAME_PROOF_LEN) return false;

    const hash_point = Ristretto255.fromBytes(username_hash) catch return false;
    const challenge: [32]u8 = proof[0..32].*;
    const responses: [3][32]u8 = .{ proof[32..64].*, proof[64..96].*, proof[96..128].* };

    const G1 = g1();
    const G2 = g2();
    const G3 = g3();

    // R = responses[0]*G1 + responses[1]*G2 + responses[2]*G3 - challenge * hash_point
    var part = (try G1.mul(responses[0])).add(try G2.mul(responses[1]));
    if (try scalarMulOpt(G3, responses[2])) |p| part = part.add(p);
    const R = part.sub(try hash_point.mul(challenge));

    var sho = try Sho.init(allocator, SHO_DOMAIN);
    defer sho.deinit(allocator);

    try sho.absorb(allocator, STATEMENT_BYTES);
    try sho.absorb(allocator, &G1.toBytes());
    try sho.absorb(allocator, &G2.toBytes());
    try sho.absorb(allocator, &G3.toBytes());
    try sho.absorb(allocator, &username_hash);
    sho.ratchet();
    try sho.absorb(allocator, &R.toBytes());
    try sho.absorbAndRatchet(allocator, &username_hash);
    const ch_wide = try sho.squeezeAndRatchet(allocator, 64);
    defer allocator.free(ch_wide);
    const expected_challenge = scalarFromWide(ch_wide[0..64].*);

    return mem.eql(u8, &challenge, &expected_challenge);
}

test "username hash consistency" {
    const h1 = try UsernameHash.compute("alice.42");
    const h2 = try UsernameHash.compute("alice.42");
    try std.testing.expectEqualSlices(u8, &h1.hash, &h2.hash);

    const h3 = try UsernameHash.compute("bob.1");
    try std.testing.expect(!mem.eql(u8, &h1.hash, &h3.hash));
}

test "username proof roundtrip" {
    var randomness: [32]u8 = undefined;
    @import("random.zig").bytes(&randomness);
    const hash = try UsernameHash.compute("alice.42");
    const proof = try usernameProof(std.testing.allocator, "alice.42", randomness);
    defer std.testing.allocator.free(proof);
    const valid = try usernameVerify(std.testing.allocator, hash.hash, proof);
    try std.testing.expect(valid);
    var bad_hash = hash.hash;
    bad_hash[0] ^= 0xFF;
    const invalid = try usernameVerify(std.testing.allocator, bad_hash, proof);
    try std.testing.expect(!invalid);
}
