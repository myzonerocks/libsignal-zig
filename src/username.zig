// Username hashing and validation per Signal's username spec.
const std = @import("std");
const Sha256 = std.crypto.hash.sha2.Sha256;
const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
const err = @import("error.zig");
const mem = std.mem;

pub const USERNAME_MAX_LENGTH = 32;
pub const USERNAME_MIN_LENGTH = 3;

pub const UsernameHash = struct {
    hash: [32]u8,

    /// Hash a username per Signal's spec.
    /// Username is lowercased and hashed with HKDF-SHA256.
    pub fn compute(username: []const u8) !UsernameHash {
        if (username.len < USERNAME_MIN_LENGTH) return err.SignalError.InvalidArgument;
        if (username.len > USERNAME_MAX_LENGTH) return err.SignalError.InvalidArgument;

        // Validate characters: only a-z, 0-9, _, .
        for (username) |c| {
            if (!std.ascii.isAlphanumeric(c) and c != '_' and c != '.') {
                return err.SignalError.InvalidArgument;
            }
        }

        // Cannot start with a digit or dot
        if (std.ascii.isDigit(username[0]) or username[0] == '.') {
            return err.SignalError.InvalidArgument;
        }

        // Normalize to lowercase
        var lower: [USERNAME_MAX_LENGTH]u8 = undefined;
        const lower_len = username.len;
        for (username, 0..) |c, i| {
            lower[i] = std.ascii.toLower(c);
        }

        const prk = HkdfSha256.extract("signal_username", lower[0..lower_len]);
        var hash: [32]u8 = undefined;
        HkdfSha256.expand(&hash, "hash", prk);

        return .{ .hash = hash };
    }

    pub fn fromBytes(bytes: [32]u8) UsernameHash {
        return .{ .hash = bytes };
    }

    pub fn toBytes(self: UsernameHash) [32]u8 {
        return self.hash;
    }
};

pub fn usernameProof(
    allocator: mem.Allocator,
    username: []const u8,
    randomness: [32]u8,
) ![]u8 {
    const hash = try UsernameHash.compute(username);

    // Build proof: hash || HMAC(randomness, username_hash)
    const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
    var proof_mac: [32]u8 = undefined;
    HmacSha256.create(&proof_mac, &hash.hash, &randomness);

    const out = try allocator.alloc(u8, 64);
    @memcpy(out[0..32], &hash.hash);
    @memcpy(out[32..64], &proof_mac);
    return out;
}

pub fn usernameVerify(
    username: []const u8,
    proof: []const u8,
) !bool {
    if (proof.len != 64) return false;
    const expected_hash = try UsernameHash.compute(username);
    return mem.eql(u8, proof[0..32], &expected_hash.hash);
}

test "username hash" {
    const hash = try UsernameHash.compute("alice");
    try std.testing.expect(hash.hash.len == 32);

    // Same username gives same hash
    const hash2 = try UsernameHash.compute("alice");
    try std.testing.expectEqualSlices(u8, &hash.hash, &hash2.hash);

    // Different username gives different hash
    const hash3 = try UsernameHash.compute("bob");
    try std.testing.expect(!mem.eql(u8, &hash.hash, &hash3.hash));
}
