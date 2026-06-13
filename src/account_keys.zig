// AccountEntropyPool and derived account keys per Signal's key derivation spec.
//
// AccountEntropyPool: a 64-character string drawn from the alphabet [a-z0-9] (base-32 compatible).
// From it, all long-lived account secrets are derived via HKDF-SHA256:
//   svr_key     = HKDF(salt="", ikm=pool, info="20231003_Signal_SVR_MasterKey")
//   backup_key  = HKDF(salt="", ikm=pool, info="20231003_Signal_BackupKey")
//   media_key   = HKDF(salt="backup_key, ikm=backup_key, info="20231003_Signal_Backups.MediaEncryptionKey")
const std = @import("std");
const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
const rnd = @import("random.zig");
const err = @import("error.zig");
const mem = std.mem;

pub const ENTROPY_POOL_LEN = 64;
pub const ENTROPY_ALPHABET = "abcdefghijklmnopqrstuvwxyz234567"; // base-32 alphabet

pub const AccountEntropyPool = struct {
    data: [ENTROPY_POOL_LEN]u8, // ASCII characters from ENTROPY_ALPHABET

    /// Generate a fresh random AccountEntropyPool.
    pub fn generate() AccountEntropyPool {
        var raw: [ENTROPY_POOL_LEN]u8 = undefined;
        rnd.bytes(&raw);
        var out: AccountEntropyPool = undefined;
        for (raw, 0..) |b, i| {
            out.data[i] = ENTROPY_ALPHABET[b % ENTROPY_ALPHABET.len];
        }
        return out;
    }

    /// Parse from an existing 64-character string.
    pub fn fromString(s: []const u8) !AccountEntropyPool {
        if (s.len != ENTROPY_POOL_LEN) return err.SignalError.InvalidArgument;
        for (s) |c| {
            if (mem.indexOfScalar(u8, ENTROPY_ALPHABET, c) == null)
                return err.SignalError.InvalidArgument;
        }
        var out: AccountEntropyPool = undefined;
        @memcpy(&out.data, s);
        return out;
    }

    pub fn asString(self: *const AccountEntropyPool) []const u8 {
        return &self.data;
    }

    fn hkdfDerive(self: *const AccountEntropyPool, info: []const u8, out: []u8) void {
        const prk = HkdfSha256.extract("", &self.data);
        HkdfSha256.expand(out[0..@min(out.len, 255)], info, prk);
    }

    /// SVR (Secure Value Recovery) master key — 32 bytes.
    pub fn deriveSvrKey(self: *const AccountEntropyPool) [32]u8 {
        var out: [32]u8 = undefined;
        self.hkdfDerive("20231003_Signal_SVR_MasterKey", &out);
        return out;
    }

    /// Backup key — 32 bytes.
    pub fn deriveBackupKey(self: *const AccountEntropyPool) BackupKey {
        var out: [32]u8 = undefined;
        self.hkdfDerive("20231003_Signal_BackupKey", &out);
        return .{ .bytes = out };
    }
};

pub const BackupKey = struct {
    bytes: [32]u8,

    /// Derive the media encryption key from the backup key.
    pub fn deriveMediaEncryptionKey(self: BackupKey) [32]u8 {
        const prk = HkdfSha256.extract(&self.bytes, &self.bytes);
        var out: [32]u8 = undefined;
        HkdfSha256.expand(&out, "20231003_Signal_Backups.MediaEncryptionKey", prk);
        return out;
    }
};

test "account entropy pool generate and derive" {
    const pool = AccountEntropyPool.generate();
    // All chars must be from the alphabet
    for (pool.data) |c| {
        try std.testing.expect(mem.indexOfScalar(u8, ENTROPY_ALPHABET, c) != null);
    }

    const svr = pool.deriveSvrKey();
    const backup = pool.deriveBackupKey();
    // Two derivations from same pool give different keys
    try std.testing.expect(!mem.eql(u8, &svr, &backup.bytes));
    // Deterministic: same pool gives same key
    const svr2 = pool.deriveSvrKey();
    try std.testing.expectEqualSlices(u8, &svr, &svr2);
}

test "account entropy pool parse roundtrip" {
    const pool = AccountEntropyPool.generate();
    const pool2 = try AccountEntropyPool.fromString(pool.asString());
    try std.testing.expectEqualSlices(u8, &pool.data, &pool2.data);
}
