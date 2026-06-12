// Signal Fingerprint: human-readable key verification.
// Implements v1 fingerprint (iterative SHA-512 hashing).
const std = @import("std");
const identity = @import("identity.zig");
const proto = @import("proto.zig");
const err = @import("error.zig");
const Sha512 = std.crypto.hash.sha2.Sha512;
const mem = std.mem;

const ITERATIONS: usize = 5200;
const FINGERPRINT_VERSION: u32 = 0;

fn iterativeHash(input: []const u8, count: usize) [64]u8 {
    var current: [64]u8 = undefined;
    var h = Sha512.init(.{});
    h.update(std.mem.asBytes(&@as(u32, FINGERPRINT_VERSION)));
    h.update(input);
    h.final(&current);

    var i: usize = 1;
    while (i < count) : (i += 1) {
        var h2 = Sha512.init(.{});
        h2.update(&current);
        h2.update(input);
        h2.final(&current);
    }
    return current;
}

fn hashForDisplay(key: []const u8, stable_id: []const u8) [30]u8 {
    // key is 33 bytes max, stable_id is typically a phone number (<20 chars)
    var combined: [128]u8 = undefined;
    const combined_len = key.len + stable_id.len;
    @memcpy(combined[0..key.len], key);
    @memcpy(combined[key.len..combined_len], stable_id);
    const digest = iterativeHash(combined[0..combined_len], ITERATIONS);
    var result: [30]u8 = undefined;
    @memcpy(&result, digest[0..30]);
    return result;
}

pub const DisplayableFingerprint = struct {
    displayable: [60]u8,

    pub fn format(self: DisplayableFingerprint) [60]u8 {
        return self.displayable;
    }
};

/// Compute a displayable fingerprint for key comparison.
/// Returns a string of 120 decimal digits (12 groups of 5 per side).
pub fn computeDisplayableFingerprint(
    allocator: mem.Allocator,
    local_key: identity.IdentityKey,
    local_stable_id: []const u8,
    remote_key: identity.IdentityKey,
    remote_stable_id: []const u8,
) ![]u8 {
    const local_key_bytes = local_key.serialize();
    const remote_key_bytes = remote_key.serialize();

    const local_hash = hashForDisplay(&local_key_bytes, local_stable_id);
    const remote_hash = hashForDisplay(&remote_key_bytes, remote_stable_id);

    // Each side: 30 bytes → 6 groups of 5 bytes → 6 groups of 5 decimal digits
    // Total: 6 groups * 2 sides * 5 digits = 60 digits per side, 120 total
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);

    for ([2][30]u8{ local_hash, remote_hash }) |hash| {
        var i: usize = 0;
        while (i + 5 <= 30) : (i += 5) {
            var val: u64 = 0;
            for (hash[i .. i + 5]) |b| {
                val = (val << 8) | b;
            }
            val = val % 100000;
            const group_str = try std.fmt.allocPrint(allocator, "{d:0>5}", .{val});
            defer allocator.free(group_str);
            try out.appendSlice(allocator, group_str);
        }
    }

    return out.toOwnedSlice(allocator);
}

pub const ScannableFingerprint = struct {
    version: u32,
    local_fingerprint: [32]u8,
    remote_fingerprint: [32]u8,
    allocator: mem.Allocator,

    pub fn compute(
        allocator: mem.Allocator,
        local_key: identity.IdentityKey,
        local_stable_id: []const u8,
        remote_key: identity.IdentityKey,
        remote_stable_id: []const u8,
    ) !ScannableFingerprint {
        const lk = local_key.serialize();
        const rk = remote_key.serialize();

        var local_combined: [100]u8 = undefined;
        const lc_len = lk.len + local_stable_id.len;
        @memcpy(local_combined[0..lk.len], &lk);
        @memcpy(local_combined[lk.len..lc_len], local_stable_id);

        var remote_combined: [100]u8 = undefined;
        const rc_len = rk.len + remote_stable_id.len;
        @memcpy(remote_combined[0..rk.len], &rk);
        @memcpy(remote_combined[rk.len..rc_len], remote_stable_id);

        const local_digest = iterativeHash(local_combined[0..lc_len], ITERATIONS);
        const remote_digest = iterativeHash(remote_combined[0..rc_len], ITERATIONS);

        return .{
            .version = FINGERPRINT_VERSION,
            .local_fingerprint = local_digest[0..32].*,
            .remote_fingerprint = remote_digest[0..32].*,
            .allocator = allocator,
        };
    }

    pub fn serialize(self: ScannableFingerprint) ![]u8 {
        var enc = proto.Encoder.init(self.allocator);
        defer enc.deinit();
        try enc.writeVarintField(1, self.version);
        try enc.writeBytesField(2, &self.local_fingerprint);
        try enc.writeBytesField(3, &self.remote_fingerprint);
        return enc.toOwnedSlice();
    }

    pub fn compareTo(self: ScannableFingerprint, their_bytes: []const u8) !bool {
        var pos: usize = 0;
        var their_local: ?[32]u8 = null;
        var their_remote: ?[32]u8 = null;
        while (try proto.nextField(their_bytes, &pos)) |field| {
            switch (field.number) {
                2 => if (field.wire_type == .len and field.data.len.len == 32) {
                    their_local = field.data.len[0..32].*;
                },
                3 => if (field.wire_type == .len and field.data.len.len == 32) {
                    their_remote = field.data.len[0..32].*;
                },
                else => {},
            }
        }
        const tl = their_local orelse return err.SignalError.FingerprintVersionMismatch;
        const tr = their_remote orelse return err.SignalError.FingerprintVersionMismatch;

        return mem.eql(u8, &self.local_fingerprint, &tr) and
            mem.eql(u8, &self.remote_fingerprint, &tl);
    }
};
