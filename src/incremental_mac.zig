// IncrementalMac: streaming HMAC-SHA256 for attachment integrity verification.
// Splits a stream into fixed-size chunks and computes a combined HMAC that can be
// verified as each chunk arrives, rather than requiring the full content upfront.
//
// Wire format: HMAC-SHA256(key, chunk_0) || HMAC-SHA256(key, chunk_1) || ...
// The final partial chunk is padded with zeros before hashing if it is not full-sized.
//
// Both Incremental (sender) and Validating (receiver) operate chunk-at-a-time.
const std = @import("std");
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const err = @import("error.zig");
const mem = std.mem;

pub const MAC_LEN = 32; // HMAC-SHA256 output per chunk
pub const DEFAULT_CHUNK_SIZE = 256 * 1024; // 256 KiB

/// Compute the number of chunks for a given total size.
pub fn chunkCount(total_size: usize, chunk_size: usize) usize {
    if (total_size == 0) return 0;
    return (total_size + chunk_size - 1) / chunk_size;
}

/// Compute the total MAC bytes for a given total size.
pub fn macBytesForSize(total_size: usize, chunk_size: usize) usize {
    return chunkCount(total_size, chunk_size) * MAC_LEN;
}

/// Sender side: call update() with each chunk of data; finalize() yields the combined MAC bytes.
pub const Incremental = struct {
    key: [32]u8,
    chunk_size: usize,
    buf: []u8, // owned buffer of chunk_size
    buf_len: usize,
    macs: std.ArrayListUnmanaged(u8),
    allocator: mem.Allocator,

    pub fn init(allocator: mem.Allocator, key: [32]u8, chunk_size: usize) !Incremental {
        const buf = try allocator.alloc(u8, chunk_size);
        return .{
            .key = key,
            .chunk_size = chunk_size,
            .buf = buf,
            .buf_len = 0,
            .macs = .empty,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Incremental) void {
        self.allocator.free(self.buf);
        self.macs.deinit(self.allocator);
    }

    /// Feed data. May be called multiple times with arbitrary-sized slices.
    pub fn update(self: *Incremental, data: []const u8) !void {
        var src = data;
        while (src.len > 0) {
            const space = self.chunk_size - self.buf_len;
            const take = @min(space, src.len);
            @memcpy(self.buf[self.buf_len .. self.buf_len + take], src[0..take]);
            self.buf_len += take;
            src = src[take..];
            if (self.buf_len == self.chunk_size) {
                try self.flushChunk(false);
            }
        }
    }

    /// Finalize: flush the last (possibly partial) chunk and return all MAC bytes.
    /// The returned slice is owned by the caller.
    pub fn finalize(self: *Incremental) ![]u8 {
        if (self.buf_len > 0) {
            try self.flushChunk(true);
        }
        return self.macs.toOwnedSlice(self.allocator);
    }

    fn flushChunk(self: *Incremental, last: bool) !void {
        var mac_out: [MAC_LEN]u8 = undefined;
        if (last and self.buf_len < self.chunk_size) {
            // Pad to chunk_size with zeros
            @memset(self.buf[self.buf_len..self.chunk_size], 0);
        }
        HmacSha256.create(&mac_out, self.buf[0..self.chunk_size], &self.key);
        try self.macs.appendSlice(self.allocator, &mac_out);
        self.buf_len = 0;
    }
};

/// Receiver side: verify each chunk against the expected per-chunk MAC as data arrives.
pub const Validating = struct {
    key: [32]u8,
    chunk_size: usize,
    expected_macs: []const u8, // borrowed slice of all expected MAC bytes
    buf: []u8, // owned buffer of chunk_size
    buf_len: usize,
    chunk_idx: usize,
    allocator: mem.Allocator,

    pub fn init(
        allocator: mem.Allocator,
        key: [32]u8,
        chunk_size: usize,
        expected_macs: []const u8,
    ) !Validating {
        const buf = try allocator.alloc(u8, chunk_size);
        return .{
            .key = key,
            .chunk_size = chunk_size,
            .expected_macs = expected_macs,
            .buf = buf,
            .buf_len = 0,
            .chunk_idx = 0,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Validating) void {
        self.allocator.free(self.buf);
    }

    /// Feed data. Returns error.InvalidMessage if a chunk MAC does not match.
    pub fn update(self: *Validating, data: []const u8) !void {
        var src = data;
        while (src.len > 0) {
            const space = self.chunk_size - self.buf_len;
            const take = @min(space, src.len);
            @memcpy(self.buf[self.buf_len .. self.buf_len + take], src[0..take]);
            self.buf_len += take;
            src = src[take..];
            if (self.buf_len == self.chunk_size) {
                try self.verifyChunk(false);
            }
        }
    }

    /// Call after all data has been fed to verify the final partial chunk.
    pub fn finalize(self: *Validating) !void {
        if (self.buf_len > 0) {
            try self.verifyChunk(true);
        }
    }

    fn verifyChunk(self: *Validating, last: bool) !void {
        const mac_offset = self.chunk_idx * MAC_LEN;
        if (mac_offset + MAC_LEN > self.expected_macs.len) return err.SignalError.InvalidMessage;
        const expected: [MAC_LEN]u8 = self.expected_macs[mac_offset .. mac_offset + MAC_LEN][0..MAC_LEN].*;

        if (last and self.buf_len < self.chunk_size) {
            @memset(self.buf[self.buf_len..self.chunk_size], 0);
        }
        var actual: [MAC_LEN]u8 = undefined;
        HmacSha256.create(&actual, self.buf[0..self.chunk_size], &self.key);

        if (!std.crypto.timing_safe.eql([MAC_LEN]u8, actual, expected))
            return err.SignalError.InvalidMessage;

        self.buf_len = 0;
        self.chunk_idx += 1;
    }
};

test "incremental mac roundtrip" {
    const allocator = std.testing.allocator;
    const key: [32]u8 = [_]u8{0x42} ** 32;
    const chunk_size = 64;

    var sender = try Incremental.init(allocator, key, chunk_size);
    defer sender.deinit();

    const data = "hello signal incremental mac verification!";
    try sender.update(data);
    const macs = try sender.finalize();
    defer allocator.free(macs);

    var receiver = try Validating.init(allocator, key, chunk_size, macs);
    defer receiver.deinit();
    try receiver.update(data);
    try receiver.finalize();
}

test "incremental mac detects corruption" {
    const allocator = std.testing.allocator;
    const key: [32]u8 = [_]u8{0x42} ** 32;
    const chunk_size = 64;

    var sender = try Incremental.init(allocator, key, chunk_size);
    defer sender.deinit();

    const data = [_]u8{0xAA} ** 64;
    try sender.update(&data);
    const macs = try sender.finalize();
    defer allocator.free(macs);

    var bad_data = data;
    bad_data[0] ^= 0xFF;

    var receiver = try Validating.init(allocator, key, chunk_size, macs);
    defer receiver.deinit();
    try receiver.update(&bad_data);
    try std.testing.expectError(err.SignalError.InvalidMessage, receiver.finalize());
}
