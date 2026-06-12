// SPQR key chain: per-epoch per-direction key derivation.
const std = @import("std");
const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
const mem = std.mem;

pub const Direction = enum(u8) { a2b = 0, b2a = 1 };

// Per-direction key state within one epoch.
const EpochDir = struct {
    ctr: u32,
    next: [32]u8,

    const KeyResult = struct { idx: u32, key: [32]u8 };

    fn nextKey(self: *EpochDir) KeyResult {
        self.ctr += 1;
        const LABEL = "Signal PQ Ratchet V1 Chain Next";
        var ctr_bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &ctr_bytes, self.ctr, .big);
        var info: [4 + LABEL.len]u8 = undefined;
        @memcpy(info[0..4], &ctr_bytes);
        @memcpy(info[4..], LABEL);
        const salt = [_]u8{0} ** 32;
        const prk = HkdfSha256.extract(&salt, &self.next);
        var out: [64]u8 = undefined;
        HkdfSha256.expand(&out, &info, prk);
        @memcpy(&self.next, out[0..32]);
        return .{ .idx = self.ctr, .key = out[32..64].* };
    }

    fn keyAt(self: *EpochDir, index: u32, max_jump: u32) !KeyResult {
        if (index <= self.ctr) return error.KeyAlreadyUsed;
        if (index > self.ctr + max_jump) return error.KeyJump;
        while (self.ctr + 1 < index) {
            _ = self.nextKey();
        }
        return self.nextKey();
    }
};

// One epoch's state (send + recv directions)
const Epoch = struct {
    send: EpochDir,
    recv: EpochDir,
};

// Chain manages keys across epochs.
pub const Chain = struct {
    dir: Direction,
    current_epoch: u64,
    send_epoch: u64,
    // Circular buffer of epochs: links[0] = oldest, links[last] = current_epoch
    links: std.ArrayListUnmanaged(Epoch),
    next_root: [32]u8,
    max_jump: u32,

    const DEFAULT_MAX_JUMP: u32 = 25_000;

    // HKDF(salt=[0]*32, ikm=initial_key, info="Signal PQ Ratchet V1 Chain  Start") → 96 bytes
    // Note: double space in "Chain  Start" is intentional (matches official implementation)
    pub fn init(allocator: mem.Allocator, initial_key: [32]u8, dir: Direction) !Chain {
        const LABEL = "Signal PQ Ratchet V1 Chain  Start";
        const salt = [_]u8{0} ** 32;
        const prk = HkdfSha256.extract(&salt, &initial_key);
        var out: [96]u8 = undefined;
        HkdfSha256.expand(&out, LABEL, prk);
        const new_root = out[0..32].*;
        // A2B: send = [32..64], recv = [64..96]; B2A: send = [64..96], recv = [32..64]
        const send_start: [32]u8 = if (dir == .a2b) out[32..64].* else out[64..96].*;
        const recv_start: [32]u8 = if (dir == .a2b) out[64..96].* else out[32..64].*;
        var links: std.ArrayListUnmanaged(Epoch) = .empty;
        try links.append(allocator, .{
            .send = .{ .ctr = 0, .next = send_start },
            .recv = .{ .ctr = 0, .next = recv_start },
        });
        return .{
            .dir = dir,
            .current_epoch = 0,
            .send_epoch = 0,
            .links = links,
            .next_root = new_root,
            .max_jump = DEFAULT_MAX_JUMP,
        };
    }

    pub fn deinit(self: *Chain, allocator: mem.Allocator) void {
        self.links.deinit(allocator);
    }

    // HKDF(salt=next_root, ikm=epoch_secret, info="Signal PQ Ratchet V1 Chain Add Epoch") → 96 bytes
    pub fn addEpoch(self: *Chain, allocator: mem.Allocator, epoch: u64, secret: [32]u8) !void {
        if (epoch != self.current_epoch + 1) return error.EpochOutOfOrder;
        const LABEL = "Signal PQ Ratchet V1 Chain Add Epoch";
        const prk = HkdfSha256.extract(&self.next_root, &secret);
        var out: [96]u8 = undefined;
        HkdfSha256.expand(&out, LABEL, prk);
        @memcpy(&self.next_root, out[0..32]);
        self.current_epoch = epoch;
        self.send_epoch = epoch;
        const send_start: [32]u8 = if (self.dir == .a2b) out[32..64].* else out[64..96].*;
        const recv_start: [32]u8 = if (self.dir == .a2b) out[64..96].* else out[32..64].*;
        try self.links.append(allocator, .{
            .send = .{ .ctr = 0, .next = send_start },
            .recv = .{ .ctr = 0, .next = recv_start },
        });
    }

    fn epochLink(self: *Chain, epoch: u64) !*Epoch {
        if (epoch > self.current_epoch) return error.EpochOutOfRange;
        const back = self.current_epoch - epoch;
        const links_len = self.links.items.len;
        if (back >= links_len) return error.EpochOutOfRange;
        return &self.links.items[links_len - 1 - back];
    }

    // Returns (index, msg_key) for the next message in the given epoch.
    pub fn sendKey(self: *Chain, epoch: u64) !struct { index: u32, key: [32]u8 } {
        const link = try self.epochLink(epoch);
        const r = link.send.nextKey();
        return .{ .index = r.idx, .key = r.key };
    }

    // Returns msg_key for given epoch + index.
    pub fn recvKey(self: *Chain, epoch: u64, index: u32) ![32]u8 {
        const link = try self.epochLink(epoch);
        const r = try link.recv.keyAt(index, self.max_jump);
        return r.key;
    }

    // Serialize chain to a flat buffer
    pub fn serialize(self: *const Chain, buf: *std.ArrayListUnmanaged(u8), a: mem.Allocator) !void {
        var tmp: [8]u8 = undefined;
        try buf.append(a, @intFromEnum(self.dir));
        std.mem.writeInt(u64, &tmp, self.current_epoch, .big);
        try buf.appendSlice(a, &tmp);
        std.mem.writeInt(u64, &tmp, self.send_epoch, .big);
        try buf.appendSlice(a, &tmp);
        try buf.appendSlice(a, &self.next_root);
        std.mem.writeInt(u32, tmp[0..4], @intCast(self.links.items.len), .big);
        try buf.appendSlice(a, tmp[0..4]);
        for (self.links.items) |*link| {
            std.mem.writeInt(u32, tmp[0..4], link.send.ctr, .big);
            try buf.appendSlice(a, tmp[0..4]);
            try buf.appendSlice(a, &link.send.next);
            std.mem.writeInt(u32, tmp[0..4], link.recv.ctr, .big);
            try buf.appendSlice(a, tmp[0..4]);
            try buf.appendSlice(a, &link.recv.next);
        }
    }

    pub fn deserialize(allocator: mem.Allocator, data: []const u8) !struct { chain: Chain, consumed: usize } {
        var pos: usize = 0;
        if (data.len < 1 + 8 + 8 + 32 + 4) return error.TooShort;
        const dir: Direction = @enumFromInt(data[pos]);
        pos += 1;
        const current_epoch = std.mem.readInt(u64, data[pos..][0..8], .big);
        pos += 8;
        const send_epoch = std.mem.readInt(u64, data[pos..][0..8], .big);
        pos += 8;
        const next_root = data[pos..][0..32].*;
        pos += 32;
        const num_links = std.mem.readInt(u32, data[pos..][0..4], .big);
        pos += 4;
        var links: std.ArrayListUnmanaged(Epoch) = .empty;
        for (0..num_links) |_| {
            if (pos + 4 + 32 + 4 + 32 > data.len) {
                links.deinit(allocator);
                return error.TooShort;
            }
            const send_ctr = std.mem.readInt(u32, data[pos..][0..4], .big);
            pos += 4;
            const send_next = data[pos..][0..32].*;
            pos += 32;
            const recv_ctr = std.mem.readInt(u32, data[pos..][0..4], .big);
            pos += 4;
            const recv_next = data[pos..][0..32].*;
            pos += 32;
            try links.append(allocator, .{
                .send = .{ .ctr = send_ctr, .next = send_next },
                .recv = .{ .ctr = recv_ctr, .next = recv_next },
            });
        }
        return .{
            .chain = .{
                .dir = dir,
                .current_epoch = current_epoch,
                .send_epoch = send_epoch,
                .links = links,
                .next_root = next_root,
                .max_jump = DEFAULT_MAX_JUMP,
            },
            .consumed = pos,
        };
    }
};
