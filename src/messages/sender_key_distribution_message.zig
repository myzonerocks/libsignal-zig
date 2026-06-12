// SenderKeyDistributionMessage: distributes sender key chain info for group messaging.
const std = @import("std");
const curve = @import("../curve.zig");
const proto = @import("../proto.zig");
const err = @import("../error.zig");
const mem = std.mem;

pub const MESSAGE_VERSION: u8 = 3;
pub const VERSION_BYTE: u8 = (MESSAGE_VERSION << 4) | MESSAGE_VERSION;

pub const SenderKeyDistributionMessage = struct {
    distribution_uuid: [16]u8,
    chain_id: u32,
    iteration: u32,
    chain_key: [32]u8,
    signing_key: curve.PublicKey,
    allocator: mem.Allocator,

    pub fn new(
        allocator: mem.Allocator,
        distribution_uuid: [16]u8,
        chain_id: u32,
        iteration: u32,
        chain_key: [32]u8,
        signing_key: curve.PublicKey,
    ) SenderKeyDistributionMessage {
        return .{
            .distribution_uuid = distribution_uuid,
            .chain_id = chain_id,
            .iteration = iteration,
            .chain_key = chain_key,
            .signing_key = signing_key,
            .allocator = allocator,
        };
    }

    pub fn deinit(_: *SenderKeyDistributionMessage) void {}

    pub fn serialize(self: SenderKeyDistributionMessage) ![]u8 {
        const allocator = self.allocator;
        var enc = proto.Encoder.init(allocator);
        defer enc.deinit();
        try enc.writeBytesField(1, &self.distribution_uuid);
        try enc.writeVarintField(2, self.chain_id);
        try enc.writeVarintField(3, self.iteration);
        try enc.writeBytesField(4, &self.chain_key);
        const sk_bytes = self.signing_key.serialize();
        try enc.writeBytesField(5, &sk_bytes);
        const body = try enc.toOwnedSlice();
        defer allocator.free(body);

        const out = try allocator.alloc(u8, 1 + body.len);
        out[0] = VERSION_BYTE;
        @memcpy(out[1..], body);
        return out;
    }

    pub fn deserialize(allocator: mem.Allocator, data: []const u8) !SenderKeyDistributionMessage {
        if (data.len < 1) return err.SignalError.InvalidMessage;
        const version = data[0] >> 4;
        if (version < 3) return err.SignalError.LegacyCiphertextVersion;
        const body = data[1..];
        var pos: usize = 0;

        var uuid: [16]u8 = undefined;
        var has_uuid = false;
        var chain_id: u32 = 0;
        var iteration: u32 = 0;
        var chain_key_raw: ?[]const u8 = null;
        var signing_key_raw: ?[]const u8 = null;

        while (try proto.nextField(body, &pos)) |field| {
            switch (field.number) {
                1 => if (field.wire_type == .len and field.data.len.len == 16) {
                    @memcpy(&uuid, field.data.len);
                    has_uuid = true;
                },
                2 => {
                    if (field.wire_type == .varint) chain_id = @intCast(field.data.varint);
                },
                3 => {
                    if (field.wire_type == .varint) iteration = @intCast(field.data.varint);
                },
                4 => {
                    if (field.wire_type == .len) chain_key_raw = field.data.len;
                },
                5 => {
                    if (field.wire_type == .len) signing_key_raw = field.data.len;
                },
                else => {},
            }
        }
        if (!has_uuid) return err.SignalError.InvalidMessage;
        const ck = chain_key_raw orelse return err.SignalError.InvalidMessage;
        if (ck.len != 32) return err.SignalError.InvalidMessage;
        const sk = try curve.PublicKey.deserialize(signing_key_raw orelse return err.SignalError.InvalidMessage);
        return .{
            .distribution_uuid = uuid,
            .chain_id = chain_id,
            .iteration = iteration,
            .chain_key = ck[0..32].*,
            .signing_key = sk,
            .allocator = allocator,
        };
    }
};
