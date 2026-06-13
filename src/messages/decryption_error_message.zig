// DecryptionErrorMessage: sent when a message cannot be decrypted.
// Enables the sender to retransmit at a known ratchet position.
// Wire format (protobuf):
//   field 1: ratchetKey (bytes)    — the ratchet key at the failed message
//   field 2: timestamp (uint64)    — timestamp of the original message
//   field 3: deviceId (uint32)     — device ID of the sender
const std = @import("std");
const curve = @import("../curve.zig");
const proto = @import("../proto.zig");
const err = @import("../error.zig");
const mem = std.mem;

pub const DecryptionErrorMessage = struct {
    ratchet_key: curve.PublicKey,
    timestamp: u64,
    device_id: u32,

    pub fn new(ratchet_key: curve.PublicKey, timestamp: u64, device_id: u32) DecryptionErrorMessage {
        return .{
            .ratchet_key = ratchet_key,
            .timestamp = timestamp,
            .device_id = device_id,
        };
    }

    pub fn serialize(self: DecryptionErrorMessage, allocator: mem.Allocator) ![]u8 {
        var enc = proto.Encoder.init(allocator);
        defer enc.deinit();
        const rk = self.ratchet_key.serialize();
        try enc.writeBytesField(1, &rk);
        try enc.writeVarintField(2, self.timestamp);
        try enc.writeVarintField(3, self.device_id);
        return enc.toOwnedSlice();
    }

    pub fn deserialize(data: []const u8) !DecryptionErrorMessage {
        var pos: usize = 0;
        var ratchet_key_bytes: ?[]const u8 = null;
        var timestamp: u64 = 0;
        var device_id: u32 = 0;

        while (try proto.nextField(data, &pos)) |field| {
            switch (field.number) {
                1 => {
                    if (field.wire_type == .len) ratchet_key_bytes = field.data.len;
                },
                2 => {
                    if (field.wire_type == .varint) timestamp = field.data.varint;
                },
                3 => {
                    if (field.wire_type == .varint) device_id = @intCast(field.data.varint & 0xFFFF_FFFF);
                },
                else => {},
            }
        }

        const rk = try curve.PublicKey.deserialize(
            ratchet_key_bytes orelse return err.SignalError.InvalidArgument,
        );
        return .{ .ratchet_key = rk, .timestamp = timestamp, .device_id = device_id };
    }
};

/// PlaintextContent wrapper for DecryptionErrorMessage.
/// Wire format: [0x08 version byte] || DecryptionErrorMessage protobuf bytes
pub const PLAINTEXT_CONTENT_VERSION: u8 = 0x08;

pub fn serializePlaintextContent(
    allocator: mem.Allocator,
    msg: DecryptionErrorMessage,
) ![]u8 {
    const inner = try msg.serialize(allocator);
    defer allocator.free(inner);
    const out = try allocator.alloc(u8, 1 + inner.len);
    out[0] = PLAINTEXT_CONTENT_VERSION;
    @memcpy(out[1..], inner);
    return out;
}

pub fn deserializePlaintextContent(data: []const u8) !DecryptionErrorMessage {
    if (data.len < 1) return err.SignalError.InvalidMessage;
    if (data[0] != PLAINTEXT_CONTENT_VERSION) return err.SignalError.InvalidVersion;
    return DecryptionErrorMessage.deserialize(data[1..]);
}

test "DecryptionErrorMessage roundtrip" {
    const kp = try curve.KeyPair.generate();
    const msg = DecryptionErrorMessage.new(kp.public_key, 1700000000, 1);
    const bytes = try msg.serialize(std.testing.allocator);
    defer std.testing.allocator.free(bytes);
    const restored = try DecryptionErrorMessage.deserialize(bytes);
    try std.testing.expectEqualSlices(u8, &msg.ratchet_key.key_bytes, &restored.ratchet_key.key_bytes);
    try std.testing.expectEqual(msg.timestamp, restored.timestamp);
    try std.testing.expectEqual(msg.device_id, restored.device_id);
}
