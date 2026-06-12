// PreKeySignalMessage: session-initiating message carrying X3DH/PQXDH materials.
// Wire format: [version_byte][protobuf_body]
const std = @import("std");
const curve = @import("../curve.zig");
const proto = @import("../proto.zig");
const err = @import("../error.zig");
const mem = std.mem;

pub const MESSAGE_VERSION: u8 = 3;
pub const VERSION_BYTE: u8 = (MESSAGE_VERSION << 4) | MESSAGE_VERSION;

pub const PreKeySignalMessage = struct {
    message_version: u8,
    registration_id: u32,
    pre_key_id: ?u32,
    signed_pre_key_id: u32,
    kyber_pre_key_id: ?u32,
    base_key: curve.PublicKey,
    identity_key: curve.PublicKey,
    kyber_ciphertext: ?[]const u8,
    message: []const u8, // serialized inner SignalMessage (with version byte + MAC)
    allocator: mem.Allocator,

    pub fn deinit(self: *PreKeySignalMessage) void {
        if (self.kyber_ciphertext) |kc| self.allocator.free(kc);
        self.allocator.free(self.message);
    }

    pub fn serialize(self: PreKeySignalMessage) ![]u8 {
        const allocator = self.allocator;
        var enc = proto.Encoder.init(allocator);
        defer enc.deinit();

        try enc.writeVarintField(5, self.registration_id);
        if (self.pre_key_id) |pkid| try enc.writeVarintField(1, pkid);
        try enc.writeVarintField(6, self.signed_pre_key_id);
        if (self.kyber_pre_key_id) |kpkid| try enc.writeVarintField(7, kpkid);
        if (self.kyber_ciphertext) |kc| try enc.writeBytesField(8, kc);
        const bk_bytes = self.base_key.serialize();
        try enc.writeBytesField(2, &bk_bytes);
        const ik_bytes = self.identity_key.serialize();
        try enc.writeBytesField(3, &ik_bytes);
        try enc.writeBytesField(4, self.message);

        const body = try enc.toOwnedSlice();
        defer allocator.free(body);

        const out = try allocator.alloc(u8, 1 + body.len);
        out[0] = VERSION_BYTE;
        @memcpy(out[1..], body);
        return out;
    }

    pub fn deserialize(allocator: mem.Allocator, data: []const u8) !PreKeySignalMessage {
        if (data.len < 1) return err.SignalError.InvalidMessage;

        const version_byte = data[0];
        const message_version = version_byte >> 4;
        if (message_version < 3) return err.SignalError.LegacyCiphertextVersion;
        if (message_version > MESSAGE_VERSION) return err.SignalError.UnknownCiphertextVersion;

        const body = data[1..];
        var pos: usize = 0;

        var reg_id: u32 = 0;
        var pre_key_id: ?u32 = null;
        var signed_pre_key_id: u32 = 0;
        var kyber_pre_key_id: ?u32 = null;
        var bk_bytes: ?[]const u8 = null;
        var ik_bytes: ?[]const u8 = null;
        var kc_bytes: ?[]const u8 = null;
        var msg_bytes: ?[]const u8 = null;

        while (try proto.nextField(body, &pos)) |field| {
            switch (field.number) {
                5 => {
                    if (field.wire_type == .varint) reg_id = @intCast(field.data.varint);
                },
                1 => {
                    if (field.wire_type == .varint) pre_key_id = @intCast(field.data.varint);
                },
                6 => {
                    if (field.wire_type == .varint) signed_pre_key_id = @intCast(field.data.varint);
                },
                7 => {
                    if (field.wire_type == .varint) kyber_pre_key_id = @intCast(field.data.varint);
                },
                8 => {
                    if (field.wire_type == .len) kc_bytes = field.data.len;
                },
                2 => {
                    if (field.wire_type == .len) bk_bytes = field.data.len;
                },
                3 => {
                    if (field.wire_type == .len) ik_bytes = field.data.len;
                },
                4 => {
                    if (field.wire_type == .len) msg_bytes = field.data.len;
                },
                else => {},
            }
        }

        const base_key = try curve.PublicKey.deserialize(bk_bytes orelse return err.SignalError.InvalidMessage);
        const identity_key = try curve.PublicKey.deserialize(ik_bytes orelse return err.SignalError.InvalidMessage);
        const msg = msg_bytes orelse return err.SignalError.InvalidMessage;

        const msg_copy = try allocator.dupe(u8, msg);
        errdefer allocator.free(msg_copy);

        const kc_copy = if (kc_bytes) |kc| blk: {
            break :blk try allocator.dupe(u8, kc);
        } else null;

        return .{
            .message_version = message_version,
            .registration_id = reg_id,
            .pre_key_id = pre_key_id,
            .signed_pre_key_id = signed_pre_key_id,
            .kyber_pre_key_id = kyber_pre_key_id,
            .base_key = base_key,
            .identity_key = identity_key,
            .kyber_ciphertext = kc_copy,
            .message = msg_copy,
            .allocator = allocator,
        };
    }
};
