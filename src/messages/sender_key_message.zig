// SenderKeyMessage: group message encrypted with sender keys.
// Wire format: [version_byte][protobuf_body][64-byte signature]
const std = @import("std");
const curve = @import("../curve.zig");
const proto = @import("../proto.zig");
const err = @import("../error.zig");
const mem = std.mem;

pub const MESSAGE_VERSION: u8 = 3;
pub const VERSION_BYTE: u8 = (MESSAGE_VERSION << 4) | MESSAGE_VERSION;
pub const SIGNATURE_LENGTH = curve.SIGNATURE_LENGTH;

pub const SenderKeyMessage = struct {
    distribution_uuid: [16]u8,
    chain_id: u32,
    iteration: u32,
    ciphertext: []const u8,
    allocator: mem.Allocator,

    pub fn deinit(self: *SenderKeyMessage) void {
        self.allocator.free(self.ciphertext);
    }

    pub fn serialize(self: SenderKeyMessage, signing_key: curve.PrivateKey) ![]u8 {
        const allocator = self.allocator;
        var enc = proto.Encoder.init(allocator);
        defer enc.deinit();
        try enc.writeBytesField(1, &self.distribution_uuid);
        try enc.writeVarintField(2, self.chain_id);
        try enc.writeVarintField(3, self.iteration);
        try enc.writeBytesField(4, self.ciphertext);
        const body = try enc.toOwnedSlice();
        defer allocator.free(body);

        const msg_bytes_len = 1 + body.len;
        const out = try allocator.alloc(u8, msg_bytes_len + SIGNATURE_LENGTH);
        errdefer allocator.free(out);
        out[0] = VERSION_BYTE;
        @memcpy(out[1..msg_bytes_len], body);

        const sig = try signing_key.calculateSignature(out[0..msg_bytes_len]);
        @memcpy(out[msg_bytes_len..], &sig);

        return out;
    }

    pub fn deserializeAndVerify(
        allocator: mem.Allocator,
        data: []const u8,
        sender_key: curve.PublicKey,
    ) !SenderKeyMessage {
        if (data.len < 1 + SIGNATURE_LENGTH) return err.SignalError.InvalidMessage;

        const version_byte = data[0];
        const message_version = version_byte >> 4;
        if (message_version < 3) return err.SignalError.LegacyCiphertextVersion;

        const sig_start = data.len - SIGNATURE_LENGTH;
        const sig_bytes = data[sig_start..][0..SIGNATURE_LENGTH].*;
        const signed_part = data[0..sig_start];

        const valid = try sender_key.verifySignature(signed_part, sig_bytes);
        if (!valid) return err.SignalError.InvalidSignature;

        const body = data[1..sig_start];
        return deserializeBody(allocator, body);
    }

    fn deserializeBody(allocator: mem.Allocator, body: []const u8) !SenderKeyMessage {
        var pos: usize = 0;
        var uuid: [16]u8 = undefined;
        var chain_id: u32 = 0;
        var iteration: u32 = 0;
        var ciphertext_raw: ?[]const u8 = null;
        var has_uuid = false;

        while (try proto.nextField(body, &pos)) |field| {
            switch (field.number) {
                1 => if (field.wire_type == .len) {
                    if (field.data.len.len == 16) {
                        @memcpy(&uuid, field.data.len);
                        has_uuid = true;
                    }
                },
                2 => {
                    if (field.wire_type == .varint) chain_id = @intCast(field.data.varint);
                },
                3 => {
                    if (field.wire_type == .varint) iteration = @intCast(field.data.varint);
                },
                4 => {
                    if (field.wire_type == .len) ciphertext_raw = field.data.len;
                },
                else => {},
            }
        }
        if (!has_uuid) return err.SignalError.InvalidMessage;
        const ct = ciphertext_raw orelse return err.SignalError.InvalidMessage;
        return .{
            .distribution_uuid = uuid,
            .chain_id = chain_id,
            .iteration = iteration,
            .ciphertext = try allocator.dupe(u8, ct),
            .allocator = allocator,
        };
    }
};
