// SignalMessage (WhisperMessage) — the regular Double Ratchet encrypted message.
// Wire format: [version_byte][protobuf_body][8-byte MAC]
const std = @import("std");
const curve = @import("../curve.zig");
const proto = @import("../proto.zig");
const err = @import("../error.zig");
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const mem = std.mem;

pub const MESSAGE_VERSION: u8 = 3;
pub const VERSION_BYTE: u8 = (MESSAGE_VERSION << 4) | MESSAGE_VERSION;
pub const MAC_LENGTH: usize = 8;

pub const SignalMessage = struct {
    ratchet_key: curve.PublicKey,
    counter: u32,
    previous_counter: u32,
    ciphertext: []const u8,
    pq_ratchet: ?[]const u8,
    allocator: mem.Allocator,

    pub fn deinit(self: *SignalMessage) void {
        self.allocator.free(self.ciphertext);
        if (self.pq_ratchet) |pqr| self.allocator.free(pqr);
    }

    /// Serialize + authenticate.
    /// sender/receiver identity keys are used for the MAC computation.
    pub fn serialize(
        self: SignalMessage,
        sender_identity: [curve.SERIALIZED_PUBLIC_KEY_LENGTH]u8,
        receiver_identity: [curve.SERIALIZED_PUBLIC_KEY_LENGTH]u8,
        mac_key: [32]u8,
    ) ![]u8 {
        const allocator = self.allocator;

        var enc = proto.Encoder.init(allocator);
        defer enc.deinit();

        const rk_bytes = self.ratchet_key.serialize();
        try enc.writeBytesField(1, &rk_bytes);
        try enc.writeVarintField(2, self.counter);
        try enc.writeVarintField(3, self.previous_counter);
        try enc.writeBytesField(4, self.ciphertext);
        if (self.pq_ratchet) |pqr| {
            try enc.writeBytesField(5, pqr);
        }

        const body = try enc.toOwnedSlice();
        defer allocator.free(body);

        const total_len = 1 + body.len + MAC_LENGTH;
        const out = try allocator.alloc(u8, total_len);

        out[0] = VERSION_BYTE;
        @memcpy(out[1 .. 1 + body.len], body);

        // MAC = HMAC-SHA256(mac_key, sender_id || receiver_id || version_byte || body)[0..8]
        var mac_engine = HmacSha256.init(&mac_key);
        mac_engine.update(&sender_identity);
        mac_engine.update(&receiver_identity);
        mac_engine.update(out[0 .. 1 + body.len]);
        var mac: [32]u8 = undefined;
        mac_engine.final(&mac);
        @memcpy(out[1 + body.len ..], mac[0..MAC_LENGTH]);

        return out;
    }

    /// Deserialize and verify MAC.
    pub fn deserializeAndVerify(
        allocator: mem.Allocator,
        data: []const u8,
        sender_identity: [curve.SERIALIZED_PUBLIC_KEY_LENGTH]u8,
        receiver_identity: [curve.SERIALIZED_PUBLIC_KEY_LENGTH]u8,
        mac_key: [32]u8,
    ) !SignalMessage {
        if (data.len < 1 + MAC_LENGTH) return err.SignalError.InvalidMessage;

        const version_byte = data[0];
        const message_version = version_byte >> 4;
        if (message_version < 3) return err.SignalError.LegacyCiphertextVersion;
        if (message_version > MESSAGE_VERSION) return err.SignalError.UnknownCiphertextVersion;

        const mac_start = data.len - MAC_LENGTH;
        const body_with_version = data[0..mac_start];
        const mac_received = data[mac_start..][0..MAC_LENGTH];

        // Verify MAC
        var mac_engine = HmacSha256.init(&mac_key);
        mac_engine.update(&sender_identity);
        mac_engine.update(&receiver_identity);
        mac_engine.update(body_with_version);
        var mac_computed: [32]u8 = undefined;
        mac_engine.final(&mac_computed);

        if (!std.mem.eql(u8, mac_received, mac_computed[0..MAC_LENGTH])) {
            return err.SignalError.InvalidMessage;
        }

        return deserialize(allocator, data[1..mac_start]);
    }

    /// Deserialize without MAC verification (for internal use).
    pub fn deserialize(allocator: mem.Allocator, body: []const u8) !SignalMessage {
        var pos: usize = 0;
        var rk_bytes: ?[]const u8 = null;
        var counter: u32 = 0;
        var prev_counter: u32 = 0;
        var ciphertext_raw: ?[]const u8 = null;
        var pq_ratchet_raw: ?[]const u8 = null;

        while (try proto.nextField(body, &pos)) |field| {
            switch (field.number) {
                1 => {
                    if (field.wire_type == .len) rk_bytes = field.data.len;
                },
                2 => {
                    if (field.wire_type == .varint) counter = @intCast(field.data.varint);
                },
                3 => {
                    if (field.wire_type == .varint) prev_counter = @intCast(field.data.varint);
                },
                4 => {
                    if (field.wire_type == .len) ciphertext_raw = field.data.len;
                },
                5 => {
                    if (field.wire_type == .len) pq_ratchet_raw = field.data.len;
                },
                else => {},
            }
        }

        const rk = try curve.PublicKey.deserialize(rk_bytes orelse return err.SignalError.InvalidMessage);
        const ct = ciphertext_raw orelse return err.SignalError.InvalidMessage;

        const ct_copy = try allocator.dupe(u8, ct);
        errdefer allocator.free(ct_copy);

        const pqr_copy = if (pq_ratchet_raw) |pqr| blk: {
            break :blk try allocator.dupe(u8, pqr);
        } else null;

        return .{
            .ratchet_key = rk,
            .counter = counter,
            .previous_counter = prev_counter,
            .ciphertext = ct_copy,
            .pq_ratchet = pqr_copy,
            .allocator = allocator,
        };
    }
};
