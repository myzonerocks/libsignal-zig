// SignalMessage (WhisperMessage) — the regular Double Ratchet encrypted message.
// Wire format: [version_byte][protobuf_body][8-byte MAC]
const std = @import("std");
const curve = @import("../curve.zig");
const proto = @import("../proto.zig");
const err = @import("../error.zig");
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const mem = std.mem;

pub const CURRENT_VERSION: u8 = 4; // PQXDH + SPQR
pub const MAC_LENGTH: usize = 8;

pub const SignalMessage = struct {
    message_version: u8,
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
    /// Version byte: (session_version << 4) | CURRENT_VERSION.
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
            if (pqr.len > 0) try enc.writeBytesField(5, pqr);
        }

        const body = try enc.toOwnedSlice();
        defer allocator.free(body);

        const total_len = 1 + body.len + MAC_LENGTH;
        const out = try allocator.alloc(u8, total_len);

        // High nibble = session version, low nibble = current wire format version.
        out[0] = ((self.message_version & 0xF) << 4) | CURRENT_VERSION;
        @memcpy(out[1 .. 1 + body.len], body);

        var mac_engine = HmacSha256.init(&mac_key);
        mac_engine.update(&sender_identity);
        mac_engine.update(&receiver_identity);
        mac_engine.update(out[0 .. 1 + body.len]);
        var mac: [32]u8 = undefined;
        mac_engine.final(&mac);
        @memcpy(out[1 + body.len ..], mac[0..MAC_LENGTH]);

        return out;
    }
};
