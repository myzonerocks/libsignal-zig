const std = @import("std");
const curve = @import("../curve.zig");
const proto = @import("../proto.zig");
const err = @import("../error.zig");
const mem = std.mem;

pub const SignedPreKeyRecord = struct {
    id: u32,
    timestamp: u64,
    key_pair: curve.KeyPair,
    signature: [curve.SIGNATURE_LENGTH]u8,

    pub fn new(
        id: u32,
        timestamp: u64,
        key_pair: curve.KeyPair,
        signature: [curve.SIGNATURE_LENGTH]u8,
    ) SignedPreKeyRecord {
        return .{
            .id = id,
            .timestamp = timestamp,
            .key_pair = key_pair,
            .signature = signature,
        };
    }

    pub fn generate(
        id: u32,
        timestamp: u64,
        identity_private_key: curve.PrivateKey,
    ) !SignedPreKeyRecord {
        const kp = try curve.KeyPair.generate();
        const pk_serialized = kp.public_key.serialize();
        const sig = try identity_private_key.calculateSignature(&pk_serialized);
        return .{
            .id = id,
            .timestamp = timestamp,
            .key_pair = kp,
            .signature = sig,
        };
    }

    pub fn publicKey(self: SignedPreKeyRecord) curve.PublicKey {
        return self.key_pair.public_key;
    }

    pub fn privateKey(self: SignedPreKeyRecord) curve.PrivateKey {
        return self.key_pair.private_key;
    }

    /// Verify signature against the given identity key.
    pub fn verifySignature(self: SignedPreKeyRecord, identity_key: @import("../identity.zig").IdentityKey) !bool {
        const pk_bytes = self.key_pair.public_key.serialize();
        return identity_key.public_key.verifySignature(&pk_bytes, self.signature);
    }

    /// Serialize to protobuf SignedPreKeyRecordStructure:
    /// field 1 (varint):  id
    /// field 2 (bytes):   public_key
    /// field 3 (bytes):   private_key
    /// field 4 (bytes):   signature (64 bytes)
    /// field 5 (fixed64): timestamp
    pub fn serialize(self: SignedPreKeyRecord, allocator: mem.Allocator) ![]u8 {
        var enc = proto.Encoder.init(allocator);
        defer enc.deinit();
        try enc.writeVarintField(1, self.id);
        const pk = self.key_pair.public_key.serialize();
        try enc.writeBytesField(2, &pk);
        const sk = self.key_pair.private_key.serialize();
        try enc.writeBytesField(3, &sk);
        try enc.writeBytesField(4, &self.signature);
        try enc.writeFixed64Field(5, self.timestamp);
        return enc.toOwnedSlice();
    }

    pub fn deserialize(bytes: []const u8) !SignedPreKeyRecord {
        var pos: usize = 0;
        var id_val: ?u32 = null;
        var pk_bytes: ?[]const u8 = null;
        var sk_bytes: ?[]const u8 = null;
        var sig_bytes: ?[]const u8 = null;
        var ts: u64 = 0;
        while (try proto.nextField(bytes, &pos)) |field| {
            switch (field.number) {
                1 => {
                    if (field.wire_type == .varint) id_val = @intCast(field.data.varint);
                },
                2 => {
                    if (field.wire_type == .len) pk_bytes = field.data.len;
                },
                3 => {
                    if (field.wire_type == .len) sk_bytes = field.data.len;
                },
                4 => {
                    if (field.wire_type == .len) sig_bytes = field.data.len;
                },
                5 => {
                    if (field.wire_type == .i64) ts = field.data.i64;
                },
                else => {},
            }
        }
        const id_v = id_val orelse return err.SignalError.InvalidArgument;
        const pk = try curve.PublicKey.deserialize(pk_bytes orelse return err.SignalError.InvalidArgument);
        const sk = try curve.PrivateKey.deserialize(sk_bytes orelse return err.SignalError.InvalidArgument);
        const sig_raw = sig_bytes orelse return err.SignalError.InvalidArgument;
        if (sig_raw.len != 64) return err.SignalError.InvalidSignature;
        return .{
            .id = id_v,
            .timestamp = ts,
            .key_pair = .{ .public_key = pk, .private_key = sk },
            .signature = sig_raw[0..64].*,
        };
    }
};
