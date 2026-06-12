const std = @import("std");
const curve = @import("../curve.zig");
const proto = @import("../proto.zig");
const err = @import("../error.zig");
const mem = std.mem;

pub const KyberPreKeyRecord = struct {
    id: u32,
    timestamp: u64,
    key_pair: curve.KyberKeyPair,
    signature: [curve.SIGNATURE_LENGTH]u8,

    pub fn new(
        id: u32,
        timestamp: u64,
        key_pair: curve.KyberKeyPair,
        signature: [curve.SIGNATURE_LENGTH]u8,
    ) KyberPreKeyRecord {
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
    ) !KyberPreKeyRecord {
        const kp = try curve.KyberKeyPair.generate();
        const sig = try identity_private_key.calculateSignature(&kp.public_key_bytes);
        return .{
            .id = id,
            .timestamp = timestamp,
            .key_pair = kp,
            .signature = sig,
        };
    }

    pub fn publicKey(self: KyberPreKeyRecord) curve.KyberKeyPair {
        return self.key_pair;
    }

    pub fn verifySignature(self: KyberPreKeyRecord, identity_key: @import("../identity.zig").IdentityKey) !bool {
        return identity_key.public_key.verifySignature(&self.key_pair.public_key_bytes, self.signature);
    }

    /// Serialize to protobuf format.
    /// field 1 (varint):  id
    /// field 2 (bytes):   public_key (ML-KEM-1024 public key, 1568 bytes)
    /// field 3 (bytes):   secret_key (ML-KEM-1024 secret key, 3168 bytes)
    /// field 4 (bytes):   signature (64 bytes)
    /// field 5 (fixed64): timestamp
    pub fn serialize(self: KyberPreKeyRecord, allocator: mem.Allocator) ![]u8 {
        var enc = proto.Encoder.init(allocator);
        defer enc.deinit();
        try enc.writeVarintField(1, self.id);
        try enc.writeBytesField(2, &self.key_pair.public_key_bytes);
        try enc.writeBytesField(3, &self.key_pair.secret_key_bytes);
        try enc.writeBytesField(4, &self.signature);
        try enc.writeFixed64Field(5, self.timestamp);
        return enc.toOwnedSlice();
    }

    pub fn deserialize(bytes: []const u8) !KyberPreKeyRecord {
        const MlKem = std.crypto.kem.ml_kem.MLKem1024;
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
        const pk_raw = pk_bytes orelse return err.SignalError.InvalidArgument;
        if (pk_raw.len != MlKem.PublicKey.encoded_length) return err.SignalError.InvalidKey;
        const sk_raw = sk_bytes orelse return err.SignalError.InvalidArgument;
        if (sk_raw.len != MlKem.SecretKey.encoded_length) return err.SignalError.InvalidKey;
        const sig_raw = sig_bytes orelse return err.SignalError.InvalidArgument;
        if (sig_raw.len != 64) return err.SignalError.InvalidSignature;
        return .{
            .id = id_v,
            .timestamp = ts,
            .key_pair = .{
                .public_key_bytes = pk_raw[0..MlKem.PublicKey.encoded_length].*,
                .secret_key_bytes = sk_raw[0..MlKem.SecretKey.encoded_length].*,
            },
            .signature = sig_raw[0..64].*,
        };
    }
};
