const std = @import("std");
const curve = @import("../curve.zig");
const proto = @import("../proto.zig");
const err = @import("../error.zig");
const mem = std.mem;

pub const PreKeyRecord = struct {
    id: u32,
    key_pair: curve.KeyPair,

    pub fn new(id: u32, key_pair: curve.KeyPair) PreKeyRecord {
        return .{ .id = id, .key_pair = key_pair };
    }

    pub fn generate(id: u32) !PreKeyRecord {
        const kp = try curve.KeyPair.generate();
        return .{ .id = id, .key_pair = kp };
    }

    pub fn publicKey(self: PreKeyRecord) curve.PublicKey {
        return self.key_pair.public_key;
    }

    pub fn privateKey(self: PreKeyRecord) curve.PrivateKey {
        return self.key_pair.private_key;
    }

    /// Serialize to protobuf PreKeyRecordStructure:
    /// field 1 (varint): id
    /// field 2 (bytes):  public_key (33 bytes with 0x05 prefix)
    /// field 3 (bytes):  private_key (32 bytes)
    pub fn serialize(self: PreKeyRecord, allocator: mem.Allocator) ![]u8 {
        var enc = proto.Encoder.init(allocator);
        defer enc.deinit();
        try enc.writeVarintField(1, self.id);
        const pk = self.key_pair.public_key.serialize();
        try enc.writeBytesField(2, &pk);
        const sk = self.key_pair.private_key.serialize();
        try enc.writeBytesField(3, &sk);
        return enc.toOwnedSlice();
    }

    pub fn deserialize(bytes: []const u8) !PreKeyRecord {
        var pos: usize = 0;
        var id_val: ?u32 = null;
        var pk_bytes: ?[]const u8 = null;
        var sk_bytes: ?[]const u8 = null;
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
                else => {},
            }
        }
        const id_v = id_val orelse return err.SignalError.InvalidArgument;
        const pk = try curve.PublicKey.deserialize(pk_bytes orelse return err.SignalError.InvalidArgument);
        const sk = try curve.PrivateKey.deserialize(sk_bytes orelse return err.SignalError.InvalidArgument);
        return .{
            .id = id_v,
            .key_pair = .{ .public_key = pk, .private_key = sk },
        };
    }
};
