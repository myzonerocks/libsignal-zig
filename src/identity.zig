const std = @import("std");
const curve = @import("curve.zig");
const xeddsa = @import("xeddsa.zig");
const proto = @import("proto.zig");
const err = @import("error.zig");
const rnd = @import("random.zig");
const mem = std.mem;

pub const IdentityKey = struct {
    public_key: curve.PublicKey,

    pub fn fromPublicKey(pk: curve.PublicKey) IdentityKey {
        return .{ .public_key = pk };
    }

    pub fn deserialize(bytes: []const u8) !IdentityKey {
        return .{ .public_key = try curve.PublicKey.deserialize(bytes) };
    }

    pub fn serialize(self: IdentityKey) [curve.SERIALIZED_PUBLIC_KEY_LENGTH]u8 {
        return self.public_key.serialize();
    }

    /// Verify that `other_key` signed by this identity is valid per `signature`.
    pub fn verifyAlternateIdentity(
        self: IdentityKey,
        other_key: IdentityKey,
        signature: [64]u8,
    ) !bool {
        const other_serialized = other_key.serialize();
        return self.public_key.verifySignature(&other_serialized, signature);
    }

    pub fn eql(a: IdentityKey, b: IdentityKey) bool {
        return a.public_key.eql(b.public_key);
    }
};

pub const IdentityKeyPair = struct {
    identity_key: IdentityKey,
    private_key: curve.PrivateKey,

    pub fn generate() !IdentityKeyPair {
        const kp = try curve.KeyPair.generate();
        return .{
            .identity_key = .{ .public_key = kp.public_key },
            .private_key = kp.private_key,
        };
    }

    pub fn fromKeyPair(kp: curve.KeyPair) IdentityKeyPair {
        return .{
            .identity_key = .{ .public_key = kp.public_key },
            .private_key = kp.private_key,
        };
    }

    /// Deserialize from protobuf IdentityKeyPairStructure:
    /// field 1 (bytes): public_key
    /// field 2 (bytes): private_key
    pub fn deserialize(allocator: mem.Allocator, bytes: []const u8) !IdentityKeyPair {
        _ = allocator;
        var pos: usize = 0;
        var pk_bytes: ?[]const u8 = null;
        var sk_bytes: ?[]const u8 = null;
        while (try proto.nextField(bytes, &pos)) |field| {
            switch (field.number) {
                1 => {
                    if (field.wire_type == .len) pk_bytes = field.data.len;
                },
                2 => {
                    if (field.wire_type == .len) sk_bytes = field.data.len;
                },
                else => {},
            }
        }
        const pk = pk_bytes orelse return err.SignalError.InvalidArgument;
        const sk = sk_bytes orelse return err.SignalError.InvalidArgument;
        const public_key = try curve.PublicKey.deserialize(pk);
        const private_key = try curve.PrivateKey.deserialize(sk);
        return .{
            .identity_key = .{ .public_key = public_key },
            .private_key = private_key,
        };
    }

    /// Serialize to protobuf IdentityKeyPairStructure.
    pub fn serialize(self: IdentityKeyPair, allocator: mem.Allocator) ![]u8 {
        var enc = proto.Encoder.init(allocator);
        defer enc.deinit();
        const pk_serialized = self.identity_key.serialize();
        try enc.writeBytesField(1, &pk_serialized);
        const sk_serialized = self.private_key.serialize();
        try enc.writeBytesField(2, &sk_serialized);
        return enc.toOwnedSlice();
    }

    /// Sign another identity key for alternate identity attestation.
    pub fn signAlternateIdentity(self: IdentityKeyPair, other_key: IdentityKey) ![64]u8 {
        const other_serialized = other_key.serialize();
        return self.private_key.calculateSignature(&other_serialized);
    }
};

test "identity key pair roundtrip" {
    const ally = std.heap.smp_allocator;
    const kp = try IdentityKeyPair.generate();
    const serialized = try kp.serialize(ally);
    defer ally.free(serialized);
    const restored = try IdentityKeyPair.deserialize(ally, serialized);
    try std.testing.expect(kp.identity_key.eql(restored.identity_key));
}
