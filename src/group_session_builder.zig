// GroupSessionBuilder: manages sender keys for group messaging.
const std = @import("std");
const address_mod = @import("address.zig");
const curve = @import("curve.zig");
const storage = @import("storage.zig");
const proto = @import("proto.zig");
const kdf = @import("kdf.zig");
const rnd = @import("random.zig");
const skdm_mod = @import("messages/sender_key_distribution_message.zig");
const err = @import("error.zig");
const mem = std.mem;

pub const SenderKeyStateRecord = struct {
    message_version: u32,
    chain_id: u32,
    chain_key: [32]u8,
    iteration: u32,
    signing_key_pair: curve.KeyPair,
    distribution_uuid: [16]u8,

    pub fn serialize(self: SenderKeyStateRecord, allocator: mem.Allocator) ![]u8 {
        var enc = proto.Encoder.init(allocator);
        defer enc.deinit();
        try enc.writeVarintField(5, self.message_version);
        try enc.writeVarintField(1, self.chain_id);
        {
            var ck_enc = proto.Encoder.init(allocator);
            defer ck_enc.deinit();
            try ck_enc.writeVarintField(1, self.iteration);
            try ck_enc.writeBytesField(2, &self.chain_key);
            const ck_bytes = try ck_enc.toOwnedSlice();
            defer allocator.free(ck_bytes);
            try enc.writeBytesField(2, ck_bytes);
        }
        {
            var sk_enc = proto.Encoder.init(allocator);
            defer sk_enc.deinit();
            const pk_bytes = self.signing_key_pair.public_key.serialize();
            try sk_enc.writeBytesField(1, &pk_bytes);
            const sk_bytes_raw = self.signing_key_pair.private_key.serialize();
            try sk_enc.writeBytesField(2, &sk_bytes_raw);
            const sk_bytes = try sk_enc.toOwnedSlice();
            defer allocator.free(sk_bytes);
            try enc.writeBytesField(3, sk_bytes);
        }
        try enc.writeBytesField(4, &self.distribution_uuid);
        return enc.toOwnedSlice();
    }

    pub fn deserialize(data: []const u8) !SenderKeyStateRecord {
        var pos: usize = 0;
        var msg_ver: u32 = 3;
        var chain_id: u32 = 0;
        var chain_key: [32]u8 = std.mem.zeroes([32]u8);
        var iteration: u32 = 0;
        var pk_bytes: ?[]const u8 = null;
        var sk_bytes_raw: ?[]const u8 = null;
        var dist_uuid: [16]u8 = std.mem.zeroes([16]u8);

        while (try proto.nextField(data, &pos)) |field| {
            switch (field.number) {
                5 => {
                    if (field.wire_type == .varint) msg_ver = @intCast(field.data.varint);
                },
                1 => {
                    if (field.wire_type == .varint) chain_id = @intCast(field.data.varint);
                },
                2 => if (field.wire_type == .len) {
                    var ck_pos: usize = 0;
                    while (try proto.nextField(field.data.len, &ck_pos)) |ckf| {
                        switch (ckf.number) {
                            1 => {
                                if (ckf.wire_type == .varint) iteration = @intCast(ckf.data.varint);
                            },
                            2 => if (ckf.wire_type == .len and ckf.data.len.len == 32) {
                                @memcpy(&chain_key, ckf.data.len);
                            },
                            else => {},
                        }
                    }
                },
                3 => if (field.wire_type == .len) {
                    var sk_pos: usize = 0;
                    while (try proto.nextField(field.data.len, &sk_pos)) |skf| {
                        switch (skf.number) {
                            1 => {
                                if (skf.wire_type == .len) pk_bytes = skf.data.len;
                            },
                            2 => {
                                if (skf.wire_type == .len) sk_bytes_raw = skf.data.len;
                            },
                            else => {},
                        }
                    }
                },
                4 => if (field.wire_type == .len and field.data.len.len == 16) {
                    @memcpy(&dist_uuid, field.data.len);
                },
                else => {},
            }
        }
        const pk = try curve.PublicKey.deserialize(pk_bytes orelse return err.SignalError.InvalidArgument);
        const sk = try curve.PrivateKey.deserialize(sk_bytes_raw orelse return err.SignalError.InvalidArgument);
        return .{
            .message_version = msg_ver,
            .chain_id = chain_id,
            .chain_key = chain_key,
            .iteration = iteration,
            .signing_key_pair = .{ .public_key = pk, .private_key = sk },
            .distribution_uuid = dist_uuid,
        };
    }
};

pub const GroupSessionBuilder = struct {
    sender_key_store: storage.SenderKeyStore,
    allocator: mem.Allocator,

    pub fn init(allocator: mem.Allocator, sender_key_store: storage.SenderKeyStore) GroupSessionBuilder {
        return .{ .sender_key_store = sender_key_store, .allocator = allocator };
    }

    /// Create or retrieve the SenderKeyDistributionMessage for a sender + distribution_id.
    /// The distribution_id is the caller-assigned UUID that identifies this group session.
    pub fn createSession(
        self: *GroupSessionBuilder,
        sender: *const address_mod.ProtocolAddress,
        distribution_id: [16]u8,
    ) !skdm_mod.SenderKeyDistributionMessage {
        const existing = try self.sender_key_store.loadSenderKey(sender, distribution_id);

        if (existing) |record_bytes| {
            defer self.allocator.free(record_bytes);
            const state = SenderKeyStateRecord.deserialize(record_bytes) catch null;
            if (state) |s| {
                return skdm_mod.SenderKeyDistributionMessage.new(
                    self.allocator,
                    s.distribution_uuid,
                    s.chain_id,
                    s.iteration,
                    s.chain_key,
                    s.signing_key_pair.public_key,
                );
            }
        }

        // Generate new sender key state
        const chain_id = std.mem.readInt(u32, distribution_id[0..4], .little);
        var chain_key: [32]u8 = undefined;
        rnd.bytes(&chain_key);
        const signing_kp = try curve.KeyPair.generate();

        const state = SenderKeyStateRecord{
            .message_version = 3,
            .chain_id = chain_id,
            .chain_key = chain_key,
            .iteration = 0,
            .signing_key_pair = signing_kp,
            .distribution_uuid = distribution_id,
        };

        const record_bytes = try state.serialize(self.allocator);
        defer self.allocator.free(record_bytes);
        try self.sender_key_store.storeSenderKey(sender, distribution_id, record_bytes);

        return skdm_mod.SenderKeyDistributionMessage.new(
            self.allocator,
            distribution_id,
            chain_id,
            0,
            chain_key,
            signing_kp.public_key,
        );
    }

    /// Process a received SenderKeyDistributionMessage and store the sender key.
    pub fn processSession(
        self: *GroupSessionBuilder,
        sender: *const address_mod.ProtocolAddress,
        distribution_msg: *const skdm_mod.SenderKeyDistributionMessage,
    ) !void {
        const state = SenderKeyStateRecord{
            .message_version = 3,
            .chain_id = distribution_msg.chain_id,
            .chain_key = distribution_msg.chain_key,
            .iteration = distribution_msg.iteration,
            .signing_key_pair = .{
                .public_key = distribution_msg.signing_key,
                .private_key = curve.PrivateKey.fromBytes(std.mem.zeroes([32]u8)),
            },
            .distribution_uuid = distribution_msg.distribution_uuid,
        };

        const record_bytes = try state.serialize(self.allocator);
        defer self.allocator.free(record_bytes);
        try self.sender_key_store.storeSenderKey(sender, distribution_msg.distribution_uuid, record_bytes);
    }
};
