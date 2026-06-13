// Serializes to/from protobuf SessionStructure.
const std = @import("std");
const curve = @import("../curve.zig");
const identity = @import("../identity.zig");
const proto = @import("../proto.zig");
const err = @import("../error.zig");
const ratchet_root = @import("../ratchet/root_key.zig");
const ratchet_chain = @import("../ratchet/chain_key.zig");
const ratchet_msg = @import("../ratchet/message_keys.zig");
const mem = std.mem;

pub const MAX_FORWARD_JUMPS: usize = 25_000;
pub const MAX_MESSAGE_KEYS: usize = 2000;
pub const MAX_RECEIVER_CHAINS: usize = 5;
pub const SESSION_VERSION: u32 = 4;

pub const SkippedMessageKey = struct {
    ratchet_key: [curve.PUBLIC_KEY_LENGTH]u8,
    counter: u32,
    keys: ratchet_msg.MessageKeys,
};

pub const ReceiverChain = struct {
    ratchet_key: curve.PublicKey,
    chain_key: ratchet_chain.ChainKey,
    message_keys: std.ArrayList(SkippedMessageKey),
    allocator: mem.Allocator,

    pub fn init(
        allocator: mem.Allocator,
        ratchet_key: curve.PublicKey,
        chain_key: ratchet_chain.ChainKey,
    ) ReceiverChain {
        return .{
            .ratchet_key = ratchet_key,
            .chain_key = chain_key,
            .message_keys = .empty,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *ReceiverChain) void {
        self.message_keys.deinit(self.allocator);
    }
};

pub const PendingPreKey = struct {
    pre_key_id: ?u32,
    signed_pre_key_id: u32,
    base_key: curve.PublicKey,
    timestamp: u64,
};

pub const PendingKyberPreKey = struct {
    pre_key_id: u32,
    ciphertext: []u8,
};

pub const SessionState = struct {
    session_version: u32,

    local_identity_key: identity.IdentityKey,
    remote_identity_key: identity.IdentityKey,

    root_key: ratchet_root.RootKey,
    previous_counter: u32,

    sender_chain_key: ratchet_chain.ChainKey,
    sender_ratchet_key_pair: curve.KeyPair,

    receiver_chains: std.ArrayList(ReceiverChain),

    pending_pre_key: ?PendingPreKey,
    pending_kyber_pre_key: ?struct { pre_key_id: u32, ciphertext: []u8 },

    remote_registration_id: u32,
    local_registration_id: u32,

    alice_base_key: ?[curve.SERIALIZED_PUBLIC_KEY_LENGTH]u8,

    pq_ratchet_state: []u8, // SPQR serialized state; empty = V0 (no-op)

    allocator: mem.Allocator,

    pub fn init(allocator: mem.Allocator) !SessionState {
        const zero_kp = try curve.KeyPair.generate();
        const zero_ik = identity.IdentityKey.fromPublicKey(zero_kp.public_key);
        return SessionState{
            .session_version = SESSION_VERSION,
            .local_identity_key = zero_ik,
            .remote_identity_key = zero_ik,
            .root_key = .{ .key = std.mem.zeroes([32]u8) },
            .previous_counter = 0,
            .sender_chain_key = ratchet_chain.ChainKey.init(std.mem.zeroes([32]u8), 0),
            .sender_ratchet_key_pair = zero_kp,
            .receiver_chains = .empty,
            .pending_pre_key = null,
            .pending_kyber_pre_key = null,
            .remote_registration_id = 0,
            .local_registration_id = 0,
            .alice_base_key = null,
            .pq_ratchet_state = &[_]u8{},
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *SessionState) void {
        for (self.receiver_chains.items) |*rc| rc.deinit();
        self.receiver_chains.deinit(self.allocator);
        if (self.pending_kyber_pre_key) |*pkpk| {
            self.allocator.free(pkpk.ciphertext);
        }
        if (self.pq_ratchet_state.len > 0) {
            self.allocator.free(self.pq_ratchet_state);
        }
    }

    pub fn aliceBaseKey(self: SessionState) ?[curve.SERIALIZED_PUBLIC_KEY_LENGTH]u8 {
        return self.alice_base_key;
    }

    pub fn remoteRegistrationId(self: SessionState) u32 {
        return self.remote_registration_id;
    }

    pub fn localRegistrationId(self: SessionState) u32 {
        return self.local_registration_id;
    }

    pub fn sessionVersion(self: SessionState) u32 {
        return self.session_version;
    }

    pub fn senderRatchetKey(self: SessionState) curve.PublicKey {
        return self.sender_ratchet_key_pair.public_key;
    }

    pub fn hasUsableSenderChain(self: SessionState) bool {
        return self.session_version >= 3;
    }

    pub fn currentRatchetKeyMatchesSenderChain(self: SessionState, ratchet_key: curve.PublicKey) bool {
        return self.sender_ratchet_key_pair.public_key.eql(ratchet_key);
    }

    pub fn addReceiverChain(
        self: *SessionState,
        ratchet_key: curve.PublicKey,
        chain_key: ratchet_chain.ChainKey,
    ) !void {
        const rc = ReceiverChain.init(self.allocator, ratchet_key, chain_key);
        try self.receiver_chains.append(self.allocator, rc);
        if (self.receiver_chains.items.len > MAX_RECEIVER_CHAINS) {
            var old = self.receiver_chains.orderedRemove(0);
            old.deinit();
        }
    }

    pub fn findReceiverChain(
        self: *SessionState,
        their_ephemeral: curve.PublicKey,
    ) ?*ReceiverChain {
        for (self.receiver_chains.items) |*rc| {
            if (rc.ratchet_key.eql(their_ephemeral)) return rc;
        }
        return null;
    }

    /// Get or compute message keys for a given counter in a receiver chain.
    pub fn getOrComputeMessageKeys(
        self: *SessionState,
        ratchet_key: curve.PublicKey,
        counter: u32,
        pqr_key: ?[32]u8,
    ) !?ratchet_msg.MessageKeys {
        const rc = self.findReceiverChain(ratchet_key) orelse return null;

        // Check skipped cache first (pre-computed without SPQR key)
        for (rc.message_keys.items, 0..) |mk, i| {
            if (mk.counter == counter and
                std.mem.eql(u8, &mk.ratchet_key, &ratchet_key.key_bytes))
            {
                const keys = mk.keys;
                _ = rc.message_keys.swapRemove(i);
                return keys;
            }
        }

        if (rc.chain_key.index > counter) return err.SignalError.DuplicateMessage;

        if (counter - rc.chain_key.index > MAX_FORWARD_JUMPS) {
            return err.SignalError.InvalidMessage;
        }

        // Advance chain key, caching skipped message keys (null pqr_key for cache)
        while (rc.chain_key.index < counter) {
            const mk = rc.chain_key.messageKeys(null);
            try rc.message_keys.append(rc.allocator, .{
                .ratchet_key = ratchet_key.key_bytes,
                .counter = rc.chain_key.index,
                .keys = mk,
            });
            if (rc.message_keys.items.len > MAX_MESSAGE_KEYS) {
                _ = rc.message_keys.orderedRemove(0);
            }
            rc.chain_key = rc.chain_key.advance();
        }

        const result = rc.chain_key.messageKeys(pqr_key);
        rc.chain_key = rc.chain_key.advance();
        return result;
    }

    // --- Protobuf serialization ---

    pub fn serialize(self: SessionState, allocator: mem.Allocator) ![]u8 {
        var enc = proto.Encoder.init(allocator);
        defer enc.deinit();

        try enc.writeVarintField(1, self.session_version);
        const lik_bytes = self.local_identity_key.serialize();
        try enc.writeBytesField(2, &lik_bytes);
        const rik_bytes = self.remote_identity_key.serialize();
        try enc.writeBytesField(3, &rik_bytes);
        try enc.writeBytesField(4, &self.root_key.key);
        try enc.writeVarintField(5, self.previous_counter);

        // Sender chain (field 6): encode as nested message
        {
            var chain_enc = proto.Encoder.init(allocator);
            defer chain_enc.deinit();
            const srk_bytes = self.sender_ratchet_key_pair.public_key.serialize();
            try chain_enc.writeBytesField(1, &srk_bytes);
            const srk_priv_bytes = self.sender_ratchet_key_pair.private_key.serialize();
            try chain_enc.writeBytesField(2, &srk_priv_bytes);
            // Chain key sub-message (field 3)
            {
                var ck_enc = proto.Encoder.init(allocator);
                defer ck_enc.deinit();
                try ck_enc.writeVarintField(1, self.sender_chain_key.index);
                try ck_enc.writeBytesField(2, &self.sender_chain_key.key);
                const ck_bytes = try ck_enc.toOwnedSlice();
                defer allocator.free(ck_bytes);
                try chain_enc.writeBytesField(3, ck_bytes);
            }
            const chain_bytes = try chain_enc.toOwnedSlice();
            defer allocator.free(chain_bytes);
            try enc.writeBytesField(6, chain_bytes);
        }

        // Receiver chains (field 7)
        for (self.receiver_chains.items) |rc| {
            var rc_enc = proto.Encoder.init(allocator);
            defer rc_enc.deinit();
            const rk_bytes = rc.ratchet_key.serialize();
            try rc_enc.writeBytesField(1, &rk_bytes);
            {
                var ck_enc = proto.Encoder.init(allocator);
                defer ck_enc.deinit();
                try ck_enc.writeVarintField(1, rc.chain_key.index);
                try ck_enc.writeBytesField(2, &rc.chain_key.key);
                const ck_bytes = try ck_enc.toOwnedSlice();
                defer allocator.free(ck_bytes);
                try rc_enc.writeBytesField(3, ck_bytes);
            }
            const rc_bytes = try rc_enc.toOwnedSlice();
            defer allocator.free(rc_bytes);
            try enc.writeBytesField(7, rc_bytes);
        }

        try enc.writeVarintField(10, self.remote_registration_id);
        try enc.writeVarintField(11, self.local_registration_id);

        if (self.pending_pre_key) |ppk| {
            var ppk_enc = proto.Encoder.init(allocator);
            defer ppk_enc.deinit();
            if (ppk.pre_key_id) |pkid| try ppk_enc.writeVarintField(1, pkid);
            const bk_bytes = ppk.base_key.serialize();
            try ppk_enc.writeBytesField(2, &bk_bytes);
            try ppk_enc.writeVarintField(3, ppk.signed_pre_key_id);
            try ppk_enc.writeFixed64Field(4, ppk.timestamp);
            const ppk_bytes = try ppk_enc.toOwnedSlice();
            defer allocator.free(ppk_bytes);
            try enc.writeBytesField(9, ppk_bytes);
        }

        if (self.alice_base_key) |abk| {
            try enc.writeBytesField(13, &abk);
        }

        if (self.pq_ratchet_state.len > 0) {
            try enc.writeBytesField(15, self.pq_ratchet_state);
        }

        if (self.pending_kyber_pre_key) |pkpk| {
            var kpk_enc = proto.Encoder.init(allocator);
            defer kpk_enc.deinit();
            try kpk_enc.writeVarintField(1, pkpk.pre_key_id);
            try kpk_enc.writeBytesField(2, pkpk.ciphertext);
            const kpk_bytes = try kpk_enc.toOwnedSlice();
            defer allocator.free(kpk_bytes);
            try enc.writeBytesField(14, kpk_bytes);
        }

        return enc.toOwnedSlice();
    }

    pub fn deserialize(allocator: mem.Allocator, data: []const u8) !SessionState {
        var ss = try init(allocator);
        errdefer ss.deinit();

        var pos: usize = 0;
        while (try proto.nextField(data, &pos)) |field| {
            switch (field.number) {
                1 => {
                    if (field.wire_type == .varint) ss.session_version = @intCast(field.data.varint);
                },
                2 => if (field.wire_type == .len) {
                    const ik = try identity.IdentityKey.deserialize(field.data.len);
                    ss.local_identity_key = ik;
                },
                3 => if (field.wire_type == .len) {
                    const ik = try identity.IdentityKey.deserialize(field.data.len);
                    ss.remote_identity_key = ik;
                },
                4 => if (field.wire_type == .len and field.data.len.len == 32) {
                    @memcpy(&ss.root_key.key, field.data.len);
                },
                5 => {
                    if (field.wire_type == .varint) ss.previous_counter = @intCast(field.data.varint);
                },
                6 => if (field.wire_type == .len) try parseSenderChain(&ss, field.data.len),
                7 => if (field.wire_type == .len) try parseReceiverChain(&ss, field.data.len),
                10 => {
                    if (field.wire_type == .varint) ss.remote_registration_id = @intCast(field.data.varint);
                },
                11 => {
                    if (field.wire_type == .varint) ss.local_registration_id = @intCast(field.data.varint);
                },
                9 => if (field.wire_type == .len) try parsePendingPreKey(&ss, field.data.len),
                13 => if (field.wire_type == .len and field.data.len.len == curve.SERIALIZED_PUBLIC_KEY_LENGTH) {
                    ss.alice_base_key = field.data.len[0..curve.SERIALIZED_PUBLIC_KEY_LENGTH].*;
                },
                14 => if (field.wire_type == .len) try parsePendingKyberPreKey(&ss, allocator, field.data.len),
                15 => if (field.wire_type == .len) {
                    if (ss.pq_ratchet_state.len > 0) allocator.free(ss.pq_ratchet_state);
                    ss.pq_ratchet_state = try allocator.dupe(u8, field.data.len);
                },
                else => {},
            }
        }
        return ss;
    }

    fn parseSenderChain(ss: *SessionState, data: []const u8) !void {
        var pos: usize = 0;
        var rk_bytes: ?[]const u8 = null;
        var rk_priv_bytes: ?[]const u8 = null;
        var ck_key: [32]u8 = std.mem.zeroes([32]u8);
        var ck_index: u32 = 0;

        while (try proto.nextField(data, &pos)) |field| {
            switch (field.number) {
                1 => {
                    if (field.wire_type == .len) rk_bytes = field.data.len;
                },
                2 => {
                    if (field.wire_type == .len) rk_priv_bytes = field.data.len;
                },
                3 => if (field.wire_type == .len) {
                    var ck_pos: usize = 0;
                    while (try proto.nextField(field.data.len, &ck_pos)) |ckf| {
                        switch (ckf.number) {
                            1 => {
                                if (ckf.wire_type == .varint) ck_index = @intCast(ckf.data.varint);
                            },
                            2 => if (ckf.wire_type == .len and ckf.data.len.len == 32) {
                                @memcpy(&ck_key, ckf.data.len);
                            },
                            else => {},
                        }
                    }
                },
                else => {},
            }
        }
        if (rk_bytes) |rkb| ss.sender_ratchet_key_pair.public_key = try curve.PublicKey.deserialize(rkb);
        if (rk_priv_bytes) |rkpb| ss.sender_ratchet_key_pair.private_key = try curve.PrivateKey.deserialize(rkpb);
        ss.sender_chain_key = ratchet_chain.ChainKey.init(ck_key, ck_index);
    }

    fn parseReceiverChain(ss: *SessionState, data: []const u8) !void {
        var pos: usize = 0;
        var rk_bytes: ?[]const u8 = null;
        var ck_key: [32]u8 = std.mem.zeroes([32]u8);
        var ck_index: u32 = 0;

        while (try proto.nextField(data, &pos)) |field| {
            switch (field.number) {
                1 => {
                    if (field.wire_type == .len) rk_bytes = field.data.len;
                },
                3 => if (field.wire_type == .len) {
                    var ck_pos: usize = 0;
                    while (try proto.nextField(field.data.len, &ck_pos)) |ckf| {
                        switch (ckf.number) {
                            1 => {
                                if (ckf.wire_type == .varint) ck_index = @intCast(ckf.data.varint);
                            },
                            2 => if (ckf.wire_type == .len and ckf.data.len.len == 32) {
                                @memcpy(&ck_key, ckf.data.len);
                            },
                            else => {},
                        }
                    }
                },
                else => {},
            }
        }
        const rk = try curve.PublicKey.deserialize(rk_bytes orelse return err.SignalError.InvalidSession);
        const rc = ReceiverChain.init(ss.allocator, rk, ratchet_chain.ChainKey.init(ck_key, ck_index));
        try ss.receiver_chains.append(ss.allocator, rc);
    }

    fn parsePendingPreKey(ss: *SessionState, data: []const u8) !void {
        var pos: usize = 0;
        var pre_key_id: ?u32 = null;
        var bk_bytes: ?[]const u8 = null;
        var spk_id: u32 = 0;
        var ts: u64 = 0;

        while (try proto.nextField(data, &pos)) |field| {
            switch (field.number) {
                1 => {
                    if (field.wire_type == .varint) pre_key_id = @intCast(field.data.varint);
                },
                2 => {
                    if (field.wire_type == .len) bk_bytes = field.data.len;
                },
                3 => {
                    if (field.wire_type == .varint) spk_id = @intCast(field.data.varint);
                },
                4 => {
                    if (field.wire_type == .i64) ts = field.data.i64;
                },
                else => {},
            }
        }
        const bk = try curve.PublicKey.deserialize(bk_bytes orelse return);
        ss.pending_pre_key = .{
            .pre_key_id = pre_key_id,
            .signed_pre_key_id = spk_id,
            .base_key = bk,
            .timestamp = ts,
        };
    }

    fn parsePendingKyberPreKey(ss: *SessionState, allocator: mem.Allocator, data: []const u8) !void {
        var pos: usize = 0;
        var kpk_id: u32 = 0;
        var ct_bytes: ?[]const u8 = null;

        while (try proto.nextField(data, &pos)) |field| {
            switch (field.number) {
                1 => {
                    if (field.wire_type == .varint) kpk_id = @intCast(field.data.varint);
                },
                2 => {
                    if (field.wire_type == .len) ct_bytes = field.data.len;
                },
                else => {},
            }
        }
        const ct = ct_bytes orelse return;
        const ct_copy = try allocator.dupe(u8, ct);
        ss.pending_kyber_pre_key = .{ .pre_key_id = kpk_id, .ciphertext = ct_copy };
    }
};
