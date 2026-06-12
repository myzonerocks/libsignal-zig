// SPQR V1 state machine: ML-KEM-768 key exchange across chunked messages.
//
// A2B epoch (Alice generates ML-KEM keys):
//   unsampled → hdr_sending → ek_sending → ek_sending_ct1 → waiting_ct2
//
// B2A epoch (Bob encapsulates):
//   waiting_hdr → ct1_sending → ct2_sending → (back to unsampled, role flip)
const std = @import("std");
const mem = std.mem;
const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;

const mlkem = @import("mlkem768_incremental.zig");
const poly = @import("poly_codec.zig");
const msg_mod = @import("msg.zig");
const auth_mod = @import("authenticator.zig");
const chain_mod = @import("chain.zig");
const rnd = @import("../random.zig");

pub const SCKA_LABEL = "Signal_PQCKA_V1_MLKEM768:SCKA Key";

fn sckaDeriveKey(ss: [32]u8, ep: u64) [32]u8 {
    var ep_bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &ep_bytes, ep, .big);
    var info: [SCKA_LABEL.len + 8]u8 = undefined;
    @memcpy(info[0..SCKA_LABEL.len], SCKA_LABEL);
    @memcpy(info[SCKA_LABEL.len..], &ep_bytes);
    const salt = [_]u8{0} ** 32;
    const prk = HkdfSha256.extract(&salt, &ss);
    var out: [32]u8 = undefined;
    HkdfSha256.expand(&out, &info, prk);
    return out;
}

// State tag byte for serialization
pub const StateTag = enum(u8) {
    unsampled = 0,
    hdr_sending = 1,
    ek_sending = 2,
    ek_sending_ct1 = 3,
    waiting_ct2 = 4,
    waiting_hdr = 5,
    ct1_sending = 6,
    ct2_sending = 7,
};

// Complete SPQR state: chain + authenticator + ML-KEM state machine
pub const SpqrState = struct {
    chain: chain_mod.Chain,
    auth: auth_mod.Authenticator,
    sm: StateMachine,

    pub fn deinit(self: *SpqrState, allocator: mem.Allocator) void {
        self.chain.deinit(allocator);
        self.sm.deinit(allocator);
    }

    pub fn serialize(self: *const SpqrState, allocator: mem.Allocator) ![]u8 {
        var buf: std.ArrayListUnmanaged(u8) = .empty;
        errdefer buf.deinit(allocator);
        try buf.append(allocator, 1); // version
        try self.chain.serialize(&buf, allocator);
        try buf.appendSlice(allocator, &self.auth.root_key);
        try buf.appendSlice(allocator, &self.auth.mac_key);
        try self.sm.serialize(&buf, allocator);
        return buf.toOwnedSlice(allocator);
    }

    pub fn deserialize(allocator: mem.Allocator, data: []const u8) !SpqrState {
        if (data.len < 1 or data[0] != 1) return error.InvalidVersion;
        var pos: usize = 1;

        const chain_r = try chain_mod.Chain.deserialize(allocator, data[pos..]);
        var chain = chain_r.chain;
        pos += chain_r.consumed;
        errdefer chain.deinit(allocator);

        if (pos + 64 > data.len) return error.TooShort;
        const auth = auth_mod.Authenticator{
            .root_key = data[pos..][0..32].*,
            .mac_key = data[pos + 32 ..][0..32].*,
        };
        pos += 64;

        const sm = try StateMachine.deserialize(allocator, data[pos..]);
        return SpqrState{ .chain = chain, .auth = auth, .sm = sm };
    }
};

pub const SendResult = struct {
    msg_bytes: []u8,
    chain_key: ?[32]u8,
};

pub const RecvResult = struct {
    chain_key: ?[32]u8,
};

pub fn send(allocator: mem.Allocator, state: *SpqrState) !SendResult {
    const ep = state.chain.current_epoch;
    const send_ep = state.chain.send_epoch;

    const payload = try state.sm.nextSendChunk(allocator, &state.auth, ep);

    const sk = state.chain.sendKey(send_ep) catch
        return SendResult{ .msg_bytes = try allocator.dupe(u8, &.{}), .chain_key = null };

    const v1msg = msg_mod.V1Msg{
        .epoch = send_ep,
        .chain_index = sk.index,
        .payload = payload,
    };
    const msg_bytes = try msg_mod.serialize(allocator, v1msg);
    return SendResult{ .msg_bytes = msg_bytes, .chain_key = sk.key };
}

pub fn recv(allocator: mem.Allocator, state: *SpqrState, data: []const u8) !RecvResult {
    const v1msg = try msg_mod.parse(data);
    const ep = v1msg.epoch;
    const idx = v1msg.chain_index;

    try state.sm.receiveChunk(allocator, &state.auth, &state.chain, v1msg.payload, ep);

    const chain_key = state.chain.recvKey(ep, idx) catch null;
    return RecvResult{ .chain_key = chain_key };
}

// ---- State Machine ----

pub const StateMachine = union(StateTag) {
    unsampled: void,
    hdr_sending: HdrSendingState,
    ek_sending: EkSendingState,
    ek_sending_ct1: EkSendingCt1State,
    waiting_ct2: WaitingCt2State,
    waiting_hdr: WaitingHdrState,
    ct1_sending: Ct1SendingState,
    ct2_sending: Ct2SendingState,

    pub fn deinit(self: *StateMachine, allocator: mem.Allocator) void {
        switch (self.*) {
            .unsampled, .waiting_hdr, .waiting_ct2, .ek_sending_ct1 => {},
            .hdr_sending => |*s| s.hdr_enc.deinit(),
            .ek_sending => |*s| s.ek_enc.deinit(),
            .ct1_sending => |*s| s.ct1_enc.deinit(),
            .ct2_sending => |*s| s.ct2_enc.deinit(),
        }
        _ = allocator;
    }

    // Returns the next chunk payload to send.
    pub fn nextSendChunk(
        self: *StateMachine,
        allocator: mem.Allocator,
        auth: *auth_mod.Authenticator,
        ep: u64,
    ) !msg_mod.Payload {
        _ = auth;
        switch (self.*) {
            .unsampled => {
                // Generate ML-KEM keypair, start sending header
                const keys = mlkem.generate();
                var hdr_enc = try poly.PolyEncoder.init(allocator, &keys.hdr);
                const c = hdr_enc.nextChunk();
                const ct1_dec = try poly.PolyDecoder.init(mlkem.CT1_SIZE);
                self.* = StateMachine{ .hdr_sending = .{
                    .hdr = keys.hdr,
                    .ek = keys.ek,
                    .dk = keys.dk,
                    .hdr_enc = hdr_enc,
                    .ct1_dec = ct1_dec,
                } };
                return msg_mod.Payload{ .hdr = .{ .index = c.index, .data = c.data } };
            },
            .hdr_sending => |*s| {
                if (s.hdr_enc.idx * poly.CHUNK_SIZE >= s.hdr_enc.msg.len) {
                    // Header fully sent; switch to EK
                    var enc = s.hdr_enc;
                    enc.deinit();
                    const ek_copy = s.ek;
                    const dk_copy = s.dk;
                    const ct1_dec_copy = s.ct1_dec;
                    var ek_enc = try poly.PolyEncoder.init(allocator, &ek_copy);
                    const c = ek_enc.nextChunk();
                    self.* = StateMachine{ .ek_sending = .{
                        .ek = ek_copy,
                        .dk = dk_copy,
                        .ek_enc = ek_enc,
                        .ct1_dec = ct1_dec_copy,
                    } };
                    return msg_mod.Payload{ .ek = .{ .index = c.index, .data = c.data } };
                }
                const c = s.hdr_enc.nextChunk();
                return msg_mod.Payload{ .hdr = .{ .index = c.index, .data = c.data } };
            },
            .ek_sending => |*s| {
                const c = s.ek_enc.nextChunk();
                const payload = msg_mod.Payload{ .ek = .{ .index = c.index, .data = c.data } };
                if (s.ek_enc.idx * poly.CHUNK_SIZE >= s.ek_enc.msg.len) {
                    const ek_copy = s.ek;
                    const dk_copy = s.dk;
                    var enc = s.ek_enc;
                    enc.deinit();
                    self.* = StateMachine{ .waiting_ct2 = .{
                        .dk = dk_copy,
                        .ct1 = null,
                        .ct2_dec = try poly.PolyDecoder.init(mlkem.CT2_SIZE),
                        .ct1_dec = s.ct1_dec,
                        .ek = ek_copy,
                    } };
                }
                return payload;
            },
            .ek_sending_ct1 => |*s| {
                // Send EkCt1Ack (EK chunk signaling CT1 receipt)
                const c = s.ek_enc.nextChunk();
                const payload = msg_mod.Payload{ .ek_ct1_ack = .{ .index = c.index, .data = c.data } };
                if (s.ek_enc.idx * poly.CHUNK_SIZE >= s.ek_enc.msg.len) {
                    const ct1_copy = s.ct1;
                    var enc = s.ek_enc;
                    enc.deinit();
                    self.* = StateMachine{ .waiting_ct2 = .{
                        .dk = s.dk,
                        .ct1 = ct1_copy,
                        .ct2_dec = try poly.PolyDecoder.init(mlkem.CT2_SIZE),
                        .ct1_dec = null,
                        .ek = s.ek,
                    } };
                }
                return payload;
            },
            .waiting_ct2 => |*s| {
                if (s.ct1 != null) {
                    return msg_mod.Payload{ .ct1_ack = true };
                }
                return msg_mod.Payload{ .none = {} };
            },
            .waiting_hdr => return msg_mod.Payload{ .none = {} },
            .ct1_sending => |*s| {
                // If full EK received, compute CT2 and transition
                if (s.full_ek) |ek| {
                    const ct2 = mlkem.encaps2(&ek, &s.es);
                    var ct1_enc = s.ct1_enc;
                    ct1_enc.deinit();
                    var ct2_enc = try poly.PolyEncoder.init(allocator, &ct2);
                    const c = ct2_enc.nextChunk();
                    const ss_copy = s.ss;
                    self.* = StateMachine{ .ct2_sending = .{
                        .ct2_enc = ct2_enc,
                        .ss = ss_copy,
                        .ep = ep,
                    } };
                    return msg_mod.Payload{ .ct2 = .{ .index = c.index, .data = c.data } };
                }
                // Still sending CT1
                if (s.ct1_enc.idx * poly.CHUNK_SIZE < s.ct1_enc.msg.len) {
                    const c = s.ct1_enc.nextChunk();
                    return msg_mod.Payload{ .ct1 = .{ .index = c.index, .data = c.data } };
                }
                // CT1 fully sent, waiting for EK
                return msg_mod.Payload{ .ct1_ack = true };
            },
            .ct2_sending => |*s| {
                if (s.ct2_enc.idx * poly.CHUNK_SIZE < s.ct2_enc.msg.len) {
                    const c = s.ct2_enc.nextChunk();
                    return msg_mod.Payload{ .ct2 = .{ .index = c.index, .data = c.data } };
                }
                return msg_mod.Payload{ .none = {} };
            },
        }
    }

    // Process an incoming V1Msg chunk.
    pub fn receiveChunk(
        self: *StateMachine,
        allocator: mem.Allocator,
        auth: *auth_mod.Authenticator,
        chain: *chain_mod.Chain,
        payload: msg_mod.Payload,
        ep: u64,
    ) !void {
        switch (self.*) {
            .unsampled, .hdr_sending, .ek_sending_ct1 => {
                // Can receive CT1 but don't store it yet (no hdr/ek state ready)
                // Ignore; SPQR is tolerant of dropped/out-of-order chunks
            },
            .ek_sending => |*s| {
                if (payload == .ct1) {
                    const c = payload.ct1;
                    const pc = poly.Chunk{ .index = c.index, .data = c.data };
                    s.ct1_dec.addChunk(&pc);
                    const maybe = try s.ct1_dec.decodedMessage(allocator);
                    if (maybe) |bytes| {
                        defer allocator.free(bytes);
                        if (bytes.len == mlkem.CT1_SIZE) {
                            var ct1: [mlkem.CT1_SIZE]u8 = undefined;
                            @memcpy(&ct1, bytes);
                            // CT1 received while sending EK → switch to ek_sending_ct1
                            const ek_copy = s.ek;
                            const dk_copy = s.dk;
                            const enc_copy = s.ek_enc;
                            self.* = StateMachine{ .ek_sending_ct1 = .{
                                .ek = ek_copy,
                                .dk = dk_copy,
                                .ek_enc = enc_copy,
                                .ct1 = ct1,
                            } };
                        }
                    }
                }
            },
            .waiting_ct2 => |*s| {
                switch (payload) {
                    .ct1 => |c| {
                        if (s.ct1 == null) {
                            if (s.ct1_dec) |*dec| {
                                const pc = poly.Chunk{ .index = c.index, .data = c.data };
                                dec.addChunk(&pc);
                                const maybe = try dec.decodedMessage(allocator);
                                if (maybe) |bytes| {
                                    defer allocator.free(bytes);
                                    if (bytes.len == mlkem.CT1_SIZE) {
                                        var ct1: [mlkem.CT1_SIZE]u8 = undefined;
                                        @memcpy(&ct1, bytes);
                                        s.ct1 = ct1;
                                        s.ct1_dec = null;
                                    }
                                }
                            }
                        }
                    },
                    .ct2 => |c| {
                        const pc = poly.Chunk{ .index = c.index, .data = c.data };
                        s.ct2_dec.addChunk(&pc);
                        const maybe = try s.ct2_dec.decodedMessage(allocator);
                        if (maybe) |bytes| {
                            defer allocator.free(bytes);
                            if (bytes.len == mlkem.CT2_SIZE) {
                                if (s.ct1) |ct1| {
                                    var ct2: [mlkem.CT2_SIZE]u8 = undefined;
                                    @memcpy(&ct2, bytes);
                                    // Decapsulate
                                    const ss_raw = try mlkem.decaps(&s.dk, &ct1, &ct2);
                                    const next_ep = ep + 1;
                                    const epoch_key = sckaDeriveKey(ss_raw, next_ep);
                                    try chain.addEpoch(allocator, next_ep, epoch_key);
                                    auth.update(next_ep, epoch_key);
                                    // Next epoch: Alice becomes CT1 sender (B2A)
                                    self.* = StateMachine{ .waiting_hdr = .{
                                        .hdr_dec = try poly.PolyDecoder.init(mlkem.HEADER_SIZE),
                                    } };
                                }
                            }
                        }
                    },
                    .ct1_ack => {},
                    else => {},
                }
            },
            .waiting_hdr => |*s| {
                if (payload == .hdr) {
                    const c = payload.hdr;
                    const pc = poly.Chunk{ .index = c.index, .data = c.data };
                    s.hdr_dec.addChunk(&pc);
                    const maybe = try s.hdr_dec.decodedMessage(allocator);
                    if (maybe) |bytes| {
                        defer allocator.free(bytes);
                        if (bytes.len == mlkem.HEADER_SIZE) {
                            var hdr: [mlkem.HEADER_SIZE]u8 = undefined;
                            @memcpy(&hdr, bytes);
                            // Encaps1: compute CT1, EncapsState, and epoch secret
                            var m_seed: [32]u8 = undefined;
                            rnd.bytes(&m_seed);
                            const encaps = mlkem.encaps1(&hdr, &m_seed);
                            // Inject epoch secret immediately (Bob knows ss from encaps1)
                            const next_ep = ep + 1;
                            const epoch_key = sckaDeriveKey(encaps.ss, next_ep);
                            try chain.addEpoch(allocator, next_ep, epoch_key);
                            auth.update(next_ep, epoch_key);
                            const ct1_enc = try poly.PolyEncoder.init(allocator, &encaps.ct1);
                            self.* = StateMachine{ .ct1_sending = .{
                                .ct1_enc = ct1_enc,
                                .ek_dec = try poly.PolyDecoder.init(mlkem.EK_SIZE),
                                .es = encaps.es,
                                .ss = encaps.ss,
                                .full_ek = null,
                                .ek_ct1_ack_received = false,
                            } };
                        }
                    }
                }
            },
            .ct1_sending => |*s| {
                switch (payload) {
                    .ek, .ek_ct1_ack => |c| {
                        if (payload == .ek_ct1_ack) s.ek_ct1_ack_received = true;
                        if (s.full_ek == null) {
                            const pc = poly.Chunk{ .index = c.index, .data = c.data };
                            s.ek_dec.addChunk(&pc);
                            const maybe = try s.ek_dec.decodedMessage(allocator);
                            if (maybe) |ek_bytes| {
                                defer allocator.free(ek_bytes);
                                if (ek_bytes.len == mlkem.EK_SIZE) {
                                    var ek: [mlkem.EK_SIZE]u8 = undefined;
                                    @memcpy(&ek, ek_bytes);
                                    s.full_ek = ek;
                                }
                            }
                        }
                    },
                    .ct1_ack => {},
                    else => {},
                }
            },
            .ct2_sending => |*s| {
                if (payload == .ct1_ack) {
                    // Alice acked CT2; Bob's epoch was already injected at encaps1.
                    // Transition to unsampled for next epoch (Bob generates keys).
                    var enc = s.ct2_enc;
                    enc.deinit();
                    self.* = StateMachine{ .unsampled = {} };
                }
            },
        }
    }

    pub fn serialize(self: *const StateMachine, buf: *std.ArrayListUnmanaged(u8), a: mem.Allocator) !void {
        try buf.append(a, @intFromEnum(std.meta.activeTag(self.*)));
        switch (self.*) {
            .unsampled => {},
            .hdr_sending => |*s| {
                try buf.appendSlice(a, &s.hdr);
                try buf.appendSlice(a, &s.ek);
                try buf.appendSlice(a, &s.dk);
                try poly.serializeEncoder(&s.hdr_enc, buf, a);
                try s.ct1_dec.serialize(buf, a);
            },
            .ek_sending => |*s| {
                try buf.appendSlice(a, &s.ek);
                try buf.appendSlice(a, &s.dk);
                try poly.serializeEncoder(&s.ek_enc, buf, a);
                try s.ct1_dec.serialize(buf, a);
            },
            .ek_sending_ct1 => |*s| {
                try buf.appendSlice(a, &s.ek);
                try buf.appendSlice(a, &s.dk);
                try poly.serializeEncoder(&s.ek_enc, buf, a);
                try buf.appendSlice(a, &s.ct1);
            },
            .waiting_ct2 => |*s| {
                try buf.appendSlice(a, &s.dk);
                try buf.appendSlice(a, &s.ek);
                const has_ct1: u8 = if (s.ct1 != null) 1 else 0;
                try buf.append(a, has_ct1);
                if (s.ct1) |ct1| try buf.appendSlice(a, &ct1);
                try s.ct2_dec.serialize(buf, a);
                const has_dec: u8 = if (s.ct1_dec != null) 1 else 0;
                try buf.append(a, has_dec);
                if (s.ct1_dec) |*dec| try dec.serialize(buf, a);
            },
            .waiting_hdr => |*s| {
                try s.hdr_dec.serialize(buf, a);
            },
            .ct1_sending => |*s| {
                try poly.serializeEncoder(&s.ct1_enc, buf, a);
                try s.ek_dec.serialize(buf, a);
                try buf.appendSlice(a, &s.es);
                try buf.appendSlice(a, &s.ss);
                const has_ek: u8 = if (s.full_ek != null) 1 else 0;
                try buf.append(a, has_ek);
                if (s.full_ek) |ek| try buf.appendSlice(a, &ek);
                try buf.append(a, if (s.ek_ct1_ack_received) 1 else 0);
            },
            .ct2_sending => |*s| {
                try poly.serializeEncoder(&s.ct2_enc, buf, a);
                try buf.appendSlice(a, &s.ss);
                var ep_bytes: [8]u8 = undefined;
                std.mem.writeInt(u64, &ep_bytes, s.ep, .big);
                try buf.appendSlice(a, &ep_bytes);
            },
        }
    }

    pub fn deserialize(allocator: mem.Allocator, data: []const u8) !StateMachine {
        if (data.len < 1) return error.TooShort;
        const tag: StateTag = @enumFromInt(data[0]);
        var pos: usize = 1;
        switch (tag) {
            .unsampled => return StateMachine{ .unsampled = {} },
            .hdr_sending => {
                if (pos + 64 + 1152 + 2400 > data.len) return error.TooShort;
                const hdr = data[pos..][0..64].*;
                pos += 64;
                const ek = data[pos..][0..1152].*;
                pos += 1152;
                const dk = data[pos..][0..2400].*;
                pos += 2400;
                const enc_r = try poly.deserializeEncoder(allocator, data[pos..]);
                pos += enc_r.consumed;
                const dec_r = try poly.PolyDecoder.deserialize(data[pos..]);
                _ = dec_r.consumed;
                return StateMachine{ .hdr_sending = .{
                    .hdr = hdr,
                    .ek = ek,
                    .dk = dk,
                    .hdr_enc = enc_r.enc,
                    .ct1_dec = dec_r.dec,
                } };
            },
            .ek_sending => {
                if (pos + 1152 + 2400 > data.len) return error.TooShort;
                const ek = data[pos..][0..1152].*;
                pos += 1152;
                const dk = data[pos..][0..2400].*;
                pos += 2400;
                const enc_r = try poly.deserializeEncoder(allocator, data[pos..]);
                pos += enc_r.consumed;
                const dec_r = try poly.PolyDecoder.deserialize(data[pos..]);
                return StateMachine{ .ek_sending = .{
                    .ek = ek,
                    .dk = dk,
                    .ek_enc = enc_r.enc,
                    .ct1_dec = dec_r.dec,
                } };
            },
            .ek_sending_ct1 => {
                if (pos + 1152 + 2400 > data.len) return error.TooShort;
                const ek = data[pos..][0..1152].*;
                pos += 1152;
                const dk = data[pos..][0..2400].*;
                pos += 2400;
                const enc_r = try poly.deserializeEncoder(allocator, data[pos..]);
                pos += enc_r.consumed;
                if (pos + 960 > data.len) return error.TooShort;
                const ct1 = data[pos..][0..960].*;
                return StateMachine{ .ek_sending_ct1 = .{
                    .ek = ek,
                    .dk = dk,
                    .ek_enc = enc_r.enc,
                    .ct1 = ct1,
                } };
            },
            .waiting_ct2 => {
                if (pos + 2400 + 1152 + 1 > data.len) return error.TooShort;
                const dk = data[pos..][0..2400].*;
                pos += 2400;
                const ek = data[pos..][0..1152].*;
                pos += 1152;
                const has_ct1 = data[pos] != 0;
                pos += 1;
                var ct1: ?[960]u8 = null;
                if (has_ct1) {
                    if (pos + 960 > data.len) return error.TooShort;
                    ct1 = data[pos..][0..960].*;
                    pos += 960;
                }
                const ct2_r = try poly.PolyDecoder.deserialize(data[pos..]);
                pos += ct2_r.consumed;
                if (pos + 1 > data.len) return error.TooShort;
                const has_dec = data[pos] != 0;
                pos += 1;
                var ct1_dec: ?poly.PolyDecoder = null;
                if (has_dec) {
                    const r = try poly.PolyDecoder.deserialize(data[pos..]);
                    pos += r.consumed;
                    ct1_dec = r.dec;
                }
                return StateMachine{ .waiting_ct2 = .{
                    .dk = dk,
                    .ek = ek,
                    .ct1 = ct1,
                    .ct2_dec = ct2_r.dec,
                    .ct1_dec = ct1_dec,
                } };
            },
            .waiting_hdr => {
                const r = try poly.PolyDecoder.deserialize(data[pos..]);
                return StateMachine{ .waiting_hdr = .{ .hdr_dec = r.dec } };
            },
            .ct1_sending => {
                const enc_r = try poly.deserializeEncoder(allocator, data[pos..]);
                pos += enc_r.consumed;
                const ek_dec_r = try poly.PolyDecoder.deserialize(data[pos..]);
                pos += ek_dec_r.consumed;
                if (pos + mlkem.ES_SIZE + 32 + 1 > data.len) return error.TooShort;
                const es = data[pos..][0..mlkem.ES_SIZE].*;
                pos += mlkem.ES_SIZE;
                const ss = data[pos..][0..32].*;
                pos += 32;
                const has_ek = data[pos] != 0;
                pos += 1;
                var full_ek: ?[1152]u8 = null;
                if (has_ek) {
                    if (pos + 1152 > data.len) return error.TooShort;
                    full_ek = data[pos..][0..1152].*;
                    pos += 1152;
                }
                if (pos + 1 > data.len) return error.TooShort;
                const acked = data[pos] != 0;
                return StateMachine{ .ct1_sending = .{
                    .ct1_enc = enc_r.enc,
                    .ek_dec = ek_dec_r.dec,
                    .es = es,
                    .ss = ss,
                    .full_ek = full_ek,
                    .ek_ct1_ack_received = acked,
                } };
            },
            .ct2_sending => {
                const enc_r = try poly.deserializeEncoder(allocator, data[pos..]);
                pos += enc_r.consumed;
                if (pos + 32 + 8 > data.len) return error.TooShort;
                const ss = data[pos..][0..32].*;
                pos += 32;
                const ep = std.mem.readInt(u64, data[pos..][0..8], .big);
                return StateMachine{ .ct2_sending = .{
                    .ct2_enc = enc_r.enc,
                    .ss = ss,
                    .ep = ep,
                } };
            },
        }
    }
};

// ---- State variant structs ----

const HdrSendingState = struct {
    hdr: [mlkem.HEADER_SIZE]u8,
    ek: [mlkem.EK_SIZE]u8,
    dk: [mlkem.DK_SIZE]u8,
    hdr_enc: poly.PolyEncoder,
    ct1_dec: poly.PolyDecoder,
};

const EkSendingState = struct {
    ek: [mlkem.EK_SIZE]u8,
    dk: [mlkem.DK_SIZE]u8,
    ek_enc: poly.PolyEncoder,
    ct1_dec: poly.PolyDecoder,
};

const EkSendingCt1State = struct {
    ek: [mlkem.EK_SIZE]u8,
    dk: [mlkem.DK_SIZE]u8,
    ek_enc: poly.PolyEncoder,
    ct1: [mlkem.CT1_SIZE]u8,
};

const WaitingCt2State = struct {
    dk: [mlkem.DK_SIZE]u8,
    ek: [mlkem.EK_SIZE]u8,
    ct1: ?[mlkem.CT1_SIZE]u8,
    ct2_dec: poly.PolyDecoder,
    ct1_dec: ?poly.PolyDecoder,
};

const WaitingHdrState = struct {
    hdr_dec: poly.PolyDecoder,
};

const Ct1SendingState = struct {
    ct1_enc: poly.PolyEncoder,
    ek_dec: poly.PolyDecoder,
    es: [mlkem.ES_SIZE]u8,
    ss: [32]u8,
    full_ek: ?[mlkem.EK_SIZE]u8,
    ek_ct1_ack_received: bool,
};

const Ct2SendingState = struct {
    ct2_enc: poly.PolyEncoder,
    ss: [32]u8,
    ep: u64,
};
