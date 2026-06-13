// SPQR V1 state machine: ML-KEM-768 key exchange across chunked messages.
//
// A2B epoch (Alice generates ML-KEM keys, sends HDR + EK):
//   unsampled → hdr_sending → ek_sending → ek_sending_ct1 → waiting_ct2
//
// B2A epoch (Bob encapsulates, sends CT1 + CT2):
//   waiting_hdr → ct1_sending → ct2_sending → (unsampled, roles swap each epoch)
//
// MAC invariant: all four objects (HDR, EK, CT1, CT2) within one epoch are
// authenticated with the mac_key established at the START of that epoch.
// auth.update() must not be called until the epoch exchange is fully complete
// (Alice: after decaps; Bob: after receiving ct1_ack confirming Alice has CT2).
// This keeps both sides' mac_keys in sync throughout the exchange.
//
// Transport assumption: SPQR relies on the underlying transport (Signal Noise
// protocol over TCP) to deliver messages reliably and in order. The Lagrange
// polynomial codec provides recovery from chunk reordering but not from loss.
// A lost index-0 chunk means the associated MAC cannot be verified; the epoch
// exchange will fail and must be restarted.
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

// Payload + optional MAC returned by nextSendChunk; MAC present only on index-0
// chunks of authenticated objects (HDR, EK, CT1, CT2).
pub const ChunkSend = struct {
    payload: msg_mod.Payload,
    mac: ?auth_mod.Mac,
};

pub fn send(allocator: mem.Allocator, state: *SpqrState) !SendResult {
    const ep = state.chain.current_epoch;
    const send_ep = state.chain.send_epoch;

    const chunk = try state.sm.nextSendChunk(allocator, &state.auth, ep);

    const sk = state.chain.sendKey(send_ep) catch
        return SendResult{ .msg_bytes = try allocator.dupe(u8, &.{}), .chain_key = null };

    const v1msg = msg_mod.V1Msg{
        .epoch = send_ep,
        .chain_index = sk.index,
        .payload = chunk.payload,
        .mac = chunk.mac,
    };
    const msg_bytes = try msg_mod.serialize(allocator, v1msg);
    return SendResult{ .msg_bytes = msg_bytes, .chain_key = sk.key };
}

pub fn recv(allocator: mem.Allocator, state: *SpqrState, data: []const u8) !RecvResult {
    const v1msg = try msg_mod.parse(data);
    const ep = v1msg.epoch;
    const idx = v1msg.chain_index;

    try state.sm.receiveChunk(allocator, &state.auth, &state.chain, v1msg.payload, v1msg.mac, ep);

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

    // Returns the next chunk + MAC to send. MAC is non-null only for the index-0
    // chunk of each authenticated object (HDR, EK, CT1, CT2).
    pub fn nextSendChunk(
        self: *StateMachine,
        allocator: mem.Allocator,
        auth: *auth_mod.Authenticator,
        ep: u64,
    ) !ChunkSend {
        switch (self.*) {
            .unsampled => {
                const keys = mlkem.generate();
                var hdr_enc = try poly.PolyEncoder.init(allocator, &keys.hdr);
                const c = hdr_enc.nextChunk(); // index 0
                const ct1_dec = try poly.PolyDecoder.init(mlkem.CT1_SIZE);
                const mac = auth.macHdr(ep, &keys.hdr);
                self.* = StateMachine{ .hdr_sending = .{
                    .hdr = keys.hdr,
                    .ek = keys.ek,
                    .dk = keys.dk,
                    .hdr_enc = hdr_enc,
                    .ct1_dec = ct1_dec,
                } };
                return ChunkSend{ .payload = .{ .hdr = .{ .index = c.index, .data = c.data } }, .mac = mac };
            },
            .hdr_sending => |*s| {
                if (s.hdr_enc.idx * poly.CHUNK_SIZE >= s.hdr_enc.msg.len) {
                    // Header fully sent; pivot to EK. First EK chunk carries MAC.
                    const ek_copy = s.ek;
                    const dk_copy = s.dk;
                    const ct1_dec_copy = s.ct1_dec;
                    var ek_enc = try poly.PolyEncoder.init(allocator, &ek_copy);
                    s.hdr_enc.deinit();
                    const c = ek_enc.nextChunk(); // index 0
                    const mac = auth.macCt(ep, &ek_copy);
                    self.* = StateMachine{ .ek_sending = .{
                        .ek = ek_copy,
                        .dk = dk_copy,
                        .ek_enc = ek_enc,
                        .ct1_dec = ct1_dec_copy,
                    } };
                    return ChunkSend{ .payload = .{ .ek = .{ .index = c.index, .data = c.data } }, .mac = mac };
                }
                const c = s.hdr_enc.nextChunk(); // index > 0
                return ChunkSend{ .payload = .{ .hdr = .{ .index = c.index, .data = c.data } }, .mac = null };
            },
            .ek_sending => |*s| {
                // EK encoder index > 0 on entry (first chunk was sent in hdr_sending transition)
                const c = s.ek_enc.nextChunk();
                const payload = msg_mod.Payload{ .ek = .{ .index = c.index, .data = c.data } };
                if (s.ek_enc.idx * poly.CHUNK_SIZE >= s.ek_enc.msg.len) {
                    const ek_copy = s.ek;
                    const dk_copy = s.dk;
                    const ct2_dec = try poly.PolyDecoder.init(mlkem.CT2_SIZE);
                    s.ek_enc.deinit();
                    self.* = StateMachine{ .waiting_ct2 = .{
                        .dk = dk_copy,
                        .ct1 = null,
                        .ct2_dec = ct2_dec,
                        .ct1_dec = s.ct1_dec,
                        .ek = ek_copy,
                    } };
                }
                return ChunkSend{ .payload = payload, .mac = null };
            },
            .ek_sending_ct1 => |*s| {
                // EK encoder picks up mid-stream; MAC already sent with index-0 chunk.
                const c = s.ek_enc.nextChunk();
                const payload = msg_mod.Payload{ .ek_ct1_ack = .{ .index = c.index, .data = c.data } };
                if (s.ek_enc.idx * poly.CHUNK_SIZE >= s.ek_enc.msg.len) {
                    const ct1_copy = s.ct1;
                    const ct2_dec = try poly.PolyDecoder.init(mlkem.CT2_SIZE);
                    s.ek_enc.deinit();
                    self.* = StateMachine{ .waiting_ct2 = .{
                        .dk = s.dk,
                        .ct1 = ct1_copy,
                        .ct2_dec = ct2_dec,
                        .ct1_dec = null,
                        .ek = s.ek,
                    } };
                }
                return ChunkSend{ .payload = payload, .mac = null };
            },
            .waiting_ct2 => |*s| {
                if (s.ct1 != null) return ChunkSend{ .payload = .{ .ct1_ack = true }, .mac = null };
                return ChunkSend{ .payload = .{ .none = {} }, .mac = null };
            },
            .waiting_hdr => return ChunkSend{ .payload = .{ .none = {} }, .mac = null },
            .ct1_sending => |*s| {
                if (s.full_ek) |ek| {
                    // EK fully received; compute CT2 and transition. First CT2 chunk carries MAC.
                    const ct2 = mlkem.encaps2(&ek, &s.es);
                    var ct2_enc = try poly.PolyEncoder.init(allocator, &ct2);
                    s.ct1_enc.deinit();
                    const c = ct2_enc.nextChunk(); // index 0
                    const mac = auth.macCt(ep, &ct2);
                    const ss_copy = s.ss;
                    self.* = StateMachine{ .ct2_sending = .{
                        .ct2_enc = ct2_enc,
                        .ss = ss_copy,
                        .ep = ep,
                    } };
                    return ChunkSend{ .payload = .{ .ct2 = .{ .index = c.index, .data = c.data } }, .mac = mac };
                }
                if (s.ct1_enc.idx * poly.CHUNK_SIZE < s.ct1_enc.msg.len) {
                    const c = s.ct1_enc.nextChunk();
                    // MAC on index-0 only
                    const mac: ?auth_mod.Mac = if (c.index == 0) auth.macCt(ep, s.ct1_enc.msg) else null;
                    return ChunkSend{ .payload = .{ .ct1 = .{ .index = c.index, .data = c.data } }, .mac = mac };
                }
                return ChunkSend{ .payload = .{ .ct1_ack = true }, .mac = null };
            },
            .ct2_sending => |*s| {
                // CT2 encoder index > 0 on entry (first chunk sent in ct1_sending transition)
                if (s.ct2_enc.idx * poly.CHUNK_SIZE < s.ct2_enc.msg.len) {
                    const c = s.ct2_enc.nextChunk();
                    return ChunkSend{ .payload = .{ .ct2 = .{ .index = c.index, .data = c.data } }, .mac = null };
                }
                return ChunkSend{ .payload = .{ .none = {} }, .mac = null };
            },
        }
    }

    // Process an incoming V1Msg chunk. mac is non-null on index-0 authenticated chunks;
    // it is stored until the full object is assembled, then verified.
    pub fn receiveChunk(
        self: *StateMachine,
        allocator: mem.Allocator,
        auth: *auth_mod.Authenticator,
        chain: *chain_mod.Chain,
        payload: msg_mod.Payload,
        mac: ?[32]u8,
        ep: u64,
    ) !void {
        switch (self.*) {
            // These states only send; incoming chunks (typically retransmissions) are ignored.
            .unsampled, .hdr_sending, .ek_sending_ct1 => {},
            .ek_sending => |*s| {
                if (payload != .ct1) return;
                const c = payload.ct1;
                // Capture MAC from index-0 CT1 chunk
                if (c.index == 0) {
                    if (mac == null) return error.MissingMac;
                    s.pending_mac_ct1 = mac;
                }
                const pc = poly.Chunk{ .index = c.index, .data = c.data };
                s.ct1_dec.addChunk(&pc);
                const maybe = try s.ct1_dec.decodedMessage(allocator);
                if (maybe) |bytes| {
                    defer allocator.free(bytes);
                    if (bytes.len == mlkem.CT1_SIZE) {
                        const pm = s.pending_mac_ct1 orelse return error.MissingMac;
                        try auth.verifyCt(ep, bytes, &pm);
                        var ct1: [mlkem.CT1_SIZE]u8 = undefined;
                        @memcpy(&ct1, bytes);
                        const enc_copy = s.ek_enc;
                        self.* = StateMachine{ .ek_sending_ct1 = .{
                            .ek = s.ek,
                            .dk = s.dk,
                            .ek_enc = enc_copy,
                            .ct1 = ct1,
                        } };
                    }
                }
            },
            .waiting_ct2 => |*s| {
                switch (payload) {
                    .ct1 => |c| {
                        if (s.ct1 != null) return; // already have CT1
                        if (c.index == 0) {
                            if (mac == null) return error.MissingMac;
                            s.pending_mac_ct1 = mac;
                        }
                        if (s.ct1_dec) |*dec| {
                            const pc = poly.Chunk{ .index = c.index, .data = c.data };
                            dec.addChunk(&pc);
                            const maybe = try dec.decodedMessage(allocator);
                            if (maybe) |bytes| {
                                defer allocator.free(bytes);
                                if (bytes.len == mlkem.CT1_SIZE) {
                                    const pm = s.pending_mac_ct1 orelse return error.MissingMac;
                                    try auth.verifyCt(ep, bytes, &pm);
                                    var ct1: [mlkem.CT1_SIZE]u8 = undefined;
                                    @memcpy(&ct1, bytes);
                                    s.ct1 = ct1;
                                    s.ct1_dec = null;
                                }
                            }
                        }
                    },
                    .ct2 => |c| {
                        if (c.index == 0) {
                            if (mac == null) return error.MissingMac;
                            s.pending_mac_ct2 = mac;
                        }
                        const pc = poly.Chunk{ .index = c.index, .data = c.data };
                        s.ct2_dec.addChunk(&pc);
                        const maybe = try s.ct2_dec.decodedMessage(allocator);
                        if (maybe) |bytes| {
                            defer allocator.free(bytes);
                            if (bytes.len == mlkem.CT2_SIZE) {
                                if (s.ct1) |ct1| {
                                    var ct2: [mlkem.CT2_SIZE]u8 = undefined;
                                    @memcpy(&ct2, bytes);
                                    // Verify CT2 MAC before decapsulating
                                    const pm = s.pending_mac_ct2 orelse return error.MissingMac;
                                    try auth.verifyCt(ep, bytes, &pm);
                                    const ss_raw = try mlkem.decaps(&s.dk, &ct1, &ct2);
                                    // ep IS the new epoch (Bob's send_epoch after his chain advanced).
                                    // Alice adds the same epoch number Bob already added on his side.
                                    const epoch_key = sckaDeriveKey(ss_raw, ep);
                                    try chain.addEpoch(allocator, ep, epoch_key);
                                    // auth.update deferred: Alice updates after decaps, Bob updates at ct1_ack.
                                    // Both sides are still on epoch-0 mac_key so this call is correct here.
                                    auth.update(ep, epoch_key);
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
                if (payload != .hdr) return;
                const c = payload.hdr;
                if (c.index == 0) {
                    if (mac == null) return error.MissingMac;
                    s.pending_mac = mac;
                }
                const pc = poly.Chunk{ .index = c.index, .data = c.data };
                s.hdr_dec.addChunk(&pc);
                const maybe = try s.hdr_dec.decodedMessage(allocator);
                if (maybe) |bytes| {
                    defer allocator.free(bytes);
                    if (bytes.len == mlkem.HEADER_SIZE) {
                        var hdr: [mlkem.HEADER_SIZE]u8 = undefined;
                        @memcpy(&hdr, bytes);
                        // Verify HDR MAC before trusting the key material
                        const pm = s.pending_mac orelse return error.MissingMac;
                        try auth.verifyHdr(ep, &hdr, &pm);
                        var m_seed: [32]u8 = undefined;
                        rnd.bytes(&m_seed);
                        const encaps = mlkem.encaps1(&hdr, &m_seed);
                        // Inject epoch secret into chain for message-key forward secrecy.
                        // auth.update is intentionally deferred to ct2_sending.receiveChunk
                        // so that CT1 and CT2 MACs are verified with the current (pre-update)
                        // mac_key, keeping Alice and Bob in sync throughout this epoch.
                        const next_ep = ep + 1;
                        const epoch_key = sckaDeriveKey(encaps.ss, next_ep);
                        try chain.addEpoch(allocator, next_ep, epoch_key);
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
            },
            .ct1_sending => |*s| {
                switch (payload) {
                    .ek, .ek_ct1_ack => |c| {
                        if (payload == .ek_ct1_ack) s.ek_ct1_ack_received = true;
                        if (s.full_ek != null) return; // already have EK
                        if (c.index == 0) {
                            if (mac == null) return error.MissingMac;
                            s.pending_mac_ek = mac;
                        }
                        const pc = poly.Chunk{ .index = c.index, .data = c.data };
                        s.ek_dec.addChunk(&pc);
                        const maybe = try s.ek_dec.decodedMessage(allocator);
                        if (maybe) |ek_bytes| {
                            defer allocator.free(ek_bytes);
                            if (ek_bytes.len == mlkem.EK_SIZE) {
                                const pm = s.pending_mac_ek orelse return error.MissingMac;
                                try auth.verifyCt(ep, ek_bytes, &pm);
                                var ek: [mlkem.EK_SIZE]u8 = undefined;
                                @memcpy(&ek, ek_bytes);
                                s.full_ek = ek;
                            }
                        }
                    },
                    .ct1_ack => {},
                    else => {},
                }
            },
            .ct2_sending => |*s| {
                if (payload != .ct1_ack) return;
                // Alice sends ct1_ack as soon as she enters waiting_ct2 (CT1 acknowledged),
                // but Bob must not advance until CT2 is fully transmitted — otherwise he frees
                // the encoder before Alice has received all chunks.
                if (s.ct2_enc.idx * poly.CHUNK_SIZE < s.ct2_enc.msg.len) return;
                // CT2 fully sent and Alice confirmed receipt. Safe to advance auth.
                const epoch_key = sckaDeriveKey(s.ss, s.ep);
                auth.update(s.ep, epoch_key);
                var old_enc = s.ct2_enc;
                old_enc.deinit();
                self.* = StateMachine{ .unsampled = {} };
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
                try serializeMac(s.pending_mac_ct1, buf, a);
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
                try serializeMac(s.pending_mac_ct1, buf, a);
                try serializeMac(s.pending_mac_ct2, buf, a);
            },
            .waiting_hdr => |*s| {
                try s.hdr_dec.serialize(buf, a);
                try serializeMac(s.pending_mac, buf, a);
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
                try serializeMac(s.pending_mac_ek, buf, a);
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
                errdefer {
                    var enc = enc_r.enc;
                    enc.deinit();
                }
                pos += enc_r.consumed;
                const dec_r = try poly.PolyDecoder.deserialize(data[pos..]);
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
                errdefer {
                    var enc = enc_r.enc;
                    enc.deinit();
                }
                pos += enc_r.consumed;
                const dec_r = try poly.PolyDecoder.deserialize(data[pos..]);
                pos += dec_r.consumed;
                const pending_mac_ct1 = try deserializeMac(data, &pos);
                return StateMachine{ .ek_sending = .{
                    .ek = ek,
                    .dk = dk,
                    .ek_enc = enc_r.enc,
                    .ct1_dec = dec_r.dec,
                    .pending_mac_ct1 = pending_mac_ct1,
                } };
            },
            .ek_sending_ct1 => {
                if (pos + 1152 + 2400 > data.len) return error.TooShort;
                const ek = data[pos..][0..1152].*;
                pos += 1152;
                const dk = data[pos..][0..2400].*;
                pos += 2400;
                const enc_r = try poly.deserializeEncoder(allocator, data[pos..]);
                errdefer {
                    var enc = enc_r.enc;
                    enc.deinit();
                }
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
                const pending_mac_ct1 = try deserializeMac(data, &pos);
                const pending_mac_ct2 = try deserializeMac(data, &pos);
                return StateMachine{ .waiting_ct2 = .{
                    .dk = dk,
                    .ek = ek,
                    .ct1 = ct1,
                    .ct2_dec = ct2_r.dec,
                    .ct1_dec = ct1_dec,
                    .pending_mac_ct1 = pending_mac_ct1,
                    .pending_mac_ct2 = pending_mac_ct2,
                } };
            },
            .waiting_hdr => {
                const r = try poly.PolyDecoder.deserialize(data[pos..]);
                pos += r.consumed;
                const pending_mac = try deserializeMac(data, &pos);
                return StateMachine{ .waiting_hdr = .{ .hdr_dec = r.dec, .pending_mac = pending_mac } };
            },
            .ct1_sending => {
                const enc_r = try poly.deserializeEncoder(allocator, data[pos..]);
                errdefer {
                    var enc = enc_r.enc;
                    enc.deinit();
                }
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
                pos += 1;
                const pending_mac_ek = try deserializeMac(data, &pos);
                return StateMachine{ .ct1_sending = .{
                    .ct1_enc = enc_r.enc,
                    .ek_dec = ek_dec_r.dec,
                    .es = es,
                    .ss = ss,
                    .full_ek = full_ek,
                    .ek_ct1_ack_received = acked,
                    .pending_mac_ek = pending_mac_ek,
                } };
            },
            .ct2_sending => {
                const enc_r = try poly.deserializeEncoder(allocator, data[pos..]);
                errdefer {
                    var enc = enc_r.enc;
                    enc.deinit();
                }
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

fn serializeMac(m: ?[32]u8, buf: *std.ArrayListUnmanaged(u8), a: mem.Allocator) !void {
    try buf.append(a, if (m != null) 1 else 0);
    if (m) |bytes| try buf.appendSlice(a, &bytes);
}

fn deserializeMac(data: []const u8, pos: *usize) !?[32]u8 {
    if (pos.* + 1 > data.len) return error.TooShort;
    const present = data[pos.*] != 0;
    pos.* += 1;
    if (!present) return null;
    if (pos.* + 32 > data.len) return error.TooShort;
    const m = data[pos.*..][0..32].*;
    pos.* += 32;
    return m;
}

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
    pending_mac_ct1: ?[32]u8 = null,
};

const EkSendingCt1State = struct {
    ek: [mlkem.EK_SIZE]u8,
    dk: [mlkem.DK_SIZE]u8,
    ek_enc: poly.PolyEncoder,
    ct1: [mlkem.CT1_SIZE]u8,
    // CT1 MAC was verified during ek_sending → ek_sending_ct1 transition.
};

const WaitingCt2State = struct {
    dk: [mlkem.DK_SIZE]u8,
    ek: [mlkem.EK_SIZE]u8,
    ct1: ?[mlkem.CT1_SIZE]u8,
    ct2_dec: poly.PolyDecoder,
    ct1_dec: ?poly.PolyDecoder,
    pending_mac_ct1: ?[32]u8 = null,
    pending_mac_ct2: ?[32]u8 = null,
};

const WaitingHdrState = struct {
    hdr_dec: poly.PolyDecoder,
    pending_mac: ?[32]u8 = null,
};

const Ct1SendingState = struct {
    ct1_enc: poly.PolyEncoder,
    ek_dec: poly.PolyDecoder,
    es: [mlkem.ES_SIZE]u8,
    ss: [32]u8,
    full_ek: ?[mlkem.EK_SIZE]u8,
    ek_ct1_ack_received: bool,
    pending_mac_ek: ?[32]u8 = null,
};

const Ct2SendingState = struct {
    ct2_enc: poly.PolyEncoder,
    ss: [32]u8,
    ep: u64,
};
