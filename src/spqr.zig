// Signal Post-Quantum Ratchet (SPQR) V1 — ML-KEM-768 based.
// Implements github.com/signalapp/SparsePostQuantumRatchet.
//
// Each message carries a V1Msg chunk. The SPQR chain key per message is fed
// into the Double Ratchet as the pqr_key salt for forward-secure message keys.
const std = @import("std");
const mem = std.mem;
const chain_mod = @import("spqr/chain.zig");
const auth_mod = @import("spqr/authenticator.zig");
const state_mod = @import("spqr/state.zig");
const mlkem = @import("spqr/mlkem768_incremental.zig");

pub const Direction = chain_mod.Direction;

pub const SendResult = struct {
    state: []u8, // new serialized state (caller frees old, stores new)
    msg: []u8, // V1Msg bytes (caller frees)
    key: ?[32]u8, // per-message chain key (null if state is empty/V0)
};

pub const RecvResult = struct {
    state: []u8, // new serialized state
    key: ?[32]u8, // per-message chain key
};

/// Create initial SPQR state from the PQXDH pqr_key.
/// dir=.a2b for Alice (session initiator, generates ML-KEM keys).
/// dir=.b2a for Bob (session responder, encapsulates).
pub fn initialState(allocator: mem.Allocator, initial_key: [32]u8, dir: Direction) ![]u8 {
    const chain = try chain_mod.Chain.init(allocator, initial_key, dir);
    var spqr_state = state_mod.SpqrState{
        .chain = chain,
        .auth = auth_mod.Authenticator.init(initial_key, 0),
        .sm = switch (dir) {
            .a2b => .unsampled, // Alice generates keys first
            .b2a => .{ .waiting_hdr = .{
                .hdr_dec = try @import("spqr/poly_codec.zig").PolyDecoder.init(mlkem.HEADER_SIZE),
            } },
        },
    };
    defer spqr_state.deinit(allocator);
    return spqr_state.serialize(allocator);
}

/// Advance the SPQR ratchet and produce a V1Msg chunk to send.
/// Returns new state, the encoded message, and the chain key for this message.
/// Caller is responsible for freeing result.state and result.msg.
pub fn send(allocator: mem.Allocator, state_bytes: ?[]const u8) !SendResult {
    const bytes = state_bytes orelse {
        const empty_state = try allocator.dupe(u8, &.{});
        errdefer allocator.free(empty_state);
        const empty_msg = try allocator.dupe(u8, &.{});
        return SendResult{ .state = empty_state, .msg = empty_msg, .key = null };
    };
    if (bytes.len == 0) {
        const empty_state = try allocator.dupe(u8, &.{});
        errdefer allocator.free(empty_state);
        const empty_msg = try allocator.dupe(u8, &.{});
        return SendResult{ .state = empty_state, .msg = empty_msg, .key = null };
    }

    var spqr_state = try state_mod.SpqrState.deserialize(allocator, bytes);
    defer spqr_state.deinit(allocator);

    const result = try state_mod.send(allocator, &spqr_state);
    errdefer allocator.free(result.msg_bytes);

    const new_state = try spqr_state.serialize(allocator);
    return .{
        .state = new_state,
        .msg = result.msg_bytes,
        .key = result.chain_key,
    };
}

/// Process an incoming V1Msg and advance the SPQR ratchet.
/// Returns new state and the chain key for this message.
/// Caller is responsible for freeing result.state.
pub fn recv(allocator: mem.Allocator, state_bytes: ?[]const u8, msg: ?[]const u8) !RecvResult {
    const bytes = state_bytes orelse return RecvResult{
        .state = try allocator.dupe(u8, &.{}),
        .key = null,
    };
    if (bytes.len == 0) return RecvResult{
        .state = try allocator.dupe(u8, &.{}),
        .key = null,
    };
    const msg_data = msg orelse return RecvResult{
        .state = try allocator.dupe(u8, bytes),
        .key = null,
    };
    if (msg_data.len == 0) return RecvResult{
        .state = try allocator.dupe(u8, bytes),
        .key = null,
    };

    var spqr_state = try state_mod.SpqrState.deserialize(allocator, bytes);
    defer spqr_state.deinit(allocator);

    const result = try state_mod.recv(allocator, &spqr_state, msg_data);
    const new_state = try spqr_state.serialize(allocator);
    return .{
        .state = new_state,
        .key = result.chain_key,
    };
}
