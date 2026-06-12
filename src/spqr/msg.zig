// SPQR V1Msg wire format serialization.
// Wire: version_byte=0x01 || protobuf(epoch, chain_index, oneof_payload)
// Chunk sub-message: { field1=chunk_index(varint), field2=data(bytes[32]) }
const std = @import("std");
const proto = @import("../proto.zig");
const mem = std.mem;

pub const VERSION: u8 = 1;
pub const CHUNK_DATA_SIZE: usize = 32;

pub const PayloadTag = enum(u8) {
    none = 0,
    hdr = 3,
    ek = 4,
    ek_ct1_ack = 5,
    ct1_ack = 6,
    ct1 = 7,
    ct2 = 8,
};

pub const Chunk = struct {
    index: u32,
    data: [CHUNK_DATA_SIZE]u8,
};

pub const Payload = union(PayloadTag) {
    none: void,
    hdr: Chunk,
    ek: Chunk,
    ek_ct1_ack: Chunk,
    ct1_ack: bool,
    ct1: Chunk,
    ct2: Chunk,
};

pub const V1Msg = struct {
    epoch: u64,
    chain_index: u32,
    payload: Payload,
    mac: ?[32]u8 = null, // HMAC-SHA256 over full object; present only on index-0 authenticated chunks
};

pub fn serialize(allocator: mem.Allocator, msg: V1Msg) ![]u8 {
    var enc = proto.Encoder.init(allocator);
    errdefer enc.deinit();

    try enc.writeVarintField(1, msg.epoch);
    try enc.writeVarintField(2, msg.chain_index);

    switch (msg.payload) {
        .none => {},
        .hdr => |c| try writeChunk(&enc, 3, c),
        .ek => |c| try writeChunk(&enc, 4, c),
        .ek_ct1_ack => |c| try writeChunk(&enc, 5, c),
        .ct1_ack => |v| try enc.writeVarintField(6, if (v) 1 else 0),
        .ct1 => |c| try writeChunk(&enc, 7, c),
        .ct2 => |c| try writeChunk(&enc, 8, c),
    }

    if (msg.mac) |m| try enc.writeBytesField(9, &m);

    const pb_bytes = try enc.toOwnedSlice();
    defer allocator.free(pb_bytes);

    // Prepend version byte
    const out = try allocator.alloc(u8, 1 + pb_bytes.len);
    out[0] = VERSION;
    @memcpy(out[1..], pb_bytes);
    return out;
}

fn writeChunk(enc: *proto.Encoder, field: u32, c: Chunk) !void {
    // Encode Chunk sub-message: { field1=index(varint), field2=data(bytes) }
    var sub = proto.Encoder.init(enc.allocator);
    defer sub.deinit();
    try sub.writeVarintField(1, c.index);
    try sub.writeBytesField(2, &c.data);
    const sub_bytes = try sub.toOwnedSlice();
    defer enc.allocator.free(sub_bytes);
    try enc.writeBytesField(field, sub_bytes);
}

pub const ParseError = error{
    InvalidVersion,
    MissingField,
    InvalidData,
    TruncatedChunk,
} || proto.DecodeError;

pub fn parse(data: []const u8) ParseError!V1Msg {
    if (data.len < 1) return ParseError.InvalidVersion;
    if (data[0] != VERSION) return ParseError.InvalidVersion;
    const pb = data[1..];

    var msg: V1Msg = .{
        .epoch = 0,
        .chain_index = 0,
        .payload = .none,
    };

    var pos: usize = 0;
    while (try proto.nextField(pb, &pos)) |field| {
        switch (field.number) {
            1 => if (field.wire_type == .varint) {
                msg.epoch = field.data.varint;
            },
            2 => if (field.wire_type == .varint) {
                msg.chain_index = @intCast(field.data.varint & 0xFFFF_FFFF);
            },
            3 => if (field.wire_type == .len) {
                msg.payload = .{ .hdr = try parseChunk(field.data.len) };
            },
            4 => if (field.wire_type == .len) {
                msg.payload = .{ .ek = try parseChunk(field.data.len) };
            },
            5 => if (field.wire_type == .len) {
                msg.payload = .{ .ek_ct1_ack = try parseChunk(field.data.len) };
            },
            6 => if (field.wire_type == .varint) {
                msg.payload = .{ .ct1_ack = field.data.varint != 0 };
            },
            7 => if (field.wire_type == .len) {
                msg.payload = .{ .ct1 = try parseChunk(field.data.len) };
            },
            8 => if (field.wire_type == .len) {
                msg.payload = .{ .ct2 = try parseChunk(field.data.len) };
            },
            9 => if (field.wire_type == .len and field.data.len.len == 32) {
                msg.mac = field.data.len[0..32].*;
            },
            else => {},
        }
    }

    return msg;
}

fn parseChunk(sub_bytes: []const u8) ParseError!Chunk {
    var c: Chunk = .{ .index = 0, .data = undefined };
    var data_set = false;
    var pos: usize = 0;
    while (try proto.nextField(sub_bytes, &pos)) |field| {
        switch (field.number) {
            1 => if (field.wire_type == .varint) {
                c.index = @intCast(field.data.varint & 0xFFFF_FFFF);
            },
            2 => if (field.wire_type == .len) {
                if (field.data.len.len != CHUNK_DATA_SIZE) return ParseError.TruncatedChunk;
                @memcpy(&c.data, field.data.len);
                data_set = true;
            },
            else => {},
        }
    }
    if (!data_set) return ParseError.InvalidData;
    return c;
}
