// Minimal protobuf encoder/decoder for Signal Protocol messages.
// Supports field types used by Signal: varint (0), length-delimited (2).
const std = @import("std");
const mem = std.mem;

pub const WireType = enum(u3) {
    varint = 0,
    i64 = 1,
    len = 2,
    i32 = 5,
};

pub const Field = struct {
    number: u32,
    wire_type: WireType,
    data: union(WireType) {
        varint: u64,
        i64: u64,
        len: []const u8,
        i32: u32,
    },
};

pub const DecodeError = error{
    Truncated,
    InvalidTag,
    Overflow,
    UnexpectedWireType,
};

pub fn decodeVarint(buf: []const u8, pos: *usize) DecodeError!u64 {
    var result: u64 = 0;
    var shift: u6 = 0;
    while (pos.* < buf.len) {
        const b = buf[pos.*];
        pos.* += 1;
        result |= @as(u64, b & 0x7F) << shift;
        if (b & 0x80 == 0) return result;
        shift += 7;
        if (shift >= 64) return DecodeError.Overflow;
    }
    return DecodeError.Truncated;
}

pub fn encodeVarint(value: u64, buf: []u8) usize {
    var v = value;
    var i: usize = 0;
    while (true) {
        buf[i] = @truncate(v & 0x7F);
        v >>= 7;
        if (v == 0) {
            i += 1;
            break;
        }
        buf[i] |= 0x80;
        i += 1;
    }
    return i;
}

pub fn nextField(buf: []const u8, pos: *usize) DecodeError!?Field {
    if (pos.* >= buf.len) return null;
    const tag = try decodeVarint(buf, pos);
    const wire_type_raw: u3 = @truncate(tag & 0x7);
    const field_number: u32 = @truncate(tag >> 3);
    if (field_number == 0) return DecodeError.InvalidTag;
    const wire_type = @as(WireType, @enumFromInt(wire_type_raw));
    return switch (wire_type) {
        .varint => {
            const v = try decodeVarint(buf, pos);
            return Field{ .number = field_number, .wire_type = .varint, .data = .{ .varint = v } };
        },
        .i64 => {
            if (pos.* + 8 > buf.len) return DecodeError.Truncated;
            const v = mem.readInt(u64, buf[pos.*..][0..8], .little);
            pos.* += 8;
            return Field{ .number = field_number, .wire_type = .i64, .data = .{ .i64 = v } };
        },
        .len => {
            const length: usize = @intCast(try decodeVarint(buf, pos));
            if (pos.* + length > buf.len) return DecodeError.Truncated;
            const data = buf[pos.* .. pos.* + length];
            pos.* += length;
            return Field{ .number = field_number, .wire_type = .len, .data = .{ .len = data } };
        },
        .i32 => {
            if (pos.* + 4 > buf.len) return DecodeError.Truncated;
            const v = mem.readInt(u32, buf[pos.*..][0..4], .little);
            pos.* += 4;
            return Field{ .number = field_number, .wire_type = .i32, .data = .{ .i32 = v } };
        },
    };
}

pub const Encoder = struct {
    buf: std.ArrayList(u8),
    allocator: mem.Allocator,

    pub fn init(allocator: mem.Allocator) Encoder {
        return .{ .buf = .empty, .allocator = allocator };
    }

    pub fn deinit(e: *Encoder) void {
        e.buf.deinit(e.allocator);
    }

    pub fn toOwnedSlice(e: *Encoder) ![]u8 {
        return e.buf.toOwnedSlice(e.allocator);
    }

    pub fn writeVarintField(e: *Encoder, field_number: u32, value: u64) !void {
        var tag_buf: [10]u8 = undefined;
        const tag = (@as(u64, field_number) << 3) | 0; // wire type 0
        const tag_len = encodeVarint(tag, &tag_buf);
        try e.buf.appendSlice(e.allocator, tag_buf[0..tag_len]);
        var val_buf: [10]u8 = undefined;
        const val_len = encodeVarint(value, &val_buf);
        try e.buf.appendSlice(e.allocator, val_buf[0..val_len]);
    }

    pub fn writeBytesField(e: *Encoder, field_number: u32, data: []const u8) !void {
        var tag_buf: [10]u8 = undefined;
        const tag = (@as(u64, field_number) << 3) | 2; // wire type 2
        const tag_len = encodeVarint(tag, &tag_buf);
        try e.buf.appendSlice(e.allocator, tag_buf[0..tag_len]);
        var len_buf: [10]u8 = undefined;
        const len_len = encodeVarint(data.len, &len_buf);
        try e.buf.appendSlice(e.allocator, len_buf[0..len_len]);
        try e.buf.appendSlice(e.allocator, data);
    }

    pub fn writeFixed64Field(e: *Encoder, field_number: u32, value: u64) !void {
        var tag_buf: [10]u8 = undefined;
        const tag = (@as(u64, field_number) << 3) | 1; // wire type 1
        const tag_len = encodeVarint(tag, &tag_buf);
        try e.buf.appendSlice(e.allocator, tag_buf[0..tag_len]);
        var val_bytes: [8]u8 = undefined;
        mem.writeInt(u64, &val_bytes, value, .little);
        try e.buf.appendSlice(e.allocator, &val_bytes);
    }

    pub fn writeBoolField(e: *Encoder, field_number: u32, value: bool) !void {
        try e.writeVarintField(field_number, if (value) 1 else 0);
    }
};
