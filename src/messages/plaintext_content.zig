// PlaintextContent: wraps a plaintext payload for cases where no encryption is applied
// (e.g., delivery receipts when the session is already established).
const std = @import("std");
const proto = @import("../proto.zig");
const err = @import("../error.zig");
const mem = std.mem;

pub const CONTENT_HINT_DEFAULT: u8 = 0;
pub const CONTENT_HINT_RESENDABLE: u8 = 1;
pub const CONTENT_HINT_IMPLICIT: u8 = 2;

pub const MESSAGE_VERSION: u8 = 3;
pub const VERSION_BYTE: u8 = (MESSAGE_VERSION << 4) | MESSAGE_VERSION;

pub const PlaintextContent = struct {
    body: []const u8,
    allocator: mem.Allocator,

    pub fn new(allocator: mem.Allocator, body: []const u8) !PlaintextContent {
        return .{
            .body = try allocator.dupe(u8, body),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *PlaintextContent) void {
        self.allocator.free(self.body);
    }

    pub fn serialize(self: PlaintextContent) ![]u8 {
        const allocator = self.allocator;
        var enc = proto.Encoder.init(allocator);
        defer enc.deinit();
        try enc.writeBytesField(1, self.body);
        const body_enc = try enc.toOwnedSlice();
        defer allocator.free(body_enc);

        const out = try allocator.alloc(u8, 1 + body_enc.len);
        out[0] = VERSION_BYTE;
        @memcpy(out[1..], body_enc);
        return out;
    }

    pub fn deserialize(allocator: mem.Allocator, data: []const u8) !PlaintextContent {
        if (data.len < 1) return err.SignalError.InvalidMessage;
        const version = data[0] >> 4;
        _ = version;
        const body_bytes = data[1..];
        var pos: usize = 0;
        var content: ?[]const u8 = null;
        while (try proto.nextField(body_bytes, &pos)) |field| {
            if (field.number == 1 and field.wire_type == .len) {
                content = field.data.len;
            }
        }
        const c = content orelse return err.SignalError.InvalidMessage;
        return .{
            .body = try allocator.dupe(u8, c),
            .allocator = allocator,
        };
    }
};
