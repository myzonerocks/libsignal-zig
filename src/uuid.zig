// UUID (RFC 4122) type — foundation for ServiceId and group distribution IDs.
const std = @import("std");
const rnd = @import("random.zig");
const mem = std.mem;

pub const UUID_STRING_LEN = 36; // "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

pub const Uuid = struct {
    bytes: [16]u8,

    /// Generate a random v4 UUID.
    pub fn generate() Uuid {
        var b: [16]u8 = undefined;
        rnd.bytes(&b);
        b[6] = (b[6] & 0x0F) | 0x40; // version 4
        b[8] = (b[8] & 0x3F) | 0x80; // variant 10xx
        return .{ .bytes = b };
    }

    pub fn fromBytes(b: [16]u8) Uuid {
        return .{ .bytes = b };
    }

    pub fn eql(a: Uuid, b: Uuid) bool {
        return mem.eql(u8, &a.bytes, &b.bytes);
    }

    /// Parse a hyphenated UUID string: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
    pub fn parse(s: []const u8) !Uuid {
        if (s.len != UUID_STRING_LEN) return error.InvalidUuid;
        if (s[8] != '-' or s[13] != '-' or s[18] != '-' or s[23] != '-') return error.InvalidUuid;
        var out: [16]u8 = undefined;
        var dst: usize = 0;
        var src: usize = 0;
        while (dst < 16) {
            if (src == 8 or src == 13 or src == 18 or src == 23) src += 1;
            if (src + 1 >= s.len) return error.InvalidUuid;
            const hi = std.fmt.charToDigit(s[src], 16) catch return error.InvalidUuid;
            const lo = std.fmt.charToDigit(s[src + 1], 16) catch return error.InvalidUuid;
            out[dst] = (hi << 4) | lo;
            src += 2;
            dst += 1;
        }
        return .{ .bytes = out };
    }

    pub fn format(
        self: Uuid,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        const b = self.bytes;
        try writer.print(
            "{x:0>2}{x:0>2}{x:0>2}{x:0>2}-{x:0>2}{x:0>2}-{x:0>2}{x:0>2}-{x:0>2}{x:0>2}-{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}",
            .{ b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15] },
        );
    }
};

test "uuid v4 generate" {
    const u = Uuid.generate();
    try std.testing.expectEqual(@as(u8, 0x40), u.bytes[6] & 0xF0); // version 4
    try std.testing.expectEqual(@as(u8, 0x80), u.bytes[8] & 0xC0); // variant 10
}

test "uuid parse roundtrip" {
    const u = Uuid.generate();
    var buf: [UUID_STRING_LEN]u8 = undefined;
    const s = try std.fmt.bufPrint(&buf, "{}", .{u});
    const parsed = try Uuid.parse(s);
    try std.testing.expect(Uuid.eql(u, parsed));
}
