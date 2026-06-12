const std = @import("std");
const builtin = @import("builtin");

extern fn arc4random_buf(ptr: [*]u8, nbytes: usize) void;

pub fn bytes(buf: []u8) void {
    if (builtin.os.tag == .linux) {
        var offset: usize = 0;
        while (offset < buf.len) {
            const n = std.os.linux.getrandom(buf.ptr + offset, buf.len - offset, 0);
            if (n > 0) offset += n;
        }
    } else {
        arc4random_buf(buf.ptr, buf.len);
    }
}

pub fn fillArray(comptime N: usize) [N]u8 {
    var buf: [N]u8 = undefined;
    bytes(&buf);
    return buf;
}
