const std = @import("std");
const mem = std.mem;

/// A Signal Protocol address: name + device_id.
/// `name` is a borrowed slice — caller owns its lifetime.
pub const ProtocolAddress = struct {
    name: []const u8,
    device_id: u32,

    pub fn eql(a: ProtocolAddress, b: ProtocolAddress) bool {
        return a.device_id == b.device_id and mem.eql(u8, a.name, b.name);
    }

    pub fn format(
        self: ProtocolAddress,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        try writer.print("{s}:{d}", .{ self.name, self.device_id });
    }
};

/// Identifies a sender within a group.
/// All slices are borrowed — caller owns their lifetime.
pub const SenderKeyName = struct {
    group_id: []const u8,
    sender: ProtocolAddress,

    pub fn eql(a: SenderKeyName, b: SenderKeyName) bool {
        return mem.eql(u8, a.group_id, b.group_id) and ProtocolAddress.eql(a.sender, b.sender);
    }
};
