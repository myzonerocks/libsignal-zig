// Signal typed identities: ACI (Account Identifier) and PNI (Phone Number Identifier).
// Wire formats:
//   fixed-width binary (17 bytes): type_byte || uuid_bytes[16]  — used in SSv2, addresses field
//   variable-width binary: ACI=16 bytes (no prefix), PNI=17 bytes (0x01 || uuid)
//   string: ACI="uuid-string", PNI="PNI:uuid-string"
const std = @import("std");
const uuid_mod = @import("uuid.zig");
const mem = std.mem;

pub const SERVICE_ID_STRING_MAX_LEN = 40; // "PNI:" + 36-char UUID

pub const ServiceIdKind = enum(u8) {
    aci = 0x00,
    pni = 0x01,
};

pub const Aci = struct {
    uuid: uuid_mod.Uuid,

    pub fn fromUuid(u: uuid_mod.Uuid) Aci {
        return .{ .uuid = u };
    }

    pub fn toServiceId(self: Aci) ServiceId {
        return .{ .aci = self };
    }
};

pub const Pni = struct {
    uuid: uuid_mod.Uuid,

    pub fn fromUuid(u: uuid_mod.Uuid) Pni {
        return .{ .uuid = u };
    }

    pub fn toServiceId(self: Pni) ServiceId {
        return .{ .pni = self };
    }
};

pub const ServiceId = union(ServiceIdKind) {
    aci: Aci,
    pni: Pni,

    pub fn kind(self: ServiceId) ServiceIdKind {
        return std.meta.activeTag(self);
    }

    /// 17-byte binary for wire formats (SSv2 recipients, addresses field).
    /// Format: type_byte || uuid_bytes[16] big-endian.
    pub fn toFixedWidthBinary(self: ServiceId) [17]u8 {
        var result: [17]u8 = undefined;
        result[0] = @intFromEnum(self.kind());
        switch (self) {
            .aci => |a| @memcpy(result[1..17], &a.uuid.bytes),
            .pni => |p| @memcpy(result[1..17], &p.uuid.bytes),
        }
        return result;
    }

    /// Parse from 17-byte fixed-width binary.
    pub fn fromFixedWidthBinary(b: [17]u8) !ServiceId {
        const uuid = uuid_mod.Uuid.fromBytes(b[1..17].*);
        return switch (b[0]) {
            0x00 => .{ .aci = .{ .uuid = uuid } },
            0x01 => .{ .pni = .{ .uuid = uuid } },
            else => error.InvalidServiceId,
        };
    }

    /// Variable-width binary: ACI = 16 bytes (raw UUID, no prefix), PNI = 17 bytes (0x01 || uuid).
    /// Returns a slice into the provided 17-byte buffer.
    pub fn toBinary(self: ServiceId, buf: *[17]u8) []u8 {
        switch (self) {
            .aci => |a| {
                @memcpy(buf[0..16], &a.uuid.bytes);
                return buf[0..16];
            },
            .pni => |p| {
                buf[0] = 0x01;
                @memcpy(buf[1..17], &p.uuid.bytes);
                return buf[0..17];
            },
        }
    }

    /// Parse from variable-width binary (16 bytes → ACI, 17 bytes → PNI).
    pub fn fromBinary(b: []const u8) !ServiceId {
        if (b.len == 16) {
            return .{ .aci = .{ .uuid = uuid_mod.Uuid.fromBytes(b[0..16].*) } };
        } else if (b.len == 17) {
            if (b[0] != 0x01) return error.InvalidServiceId;
            return .{ .pni = .{ .uuid = uuid_mod.Uuid.fromBytes(b[1..17].*) } };
        }
        return error.InvalidServiceId;
    }

    /// Parse from string. ACI: plain hyphenated UUID. PNI: "PNI:" + hyphenated UUID.
    pub fn parseFromString(s: []const u8) !ServiceId {
        if (mem.startsWith(u8, s, "PNI:")) {
            const uuid = try uuid_mod.Uuid.parse(s[4..]);
            return .{ .pni = .{ .uuid = uuid } };
        }
        const uuid = try uuid_mod.Uuid.parse(s);
        return .{ .aci = .{ .uuid = uuid } };
    }

    /// Write the string form into buf. Returns the written slice.
    /// buf must be at least SERVICE_ID_STRING_MAX_LEN bytes.
    pub fn toString(self: ServiceId, buf: []u8) []const u8 {
        return switch (self) {
            .aci => |a| std.fmt.bufPrint(buf, "{}", .{a.uuid}) catch unreachable,
            .pni => |p| std.fmt.bufPrint(buf, "PNI:{}", .{p.uuid}) catch unreachable,
        };
    }

    pub fn eql(a: ServiceId, b: ServiceId) bool {
        return switch (a) {
            .aci => |ac| switch (b) {
                .aci => |bc| uuid_mod.Uuid.eql(ac.uuid, bc.uuid),
                .pni => false,
            },
            .pni => |ap| switch (b) {
                .pni => |bp| uuid_mod.Uuid.eql(ap.uuid, bp.uuid),
                .aci => false,
            },
        };
    }
};

test "service_id aci roundtrip" {
    const u = uuid_mod.Uuid.generate();
    const sid = Aci.fromUuid(u).toServiceId();

    const bin = sid.toFixedWidthBinary();
    try std.testing.expectEqual(@as(u8, 0x00), bin[0]);
    const sid2 = try ServiceId.fromFixedWidthBinary(bin);
    try std.testing.expect(ServiceId.eql(sid, sid2));

    var strbuf: [SERVICE_ID_STRING_MAX_LEN]u8 = undefined;
    const s = sid.toString(&strbuf);
    const sid3 = try ServiceId.parseFromString(s);
    try std.testing.expect(ServiceId.eql(sid, sid3));
}

test "service_id pni roundtrip" {
    const u = uuid_mod.Uuid.generate();
    const sid = Pni.fromUuid(u).toServiceId();

    const bin = sid.toFixedWidthBinary();
    try std.testing.expectEqual(@as(u8, 0x01), bin[0]);
    const sid2 = try ServiceId.fromFixedWidthBinary(bin);
    try std.testing.expect(ServiceId.eql(sid, sid2));

    var strbuf: [SERVICE_ID_STRING_MAX_LEN]u8 = undefined;
    const s = sid.toString(&strbuf);
    try std.testing.expect(mem.startsWith(u8, s, "PNI:"));
    const sid3 = try ServiceId.parseFromString(s);
    try std.testing.expect(ServiceId.eql(sid, sid3));
}
