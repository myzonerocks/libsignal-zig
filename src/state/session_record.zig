const std = @import("std");
const SessionState = @import("session_state.zig").SessionState;
const proto = @import("../proto.zig");
const err = @import("../error.zig");
const mem = std.mem;

pub const MAX_ARCHIVED_STATES: usize = 40;

pub const SessionRecord = struct {
    current_state: ?SessionState,
    previous_sessions: std.ArrayList([]u8), // serialized previous states
    allocator: mem.Allocator,

    pub fn new(allocator: mem.Allocator) SessionRecord {
        return .{
            .current_state = null,
            .previous_sessions = .empty,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *SessionRecord) void {
        if (self.current_state) |*cs| cs.deinit();
        for (self.previous_sessions.items) |ps| self.allocator.free(ps);
        self.previous_sessions.deinit(self.allocator);
    }

    pub fn hasCurrentSession(self: SessionRecord) bool {
        return self.current_state != null;
    }

    pub fn currentState(self: *SessionRecord) ?*SessionState {
        return if (self.current_state != null) &self.current_state.? else null;
    }

    pub fn archiveCurrentState(self: *SessionRecord) !void {
        if (self.current_state) |*cs| {
            const serialized = try cs.serialize(self.allocator);
            try self.previous_sessions.insert(self.allocator, 0, serialized);
            if (self.previous_sessions.items.len > MAX_ARCHIVED_STATES) {
                const old = self.previous_sessions.pop();
                self.allocator.free(old.?);
            }
            cs.deinit();
            self.current_state = null;
        }
    }

    pub fn promoteState(self: *SessionRecord, state: SessionState) !void {
        if (self.current_state) |*cs| {
            const serialized = try cs.serialize(self.allocator);
            errdefer self.allocator.free(serialized);
            try self.previous_sessions.insert(self.allocator, 0, serialized);
            if (self.previous_sessions.items.len > MAX_ARCHIVED_STATES) {
                const old = self.previous_sessions.pop();
                self.allocator.free(old.?);
            }
            cs.deinit();
        }
        self.current_state = state;
    }

    pub fn previousSessionHasKey(self: SessionRecord, base_key_bytes: [33]u8) !bool {
        for (self.previous_sessions.items) |ps| {
            const ps_state = SessionState.deserialize(self.allocator, ps) catch continue;
            defer {
                var s = ps_state;
                s.deinit();
            }
            if (ps_state.alice_base_key) |abk| {
                if (std.mem.eql(u8, &abk, &base_key_bytes)) return true;
            }
        }
        return false;
    }

    pub fn serialize(self: SessionRecord) ![]u8 {
        var enc = proto.Encoder.init(self.allocator);
        defer enc.deinit();

        if (self.current_state) |cs| {
            const cs_bytes = try cs.serialize(self.allocator);
            defer self.allocator.free(cs_bytes);
            try enc.writeBytesField(1, cs_bytes);
        }

        for (self.previous_sessions.items) |ps| {
            try enc.writeBytesField(2, ps);
        }

        return enc.toOwnedSlice();
    }

    pub fn deserialize(allocator: mem.Allocator, data: []const u8) !SessionRecord {
        var record = new(allocator);
        errdefer record.deinit();

        var pos: usize = 0;
        while (try proto.nextField(data, &pos)) |field| {
            switch (field.number) {
                1 => if (field.wire_type == .len) {
                    const state = try SessionState.deserialize(allocator, field.data.len);
                    record.current_state = state;
                },
                2 => if (field.wire_type == .len) {
                    const copy = try allocator.dupe(u8, field.data.len);
                    try record.previous_sessions.append(allocator, copy);
                },
                else => {},
            }
        }

        return record;
    }
};
