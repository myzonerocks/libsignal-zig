//! SignalProtocolAddress opaque type.

const std = @import("std");
const err_mod = @import("error.zig");
const keys = @import("keys.zig");
const gpa = std.heap.c_allocator;

const SignalFfiError = err_mod.SignalFfiError;
const SignalOwnedBuffer = keys.SignalOwnedBuffer;
const SignalBorrowedBuffer = keys.SignalBorrowedBuffer;

pub const SignalProtocolAddress = struct {
    name: [:0]u8, // owned, null-terminated for C callers
    device_id: u32,

    pub fn deinit(self: *SignalProtocolAddress) void {
        gpa.free(self.name);
    }
};

pub const SignalMutPointerProtocolAddress = extern struct { raw: ?*SignalProtocolAddress };
pub const SignalConstPointerProtocolAddress = extern struct { raw: ?*const SignalProtocolAddress };

pub export fn signal_address_new(out: *SignalMutPointerProtocolAddress, name: [*:0]const u8, device_id: u32) ?*SignalFfiError {
    const name_slice = std.mem.span(name);
    const obj = gpa.create(SignalProtocolAddress) catch return err_mod.alloc(.internal_error, "OOM");
    obj.name = gpa.dupeZ(u8, name_slice) catch {
        gpa.destroy(obj);
        return err_mod.alloc(.internal_error, "OOM");
    };
    obj.device_id = device_id;
    out.raw = obj;
    return null;
}

pub export fn signal_address_clone(new_obj: *SignalMutPointerProtocolAddress, obj: SignalConstPointerProtocolAddress) ?*SignalFfiError {
    const src = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    const copy = gpa.create(SignalProtocolAddress) catch return err_mod.alloc(.internal_error, "OOM");
    copy.name = gpa.dupeZ(u8, src.name) catch {
        gpa.destroy(copy);
        return err_mod.alloc(.internal_error, "OOM");
    };
    copy.device_id = src.device_id;
    new_obj.raw = copy;
    return null;
}

pub export fn signal_address_destroy(p: SignalMutPointerProtocolAddress) ?*SignalFfiError {
    if (p.raw) |obj| {
        obj.deinit();
        gpa.destroy(obj);
    }
    return null;
}

pub export fn signal_address_get_name(out: *[*:0]const u8, obj: SignalConstPointerProtocolAddress) ?*SignalFfiError {
    const addr = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    out.* = addr.name.ptr;
    return null;
}

pub export fn signal_address_get_device_id(out: *u32, obj: SignalConstPointerProtocolAddress) ?*SignalFfiError {
    const addr = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    out.* = addr.device_id;
    return null;
}
