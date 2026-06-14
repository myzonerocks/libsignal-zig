//! C FFI library root — compiles all signal_ffi.h-compatible modules.
//! Root is at src/ so ffi/*.zig can reach ../curve.zig etc. without crossing
//! the module boundary.

comptime {
    _ = @import("ffi/error.zig");
    _ = @import("ffi/keys.zig");
    _ = @import("ffi/crypto.zig");
    _ = @import("ffi/address.zig");
    _ = @import("ffi/records.zig");
    _ = @import("ffi/messages.zig");
    _ = @import("ffi/bundle.zig");
    _ = @import("ffi/session.zig");
    _ = @import("ffi/sealed_sender.zig");
    _ = @import("ffi/identity_misc.zig");
    _ = @import("ffi/stubs.zig");
}
