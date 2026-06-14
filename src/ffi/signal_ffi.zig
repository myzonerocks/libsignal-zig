//! C FFI entry point — pulls in all signal_ffi.h-compatible modules so their
//! `pub export` symbols are included in the compiled library.

comptime {
    _ = @import("error.zig");
    _ = @import("keys.zig");
    _ = @import("crypto.zig");
    _ = @import("address.zig");
    _ = @import("records.zig");
    _ = @import("messages.zig");
    _ = @import("bundle.zig");
    _ = @import("session.zig");
}
