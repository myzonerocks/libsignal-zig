//! SignalFfiError — heap-allocated opaque error type returned by every FFI function.
//!
//! Contract: NULL return = success. Non-NULL = caller must call signal_error_free().

const std = @import("std");
const gpa = std.heap.c_allocator;

// ── Error codes ─────────────────

pub const SignalErrorCode = enum(u32) {
    unknown_error = 1,
    invalid_state = 2,
    internal_error = 3,
    null_parameter = 4,
    invalid_argument = 5,
    invalid_type = 6,
    invalid_utf8_string = 7,
    cancelled = 8,
    protobuf_error = 10,
    legacy_ciphertext_version = 21,
    unknown_ciphertext_version = 22,
    unrecognized_message_version = 23,
    invalid_message = 30,
    sealed_sender_self_send = 31,
    invalid_key = 40,
    invalid_signature = 41,
    invalid_attestation_data = 42,
    fingerprint_version_mismatch = 51,
    fingerprint_parsing_error = 52,
    untrusted_identity = 60,
    invalid_key_identifier = 70,
    session_not_found = 80,
    invalid_registration_id = 81,
    invalid_session = 82,
    invalid_sender_key_session = 83,
    invalid_protocol_address = 84,
    duplicated_message = 90,
    callback_error = 100,
    verification_failure = 110,
    username_cannot_be_empty = 120,
    username_cannot_start_with_digit = 121,
    username_missing_separator = 122,
    username_bad_discriminator_character = 123,
    username_bad_nickname_character = 124,
    username_too_short = 125,
    username_too_long = 126,
    username_link_invalid_entropy_data_length = 127,
    username_link_invalid = 128,
    username_discriminator_cannot_be_empty = 130,
    username_discriminator_cannot_be_zero = 131,
    username_discriminator_cannot_be_single_digit = 132,
    username_discriminator_cannot_have_leading_zeros = 133,
    username_discriminator_too_large = 134,
    io_error = 140,
    invalid_media_input = 141,
    unsupported_media_input = 142,
    connection_timed_out = 143,
    network_protocol = 144,
    rate_limited = 145,
    web_socket = 146,
    cdsi_invalid_token = 147,
    connection_failed = 148,
    chat_service_inactive = 149,
    request_timed_out = 150,
    rate_limit_challenge = 151,
    possible_captive_network = 152,
    svr_data_missing = 160,
    svr_restore_failed = 161,
    svr_rotation_machine_too_many_steps = 162,
    svr_request_failed = 163,
    app_expired = 170,
    device_deregistered = 171,
    connection_invalidated = 172,
    connected_elsewhere = 173,
    backup_validation = 180,
    registration_invalid_session_id = 190,
    registration_unknown = 192,
    registration_session_not_found = 193,
    registration_not_ready_for_verification = 194,
    registration_send_verification_code_failed = 195,
    registration_code_not_deliverable = 196,
    registration_session_update_rejected = 197,
    registration_credentials_could_not_be_parsed = 198,
    registration_device_transfer_possible = 199,
    registration_recovery_verification_failed = 200,
    registration_lock = 201,
    key_transparency_error = 210,
    key_transparency_verification_failed = 211,
    request_unauthorized = 220,
    mismatched_devices = 221,
    service_id_not_found = 222,
    upload_too_large = 223,
    _,
};

// ── Optional context payloads ──────────────────────────────────────────────────

pub const ErrorAddress = struct {
    name: []u8,
    device_id: u32,
};

pub const ErrorInvalidProtocolAddress = struct {
    name: []u8,
    device_id: u32,
};

pub const ErrorRegistrationLock = struct {
    time_remaining_seconds: u64,
    svr2_username: []u8,
    svr2_password: []u8,
};

pub const ErrorRateLimitChallenge = struct {
    token: []u8,
    options: []u8,
    retry_after: i64,
};

pub const ErrorRegistrationNotDeliverable = struct {
    transport: []u8,
    may_retry: bool,
};

pub const MismatchedDevicesEntry = struct {
    account: [17]u8,
    missing_devices: []u32,
    extra_devices: []u32,
    stale_devices: []u32,
};

pub const ErrorContext = union(enum) {
    none,
    address: ErrorAddress,
    uuid: [16]u8,
    retry_after_seconds: u32,
    tries_remaining: u32,
    our_fingerprint_version: u32,
    their_fingerprint_version: u32,
    invalid_protocol_address: ErrorInvalidProtocolAddress,
    registration_lock: ErrorRegistrationLock,
    rate_limit_challenge: ErrorRateLimitChallenge,
    registration_not_deliverable: ErrorRegistrationNotDeliverable,
    mismatched_devices: []MismatchedDevicesEntry,
    unknown_fields: [][]u8,
};

// ── SignalFfiError opaque type ─────────────────────────────────────────────────

pub const SignalFfiError = struct {
    code: SignalErrorCode,
    message: [:0]u8, // always null-terminated so .ptr is a valid C string
    context: ErrorContext,

    pub fn deinit(self: *SignalFfiError) void {
        gpa.free(self.message);
        switch (self.context) {
            .none => {},
            .address => |a| gpa.free(a.name),
            .uuid => {},
            .retry_after_seconds => {},
            .tries_remaining => {},
            .our_fingerprint_version => {},
            .their_fingerprint_version => {},
            .invalid_protocol_address => |p| gpa.free(p.name),
            .registration_lock => |r| {
                gpa.free(r.svr2_username);
                gpa.free(r.svr2_password);
            },
            .rate_limit_challenge => |r| {
                gpa.free(r.token);
                gpa.free(r.options);
            },
            .registration_not_deliverable => |r| gpa.free(r.transport),
            .mismatched_devices => |md| {
                for (md) |*e| {
                    gpa.free(e.missing_devices);
                    gpa.free(e.extra_devices);
                    gpa.free(e.stale_devices);
                }
                gpa.free(md);
            },
            .unknown_fields => |uf| {
                for (uf) |f| gpa.free(f);
                gpa.free(uf);
            },
        }
    }
};

// ── Allocation helpers ─────────────────────────────────────────────────────────

pub fn alloc(code: SignalErrorCode, msg: []const u8) *SignalFfiError {
    const e = gpa.create(SignalFfiError) catch @panic("OOM allocating SignalFfiError");
    e.* = .{
        .code = code,
        .message = gpa.dupeZ(u8, msg) catch @panic("OOM duplicating error message"),
        .context = .none,
    };
    return e;
}

pub fn allocWithContext(code: SignalErrorCode, msg: []const u8, ctx: ErrorContext) *SignalFfiError {
    const e = alloc(code, msg);
    e.context = ctx;
    return e;
}

/// Map a Zig error to a SignalFfiError. This is the primary error conversion path.
pub fn fromZigError(e: anyerror) *SignalFfiError {
    const sig_err = @import("../error.zig");
    return switch (e) {
        sig_err.SignalError.InvalidKey,
        sig_err.SignalError.WeakPublicKey,
        sig_err.SignalError.IdentityElement,
        => alloc(.invalid_key, "Invalid key"),

        sig_err.SignalError.InvalidSignature,
        sig_err.SignalError.SignatureMismatch,
        => alloc(.invalid_signature, "Invalid signature"),

        sig_err.SignalError.InvalidMessage => alloc(.invalid_message, "Invalid message"),

        sig_err.SignalError.LegacyCiphertextVersion => alloc(.legacy_ciphertext_version, "Legacy ciphertext version"),

        sig_err.SignalError.UnknownCiphertextVersion => alloc(.unknown_ciphertext_version, "Unknown ciphertext version"),

        sig_err.SignalError.UnrecognizedMessageVersion => alloc(.unrecognized_message_version, "Unrecognized message version"),

        sig_err.SignalError.UntrustedIdentity => alloc(.untrusted_identity, "Untrusted identity"),

        sig_err.SignalError.DuplicateMessage => alloc(.duplicated_message, "Duplicate message"),

        sig_err.SignalError.InvalidKeyIdentifier,
        sig_err.SignalError.SessionNotFound,
        => alloc(.invalid_key_identifier, "Key/session not found"),

        sig_err.SignalError.InvalidSession => alloc(.invalid_session, "Invalid session"),

        sig_err.SignalError.InvalidArgument => alloc(.invalid_argument, "Invalid argument"),

        sig_err.SignalError.InvalidType => alloc(.invalid_type, "Invalid type"),

        sig_err.SignalError.InvalidUtf8String => alloc(.invalid_utf8_string, "Invalid UTF-8 string"),

        sig_err.SignalError.FingerprintVersionMismatch => alloc(.fingerprint_version_mismatch, "Fingerprint version mismatch"),

        sig_err.SignalError.FingerprintIdentifierMismatch => alloc(.fingerprint_parsing_error, "Fingerprint identifier mismatch"),

        sig_err.SignalError.ProtobufError => alloc(.protobuf_error, "Protobuf encoding error"),

        sig_err.SignalError.NullParameter => alloc(.null_parameter, "Null parameter"),

        sig_err.SignalError.CallbackError => alloc(.callback_error, "Callback error"),

        sig_err.SignalError.VerifyFailed => alloc(.verification_failure, "Verification failed"),

        sig_err.SignalError.OutOfMemory => alloc(.internal_error, "Out of memory"),

        sig_err.SignalError.InvalidState => alloc(.invalid_state, "Invalid state"),

        else => alloc(.internal_error, @errorName(e)),
    };
}

/// Convenience: wrap a fallible call, return null on success or *SignalFfiError on failure.
pub inline fn wrap(result: anytype) ?*SignalFfiError {
    _ = result catch |e| return fromZigError(e);
    return null;
}

// ── C-exported error lifecycle + getters ──────────────────────────────────────
// NULL return = success (consistent with all other FFI functions).

pub export fn signal_error_free(e: ?*SignalFfiError) void {
    if (e) |err_ptr| {
        err_ptr.deinit();
        gpa.destroy(err_ptr);
    }
}

pub export fn signal_error_get_type(out: *u32, e: *const SignalFfiError) ?*SignalFfiError {
    out.* = @intFromEnum(e.code);
    return null;
}

/// Returns a borrowed C string valid until signal_error_free is called.
pub export fn signal_error_get_message(out: *[*:0]const u8, e: *const SignalFfiError) ?*SignalFfiError {
    out.* = e.message.ptr;
    return null;
}

pub export fn signal_error_get_address(out_name: *[*:0]const u8, out_device_id: *u32, e: *const SignalFfiError) ?*SignalFfiError {
    switch (e.context) {
        .address => |a| {
            out_name.* = @ptrCast(a.name.ptr);
            out_device_id.* = a.device_id;
        },
        else => return alloc(.invalid_argument, "error has no address context"),
    }
    return null;
}

pub export fn signal_error_get_uuid(out: *[*]const u8, e: *const SignalFfiError) ?*SignalFfiError {
    switch (e.context) {
        .uuid => |*u| {
            out.* = u;
        },
        else => return alloc(.invalid_argument, "error has no uuid context"),
    }
    return null;
}

pub export fn signal_error_get_retry_after_seconds(out: *u32, e: *const SignalFfiError) ?*SignalFfiError {
    switch (e.context) {
        .retry_after_seconds => |s| {
            out.* = s;
        },
        else => return alloc(.invalid_argument, "error has no retry_after_seconds context"),
    }
    return null;
}

pub export fn signal_error_get_tries_remaining(out: *u32, e: *const SignalFfiError) ?*SignalFfiError {
    switch (e.context) {
        .tries_remaining => |t| {
            out.* = t;
        },
        else => return alloc(.invalid_argument, "error has no tries_remaining context"),
    }
    return null;
}

pub export fn signal_error_get_our_fingerprint_version(out: *u32, e: *const SignalFfiError) ?*SignalFfiError {
    switch (e.context) {
        .our_fingerprint_version => |v| {
            out.* = v;
        },
        else => return alloc(.invalid_argument, "error has no our_fingerprint_version context"),
    }
    return null;
}

pub export fn signal_error_get_their_fingerprint_version(out: *u32, e: *const SignalFfiError) ?*SignalFfiError {
    switch (e.context) {
        .their_fingerprint_version => |v| {
            out.* = v;
        },
        else => return alloc(.invalid_argument, "error has no their_fingerprint_version context"),
    }
    return null;
}

pub export fn signal_error_get_invalid_protocol_address(out_name: *[*:0]const u8, out_device_id: *u32, e: *const SignalFfiError) ?*SignalFfiError {
    switch (e.context) {
        .invalid_protocol_address => |p| {
            out_name.* = @ptrCast(p.name.ptr);
            out_device_id.* = p.device_id;
        },
        else => return alloc(.invalid_argument, "error has no invalid_protocol_address context"),
    }
    return null;
}

pub export fn signal_error_get_registration_lock(out_time_remaining: *u64, out_svr2_username: *[*:0]const u8, out_svr2_password: *[*:0]const u8, e: *const SignalFfiError) ?*SignalFfiError {
    switch (e.context) {
        .registration_lock => |r| {
            out_time_remaining.* = r.time_remaining_seconds;
            out_svr2_username.* = @ptrCast(r.svr2_username.ptr);
            out_svr2_password.* = @ptrCast(r.svr2_password.ptr);
        },
        else => return alloc(.invalid_argument, "error has no registration_lock context"),
    }
    return null;
}

pub export fn signal_error_get_rate_limit_challenge(out_token: *[*:0]const u8, out_options: *[*:0]const u8, out_retry_after: *i64, e: *const SignalFfiError) ?*SignalFfiError {
    switch (e.context) {
        .rate_limit_challenge => |r| {
            out_token.* = @ptrCast(r.token.ptr);
            out_options.* = @ptrCast(r.options.ptr);
            out_retry_after.* = r.retry_after;
        },
        else => return alloc(.invalid_argument, "error has no rate_limit_challenge context"),
    }
    return null;
}

pub export fn signal_error_get_registration_error_not_deliverable(out_transport: *[*:0]const u8, out_may_retry: *bool, e: *const SignalFfiError) ?*SignalFfiError {
    switch (e.context) {
        .registration_not_deliverable => |r| {
            out_transport.* = @ptrCast(r.transport.ptr);
            out_may_retry.* = r.may_retry;
        },
        else => return alloc(.invalid_argument, "error has no registration_not_deliverable context"),
    }
    return null;
}

pub export fn signal_error_get_mismatched_device_errors(out_count: *usize, e: *const SignalFfiError) ?*SignalFfiError {
    switch (e.context) {
        .mismatched_devices => |md| {
            out_count.* = md.len;
        },
        else => return alloc(.invalid_argument, "error has no mismatched_devices context"),
    }
    return null;
}

pub export fn signal_error_get_unknown_fields(out_count: *usize, e: *const SignalFfiError) ?*SignalFfiError {
    switch (e.context) {
        .unknown_fields => |uf| {
            out_count.* = uf.len;
        },
        else => return alloc(.invalid_argument, "error has no unknown_fields context"),
    }
    return null;
}

// ── Buffer / string free functions ────────────────────────────────────────────

pub export fn signal_free_buffer(buf: ?[*]u8, len: usize) void {
    if (buf) |ptr| gpa.free(ptr[0..len]);
}

pub export fn signal_free_string(s: ?[*:0]u8) void {
    if (s) |ptr| gpa.free(std.mem.span(ptr));
}

pub export fn signal_free_list_of_strings(strs: ?[*][*:0]u8, len: usize) void {
    if (strs) |ptr| {
        for (ptr[0..len]) |s| gpa.free(std.mem.span(s));
        gpa.free(ptr[0..len]);
    }
}

// ── Logger ─────────────────────────────────────────────────────────────────────

pub const SignalFfiLogLevel = enum(u32) {
    error_level = 1,
    warn = 2,
    info = 3,
    debug = 4,
    trace = 5,
};

pub const SignalFfiLoggerCallback = ?*const fn (
    level: u32,
    file: ?[*:0]const u8,
    line: u32,
    message: ?[*:0]const u8,
    ctx: ?*anyopaque,
) callconv(.c) void;

var g_log_callback: SignalFfiLoggerCallback = null;
var g_log_ctx: ?*anyopaque = null;
var g_log_max_level: u32 = 0;

pub export fn signal_init_logger(max_level: u32, callback: SignalFfiLoggerCallback, ctx: ?*anyopaque) ?*SignalFfiError {
    g_log_max_level = max_level;
    g_log_callback = callback;
    g_log_ctx = ctx;
    return null;
}

// ── Utility ───────────────────────────────────────────────────────────────────

pub export fn signal_print_ptr(out: *[*:0]u8, ptr: ?*const anyopaque) ?*SignalFfiError {
    const addr: usize = if (ptr) |p| @intFromPtr(p) else 0;
    const s = std.fmt.allocPrint(gpa, "0x{x}\x00", .{addr}) catch return alloc(.internal_error, "OOM");
    out.* = @ptrCast(s.ptr);
    return null;
}

pub export fn signal_hex_encode(out: *[*:0]u8, bytes: @import("keys.zig").SignalBorrowedBuffer) ?*SignalFfiError {
    const src = bytes.slice();
    const hex_chars = "0123456789abcdef";
    const result = gpa.allocSentinel(u8, src.len * 2, 0) catch return alloc(.internal_error, "OOM");
    for (src, 0..) |b, i| {
        result[i * 2] = hex_chars[b >> 4];
        result[i * 2 + 1] = hex_chars[b & 0xF];
    }
    out.* = result.ptr;
    return null;
}

// ── SignalBytestringArray ──────────────────────────────────────────────────────

pub const SignalBytestringArray = extern struct {
    bytes: ?[*]const u8,
    lengths: ?[*]usize,
    count: usize,
};

pub export fn signal_bytestring_array_free(arr: SignalBytestringArray) void {
    if (arr.count == 0) return;
    if (arr.lengths) |lens| {
        if (arr.bytes) |base| {
            var offset: usize = 0;
            for (lens[0..arr.count]) |len| {
                _ = base[offset .. offset + len];
                offset += len;
            }
            gpa.free(base[0..offset]);
        }
        gpa.free(lens[0..arr.count]);
    }
}
