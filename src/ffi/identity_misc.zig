//! Fingerprint, ServiceId, Username, Account Keys FFI.

const std = @import("std");
const err_mod = @import("error.zig");
const keys = @import("keys.zig");
const fingerprint_mod = @import("../fingerprint.zig");
const service_id_mod = @import("../service_id.zig");
const username_mod = @import("../username.zig");
const account_keys_mod = @import("../account_keys.zig");
const identity_mod = @import("../identity.zig");
const rnd = @import("../random.zig");
const gpa = std.heap.c_allocator;

const SignalFfiError = err_mod.SignalFfiError;
const SignalOwnedBuffer = keys.SignalOwnedBuffer;
const SignalBorrowedBuffer = keys.SignalBorrowedBuffer;
const SignalConstPointerPublicKey = keys.SignalConstPointerPublicKey;

// ── Fingerprint ───────────────────────────────────────────────────────────────

pub const SignalFingerprint = struct {
    displayable: [60]u8,
    scannable_bytes: []u8,

    pub fn deinit(self: *SignalFingerprint) void {
        gpa.free(self.scannable_bytes);
    }
};

pub const SignalMutPointerFingerprint = extern struct { raw: ?*SignalFingerprint };
pub const SignalConstPointerFingerprint = extern struct { raw: ?*const SignalFingerprint };

pub export fn signal_fingerprint_new(
    out: *SignalMutPointerFingerprint,
    iterations: u32,
    version: u32,
    local_identifier: SignalBorrowedBuffer,
    local_key: SignalConstPointerPublicKey,
    remote_identifier: SignalBorrowedBuffer,
    remote_key: SignalConstPointerPublicKey,
) ?*SignalFfiError {
    _ = iterations;
    _ = version;
    const lk = local_key.raw orelse return err_mod.alloc(.null_parameter, "local_key is null");
    const rk = remote_key.raw orelse return err_mod.alloc(.null_parameter, "remote_key is null");
    const local_ik = identity_mod.IdentityKey.fromPublicKey(lk.inner);
    const remote_ik = identity_mod.IdentityKey.fromPublicKey(rk.inner);

    const fp = fingerprint_mod.Fingerprint.compute(gpa, local_ik, local_identifier.slice(), remote_ik, remote_identifier.slice()) catch |e| return err_mod.fromZigError(e);
    const scannable = fp.scannable.serialize() catch return err_mod.alloc(.internal_error, "OOM");
    const obj = gpa.create(SignalFingerprint) catch {
        gpa.free(scannable);
        return err_mod.alloc(.internal_error, "OOM");
    };
    obj.* = .{ .displayable = fp.displayable.displayable, .scannable_bytes = scannable };
    out.raw = obj;
    return null;
}

pub export fn signal_fingerprint_clone(new_obj: *SignalMutPointerFingerprint, obj: SignalConstPointerFingerprint) ?*SignalFfiError {
    const src = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    const copy = gpa.create(SignalFingerprint) catch return err_mod.alloc(.internal_error, "OOM");
    copy.displayable = src.displayable;
    copy.scannable_bytes = gpa.dupe(u8, src.scannable_bytes) catch {
        gpa.destroy(copy);
        return err_mod.alloc(.internal_error, "OOM");
    };
    new_obj.raw = copy;
    return null;
}

pub export fn signal_fingerprint_destroy(p: SignalMutPointerFingerprint) ?*SignalFfiError {
    if (p.raw) |obj| {
        obj.deinit();
        gpa.destroy(obj);
    }
    return null;
}

pub export fn signal_fingerprint_display_string(out: *[*:0]u8, obj: SignalConstPointerFingerprint) ?*SignalFfiError {
    const fp = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    // displayable is 60 decimal digits; caller frees with signal_free_string
    const s = gpa.dupeZ(u8, &fp.displayable) catch return err_mod.alloc(.internal_error, "OOM");
    out.* = s.ptr;
    return null;
}

pub export fn signal_fingerprint_scannable_encoding(out: *SignalOwnedBuffer, obj: SignalConstPointerFingerprint) ?*SignalFfiError {
    const fp = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    out.* = SignalOwnedBuffer.dupe(fp.scannable_bytes) catch return err_mod.alloc(.internal_error, "OOM");
    return null;
}

pub export fn signal_fingerprint_compare(out: *bool, obj: SignalConstPointerFingerprint, their_scannable: SignalBorrowedBuffer) ?*SignalFfiError {
    const fp = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    const scannable = fingerprint_mod.ScannableFingerprint{
        .version = 0,
        .local_fingerprint = undefined,
        .remote_fingerprint = undefined,
        .allocator = gpa,
    };
    _ = scannable;
    // Compare by re-parsing our scannable encoding vs theirs via ScannableFingerprint.compareTo
    const sf = blk: {
        var pos: usize = 0;
        const proto = @import("../proto.zig");
        var version: u32 = 0;
        var local_fp: ?[32]u8 = null;
        var remote_fp: ?[32]u8 = null;
        while (proto.nextField(fp.scannable_bytes, &pos) catch break :blk null) |field| {
            switch (field.number) {
                1 => if (field.wire_type == .varint) { version = @intCast(field.data.varint); },
                2 => if (field.wire_type == .len and field.data.len.len == 32) { local_fp = field.data.len[0..32].*; },
                3 => if (field.wire_type == .len and field.data.len.len == 32) { remote_fp = field.data.len[0..32].*; },
                else => {},
            }
        }
        break :blk fingerprint_mod.ScannableFingerprint{
            .version = version,
            .local_fingerprint = local_fp orelse break :blk null,
            .remote_fingerprint = remote_fp orelse break :blk null,
            .allocator = gpa,
        };
    } orelse return err_mod.alloc(.invalid_argument, "invalid scannable bytes");

    out.* = sf.compareTo(their_scannable.slice()) catch |e| return err_mod.fromZigError(e);
    return null;
}

// ── ServiceId ─────────────────────────────────────────────────────────────────

pub export fn signal_service_id_parse_from_service_id_string(out: *[17]u8, input: [*:0]const u8) ?*SignalFfiError {
    const s = std.mem.span(input);
    const sid = service_id_mod.ServiceId.parseFromString(s) catch return err_mod.alloc(.invalid_argument, "invalid ServiceId string");
    out.* = sid.toFixedWidthBinary();
    return null;
}

pub export fn signal_service_id_service_id_string(out: *[*:0]u8, bytes: *const [17]u8) ?*SignalFfiError {
    const sid = service_id_mod.ServiceId.fromFixedWidthBinary(bytes.*) catch return err_mod.alloc(.invalid_argument, "invalid ServiceId bytes");
    var buf: [service_id_mod.SERVICE_ID_STRING_MAX_LEN]u8 = undefined;
    const s = sid.toString(&buf);
    const z = gpa.dupeZ(u8, s) catch return err_mod.alloc(.internal_error, "OOM");
    out.* = z.ptr;
    return null;
}

pub export fn signal_service_id_service_id_binary(out: *SignalOwnedBuffer, bytes: *const [17]u8) ?*SignalFfiError {
    const sid = service_id_mod.ServiceId.fromFixedWidthBinary(bytes.*) catch return err_mod.alloc(.invalid_argument, "invalid ServiceId bytes");
    var buf: [17]u8 = undefined;
    const bin = sid.toBinary(&buf);
    out.* = SignalOwnedBuffer.dupe(bin) catch return err_mod.alloc(.internal_error, "OOM");
    return null;
}

pub export fn signal_service_id_parse_from_service_id_binary(out: *[17]u8, bytes: SignalBorrowedBuffer) ?*SignalFfiError {
    const sid = service_id_mod.ServiceId.fromBinary(bytes.slice()) catch return err_mod.alloc(.invalid_argument, "invalid ServiceId binary");
    out.* = sid.toFixedWidthBinary();
    return null;
}

// ── Username ──────────────────────────────────────────────────────────────────

pub export fn signal_username_hash(out: *[username_mod.USERNAME_HASH_LEN]u8, username: [*:0]const u8) ?*SignalFfiError {
    const s = std.mem.span(username);
    const h = username_mod.UsernameHash.compute(s) catch |e| return err_mod.fromZigError(e);
    out.* = h.hash;
    return null;
}

pub export fn signal_username_hash_from_parts(
    out: *[username_mod.USERNAME_HASH_LEN]u8,
    nickname: [*:0]const u8,
    discriminator: u64,
) ?*SignalFfiError {
    // Build a "nickname.discriminator" string for compute()
    const nick = std.mem.span(nickname);
    var buf: [username_mod.USERNAME_MAX_LENGTH + 1 + 20]u8 = undefined;
    const full = std.fmt.bufPrint(&buf, "{s}.{d}", .{ nick, discriminator }) catch return err_mod.alloc(.invalid_argument, "username too long");
    const h = username_mod.UsernameHash.compute(full) catch |e| return err_mod.fromZigError(e);
    out.* = h.hash;
    return null;
}

pub export fn signal_username_proof(
    out: *SignalOwnedBuffer,
    username: [*:0]const u8,
) ?*SignalFfiError {
    var randomness: [32]u8 = undefined;
    rnd.bytes(&randomness);
    const s = std.mem.span(username);
    const proof = username_mod.usernameProof(gpa, s, randomness) catch |e| return err_mod.fromZigError(e);
    out.* = .{ .base = proof.ptr, .length = proof.len };
    return null;
}

pub export fn signal_username_verify(
    out: *bool,
    username_hash: *const [username_mod.USERNAME_HASH_LEN]u8,
    proof: SignalBorrowedBuffer,
) ?*SignalFfiError {
    out.* = username_mod.usernameVerify(gpa, username_hash.*, proof.slice()) catch |e| return err_mod.fromZigError(e);
    return null;
}

// ── Account Entropy Pool ──────────────────────────────────────────────────────

pub const SignalAccountEntropyPool = struct {
    inner: account_keys_mod.AccountEntropyPool,
};

pub const SignalMutPointerAccountEntropyPool = extern struct { raw: ?*SignalAccountEntropyPool };
pub const SignalConstPointerAccountEntropyPool = extern struct { raw: ?*const SignalAccountEntropyPool };

pub export fn signal_account_entropy_pool_generate(out: *SignalMutPointerAccountEntropyPool) ?*SignalFfiError {
    const obj = gpa.create(SignalAccountEntropyPool) catch return err_mod.alloc(.internal_error, "OOM");
    obj.inner = account_keys_mod.AccountEntropyPool.generate();
    out.raw = obj;
    return null;
}

pub export fn signal_account_entropy_pool_parse(out: *SignalMutPointerAccountEntropyPool, input: [*:0]const u8) ?*SignalFfiError {
    const s = std.mem.span(input);
    const obj = gpa.create(SignalAccountEntropyPool) catch return err_mod.alloc(.internal_error, "OOM");
    obj.inner = account_keys_mod.AccountEntropyPool.fromString(s) catch |e| {
        gpa.destroy(obj);
        return err_mod.fromZigError(e);
    };
    out.raw = obj;
    return null;
}

pub export fn signal_account_entropy_pool_destroy(p: SignalMutPointerAccountEntropyPool) ?*SignalFfiError {
    if (p.raw) |obj| gpa.destroy(obj);
    return null;
}

pub export fn signal_account_entropy_pool_as_string(out: *[*:0]const u8, obj: SignalConstPointerAccountEntropyPool) ?*SignalFfiError {
    const pool = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    const s = gpa.dupeZ(u8, pool.inner.asString()) catch return err_mod.alloc(.internal_error, "OOM");
    out.* = s.ptr;
    return null;
}

pub export fn signal_account_entropy_pool_derive_svr_key(out: *[32]u8, obj: SignalConstPointerAccountEntropyPool) ?*SignalFfiError {
    const pool = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    out.* = pool.inner.deriveSvrKey();
    return null;
}

pub export fn signal_account_entropy_pool_derive_backup_key(out: *[32]u8, obj: SignalConstPointerAccountEntropyPool) ?*SignalFfiError {
    const pool = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    out.* = pool.inner.deriveBackupKey().bytes;
    return null;
}

// ── BackupKey ─────────────────────────────────────────────────────────────────

pub const SignalBackupKey = struct {
    bytes: [32]u8,
};

pub const SignalMutPointerBackupKey = extern struct { raw: ?*SignalBackupKey };
pub const SignalConstPointerBackupKey = extern struct { raw: ?*const SignalBackupKey };

pub export fn signal_backup_key_from_account_entropy_pool(out: *SignalMutPointerBackupKey, pool: SignalConstPointerAccountEntropyPool) ?*SignalFfiError {
    const p = pool.raw orelse return err_mod.alloc(.null_parameter, "pool is null");
    const obj = gpa.create(SignalBackupKey) catch return err_mod.alloc(.internal_error, "OOM");
    obj.bytes = p.inner.deriveBackupKey().bytes;
    out.raw = obj;
    return null;
}

pub export fn signal_backup_key_from_bytes(out: *SignalMutPointerBackupKey, bytes: SignalBorrowedBuffer) ?*SignalFfiError {
    if (bytes.length != 32) return err_mod.alloc(.invalid_argument, "backup key must be 32 bytes");
    const obj = gpa.create(SignalBackupKey) catch return err_mod.alloc(.internal_error, "OOM");
    obj.bytes = bytes.slice()[0..32].*;
    out.raw = obj;
    return null;
}

pub export fn signal_backup_key_destroy(p: SignalMutPointerBackupKey) ?*SignalFfiError {
    if (p.raw) |obj| gpa.destroy(obj);
    return null;
}

pub export fn signal_backup_key_get_bytes(out: *SignalOwnedBuffer, obj: SignalConstPointerBackupKey) ?*SignalFfiError {
    const bk = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    out.* = SignalOwnedBuffer.dupe(&bk.bytes) catch return err_mod.alloc(.internal_error, "OOM");
    return null;
}

pub export fn signal_backup_key_derive_media_encryption_key(out: *[32]u8, obj: SignalConstPointerBackupKey) ?*SignalFfiError {
    const bk = obj.raw orelse return err_mod.alloc(.null_parameter, "obj is null");
    const inner = account_keys_mod.BackupKey{ .bytes = bk.bytes };
    out.* = inner.deriveMediaEncryptionKey();
    return null;
}
