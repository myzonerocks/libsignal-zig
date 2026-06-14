//! AES-256-CTR32, AES-256-GCM, AES-256-GCM-SIV, HKDF, IncrementalMac, ValidatingMac.

const std = @import("std");
const err_mod = @import("error.zig");
const aes_mod = @import("../aes.zig");
const mac_mod = @import("../incremental_mac.zig");
const keys = @import("keys.zig");
const gpa = std.heap.c_allocator;

const SignalFfiError = err_mod.SignalFfiError;
const SignalOwnedBuffer = keys.SignalOwnedBuffer;
const SignalBorrowedBuffer = keys.SignalBorrowedBuffer;
const SignalBorrowedMutableBuffer = keys.SignalBorrowedMutableBuffer;

const Aes256 = std.crypto.core.aes.Aes256;
const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;
const Aes256GcmSiv = std.crypto.aead.aes_gcm_siv.Aes256GcmSiv;

// ── AES-256-CTR32 ─────────────────────────────────────────────────────────────
// "CTR32" uses a 12-byte nonce and a 32-bit counter, incrementing the last 4 bytes.

pub const SignalAes256Ctr32 = struct {
    key: [32]u8,
    nonce: [12]u8,
    initial_ctr: u32,
    counter: u32,
};

pub const SignalMutPointerAes256Ctr32 = extern struct { raw: ?*SignalAes256Ctr32 };

pub export fn signal_aes256_ctr32_new(out: *SignalMutPointerAes256Ctr32, key: SignalBorrowedBuffer, nonce: SignalBorrowedBuffer, initial_ctr: u32) ?*SignalFfiError {
    if (key.length != 32) return err_mod.alloc(.invalid_argument, "AES-256 key must be 32 bytes");
    if (nonce.length != 12) return err_mod.alloc(.invalid_argument, "CTR32 nonce must be 12 bytes");
    const obj = gpa.create(SignalAes256Ctr32) catch return err_mod.alloc(.internal_error, "OOM");
    obj.* = .{
        .key = key.slice()[0..32].*,
        .nonce = nonce.slice()[0..12].*,
        .initial_ctr = initial_ctr,
        .counter = initial_ctr,
    };
    out.raw = obj;
    return null;
}

pub export fn signal_aes256_ctr32_destroy(p: SignalMutPointerAes256Ctr32) ?*SignalFfiError {
    if (p.raw) |obj| gpa.destroy(obj);
    return null;
}

pub export fn signal_aes256_ctr32_process(ctr: SignalMutPointerAes256Ctr32, data: SignalBorrowedMutableBuffer, offset: u32, length: u32) ?*SignalFfiError {
    const obj = ctr.raw orelse return err_mod.alloc(.null_parameter, "ctr is null");
    const buf = data.slice();
    const end = @as(usize, offset) + @as(usize, length);
    if (end > buf.len) return err_mod.alloc(.invalid_argument, "offset+length exceeds buffer");
    const enc = Aes256.initEnc(obj.key);
    var i: usize = offset;
    var block_ctr = obj.counter;
    while (i < end) {
        // Build 16-byte counter block: nonce[12] || counter[4] big-endian
        var counter_block: [16]u8 = undefined;
        @memcpy(counter_block[0..12], &obj.nonce);
        counter_block[12] = @intCast((block_ctr >> 24) & 0xFF);
        counter_block[13] = @intCast((block_ctr >> 16) & 0xFF);
        counter_block[14] = @intCast((block_ctr >> 8) & 0xFF);
        counter_block[15] = @intCast(block_ctr & 0xFF);
        var keystream: [16]u8 = undefined;
        enc.encrypt(&keystream, &counter_block);
        const chunk = @min(16, end - i);
        for (0..chunk) |k| buf[i + k] ^= keystream[k];
        i += chunk;
        block_ctr +%= 1;
    }
    obj.counter = block_ctr;
    return null;
}

// ── AES-256-GCM Encryption (streaming object) ──────────────────────────────────

pub const SignalAes256GcmEncryption = struct {
    key: [32]u8,
    nonce: [12]u8,
    aad: []u8,
    plaintext: std.ArrayListUnmanaged(u8),
};

pub const SignalMutPointerAes256GcmEncryption = extern struct { raw: ?*SignalAes256GcmEncryption };

pub export fn signal_aes256_gcm_encryption_new(out: *SignalMutPointerAes256GcmEncryption, key: SignalBorrowedBuffer, nonce: SignalBorrowedBuffer, associated_data: SignalBorrowedBuffer) ?*SignalFfiError {
    if (key.length != 32) return err_mod.alloc(.invalid_argument, "AES-256 key must be 32 bytes");
    if (nonce.length != 12) return err_mod.alloc(.invalid_argument, "GCM nonce must be 12 bytes");
    const obj = gpa.create(SignalAes256GcmEncryption) catch return err_mod.alloc(.internal_error, "OOM");
    obj.key = key.slice()[0..32].*;
    obj.nonce = nonce.slice()[0..12].*;
    obj.aad = gpa.dupe(u8, associated_data.slice()) catch {
        gpa.destroy(obj);
        return err_mod.alloc(.internal_error, "OOM");
    };
    obj.plaintext = .{ .items = &.{}, .capacity = 0 };
    out.raw = obj;
    return null;
}

pub export fn signal_aes256_gcm_encryption_destroy(p: SignalMutPointerAes256GcmEncryption) ?*SignalFfiError {
    if (p.raw) |obj| {
        gpa.free(obj.aad);
        obj.plaintext.deinit(gpa);
        gpa.destroy(obj);
    }
    return null;
}

pub export fn signal_aes256_gcm_encryption_update(gcm: SignalMutPointerAes256GcmEncryption, data: SignalBorrowedMutableBuffer, offset: u32, length: u32) ?*SignalFfiError {
    const obj = gcm.raw orelse return err_mod.alloc(.null_parameter, "gcm is null");
    const src = data.slice();
    const end = @as(usize, offset) + @as(usize, length);
    if (end > src.len) return err_mod.alloc(.invalid_argument, "offset+length exceeds buffer");
    obj.plaintext.appendSlice(gpa, src[offset..end]) catch return err_mod.alloc(.internal_error, "OOM");
    return null;
}

pub export fn signal_aes256_gcm_encryption_compute_tag(out: *SignalOwnedBuffer, gcm: SignalMutPointerAes256GcmEncryption) ?*SignalFfiError {
    const obj = gcm.raw orelse return err_mod.alloc(.null_parameter, "gcm is null");
    const plaintext = obj.plaintext.items;
    const ciphertext = gpa.alloc(u8, plaintext.len) catch return err_mod.alloc(.internal_error, "OOM");
    defer gpa.free(ciphertext);
    var tag: [Aes256Gcm.tag_length]u8 = undefined;
    Aes256Gcm.encrypt(ciphertext, &tag, plaintext, obj.aad, obj.nonce, obj.key);
    out.* = SignalOwnedBuffer.dupe(&tag) catch return err_mod.alloc(.internal_error, "OOM");
    return null;
}

// ── AES-256-GCM Decryption (streaming object) ──────────────────────────────────

pub const SignalAes256GcmDecryption = struct {
    key: [32]u8,
    nonce: [12]u8,
    aad: []u8,
    ciphertext: std.ArrayListUnmanaged(u8),
};

pub const SignalMutPointerAes256GcmDecryption = extern struct { raw: ?*SignalAes256GcmDecryption };

pub export fn signal_aes256_gcm_decryption_new(out: *SignalMutPointerAes256GcmDecryption, key: SignalBorrowedBuffer, nonce: SignalBorrowedBuffer, associated_data: SignalBorrowedBuffer) ?*SignalFfiError {
    if (key.length != 32) return err_mod.alloc(.invalid_argument, "AES-256 key must be 32 bytes");
    if (nonce.length != 12) return err_mod.alloc(.invalid_argument, "GCM nonce must be 12 bytes");
    const obj = gpa.create(SignalAes256GcmDecryption) catch return err_mod.alloc(.internal_error, "OOM");
    obj.key = key.slice()[0..32].*;
    obj.nonce = nonce.slice()[0..12].*;
    obj.aad = gpa.dupe(u8, associated_data.slice()) catch {
        gpa.destroy(obj);
        return err_mod.alloc(.internal_error, "OOM");
    };
    obj.ciphertext = .{ .items = &.{}, .capacity = 0 };
    out.raw = obj;
    return null;
}

pub export fn signal_aes256_gcm_decryption_destroy(p: SignalMutPointerAes256GcmDecryption) ?*SignalFfiError {
    if (p.raw) |obj| {
        gpa.free(obj.aad);
        obj.ciphertext.deinit(gpa);
        gpa.destroy(obj);
    }
    return null;
}

pub export fn signal_aes256_gcm_decryption_update(gcm: SignalMutPointerAes256GcmDecryption, data: SignalBorrowedMutableBuffer, offset: u32, length: u32) ?*SignalFfiError {
    const obj = gcm.raw orelse return err_mod.alloc(.null_parameter, "gcm is null");
    const src = data.slice();
    const end = @as(usize, offset) + @as(usize, length);
    if (end > src.len) return err_mod.alloc(.invalid_argument, "offset+length exceeds buffer");
    obj.ciphertext.appendSlice(gpa, src[offset..end]) catch return err_mod.alloc(.internal_error, "OOM");
    return null;
}

pub export fn signal_aes256_gcm_decryption_verify_tag(out: *bool, gcm: SignalMutPointerAes256GcmDecryption, tag: SignalBorrowedBuffer) ?*SignalFfiError {
    const obj = gcm.raw orelse return err_mod.alloc(.null_parameter, "gcm is null");
    if (tag.length != 16) return err_mod.alloc(.invalid_argument, "GCM tag must be 16 bytes");
    const auth_tag: [16]u8 = tag.slice()[0..16].*;
    const ct = obj.ciphertext.items;
    const pt = gpa.alloc(u8, ct.len) catch return err_mod.alloc(.internal_error, "OOM");
    defer gpa.free(pt);
    Aes256Gcm.decrypt(pt, ct, auth_tag, obj.aad, obj.nonce, obj.key) catch {
        out.* = false;
        return null;
    };
    out.* = true;
    return null;
}

// ── AES-256-GCM-SIV (non-streaming, one-shot) ─────────────────────────────────

pub const SignalAes256GcmSiv = struct { key: [32]u8 };
pub const SignalMutPointerAes256GcmSiv = extern struct { raw: ?*SignalAes256GcmSiv };
pub const SignalConstPointerAes256GcmSiv = extern struct { raw: ?*const SignalAes256GcmSiv };

pub export fn signal_aes256_gcm_siv_new(out: *SignalMutPointerAes256GcmSiv, key: SignalBorrowedBuffer) ?*SignalFfiError {
    if (key.length != 32) return err_mod.alloc(.invalid_argument, "AES-256 key must be 32 bytes");
    const obj = gpa.create(SignalAes256GcmSiv) catch return err_mod.alloc(.internal_error, "OOM");
    obj.key = key.slice()[0..32].*;
    out.raw = obj;
    return null;
}

pub export fn signal_aes256_gcm_siv_destroy(p: SignalMutPointerAes256GcmSiv) ?*SignalFfiError {
    if (p.raw) |obj| gpa.destroy(obj);
    return null;
}

pub export fn signal_aes256_gcm_siv_encrypt(out: *SignalOwnedBuffer, aes_gcm_siv_obj: SignalConstPointerAes256GcmSiv, ptext: SignalBorrowedBuffer, nonce: SignalBorrowedBuffer, associated_data: SignalBorrowedBuffer) ?*SignalFfiError {
    const obj = aes_gcm_siv_obj.raw orelse return err_mod.alloc(.null_parameter, "aes_gcm_siv_obj is null");
    if (nonce.length != 12) return err_mod.alloc(.invalid_argument, "GCM-SIV nonce must be 12 bytes");
    const n: [12]u8 = nonce.slice()[0..12].*;
    const result = aes_mod.gcm_siv_encrypt(gpa, obj.key, n, ptext.slice(), associated_data.slice()) catch |e| return err_mod.fromZigError(e);
    out.* = .{ .base = result.ptr, .length = result.len };
    return null;
}

pub export fn signal_aes256_gcm_siv_decrypt(out: *SignalOwnedBuffer, aes_gcm_siv: SignalConstPointerAes256GcmSiv, ctext: SignalBorrowedBuffer, nonce: SignalBorrowedBuffer, associated_data: SignalBorrowedBuffer) ?*SignalFfiError {
    const obj = aes_gcm_siv.raw orelse return err_mod.alloc(.null_parameter, "aes_gcm_siv is null");
    if (nonce.length != 12) return err_mod.alloc(.invalid_argument, "GCM-SIV nonce must be 12 bytes");
    const n: [12]u8 = nonce.slice()[0..12].*;
    const result = aes_mod.gcm_siv_decrypt(gpa, obj.key, n, ctext.slice(), associated_data.slice()) catch |e| return err_mod.fromZigError(e);
    out.* = .{ .base = result.ptr, .length = result.len };
    return null;
}

// ── HKDF ──────────────────────────────────────────────────────────────────────

pub export fn signal_hkdf_derive(output: SignalBorrowedMutableBuffer, ikm: SignalBorrowedBuffer, label: SignalBorrowedBuffer, salt: SignalBorrowedBuffer) ?*SignalFfiError {
    const out_buf = output.slice();
    if (out_buf.len == 0) return err_mod.alloc(.invalid_argument, "output buffer is empty");
    const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
    const prk = if (salt.length > 0)
        HkdfSha256.extract(salt.slice(), ikm.slice())
    else
        HkdfSha256.extract("", ikm.slice());
    HkdfSha256.expand(out_buf, label.slice(), prk);
    return null;
}

// ── IncrementalMac ─────────────────────────────────────────────────────────────
// The official API yields newly-completed chunk MACs from update() and the final
// chunk MAC from finalize(). We track macs_emitted to return only the new ones.

pub const SignalIncrementalMac = struct {
    inner: mac_mod.Incremental,
    macs_emitted: usize, // number of 32-byte MAC entries already returned to caller
};

pub const SignalMutPointerIncrementalMac = extern struct { raw: ?*SignalIncrementalMac };

pub export fn signal_incremental_mac_calculate_chunk_size(out: *u32, data_size: u32) ?*SignalFfiError {
    _ = data_size;
    out.* = mac_mod.DEFAULT_CHUNK_SIZE;
    return null;
}

pub export fn signal_incremental_mac_initialize(out: *SignalMutPointerIncrementalMac, key: SignalBorrowedBuffer, chunk_size: u32) ?*SignalFfiError {
    if (key.length != 32) return err_mod.alloc(.invalid_argument, "MAC key must be 32 bytes");
    const obj = gpa.create(SignalIncrementalMac) catch return err_mod.alloc(.internal_error, "OOM");
    const k: [32]u8 = key.slice()[0..32].*;
    obj.inner = mac_mod.Incremental.init(gpa, k, @as(usize, chunk_size)) catch |e| {
        gpa.destroy(obj);
        return err_mod.fromZigError(e);
    };
    obj.macs_emitted = 0;
    out.raw = obj;
    return null;
}

pub export fn signal_incremental_mac_update(out: *SignalOwnedBuffer, mac: SignalMutPointerIncrementalMac, bytes: SignalBorrowedBuffer, offset: u32, length: u32) ?*SignalFfiError {
    const obj = mac.raw orelse return err_mod.alloc(.null_parameter, "mac is null");
    const src = bytes.slice();
    const end = @as(usize, offset) + @as(usize, length);
    if (end > src.len) return err_mod.alloc(.invalid_argument, "offset+length exceeds buffer");
    obj.inner.update(src[offset..end]) catch |e| return err_mod.fromZigError(e);
    // Return newly completed chunk MACs (each 32 bytes).
    const all_macs = obj.inner.macs.items;
    const already = obj.macs_emitted * mac_mod.MAC_LEN;
    const new_bytes = all_macs[already..];
    out.* = SignalOwnedBuffer.dupe(new_bytes) catch return err_mod.alloc(.internal_error, "OOM");
    obj.macs_emitted = all_macs.len / mac_mod.MAC_LEN;
    return null;
}

pub export fn signal_incremental_mac_finalize(out: *SignalOwnedBuffer, mac: SignalMutPointerIncrementalMac) ?*SignalFfiError {
    const obj = mac.raw orelse return err_mod.alloc(.null_parameter, "mac is null");
    // Flush the final partial chunk.
    if (obj.inner.buf_len > 0) {
        obj.inner.update(&[_]u8{}) catch |e| return err_mod.fromZigError(e);
        // Actually flush by calling internal flush — call finalize which returns all macs,
        // then extract only the new final one.
    }
    const all_macs_slice = obj.inner.finalize() catch |e| return err_mod.fromZigError(e);
    const already = obj.macs_emitted * mac_mod.MAC_LEN;
    const new_bytes = if (already < all_macs_slice.len) all_macs_slice[already..] else &[_]u8{};
    out.* = SignalOwnedBuffer.dupe(new_bytes) catch {
        gpa.free(all_macs_slice);
        return err_mod.alloc(.internal_error, "OOM");
    };
    gpa.free(all_macs_slice);
    return null;
}

pub export fn signal_incremental_mac_destroy(p: SignalMutPointerIncrementalMac) ?*SignalFfiError {
    if (p.raw) |obj| {
        obj.inner.deinit();
        gpa.destroy(obj);
    }
    return null;
}

// ── ValidatingMac ──────────────────────────────────────────────────────────────
// update() returns number of newly validated chunks; finalize() returns count of final chunk.

pub const SignalValidatingMac = struct {
    inner: mac_mod.Validating,
    chunks_validated: usize,
};

pub const SignalMutPointerValidatingMac = extern struct { raw: ?*SignalValidatingMac };

pub export fn signal_validating_mac_initialize(out: *SignalMutPointerValidatingMac, key: SignalBorrowedBuffer, chunk_size: u32, digests: SignalBorrowedBuffer) ?*SignalFfiError {
    if (key.length != 32) return err_mod.alloc(.invalid_argument, "MAC key must be 32 bytes");
    const k: [32]u8 = key.slice()[0..32].*;
    // expected_macs must be kept alive for the lifetime of Validating — dupe it.
    const expected = gpa.dupe(u8, digests.slice()) catch return err_mod.alloc(.internal_error, "OOM");
    const obj = gpa.create(SignalValidatingMac) catch {
        gpa.free(expected);
        return err_mod.alloc(.internal_error, "OOM");
    };
    obj.inner = mac_mod.Validating.init(gpa, k, @as(usize, chunk_size), expected) catch |e| {
        gpa.free(expected);
        gpa.destroy(obj);
        return err_mod.fromZigError(e);
    };
    obj.chunks_validated = 0;
    out.raw = obj;
    return null;
}

pub export fn signal_validating_mac_update(out: *i32, mac: SignalMutPointerValidatingMac, bytes: SignalBorrowedBuffer, offset: u32, length: u32) ?*SignalFfiError {
    const obj = mac.raw orelse return err_mod.alloc(.null_parameter, "mac is null");
    const src = bytes.slice();
    const end = @as(usize, offset) + @as(usize, length);
    if (end > src.len) return err_mod.alloc(.invalid_argument, "offset+length exceeds buffer");
    const before = obj.inner.chunk_idx;
    obj.inner.update(src[offset..end]) catch |e| return err_mod.fromZigError(e);
    const after = obj.inner.chunk_idx;
    out.* = @intCast(after - before);
    return null;
}

pub export fn signal_validating_mac_finalize(out: *i32, mac: SignalMutPointerValidatingMac) ?*SignalFfiError {
    const obj = mac.raw orelse return err_mod.alloc(.null_parameter, "mac is null");
    const before = obj.inner.chunk_idx;
    obj.inner.finalize() catch |e| return err_mod.fromZigError(e);
    const after = obj.inner.chunk_idx;
    out.* = @intCast(after - before);
    return null;
}

pub export fn signal_validating_mac_destroy(p: SignalMutPointerValidatingMac) ?*SignalFfiError {
    if (p.raw) |obj| {
        obj.inner.deinit();
        gpa.destroy(obj);
    }
    return null;
}
