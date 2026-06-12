// AES utilities: CBC, CTR, GCM-SIV modes.
const std = @import("std");
const err = @import("error.zig");
const mem = std.mem;

const Aes256 = std.crypto.core.aes.Aes256;

// --- AES-256-CBC ---

pub fn cbc_encrypt(allocator: mem.Allocator, key: [32]u8, iv: [16]u8, plaintext: []const u8) ![]u8 {
    const pad_len: u8 = @intCast(16 - (plaintext.len % 16));
    const padded_len = plaintext.len + pad_len;
    const padded = try allocator.alloc(u8, padded_len);
    defer allocator.free(padded);
    @memcpy(padded[0..plaintext.len], plaintext);
    @memset(padded[plaintext.len..], pad_len);

    const out = try allocator.alloc(u8, padded_len);
    const enc = Aes256.initEnc(key);
    var prev: [16]u8 = iv;
    var i: usize = 0;
    while (i < padded_len) : (i += 16) {
        var block: [16]u8 = padded[i..][0..16].*;
        for (0..16) |j| block[j] ^= prev[j];
        enc.encrypt(&prev, &block);
        @memcpy(out[i..][0..16], &prev);
    }
    return out;
}

pub fn cbc_decrypt(allocator: mem.Allocator, key: [32]u8, iv: [16]u8, ciphertext: []const u8) ![]u8 {
    if (ciphertext.len == 0 or ciphertext.len % 16 != 0) return err.SignalError.InvalidMessage;
    const buf = try allocator.alloc(u8, ciphertext.len);
    const dec = Aes256.initDec(key);
    var prev: [16]u8 = iv;
    var i: usize = 0;
    while (i < ciphertext.len) : (i += 16) {
        const ct_block: [16]u8 = ciphertext[i..][0..16].*;
        var pt_block: [16]u8 = undefined;
        dec.decrypt(&pt_block, &ct_block);
        for (0..16) |j| pt_block[j] ^= prev[j];
        @memcpy(buf[i..][0..16], &pt_block);
        prev = ct_block;
    }
    // Remove PKCS7 padding
    const pad_byte = buf[buf.len - 1];
    if (pad_byte == 0 or pad_byte > 16) {
        allocator.free(buf);
        return err.SignalError.PaddingError;
    }
    for (buf[buf.len - pad_byte ..]) |b| {
        if (b != pad_byte) {
            allocator.free(buf);
            return err.SignalError.PaddingError;
        }
    }
    const result = try allocator.dupe(u8, buf[0 .. buf.len - pad_byte]);
    allocator.free(buf);
    return result;
}

// --- AES-256-CTR ---

pub fn ctr_encrypt(key: [32]u8, iv: [16]u8, input: []const u8, output: []u8) void {
    const enc = Aes256.initEnc(key);
    var counter: [16]u8 = iv;
    var i: usize = 0;
    while (i < input.len) {
        var keystream: [16]u8 = undefined;
        enc.encrypt(&keystream, &counter);
        // Increment counter (big-endian)
        var j: usize = 15;
        while (true) {
            counter[j] +%= 1;
            if (counter[j] != 0 or j == 0) break;
            j -= 1;
        }
        const chunk_len = @min(16, input.len - i);
        for (0..chunk_len) |k| {
            output[i + k] = input[i + k] ^ keystream[k];
        }
        i += chunk_len;
    }
}

// --- AES-256-GCM (via std.crypto.aead.aes_gcm) ---

pub const AES256_GCM_NONCE_LEN = 12;
pub const AES256_GCM_TAG_LEN = 16;

pub fn gcm_encrypt(
    allocator: mem.Allocator,
    key: [32]u8,
    nonce: [AES256_GCM_NONCE_LEN]u8,
    plaintext: []const u8,
    aad: []const u8,
) ![]u8 {
    const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;
    const out = try allocator.alloc(u8, plaintext.len + AES256_GCM_TAG_LEN);
    errdefer allocator.free(out);
    var tag: [Aes256Gcm.tag_length]u8 = undefined;
    Aes256Gcm.encrypt(out[0..plaintext.len], &tag, plaintext, aad, nonce, key);
    @memcpy(out[plaintext.len..], &tag);
    return out;
}

pub fn gcm_decrypt(
    allocator: mem.Allocator,
    key: [32]u8,
    nonce: [AES256_GCM_NONCE_LEN]u8,
    ciphertext_with_tag: []const u8,
    aad: []const u8,
) ![]u8 {
    const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;
    if (ciphertext_with_tag.len < AES256_GCM_TAG_LEN) return err.SignalError.InvalidMessage;
    const ct_len = ciphertext_with_tag.len - AES256_GCM_TAG_LEN;
    const tag: [Aes256Gcm.tag_length]u8 = ciphertext_with_tag[ct_len..][0..Aes256Gcm.tag_length].*;
    const out = try allocator.alloc(u8, ct_len);
    errdefer allocator.free(out);
    try Aes256Gcm.decrypt(out, ciphertext_with_tag[0..ct_len], tag, aad, nonce, key);
    return out;
}

// --- AES-256-GCM-SIV ---

pub fn gcm_siv_encrypt(
    allocator: mem.Allocator,
    key: [32]u8,
    nonce: [12]u8,
    plaintext: []const u8,
    aad: []const u8,
) ![]u8 {
    const AesGcmSiv = std.crypto.aead.aes_gcm_siv.Aes256GcmSiv;
    const out = try allocator.alloc(u8, plaintext.len + AesGcmSiv.tag_length);
    errdefer allocator.free(out);
    var tag: [AesGcmSiv.tag_length]u8 = undefined;
    AesGcmSiv.encrypt(out[0..plaintext.len], &tag, plaintext, aad, nonce, key);
    @memcpy(out[plaintext.len..], &tag);
    return out;
}

pub fn gcm_siv_decrypt(
    allocator: mem.Allocator,
    key: [32]u8,
    nonce: [12]u8,
    ciphertext_with_tag: []const u8,
    aad: []const u8,
) ![]u8 {
    const AesGcmSiv = std.crypto.aead.aes_gcm_siv.Aes256GcmSiv;
    if (ciphertext_with_tag.len < AesGcmSiv.tag_length) return err.SignalError.InvalidMessage;
    const ct_len = ciphertext_with_tag.len - AesGcmSiv.tag_length;
    const tag: [AesGcmSiv.tag_length]u8 = ciphertext_with_tag[ct_len..][0..AesGcmSiv.tag_length].*;
    const out = try allocator.alloc(u8, ct_len);
    errdefer allocator.free(out);
    try AesGcmSiv.decrypt(out, ciphertext_with_tag[0..ct_len], tag, aad, nonce, key);
    return out;
}

test "aes-256-cbc roundtrip" {
    const ally = std.heap.smp_allocator;
    const key: [32]u8 = [_]u8{0x42} ** 32;
    const iv: [16]u8 = [_]u8{0x13} ** 16;
    const plaintext = "hello signal protocol!";

    const ct = try cbc_encrypt(ally, key, iv, plaintext);
    defer ally.free(ct);
    const pt = try cbc_decrypt(ally, key, iv, ct);
    defer ally.free(pt);
    try std.testing.expectEqualSlices(u8, plaintext, pt);
}

test "aes-256-gcm roundtrip" {
    const ally = std.heap.smp_allocator;
    const key: [32]u8 = [_]u8{0x42} ** 32;
    const nonce: [12]u8 = [_]u8{0x13} ** 12;
    const plaintext = "hello sealed sender!";
    const aad = "associated data";

    const ct = try gcm_encrypt(ally, key, nonce, plaintext, aad);
    defer ally.free(ct);
    const pt = try gcm_decrypt(ally, key, nonce, ct, aad);
    defer ally.free(pt);
    try std.testing.expectEqualSlices(u8, plaintext, pt);
}
