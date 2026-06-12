const std = @import("std");

const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

pub const ZERO_SALT = [_]u8{0} ** 32;

pub fn deriveSecrets(
    input_key_material: []const u8,
    salt: []const u8,
    info: []const u8,
    comptime output_len: usize,
) [output_len]u8 {
    const prk = HkdfSha256.extract(salt, input_key_material);
    var out: [output_len]u8 = undefined;
    HkdfSha256.expand(&out, info, prk);
    return out;
}

pub fn createChain(
    root_key: [32]u8,
    dh_output: [32]u8,
) struct { root_key: [32]u8, chain_key: [32]u8 } {
    const prk = HkdfSha256.extract(&root_key, &dh_output);
    var out: [64]u8 = undefined;
    HkdfSha256.expand(&out, "WhisperRatchet", prk);
    return .{
        .root_key = out[0..32].*,
        .chain_key = out[32..64].*,
    };
}

pub fn createSessionKeys(
    input_key_material: []const u8,
    pqxdh: bool,
) struct { root_key: [32]u8, chain_key: [32]u8 } {
    const label = if (pqxdh)
        "WhisperText_X25519_SHA-256_CRYSTALS-KYBER-1024"
    else
        "WhisperText";
    const prk = HkdfSha256.extract(&ZERO_SALT, input_key_material);
    var out: [64]u8 = undefined;
    HkdfSha256.expand(&out, label, prk);
    return .{
        .root_key = out[0..32].*,
        .chain_key = out[32..64].*,
    };
}

pub fn deriveMessageKeys(
    chain_key_seed: [32]u8,
) struct { cipher_key: [32]u8, mac_key: [32]u8, iv: [16]u8 } {
    const prk = HkdfSha256.extract(&ZERO_SALT, &chain_key_seed);
    var out: [80]u8 = undefined;
    HkdfSha256.expand(&out, "WhisperMessageKeys", prk);
    return .{
        .cipher_key = out[0..32].*,
        .mac_key = out[32..64].*,
        .iv = out[64..80].*,
    };
}

pub fn nextChainKey(current: [32]u8) [32]u8 {
    var next: [32]u8 = undefined;
    const seed = [1]u8{0x02};
    HmacSha256.create(&next, &seed, &current);
    return next;
}

pub fn messageKeySeed(chain_key: [32]u8) [32]u8 {
    var seed: [32]u8 = undefined;
    const input = [1]u8{0x01};
    HmacSha256.create(&seed, &input, &chain_key);
    return seed;
}

pub fn senderKeyDerive(
    iteration: u32,
    chain_key: [32]u8,
) struct { cipher_key: [32]u8, iv: [16]u8, mac_key: [32]u8 } {
    var iter_bytes: [4]u8 = undefined;
    @memcpy(&iter_bytes, std.mem.asBytes(&iteration));
    var seed_material: [36]u8 = undefined;
    @memcpy(seed_material[0..32], &chain_key);
    @memcpy(seed_material[32..36], &iter_bytes);

    const prk = HkdfSha256.extract(&ZERO_SALT, &seed_material);
    var out: [80]u8 = undefined;
    HkdfSha256.expand(&out, "WhisperGroup", prk);
    return .{
        .cipher_key = out[0..32].*,
        .iv = out[32..48].*,
        .mac_key = out[48..80].*,
    };
}

pub fn nextSenderChainKey(current: [32]u8) [32]u8 {
    const prk = HkdfSha256.extract(&ZERO_SALT, &current);
    var out: [32]u8 = undefined;
    HkdfSha256.expand(&out, "WhisperGroup", prk);
    return out;
}
