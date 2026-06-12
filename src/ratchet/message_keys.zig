const std = @import("std");
const kdf = @import("../kdf.zig");

pub const MessageKeys = struct {
    cipher_key: [32]u8,
    mac_key: [32]u8,
    iv: [16]u8,
    counter: u32,

    pub fn fromSeed(seed: [32]u8, counter: u32, pqr_key: ?[32]u8) MessageKeys {
        const derived = kdf.deriveMessageKeys(seed, pqr_key);
        return .{
            .cipher_key = derived.cipher_key,
            .mac_key = derived.mac_key,
            .iv = derived.iv,
            .counter = counter,
        };
    }
};
