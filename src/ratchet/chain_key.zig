const std = @import("std");
const kdf = @import("../kdf.zig");
const MessageKeys = @import("message_keys.zig").MessageKeys;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

pub const ChainKey = struct {
    key: [32]u8,
    index: u32,

    pub fn init(key: [32]u8, index: u32) ChainKey {
        return .{ .key = key, .index = index };
    }

    pub fn messageKeys(self: ChainKey) MessageKeys {
        const seed = kdf.messageKeySeed(self.key);
        return MessageKeys.fromSeed(seed, self.index);
    }

    pub fn advance(self: ChainKey) ChainKey {
        return .{
            .key = kdf.nextChainKey(self.key),
            .index = self.index + 1,
        };
    }
};
