const std = @import("std");
const kdf = @import("../kdf.zig");
const ChainKey = @import("chain_key.zig").ChainKey;
const curve = @import("../curve.zig");

pub const RootKey = struct {
    key: [32]u8,

    pub fn init(key: [32]u8) RootKey {
        return .{ .key = key };
    }

    /// Perform a DH ratchet step and derive a new RootKey + ChainKey.
    pub fn createChain(
        self: RootKey,
        their_ratchet_key: curve.PublicKey,
        our_ratchet_key: curve.PrivateKey,
    ) !struct { root_key: RootKey, chain_key: ChainKey } {
        const dh_output = try our_ratchet_key.calculateAgreement(their_ratchet_key);
        const derived = kdf.createChain(self.key, dh_output);
        return .{
            .root_key = .{ .key = derived.root_key },
            .chain_key = ChainKey.init(derived.chain_key, 0),
        };
    }
};
