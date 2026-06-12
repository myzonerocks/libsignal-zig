// Bob (responder) X3DH / PQXDH key agreement parameters.
const std = @import("std");
const curve = @import("../curve.zig");
const identity = @import("../identity.zig");
const kdf = @import("../kdf.zig");
const RootKey = @import("root_key.zig").RootKey;
const ChainKey = @import("chain_key.zig").ChainKey;
const mem = std.mem;

pub const BobSignalProtocolParameters = struct {
    our_identity_key_pair: identity.IdentityKeyPair,
    our_signed_pre_key_pair: curve.KeyPair,
    our_one_time_pre_key_pair: ?curve.KeyPair,
    our_ratchet_key_pair: curve.KeyPair, // = our_signed_pre_key_pair initially
    our_kyber_pre_key_pair: ?curve.KyberKeyPair,
    their_identity_key: identity.IdentityKey,
    their_base_key: curve.PublicKey, // Alice's ephemeral key
    their_kyber_ciphertext: ?[]const u8,
};

pub const DerivedKeys = struct {
    root_key: RootKey,
    chain_key: ChainKey,
};

/// Perform X3DH/PQXDH key agreement from Bob's perspective.
pub fn initialize(
    _: mem.Allocator,
    params: BobSignalProtocolParameters,
) !DerivedKeys {
    const DISCONTINUITY: [32]u8 = [_]u8{0xFF} ** 32;

    // dh1 = ECDH(our_signed_prekey, their_identity)
    const dh1 = try params.our_signed_pre_key_pair.private_key.calculateAgreement(
        params.their_identity_key.public_key,
    );
    // dh2 = ECDH(our_identity, their_base_key)
    const dh2 = try params.our_identity_key_pair.private_key.calculateAgreement(
        params.their_base_key,
    );
    // dh3 = ECDH(our_signed_prekey, their_base_key)
    const dh3 = try params.our_signed_pre_key_pair.private_key.calculateAgreement(
        params.their_base_key,
    );

    const allocator = std.heap.smp_allocator;
    var secret: std.ArrayList(u8) = .empty;
    defer secret.deinit(allocator);
    try secret.appendSlice(allocator, &DISCONTINUITY);
    try secret.appendSlice(allocator, &dh1);
    try secret.appendSlice(allocator, &dh2);
    try secret.appendSlice(allocator, &dh3);

    // dh4 = ECDH(our_one_time_prekey, their_base_key) if present
    if (params.our_one_time_pre_key_pair) |opk_pair| {
        const dh4 = try opk_pair.private_key.calculateAgreement(params.their_base_key);
        try secret.appendSlice(allocator, &dh4);
    }

    // Kyber decapsulation if present
    const use_pqxdh = params.our_kyber_pre_key_pair != null;
    if (params.our_kyber_pre_key_pair) |kpk| {
        const ct = params.their_kyber_ciphertext orelse return error.InvalidArgument;
        const MlKem = std.crypto.kem.ml_kem.MLKem1024;
        if (ct.len != MlKem.ciphertext_length) return error.InvalidArgument;
        const sk = try MlKem.SecretKey.fromBytes(&kpk.secret_key_bytes);
        const ss = try sk.decaps(ct[0..MlKem.ciphertext_length]);
        try secret.appendSlice(allocator, &ss);
    }

    const derived = kdf.createSessionKeys(secret.items, use_pqxdh);

    return .{
        .root_key = RootKey.init(derived.root_key),
        .chain_key = ChainKey.init(derived.chain_key, 0),
    };
}
