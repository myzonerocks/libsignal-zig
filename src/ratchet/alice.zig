// Alice (initiator) PQXDH key agreement parameters for session establishment.
const std = @import("std");
const curve = @import("../curve.zig");
const identity = @import("../identity.zig");
const kdf = @import("../kdf.zig");
const RootKey = @import("root_key.zig").RootKey;
const ChainKey = @import("chain_key.zig").ChainKey;
const mem = std.mem;

pub const AliceSignalProtocolParameters = struct {
    our_identity_key_pair: identity.IdentityKeyPair,
    our_base_key_pair: curve.KeyPair, // ephemeral
    their_identity_key: identity.IdentityKey,
    their_signed_pre_key: curve.PublicKey,
    their_one_time_pre_key: ?curve.PublicKey,
    their_ratchet_key: curve.PublicKey, // = their_signed_pre_key in first message
    their_kyber_pre_key: ?curve.KyberKeyPair, // only public key bytes matter
};

pub const DerivedKeys = struct {
    root_key: RootKey,
    chain_key: ChainKey,
    pqr_key: ?[32]u8, // present for PQXDH, null for X3DH
    kyber_ciphertext: ?[]u8, // if PQXDH was used; caller must free
};

/// Perform X3DH/PQXDH key agreement from Alice's perspective.
pub fn initialize(
    allocator: mem.Allocator,
    params: AliceSignalProtocolParameters,
) !DerivedKeys {
    const DISCONTINUITY: [32]u8 = [_]u8{0xFF} ** 32;

    // dh1 = ECDH(our_identity, their_signed_prekey)
    const dh1 = try params.our_identity_key_pair.private_key.calculateAgreement(
        params.their_signed_pre_key,
    );
    // dh2 = ECDH(our_base_key, their_identity)
    const dh2 = try params.our_base_key_pair.private_key.calculateAgreement(
        params.their_identity_key.public_key,
    );
    // dh3 = ECDH(our_base_key, their_signed_prekey)
    const dh3 = try params.our_base_key_pair.private_key.calculateAgreement(
        params.their_signed_pre_key,
    );

    var secret: std.ArrayList(u8) = .empty;
    defer secret.deinit(allocator);
    try secret.appendSlice(allocator, &DISCONTINUITY);
    try secret.appendSlice(allocator, &dh1);
    try secret.appendSlice(allocator, &dh2);
    try secret.appendSlice(allocator, &dh3);

    // dh4 = ECDH(our_base_key, their_one_time_prekey) if present
    if (params.their_one_time_pre_key) |opk| {
        const dh4 = try params.our_base_key_pair.private_key.calculateAgreement(opk);
        try secret.appendSlice(allocator, &dh4);
    }

    // Kyber encapsulation if present
    var kyber_ct_buf: ?[]u8 = null;
    const use_pqxdh = params.their_kyber_pre_key != null;
    if (params.their_kyber_pre_key) |kpk| {
        const MlKem = std.crypto.kem.ml_kem.MLKem1024;
        const pk = try MlKem.PublicKey.fromBytes(&kpk.public_key_bytes);
        const rnd = @import("../random.zig");
        const enc_seed = rnd.fillArray(MlKem.encaps_seed_length);
        const enc = pk.encapsDeterministic(&enc_seed);
        try secret.appendSlice(allocator, &enc.shared_secret);
        const ct_copy = try allocator.dupe(u8, &enc.ciphertext);
        kyber_ct_buf = ct_copy;
    }

    const secret_slice = secret.items;
    const derived = kdf.createSessionKeys(secret_slice, use_pqxdh);

    return .{
        .root_key = RootKey.init(derived.root_key),
        .chain_key = ChainKey.init(derived.chain_key, 0),
        .pqr_key = derived.pqr_key,
        .kyber_ciphertext = kyber_ct_buf,
    };
}
