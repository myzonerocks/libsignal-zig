const std = @import("std");
const curve = @import("../curve.zig");
const identity = @import("../identity.zig");
const err = @import("../error.zig");

pub const PreKeyBundle = struct {
    registration_id: u32,
    device_id: u32,
    identity_key: identity.IdentityKey,

    // Optional EC one-time pre-key
    pre_key_id: ?u32,
    pre_key_public: ?curve.PublicKey,

    // Required signed EC pre-key
    signed_pre_key_id: u32,
    signed_pre_key_public: curve.PublicKey,
    signed_pre_key_signature: [curve.SIGNATURE_LENGTH]u8,

    // Optional Kyber pre-key (for PQXDH)
    kyber_pre_key_id: ?u32,
    kyber_pre_key_public: ?[curve.KyberKeyPair.KYBER_PUBLIC_KEY_LENGTH]u8,
    kyber_pre_key_signature: ?[curve.SIGNATURE_LENGTH]u8,

    pub fn new(
        registration_id: u32,
        device_id: u32,
        pre_key_id: ?u32,
        pre_key_public: ?curve.PublicKey,
        signed_pre_key_id: u32,
        signed_pre_key_public: curve.PublicKey,
        signed_pre_key_signature: [curve.SIGNATURE_LENGTH]u8,
        identity_key: identity.IdentityKey,
        kyber_pre_key_id: ?u32,
        kyber_pre_key_public: ?[curve.KyberKeyPair.KYBER_PUBLIC_KEY_LENGTH]u8,
        kyber_pre_key_signature: ?[curve.SIGNATURE_LENGTH]u8,
    ) PreKeyBundle {
        return .{
            .registration_id = registration_id,
            .device_id = device_id,
            .identity_key = identity_key,
            .pre_key_id = pre_key_id,
            .pre_key_public = pre_key_public,
            .signed_pre_key_id = signed_pre_key_id,
            .signed_pre_key_public = signed_pre_key_public,
            .signed_pre_key_signature = signed_pre_key_signature,
            .kyber_pre_key_id = kyber_pre_key_id,
            .kyber_pre_key_public = kyber_pre_key_public,
            .kyber_pre_key_signature = kyber_pre_key_signature,
        };
    }

    /// Validate that signed pre-key and Kyber pre-key signatures are correct.
    pub fn validate(self: PreKeyBundle) !void {
        const pk_bytes = self.signed_pre_key_public.serialize();
        const valid_spk = try self.identity_key.public_key.verifySignature(
            &pk_bytes,
            self.signed_pre_key_signature,
        );
        if (!valid_spk) return err.SignalError.InvalidSignature;

        if (self.kyber_pre_key_public) |kpk_bytes| {
            const kpk_sig = self.kyber_pre_key_signature orelse return err.SignalError.InvalidArgument;
            const valid_kpk = try self.identity_key.public_key.verifySignature(&kpk_bytes, kpk_sig);
            if (!valid_kpk) return err.SignalError.InvalidSignature;
        }
    }
};
