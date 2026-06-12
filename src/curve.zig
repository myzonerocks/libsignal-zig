// Curve25519 key types for Signal Protocol.
// Public keys are 33 bytes: 0x05 || 32-byte X25519 key.
// Private keys are 32 bytes, stored clamped.
const std = @import("std");
const mem = std.mem;
const xeddsa = @import("xeddsa.zig");
const rnd = @import("random.zig");
const err = @import("error.zig");

const X25519 = std.crypto.dh.X25519;

pub const KEY_TYPE_DJB: u8 = 0x05;
pub const PRIVATE_KEY_LENGTH = 32;
pub const PUBLIC_KEY_LENGTH = 32;
pub const SERIALIZED_PUBLIC_KEY_LENGTH = 33; // 0x05 prefix + 32 bytes
pub const SIGNATURE_LENGTH = 64;

pub const PublicKey = struct {
    key_bytes: [PUBLIC_KEY_LENGTH]u8,

    /// Parse a 32-byte X25519 public key (without 0x05 prefix).
    pub fn fromBytes(bytes: [PUBLIC_KEY_LENGTH]u8) PublicKey {
        return .{ .key_bytes = bytes };
    }

    /// Parse from serialized format: [0x05][32 bytes].
    pub fn deserialize(bytes: []const u8) !PublicKey {
        if (bytes.len < SERIALIZED_PUBLIC_KEY_LENGTH) return err.SignalError.InvalidKey;
        if (bytes[0] != KEY_TYPE_DJB) return err.SignalError.InvalidType;
        return .{ .key_bytes = bytes[1..33].* };
    }

    /// Serialize to [0x05][32 bytes].
    pub fn serialize(self: PublicKey) [SERIALIZED_PUBLIC_KEY_LENGTH]u8 {
        var out: [SERIALIZED_PUBLIC_KEY_LENGTH]u8 = undefined;
        out[0] = KEY_TYPE_DJB;
        @memcpy(out[1..33], &self.key_bytes);
        return out;
    }

    /// Verify an XEdDSA signature over message_parts concatenated.
    pub fn verifySignature(self: PublicKey, message: []const u8, sig: [SIGNATURE_LENGTH]u8) !bool {
        return xeddsa.verify(self.key_bytes, message, sig);
    }

    pub fn eql(a: PublicKey, b: PublicKey) bool {
        return mem.eql(u8, &a.key_bytes, &b.key_bytes);
    }

    pub fn compare(a: PublicKey, b: PublicKey) std.math.Order {
        return mem.order(u8, &a.key_bytes, &b.key_bytes);
    }
};

pub const PrivateKey = struct {
    key_bytes: [PRIVATE_KEY_LENGTH]u8,

    /// Create a PrivateKey from raw bytes (stores as-is, caller must clamp).
    pub fn fromBytes(bytes: [PRIVATE_KEY_LENGTH]u8) PrivateKey {
        return .{ .key_bytes = bytes };
    }

    /// Deserialize from serialized format (just 32 bytes for private keys).
    pub fn deserialize(bytes: []const u8) !PrivateKey {
        if (bytes.len < PRIVATE_KEY_LENGTH) return err.SignalError.InvalidKey;
        return .{ .key_bytes = bytes[0..32].* };
    }

    pub fn serialize(self: PrivateKey) [PRIVATE_KEY_LENGTH]u8 {
        return self.key_bytes;
    }

    /// Derive the corresponding public key.
    pub fn publicKey(self: PrivateKey) !PublicKey {
        const Curve25519 = X25519.Curve;
        const clamped = clampScalar(self.key_bytes);
        const pub_point = try Curve25519.basePoint.clampedMul(clamped);
        return .{ .key_bytes = pub_point.toBytes() };
    }

    /// Compute X25519 Diffie-Hellman shared secret.
    pub fn calculateAgreement(self: PrivateKey, their_public: PublicKey) ![32]u8 {
        return X25519.scalarmult(self.key_bytes, their_public.key_bytes);
    }

    /// Sign a message with XEdDSA.
    pub fn calculateSignature(self: PrivateKey, message: []const u8) ![SIGNATURE_LENGTH]u8 {
        const random_64 = rnd.fillArray(64);
        return xeddsa.sign(self.key_bytes, message, random_64);
    }

    /// Sign a message with a provided nonce (for testing).
    pub fn calculateSignatureDeterministic(
        self: PrivateKey,
        message: []const u8,
        random_64: [64]u8,
    ) ![SIGNATURE_LENGTH]u8 {
        return xeddsa.sign(self.key_bytes, message, random_64);
    }
};

pub const KeyPair = struct {
    public_key: PublicKey,
    private_key: PrivateKey,

    /// Generate a new random key pair.
    pub fn generate() !KeyPair {
        var seed: [32]u8 = undefined;
        rnd.bytes(&seed);
        return generateDeterministic(seed);
    }

    pub fn generateDeterministic(seed: [32]u8) !KeyPair {
        const kp = try X25519.KeyPair.generateDeterministic(seed);
        return .{
            .public_key = .{ .key_bytes = kp.public_key },
            .private_key = .{ .key_bytes = kp.secret_key },
        };
    }

    pub fn fromPrivateKey(private_key: PrivateKey) !KeyPair {
        return .{
            .public_key = try private_key.publicKey(),
            .private_key = private_key,
        };
    }
};

pub const KyberKeyPair = struct {
    const MlKem = std.crypto.kem.ml_kem.MLKem1024;

    pub const KYBER_PUBLIC_KEY_LENGTH = MlKem.PublicKey.encoded_length;
    pub const KYBER_SECRET_KEY_LENGTH = MlKem.SecretKey.encoded_length;
    pub const CIPHERTEXT_LENGTH = MlKem.ciphertext_length;
    pub const SHARED_SECRET_LENGTH = MlKem.shared_length;

    public_key_bytes: [KYBER_PUBLIC_KEY_LENGTH]u8,
    secret_key_bytes: [KYBER_SECRET_KEY_LENGTH]u8,

    pub fn generate() !KyberKeyPair {
        const seed = rnd.fillArray(MlKem.seed_length);
        return generateDeterministic(seed);
    }

    pub fn generateDeterministic(seed: [MlKem.seed_length]u8) !KyberKeyPair {
        const kp = try MlKem.KeyPair.generateDeterministic(seed);
        return .{
            .public_key_bytes = kp.public_key.toBytes(),
            .secret_key_bytes = kp.secret_key.toBytes(),
        };
    }

    pub fn publicKey(self: KyberKeyPair) !MlKem.PublicKey {
        return MlKem.PublicKey.fromBytes(&self.public_key_bytes);
    }

    pub fn secretKey(self: KyberKeyPair) !MlKem.SecretKey {
        return MlKem.SecretKey.fromBytes(&self.secret_key_bytes);
    }

    pub fn encapsulate(
        self: KyberKeyPair,
    ) !struct { ciphertext: [CIPHERTEXT_LENGTH]u8, shared_secret: [SHARED_SECRET_LENGTH]u8 } {
        const pk = try self.publicKey();
        const seed = rnd.fillArray(MlKem.encaps_seed_length);
        const enc = pk.encapsDeterministic(&seed);
        return .{ .ciphertext = enc.ciphertext, .shared_secret = enc.shared_secret };
    }

    pub fn encapsulateDeterministic(
        self: KyberKeyPair,
        seed: [MlKem.encaps_seed_length]u8,
    ) !struct { ciphertext: [CIPHERTEXT_LENGTH]u8, shared_secret: [SHARED_SECRET_LENGTH]u8 } {
        const pk = try self.publicKey();
        const enc = pk.encapsDeterministic(&seed);
        return .{ .ciphertext = enc.ciphertext, .shared_secret = enc.shared_secret };
    }

    pub fn decapsulate(self: KyberKeyPair, ciphertext: [CIPHERTEXT_LENGTH]u8) ![SHARED_SECRET_LENGTH]u8 {
        const sk = try self.secretKey();
        return sk.decaps(&ciphertext);
    }
};

fn clampScalar(s: [32]u8) [32]u8 {
    var c = s;
    c[0] &= 248;
    c[31] &= 127;
    c[31] |= 64;
    return c;
}

test "key pair generate and agreement" {
    const alice = try KeyPair.generate();
    const bob = try KeyPair.generate();
    const shared_ab = try alice.private_key.calculateAgreement(bob.public_key);
    const shared_ba = try bob.private_key.calculateAgreement(alice.public_key);
    try std.testing.expectEqualSlices(u8, &shared_ab, &shared_ba);
}

test "public key serialization roundtrip" {
    const kp = try KeyPair.generate();
    const serialized = kp.public_key.serialize();
    const deserialized = try PublicKey.deserialize(&serialized);
    try std.testing.expect(kp.public_key.eql(deserialized));
}

test "sign and verify" {
    const kp = try KeyPair.generate();
    const message = "test message";
    const sig = try kp.private_key.calculateSignature(message);
    const ok = try kp.public_key.verifySignature(message, sig);
    try std.testing.expect(ok);
}
