// Sealed Sender: anonymous delivery of Signal Protocol messages.
// Hides sender identity from the Signal server while still authenticating to recipient.
//
// V1 (sealedSenderEncrypt / sealedSenderDecryptToUsmc):
//   Single-recipient AES-256-CBC. Wire: protobuf {ephemeralPub, encryptedStatic, encryptedMessage}.
//
// V2 (sealedSenderEncryptV2 / sealedSenderDecryptV2):
//   Multi-recipient AES-256-GCM-SIV. One shared ciphertext; per-recipient (C_i, AT_i) pair.
//   Sent message version byte 0x23; received message version byte 0x22.
const std = @import("std");
const curve = @import("curve.zig");
const identity = @import("identity.zig");
const service_id_mod = @import("service_id.zig");
const address_mod = @import("address.zig");
const proto = @import("proto.zig");
const kdf = @import("kdf.zig");
const rnd = @import("random.zig");
const aes_mod = @import("aes.zig");
const err = @import("error.zig");
const aes_cbc = @import("session_builder.zig").aes_cbc;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
const mem = std.mem;

// ---- V2 constants ----
const SSV2_SENT_VERSION: u8 = 0x23; // ServiceId-typed recipients
const SSV2_RECV_VERSION: u8 = 0x22; // per-device received format

const LABEL_R = "Sealed Sender v2: r (2023-08)";
const LABEL_K = "Sealed Sender v2: K";
const LABEL_DH = "Sealed Sender v2: DH";
const LABEL_DH_S = "Sealed Sender v2: DH-sender";

const C_LEN: usize = 32;
const AT_LEN: usize = 16;
const E_PUB_LEN: usize = 32; // raw Curve25519, no type byte

// ---- Message type values ----
pub const ContentType = enum(u8) {
    prekey_message = 1,
    message = 2,
    sender_key_message = 7,
    plaintext_content = 8,
};

pub const ContentHint = enum(u8) {
    default = 0,
    resendable = 1,
    implicit = 2,
};

pub const ServerCertificate = struct {
    key_id: u32,
    key: curve.PublicKey,
    certificate: []const u8,
    signature: [64]u8,
    allocator: mem.Allocator,

    pub fn new(
        allocator: mem.Allocator,
        key_id: u32,
        key: curve.PublicKey,
        trust_root_key: curve.PrivateKey,
    ) !ServerCertificate {
        var cert_enc = proto.Encoder.init(allocator);
        defer cert_enc.deinit();
        try cert_enc.writeVarintField(1, key_id);
        const key_bytes = key.serialize();
        try cert_enc.writeBytesField(2, &key_bytes);
        const cert_bytes = try cert_enc.toOwnedSlice();

        const sig = try trust_root_key.calculateSignature(cert_bytes);
        return .{
            .key_id = key_id,
            .key = key,
            .certificate = cert_bytes,
            .signature = sig,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *ServerCertificate) void {
        self.allocator.free(self.certificate);
    }

    pub fn validate(self: ServerCertificate, trust_root: curve.PublicKey) !bool {
        return trust_root.verifySignature(self.certificate, self.signature);
    }

    pub fn serialize(self: ServerCertificate) ![]u8 {
        var enc = proto.Encoder.init(self.allocator);
        defer enc.deinit();
        try enc.writeBytesField(1, self.certificate);
        try enc.writeBytesField(2, &self.signature);
        return enc.toOwnedSlice();
    }

    pub fn deserialize(allocator: mem.Allocator, data: []const u8) !ServerCertificate {
        var pos: usize = 0;
        var cert_bytes: ?[]const u8 = null;
        var sig_bytes: ?[]const u8 = null;
        while (try proto.nextField(data, &pos)) |field| {
            switch (field.number) {
                1 => {
                    if (field.wire_type == .len) cert_bytes = field.data.len;
                },
                2 => {
                    if (field.wire_type == .len) sig_bytes = field.data.len;
                },
                else => {},
            }
        }
        const cert = cert_bytes orelse return err.SignalError.InvalidArgument;
        const sig_raw = sig_bytes orelse return err.SignalError.InvalidArgument;
        if (sig_raw.len != 64) return err.SignalError.InvalidSignature;

        var cert_pos: usize = 0;
        var key_id: u32 = 0;
        var key_bytes: ?[]const u8 = null;
        while (try proto.nextField(cert, &cert_pos)) |field| {
            switch (field.number) {
                1 => {
                    if (field.wire_type == .varint) key_id = @intCast(field.data.varint);
                },
                2 => {
                    if (field.wire_type == .len) key_bytes = field.data.len;
                },
                else => {},
            }
        }
        const key = try curve.PublicKey.deserialize(key_bytes orelse return err.SignalError.InvalidArgument);
        const cert_copy = try allocator.dupe(u8, cert);
        return .{
            .key_id = key_id,
            .key = key,
            .certificate = cert_copy,
            .signature = sig_raw[0..64].*,
            .allocator = allocator,
        };
    }
};

pub const SenderCertificate = struct {
    sender_uuid: []const u8,
    sender_e164: ?[]const u8,
    sender_device_id: u32,
    sender_key: curve.PublicKey,
    expiration: u64,
    signer: ServerCertificate,
    certificate: []const u8,
    signature: [64]u8,
    allocator: mem.Allocator,

    pub fn new(
        allocator: mem.Allocator,
        sender_uuid: []const u8,
        sender_e164: ?[]const u8,
        sender_device_id: u32,
        sender_key: curve.PublicKey,
        expiration: u64,
        server_cert: ServerCertificate,
        server_key: curve.PrivateKey,
    ) !SenderCertificate {
        var cert_enc = proto.Encoder.init(allocator);
        defer cert_enc.deinit();
        try cert_enc.writeBytesField(6, sender_uuid);
        if (sender_e164) |e164| try cert_enc.writeBytesField(1, e164);
        try cert_enc.writeVarintField(2, sender_device_id);
        try cert_enc.writeFixed64Field(3, expiration);
        const sk_bytes = sender_key.serialize();
        try cert_enc.writeBytesField(4, &sk_bytes);
        const sc_bytes = try server_cert.serialize();
        defer allocator.free(sc_bytes);
        try cert_enc.writeBytesField(5, sc_bytes);
        const cert_bytes = try cert_enc.toOwnedSlice();

        const sig = try server_key.calculateSignature(cert_bytes);
        const uuid_copy = try allocator.dupe(u8, sender_uuid);
        errdefer allocator.free(uuid_copy);
        const e164_copy = if (sender_e164) |e| try allocator.dupe(u8, e) else null;

        return .{
            .sender_uuid = uuid_copy,
            .sender_e164 = e164_copy,
            .sender_device_id = sender_device_id,
            .sender_key = sender_key,
            .expiration = expiration,
            .signer = server_cert,
            .certificate = cert_bytes,
            .signature = sig,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *SenderCertificate) void {
        self.allocator.free(self.sender_uuid);
        if (self.sender_e164) |e| self.allocator.free(e);
        self.allocator.free(self.certificate);
        self.signer.deinit();
    }

    pub fn validate(self: SenderCertificate, trust_root: curve.PublicKey, current_time: u64) !bool {
        if (current_time > self.expiration) return false;
        if (!try self.signer.validate(trust_root)) return false;
        return self.signer.key.verifySignature(self.certificate, self.signature);
    }

    pub fn serialize(self: SenderCertificate) ![]u8 {
        var enc = proto.Encoder.init(self.allocator);
        defer enc.deinit();
        try enc.writeBytesField(1, self.certificate);
        try enc.writeBytesField(2, &self.signature);
        return enc.toOwnedSlice();
    }

    pub fn deserialize(allocator: mem.Allocator, data: []const u8) !SenderCertificate {
        var pos: usize = 0;
        var cert_bytes: ?[]const u8 = null;
        var sig_bytes: ?[]const u8 = null;
        while (try proto.nextField(data, &pos)) |field| {
            switch (field.number) {
                1 => {
                    if (field.wire_type == .len) cert_bytes = field.data.len;
                },
                2 => {
                    if (field.wire_type == .len) sig_bytes = field.data.len;
                },
                else => {},
            }
        }
        const cert = cert_bytes orelse return err.SignalError.InvalidArgument;
        const sig_raw = sig_bytes orelse return err.SignalError.InvalidArgument;
        if (sig_raw.len != 64) return err.SignalError.InvalidSignature;

        var uuid: ?[]const u8 = null;
        var e164: ?[]const u8 = null;
        var device_id: u32 = 1;
        var expiration: u64 = 0;
        var sender_key_bytes: ?[]const u8 = null;
        var server_cert_bytes: ?[]const u8 = null;

        var cert_pos: usize = 0;
        while (try proto.nextField(cert, &cert_pos)) |field| {
            switch (field.number) {
                1 => {
                    if (field.wire_type == .len) e164 = field.data.len;
                },
                2 => {
                    if (field.wire_type == .varint) device_id = @intCast(field.data.varint);
                },
                3 => {
                    if (field.wire_type == .i64) expiration = field.data.i64;
                },
                4 => {
                    if (field.wire_type == .len) sender_key_bytes = field.data.len;
                },
                5 => {
                    if (field.wire_type == .len) server_cert_bytes = field.data.len;
                },
                6 => {
                    if (field.wire_type == .len) uuid = field.data.len;
                },
                else => {},
            }
        }

        const uuid_str = uuid orelse return err.SignalError.InvalidArgument;
        const sender_key = try curve.PublicKey.deserialize(sender_key_bytes orelse return err.SignalError.InvalidArgument);
        const server_cert = try ServerCertificate.deserialize(
            allocator,
            server_cert_bytes orelse return err.SignalError.InvalidArgument,
        );

        return .{
            .sender_uuid = try allocator.dupe(u8, uuid_str),
            .sender_e164 = if (e164) |e| try allocator.dupe(u8, e) else null,
            .sender_device_id = device_id,
            .sender_key = sender_key,
            .expiration = expiration,
            .signer = server_cert,
            .certificate = try allocator.dupe(u8, cert),
            .signature = sig_raw[0..64].*,
            .allocator = allocator,
        };
    }
};

pub const UnidentifiedSenderMessageContent = struct {
    msg_type: ContentType,
    sender_cert: SenderCertificate,
    content_hint: ContentHint,
    group_id: ?[]const u8,
    contents: []const u8,
    allocator: mem.Allocator,

    pub fn new(
        allocator: mem.Allocator,
        msg_type: ContentType,
        sender_cert: SenderCertificate,
        content_hint: ContentHint,
        group_id: ?[]const u8,
        contents: []const u8,
    ) !UnidentifiedSenderMessageContent {
        return .{
            .msg_type = msg_type,
            .sender_cert = sender_cert,
            .content_hint = content_hint,
            .group_id = if (group_id) |g| try allocator.dupe(u8, g) else null,
            .contents = try allocator.dupe(u8, contents),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *UnidentifiedSenderMessageContent) void {
        self.sender_cert.deinit();
        if (self.group_id) |g| self.allocator.free(g);
        self.allocator.free(self.contents);
    }

    pub fn serialize(self: UnidentifiedSenderMessageContent) ![]u8 {
        var enc = proto.Encoder.init(self.allocator);
        defer enc.deinit();
        try enc.writeVarintField(1, @intFromEnum(self.msg_type));
        const sc_bytes = try self.sender_cert.serialize();
        defer self.allocator.free(sc_bytes);
        try enc.writeBytesField(2, sc_bytes);
        try enc.writeBytesField(3, self.contents);
        if (self.content_hint != .default) {
            try enc.writeVarintField(4, @intFromEnum(self.content_hint));
        }
        if (self.group_id) |g| try enc.writeBytesField(5, g);
        return enc.toOwnedSlice();
    }

    pub fn deserialize(allocator: mem.Allocator, data: []const u8) !UnidentifiedSenderMessageContent {
        var pos: usize = 0;
        var msg_type: ContentType = .message;
        var sender_cert_bytes: ?[]const u8 = null;
        var contents: ?[]const u8 = null;
        var content_hint: ContentHint = .default;
        var group_id: ?[]const u8 = null;

        while (try proto.nextField(data, &pos)) |field| {
            switch (field.number) {
                1 => {
                    if (field.wire_type == .varint) msg_type = @enumFromInt(@as(u8, @intCast(field.data.varint & 0xFF)));
                },
                2 => {
                    if (field.wire_type == .len) sender_cert_bytes = field.data.len;
                },
                3 => {
                    if (field.wire_type == .len) contents = field.data.len;
                },
                4 => {
                    if (field.wire_type == .varint) content_hint = @enumFromInt(@as(u8, @intCast(field.data.varint & 0xFF)));
                },
                5 => {
                    if (field.wire_type == .len) group_id = field.data.len;
                },
                else => {},
            }
        }
        const sc = try SenderCertificate.deserialize(
            allocator,
            sender_cert_bytes orelse return err.SignalError.InvalidArgument,
        );
        const ct = contents orelse return err.SignalError.InvalidArgument;
        return .{
            .msg_type = msg_type,
            .sender_cert = sc,
            .content_hint = content_hint,
            .group_id = if (group_id) |g| try allocator.dupe(u8, g) else null,
            .contents = try allocator.dupe(u8, ct),
            .allocator = allocator,
        };
    }
};

// ---- V1 ----

fn hkdfDeriveUnidentified(dh_output: [32]u8) [96]u8 {
    const prk = HkdfSha256.extract("UnidentifiedDelivery", &dh_output);
    var out: [96]u8 = undefined;
    HkdfSha256.expand(&out, "", prk);
    return out;
}

/// Encrypt a message for V1 sealed sender delivery.
/// Returns the UnidentifiedSenderMessage bytes to send to the server.
pub fn sealedSenderEncrypt(
    allocator: mem.Allocator,
    recipient_identity: curve.PublicKey,
    usmc: *const UnidentifiedSenderMessageContent,
) ![]u8 {
    const plaintext = try usmc.serialize();
    defer allocator.free(plaintext);

    const ephemeral_kp = try curve.KeyPair.generate();
    const ephemeral_pub = ephemeral_kp.public_key.serialize();

    // DH(e, recipient) → derive ephemeral-layer keys
    const ecdh_1 = try ephemeral_kp.private_key.calculateAgreement(recipient_identity);
    const e_keys = hkdfDeriveUnidentified(ecdh_1);
    const e_iv: [16]u8 = e_keys[0..16].*;
    const e_cipher_key: [32]u8 = e_keys[32..64].*;
    const e_mac_key: [32]u8 = e_keys[64..96].*;

    const e_ciphertext = try aes_cbc.encrypt(allocator, e_cipher_key, e_iv, plaintext);
    defer allocator.free(e_ciphertext);

    var e_mac_engine = HmacSha256.init(&e_mac_key);
    e_mac_engine.update(&ephemeral_pub);
    e_mac_engine.update(e_ciphertext);
    var e_mac: [32]u8 = undefined;
    e_mac_engine.final(&e_mac);

    // DH(e, sender_identity_key) → static-layer binding (proves sender used their identity key)
    const ecdh_2 = try ephemeral_kp.private_key.calculateAgreement(usmc.sender_cert.sender_key);
    var static_ikm: [40]u8 = undefined;
    @memcpy(static_ikm[0..32], &ecdh_2);
    @memcpy(static_ikm[32..40], e_mac[0..8]);
    const s_prk = HkdfSha256.extract("", &static_ikm);
    var s_keys: [96]u8 = undefined;
    HkdfSha256.expand(&s_keys, "", s_prk);
    const s_iv: [16]u8 = s_keys[0..16].*;
    const s_cipher_key: [32]u8 = s_keys[32..64].*;
    const s_mac_key: [32]u8 = s_keys[64..96].*;

    const sc_bytes = try usmc.sender_cert.serialize();
    defer allocator.free(sc_bytes);
    var static_pt: std.ArrayListUnmanaged(u8) = .empty;
    defer static_pt.deinit(allocator);
    try static_pt.appendSlice(allocator, sc_bytes);
    try static_pt.appendSlice(allocator, e_ciphertext);
    try static_pt.appendSlice(allocator, e_mac[0..8]);

    const s_ciphertext = try aes_cbc.encrypt(allocator, s_cipher_key, s_iv, static_pt.items);
    defer allocator.free(s_ciphertext);

    var s_mac_engine = HmacSha256.init(&s_mac_key);
    s_mac_engine.update(&ephemeral_pub);
    s_mac_engine.update(s_ciphertext);
    var s_mac: [32]u8 = undefined;
    s_mac_engine.final(&s_mac);

    // encrypted_static = s_ciphertext || s_mac[0..10]
    const encrypted_static = try allocator.alloc(u8, s_ciphertext.len + 10);
    defer allocator.free(encrypted_static);
    @memcpy(encrypted_static[0..s_ciphertext.len], s_ciphertext);
    @memcpy(encrypted_static[s_ciphertext.len..], s_mac[0..10]);

    var enc = proto.Encoder.init(allocator);
    defer enc.deinit();
    try enc.writeBytesField(1, &ephemeral_pub);
    try enc.writeBytesField(2, encrypted_static);
    try enc.writeBytesField(3, e_ciphertext);

    return enc.toOwnedSlice();
}

pub const SealedSenderDecryptResult = struct {
    plaintext: []u8,
    sender_uuid: []const u8,
    sender_e164: ?[]const u8,
    sender_device_id: u32,
    content_type: ContentType,
    allocator: mem.Allocator,

    pub fn deinit(self: *SealedSenderDecryptResult) void {
        self.allocator.free(self.plaintext);
        self.allocator.free(self.sender_uuid);
        if (self.sender_e164) |e| self.allocator.free(e);
    }
};

/// Decrypt a V1 sealed sender message (recipient side).
pub fn sealedSenderDecryptToUsmc(
    allocator: mem.Allocator,
    data: []const u8,
    our_identity: curve.PrivateKey,
) !UnidentifiedSenderMessageContent {
    var pos: usize = 0;
    var ephemeral_pub_bytes: ?[]const u8 = null;
    var encrypted_message: ?[]const u8 = null;

    while (try proto.nextField(data, &pos)) |field| {
        switch (field.number) {
            1 => {
                if (field.wire_type == .len) ephemeral_pub_bytes = field.data.len;
            },
            3 => {
                if (field.wire_type == .len) encrypted_message = field.data.len;
            },
            else => {},
        }
    }

    const e_pub_raw = ephemeral_pub_bytes orelse return err.SignalError.InvalidMessage;
    const encrypted_message_raw = encrypted_message orelse return err.SignalError.InvalidMessage;

    const ephemeral_pub = try curve.PublicKey.deserialize(e_pub_raw);

    // Derive ephemeral-layer keys
    const ecdh_1 = try our_identity.calculateAgreement(ephemeral_pub);
    const e_keys = hkdfDeriveUnidentified(ecdh_1);
    const e_iv: [16]u8 = e_keys[0..16].*;
    const e_cipher_key: [32]u8 = e_keys[32..64].*;

    const usmc_bytes = try aes_cbc.decrypt(allocator, e_cipher_key, e_iv, encrypted_message_raw);
    defer allocator.free(usmc_bytes);

    return UnidentifiedSenderMessageContent.deserialize(allocator, usmc_bytes);
}

// ---- V2 ----

/// One recipient for SSv2 encryption.
pub const SealedSenderV2Recipient = struct {
    service_id: service_id_mod.ServiceId,
    device_id: u8,
    identity_key: curve.PublicKey,
};

/// SSv2 per-recipient data embedded in the received message.
pub const SealedSenderV2ReceivedData = struct {
    c: [C_LEN]u8,
    at: [AT_LEN]u8,
    e_pub: [E_PUB_LEN]u8,
    ciphertext: []const u8, // borrowed from the received message bytes
};

fn hkdfV2(ikm: []const u8, info: []const u8, out: []u8) void {
    const prk = HkdfSha256.extract("", ikm);
    // HKDF-SHA256 expand in 32-byte blocks
    var counter: u8 = 1;
    var prev: [32]u8 = undefined;
    var produced: usize = 0;
    while (produced < out.len) {
        var h = HmacSha256.init(&@as([32]u8, prk));
        if (produced > 0) h.update(&prev);
        h.update(info);
        h.update(&[1]u8{counter});
        var block: [32]u8 = undefined;
        h.final(&block);
        prev = block;
        const chunk = @min(32, out.len - produced);
        @memcpy(out[produced .. produced + chunk], block[0..chunk]);
        produced += chunk;
        counter += 1;
    }
}

fn computePad(e_priv_bytes: [32]u8, r_pub: curve.PublicKey, e_pub_bytes: [32]u8) ![32]u8 {
    const e_priv = curve.PrivateKey.fromBytes(e_priv_bytes);
    const dh = try e_priv.calculateAgreement(r_pub);
    // ikm = DH(e, R) || e_pub || R_pub
    var ikm: [32 + 32 + 32]u8 = undefined;
    @memcpy(ikm[0..32], &dh);
    @memcpy(ikm[32..64], &e_pub_bytes);
    @memcpy(ikm[64..96], &r_pub.key_bytes);
    var pad: [32]u8 = undefined;
    hkdfV2(&ikm, LABEL_DH, &pad);
    return pad;
}

fn computeAt(
    s_priv: curve.PrivateKey,
    r_pub: curve.PublicKey,
    e_pub_bytes: [32]u8,
    c: [32]u8,
    s_pub_bytes: [32]u8,
) ![AT_LEN]u8 {
    const dh_s = try s_priv.calculateAgreement(r_pub);
    // ikm = DH(S, R) || e_pub || C || S_pub || R_pub
    var ikm: [32 + 32 + 32 + 32 + 32]u8 = undefined;
    @memcpy(ikm[0..32], &dh_s);
    @memcpy(ikm[32..64], &e_pub_bytes);
    @memcpy(ikm[64..96], &c);
    @memcpy(ikm[96..128], &s_pub_bytes);
    @memcpy(ikm[128..160], &r_pub.key_bytes);
    var at: [AT_LEN]u8 = undefined;
    hkdfV2(&ikm, LABEL_DH_S, &at);
    return at;
}

/// Encrypt a message for SSv2 multi-recipient delivery.
/// Returns the complete sent-message bytes (version 0x23 format) to upload to the Signal server.
pub fn sealedSenderEncryptV2(
    allocator: mem.Allocator,
    message: []const u8,
    sender_identity_kp: curve.KeyPair,
    recipients: []const SealedSenderV2Recipient,
    excluded: []const service_id_mod.ServiceId,
) ![]u8 {
    // Step 1: generate 32 random bytes, derive ephemeral keypair + AES key
    var m: [32]u8 = undefined;
    rnd.bytes(&m);

    var e_priv_bytes: [32]u8 = undefined;
    hkdfV2(&m, LABEL_R, &e_priv_bytes);
    // Clamp as X25519 private key
    e_priv_bytes[0] &= 248;
    e_priv_bytes[31] &= 127;
    e_priv_bytes[31] |= 64;

    const e_priv = curve.PrivateKey.fromBytes(e_priv_bytes);
    const e_pub_bytes = (try e_priv.publicKey()).key_bytes;

    var K: [32]u8 = undefined;
    hkdfV2(&m, LABEL_K, &K);

    // Step 2: AES-256-GCM-SIV encrypt message (once, shared across all recipients)
    const nonce = [_]u8{0} ** 12;
    const ciphertext_with_tag = try aes_mod.gcm_siv_encrypt(allocator, K, nonce, message, &[0]u8{});
    defer allocator.free(ciphertext_with_tag);

    const s_pub_bytes = sender_identity_kp.public_key.key_bytes;

    // Step 3: per-recipient C_i and AT_i
    const total_recipients = recipients.len + excluded.len;

    var out: std.ArrayListUnmanaged(u8) = .empty;
    defer out.deinit(allocator);

    try out.append(allocator, SSV2_SENT_VERSION);

    // Write count as protobuf-style varint
    var varint_buf: [10]u8 = undefined;
    const varint_len = writeVarint(total_recipients, &varint_buf);
    try out.appendSlice(allocator, varint_buf[0..varint_len]);

    for (recipients) |recipient| {
        // service_id fixed-width binary (17 bytes)
        const sid_bin = recipient.service_id.toFixedWidthBinary();
        try out.appendSlice(allocator, &sid_bin);

        // device entry: device_id (u8) + reg_id_and_has_more (u16 BE, high bit = 0 = no more devices)
        // We encode a single device with placeholder reg_id=0
        try out.append(allocator, recipient.device_id);
        const reg_word: u16 = 0; // no more devices
        try out.append(allocator, @intCast(reg_word >> 8));
        try out.append(allocator, @intCast(reg_word & 0xFF));

        // C_i = pad XOR m
        const pad = try computePad(e_priv_bytes, recipient.identity_key, e_pub_bytes);
        var c: [32]u8 = undefined;
        for (0..32) |i| c[i] = pad[i] ^ m[i];
        try out.appendSlice(allocator, &c);

        // AT_i
        const at = try computeAt(sender_identity_kp.private_key, recipient.identity_key, e_pub_bytes, c, s_pub_bytes);
        try out.appendSlice(allocator, &at);
    }

    // Excluded recipients: service_id || 0x00
    for (excluded) |sid| {
        const sid_bin = sid.toFixedWidthBinary();
        try out.appendSlice(allocator, &sid_bin);
        try out.append(allocator, 0x00);
    }

    // Shared suffix: e_pub (raw 32 bytes) || ciphertext_with_tag
    try out.appendSlice(allocator, &e_pub_bytes);
    try out.appendSlice(allocator, ciphertext_with_tag);

    return out.toOwnedSlice(allocator);
}

/// Decrypt a received SSv2 message (per-device received format, version 0x22).
/// received_data layout: 0x22 || C[32] || AT[16] || e_pub[32] || ciphertext_with_tag[...]
pub fn sealedSenderDecryptV2(
    allocator: mem.Allocator,
    received: []const u8,
    our_identity_kp: curve.KeyPair,
    sender_identity_pub: curve.PublicKey,
) ![]u8 {
    if (received.len < 1 + C_LEN + AT_LEN + E_PUB_LEN + 16)
        return err.SignalError.InvalidMessage;
    if (received[0] != SSV2_RECV_VERSION)
        return err.SignalError.UnknownCiphertextVersion;

    var pos: usize = 1;
    const c: [32]u8 = received[pos..][0..32].*;
    pos += 32;
    const at: [16]u8 = received[pos..][0..16].*;
    pos += 16;
    const e_pub_bytes: [32]u8 = received[pos..][0..32].*;
    pos += 32;
    const ciphertext_with_tag = received[pos..];

    const e_pub = curve.PublicKey.fromBytes(e_pub_bytes);

    // Recover m: pad = HKDF(DH(our_priv, e_pub) || e_pub || our_pub, LABEL_DH)
    const r_priv = our_identity_kp.private_key;
    const r_pub_bytes = our_identity_kp.public_key.key_bytes;
    const dh = try r_priv.calculateAgreement(e_pub);
    var ikm_dh: [96]u8 = undefined;
    @memcpy(ikm_dh[0..32], &dh);
    @memcpy(ikm_dh[32..64], &e_pub_bytes);
    @memcpy(ikm_dh[64..96], &r_pub_bytes);
    var pad: [32]u8 = undefined;
    hkdfV2(&ikm_dh, LABEL_DH, &pad);
    var m: [32]u8 = undefined;
    for (0..32) |i| m[i] = pad[i] ^ c[i];

    // Verify ephemeral key consistency
    var e_derived: [32]u8 = undefined;
    hkdfV2(&m, LABEL_R, &e_derived);
    e_derived[0] &= 248;
    e_derived[31] &= 127;
    e_derived[31] |= 64;
    const derived_pub = (try curve.PrivateKey.fromBytes(e_derived).publicKey()).key_bytes;
    if (!mem.eql(u8, &derived_pub, &e_pub_bytes))
        return err.SignalError.InvalidMessage;

    // Decrypt
    var K: [32]u8 = undefined;
    hkdfV2(&m, LABEL_K, &K);
    const nonce = [_]u8{0} ** 12;
    const plaintext = try aes_mod.gcm_siv_decrypt(allocator, K, nonce, ciphertext_with_tag, &[0]u8{});
    errdefer allocator.free(plaintext);

    // Verify authentication tag AT
    var ikm_s: [160]u8 = undefined;
    const dh_s = try r_priv.calculateAgreement(sender_identity_pub);
    @memcpy(ikm_s[0..32], &dh_s);
    @memcpy(ikm_s[32..64], &e_pub_bytes);
    @memcpy(ikm_s[64..96], &c);
    @memcpy(ikm_s[96..128], &sender_identity_pub.key_bytes);
    @memcpy(ikm_s[128..160], &r_pub_bytes);
    var expected_at: [AT_LEN]u8 = undefined;
    hkdfV2(&ikm_s, LABEL_DH_S, &expected_at);

    if (!std.crypto.timing_safe.eql([AT_LEN]u8, at, expected_at)) {
        allocator.free(plaintext);
        return err.SignalError.InvalidMessage;
    }

    return plaintext;
}

fn writeVarint(v: usize, buf: []u8) usize {
    var val = v;
    var pos: usize = 0;
    while (true) {
        if (val < 0x80) {
            buf[pos] = @intCast(val);
            pos += 1;
            break;
        }
        buf[pos] = @intCast((val & 0x7F) | 0x80);
        pos += 1;
        val >>= 7;
    }
    return pos;
}
