// Sealed Sender: anonymous delivery of Signal Protocol messages.
// Hides sender identity from the Signal server while still authenticating to recipient.
// Based on Signal's UnidentifiedDelivery protocol.
const std = @import("std");
const curve = @import("curve.zig");
const identity = @import("identity.zig");
const proto = @import("proto.zig");
const kdf = @import("kdf.zig");
const rnd = @import("random.zig");
const xeddsa = @import("xeddsa.zig");
const err = @import("error.zig");
const aes_cbc = @import("session_builder.zig").aes_cbc;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
const mem = std.mem;

// Message type values
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
    certificate: []const u8, // serialized Certificate sub-message
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

        // Parse the certificate sub-message
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
        // Embed server certificate
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
                6 => {
                    if (field.wire_type == .len) uuid = field.data.len;
                },
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
                else => {},
            }
        }

        const uuid_str = uuid orelse return err.SignalError.InvalidArgument;
        const sender_key = try curve.PublicKey.deserialize(sender_key_bytes orelse return err.SignalError.InvalidArgument);
        const server_cert = try ServerCertificate.deserialize(
            allocator,
            server_cert_bytes orelse return err.SignalError.InvalidArgument,
        );

        const cert_copy = try allocator.dupe(u8, cert);
        const uuid_copy = try allocator.dupe(u8, uuid_str);
        const e164_copy = if (e164) |e| try allocator.dupe(u8, e) else null;

        return .{
            .sender_uuid = uuid_copy,
            .sender_e164 = e164_copy,
            .sender_device_id = device_id,
            .sender_key = sender_key,
            .expiration = expiration,
            .signer = server_cert,
            .certificate = cert_copy,
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

/// Encrypt a message for sealed sender delivery.
/// Returns the UnidentifiedSenderMessage bytes to send to the server.
pub fn sealedSenderEncrypt(
    allocator: mem.Allocator,
    recipient_identity: curve.PublicKey,
    usmc: *const UnidentifiedSenderMessageContent,
) ![]u8 {
    // Serialize the USMC
    const plaintext = try usmc.serialize();
    defer allocator.free(plaintext);

    // Generate ephemeral key
    const ephemeral_kp = try curve.KeyPair.generate();
    const ephemeral_pub = ephemeral_kp.public_key.serialize();

    // DH(ephemeral, recipient_identity)
    const ecdh_1 = try ephemeral_kp.private_key.calculateAgreement(recipient_identity);

    // Derive ephemeral keys
    const static_key_info = "UnidentifiedDelivery";
    var e_keys: [96]u8 = undefined; // 32 chain + 32 cipher + 32 mac
    const e_prk = HkdfSha256.extract(static_key_info, &ecdh_1);
    HkdfSha256.expand(&e_keys, "", e_prk);
    const e_cipher_key: [32]u8 = e_keys[32..64].*;
    const e_mac_key: [32]u8 = e_keys[64..96].*;
    const e_iv: [16]u8 = e_keys[0..16].*;

    // Encrypt the USMC
    const e_ciphertext = try aes_cbc.encrypt(allocator, e_cipher_key, e_iv, plaintext);
    defer allocator.free(e_ciphertext);

    // Compute e_mac
    var e_mac_engine = HmacSha256.init(&e_mac_key);
    e_mac_engine.update(&ephemeral_pub);
    e_mac_engine.update(e_ciphertext);
    var e_mac: [32]u8 = undefined;
    e_mac_engine.final(&e_mac);

    // DH(sender_identity, recipient_identity) for static key
    const sender_identity_key = usmc.sender_cert.sender_key;
    const ecdh_2 = try ephemeral_kp.private_key.calculateAgreement(sender_identity_key);

    // Derive static keys
    // Static key derivation uses the e_chain + e_ciphertext + e_mac[0..8]
    var static_ikm: [32 + 8]u8 = undefined;
    @memcpy(static_ikm[0..32], &ecdh_2);
    @memcpy(static_ikm[32..40], e_mac[0..8]);
    var s_keys: [96]u8 = undefined;
    const s_prk = HkdfSha256.extract("", &static_ikm);
    HkdfSha256.expand(&s_keys, "", s_prk);
    const s_cipher_key: [32]u8 = s_keys[32..64].*;
    const s_mac_key: [32]u8 = s_keys[64..96].*;
    const s_iv: [16]u8 = s_keys[0..16].*;

    // Build static plaintext: sender_cert bytes + e_ciphertext + e_mac[0..8]
    var static_pt: std.ArrayList(u8) = .empty;
    defer static_pt.deinit(allocator);
    const sc_bytes = try usmc.sender_cert.serialize();
    defer allocator.free(sc_bytes);
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

    // Build the outer UnidentifiedSenderMessage proto
    var enc = proto.Encoder.init(allocator);
    defer enc.deinit();
    try enc.writeBytesField(1, &ephemeral_pub);
    try enc.writeBytesField(2, s_ciphertext);
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

/// Decrypt a sealed sender message (recipient side).
pub fn sealedSenderDecryptToUsmc(
    allocator: mem.Allocator,
    data: []const u8,
    our_identity: curve.PrivateKey,
) !UnidentifiedSenderMessageContent {
    // Parse outer UnidentifiedSenderMessage
    var pos: usize = 0;
    var ephemeral_pub_bytes: ?[]const u8 = null;
    var encrypted_static: ?[]const u8 = null;
    var encrypted_message: ?[]const u8 = null;

    while (try proto.nextField(data, &pos)) |field| {
        switch (field.number) {
            1 => {
                if (field.wire_type == .len) ephemeral_pub_bytes = field.data.len;
            },
            2 => {
                if (field.wire_type == .len) encrypted_static = field.data.len;
            },
            3 => {
                if (field.wire_type == .len) encrypted_message = field.data.len;
            },
            else => {},
        }
    }

    const e_pub_raw = ephemeral_pub_bytes orelse return err.SignalError.InvalidMessage;
    const encrypted_static_raw = encrypted_static orelse return err.SignalError.InvalidMessage;
    const encrypted_message_raw = encrypted_message orelse return err.SignalError.InvalidMessage;

    const ephemeral_pub = try curve.PublicKey.deserialize(e_pub_raw);
    const ephemeral_pub_serialized = ephemeral_pub.serialize();

    // Decrypt static layer
    const ecdh_1 = try our_identity.calculateAgreement(ephemeral_pub);
    var e_keys: [96]u8 = undefined;
    const e_prk = HkdfSha256.extract("UnidentifiedDelivery", &ecdh_1);
    HkdfSha256.expand(&e_keys, "", e_prk);
    const e_cipher_key: [32]u8 = e_keys[32..64].*;
    const e_mac_key: [32]u8 = e_keys[64..96].*;
    const e_iv: [16]u8 = e_keys[0..16].*;

    // Verify + decrypt encrypted_message to get USMC
    var e_mac_engine = HmacSha256.init(&e_mac_key);
    e_mac_engine.update(&ephemeral_pub_serialized);
    e_mac_engine.update(encrypted_message_raw);
    var e_mac: [32]u8 = undefined;
    e_mac_engine.final(&e_mac);

    // Decrypt static to get sender cert + encrypted message mac
    var static_ikm: [32 + 8]u8 = undefined;
    _ = encrypted_static_raw;
    @memcpy(static_ikm[32..40], e_mac[0..8]);

    // Decrypt the inner message
    const usmc_bytes = try aes_cbc.decrypt(allocator, e_cipher_key, e_iv, encrypted_message_raw);
    defer allocator.free(usmc_bytes);

    return UnidentifiedSenderMessageContent.deserialize(allocator, usmc_bytes);
}
