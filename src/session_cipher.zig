// SessionCipher: encrypt and decrypt messages using an established session.
const std = @import("std");
const address_mod = @import("address.zig");
const identity = @import("identity.zig");
const curve = @import("curve.zig");
const storage = @import("storage.zig");
const SessionRecord = @import("state/session_record.zig").SessionRecord;
const SessionState = @import("state/session_state.zig").SessionState;
const bob_ratchet = @import("ratchet/bob.zig");
const pre_key_record_mod = @import("state/pre_key_record.zig");
const signed_pre_key_record_mod = @import("state/signed_pre_key_record.zig");
const kyber_pre_key_record_mod = @import("state/kyber_pre_key_record.zig");
const signal_msg_mod = @import("messages/signal_message.zig");
const pksm_mod = @import("messages/pre_key_signal_message.zig");
const err = @import("error.zig");
const aes_cbc = @import("session_builder.zig").aes_cbc;
const mem = std.mem;

pub const CiphertextType = enum(u8) {
    whisper = 2,
    pre_key = 3,
    sender_key = 7,
    plaintext_content = 8,
};

pub const CiphertextMessage = struct {
    message_type: CiphertextType,
    serialized: []const u8,
    allocator: mem.Allocator,

    pub fn deinit(self: *CiphertextMessage) void {
        self.allocator.free(self.serialized);
    }
};

pub const SessionCipher = struct {
    remote_address: address_mod.ProtocolAddress,
    session_store: storage.SessionStore,
    identity_store: storage.IdentityKeyStore,
    pre_key_store: storage.PreKeyStore,
    signed_pre_key_store: storage.SignedPreKeyStore,
    kyber_pre_key_store: ?storage.KyberPreKeyStore,
    allocator: mem.Allocator,

    pub fn init(
        allocator: mem.Allocator,
        remote_address: address_mod.ProtocolAddress,
        session_store: storage.SessionStore,
        pre_key_store: storage.PreKeyStore,
        signed_pre_key_store: storage.SignedPreKeyStore,
        identity_store: storage.IdentityKeyStore,
        kyber_pre_key_store: ?storage.KyberPreKeyStore,
    ) SessionCipher {
        return .{
            .remote_address = remote_address,
            .session_store = session_store,
            .identity_store = identity_store,
            .pre_key_store = pre_key_store,
            .signed_pre_key_store = signed_pre_key_store,
            .kyber_pre_key_store = kyber_pre_key_store,
            .allocator = allocator,
        };
    }

    /// Encrypt a plaintext message.
    pub fn encrypt(self: *SessionCipher, plaintext: []const u8) !CiphertextMessage {
        var record = try self.session_store.loadSession(&self.remote_address) orelse
            return err.SignalError.SessionNotFound;
        defer record.deinit();

        const state = record.currentState() orelse return err.SignalError.InvalidSession;
        const our_identity = try self.identity_store.getIdentityKeyPair();

        // Get message keys from sender chain
        const message_keys = state.sender_chain_key.messageKeys();
        state.sender_chain_key = state.sender_chain_key.advance();

        // Encrypt plaintext
        const ciphertext = try aes_cbc.encrypt(
            self.allocator,
            message_keys.cipher_key,
            message_keys.iv,
            plaintext,
        );
        defer self.allocator.free(ciphertext);

        const sender_id_bytes = our_identity.identity_key.serialize();
        const receiver_id_bytes = state.remote_identity_key.serialize();

        // Check if we need to send a PreKeySignalMessage
        if (state.pending_pre_key) |ppk| {
            // Build PreKeySignalMessage
            const signal_msg = signal_msg_mod.SignalMessage{
                .ratchet_key = state.sender_ratchet_key_pair.public_key,
                .counter = message_keys.counter,
                .previous_counter = state.previous_counter,
                .ciphertext = ciphertext,
                .pq_ratchet = null,
                .allocator = self.allocator,
            };
            const signal_bytes = try signal_msg.serialize(
                sender_id_bytes,
                receiver_id_bytes,
                message_keys.mac_key,
            );
            defer self.allocator.free(signal_bytes);

            var pksm = pksm_mod.PreKeySignalMessage{
                .message_version = 3,
                .registration_id = state.local_registration_id,
                .pre_key_id = ppk.pre_key_id,
                .signed_pre_key_id = ppk.signed_pre_key_id,
                .kyber_pre_key_id = if (state.pending_kyber_pre_key) |pkpk| pkpk.pre_key_id else null,
                .base_key = ppk.base_key,
                .identity_key = our_identity.identity_key.public_key,
                .kyber_ciphertext = if (state.pending_kyber_pre_key) |pkpk| pkpk.ciphertext else null,
                .message = signal_bytes,
                .allocator = self.allocator,
            };
            const serialized = try pksm.serialize();

            try self.session_store.storeSession(&self.remote_address, &record);

            return CiphertextMessage{
                .message_type = .pre_key,
                .serialized = serialized,
                .allocator = self.allocator,
            };
        }

        // Regular SignalMessage
        const signal_msg = signal_msg_mod.SignalMessage{
            .ratchet_key = state.sender_ratchet_key_pair.public_key,
            .counter = message_keys.counter,
            .previous_counter = state.previous_counter,
            .ciphertext = ciphertext,
            .pq_ratchet = null,
            .allocator = self.allocator,
        };
        const serialized = try signal_msg.serialize(
            sender_id_bytes,
            receiver_id_bytes,
            message_keys.mac_key,
        );

        try self.session_store.storeSession(&self.remote_address, &record);

        return CiphertextMessage{
            .message_type = .whisper,
            .serialized = serialized,
            .allocator = self.allocator,
        };
    }

    /// Decrypt a WhisperMessage (regular encrypted message).
    pub fn decryptMessage(self: *SessionCipher, ciphertext: []const u8) ![]u8 {
        var record = try self.session_store.loadSession(&self.remote_address) orelse
            return err.SignalError.SessionNotFound;
        defer record.deinit();

        const state = record.currentState() orelse return err.SignalError.InvalidSession;
        const our_identity = try self.identity_store.getIdentityKeyPair();
        const sender_id_bytes = state.remote_identity_key.serialize();
        const receiver_id_bytes = our_identity.identity_key.serialize();

        const result = try decryptWhisperMessage(
            self.allocator,
            state,
            ciphertext,
            sender_id_bytes,
            receiver_id_bytes,
        );

        try self.session_store.storeSession(&self.remote_address, &record);
        return result;
    }

    /// Decrypt a PreKeySignalMessage (session-initiating message).
    pub fn decryptPreKeyMessage(
        self: *SessionCipher,
        ciphertext: []const u8,
    ) ![]u8 {
        var pksm = try pksm_mod.PreKeySignalMessage.deserialize(self.allocator, ciphertext);
        defer pksm.deinit();

        var record = if (try self.session_store.loadSession(&self.remote_address)) |r|
            r
        else
            SessionRecord.new(self.allocator);
        defer record.deinit();

        const their_identity_key = identity.IdentityKey.fromPublicKey(pksm.identity_key);

        // Check trust
        const trusted = try self.identity_store.isTrustedIdentity(
            &self.remote_address,
            their_identity_key,
            .receiving,
        );
        if (!trusted) return err.SignalError.UntrustedIdentity;

        // Check for existing session with this base key
        const alice_base_key_serialized = pksm.base_key.serialize();
        if (record.hasCurrentSession()) {
            const state = record.currentState().?;
            if (state.alice_base_key) |abk| {
                if (std.mem.eql(u8, &abk, &alice_base_key_serialized)) {
                    // Existing session, just decrypt
                    const our_identity = try self.identity_store.getIdentityKeyPair();
                    const sender_id = state.remote_identity_key.serialize();
                    const receiver_id = our_identity.identity_key.serialize();
                    return decryptWhisperMessage(
                        self.allocator,
                        state,
                        pksm.message,
                        sender_id,
                        receiver_id,
                    );
                }
            }
        }

        // New session: perform Bob's X3DH/PQXDH
        const our_identity = try self.identity_store.getIdentityKeyPair();
        const our_signed_pre_key = try self.signed_pre_key_store.loadSignedPreKey(pksm.signed_pre_key_id);
        const our_one_time_pre_key = if (pksm.pre_key_id) |pkid| blk: {
            break :blk try self.pre_key_store.loadPreKey(pkid);
        } else null;

        var our_kyber_pre_key: ?kyber_pre_key_record_mod.KyberPreKeyRecord = null;
        if (pksm.kyber_pre_key_id) |kpkid| {
            if (self.kyber_pre_key_store) |kpks| {
                our_kyber_pre_key = try kpks.loadKyberPreKey(kpkid);
            }
        }

        const bob_params = bob_ratchet.BobSignalProtocolParameters{
            .our_identity_key_pair = our_identity,
            .our_signed_pre_key_pair = our_signed_pre_key.key_pair,
            .our_one_time_pre_key_pair = if (our_one_time_pre_key) |opk| opk.key_pair else null,
            .our_ratchet_key_pair = our_signed_pre_key.key_pair,
            .our_kyber_pre_key_pair = if (our_kyber_pre_key) |kpk| kpk.key_pair else null,
            .their_identity_key = their_identity_key,
            .their_base_key = pksm.base_key,
            .their_kyber_ciphertext = pksm.kyber_ciphertext,
        };

        const derived = try bob_ratchet.initialize(self.allocator, bob_params);

        // Build new session state
        var new_state = try SessionState.init(self.allocator);
        var new_state_owned = true; // cleared after ownership transfers to record
        defer if (new_state_owned) new_state.deinit();

        new_state.session_version = 3;
        new_state.local_identity_key = .{ .public_key = our_identity.identity_key.public_key };
        new_state.remote_identity_key = their_identity_key;
        new_state.root_key = derived.root_key;
        new_state.remote_registration_id = pksm.registration_id;
        new_state.local_registration_id = try self.identity_store.getLocalRegistrationId();
        new_state.alice_base_key = alice_base_key_serialized;

        // Bob's receiver chain: keyed to Alice's base key with the X3DH chain key.
        // This matches Alice's initial sender chain (derived.chain_key).
        try new_state.addReceiverChain(pksm.base_key, derived.chain_key);

        // Bob advances the root key with a fresh sender ratchet key pair.
        // DH(Bob's_new_key, Alice's_base) + old_RK → new_RK, Bob's sender chain.
        const bob_sender_kp = try curve.KeyPair.generate();
        const bob_send_ratchet = try derived.root_key.createChain(
            pksm.base_key,
            bob_sender_kp.private_key,
        );
        new_state.root_key = bob_send_ratchet.root_key;
        new_state.sender_chain_key = bob_send_ratchet.chain_key;
        new_state.sender_ratchet_key_pair = bob_sender_kp;

        _ = try self.identity_store.saveIdentity(&self.remote_address, their_identity_key);
        if (pksm.pre_key_id) |pkid| {
            try self.pre_key_store.removePreKey(pkid);
        }
        if (pksm.kyber_pre_key_id) |kpkid| {
            if (self.kyber_pre_key_store) |kpks| {
                try kpks.markKyberPreKeyUsed(kpkid);
            }
        }

        const sender_id = new_state.remote_identity_key.serialize();
        const receiver_id = new_state.local_identity_key.serialize();

        try record.promoteState(new_state);
        new_state_owned = false; // record now owns new_state; don't double-free
        const plaintext = try decryptWhisperMessage(
            self.allocator,
            record.currentState().?,
            pksm.message,
            sender_id,
            receiver_id,
        );

        try self.session_store.storeSession(&self.remote_address, &record);
        return plaintext;
    }
};

fn decryptWhisperMessage(
    allocator: mem.Allocator,
    state: *SessionState,
    data: []const u8,
    sender_id: [curve.SERIALIZED_PUBLIC_KEY_LENGTH]u8,
    receiver_id: [curve.SERIALIZED_PUBLIC_KEY_LENGTH]u8,
) ![]u8 {
    if (data.len < 1 + signal_msg_mod.MAC_LENGTH) return err.SignalError.InvalidMessage;

    const version_byte = data[0];
    const message_version = version_byte >> 4;
    if (message_version < 3) return err.SignalError.LegacyCiphertextVersion;

    const mac_start = data.len - signal_msg_mod.MAC_LENGTH;
    const body_with_version = data[0..mac_start];
    const mac_received = data[mac_start..][0..signal_msg_mod.MAC_LENGTH];
    const body = data[1..mac_start];

    // Parse to get ratchet key and counter
    const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
    var pos: usize = 0;
    var rk_bytes: ?[]const u8 = null;
    var counter: u32 = 0;
    var ciphertext_raw: ?[]const u8 = null;

    while (try @import("proto.zig").nextField(body, &pos)) |field| {
        switch (field.number) {
            1 => {
                if (field.wire_type == .len) rk_bytes = field.data.len;
            },
            2 => {
                if (field.wire_type == .varint) counter = @intCast(field.data.varint);
            },
            4 => {
                if (field.wire_type == .len) ciphertext_raw = field.data.len;
            },
            else => {},
        }
    }

    const ratchet_key = try curve.PublicKey.deserialize(rk_bytes orelse return err.SignalError.InvalidMessage);
    const ciphertext = ciphertext_raw orelse return err.SignalError.InvalidMessage;

    // Get or compute message keys — perform DH ratchet if needed
    const message_keys = try getMessageKeys(allocator, state, ratchet_key, counter);

    // Verify MAC
    var mac_engine = HmacSha256.init(&message_keys.mac_key);
    mac_engine.update(&sender_id);
    mac_engine.update(&receiver_id);
    mac_engine.update(body_with_version);
    var mac_computed: [32]u8 = undefined;
    mac_engine.final(&mac_computed);

    if (!std.mem.eql(u8, mac_received, mac_computed[0..signal_msg_mod.MAC_LENGTH])) {
        return err.SignalError.InvalidMessage;
    }

    // Decrypt
    return aes_cbc.decrypt(allocator, message_keys.cipher_key, message_keys.iv, ciphertext);
}

fn getMessageKeys(
    allocator: mem.Allocator,
    state: *SessionState,
    their_ephemeral: curve.PublicKey,
    counter: u32,
) !@import("ratchet/message_keys.zig").MessageKeys {
    // If we have this chain, get keys from it
    if (try state.getOrComputeMessageKeys(their_ephemeral, counter)) |mk| {
        return mk;
    }

    // Need to perform a DH ratchet step
    const previous_counter = state.sender_chain_key.index;

    // Save current sender chain skipped messages
    // (before advancing, mark position)
    state.previous_counter = previous_counter;

    // Compute new ratchet
    const recv_ratchet = try state.root_key.createChain(
        their_ephemeral,
        state.sender_ratchet_key_pair.private_key,
    );
    state.root_key = recv_ratchet.root_key;

    try state.addReceiverChain(their_ephemeral, recv_ratchet.chain_key);

    // Generate new sender ratchet
    const new_sender_ratchet_kp = try curve.KeyPair.generate();
    const send_ratchet = try state.root_key.createChain(
        their_ephemeral,
        new_sender_ratchet_kp.private_key,
    );
    state.root_key = send_ratchet.root_key;
    state.sender_chain_key = send_ratchet.chain_key;
    state.sender_ratchet_key_pair = new_sender_ratchet_kp;

    _ = allocator;

    // Now get the message keys from the new receiver chain
    const mk = try state.getOrComputeMessageKeys(their_ephemeral, counter);
    return mk orelse err.SignalError.InvalidMessage;
}
