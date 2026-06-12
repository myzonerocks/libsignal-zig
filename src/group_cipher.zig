// GroupCipher: encrypt/decrypt group messages using sender keys.
const std = @import("std");
const address_mod = @import("address.zig");
const curve = @import("curve.zig");
const storage = @import("storage.zig");
const kdf = @import("kdf.zig");
const rnd = @import("random.zig");
const proto = @import("proto.zig");
const skm_mod = @import("messages/sender_key_message.zig");
const group_builder = @import("group_session_builder.zig");
const err = @import("error.zig");
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const aes_cbc = @import("session_builder.zig").aes_cbc;
const mem = std.mem;

pub const GroupCipher = struct {
    sender_key_store: storage.SenderKeyStore,
    sender_key_name: address_mod.SenderKeyName,
    allocator: mem.Allocator,

    pub fn init(
        allocator: mem.Allocator,
        sender_key_store: storage.SenderKeyStore,
        sender_key_name: address_mod.SenderKeyName,
    ) GroupCipher {
        return .{
            .sender_key_store = sender_key_store,
            .sender_key_name = sender_key_name,
            .allocator = allocator,
        };
    }

    pub fn encrypt(self: *GroupCipher, plaintext: []const u8) ![]u8 {
        const record_bytes = try self.sender_key_store.loadSenderKey(&self.sender_key_name) orelse
            return err.SignalError.SessionNotFound;
        defer self.allocator.free(record_bytes);

        var state = try group_builder.SenderKeyStateRecord.deserialize(record_bytes);

        // Derive message keys for current iteration
        const derived = kdf.senderKeyDerive(state.iteration, state.chain_key);

        // Encrypt
        const ciphertext = try aes_cbc.encrypt(
            self.allocator,
            derived.cipher_key,
            derived.iv,
            plaintext,
        );
        defer self.allocator.free(ciphertext);

        // Build SenderKeyMessage and sign it
        var msg = skm_mod.SenderKeyMessage{
            .distribution_uuid = state.distribution_uuid,
            .chain_id = state.chain_id,
            .iteration = state.iteration,
            .ciphertext = ciphertext,
            .allocator = self.allocator,
        };
        const serialized = try msg.serialize(state.signing_key_pair.private_key);
        errdefer self.allocator.free(serialized);

        // Advance chain key
        state.chain_key = kdf.nextSenderChainKey(state.chain_key);
        state.iteration += 1;

        const new_record_bytes = try state.serialize(self.allocator);
        defer self.allocator.free(new_record_bytes);
        try self.sender_key_store.storeSenderKey(&self.sender_key_name, new_record_bytes);

        return serialized;
    }

    pub fn decrypt(self: *GroupCipher, ciphertext: []const u8) ![]u8 {
        const record_bytes = try self.sender_key_store.loadSenderKey(&self.sender_key_name) orelse
            return err.SignalError.SessionNotFound;
        defer self.allocator.free(record_bytes);

        const state = try group_builder.SenderKeyStateRecord.deserialize(record_bytes);

        // Deserialize and verify signature
        const skm = try skm_mod.SenderKeyMessage.deserializeAndVerify(
            self.allocator,
            ciphertext,
            state.signing_key_pair.public_key,
        );
        defer {
            var m = skm;
            m.deinit();
        }

        if (skm.chain_id != state.chain_id) return err.SignalError.InvalidMessage;

        // Advance chain key to the correct iteration
        var current_state = state;
        while (current_state.iteration < skm.iteration) {
            current_state.chain_key = kdf.nextSenderChainKey(current_state.chain_key);
            current_state.iteration += 1;
        }

        if (current_state.iteration != skm.iteration) return err.SignalError.DuplicateMessage;

        // Derive message keys
        const derived = kdf.senderKeyDerive(current_state.iteration, current_state.chain_key);

        // Decrypt
        const plaintext = try aes_cbc.decrypt(
            self.allocator,
            derived.cipher_key,
            derived.iv,
            skm.ciphertext,
        );

        // Advance and save
        current_state.chain_key = kdf.nextSenderChainKey(current_state.chain_key);
        current_state.iteration += 1;

        const new_record_bytes = try current_state.serialize(self.allocator);
        defer self.allocator.free(new_record_bytes);
        try self.sender_key_store.storeSenderKey(&self.sender_key_name, new_record_bytes);

        return plaintext;
    }
};
