// GroupCipher: encrypt/decrypt group messages using sender keys.
const std = @import("std");
const address_mod = @import("address.zig");
const curve = @import("curve.zig");
const storage = @import("storage.zig");
const kdf = @import("kdf.zig");
const proto = @import("proto.zig");
const skm_mod = @import("messages/sender_key_message.zig");
const group_builder = @import("group_session_builder.zig");
const err = @import("error.zig");
const aes_cbc = @import("session_builder.zig").aes_cbc;
const mem = std.mem;

pub const GroupCipher = struct {
    sender_key_store: storage.SenderKeyStore,
    sender: address_mod.ProtocolAddress,
    distribution_id: [16]u8,
    allocator: mem.Allocator,

    pub fn init(
        allocator: mem.Allocator,
        sender_key_store: storage.SenderKeyStore,
        sender: address_mod.ProtocolAddress,
        distribution_id: [16]u8,
    ) GroupCipher {
        return .{
            .sender_key_store = sender_key_store,
            .sender = sender,
            .distribution_id = distribution_id,
            .allocator = allocator,
        };
    }

    pub fn encrypt(self: *GroupCipher, plaintext: []const u8) ![]u8 {
        const record_bytes = try self.sender_key_store.loadSenderKey(&self.sender, self.distribution_id) orelse
            return err.SignalError.SessionNotFound;
        defer self.allocator.free(record_bytes);

        var state = try group_builder.SenderKeyStateRecord.deserialize(record_bytes);

        const derived = kdf.senderKeyDerive(state.iteration, state.chain_key);

        const ciphertext = try aes_cbc.encrypt(
            self.allocator,
            derived.cipher_key,
            derived.iv,
            plaintext,
        );
        defer self.allocator.free(ciphertext);

        var msg = skm_mod.SenderKeyMessage{
            .distribution_uuid = state.distribution_uuid,
            .chain_id = state.chain_id,
            .iteration = state.iteration,
            .ciphertext = ciphertext,
            .allocator = self.allocator,
        };
        const serialized = try msg.serialize(state.signing_key_pair.private_key);
        errdefer self.allocator.free(serialized);

        state.chain_key = kdf.nextSenderChainKey(state.chain_key);
        state.iteration += 1;

        const new_record_bytes = try state.serialize(self.allocator);
        defer self.allocator.free(new_record_bytes);
        try self.sender_key_store.storeSenderKey(&self.sender, self.distribution_id, new_record_bytes);

        return serialized;
    }

    pub fn decrypt(self: *GroupCipher, ciphertext: []const u8) ![]u8 {
        const record_bytes = try self.sender_key_store.loadSenderKey(&self.sender, self.distribution_id) orelse
            return err.SignalError.SessionNotFound;
        defer self.allocator.free(record_bytes);

        const state = try group_builder.SenderKeyStateRecord.deserialize(record_bytes);

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

        var current_state = state;
        while (current_state.iteration < skm.iteration) {
            current_state.chain_key = kdf.nextSenderChainKey(current_state.chain_key);
            current_state.iteration += 1;
        }

        if (current_state.iteration != skm.iteration) return err.SignalError.DuplicateMessage;

        const derived = kdf.senderKeyDerive(current_state.iteration, current_state.chain_key);

        const plaintext = try aes_cbc.decrypt(
            self.allocator,
            derived.cipher_key,
            derived.iv,
            skm.ciphertext,
        );

        current_state.chain_key = kdf.nextSenderChainKey(current_state.chain_key);
        current_state.iteration += 1;

        const new_record_bytes = try current_state.serialize(self.allocator);
        defer self.allocator.free(new_record_bytes);
        try self.sender_key_store.storeSenderKey(&self.sender, self.distribution_id, new_record_bytes);

        return plaintext;
    }
};
