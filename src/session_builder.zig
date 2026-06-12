// SessionBuilder: establishes Signal Protocol sessions from PreKeyBundles.
const std = @import("std");
const address_mod = @import("address.zig");
const identity = @import("identity.zig");
const curve = @import("curve.zig");
const storage = @import("storage.zig");
const bundle_mod = @import("state/bundle.zig");
const SessionRecord = @import("state/session_record.zig").SessionRecord;
const SessionState = @import("state/session_state.zig").SessionState;
const alice_ratchet = @import("ratchet/alice.zig");
const bob_ratchet = @import("ratchet/bob.zig");
const spqr = @import("spqr.zig");
const rnd = @import("random.zig");
const err = @import("error.zig");
const mem = std.mem;

pub const SessionBuilder = struct {
    remote_address: address_mod.ProtocolAddress,
    identity_store: storage.IdentityKeyStore,
    session_store: storage.SessionStore,
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
    ) SessionBuilder {
        return .{
            .remote_address = remote_address,
            .identity_store = identity_store,
            .session_store = session_store,
            .pre_key_store = pre_key_store,
            .signed_pre_key_store = signed_pre_key_store,
            .kyber_pre_key_store = kyber_pre_key_store,
            .allocator = allocator,
        };
    }

    /// Process a PreKeyBundle to establish a session with the remote party.
    pub fn processPreKeyBundle(self: *SessionBuilder, bundle: bundle_mod.PreKeyBundle) !void {
        const their_identity_key = bundle.identity_key;

        // Check identity trust
        const trusted = try self.identity_store.isTrustedIdentity(
            &self.remote_address,
            their_identity_key,
            .sending,
        );
        if (!trusted) return err.SignalError.UntrustedIdentity;

        // Validate the bundle's signatures
        try bundle.validate();

        // Generate our ephemeral base key
        const our_base_key = try curve.KeyPair.generate();
        const our_identity_key_pair = try self.identity_store.getIdentityKeyPair();

        // Check if Kyber pre-key is present (PQXDH)
        var kyber_pre_key_kp: ?curve.KyberKeyPair = null;
        if (bundle.kyber_pre_key_public) |kpk_bytes| {
            kyber_pre_key_kp = .{
                .public_key_bytes = kpk_bytes,
                .secret_key_bytes = undefined, // not needed for encapsulation
            };
        }

        const params = alice_ratchet.AliceSignalProtocolParameters{
            .our_identity_key_pair = our_identity_key_pair,
            .our_base_key_pair = our_base_key,
            .their_identity_key = their_identity_key,
            .their_signed_pre_key = bundle.signed_pre_key_public,
            .their_one_time_pre_key = bundle.pre_key_public,
            .their_ratchet_key = bundle.signed_pre_key_public,
            .their_kyber_pre_key = kyber_pre_key_kp,
        };

        const derived = try alice_ratchet.initialize(self.allocator, params);
        defer if (derived.kyber_ciphertext) |kc| self.allocator.free(kc);

        // Build the initial session state
        var session_state = try SessionState.init(self.allocator);
        errdefer session_state.deinit();

        session_state.session_version = if (derived.pqr_key != null) 4 else 3;
        session_state.remote_identity_key = their_identity_key;
        session_state.local_identity_key = .{ .public_key = our_identity_key_pair.identity_key.public_key };
        session_state.remote_registration_id = bundle.registration_id;
        session_state.local_registration_id = try self.identity_store.getLocalRegistrationId();

        // Session init:
        // 1. Generate a fresh sender ratchet key (distinct from our_base_key).
        // 2. Perform a DH ratchet step to derive the initial sender chain.
        // 3. Add a receiver chain keyed to their_ratchet_key with the X3DH chain_key.
        const sending_ratchet_key = try curve.KeyPair.generate();
        const send_ratchet = try derived.root_key.createChain(
            bundle.signed_pre_key_public, // their_ratchet_key
            sending_ratchet_key.private_key,
        );
        session_state.root_key = send_ratchet.root_key;
        session_state.sender_chain_key = send_ratchet.chain_key;
        session_state.sender_ratchet_key_pair = sending_ratchet_key;

        // Receiver chain for Bob's initial sender (Bob's SPK = their_ratchet_key).
        try session_state.addReceiverChain(bundle.signed_pre_key_public, derived.chain_key);

        // SPQR: Alice (A2B) generates ML-KEM keys and sends header+EK.
        if (derived.pqr_key) |pqrk| {
            const pqr_state = try spqr.initialState(self.allocator, pqrk, .a2b);
            if (session_state.pq_ratchet_state.len > 0) self.allocator.free(session_state.pq_ratchet_state);
            session_state.pq_ratchet_state = pqr_state;
        }

        // Store pending pre-key info (carried in the first PreKeySignalMessage).
        const alice_base_key_serialized = our_base_key.public_key.serialize();
        session_state.alice_base_key = alice_base_key_serialized;
        session_state.pending_pre_key = .{
            .pre_key_id = bundle.pre_key_id,
            .signed_pre_key_id = bundle.signed_pre_key_id,
            .base_key = our_base_key.public_key,
            .timestamp = 0,
        };

        if (derived.kyber_ciphertext) |kc| {
            const kc_copy = try self.allocator.dupe(u8, kc);
            session_state.pending_kyber_pre_key = .{
                .pre_key_id = bundle.kyber_pre_key_id.?,
                .ciphertext = kc_copy,
            };
        }

        // Save identity key
        _ = try self.identity_store.saveIdentity(&self.remote_address, their_identity_key);

        // Load or create session record
        var record = if (try self.session_store.loadSession(&self.remote_address)) |r|
            r
        else
            SessionRecord.new(self.allocator);
        defer record.deinit();

        try record.promoteState(session_state);
        try self.session_store.storeSession(&self.remote_address, &record);
    }
};

// AES-256-CBC utilities
pub const aes_cbc = struct {
    const Aes256 = std.crypto.core.aes.Aes256;

    pub fn encrypt(allocator: mem.Allocator, key: [32]u8, iv: [16]u8, plaintext: []const u8) ![]u8 {
        // PKCS7 pad
        const pad_len: u8 = @intCast(16 - (plaintext.len % 16));
        const padded_len = plaintext.len + pad_len;
        const padded = try allocator.alloc(u8, padded_len);
        defer allocator.free(padded);
        @memcpy(padded[0..plaintext.len], plaintext);
        @memset(padded[plaintext.len..], pad_len);

        const out = try allocator.alloc(u8, padded_len);
        const enc = Aes256.initEnc(key);
        var prev: [16]u8 = iv;
        var i: usize = 0;
        while (i < padded_len) : (i += 16) {
            var block: [16]u8 = padded[i..][0..16].*;
            for (0..16) |j| block[j] ^= prev[j];
            enc.encrypt(&prev, &block);
            @memcpy(out[i..][0..16], &prev);
        }
        return out;
    }

    pub fn decrypt(allocator: mem.Allocator, key: [32]u8, iv: [16]u8, ciphertext: []const u8) ![]u8 {
        if (ciphertext.len == 0 or ciphertext.len % 16 != 0) return err.SignalError.InvalidMessage;
        const out = try allocator.alloc(u8, ciphertext.len);
        const dec = Aes256.initDec(key);
        var prev: [16]u8 = iv;
        var i: usize = 0;
        while (i < ciphertext.len) : (i += 16) {
            const ct_block: [16]u8 = ciphertext[i..][0..16].*;
            var pt_block: [16]u8 = undefined;
            dec.decrypt(&pt_block, &ct_block);
            for (0..16) |j| pt_block[j] ^= prev[j];
            @memcpy(out[i..][0..16], &pt_block);
            prev = ct_block;
        }
        // Remove PKCS7 padding
        const pad_byte = out[out.len - 1];
        if (pad_byte == 0 or pad_byte > 16) {
            allocator.free(out);
            return err.SignalError.PaddingError;
        }
        for (out[out.len - pad_byte ..]) |b| {
            if (b != pad_byte) {
                allocator.free(out);
                return err.SignalError.PaddingError;
            }
        }
        const result = try allocator.dupe(u8, out[0 .. out.len - pad_byte]);
        allocator.free(out);
        return result;
    }
};
