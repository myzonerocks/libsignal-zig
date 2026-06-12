pub const err = @import("error.zig");
pub const random = @import("random.zig");
pub const kdf = @import("kdf.zig");
pub const proto = @import("proto.zig");
pub const address = @import("address.zig");
pub const xeddsa = @import("xeddsa.zig");
pub const curve = @import("curve.zig");
pub const identity = @import("identity.zig");
pub const storage = @import("storage.zig");
pub const aes = @import("aes.zig");
pub const fingerprint = @import("fingerprint.zig");
pub const username = @import("username.zig");

// State records
pub const pre_key_record = @import("state/pre_key_record.zig");
pub const signed_pre_key_record = @import("state/signed_pre_key_record.zig");
pub const kyber_pre_key_record = @import("state/kyber_pre_key_record.zig");
pub const bundle = @import("state/bundle.zig");
pub const session_state = @import("state/session_state.zig");
pub const session_record = @import("state/session_record.zig");

// Messages
pub const signal_message = @import("messages/signal_message.zig");
pub const pre_key_signal_message = @import("messages/pre_key_signal_message.zig");
pub const sender_key_message = @import("messages/sender_key_message.zig");
pub const sender_key_distribution_message = @import("messages/sender_key_distribution_message.zig");
pub const plaintext_content = @import("messages/plaintext_content.zig");

// Ratchet internals
pub const message_keys = @import("ratchet/message_keys.zig");
pub const chain_key = @import("ratchet/chain_key.zig");
pub const root_key = @import("ratchet/root_key.zig");
pub const alice_ratchet = @import("ratchet/alice.zig");
pub const bob_ratchet = @import("ratchet/bob.zig");

// Session management
pub const session_builder = @import("session_builder.zig");
pub const session_cipher = @import("session_cipher.zig");

// Group messaging
pub const group_session_builder = @import("group_session_builder.zig");
pub const group_cipher = @import("group_cipher.zig");

// Sealed sender
pub const sealed_sender = @import("sealed_sender.zig");

// Convenience re-exports
pub const SignalError = err.SignalError;
pub const ProtocolAddress = address.ProtocolAddress;
pub const SenderKeyName = address.SenderKeyName;
pub const PublicKey = curve.PublicKey;
pub const PrivateKey = curve.PrivateKey;
pub const KeyPair = curve.KeyPair;
pub const KyberKeyPair = curve.KyberKeyPair;
pub const IdentityKey = identity.IdentityKey;
pub const IdentityKeyPair = identity.IdentityKeyPair;
pub const PreKeyRecord = pre_key_record.PreKeyRecord;
pub const SignedPreKeyRecord = signed_pre_key_record.SignedPreKeyRecord;
pub const KyberPreKeyRecord = kyber_pre_key_record.KyberPreKeyRecord;
pub const PreKeyBundle = bundle.PreKeyBundle;
pub const SessionRecord = session_record.SessionRecord;
pub const SessionBuilder = session_builder.SessionBuilder;
pub const SessionCipher = session_cipher.SessionCipher;
pub const GroupSessionBuilder = group_session_builder.GroupSessionBuilder;
pub const GroupCipher = group_cipher.GroupCipher;
pub const SignalMessage = signal_message.SignalMessage;
pub const PreKeySignalMessage = pre_key_signal_message.PreKeySignalMessage;
pub const SenderKeyMessage = sender_key_message.SenderKeyMessage;
pub const SenderKeyDistributionMessage = sender_key_distribution_message.SenderKeyDistributionMessage;
pub const UsernameHash = username.UsernameHash;
pub const ScannableFingerprint = fingerprint.ScannableFingerprint;
