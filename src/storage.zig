// Store interfaces for the Signal Protocol.
// In Zig, we use comptime interfaces (vtable-like structs with function pointers).
const std = @import("std");
const address = @import("address.zig");
const identity = @import("identity.zig");
const curve = @import("curve.zig");
const SessionRecord = @import("state/session_record.zig").SessionRecord;
const PreKeyRecord = @import("state/pre_key_record.zig").PreKeyRecord;
const SignedPreKeyRecord = @import("state/signed_pre_key_record.zig").SignedPreKeyRecord;
const KyberPreKeyRecord = @import("state/kyber_pre_key_record.zig").KyberPreKeyRecord;
const mem = std.mem;

// Direction for trust evaluation
pub const Direction = enum { sending, receiving };

// Identity Key Store
pub const IdentityKeyStore = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        getIdentityKeyPair: *const fn (ptr: *anyopaque) anyerror!identity.IdentityKeyPair,
        getLocalRegistrationId: *const fn (ptr: *anyopaque) anyerror!u32,
        saveIdentity: *const fn (ptr: *anyopaque, address: *const address.ProtocolAddress, key: identity.IdentityKey) anyerror!bool,
        isTrustedIdentity: *const fn (ptr: *anyopaque, address: *const address.ProtocolAddress, key: identity.IdentityKey, dir: Direction) anyerror!bool,
        getIdentity: *const fn (ptr: *anyopaque, address: *const address.ProtocolAddress) anyerror!?identity.IdentityKey,
    };

    pub fn getIdentityKeyPair(self: IdentityKeyStore) !identity.IdentityKeyPair {
        return self.vtable.getIdentityKeyPair(self.ptr);
    }

    pub fn getLocalRegistrationId(self: IdentityKeyStore) !u32 {
        return self.vtable.getLocalRegistrationId(self.ptr);
    }

    pub fn saveIdentity(self: IdentityKeyStore, addr: *const address.ProtocolAddress, key: identity.IdentityKey) !bool {
        return self.vtable.saveIdentity(self.ptr, addr, key);
    }

    pub fn isTrustedIdentity(self: IdentityKeyStore, addr: *const address.ProtocolAddress, key: identity.IdentityKey, dir: Direction) !bool {
        return self.vtable.isTrustedIdentity(self.ptr, addr, key, dir);
    }

    pub fn getIdentity(self: IdentityKeyStore, addr: *const address.ProtocolAddress) !?identity.IdentityKey {
        return self.vtable.getIdentity(self.ptr, addr);
    }
};

// Session Store
pub const SessionStore = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        loadSession: *const fn (ptr: *anyopaque, addr: *const address.ProtocolAddress) anyerror!?SessionRecord,
        storeSession: *const fn (ptr: *anyopaque, addr: *const address.ProtocolAddress, record: *const SessionRecord) anyerror!void,
    };

    pub fn loadSession(self: SessionStore, addr: *const address.ProtocolAddress) !?SessionRecord {
        return self.vtable.loadSession(self.ptr, addr);
    }

    pub fn storeSession(self: SessionStore, addr: *const address.ProtocolAddress, record: *const SessionRecord) !void {
        return self.vtable.storeSession(self.ptr, addr, record);
    }
};

// Pre-Key Store
pub const PreKeyStore = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        loadPreKey: *const fn (ptr: *anyopaque, id: u32) anyerror!PreKeyRecord,
        storePreKey: *const fn (ptr: *anyopaque, id: u32, record: *const PreKeyRecord) anyerror!void,
        removePreKey: *const fn (ptr: *anyopaque, id: u32) anyerror!void,
    };

    pub fn loadPreKey(self: PreKeyStore, id: u32) !PreKeyRecord {
        return self.vtable.loadPreKey(self.ptr, id);
    }

    pub fn storePreKey(self: PreKeyStore, id: u32, record: *const PreKeyRecord) !void {
        return self.vtable.storePreKey(self.ptr, id, record);
    }

    pub fn removePreKey(self: PreKeyStore, id: u32) !void {
        return self.vtable.removePreKey(self.ptr, id);
    }
};

// Signed Pre-Key Store
pub const SignedPreKeyStore = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        loadSignedPreKey: *const fn (ptr: *anyopaque, id: u32) anyerror!SignedPreKeyRecord,
        storeSignedPreKey: *const fn (ptr: *anyopaque, id: u32, record: *const SignedPreKeyRecord) anyerror!void,
    };

    pub fn loadSignedPreKey(self: SignedPreKeyStore, id: u32) !SignedPreKeyRecord {
        return self.vtable.loadSignedPreKey(self.ptr, id);
    }

    pub fn storeSignedPreKey(self: SignedPreKeyStore, id: u32, record: *const SignedPreKeyRecord) !void {
        return self.vtable.storeSignedPreKey(self.ptr, id, record);
    }
};

// Kyber Pre-Key Store
pub const KyberPreKeyStore = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        loadKyberPreKey: *const fn (ptr: *anyopaque, id: u32) anyerror!KyberPreKeyRecord,
        storeKyberPreKey: *const fn (ptr: *anyopaque, id: u32, record: *const KyberPreKeyRecord) anyerror!void,
        markKyberPreKeyUsed: *const fn (ptr: *anyopaque, id: u32) anyerror!void,
    };

    pub fn loadKyberPreKey(self: KyberPreKeyStore, id: u32) !KyberPreKeyRecord {
        return self.vtable.loadKyberPreKey(self.ptr, id);
    }

    pub fn storeKyberPreKey(self: KyberPreKeyStore, id: u32, record: *const KyberPreKeyRecord) !void {
        return self.vtable.storeKyberPreKey(self.ptr, id, record);
    }

    pub fn markKyberPreKeyUsed(self: KyberPreKeyStore, id: u32) !void {
        return self.vtable.markKyberPreKeyUsed(self.ptr, id);
    }
};

// Sender Key Store
pub const SenderKeyStore = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        storeSenderKey: *const fn (ptr: *anyopaque, sender_key_name: *const address.SenderKeyName, record: []const u8) anyerror!void,
        loadSenderKey: *const fn (ptr: *anyopaque, sender_key_name: *const address.SenderKeyName) anyerror!?[]u8,
    };

    pub fn storeSenderKey(self: SenderKeyStore, name: *const address.SenderKeyName, record: []const u8) !void {
        return self.vtable.storeSenderKey(self.ptr, name, record);
    }

    pub fn loadSenderKey(self: SenderKeyStore, name: *const address.SenderKeyName) !?[]u8 {
        return self.vtable.loadSenderKey(self.ptr, name);
    }
};
