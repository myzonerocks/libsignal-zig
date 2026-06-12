// SPQR Authenticator: HKDF+HMAC-based MAC for header and ciphertext chunks.
const std = @import("std");
const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

pub const MAC_SIZE: usize = 32;
pub const Mac = [MAC_SIZE]u8;

pub const Authenticator = struct {
    root_key: [32]u8,
    mac_key: [32]u8,

    // Create from root_key; immediately calls update(ep, root_key).
    pub fn init(root_key: [32]u8, ep: u64) Authenticator {
        var a: Authenticator = .{
            .root_key = [_]u8{0} ** 32,
            .mac_key = [_]u8{0} ** 32,
        };
        a.update(ep, root_key);
        return a;
    }

    // HKDF(salt=[0]*32, ikm=root_key||k, info=LABEL||ep_be64) → [new_root(32), mac_key(32)]
    pub fn update(self: *Authenticator, ep: u64, k: [32]u8) void {
        const LABEL = "Signal_PQCKA_V1_MLKEM768:Authenticator Update";
        var ikm: [64]u8 = undefined;
        @memcpy(ikm[0..32], &self.root_key);
        @memcpy(ikm[32..64], &k);
        var ep_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &ep_bytes, ep, .big);
        var info_buf: [LABEL.len + 8]u8 = undefined;
        @memcpy(info_buf[0..LABEL.len], LABEL);
        @memcpy(info_buf[LABEL.len..], &ep_bytes);
        const salt = [_]u8{0} ** 32;
        const prk = HkdfSha256.extract(&salt, &ikm);
        var out: [64]u8 = undefined;
        HkdfSha256.expand(&out, &info_buf, prk);
        @memcpy(&self.root_key, out[0..32]);
        @memcpy(&self.mac_key, out[32..64]);
    }

    // HMAC-SHA256(mac_key, LABEL_HDR||ep_be64||hdr)[0..32]
    pub fn macHdr(self: *const Authenticator, ep: u64, hdr: *const [64]u8) Mac {
        const LABEL = "Signal_PQCKA_V1_MLKEM768:ekheader";
        var ep_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &ep_bytes, ep, .big);
        var mac: [32]u8 = undefined;
        var h = HmacSha256.init(&self.mac_key);
        h.update(LABEL);
        h.update(&ep_bytes);
        h.update(hdr);
        h.final(&mac);
        return mac;
    }

    // HMAC-SHA256(mac_key, LABEL_CT||ep_be64||ct)[0..32]
    pub fn macCt(self: *const Authenticator, ep: u64, ct: []const u8) Mac {
        const LABEL = "Signal_PQCKA_V1_MLKEM768:ciphertext";
        var ep_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &ep_bytes, ep, .big);
        var mac: [32]u8 = undefined;
        var h = HmacSha256.init(&self.mac_key);
        h.update(LABEL);
        h.update(&ep_bytes);
        h.update(ct);
        h.final(&mac);
        return mac;
    }

    pub fn verifyHdr(self: *const Authenticator, ep: u64, hdr: *const [64]u8, mac: *const Mac) !void {
        const expected = self.macHdr(ep, hdr);
        if (!std.mem.eql(u8, &expected, mac)) return error.InvalidMac;
    }

    pub fn verifyCt(self: *const Authenticator, ep: u64, ct: []const u8, mac: *const Mac) !void {
        const expected = self.macCt(ep, ct);
        if (!std.mem.eql(u8, &expected, mac)) return error.InvalidMac;
    }
};
