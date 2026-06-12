// Incremental ML-KEM-768 for SPQR: split encapsulation across two rounds.
// encaps1(header) → ct1 + EncapsState  (only needs rho from header)
// encaps2(ek, es) → ct2               (needs NTT(t) from EK)
// Standard generate() and decaps() delegate to std.crypto.ml_kem.nist.MLKem768.
//
// Polynomial arithmetic copied/adapted from std/crypto/ml_kem.zig (private internals).
const std = @import("std");
const builtin = @import("builtin");
const sha3 = std.crypto.hash.sha3;
const math = std.math;
const rnd = @import("../random.zig");

// ML-KEM-768 parameters
const K: u8 = 3;
const ETA1: u8 = 2;
const ETA2: u8 = 2;
const DU: u8 = 10;
const DV: u8 = 4;
const N: usize = 256;
const Q: i16 = 3329;
const R: i32 = 1 << 16;

pub const HEADER_SIZE: usize = 64; // rho(32) || H(pk)(32)
pub const EK_SIZE: usize = 1152; // NTT(t) = 3 polys * 384 bytes
pub const CT1_SIZE: usize = 960; // compress(u, 10) = 3 * 320
pub const CT2_SIZE: usize = 128; // compress(v, 4) = 128
pub const DK_SIZE: usize = 2400; // full secret key
// ES = r_hat (normalized, 3*384) || e2 (normalized, 384) || m (32)
pub const ES_SIZE: usize = 3 * 384 + 384 + 32; // 1568

pub const Keys = struct {
    hdr: [HEADER_SIZE]u8,
    ek: [EK_SIZE]u8,
    dk: [DK_SIZE]u8,
};

pub fn generate() Keys {
    const MLK = std.crypto.kem.ml_kem.MLKem768;
    var seed: [MLK.seed_length]u8 = undefined;
    rnd.bytes(&seed);
    const kp = while (true) {
        if (MLK.KeyPair.generateDeterministic(seed)) |kp| break kp else |_| rnd.bytes(&seed);
    };
    const pk_bytes = kp.public_key.toBytes(); // th(1152) || rho(32) = 1184 bytes
    var hdr: [HEADER_SIZE]u8 = undefined;
    @memcpy(hdr[0..32], pk_bytes[EK_SIZE..]); // rho
    @memcpy(hdr[32..64], &kp.public_key.hpk); // H(pk)
    return .{
        .hdr = hdr,
        .ek = pk_bytes[0..EK_SIZE].*,
        .dk = kp.secret_key.toBytes(),
    };
}

pub fn encaps1(hdr: *const [HEADER_SIZE]u8, m_seed: *const [32]u8) struct {
    ct1: [CT1_SIZE]u8,
    es: [ES_SIZE]u8,
    ss: [32]u8,
} {
    const rho = hdr[0..32];
    const hpk = hdr[32..64];

    // (K', r) = SHA3-512(m || H(pk))
    var kr: [64]u8 = undefined;
    var g = sha3.Sha3_512.init(.{});
    g.update(m_seed);
    g.update(hpk);
    g.final(&kr);
    const ss = kr[0..32].*;
    const r_seed = kr[32..64];

    // Sample r_hat, e1, e2
    const V = PolyVec(K);
    const rh = V.noiseVec(ETA1, 0, r_seed).ntt().barrettReduce();
    const e1 = V.noiseVec(ETA2, K, r_seed);
    const e2 = polyNoise(ETA2, 2 * K, r_seed);

    // A^T from rho
    const aT = matUniform(rho.*, true);

    // u = A^T * r_hat + e1
    var u: V = undefined;
    for (0..K) |i| {
        u.ps[i] = aT.rows[i].dotHat(rh);
    }
    u = u.barrettReduce().invNTT().add(e1).normalize();

    // CT1 = compress(u, 10)
    const ct1 = u.compress(DU);

    // ES = normalize(r_hat) bytes || normalize(e2) bytes || m
    var es: [ES_SIZE]u8 = undefined;
    const rh_n = rh.normalize();
    const rh_b = rh_n.toBytes();
    @memcpy(es[0 .. 3 * 384], &rh_b);
    const e2_b = e2.normalize().toBytes();
    @memcpy(es[3 * 384 .. 3 * 384 + 384], &e2_b);
    @memcpy(es[3 * 384 + 384 ..], m_seed);

    return .{ .ct1 = ct1, .es = es, .ss = ss };
}

pub fn encaps2(ek: *const [EK_SIZE]u8, es: *const [ES_SIZE]u8) [CT2_SIZE]u8 {
    const V = PolyVec(K);

    // Parse th from EK
    var th: V = undefined;
    inline for (0..K) |i| {
        th.ps[i] = polyFromBytes(ek[i * 384 ..][0..384]).normalize();
    }

    // Deserialize ES
    const rh = V.fromBytes(es[0 .. 3 * 384]).normalize();
    const e2 = polyFromBytes(es[3 * 384 ..][0..384]).normalize();
    const m = es[3 * 384 + 384 ..][0..32];

    // v = t^T * r_hat + e2 + Decompress(m, 1)
    const v = th.dotHat(rh).barrettReduce().invNTT()
        .add(polyDecompress(1, m[0..32]))
        .add(e2)
        .normalize();

    return v.compress(DV);
}

pub fn decaps(dk: *const [DK_SIZE]u8, ct1: *const [CT1_SIZE]u8, ct2: *const [CT2_SIZE]u8) ![32]u8 {
    const MLK = std.crypto.kem.ml_kem.MLKem768;
    var ct: [CT1_SIZE + CT2_SIZE]u8 = undefined;
    @memcpy(ct[0..CT1_SIZE], ct1);
    @memcpy(ct[CT1_SIZE..], ct2);
    const sk = try MLK.SecretKey.fromBytes(dk);
    return sk.decaps(&ct);
}

pub fn ekMatchesHeader(ek: *const [EK_SIZE]u8, hdr: *const [HEADER_SIZE]u8) bool {
    // full_pk = NTT(t)(1152) || rho(32) = 1184 bytes
    var full_pk: [1184]u8 = undefined;
    @memcpy(full_pk[0..EK_SIZE], ek);
    @memcpy(full_pk[EK_SIZE..], hdr[0..32]);
    var h: [32]u8 = undefined;
    sha3.Sha3_256.hash(&full_pk, &h, .{});
    return std.mem.eql(u8, &h, hdr[32..64]);
}

// ---- Polynomial internals (adapted from std/crypto/ml_kem.zig) ----

const r_mod_q: i32 = @rem(@as(i32, R), Q);
const r2_mod_q: i32 = @rem(r_mod_q * r_mod_q, Q);
const r2_over_128: i32 = @mod(invertMod(@as(i32, 128), @as(i32, Q)) * r2_mod_q, Q);
const zetas = computeZetas();

const inv_ntt_reductions = [_]i16{
    -1,
    -1,
    16,
    17,
    48,
    49,
    80,
    81,
    112,
    113,
    144,
    145,
    176,
    177,
    208,
    209,
    240,
    241,
    -1,
    0,
    1,
    32,
    33,
    34,
    35,
    64,
    65,
    96,
    97,
    98,
    99,
    128,
    129,
    160,
    161,
    162,
    163,
    192,
    193,
    224,
    225,
    226,
    227,
    -1,
    2,
    3,
    66,
    67,
    68,
    69,
    70,
    71,
    130,
    131,
    194,
    195,
    196,
    197,
    198,
    199,
    -1,
    4,
    5,
    6,
    7,
    132,
    133,
    134,
    135,
    136,
    137,
    138,
    139,
    140,
    141,
    142,
    143,
    -1,
    -1,
};

fn invertMod(a: i32, p: i32) i32 {
    const r = extendedEuclidean(a, p);
    std.debug.assert(r.gcd == 1);
    return r.x;
}

fn extendedEuclidean(a_in: i32, b_in: i32) struct { gcd: i32, x: i32, y: i32 } {
    var old_r: i32 = a_in;
    var r: i32 = b_in;
    var old_s: i32 = 1;
    var s: i32 = 0;
    while (r != 0) {
        const q = @divTrunc(old_r, r);
        const tmp_r = r;
        r = old_r - q * r;
        old_r = tmp_r;
        const tmp_s = s;
        s = old_s - q * s;
        old_s = tmp_s;
    }
    return .{ .gcd = old_r, .x = old_s, .y = if (b_in != 0) @divTrunc(old_r - old_s * a_in, b_in) else 0 };
}

fn computeZetas() [128]i16 {
    @setEvalBranchQuota(10000);
    var ret: [128]i16 = undefined;
    const zeta_val: i16 = 17;
    for (&ret, 0..) |*r_val, i| {
        const exp = @bitReverse(@as(u7, @intCast(i)));
        var base: i32 = zeta_val;
        var result: i32 = 1;
        var e: u7 = exp;
        while (e > 0) : (e >>= 1) {
            if (e & 1 != 0) result = @rem(result * base, Q);
            base = @rem(base * base, Q);
        }
        const t: i16 = @intCast(result);
        r_val.* = csubq(feBarrettReduce(feToMont(t)));
    }
    return ret;
}

fn montReduce(x: i32) i16 {
    // Q^{-1} mod 2^16: Newton's method, doubles precision each iteration.
    // 3329 * q_inv ≡ 1 (mod 65536)
    const q_inv: i32 = comptime blk: {
        var inv: u32 = 1;
        const q_u: u32 = @intCast(Q);
        var j: usize = 0;
        while (j < 16) : (j += 1) {
            inv = inv *% (2 -% q_u *% inv);
        }
        break :blk @intCast(inv & 0xFFFF);
    };
    const m: i16 = @truncate(@as(i32, @truncate(x *% q_inv)));
    const yR = x - @as(i32, m) * @as(i32, Q);
    return @bitCast(@as(u16, @truncate(@as(u32, @bitCast(yR)) >> 16)));
}

fn feToMont(x: i16) i16 {
    return montReduce(@as(i32, x) * r2_mod_q);
}

fn feBarrettReduce(x: i16) i16 {
    return x -% @as(i16, @intCast((@as(i32, x) * 20159) >> 26)) *% Q;
}

fn csubq(x: i16) i16 {
    var r = x;
    r -= Q;
    r += (r >> 15) & Q;
    return r;
}

const Poly = struct {
    cs: [N]i16,

    const encoded_length = N / 2 * 3; // 384 bytes, 12-bit packing
    const zero: Poly = .{ .cs = .{0} ** N };

    fn add(a: Poly, b: Poly) Poly {
        var ret: Poly = undefined;
        for (0..N) |i| ret.cs[i] = a.cs[i] + b.cs[i];
        return ret;
    }

    fn sub(a: Poly, b: Poly) Poly {
        var ret: Poly = undefined;
        for (0..N) |i| ret.cs[i] = a.cs[i] - b.cs[i];
        return ret;
    }

    fn ntt(a: Poly) Poly {
        var p = a;
        var k: usize = 0;
        var l = N >> 1;
        while (l > 1) : (l >>= 1) {
            var offset: usize = 0;
            while (offset < N - l) : (offset += 2 * l) {
                k += 1;
                const z = @as(i32, zetas[k]);
                for (offset..offset + l) |j| {
                    const t = montReduce(z * @as(i32, p.cs[j + l]));
                    p.cs[j + l] = p.cs[j] - t;
                    p.cs[j] += t;
                }
            }
        }
        return p;
    }

    fn invNTT(a: Poly) Poly {
        var k: usize = 127;
        var ri: usize = 0;
        var p = a;
        var l: usize = 2;
        while (l < N) : (l <<= 1) {
            var offset: usize = 0;
            while (offset < N - l) : (offset += 2 * l) {
                const minZeta = @as(i32, zetas[k]);
                k -= 1;
                for (offset..offset + l) |j| {
                    const t = p.cs[j + l] - p.cs[j];
                    p.cs[j] += p.cs[j + l];
                    p.cs[j + l] = montReduce(minZeta * @as(i32, t));
                }
            }
            while (true) {
                const idx = inv_ntt_reductions[ri];
                ri += 1;
                if (idx < 0) break;
                p.cs[@intCast(idx)] = feBarrettReduce(p.cs[@intCast(idx)]);
            }
        }
        for (0..N) |j| {
            p.cs[j] = montReduce(r2_over_128 * @as(i32, p.cs[j]));
        }
        return p;
    }

    fn normalize(a: Poly) Poly {
        var ret: Poly = undefined;
        for (0..N) |i| ret.cs[i] = csubq(feBarrettReduce(a.cs[i]));
        return ret;
    }

    fn barrettReduce(a: Poly) Poly {
        var ret: Poly = undefined;
        for (0..N) |i| ret.cs[i] = feBarrettReduce(a.cs[i]);
        return ret;
    }

    fn mulHat(a: Poly, b: Poly) Poly {
        var p: Poly = undefined;
        var k: usize = 64;
        var i: usize = 0;
        while (i < N) : (i += 4) {
            const z = @as(i32, zetas[k]);
            k += 1;
            const a1b1 = montReduce(@as(i32, a.cs[i + 1]) * @as(i32, b.cs[i + 1]));
            const a0b0 = montReduce(@as(i32, a.cs[i]) * @as(i32, b.cs[i]));
            const a1b0 = montReduce(@as(i32, a.cs[i + 1]) * @as(i32, b.cs[i]));
            const a0b1 = montReduce(@as(i32, a.cs[i]) * @as(i32, b.cs[i + 1]));
            p.cs[i] = montReduce(a1b1 * z) + a0b0;
            p.cs[i + 1] = a0b1 + a1b0;
            const a3b3 = montReduce(@as(i32, a.cs[i + 3]) * @as(i32, b.cs[i + 3]));
            const a2b2 = montReduce(@as(i32, a.cs[i + 2]) * @as(i32, b.cs[i + 2]));
            const a3b2 = montReduce(@as(i32, a.cs[i + 3]) * @as(i32, b.cs[i + 2]));
            const a2b3 = montReduce(@as(i32, a.cs[i + 2]) * @as(i32, b.cs[i + 3]));
            p.cs[i + 2] = a2b2 - montReduce(a3b3 * z);
            p.cs[i + 3] = a2b3 + a3b2;
        }
        return p;
    }

    fn compressedSize(comptime d: u8) usize {
        return @divTrunc(N * d, 8);
    }

    fn compress(p: Poly, comptime d: u8) [compressedSize(d)]u8 {
        @setEvalBranchQuota(10000);
        const q_over_2: u32 = comptime @divTrunc(Q, 2);
        const two_d_min_1: u32 = comptime (1 << d) - 1;
        var in_off: usize = 0;
        var out_off: usize = 0;
        const batch_size: usize = comptime math.lcm(d, 8);
        const in_batch_size: usize = comptime batch_size / d;
        const out_batch_size: usize = comptime batch_size / 8;
        const out_length: usize = comptime @divTrunc(N * d, 8);
        var out = [_]u8{0} ** out_length;
        while (in_off < N) {
            var in: [in_batch_size]u16 = undefined;
            inline for (0..in_batch_size) |i| {
                const t = @as(u24, @intCast(p.cs[in_off + i])) << d;
                comptime std.debug.assert(d <= 11);
                comptime std.debug.assert(((20642679 * @as(u64, Q)) >> 36) == 1);
                const u: u32 = @intCast((@as(u64, t + q_over_2) * 20642679) >> 36);
                in[i] = @intCast(u & two_d_min_1);
            }
            comptime var in_shift: usize = 0;
            comptime var j: usize = 0;
            comptime var ci: usize = 0;
            inline while (ci < in_batch_size) : (j += 1) {
                comptime var todo: usize = 8;
                inline while (todo > 0) {
                    const out_shift = comptime 8 - todo;
                    out[out_off + j] |= @as(u8, @truncate((in[ci] >> in_shift) << out_shift));
                    const done = comptime @min(@min(d, todo), d - in_shift);
                    todo -= done;
                    in_shift += done;
                    if (in_shift == d) {
                        in_shift = 0;
                        ci += 1;
                    }
                }
            }
            in_off += in_batch_size;
            out_off += out_batch_size;
        }
        return out;
    }

    fn toBytes(p: Poly) [encoded_length]u8 {
        var ret: [encoded_length]u8 = undefined;
        for (0..comptime N / 2) |i| {
            const t0 = @as(u16, @intCast(p.cs[2 * i]));
            const t1 = @as(u16, @intCast(p.cs[2 * i + 1]));
            ret[3 * i] = @as(u8, @truncate(t0));
            ret[3 * i + 1] = @as(u8, @truncate((t0 >> 8) | (t1 << 4)));
            ret[3 * i + 2] = @as(u8, @truncate(t1 >> 4));
        }
        return ret;
    }
};

fn polyFromBytes(buf: *const [Poly.encoded_length]u8) Poly {
    var ret: Poly = undefined;
    for (0..comptime N / 2) |i| {
        const b0 = @as(i16, buf[3 * i]);
        const b1 = @as(i16, buf[3 * i + 1]);
        const b2 = @as(i16, buf[3 * i + 2]);
        ret.cs[2 * i] = b0 | ((b1 & 0xf) << 8);
        ret.cs[2 * i + 1] = (b1 >> 4) | b2 << 4;
    }
    return ret;
}

fn polyDecompress(comptime d: u8, in: *const [Poly.compressedSize(d)]u8) Poly {
    @setEvalBranchQuota(10000);
    const in_len = comptime @divTrunc(N * d, 8);
    comptime std.debug.assert(in_len * 8 == d * N);
    var ret: Poly = undefined;
    var in_off: usize = 0;
    var out_off: usize = 0;
    const batch_size: usize = comptime math.lcm(d, 8);
    const in_batch_size: usize = comptime batch_size / 8;
    const out_batch_size: usize = comptime batch_size / d;
    while (out_off < N) {
        comptime var in_shift: usize = 0;
        comptime var j: usize = 0;
        comptime var ci: usize = 0;
        inline while (ci < out_batch_size) : (ci += 1) {
            comptime var todo = d;
            var out: u16 = 0;
            inline while (todo > 0) {
                const out_shift = comptime d - todo;
                const m = comptime (1 << d) - 1;
                out |= (@as(u16, in[in_off + j] >> in_shift) << out_shift) & m;
                const done = comptime @min(@min(8, todo), 8 - in_shift);
                todo -= done;
                in_shift += done;
                if (in_shift == 8) {
                    in_shift = 0;
                    j += 1;
                }
            }
            const qx = @as(u32, out) * @as(u32, Q);
            ret.cs[out_off + ci] = @as(i16, @intCast((qx + (1 << (d - 1))) >> d));
        }
        in_off += in_batch_size;
        out_off += out_batch_size;
    }
    return ret;
}

fn polyNoise(comptime eta: u8, nonce: u8, seed: *const [32]u8) Poly {
    var h = sha3.Shake256.init(.{});
    const suffix: [1]u8 = .{nonce};
    h.update(seed);
    h.update(&suffix);
    const buf_len = comptime 2 * eta * N / 8;
    var buf: [buf_len]u8 = undefined;
    h.squeeze(&buf);
    const T = switch (builtin.target.cpu.arch) {
        .x86_64, .x86 => u32,
        else => u64,
    };
    comptime var batch_count: usize = undefined;
    comptime var batch_bytes: usize = undefined;
    comptime var mask: T = 0;
    comptime {
        batch_count = @bitSizeOf(T) / @as(usize, 2 * eta);
        while (@rem(N, batch_count) != 0 and batch_count > 0) : (batch_count -= 1) {}
        std.debug.assert(batch_count > 0);
        std.debug.assert(@rem(2 * eta * batch_count, 8) == 0);
        batch_bytes = 2 * eta * batch_count / 8;
        for (0..2 * eta * batch_count) |_| {
            mask <<= eta;
            mask |= 1;
        }
    }
    var ret: Poly = undefined;
    for (0..comptime N / batch_count) |i| {
        var t: T = 0;
        inline for (0..batch_bytes) |j| {
            t |= @as(T, buf[batch_bytes * i + j]) << (8 * j);
        }
        var d: T = 0;
        inline for (0..eta) |j| {
            d += (t >> j) & mask;
        }
        inline for (0..batch_count) |j| {
            const mask2 = comptime (1 << eta) - 1;
            const a = @as(i16, @intCast((d >> (comptime (2 * j * eta))) & mask2));
            const b = @as(i16, @intCast((d >> (comptime ((2 * j + 1) * eta))) & mask2));
            ret.cs[batch_count * i + j] = a - b;
        }
    }
    return ret;
}

fn polyUniform(seed: [32]u8, x: u8, y: u8) Poly {
    const domain_sep: [2]u8 = .{ x, y };
    var h = sha3.Shake128.init(.{});
    h.update(&seed);
    h.update(&domain_sep);
    const buf_len = sha3.Shake128.block_length;
    var buf: [buf_len]u8 = undefined;
    var ret: Poly = undefined;
    var coef_idx: usize = 0;
    outer: while (true) {
        h.squeeze(&buf);
        var j: usize = 0;
        while (j < buf_len) : (j += 3) {
            const b0 = @as(u16, buf[j]);
            const b1 = @as(u16, buf[j + 1]);
            const b2 = @as(u16, buf[j + 2]);
            const ts: [2]u16 = .{
                b0 | ((b1 & 0xf) << 8),
                (b1 >> 4) | (b2 << 4),
            };
            inline for (ts) |t| {
                if (t < Q) {
                    ret.cs[coef_idx] = @intCast(t);
                    coef_idx += 1;
                    if (coef_idx == N) break :outer;
                }
            }
        }
    }
    return ret;
}

fn PolyVec(comptime k: u8) type {
    return struct {
        ps: [k]Poly,

        const Self = @This();
        const encoded_length = k * Poly.encoded_length;

        fn compressedSize(comptime d: u8) usize {
            return Poly.compressedSize(d) * k;
        }

        fn ntt(v: Self) Self {
            var ret: Self = undefined;
            inline for (0..k) |i| ret.ps[i] = v.ps[i].ntt();
            return ret;
        }

        fn invNTT(v: Self) Self {
            var ret: Self = undefined;
            inline for (0..k) |i| ret.ps[i] = v.ps[i].invNTT();
            return ret;
        }

        fn normalize(v: Self) Self {
            var ret: Self = undefined;
            inline for (0..k) |i| ret.ps[i] = v.ps[i].normalize();
            return ret;
        }

        fn barrettReduce(v: Self) Self {
            var ret: Self = undefined;
            inline for (0..k) |i| ret.ps[i] = v.ps[i].barrettReduce();
            return ret;
        }

        fn add(a: Self, b: Self) Self {
            var ret: Self = undefined;
            inline for (0..k) |i| ret.ps[i] = a.ps[i].add(b.ps[i]);
            return ret;
        }

        fn noiseVec(comptime eta: u8, nonce: u8, seed: *const [32]u8) Self {
            var ret: Self = undefined;
            for (0..k) |i| ret.ps[i] = polyNoise(eta, nonce + @as(u8, @intCast(i)), seed);
            return ret;
        }

        fn dotHat(a: Self, b: Self) Poly {
            var ret: Poly = Poly.zero;
            for (0..k) |i| ret = ret.add(a.ps[i].mulHat(b.ps[i]));
            return ret;
        }

        fn compress(v: Self, comptime d: u8) [compressedSize(d)]u8 {
            const cs = comptime Poly.compressedSize(d);
            var ret: [compressedSize(d)]u8 = undefined;
            inline for (0..k) |i| {
                ret[i * cs .. (i + 1) * cs].* = v.ps[i].compress(d);
            }
            return ret;
        }

        fn toBytes(v: Self) [encoded_length]u8 {
            var ret: [encoded_length]u8 = undefined;
            inline for (0..k) |i| {
                ret[i * Poly.encoded_length .. (i + 1) * Poly.encoded_length].* = v.ps[i].toBytes();
            }
            return ret;
        }

        fn fromBytes(buf: *const [encoded_length]u8) Self {
            var ret: Self = undefined;
            inline for (0..k) |i| {
                ret.ps[i] = polyFromBytes(buf[i * Poly.encoded_length ..][0..Poly.encoded_length]);
            }
            return ret;
        }
    };
}

const MatK = struct {
    rows: [K]PolyVec(K),
};

fn matUniform(seed: [32]u8, comptime transposed: bool) MatK {
    var ret: MatK = undefined;
    var i: u8 = 0;
    while (i < K) : (i += 1) {
        var j: u8 = 0;
        while (j < K) : (j += 1) {
            ret.rows[i].ps[j] = polyUniform(
                seed,
                if (transposed) i else j,
                if (transposed) j else i,
            );
        }
    }
    return ret;
}
