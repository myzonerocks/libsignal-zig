// GF(2^16) arithmetic for SPQR polynomial coding.
// Irreducible polynomial: x^16 + x^12 + x^3 + x + 1 = 0x1100b
const std = @import("std");

const POLY: u32 = 0x1100b;

// REDUCE_BYTES[i] = i * x^16 mod POLY
const REDUCE_BYTES: [256]u16 = blk: {
    @setEvalBranchQuota(20000);
    var table: [256]u16 = undefined;
    var i: usize = 0;
    while (i < 256) : (i += 1) {
        var v: u32 = @intCast(i);
        v <<= 16;
        var bit: usize = 23;
        while (bit >= 16) : (bit -= 1) {
            if ((v >> @intCast(bit)) & 1 != 0) {
                v ^= POLY << @intCast(bit - 16);
            }
        }
        table[i] = @intCast(v & 0xFFFF);
    }
    break :blk table;
};

fn polyReduce(v: u32) u16 {
    const idx1: u8 = @intCast(v >> 24);
    const vv: u32 = v ^ (@as(u32, REDUCE_BYTES[idx1]) << 8);
    const idx2: u8 = @intCast((vv >> 16) & 0xFF);
    return @intCast((vv ^ REDUCE_BYTES[idx2]) & 0xFFFF);
}

fn polyMul(a: u16, b: u16) u32 {
    var result: u32 = 0;
    var av: u32 = a;
    var bv: u32 = b;
    while (av != 0) {
        if (av & 1 != 0) result ^= bv;
        av >>= 1;
        bv <<= 1;
    }
    return result;
}

pub inline fn add(a: u16, b: u16) u16 {
    return a ^ b;
}

pub inline fn mul(a: u16, b: u16) u16 {
    return polyReduce(polyMul(a, b));
}

// Multiplicative inverse via Fermat: a^(2^16-2)
pub fn inv(a: u16) u16 {
    if (a == 0) return 0;
    var result: u16 = 1;
    var base: u16 = a;
    var exp: u32 = 0xFFFE;
    while (exp > 0) {
        if (exp & 1 != 0) result = mul(result, base);
        base = mul(base, base);
        exp >>= 1;
    }
    return result;
}
