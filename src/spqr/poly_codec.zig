// Polynomial encoder/decoder for SPQR chunked transmission.
// Messages are split into 16 parallel GF(2^16) streams.
// chunk[k] = [stream[0][k], stream[1][k], ..., stream[15][k]] as 16 BE u16 values = 32 bytes.
// Redundant chunks (k >= pts_per_stream) are computed via Lagrange interpolation.
const std = @import("std");
const gf = @import("gf16.zig");
const mem = std.mem;

pub const CHUNK_SIZE: usize = 32;
pub const NUM_POLYS: usize = 16; // CHUNK_SIZE / 2

pub const Chunk = struct {
    index: u32,
    data: [CHUNK_SIZE]u8,
};

// Lagrange interpolation at x given points (xs[i], ys[i]).
// xs and ys have equal length n. Returns p(x).
fn lagrange(x: u16, xs: []const u16, ys: []const u16) u16 {
    var result: u16 = 0;
    const n = xs.len;
    for (0..n) |i| {
        var num: u16 = ys[i];
        var den: u16 = 1;
        for (0..n) |j| {
            if (j == i) continue;
            num = gf.mul(num, gf.add(x, xs[j]));
            den = gf.mul(den, gf.add(xs[i], xs[j]));
        }
        result = gf.add(result, gf.mul(num, gf.inv(den)));
    }
    return result;
}

// Maximum number of points we'll store per polynomial.
// For EK (largest): 36 points. We store at most 2x for redundancy.
const MAX_PTS: usize = 80;

const PolyPts = struct {
    xs: [MAX_PTS]u16 = undefined,
    ys: [MAX_PTS]u16 = undefined,
    count: u32 = 0,

    fn add(self: *PolyPts, x: u16, y: u16, needed: usize) void {
        // Accept if x < needed (direct coefficient) or we haven't filled needed slots yet
        if (x < needed or self.count < needed) {
            // Reject duplicates by x
            for (self.xs[0..self.count]) |existing_x| {
                if (existing_x == x) return;
            }
            if (self.count < MAX_PTS) {
                self.xs[self.count] = x;
                self.ys[self.count] = y;
                self.count += 1;
            }
        }
    }

    fn getY(self: *const PolyPts, x: u16, needed: usize) ?u16 {
        // Direct lookup
        for (0..self.count) |i| {
            if (self.xs[i] == x) return self.ys[i];
        }
        // Lagrange interpolation if we have enough points
        if (self.count >= needed) {
            return lagrange(x, self.xs[0..self.count], self.ys[0..self.count]);
        }
        return null;
    }
};

// number of points needed for polynomial `poly` of 16, given total pts_needed
fn necessaryPoints(pts_needed: usize, poly: usize) usize {
    const per_poly = pts_needed / 16;
    const remainder = pts_needed % 16;
    return per_poly + @as(usize, if (poly < remainder) 1 else 0);
}

pub const PolyEncoder = struct {
    idx: u32,
    msg: []u8,
    allocator: mem.Allocator,

    pub fn init(allocator: mem.Allocator, msg: []const u8) !PolyEncoder {
        std.debug.assert(msg.len % 2 == 0);
        const copy = try allocator.dupe(u8, msg);
        return .{ .idx = 0, .msg = copy, .allocator = allocator };
    }

    pub fn deinit(self: *PolyEncoder) void {
        self.allocator.free(self.msg);
    }

    // Number of GF elements per polynomial stream
    fn ptsNeeded(self: *const PolyEncoder) usize {
        return self.msg.len / 2;
    }

    // Get GF(2^16) element from the message for polynomial `poly` at index `k`.
    // For k < stream_len: direct lookup.
    // For k >= stream_len: Lagrange extrapolation.
    fn getElement(self: *const PolyEncoder, poly: usize, k: usize) u16 {
        const pts_needed = self.ptsNeeded();
        const needed = necessaryPoints(pts_needed, poly);
        const stream_len = needed; // coefficients for this polynomial
        if (k < stream_len) {
            // Direct: element at message position (k * 16 + poly) * 2
            const msg_idx = (k * 16 + poly) * 2;
            if (msg_idx + 1 < self.msg.len) {
                return (@as(u16, self.msg[msg_idx]) << 8) | self.msg[msg_idx + 1];
            }
            return 0;
        }
        // Need Lagrange extrapolation: collect known points (0, v0), (1, v1), ..., (stream_len-1, v_{n-1})
        var xs: [MAX_PTS]u16 = undefined;
        var ys: [MAX_PTS]u16 = undefined;
        for (0..stream_len) |i| {
            xs[i] = @intCast(i);
            const msg_idx = (i * 16 + poly) * 2;
            ys[i] = if (msg_idx + 1 < self.msg.len)
                (@as(u16, self.msg[msg_idx]) << 8) | self.msg[msg_idx + 1]
            else
                0;
        }
        return lagrange(@intCast(k), xs[0..stream_len], ys[0..stream_len]);
    }

    pub fn chunkAt(self: *const PolyEncoder, idx: u16) Chunk {
        var data: [CHUNK_SIZE]u8 = undefined;
        for (0..NUM_POLYS) |i| {
            // total_idx = idx*16 + i; poly = total_idx%16 = i; poly_idx = total_idx/16 = idx
            const poly = i;
            const poly_idx = @as(usize, idx);
            const v = self.getElement(poly, poly_idx);
            data[i * 2] = @intCast(v >> 8);
            data[i * 2 + 1] = @intCast(v & 0xFF);
        }
        return Chunk{ .index = idx, .data = data };
    }

    pub fn nextChunk(self: *PolyEncoder) Chunk {
        const c = self.chunkAt(@intCast(self.idx));
        self.idx += 1;
        return c;
    }
};

pub const PolyDecoder = struct {
    pts_needed: usize,
    pts: [NUM_POLYS]PolyPts,
    is_complete: bool,

    pub fn init(len_bytes: usize) !PolyDecoder {
        if (len_bytes % 2 != 0) return error.OddLength;
        return .{
            .pts_needed = len_bytes / 2,
            .pts = [_]PolyPts{.{}} ** NUM_POLYS,
            .is_complete = false,
        };
    }

    pub fn addChunk(self: *PolyDecoder, chunk: *const Chunk) void {
        for (0..NUM_POLYS) |i| {
            const total_idx = @as(usize, chunk.index) * NUM_POLYS + i;
            const poly = total_idx % NUM_POLYS; // = i
            const poly_idx: u16 = @intCast(total_idx / NUM_POLYS); // = chunk.index
            const y: u16 = (@as(u16, chunk.data[i * 2]) << 8) | chunk.data[i * 2 + 1];
            const needed = necessaryPoints(self.pts_needed, poly);
            self.pts[poly].add(poly_idx, y, needed);
        }
    }

    pub fn decodedMessage(self: *PolyDecoder, allocator: mem.Allocator) !?[]u8 {
        if (self.is_complete) return null;
        // Check if we have enough points for all polynomials
        for (0..NUM_POLYS) |i| {
            if (self.pts[i].count < necessaryPoints(self.pts_needed, i)) return null;
        }
        // Reconstruct message
        const out = try allocator.alloc(u8, self.pts_needed * 2);
        for (0..self.pts_needed) |i| {
            const poly = i % NUM_POLYS;
            const poly_idx: u16 = @intCast(i / NUM_POLYS);
            const needed = necessaryPoints(self.pts_needed, poly);
            const v = self.pts[poly].getY(poly_idx, needed) orelse {
                allocator.free(out);
                return null;
            };
            out[i * 2] = @intCast(v >> 8);
            out[i * 2 + 1] = @intCast(v & 0xFF);
        }
        self.is_complete = true;
        return out;
    }

    // Serialize decoder state to writer
    pub fn serialize(self: *const PolyDecoder, buf: *std.ArrayListUnmanaged(u8), a: mem.Allocator) !void {
        // pts_needed (u32 BE)
        var tmp: [4]u8 = undefined;
        std.mem.writeInt(u32, &tmp, @intCast(self.pts_needed), .big);
        try buf.appendSlice(a, &tmp);
        // is_complete (u8)
        try buf.append(a, if (self.is_complete) 1 else 0);
        // 16 poly pt sets
        for (0..NUM_POLYS) |i| {
            const pp = &self.pts[i];
            std.mem.writeInt(u32, &tmp, pp.count, .big);
            try buf.appendSlice(a, &tmp);
            for (0..pp.count) |j| {
                std.mem.writeInt(u16, tmp[0..2], pp.xs[j], .big);
                std.mem.writeInt(u16, tmp[2..4], pp.ys[j], .big);
                try buf.appendSlice(a, tmp[0..4]);
            }
        }
    }

    // Deserialize decoder state from bytes, returns bytes consumed
    pub fn deserialize(data: []const u8) !struct { dec: PolyDecoder, consumed: usize } {
        var pos: usize = 0;
        if (data.len < 5) return error.TooShort;
        const pts_needed = std.mem.readInt(u32, data[pos..][0..4], .big);
        pos += 4;
        const is_complete = data[pos] != 0;
        pos += 1;
        var pts: [NUM_POLYS]PolyPts = [_]PolyPts{.{}} ** NUM_POLYS;
        for (0..NUM_POLYS) |i| {
            if (pos + 4 > data.len) return error.TooShort;
            const count = std.mem.readInt(u32, data[pos..][0..4], .big);
            pos += 4;
            if (count > MAX_PTS) return error.Invalid;
            for (0..count) |j| {
                if (pos + 4 > data.len) return error.TooShort;
                const x = std.mem.readInt(u16, data[pos..][0..2], .big);
                const y = std.mem.readInt(u16, data[pos + 2 ..][0..2], .big);
                pos += 4;
                pts[i].xs[j] = x;
                pts[i].ys[j] = y;
            }
            pts[i].count = count;
        }
        return .{
            .dec = .{ .pts_needed = pts_needed, .pts = pts, .is_complete = is_complete },
            .consumed = pos,
        };
    }
};

// Serialize encoder state
pub fn serializeEncoder(enc: *const PolyEncoder, buf: *std.ArrayListUnmanaged(u8), a: mem.Allocator) !void {
    var tmp: [4]u8 = undefined;
    // idx (u32 BE)
    std.mem.writeInt(u32, &tmp, enc.idx, .big);
    try buf.appendSlice(a, &tmp);
    // msg len (u32 BE)
    std.mem.writeInt(u32, &tmp, @intCast(enc.msg.len), .big);
    try buf.appendSlice(a, &tmp);
    try buf.appendSlice(a, enc.msg);
}

// Deserialize encoder state
pub fn deserializeEncoder(allocator: mem.Allocator, data: []const u8) !struct { enc: PolyEncoder, consumed: usize } {
    if (data.len < 8) return error.TooShort;
    var pos: usize = 0;
    const idx = std.mem.readInt(u32, data[pos..][0..4], .big);
    pos += 4;
    const msg_len = std.mem.readInt(u32, data[pos..][0..4], .big);
    pos += 4;
    if (pos + msg_len > data.len) return error.TooShort;
    const msg = try allocator.dupe(u8, data[pos .. pos + msg_len]);
    pos += msg_len;
    return .{ .enc = .{ .idx = idx, .msg = msg, .allocator = allocator }, .consumed = pos };
}
