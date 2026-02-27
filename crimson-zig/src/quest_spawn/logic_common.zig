const std = @import("std");
const game_ids = @import("../game_ids.zig");

const math_runtime = @import("../runtime/math.zig");
const spawn_runtime = @import("../runtime/spawn.zig");

pub const QuestSpawnBuildError = error{
    UnsupportedQuestSpawnTable,
    OutOfSpace,
};

pub const QuestSpawnBuildResult = struct {
    entries: []const spawn_runtime.QuestSpawnEntry,
    start_weapon_id: game_ids.WeaponId,
};

pub const BuildContext = struct {
    width: f64,
    height: f64,
    player_count: i32,
};

pub const BuildFn = *const fn (
    ctx: BuildContext,
    rng: *PythonRandom,
    out_entries: []spawn_runtime.QuestSpawnEntry,
    len: *usize,
) QuestSpawnBuildError!void;

pub const LevelBuilder = struct {
    level_key: i32,
    start_weapon_id: game_ids.WeaponId,
    build: BuildFn,
};

pub const EdgePoints = struct {
    left: spawn_runtime.Vec2,
    right: spawn_runtime.Vec2,
    top: spawn_runtime.Vec2,
    bottom: spawn_runtime.Vec2,
};

pub const CornerPoints = struct {
    top_left: spawn_runtime.Vec2,
    top_right: spawn_runtime.Vec2,
    bottom_left: spawn_runtime.Vec2,
    bottom_right: spawn_runtime.Vec2,
};

pub const RingHeadingMode = enum {
    zero,
    angle,
};

pub const RadialHeadingMode = enum {
    zero,
    from_center,
};

pub inline fn appendEntry(
    out_entries: []spawn_runtime.QuestSpawnEntry,
    len: *usize,
    entry: spawn_runtime.QuestSpawnEntry,
) QuestSpawnBuildError!void {
    if (len.* >= out_entries.len) return error.OutOfSpace;
    out_entries[len.*] = entry;
    len.* += 1;
}

pub inline fn appendSpawn(
    out_entries: []spawn_runtime.QuestSpawnEntry,
    len: *usize,
    pos: spawn_runtime.Vec2,
    heading: f64,
    spawn_id: SpawnId,
    trigger_ms: i32,
    count: i32,
) QuestSpawnBuildError!void {
    try appendEntry(out_entries, len, .{
        .pos = pos,
        .heading = @floatCast(heading),
        .spawn_id = spawn_id,
        .trigger_ms = trigger_ms,
        .count = count,
    });
}

pub inline fn centerPoint(width: f64, height: f64) spawn_runtime.Vec2 {
    return .{
        .x = width * 0.5,
        .y = height * 0.5,
    };
}

pub inline fn edgeMidpoints(width: f64, height: f64, offset: f64) EdgePoints {
    const center = centerPoint(width, height);
    return .{
        .left = .{ .x = -offset, .y = center.y },
        .right = .{ .x = width + offset, .y = center.y },
        .top = .{ .x = center.x, .y = -offset },
        .bottom = .{ .x = center.x, .y = height + offset },
    };
}

pub inline fn squareEdgeMidpoints(width: f64, offset: f64) EdgePoints {
    return edgeMidpoints(width, width, offset);
}

pub inline fn cornerPoints(width: f64, height: f64, offset: f64) CornerPoints {
    return .{
        .top_left = .{ .x = -offset, .y = -offset },
        .top_right = .{ .x = width + offset, .y = -offset },
        .bottom_left = .{ .x = -offset, .y = height + offset },
        .bottom_right = .{ .x = width + offset, .y = height + offset },
    };
}

pub inline fn insetCornerPoints(width: f64, height: f64, inset: f64) CornerPoints {
    return .{
        .top_left = .{ .x = inset, .y = inset },
        .top_right = .{ .x = width - inset, .y = inset },
        .bottom_left = .{ .x = inset, .y = height - inset },
        .bottom_right = .{ .x = width - inset, .y = height - inset },
    };
}

pub inline fn cornerPointTopLeft(width: f64, height: f64, offset: f64) spawn_runtime.Vec2 {
    _ = width;
    _ = height;
    return .{ .x = -offset, .y = -offset };
}

pub inline fn cornerPointTopRight(width: f64, height: f64, offset: f64) spawn_runtime.Vec2 {
    _ = height;
    return .{ .x = width + offset, .y = -offset };
}

pub inline fn cornerPointBottomLeft(width: f64, height: f64, offset: f64) spawn_runtime.Vec2 {
    _ = width;
    return .{ .x = -offset, .y = height + offset };
}

pub inline fn cornerPointBottomRight(width: f64, height: f64, offset: f64) spawn_runtime.Vec2 {
    return .{ .x = width + offset, .y = height + offset };
}

pub inline fn randomAngle(rng: *PythonRandom) f64 {
    // Native quest scripts draw a 0..611 integer and scale by 0.01 radians.
    return @as(f64, @floatFromInt(rng.randBelow(0x264))) * 0.01;
}

pub inline fn headingFromCenter(point: spawn_runtime.Vec2, center: spawn_runtime.Vec2) f64 {
    return math_runtime.atan2(point.y - center.y, point.x - center.x) - (std.math.pi / 2.0);
}

pub inline fn vecFromAngle(angle: f64) spawn_runtime.Vec2 {
    return .{
        .x = math_runtime.cos(angle),
        .y = math_runtime.sin(angle),
    };
}

pub inline fn addVec(a: spawn_runtime.Vec2, b: spawn_runtime.Vec2) spawn_runtime.Vec2 {
    return .{
        .x = a.x + b.x,
        .y = a.y + b.y,
    };
}

pub inline fn subVec(a: spawn_runtime.Vec2, b: spawn_runtime.Vec2) spawn_runtime.Vec2 {
    return .{
        .x = a.x - b.x,
        .y = a.y - b.y,
    };
}

pub inline fn mulVec(vec: spawn_runtime.Vec2, scalar: f64) spawn_runtime.Vec2 {
    return .{
        .x = vec.x * scalar,
        .y = vec.y * scalar,
    };
}

pub inline fn toAngle(vec: spawn_runtime.Vec2) f64 {
    return math_runtime.atan2(vec.y, vec.x);
}

pub inline fn linePointAt(start: spawn_runtime.Vec2, step: spawn_runtime.Vec2, idx: i32) spawn_runtime.Vec2 {
    return addVec(start, mulVec(step, @as(f64, @floatFromInt(idx))));
}

pub inline fn ringPoint(center: spawn_runtime.Vec2, radius: f64, angle: f64) spawn_runtime.Vec2 {
    return addVec(center, mulVec(vecFromAngle(angle), radius));
}

pub inline fn appendSpawnAtAllEdges(
    out_entries: []spawn_runtime.QuestSpawnEntry,
    len: *usize,
    edges: EdgePoints,
    heading: f64,
    spawn_id: SpawnId,
    trigger_ms: i32,
    count: i32,
) QuestSpawnBuildError!void {
    try appendSpawn(out_entries, len, edges.right, heading, spawn_id, trigger_ms, count);
    try appendSpawn(out_entries, len, edges.left, heading, spawn_id, trigger_ms, count);
    try appendSpawn(out_entries, len, edges.bottom, heading, spawn_id, trigger_ms, count);
    try appendSpawn(out_entries, len, edges.top, heading, spawn_id, trigger_ms, count);
}

pub fn appendRingSpawns(
    out_entries: []spawn_runtime.QuestSpawnEntry,
    len: *usize,
    center: spawn_runtime.Vec2,
    radius: f64,
    count: i32,
    step: f64,
    start_angle: f64,
    heading_mode: RingHeadingMode,
    spawn_id: SpawnId,
    trigger_start: i32,
    trigger_step: i32,
    spawn_count: i32,
) QuestSpawnBuildError!void {
    if (count <= 0) return;
    var trigger = trigger_start;
    var idx: i32 = 0;
    while (idx < count) : (idx += 1) {
        const angle = start_angle + @as(f64, @floatFromInt(idx)) * step;
        const heading = switch (heading_mode) {
            .zero => 0.0,
            .angle => angle,
        };
        try appendSpawn(
            out_entries,
            len,
            ringPoint(center, radius, angle),
            heading,
            spawn_id,
            trigger,
            spawn_count,
        );
        trigger += trigger_step;
    }
}

pub fn appendRadialSpawns(
    out_entries: []spawn_runtime.QuestSpawnEntry,
    len: *usize,
    center: spawn_runtime.Vec2,
    angle: f64,
    radius_start: f64,
    radius_end: f64,
    radius_step: f64,
    heading_mode: RadialHeadingMode,
    spawn_id: SpawnId,
    trigger_ms: i32,
    count: i32,
) QuestSpawnBuildError!void {
    if (radius_step <= 0.0 or radius_end < radius_start) return error.UnsupportedQuestSpawnTable;
    const direction = vecFromAngle(angle);
    var radius = radius_start;
    while (radius < radius_end) : (radius += radius_step) {
        const pos = addVec(center, mulVec(direction, radius));
        const heading = switch (heading_mode) {
            .zero => 0.0,
            .from_center => headingFromCenter(pos, center),
        };
        try appendSpawn(out_entries, len, pos, heading, spawn_id, trigger_ms, count);
    }
}

pub const PythonRandom = struct {
    const n: usize = 624;
    const m: usize = 397;
    const matrix_a: u32 = 0x9908B0DF;
    const upper_mask: u32 = 0x80000000;
    const lower_mask: u32 = 0x7fffffff;

    state: [n]u32 = [_]u32{0} ** n,
    index: usize = n,

    pub fn init(seed_value: u32) PythonRandom {
        var rng = PythonRandom{};
        rng.seed(seed_value);
        return rng;
    }

    fn seed(self: *PythonRandom, seed_value: u32) void {
        self.initGenrand(19_650_218);

        var i: usize = 1;
        var j: u32 = 0;
        var k: usize = @max(n, @as(usize, 1));
        while (k > 0) : (k -= 1) {
            const prev = self.state[i - 1];
            self.state[i] = (self.state[i] ^ ((prev ^ (prev >> 30)) *% 1_664_525)) +% seed_value +% j;
            i += 1;
            j +%= 1;
            if (i >= n) {
                self.state[0] = self.state[n - 1];
                i = 1;
            }
            if (j >= 1) {
                j = 0;
            }
        }

        var rounds: usize = n - 1;
        while (rounds > 0) : (rounds -= 1) {
            const prev = self.state[i - 1];
            self.state[i] = (self.state[i] ^ ((prev ^ (prev >> 30)) *% 1_566_083_941)) -% @as(u32, @intCast(i));
            i += 1;
            if (i >= n) {
                self.state[0] = self.state[n - 1];
                i = 1;
            }
        }
        self.state[0] = upper_mask;
        self.index = n;
    }

    fn initGenrand(self: *PythonRandom, seed_value: u32) void {
        self.state[0] = seed_value;
        var i: usize = 1;
        while (i < n) : (i += 1) {
            const prev = self.state[i - 1];
            self.state[i] = 1_812_433_253 *% (prev ^ (prev >> 30)) +% @as(u32, @intCast(i));
        }
        self.index = n;
    }

    pub fn randBelow(self: *PythonRandom, n_in: u32) u32 {
        std.debug.assert(n_in > 0);
        const bits = bitLength(n_in);
        while (true) {
            const value = self.getRandBits(bits);
            if (value < n_in) return value;
        }
    }

    fn getRandBits(self: *PythonRandom, bits: u32) u32 {
        std.debug.assert(bits > 0 and bits <= 32);
        if (bits == 32) return self.rand32();
        return self.rand32() >> @as(u5, @intCast(32 - bits));
    }

    fn rand32(self: *PythonRandom) u32 {
        if (self.index >= n) {
            self.twist();
        }
        var y = self.state[self.index];
        self.index += 1;
        y ^= y >> 11;
        y ^= (y << 7) & 0x9D2C5680;
        y ^= (y << 15) & 0xEFC60000;
        y ^= y >> 18;
        return y;
    }

    fn twist(self: *PythonRandom) void {
        var kk: usize = 0;
        while (kk < n - m) : (kk += 1) {
            const y = (self.state[kk] & upper_mask) | (self.state[kk + 1] & lower_mask);
            self.state[kk] = self.state[kk + m] ^ (y >> 1) ^ mag01(y & 1);
        }
        while (kk < n - 1) : (kk += 1) {
            const y = (self.state[kk] & upper_mask) | (self.state[kk + 1] & lower_mask);
            self.state[kk] = self.state[kk - (n - m)] ^ (y >> 1) ^ mag01(y & 1);
        }
        const y_last = (self.state[n - 1] & upper_mask) | (self.state[0] & lower_mask);
        self.state[n - 1] = self.state[m - 1] ^ (y_last >> 1) ^ mag01(y_last & 1);
        self.index = 0;
    }
};

fn mag01(value: u32) u32 {
    return if ((value & 1) == 0) 0 else PythonRandom.matrix_a;
}

fn bitLength(value: u32) u32 {
    var bits: u32 = 0;
    var v = value;
    while (v > 0) : (v >>= 1) {
        bits += 1;
    }
    return bits;
}

pub const SpawnId = spawn_runtime.SpawnId;
