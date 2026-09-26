const std = @import("std");
const game_ids = @import("../game_ids.zig");

const native_math = @import("../runtime/native_math.zig");
const spawn_runtime = @import("../runtime/spawn.zig");

/// Most builders bake the 1024x1024 quest terrain into float literals (1088.0
/// for `1024 + 64`, 512.0 for the center) instead of reading
/// `terrain_texture_width`.
pub const native_terrain_size: f32 = 1024.0;
pub const native_center: spawn_runtime.Vec2 = .{ .x = 512.0, .y = 512.0 };

pub const QuestSpawnBuildError = error{
    InvalidQuestSpawnTable,
    OutOfSpace,
};

pub const QuestSpawnBuildResult = struct {
    entries: []const spawn_runtime.QuestSpawnEntry,
    start_weapon_id: game_ids.WeaponId,
    /// CRT RNG state after the builder's draws.
    rng_state: u32,
};

pub const BuildContext = struct {
    width: f32,
    height: f32,
    player_count: i32,
    hardcore: bool = false,
};

pub const BuildFn = *const fn (
    ctx: BuildContext,
    rng: *QuestRng,
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
    heading: f32,
    spawn_id: SpawnId,
    trigger_ms: i32,
    count: i32,
) QuestSpawnBuildError!void {
    try appendEntry(out_entries, len, .{
        .pos = pos,
        .heading = heading,
        .spawn_id = spawn_id,
        .trigger_ms = trigger_ms,
        .count = count,
    });
}

pub inline fn centerPoint(width: f32, height: f32) spawn_runtime.Vec2 {
    return .{
        .x = width * 0.5,
        .y = height * 0.5,
    };
}

pub inline fn edgeMidpoints(width: f32, height: f32, offset: f32) EdgePoints {
    const center = centerPoint(width, height);
    return .{
        .left = .{ .x = -offset, .y = center.y },
        .right = .{ .x = width + offset, .y = center.y },
        .top = .{ .x = center.x, .y = -offset },
        .bottom = .{ .x = center.x, .y = height + offset },
    };
}

pub inline fn squareEdgeMidpoints(width: f32, offset: f32) EdgePoints {
    return edgeMidpoints(width, width, offset);
}

pub inline fn cornerPoints(width: f32, height: f32, offset: f32) CornerPoints {
    return .{
        .top_left = .{ .x = -offset, .y = -offset },
        .top_right = .{ .x = width + offset, .y = -offset },
        .bottom_left = .{ .x = -offset, .y = height + offset },
        .bottom_right = .{ .x = width + offset, .y = height + offset },
    };
}

pub inline fn insetCornerPoints(width: f32, height: f32, inset: f32) CornerPoints {
    return .{
        .top_left = .{ .x = inset, .y = inset },
        .top_right = .{ .x = width - inset, .y = inset },
        .bottom_left = .{ .x = inset, .y = height - inset },
        .bottom_right = .{ .x = width - inset, .y = height - inset },
    };
}

pub inline fn cornerPointTopLeft(width: f32, height: f32, offset: f32) spawn_runtime.Vec2 {
    _ = width;
    _ = height;
    return .{ .x = -offset, .y = -offset };
}

pub inline fn cornerPointTopRight(width: f32, height: f32, offset: f32) spawn_runtime.Vec2 {
    _ = height;
    return .{ .x = width + offset, .y = -offset };
}

pub inline fn cornerPointBottomLeft(width: f32, height: f32, offset: f32) spawn_runtime.Vec2 {
    _ = width;
    return .{ .x = -offset, .y = height + offset };
}

pub inline fn cornerPointBottomRight(width: f32, height: f32, offset: f32) spawn_runtime.Vec2 {
    return .{ .x = width + offset, .y = height + offset };
}

/// `(float)(crt_rand() % 612) * 0.01f`, rounded by the x87 `fmul`.
pub inline fn randomAngle(rng: *QuestRng) f32 {
    return native_math.pc24Mul(@as(f32, @floatFromInt(rng.randBelow(0x264))), @as(f32, 0.01));
}

/// `(float)index * step + start` with each x87 op rounded to float32.
pub inline fn angleStep(index: i32, step: f32, start: f32) f32 {
    const angle = native_math.pc24Mul(@as(f32, @floatFromInt(index)), step);
    return if (start != 0.0) native_math.pc24Add(angle, start) else angle;
}

/// `atan2(pos - center) - 1.5707964f` on the stored float32 position: `fpatan`
/// stays wide and the `fsub` rounds (`quest_build_target_practice` 0x00437a00).
pub inline fn headingFromCenter(point: spawn_runtime.Vec2, center: spawn_runtime.Vec2) f32 {
    const angle = native_math.fpatan(native_math.pc24Sub(point.y, center.y), native_math.pc24Sub(point.x, center.x));
    return native_math.pc24Sub(angle, native_math.native_half_pi);
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

pub inline fn mulVec(vec: spawn_runtime.Vec2, scalar: f32) spawn_runtime.Vec2 {
    return .{
        .x = vec.x * scalar,
        .y = vec.y * scalar,
    };
}

pub inline fn linePointAt(start: spawn_runtime.Vec2, step: spawn_runtime.Vec2, idx: i32) spawn_runtime.Vec2 {
    return addVec(start, mulVec(step, @as(f32, @floatFromInt(idx))));
}

/// `(float)cos(angle) * radius + center`: `fcos`/`fsin` stay wide, the `fmul`
/// and `fadd` round.
pub inline fn ringPoint(center: spawn_runtime.Vec2, radius: f32, angle: f32) spawn_runtime.Vec2 {
    return .{
        .x = native_math.pc24Add(native_math.pc24Mul(@cos(@as(f64, angle)), radius), center.x),
        .y = native_math.pc24Add(native_math.pc24Mul(@sin(@as(f64, angle)), radius), center.y),
    };
}

pub inline fn appendSpawnAtAllEdges(
    out_entries: []spawn_runtime.QuestSpawnEntry,
    len: *usize,
    edges: EdgePoints,
    heading: f32,
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
    radius: f32,
    count: i32,
    step: f32,
    start_angle: f32,
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
        const angle = angleStep(idx, step, start_angle);
        const heading: f32 = switch (heading_mode) {
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
    angle: f32,
    radius_start: i32,
    radius_end: i32,
    radius_step: i32,
    heading_mode: RadialHeadingMode,
    spawn_id: SpawnId,
    trigger_ms: i32,
    count: i32,
) QuestSpawnBuildError!void {
    if (radius_step <= 0 or radius_end < radius_start) return error.InvalidQuestSpawnTable;
    // `quest_build_sweep_stakes` (0x00437810) and `quest_build_deja_vu`
    // (0x00437920) spill `cos(angle)` to a float local but keep `sin(angle)`
    // on the x87 stack.
    const cos_f32 = native_math.roundF32(@cos(@as(f64, angle)));
    const sin_wide = @sin(@as(f64, angle));
    var radius = radius_start;
    while (radius < radius_end) : (radius += radius_step) {
        const r: f32 = @floatFromInt(radius);
        const pos: spawn_runtime.Vec2 = .{
            .x = native_math.pc24Add(native_math.pc24Mul(r, cos_f32), center.x),
            .y = native_math.pc24Add(native_math.pc24Mul(r, sin_wide), center.y),
        };
        const heading = switch (heading_mode) {
            .zero => 0.0,
            .from_center => headingFromCenter(pos, center),
        };
        try appendSpawn(out_entries, len, pos, heading, spawn_id, trigger_ms, count);
    }
}

pub const QuestRng = struct {
    const crt_rand_mult: u32 = 214_013;
    const crt_rand_inc: u32 = 2_531_011;

    state: u32 = 0,

    pub fn init(seed_value: u32) QuestRng {
        return .{ .state = seed_value };
    }

    pub fn randBelow(self: *QuestRng, n_in: u32) u32 {
        std.debug.assert(n_in > 0);
        return self.rand() % n_in;
    }

    fn rand(self: *QuestRng) u32 {
        self.state = self.state *% crt_rand_mult +% crt_rand_inc;
        return (self.state >> 16) & 0x7fff;
    }
};

pub const SpawnId = spawn_runtime.SpawnId;
