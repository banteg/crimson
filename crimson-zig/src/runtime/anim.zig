const std = @import("std");
const native_math = @import("native_math.zig");
const spawn_mod = @import("spawn.zig");

const narrowF32 = native_math.roundF32;

pub const CreatureAnimInfo = struct {
    base: i32,
    anim_rate: f32,
    mirror: bool,
};

pub const PhaseAdvance = struct {
    phase: f32,
    step: f32,
};

pub const FrameMode = enum {
    long,
    ping_pong,
};

pub const FrameSelection = struct {
    frame: i32,
    mirrored: bool,
    mode: FrameMode,
};

const creature_corpse_frames = std.EnumArray(spawn_mod.CreatureTypeId, i32).init(.{
    .zombie = 0,
    .lizard = 3,
    .alien = 4,
    .spider_sp1 = 1,
    .spider_sp2 = 2,
    .trooper = 7,
});

pub const creature_anim_info = std.EnumArray(spawn_mod.CreatureTypeId, CreatureAnimInfo).init(.{
    .zombie = .{ .base = 0x20, .anim_rate = 1.2, .mirror = false },
    .lizard = .{ .base = 0x10, .anim_rate = 1.6, .mirror = true },
    .alien = .{ .base = 0x20, .anim_rate = 1.35, .mirror = false },
    .spider_sp1 = .{ .base = 0x10, .anim_rate = 1.5, .mirror = true },
    .spider_sp2 = .{ .base = 0x10, .anim_rate = 1.5, .mirror = true },
    .trooper = .{ .base = 0x00, .anim_rate = 1.0, .mirror = false },
});

pub fn creatureAnimInfoForRawTypeId(type_id_raw: i32) ?CreatureAnimInfo {
    const type_id = std.meta.intToEnum(spawn_mod.CreatureTypeId, type_id_raw) catch return null;
    return creature_anim_info.get(type_id);
}

pub fn creatureCorpseFrameForType(type_id_raw: i32) i32 {
    if (type_id_raw == 7) return 6;
    const type_id = std.meta.intToEnum(spawn_mod.CreatureTypeId, type_id_raw) catch return type_id_raw & 0xF;
    return creature_corpse_frames.get(type_id);
}

pub fn creatureAnimIsLongStrip(flags: u32) bool {
    return (flags & spawn_mod.CreatureFlags.anim_ping_pong) == 0 or
        (flags & spawn_mod.CreatureFlags.anim_long_strip) != 0;
}

pub fn creatureAnimPhaseStep(
    anim_rate: f32,
    move_speed: f32,
    dt: f32,
    size: f32,
    local_scale: f32,
    flags: u32,
    ai_mode: spawn_mod.CreatureAiMode,
) f32 {
    if (size == 0.0) return 0.0;

    const anim_rate_f32 = narrowF32(anim_rate);
    const move_speed_f32 = narrowF32(move_speed);
    const dt_f32 = narrowF32(dt);
    const size_f32 = narrowF32(size);
    const local_scale_f32 = narrowF32(local_scale);
    const speed_scale = narrowF32(30.0) / size_f32;
    const is_long_strip = creatureAnimIsLongStrip(flags);
    if (is_long_strip and ai_mode == .hold_timer) return 0.0;

    const strip_mul: f32 = if (is_long_strip) narrowF32(25.0) else narrowF32(22.0);
    return narrowF32(anim_rate_f32 * move_speed_f32 * dt_f32 * speed_scale * strip_mul * local_scale_f32);
}

pub fn creatureAnimAdvancePhase(
    phase: f32,
    anim_rate: f32,
    move_speed: f32,
    dt: f32,
    size: f32,
    local_scale: f32,
    flags: u32,
    ai_mode: spawn_mod.CreatureAiMode,
) PhaseAdvance {
    var next_phase = narrowF32(phase);
    const step = creatureAnimPhaseStep(anim_rate, move_speed, dt, size, local_scale, flags, ai_mode);
    if (step == 0.0) {
        return .{ .phase = next_phase, .step = 0.0 };
    }

    next_phase = narrowF32(next_phase + step);
    if (creatureAnimIsLongStrip(flags)) {
        while (next_phase > 31.0) {
            next_phase = narrowF32(next_phase - 31.0);
        }
    } else {
        while (next_phase > 15.0) {
            next_phase = narrowF32(next_phase - 15.0);
        }
    }

    return .{ .phase = next_phase, .step = step };
}

pub fn creatureAnimSelectFrame(
    phase: f32,
    base_frame: i32,
    mirror_long: bool,
    flags: u32,
) FrameSelection {
    if (creatureAnimIsLongStrip(flags)) {
        if (phase < 0.0) {
            return .{ .frame = base_frame + 0x0F, .mirrored = false, .mode = .long };
        }

        var frame: i32 = @intFromFloat(phase + 0.5);
        var mirrored = false;
        if (mirror_long and frame > 0x0F) {
            frame = 0x1F - frame;
            mirrored = true;
        }
        if ((flags & spawn_mod.CreatureFlags.ranged_attack_shock) != 0) {
            frame += 0x20;
        }
        return .{ .frame = frame, .mirrored = mirrored, .mode = .long };
    }

    const raw: i32 = @intFromFloat(phase + 0.5);
    var idx: i32 = @bitCast(@as(u32, @bitCast(raw)) & 0x8000000F);
    if (idx < 0) {
        idx = @bitCast((@as(u32, @bitCast(idx - 1)) | 0xFFFFFFF0) + 1);
    }
    if (idx > 7) idx = 0x0F - idx;
    return .{ .frame = base_frame + 0x10 + idx, .mirrored = false, .mode = .ping_pong };
}

test "creature anim select mirrors long strips and shock frames" {
    const base = creature_anim_info.get(.lizard).base;
    const mirrored = creatureAnimSelectFrame(17.2, base, true, 0);
    try std.testing.expectEqual(@as(i32, 14), mirrored.frame);
    try std.testing.expect(mirrored.mirrored);
    try std.testing.expectEqual(FrameMode.long, mirrored.mode);

    const shocked = creatureAnimSelectFrame(2.0, base, false, spawn_mod.CreatureFlags.ranged_attack_shock);
    try std.testing.expectEqual(@as(i32, 0x22), shocked.frame);
}

test "creature anim select handles ping pong strips" {
    const selection = creatureAnimSelectFrame(
        9.0,
        creature_anim_info.get(.alien).base,
        false,
        spawn_mod.CreatureFlags.anim_ping_pong,
    );
    try std.testing.expectEqual(@as(i32, 0x36), selection.frame);
    try std.testing.expectEqual(FrameMode.ping_pong, selection.mode);
}

test "creature anim advance wraps long strips" {
    const advanced = creatureAnimAdvancePhase(
        30.0,
        1.0,
        1.0,
        0.1,
        30.0,
        1.0,
        0,
        .orbit_player,
    );
    try std.testing.expectApproxEqAbs(@as(f32, 1.5), advanced.phase, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 2.5), advanced.step, 1e-6);
}

test "creature corpse frame table matches bodyset mapping" {
    try std.testing.expectEqual(@as(i32, 0), creatureCorpseFrameForType(@intFromEnum(spawn_mod.CreatureTypeId.zombie)));
    try std.testing.expectEqual(@as(i32, 6), creatureCorpseFrameForType(7));
    try std.testing.expectEqual(@as(i32, 9), creatureCorpseFrameForType(9));
}
