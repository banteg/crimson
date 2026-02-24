const std = @import("std");

const crt_rand_mult: u32 = 214_013;
const crt_rand_inc: u32 = 2_531_011;

pub const CreatureTypeId = enum(i32) {
    zombie = 0,
    lizard = 1,
    alien = 2,
    spider_sp1 = 3,
    spider_sp2 = 4,
    trooper = 5,
};

pub const CreatureAiMode = struct {
    pub const orbit_player: i32 = 0;
    pub const hold_timer: i32 = 7;
};

pub const CreatureFlags = struct {
    pub const ai7_link_timer: u32 = 0x80;
};

pub const SpawnId = struct {
    pub const spider_sp2_splitter_01: i32 = 0x01;
    pub const formation_ring_alien_8_12: i32 = 0x12;
    pub const alien_const_red_fast_2b: i32 = 0x2B;
    pub const alien_const_red_boss_2c: i32 = 0x2C;
    pub const spider_sp2_random_35: i32 = 0x35;
    pub const spider_sp1_ai7_timer_38: i32 = 0x38;
    pub const spider_sp1_const_shock_boss_3a: i32 = 0x3A;
    pub const spider_sp1_const_ranged_variant_3c: i32 = 0x3C;
};

pub const Vec2 = struct {
    x: f64,
    y: f64,
};

pub const Crand = struct {
    state: u32 = 0,

    pub fn init(seed: u32) Crand {
        return .{ .state = seed };
    }

    pub fn srand(self: *Crand, seed: u32) void {
        self.state = seed;
    }

    pub fn rand(self: *Crand) u32 {
        self.state = self.state *% crt_rand_mult +% crt_rand_inc;
        return (self.state >> 16) & 0x7fff;
    }
};

pub const CreatureInit = struct {
    origin_template_id: i32 = -1,
    pos: Vec2,
    heading: f64 = 0.0,
    phase_seed: f64 = 0.0,
    type_id: CreatureTypeId = .alien,
    ai_mode: i32 = CreatureAiMode.orbit_player,
    flags: u32 = 0,
    size: f64 = 0.0,
    move_speed: f64 = 0.0,
    health: f64 = 0.0,
    max_health: f64 = 0.0,
    reward_value: f64 = 0.0,
    contact_damage: f64 = 0.0,
    tint: [4]f64 = .{ 1.0, 1.0, 1.0, 1.0 },
};

pub const WaveSpawnResult = struct {
    cooldown: f64,
    spawns: []CreatureInit,

    pub fn deinit(self: WaveSpawnResult, allocator: std.mem.Allocator) void {
        allocator.free(self.spawns);
    }
};

pub const WaveSpawnCountResult = struct {
    cooldown: f64,
    spawn_count: usize,
};

pub const max_wave_spawn_batch: usize = 128;

const empty_creature_init = CreatureInit{
    .pos = .{ .x = 0.0, .y = 0.0 },
};

pub const WaveSpawnBatchResult = struct {
    cooldown: f64,
    count: usize,
    spawns: [max_wave_spawn_batch]CreatureInit = [_]CreatureInit{empty_creature_init} ** max_wave_spawn_batch,

    pub fn slice(self: *const WaveSpawnBatchResult) []const CreatureInit {
        return self.spawns[0..self.count];
    }
};

pub const SpawnTemplateCall = struct {
    template_id: i32,
    pos: Vec2,
    heading: f64,
};

pub const SpawnStageResult = struct {
    stage: i32,
    count: usize = 0,
    calls: [32]SpawnTemplateCall = [_]SpawnTemplateCall{.{
        .template_id = 0,
        .pos = .{ .x = 0.0, .y = 0.0 },
        .heading = 0.0,
    }} ** 32,

    pub fn slice(self: *const SpawnStageResult) []const SpawnTemplateCall {
        return self.calls[0..self.count];
    }
};

pub fn buildSurvivalSpawnCreature(
    pos: Vec2,
    rng: *Crand,
    player_experience: i32,
) CreatureInit {
    const xp: i32 = player_experience;

    var creature = allocCreature(-1, pos, rng);
    creature.ai_mode = CreatureAiMode.orbit_player;

    const r10 = @as(i32, @intCast(rng.rand() % 10));

    var type_id: i32 = 0;
    if (xp < 12_000) {
        type_id = if (r10 < 9) 2 else 3;
    } else if (xp < 25_000) {
        type_id = if (r10 < 4) 0 else 3;
        if (8 < r10) type_id = 2;
    } else if (xp < 42_000) {
        if (r10 < 5) {
            type_id = 2;
        } else {
            type_id = @as(i32, @intCast((rng.rand() & 1) + 3));
        }
    } else if (xp < 50_000) {
        type_id = 2;
    } else if (xp < 90_000) {
        type_id = 4;
    } else {
        if (109_999 < xp) {
            if (r10 < 6) {
                type_id = 2;
            } else if (r10 < 9) {
                type_id = 4;
            } else {
                type_id = 0;
            }
        } else {
            type_id = 0;
        }
    }

    if ((rng.rand() & 0x1f) == 2) {
        type_id = 3;
    }
    creature.type_id = @enumFromInt(type_id);

    creature.size = @floatFromInt(rng.rand() % 20 + 44);
    {
        const heading_base: f32 = @floatFromInt(rng.rand() % 314);
        const heading_scaled: f32 = @as(f32, heading_base * @as(f32, 0.01));
        creature.heading = @floatCast(heading_scaled);
    }

    var move_speed: f32 = @floatFromInt(@divTrunc(xp, 4000));
    move_speed = @as(f32, move_speed * @as(f32, 0.045));
    move_speed = @as(f32, move_speed + @as(f32, 0.9));
    if (creature.type_id == .spider_sp1) {
        creature.flags |= CreatureFlags.ai7_link_timer;
        move_speed = @as(f32, move_speed * @as(f32, 1.3));
    }

    const r_health = rng.rand();
    var health: f32 = @floatFromInt(xp);
    health = @as(f32, health * @as(f32, 0.00125));
    health = @as(f32, health + @as(f32, @floatFromInt(r_health & 0xF)));
    health = @as(f32, health + @as(f32, 52.0));

    if (creature.type_id == .zombie) {
        move_speed = @as(f32, move_speed * @as(f32, 0.6));
        if (move_speed < @as(f32, 1.3)) move_speed = 1.3;
        health = @as(f32, health * @as(f32, 1.5));
    }

    if (move_speed > @as(f32, 3.5)) move_speed = 3.5;

    creature.move_speed = @floatCast(move_speed);
    creature.health = @floatCast(health);
    creature.reward_value = 0.0;

    const tint_a = 1.0;
    var tint_r: f64 = 0.0;
    var tint_g: f64 = 0.0;
    var tint_b: f64 = 0.0;
    if (xp < 50_000) {
        tint_r = 1.0 - 1.0 / (@as(f64, @floatFromInt(@divTrunc(xp, 1000))) + 10.0);
        tint_g = @as(f64, @floatFromInt(rng.rand() % 10)) * 0.01 + 0.9 - 1.0 / (@as(f64, @floatFromInt(@divTrunc(xp, 10_000))) + 10.0);
        tint_b = @as(f64, @floatFromInt(rng.rand() % 10)) * 0.01 + 0.7;
    } else if (xp < 100_000) {
        tint_r = 0.9 - 1.0 / (@as(f64, @floatFromInt(@divTrunc(xp, 1000))) + 10.0);
        tint_g = @as(f64, @floatFromInt(rng.rand() % 10)) * 0.01 + 0.8 - 1.0 / (@as(f64, @floatFromInt(@divTrunc(xp, 10_000))) + 10.0);
        tint_b = @as(f64, @floatFromInt(xp - 50_000)) * 6e-06 + @as(f64, @floatFromInt(rng.rand() % 10)) * 0.01 + 0.7;
    } else {
        tint_r = 1.0 - 1.0 / (@as(f64, @floatFromInt(@divTrunc(xp, 1000))) + 10.0);
        tint_g = @as(f64, @floatFromInt(rng.rand() % 10)) * 0.01 + 0.9 - 1.0 / (@as(f64, @floatFromInt(@divTrunc(xp, 10_000))) + 10.0);
        tint_b = @as(f64, @floatFromInt(rng.rand() % 10)) * 0.01 + 1.0 - @as(f64, @floatFromInt(xp - 100_000)) * 3e-06;
        if (tint_b < 0.5) tint_b = 0.5;
    }
    creature.tint = .{ tint_r, tint_g, tint_b, tint_a };

    creature.contact_damage = creature.size * (2.0 / 21.0);
    creature.reward_value = creature.health * 0.4 +
        creature.contact_damage * 0.8 +
        @as(f64, @floatCast(move_speed)) * 5.0 +
        @as(f64, @floatFromInt(rng.rand() % 10 + 10));

    var r = rng.rand();
    if ((r % 180) < 2) {
        applyTint(&creature, .{ 0.9, 0.4, 0.4, 1.0 });
        creature.health = 65.0;
        creature.reward_value = 320.0;
    } else {
        r = rng.rand();
        if ((r % 240) < 2) {
            applyTint(&creature, .{ 0.4, 0.9, 0.4, 1.0 });
            creature.health = 85.0;
            creature.reward_value = 420.0;
        } else {
            r = rng.rand();
            if ((r % 360) < 2) {
                applyTint(&creature, .{ 0.4, 0.4, 0.9, 1.0 });
                creature.health = 125.0;
                creature.reward_value = 520.0;
            }
        }
    }

    r = rng.rand();
    if ((r % 1320) < 4) {
        applyTint(&creature, .{ 0.84, 0.24, 0.89, 1.0 });
        creature.size = 80.0;
        creature.reward_value = 600.0;
        creature.health += 230.0;
    } else {
        r = rng.rand();
        if ((r % 1620) < 4) {
            applyTint(&creature, .{ 0.94, 0.84, 0.29, 1.0 });
            creature.size = 85.0;
            creature.reward_value = 900.0;
            creature.health += 2230.0;
        }
    }

    creature.max_health = creature.health;
    creature.reward_value *= 0.8;
    creature.tint = .{
        clamp01(creature.tint[0]),
        clamp01(creature.tint[1]),
        clamp01(creature.tint[2]),
        clamp01(creature.tint[3]),
    };

    return creature;
}

pub fn randSurvivalSpawnPos(
    rng: *Crand,
    terrain_width: i32,
    terrain_height: i32,
) Vec2 {
    const width: u32 = @intCast(@max(1, terrain_width));
    const height: u32 = @intCast(@max(1, terrain_height));

    return switch (rng.rand() & 3) {
        0 => .{ .x = @floatFromInt(rng.rand() % width), .y = -40.0 },
        1 => .{ .x = @floatFromInt(rng.rand() % width), .y = @as(f64, @floatFromInt(terrain_height)) + 40.0 },
        2 => .{ .x = -40.0, .y = @floatFromInt(rng.rand() % height) },
        else => .{ .x = @as(f64, @floatFromInt(terrain_width)) + 40.0, .y = @floatFromInt(rng.rand() % height) },
    };
}

pub fn tickSurvivalWaveSpawns(
    allocator: std.mem.Allocator,
    spawn_cooldown: f64,
    frame_dt_ms: f64,
    rng: *Crand,
    player_count: i32,
    survival_elapsed_ms: f64,
    player_experience: i32,
    terrain_width: i32,
    terrain_height: i32,
) !WaveSpawnResult {
    var cooldown = spawn_cooldown - @as(f64, @floatFromInt(player_count)) * frame_dt_ms;

    var spawns: std.ArrayList(CreatureInit) = .empty;
    defer spawns.deinit(allocator);

    if (cooldown > -1.0) {
        return .{
            .cooldown = cooldown,
            .spawns = try spawns.toOwnedSlice(allocator),
        };
    }

    var interval_ms: i32 = 500 - @divTrunc(@as(i32, @intFromFloat(survival_elapsed_ms)), 1800);
    if (interval_ms < 0) {
        const extra: i32 = @divTrunc(1 - interval_ms, 2);
        interval_ms += extra * 2;
        for (0..@as(usize, @intCast(extra))) |_| {
            const pos = randSurvivalSpawnPos(rng, terrain_width, terrain_height);
            try spawns.append(allocator, buildSurvivalSpawnCreature(pos, rng, player_experience));
        }
    }

    if (interval_ms < 1) interval_ms = 1;
    cooldown += @floatFromInt(interval_ms);

    const pos = randSurvivalSpawnPos(rng, terrain_width, terrain_height);
    try spawns.append(allocator, buildSurvivalSpawnCreature(pos, rng, player_experience));

    return .{
        .cooldown = cooldown,
        .spawns = try spawns.toOwnedSlice(allocator),
    };
}

pub fn tickSurvivalWaveSpawnsCount(
    spawn_cooldown: f64,
    frame_dt_ms: f64,
    rng: *Crand,
    player_count: i32,
    survival_elapsed_ms: f64,
    player_experience: i32,
    terrain_width: i32,
    terrain_height: i32,
) WaveSpawnCountResult {
    var cooldown = spawn_cooldown - @as(f64, @floatFromInt(player_count)) * frame_dt_ms;
    var count: usize = 0;

    if (cooldown > -1.0) {
        return .{
            .cooldown = cooldown,
            .spawn_count = count,
        };
    }

    var interval_ms: i32 = 500 - @divTrunc(@as(i32, @intFromFloat(survival_elapsed_ms)), 1800);
    if (interval_ms < 0) {
        const extra: i32 = @divTrunc(1 - interval_ms, 2);
        interval_ms += extra * 2;
        for (0..@as(usize, @intCast(extra))) |_| {
            const pos = randSurvivalSpawnPos(rng, terrain_width, terrain_height);
            _ = buildSurvivalSpawnCreature(pos, rng, player_experience);
            count += 1;
        }
    }

    if (interval_ms < 1) interval_ms = 1;
    cooldown += @floatFromInt(interval_ms);

    const pos = randSurvivalSpawnPos(rng, terrain_width, terrain_height);
    _ = buildSurvivalSpawnCreature(pos, rng, player_experience);
    count += 1;

    return .{
        .cooldown = cooldown,
        .spawn_count = count,
    };
}

pub fn tickSurvivalWaveSpawnsBatch(
    spawn_cooldown: f64,
    frame_dt_ms: f64,
    rng: *Crand,
    player_count: i32,
    survival_elapsed_ms: f64,
    player_experience: i32,
    terrain_width: i32,
    terrain_height: i32,
) WaveSpawnBatchResult {
    var result = WaveSpawnBatchResult{
        .cooldown = spawn_cooldown - @as(f64, @floatFromInt(player_count)) * frame_dt_ms,
        .count = 0,
    };

    if (result.cooldown > -1.0) {
        return result;
    }

    var interval_ms: i32 = 500 - @divTrunc(@as(i32, @intFromFloat(survival_elapsed_ms)), 1800);
    if (interval_ms < 0) {
        const extra: i32 = @divTrunc(1 - interval_ms, 2);
        interval_ms += extra * 2;
        for (0..@as(usize, @intCast(extra))) |_| {
            if (result.count >= result.spawns.len) break;
            const pos = randSurvivalSpawnPos(rng, terrain_width, terrain_height);
            result.spawns[result.count] = buildSurvivalSpawnCreature(pos, rng, player_experience);
            result.count += 1;
        }
    }

    if (interval_ms < 1) interval_ms = 1;
    result.cooldown += @floatFromInt(interval_ms);

    if (result.count < result.spawns.len) {
        const pos = randSurvivalSpawnPos(rng, terrain_width, terrain_height);
        result.spawns[result.count] = buildSurvivalSpawnCreature(pos, rng, player_experience);
        result.count += 1;
    }

    return result;
}

pub fn advanceSurvivalSpawnStage(
    stage_in: i32,
    player_level: i32,
) SpawnStageResult {
    var result = SpawnStageResult{
        .stage = stage_in,
    };
    var stage = stage_in;
    const heading = std.math.pi;
    const level = player_level;

    while (true) {
        if (stage == 0) {
            if (level < 5) break;
            stage = 1;
            appendSpawnCall(&result, SpawnId.formation_ring_alien_8_12, -164.0, 512.0, heading);
            appendSpawnCall(&result, SpawnId.formation_ring_alien_8_12, 1188.0, 512.0, heading);
            continue;
        }
        if (stage == 1) {
            if (level < 9) break;
            stage = 2;
            appendSpawnCall(&result, SpawnId.alien_const_red_boss_2c, 1088.0, 512.0, heading);
            continue;
        }
        if (stage == 2) {
            if (level < 11) break;
            stage = 3;
            const step = 128.0 / 3.0;
            for (0..12) |idx| {
                appendSpawnCall(
                    &result,
                    SpawnId.spider_sp2_random_35,
                    1088.0,
                    @as(f64, @floatFromInt(idx)) * step + 256.0,
                    heading,
                );
            }
            continue;
        }
        if (stage == 3) {
            if (level < 13) break;
            stage = 4;
            for (0..4) |idx| {
                appendSpawnCall(
                    &result,
                    SpawnId.alien_const_red_fast_2b,
                    1088.0,
                    @as(f64, @floatFromInt(idx)) * 64.0 + 384.0,
                    heading,
                );
            }
            continue;
        }
        if (stage == 4) {
            if (level < 15) break;
            stage = 5;
            for (0..4) |idx| {
                appendSpawnCall(
                    &result,
                    SpawnId.spider_sp1_ai7_timer_38,
                    1088.0,
                    @as(f64, @floatFromInt(idx)) * 64.0 + 384.0,
                    heading,
                );
            }
            for (0..4) |idx| {
                appendSpawnCall(
                    &result,
                    SpawnId.spider_sp1_ai7_timer_38,
                    -64.0,
                    @as(f64, @floatFromInt(idx)) * 64.0 + 384.0,
                    heading,
                );
            }
            continue;
        }
        if (stage == 5) {
            if (level < 17) break;
            stage = 6;
            appendSpawnCall(&result, SpawnId.spider_sp1_const_shock_boss_3a, 1088.0, 512.0, heading);
            continue;
        }
        if (stage == 6) {
            if (level < 19) break;
            stage = 7;
            appendSpawnCall(&result, SpawnId.spider_sp2_splitter_01, 640.0, 512.0, heading);
            continue;
        }
        if (stage == 7) {
            if (level < 21) break;
            stage = 8;
            appendSpawnCall(&result, SpawnId.spider_sp2_splitter_01, 384.0, 256.0, heading);
            appendSpawnCall(&result, SpawnId.spider_sp2_splitter_01, 640.0, 768.0, heading);
            continue;
        }
        if (stage == 8) {
            if (level < 26) break;
            stage = 9;
            for (0..4) |idx| {
                appendSpawnCall(
                    &result,
                    SpawnId.spider_sp1_const_ranged_variant_3c,
                    1088.0,
                    @as(f64, @floatFromInt(idx)) * 64.0 + 384.0,
                    heading,
                );
            }
            for (0..4) |idx| {
                appendSpawnCall(
                    &result,
                    SpawnId.spider_sp1_const_ranged_variant_3c,
                    -64.0,
                    @as(f64, @floatFromInt(idx)) * 64.0 + 384.0,
                    heading,
                );
            }
            continue;
        }
        if (stage == 9) {
            if (level <= 31) break;
            stage = 10;
            appendSpawnCall(&result, SpawnId.spider_sp1_const_shock_boss_3a, 1088.0, 512.0, heading);
            appendSpawnCall(&result, SpawnId.spider_sp1_const_shock_boss_3a, -64.0, 512.0, heading);
            for (0..4) |idx| {
                appendSpawnCall(
                    &result,
                    SpawnId.spider_sp1_const_ranged_variant_3c,
                    @as(f64, @floatFromInt(idx)) * 64.0 + 384.0,
                    -64.0,
                    heading,
                );
            }
            for (0..4) |idx| {
                appendSpawnCall(
                    &result,
                    SpawnId.spider_sp1_const_ranged_variant_3c,
                    @as(f64, @floatFromInt(idx)) * 64.0 + 384.0,
                    1088.0,
                    heading,
                );
            }
            continue;
        }
        break;
    }

    result.stage = stage;
    return result;
}

fn allocCreature(template_id: i32, pos: Vec2, rng: *Crand) CreatureInit {
    const phase_seed = @as(f64, @floatFromInt(rng.rand() & 0x17f));
    return .{
        .origin_template_id = template_id,
        .pos = pos,
        .phase_seed = phase_seed,
    };
}

fn clamp01(value: f64) f64 {
    if (value < 0.0) return 0.0;
    if (value > 1.0) return 1.0;
    return value;
}

fn applyTint(creature: *CreatureInit, tint: [4]f64) void {
    creature.tint = tint;
}

fn appendSpawnCall(
    result: *SpawnStageResult,
    template_id: i32,
    x: f64,
    y: f64,
    heading: f64,
) void {
    std.debug.assert(result.count < result.calls.len);
    result.calls[result.count] = .{
        .template_id = template_id,
        .pos = .{ .x = x, .y = y },
        .heading = heading,
    };
    result.count += 1;
}

fn expectFloatClose(expected: f64, actual: f64) !void {
    try std.testing.expectApproxEqAbs(expected, actual, 1e-6);
}

test "survival wave no trigger" {
    var rng = Crand.init(123);
    const allocator = std.testing.allocator;
    const out = try tickSurvivalWaveSpawns(
        allocator,
        100.0,
        16.0,
        &rng,
        2,
        0.0,
        0,
        1024,
        1024,
    );
    defer out.deinit(allocator);

    try expectFloatClose(68.0, out.cooldown);
    try std.testing.expectEqual(@as(usize, 0), out.spawns.len);
    try std.testing.expectEqual(@as(u32, 123), rng.state);
}

test "survival wave single spawn" {
    var rng = Crand.init(1);
    const allocator = std.testing.allocator;
    const out = try tickSurvivalWaveSpawns(
        allocator,
        -1.0,
        0.0,
        &rng,
        1,
        0.0,
        0,
        1024,
        1024,
    );
    defer out.deinit(allocator);

    try expectFloatClose(499.0, out.cooldown);
    try std.testing.expectEqual(@as(usize, 1), out.spawns.len);
    const creature = out.spawns[0];
    try expectFloatClose(35.0, creature.pos.x);
    try expectFloatClose(1064.0, creature.pos.y);
    try std.testing.expect(creature.type_id == .alien);
    try expectFloatClose(85.0, creature.health);
    try expectFloatClose(336.0, creature.reward_value);
    try std.testing.expectEqual(@as(u32, 0xA6E9C9A6), rng.state);
}

test "survival wave extra spawns on negative interval" {
    var rng = Crand.init(1);
    const allocator = std.testing.allocator;
    const out = try tickSurvivalWaveSpawns(
        allocator,
        -1.0,
        0.0,
        &rng,
        1,
        905_400.0,
        0,
        1024,
        1024,
    );
    defer out.deinit(allocator);

    try expectFloatClose(0.0, out.cooldown);
    try std.testing.expectEqual(@as(usize, 3), out.spawns.len);
    const expected_pos = [_][2]f64{
        .{ 35.0, 1064.0 },
        .{ 1064.0, 947.0 },
        .{ -40.0, 435.0 },
    };
    for (out.spawns, expected_pos) |spawn, expected| {
        try expectFloatClose(expected[0], spawn.pos.x);
        try expectFloatClose(expected[1], spawn.pos.y);
    }
    try std.testing.expect(out.spawns[0].type_id == .alien);
    try std.testing.expect(out.spawns[1].type_id == .alien);
    try std.testing.expect(out.spawns[2].type_id == .spider_sp1);
    try std.testing.expectEqual(@as(u32, 0xBB25E9C6), rng.state);
}

test "survival spawn baseline seed1 xp0" {
    var rng = Crand.init(1);
    const creature = buildSurvivalSpawnCreature(.{ .x = 1.0, .y = 2.0 }, &rng, 0);

    try std.testing.expect(creature.type_id == .alien);
    try std.testing.expectEqual(@as(u32, 0), creature.flags);
    try std.testing.expectEqual(@as(i32, 0), creature.ai_mode);
    try expectFloatClose(44.0, creature.size);
    try expectFloatClose(@floatCast(@as(f32, @as(f32, 15.0) * @as(f32, 0.01))), creature.heading);
    try expectFloatClose(@floatCast(@as(f32, 0.9)), creature.move_speed);
    try expectFloatClose(64.0, creature.health);
    try expectFloatClose(64.0, creature.max_health);
    try expectFloatClose(4.19047619047619, creature.contact_damage);
    try expectFloatClose(36.36190466653733, creature.reward_value);
    try expectFloatClose(0.9, creature.tint[0]);
    try expectFloatClose(0.88, creature.tint[1]);
    try expectFloatClose(0.78, creature.tint[2]);
    try expectFloatClose(1.0, creature.tint[3]);
    try std.testing.expectEqual(@as(u32, 0xC1BBB05F), rng.state);
}

test "survival spawn xp threshold 25000 consumes extra rand" {
    var rng_24999 = Crand.init(1);
    const creature_24999 = buildSurvivalSpawnCreature(.{ .x = 1.0, .y = 2.0 }, &rng_24999, 24_999);
    try std.testing.expect(creature_24999.type_id == .spider_sp1);
    try std.testing.expect((creature_24999.flags & CreatureFlags.ai7_link_timer) != 0);
    try std.testing.expectEqual(@as(u32, 0xC1BBB05F), rng_24999.state);

    var rng_25000 = Crand.init(1);
    const creature_25000 = buildSurvivalSpawnCreature(.{ .x = 1.0, .y = 2.0 }, &rng_25000, 25_000);
    try std.testing.expect(creature_25000.type_id == .spider_sp1);
    try std.testing.expect((creature_25000.flags & CreatureFlags.ai7_link_timer) != 0);
    try std.testing.expectEqual(@as(u32, 0xA6E9C9A6), rng_25000.state);
}

test "survival spawn zombie speed floor and health scale" {
    var rng = Crand.init(1);
    const creature = buildSurvivalSpawnCreature(.{ .x = 1.0, .y = 2.0 }, &rng, 90_000);
    try std.testing.expect(creature.type_id == .zombie);
    try std.testing.expectEqual(@as(u32, 0), creature.flags);
    try expectFloatClose(@floatCast(@as(f32, 1.3)), creature.move_speed);
    try expectFloatClose(264.75, creature.health);
    try expectFloatClose(264.75, creature.max_health);
    try std.testing.expectEqual(@as(u32, 0xC1BBB05F), rng.state);
}

test "survival spawn rare variants" {
    const cases = [_]struct {
        seed: u32,
        expected_size: f64,
        expected_contact_damage: f64,
        expected_health: f64,
        expected_reward_value: f64,
        expected_tint_r: f64,
        expected_tint_g: f64,
        expected_tint_b: f64,
        expected_rng_state: u32,
    }{
        .{
            .seed = 0x66,
            .expected_size = 47.0,
            .expected_contact_damage = 4.476190476190476,
            .expected_health = 65.0,
            .expected_reward_value = 256.0,
            .expected_tint_r = 0.9,
            .expected_tint_g = 0.4,
            .expected_tint_b = 0.4,
            .expected_rng_state = 0xFF51C012,
        },
        .{
            .seed = 0x51,
            .expected_size = 57.0,
            .expected_contact_damage = 5.428571428571428,
            .expected_health = 85.0,
            .expected_reward_value = 336.0,
            .expected_tint_r = 0.4,
            .expected_tint_g = 0.9,
            .expected_tint_b = 0.4,
            .expected_rng_state = 0xE157C2DC,
        },
        .{
            .seed = 0x6A,
            .expected_size = 56.0,
            .expected_contact_damage = 5.333333333333333,
            .expected_health = 125.0,
            .expected_reward_value = 416.0,
            .expected_tint_r = 0.4,
            .expected_tint_g = 0.4,
            .expected_tint_b = 0.9,
            .expected_rng_state = 0x444FED00,
        },
        .{
            .seed = 0x422,
            .expected_size = 80.0,
            .expected_contact_damage = 4.857142857142857,
            .expected_health = 287.0,
            .expected_reward_value = 480.0,
            .expected_tint_r = 0.84,
            .expected_tint_g = 0.24,
            .expected_tint_b = 0.89,
            .expected_rng_state = 0xEC494E99,
        },
        .{
            .seed = 0x43,
            .expected_size = 85.0,
            .expected_contact_damage = 4.857142857142857,
            .expected_health = 2290.0,
            .expected_reward_value = 720.0,
            .expected_tint_r = 0.94,
            .expected_tint_g = 0.84,
            .expected_tint_b = 0.29,
            .expected_rng_state = 0x6B953591,
        },
    };

    for (cases) |case| {
        var rng = Crand.init(case.seed);
        const creature = buildSurvivalSpawnCreature(.{ .x = 1.0, .y = 2.0 }, &rng, 0);
        try std.testing.expect(creature.type_id == .alien);
        try std.testing.expectEqual(@as(u32, 0), creature.flags);
        try std.testing.expectEqual(@as(i32, 0), creature.ai_mode);
        try expectFloatClose(case.expected_size, creature.size);
        try expectFloatClose(case.expected_contact_damage, creature.contact_damage);
        try expectFloatClose(case.expected_health, creature.health);
        try expectFloatClose(case.expected_health, creature.max_health);
        try expectFloatClose(case.expected_reward_value, creature.reward_value);
        try expectFloatClose(case.expected_tint_r, creature.tint[0]);
        try expectFloatClose(case.expected_tint_g, creature.tint[1]);
        try expectFloatClose(case.expected_tint_b, creature.tint[2]);
        try expectFloatClose(1.0, creature.tint[3]);
        try std.testing.expectEqual(case.expected_rng_state, rng.state);
    }
}

test "survival milestone thresholds" {
    const cases = [_]struct {
        stage: i32,
        level: i32,
        expected_stage: i32,
        expected_count: usize,
    }{
        .{ .stage = 0, .level = 4, .expected_stage = 0, .expected_count = 0 },
        .{ .stage = 0, .level = 5, .expected_stage = 1, .expected_count = 2 },
        .{ .stage = 0, .level = 20, .expected_stage = 7, .expected_count = 29 },
        .{ .stage = 1, .level = 8, .expected_stage = 1, .expected_count = 0 },
        .{ .stage = 1, .level = 9, .expected_stage = 2, .expected_count = 1 },
        .{ .stage = 2, .level = 10, .expected_stage = 2, .expected_count = 0 },
        .{ .stage = 2, .level = 11, .expected_stage = 3, .expected_count = 12 },
        .{ .stage = 3, .level = 13, .expected_stage = 4, .expected_count = 4 },
        .{ .stage = 4, .level = 15, .expected_stage = 5, .expected_count = 8 },
        .{ .stage = 5, .level = 17, .expected_stage = 6, .expected_count = 1 },
        .{ .stage = 6, .level = 19, .expected_stage = 7, .expected_count = 1 },
        .{ .stage = 7, .level = 21, .expected_stage = 8, .expected_count = 2 },
        .{ .stage = 8, .level = 26, .expected_stage = 9, .expected_count = 8 },
        .{ .stage = 9, .level = 31, .expected_stage = 9, .expected_count = 0 },
        .{ .stage = 9, .level = 32, .expected_stage = 10, .expected_count = 10 },
    };

    for (cases) |case| {
        const out = advanceSurvivalSpawnStage(case.stage, case.level);
        try std.testing.expectEqual(case.expected_stage, out.stage);
        try std.testing.expectEqual(case.expected_count, out.count);
    }
}

test "survival milestone stage2 grid positions" {
    const out = advanceSurvivalSpawnStage(2, 11);
    try std.testing.expectEqual(@as(i32, 3), out.stage);
    try std.testing.expectEqual(@as(usize, 12), out.count);

    for (out.slice()) |spawn| {
        try std.testing.expectEqual(SpawnId.spider_sp2_random_35, spawn.template_id);
        try expectFloatClose(std.math.pi, spawn.heading);
    }
    try expectFloatClose(1088.0, out.calls[0].pos.x);
    try expectFloatClose(256.0, out.calls[0].pos.y);
    try expectFloatClose(1088.0, out.calls[out.count - 1].pos.x);
    try expectFloatClose(256.0 + 11.0 * (128.0 / 3.0), out.calls[out.count - 1].pos.y);
}

test "survival milestone stage9 final wave layout" {
    const out = advanceSurvivalSpawnStage(9, 32);
    try std.testing.expectEqual(@as(i32, 10), out.stage);
    try std.testing.expectEqual(@as(usize, 10), out.count);

    try std.testing.expectEqual(SpawnId.spider_sp1_const_shock_boss_3a, out.calls[0].template_id);
    try std.testing.expectEqual(SpawnId.spider_sp1_const_shock_boss_3a, out.calls[1].template_id);
    try expectFloatClose(1088.0, out.calls[0].pos.x);
    try expectFloatClose(512.0, out.calls[0].pos.y);
    try expectFloatClose(-64.0, out.calls[1].pos.x);
    try expectFloatClose(512.0, out.calls[1].pos.y);

    for (out.calls[2..6]) |spawn| {
        try std.testing.expectEqual(SpawnId.spider_sp1_const_ranged_variant_3c, spawn.template_id);
        try expectFloatClose(-64.0, spawn.pos.y);
    }
    for (out.calls[6..10]) |spawn| {
        try std.testing.expectEqual(SpawnId.spider_sp1_const_ranged_variant_3c, spawn.template_id);
        try expectFloatClose(1088.0, spawn.pos.y);
    }
}
