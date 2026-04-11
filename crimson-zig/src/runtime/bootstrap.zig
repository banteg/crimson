const std = @import("std");
const game_ids = @import("../game_ids.zig");
const rng_callers = @import("../rng_caller_static.zig");
const replay_codec = @import("../replay_codec.zig");

const player_runtime = @import("player.zig");
const spawn_mod = @import("spawn.zig");
const state_mod = @import("state.zig");

const terrain_density_base: u64 = 800;
const terrain_density_overlay: u64 = 0x23;
const terrain_density_detail: u64 = 0x0F;
const terrain_density_shift: u6 = 19;
const terrain_rand_draws_per_stamp: u64 = 3;
const rush_forced_ammo: f32 = 30.0;

pub const TerrainSlotTriplet = [3]u8;

pub const TerrainSetup = struct {
    terrain_slots: TerrainSlotTriplet,
    terrain_seed: u32,
};

const TerrainGenerationKind = enum {
    explicit,
    unlock_random,
};

const TerrainStampCallerTriplet = struct {
    rotation: rng_callers.Caller,
    y: rng_callers.Caller,
    x: rng_callers.Caller,
};

const default_terrain_slots: TerrainSlotTriplet = .{ 0, 1, 0 };

const unlock_terrain_slots = [_]struct {
    threshold: i32,
    slots: TerrainSlotTriplet,
}{
    .{ .threshold = 40, .slots = .{ 6, 7, 6 } },
    .{ .threshold = 30, .slots = .{ 4, 5, 4 } },
    .{ .threshold = 20, .slots = .{ 2, 3, 2 } },
};

const unlock_random_terrain_prelude_callers = [_]rng_callers.Caller{
    rng_callers.terrain_generate_random_prelude_1,
    rng_callers.terrain_generate_random_prelude_2,
    rng_callers.terrain_generate_random_prelude_3,
};

const unlock_random_terrain_stamp_callers = [_]TerrainStampCallerTriplet{
    .{
        .rotation = rng_callers.terrain_generate_random_base_rotation,
        .y = rng_callers.terrain_generate_random_base_y,
        .x = rng_callers.terrain_generate_random_base_x,
    },
    .{
        .rotation = rng_callers.terrain_generate_random_overlay_rotation,
        .y = rng_callers.terrain_generate_random_overlay_y,
        .x = rng_callers.terrain_generate_random_overlay_x,
    },
    .{
        .rotation = rng_callers.terrain_generate_random_detail_rotation,
        .y = rng_callers.terrain_generate_random_detail_y,
        .x = rng_callers.terrain_generate_random_detail_x,
    },
};

const explicit_terrain_stamp_callers = [_]TerrainStampCallerTriplet{
    .{
        .rotation = rng_callers.terrain_generate_base_rotation,
        .y = rng_callers.terrain_generate_base_y,
        .x = rng_callers.terrain_generate_base_x,
    },
    .{
        .rotation = rng_callers.terrain_generate_overlay_rotation,
        .y = rng_callers.terrain_generate_overlay_y,
        .x = rng_callers.terrain_generate_overlay_x,
    },
    .{
        .rotation = rng_callers.terrain_generate_detail_rotation,
        .y = rng_callers.terrain_generate_detail_y,
        .x = rng_callers.terrain_generate_detail_x,
    },
};

pub const ParsedQuestLevel = struct {
    major: i32,
    minor: i32,
};

pub fn parseQuestLevel(value: []const u8) ?ParsedQuestLevel {
    const dot = std.mem.indexOfScalar(u8, value, '.') orelse return null;
    if (dot == 0 or dot + 1 >= value.len) return null;
    const major = std.fmt.parseInt(i32, value[0..dot], 10) catch return null;
    const minor = std.fmt.parseInt(i32, value[dot + 1 ..], 10) catch return null;
    return .{
        .major = major,
        .minor = minor,
    };
}

pub fn resolveQuestLevelKey(header: replay_codec.ReplayHeader) ?i32 {
    if (parseQuestLevel(header.quest_level)) |parsed| {
        if (parsed.major >= 1 and parsed.major <= 5 and parsed.minor >= 1 and parsed.minor <= 10) {
            return parsed.major * 100 + parsed.minor;
        }
    }
    if (header.seed > @as(u32, @intCast(std.math.maxInt(i32)))) return null;
    const seed_i32: i32 = @intCast(header.seed);
    const major = @divTrunc(seed_i32, 100);
    const minor = @mod(seed_i32, 100);
    if (major < 1 or major > 5 or minor < 1 or minor > 10) return null;
    return major * 100 + minor;
}

pub fn applyQuestStageFromHeader(
    state: *state_mod.GameplayState,
    header: replay_codec.ReplayHeader,
) void {
    if (resolveQuestLevelKey(header)) |level_key| {
        state.quest_stage_major = @divTrunc(level_key, 100);
        state.quest_stage_minor = @mod(level_key, 100);
        return;
    }
    state.quest_stage_major = 0;
    state.quest_stage_minor = 0;
}

pub fn enforceRushLoadout(players: []state_mod.PlayerState) void {
    for (players) |*player| {
        if (player.weapon.weapon_id != game_ids.WeaponId.assault_rifle) {
            player_runtime.weaponAssignPlayer(player, game_ids.WeaponId.assault_rifle);
        }
        player.weapon.ammo = rush_forced_ammo;
    }
}

pub fn advanceReplayBootstrapRng(
    rng: *spawn_mod.Crand,
    game_mode: game_ids.GameModeId,
    unlock_index: i32,
    terrain_width: i32,
    terrain_height: i32,
) void {
    switch (game_mode) {
        .survival, .rush, .typo, .tutorial => {
            advanceUnlockTerrainRng(rng, unlock_index, terrain_width, terrain_height);
        },
        .quests => {
            advanceUnlockTerrainRng(rng, unlock_index, terrain_width, terrain_height);
            _ = rng.randTagged(rng_callers.quest_start_selected_highscore_random_tag);
            advanceTerrainStampingRng(rng, terrain_width, terrain_height, .explicit);
        },
    }
}

pub fn previewUnlockTerrain(
    seed: u32,
    unlock_index: i32,
    terrain_width: i32,
    terrain_height: i32,
) TerrainSetup {
    var rng = spawn_mod.Crand.init(seed);
    return advanceUnlockTerrain(
        &rng,
        unlock_index,
        terrain_width,
        terrain_height,
    );
}

pub fn previewExplicitTerrain(
    seed: u32,
    terrain_slots: TerrainSlotTriplet,
    terrain_width: i32,
    terrain_height: i32,
) TerrainSetup {
    var rng = spawn_mod.Crand.init(seed);
    return advanceExplicitTerrain(
        &rng,
        terrain_slots,
        terrain_width,
        terrain_height,
    );
}

pub fn terrainSlotsForQuestLevelKey(level_key: i32) ?TerrainSlotTriplet {
    const major = @divTrunc(level_key, 100);
    const minor = @mod(level_key, 100);
    if (major < 1 or major > 5 or minor < 1 or minor > 10) return null;

    if (major <= 4) {
        const base: u8 = @intCast((major - 1) * 2);
        const alt: u8 = base + 1;
        if (minor < 6) return .{ base, alt, base };
        return .{ base, base, alt };
    }

    return .{
        @intCast(minor & 3),
        1,
        3,
    };
}

fn terrainStampingDraws(width: i32, height: i32) usize {
    const clamped_width: u64 = @intCast(@max(width, 0));
    const clamped_height: u64 = @intCast(@max(height, 0));
    const area = clamped_width * clamped_height;
    const stamps = ((area * terrain_density_base) >> terrain_density_shift) +
        ((area * terrain_density_overlay) >> terrain_density_shift) +
        ((area * terrain_density_detail) >> terrain_density_shift);
    return @intCast(stamps * terrain_rand_draws_per_stamp);
}

fn advanceUnlockTerrainRng(
    rng: *spawn_mod.Crand,
    unlock_index: i32,
    width: i32,
    height: i32,
) void {
    _ = advanceUnlockTerrain(rng, unlock_index, width, height);
}

pub fn advanceUnlockTerrain(
    rng: *spawn_mod.Crand,
    unlock_index: i32,
    width: i32,
    height: i32,
) TerrainSetup {
    advanceRandomTerrainPreludeRng(rng);
    const terrain_slots = chooseUnlockTerrainSlots(rng, unlock_index);
    const terrain_seed = rng.state;
    advanceTerrainStampingRng(rng, width, height, .unlock_random);
    return .{
        .terrain_slots = terrain_slots,
        .terrain_seed = terrain_seed,
    };
}

pub fn advanceExplicitTerrain(
    rng: *spawn_mod.Crand,
    terrain_slots: TerrainSlotTriplet,
    width: i32,
    height: i32,
) TerrainSetup {
    const terrain_seed = rng.state;
    advanceTerrainStampingRng(rng, width, height, .explicit);
    return .{
        .terrain_slots = terrain_slots,
        .terrain_seed = terrain_seed,
    };
}

fn chooseUnlockTerrainSlots(
    rng: *spawn_mod.Crand,
    unlock_index: i32,
) TerrainSlotTriplet {
    for (unlock_terrain_slots) |entry| {
        const caller = switch (entry.threshold) {
            40 => rng_callers.unlock_terrain_q4,
            30 => rng_callers.unlock_terrain_q3,
            20 => rng_callers.unlock_terrain_q2,
            else => unreachable,
        };
        if (unlock_index >= entry.threshold and (rng.randTagged(caller) & 7) == 3) {
            return entry.slots;
        }
    }
    return default_terrain_slots;
}

fn advanceRandomTerrainPreludeRng(rng: *spawn_mod.Crand) void {
    for (unlock_random_terrain_prelude_callers) |caller| {
        _ = rng.randTagged(caller);
    }
}

fn advanceTerrainStampingRng(
    rng: *spawn_mod.Crand,
    width: i32,
    height: i32,
    generation_kind: TerrainGenerationKind,
) void {
    const caller_sets = switch (generation_kind) {
        .unlock_random => unlock_random_terrain_stamp_callers[0..],
        .explicit => explicit_terrain_stamp_callers[0..],
    };
    const clamped_width: u64 = @intCast(@max(width, 0));
    const clamped_height: u64 = @intCast(@max(height, 0));
    const area = clamped_width * clamped_height;
    const densities = [_]u64{ terrain_density_base, terrain_density_overlay, terrain_density_detail };
    for (caller_sets, densities) |callers, density| {
        const count = (area * density) >> terrain_density_shift;
        for (0..count) |_| {
            _ = rng.randTagged(callers.rotation);
            _ = rng.randTagged(callers.y);
            _ = rng.randTagged(callers.x);
        }
    }
}

test "preview unlock terrain matches replay bootstrap rng advance for survival" {
    const terrain = previewUnlockTerrain(0xBEEF, 30, 1024, 1024);

    var expected_rng = spawn_mod.Crand.init(0xBEEF);
    advanceRandomTerrainPreludeRng(&expected_rng);
    const expected_slots = chooseUnlockTerrainSlots(&expected_rng, 30);
    const expected_seed = expected_rng.state;
    advanceTerrainStampingRng(&expected_rng, 1024, 1024, .unlock_random);

    var rng = spawn_mod.Crand.init(0xBEEF);
    advanceReplayBootstrapRng(&rng, .survival, 30, 1024, 1024);

    try std.testing.expectEqualDeep(expected_slots, terrain.terrain_slots);
    try std.testing.expectEqual(expected_seed, terrain.terrain_seed);
    try std.testing.expectEqual(expected_rng.state, rng.state);
}

test "terrain slots for quest level key mirror quest stage mapping" {
    try std.testing.expectEqualDeep(@as(TerrainSlotTriplet, .{ 0, 1, 0 }), terrainSlotsForQuestLevelKey(101).?);
    try std.testing.expectEqualDeep(@as(TerrainSlotTriplet, .{ 0, 0, 1 }), terrainSlotsForQuestLevelKey(106).?);
    try std.testing.expectEqualDeep(@as(TerrainSlotTriplet, .{ 2, 3, 2 }), terrainSlotsForQuestLevelKey(201).?);
    try std.testing.expectEqualDeep(@as(TerrainSlotTriplet, .{ 2, 2, 3 }), terrainSlotsForQuestLevelKey(206).?);
    try std.testing.expectEqualDeep(@as(TerrainSlotTriplet, .{ 1, 1, 3 }), terrainSlotsForQuestLevelKey(505).?);
    try std.testing.expect(terrainSlotsForQuestLevelKey(0) == null);
    try std.testing.expect(terrainSlotsForQuestLevelKey(511) == null);
}

test "preview explicit terrain preserves slot choice and advances stamping rng" {
    const slots: TerrainSlotTriplet = .{ 2, 2, 3 };
    const terrain = previewExplicitTerrain(0xBEEF, slots, 1024, 1024);

    var rng = spawn_mod.Crand.init(0xBEEF);
    const expected_seed = rng.state;
    advanceTerrainStampingRng(&rng, 1024, 1024, .explicit);

    try std.testing.expectEqualDeep(slots, terrain.terrain_slots);
    try std.testing.expectEqual(expected_seed, terrain.terrain_seed);
    try std.testing.expectEqual(rng.state, blk: {
        var verify_rng = spawn_mod.Crand.init(0xBEEF);
        _ = advanceExplicitTerrain(&verify_rng, slots, 1024, 1024);
        break :blk verify_rng.state;
    });
}
