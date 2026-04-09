const std = @import("std");
const game_ids = @import("../game_ids.zig");
const replay_codec = @import("../replay_codec.zig");

const player_runtime = @import("player.zig");
const spawn_mod = @import("spawn.zig");
const state_mod = @import("state.zig");

const terrain_random_prelude_draws: usize = 3;
const terrain_density_base: u64 = 800;
const terrain_density_overlay: u64 = 0x23;
const terrain_density_detail: u64 = 0x0F;
const terrain_density_shift: u6 = 19;
const terrain_rand_draws_per_stamp: u64 = 3;
const rush_forced_ammo: f32 = 30.0;

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
            _ = rng.rand();
            advanceRng(rng, terrainStampingDraws(terrain_width, terrain_height));
        },
    }
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

fn advanceRng(rng: *spawn_mod.Crand, draws: usize) void {
    for (0..draws) |_| _ = rng.rand();
}

fn advanceUnlockTerrainRng(
    rng: *spawn_mod.Crand,
    unlock_index: i32,
    width: i32,
    height: i32,
) void {
    advanceRng(rng, terrain_random_prelude_draws);
    if (unlock_index >= 40 and (rng.rand() & 7) == 3) {
        advanceRng(rng, terrainStampingDraws(width, height));
        return;
    }
    if (unlock_index >= 30 and (rng.rand() & 7) == 3) {
        advanceRng(rng, terrainStampingDraws(width, height));
        return;
    }
    if (unlock_index >= 20 and (rng.rand() & 7) == 3) {
        advanceRng(rng, terrainStampingDraws(width, height));
        return;
    }
    advanceRng(rng, terrainStampingDraws(width, height));
}
