const std = @import("std");
const game_ids = @import("../../game_ids.zig");
const replay_codec = @import("../../replay_codec.zig");

const bonus_runtime = @import("../bonuses.zig");
const creatures_mod = @import("../creatures.zig");
const particles_mod = @import("../particles.zig");
const player_runtime = @import("../player.zig");
const projectiles_mod = @import("../projectiles.zig");
const secondary_projectiles_mod = @import("../secondary_projectiles.zig");
const spawn_mod = @import("../spawn.zig");
const state_mod = @import("../state.zig");

const capture_state = @import("capture_state.zig");

pub const max_sim_quest_spawn_entries: usize = 1024;
const terrain_random_prelude_draws: usize = 3;
const terrain_density_base: u64 = 800;
const terrain_density_overlay: u64 = 0x23;
const terrain_density_detail: u64 = 0x0F;
const terrain_density_shift: u6 = 19;
const terrain_rand_draws_per_stamp: u64 = 3;

pub const SimulationContextError = error{
    InvalidPlayerCount,
    InvalidWorldSize,
    InvalidTickRate,
    UnsupportedGameMode,
    UnsupportedQuestSpawnTable,
};

pub const HeaderInitOptions = struct {
    strict_events: bool = true,
    inter_tick_rand_draws: i32 = 0,
    defer_menu_open_events: bool = false,
    apply_world_dt_steps: bool = true,
    capture_spawn_events_authoritative: bool = false,
    quest_start_weapon_id_for_reset: i32 = @intFromEnum(game_ids.WeaponId.pistol),
    quest_spawn_entries: ?[]const spawn_mod.QuestSpawnEntry = null,
};

pub const FinalizeSummary = struct {
    ticks_processed: usize,
    event_index: usize,
    elapsed_ms_sim: i64,
    perk_menu_open_count: usize,
    perk_pick_count: usize,
    fire_pressed_count: usize,
    reload_pressed_count: usize,
    stage_spawn_count: usize,
    wave_spawn_count: usize,
    wave_spawn_rng_state: u32,
    player_level: i32,
    player_experience: i32,
    player_weapon_id: i32,
    perk_pending_count: i32,
    creature_active_count: usize,
};

pub const SimulationContext = struct {
    state: state_mod.GameplayState,
    players_storage: [state_mod.max_players]state_mod.PlayerState = undefined,
    players_len: usize,

    creatures: creatures_mod.CreaturePool = .{},
    particles: particles_mod.ParticlePool = .{},
    projectiles: projectiles_mod.ProjectilePool = .{},
    secondary_projectiles: secondary_projectiles_mod.SecondaryProjectilePool = .{},
    bonuses: bonus_runtime.BonusPool = .{},
    tick_bonus_pickups: bonus_runtime.BonusPickupBuffer = .{},

    game_mode: game_ids.GameModeId,
    player_count: i32,
    quest_unlock_index: i32,
    world_size: f32,
    detail_preset: i32,
    gore_disabled: i32,
    terrain_size: i32,
    dt_nominal: f32,

    strict_events: bool,
    inter_tick_rand_draws: i32,
    defer_menu_open_events: bool,
    apply_world_dt_steps: bool,
    capture_spawn_events_authoritative: bool,

    quest_start_weapon_id_for_reset: i32,
    reset_quest_spawn_entries_len: usize = 0,
    quest_spawn_entries_storage: [max_sim_quest_spawn_entries]spawn_mod.QuestSpawnEntry = undefined,
    quest_spawn_entries: []spawn_mod.QuestSpawnEntry,

    tick_index: usize = 0,
    event_index: usize = 0,

    perk_menu_open_count: usize = 0,
    perk_pick_count: usize = 0,
    fire_pressed_count: usize = 0,
    reload_pressed_count: usize = 0,

    stage_spawn_count: usize = 0,
    wave_spawn_count: usize = 0,
    spawn_cooldown: f32 = 0.0,
    spawn_stage: i32 = 0,

    elapsed_ms_sim: f32 = 0.0,
    elapsed_ms_sim_rush: i64 = 0,

    quest_spawn_timeline_ms: f32 = 0.0,
    quest_no_creatures_timer_ms: f32 = 0.0,
    quest_creatures_none_active: bool = false,
    quest_completion_transition_ms: f32 = -1.0,
    quest_completed: bool = false,
    quest_play_hit_sfx: bool = false,
    quest_play_completion_music: bool = false,

    pending_capture_state_reset: bool = false,

    pub fn initFromReplayHeader(
        header: replay_codec.ReplayHeader,
        options: HeaderInitOptions,
    ) SimulationContextError!SimulationContext {
        const game_mode = std.meta.intToEnum(game_ids.GameModeId, header.game_mode_id) catch {
            return error.UnsupportedGameMode;
        };
        if (header.player_count <= 0 or header.player_count > state_mod.max_players) {
            return error.InvalidPlayerCount;
        }
        if (!std.math.isFinite(header.world_size) or header.world_size <= 0.0) {
            return error.InvalidWorldSize;
        }
        if (header.tick_rate <= 0) {
            return error.InvalidTickRate;
        }
        const terrain_size_floor = @floor(header.world_size);
        if (terrain_size_floor > @as(f32, @floatFromInt(std.math.maxInt(i32)))) {
            return error.InvalidWorldSize;
        }

        var context: SimulationContext = .{
            .state = state_mod.GameplayState.init(header.seed),
            .players_len = @intCast(header.player_count),
            .game_mode = game_mode,
            .player_count = header.player_count,
            .quest_unlock_index = header.status.quest_unlock_index,
            .world_size = header.world_size,
            .detail_preset = header.detail_preset,
            .gore_disabled = header.gore_disabled,
            .terrain_size = @max(@as(i32, 1), @as(i32, @intFromFloat(terrain_size_floor))),
            .dt_nominal = 1.0 / @as(f32, @floatFromInt(header.tick_rate)),
            .strict_events = options.strict_events,
            .inter_tick_rand_draws = options.inter_tick_rand_draws,
            .defer_menu_open_events = options.defer_menu_open_events,
            .apply_world_dt_steps = options.apply_world_dt_steps,
            .capture_spawn_events_authoritative = options.capture_spawn_events_authoritative,
            .quest_start_weapon_id_for_reset = options.quest_start_weapon_id_for_reset,
            .quest_spawn_entries = undefined,
        };

        context.quest_spawn_entries = context.quest_spawn_entries_storage[0..0];

        context.state.gore_disabled = header.gore_disabled;
        context.state.game_mode = game_mode;
        context.state.hardcore = header.hardcore;
        context.state.preserve_bugs = header.preserve_bugs;
        context.state.status_quest_unlock_index = header.status.quest_unlock_index;
        context.state.status_quest_unlock_index_full = header.status.quest_unlock_index_full;

        for (header.status.weapon_usage_counts, 0..) |count, idx| {
            if (idx >= state_mod.weapon_count_size) break;
            const weapon_id: game_ids.WeaponId = @enumFromInt(idx);
            context.state.status_weapon_usage_counts.set(weapon_id, count);
        }

        player_runtime.resetPlayers(context.players(), header.world_size, null);
        context.creatures.capture_spawn_events_authoritative = options.capture_spawn_events_authoritative;

        if (game_mode == .rush) {
            capture_state.enforceRushLoadout(context.players());
        } else if (game_mode == .quests) {
            capture_state.applyQuestStageFromHeader(&context.state, header);
        }

        advanceReplayBootstrapRng(
            &context.state.rng,
            game_mode,
            header.status.quest_unlock_index,
            context.terrain_size,
            context.terrain_size,
        );

        if (options.quest_spawn_entries) |quest_spawn_entries| {
            try context.setQuestSpawnEntries(quest_spawn_entries);
        }
        if (options.capture_spawn_events_authoritative) {
            context.reset_quest_spawn_entries_len = 0;
            context.quest_spawn_entries = context.quest_spawn_entries_storage[0..0];
        }

        return context;
    }

    pub fn rebindQuestSpawnEntries(self: *SimulationContext) void {
        self.quest_spawn_entries = self.quest_spawn_entries_storage[0..self.reset_quest_spawn_entries_len];
    }

    pub fn players(self: *SimulationContext) []state_mod.PlayerState {
        return self.players_storage[0..self.players_len];
    }

    pub fn playersConst(self: *const SimulationContext) []const state_mod.PlayerState {
        return self.players_storage[0..self.players_len];
    }

    pub fn finalize(self: *const SimulationContext) FinalizeSummary {
        var player_level: i32 = 0;
        var player_experience: i32 = 0;
        var player_weapon_id: i32 = @intFromEnum(game_ids.WeaponId.pistol);
        if (self.players_len > 0) {
            const player0 = self.players_storage[0];
            player_level = player0.level;
            player_experience = player0.experience;
            player_weapon_id = @intFromEnum(player0.weapon.weapon_id);
        }

        const elapsed_ms_sim_i64: i64 = if (self.game_mode == .rush)
            self.elapsed_ms_sim_rush
        else
            @intFromFloat(self.elapsed_ms_sim);

        return .{
            .ticks_processed = self.tick_index,
            .event_index = self.event_index,
            .elapsed_ms_sim = elapsed_ms_sim_i64,
            .perk_menu_open_count = self.perk_menu_open_count,
            .perk_pick_count = self.perk_pick_count,
            .fire_pressed_count = self.fire_pressed_count,
            .reload_pressed_count = self.reload_pressed_count,
            .stage_spawn_count = self.stage_spawn_count,
            .wave_spawn_count = self.wave_spawn_count,
            .wave_spawn_rng_state = self.state.rng.state,
            .player_level = player_level,
            .player_experience = player_experience,
            .player_weapon_id = player_weapon_id,
            .perk_pending_count = self.state.perk_selection.pending_count,
            .creature_active_count = self.creatures.activeCount(),
        };
    }

    fn setQuestSpawnEntries(
        self: *SimulationContext,
        entries: []const spawn_mod.QuestSpawnEntry,
    ) SimulationContextError!void {
        if (entries.len > self.quest_spawn_entries_storage.len) {
            return error.UnsupportedQuestSpawnTable;
        }
        @memcpy(self.quest_spawn_entries_storage[0..entries.len], entries);
        self.reset_quest_spawn_entries_len = entries.len;
        self.quest_spawn_entries = self.quest_spawn_entries_storage[0..entries.len];
    }
};

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

fn advanceReplayBootstrapRng(
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

fn testHeader(game_mode: game_ids.GameModeId) replay_codec.ReplayHeader {
    return .{
        .game_mode_id = @intFromEnum(game_mode),
        .seed = 0xBEEF,
        .replay_format_version = replay_codec.replay_format_version,
        .quest_level = @constCast("2.7"),
        .bootstrap_kind = @constCast("none"),
        .bootstrap_seed = 0,
        .game_version = @constCast("test"),
        .tick_rate = 60,
        .difficulty_level = 0,
        .hardcore = false,
        .preserve_bugs = false,
        .detail_preset = 5,
        .gore_disabled = 1,
        .world_size = 1024.0,
        .player_count = 1,
        .status = .{},
        .claimed_stats = .{},
        .input_quantization = @constCast("f32"),
    };
}

test "simulation context init from header seeds mutable loop state" {
    const header = testHeader(.quests);
    var context = try SimulationContext.initFromReplayHeader(header, .{});
    context.rebindQuestSpawnEntries();

    try std.testing.expectEqual(@as(usize, 1), context.players().len);
    try std.testing.expectEqual(@as(i32, 1), context.player_count);
    try std.testing.expectEqual(@as(f32, 1.0 / 60.0), context.dt_nominal);
    try std.testing.expectEqual(@as(i32, 2), context.state.quest_stage_major);
    try std.testing.expectEqual(@as(i32, 7), context.state.quest_stage_minor);

    context.tick_index = 3;
    context.fire_pressed_count = 9;
    const summary = context.finalize();
    try std.testing.expectEqual(@as(usize, 3), summary.ticks_processed);
    try std.testing.expectEqual(@as(usize, 9), summary.fire_pressed_count);
}

test "simulation context init advances survival terrain bootstrap rng" {
    var header = testHeader(.survival);
    header.seed = 0x1234;
    header.status.quest_unlock_index = 0;
    header.world_size = 1024.0;

    var context = try SimulationContext.initFromReplayHeader(header, .{});
    context.rebindQuestSpawnEntries();

    try std.testing.expectEqual(@as(u32, 623756981), context.state.rng.state);
}
