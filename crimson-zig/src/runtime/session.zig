const std = @import("std");
const game_ids = @import("../game_ids.zig");
const replay_codec = @import("../replay_codec.zig");

const bonus_runtime = @import("bonuses.zig");
const runtime_bootstrap = @import("bootstrap.zig");
const creatures_mod = @import("creatures.zig");
const effects_mod = @import("effects.zig");
const terrain_fx_mod = @import("terrain_fx.zig");
const particles_mod = @import("particles.zig");
const player_runtime = @import("player.zig");
const projectiles_mod = @import("projectiles.zig");
const secondary_projectiles_mod = @import("secondary_projectiles.zig");
const spawn_mod = @import("spawn.zig");
const state_mod = @import("state.zig");

pub const max_sim_quest_spawn_entries: usize = 1024;
pub const DeterministicSessionError = error{
    InvalidPlayerCount,
    InvalidWorldSize,
    InvalidTickRate,
    UnsupportedGameMode,
    InvalidQuestSpawnTable,
};

pub const SessionConfig = struct {
    seed: u32,
    game_mode: game_ids.GameModeId,
    player_count: i32,
    world_size: f32,
    tick_rate: i32,
    detail_preset: i32 = 5,
    violence_disabled: i32 = 0,
    hardcore: bool = false,
    preserve_bugs: bool = false,
    quest_fail_retry_count: i32 = 0,
    status_quest_unlock_index: i32 = 0,
    status_quest_unlock_index_full: i32 = 0,
    status_weapon_usage_counts: [state_mod.weapon_count_size]u32 = [_]u32{0} ** state_mod.weapon_count_size,
    quest_stage_major: i32 = 0,
    quest_stage_minor: i32 = 0,
    demo_mode_active: bool = false,
    initial_creature_pool: []const replay_codec.ReplayCreatureSlotResidue = &.{},

    pub fn fromReplayHeader(header: replay_codec.ReplayHeader) DeterministicSessionError!SessionConfig {
        const game_mode = std.enums.fromInt(game_ids.GameModeId, header.game_mode_id) orelse {
            return error.UnsupportedGameMode;
        };

        var config: SessionConfig = .{
            .seed = header.seed,
            .game_mode = game_mode,
            .player_count = header.player_count,
            .world_size = header.world_size,
            .tick_rate = header.tick_rate,
            .detail_preset = header.detail_preset,
            .violence_disabled = header.violence_disabled,
            .hardcore = header.hardcore,
            .preserve_bugs = header.preserve_bugs,
            .quest_fail_retry_count = header.quest_fail_retry_count,
            .status_quest_unlock_index = header.status.quest_unlock_index,
            .status_quest_unlock_index_full = header.status.quest_unlock_index_full,
            .initial_creature_pool = header.initial_creature_pool orelse &.{},
        };

        for (header.status.weapon_usage_counts, 0..) |count, idx| {
            if (idx >= config.status_weapon_usage_counts.len) break;
            config.status_weapon_usage_counts[idx] = count;
        }

        if (runtime_bootstrap.resolveQuestLevelKey(header)) |level_key| {
            config.quest_stage_major = @divTrunc(level_key, 100);
            config.quest_stage_minor = @mod(level_key, 100);
        }

        return config;
    }
};

pub const SessionInitOptions = struct {
    strict_events: bool = true,
    defer_menu_open_events: bool = false,
    apply_world_dt_steps: bool = true,
    capture_spawn_events_authoritative: bool = false,
    quest_start_weapon_id_for_reset: i32 = @intFromEnum(game_ids.WeaponId.pistol),
    quest_spawn_entries: ?[]const spawn_mod.QuestSpawnEntry = null,
};

pub const SessionSummary = struct {
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

pub const DeterministicSession = struct {
    state: state_mod.GameplayState,
    players_storage: [state_mod.max_players]state_mod.PlayerState = undefined,
    players_len: usize,

    creatures: creatures_mod.CreaturePool = .{},
    effects: effects_mod.EffectPool = .{},
    sprite_effects: effects_mod.SpriteEffectPool = .{},
    terrain_fx: terrain_fx_mod.TerrainFxScratch = .{},
    particles: particles_mod.ParticlePool = .{},
    projectiles: projectiles_mod.ProjectilePool = .{},
    secondary_projectiles: secondary_projectiles_mod.SecondaryProjectilePool = .{},
    bonuses: bonus_runtime.BonusPool = .{},
    tick_bonus_pickups: bonus_runtime.BonusPickupBuffer = .{},

    game_mode: game_ids.GameModeId,
    player_count: i32,
    quest_unlock_index: i32,
    perk_progression_enabled: bool,
    world_size: f32,
    detail_preset: i32,
    gore_disabled: i32,
    terrain_size: i32,
    dt_nominal: f32,

    strict_events: bool,
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

    pub fn init(
        config: SessionConfig,
        options: SessionInitOptions,
    ) DeterministicSessionError!DeterministicSession {
        if (config.player_count <= 0 or config.player_count > state_mod.max_players) {
            return error.InvalidPlayerCount;
        }
        if (!std.math.isFinite(config.world_size) or config.world_size <= 0.0) {
            return error.InvalidWorldSize;
        }
        if (config.tick_rate <= 0) {
            return error.InvalidTickRate;
        }
        const terrain_size_floor = @floor(config.world_size);
        if (terrain_size_floor > @as(f32, @floatFromInt(std.math.maxInt(i32)))) {
            return error.InvalidWorldSize;
        }

        var session: DeterministicSession = .{
            .state = state_mod.GameplayState.init(config.seed),
            .players_len = @intCast(config.player_count),
            .game_mode = config.game_mode,
            .player_count = config.player_count,
            .quest_unlock_index = config.status_quest_unlock_index,
            .perk_progression_enabled = config.game_mode != .rush and config.game_mode != .typo,
            .world_size = config.world_size,
            .detail_preset = config.detail_preset,
            .gore_disabled = config.violence_disabled,
            .terrain_size = @max(@as(i32, 1), @as(i32, @intFromFloat(terrain_size_floor))),
            .dt_nominal = 1.0 / @as(f32, @floatFromInt(config.tick_rate)),
            .strict_events = options.strict_events,
            .defer_menu_open_events = options.defer_menu_open_events,
            .apply_world_dt_steps = options.apply_world_dt_steps,
            .capture_spawn_events_authoritative = options.capture_spawn_events_authoritative,
            .quest_start_weapon_id_for_reset = options.quest_start_weapon_id_for_reset,
            .quest_spawn_entries = undefined,
        };

        session.quest_spawn_entries = session.quest_spawn_entries_storage[0..0];

        session.state.gore_disabled = config.violence_disabled;
        session.state.game_mode = config.game_mode;
        session.state.hardcore = config.hardcore;
        session.state.preserve_bugs = config.preserve_bugs;
        session.state.demo_mode_active = config.demo_mode_active;
        session.state.quest_fail_retry_count = config.quest_fail_retry_count;
        session.state.status_quest_unlock_index = config.status_quest_unlock_index;
        session.state.status_quest_unlock_index_full = config.status_quest_unlock_index_full;
        session.state.quest_stage_major = config.quest_stage_major;
        session.state.quest_stage_minor = config.quest_stage_minor;

        for (config.status_weapon_usage_counts, 0..) |count, idx| {
            if (idx >= state_mod.weapon_count_size) break;
            const weapon_id: game_ids.WeaponId = @enumFromInt(idx);
            session.state.status_weapon_usage_counts.set(weapon_id, count);
        }

        session.creatures.hardcore = config.hardcore;
        session.creatures.demo_mode_active = config.demo_mode_active;
        session.creatures.quest_fail_retry_count = config.quest_fail_retry_count;

        session.creatures.applyGameplayResetTargetPlayers(config.player_count);
        creatures_mod.applyPoolResidue(&session.creatures, config.initial_creature_pool);
        player_runtime.initializePlayers(session.players());
        player_runtime.resetPlayers(session.players(), config.world_size, null);
        session.creatures.capture_spawn_events_authoritative = options.capture_spawn_events_authoritative;
        session.creatures.effects = &session.effects;

        if (config.game_mode == .rush) {
            runtime_bootstrap.enforceRushLoadout(session.players());
        }

        runtime_bootstrap.advanceReplayBootstrapRng(
            &session.state.rng,
            config.game_mode,
            config.status_quest_unlock_index,
            session.terrain_size,
            session.terrain_size,
        );

        if (options.quest_spawn_entries) |quest_spawn_entries| {
            try session.setQuestSpawnEntries(quest_spawn_entries);
        }
        if (options.capture_spawn_events_authoritative) {
            session.reset_quest_spawn_entries_len = 0;
            session.quest_spawn_entries = session.quest_spawn_entries_storage[0..0];
        }

        return session;
    }

    pub fn initFromReplayHeader(
        header: replay_codec.ReplayHeader,
        options: SessionInitOptions,
    ) DeterministicSessionError!DeterministicSession {
        return init(try SessionConfig.fromReplayHeader(header), options);
    }

    pub fn rebindQuestSpawnEntries(self: *DeterministicSession) void {
        self.quest_spawn_entries = self.quest_spawn_entries_storage[0..self.reset_quest_spawn_entries_len];
    }

    pub fn rebindInternalPointers(self: *DeterministicSession) void {
        self.rebindQuestSpawnEntries();
        self.creatures.effects = &self.effects;
    }

    pub fn players(self: *DeterministicSession) []state_mod.PlayerState {
        return self.players_storage[0..self.players_len];
    }

    pub fn playersConst(self: *const DeterministicSession) []const state_mod.PlayerState {
        return self.players_storage[0..self.players_len];
    }

    pub fn finalize(self: *const DeterministicSession) SessionSummary {
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

    pub fn setQuestSpawnEntries(
        self: *DeterministicSession,
        entries: []const spawn_mod.QuestSpawnEntry,
    ) DeterministicSessionError!void {
        if (entries.len > self.quest_spawn_entries_storage.len) {
            return error.InvalidQuestSpawnTable;
        }
        @memcpy(self.quest_spawn_entries_storage[0..entries.len], entries);
        self.reset_quest_spawn_entries_len = entries.len;
        self.quest_spawn_entries = self.quest_spawn_entries_storage[0..entries.len];
    }
};

fn testHeader(game_mode: game_ids.GameModeId) replay_codec.ReplayHeader {
    return .{
        .game_mode_id = @intFromEnum(game_mode),
        .seed = 0xBEEF,
        .replay_format_version = replay_codec.replay_format_version,
        .quest_level = @constCast("2.7"),
        .game_version = @constCast("test"),
        .tick_rate = 60,
        .quest_fail_retry_count = 0,
        .hardcore = false,
        .preserve_bugs = false,
        .detail_preset = 5,
        .violence_disabled = 1,
        .world_size = 1024.0,
        .player_count = 1,
        .status = .{},
        .claimed_stats = .{},
        .input_quantization = @constCast("f32"),
    };
}

test "deterministic session init from header seeds mutable loop state" {
    const header = testHeader(.quests);
    var session = try DeterministicSession.initFromReplayHeader(header, .{});
    session.rebindQuestSpawnEntries();

    try std.testing.expectEqual(@as(usize, 1), session.players().len);
    try std.testing.expectEqual(@as(i32, 1), session.player_count);
    try std.testing.expectEqual(@as(f32, 1.0 / 60.0), session.dt_nominal);
    try std.testing.expectEqual(@as(i32, 2), session.state.quest_stage_major);
    try std.testing.expectEqual(@as(i32, 7), session.state.quest_stage_minor);

    session.tick_index = 3;
    session.fire_pressed_count = 9;
    const summary = session.finalize();
    try std.testing.expectEqual(@as(usize, 3), summary.ticks_processed);
    try std.testing.expectEqual(@as(usize, 9), summary.fire_pressed_count);
}

test "deterministic session init advances survival terrain bootstrap rng" {
    var header = testHeader(.survival);
    header.seed = 0x1234;
    header.status.quest_unlock_index = 0;
    header.world_size = 1024.0;

    var session = try DeterministicSession.initFromReplayHeader(header, .{});
    session.rebindQuestSpawnEntries();

    try std.testing.expectEqual(@as(u32, 623756981), session.state.rng.state);
}

test "deterministic session init round robins native creature targets" {
    var header = testHeader(.survival);
    header.player_count = 2;

    var session = try DeterministicSession.initFromReplayHeader(header, .{});
    session.rebindQuestSpawnEntries();

    try std.testing.expectEqual(@as(i32, 0), session.creatures.entries[0].target_player);
    try std.testing.expectEqual(@as(i32, 1), session.creatures.entries[1].target_player);
    try std.testing.expectEqual(@as(i32, 0), session.creatures.entries[2].target_player);
    try std.testing.expectEqual(@as(i32, 1), session.creatures.entries[3].target_player);
}
