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

    pub fn fromRunSpec(run: replay_codec.RunSpec) SessionConfig {
        var config: SessionConfig = .{
            .seed = run.seed,
            .game_mode = run.game_mode,
            .player_count = run.player_count,
            .world_size = replay_codec.world_size,
            .tick_rate = replay_codec.tick_rate,
            .detail_preset = run.detail_preset,
            .violence_disabled = run.violence_disabled,
            .hardcore = run.hardcore,
            .preserve_bugs = run.preserve_bugs,
            .quest_fail_retry_count = run.quest_fail_retry_count,
            .status_quest_unlock_index = run.status.quest_unlock_index,
            .status_quest_unlock_index_full = run.status.quest_unlock_index_full,
            .demo_mode_active = run.demo,
        };
        comptime std.debug.assert(replay_codec.weapon_usage_count <= state_mod.weapon_count_size);
        @memcpy(config.status_weapon_usage_counts[0..replay_codec.weapon_usage_count], &run.status.weapon_usage_counts);
        if (run.quest_level) |level| {
            config.quest_stage_major = level.major;
            config.quest_stage_minor = level.minor;
        }
        return config;
    }
};

pub const SessionInitOptions = struct {
    quest_spawn_entries: ?[]const spawn_mod.QuestSpawnEntry = null,
};

pub const SessionSummary = struct {
    ticks_processed: usize,
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

    quest_spawn_entries_len: usize = 0,
    quest_spawn_entries_storage: [max_sim_quest_spawn_entries]spawn_mod.QuestSpawnEntry = undefined,

    tick_index: usize = 0,

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
        };

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
        player_runtime.initializePlayers(session.players());
        player_runtime.resetPlayers(session.players(), config.world_size, null);
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

        return session;
    }

    pub fn questSpawnEntries(self: *DeterministicSession) []spawn_mod.QuestSpawnEntry {
        return self.quest_spawn_entries_storage[0..self.quest_spawn_entries_len];
    }

    /// Elapsed run time as scored: the spawn timeline for quests, session time otherwise.
    pub fn runElapsedMs(self: *const DeterministicSession) f64 {
        return switch (self.game_mode) {
            .quests => self.quest_spawn_timeline_ms,
            .rush => @floatFromInt(self.elapsed_ms_sim_rush),
            else => self.elapsed_ms_sim,
        };
    }

    /// Outcome when the last tick ends the run in live play, else null.
    pub fn terminalOutcome(self: *const DeterministicSession) ?replay_codec.RunOutcome {
        const players_list = self.playersConst();
        return switch (self.game_mode) {
            .survival => if (deathTransitionReady(players_list)) .death else null,
            // Rush and Typ-o end as soon as nobody is alive; there is no
            // death animation hold (Typ-o plays it outside ticks).
            .rush, .typo => if (allPlayersDead(players_list)) .death else null,
            .quests => if (self.quest_completed)
                .quest_completed
            else if (deathTransitionReady(players_list)) .death else null,
            .tutorial => null,
        };
    }

    /// Outcome of a run whose recording stops after the last simulated tick.
    pub fn endOutcome(self: *const DeterministicSession) replay_codec.RunOutcome {
        if (self.terminalOutcome()) |outcome| return outcome;
        return switch (self.game_mode) {
            // The failed-quest countdown keeps running while paused, so a
            // failed run may close between ticks before the death animation ends.
            .quests => if (allPlayersDead(self.playersConst())) .death else .incomplete,
            // The tutorial has no terminal tick: players leave it from the UI.
            .tutorial => if (self.state.tutorial.stage_index >= 8) .tutorial_completed else .incomplete,
            .survival, .rush, .typo => .incomplete,
        };
    }

    pub fn rebindInternalPointers(self: *DeterministicSession) void {
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
        self.quest_spawn_entries_len = entries.len;
    }
};

pub fn allPlayersDead(players: []const state_mod.PlayerState) bool {
    if (players.len == 0) return false;
    for (players) |player| {
        if (player.health > 0.0) return false;
    }
    return true;
}

/// Every player is dead and their death animation has finished.
pub fn deathTransitionReady(players: []const state_mod.PlayerState) bool {
    if (!allPlayersDead(players)) return false;
    for (players) |player| {
        if (!(player.death_timer < 0.0)) return false;
    }
    return true;
}

fn testConfig(game_mode: game_ids.GameModeId) SessionConfig {
    return SessionConfig.fromRunSpec(.{
        .game_mode = game_mode,
        .seed = 0xBEEF,
        .quest_level = if (game_mode == .quests) .{ .major = 2, .minor = 7 } else null,
        .violence_disabled = 1,
    });
}

test "deterministic session init from run spec seeds mutable loop state" {
    var session = try DeterministicSession.init(testConfig(.quests), .{});

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
    var config = testConfig(.survival);
    config.seed = 0x1234;

    const session = try DeterministicSession.init(config, .{});

    try std.testing.expectEqual(@as(u32, 623756981), session.state.rng.state);
}

test "deterministic session init round robins native creature targets" {
    var config = testConfig(.survival);
    config.player_count = 2;

    const session = try DeterministicSession.init(config, .{});

    try std.testing.expectEqual(@as(i32, 0), session.creatures.entries[0].target_player);
    try std.testing.expectEqual(@as(i32, 1), session.creatures.entries[1].target_player);
    try std.testing.expectEqual(@as(i32, 0), session.creatures.entries[2].target_player);
    try std.testing.expectEqual(@as(i32, 1), session.creatures.entries[3].target_player);
}

test "terminal and end outcomes follow each mode's end condition" {
    var survival = try DeterministicSession.init(testConfig(.survival), .{});
    survival.players()[0].health = 0.0;
    try std.testing.expectEqual(@as(?replay_codec.RunOutcome, null), survival.terminalOutcome());
    survival.players()[0].death_timer = -0.5;
    try std.testing.expectEqual(@as(?replay_codec.RunOutcome, .death), survival.terminalOutcome());

    var rush = try DeterministicSession.init(testConfig(.rush), .{});
    rush.players()[0].health = -1.0;
    try std.testing.expectEqual(@as(?replay_codec.RunOutcome, .death), rush.terminalOutcome());

    var quest = try DeterministicSession.init(testConfig(.quests), .{});
    quest.players()[0].health = 0.0;
    try std.testing.expectEqual(@as(?replay_codec.RunOutcome, null), quest.terminalOutcome());
    try std.testing.expectEqual(replay_codec.RunOutcome.death, quest.endOutcome());
    quest.quest_completed = true;
    try std.testing.expectEqual(@as(?replay_codec.RunOutcome, .quest_completed), quest.terminalOutcome());

    var tutorial = try DeterministicSession.init(testConfig(.tutorial), .{});
    tutorial.players()[0].health = 0.0;
    try std.testing.expectEqual(replay_codec.RunOutcome.incomplete, tutorial.endOutcome());
    tutorial.state.tutorial.stage_index = 8;
    try std.testing.expectEqual(replay_codec.RunOutcome.tutorial_completed, tutorial.endOutcome());
}
