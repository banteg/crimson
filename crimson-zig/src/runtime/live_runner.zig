const std = @import("std");
const game_ids = @import("../game_ids.zig");

const perks = @import("perks.zig");
const player_runtime = @import("player.zig");
const projectiles = @import("projectiles.zig");
const quest_spawn_logic = @import("../quest_spawn/logic_full.zig");
const replay_step = @import("replay/step.zig");
const runtime_bootstrap = @import("bootstrap.zig");
const runtime_session = @import("session.zig");
const session_builders = @import("session_builders.zig");
const spawn_mod = @import("spawn.zig");
const state_mod = @import("state.zig");
const creatures = @import("creatures.zig");
const survival_progression = @import("survival_progression.zig");

pub const LiveRunnerError = runtime_session.DeterministicSessionError ||
    replay_step.StepError ||
    perks.PerkApplyError;

const max_frame_dt: f32 = 0.25;
const epsilon_dt: f32 = 1e-6;

pub const LiveModeConfig = struct {
    seed: u32 = 1,
    game_mode: game_ids.GameModeId = .survival,
    quest_level_key: i32 = 101,
    player_count: i32 = 1,
    world_size: f32 = 1024.0,
    tick_rate: i32 = 60,
    detail_preset: i32 = 5,
    gore_disabled: i32 = 0,
    hardcore: bool = false,
    preserve_bugs: bool = false,
    status_quest_unlock_index: i32 = 0,
    status_quest_unlock_index_full: i32 = 0,
};

pub const LiveSurvivalConfig = LiveModeConfig;

pub const FrameInput = struct {
    player: player_runtime.GameInput = defaultGameInput(),
    perk_choice_index: ?i32 = null,
};

pub const ShotAudioEvent = struct {
    weapon_id: i32,
    fire_bullets_active: bool,
};

pub const FrameAudioEvents = struct {
    shot_events: [8]ShotAudioEvent = [_]ShotAudioEvent{.{
        .weapon_id = 0,
        .fire_bullets_active = false,
    }} ** 8,
    shot_event_count: usize = 0,
    reload_weapon_ids: [8]i32 = [_]i32{0} ** 8,
    reload_event_count: usize = 0,
    hit_events: [4]creatures.HitSfxPlan = [_]creatures.HitSfxPlan{.{}} ** 4,
    hit_event_count: usize = 0,
    trigger_game_tune: bool = false,
    perk_menu_opened: bool = false,
    quest_play_hit_sfx: bool = false,
    quest_play_completion_music: bool = false,

    fn appendShot(self: *FrameAudioEvents, weapon_id: game_ids.WeaponId, fire_bullets_active: bool) void {
        if (self.shot_event_count >= self.shot_events.len) return;
        self.shot_events[self.shot_event_count] = .{
            .weapon_id = @intFromEnum(weapon_id),
            .fire_bullets_active = fire_bullets_active,
        };
        self.shot_event_count += 1;
    }

    fn appendReload(self: *FrameAudioEvents, weapon_id: game_ids.WeaponId) void {
        if (self.reload_event_count >= self.reload_weapon_ids.len) return;
        self.reload_weapon_ids[self.reload_event_count] = @intFromEnum(weapon_id);
        self.reload_event_count += 1;
    }

    fn appendHitPlans(self: *FrameAudioEvents, tick_stats: projectiles.ProjectileTickStats) void {
        self.trigger_game_tune = self.trigger_game_tune or tick_stats.hit_audio_trigger_game_tune;
        var idx: usize = 0;
        while (idx < tick_stats.hit_audio_event_count and self.hit_event_count < self.hit_events.len) : (idx += 1) {
            self.hit_events[self.hit_event_count] = tick_stats.hit_audio_events[idx];
            self.hit_event_count += 1;
        }
    }
};

pub const FrameUpdate = struct {
    ticks_advanced: usize,
    paused_for_perk_pick: bool,
    all_players_dead: bool,
    player_health: f32,
    player_level: i32,
    player_experience: i32,
    player_weapon_id: i32,
    creature_active_count: usize,
    bonus_active_count: usize,
    elapsed_ms_sim: i64,
    shots_fired: i32,
    shots_hit: i32,
    audio: FrameAudioEvents,
};

pub fn defaultGameInput() player_runtime.GameInput {
    return .{
        .move_x = 0.0,
        .move_y = 0.0,
        .aim_x = 0.0,
        .aim_y = 0.0,
        .flags = .{
            .fire_down = false,
            .fire_pressed = false,
            .reload_pressed = false,
        },
    };
}

pub const LiveRunner = struct {
    seed: u32,
    terrain_setup: runtime_bootstrap.TerrainSetup,
    quest_level_key: ?i32 = null,
    session: runtime_session.DeterministicSession,
    accumulator: f32 = 0.0,
    max_substeps_per_frame: usize = 8,

    pub fn init(config: LiveModeConfig) LiveRunnerError!LiveRunner {
        const base_config: runtime_session.SessionConfig = .{
            .seed = config.seed,
            .game_mode = config.game_mode,
            .player_count = config.player_count,
            .world_size = config.world_size,
            .tick_rate = config.tick_rate,
            .detail_preset = config.detail_preset,
            .gore_disabled = config.gore_disabled,
            .hardcore = config.hardcore,
            .preserve_bugs = config.preserve_bugs,
            .status_quest_unlock_index = config.status_quest_unlock_index,
            .status_quest_unlock_index_full = config.status_quest_unlock_index_full,
        };
        const terrain_size = @max(1, @as(i32, @intFromFloat(@floor(config.world_size))));

        var terrain_setup: runtime_bootstrap.TerrainSetup = undefined;
        var quest_level_key: ?i32 = null;
        var quest_spawn_entries_storage: [runtime_session.max_sim_quest_spawn_entries]spawn_mod.QuestSpawnEntry = undefined;
        const session = switch (config.game_mode) {
            .survival => blk: {
                terrain_setup = runtime_bootstrap.previewUnlockTerrain(
                    config.seed,
                    config.status_quest_unlock_index,
                    terrain_size,
                    terrain_size,
                );
                break :blk try session_builders.buildSurvivalSession(base_config, .{});
            },
            .rush => blk: {
                terrain_setup = runtime_bootstrap.previewUnlockTerrain(
                    config.seed,
                    config.status_quest_unlock_index,
                    terrain_size,
                    terrain_size,
                );
                break :blk try session_builders.buildRushSession(base_config, .{});
            },
            .quests => blk: {
                quest_level_key = config.quest_level_key;
                const terrain_slots = runtime_bootstrap.terrainSlotsForQuestLevelKey(config.quest_level_key) orelse
                    return error.UnsupportedQuestSpawnTable;
                const built = quest_spawn_logic.buildQuestSpawnTable(
                    config.quest_level_key,
                    config.player_count,
                    config.seed,
                    config.world_size,
                    quest_spawn_entries_storage[0..],
                ) catch |err| switch (err) {
                    error.UnsupportedQuestSpawnTable => return error.UnsupportedQuestSpawnTable,
                    error.OutOfSpace => return error.UnsupportedQuestSpawnTable,
                };
                const quest_entries = quest_spawn_entries_storage[0..built.entries.len];
                if (config.hardcore) {
                    spawn_mod.applyHardcoreQuestSpawnTableAdjustment(quest_entries);
                }

                var terrain_rng = spawn_mod.Crand.init(config.seed);
                _ = runtime_bootstrap.advanceUnlockTerrain(
                    &terrain_rng,
                    config.status_quest_unlock_index,
                    terrain_size,
                    terrain_size,
                );
                _ = terrain_rng.rand();
                terrain_setup = runtime_bootstrap.advanceExplicitTerrain(
                    &terrain_rng,
                    terrain_slots,
                    terrain_size,
                    terrain_size,
                );

                break :blk try session_builders.buildQuestSession(
                    .{
                        .seed = base_config.seed,
                        .game_mode = .quests,
                        .player_count = base_config.player_count,
                        .world_size = base_config.world_size,
                        .tick_rate = base_config.tick_rate,
                        .detail_preset = base_config.detail_preset,
                        .gore_disabled = base_config.gore_disabled,
                        .hardcore = base_config.hardcore,
                        .preserve_bugs = base_config.preserve_bugs,
                        .status_quest_unlock_index = base_config.status_quest_unlock_index,
                        .status_quest_unlock_index_full = base_config.status_quest_unlock_index_full,
                        .quest_stage_major = @divTrunc(config.quest_level_key, 100),
                        .quest_stage_minor = @mod(config.quest_level_key, 100),
                    },
                    .{
                        .quest_spawn_entries = quest_entries,
                        .quest_start_weapon_id = @intFromEnum(built.start_weapon_id),
                    },
                );
            },
            else => return error.UnsupportedGameMode,
        };

        return .{
            .seed = config.seed,
            .terrain_setup = terrain_setup,
            .quest_level_key = quest_level_key,
            .session = session,
        };
    }

    pub fn stepFrame(self: *LiveRunner, frame_dt: f32, input: FrameInput) LiveRunnerError!FrameUpdate {
        const clamped_dt = std.math.clamp(frame_dt, @as(f32, 0.0), max_frame_dt);
        if (input.perk_choice_index) |choice_index| {
            _ = try self.pickPerk(choice_index, clamped_dt);
        }

        const paused_for_perk_pick = self.perkPendingCount() > 0;
        if (self.allPlayersDead() or paused_for_perk_pick or !(frame_dt > 0.0)) {
            return self.snapshot(0, paused_for_perk_pick, .{});
        }

        self.accumulator = std.math.clamp(self.accumulator + clamped_dt, @as(f32, 0.0), max_frame_dt);

        var ticks_advanced: usize = 0;
        var frame_audio: FrameAudioEvents = .{};
        const tick_inputs = [_]player_runtime.GameInput{input.player};
        while (ticks_advanced < self.max_substeps_per_frame and
            !self.allPlayersDead() and
            self.perkPendingCount() <= 0 and
            self.accumulator + epsilon_dt >= self.session.dt_nominal)
        {
            const before_player = self.player0Const().?.*;
            const before_perk_pending = self.perkPendingCount();
            const before_quest_hit_sfx = self.session.quest_play_hit_sfx;
            const before_quest_completion_music = self.session.quest_play_completion_music;
            const step_result = try replay_step.stepTick(
                &self.session,
                self.session.tick_index,
                tick_inputs[0..],
                &.{},
                self.session.dt_nominal,
                .{},
            );
            const after_player = self.player0Const().?.*;
            if (after_player.shot_seq > before_player.shot_seq) {
                frame_audio.appendShot(after_player.weapon.weapon_id, after_player.fire_bullets_timer > 0.0);
            }
            const reload_started = (!before_player.weapon.reload_active and after_player.weapon.reload_active) or
                (after_player.weapon.reload_timer > before_player.weapon.reload_timer + 1e-6);
            if (reload_started) {
                frame_audio.appendReload(after_player.weapon.weapon_id);
            }
            if (before_perk_pending <= 0 and self.perkPendingCount() > 0) {
                frame_audio.perk_menu_opened = true;
            }
            frame_audio.appendHitPlans(step_result.projectile_tick_stats);
            frame_audio.quest_play_hit_sfx = frame_audio.quest_play_hit_sfx or
                (!before_quest_hit_sfx and self.session.quest_play_hit_sfx);
            frame_audio.quest_play_completion_music = frame_audio.quest_play_completion_music or
                (!before_quest_completion_music and self.session.quest_play_completion_music);
            self.accumulator = @max(0.0, self.accumulator - self.session.dt_nominal);
            ticks_advanced += 1;
        }

        return self.snapshot(ticks_advanced, self.perkPendingCount() > 0, frame_audio);
    }

    pub fn perkPendingCount(self: *const LiveRunner) i32 {
        return self.session.state.perk_selection.pending_count;
    }

    pub fn currentPerkChoices(self: *LiveRunner) []const game_ids.PerkId {
        return perks.perkSelectionCurrentChoices(
            &self.session.state,
            self.session.players(),
            self.session.game_mode,
            self.session.player_count,
            self.session.quest_unlock_index,
        );
    }

    pub fn pickPerk(self: *LiveRunner, choice_index: i32, frame_dt: f32) LiveRunnerError!bool {
        const dt_sim = survival_progression.timeScaleReflexBoostBonus(
            self.session.state.bonuses.reflex_boost,
            self.session.state.time_scale_active,
            frame_dt,
        );
        const picked = try perks.perkSelectionPickWithContext(
            &self.session.state,
            self.session.players(),
            choice_index,
            self.session.game_mode,
            self.session.player_count,
            self.session.quest_unlock_index,
            .{
                .creatures = &self.session.creatures,
                .dt_frame = dt_sim,
            },
        );
        return picked != null;
    }

    pub fn allPlayersDead(self: *const LiveRunner) bool {
        const players = self.session.playersConst();
        if (players.len == 0) return true;
        for (players) |player| {
            if (player.health > 0.0) return false;
        }
        return true;
    }

    pub fn player0(self: *LiveRunner) ?*state_mod.PlayerState {
        const players = self.session.players();
        if (players.len == 0) return null;
        return &players[0];
    }

    pub fn player0Const(self: *const LiveRunner) ?*const state_mod.PlayerState {
        const players = self.session.playersConst();
        if (players.len == 0) return null;
        return &players[0];
    }

    pub fn summary(self: *const LiveRunner) runtime_session.SessionSummary {
        return self.session.finalize();
    }

    fn snapshot(
        self: *const LiveRunner,
        ticks_advanced: usize,
        paused_for_perk_pick: bool,
        audio: FrameAudioEvents,
    ) FrameUpdate {
        const run_summary = self.session.finalize();
        const player_health = if (self.player0Const()) |player| player.health else 0.0;
        var shots_hit_total: i32 = 0;
        for (self.session.state.shots_hit) |shots_hit| {
            shots_hit_total += shots_hit;
        }
        return .{
            .ticks_advanced = ticks_advanced,
            .paused_for_perk_pick = paused_for_perk_pick,
            .all_players_dead = self.allPlayersDead(),
            .player_health = player_health,
            .player_level = run_summary.player_level,
            .player_experience = run_summary.player_experience,
            .player_weapon_id = run_summary.player_weapon_id,
            .creature_active_count = run_summary.creature_active_count,
            .bonus_active_count = self.session.bonuses.activeCount(),
            .elapsed_ms_sim = run_summary.elapsed_ms_sim,
            .shots_fired = self.session.state.shots_fired_total,
            .shots_hit = shots_hit_total,
            .audio = audio,
        };
    }
};

pub const LiveSurvivalRunner = LiveRunner;

test "live survival runner bootstraps pistol survival session" {
    var runner = try LiveSurvivalRunner.init(.{});
    try std.testing.expectEqual(game_ids.GameModeId.survival, runner.session.game_mode);
    try std.testing.expectEqual(@as(usize, 1), runner.session.players().len);
    try std.testing.expectEqual(game_ids.WeaponId.pistol, runner.session.players()[0].weapon.weapon_id);
}

test "live runner bootstraps rush session with forced assault rifle" {
    var runner = try LiveRunner.init(.{
        .game_mode = .rush,
    });
    try std.testing.expectEqual(game_ids.GameModeId.rush, runner.session.game_mode);
    try std.testing.expectEqual(game_ids.WeaponId.assault_rifle, runner.session.players()[0].weapon.weapon_id);
    try std.testing.expectEqual(@as(f32, 30.0), runner.session.players()[0].weapon.ammo);
}

test "live runner bootstraps quest session from level key" {
    var runner = try LiveRunner.init(.{
        .game_mode = .quests,
        .quest_level_key = 205,
    });
    try std.testing.expectEqual(game_ids.GameModeId.quests, runner.session.game_mode);
    try std.testing.expectEqual(@as(?i32, 205), runner.quest_level_key);
    try std.testing.expectEqual(@as(i32, 2), runner.session.state.quest_stage_major);
    try std.testing.expectEqual(@as(i32, 5), runner.session.state.quest_stage_minor);
    try std.testing.expectEqual(game_ids.WeaponId.gauss_gun, runner.session.players()[0].weapon.weapon_id);
    try std.testing.expectEqualDeep(@as(runtime_bootstrap.TerrainSlotTriplet, .{ 2, 3, 2 }), runner.terrain_setup.terrain_slots);
}

test "live survival runner advances fixed ticks from frame time" {
    var runner = try LiveSurvivalRunner.init(.{});
    const update = try runner.stepFrame(
        runner.session.dt_nominal,
        .{
            .player = .{
                .move_x = 1.0,
                .move_y = 0.0,
                .aim_x = 700.0,
                .aim_y = 512.0,
                .flags = .{
                    .fire_down = false,
                    .fire_pressed = false,
                    .reload_pressed = false,
                    .move_mode = 3,
                    .aim_scheme = 0,
                },
            },
        },
    );
    try std.testing.expectEqual(@as(usize, 1), update.ticks_advanced);
    try std.testing.expectEqual(@as(usize, 1), runner.session.tick_index);
}

test "live survival runner pauses for pending perk picks" {
    var runner = try LiveSurvivalRunner.init(.{});
    runner.session.state.perk_selection.pending_count = 1;
    runner.session.state.perk_selection.choices_dirty = true;

    const blocked = try runner.stepFrame(runner.session.dt_nominal, .{});
    try std.testing.expectEqual(@as(usize, 0), blocked.ticks_advanced);
    try std.testing.expect(blocked.paused_for_perk_pick);

    const choices = runner.currentPerkChoices();
    try std.testing.expect(choices.len > 0);
    try std.testing.expect(try runner.pickPerk(0, runner.session.dt_nominal));
    try std.testing.expectEqual(@as(i32, 0), runner.perkPendingCount());
}

test "live survival runner reports dead run state" {
    var runner = try LiveSurvivalRunner.init(.{});
    runner.session.players()[0].health = 0.0;

    const update = try runner.stepFrame(runner.session.dt_nominal, .{});
    try std.testing.expect(update.all_players_dead);
    try std.testing.expectEqual(@as(usize, 0), update.ticks_advanced);
}

test "live survival runner perk picks apply immediate creature effects" {
    var runner = try LiveSurvivalRunner.init(.{});
    runner.session.state.perk_selection.pending_count = 1;
    runner.session.state.perk_selection.choice_count = 1;
    runner.session.state.perk_selection.choices[0] = .breathing_room;
    runner.session.state.perk_selection.choices_dirty = false;
    runner.session.creatures.entries[0].active = true;
    runner.session.creatures.entries[0].lifecycle_stage = 5.0;

    try std.testing.expect(try runner.pickPerk(0, 0.25));
    try std.testing.expectApproxEqAbs(@as(f32, 4.75), runner.session.creatures.entries[0].lifecycle_stage, 1e-6);
}
