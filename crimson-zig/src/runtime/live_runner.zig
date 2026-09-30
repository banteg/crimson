const std = @import("std");
const game_ids = @import("../game_ids.zig");
const replay_codec = @import("../replay_codec.zig");
const rng_callers = @import("../rng_caller_static.zig");

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
const terrain_fx_mod = @import("terrain_fx.zig");
const typo_runtime = @import("../typo/runtime.zig");

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
    violence_disabled: i32 = 0,
    hardcore: bool = false,
    preserve_bugs: bool = false,
    quest_fail_retry_count: i32 = 0,
    status_quest_unlock_index: i32 = 0,
    status_quest_unlock_index_full: i32 = 0,
    status_weapon_usage_counts: [state_mod.weapon_count_size]u32 = [_]u32{0} ** state_mod.weapon_count_size,
};

pub const LiveSurvivalConfig = LiveModeConfig;

pub const FrameInput = struct {
    player: player_runtime.GameInput = defaultGameInput(),
    players: [state_mod.max_players]player_runtime.GameInput = [_]player_runtime.GameInput{defaultGameInput()} ** state_mod.max_players,
    player_count: usize = 0,
    perk_choice_index: ?i32 = null,
    perk_menu_active: bool = false,
    typo_char: ?u21 = null,
    typo_backspace: bool = false,
    typo_submit: bool = false,
};

pub const FrameAudioEvents = struct {
    hit_events: [4]creatures.HitSfxPlan = [_]creatures.HitSfxPlan{.{}} ** 4,
    hit_event_count: usize = 0,
    sfx_events: [state_mod.runtime_sfx_queue_max]state_mod.SfxId = [_]state_mod.SfxId{.ui_bonus} ** state_mod.runtime_sfx_queue_max,
    sfx_event_count: usize = 0,
    trigger_game_tune: bool = false,
    quest_play_hit_sfx: bool = false,
    quest_play_completion_music: bool = false,

    fn appendHitPlans(self: *FrameAudioEvents, tick_stats: projectiles.ProjectileTickStats) void {
        self.trigger_game_tune = self.trigger_game_tune or tick_stats.hit_audio_trigger_game_tune;
        var idx: usize = 0;
        while (idx < tick_stats.hit_audio_event_count and self.hit_event_count < self.hit_events.len) : (idx += 1) {
            self.hit_events[self.hit_event_count] = tick_stats.hit_audio_events[idx];
            self.hit_event_count += 1;
        }
    }

    fn appendSfx(self: *FrameAudioEvents, sfx_id: state_mod.SfxId) void {
        if (self.sfx_event_count >= self.sfx_events.len) return;
        self.sfx_events[self.sfx_event_count] = sfx_id;
        self.sfx_event_count += 1;
    }

    fn appendRuntimeSfx(self: *FrameAudioEvents, sfx_events: []const state_mod.SfxId) void {
        for (sfx_events) |sfx_id| {
            self.appendSfx(sfx_id);
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
    terrain_fx: terrain_fx_mod.TerrainFxBatch,
    /// A requested perk menu opened during this frame's ticks.
    perk_menu_opened: bool = false,
};

pub const LiveRunnerSnapshot = struct {
    runner: LiveRunner,
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
    /// The next tick carries a perk menu request, which opens mid-tick as in native.
    perk_menu_requested: bool = false,
    max_substeps_per_frame: usize = 8,

    pub fn init(config: LiveModeConfig) LiveRunnerError!LiveRunner {
        const base_config: runtime_session.SessionConfig = .{
            .seed = config.seed,
            .game_mode = config.game_mode,
            .player_count = config.player_count,
            .world_size = config.world_size,
            .tick_rate = config.tick_rate,
            .detail_preset = config.detail_preset,
            .violence_disabled = config.violence_disabled,
            .hardcore = config.hardcore,
            .preserve_bugs = config.preserve_bugs,
            .quest_fail_retry_count = config.quest_fail_retry_count,
            .status_quest_unlock_index = config.status_quest_unlock_index,
            .status_quest_unlock_index_full = config.status_quest_unlock_index_full,
            .status_weapon_usage_counts = config.status_weapon_usage_counts,
        };
        const terrain_size = @max(1, @as(i32, @intFromFloat(@floor(config.world_size))));

        var terrain_setup: runtime_bootstrap.TerrainSetup = undefined;
        var quest_level_key: ?i32 = null;
        var quest_spawn_entries_storage: [runtime_session.max_sim_quest_spawn_entries]spawn_mod.QuestSpawnEntry = undefined;
        var session = switch (config.game_mode) {
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
                    return error.InvalidQuestSpawnTable;
                const built = quest_spawn_logic.buildQuestSpawnTableWithHardcore(
                    config.quest_level_key,
                    config.player_count,
                    config.seed,
                    config.world_size,
                    config.hardcore,
                    quest_spawn_entries_storage[0..],
                ) catch |err| switch (err) {
                    error.InvalidQuestSpawnTable => return error.InvalidQuestSpawnTable,
                    error.OutOfSpace => return error.InvalidQuestSpawnTable,
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
                _ = terrain_rng.randTagged(rng_callers.quest_start_selected_highscore_random_tag);
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
                        .violence_disabled = base_config.violence_disabled,
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
            .typo => blk: {
                terrain_setup = runtime_bootstrap.previewUnlockTerrain(
                    config.seed,
                    config.status_quest_unlock_index,
                    terrain_size,
                    terrain_size,
                );
                break :blk try session_builders.buildTypoSession(base_config, .{});
            },
            .tutorial => blk: {
                terrain_setup = runtime_bootstrap.previewUnlockTerrain(
                    config.seed,
                    config.status_quest_unlock_index,
                    terrain_size,
                    terrain_size,
                );
                break :blk try session_builders.buildTutorialSession(base_config, .{});
            },
        };
        session.finishRunSetup();

        return .{
            .seed = config.seed,
            .terrain_setup = terrain_setup,
            .quest_level_key = quest_level_key,
            .session = session,
        };
    }

    pub fn stepFrame(self: *LiveRunner, frame_dt: f32, input: FrameInput) LiveRunnerError!FrameUpdate {
        const clamped_dt = std.math.clamp(frame_dt, @as(f32, 0.0), max_frame_dt);
        if (self.session.game_mode == .typo) {
            if (input.typo_backspace) {
                typo_runtime.applyBackspaceCommand(&self.session.state);
            } else if (input.typo_char) |codepoint| {
                var encoded: [4]u8 = undefined;
                const len = std.unicode.utf8Encode(codepoint, &encoded) catch unreachable;
                typo_runtime.applyCharCommand(&self.session.state, encoded[0..len]);
            }
            if (input.typo_submit) {
                typo_runtime.applySubmitCommand(&self.session.state, &self.session.creatures);
            }
        }
        if (input.perk_choice_index) |choice_index| {
            _ = try self.pickPerk(choice_index, clamped_dt);
        }

        const paused_for_perk_pick = input.perk_menu_active and self.perkPendingCount() > 0;
        if (self.allPlayersDead() or paused_for_perk_pick or !(frame_dt > 0.0)) {
            return self.snapshot(0, paused_for_perk_pick, .{}, .{});
        }

        self.accumulator = std.math.clamp(self.accumulator + clamped_dt, @as(f32, 0.0), max_frame_dt);

        var ticks_advanced: usize = 0;
        var perk_menu_opened = false;
        var frame_audio: FrameAudioEvents = .{};
        var frame_terrain_fx: terrain_fx_mod.TerrainFxScratch = .{};
        const tick_inputs = tickInputsForFrame(input, self.session.playersConst().len);
        while (ticks_advanced < self.max_substeps_per_frame and
            !self.allPlayersDead() and
            !(input.perk_menu_active and self.perkPendingCount() > 0) and
            self.accumulator + epsilon_dt >= self.session.dt_nominal)
        {
            const before_quest_hit_sfx = self.session.quest_play_hit_sfx;
            const before_quest_completion_music = self.session.quest_play_completion_music;
            const open_request = [_]replay_codec.Command{.{ .perk_menu_open = .{ .player_index = 0 } }};
            const before_menu_opens = self.session.perk_menu_open_count;
            const step_result = try replay_step.stepTick(
                &self.session,
                self.session.tick_index,
                tick_inputs.slice(),
                if (self.perk_menu_requested) open_request[0..] else &.{},
                self.session.dt_nominal,
                .{},
            );
            frame_audio.appendHitPlans(step_result.projectile_tick_stats);
            frame_audio.appendRuntimeSfx(step_result.hit_sfx.constSlice());
            frame_audio.appendRuntimeSfx(step_result.sfx_events.constSlice());
            frame_audio.quest_play_hit_sfx = frame_audio.quest_play_hit_sfx or
                (!before_quest_hit_sfx and self.session.quest_play_hit_sfx);
            frame_audio.quest_play_completion_music = frame_audio.quest_play_completion_music or
                (!before_quest_completion_music and self.session.quest_play_completion_music);
            for (step_result.terrain_fx.decalsSlice()) |entry| {
                _ = frame_terrain_fx.decals.add(
                    entry.effect_id,
                    entry.pos,
                    entry.width,
                    entry.height,
                    entry.rotation,
                    entry.color,
                );
            }
            for (step_result.terrain_fx.corpsesSlice()) |entry| {
                _ = frame_terrain_fx.corpses.append(entry);
            }
            self.accumulator = @max(0.0, self.accumulator - self.session.dt_nominal);
            ticks_advanced += 1;
            // The request rode this tick; the menu opened only if native would have.
            self.perk_menu_requested = false;
            if (self.session.perk_menu_open_count > before_menu_opens) {
                perk_menu_opened = true;
                break;
            }
        }

        var update = self.snapshot(ticks_advanced, input.perk_menu_active and self.perkPendingCount() > 0, frame_audio, frame_terrain_fx.takeBatch());
        update.perk_menu_opened = perk_menu_opened;
        return update;
    }

    pub fn perkPendingCount(self: *const LiveRunner) i32 {
        return self.session.state.perk_selection.pending_count;
    }

    pub fn preparedPerkChoices(self: *LiveRunner) []const game_ids.PerkId {
        return perks.perkSelectionPreparedChoices(
            self.session.players(),
            &self.session.state.perk_selection,
        );
    }

    /// Ask the next tick to open the perk menu.
    pub fn requestPerkMenu(self: *LiveRunner) void {
        self.perk_menu_requested = true;
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
        if (picked != null) {
            self.session.perk_pick_count += 1;
        }
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

    pub fn captureSnapshot(self: *const LiveRunner) LiveRunnerSnapshot {
        var captured: LiveRunnerSnapshot = .{ .runner = self.* };
        // Snapshots are movable values. Only restoration has a stable destination
        // at which the session's internal effect-pool pointer can be rebound.
        captured.runner.session.creatures.effects = null;
        return captured;
    }

    pub fn restoreSnapshot(self: *LiveRunner, captured: *const LiveRunnerSnapshot) void {
        self.* = captured.runner;
        self.rebindInternalPointers();
    }

    fn rebindInternalPointers(self: *LiveRunner) void {
        self.session.rebindInternalPointers();
    }

    fn snapshot(
        self: *const LiveRunner,
        ticks_advanced: usize,
        paused_for_perk_pick: bool,
        audio: FrameAudioEvents,
        terrain_fx: terrain_fx_mod.TerrainFxBatch,
    ) FrameUpdate {
        const run_summary = self.session.finalize();
        const player_health = if (self.player0Const()) |player| player.health else 0.0;
        const shot_counts = survival_progression.runShotCounts(self.session.state);
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
            .shots_fired = shot_counts.fired,
            .shots_hit = shot_counts.hit,
            .audio = audio,
            .terrain_fx = terrain_fx,
        };
    }
};

pub const LiveSurvivalRunner = LiveRunner;

const TickInputs = struct {
    items: [state_mod.max_players]player_runtime.GameInput,
    len: usize,

    fn slice(self: *const TickInputs) []const player_runtime.GameInput {
        return self.items[0..self.len];
    }
};

fn tickInputsForFrame(input: FrameInput, active_player_count: usize) TickInputs {
    var out: TickInputs = .{
        .items = [_]player_runtime.GameInput{defaultGameInput()} ** state_mod.max_players,
        .len = @min(active_player_count, state_mod.max_players),
    };
    if (out.len == 0) return out;

    if (input.player_count == 0) {
        out.items[0] = input.player;
        return out;
    }

    const provided_count = @min(@min(input.player_count, out.len), state_mod.max_players);
    for (0..provided_count) |idx| {
        out.items[idx] = input.players[idx];
    }
    return out;
}

test "live survival runner bootstraps pistol survival session" {
    var runner = try LiveSurvivalRunner.init(.{});
    try std.testing.expectEqual(game_ids.GameModeId.survival, runner.session.game_mode);
    try std.testing.expectEqual(@as(usize, 1), runner.session.players().len);
    try std.testing.expectEqual(game_ids.WeaponId.pistol, runner.session.players()[0].weapon.weapon_id);
}

test "live runner rush stomps the assault rifle and ammo each frame" {
    var runner = try LiveRunner.init(.{
        .game_mode = .rush,
    });
    try std.testing.expectEqual(game_ids.GameModeId.rush, runner.session.game_mode);
    try std.testing.expectEqual(game_ids.WeaponId.pistol, runner.session.players()[0].weapon.weapon_id);
    _ = try runner.stepFrame(runner.session.dt_nominal, .{});
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

test "live runner bootstraps typo session" {
    var runner = try LiveRunner.init(.{
        .game_mode = .typo,
    });
    try std.testing.expectEqual(game_ids.GameModeId.typo, runner.session.game_mode);
    try std.testing.expectEqual(@as(usize, 1), runner.session.players().len);
}

test "live runner typo commands update shot summary counts" {
    var runner = try LiveRunner.init(.{
        .game_mode = .typo,
    });

    runner.session.state.typo.names.names[0][0] = 'a';
    runner.session.state.typo.names.names[0][1] = 0;
    runner.session.creatures.entries[0].active = true;
    runner.session.creatures.entries[0].hp = 1.0;
    runner.session.creatures.entries[0].pos = .{ .x = 100.0, .y = 120.0 };

    _ = try runner.stepFrame(0.0, .{ .typo_char = 'a' });
    const update = try runner.stepFrame(0.0, .{ .typo_submit = true });
    try std.testing.expectEqual(@as(i32, 1), update.shots_fired);
    try std.testing.expectEqual(@as(i32, 1), update.shots_hit);
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

test "live frame keeps corpse tint after multiple simulation ticks" {
    var runner = try LiveSurvivalRunner.init(.{});
    runner.session.creatures.entries[0] = .{
        .active = true,
        .hp = 0,
        .lifecycle_stage = 0.1,
        .size = 40,
        .type_id = 3,
        .pos = .{ .x = 400, .y = 400 },
        .tint = .{ 0.6, 0.4, 0.8, 0.7 },
    };
    const update = try runner.stepFrame(runner.session.dt_nominal * 2, .{});
    try std.testing.expectEqual(@as(usize, 2), update.ticks_advanced);
    const corpses = update.terrain_fx.corpsesSlice();
    try std.testing.expectEqual(@as(usize, 1), corpses.len);
    // Original queue witness: 0.7 * 0.8 at PC=24. Batching must not attenuate again.
    try std.testing.expectEqual(@as(u32, 0x3f0f5c29), @as(u32, @bitCast(corpses[0].color.a)));
    try std.testing.expectEqual(@as(f32, 0.6), corpses[0].color.r);
    try std.testing.expectEqual(@as(f32, 0.4), corpses[0].color.g);
    try std.testing.expectEqual(@as(f32, 0.8), corpses[0].color.b);
}

test "live runner snapshots restore deterministic session state" {
    var runner = try LiveRunner.init(.{
        .seed = 1234,
        .player_count = 1,
        .tick_rate = 60,
    });

    runner.player0().?.health = 12.5;
    runner.session.tick_index = 3;
    runner.session.state.rng.state = 0xDEADBEEF;

    const snapshot = runner.captureSnapshot();
    try std.testing.expect(snapshot.runner.session.creatures.effects == null);

    runner.player0().?.health = 0.0;
    runner.session.tick_index = 99;
    runner.session.state.rng.state = 1;

    runner.restoreSnapshot(&snapshot);

    try std.testing.expectEqual(@as(usize, 3), runner.session.tick_index);
    try std.testing.expectEqual(@as(u32, 0xDEADBEEF), runner.session.state.rng.state);
    try std.testing.expectApproxEqAbs(@as(f32, 12.5), runner.player0().?.health, 0.001);
    try std.testing.expect(runner.session.creatures.effects.? == &runner.session.effects);
}

test "live runner applies local inputs for every active player" {
    var runner = try LiveSurvivalRunner.init(.{
        .player_count = 2,
    });

    // Face each input direction so native turn alignment does not suppress
    // translation while a player turns through the opposite heading.
    runner.session.players()[0].heading = std.math.pi / 2.0;
    runner.session.players()[1].heading = std.math.pi;

    const before_p0 = runner.session.players()[0].pos;
    const before_p1 = runner.session.players()[1].pos;

    var inputs = [_]player_runtime.GameInput{defaultGameInput()} ** state_mod.max_players;
    inputs[0] = .{
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
    };
    inputs[1] = .{
        .move_x = 0.0,
        .move_y = 1.0,
        .aim_x = 512.0,
        .aim_y = 700.0,
        .flags = .{
            .fire_down = false,
            .fire_pressed = false,
            .reload_pressed = false,
            .move_mode = 3,
            .aim_scheme = 0,
        },
    };

    const update = try runner.stepFrame(runner.session.dt_nominal, .{
        .players = inputs,
        .player_count = 2,
    });

    const after_p0 = runner.session.players()[0].pos;
    const after_p1 = runner.session.players()[1].pos;
    try std.testing.expectEqual(@as(usize, 1), update.ticks_advanced);
    try std.testing.expect(after_p0.x != before_p0.x or after_p0.y != before_p0.y);
    try std.testing.expect(after_p1.x != before_p1.x or after_p1.y != before_p1.y);
}

test "live runner emits shot audio for secondary local player" {
    var runner = try LiveSurvivalRunner.init(.{
        .player_count = 2,
    });
    // The native reset starts every pistol with a 0.8-second shot cooldown.
    runner.session.players()[1].weapon.shot_cooldown = 0.0;

    var inputs = [_]player_runtime.GameInput{defaultGameInput()} ** state_mod.max_players;
    inputs[1] = .{
        .move_x = 0.0,
        .move_y = 0.0,
        .aim_x = 700.0,
        .aim_y = 512.0,
        .flags = .{
            .fire_down = true,
            .fire_pressed = true,
            .reload_pressed = false,
            .move_mode = 3,
            .aim_scheme = 0,
        },
    };

    const update = try runner.stepFrame(runner.session.dt_nominal, .{
        .players = inputs,
        .player_count = 2,
    });

    try std.testing.expectEqualSlices(
        state_mod.SfxId,
        &.{.pistol_fire},
        update.audio.sfx_events[0..update.audio.sfx_event_count],
    );
}

test "live survival runner pauses for pending perk picks" {
    var runner = try LiveSurvivalRunner.init(.{});
    runner.session.state.perk_selection.pending_count = 1;
    runner.session.state.perk_selection.choices_dirty = true;

    const moving = try runner.stepFrame(runner.session.dt_nominal, .{});
    try std.testing.expectEqual(@as(usize, 1), moving.ticks_advanced);
    try std.testing.expect(!moving.paused_for_perk_pick);

    const blocked = try runner.stepFrame(runner.session.dt_nominal, .{
        .perk_menu_active = true,
    });
    try std.testing.expectEqual(@as(usize, 0), blocked.ticks_advanced);
    try std.testing.expect(blocked.paused_for_perk_pick);

    try std.testing.expectEqual(@as(usize, 0), runner.preparedPerkChoices().len);
    runner.requestPerkMenu();
    const opening = try runner.stepFrame(runner.session.dt_nominal, .{});
    try std.testing.expectEqual(@as(usize, 1), opening.ticks_advanced);
    try std.testing.expect(opening.perk_menu_opened);
    try std.testing.expect(runner.preparedPerkChoices().len > 0);
    try std.testing.expectEqual(@as(usize, 1), runner.session.perk_menu_open_count);
    try std.testing.expect(try runner.pickPerk(0, runner.session.dt_nominal));
    try std.testing.expectEqual(@as(usize, 1), runner.session.perk_pick_count);
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

test "live runner emits ui bonus pickup sfx" {
    var runner = try LiveSurvivalRunner.init(.{});
    const player_pos = runner.session.players()[0].pos;
    runner.session.bonuses.entries[0] = .{
        .bonus_id = .points,
        .picked = false,
        .time_left = 5.0,
        .time_max = 5.0,
        .pos = player_pos,
        .amount = 100,
    };

    const update = try runner.stepFrame(runner.session.dt_nominal, .{});
    try std.testing.expectEqual(@as(usize, 1), update.audio.sfx_event_count);
    try std.testing.expectEqual(state_mod.SfxId.ui_bonus, update.audio.sfx_events[0]);
}

test "live runner emits bonus-specific apply sfx after pickup" {
    var runner = try LiveSurvivalRunner.init(.{});
    const player_pos = runner.session.players()[0].pos;
    runner.session.bonuses.entries[0] = .{
        .bonus_id = .fireblast,
        .picked = false,
        .time_left = 5.0,
        .time_max = 5.0,
        .pos = player_pos,
        .amount = 1,
    };

    const update = try runner.stepFrame(runner.session.dt_nominal, .{});
    try std.testing.expectEqual(@as(usize, 2), update.audio.sfx_event_count);
    try std.testing.expectEqual(state_mod.SfxId.ui_bonus, update.audio.sfx_events[0]);
    try std.testing.expectEqual(state_mod.SfxId.explosion_medium, update.audio.sfx_events[1]);
}
