const std = @import("std");
const game_ids = @import("../game_ids.zig");

const perks = @import("perks.zig");
const player_runtime = @import("player.zig");
const replay_step = @import("replay/step.zig");
const runtime_session = @import("session.zig");
const session_builders = @import("session_builders.zig");
const state_mod = @import("state.zig");

pub const LiveRunnerError = runtime_session.DeterministicSessionError ||
    replay_step.StepError ||
    perks.PerkApplyError;

const max_frame_dt: f32 = 0.25;
const epsilon_dt: f32 = 1e-6;

pub const LiveSurvivalConfig = struct {
    seed: u32 = 1,
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

pub const FrameInput = struct {
    player: player_runtime.GameInput = defaultGameInput(),
    perk_choice_index: ?i32 = null,
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

pub const LiveSurvivalRunner = struct {
    session: runtime_session.DeterministicSession,
    accumulator: f32 = 0.0,
    max_substeps_per_frame: usize = 8,

    pub fn init(config: LiveSurvivalConfig) LiveRunnerError!LiveSurvivalRunner {
        const session = try session_builders.buildSurvivalSession(
            .{
                .seed = config.seed,
                .game_mode = .survival,
                .player_count = config.player_count,
                .world_size = config.world_size,
                .tick_rate = config.tick_rate,
                .detail_preset = config.detail_preset,
                .gore_disabled = config.gore_disabled,
                .hardcore = config.hardcore,
                .preserve_bugs = config.preserve_bugs,
                .status_quest_unlock_index = config.status_quest_unlock_index,
                .status_quest_unlock_index_full = config.status_quest_unlock_index_full,
            },
            .{},
        );

        return .{
            .session = session,
        };
    }

    pub fn stepFrame(self: *LiveSurvivalRunner, frame_dt: f32, input: FrameInput) LiveRunnerError!FrameUpdate {
        if (input.perk_choice_index) |choice_index| {
            _ = try self.pickPerk(choice_index);
        }

        const paused_for_perk_pick = self.perkPendingCount() > 0;
        if (self.allPlayersDead() or paused_for_perk_pick or !(frame_dt > 0.0)) {
            return self.snapshot(0, paused_for_perk_pick);
        }

        const clamped_dt = std.math.clamp(frame_dt, @as(f32, 0.0), max_frame_dt);
        self.accumulator = std.math.clamp(self.accumulator + clamped_dt, @as(f32, 0.0), max_frame_dt);

        var ticks_advanced: usize = 0;
        const tick_inputs = [_]player_runtime.GameInput{input.player};
        while (ticks_advanced < self.max_substeps_per_frame and
            !self.allPlayersDead() and
            self.perkPendingCount() <= 0 and
            self.accumulator + epsilon_dt >= self.session.dt_nominal)
        {
            _ = try replay_step.stepTick(
                &self.session,
                self.session.tick_index,
                tick_inputs[0..],
                &.{},
                self.session.dt_nominal,
                .{},
            );
            self.accumulator = @max(0.0, self.accumulator - self.session.dt_nominal);
            ticks_advanced += 1;
        }

        return self.snapshot(ticks_advanced, self.perkPendingCount() > 0);
    }

    pub fn perkPendingCount(self: *const LiveSurvivalRunner) i32 {
        return self.session.state.perk_selection.pending_count;
    }

    pub fn currentPerkChoices(self: *LiveSurvivalRunner) []const game_ids.PerkId {
        return perks.perkSelectionCurrentChoices(
            &self.session.state,
            self.session.players(),
            self.session.game_mode,
            self.session.player_count,
            self.session.quest_unlock_index,
        );
    }

    pub fn pickPerk(self: *LiveSurvivalRunner, choice_index: i32) LiveRunnerError!bool {
        const picked = try perks.perkSelectionPick(
            &self.session.state,
            self.session.players(),
            choice_index,
            self.session.game_mode,
            self.session.player_count,
            self.session.quest_unlock_index,
        );
        return picked != null;
    }

    pub fn allPlayersDead(self: *const LiveSurvivalRunner) bool {
        const players = self.session.playersConst();
        if (players.len == 0) return true;
        for (players) |player| {
            if (player.health > 0.0) return false;
        }
        return true;
    }

    pub fn player0(self: *LiveSurvivalRunner) ?*state_mod.PlayerState {
        const players = self.session.players();
        if (players.len == 0) return null;
        return &players[0];
    }

    pub fn player0Const(self: *const LiveSurvivalRunner) ?*const state_mod.PlayerState {
        const players = self.session.playersConst();
        if (players.len == 0) return null;
        return &players[0];
    }

    pub fn summary(self: *const LiveSurvivalRunner) runtime_session.SessionSummary {
        return self.session.finalize();
    }

    fn snapshot(self: *const LiveSurvivalRunner, ticks_advanced: usize, paused_for_perk_pick: bool) FrameUpdate {
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
        };
    }
};

test "live survival runner bootstraps pistol survival session" {
    var runner = try LiveSurvivalRunner.init(.{});
    try std.testing.expectEqual(game_ids.GameModeId.survival, runner.session.game_mode);
    try std.testing.expectEqual(@as(usize, 1), runner.session.players().len);
    try std.testing.expectEqual(game_ids.WeaponId.pistol, runner.session.players()[0].weapon.weapon_id);
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
    try std.testing.expect(try runner.pickPerk(0));
    try std.testing.expectEqual(@as(i32, 0), runner.perkPendingCount());
}

test "live survival runner reports dead run state" {
    var runner = try LiveSurvivalRunner.init(.{});
    runner.session.players()[0].health = 0.0;

    const update = try runner.stepFrame(runner.session.dt_nominal, .{});
    try std.testing.expect(update.all_players_dead);
    try std.testing.expectEqual(@as(usize, 0), update.ticks_advanced);
}
