const std = @import("std");
const game_ids = @import("../game_ids.zig");
const native_math = @import("native_math.zig");

const replay_codec = @import("../replay_codec.zig");
const bonus_runtime = @import("bonuses.zig");
const creature_lifecycle = @import("lifecycle.zig").CreatureLifecycle;
const creatures_mod = @import("creatures.zig");
const owner_ref = @import("owner_ref.zig");
const perks = @import("perks.zig");
const particles_mod = @import("particles.zig");
const player_runtime = @import("player.zig");
const projectiles_mod = @import("projectiles.zig");
const secondary_projectiles_mod = @import("secondary_projectiles.zig");
const spawn_mod = @import("spawn.zig");
const quest_spawn_logic = @import("../quest_spawn/logic_full.zig");
const state_mod = @import("state.zig");
const survival_progression = @import("survival_progression.zig");
const weapon_data = @import("weapon_data.zig");
const weapons_runtime = @import("weapons.zig");
const math = @import("math.zig");
const replay_capture_state = @import("replay/capture_state.zig");
const replay_context_mod = @import("replay/context.zig");
const replay_diagnostic_trace = @import("replay/diagnostic_trace.zig");
const replay_events = @import("replay/events.zig");
const replay_step = @import("replay/step.zig");

const narrowF32 = native_math.roundF32;
const PerkId = perks.PerkId;
const GameModeId = game_ids.GameModeId;
const native_half_pi: f32 = native_math.native_half_pi;
const native_pi: f32 = native_math.native_pi;
const native_tau: f32 = native_math.native_tau;
const relative_move_heading_none: f32 = -1.0;
const relative_move_heading_forward: f32 = 0.0;
const relative_move_heading_forward_right: f32 = 0.7853981852531433;
const relative_move_heading_right: f32 = native_half_pi;
const relative_move_heading_backward_right: f32 = 2.356194496154785;
const relative_move_heading_backward: f32 = native_pi;
const relative_move_heading_backward_left: f32 = 3.9269909858703613;
const relative_move_heading_left: f32 = narrowF32(native_tau - native_half_pi);
const relative_move_heading_forward_left: f32 = 5.4977874755859375;
const relative_move_turn_align_scale: f32 = 7.957746982574463;
const movement_control_relative: i32 = 1;
const movement_control_static: i32 = 2;
const movement_control_dual_action_pad: i32 = 3;
const movement_control_computer: i32 = 5;
const aim_scheme_mouse: i32 = 0;
const aim_scheme_computer: i32 = 5;
const TickEventPhase = enum {
    pre_step,
    post_state_transition,
    post_spawn_hook,
    post_menu_open,
};
const max_test_quest_spawn_entries: usize = 1024;
// Native capture state-transition rows that target state 12 trigger a full run-state reset.
const capture_state_reset_target: i32 = 12;
// Native creature_update_all writes `link_index = -700 - (rand & 0x3ff)` when AI7
// timer mode rolls from active to cooldown. Capture rows can carry that result
// directly, so replay backfills the skipped RNG draw for this range.
const ai7_link_timer_rollover_min: i32 = -1723;
const ai7_link_timer_rollover_max: i32 = -700;

pub const ReplayRunnerError = error{
    OutOfMemory,
    InvalidHeaderValue,
    InvalidCaptureEnumValue,
    UnsupportedGameMode,
    UnsupportedPlayerCount,
    UnsupportedInputQuantization,
    UnsupportedDemoMode,
    UnsupportedPreserveBugs,
    UnsupportedEventOrdering,
    UnsupportedEventKind,
    UnsupportedEventPlayerIndex,
    InvalidPerkPickEvent,
    UnsupportedPerkApplyHandler,
    UnsupportedSpawnTemplate,
    UnsupportedQuestSpawnTable,
    UnsupportedWeaponFirePath,
    UnsupportedBonusApplyPath,
};

fn parseCaptureCreatureAiMode(value: i32) ReplayRunnerError!spawn_mod.CreatureAiMode {
    const mode: spawn_mod.CreatureAiMode = @enumFromInt(value);
    return switch (mode) {
        .orbit_player,
        .orbit_player_tight,
        .chase_player,
        .follow_link,
        .link_guard,
        .follow_link_tethered,
        .orbit_link,
        .hold_timer,
        .orbit_player_wide,
        => mode,
        else => error.InvalidCaptureEnumValue,
    };
}

fn isAi7LinkTimerRolloverValue(link_index: i32) bool {
    return link_index >= ai7_link_timer_rollover_min and
        link_index <= ai7_link_timer_rollover_max;
}

pub const ReplayScaffoldResult = struct {
    ticks: usize,
    elapsed_ms_nominal: i64,
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
    most_used_weapon_id: i32,
    shots_fired: i32,
    shots_hit: i32,
    creature_kill_count: i32,
    creature_active_count: usize,
    perk_pending_count: i32,
    survival_reward_handout_enabled: bool,
    survival_reward_fire_seen: bool,
    survival_reward_damage_seen: bool,
    spawn_stage: i32,
    spawn_cooldown_ms: f32,
    quest_completion_transition_ms: f32,
    quest_completed: bool,
    quest_play_hit_sfx: bool,
    quest_play_completion_music: bool,
};

pub const ProjectileTraceEntry = replay_diagnostic_trace.ProjectileTraceEntry;
pub const CreatureTraceEntry = replay_diagnostic_trace.CreatureTraceEntry;
pub const ReplayTickTrace = replay_diagnostic_trace.ReplayTickTraceV2;

pub const DtFrameOverride = struct {
    tick_index: usize,
    dt_frame: f32,
};

pub const ReplayScaffoldOptions = struct {
    strict_events: bool = true,
    inter_tick_rand_draws: i32 = 0,
    dt_frame_overrides: ?[]const DtFrameOverride = null,
    quest_spawn_entries: ?[]const spawn_mod.QuestSpawnEntry = null,
    quest_start_weapon_id: ?i32 = null,
};

fn ensureSupportedReplayFeatureFlags(
    demo_mode_active: bool,
    preserve_bugs: bool,
) ReplayRunnerError!void {
    if (demo_mode_active) return error.UnsupportedDemoMode;
    if (preserve_bugs) return error.UnsupportedPreserveBugs;
}

pub fn runReplayScaffold(
    replay: replay_codec.Replay,
) ReplayRunnerError!ReplayScaffoldResult {
    return runReplayScaffoldWithOptions(replay, .{});
}

pub fn runReplayScaffoldWithOptions(
    replay: replay_codec.Replay,
    options: ReplayScaffoldOptions,
) ReplayRunnerError!ReplayScaffoldResult {
    return runReplayScaffoldWithTrace(
        replay,
        null,
        std.heap.page_allocator,
        options,
    );
}

pub fn runReplayScaffoldWithTrace(
    replay: replay_codec.Replay,
    trace_out: ?*std.ArrayList(ReplayTickTrace),
    trace_allocator: std.mem.Allocator,
    options: ReplayScaffoldOptions,
) ReplayRunnerError!ReplayScaffoldResult {
    const header = replay.header;
    const game_mode = std.meta.intToEnum(GameModeId, header.game_mode_id) catch {
        return error.UnsupportedGameMode;
    };
    if (header.player_count <= 0 or header.player_count > state_mod.max_players) {
        return error.UnsupportedPlayerCount;
    }
    try ensureSupportedReplayFeatureFlags(false, header.preserve_bugs);
    if (!std.mem.eql(u8, header.input_quantization, "raw") and !std.mem.eql(u8, header.input_quantization, "f32")) {
        return error.UnsupportedInputQuantization;
    }
    const max_world_size_i32_f32: f32 = @floatFromInt(std.math.maxInt(i32));
    if (!std.math.isFinite(header.world_size) or header.world_size <= 0.0 or header.world_size > max_world_size_i32_f32) {
        return error.InvalidHeaderValue;
    }

    const events = replay.events;
    var original_capture_replay = false;
    var has_capture_creature_spawn_events = false;
    for (events) |event| {
        switch (event) {
            .capture_bootstrap => original_capture_replay = true,
            .capture_creature_spawn => has_capture_creature_spawn_events = true,
            else => {},
        }
    }
    const capture_spawn_events_authoritative = original_capture_replay and has_capture_creature_spawn_events;
    const apply_world_dt_steps = !(original_capture_replay and options.dt_frame_overrides != null);
    const defer_menu_open_events = original_capture_replay;

    var quest_start_weapon_id_for_reset: i32 = options.quest_start_weapon_id orelse @intFromEnum(game_ids.WeaponId.pistol);
    var quest_spawn_entries_storage: [max_test_quest_spawn_entries]spawn_mod.QuestSpawnEntry = undefined;
    var quest_spawn_entries: []spawn_mod.QuestSpawnEntry = quest_spawn_entries_storage[0..0];

    if (game_mode == .quests) {
        if (options.quest_spawn_entries) |entries| {
            if (entries.len > quest_spawn_entries_storage.len) {
                return error.UnsupportedQuestSpawnTable;
            }
            @memcpy(quest_spawn_entries_storage[0..entries.len], entries);
            quest_spawn_entries = quest_spawn_entries_storage[0..entries.len];
        } else {
            const level_key = resolveQuestLevelKey(header) orelse return error.UnsupportedQuestSpawnTable;
            const built = quest_spawn_logic.buildQuestSpawnTable(
                level_key,
                header.player_count,
                header.seed,
                header.world_size,
                quest_spawn_entries_storage[0..],
            ) catch |build_err| switch (build_err) {
                error.UnsupportedQuestSpawnTable => return error.UnsupportedQuestSpawnTable,
                error.OutOfSpace => return error.UnsupportedQuestSpawnTable,
            };
            quest_spawn_entries = quest_spawn_entries_storage[0..built.entries.len];
            if (options.quest_start_weapon_id == null) {
                quest_start_weapon_id_for_reset = @intFromEnum(built.start_weapon_id);
            }
            if (quest_spawn_entries.len == 0) {
                return error.UnsupportedQuestSpawnTable;
            }
        }
        if (header.hardcore) {
            spawn_mod.applyHardcoreQuestSpawnTableAdjustment(quest_spawn_entries);
        }
        if (capture_spawn_events_authoritative) {
            quest_spawn_entries = quest_spawn_entries_storage[0..0];
        }
    }

    var context = replay_context_mod.SimulationContext.initFromReplayHeader(
        header,
        .{
            .strict_events = options.strict_events,
            .inter_tick_rand_draws = options.inter_tick_rand_draws,
            .defer_menu_open_events = defer_menu_open_events,
            .apply_world_dt_steps = apply_world_dt_steps,
            .capture_spawn_events_authoritative = capture_spawn_events_authoritative,
            .quest_start_weapon_id_for_reset = quest_start_weapon_id_for_reset,
            .quest_spawn_entries = if (game_mode == .quests and !capture_spawn_events_authoritative)
                quest_spawn_entries
            else
                null,
        },
    ) catch |err| switch (err) {
        error.InvalidPlayerCount => return error.UnsupportedPlayerCount,
        error.InvalidWorldSize => return error.InvalidHeaderValue,
        error.InvalidTickRate => return error.InvalidHeaderValue,
        error.UnsupportedGameMode => return error.UnsupportedGameMode,
        error.UnsupportedQuestSpawnTable => return error.UnsupportedQuestSpawnTable,
    };

    if (game_mode == .quests) {
        const weapon_id = @max(1, quest_start_weapon_id_for_reset);
        for (context.players()) |*player| {
            const start_weapon = weapon_data.weaponIdFromInt(weapon_id);
            player_runtime.weaponAssignPlayer(player, start_weapon);
        }
    }

    for (0..replay.tickCount()) |tick_index| {
        if (context.event_index < events.len and events[context.event_index].tickIndex() < tick_index) {
            return error.UnsupportedEventOrdering;
        }

        const dt_tick = resolveDtFrame(options.dt_frame_overrides, tick_index, context.dt_nominal);
        const tick_event_start = context.event_index;
        var tick_event_end = tick_event_start;
        while (tick_event_end < events.len and events[tick_event_end].tickIndex() == tick_index) : (tick_event_end += 1) {}

        const step_result = try replay_step.stepTick(
            &context,
            tick_index,
            replay.inputs[tick_index],
            events[tick_event_start..tick_event_end],
            dt_tick,
            .{},
        );

        if (trace_out) |trace| {
            const trace_elapsed_ms = switch (game_mode) {
                .quests => context.quest_spawn_timeline_ms,
                .rush => @as(f32, @floatFromInt(context.elapsed_ms_sim_rush)),
                else => context.elapsed_ms_sim,
            };
            const players = context.playersConst();
            const player0 = players[0];
            try trace.append(
                trace_allocator,
                buildTickTrace(
                    tick_index,
                    narrowF32(trace_elapsed_ms),
                    &context.state,
                    player0,
                    &context.creatures,
                    &context.bonuses,
                    &context.projectiles,
                    step_result.projectile_tick_stats,
                    step_result.rng_after_perk_effects,
                    step_result.rng_after_creatures,
                    step_result.rng_after_projectiles,
                    step_result.rng_after_secondary_projectiles,
                    step_result.rng_after_particles,
                    step_result.rng_after_player_update,
                    step_result.rng_after_stage_spawns,
                    step_result.rng_after_wave_spawns,
                    step_result.rng_after_spawns,
                    step_result.rng_after_bonus_update,
                ),
            );
        }
    }

    const terminal_tick = replay.tickCount();
    if (context.event_index < events.len and events[context.event_index].tickIndex() < terminal_tick) {
        return error.UnsupportedEventOrdering;
    }
    var terminal_menu_open_seen = false;
    while (context.event_index < events.len and events[context.event_index].tickIndex() == terminal_tick) : (context.event_index += 1) {
        const dt_tick = resolveDtFrame(options.dt_frame_overrides, terminal_tick, context.dt_nominal);
        const outcome = try replay_events.applyReplayEvent(
            events[context.event_index],
            &context.state,
            context.players(),
            &context.creatures,
            narrowF32(dt_tick),
            &context.quest_spawn_timeline_ms,
            &context.quest_no_creatures_timer_ms,
            &context.quest_completion_transition_ms,
            .{
                .game_mode = context.game_mode,
                .player_count = context.player_count,
                .quest_unlock_index = context.quest_unlock_index,
                .strict_events = context.strict_events,
                .menu_open_seen_this_tick = terminal_menu_open_seen,
            },
        );
        terminal_menu_open_seen = terminal_menu_open_seen or outcome.menu_open_seen_this_tick;
        context.perk_menu_open_count += outcome.perk_menu_open_count_delta;
        context.perk_pick_count += outcome.perk_pick_count_delta;
        if (outcome.signal == .request_capture_state_reset) {
            context.pending_capture_state_reset = true;
        }
        try ensureSupportedReplayFeatureFlags(context.state.demo_mode_active, context.state.preserve_bugs);
    }
    if (context.event_index != events.len) return error.UnsupportedEventOrdering;

    const tick_rate_f32: f32 = @floatFromInt(header.tick_rate);
    const ticks_f32: f32 = @floatFromInt(replay.tickCount());
    const elapsed_ms_nominal: i64 = @intFromFloat(@round(ticks_f32 * (1000.0 / tick_rate_f32)));
    const elapsed_ms_sim_i64: i64 = switch (game_mode) {
        .quests => @intFromFloat(context.quest_spawn_timeline_ms),
        .rush => context.elapsed_ms_sim_rush,
        else => @intFromFloat(context.elapsed_ms_sim),
    };

    const players = context.playersConst();
    const player0 = players[0];
    const shots = survival_progression.player0Shots(context.state);
    const most_used_weapon_id = survival_progression.mostUsedWeaponIdForPlayer(
        context.state,
        0,
        player0.weapon_id,
    );

    return .{
        .ticks = replay.tickCount(),
        .elapsed_ms_nominal = elapsed_ms_nominal,
        .elapsed_ms_sim = elapsed_ms_sim_i64,
        .perk_menu_open_count = context.perk_menu_open_count,
        .perk_pick_count = context.perk_pick_count,
        .fire_pressed_count = context.fire_pressed_count,
        .reload_pressed_count = context.reload_pressed_count,
        .stage_spawn_count = context.stage_spawn_count,
        .wave_spawn_count = context.wave_spawn_count,
        .wave_spawn_rng_state = context.state.rng.state,
        .player_level = player0.level,
        .player_experience = player0.experience,
        .player_weapon_id = @intFromEnum(player0.weapon_id),
        .most_used_weapon_id = @intFromEnum(most_used_weapon_id),
        .shots_fired = shots.fired,
        .shots_hit = shots.hit,
        .creature_kill_count = context.creatures.kill_count,
        .creature_active_count = context.creatures.activeCount(),
        .perk_pending_count = context.state.perk_selection.pending_count,
        .survival_reward_handout_enabled = context.state.survival_reward_handout_enabled,
        .survival_reward_fire_seen = context.state.survival_reward_fire_seen,
        .survival_reward_damage_seen = context.state.survival_reward_damage_seen,
        .spawn_stage = context.spawn_stage,
        .spawn_cooldown_ms = context.spawn_cooldown,
        .quest_completion_transition_ms = @floatCast(context.quest_completion_transition_ms),
        .quest_completed = context.quest_completed,
        .quest_play_hit_sfx = context.quest_play_hit_sfx,
        .quest_play_completion_music = context.quest_play_completion_music,
    };
}

fn buildTickTrace(
    tick_index: usize,
    elapsed_ms_sim: f32,
    state: *const state_mod.GameplayState,
    player: state_mod.PlayerState,
    creatures: *const creatures_mod.CreaturePool,
    bonuses: *const bonus_runtime.BonusPool,
    projectiles: *const projectiles_mod.ProjectilePool,
    projectile_tick_stats: projectiles_mod.ProjectileTickStats,
    rng_after_perk_effects: u32,
    rng_after_creatures: u32,
    rng_after_projectiles: u32,
    rng_after_secondary_projectiles: u32,
    rng_after_particles: u32,
    rng_after_player_update: u32,
    rng_after_stage_spawns: u32,
    rng_after_wave_spawns: u32,
    rng_after_spawns: u32,
    rng_after_bonus_update: u32,
) ReplayTickTrace {
    return replay_diagnostic_trace.buildReplayTickTraceV2(
        tick_index,
        elapsed_ms_sim,
        state,
        player,
        creatures,
        bonuses,
        projectiles,
        projectile_tick_stats,
        rng_after_perk_effects,
        rng_after_creatures,
        rng_after_projectiles,
        rng_after_secondary_projectiles,
        rng_after_particles,
        rng_after_player_update,
        rng_after_stage_spawns,
        rng_after_wave_spawns,
        rng_after_spawns,
        rng_after_bonus_update,
    );
}

fn quantizeQ4(value: f32) i32 {
    const scaled = @round(value * 10000.0);
    if (scaled <= @as(f32, @floatFromInt(std.math.minInt(i32)))) return std.math.minInt(i32);
    if (scaled >= @as(f32, @floatFromInt(std.math.maxInt(i32)))) return std.math.maxInt(i32);
    return @intFromFloat(scaled);
}

fn quantizeQ6(value: f32) i32 {
    const scaled = @round(value * 1_000_000.0);
    if (scaled <= @as(f32, @floatFromInt(std.math.minInt(i32)))) return std.math.minInt(i32);
    if (scaled >= @as(f32, @floatFromInt(std.math.maxInt(i32)))) return std.math.maxInt(i32);
    return @intFromFloat(scaled);
}

fn bonusTimerMs(seconds: f32) i32 {
    if (!(seconds > 0.0)) return 0;
    const ms = @round(seconds * 1000.0);
    if (ms <= 0.0) return 0;
    if (ms >= @as(f32, @floatFromInt(std.math.maxInt(i32)))) return std.math.maxInt(i32);
    return @intFromFloat(ms);
}

fn hashMix(seed: u64, value: u64) u64 {
    var h = seed ^ value;
    h *%= 1099511628211;
    return h;
}

fn cameraShakeUpdate(
    state: *state_mod.GameplayState,
    dt: f32,
) void {
    if (state.camera_shake_timer <= 0.0) {
        state.camera_shake_offset = .{};
        return;
    }

    state.camera_shake_timer = narrowF32(state.camera_shake_timer - dt * 3.0);
    if (state.camera_shake_timer >= 0.0) return;

    state.camera_shake_pulses -= 1;
    if (state.camera_shake_pulses < 1) {
        state.camera_shake_timer = 0.0;
        return;
    }

    state.camera_shake_timer = if (state.bonuses.reflex_boost > 0.0) 0.06 else 0.1;
    const max_amp = state.camera_shake_pulses * 3;
    if (max_amp <= 0) {
        state.camera_shake_offset = .{};
        state.camera_shake_timer = 0.0;
        state.camera_shake_pulses = 0;
        return;
    }

    const max_amp_u32: u32 = @intCast(max_amp);
    var mag_x: i32 = @intCast(state.rng.rand() % max_amp_u32);
    mag_x += @intCast(state.rng.rand() % 10);
    if ((state.rng.rand() & 1) == 0) {
        mag_x = -mag_x;
    }

    var mag_y: i32 = @intCast(state.rng.rand() % max_amp_u32);
    mag_y += @intCast(state.rng.rand() % 10);
    if ((state.rng.rand() & 1) == 0) {
        mag_y = -mag_y;
    }

    state.camera_shake_offset = .{
        .x = narrowF32(@as(f32, @floatFromInt(mag_x))),
        .y = narrowF32(@as(f32, @floatFromInt(mag_y))),
    };
}

fn applyPendingBonusEffects(
    state: *state_mod.GameplayState,
    players: []state_mod.PlayerState,
    projectiles: *projectiles_mod.ProjectilePool,
    creatures: *creatures_mod.CreaturePool,
    bonuses: *bonus_runtime.BonusPool,
    dt: f32,
    world_size: f32,
    tick_index: usize,
) void {
    state.debug_nuke_kills_last = 0;
    state.debug_nuke_tick_last = -1;
    state.debug_nuke_kill_index_sum = 0;

    const pending_fireblast_count_i32 = @min(state.pending_fireblast_count, @as(i32, @intCast(state.pending_fireblast_origins.len)));
    var pending_fireblast_idx: i32 = 0;
    while (pending_fireblast_idx < pending_fireblast_count_i32) : (pending_fireblast_idx += 1) {
        const origin = state.pending_fireblast_origins[@intCast(pending_fireblast_idx)];
        applyFireblastBonus(
            state,
            projectiles,
            origin,
        );
    }
    state.pending_fireblast_count = 0;

    const pending_shock_chain_count_i32 = @min(state.pending_shock_chain_count, @as(i32, @intCast(state.pending_shock_chain_origins.len)));
    var pending_shock_chain_idx: i32 = 0;
    while (pending_shock_chain_idx < pending_shock_chain_count_i32) : (pending_shock_chain_idx += 1) {
        const origin = state.pending_shock_chain_origins[@intCast(pending_shock_chain_idx)];
        applyShockChainBonus(
            state,
            projectiles,
            creatures,
            origin,
        );
    }
    state.pending_shock_chain_count = 0;

    const pending_count_i32 = @min(state.pending_nuke_count, @as(i32, @intCast(state.pending_nuke_origins.len)));
    var pending_idx: i32 = 0;
    while (pending_idx < pending_count_i32) : (pending_idx += 1) {
        const origin = state.pending_nuke_origins[@intCast(pending_idx)];
        applyNukeBonus(
            state,
            players,
            projectiles,
            creatures,
            bonuses,
            origin,
            dt,
            world_size,
            tick_index,
        );
    }
    state.pending_nuke_count = 0;
}

fn applyPendingCreatureProjectiles(
    state: *state_mod.GameplayState,
    projectiles: *projectiles_mod.ProjectilePool,
) void {
    if (state.pending_creature_projectile_count <= 0) {
        state.pending_creature_projectile_count = 0;
        return;
    }

    const pending_count_i32 = @min(
        state.pending_creature_projectile_count,
        @as(i32, @intCast(state.pending_creature_projectiles.len)),
    );

    var idx_i32: i32 = 0;
    while (idx_i32 < pending_count_i32) : (idx_i32 += 1) {
        const idx: usize = @intCast(idx_i32);
        const pending = state.pending_creature_projectiles[idx];
        const type_id = pending.type_id;
        if (type_id <= 0) continue;
        const angle = pending.angle;
        const pos = pending.pos;
        const owner = pending.owner;
        const meta = projectileTravelBudgetFromRawId(type_id);
        _ = projectiles.spawn(pos, narrowF32(angle), type_id, owner, meta, true);
    }
    state.pending_creature_projectile_count = 0;
}

fn applyFireblastBonus(
    state: *state_mod.GameplayState,
    projectiles: *projectiles_mod.ProjectilePool,
    origin: state_mod.Vec2,
) void {
    const projectile_owner = owner_ref.OwnerRef.fromLocalPlayer(0);
    const prev_spawn_guard = state.bonus_spawn_guard;
    state.bonus_spawn_guard = true;
    defer state.bonus_spawn_guard = prev_spawn_guard;

    const count: usize = 16;
    const step = std.math.tau / @as(f32, @floatFromInt(count));
    for (0..count) |idx| {
        const angle = @as(f32, @floatFromInt(idx)) * step;
        const type_id = @intFromEnum(game_ids.ProjectileTypeId.plasma_rifle);
        const meta = projectileTravelBudgetFromRawId(type_id);
        _ = projectiles.spawn(origin, narrowF32(angle), type_id, projectile_owner, meta, false);
    }
}

fn applyShockChainBonus(
    state: *state_mod.GameplayState,
    projectiles: *projectiles_mod.ProjectilePool,
    creatures: *creatures_mod.CreaturePool,
    origin: state_mod.Vec2,
) void {
    if (creatures.entries.len == 0) return;

    var best_idx: ?usize = null;
    var best_dist_sq: f32 = 1e12;
    for (creatures.entries, 0..) |creature, idx| {
        if (!creature.active) continue;
        if (!creature_lifecycle.isAlive(creature.lifecycle_stage)) continue;
        const d_sq = distanceSq(origin, creature.pos);
        if (d_sq < best_dist_sq) {
            best_dist_sq = d_sq;
            best_idx = idx;
        }
    }
    const target_idx = best_idx orelse return;

    const target = creatures.entries[target_idx];
    const angle = state_mod.Vec2.sub(target.pos, origin).toHeading();
    const projectile_owner = owner_ref.OwnerRef.fromLocalPlayer(0);
    const type_id = @intFromEnum(game_ids.ProjectileTypeId.ion_rifle);
    const meta = projectileTravelBudgetFromRawId(type_id);

    const prev_spawn_guard = state.bonus_spawn_guard;
    state.bonus_spawn_guard = true;
    defer state.bonus_spawn_guard = prev_spawn_guard;

    state.shock_chain_links_left = 0x20;
    const proj_idx = projectiles.spawn(origin, narrowF32(angle), type_id, projectile_owner, meta, false);
    state.shock_chain_projectile_id = @intCast(proj_idx);
}

fn distanceSq(a: state_mod.Vec2, b: state_mod.Vec2) f32 {
    const dx = a.x - b.x;
    const dy = a.y - b.y;
    return dx * dx + dy * dy;
}

fn projectileTravelBudgetFromRawId(raw_id: i32) f32 {
    const weapon_id = weapon_data.weaponIdFromInt(raw_id);
    return weapon_data.weapon_stats.get(weapon_id).travel_budget;
}

fn applyPyrokineticEffects(
    state: *state_mod.GameplayState,
    players: []state_mod.PlayerState,
    creatures: *creatures_mod.CreaturePool,
    particles: *particles_mod.ParticlePool,
    dt: f32,
) void {
    if (!(dt > 0.0)) return;
    if (players.len == 0) return;

    const burn_intensities = [_]f32{ 0.8, 0.6, 0.4, 0.3, 0.2 };

    for (players) |*player| {
        if (player.health <= 0.0) continue;
        if (!perks.perkActive(player, PerkId.pyrokinetic)) continue;

        const target_idx = creatureFindInRadius(creatures.entries[0..], player.aim, 12.0, 0);
        if (target_idx == -1) continue;

        var creature = &creatures.entries[@intCast(target_idx)];
        creature.collision_timer = narrowF32(creature.collision_timer - dt);
        if (creature.collision_timer >= 0.0) continue;

        creature.collision_timer = 0.5;
        for (burn_intensities) |intensity| {
            const angle = narrowF32(@as(f32, @floatFromInt(state.rng.rand() % 0x274)) * 0.01);
            _ = particles.spawnParticle(
                state,
                creature.pos,
                angle,
                intensity,
                owner_ref.OwnerRef.fromLocalPlayer(0),
            );
        }
        // Consume native fx_queue_add_random RNG even though verifier does not render decals.
        _ = state.rng.rand();
        _ = state.rng.rand();
        _ = state.rng.rand();
        _ = state.rng.rand();
    }
}

fn updateEvilEyesTargets(
    _: *const state_mod.GameplayState,
    players: []state_mod.PlayerState,
    creatures: []const creatures_mod.CreatureState,
) void {
    if (players.len == 0) return;
    for (players) |*player| {
        if (player.health <= 0.0 or !perks.perkActive(player, PerkId.evil_eyes)) {
            player.evil_eyes_target_creature = -1;
            continue;
        }
        player.evil_eyes_target_creature = creatureFindInRadius(creatures, player.aim, 12.0, 0);
    }
}

fn creatureFindInRadius(
    creatures: []const creatures_mod.CreatureState,
    pos: state_mod.Vec2,
    radius: f32,
    start_index: usize,
) i32 {
    var idx = start_index;
    const max_index = @min(creatures.len, creatures_mod.max_creatures);
    while (idx < max_index) : (idx += 1) {
        const creature = creatures[idx];
        if (!creature.active) continue;
        if (!creature_lifecycle.isCollidable(creature.lifecycle_stage)) continue;
        const dist = narrowF32(state_mod.Vec2.sub(creature.pos, pos).length() - radius);
        const threshold = narrowF32(creature.size * 0.14285715 + 3.0);
        if (threshold < dist) continue;
        return @intCast(idx);
    }
    return -1;
}

fn applyNukeBonus(
    state: *state_mod.GameplayState,
    players: []state_mod.PlayerState,
    projectiles: *projectiles_mod.ProjectilePool,
    creatures: *creatures_mod.CreaturePool,
    bonuses: *bonus_runtime.BonusPool,
    origin: state_mod.Vec2,
    dt: f32,
    world_size: f32,
    tick_index: usize,
) void {
    if (players.len == 0) return;
    const player = &players[0];
    const projectile_owner = owner_ref.OwnerRef.fromLocalPlayer(0);
    const damage_owner = owner_ref.OwnerRef.fromPlayer(@intCast(player.index));
    var nuke_kill_count: i32 = 0;
    state.camera_shake_pulses = 0x14;
    state.camera_shake_timer = 0.2;

    var bullet_count: i32 = @intCast(state.rng.rand() & 3);
    bullet_count += 4;
    var bullet_idx: i32 = 0;
    while (bullet_idx < bullet_count) : (bullet_idx += 1) {
        const angle = @as(f32, @floatFromInt(state.rng.rand() % 0x274)) * 0.01;
        var type_id = @intFromEnum(game_ids.ProjectileTypeId.pistol);
        applyPlayerProjectileSpawnRules(state, players, projectile_owner, &type_id);
        const meta = projectileTravelBudgetFromRawId(type_id);
        const proj_idx = projectiles.spawn(origin, narrowF32(angle), type_id, projectile_owner, meta, false);
        const speed_scale = @as(f32, @floatFromInt(state.rng.rand() % 0x32)) * 0.01 + 0.5;
        projectiles.entries[proj_idx].speed_scale *= narrowF32(speed_scale);
    }

    for (0..2) |_| {
        const angle = @as(f32, @floatFromInt(state.rng.rand() % 0x274)) * 0.01;
        var type_id = @intFromEnum(game_ids.ProjectileTypeId.gauss_gun);
        applyPlayerProjectileSpawnRules(state, players, projectile_owner, &type_id);
        const meta = projectileTravelBudgetFromRawId(type_id);
        _ = projectiles.spawn(origin, narrowF32(angle), type_id, projectile_owner, meta, false);
    }

    consumeExplosionBurstRng(state, 5);

    const prev_spawn_guard = state.bonus_spawn_guard;
    state.bonus_spawn_guard = true;
    defer state.bonus_spawn_guard = prev_spawn_guard;

    for (creatures.entries, 0..) |creature, idx| {
        if (!creature.active) continue;
        const dx = creature.pos.x - origin.x;
        const dy = creature.pos.y - origin.y;
        if (@abs(dx) > 256.0 or @abs(dy) > 256.0) continue;
        const dist = std.math.sqrt(dx * dx + dy * dy);
        if (dist >= 256.0) continue;
        const damage = (256.0 - dist) * 5.0;
        const xp = creatures.applyExplosionDamage(
            state,
            players,
            bonuses,
            idx,
            damage,
            .{},
            damage_owner,
            dt,
            world_size,
            null,
        );
        if (xp > 0) {
            state.debug_nuke_kill_index_sum += @intCast(idx);
            nuke_kill_count += 1;
        }
    }
    state.debug_nuke_kills_last = nuke_kill_count;
    state.debug_nuke_tick_last = @intCast(tick_index);
}

fn applyFinalRevengeOnDeathTransition(
    state: *state_mod.GameplayState,
    players: []state_mod.PlayerState,
    player_index: usize,
    health_before: f32,
    creatures: *creatures_mod.CreaturePool,
    bonuses: *bonus_runtime.BonusPool,
    dt: f32,
    world_size: f32,
    detail_preset: i32,
) void {
    if (player_index >= players.len) return;
    const player = &players[player_index];
    if (!(health_before > 0.0) or !(player.health <= 0.0)) return;
    if (!perks.perkActive(player, PerkId.final_revenge)) return;

    consumeExplosionBurstRng(state, detail_preset);
    const prev_spawn_guard = state.bonus_spawn_guard;
    state.bonus_spawn_guard = true;
    defer state.bonus_spawn_guard = prev_spawn_guard;

    const owner = owner_ref.OwnerRef.fromPlayer(@intCast(player.index));
    for (creatures.entries, 0..) |creature, idx| {
        if (!creature.active) continue;
        const dx = narrowF32(creature.pos.x - player.pos.x);
        const dy = narrowF32(creature.pos.y - player.pos.y);
        if (@abs(dx) > 512.0 or @abs(dy) > 512.0) continue;
        const distance = narrowF32(std.math.sqrt(narrowF32(dx * dx + dy * dy)));
        const remaining = narrowF32(512.0 - distance);
        if (!(remaining > 0.0)) continue;
        const damage = narrowF32(remaining * 5.0);
        _ = creatures.applyExplosionDamage(
            state,
            players,
            bonuses,
            idx,
            damage,
            .{},
            owner,
            dt,
            world_size,
            null,
        );
    }
}

fn applyPlayerProjectileSpawnRules(
    state: *state_mod.GameplayState,
    players: []const state_mod.PlayerState,
    owner: owner_ref.OwnerRef,
    type_id: *i32,
) void {
    if (state.bonus_spawn_guard) return;
    const player_ref = switch (owner) {
        .player => |ref| ref,
        else => return,
    };
    const player_index: ?usize = if (player_ref.local_host and player_ref.index == 0)
        if (players.len == 1) @as(?usize, 0) else null
    else if (player_ref.index < players.len)
        player_ref.index
    else
        null;

    var shot_credit: i32 = 1;
    if (player_index) |idx| {
        if (type_id.* != @intFromEnum(game_ids.ProjectileTypeId.fire_bullets) and
            players[idx].fire_bullets_timer > 0.0)
        {
            type_id.* = @intFromEnum(game_ids.ProjectileTypeId.fire_bullets);
            shot_credit = 2;
        }
        if (idx < state.shots_fired.len) {
            state.shots_fired[idx] += shot_credit;
        }
    }
    state.shots_fired_total += shot_credit;
}

fn consumeExplosionBurstRng(
    state: *state_mod.GameplayState,
    detail_preset: i32,
) void {
    if (detail_preset > 3) {
        for (0..2) |_| {
            _ = state.rng.rand() % 0x266;
        }
    }
    const count: usize = if (detail_preset < 2) 1 else 3 + (if (detail_preset > 3) @as(usize, 1) else 0);
    for (0..count) |_| {
        _ = state.rng.rand() % 0x13A;
        _ = state.rng.rand() & 0x3F;
        _ = state.rng.rand() & 0x3F;
        _ = state.rng.rand();
        _ = state.rng.rand();
    }
}

fn resolveDtFrame(
    overrides: ?[]const DtFrameOverride,
    tick_index: usize,
    default_dt: f32,
) f32 {
    if (overrides) |entries| {
        for (entries) |entry| {
            if (entry.tick_index == tick_index) return entry.dt_frame;
        }
    }
    return default_dt;
}

fn applyQuestStageFromHeader(
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

const ParsedQuestLevel = struct {
    major: i32,
    minor: i32,
};

fn parseQuestLevel(value: []const u8) ?ParsedQuestLevel {
    const dot = std.mem.indexOfScalar(u8, value, '.') orelse return null;
    if (dot == 0 or dot + 1 >= value.len) return null;
    const major = std.fmt.parseInt(i32, value[0..dot], 10) catch return null;
    const minor = std.fmt.parseInt(i32, value[dot + 1 ..], 10) catch return null;
    return .{
        .major = major,
        .minor = minor,
    };
}

fn resolveQuestLevelKey(header: replay_codec.ReplayHeader) ?i32 {
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

fn enforceRushLoadout(players: []state_mod.PlayerState) void {
    for (players) |*player| {
        if (player.weapon_id != game_ids.WeaponId.assault_rifle) {
            player_runtime.weaponAssignPlayer(player, game_ids.WeaponId.assault_rifle);
        }
        player.ammo = @floatFromInt(@max(0, player.clip_size));
    }
}

fn applyReplayEvent(
    event: replay_codec.ReplayEvent,
    state: *state_mod.GameplayState,
    players: []state_mod.PlayerState,
    creatures: *creatures_mod.CreaturePool,
    dt_frame: f32,
    quest_spawn_timeline_ms: *f32,
    quest_no_creatures_timer_ms: *f32,
    quest_completion_transition_ms: *f32,
    pending_capture_state_reset: *bool,
    game_mode: GameModeId,
    player_count: i32,
    quest_unlock_index: i32,
    strict_events: bool,
    perk_menu_open_count: *usize,
    perk_pick_count: *usize,
    menu_open_seen_this_tick: *bool,
) ReplayRunnerError!void {
    switch (event) {
        .perk_menu_open => |open| {
            menu_open_seen_this_tick.* = true;
            if (game_mode == .rush) {
                if (strict_events) return error.UnsupportedEventKind;
                return;
            }
            if (open.player_index < 0 or open.player_index >= @as(i32, @intCast(players.len))) {
                return error.UnsupportedEventPlayerIndex;
            }
            _ = perks.perkSelectionCurrentChoices(
                state,
                players,
                game_mode,
                player_count,
                quest_unlock_index,
            );
            perk_menu_open_count.* += 1;
        },
        .perk_pick => |pick| {
            if (game_mode == .rush) {
                if (strict_events) return error.UnsupportedEventKind;
                return;
            }
            if (pick.player_index < 0 or pick.player_index >= @as(i32, @intCast(players.len))) {
                return error.UnsupportedEventPlayerIndex;
            }
            const applied = perks.perkSelectionPick(
                state,
                players,
                pick.choice_index,
                game_mode,
                player_count,
                quest_unlock_index,
            ) catch |err| switch (err) {
                error.UnsupportedPerkApplyHandler => return error.UnsupportedPerkApplyHandler,
            };
            if (applied == null) {
                if (!strict_events) {
                    return;
                }
                if (menu_open_seen_this_tick.* and state.perk_selection.pending_count <= 0) {
                    return;
                }
                return error.InvalidPerkPickEvent;
            }
            applyReplayPerkCreatureEffects(
                applied.?,
                state,
                creatures,
                narrowF32(dt_frame),
            );
            perk_pick_count.* += 1;
        },
        .capture_bootstrap => |bootstrap| {
            try applyCaptureBootstrapEvent(
                bootstrap,
                state,
                players,
                quest_spawn_timeline_ms,
                quest_no_creatures_timer_ms,
                quest_completion_transition_ms,
            );
        },
        .capture_perk_apply => |capture_perk_apply| {
            if (game_mode == .rush) {
                if (strict_events) return error.UnsupportedEventKind;
                return;
            }
            if (players.len == 0) return;
            var rng_state_before: ?u32 = null;
            if (capture_perk_apply.outside_before) {
                if (capture_perk_apply.pending_before) |pending_before| {
                    state.perk_selection.pending_count = pending_before;
                }
                rng_state_before = state.rng.state;
            }
            const perk_id = std.meta.intToEnum(PerkId, capture_perk_apply.perk_id) catch {
                if (strict_events) return error.UnsupportedEventKind;
                return;
            };
            perks.applyPerk(state, players, perk_id) catch |err| switch (err) {
                error.UnsupportedPerkApplyHandler => return error.UnsupportedPerkApplyHandler,
            };
            applyReplayPerkCreatureEffects(
                perk_id,
                state,
                creatures,
                narrowF32(dt_frame),
            );
            if (capture_perk_apply.outside_before) {
                if (capture_perk_apply.pending_after) |pending_after| {
                    state.perk_selection.pending_count = pending_after;
                }
                if (state.perk_selection.pending_count > 0) {
                    state.perk_selection.pending_count -= 1;
                }
                if (rng_state_before) |rng_state| {
                    state.rng.srand(rng_state);
                }
            }
        },
        .capture_perk_pending => |capture_perk_pending| {
            if (game_mode == .rush) {
                if (strict_events) return error.UnsupportedEventKind;
                return;
            }
            if (capture_perk_pending.perk_pending < 0) {
                if (strict_events) return error.UnsupportedEventKind;
                return;
            }
            state.perk_selection.pending_count = capture_perk_pending.perk_pending;
            state.perk_selection.choices_dirty = true;
        },
        .capture_creature_spawn => |capture_spawn| {
            try applyCaptureCreatureSpawnEvent(
                state,
                creatures,
                capture_spawn,
            );
        },
        .capture_state_transition => |capture_state_transition| {
            for (capture_state_transition.transitions[0..capture_state_transition.transition_count]) |transition| {
                if (transition.target_state == capture_state_reset_target) {
                    pending_capture_state_reset.* = true;
                    break;
                }
            }
        },
    }
}

fn classifyTickEvent(
    event: replay_codec.ReplayEvent,
    defer_menu_open: bool,
) TickEventPhase {
    if (!defer_menu_open) return .pre_step;
    return switch (event) {
        .perk_menu_open => .post_menu_open,
        .capture_creature_spawn => .post_spawn_hook,
        .capture_state_transition => .post_state_transition,
        else => .pre_step,
    };
}

fn applyReplayPerkCreatureEffects(
    perk_id: PerkId,
    state: *state_mod.GameplayState,
    creatures: *creatures_mod.CreaturePool,
    dt_frame: f32,
) void {
    switch (perk_id) {
        PerkId.breathing_room => {
            for (&creatures.entries) |*creature| {
                if (!creature.active) continue;
                creature.lifecycle_stage = narrowF32(creature.lifecycle_stage - dt_frame);
            }
        },
        PerkId.lifeline_50_50 => {
            var kill_toggle = false;
            for (&creatures.entries) |*creature| {
                if (kill_toggle and
                    creature.active and
                    creature.hp <= 500.0 and
                    (creature.flags & spawn_mod.CreatureFlags.anim_ping_pong) == 0)
                {
                    creature.active = false;
                    consumeSpawnBurstRng(state, 4);
                }
                kill_toggle = !kill_toggle;
            }
        },
        else => {},
    }
}

fn applyCaptureBootstrapEvent(
    bootstrap: replay_codec.CaptureBootstrapEvent,
    state: *state_mod.GameplayState,
    players: []state_mod.PlayerState,
    quest_spawn_timeline_ms: *f32,
    quest_no_creatures_timer_ms: *f32,
    quest_completion_transition_ms: *f32,
) ReplayRunnerError!void {
    const player_count = @min(players.len, bootstrap.player_count);
    for (0..player_count) |idx| {
        const payload = bootstrap.players[idx];
        if (payload.weapon_id > 0) {
            const weapon_id = weapon_data.weaponIdFromInt(payload.weapon_id);
            if (players[idx].weapon_id != weapon_id) {
                player_runtime.weaponAssignPlayer(&players[idx], weapon_id);
            }
        }
        players[idx].pos.x = payload.pos_x;
        players[idx].pos.y = payload.pos_y;
        players[idx].health = payload.health;
        players[idx].ammo = payload.ammo;
        players[idx].experience = payload.experience;
        if (payload.level > 0) {
            players[idx].level = payload.level;
        }
        if (payload.clip_size) |clip_size| {
            if (clip_size >= 0) players[idx].clip_size = clip_size;
        }
        if (payload.reload_active) |reload_active| {
            players[idx].reload_active = reload_active;
        }
        if (payload.reload_timer) |reload_timer| {
            players[idx].reload_timer = @max(0.0, reload_timer);
        }
        if (payload.reload_timer_max) |reload_timer_max| {
            players[idx].reload_timer_max = @max(0.0, reload_timer_max);
        }
        if (payload.shot_cooldown) |shot_cooldown| {
            players[idx].shot_cooldown = @max(0.0, shot_cooldown);
        }
        if (payload.spread_heat) |spread_heat| {
            players[idx].spread_heat = @max(0.0, spread_heat);
        }
        if (payload.aim_x) |aim_x| {
            players[idx].aim.x = aim_x;
        }
        if (payload.aim_y) |aim_y| {
            players[idx].aim.y = aim_y;
        }
        if (payload.aim_heading) |aim_heading| {
            players[idx].aim_heading = aim_heading;
            players[idx].aim_dir = state_mod.Vec2.fromAngle(players[idx].aim_heading);
        }
        if (payload.alt_weapon_id) |alt_weapon_id| {
            players[idx].alt_weapon_id = if (alt_weapon_id > 0) weapon_data.weaponIdFromInt(alt_weapon_id) else null;
        }
        if (payload.alt_clip_size) |alt_clip_size| {
            if (alt_clip_size >= 0) players[idx].alt_clip_size = alt_clip_size;
        }
        if (payload.alt_ammo) |alt_ammo| {
            players[idx].alt_ammo = alt_ammo;
        }
        if (payload.alt_reload_active) |alt_reload_active| {
            players[idx].alt_reload_active = alt_reload_active;
        }
        if (payload.alt_reload_timer) |alt_reload_timer| {
            players[idx].alt_reload_timer = @max(0.0, alt_reload_timer);
        }
        if (payload.alt_reload_timer_max) |alt_reload_timer_max| {
            players[idx].alt_reload_timer_max = @max(0.0, alt_reload_timer_max);
        }
        if (payload.alt_shot_cooldown) |alt_shot_cooldown| {
            players[idx].alt_shot_cooldown = @max(0.0, alt_shot_cooldown);
        }
        if (payload.shield_ms) |shield_ms| {
            players[idx].shield_timer = @max(0.0, @as(f32, @floatFromInt(shield_ms)) / 1000.0);
        }
        if (payload.fire_bullets_ms) |fire_bullets_ms| {
            players[idx].fire_bullets_timer = @max(0.0, @as(f32, @floatFromInt(fire_bullets_ms)) / 1000.0);
        }
        if (payload.speed_bonus_ms) |speed_bonus_ms| {
            players[idx].speed_bonus_timer = @max(0.0, @as(f32, @floatFromInt(speed_bonus_ms)) / 1000.0);
        }
        if (payload.hot_tempered_timer) |hot_tempered_timer| {
            players[idx].hot_tempered_timer = @max(0.0, hot_tempered_timer);
        }
        if (payload.man_bomb_timer) |man_bomb_timer| {
            players[idx].man_bomb_timer = @max(0.0, man_bomb_timer);
        }
        if (payload.living_fortress_timer) |living_fortress_timer| {
            players[idx].living_fortress_timer = @max(0.0, living_fortress_timer);
        }
        if (payload.fire_cough_timer) |fire_cough_timer| {
            players[idx].fire_cough_timer = @max(0.0, fire_cough_timer);
        }
    }

    state.perk_selection.pending_count = @max(0, bootstrap.perk_pending_count);
    state.perk_selection.choice_count = @min(bootstrap.perk_choice_count, state.perk_selection.choices.len);
    state.perk_selection.choices_dirty = bootstrap.perk_choices_dirty;
    for (0..state.perk_selection.choices.len) |idx| {
        state.perk_selection.choices[idx] =
            std.meta.intToEnum(PerkId, bootstrap.perk_choices[idx]) catch return error.InvalidCaptureEnumValue;
    }
    for (players, 0..) |*player, player_idx| {
        player.perk_counts = std.EnumArray(PerkId, i32).initFill(0);
        const perk_counts = bootstrap.player_perk_counts[player_idx];
        for (0..perk_counts.pair_count) |pair_idx| {
            const pair = perk_counts.pairs[pair_idx];
            const perk_id = std.meta.intToEnum(PerkId, pair.perk_id) catch return error.InvalidCaptureEnumValue;
            player.perk_counts.set(perk_id, pair.count);
        }
    }

    if (bootstrap.weapon_power_up_ms) |timer_ms| {
        state.bonuses.weapon_power_up = @max(0.0, @as(f32, @floatFromInt(timer_ms)) / 1000.0);
    }
    if (bootstrap.reflex_boost_ms) |timer_ms| {
        state.bonuses.reflex_boost = @max(0.0, @as(f32, @floatFromInt(timer_ms)) / 1000.0);
    }
    if (bootstrap.energizer_ms) |timer_ms| {
        state.bonuses.energizer = @max(0.0, @as(f32, @floatFromInt(timer_ms)) / 1000.0);
    }
    if (bootstrap.double_experience_ms) |timer_ms| {
        state.bonuses.double_experience = @max(0.0, @as(f32, @floatFromInt(timer_ms)) / 1000.0);
    }
    if (bootstrap.freeze_ms) |timer_ms| {
        state.bonuses.freeze = @max(0.0, @as(f32, @floatFromInt(timer_ms)) / 1000.0);
    }
    state.time_scale_active = state.bonuses.reflex_boost > 0.0;

    if (bootstrap.perk_interval_man_bomb) |value| {
        state.perk_interval_man_bomb = @max(0.0, value);
    }
    if (bootstrap.perk_interval_fire_cough) |value| {
        state.perk_interval_fire_cough = @max(0.0, value);
    }
    if (bootstrap.perk_interval_hot_tempered) |value| {
        state.perk_interval_hot_tempered = @max(0.0, value);
    }

    if (bootstrap.quest_session) |quest_session| {
        quest_spawn_timeline_ms.* = @max(0.0, quest_session.spawn_timeline_ms);
        quest_no_creatures_timer_ms.* = @max(0.0, quest_session.no_creatures_timer_ms);
        if (quest_session.completion_transition_ms < 0.0) {
            quest_completion_transition_ms.* = -1.0;
        } else {
            quest_completion_transition_ms.* = @max(0.0, quest_session.completion_transition_ms);
        }
    }
}

fn applyCaptureCreatureSpawnEvent(
    state: *state_mod.GameplayState,
    creatures: *creatures_mod.CreaturePool,
    event: replay_codec.CaptureCreatureSpawnEvent,
) ReplayRunnerError!void {
    var spawned_indices = [_]bool{false} ** creatures_mod.max_creatures;
    var active_before = [_]bool{false} ** creatures_mod.max_creatures;
    for (creatures.entries, 0..) |entry, idx| {
        active_before[idx] = entry.active;
    }

    for (event.spawns[0..event.spawn_count]) |spawn_row| {
        creatures.spawnTemplateCall(
            .{
                .template_id = spawn_row.template_id,
                .pos = .{
                    .x = spawn_row.pos_x,
                    .y = spawn_row.pos_y,
                },
                .heading = spawn_row.heading,
            },
            &state.rng,
        ) catch |err| switch (err) {
            error.UnsupportedSpawnTemplate => return error.UnsupportedSpawnTemplate,
        };
        for (creatures.entries, 0..) |entry, idx| {
            if (!active_before[idx] and entry.active) {
                spawned_indices[idx] = true;
            }
            active_before[idx] = entry.active;
        }
    }

    for (event.added_head[0..event.added_head_count]) |row| {
        if (row.index < 0 or row.index >= creatures.entries.len) continue;
        const idx: usize = @intCast(row.index);
        const entry = &creatures.entries[idx];
        if (!entry.active) continue;

        const ai_mode = if (row.has_ai_mode) try parseCaptureCreatureAiMode(row.ai_mode) else null;

        const flags_i32 = if (row.has_flags) row.flags else @as(i32, @intCast(entry.flags));
        const needs_ai7_rollover_rng_backfill = spawned_indices[idx] and
            row.has_link_index and
            isAi7LinkTimerRolloverValue(row.link_index) and
            (flags_i32 & @as(i32, @intCast(spawn_mod.CreatureFlags.ai7_link_timer))) != 0;
        if (needs_ai7_rollover_rng_backfill) {
            _ = state.rng.rand();
        }

        if (row.has_pos) {
            entry.pos = .{
                .x = row.pos_x,
                .y = row.pos_y,
            };
        }
        if (row.has_heading) entry.heading = row.heading;
        if (row.has_target_heading) entry.target_heading = row.target_heading;
        if (ai_mode) |mode| entry.ai_mode = mode;
        if (row.has_link_index) entry.link_index = row.link_index;
        if (row.has_hp) entry.hp = row.hp;
        if (row.has_lifecycle_stage) entry.lifecycle_stage = row.lifecycle_stage;
        if (row.has_orbit_angle) entry.orbit_angle = row.orbit_angle;
        if (row.has_orbit_radius) entry.orbit_radius = row.orbit_radius;
        if (row.has_flags) entry.flags = @intCast(@max(0, flags_i32));
        if (row.has_type_id) entry.type_id = row.type_id;
    }
}

fn applyCaptureStateReset(
    state: *state_mod.GameplayState,
    players: []state_mod.PlayerState,
    creatures: *creatures_mod.CreaturePool,
    particles: *particles_mod.ParticlePool,
    projectiles: *projectiles_mod.ProjectilePool,
    secondary_projectiles: *secondary_projectiles_mod.SecondaryProjectilePool,
    bonuses: *bonus_runtime.BonusPool,
    world_size: f32,
    quest_start_weapon_id: i32,
    fx_toggle: i32,
    capture_spawn_events_authoritative: bool,
    quest_spawn_entries_storage: []spawn_mod.QuestSpawnEntry,
    reset_quest_spawn_entries_len: usize,
    quest_spawn_entries: *[]spawn_mod.QuestSpawnEntry,
    quest_spawn_timeline_ms: *f32,
    quest_no_creatures_timer_ms: *f32,
    quest_completion_transition_ms: *f32,
) void {
    const rng_state = state.rng.state;
    const status_quest_unlock_index = state.status_quest_unlock_index;
    const status_quest_unlock_index_full = state.status_quest_unlock_index_full;
    const status_weapon_usage_counts = state.status_weapon_usage_counts;
    const game_mode = state.game_mode;
    const hardcore = state.hardcore;
    const quest_stage_major = state.quest_stage_major;
    const quest_stage_minor = state.quest_stage_minor;
    const perk_pending_count = state.perk_selection.pending_count;
    const perk_choice_count = state.perk_selection.choice_count;
    const perk_choices_dirty = state.perk_selection.choices_dirty;
    const perk_choices = state.perk_selection.choices;
    const perk_interval_man_bomb = state.perk_interval_man_bomb;
    const perk_interval_fire_cough = state.perk_interval_fire_cough;
    const perk_interval_hot_tempered = state.perk_interval_hot_tempered;

    state.* = state_mod.GameplayState.init(rng_state);
    state.status_quest_unlock_index = status_quest_unlock_index;
    state.status_quest_unlock_index_full = status_quest_unlock_index_full;
    state.status_weapon_usage_counts = status_weapon_usage_counts;
    state.fx_toggle = fx_toggle;
    state.game_mode = game_mode;
    state.hardcore = hardcore;
    state.quest_stage_major = quest_stage_major;
    state.quest_stage_minor = quest_stage_minor;
    state.perk_selection.pending_count = perk_pending_count;
    state.perk_selection.choice_count = perk_choice_count;
    state.perk_selection.choices_dirty = perk_choices_dirty;
    state.perk_selection.choices = perk_choices;
    state.perk_interval_man_bomb = perk_interval_man_bomb;
    state.perk_interval_fire_cough = perk_interval_fire_cough;
    state.perk_interval_hot_tempered = perk_interval_hot_tempered;

    player_runtime.resetPlayers(players, world_size, null);
    for (players) |*player| {
        const quest_weapon = weapon_data.weaponIdFromInt(quest_start_weapon_id);
        player_runtime.weaponAssignPlayer(player, quest_weapon);
        if (quest_start_weapon_id == @intFromEnum(game_ids.WeaponId.pistol)) {
            player.clip_size = @max(12, player.clip_size);
            if (player.ammo < 12.0) {
                player.ammo = 12.0;
            }
        }
    }

    creatures.reset();
    particles.reset();
    projectiles.reset();
    secondary_projectiles.reset();
    bonuses.reset();
    creatures.capture_spawn_events_authoritative = capture_spawn_events_authoritative;
    quest_spawn_entries.* = quest_spawn_entries_storage[0..reset_quest_spawn_entries_len];
    quest_spawn_timeline_ms.* = 0.0;
    quest_no_creatures_timer_ms.* = 0.0;
    quest_completion_transition_ms.* = -1.0;
}

fn applyJinxedEffects(
    state: *state_mod.GameplayState,
    players: []state_mod.PlayerState,
    creatures: *creatures_mod.CreaturePool,
    dt: f32,
) void {
    if (state.jinxed_timer >= 0.0) {
        state.jinxed_timer = narrowF32(state.jinxed_timer - dt);
    }
    if (state.jinxed_timer >= 0.0) return;
    if (players.len == 0) return;
    if (!perks.perkActive(&players[0], PerkId.jinxed)) return;

    if ((state.rng.rand() % 10) == 3) {
        const target_idx = selectJinxedAccidentTarget(state, players);
        players[target_idx].health = narrowF32(players[target_idx].health - 5.0);
    }

    const timer_roll = @as(f32, @floatFromInt(state.rng.rand() % 0x14));
    state.jinxed_timer = narrowF32(narrowF32(timer_roll * 0.1) + state.jinxed_timer + 2.0);

    if (state.bonuses.freeze > 0.0) return;

    const pool_limit: usize = 0x180;
    const pool_mod = @min(pool_limit, creatures.entries.len);
    if (pool_mod == 0) return;

    var idx: usize = @intCast(state.rng.rand() % @as(u32, @intCast(pool_mod)));
    var attempts: usize = 0;
    while (attempts < 10 and !creatures.entries[idx].active) : (attempts += 1) {
        idx = @intCast(state.rng.rand() % @as(u32, @intCast(pool_mod)));
    }
    if (!creatures.entries[idx].active) return;

    creatures.entries[idx].hp = -1.0;
    creatures.entries[idx].lifecycle_stage = narrowF32(
        creatures.entries[idx].lifecycle_stage - dt * 20.0,
    );
    awardExperienceFromReward(state, &players[0], creatures.entries[idx].reward_value);
}

fn selectJinxedAccidentTarget(
    state: *state_mod.GameplayState,
    players: []const state_mod.PlayerState,
) usize {
    if (players.len == 0) return 0;

    var alive_indices = [_]usize{0} ** state_mod.max_players;
    var alive_count: usize = 0;
    for (players, 0..) |player, idx| {
        if (player.health <= 0.0) continue;
        if (alive_count >= alive_indices.len) break;
        alive_indices[alive_count] = idx;
        alive_count += 1;
    }
    if (alive_count == 0) return 0;
    if (alive_count == 1) return alive_indices[0];
    const pick = state.rng.rand() % @as(u32, @intCast(alive_count));
    return alive_indices[@intCast(pick)];
}

fn awardExperienceFromReward(
    state: *state_mod.GameplayState,
    player: *state_mod.PlayerState,
    reward_value: f32,
) void {
    const first_gain = awardExperienceOnceFromReward(player, reward_value);
    if (first_gain <= 0) return;
    if (state.bonuses.double_experience > 0.0) {
        _ = awardExperienceOnceFromReward(player, reward_value);
    }
}

fn awardExperienceOnceFromReward(
    player: *state_mod.PlayerState,
    reward_value: f32,
) i32 {
    if (reward_value <= 0.0) return 0;

    const before = player.experience;
    const before_f32 = narrowF32(@as(f32, @floatFromInt(before)));
    const total_f32 = narrowF32(before_f32 + reward_value);
    const after: i32 = @intFromFloat(total_f32);
    player.experience = after;
    return after - before;
}

fn consumeSpawnBurstRng(
    state: *state_mod.GameplayState,
    count: usize,
) void {
    for (0..count) |_| {
        _ = state.rng.rand();
        _ = state.rng.rand();
        _ = state.rng.rand();
        _ = state.rng.rand();
    }
}

fn applyFreezePickupCorpseCleanupRng(
    state: *state_mod.GameplayState,
    creatures: *creatures_mod.CreaturePool,
    freeze_corpse_at_tick_start: []const bool,
) void {
    for (&creatures.entries, 0..) |*creature, idx| {
        if (!creature.active) continue;
        if (creature.hp > 0.0) continue;

        if (creature_lifecycle.isDespawned(creature.lifecycle_stage)) {
            creature.active = false;
            continue;
        }

        if (idx < freeze_corpse_at_tick_start.len and freeze_corpse_at_tick_start[idx]) {
            // `bonus_apply` freeze pickup corpse pass: 8 freeze shards + 1 freeze shatter.
            for (0..8) |_| {
                _ = state.rng.rand() % 0x264;
                for (0..6) |_| {
                    _ = state.rng.rand();
                }
            }
            _ = state.rng.rand() % 0x264;
            for (0..4) |_| {
                _ = state.rng.rand();
                _ = state.rng.rand();
            }
            for (0..4) |_| {
                _ = state.rng.rand() % 0x264;
                for (0..6) |_| {
                    _ = state.rng.rand();
                }
            }
        }

        creature.active = false;
    }
}

fn updatePlayerFromReplayInput(
    player: *state_mod.PlayerState,
    input: replay_codec.ReplayPlayerInput,
    flags: replay_codec.InputFlags,
    state: *const state_mod.GameplayState,
    creatures: ?*const creatures_mod.CreaturePool,
    dt: f32,
) void {
    const prev_pos = player.pos;
    var movement_dt = dt;
    if (state.time_scale_active and movement_dt > 0.0) {
        const reflex_f32 = narrowF32(state.bonuses.reflex_boost);
        var time_scale_factor = narrowF32(0.3);
        if (reflex_f32 < 1.0) {
            time_scale_factor = narrowF32((1.0 - reflex_f32) * 0.7 + 0.3);
        }
        if (time_scale_factor > 0.0) {
            movement_dt = narrowF32((0.6 / time_scale_factor) * movement_dt);
        }
    }

    const move_mode = resolveMoveModeForUpdate(flags);
    const aim_scheme = resolveAimSchemeForUpdate(flags);

    var raw_move = state_mod.Vec2{
        .x = narrowF32(input.move_x),
        .y = narrowF32(input.move_y),
    };
    const raw_mag = raw_move.length();
    var move_ext = directionFromHeadingNativeExt(player.heading);

    var speed_multiplier = player.speed_multiplier;
    if (player.speed_bonus_timer > 0.0) {
        speed_multiplier += 1.0;
    }

    var speed: f32 = 0.0;
    var phase_sign: f32 = 1.0;
    var move_delta_override: ?state_mod.Vec2 = null;
    const player_controlled_movement =
        move_mode != movement_control_computer and
        aim_scheme != aim_scheme_computer;

    if (player_controlled_movement) {
        if (move_mode == movement_control_relative) {
            const turning_left = flags.turn_left_pressed orelse false;
            const turning_right = flags.turn_right_pressed orelse false;
            const moving_forward = flags.move_forward_pressed orelse false;
            const moving_backward = flags.move_backward_pressed orelse false;
            var turned = false;

            if (player.turn_speed < 1.0) player.turn_speed = 1.0;
            if (player.turn_speed > 7.0) player.turn_speed = 7.0;

            if (turning_left) {
                player.turn_speed = narrowF32(player.turn_speed + movement_dt * 10.0);
                const turn_step = narrowF32(player.turn_speed * movement_dt * 0.5);
                player.heading = narrowF32(player.heading - turn_step);
                player.aim_heading = narrowF32(player.aim_heading - turn_step);
                turned = true;
            } else if (turning_right) {
                player.turn_speed = narrowF32(player.turn_speed + movement_dt * 10.0);
                const turn_step = narrowF32(player.turn_speed * movement_dt * 0.5);
                player.heading = narrowF32(player.heading + turn_step);
                player.aim_heading = narrowF32(player.aim_heading + turn_step);
                turned = true;
            }

            if (moving_forward) {
                playerAccelerateMoveSpeed(player, movement_dt);
                playerApplyMoveSpeedCaps(player);
                move_delta_override = playerMoveDeltaFromHeading(player, movement_dt, 25.0);
            } else if (moving_backward) {
                playerAccelerateMoveSpeed(player, movement_dt);
                phase_sign = -1.0;
                move_delta_override = playerMoveDeltaFromHeading(player, movement_dt, -25.0);
            } else {
                if (!turned) {
                    player.turn_speed = 1.0;
                }
                playerDecelerateMoveSpeed(player, movement_dt);
                move_delta_override = playerMoveDeltaFromHeading(player, movement_dt, 25.0);
            }
        } else if (move_mode == movement_control_static) {
            const moving_forward = flags.move_forward_pressed orelse (raw_move.y < -0.5);
            const moving_backward = flags.move_backward_pressed orelse (raw_move.y > 0.5);
            const turning_left = flags.turn_left_pressed orelse (raw_move.x < -0.5);
            const turning_right = flags.turn_right_pressed orelse (raw_move.x > 0.5);

            var target_heading = relative_move_heading_none;
            if (turning_left) target_heading = relative_move_heading_left;
            if (turning_right) target_heading = relative_move_heading_right;

            if (moving_forward) {
                if (turning_left) {
                    target_heading = relative_move_heading_forward_left;
                } else if (turning_right) {
                    target_heading = relative_move_heading_forward_right;
                } else {
                    target_heading = relative_move_heading_forward;
                }
            }
            if (moving_backward) {
                if (turning_left) {
                    target_heading = relative_move_heading_backward_left;
                } else if (turning_right) {
                    target_heading = relative_move_heading_backward_right;
                } else {
                    target_heading = relative_move_heading_backward;
                }
            }

            if (!moving_backward and target_heading == relative_move_heading_none) {
                playerDecelerateMoveSpeed(player, movement_dt);
                move_ext = directionFromHeadingNativeExt(player.heading);
                const move_dx = headingMulNarrow(move_ext.x, player.move_speed * speed_multiplier * 25.0);
                const move_dy = headingMulNarrow(move_ext.y, player.move_speed * speed_multiplier * 25.0);
                move_delta_override = .{
                    .x = narrowF32(movement_dt * move_dx),
                    .y = narrowF32(movement_dt * move_dy),
                };
            } else {
                const heading_result = playerHeadingApproachTargetWithDelta(
                    player,
                    target_heading,
                    movement_dt,
                );
                player.aim_heading = narrowF32(player.aim_heading + heading_result.turn_delta);
                playerAccelerateMoveSpeed(player, movement_dt);
                playerApplyMoveSpeedCaps(player);
                move_ext = directionFromHeadingNativeExt(player.heading);
                const turn_align =
                    (native_pi - heading_result.diff) *
                    speed_multiplier *
                    relative_move_turn_align_scale;
                const move_dx = headingMulNarrow(move_ext.x, player.move_speed * turn_align);
                const move_dy = headingMulNarrow(move_ext.y, player.move_speed * turn_align);
                move_delta_override = .{
                    .x = narrowF32(movement_dt * move_dx),
                    .y = narrowF32(movement_dt * move_dy),
                };
            }
        } else {
            const moving_input = raw_mag > 0.2;
            var turn_alignment_scale: f32 = 1.0;
            if (moving_input) {
                const inv = if (raw_mag > 1e-9) 1.0 / raw_mag else 0.0;
                raw_move = raw_move.mul(inv);
                const target_heading = normalizeHeading(raw_move.toHeading());
                const angle_diff = playerHeadingApproachTarget(player, target_heading, movement_dt);
                move_ext = directionFromHeadingNativeExt(player.heading);
                turn_alignment_scale = @max(0.0, (native_pi - angle_diff) / native_pi);
                playerAccelerateMoveSpeed(player, movement_dt);
            } else {
                playerDecelerateMoveSpeed(player, movement_dt);
                move_ext = directionFromHeadingNativeExt(player.heading);
            }

            playerApplyMoveSpeedCaps(player);
            speed = player.move_speed * speed_multiplier * 25.0;
            if (moving_input) {
                speed *= @min(1.0, raw_mag);
                speed *= turn_alignment_scale;
            }
        }
    } else {
        const move_input_threshold: f32 = 0.2;
        const moving_input = raw_mag > move_input_threshold;
        var turn_alignment_scale: f32 = 1.0;
        if (moving_input) {
            const inv = if (raw_mag > 1e-9) 1.0 / raw_mag else 0.0;
            raw_move = raw_move.mul(inv);
            const target_heading = normalizeHeading(raw_move.toHeading());
            const angle_diff = playerHeadingApproachTarget(player, target_heading, movement_dt);
            move_ext = directionFromHeadingNativeExt(player.heading);
            turn_alignment_scale = @max(0.0, (native_pi - angle_diff) / native_pi);
            playerAccelerateMoveSpeed(player, movement_dt);
        } else {
            playerDecelerateMoveSpeed(player, movement_dt);
            move_ext = directionFromHeadingNativeExt(player.heading);
        }

        playerApplyMoveSpeedCaps(player);
        speed = player.move_speed * speed_multiplier * 25.0;
        if (moving_input) {
            speed *= @min(1.0, raw_mag);
            speed *= turn_alignment_scale;
        }
    }

    const delta = if (move_delta_override) |override|
        override
    else
        state_mod.Vec2{
            .x = headingMulNarrow(move_ext.x, narrowF32(speed * movement_dt)),
            .y = headingMulNarrow(move_ext.y, narrowF32(speed * movement_dt)),
        };
    playerApplyMoveWithSpawnAvoidance(player, delta, creatures);

    const move_delta = state_mod.Vec2.sub(player.pos, prev_pos);
    const reload_stationary = @abs(move_delta.x) <= 1e-9 and @abs(move_delta.y) <= 1e-9;
    player.reload_stationary_latch = reload_stationary;
    if (!reload_stationary) {
        // Native clears these post-perk-tick timers after movement when position changed.
        player.man_bomb_timer = 0.0;
        player.living_fortress_timer = 0.0;
    }
    player.move_phase = narrowF32(player.move_phase + narrowF32(phase_sign * movement_dt * player.move_speed * 19.0));

    player.aim = .{
        .x = narrowF32(input.aim_x),
        .y = narrowF32(input.aim_y),
    };
    var aim_dir = state_mod.Vec2.sub(player.aim, player.pos);
    const aim_len_sq = aim_dir.lengthSq();
    if (aim_len_sq > 0.0) {
        aim_dir = aim_dir.mul(1.0 / std.math.sqrt(aim_len_sq));
        player.aim_dir = aim_dir;
        player.aim_heading = player.aim_dir.toHeading();
    }
}

fn finalizePlayerPostUpdate(
    player: *state_mod.PlayerState,
    world_size: f32,
) void {
    while (player.move_phase > 14.0) {
        player.move_phase = narrowF32(player.move_phase - 14.0);
    }
    while (player.move_phase < 0.0) {
        player.move_phase = narrowF32(player.move_phase + 14.0);
    }

    const half_size = @max(0.0, player.size * 0.5);
    const clamped_pos = player.pos.clampRect(
        half_size,
        half_size,
        narrowF32(world_size - half_size),
        narrowF32(world_size - half_size),
    );
    player.pos = .{
        .x = narrowF32(clamped_pos.x),
        .y = narrowF32(clamped_pos.y),
    };
    if (player.muzzle_flash_alpha > 0.8) {
        player.muzzle_flash_alpha = 0.8;
    }
}

fn resolveMoveModeForUpdate(
    flags: replay_codec.InputFlags,
) i32 {
    if (flags.move_mode) |mode| return mode;
    if (flags.move_forward_pressed != null and
        flags.move_backward_pressed != null and
        flags.turn_left_pressed != null and
        flags.turn_right_pressed != null)
    {
        return movement_control_static;
    }
    return movement_control_dual_action_pad;
}

fn resolveAimSchemeForUpdate(
    flags: replay_codec.InputFlags,
) i32 {
    if (flags.aim_scheme) |scheme| return scheme;
    return aim_scheme_mouse;
}

fn playerMoveDeltaFromHeading(
    player: *const state_mod.PlayerState,
    movement_dt: f32,
    speed_scale: f32,
) state_mod.Vec2 {
    const move_ext = directionFromHeadingNativeExt(player.heading);
    const move_dx = headingMulNarrow(move_ext.x, player.move_speed * speed_scale);
    const move_dy = headingMulNarrow(move_ext.y, player.move_speed * speed_scale);
    return .{
        .x = narrowF32(movement_dt * move_dx),
        .y = narrowF32(movement_dt * move_dy),
    };
}

const HeadingDirectionExt = struct {
    x: f64,
    y: f64,
};

fn headingMulNarrow(component: f64, scalar: f32) f32 {
    return narrowF32(@as(f32, @floatCast(component * @as(f64, @floatCast(scalar)))));
}

fn distanceF32XY(
    ax: f32,
    ay: f32,
    bx: f32,
    by: f32,
) f32 {
    const dx = narrowF32(ax - bx);
    const dy = narrowF32(ay - by);
    const dist_sq = narrowF32(narrowF32(dx * dx) + narrowF32(dy * dy));
    return narrowF32(std.math.sqrt(dist_sq));
}

fn playerApplyMoveWithSpawnAvoidance(
    player: *state_mod.PlayerState,
    delta: state_mod.Vec2,
    creatures: ?*const creatures_mod.CreaturePool,
) void {
    var dx = delta.x;
    var dy = delta.y;
    if (perks.perkActive(player, PerkId.alternate_weapon)) {
        dx = narrowF32(dx * 0.8);
        dy = narrowF32(dy * 0.8);
    }

    var pos_x = narrowF32(player.pos.x + dx);
    var pos_y = narrowF32(player.pos.y + dy);

    if (creatures) |creature_pool| {
        const slot_count = @min(creature_pool.spawn_slot_count, creature_pool.spawn_slots.len);
        for (creature_pool.spawn_slots[0..slot_count]) |slot| {
            if (slot.owner_creature < 0) continue;
            const owner_idx: usize = @intCast(slot.owner_creature);
            if (owner_idx >= creature_pool.entries.len) continue;
            const owner = creature_pool.entries[owner_idx];
            const owner_pos = owner.pos;
            const radius = narrowF32((owner.size + player.size) * 0.33333334);
            if (distanceF32XY(owner_pos.x, owner_pos.y, pos_x, pos_y) > radius) continue;

            const old_x = narrowF32(pos_x - dx);
            const old_y = narrowF32(pos_y - dy);
            const old_dist = distanceF32XY(owner_pos.x, owner_pos.y, old_x, old_y);
            const x_candidate = narrowF32(old_x + dx);
            const y_candidate = narrowF32(old_y + dy);

            if (radius < old_dist) {
                pos_x = x_candidate;
                pos_y = old_y;
                if (distanceF32XY(owner_pos.x, owner_pos.y, pos_x, pos_y) <= radius) {
                    pos_x = narrowF32(x_candidate - dx);
                    pos_y = y_candidate;
                    if (distanceF32XY(owner_pos.x, owner_pos.y, pos_x, pos_y) <= radius) {
                        pos_y = narrowF32(y_candidate - dy);
                    }
                }
            } else {
                pos_x = x_candidate;
                pos_y = y_candidate;
            }
        }
    }

    player.pos = .{
        .x = narrowF32(pos_x),
        .y = narrowF32(pos_y),
    };
}

fn directionFromHeadingNativeExt(heading: f32) HeadingDirectionExt {
    const radians = @as(f64, @floatCast(heading - native_half_pi));
    return .{
        .x = std.math.cos(radians),
        .y = std.math.sin(radians),
    };
}

fn directionFromHeadingNative(heading: f32) state_mod.Vec2 {
    const ext = directionFromHeadingNativeExt(heading);
    return .{
        .x = @floatCast(ext.x),
        .y = @floatCast(ext.y),
    };
}

fn playerAccelerateMoveSpeed(
    player: *state_mod.PlayerState,
    dt: f32,
) void {
    if (perks.perkActive(player, PerkId.long_distance_runner)) {
        if (player.move_speed < 2.0) {
            player.move_speed = narrowF32(player.move_speed + dt * 4.0);
        }
        player.move_speed = narrowF32(player.move_speed + dt);
        if (player.move_speed > 2.8) player.move_speed = 2.8;
    } else {
        player.move_speed = narrowF32(player.move_speed + dt * 5.0);
        if (player.move_speed > 2.0) player.move_speed = 2.0;
    }
}

fn playerDecelerateMoveSpeed(
    player: *state_mod.PlayerState,
    dt: f32,
) void {
    player.move_speed = narrowF32(player.move_speed - dt * 15.0);
    if (player.move_speed < 0.0) player.move_speed = 0.0;
}

fn playerApplyMoveSpeedCaps(
    player: *state_mod.PlayerState,
) void {
    if (player.weapon_id == game_ids.WeaponId.mean_minigun and player.move_speed > 0.8) {
        player.move_speed = 0.8;
    }
}

const HeadingApproachResult = struct {
    diff: f32,
    turn_delta: f32,
};

fn playerHeadingApproachTargetWithDelta(
    player: *state_mod.PlayerState,
    target_heading: f32,
    dt: f32,
) HeadingApproachResult {
    var heading = normalizeHeading(player.heading);
    player.heading = heading;
    const target = target_heading;

    const direct = narrowF32(@abs(narrowF32(target - heading)));
    var high = heading;
    if (target > high) high = target;
    var low = heading;
    if (target < low) low = target;
    const wrapped = narrowF32(@abs(narrowF32(native_tau - high + low)));
    const diff = if (direct >= wrapped) wrapped else direct;

    const scaled = narrowF32(dt * diff);
    var turn_delta: f32 = 0.0;
    if (direct <= wrapped) {
        if (target > heading) {
            turn_delta = narrowF32(scaled * 5.0);
        } else {
            turn_delta = narrowF32(scaled * -5.0);
        }
    } else {
        if (target >= heading) {
            turn_delta = narrowF32(scaled * -5.0);
        } else {
            turn_delta = narrowF32(scaled * 5.0);
        }
    }

    heading = narrowF32(heading + turn_delta);
    player.heading = heading;
    return .{
        .diff = diff,
        .turn_delta = turn_delta,
    };
}

fn playerHeadingApproachTarget(
    player: *state_mod.PlayerState,
    target_heading: f32,
    dt: f32,
) f32 {
    return playerHeadingApproachTargetWithDelta(player, target_heading, dt).diff;
}

fn normalizeHeading(value: f32) f32 {
    return native_math.wrapAngle0Tau(value);
}

fn applyPerkWorldDtSteps(
    players: []const state_mod.PlayerState,
    dt: f32,
) f32 {
    if (!(dt > 0.0)) return dt;
    if (players.len == 0) return dt;
    if (!perks.perkActive(&players[0], PerkId.reflex_boosted)) return dt;
    return narrowF32(dt * 0.9);
}

fn playerFrameDtAfterRoundtrip(
    dt: f32,
    time_scale_active: bool,
    reflex_boost_timer: f32,
) f32 {
    if (!time_scale_active or dt <= 0.0) {
        return dt;
    }

    var time_scale_factor = narrowF32(0.3);
    if (reflex_boost_timer < 1.0) {
        time_scale_factor = narrowF32((1.0 - reflex_boost_timer) * 0.7 + 0.3);
    }
    if (time_scale_factor <= 0.0) {
        return dt;
    }

    const movement_dt = narrowF32((0.6 / time_scale_factor) * dt);
    return narrowF32(time_scale_factor * movement_dt * 1.6666666);
}

test "replay scaffold rejects unsupported demo/preserve feature flags" {
    try std.testing.expectError(
        error.UnsupportedDemoMode,
        ensureSupportedReplayFeatureFlags(true, false),
    );
    try std.testing.expectError(
        error.UnsupportedPreserveBugs,
        ensureSupportedReplayFeatureFlags(false, true),
    );
    try ensureSupportedReplayFeatureFlags(false, false);
}

test "survival scaffold tracks event and input counters" {
    const allocator = std.testing.allocator;

    var replay = try buildTestReplay(allocator, .{
        .tick_rate = 60,
        .inputs = &.{
            replay_codec.fire_pressed_flag,
            replay_codec.reload_pressed_flag,
        },
        .events = &.{
            .{ .perk_menu_open = .{ .tick_index = 0, .player_index = 0 } },
        },
    });
    defer replay.deinit(allocator);

    const result = try runReplayScaffold(replay);
    try std.testing.expectEqual(@as(usize, 2), result.ticks);
    try std.testing.expectEqual(@as(i64, 33), result.elapsed_ms_nominal);
    try std.testing.expectEqual(@as(i64, 33), result.elapsed_ms_sim);
    try std.testing.expectEqual(@as(usize, 1), result.perk_menu_open_count);
    try std.testing.expectEqual(@as(usize, 0), result.perk_pick_count);
    try std.testing.expectEqual(@as(usize, 1), result.fire_pressed_count);
    try std.testing.expectEqual(@as(usize, 1), result.reload_pressed_count);
    try std.testing.expectEqual(@as(usize, 0), result.stage_spawn_count);
    try std.testing.expectEqual(@as(usize, 1), result.wave_spawn_count);
    try std.testing.expectEqual(@intFromEnum(game_ids.WeaponId.pistol), result.player_weapon_id);
    try std.testing.expectEqual(@intFromEnum(game_ids.WeaponId.pistol), result.most_used_weapon_id);
    try std.testing.expectEqual(@as(i32, 0), result.shots_fired);
    try std.testing.expectEqual(@as(i32, 0), result.shots_hit);
    try std.testing.expectEqual(@as(i32, 1), result.player_level);
    try std.testing.expectEqual(@as(i32, 0), result.perk_pending_count);
    try std.testing.expect(!result.survival_reward_fire_seen);
}

test "survival scaffold rejects unsupported event player index" {
    const allocator = std.testing.allocator;

    var replay = try buildTestReplay(allocator, .{
        .tick_rate = 60,
        .inputs = &.{replay_codec.fire_down_flag},
        .events = &.{
            .{ .perk_menu_open = .{ .tick_index = 0, .player_index = 1 } },
        },
    });
    defer replay.deinit(allocator);

    try std.testing.expectError(
        error.UnsupportedEventPlayerIndex,
        runReplayScaffold(replay),
    );
}

test "survival scaffold accepts multiplayer event player indices" {
    const allocator = std.testing.allocator;

    const replay = try buildTestReplayMulti(allocator, .{
        .tick_rate = 60,
        .player_count = 2,
        .inputs = &.{
            &.{ replay_codec.fire_pressed_flag, replay_codec.reload_pressed_flag },
        },
        .events = &.{
            .{ .perk_menu_open = .{ .tick_index = 0, .player_index = 1 } },
        },
    });
    defer replay.deinit(allocator);

    const result = try runReplayScaffold(replay);
    try std.testing.expectEqual(@as(usize, 1), result.ticks);
    try std.testing.expectEqual(@as(usize, 1), result.perk_menu_open_count);
    try std.testing.expectEqual(@as(usize, 1), result.fire_pressed_count);
    try std.testing.expectEqual(@as(usize, 1), result.reload_pressed_count);
}

test "survival scaffold rejects multiplayer event player index out of bounds" {
    const allocator = std.testing.allocator;

    const replay = try buildTestReplayMulti(allocator, .{
        .tick_rate = 60,
        .player_count = 2,
        .inputs = &.{
            &.{ 0, 0 },
        },
        .events = &.{
            .{ .perk_menu_open = .{ .tick_index = 0, .player_index = 2 } },
        },
    });
    defer replay.deinit(allocator);

    try std.testing.expectError(
        error.UnsupportedEventPlayerIndex,
        runReplayScaffold(replay),
    );
}

test "survival scaffold rejects invalid perk pick event in strict mode" {
    const allocator = std.testing.allocator;

    var replay = try buildTestReplay(allocator, .{
        .tick_rate = 60,
        .inputs = &.{replay_codec.fire_down_flag},
        .events = &.{
            .{ .perk_pick = .{ .tick_index = 0, .player_index = 0, .choice_index = 0 } },
        },
    });
    defer replay.deinit(allocator);

    try std.testing.expectError(
        error.InvalidPerkPickEvent,
        runReplayScaffold(replay),
    );
}

test "survival scaffold can skip invalid perk pick event in non-strict mode" {
    const allocator = std.testing.allocator;

    var replay = try buildTestReplay(allocator, .{
        .tick_rate = 60,
        .inputs = &.{replay_codec.fire_down_flag},
        .events = &.{
            .{ .perk_pick = .{ .tick_index = 0, .player_index = 0, .choice_index = 0 } },
        },
    });
    defer replay.deinit(allocator);

    const result = try runReplayScaffoldWithOptions(replay, .{
        .strict_events = false,
    });
    try std.testing.expectEqual(@as(usize, 1), result.ticks);
    try std.testing.expectEqual(@as(usize, 0), result.perk_pick_count);
    try std.testing.expectEqual(@as(i32, 0), result.perk_pending_count);
}

test "survival scaffold treats same-tick stale perk pick after menu open as strict no-op" {
    const allocator = std.testing.allocator;

    const menu_only = try buildTestReplay(allocator, .{
        .tick_rate = 60,
        .inputs = &.{0},
        .events = &.{
            .{ .perk_menu_open = .{ .tick_index = 0, .player_index = 0 } },
        },
    });
    defer menu_only.deinit(allocator);

    const with_stale_pick = try buildTestReplay(allocator, .{
        .tick_rate = 60,
        .inputs = &.{0},
        .events = &.{
            .{ .perk_menu_open = .{ .tick_index = 0, .player_index = 0 } },
            .{ .perk_pick = .{ .tick_index = 0, .player_index = 0, .choice_index = 1 } },
        },
    });
    defer with_stale_pick.deinit(allocator);

    const menu_result = try runReplayScaffold(menu_only);
    const stale_result = try runReplayScaffold(with_stale_pick);

    try std.testing.expectEqual(menu_result.wave_spawn_rng_state, stale_result.wave_spawn_rng_state);
    try std.testing.expectEqual(menu_result.perk_pending_count, stale_result.perk_pending_count);
    try std.testing.expectEqual(@as(usize, 0), stale_result.perk_pick_count);
}

test "tick event classification defers state transition then spawn then menu in capture mode" {
    var transition = replay_codec.CaptureStateTransitionEvent{
        .tick_index = 0,
    };
    transition.transition_count = 1;
    transition.transitions[0] = .{
        .target_state = 6,
        .has_before_state = false,
        .before_state = 0,
        .has_after_state = false,
        .after_state = 0,
    };
    const events = [_]replay_codec.ReplayEvent{
        .{ .perk_menu_open = .{ .tick_index = 0, .player_index = 0 } },
        .{ .capture_creature_spawn = .{ .tick_index = 0 } },
        .{ .capture_state_transition = transition },
    };

    var pre_count: usize = 0;
    for (events) |event| {
        if (classifyTickEvent(event, true) == .pre_step) pre_count += 1;
    }
    try std.testing.expectEqual(@as(usize, 0), pre_count);

    var ordered = [_]TickEventPhase{.pre_step} ** 3;
    var ordered_count: usize = 0;
    for ([_]TickEventPhase{
        .post_state_transition,
        .post_spawn_hook,
        .post_menu_open,
    }) |phase| {
        for (events) |event| {
            if (classifyTickEvent(event, true) != phase) continue;
            ordered[ordered_count] = phase;
            ordered_count += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 3), ordered_count);
    try std.testing.expectEqual(TickEventPhase.post_state_transition, ordered[0]);
    try std.testing.expectEqual(TickEventPhase.post_spawn_hook, ordered[1]);
    try std.testing.expectEqual(TickEventPhase.post_menu_open, ordered[2]);
}

test "survival scaffold defers menu-open processing in original capture replays" {
    const allocator = std.testing.allocator;

    const run = struct {
        fn runCase(
            allocator_inner: std.mem.Allocator,
            menu_before_pick: bool,
        ) !ReplayScaffoldResult {
            var bootstrap = replay_codec.CaptureBootstrapEvent{
                .tick_index = 0,
            };
            bootstrap.player_count = 1;
            bootstrap.perk_pending_count = 1;
            bootstrap.perk_choices_dirty = true;

            const menu_event = replay_codec.ReplayEvent{
                .perk_menu_open = .{
                    .tick_index = 0,
                    .player_index = 0,
                },
            };
            const pick_event = replay_codec.ReplayEvent{
                .perk_pick = .{
                    .tick_index = 0,
                    .player_index = 0,
                    .choice_index = 0,
                },
            };

            const replay = try buildTestReplay(allocator_inner, .{
                .tick_rate = 60,
                .seed = 0x1234,
                .inputs = &.{0},
                .events = if (menu_before_pick)
                    &.{
                        .{ .capture_bootstrap = bootstrap },
                        menu_event,
                        pick_event,
                    }
                else
                    &.{
                        .{ .capture_bootstrap = bootstrap },
                        pick_event,
                        menu_event,
                    },
            });
            defer replay.deinit(allocator_inner);
            return runReplayScaffold(replay);
        }
    }.runCase;

    const menu_first = try run(allocator, true);
    const pick_first = try run(allocator, false);

    try std.testing.expectEqual(menu_first.wave_spawn_rng_state, pick_first.wave_spawn_rng_state);
    try std.testing.expectEqual(menu_first.perk_pick_count, pick_first.perk_pick_count);
    try std.testing.expectEqual(menu_first.perk_menu_open_count, pick_first.perk_menu_open_count);
    try std.testing.expectEqual(menu_first.perk_pending_count, pick_first.perk_pending_count);
}

test "survival scaffold tracks weapon runtime counters" {
    const allocator = std.testing.allocator;

    var replay = try buildTestReplay(allocator, .{
        .tick_rate = 60,
        .inputs = &.{
            replay_codec.fire_down_flag,
            replay_codec.fire_down_flag,
        },
        .events = &.{},
    });
    defer replay.deinit(allocator);

    const result = try runReplayScaffold(replay);
    try std.testing.expectEqual(@as(i32, 1), result.shots_fired);
    try std.testing.expectEqual(@as(i32, 0), result.shots_hit);
    try std.testing.expectEqual(@intFromEnum(game_ids.WeaponId.pistol), result.most_used_weapon_id);
}

test "survival scaffold honors dt overrides for elapsed_ms" {
    const allocator = std.testing.allocator;

    var replay = try buildTestReplay(allocator, .{
        .tick_rate = 60,
        .inputs = &.{0},
        .events = &.{},
    });
    defer replay.deinit(allocator);

    const result = try runReplayScaffoldWithOptions(replay, .{
        .dt_frame_overrides = &.{
            .{ .tick_index = 0, .dt_frame = 0.5 },
        },
    });
    try std.testing.expectEqual(@as(i64, 500), result.elapsed_ms_sim);
}

test "survival scaffold inter-tick rand draws shift rng deterministically" {
    const allocator = std.testing.allocator;

    const replay = try buildTestReplay(allocator, .{
        .tick_rate = 60,
        .seed = 0x1234,
        .inputs = &.{ 0, 0, 0 },
        .events = &.{},
    });
    defer replay.deinit(allocator);

    const baseline = try runReplayScaffold(replay);
    const shifted = try runReplayScaffoldWithOptions(replay, .{
        .inter_tick_rand_draws = 1,
    });
    const shifted_again = try runReplayScaffoldWithOptions(replay, .{
        .inter_tick_rand_draws = 1,
    });

    try std.testing.expectEqual(@as(usize, 3), baseline.ticks);
    try std.testing.expectEqual(shifted.wave_spawn_rng_state, shifted_again.wave_spawn_rng_state);
    try std.testing.expect(shifted.wave_spawn_rng_state != baseline.wave_spawn_rng_state);
}

test "survival scaffold applies capture bootstrap payload state" {
    const allocator = std.testing.allocator;

    var bootstrap = replay_codec.CaptureBootstrapEvent{
        .tick_index = 0,
    };
    bootstrap.player_count = 1;
    bootstrap.players[0] = .{
        .weapon_id = 9,
        .pos_x = 600.0,
        .pos_y = 600.0,
        .health = 75.0,
        .ammo = 4.0,
        .experience = 321,
        .level = 5,
    };
    bootstrap.perk_pending_count = 2;
    bootstrap.double_experience_ms = 1500;

    const replay = try buildTestReplay(allocator, .{
        .tick_rate = 60,
        .seed = 0x1234,
        .inputs = &.{0},
        .events = &.{
            .{ .capture_bootstrap = bootstrap },
        },
    });
    defer replay.deinit(allocator);

    const result = try runReplayScaffold(replay);
    try std.testing.expectEqual(@as(usize, 1), result.ticks);
    try std.testing.expectEqual(@as(i32, 321), result.player_experience);
    try std.testing.expectEqual(@as(i32, 5), result.player_level);
    try std.testing.expectEqual(@as(i32, 2), result.perk_pending_count);
}

test "survival scaffold applies terminal tick events" {
    const allocator = std.testing.allocator;

    const with_terminal_event = try buildTestReplay(allocator, .{
        .tick_rate = 60,
        .seed = 0x1234,
        .inputs = &.{ 0, 0, 0 },
        .events = &.{
            .{ .perk_menu_open = .{ .tick_index = 3, .player_index = 0 } },
        },
    });
    defer with_terminal_event.deinit(allocator);

    const without_terminal_event = try buildTestReplay(allocator, .{
        .tick_rate = 60,
        .seed = 0x1234,
        .inputs = &.{ 0, 0, 0 },
        .events = &.{},
    });
    defer without_terminal_event.deinit(allocator);

    const with_result = try runReplayScaffold(with_terminal_event);
    const without_result = try runReplayScaffold(without_terminal_event);
    try std.testing.expect(with_result.wave_spawn_rng_state != without_result.wave_spawn_rng_state);
}

test "survival scaffold bootstrap player shot cooldown blocks first-tick fire" {
    const allocator = std.testing.allocator;

    const run = struct {
        fn runCase(
            allocator_inner: std.mem.Allocator,
            include_shot_cooldown: bool,
        ) !struct { shots_fired: i32, ammo_q4: i32 } {
            var bootstrap = replay_codec.CaptureBootstrapEvent{
                .tick_index = 0,
            };
            bootstrap.player_count = 1;
            bootstrap.players[0] = .{
                .weapon_id = 1,
                .ammo = 12.0,
                .reload_active = false,
                .reload_timer = 0.0,
                .reload_timer_max = 1.0,
                .spread_heat = 0.0,
            };
            if (include_shot_cooldown) {
                bootstrap.players[0].shot_cooldown = 0.5;
            }

            var replay = try buildTestReplay(allocator_inner, .{
                .tick_rate = 60,
                .seed = 0x1234,
                .inputs = &.{replay_codec.fire_down_flag},
                .events = &.{
                    .{ .capture_bootstrap = bootstrap },
                },
            });
            defer replay.deinit(allocator_inner);
            replay.inputs[0][0].aim_x = 700.0;
            replay.inputs[0][0].aim_y = 512.0;

            var trace: std.ArrayList(ReplayTickTrace) = .empty;
            defer trace.deinit(allocator_inner);
            const result = try runReplayScaffoldWithTrace(
                replay,
                &trace,
                allocator_inner,
                .{},
            );
            try std.testing.expectEqual(@as(usize, 1), trace.items.len);
            return .{
                .shots_fired = result.shots_fired,
                .ammo_q4 = trace.items[0].player.player_ammo_q4,
            };
        }
    }.runCase;

    const without_cooldown = try run(allocator, false);
    const with_cooldown = try run(allocator, true);
    try std.testing.expect(without_cooldown.shots_fired > with_cooldown.shots_fired);
    try std.testing.expectEqual(@as(i32, 0), with_cooldown.shots_fired);
    try std.testing.expect(without_cooldown.ammo_q4 < with_cooldown.ammo_q4);
    try std.testing.expectEqual(quantizeQ4(12.0), with_cooldown.ammo_q4);
}

test "survival scaffold bootstrap perk counts enable alternate weapon swap" {
    const allocator = std.testing.allocator;

    const run = struct {
        fn runCase(
            allocator_inner: std.mem.Allocator,
            include_perk_counts: bool,
        ) !i32 {
            var bootstrap = replay_codec.CaptureBootstrapEvent{
                .tick_index = 0,
            };
            bootstrap.player_count = 1;
            bootstrap.players[0] = .{
                .weapon_id = 11,
                .ammo = 0.0,
                .reload_active = false,
                .reload_timer = 0.0,
                .reload_timer_max = 1.0,
                .alt_weapon_id = 1,
                .alt_clip_size = 12,
                .alt_ammo = 12.0,
                .alt_reload_active = false,
                .alt_reload_timer = 0.0,
                .alt_reload_timer_max = 1.2,
                .alt_shot_cooldown = 0.0,
            };
            if (include_perk_counts) {
                bootstrap.player_perk_counts[0].pair_count = 1;
                bootstrap.player_perk_counts[0].pairs[0] = .{
                    .perk_id = @intFromEnum(PerkId.alternate_weapon),
                    .count = 1,
                };
            }

            const replay = try buildTestReplay(allocator_inner, .{
                .tick_rate = 60,
                .seed = 0x1234,
                .inputs = &.{replay_codec.reload_pressed_flag},
                .events = &.{
                    .{ .capture_bootstrap = bootstrap },
                },
            });
            defer replay.deinit(allocator_inner);

            const result = try runReplayScaffold(replay);
            return result.player_weapon_id;
        }
    }.runCase;

    const without_counts = try run(allocator, false);
    const with_counts = try run(allocator, true);
    try std.testing.expectEqual(@as(i32, 11), without_counts);
    try std.testing.expectEqual(@as(i32, 1), with_counts);
}

test "survival scaffold bootstrap rejects invalid perk id in perk counts" {
    const allocator = std.testing.allocator;

    var bootstrap = replay_codec.CaptureBootstrapEvent{
        .tick_index = 0,
    };
    bootstrap.player_count = 1;
    bootstrap.player_perk_counts[0].pair_count = 1;
    bootstrap.player_perk_counts[0].pairs[0] = .{
        .perk_id = 999,
        .count = 1,
    };

    const replay = try buildTestReplay(allocator, .{
        .tick_rate = 60,
        .seed = 0x1234,
        .inputs = &.{0},
        .events = &.{
            .{ .capture_bootstrap = bootstrap },
        },
    });
    defer replay.deinit(allocator);

    try std.testing.expectError(
        error.InvalidCaptureEnumValue,
        runReplayScaffold(replay),
    );
}

test "survival scaffold bootstrap rejects invalid perk id in choices" {
    const allocator = std.testing.allocator;

    var bootstrap = replay_codec.CaptureBootstrapEvent{
        .tick_index = 0,
    };
    bootstrap.player_count = 1;
    bootstrap.perk_choice_count = 1;
    bootstrap.perk_choices[0] = 999;

    const replay = try buildTestReplay(allocator, .{
        .tick_rate = 60,
        .seed = 0x1234,
        .inputs = &.{0},
        .events = &.{
            .{ .capture_bootstrap = bootstrap },
        },
    });
    defer replay.deinit(allocator);

    try std.testing.expectError(
        error.InvalidCaptureEnumValue,
        runReplayScaffold(replay),
    );
}

test "capture perk pending event sets pending without shifting rng in survival and quest modes" {
    const allocator = std.testing.allocator;

    const run = struct {
        fn runCase(
            allocator_inner: std.mem.Allocator,
            game_mode_id: GameModeId,
            apply_pending_event: bool,
        ) !struct { rng_state: u32, pending: i32 } {
            var bootstrap = replay_codec.CaptureBootstrapEvent{
                .tick_index = 0,
            };
            bootstrap.player_count = 1;
            bootstrap.perk_pending_count = 2;
            const pending_event = replay_codec.ReplayEvent{
                .capture_perk_pending = .{
                    .tick_index = 0,
                    .perk_pending = 0,
                },
            };
            const replay = try buildTestReplay(allocator_inner, .{
                .game_mode_id = @intFromEnum(game_mode_id),
                .tick_rate = 60,
                .seed = 0x1234,
                .inputs = &.{0},
                .events = if (apply_pending_event)
                    &.{
                        .{ .capture_bootstrap = bootstrap },
                        pending_event,
                    }
                else
                    &.{
                        .{ .capture_bootstrap = bootstrap },
                    },
            });
            defer replay.deinit(allocator_inner);

            const result = try runReplayScaffoldWithOptions(replay, .{
                .quest_spawn_entries = if (game_mode_id == .quests) &.{} else null,
            });
            return .{
                .rng_state = result.wave_spawn_rng_state,
                .pending = result.perk_pending_count,
            };
        }
    }.runCase;

    for ([_]GameModeId{ .survival, .quests }) |mode| {
        const baseline = try run(allocator, mode, false);
        const with_pending = try run(allocator, mode, true);
        try std.testing.expectEqual(baseline.rng_state, with_pending.rng_state);
        try std.testing.expectEqual(@as(i32, 0), with_pending.pending);
    }
}

test "capture perk apply outside-before keeps rng anchored and consumes pending-after" {
    const allocator = std.testing.allocator;

    const run = struct {
        fn runCase(
            allocator_inner: std.mem.Allocator,
            include_perk_apply: bool,
        ) !ReplayScaffoldResult {
            var bootstrap = replay_codec.CaptureBootstrapEvent{
                .tick_index = 0,
            };
            bootstrap.player_count = 1;
            bootstrap.perk_pending_count = 1;
            bootstrap.players[0] = .{
                .weapon_id = @intFromEnum(game_ids.WeaponId.assault_rifle),
                .ammo = 6.0,
            };

            const apply_event = replay_codec.ReplayEvent{
                .capture_perk_apply = .{
                    .tick_index = 0,
                    .perk_id = @intFromEnum(PerkId.random_weapon),
                    .outside_before = true,
                    .pending_before = 1,
                    .pending_after = 4,
                },
            };

            const replay = try buildTestReplay(allocator_inner, .{
                .game_mode_id = @intFromEnum(GameModeId.survival),
                .tick_rate = 60,
                .seed = 0x1234,
                .inputs = &.{0},
                .events = if (include_perk_apply)
                    &.{
                        .{ .capture_bootstrap = bootstrap },
                        apply_event,
                    }
                else
                    &.{
                        .{ .capture_bootstrap = bootstrap },
                    },
            });
            defer replay.deinit(allocator_inner);
            return runReplayScaffold(replay);
        }
    }.runCase;

    const baseline = try run(allocator, false);
    const applied = try run(allocator, true);

    try std.testing.expectEqual(baseline.wave_spawn_rng_state, applied.wave_spawn_rng_state);
    try std.testing.expectEqual(@as(i32, 3), applied.perk_pending_count);
}

test "rush scaffold is deterministic and enforces assault rifle loadout" {
    const allocator = std.testing.allocator;

    const replay = try buildTestReplay(allocator, .{
        .game_mode_id = @intFromEnum(GameModeId.rush),
        .seed = 0x1234,
        .tick_rate = 60,
        .inputs = &.{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
        .events = &.{},
    });
    defer replay.deinit(allocator);

    const result0 = try runReplayScaffold(replay);
    const result1 = try runReplayScaffold(replay);
    try std.testing.expectEqual(result0.wave_spawn_rng_state, result1.wave_spawn_rng_state);
    try std.testing.expectEqual(@as(usize, 10), result0.ticks);
    try std.testing.expectEqual(@intFromEnum(game_ids.WeaponId.assault_rifle), result0.player_weapon_id);
    try std.testing.expectEqual(@intFromEnum(game_ids.WeaponId.assault_rifle), result0.most_used_weapon_id);
}

test "rush scaffold honors dt overrides for elapsed_ms" {
    const allocator = std.testing.allocator;

    const replay = try buildTestReplay(allocator, .{
        .game_mode_id = @intFromEnum(GameModeId.rush),
        .tick_rate = 60,
        .inputs = &.{0},
        .events = &.{},
    });
    defer replay.deinit(allocator);

    const result = try runReplayScaffoldWithOptions(replay, .{
        .dt_frame_overrides = &.{
            .{ .tick_index = 0, .dt_frame = 0.5 },
        },
    });
    try std.testing.expectEqual(@as(i64, 500), result.elapsed_ms_sim);
}

test "rush scaffold spawn cadence uses raw frame dt, not sim dt" {
    const allocator = std.testing.allocator;

    const inputs = [_]u32{0} ** 15;
    const replay = try buildTestReplay(allocator, .{
        .game_mode_id = @intFromEnum(GameModeId.rush),
        .seed = 0x1234,
        .tick_rate = 60,
        .inputs = inputs[0..],
        .events = &.{},
    });
    defer replay.deinit(allocator);

    const result = try runReplayScaffold(replay);
    // Native rush cooldown arithmetic is float32; at 60 Hz nominal dt this yields a
    // second batch on tick 15 (0-indexed tick 14), so 4 total creatures in 15 ticks.
    try std.testing.expectEqual(@as(usize, 4), result.wave_spawn_count);
}

test "rush scaffold inter-tick rand draws shift rng deterministically" {
    const allocator = std.testing.allocator;

    const replay = try buildTestReplay(allocator, .{
        .game_mode_id = @intFromEnum(GameModeId.rush),
        .seed = 0x1234,
        .tick_rate = 60,
        .inputs = &.{ 0, 0, 0 },
        .events = &.{},
    });
    defer replay.deinit(allocator);

    const baseline = try runReplayScaffold(replay);
    const shifted = try runReplayScaffoldWithOptions(replay, .{
        .inter_tick_rand_draws = 1,
    });
    const shifted_again = try runReplayScaffoldWithOptions(replay, .{
        .inter_tick_rand_draws = 1,
    });

    try std.testing.expectEqual(@as(usize, 3), baseline.ticks);
    try std.testing.expectEqual(shifted.wave_spawn_rng_state, shifted_again.wave_spawn_rng_state);
    try std.testing.expect(shifted.wave_spawn_rng_state != baseline.wave_spawn_rng_state);
}

test "rush scaffold rejects replay events" {
    const allocator = std.testing.allocator;

    const replay = try buildTestReplay(allocator, .{
        .game_mode_id = @intFromEnum(GameModeId.rush),
        .tick_rate = 60,
        .inputs = &.{0},
        .events = &.{
            .{ .perk_pick = .{ .tick_index = 0, .player_index = 0, .choice_index = 0 } },
        },
    });
    defer replay.deinit(allocator);

    try std.testing.expectError(error.UnsupportedEventKind, runReplayScaffold(replay));
}

test "rush scaffold accepts capture bootstrap events" {
    const allocator = std.testing.allocator;

    var bootstrap = replay_codec.CaptureBootstrapEvent{
        .tick_index = 0,
    };
    bootstrap.player_count = 1;
    bootstrap.players[0] = .{
        .weapon_id = 17,
        .pos_x = 256.0,
        .pos_y = 256.0,
        .health = 100.0,
        .ammo = 6.0,
        .experience = 123,
        .level = 2,
    };

    const replay = try buildTestReplay(allocator, .{
        .game_mode_id = @intFromEnum(GameModeId.rush),
        .seed = 42,
        .tick_rate = 60,
        .inputs = &.{0},
        .events = &.{
            .{ .capture_bootstrap = bootstrap },
        },
    });
    defer replay.deinit(allocator);

    const result = try runReplayScaffold(replay);
    try std.testing.expectEqual(@as(usize, 1), result.ticks);
    try std.testing.expectEqual(@intFromEnum(game_ids.WeaponId.assault_rifle), result.player_weapon_id);
    try std.testing.expectEqual(@as(i32, 123), result.player_experience);
}

test "rush scaffold original capture bootstrap keeps packed move vector behavior" {
    const allocator = std.testing.allocator;

    var bootstrap = replay_codec.CaptureBootstrapEvent{
        .tick_index = 0,
    };
    bootstrap.player_count = 1;
    bootstrap.players[0] = .{
        .weapon_id = @intFromEnum(game_ids.WeaponId.assault_rifle),
        .pos_x = 512.0,
        .pos_y = 512.0,
        .health = 100.0,
        .ammo = 50.0,
    };
    bootstrap.digital_move_enabled_by_player[0] = true;

    const replay = try buildTestReplay(allocator, .{
        .game_mode_id = @intFromEnum(GameModeId.rush),
        .seed = 0x1234,
        .tick_rate = 60,
        .inputs = &.{0},
        .events = &.{
            .{ .capture_bootstrap = bootstrap },
        },
    });
    defer replay.deinit(allocator);
    replay.inputs[0][0].move_x = 1.0;
    replay.inputs[0][0].move_y = 0.0;
    replay.inputs[0][0].aim_x = 600.0;
    replay.inputs[0][0].aim_y = 512.0;

    var trace: std.ArrayList(ReplayTickTrace) = .empty;
    defer trace.deinit(allocator);
    _ = try runReplayScaffoldWithTrace(
        replay,
        &trace,
        allocator,
        .{},
    );
    try std.testing.expectEqual(@as(usize, 1), trace.items.len);
    try std.testing.expect(trace.items[0].player.player_pos_x_q4 > quantizeQ4(512.0));
}

test "rush scaffold supports multiplayer replays" {
    const allocator = std.testing.allocator;

    const replay = try buildTestReplayMulti(allocator, .{
        .game_mode_id = @intFromEnum(GameModeId.rush),
        .seed = 0x1234,
        .tick_rate = 60,
        .player_count = 2,
        .inputs = &.{
            &.{ 0, 0 },
            &.{ replay_codec.fire_down_flag, 0 },
            &.{ 0, replay_codec.reload_pressed_flag },
        },
        .events = &.{},
    });
    defer replay.deinit(allocator);

    const result = try runReplayScaffold(replay);
    try std.testing.expectEqual(@as(usize, 3), result.ticks);
    try std.testing.expectEqual(@intFromEnum(game_ids.WeaponId.assault_rifle), result.player_weapon_id);
    try std.testing.expectEqual(@intFromEnum(game_ids.WeaponId.assault_rifle), result.most_used_weapon_id);
}

test "rush scaffold disables progression updates even above level threshold" {
    const allocator = std.testing.allocator;

    var bootstrap = replay_codec.CaptureBootstrapEvent{
        .tick_index = 0,
    };
    bootstrap.player_count = 1;
    bootstrap.players[0] = .{
        .weapon_id = @intFromEnum(game_ids.WeaponId.assault_rifle),
        .experience = 2060,
        .level = 1,
        .ammo = 50.0,
        .health = 100.0,
    };

    const replay = try buildTestReplay(allocator, .{
        .game_mode_id = @intFromEnum(GameModeId.rush),
        .seed = 0x1234,
        .tick_rate = 60,
        .inputs = &.{0},
        .events = &.{
            .{ .capture_bootstrap = bootstrap },
        },
    });
    defer replay.deinit(allocator);

    const result = try runReplayScaffold(replay);
    try std.testing.expectEqual(@as(i32, 2060), result.player_experience);
    try std.testing.expectEqual(@as(i32, 1), result.player_level);
    try std.testing.expectEqual(@as(i32, 0), result.perk_pending_count);
}

test "survival scaffold supports player counts 1 through 4" {
    const allocator = std.testing.allocator;

    var player_count: i32 = 1;
    while (player_count <= 4) : (player_count += 1) {
        const players_len: usize = @intCast(player_count);
        const fire_player: usize = players_len - 1;

        const row0_storage = [_]u32{0} ** state_mod.max_players;
        var row1_storage = [_]u32{0} ** state_mod.max_players;
        row1_storage[fire_player] = replay_codec.fire_down_flag;

        const rows = [_][]const u32{
            row0_storage[0..players_len],
            row1_storage[0..players_len],
        };

        const replay = try buildTestReplayMulti(allocator, .{
            .game_mode_id = @intFromEnum(GameModeId.survival),
            .seed = 0x1234,
            .tick_rate = 60,
            .player_count = player_count,
            .inputs = rows[0..],
            .events = &.{
                .{ .perk_menu_open = .{
                    .tick_index = 1,
                    .player_index = @intCast(player_count - 1),
                } },
            },
        });
        defer replay.deinit(allocator);

        const result = try runReplayScaffold(replay);
        try std.testing.expectEqual(@as(usize, 2), result.ticks);
        try std.testing.expectEqual(@as(usize, 1), result.perk_menu_open_count);
    }
}

test "rush scaffold supports player counts 1 through 4" {
    const allocator = std.testing.allocator;

    var player_count: i32 = 1;
    while (player_count <= 4) : (player_count += 1) {
        const players_len: usize = @intCast(player_count);

        const row0_storage = [_]u32{0} ** state_mod.max_players;
        const row1_storage = [_]u32{replay_codec.fire_down_flag} ** state_mod.max_players;
        const rows = [_][]const u32{
            row0_storage[0..players_len],
            row1_storage[0..players_len],
        };

        const replay = try buildTestReplayMulti(allocator, .{
            .game_mode_id = @intFromEnum(GameModeId.rush),
            .seed = 0x1234,
            .tick_rate = 60,
            .player_count = player_count,
            .inputs = rows[0..],
            .events = &.{},
        });
        defer replay.deinit(allocator);

        const result = try runReplayScaffold(replay);
        try std.testing.expectEqual(@as(usize, 2), result.ticks);
        try std.testing.expectEqual(@intFromEnum(game_ids.WeaponId.assault_rifle), result.player_weapon_id);
        try std.testing.expectEqual(@intFromEnum(game_ids.WeaponId.assault_rifle), result.most_used_weapon_id);
    }
}

test "quest scaffold is deterministic with explicit spawn entries" {
    const allocator = std.testing.allocator;

    const replay = try buildTestReplay(allocator, .{
        .game_mode_id = @intFromEnum(GameModeId.quests),
        .seed = 101,
        .tick_rate = 60,
        .inputs = &.{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
        .events = &.{},
    });
    defer replay.deinit(allocator);

    const quest_entries = [_]spawn_mod.QuestSpawnEntry{
        .{
            .pos = .{ .x = 512.0, .y = 512.0 },
            .heading = 0.0,
            .spawn_id = spawn_mod.SpawnId.formation_ring_alien_8_12,
            .trigger_ms = 5000,
            .count = 1,
        },
    };
    const result0 = try runReplayScaffoldWithOptions(replay, .{
        .quest_spawn_entries = quest_entries[0..],
        .quest_start_weapon_id = @intFromEnum(game_ids.WeaponId.pistol),
    });
    const result1 = try runReplayScaffoldWithOptions(replay, .{
        .quest_spawn_entries = quest_entries[0..],
        .quest_start_weapon_id = @intFromEnum(game_ids.WeaponId.pistol),
    });
    try std.testing.expectEqual(result0.wave_spawn_rng_state, result1.wave_spawn_rng_state);
    try std.testing.expectEqual(@as(usize, 10), result0.ticks);
}

test "quest scaffold timeline uses frame dt even when reflex boost is active" {
    const allocator = std.testing.allocator;

    var bootstrap = replay_codec.CaptureBootstrapEvent{
        .tick_index = 0,
    };
    bootstrap.player_count = 1;
    bootstrap.players[0] = .{
        .weapon_id = @intFromEnum(game_ids.WeaponId.pistol),
        .pos_x = 512.0,
        .pos_y = 512.0,
        .health = 100.0,
        .ammo = 11.0,
    };
    bootstrap.reflex_boost_ms = 500;

    const quest_entries = [_]spawn_mod.QuestSpawnEntry{
        .{
            .pos = .{ .x = 512.0, .y = 512.0 },
            .heading = 0.0,
            .spawn_id = spawn_mod.SpawnId.formation_ring_alien_8_12,
            .trigger_ms = 100_000,
            .count = 1,
        },
    };

    const replay = try buildTestReplay(allocator, .{
        .game_mode_id = @intFromEnum(GameModeId.quests),
        .seed = 101,
        .tick_rate = 60,
        .inputs = &.{0},
        .events = &.{
            .{ .capture_bootstrap = bootstrap },
        },
    });
    defer replay.deinit(allocator);

    const result = try runReplayScaffoldWithOptions(replay, .{
        .quest_spawn_entries = quest_entries[0..],
        .quest_start_weapon_id = @intFromEnum(game_ids.WeaponId.pistol),
    });
    try std.testing.expectEqual(@as(i64, 16), result.elapsed_ms_sim);
}

test "quest scaffold advances spawn timeline and fires entries" {
    const allocator = std.testing.allocator;

    const replay = try buildTestReplay(allocator, .{
        .game_mode_id = @intFromEnum(GameModeId.quests),
        .seed = 101,
        .tick_rate = 60,
        .inputs = &.{0},
        .events = &.{},
    });
    defer replay.deinit(allocator);

    const quest_entries = [_]spawn_mod.QuestSpawnEntry{
        .{
            .pos = .{ .x = 512.0, .y = 512.0 },
            .heading = 0.0,
            .spawn_id = spawn_mod.SpawnId.formation_ring_alien_8_12,
            .trigger_ms = 200,
            .count = 1,
        },
    };
    const result = try runReplayScaffoldWithOptions(replay, .{
        .quest_spawn_entries = quest_entries[0..],
        .dt_frame_overrides = &.{
            .{ .tick_index = 0, .dt_frame = 0.5 },
        },
    });
    try std.testing.expectEqual(@as(i64, 500), result.elapsed_ms_sim);
    try std.testing.expect(result.wave_spawn_count > 0);
    try std.testing.expect(result.creature_active_count > 0);
}

test "quest scaffold supports multiplayer replays with explicit start weapon" {
    const allocator = std.testing.allocator;

    const replay = try buildTestReplayMulti(allocator, .{
        .game_mode_id = @intFromEnum(GameModeId.quests),
        .seed = 101,
        .tick_rate = 60,
        .player_count = 2,
        .inputs = &.{
            &.{ 0, 0 },
            &.{ replay_codec.fire_pressed_flag, replay_codec.reload_pressed_flag },
        },
        .events = &.{
            .{ .perk_menu_open = .{ .tick_index = 1, .player_index = 1 } },
        },
    });
    defer replay.deinit(allocator);

    const result = try runReplayScaffoldWithOptions(replay, .{
        .quest_start_weapon_id = @intFromEnum(game_ids.WeaponId.ion_cannon),
    });
    try std.testing.expectEqual(@as(usize, 2), result.ticks);
    try std.testing.expectEqual(@intFromEnum(game_ids.WeaponId.ion_cannon), result.player_weapon_id);
    try std.testing.expectEqual(@as(usize, 1), result.perk_menu_open_count);
}

test "quest scaffold resolves native quest preset and start weapon from replay header" {
    const allocator = std.testing.allocator;

    const replay = try buildTestReplay(allocator, .{
        .game_mode_id = @intFromEnum(GameModeId.quests),
        .seed = 205,
        .tick_rate = 60,
        .quest_level = "2.5",
        .inputs = &.{0},
        .events = &.{},
    });
    defer replay.deinit(allocator);

    const result = try runReplayScaffoldWithOptions(replay, .{
        .dt_frame_overrides = &.{
            .{ .tick_index = 0, .dt_frame = 3.0 },
        },
    });
    try std.testing.expectEqual(@as(i32, 6), result.player_weapon_id);
    try std.testing.expect(result.wave_spawn_count > 0);
}

test "quest scaffold supports dynamic quest seed variants when no spawn entries are provided" {
    const allocator = std.testing.allocator;

    const replay = try buildTestReplay(allocator, .{
        .game_mode_id = @intFromEnum(GameModeId.quests),
        .seed = 999,
        .tick_rate = 60,
        .quest_level = "2.5",
        .inputs = &.{0},
        .events = &.{},
    });
    defer replay.deinit(allocator);

    const result = try runReplayScaffoldWithOptions(replay, .{
        .dt_frame_overrides = &.{
            .{ .tick_index = 0, .dt_frame = 3.0 },
        },
    });
    try std.testing.expectEqual(@as(i32, 6), result.player_weapon_id);
    try std.testing.expect(result.wave_spawn_count > 0);
}

test "quest scaffold rejects unknown quest level when no spawn entries are provided" {
    const allocator = std.testing.allocator;

    const replay = try buildTestReplay(allocator, .{
        .game_mode_id = @intFromEnum(GameModeId.quests),
        .seed = 999,
        .tick_rate = 60,
        .quest_level = "9.9",
        .inputs = &.{0},
        .events = &.{},
    });
    defer replay.deinit(allocator);

    try std.testing.expectError(error.UnsupportedQuestSpawnTable, runReplayScaffold(replay));
}

test "quest scaffold supports player counts 1 through 4 across static and dynamic levels" {
    const allocator = std.testing.allocator;
    const level_cases = [_]struct {
        quest_level: []const u8,
        seed: u32,
        expected_start_weapon: i32,
    }{
        .{ .quest_level = "1.1", .seed = 101, .expected_start_weapon = @intFromEnum(game_ids.WeaponId.pistol) },
        .{ .quest_level = "2.5", .seed = 205, .expected_start_weapon = 6 },
        .{ .quest_level = "3.3", .seed = 205, .expected_start_weapon = @intFromEnum(game_ids.WeaponId.pistol) },
        .{ .quest_level = "3.9", .seed = 999, .expected_start_weapon = 6 },
    };

    for (level_cases) |case| {
        var player_count: i32 = 1;
        while (player_count <= 4) : (player_count += 1) {
            const players_len: usize = @intCast(player_count);
            const row_storage = [_]u32{0} ** state_mod.max_players;
            const rows = [_][]const u32{row_storage[0..players_len]};

            const replay = try buildTestReplayMulti(allocator, .{
                .game_mode_id = @intFromEnum(GameModeId.quests),
                .seed = case.seed,
                .tick_rate = 60,
                .player_count = player_count,
                .quest_level = case.quest_level,
                .inputs = rows[0..],
                .events = &.{},
            });
            defer replay.deinit(allocator);

            const result = try runReplayScaffoldWithOptions(replay, .{
                .dt_frame_overrides = &.{
                    .{ .tick_index = 0, .dt_frame = 3.0 },
                },
            });
            try std.testing.expectEqual(@as(usize, 1), result.ticks);
            try std.testing.expectEqual(case.expected_start_weapon, result.player_weapon_id);
            try std.testing.expect(result.wave_spawn_count > 0);
        }
    }
}

test "quest scaffold applies capture bootstrap quest session timers" {
    const allocator = std.testing.allocator;

    const inputs = [_]u32{0} ** 20;
    const replay_baseline = try buildTestReplay(allocator, .{
        .game_mode_id = @intFromEnum(GameModeId.quests),
        .seed = 101,
        .tick_rate = 60,
        .inputs = inputs[0..],
        .events = &.{},
    });
    defer replay_baseline.deinit(allocator);

    const quest_entries = [_]spawn_mod.QuestSpawnEntry{
        .{
            .pos = .{ .x = 512.0, .y = 512.0 },
            .heading = 0.0,
            .spawn_id = spawn_mod.SpawnId.formation_ring_alien_8_12,
            .trigger_ms = 5000,
            .count = 1,
        },
    };

    var dt_overrides: [20]DtFrameOverride = undefined;
    for (&dt_overrides, 0..) |*entry, idx| {
        entry.* = .{
            .tick_index = idx,
            .dt_frame = 0.1,
        };
    }

    var baseline_trace: std.ArrayList(ReplayTickTrace) = .empty;
    defer baseline_trace.deinit(allocator);
    _ = try runReplayScaffoldWithTrace(
        replay_baseline,
        &baseline_trace,
        allocator,
        .{
            .quest_spawn_entries = quest_entries[0..],
            .dt_frame_overrides = dt_overrides[0..],
        },
    );
    try std.testing.expectEqual(@as(usize, 20), baseline_trace.items.len);
    try std.testing.expectEqual(@as(usize, 0), baseline_trace.items[19].summary.creature_count);

    var bootstrap = replay_codec.CaptureBootstrapEvent{
        .tick_index = 0,
    };
    bootstrap.player_count = 1;
    bootstrap.players[0] = .{
        .weapon_id = 1,
        .pos_x = 512.0,
        .pos_y = 512.0,
        .health = 100.0,
        .ammo = 11.0,
        .experience = 0,
        .level = 1,
    };
    bootstrap.quest_session = .{
        .spawn_timeline_ms = 1701.0,
        .no_creatures_timer_ms = 3100.0,
        .completion_transition_ms = -1.0,
    };
    const events = [_]replay_codec.ReplayEvent{
        .{ .capture_bootstrap = bootstrap },
    };
    const replay_bootstrapped = try buildTestReplay(allocator, .{
        .game_mode_id = @intFromEnum(GameModeId.quests),
        .seed = 101,
        .tick_rate = 60,
        .inputs = inputs[0..],
        .events = events[0..],
    });
    defer replay_bootstrapped.deinit(allocator);

    var bootstrapped_trace: std.ArrayList(ReplayTickTrace) = .empty;
    defer bootstrapped_trace.deinit(allocator);
    _ = try runReplayScaffoldWithTrace(
        replay_bootstrapped,
        &bootstrapped_trace,
        allocator,
        .{
            .quest_spawn_entries = quest_entries[0..],
            .dt_frame_overrides = dt_overrides[0..],
        },
    );
    try std.testing.expectEqual(@as(usize, 20), bootstrapped_trace.items.len);
    try std.testing.expect(bootstrapped_trace.items[19].summary.creature_count > 0);
}

test "quest scaffold disables runtime spawn slot ticks when capture spawns are authoritative" {
    const allocator = std.testing.allocator;

    const inputs = [_]u32{0} ** 40;
    var bootstrap = replay_codec.CaptureBootstrapEvent{
        .tick_index = 0,
    };
    bootstrap.player_count = 1;
    bootstrap.players[0] = .{
        .weapon_id = 1,
        .pos_x = 512.0,
        .pos_y = 512.0,
        .health = 100.0,
        .ammo = 11.0,
        .experience = 0,
        .level = 1,
    };
    bootstrap.quest_session = .{
        .spawn_timeline_ms = 0.0,
        .no_creatures_timer_ms = 0.0,
        .completion_transition_ms = -1.0,
    };

    var capture_spawn = replay_codec.CaptureCreatureSpawnEvent{
        .tick_index = 0,
    };
    capture_spawn.spawn_count = 1;
    capture_spawn.spawns[0] = .{
        .template_id = 0x0A,
        .pos_x = 900.0,
        .pos_y = 900.0,
        .heading = 0.0,
    };
    const events = [_]replay_codec.ReplayEvent{
        .{ .capture_bootstrap = bootstrap },
        .{ .capture_creature_spawn = capture_spawn },
    };

    const replay = try buildTestReplay(allocator, .{
        .game_mode_id = @intFromEnum(GameModeId.quests),
        .seed = 101,
        .tick_rate = 60,
        .inputs = inputs[0..],
        .events = events[0..],
    });
    defer replay.deinit(allocator);

    var dt_overrides: [40]DtFrameOverride = undefined;
    for (&dt_overrides, 0..) |*entry, idx| {
        entry.* = .{
            .tick_index = idx,
            .dt_frame = 0.1,
        };
    }

    const empty_entries = [_]spawn_mod.QuestSpawnEntry{};
    var trace: std.ArrayList(ReplayTickTrace) = .empty;
    defer trace.deinit(allocator);
    _ = try runReplayScaffoldWithTrace(
        replay,
        &trace,
        allocator,
        .{
            .quest_spawn_entries = empty_entries[0..],
            .dt_frame_overrides = dt_overrides[0..],
        },
    );
    try std.testing.expectEqual(@as(usize, 40), trace.items.len);
    try std.testing.expectEqual(@as(usize, 1), trace.items[39].summary.creature_count);
}

test "capture creature spawn event applies added head overrides" {
    var state = state_mod.GameplayState.init(1);
    var creatures = creatures_mod.CreaturePool{};
    creatures.reset();

    var event = replay_codec.CaptureCreatureSpawnEvent{
        .tick_index = 0,
    };
    event.spawn_count = 1;
    event.spawns[0] = .{
        .template_id = 0x18,
        .pos_x = -256.0,
        .pos_y = 256.0,
        .heading = -4.083981990814209,
    };
    event.added_head_count = 1;
    event.added_head[0] = .{
        .index = 1,
        .has_heading = true,
        .heading = 1.1278764009475708,
        .has_target_heading = true,
        .target_heading = 0.621416449546814,
        .has_ai_mode = true,
        .ai_mode = @intFromEnum(spawn_mod.CreatureAiMode.follow_link),
        .has_link_index = true,
        .link_index = 0,
        .has_hp = true,
        .hp = 123.5,
        .has_lifecycle_stage = true,
        .lifecycle_stage = 9.5,
        .has_orbit_angle = true,
        .orbit_angle = 0.25,
        .has_orbit_radius = true,
        .orbit_radius = 0.75,
        .has_flags = true,
        .flags = 17,
        .has_type_id = true,
        .type_id = 7,
        .has_pos = true,
        .pos_x = 12.25,
        .pos_y = 34.5,
    };

    try applyCaptureCreatureSpawnEvent(&state, &creatures, event);
    const creature = creatures.entries[1];
    try std.testing.expect(creature.active);
    try std.testing.expectApproxEqAbs(@as(f32, 1.1278764009475708), creature.heading, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 0.621416449546814), creature.target_heading, 1e-6);
    try std.testing.expectEqual(spawn_mod.CreatureAiMode.follow_link, creature.ai_mode);
    try std.testing.expectEqual(@as(i32, 0), creature.link_index);
    try std.testing.expectApproxEqAbs(@as(f32, 123.5), creature.hp, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 9.5), creature.lifecycle_stage, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 0.25), creature.orbit_angle, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 0.75), creature.orbit_radius, 1e-6);
    try std.testing.expectEqual(@as(u32, 17), creature.flags);
    try std.testing.expectEqual(@as(i32, 7), creature.type_id);
    try std.testing.expectApproxEqAbs(@as(f32, 12.25), creature.pos.x, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 34.5), creature.pos.y, 1e-6);
}

test "capture creature spawn event backfills ai7 rollover rng draw for spawned rows" {
    var base_state = state_mod.GameplayState.init(0x1234ABCD);
    var base_creatures = creatures_mod.CreaturePool{};
    base_creatures.reset();
    var base_event = replay_codec.CaptureCreatureSpawnEvent{
        .tick_index = 0,
    };
    base_event.spawn_count = 1;
    base_event.spawns[0] = .{
        .template_id = 0x20,
        .pos_x = 256.0,
        .pos_y = 256.0,
        .heading = -100.0,
    };
    try applyCaptureCreatureSpawnEvent(&base_state, &base_creatures, base_event);
    const rng_after_base = base_state.rng.state;

    var rollover_state = state_mod.GameplayState.init(0x1234ABCD);
    var rollover_creatures = creatures_mod.CreaturePool{};
    rollover_creatures.reset();
    var rollover_event = base_event;
    rollover_event.added_head_count = 1;
    rollover_event.added_head[0] = .{
        .index = 0,
        .has_flags = true,
        .flags = @intCast(spawn_mod.CreatureFlags.ai7_link_timer),
        .has_link_index = true,
        .link_index = -975,
    };
    try applyCaptureCreatureSpawnEvent(&rollover_state, &rollover_creatures, rollover_event);
    const rng_after_rollover = rollover_state.rng.state;

    var probe_rng = spawn_mod.Crand.init(rng_after_base);
    _ = probe_rng.rand();
    try std.testing.expectEqual(probe_rng.state, rng_after_rollover);
    try std.testing.expectEqual(@as(i32, -975), rollover_creatures.entries[0].link_index);
}

test "capture creature spawn event applies added head rows without spawn rows" {
    var state = state_mod.GameplayState.init(1);
    var creatures = creatures_mod.CreaturePool{};
    creatures.reset();

    var seed_event = replay_codec.CaptureCreatureSpawnEvent{
        .tick_index = 0,
    };
    seed_event.spawn_count = 1;
    seed_event.spawns[0] = .{
        .template_id = 0x24,
        .pos_x = 256.0,
        .pos_y = 256.0,
        .heading = 0.0,
    };
    try applyCaptureCreatureSpawnEvent(&state, &creatures, seed_event);

    var update_event = replay_codec.CaptureCreatureSpawnEvent{
        .tick_index = 0,
    };
    update_event.added_head_count = 1;
    update_event.added_head[0] = .{
        .index = 0,
        .has_heading = true,
        .heading = 0.28999999165534973,
        .has_target_heading = true,
        .target_heading = 0.521416425704956,
        .has_ai_mode = true,
        .ai_mode = @intFromEnum(spawn_mod.CreatureAiMode.orbit_player),
        .has_link_index = true,
        .link_index = 1,
        .has_orbit_radius = true,
        .orbit_radius = 1.25,
        .has_flags = true,
        .flags = 5,
    };
    try applyCaptureCreatureSpawnEvent(&state, &creatures, update_event);

    const creature = creatures.entries[0];
    try std.testing.expect(creature.active);
    try std.testing.expectApproxEqAbs(@as(f32, 0.28999999165534973), creature.heading, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 0.521416425704956), creature.target_heading, 1e-6);
    try std.testing.expectEqual(spawn_mod.CreatureAiMode.orbit_player, creature.ai_mode);
    try std.testing.expectEqual(@as(i32, 1), creature.link_index);
    try std.testing.expectApproxEqAbs(@as(f32, 1.25), creature.orbit_radius, 1e-6);
    try std.testing.expectEqual(@as(u32, 5), creature.flags);
}

test "capture creature spawn event hard fails on invalid ai mode enum" {
    var state = state_mod.GameplayState.init(1);
    var creatures = creatures_mod.CreaturePool{};
    creatures.reset();

    var seed_event = replay_codec.CaptureCreatureSpawnEvent{
        .tick_index = 0,
    };
    seed_event.spawn_count = 1;
    seed_event.spawns[0] = .{
        .template_id = 0x24,
        .pos_x = 256.0,
        .pos_y = 256.0,
        .heading = 0.0,
    };
    try applyCaptureCreatureSpawnEvent(&state, &creatures, seed_event);

    var invalid_event = replay_codec.CaptureCreatureSpawnEvent{
        .tick_index = 1,
    };
    invalid_event.added_head_count = 1;
    invalid_event.added_head[0] = .{
        .index = 0,
        .has_ai_mode = true,
        .ai_mode = 999,
        .has_heading = true,
        .heading = 1.5,
    };

    const heading_before = creatures.entries[0].heading;
    try std.testing.expectError(
        error.InvalidCaptureEnumValue,
        applyCaptureCreatureSpawnEvent(&state, &creatures, invalid_event),
    );
    try std.testing.expectApproxEqAbs(heading_before, creatures.entries[0].heading, 1e-6);
}

test "quest scaffold resets run state on capture transition to terminal state" {
    const allocator = std.testing.allocator;

    var replay = try buildTestReplay(allocator, .{
        .game_mode_id = @intFromEnum(GameModeId.quests),
        .seed = 101,
        .tick_rate = 60,
        .inputs = &.{ 0, replay_codec.fire_down_flag },
        .events = &.{},
    });
    defer replay.deinit(allocator);

    var bootstrap = replay_codec.CaptureBootstrapEvent{
        .tick_index = 0,
    };
    bootstrap.player_count = 1;
    bootstrap.players[0] = .{
        .weapon_id = 17,
        .pos_x = 512.0,
        .pos_y = 512.0,
        .health = 0.0,
        .ammo = 6.0,
        .experience = 11581,
        .level = 4,
    };
    bootstrap.reflex_boost_ms = 1769;
    bootstrap.player_perk_counts[0].pair_count = 1;
    bootstrap.player_perk_counts[0].pairs[0] = .{
        .perk_id = @intFromEnum(PerkId.fire_caugh),
        .count = 1,
    };

    var transition = replay_codec.CaptureStateTransitionEvent{
        .tick_index = 0,
    };
    transition.transition_count = 1;
    transition.transitions[0] = .{
        .target_state = capture_state_reset_target,
        .has_before_state = true,
        .before_state = 9,
        .has_after_state = true,
        .after_state = capture_state_reset_target,
    };

    replay.events = blk: {
        const events = try allocator.alloc(replay_codec.ReplayEvent, 2);
        events[0] = .{ .capture_bootstrap = bootstrap };
        events[1] = .{ .capture_state_transition = transition };
        allocator.free(replay.events);
        break :blk events;
    };

    var trace: std.ArrayList(ReplayTickTrace) = .empty;
    defer trace.deinit(allocator);
    const result = try runReplayScaffoldWithTrace(
        replay,
        &trace,
        allocator,
        .{
            .dt_frame_overrides = &.{
                .{ .tick_index = 0, .dt_frame = 0.1 },
                .{ .tick_index = 1, .dt_frame = 0.1 },
            },
            .quest_spawn_entries = &.{},
        },
    );

    try std.testing.expectEqual(@as(i32, 1), result.player_weapon_id);
    try std.testing.expectEqual(@as(i32, 0), result.player_experience);
    try std.testing.expectEqual(@as(i32, 1), result.player_level);
    try std.testing.expectEqual(@as(usize, 0), result.creature_active_count);
    try std.testing.expectEqual(@as(usize, 2), trace.items.len);
    try std.testing.expectEqual(@as(i32, 0), trace.items[1].bonuses.bonus_reflex_boost_ms);
    try std.testing.expectEqual(@as(i32, 0), trace.items[1].player.player_perk54_count);
}

test "capture state reset clears transient pools and restores header fx toggle" {
    var state = state_mod.GameplayState.init(0x1234);
    state.game_mode = .quests;
    state.fx_toggle = 1;
    state.hardcore = true;
    state.perk_selection.pending_count = 2;

    var players_storage: [state_mod.max_players]state_mod.PlayerState = undefined;
    const players = players_storage[0..1];
    player_runtime.resetPlayers(players, 1024.0, null);

    var creatures = creatures_mod.CreaturePool{};
    creatures.entries[0].active = true;
    creatures.entries[0].lifecycle_stage = creature_lifecycle.alive;

    var particles = particles_mod.ParticlePool{};
    particles.entries[0].active = true;

    var projectiles = projectiles_mod.ProjectilePool{};
    projectiles.entries[0].active = true;

    var secondary_projectiles = secondary_projectiles_mod.SecondaryProjectilePool{};
    secondary_projectiles.entries[0].active = true;

    var bonuses = bonus_runtime.BonusPool{};
    bonuses.entries[0].bonus_id = .weapon;
    bonuses.entries[0].amount = 12;

    var quest_spawn_entries_storage: [max_test_quest_spawn_entries]spawn_mod.QuestSpawnEntry = undefined;
    var quest_spawn_entries: []spawn_mod.QuestSpawnEntry = &.{};
    var quest_spawn_timeline_ms: f32 = 100.0;
    var quest_no_creatures_timer_ms: f32 = 50.0;
    var quest_completion_transition_ms: f32 = 42.0;

    applyCaptureStateReset(
        &state,
        players,
        &creatures,
        &particles,
        &projectiles,
        &secondary_projectiles,
        &bonuses,
        1024.0,
        @intFromEnum(game_ids.WeaponId.pistol),
        0,
        true,
        quest_spawn_entries_storage[0..],
        0,
        &quest_spawn_entries,
        &quest_spawn_timeline_ms,
        &quest_no_creatures_timer_ms,
        &quest_completion_transition_ms,
    );

    try std.testing.expectEqual(@as(i32, 0), state.fx_toggle);
    try std.testing.expectEqual(@as(i32, 2), state.perk_selection.pending_count);
    try std.testing.expect(!creatures.entries[0].active);
    try std.testing.expect(!particles.entries[0].active);
    try std.testing.expect(!projectiles.entries[0].active);
    try std.testing.expect(!secondary_projectiles.entries[0].active);
    try std.testing.expectEqual(game_ids.BonusId.unused, bonuses.entries[0].bonus_id);
    try std.testing.expect(creatures.capture_spawn_events_authoritative);
}

test "shock chain bonus no-ops when no alive target exists" {
    var state = state_mod.GameplayState.init(0x1234);
    var projectiles = projectiles_mod.ProjectilePool{};
    var creatures = creatures_mod.CreaturePool{};
    creatures.entries[0].active = true;
    creatures.entries[0].lifecycle_stage = 0.0;

    applyShockChainBonus(
        &state,
        &projectiles,
        &creatures,
        .{ .x = 512.0, .y = 512.0 },
    );

    try std.testing.expectEqual(@as(i32, 0), state.shock_chain_links_left);
    try std.testing.expectEqual(@as(i32, -1), state.shock_chain_projectile_id);
    try std.testing.expect(!projectiles.entries[0].active);
}

test "resolve quest level key ignores seed fallback outside i32 range" {
    const allocator = std.testing.allocator;
    var replay = try buildTestReplay(allocator, .{
        .game_mode_id = @intFromEnum(GameModeId.quests),
        .seed = std.math.maxInt(u32),
        .tick_rate = 60,
        .inputs = &.{0},
        .events = &.{},
    });
    defer replay.deinit(allocator);

    try std.testing.expect(resolveQuestLevelKey(replay.header) == null);
}

test "quest scaffold rejects oversized quest spawn override table" {
    const allocator = std.testing.allocator;
    var replay = try buildTestReplay(allocator, .{
        .game_mode_id = @intFromEnum(GameModeId.quests),
        .seed = 101,
        .tick_rate = 60,
        .inputs = &.{0},
        .events = &.{},
    });
    defer replay.deinit(allocator);

    const oversized = try allocator.alloc(
        spawn_mod.QuestSpawnEntry,
        max_test_quest_spawn_entries + 1,
    );
    defer allocator.free(oversized);
    for (oversized) |*entry| {
        entry.* = .{
            .pos = .{ .x = 0.0, .y = 0.0 },
            .heading = 0.0,
            .spawn_id = .zombie_boss_spawner_00,
            .trigger_ms = 0,
            .count = 0,
        };
    }

    try std.testing.expectError(
        error.UnsupportedQuestSpawnTable,
        runReplayScaffoldWithOptions(replay, .{
            .quest_spawn_entries = oversized,
        }),
    );
}

test "survival scaffold rejects world_size outside i32 range" {
    const allocator = std.testing.allocator;
    var replay = try buildTestReplay(allocator, .{
        .tick_rate = 60,
        .inputs = &.{0},
        .events = &.{},
    });
    defer replay.deinit(allocator);

    replay.header.world_size = 3_000_000_000.0;
    try std.testing.expectError(error.InvalidHeaderValue, runReplayScaffold(replay));
}

test "quest scaffold disables world dt perk steps for original capture dt overrides" {
    const allocator = std.testing.allocator;

    const bootstrap_event = replay_codec.ReplayEvent{
        .capture_bootstrap = blk: {
            var bootstrap = replay_codec.CaptureBootstrapEvent{
                .tick_index = 0,
            };
            bootstrap.player_count = 1;
            bootstrap.players[0] = .{
                .weapon_id = 1,
                .pos_x = 512.0,
                .pos_y = 512.0,
                .health = 100.0,
                .ammo = 11.0,
                .experience = 0,
                .level = 1,
            };
            break :blk bootstrap;
        },
    };
    const reflex_apply_event = replay_codec.ReplayEvent{
        .capture_perk_apply = .{
            .tick_index = 0,
            .perk_id = @intFromEnum(PerkId.reflex_boosted),
            .outside_before = true,
        },
    };

    const run = struct {
        fn runCase(
            allocator_inner: std.mem.Allocator,
            bootstrap: replay_codec.ReplayEvent,
            reflex_apply: replay_codec.ReplayEvent,
            include_reflex_boosted: bool,
            dt_overrides: ?[]const DtFrameOverride,
        ) !struct { x_q4: i32, y_q4: i32 } {
            const events = [_]replay_codec.ReplayEvent{ bootstrap, reflex_apply };
            var replay = try buildTestReplay(allocator_inner, .{
                .game_mode_id = @intFromEnum(GameModeId.quests),
                .seed = 101,
                .tick_rate = 60,
                .inputs = &.{0},
                .events = if (include_reflex_boosted) events[0..2] else events[0..1],
            });
            defer replay.deinit(allocator_inner);

            replay.inputs[0][0].move_x = 1.0;
            replay.inputs[0][0].move_y = 0.0;
            replay.inputs[0][0].aim_x = 700.0;
            replay.inputs[0][0].aim_y = 512.0;

            var trace: std.ArrayList(ReplayTickTrace) = .empty;
            defer trace.deinit(allocator_inner);
            _ = try runReplayScaffoldWithTrace(
                replay,
                &trace,
                allocator_inner,
                .{
                    .quest_spawn_entries = &.{},
                    .dt_frame_overrides = dt_overrides,
                },
            );
            try std.testing.expectEqual(@as(usize, 1), trace.items.len);
            return .{
                .x_q4 = trace.items[0].player.player_pos_x_q4,
                .y_q4 = trace.items[0].player.player_pos_y_q4,
            };
        }
    }.runCase;

    const no_override_without_perk = try run(
        allocator,
        bootstrap_event,
        reflex_apply_event,
        false,
        null,
    );
    const no_override_with_perk = try run(
        allocator,
        bootstrap_event,
        reflex_apply_event,
        true,
        null,
    );
    try std.testing.expect(no_override_with_perk.x_q4 != no_override_without_perk.x_q4);

    const dt_override_rows = [_]DtFrameOverride{
        .{ .tick_index = 0, .dt_frame = 0.1 },
    };
    const override_without_perk = try run(
        allocator,
        bootstrap_event,
        reflex_apply_event,
        false,
        dt_override_rows[0..],
    );
    const override_with_perk = try run(
        allocator,
        bootstrap_event,
        reflex_apply_event,
        true,
        dt_override_rows[0..],
    );
    try std.testing.expectEqual(override_without_perk.x_q4, override_with_perk.x_q4);
    try std.testing.expectEqual(override_without_perk.y_q4, override_with_perk.y_q4);
}

test "evil eyes targeting defaults to alive player slot" {
    var state = state_mod.GameplayState.init(1);
    var players = [_]state_mod.PlayerState{
        .{ .index = 0, .pos = .{}, .health = 0.0 },
        .{
            .index = 1,
            .pos = .{},
            .health = 100.0,
            .aim = .{ .x = 100.0, .y = 200.0 },
        },
    };
    players[1].perk_counts.set(PerkId.evil_eyes, 1);

    var creatures = [_]creatures_mod.CreatureState{
        .{
            .active = true,
            .pos = .{ .x = 100.0, .y = 200.0 },
            .lifecycle_stage = creature_lifecycle.alive,
            .size = 50.0,
            .hp = 100.0,
        },
    };

    updateEvilEyesTargets(&state, players[0..], creatures[0..]);
    try std.testing.expectEqual(@as(i32, -1), players[0].evil_eyes_target_creature);
    try std.testing.expectEqual(@as(i32, 0), players[1].evil_eyes_target_creature);
}

test "evil eyes targeting assigns each alive owner" {
    var state = state_mod.GameplayState.init(1);
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{},
            .health = 100.0,
            .aim = .{ .x = 100.0, .y = 200.0 },
        },
        .{
            .index = 1,
            .pos = .{},
            .health = 100.0,
            .aim = .{ .x = 140.0, .y = 200.0 },
        },
    };
    players[0].perk_counts.set(PerkId.evil_eyes, 1);
    players[1].perk_counts.set(PerkId.evil_eyes, 1);

    var creatures = [_]creatures_mod.CreatureState{
        .{
            .active = true,
            .pos = .{ .x = 100.0, .y = 200.0 },
            .lifecycle_stage = creature_lifecycle.alive,
            .size = 50.0,
            .hp = 100.0,
        },
        .{
            .active = true,
            .pos = .{ .x = 140.0, .y = 200.0 },
            .lifecycle_stage = creature_lifecycle.alive,
            .size = 50.0,
            .hp = 100.0,
        },
    };

    updateEvilEyesTargets(&state, players[0..], creatures[0..]);
    try std.testing.expectEqual(@as(i32, 0), players[0].evil_eyes_target_creature);
    try std.testing.expectEqual(@as(i32, 1), players[1].evil_eyes_target_creature);
}

fn activeParticleCount(particles: *const particles_mod.ParticlePool) usize {
    var count: usize = 0;
    for (particles.entries) |entry| {
        if (entry.active) count += 1;
    }
    return count;
}

test "pyrokinetic spawns particle burst when collision timer wraps" {
    var state = state_mod.GameplayState.init(0);
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{},
            .health = 100.0,
            .aim = .{ .x = 100.0, .y = 200.0 },
        },
    };
    players[0].perk_counts.set(PerkId.pyrokinetic, 1);

    var creatures = creatures_mod.CreaturePool{};
    creatures.entries[0] = .{
        .active = true,
        .pos = .{ .x = 100.0, .y = 200.0 },
        .lifecycle_stage = creature_lifecycle.alive,
        .collision_timer = 0.1,
        .size = 50.0,
        .hp = 100.0,
    };

    var particles = particles_mod.ParticlePool{};

    applyPyrokineticEffects(&state, players[0..], &creatures, &particles, 0.2);
    try std.testing.expectApproxEqAbs(@as(f32, 0.5), creatures.entries[0].collision_timer, 1e-6);
    try std.testing.expectEqual(@as(usize, 5), activeParticleCount(&particles));

    const expected_intensities = [_]f32{ 0.8, 0.6, 0.4, 0.3, 0.2 };
    for (expected_intensities, 0..) |expected, idx| {
        try std.testing.expectApproxEqAbs(expected, particles.entries[idx].intensity, 1e-6);
    }
}

test "pyrokinetic uses f32 timer threshold before wrapping" {
    var state = state_mod.GameplayState.init(0);
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{},
            .health = 100.0,
            .aim = .{ .x = 100.0, .y = 200.0 },
        },
    };
    players[0].perk_counts.set(PerkId.pyrokinetic, 1);

    var creatures = creatures_mod.CreaturePool{};
    creatures.entries[0] = .{
        .active = true,
        .pos = .{ .x = 100.0, .y = 200.0 },
        .lifecycle_stage = creature_lifecycle.alive,
        .collision_timer = 0.034000009298324585,
        .size = 50.0,
        .hp = 100.0,
    };

    var particles = particles_mod.ParticlePool{};

    applyPyrokineticEffects(
        &state,
        players[0..],
        &creatures,
        &particles,
        0.03400000184774399,
    );
    try std.testing.expect(creatures.entries[0].collision_timer > 0.0);
    try std.testing.expect(creatures.entries[0].collision_timer < 1e-6);
    try std.testing.expectEqual(@as(usize, 0), activeParticleCount(&particles));

    applyPyrokineticEffects(
        &state,
        players[0..],
        &creatures,
        &particles,
        0.03200000151991844,
    );
    try std.testing.expectApproxEqAbs(@as(f32, 0.5), creatures.entries[0].collision_timer, 1e-6);
    try std.testing.expectEqual(@as(usize, 5), activeParticleCount(&particles));
}

test "pyrokinetic defaults to first alive player slot" {
    var state = state_mod.GameplayState.init(0);
    var players = [_]state_mod.PlayerState{
        .{ .index = 0, .pos = .{}, .health = 0.0 },
        .{
            .index = 1,
            .pos = .{},
            .health = 100.0,
            .aim = .{ .x = 100.0, .y = 200.0 },
        },
    };
    players[1].perk_counts.set(PerkId.pyrokinetic, 1);

    var creatures = creatures_mod.CreaturePool{};
    creatures.entries[0] = .{
        .active = true,
        .pos = .{ .x = 100.0, .y = 200.0 },
        .lifecycle_stage = creature_lifecycle.alive,
        .collision_timer = 0.1,
        .size = 50.0,
        .hp = 100.0,
    };
    var particles = particles_mod.ParticlePool{};

    applyPyrokineticEffects(&state, players[0..], &creatures, &particles, 0.2);
    try std.testing.expectApproxEqAbs(@as(f32, 0.5), creatures.entries[0].collision_timer, 1e-6);
    try std.testing.expectEqual(@as(usize, 5), activeParticleCount(&particles));
}

test "pyrokinetic targets all alive owners in default mode" {
    var state = state_mod.GameplayState.init(0);
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{},
            .health = 100.0,
            .aim = .{ .x = 100.0, .y = 200.0 },
        },
        .{
            .index = 1,
            .pos = .{},
            .health = 100.0,
            .aim = .{ .x = 140.0, .y = 200.0 },
        },
    };
    players[0].perk_counts.set(PerkId.pyrokinetic, 1);
    players[1].perk_counts.set(PerkId.pyrokinetic, 1);

    var creatures = creatures_mod.CreaturePool{};
    creatures.entries[0] = .{
        .active = true,
        .pos = .{ .x = 100.0, .y = 200.0 },
        .lifecycle_stage = creature_lifecycle.alive,
        .collision_timer = 0.1,
        .size = 50.0,
        .hp = 100.0,
    };
    creatures.entries[1] = .{
        .active = true,
        .pos = .{ .x = 140.0, .y = 200.0 },
        .lifecycle_stage = creature_lifecycle.alive,
        .collision_timer = 0.1,
        .size = 50.0,
        .hp = 100.0,
    };
    var particles = particles_mod.ParticlePool{};

    applyPyrokineticEffects(&state, players[0..], &creatures, &particles, 0.2);
    try std.testing.expectApproxEqAbs(@as(f32, 0.5), creatures.entries[0].collision_timer, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 0.5), creatures.entries[1].collision_timer, 1e-6);
    try std.testing.expectEqual(@as(usize, 10), activeParticleCount(&particles));
}

test "long distance runner ramps speed above base cap and coasts on release" {
    const dt = 0.1;
    const steps: usize = 12;
    var state = state_mod.GameplayState.init(1);
    var base_player = state_mod.PlayerState{
        .index = 0,
        .pos = .{ .x = 100.0, .y = 100.0 },
        .heading = (state_mod.Vec2{ .x = 1.0, .y = 0.0 }).toHeading(),
    };
    var perk_player = state_mod.PlayerState{
        .index = 0,
        .pos = .{ .x = 100.0, .y = 100.0 },
        .heading = (state_mod.Vec2{ .x = 1.0, .y = 0.0 }).toHeading(),
    };
    perk_player.perk_counts.set(PerkId.long_distance_runner, 1);

    const move_input = replay_codec.ReplayPlayerInput{
        .move_x = 1.0,
        .move_y = 0.0,
        .aim_x = 101.0,
        .aim_y = 100.0,
        .flags = 0,
    };
    const move_flags = replay_codec.unpackInputFlags(0);

    for (0..steps) |_| {
        updatePlayerFromReplayInput(&base_player, move_input, move_flags, &state, null, dt);
        finalizePlayerPostUpdate(&base_player, 1024.0);
        updatePlayerFromReplayInput(&perk_player, move_input, move_flags, &state, null, dt);
        finalizePlayerPostUpdate(&perk_player, 1024.0);
    }

    var expected_perk_speed: f32 = 0.0;
    const dt_f32 = narrowF32(dt);
    for (0..steps) |_| {
        if (expected_perk_speed < 2.0) {
            expected_perk_speed = narrowF32(expected_perk_speed + dt_f32 * 4.0);
        }
        expected_perk_speed = narrowF32(expected_perk_speed + dt_f32);
        if (expected_perk_speed > 2.8) {
            expected_perk_speed = 2.8;
        }
    }

    try std.testing.expectApproxEqAbs(@as(f32, 2.0), base_player.move_speed, 1e-6);
    try std.testing.expectApproxEqAbs(expected_perk_speed, perk_player.move_speed, 1e-6);
    try std.testing.expect(perk_player.pos.x > base_player.pos.x);

    const prev_x = perk_player.pos.x;
    const coast_input = replay_codec.ReplayPlayerInput{
        .move_x = 0.0,
        .move_y = 0.0,
        .aim_x = perk_player.pos.x + 1.0,
        .aim_y = perk_player.pos.y,
        .flags = 0,
    };
    updatePlayerFromReplayInput(&perk_player, coast_input, move_flags, &state, null, dt);
    finalizePlayerPostUpdate(&perk_player, 1024.0);

    const expected_coast_speed = narrowF32(expected_perk_speed - dt_f32 * 15.0);
    try std.testing.expectApproxEqAbs(expected_coast_speed, perk_player.move_speed, 1e-6);
    try std.testing.expect(perk_player.pos.x > prev_x);
}

test "alternate weapon slows movement by 20 percent" {
    var state = state_mod.GameplayState.init(1);
    const move_heading = (state_mod.Vec2{ .x = 1.0, .y = 0.0 }).toHeading();
    var base_player = state_mod.PlayerState{
        .index = 0,
        .pos = .{},
        .move_speed = 2.0,
        .heading = move_heading,
    };
    var perk_player = state_mod.PlayerState{
        .index = 0,
        .pos = .{},
        .move_speed = 2.0,
        .heading = move_heading,
    };
    perk_player.perk_counts.set(PerkId.alternate_weapon, 1);

    const input = replay_codec.ReplayPlayerInput{
        .move_x = 1.0,
        .move_y = 0.0,
        .aim_x = 0.0,
        .aim_y = 0.0,
        .flags = 0,
    };
    const flags = replay_codec.unpackInputFlags(0);

    updatePlayerFromReplayInput(&base_player, input, flags, &state, null, 1.0);
    finalizePlayerPostUpdate(&base_player, 1024.0);
    updatePlayerFromReplayInput(&perk_player, input, flags, &state, null, 1.0);
    finalizePlayerPostUpdate(&perk_player, 1024.0);

    try std.testing.expectApproxEqAbs(@as(f32, 100.0), base_player.pos.x, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 80.0), perk_player.pos.x, 1e-6);
}

test "fire cough projectile uses pre-move player position for muzzle origin" {
    var state = state_mod.GameplayState.init(1);
    var projectiles = projectiles_mod.ProjectilePool{};
    var player = state_mod.PlayerState{
        .index = 0,
        .pos = .{ .x = 100.0, .y = 100.0 },
        .aim = .{ .x = 200.0, .y = 100.0 },
        .aim_heading = 0.0,
        .fire_cough_timer = 1.95,
    };
    player.perk_counts.set(PerkId.fire_caugh, 1);

    const before_pos = player.pos;
    weapons_runtime.applyPlayerPerkTicks(
        &state,
        &player,
        &projectiles,
        0.1,
    );

    const move_input = replay_codec.ReplayPlayerInput{
        .move_x = 1.0,
        .move_y = 0.0,
        .aim_x = 200.0,
        .aim_y = 100.0,
        .flags = 0,
    };
    const move_flags = replay_codec.unpackInputFlags(0);
    updatePlayerFromReplayInput(&player, move_input, move_flags, &state, null, 0.1);
    finalizePlayerPostUpdate(&player, 1024.0);

    try std.testing.expect(player.pos.x > before_pos.x);

    const proj = projectiles.entries[0];
    try std.testing.expect(proj.active);
    try std.testing.expectEqual(@intFromEnum(game_ids.ProjectileTypeId.fire_bullets), proj.type_id);

    const muzzle_dir = blk: {
        const dir = directionFromHeadingNative(0.0);
        const cos_theta = math.cos(-0.150915);
        const sin_theta = math.sin(-0.150915);
        break :blk state_mod.Vec2{
            .x = dir.x * cos_theta - dir.y * sin_theta,
            .y = dir.x * sin_theta + dir.y * cos_theta,
        };
    };
    const expected_pos = state_mod.Vec2.add(before_pos, muzzle_dir.mul(16.0));
    try std.testing.expectApproxEqAbs(expected_pos.x, proj.pos.x, 1e-6);
    try std.testing.expectApproxEqAbs(expected_pos.y, proj.pos.y, 1e-6);
}

test "pending fireblast spawns sixteen plasma rifle projectiles" {
    var state = state_mod.GameplayState.init(1);
    var players = [_]state_mod.PlayerState{
        .{ .index = 0, .pos = .{ .x = 512.0, .y = 512.0 } },
    };
    var projectiles = projectiles_mod.ProjectilePool{};
    var creatures = creatures_mod.CreaturePool{};
    var bonuses = bonus_runtime.BonusPool{};

    state.pending_fireblast_origins[0] = players[0].pos;
    state.pending_fireblast_count = 1;

    applyPendingBonusEffects(
        &state,
        players[0..],
        &projectiles,
        &creatures,
        &bonuses,
        0.016,
        1024.0,
        1,
    );

    var active_count: i32 = 0;
    for (projectiles.entries) |entry| {
        if (!entry.active) continue;
        active_count += 1;
        try std.testing.expectEqual(@intFromEnum(game_ids.ProjectileTypeId.plasma_rifle), entry.type_id);
    }
    try std.testing.expectEqual(@as(i32, 16), active_count);
    try std.testing.expectEqual(@as(i32, 0), state.pending_fireblast_count);
}

test "pending fireblast does not convert into fire bullets while guard is active" {
    var state = state_mod.GameplayState.init(1);
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{ .x = 512.0, .y = 512.0 },
            .fire_bullets_timer = 1.0,
        },
    };
    var projectiles = projectiles_mod.ProjectilePool{};
    var creatures = creatures_mod.CreaturePool{};
    var bonuses = bonus_runtime.BonusPool{};

    state.pending_fireblast_origins[0] = players[0].pos;
    state.pending_fireblast_count = 1;

    applyPendingBonusEffects(
        &state,
        players[0..],
        &projectiles,
        &creatures,
        &bonuses,
        0.016,
        1024.0,
        1,
    );

    var plasma_count: i32 = 0;
    var fire_bullets_count: i32 = 0;
    for (projectiles.entries) |entry| {
        if (!entry.active) continue;
        if (entry.type_id == @intFromEnum(game_ids.ProjectileTypeId.plasma_rifle)) plasma_count += 1;
        if (entry.type_id == @intFromEnum(game_ids.ProjectileTypeId.fire_bullets)) fire_bullets_count += 1;
    }
    try std.testing.expectEqual(@as(i32, 16), plasma_count);
    try std.testing.expectEqual(@as(i32, 0), fire_bullets_count);
}

test "pending nuke damage is limited to radius" {
    var state = state_mod.GameplayState.init(1);
    var players = [_]state_mod.PlayerState{
        .{ .index = 0, .pos = .{ .x = 512.0, .y = 512.0 } },
    };
    var projectiles = projectiles_mod.ProjectilePool{};
    var creatures = creatures_mod.CreaturePool{};
    var bonuses = bonus_runtime.BonusPool{};

    _ = creatures.spawnInit(.{
        .origin_template_id = -1,
        .pos = .{ .x = 612.0, .y = 512.0 },
        .heading = 0.0,
        .phase_seed = 0.0,
        .type_id = .alien,
        .size = 44.0,
        .move_speed = 0.0,
        .health = 10.0,
        .max_health = 10.0,
        .reward_value = 50.0,
        .contact_damage = 4.0,
    });
    _ = creatures.spawnInit(.{
        .origin_template_id = -1,
        .pos = .{ .x = 812.0, .y = 512.0 },
        .heading = 0.0,
        .phase_seed = 0.0,
        .type_id = .alien,
        .size = 44.0,
        .move_speed = 0.0,
        .health = 10.0,
        .max_health = 10.0,
        .reward_value = 50.0,
        .contact_damage = 4.0,
    });

    state.pending_nuke_origins[0] = players[0].pos;
    state.pending_nuke_count = 1;

    applyPendingBonusEffects(
        &state,
        players[0..],
        &projectiles,
        &creatures,
        &bonuses,
        0.016,
        1024.0,
        1,
    );

    try std.testing.expect(creatures.entries[0].hp <= 0.0);
    try std.testing.expectApproxEqAbs(@as(f32, 10.0), creatures.entries[1].hp, 1e-6);
    try std.testing.expectEqual(@as(i32, 0), state.pending_nuke_count);
}

test "poison bullets does not trigger on pending nuke radius damage" {
    var state = state_mod.GameplayState.init(1);
    state.rng.state = 1; // Mirrors poison-hit seed but nuke path must not set poison flags.
    var players = [_]state_mod.PlayerState{
        .{ .index = 0, .pos = .{ .x = 512.0, .y = 512.0 } },
    };
    players[0].perk_counts.set(PerkId.poison_bullets, 1);
    var projectiles = projectiles_mod.ProjectilePool{};
    var creatures = creatures_mod.CreaturePool{};
    var bonuses = bonus_runtime.BonusPool{};

    _ = creatures.spawnInit(.{
        .origin_template_id = -1,
        .pos = .{ .x = 612.0, .y = 512.0 },
        .heading = 0.0,
        .phase_seed = 0.0,
        .type_id = .alien,
        .flags = spawn_mod.CreatureFlags.anim_ping_pong,
        .size = 44.0,
        .move_speed = 0.0,
        .health = 2000.0,
        .max_health = 2000.0,
        .reward_value = 50.0,
        .contact_damage = 4.0,
    });

    state.pending_nuke_origins[0] = players[0].pos;
    state.pending_nuke_count = 1;

    applyPendingBonusEffects(
        &state,
        players[0..],
        &projectiles,
        &creatures,
        &bonuses,
        0.016,
        1024.0,
        1,
    );

    try std.testing.expect((creatures.entries[0].flags & spawn_mod.CreatureFlags.self_damage_tick) == 0);
}

test "pending nuke spawns pistol and gauss projectiles with native meta ranges" {
    var state = state_mod.GameplayState.init(1);
    var players = [_]state_mod.PlayerState{
        .{ .index = 0, .pos = .{ .x = 512.0, .y = 512.0 } },
    };
    var projectiles = projectiles_mod.ProjectilePool{};
    var creatures = creatures_mod.CreaturePool{};
    var bonuses = bonus_runtime.BonusPool{};

    state.pending_nuke_origins[0] = players[0].pos;
    state.pending_nuke_count = 1;

    applyPendingBonusEffects(
        &state,
        players[0..],
        &projectiles,
        &creatures,
        &bonuses,
        0.016,
        1024.0,
        1,
    );

    var pistol_count: i32 = 0;
    var gauss_count: i32 = 0;
    for (projectiles.entries) |entry| {
        if (!entry.active) continue;
        if (entry.type_id == @intFromEnum(game_ids.ProjectileTypeId.pistol)) {
            pistol_count += 1;
            try std.testing.expectApproxEqAbs(@as(f32, 55.0), entry.travel_budget, 1e-6);
            try std.testing.expect(entry.speed_scale >= 0.5);
            try std.testing.expect(entry.speed_scale < 1.0);
        } else if (entry.type_id == @intFromEnum(game_ids.ProjectileTypeId.gauss_gun)) {
            gauss_count += 1;
            try std.testing.expectApproxEqAbs(@as(f32, 215.0), entry.travel_budget, 1e-6);
            try std.testing.expectApproxEqAbs(@as(f32, 1.0), entry.speed_scale, 1e-6);
        }
    }

    try std.testing.expect(pistol_count >= 4);
    try std.testing.expect(pistol_count <= 7);
    try std.testing.expectEqual(@as(i32, 2), gauss_count);
}

test "pending creature projectile queue materializes hostile shots before projectile step" {
    var state = state_mod.GameplayState.init(1);
    var projectiles = projectiles_mod.ProjectilePool{};

    state.pending_creature_projectile_count = 1;
    state.pending_creature_projectiles[0] = .{
        .type_id = @intFromEnum(game_ids.ProjectileTypeId.plasma_rifle),
        .owner = owner_ref.OwnerRef.fromCreature(17),
        .angle = native_half_pi,
        .pos = .{ .x = 100.0, .y = 200.0 },
    };

    applyPendingCreatureProjectiles(&state, &projectiles);

    try std.testing.expectEqual(@as(i32, 0), state.pending_creature_projectile_count);
    try std.testing.expect(projectiles.entries[0].active);
    try std.testing.expect(projectiles.entries[0].hits_players);
    try std.testing.expectEqual(@intFromEnum(game_ids.ProjectileTypeId.plasma_rifle), projectiles.entries[0].type_id);
    try std.testing.expectEqual(@as(i32, 17), projectiles.entries[0].owner.toLegacy());
    try std.testing.expectApproxEqAbs(@as(f32, 100.0), projectiles.entries[0].pos.x, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 200.0), projectiles.entries[0].pos.y, 1e-6);
}

test "lifeline 50-50 replay perk effect deactivates every other eligible creature slot" {
    var state = state_mod.GameplayState.init(1);
    const before_rng = state.rng.state;
    var creatures = creatures_mod.CreaturePool{};

    for (0..8) |idx| {
        creatures.entries[idx].active = true;
        creatures.entries[idx].hp = 100.0;
        creatures.entries[idx].pos = .{
            .x = @floatFromInt(idx),
            .y = @as(f32, @floatFromInt(idx)) * 10.0,
        };
        creatures.entries[idx].flags = 0;
    }
    creatures.entries[3].flags = spawn_mod.CreatureFlags.anim_ping_pong;
    creatures.entries[5].hp = 600.0;

    applyReplayPerkCreatureEffects(
        PerkId.lifeline_50_50,
        &state,
        &creatures,
        0.016,
    );

    const expected = [_]bool{ true, false, true, true, true, true, true, false };
    for (expected, 0..) |active_expected, idx| {
        try std.testing.expectEqual(active_expected, creatures.entries[idx].active);
    }
    try std.testing.expect(before_rng != state.rng.state);
}

fn findSeedForRandModSequence(
    moduli: []const u32,
    targets: []const u32,
    max_seed: u32,
) ?u32 {
    if (moduli.len == 0 or moduli.len != targets.len) return null;

    var seed: u32 = 0;
    while (seed < max_seed) : (seed += 1) {
        var rng = spawn_mod.Crand.init(seed);
        var matches = true;
        for (moduli, targets) |modulus, target| {
            if (modulus == 0) return null;
            if ((rng.rand() % modulus) != target) {
                matches = false;
                break;
            }
        }
        if (matches) return seed;
    }
    return null;
}

test "jinxed kills creature and awards base reward" {
    const seed = findSeedForRandModSequence(
        &.{ 10, 0x14, 0x180 },
        &.{ 0, 0, 2 },
        500_000,
    ) orelse unreachable;
    const dt = 0.2;

    var state = state_mod.GameplayState.init(seed);
    state.jinxed_timer = 0.0;
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{ .x = 10.0, .y = 20.0 },
            .health = 50.0,
            .experience = 100,
        },
    };
    players[0].perk_counts.set(PerkId.jinxed, 1);
    var creatures = creatures_mod.CreaturePool{};
    creatures.entries[2].active = true;
    creatures.entries[2].hp = 100.0;
    creatures.entries[2].lifecycle_stage = creature_lifecycle.alive;
    creatures.entries[2].reward_value = 12.7;

    applyJinxedEffects(&state, players[0..], &creatures, dt);

    try std.testing.expectApproxEqAbs(@as(f32, 1.8), state.jinxed_timer, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, -1.0), creatures.entries[2].hp, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 12.0), creatures.entries[2].lifecycle_stage, 1e-6);
    try std.testing.expectEqual(@as(i32, 112), players[0].experience);
}

test "jinxed reward uses float32 sum before truncation" {
    const seed = findSeedForRandModSequence(
        &.{ 10, 0x14, 0x180 },
        &.{ 0, 0, 2 },
        500_000,
    ) orelse unreachable;
    const dt = 0.2;

    var state = state_mod.GameplayState.init(seed);
    state.jinxed_timer = 0.0;
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{ .x = 10.0, .y = 20.0 },
            .health = 50.0,
            .experience = 139_451,
        },
    };
    players[0].perk_counts.set(PerkId.jinxed, 1);
    var creatures = creatures_mod.CreaturePool{};
    creatures.entries[2].active = true;
    creatures.entries[2].hp = 100.0;
    creatures.entries[2].lifecycle_stage = creature_lifecycle.alive;
    creatures.entries[2].reward_value = 97.99636190476191;

    applyJinxedEffects(&state, players[0..], &creatures, dt);

    try std.testing.expectEqual(@as(i32, 139_549), players[0].experience);
}

test "jinxed accident can target another alive player" {
    const seed = findSeedForRandModSequence(
        &.{ 10, 2, 0x14 },
        &.{ 3, 1, 0 },
        500_000,
    ) orelse unreachable;
    const dt = 0.2;

    var state = state_mod.GameplayState.init(seed);
    state.jinxed_timer = 0.0;
    state.bonuses.freeze = 1.0;
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{ .x = 10.0, .y = 20.0 },
            .health = 50.0,
        },
        .{
            .index = 1,
            .pos = .{ .x = 20.0, .y = 20.0 },
            .health = 70.0,
        },
    };
    players[0].perk_counts.set(PerkId.jinxed, 1);
    var creatures = creatures_mod.CreaturePool{};

    applyJinxedEffects(&state, players[0..], &creatures, dt);

    try std.testing.expectApproxEqAbs(@as(f32, 1.8), state.jinxed_timer, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 50.0), players[0].health, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 65.0), players[1].health, 1e-6);
}

test "jinxed timer uses f32 underflow threshold before proc" {
    const dt = 0.03400000184774399;
    var state = state_mod.GameplayState.init(7);
    state.jinxed_timer = 0.034000836312770844;
    const rng_before = state.rng.state;
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{ .x = 10.0, .y = 20.0 },
            .health = 50.0,
        },
    };
    players[0].perk_counts.set(PerkId.jinxed, 1);
    var creatures = creatures_mod.CreaturePool{};

    applyJinxedEffects(&state, players[0..], &creatures, dt);

    try std.testing.expectApproxEqAbs(@as(f32, 8.344650268554688e-07), state.jinxed_timer, 1e-12);
    try std.testing.expectApproxEqAbs(@as(f32, 50.0), players[0].health, 1e-6);
    try std.testing.expectEqual(rng_before, state.rng.state);
}

test "jinxed pool uses full 384-slot upper bound" {
    const seed = findSeedForRandModSequence(
        &.{ 10, 0x14, 0x180 },
        &.{ 0, 0, 0x17F },
        1_000_000,
    ) orelse unreachable;
    const dt = 0.2;

    var default_state = state_mod.GameplayState.init(seed);
    default_state.jinxed_timer = 0.0;
    var default_players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{},
            .health = 50.0,
            .experience = 100,
        },
    };
    default_players[0].perk_counts.set(PerkId.jinxed, 1);
    var default_creatures = creatures_mod.CreaturePool{};
    default_creatures.entries[0x17F].active = true;
    default_creatures.entries[0x17F].hp = 100.0;
    default_creatures.entries[0x17F].lifecycle_stage = creature_lifecycle.alive;
    default_creatures.entries[0x17F].reward_value = 12.7;

    applyJinxedEffects(&default_state, default_players[0..], &default_creatures, dt);

    try std.testing.expectApproxEqAbs(@as(f32, -1.0), default_creatures.entries[0x17F].hp, 1e-6);
    try std.testing.expectEqual(@as(i32, 112), default_players[0].experience);
}

test "reflex boosted perk scales world dt by 0.9" {
    const base_players = [_]state_mod.PlayerState{
        .{ .index = 0, .pos = .{} },
    };
    var perk_players = [_]state_mod.PlayerState{
        .{ .index = 0, .pos = .{} },
    };
    perk_players[0].perk_counts.set(PerkId.reflex_boosted, 1);

    try std.testing.expectApproxEqAbs(@as(f32, 1.0), applyPerkWorldDtSteps(base_players[0..], 1.0), 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 0.9), applyPerkWorldDtSteps(perk_players[0..], 1.0), 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 0.0), applyPerkWorldDtSteps(perk_players[0..], 0.0), 1e-6);
}

test "final revenge explosion applies radial damage on death transition" {
    var state = state_mod.GameplayState.init(1);
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{ .x = 100.0, .y = 100.0 },
            .health = -0.5,
        },
    };
    players[0].perk_counts.set(PerkId.final_revenge, 1);
    var creatures = creatures_mod.CreaturePool{};
    var bonuses = bonus_runtime.BonusPool{};

    _ = creatures.spawnInit(.{
        .origin_template_id = -1,
        .pos = .{ .x = 100.0, .y = 100.0 },
        .heading = 0.0,
        .phase_seed = 0.0,
        .type_id = .alien,
        .flags = 0,
        .size = 44.0,
        .move_speed = 0.0,
        .health = 10000.0,
        .max_health = 10000.0,
        .reward_value = 10.0,
        .contact_damage = 0.0,
    });

    applyFinalRevengeOnDeathTransition(
        &state,
        players[0..],
        0,
        0.5,
        &creatures,
        &bonuses,
        0.2,
        1024.0,
        5,
    );

    try std.testing.expectApproxEqAbs(@as(f32, 7440.0), creatures.entries[0].hp, 1e-6);
}

test "final revenge aoe includes active non-positive hp entries" {
    var state = state_mod.GameplayState.init(1);
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{ .x = 100.0, .y = 100.0 },
            .health = -1.0,
        },
    };
    players[0].perk_counts.set(PerkId.final_revenge, 1);
    var creatures = creatures_mod.CreaturePool{};
    var bonuses = bonus_runtime.BonusPool{};

    _ = creatures.spawnInit(.{
        .origin_template_id = -1,
        .pos = .{ .x = 100.0, .y = 100.0 },
        .heading = 0.0,
        .phase_seed = 0.0,
        .type_id = .alien,
        .flags = 0,
        .size = 44.0,
        .move_speed = 0.0,
        .health = 1.0,
        .max_health = 1.0,
        .reward_value = 10.0,
        .contact_damage = 0.0,
    });
    creatures.entries[0].hp = 0.0;
    creatures.entries[0].lifecycle_stage = creature_lifecycle.alive;

    _ = creatures.spawnInit(.{
        .origin_template_id = -1,
        .pos = .{ .x = 100.0, .y = 100.0 },
        .heading = 0.0,
        .phase_seed = 0.0,
        .type_id = .alien,
        .flags = 0,
        .size = 44.0,
        .move_speed = 0.0,
        .health = 10.0,
        .max_health = 10.0,
        .reward_value = 10.0,
        .contact_damage = 0.0,
    });
    _ = creatures.spawnInit(.{
        .origin_template_id = -1,
        .pos = .{ .x = 2000.0, .y = 2000.0 },
        .heading = 0.0,
        .phase_seed = 0.0,
        .type_id = .alien,
        .flags = 0,
        .size = 44.0,
        .move_speed = 0.0,
        .health = 10.0,
        .max_health = 10.0,
        .reward_value = 10.0,
        .contact_damage = 0.0,
    });

    applyFinalRevengeOnDeathTransition(
        &state,
        players[0..],
        0,
        1.0,
        &creatures,
        &bonuses,
        0.1,
        1024.0,
        5,
    );

    try std.testing.expectApproxEqAbs(@as(f32, 14.5), creatures.entries[0].lifecycle_stage, 1e-6);
    try std.testing.expect(creatures.entries[1].hp < 10.0);
    try std.testing.expectApproxEqAbs(@as(f32, 10.0), creatures.entries[2].hp, 1e-6);
}

const TestReplayConfig = struct {
    game_mode_id: i32 = @intFromEnum(GameModeId.survival),
    seed: u32 = 1,
    tick_rate: i32,
    quest_level: []const u8 = "",
    inputs: []const u32,
    events: []const replay_codec.ReplayEvent,
};

const TestReplayMultiConfig = struct {
    game_mode_id: i32 = @intFromEnum(GameModeId.survival),
    seed: u32 = 1,
    tick_rate: i32,
    player_count: i32,
    quest_level: []const u8 = "",
    inputs: []const []const u32,
    events: []const replay_codec.ReplayEvent,
};

fn buildTestReplay(
    allocator: std.mem.Allocator,
    cfg: TestReplayConfig,
) !replay_codec.Replay {
    const ticks = try allocator.alloc(replay_codec.ReplayTickInputs, cfg.inputs.len);
    errdefer allocator.free(ticks);

    for (cfg.inputs, 0..) |flags, tick_index| {
        const input_tick = try allocator.alloc(replay_codec.ReplayPlayerInput, 1);
        input_tick[0] = .{
            .move_x = 0.0,
            .move_y = 0.0,
            .aim_x = 0.0,
            .aim_y = 0.0,
            .flags = flags,
        };
        ticks[tick_index] = input_tick;
    }

    const events = try allocator.alloc(replay_codec.ReplayEvent, cfg.events.len);
    for (cfg.events, 0..) |event, idx| {
        events[idx] = event;
    }

    return .{
        .header = .{
            .game_mode_id = cfg.game_mode_id,
            .seed = cfg.seed,
            .replay_format_version = replay_codec.replay_format_version,
            .quest_level = try allocator.dupe(u8, cfg.quest_level),
            .bootstrap_kind = try allocator.dupe(u8, "none"),
            .bootstrap_seed = 1,
            .game_version = try allocator.dupe(u8, "0.7.0"),
            .tick_rate = cfg.tick_rate,
            .difficulty_level = 0,
            .hardcore = false,
            .preserve_bugs = false,
            .detail_preset = 5,
            .fx_toggle = 0,
            .world_size = 1024.0,
            .player_count = 1,
            .status = .{
                .quest_unlock_index = 0,
                .quest_unlock_index_full = 0,
                .weapon_usage_counts = [_]u32{0} ** replay_codec.weapon_usage_count,
            },
            .input_quantization = try allocator.dupe(u8, "raw"),
        },
        .inputs = ticks,
        .events = events,
    };
}

fn buildTestReplayMulti(
    allocator: std.mem.Allocator,
    cfg: TestReplayMultiConfig,
) !replay_codec.Replay {
    const ticks = try allocator.alloc(replay_codec.ReplayTickInputs, cfg.inputs.len);
    errdefer allocator.free(ticks);
    const players_len: usize = @intCast(cfg.player_count);

    for (cfg.inputs, 0..) |tick_flags, tick_index| {
        std.debug.assert(tick_flags.len == players_len);
        const input_tick = try allocator.alloc(replay_codec.ReplayPlayerInput, players_len);
        for (tick_flags, 0..) |flags, player_index| {
            input_tick[player_index] = .{
                .move_x = 0.0,
                .move_y = 0.0,
                .aim_x = 0.0,
                .aim_y = 0.0,
                .flags = flags,
            };
        }
        ticks[tick_index] = input_tick;
    }

    const events = try allocator.alloc(replay_codec.ReplayEvent, cfg.events.len);
    for (cfg.events, 0..) |event, idx| {
        events[idx] = event;
    }

    return .{
        .header = .{
            .game_mode_id = cfg.game_mode_id,
            .seed = cfg.seed,
            .replay_format_version = replay_codec.replay_format_version,
            .quest_level = try allocator.dupe(u8, cfg.quest_level),
            .bootstrap_kind = try allocator.dupe(u8, "none"),
            .bootstrap_seed = 1,
            .game_version = try allocator.dupe(u8, "0.7.0"),
            .tick_rate = cfg.tick_rate,
            .difficulty_level = 0,
            .hardcore = false,
            .preserve_bugs = false,
            .detail_preset = 5,
            .fx_toggle = 0,
            .world_size = 1024.0,
            .player_count = cfg.player_count,
            .status = .{
                .quest_unlock_index = 0,
                .quest_unlock_index_full = 0,
                .weapon_usage_counts = [_]u32{0} ** replay_codec.weapon_usage_count,
            },
            .input_quantization = try allocator.dupe(u8, "raw"),
        },
        .inputs = ticks,
        .events = events,
    };
}
