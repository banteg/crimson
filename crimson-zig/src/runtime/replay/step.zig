const std = @import("std");
const game_ids = @import("../../game_ids.zig");
const native_math = @import("../native_math.zig");
const replay_codec = @import("../../replay_codec.zig");

const runtime_bootstrap = @import("../bootstrap.zig");
const events = @import("events.zig");
const movement = @import("../movement.zig");
const timing = @import("../timing.zig");
const capture_state = @import("capture_state.zig");
const session_mod = @import("../session.zig");
const diagnostic_trace_mod = @import("diagnostic_trace.zig");

const bonus_runtime = @import("../bonuses.zig");
const creatures_mod = @import("../creatures.zig");
const effects_mod = @import("../effects.zig");
const perks = @import("../perks.zig");
const player_runtime = @import("../player.zig");
const projectiles_mod = @import("../projectiles.zig");
const rng_callers = @import("../../rng_caller_static.zig");
const spawn_mod = @import("../spawn.zig");
const state_mod = @import("../state.zig");
const survival_progression = @import("../survival_progression.zig");
const terrain_fx_mod = @import("../terrain_fx.zig");
const tutorial_runtime = @import("../../tutorial/runtime.zig");
const typo_runtime = @import("../../typo/runtime.zig");
const weapons_runtime = @import("../weapons.zig");

const narrowF32 = native_math.roundF32;
const SimulationContext = session_mod.DeterministicSession;

pub const StepError = events.EventError ||
    creatures_mod.CreatureRuntimeError ||
    bonus_runtime.BonusRuntimeError ||
    weapons_runtime.WeaponRuntimeError;

pub const TickPhase = enum {
    pre_reset,
    pre_events,
    post_pre_events,
    pre_effects,
    post_effects,
    pre_core_simulation,
    post_core_simulation,
    pre_player_movement,
    post_player_movement,
    pre_bonus_effects,
    post_bonus_effects,
    pre_post_events,
    post_post_events,
    finalize,
};

pub const StepFrame = struct {
    tick_index: usize,
    dt: f32,
    dt_world: f32 = 0.0,
    dt_sim: f32 = 0.0,
    dt_ms_i32: i32 = 0,
    dt_sim_ms_i32: i32 = 0,
    menu_open_seen_this_tick: bool = false,
    reload_active_any: bool = false,
    pre_events_applied: usize = 0,
    post_events_applied: usize = 0,
    rng_after_effects: u32 = 0,
    rng_after_perk_effects: u32 = 0,
    rng_after_creatures: u32 = 0,
    rng_after_projectiles: u32 = 0,
    rng_after_secondary_projectiles: u32 = 0,
    rng_after_particles: u32 = 0,
    rng_after_player_update: u32 = 0,
    rng_after_stage_spawns: u32 = 0,
    rng_after_wave_spawns: u32 = 0,
    rng_after_spawns: u32 = 0,
    rng_after_bonus_update: u32 = 0,
    projectile_tick_stats: projectiles_mod.ProjectileTickStats = .{},
};

pub const StepResult = struct {
    tick_index: usize,
    pre_events_applied: usize,
    post_events_applied: usize,
    reload_active_any: bool,
    dt_world: f32,
    dt_sim: f32,
    rng_after_effects: u32,
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
    projectile_tick_stats: projectiles_mod.ProjectileTickStats,
    bonus_pickups: bonus_runtime.BonusPickupBuffer,
    sfx_events: state_mod.RuntimeSfxBuffer,
    terrain_fx: terrain_fx_mod.TerrainFxBatch,
    rng_end: u32,
    pending_capture_state_reset: bool,
};

pub const PhaseHook = *const fn (
    context: *SimulationContext,
    phase: TickPhase,
    frame: *const StepFrame,
) void;

pub const CoreSimulationHook = *const fn (
    context: *SimulationContext,
    frame: *const StepFrame,
) void;

pub const StepHooks = struct {
    on_phase: ?PhaseHook = null,
    run_core_simulation: ?CoreSimulationHook = null,
};

pub const StepOptions = struct {
    hooks: StepHooks = .{},
    trace_sink: ?diagnostic_trace.Sink = null,
    diagnostic_trace_sink: ?DiagnosticTraceSink = null,
    timing_trace_ctx: ?*anyopaque = null,
    timing_trace_sink: ?TimingTraceSink = null,
};

const NativePlayerDamageContext = struct {
    state: *state_mod.GameplayState,
    players: []state_mod.PlayerState,
    creatures: *creatures_mod.CreaturePool,
    bonuses: *bonus_runtime.BonusPool,
    effects: *effects_mod.EffectPool,
    terrain_fx: *terrain_fx_mod.TerrainFxScratch,
    world_size: f32,
    detail_preset: i32,
};

fn onNativePlayerDamage(
    opaque_context: ?*anyopaque,
    player_index_i32: i32,
    health_before: f32,
    player1_health_before: f32,
    dt: f32,
) void {
    const context: *NativePlayerDamageContext = @ptrCast(@alignCast(opaque_context orelse return));
    if (player_index_i32 < 0) return;
    const player_index: usize = @intCast(player_index_i32);
    context.creatures.applyFinalRevengeOnPlayerDamage(
        context.state,
        context.players,
        player_index,
        health_before,
        player1_health_before,
        context.bonuses,
        context.effects,
        context.terrain_fx,
        dt,
        context.world_size,
        context.detail_preset,
    );
}

pub const DiagnosticTraceSink = *const fn (trace: diagnostic_trace_mod.ReplayTickTrace) void;
pub const TimingTraceSink = *const fn (ctx: ?*anyopaque, sample: diagnostic_trace_mod.ReplayTickTimingSample) void;

pub const diagnostic_trace = struct {
    pub const TickSnapshot = struct {
        tick_index: usize,
        dt: f32,
        dt_world: f32,
        dt_sim: f32,
        pre_events_applied: usize,
        post_events_applied: usize,
        rng_state: u32,
        rng_after_effects: u32,
        creature_active_count: usize,
        pending_capture_state_reset: bool,
    };

    pub const Sink = *const fn (snapshot: TickSnapshot) void;

    pub fn emit(sink: ?Sink, snapshot: TickSnapshot) void {
        if (sink) |trace_sink| {
            trace_sink(snapshot);
        }
    }
};

pub fn stepTick(
    context: *SimulationContext,
    tick_index: usize,
    tick_inputs: []const player_runtime.GameInput,
    tick_events: []const replay_codec.ReplayEvent,
    dt: f32,
    options: StepOptions,
) (events.EventError ||
    creatures_mod.CreatureRuntimeError ||
    bonus_runtime.BonusRuntimeError ||
    weapons_runtime.WeaponRuntimeError)!StepResult {
    var frame: StepFrame = .{
        .tick_index = tick_index,
        .dt = narrowF32(dt),
    };

    callPhaseHook(options.hooks, context, .pre_reset, &frame);
    context.state.sfx_queue.clear();
    if (context.pending_capture_state_reset) {
        capture_state.applyCaptureStateReset(
            &context.state,
            context.players(),
            &context.creatures,
            &context.effects,
            &context.sprite_effects,
            &context.particles,
            &context.projectiles,
            &context.secondary_projectiles,
            &context.bonuses,
            context.world_size,
            context.quest_start_weapon_id_for_reset,
            context.gore_disabled,
            context.capture_spawn_events_authoritative,
            &context.quest_spawn_timeline_ms,
            &context.quest_no_creatures_timer_ms,
            &context.quest_completion_transition_ms,
        );
        context.pending_capture_state_reset = false;
    }

    context.state.game_mode = context.game_mode;
    callPhaseHook(options.hooks, context, .pre_events, &frame);
    const perk_event_dt = survival_progression.timeScaleReflexBoostBonus(
        context.state.bonuses.reflex_boost,
        context.state.time_scale_active,
        frame.dt,
    );
    frame.pre_events_applied = try applyEventsForPhase(
        context,
        tick_events,
        .pre_step,
        perk_event_dt,
        &frame.menu_open_seen_this_tick,
    );
    callPhaseHook(options.hooks, context, .post_pre_events, &frame);

    var players = context.players();
    const players_for_inputs = @min(players.len, tick_inputs.len);
    for (tick_inputs[0..players_for_inputs]) |input| {
        const flags = input.flags;
        if (flags.fire_pressed) {
            context.fire_pressed_count += 1;
        }
        if (flags.reload_pressed) {
            context.reload_pressed_count += 1;
        }
        if (flags.reload_pressed or flags.reload_down) {
            frame.reload_active_any = true;
        }
    }

    frame.dt_world = if (context.apply_world_dt_steps)
        movement.applyPerkWorldDtSteps(players, frame.dt)
    else
        frame.dt;

    frame.dt_sim = survival_progression.timeScaleReflexBoostBonus(
        context.state.bonuses.reflex_boost,
        context.state.time_scale_active,
        frame.dt_world,
    );

    frame.dt_ms_i32 = timing.ftolMsI32(frame.dt);
    frame.dt_sim_ms_i32 = timing.ftolMsI32(frame.dt_sim);
    const dt_sim_ms: f32 = @floatFromInt(frame.dt_sim_ms_i32);
    emitTimingTrace(options, .{
        .tick_index = @intCast(tick_index),
        .gameplay_frame = @intCast(tick_index),
        .phase = "gpur_enter",
        .frame_dt_f32 = frame.dt,
        .frame_dt_ms_i32 = frame.dt_ms_i32,
        .frame_dt_ms_f32 = @floatFromInt(frame.dt_ms_i32),
        .time_scale_active_entry = context.state.time_scale_active,
        .time_scale_active_current = context.state.time_scale_active,
        .time_scale_factor = currentTimeScaleFactor(
            context.state.bonuses.reflex_boost,
            context.state.time_scale_active,
        ),
        .bonus_reflex_boost_timer = context.state.bonuses.reflex_boost,
        .mode_fn = "gameplay_update_and_render",
    });
    const elapsed_before_ms: f32 = if (context.game_mode == .rush)
        @floatFromInt(context.elapsed_ms_sim_rush)
    else
        context.elapsed_ms_sim;
    const elapsed_after_ms = if (context.game_mode == .survival)
        elapsed_before_ms + @as(f32, @floatFromInt(frame.dt_sim_ms_i32))
    else if (context.game_mode == .rush)
        @as(f32, @floatFromInt(context.elapsed_ms_sim_rush + @as(i64, frame.dt_ms_i32)))
    else
        elapsed_before_ms + @as(f32, @floatFromInt(frame.dt_sim_ms_i32));

    callPhaseHook(options.hooks, context, .pre_effects, &frame);
    context.effects.update(frame.dt, &context.terrain_fx.decals);
    perks.updateEvilEyesTargets(context.state.preserve_bugs, players, context.creatures.entries[0..]);
    perks.updatePerkEffects(&context.state, players, frame.dt_sim);
    perks.applyJinxedEffects(&context.state, players, &context.creatures, &context.terrain_fx, frame.dt_sim);
    perks.applyPyrokineticEffects(
        &context.state,
        players,
        &context.creatures,
        &context.particles,
        &context.terrain_fx,
        frame.dt_sim,
    );
    frame.rng_after_perk_effects = context.state.rng.state;
    frame.rng_after_effects = frame.rng_after_perk_effects;
    callPhaseHook(options.hooks, context, .post_effects, &frame);

    callPhaseHook(options.hooks, context, .pre_core_simulation, &frame);
    try context.creatures.updateWithTerrainFx(
        &context.state,
        players,
        frame.dt_sim,
        context.world_size,
        &context.bonuses,
        &context.terrain_fx,
        context.detail_preset,
    );
    bonus_runtime.applyPendingCreatureProjectiles(&context.state, &context.projectiles);
    frame.rng_after_creatures = context.state.rng.state;

    frame.projectile_tick_stats = context.projectiles.updateWithEffects(
        &context.state,
        players,
        &context.creatures,
        &context.bonuses,
        &context.effects,
        &context.terrain_fx,
        context.detail_preset,
        frame.dt_sim,
        context.world_size,
    );
    frame.rng_after_projectiles = context.state.rng.state;

    context.secondary_projectiles.updatePulseGunWithEffects(
        &context.state,
        players,
        &context.creatures,
        &context.bonuses,
        &context.effects,
        &context.sprite_effects,
        &context.terrain_fx,
        frame.dt_sim,
        context.world_size,
        context.detail_preset,
    );
    frame.rng_after_secondary_projectiles = context.state.rng.state;

    // Native updates the sprite pool before the particle loop, so sprites
    // spawned by particles only advance on the next tick.
    context.sprite_effects.update(frame.dt);
    context.particles.update(
        &context.state,
        players,
        &context.creatures,
        &context.bonuses,
        &context.sprite_effects,
        &context.terrain_fx,
        frame.dt_sim,
        context.world_size,
    );
    frame.rng_after_particles = context.state.rng.state;
    callPhaseHook(options.hooks, context, .post_core_simulation, &frame);

    callPhaseHook(options.hooks, context, .pre_player_movement, &frame);
    if (context.game_mode == .rush) {
        runtime_bootstrap.enforceRushLoadout(players);
    } else if (context.game_mode == .typo) {
        typo_runtime.beforeStep(&context.state, players);
    } else if (context.game_mode == .tutorial) {
        tutorial_runtime.beforeStep(&context.state, &context.creatures);
    }
    var player_preprocessed_alive = [_]bool{false} ** state_mod.max_players;
    for (players, 0..) |*player, player_idx| {
        const should_tick_perks = weapons_runtime.preprocessPlayerForPerkTicksWithEffects(
            &context.state,
            player,
            &context.effects,
            context.detail_preset,
            frame.dt_sim,
        );
        player_preprocessed_alive[player_idx] = should_tick_perks;
        if (!should_tick_perks) continue;
        weapons_runtime.applyPlayerPerkTicksWithEffects(
            &context.state,
            player,
            players,
            &context.projectiles,
            &context.sprite_effects,
            frame.dt_sim,
        );
    }
    for (tick_inputs[0..players_for_inputs], players[0..players_for_inputs], 0..) |raw_input, *player, player_idx| {
        if (!player_preprocessed_alive[player_idx]) {
            continue;
        }
        const input = if (context.game_mode == .typo and player_idx == 0)
            typo_runtime.transformPrimaryInput(&context.state, raw_input)
        else if (context.game_mode == .tutorial and player_idx == 0)
            tutorial_runtime.transformPrimaryInput(&context.state, raw_input)
        else
            raw_input;
        const flags = input.flags;
        const move_mode_for_tick = movement.resolveMoveModeForUpdate(flags);

        movement.updatePlayerFromGameInputWithPlayers(
            player,
            input,
            &context.state,
            players,
            &context.creatures,
            frame.dt_sim,
        );
        var player_damage_context: NativePlayerDamageContext = .{
            .state = &context.state,
            .players = players,
            .creatures = &context.creatures,
            .bonuses = &context.bonuses,
            .effects = &context.effects,
            .terrain_fx = &context.terrain_fx,
            .world_size = context.world_size,
            .detail_preset = context.detail_preset,
        };
        try weapons_runtime.stepPlayerForTickWithEffects(
            &context.state,
            player,
            players,
            &context.projectiles,
            &context.secondary_projectiles,
            &context.creatures,
            &context.particles,
            &context.effects,
            &context.sprite_effects,
            .{
                .context = &player_damage_context,
                .on_player_damage = onNativePlayerDamage,
            },
            context.detail_preset,
            .{
                .fire_down = flags.fire_down,
                .fire_pressed = flags.fire_pressed,
                .reload_pressed = flags.reload_pressed,
                .reload_down = flags.reload_down,
                .reload_active_any = frame.reload_active_any,
                .move_mode = move_mode_for_tick,
                .single_player_mode = players.len == 1,
                .preprocessed_player_tick = true,
            },
            frame.dt_sim,
        );
        movement.finalizePlayerPostUpdate(player, context.world_size);
    }
    frame.rng_after_player_update = context.state.rng.state;
    callPhaseHook(options.hooks, context, .post_player_movement, &frame);

    frame.rng_after_stage_spawns = context.state.rng.state;
    frame.rng_after_wave_spawns = context.state.rng.state;
    switch (context.game_mode) {
        .survival => {
            survival_progression.survivalUpdateWeaponHandouts(
                &context.state,
                players,
                narrowF32(elapsed_before_ms),
            );

            if (players.len > 0) {
                const stage_result = spawn_mod.advanceSurvivalSpawnStage(
                    context.spawn_stage,
                    players[0].level,
                );
                context.spawn_stage = stage_result.stage;
                context.stage_spawn_count += stage_result.count;
                for (stage_result.slice()) |spawn_call| {
                    try context.creatures.spawnTemplateCallWithRuntimeContext(
                        spawn_call,
                        &context.state.rng,
                        &context.state,
                        context.world_size,
                    );
                }
                frame.rng_after_stage_spawns = context.state.rng.state;

                const wave_result = spawn_mod.tickSurvivalWaveSpawnsBatch(
                    context.spawn_cooldown,
                    dt_sim_ms,
                    &context.state.rng,
                    context.player_count,
                    elapsed_before_ms,
                    players[0].experience,
                    context.terrain_size,
                    context.terrain_size,
                );
                context.spawn_cooldown = wave_result.cooldown;
                context.wave_spawn_count += wave_result.count;
                context.creatures.spawnInits(wave_result.slice());
                frame.rng_after_wave_spawns = context.state.rng.state;
            }
        },
        .rush => {
            const wave_result = spawn_mod.tickRushModeSpawnsBatch(
                context.spawn_cooldown,
                @floatFromInt(frame.dt_ms_i32),
                &context.state.rng,
                context.player_count,
                elapsed_before_ms,
                context.terrain_size,
                context.terrain_size,
            );
            context.spawn_cooldown = wave_result.cooldown;
            context.wave_spawn_count += wave_result.count;
            context.creatures.spawnInits(wave_result.slice());
            frame.rng_after_stage_spawns = context.state.rng.state;
            frame.rng_after_wave_spawns = context.state.rng.state;
        },
        .quests => {
            context.quest_creatures_none_active = context.creatures.activeCount() == 0;
            const quest_spawns = spawn_mod.tickQuestModeSpawns(
                context.questSpawnEntries(),
                context.quest_spawn_timeline_ms,
                dt_sim_ms,
                @floatFromInt(context.terrain_size),
                context.quest_creatures_none_active,
                context.quest_no_creatures_timer_ms,
            );
            context.quest_spawn_timeline_ms = quest_spawns.quest_spawn_timeline_ms;
            context.quest_creatures_none_active = quest_spawns.creatures_none_active;
            context.quest_no_creatures_timer_ms = quest_spawns.no_creatures_timer_ms;
            context.wave_spawn_count += quest_spawns.spawn_count;
            for (quest_spawns.slice()) |spawn_call| {
                try context.creatures.spawnTemplateCallWithRuntimeContext(
                    spawn_call,
                    &context.state.rng,
                    &context.state,
                    context.world_size,
                );
            }

            const spawn_table_empty_now = spawn_mod.questSpawnTableEmpty(context.questSpawnEntries());
            if (context.quest_creatures_none_active and spawn_table_empty_now) {
                context.state.bonuses.reflex_boost = 0.0;
                context.state.time_scale_active = false;
            }

            // Native quest_mode_update has no player-alive gate on the
            // completion transition: if the timer crosses 2500 ms while the
            // death animation is still playing, the quest completes anyway.
            const quest_completion = spawn_mod.tickQuestCompletionTransition(
                context.quest_completion_transition_ms,
                dt_sim_ms,
                context.quest_creatures_none_active,
                spawn_table_empty_now,
            );
            context.quest_completion_transition_ms = quest_completion.completion_transition_ms;
            context.quest_completed = quest_completion.completed;
            context.quest_play_hit_sfx = quest_completion.play_hit_sfx;
            context.quest_play_completion_music = quest_completion.play_completion_music;

            frame.rng_after_stage_spawns = context.state.rng.state;
            frame.rng_after_wave_spawns = context.state.rng.state;
        },
        .typo => {
            typo_runtime.midStep(
                &context.state,
                players,
                &context.creatures,
                elapsed_before_ms,
                dt_sim_ms,
                context.world_size,
            );
            frame.rng_after_stage_spawns = context.state.rng.state;
            frame.rng_after_wave_spawns = context.state.rng.state;
        },
        else => {},
    }
    frame.rng_after_spawns = context.state.rng.state;
    context.state.highscore_score_xp = if (players.len > 0) players[0].experience else 0;

    callPhaseHook(options.hooks, context, .pre_bonus_effects, &frame);
    const dt_after_player = movement.playerFrameDtAfterRoundtrip(
        narrowF32(frame.dt_sim),
        context.state.time_scale_active,
        context.state.bonuses.reflex_boost,
    );
    cameraShakeUpdate(&context.state, dt_after_player);
    if (context.perk_progression_enabled) {
        _ = survival_progression.survivalProgressionUpdate(&context.state, players);
    }
    context.state.time_scale_active = context.state.bonuses.reflex_boost > 0.0;
    bonus_runtime.updatePrePickupTimers(&context.state, dt_after_player);
    survival_progression.gameplayAccumulateWeaponUsageTime(&context.state, players, frame.dt_sim_ms_i32);
    survival_progression.gameplayEnforceWeaponGuards(&context.state, players);
    try bonus_runtime.bonusUpdate(
        &context.bonuses,
        &context.state,
        players,
        dt_after_player,
        &context.tick_bonus_pickups,
    );
    bonus_runtime.emitBonusPickupEffects(
        &context.state,
        context.tick_bonus_pickups.constSlice(),
        &context.effects,
        context.detail_preset,
    );
    var freeze_pickup_seen = false;
    for (context.tick_bonus_pickups.constSlice()) |pickup| {
        if (pickup.bonus_id == .freeze) {
            freeze_pickup_seen = true;
            break;
        }
    }
    if (freeze_pickup_seen) {
        bonus_runtime.applyFreezePickupCorpseEffects(
            &context.state,
            &context.creatures,
            &context.effects,
            context.detail_preset,
        );
    }
    bonus_runtime.applyPendingBonusEffectsWithEffects(
        &context.state,
        players,
        &context.projectiles,
        &context.creatures,
        &context.bonuses,
        &context.effects,
        &context.terrain_fx,
        dt_after_player,
        context.world_size,
    );
    frame.rng_after_bonus_update = context.state.rng.state;
    if (context.game_mode == .typo) {
        typo_runtime.postStep(&context.state);
    } else if (context.game_mode == .tutorial) {
        try tutorial_runtime.postStep(
            &context.state,
            players,
            &context.creatures,
            &context.bonuses,
            &context.effects,
            frame.dt_sim_ms_i32,
            context.world_size,
            context.detail_preset,
        );
    }
    callPhaseHook(options.hooks, context, .post_bonus_effects, &frame);

    context.creatures.finalizePostRenderLifecycle();
    if (context.game_mode == .rush) {
        context.elapsed_ms_sim_rush += @as(i64, frame.dt_ms_i32);
        context.elapsed_ms_sim = @floatFromInt(context.elapsed_ms_sim_rush);
    } else {
        context.elapsed_ms_sim = elapsed_after_ms;
    }

    if (context.defer_menu_open_events and tick_events.len > 0) {
        callPhaseHook(options.hooks, context, .pre_post_events, &frame);
        for ([_]events.TickEventPhase{
            .post_state_transition,
            .post_spawn_hook,
            .post_menu_open,
        }) |post_phase| {
            frame.post_events_applied += try applyEventsForPhase(
                context,
                tick_events,
                post_phase,
                perk_event_dt,
                &frame.menu_open_seen_this_tick,
            );
        }
        callPhaseHook(options.hooks, context, .post_post_events, &frame);
    }

    context.event_index += tick_events.len;

    const result: StepResult = .{
        .tick_index = tick_index,
        .pre_events_applied = frame.pre_events_applied,
        .post_events_applied = frame.post_events_applied,
        .reload_active_any = frame.reload_active_any,
        .dt_world = frame.dt_world,
        .dt_sim = frame.dt_sim,
        .rng_after_effects = frame.rng_after_effects,
        .rng_after_perk_effects = frame.rng_after_perk_effects,
        .rng_after_creatures = frame.rng_after_creatures,
        .rng_after_projectiles = frame.rng_after_projectiles,
        .rng_after_secondary_projectiles = frame.rng_after_secondary_projectiles,
        .rng_after_particles = frame.rng_after_particles,
        .rng_after_player_update = frame.rng_after_player_update,
        .rng_after_stage_spawns = frame.rng_after_stage_spawns,
        .rng_after_wave_spawns = frame.rng_after_wave_spawns,
        .rng_after_spawns = frame.rng_after_spawns,
        .rng_after_bonus_update = frame.rng_after_bonus_update,
        .projectile_tick_stats = frame.projectile_tick_stats,
        .bonus_pickups = context.tick_bonus_pickups,
        .sfx_events = context.state.sfx_queue.take(),
        .terrain_fx = context.terrain_fx.takeBatch(),
        .rng_end = context.state.rng.state,
        .pending_capture_state_reset = context.pending_capture_state_reset,
    };

    diagnostic_trace.emit(options.trace_sink, .{
        .tick_index = tick_index,
        .dt = frame.dt,
        .dt_world = frame.dt_world,
        .dt_sim = frame.dt_sim,
        .pre_events_applied = frame.pre_events_applied,
        .post_events_applied = frame.post_events_applied,
        .rng_state = context.state.rng.state,
        .rng_after_effects = frame.rng_after_effects,
        .creature_active_count = context.creatures.activeCount(),
        .pending_capture_state_reset = context.pending_capture_state_reset,
    });
    if (options.diagnostic_trace_sink) |diagnostic_trace_sink| {
        diagnostic_trace_sink(buildDiagnosticTrace(context, tick_index, &frame));
    }

    context.tick_index = tick_index + 1;
    callPhaseHook(options.hooks, context, .finalize, &frame);
    return result;
}

fn callPhaseHook(
    hooks: StepHooks,
    context: *SimulationContext,
    phase: TickPhase,
    frame: *const StepFrame,
) void {
    if (hooks.on_phase) |on_phase| {
        on_phase(context, phase, frame);
    }
}

fn emitTimingTrace(
    options: StepOptions,
    sample: diagnostic_trace_mod.ReplayTickTimingSample,
) void {
    if (options.timing_trace_sink) |sink| {
        sink(options.timing_trace_ctx, sample);
    }
}

fn currentTimeScaleFactor(
    reflex_boost_timer: f32,
    time_scale_active: bool,
) f32 {
    if (!time_scale_active) return 1.0;

    return survival_progression.reflexBoostTimeScaleFactor(
        reflex_boost_timer,
        true,
    );
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

    state.camera_shake_timer = if (state.time_scale_active) 0.06 else 0.1;
    const max_amp = state.camera_shake_pulses * 3;
    if (max_amp <= 0) {
        state.camera_shake_offset = .{};
        state.camera_shake_timer = 0.0;
        state.camera_shake_pulses = 0;
        return;
    }

    const max_amp_u32: u32 = @intCast(max_amp);
    var mag_x: i32 = @intCast(state.rng.randTagged(rng_callers.camera_update_offset_x_base) % max_amp_u32);
    mag_x += @intCast(state.rng.randTagged(rng_callers.camera_update_offset_x_spread) % 10);
    if ((state.rng.randTagged(rng_callers.camera_update_offset_x_sign) & 1) == 0) {
        mag_x = -mag_x;
    }

    var mag_y: i32 = @intCast(state.rng.randTagged(rng_callers.camera_update_offset_y_base) % max_amp_u32);
    mag_y += @intCast(state.rng.randTagged(rng_callers.camera_update_offset_y_spread) % 10);
    if ((state.rng.randTagged(rng_callers.camera_update_offset_y_sign) & 1) == 0) {
        mag_y = -mag_y;
    }

    state.camera_shake_offset = .{
        .x = narrowF32(@as(f32, @floatFromInt(mag_x))),
        .y = narrowF32(@as(f32, @floatFromInt(mag_y))),
    };
}

fn applyEventsForPhase(
    context: *SimulationContext,
    tick_events: []const replay_codec.ReplayEvent,
    phase: events.TickEventPhase,
    dt: f32,
    menu_open_seen_this_tick: *bool,
) StepError!usize {
    var applied: usize = 0;
    const players = context.players();

    for (tick_events) |event| {
        if (events.classifyTickEvent(event, context.defer_menu_open_events) != phase) {
            continue;
        }
        const outcome = try events.applyReplayEvent(
            event,
            &context.state,
            players,
            &context.creatures,
            dt,
            &context.quest_spawn_timeline_ms,
            &context.quest_no_creatures_timer_ms,
            &context.quest_completion_transition_ms,
            .{
                .game_mode = context.game_mode,
                .player_count = context.player_count,
                .quest_unlock_index = context.quest_unlock_index,
                .strict_events = context.strict_events,
                .menu_open_seen_this_tick = menu_open_seen_this_tick.*,
            },
        );
        menu_open_seen_this_tick.* = menu_open_seen_this_tick.* or outcome.menu_open_seen_this_tick;
        context.perk_menu_open_count += outcome.perk_menu_open_count_delta;
        context.perk_pick_count += outcome.perk_pick_count_delta;
        if (outcome.signal == .request_capture_state_reset) {
            context.pending_capture_state_reset = true;
        }
        applied += 1;
    }

    return applied;
}

fn buildDiagnosticTrace(
    context: *SimulationContext,
    tick_index: usize,
    frame: *const StepFrame,
) diagnostic_trace_mod.ReplayTickTrace {
    const players = context.players();
    var player0: state_mod.PlayerState = .{
        .index = 0,
        .pos = .{},
    };
    if (players.len > 0) {
        player0 = players[0];
    }

    const trace_elapsed_ms = switch (context.game_mode) {
        .quests => context.quest_spawn_timeline_ms,
        .rush => @as(f32, @floatFromInt(context.elapsed_ms_sim_rush)),
        else => context.elapsed_ms_sim,
    };
    return diagnostic_trace_mod.buildReplayTickTrace(
        tick_index,
        narrowF32(trace_elapsed_ms),
        &context.state,
        player0,
        &.{},
        &context.creatures,
        frame.rng_after_perk_effects,
        frame.rng_after_creatures,
        frame.rng_after_projectiles,
        frame.rng_after_secondary_projectiles,
        frame.rng_after_particles,
        frame.rng_after_player_update,
        frame.rng_after_stage_spawns,
        frame.rng_after_wave_spawns,
        frame.rng_after_spawns,
        frame.rng_after_bonus_update,
        &.{},
        &.{},
    );
}

fn testHeader() replay_codec.ReplayHeader {
    return .{
        .game_mode_id = @intFromEnum(game_ids.GameModeId.survival),
        .seed = 0xD00D,
        .replay_format_version = replay_codec.replay_format_version,
        .quest_level = @constCast("1.1"),
        .game_version = @constCast("test"),
        .tick_rate = 60,
        .quest_fail_retry_count = 0,
        .hardcore = false,
        .preserve_bugs = false,
        .detail_preset = 5,
        .violence_disabled = 0,
        .world_size = 1024.0,
        .player_count = 1,
        .status = .{},
        .claimed_stats = .{},
        .input_quantization = @constCast("f32"),
    };
}

test "camera shake uses latched scaling across bonus expiry and pickup" {
    var context = try session_mod.DeterministicSession.initFromReplayHeader(testHeader(), .{});
    for ([_]bool{ true, false }) |latched| {
        context.state.time_scale_active = latched;
        context.state.bonuses.reflex_boost = if (latched) -0.01 else 1.0;
        context.state.camera_shake_timer = 0.01;
        context.state.camera_shake_pulses = 5;
        cameraShakeUpdate(&context.state, 0.01);
        try std.testing.expectEqual(@as(f32, if (latched) 0.06 else 0.1), context.state.camera_shake_timer);
        try std.testing.expectEqual(@as(i32, 4), context.state.camera_shake_pulses);
    }
}

test "step tick applies counters and emits trace snapshot" {
    const header = testHeader();
    var context = try session_mod.DeterministicSession.initFromReplayHeader(header, .{});

    const before_speed = context.players()[0].move_speed;

    const input: player_runtime.GameInput = .{
        .move_x = 1.0,
        .move_y = 0.0,
        .aim_x = 700.0,
        .aim_y = 512.0,
        .flags = .{
            .fire_down = false,
            .fire_pressed = true,
            .reload_pressed = true,
        },
    };

    const TraceCapture = struct {
        var calls: usize = 0;
        var last_tick_index: usize = 0;

        fn sink(snapshot: diagnostic_trace.TickSnapshot) void {
            calls += 1;
            last_tick_index = snapshot.tick_index;
        }
    };

    TraceCapture.calls = 0;
    const result = try stepTick(
        &context,
        0,
        &[_]player_runtime.GameInput{input},
        &.{},
        context.dt_nominal,
        .{
            .trace_sink = TraceCapture.sink,
        },
    );

    try std.testing.expectEqual(@as(usize, 1), context.tick_index);
    try std.testing.expectEqual(@as(usize, 1), context.fire_pressed_count);
    try std.testing.expectEqual(@as(usize, 1), context.reload_pressed_count);
    try std.testing.expect(result.reload_active_any);
    try std.testing.expect(context.players()[0].move_speed > before_speed);

    try std.testing.expectEqual(@as(usize, 1), TraceCapture.calls);
    try std.testing.expectEqual(@as(usize, 0), TraceCapture.last_tick_index);
}

test "step tick treats held replay reload as active without counting a press" {
    var header = testHeader();
    header.seed = 1;
    header.player_count = 1;
    var context = try session_mod.DeterministicSession.initFromReplayHeader(header, .{});

    const input: player_runtime.GameInput = .{
        .move_x = 0.0,
        .move_y = 0.0,
        .aim_x = 700.0,
        .aim_y = 512.0,
        .flags = .{
            .fire_down = false,
            .fire_pressed = false,
            .reload_pressed = false,
            .reload_down = true,
        },
    };

    const result = try stepTick(
        &context,
        0,
        &[_]player_runtime.GameInput{input},
        &.{},
        context.dt_nominal,
        .{},
    );

    try std.testing.expectEqual(@as(usize, 1), context.tick_index);
    try std.testing.expectEqual(@as(usize, 0), context.reload_pressed_count);
    try std.testing.expect(result.reload_active_any);
}

test "step tick accepts preserve bugs and keeps player zero perk targeting" {
    var header = testHeader();
    header.seed = 1;
    header.player_count = 2;
    header.preserve_bugs = true;

    var context = try session_mod.DeterministicSession.initFromReplayHeader(header, .{});

    context.state.rng.srand(1);

    const players = context.players();
    players[0].health = 90.0;
    players[1].health = 80.0;
    players[0].perk_counts.set(perks.PerkId.regeneration, 1);

    const idle_input: player_runtime.GameInput = .{
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

    _ = try stepTick(
        &context,
        0,
        &[_]player_runtime.GameInput{ idle_input, idle_input },
        &.{},
        0.2,
        .{},
    );

    try std.testing.expectApproxEqAbs(@as(f32, 90.4), players[0].health, 1e-5);
    try std.testing.expectApproxEqAbs(@as(f32, 80.0), players[1].health, 1e-6);
}

test "direct death clock drain does not trigger final revenge" {
    const header = testHeader();
    var context = try session_mod.DeterministicSession.initFromReplayHeader(header, .{});

    const players = context.players();
    players[0].health = 0.1;
    players[0].perk_counts.set(perks.PerkId.death_clock, 1);
    players[0].perk_counts.set(perks.PerkId.final_revenge, 1);

    const result = try stepTick(
        &context,
        0,
        &[_]player_runtime.GameInput{.{}},
        &.{},
        0.05,
        .{},
    );

    try std.testing.expect(players[0].health < 0.0);
    for (result.sfx_events.constSlice()) |sfx_id| {
        try std.testing.expect(sfx_id != .explosion_large);
        try std.testing.expect(sfx_id != .shockwave);
    }
}

test "ammunition within triggers final revenge inline with frame dt" {
    const header = testHeader();
    var context = try session_mod.DeterministicSession.initFromReplayHeader(header, .{});

    const players = context.players();
    players[0].health = 0.1;
    players[0].death_timer = 16.0;
    players[0].experience = 100;
    players[0].weapon.reload_active = true;
    players[0].weapon.reload_timer = 1.0;
    players[0].weapon.reload_timer_max = 1.0;
    players[0].perk_counts.set(perks.PerkId.ammunition_within, 1);
    players[0].perk_counts.set(perks.PerkId.final_revenge, 1);

    const result = try stepTick(
        &context,
        0,
        &[_]player_runtime.GameInput{.{
            .aim_x = 700.0,
            .aim_y = 512.0,
            .flags = .{ .fire_down = true },
        }},
        &.{},
        0.05,
        .{},
    );

    try std.testing.expect(players[0].health < 0.0);
    try std.testing.expectEqual(
        native_math.pc24Sub(16.0, native_math.pc24Mul(0.05, 28.0)),
        players[0].death_timer,
    );
    var saw_explosion = false;
    var saw_shockwave = false;
    for (result.sfx_events.constSlice()) |sfx_id| {
        saw_explosion = saw_explosion or sfx_id == .explosion_large;
        saw_shockwave = saw_shockwave or sfx_id == .shockwave;
    }
    try std.testing.expect(saw_explosion);
    try std.testing.expect(saw_shockwave);
}

test "step tick applies freeze corpse effects when freeze is not last pickup" {
    const header = testHeader();
    var context = try session_mod.DeterministicSession.initFromReplayHeader(header, .{});

    const player_pos = context.players()[0].pos;
    context.creatures.entries[0] = .{
        .active = true,
        .type_id = 0,
        .pos = player_pos,
        .hp = 0.0,
        .max_hp = 10.0,
        .size = 48.0,
        .lifecycle_stage = 0.0,
    };
    context.bonuses.entries[0] = .{
        .bonus_id = .freeze,
        .picked = false,
        .time_left = 5.0,
        .time_max = 5.0,
        .pos = player_pos,
        .amount = 5,
    };
    context.bonuses.entries[1] = .{
        .bonus_id = .points,
        .picked = false,
        .time_left = 5.0,
        .time_max = 5.0,
        .pos = player_pos,
        .amount = 100,
    };

    const result = try stepTick(
        &context,
        0,
        &[_]player_runtime.GameInput{.{}},
        &.{},
        context.dt_nominal,
        .{},
    );

    try std.testing.expectEqual(@as(usize, 2), result.bonus_pickups.len);
    try std.testing.expect(!context.creatures.entries[0].active);

    var freeze_fx_count: usize = 0;
    for (context.effects.entries) |entry| {
        if (entry.flags == 0) continue;
        if (entry.effect_id == @intFromEnum(effects_mod.EffectId.freeze_shatter) or
            entry.effect_id == @intFromEnum(effects_mod.EffectId.freeze_shard_0) or
            entry.effect_id == @intFromEnum(effects_mod.EffectId.freeze_shard_1) or
            entry.effect_id == @intFromEnum(effects_mod.EffectId.freeze_shard_2))
        {
            freeze_fx_count += 1;
        }
    }
    try std.testing.expect(freeze_fx_count > 0);
}

test "weapon guard runs before same-frame locked splitter pickup" {
    const header = testHeader();
    var context = try session_mod.DeterministicSession.initFromReplayHeader(header, .{});

    const players = context.players();
    player_runtime.weaponAssignPlayer(&players[0], .pistol);
    context.state.status_quest_unlock_index_full = 0;
    context.bonuses.entries[0] = .{
        .bonus_id = .weapon,
        .picked = false,
        .time_left = 5.0,
        .time_max = 5.0,
        .pos = players[0].pos,
        .amount = @intFromEnum(game_ids.WeaponId.splitter_gun),
    };

    const pickup_tick = try stepTick(
        &context,
        0,
        &[_]player_runtime.GameInput{.{}},
        &.{},
        context.dt_nominal,
        .{},
    );

    try std.testing.expectEqual(@as(usize, 1), pickup_tick.bonus_pickups.len);
    try std.testing.expectEqual(game_ids.WeaponId.splitter_gun, players[0].weapon.weapon_id);

    _ = try stepTick(
        &context,
        1,
        &[_]player_runtime.GameInput{.{}},
        &.{},
        context.dt_nominal,
        .{},
    );

    try std.testing.expectEqual(game_ids.WeaponId.pistol, players[0].weapon.weapon_id);
}

test "weapon usage time precedes same-frame weapon pickup" {
    const header = testHeader();
    var context = try session_mod.DeterministicSession.initFromReplayHeader(header, .{});

    const players = context.players();
    player_runtime.weaponAssignPlayer(&players[0], .pistol);
    context.bonuses.entries[0] = .{
        .bonus_id = .weapon,
        .picked = false,
        .time_left = 5.0,
        .time_max = 5.0,
        .pos = players[0].pos,
        .amount = @intFromEnum(game_ids.WeaponId.assault_rifle),
    };

    const pickup_tick = try stepTick(
        &context,
        0,
        &[_]player_runtime.GameInput{.{}},
        &.{},
        context.dt_nominal,
        .{},
    );

    try std.testing.expectEqual(@as(usize, 1), pickup_tick.bonus_pickups.len);
    try std.testing.expectEqual(game_ids.WeaponId.assault_rifle, players[0].weapon.weapon_id);
    try std.testing.expectEqual(@as(u32, 16), context.state.weapon_usage_time[@intFromEnum(game_ids.WeaponId.pistol)]);
    try std.testing.expectEqual(@as(u32, 0), context.state.weapon_usage_time[@intFromEnum(game_ids.WeaponId.assault_rifle)]);

    _ = try stepTick(
        &context,
        1,
        &[_]player_runtime.GameInput{.{}},
        &.{},
        context.dt_nominal,
        .{},
    );

    try std.testing.expectEqual(@as(u32, 16), context.state.weapon_usage_time[@intFromEnum(game_ids.WeaponId.pistol)]);
    try std.testing.expectEqual(@as(u32, 16), context.state.weapon_usage_time[@intFromEnum(game_ids.WeaponId.assault_rifle)]);
}

test "highscore score stages before same-frame points pickup" {
    const header = testHeader();
    var context = try session_mod.DeterministicSession.initFromReplayHeader(header, .{});

    const players = context.players();
    players[0].experience = 10;
    context.bonuses.entries[0] = .{
        .bonus_id = .points,
        .picked = false,
        .time_left = 5.0,
        .time_max = 5.0,
        .pos = players[0].pos,
        .amount = 500,
    };

    const pickup_tick = try stepTick(
        &context,
        0,
        &[_]player_runtime.GameInput{.{}},
        &.{},
        context.dt_nominal,
        .{},
    );

    try std.testing.expectEqual(@as(usize, 1), pickup_tick.bonus_pickups.len);
    try std.testing.expectEqual(@as(i32, 10), context.state.highscore_score_xp);
    try std.testing.expectEqual(@as(i32, 510), players[0].experience);

    _ = try stepTick(
        &context,
        1,
        &[_]player_runtime.GameInput{.{}},
        &.{},
        context.dt_nominal,
        .{},
    );

    try std.testing.expectEqual(@as(i32, 510), context.state.highscore_score_xp);
}
