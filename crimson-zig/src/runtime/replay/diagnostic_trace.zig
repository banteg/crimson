const creatures_mod = @import("../creatures.zig");
const state_mod = @import("../state.zig");

pub const replay_tick_trace_schema_version: i32 = 6;
pub const replay_tick_trace_msgpack_magic = "crimson_replay_tick_trace_msgpack_v3\n";

pub const ReplayTickTiming = struct {
    elapsed_ms: i64,
};

pub const ReplayTickRng = struct {
    rng_state: u32,
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
};

pub const ReplayTickSummary = struct {
    score_xp: i32,
    kills: i32,
    shots_fired_p0: i32,
    creature_count: usize,
    perk_pending: i32,
};

pub const ReplayTickTrace = struct {
    schema_version: i32 = replay_tick_trace_schema_version,
    tick_index: usize,
    timing: ReplayTickTiming,
    rng: ReplayTickRng,
    summary: ReplayTickSummary,
    gameplay_state: state_mod.GameplayState,
    player_state: state_mod.PlayerState,
};

pub fn buildReplayTickTrace(
    tick_index: usize,
    elapsed_ms_sim: f32,
    state: *const state_mod.GameplayState,
    player: state_mod.PlayerState,
    creatures: *const creatures_mod.CreaturePool,
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
    return .{
        .schema_version = replay_tick_trace_schema_version,
        .tick_index = tick_index,
        .timing = .{
            .elapsed_ms = @intFromFloat(@round(elapsed_ms_sim)),
        },
        .rng = .{
            .rng_state = state.rng.state,
            .rng_after_perk_effects = rng_after_perk_effects,
            .rng_after_creatures = rng_after_creatures,
            .rng_after_projectiles = rng_after_projectiles,
            .rng_after_secondary_projectiles = rng_after_secondary_projectiles,
            .rng_after_particles = rng_after_particles,
            .rng_after_player_update = rng_after_player_update,
            .rng_after_stage_spawns = rng_after_stage_spawns,
            .rng_after_wave_spawns = rng_after_wave_spawns,
            .rng_after_spawns = rng_after_spawns,
            .rng_after_bonus_update = rng_after_bonus_update,
        },
        .summary = .{
            .score_xp = player.experience,
            .kills = creatures.kill_count,
            .shots_fired_p0 = if (state.shots_fired.len > 0) state.shots_fired[0] else 0,
            .creature_count = creatures.activeCount(),
            .perk_pending = state.perk_selection.pending_count,
        },
        .gameplay_state = state.*,
        .player_state = player,
    };
}
