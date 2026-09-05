const std = @import("std");
const native_math = @import("native_math.zig");
const rng_callers = @import("../rng_caller_static.zig");

const crt_rand_mult: u32 = 214_013;
const crt_rand_inc: u32 = 2_531_011;

const narrowF32 = native_math.roundF32;
const RngCaller = rng_callers.Caller;
const rush_tint_sin_scale: f32 = @bitCast(@as(u32, 0x38D1B718));

pub const CreatureTypeId = enum(i32) {
    zombie = 0,
    lizard = 1,
    alien = 2,
    spider_sp1 = 3,
    spider_sp2 = 4,
    trooper = 5,
};

pub const CreatureAiMode = enum(i32) {
    orbit_player = 0,
    orbit_player_tight = 1,
    chase_player = 2,
    follow_link = 3,
    link_guard = 4,
    follow_link_tethered = 5,
    orbit_link = 6,
    hold_timer = 7,
    orbit_player_wide = 8,
    _,
};

pub const CreatureFlags = struct {
    pub const self_damage_tick: u32 = 0x01;
    pub const self_damage_tick_strong: u32 = 0x02;
    pub const anim_ping_pong: u32 = 0x04;
    pub const split_on_death: u32 = 0x08;
    pub const ranged_attack_shock: u32 = 0x10;
    pub const anim_long_strip: u32 = 0x40;
    pub const ai7_link_timer: u32 = 0x80;
    pub const ranged_attack_variant: u32 = 0x100;
    pub const bonus_on_death: u32 = 0x400;
};

/// Semantic names are provenance-backed against the remake creature data; see
/// docs/creatures/spawning.md. Numeric suffixes preserve the native Windows ids.
pub const SpawnId = enum(i32) {
    zombie_boss_spawner_00 = 0x00,
    spider_sp2_splitter_01 = 0x01,
    spider_sp1_random_03 = 0x03,
    lizard_random_04 = 0x04,
    spider_sp2_random_05 = 0x05,
    alien_random_06 = 0x06,
    den_alien_basic_07 = 0x07,
    den_alien_basic_slower_08 = 0x08,
    den_alien_weak_small_09 = 0x09,
    den_spider_basic_0a = 0x0A,
    den_spider_plasma_shooters_0b = 0x0B,
    den_lizard_weak_0c = 0x0C,
    den_lizard_weak_slower_0d = 0x0D,
    alien_spawner_ring_24_0e = 0x0E,
    alien_ghost_0f = 0x0F,
    den_spider_weak_10 = 0x10,
    formation_chain_lizard_4_11 = 0x11,
    formation_ring_alien_8_12 = 0x12,
    formation_chain_alien_10_13 = 0x13,
    formation_grid_alien_green_14 = 0x14,
    formation_grid_alien_white_15 = 0x15,
    formation_grid_lizard_white_16 = 0x16,
    formation_grid_spider_sp1_white_17 = 0x17,
    formation_grid_alien_bronze_18 = 0x18,
    formation_ring_alien_5_19 = 0x19,
    ai1_alien_blue_tint_1a = 0x1A,
    ai1_spider_sp1_blue_tint_1b = 0x1B,
    ai1_lizard_blue_tint_1c = 0x1C,
    alien_random_1d = 0x1D,
    alien_random_1e = 0x1E,
    alien_random_1f = 0x1F,
    alien_random_green_20 = 0x20,
    alien_hidden_1_21 = 0x21,
    alien_hidden_2_22 = 0x22,
    alien_hidden_3_23 = 0x23,
    alien_const_green_24 = 0x24,
    alien_small_green_man_25 = 0x25,
    alien_small_gray_26 = 0x26,
    alien_bonus_carrier_27 = 0x27,
    alien_const_purple_28 = 0x28,
    alien_big_gray_29 = 0x29,
    alien_const_grey_fast_2a = 0x2A,
    alien_deadly_fast_2b = 0x2B,
    alien_const_red_boss_2c = 0x2C,
    alien_const_cyan_ai2_2d = 0x2D,
    lizard_random_2e = 0x2E,
    lizard_const_grey_2f = 0x2F,
    lizard_const_yellow_boss_30 = 0x30,
    lizard_random_31 = 0x31,
    spider_sp1_random_32 = 0x32,
    spider_sp1_random_red_33 = 0x33,
    spider_sp1_random_green_34 = 0x34,
    spider_sp2_random_35 = 0x35,
    alien_ai7_orbiter_36 = 0x36,
    spider_sp2_ranged_variant_37 = 0x37,
    spider_sp1_ai7_timer_38 = 0x38,
    spider_sp1_ai7_timer_weak_39 = 0x39,
    spider_boss_3a = 0x3A,
    spider_sp1_const_red_boss_3b = 0x3B,
    spider_plasma_shooter_3c = 0x3C,
    spider_sp1_random_3d = 0x3D,
    spider_sp1_const_white_fast_3e = 0x3E,
    spider_sp1_const_brown_small_3f = 0x3F,
    spider_small_blue_40 = 0x40,
    zombie_random_41 = 0x41,
    zombie_small_white_42 = 0x42,
    zombie_const_green_brute_43 = 0x43,
};

pub const Vec2 = struct {
    x: f32,
    y: f32,
};

pub const Crand = struct {
    pub const Caller = RngCaller;
    pub const TraceDraw = struct {
        state_before: u32,
        state_after: u32,
        value_15: u32,
        caller: ?Caller,
    };

    pub const TraceSink = *const fn (ctx: ?*anyopaque, draw: TraceDraw) void;

    state: u32 = 0,
    trace_ctx: ?*anyopaque = null,
    trace_sink: ?TraceSink = null,
    trace_require_caller: bool = false,
    missing_trace_caller: bool = false,

    pub fn init(seed: u32) Crand {
        return .{ .state = seed };
    }

    pub fn srand(self: *Crand, seed: u32) void {
        self.state = seed;
    }

    pub fn setTraceSink(self: *Crand, ctx: ?*anyopaque, sink: ?TraceSink, require_caller: bool) void {
        self.trace_ctx = ctx;
        self.trace_sink = sink;
        self.trace_require_caller = require_caller;
        self.missing_trace_caller = false;
    }

    pub fn msgpackWrite(self: Crand, packer: anytype) !void {
        try packer.writeMapHeader(1);
        try packer.writeString("state");
        try packer.writeInt(self.state);
    }

    pub fn rand(self: *Crand) u32 {
        return self.draw(null);
    }

    fn draw(self: *Crand, caller: ?Caller) u32 {
        const state_before = self.state;
        self.state = self.state *% crt_rand_mult +% crt_rand_inc;
        const value = (self.state >> 16) & 0x7fff;
        if (self.trace_sink) |sink| {
            if (self.trace_require_caller and caller == null) {
                self.missing_trace_caller = true;
            }
            sink(self.trace_ctx, .{
                .state_before = state_before,
                .state_after = self.state,
                .value_15 = value,
                .caller = caller,
            });
        }
        return value;
    }

    pub fn randTagged(self: *Crand, caller: Caller) u32 {
        return self.draw(caller);
    }

    pub fn consumeMissingTraceCaller(self: *Crand) bool {
        const missing = self.missing_trace_caller;
        self.missing_trace_caller = false;
        return missing;
    }
};

const SurvivalSpawnPosCallers = struct {
    edge: RngCaller,
    top_x: RngCaller,
    bottom_x: RngCaller,
    left_y: RngCaller,
    right_y: RngCaller,
};

const survival_spawn_pos_callers_extra: SurvivalSpawnPosCallers = .{
    .edge = rng_callers.survival_update_extra_spawn_edge,
    .top_x = rng_callers.survival_update_extra_spawn_top_x,
    .bottom_x = rng_callers.survival_update_extra_spawn_bottom_x,
    .left_y = rng_callers.survival_update_extra_spawn_left_y,
    .right_y = rng_callers.survival_update_extra_spawn_right_y,
};

const survival_spawn_pos_callers_main: SurvivalSpawnPosCallers = .{
    .edge = rng_callers.survival_update_main_spawn_edge,
    .top_x = rng_callers.survival_update_main_spawn_top_x,
    .bottom_x = rng_callers.survival_update_main_spawn_bottom_x,
    .left_y = rng_callers.survival_update_main_spawn_left_y,
    .right_y = rng_callers.survival_update_main_spawn_right_y,
};

pub const CreatureInit = struct {
    origin_template_id: i32 = -1,
    pos: Vec2,
    heading: f32 = 0.0,
    set_heading: bool = true,
    phase_seed: i32 = 0,
    preserve_force_target: bool = false,
    preserve_max_health: bool = false,
    type_id: CreatureTypeId = .alien,
    ai_mode: CreatureAiMode = .orbit_player,
    flags: u32 = 0,
    size: f32 = 0.0,
    move_speed: f32 = 0.0,
    health: f32 = 0.0,
    max_health: f32 = 0.0,
    reward_value: f32 = 0.0,
    contact_damage: f32 = 0.0,
    tint: [4]f32 = .{ 1.0, 1.0, 1.0, 1.0 },
};

pub const WaveSpawnResult = struct {
    cooldown: f32,
    spawns: []CreatureInit,

    pub fn deinit(self: WaveSpawnResult, allocator: std.mem.Allocator) void {
        allocator.free(self.spawns);
    }
};

pub const WaveSpawnCountResult = struct {
    cooldown: f32,
    spawn_count: usize,
};

pub const max_wave_spawn_batch: usize = 128;

const empty_creature_init: CreatureInit = .{
    .pos = .{ .x = 0.0, .y = 0.0 },
};

pub const WaveSpawnBatchResult = struct {
    cooldown: f32,
    count: usize,
    spawns: [max_wave_spawn_batch]CreatureInit = [_]CreatureInit{empty_creature_init} ** max_wave_spawn_batch,

    pub fn slice(self: *const WaveSpawnBatchResult) []const CreatureInit {
        return self.spawns[0..self.count];
    }
};

pub const SpawnTemplateCall = struct {
    template_id: i32,
    pos: Vec2,
    heading: f32,
};

pub const SpawnSlotInit = struct {
    owner_creature: i32,
    timer: f32,
    count: i32,
    limit: i32,
    interval: f32,
    child_template_id: i32,
};

pub const QuestSpawnEntry = struct {
    pos: Vec2,
    heading: f32,
    spawn_id: SpawnId,
    trigger_ms: i32,
    count: i32,
};

pub const max_quest_spawn_batch: usize = 1024;

const empty_spawn_template_call: SpawnTemplateCall = .{
    .template_id = 0,
    .pos = .{ .x = 0.0, .y = 0.0 },
    .heading = 0.0,
};

pub const QuestSpawnTimelineResult = struct {
    creatures_none_active: bool,
    no_creatures_timer_ms: f32,
    spawn_count: usize = 0,
    spawns: [max_quest_spawn_batch]SpawnTemplateCall = [_]SpawnTemplateCall{empty_spawn_template_call} ** max_quest_spawn_batch,

    pub fn slice(self: *const QuestSpawnTimelineResult) []const SpawnTemplateCall {
        return self.spawns[0..self.spawn_count];
    }
};

pub const QuestModeSpawnsResult = struct {
    quest_spawn_timeline_ms: f32,
    creatures_none_active: bool,
    no_creatures_timer_ms: f32,
    spawn_count: usize = 0,
    spawns: [max_quest_spawn_batch]SpawnTemplateCall = [_]SpawnTemplateCall{empty_spawn_template_call} ** max_quest_spawn_batch,

    pub fn slice(self: *const QuestModeSpawnsResult) []const SpawnTemplateCall {
        return self.spawns[0..self.spawn_count];
    }
};

pub const QuestCompletionTransitionResult = struct {
    completion_transition_ms: f32,
    completed: bool,
    play_hit_sfx: bool,
    play_completion_music: bool,
};

pub const quest_completion_hit_sfx_start_ms: f32 = 800.0;
pub const quest_completion_hit_sfx_end_ms: f32 = 0x353;
pub const quest_completion_music_start_ms: f32 = 2000.0;
pub const quest_completion_music_end_ms: f32 = 0x803;
pub const quest_completion_transition_ms: f32 = 0x9C4;

pub fn tickSpawnSlot(slot: *SpawnSlotInit, frame_dt: f32) ?i32 {
    const dt = frame_dt;

    slot.timer = narrowF32(slot.timer - dt);
    if (slot.timer < 0.0) {
        slot.timer = narrowF32(slot.timer + slot.interval);
        if (slot.count < slot.limit) {
            slot.count += 1;
            return slot.child_template_id;
        }
    }
    return null;
}

pub fn questSpawnTableEmpty(entries: []const QuestSpawnEntry) bool {
    for (entries) |entry| {
        if (entry.count > 0) return false;
    }
    return true;
}

pub fn applyHardcoreQuestSpawnTableAdjustment(entries: []QuestSpawnEntry) void {
    for (entries) |*entry| {
        if (entry.count <= 1) continue;
        if (entry.spawn_id == .spider_plasma_shooter_3c) continue;
        if (entry.spawn_id == .alien_deadly_fast_2b) {
            entry.count += 2;
        } else {
            entry.count += 8;
        }
    }
}

pub fn tickQuestSpawnTimeline(
    entries: []QuestSpawnEntry,
    quest_spawn_timeline_ms: f32,
    frame_dt_ms: f32,
    terrain_width: f32,
    creatures_none_active: bool,
    no_creatures_timer_ms: f32,
) QuestSpawnTimelineResult {
    var result: QuestSpawnTimelineResult = .{
        .creatures_none_active = creatures_none_active,
        .no_creatures_timer_ms = no_creatures_timer_ms,
    };

    if (!result.creatures_none_active) {
        result.no_creatures_timer_ms = 0.0;
    } else {
        result.no_creatures_timer_ms += frame_dt_ms;
    }

    const force_spawn = result.creatures_none_active and
        result.no_creatures_timer_ms > 3000.0 and
        quest_spawn_timeline_ms > 0x6A4;

    var start_idx: ?usize = null;
    for (entries, 0..) |entry, idx| {
        if (entry.count <= 0) continue;
        if (@as(f32, @floatFromInt(entry.trigger_ms)) < quest_spawn_timeline_ms or force_spawn) {
            start_idx = idx;
            break;
        }
    }

    if (start_idx == null) {
        return result;
    }

    const trigger_ms = entries[start_idx.?].trigger_ms;
    for (entries[start_idx.?..], start_idx.?..) |entry, idx| {
        if (entry.trigger_ms != trigger_ms) break;

        const entry_x = entry.pos.x;
        const offscreen_x = entry_x < 0.0 or terrain_width < entry_x;
        for (0..@as(usize, @intCast(@max(entry.count, 0)))) |spawn_idx| {
            if (result.spawn_count >= result.spawns.len) break;
            const magnitude = @as(f32, @floatFromInt(spawn_idx * 0x28));
            const offset = if ((spawn_idx & 1) == 0) magnitude else -magnitude;
            var pos = entry.pos;
            if (offscreen_x) {
                pos.y += offset;
            } else {
                pos.x += offset;
            }
            result.spawns[result.spawn_count] = .{
                .template_id = @intFromEnum(entry.spawn_id),
                .pos = pos,
                .heading = entry.heading,
            };
            result.spawn_count += 1;
        }

        if (entries[idx].count != 0) {
            entries[idx].count = 0;
        }
    }

    result.creatures_none_active = false;
    return result;
}

pub fn tickQuestModeSpawns(
    entries: []QuestSpawnEntry,
    quest_spawn_timeline_ms: f32,
    frame_dt_ms: f32,
    terrain_width: f32,
    creatures_none_active: bool,
    no_creatures_timer_ms: f32,
) QuestModeSpawnsResult {
    var timeline_ms = quest_spawn_timeline_ms;
    if (!creatures_none_active or !questSpawnTableEmpty(entries)) {
        timeline_ms += frame_dt_ms;
    }

    const timeline_result = tickQuestSpawnTimeline(
        entries,
        timeline_ms,
        frame_dt_ms,
        terrain_width,
        creatures_none_active,
        no_creatures_timer_ms,
    );
    var result: QuestModeSpawnsResult = .{
        .quest_spawn_timeline_ms = timeline_ms,
        .creatures_none_active = timeline_result.creatures_none_active,
        .no_creatures_timer_ms = timeline_result.no_creatures_timer_ms,
        .spawn_count = timeline_result.spawn_count,
    };
    if (timeline_result.spawn_count > 0) {
        @memcpy(result.spawns[0..timeline_result.spawn_count], timeline_result.slice());
    }
    return result;
}

pub fn tickQuestCompletionTransition(
    completion_transition_ms_value: f32,
    frame_dt_ms: f32,
    creatures_none_active: bool,
    spawn_table_empty: bool,
) QuestCompletionTransitionResult {
    if (creatures_none_active and spawn_table_empty) {
        if (completion_transition_ms_value < 0.0) {
            return .{
                .completion_transition_ms = frame_dt_ms,
                .completed = false,
                .play_hit_sfx = false,
                .play_completion_music = false,
            };
        }
        if (completion_transition_ms_value > quest_completion_hit_sfx_start_ms and
            completion_transition_ms_value < quest_completion_hit_sfx_end_ms)
        {
            return .{
                .completion_transition_ms = quest_completion_hit_sfx_end_ms + frame_dt_ms,
                .completed = false,
                .play_hit_sfx = true,
                .play_completion_music = false,
            };
        }
        if (completion_transition_ms_value > quest_completion_music_start_ms and
            completion_transition_ms_value < quest_completion_music_end_ms)
        {
            return .{
                .completion_transition_ms = quest_completion_music_end_ms + frame_dt_ms,
                .completed = false,
                .play_hit_sfx = false,
                .play_completion_music = true,
            };
        }
        return .{
            .completion_transition_ms = completion_transition_ms_value + frame_dt_ms,
            .completed = completion_transition_ms_value > quest_completion_transition_ms,
            .play_hit_sfx = false,
            .play_completion_music = false,
        };
    }
    return .{
        .completion_transition_ms = -1.0,
        .completed = false,
        .play_hit_sfx = false,
        .play_completion_music = false,
    };
}

pub const SpawnStageResult = struct {
    stage: i32,
    count: usize = 0,
    calls: [32]SpawnTemplateCall = [_]SpawnTemplateCall{.{
        .template_id = 0,
        .pos = .{ .x = 0.0, .y = 0.0 },
        .heading = 0.0,
    }} ** 32,

    pub fn slice(self: *const SpawnStageResult) []const SpawnTemplateCall {
        return self.calls[0..self.count];
    }
};

pub fn buildSurvivalSpawnCreature(
    pos: Vec2,
    rng: *Crand,
    player_experience: i32,
) CreatureInit {
    const xp: i32 = player_experience;

    var creature = allocCreature(-1, pos, rng);
    creature.ai_mode = CreatureAiMode.orbit_player;

    const r10 = @as(i32, @intCast(rng.randTagged(rng_callers.survival_spawn_creature_type_roll) % 10));

    var type_id: CreatureTypeId = .zombie;
    if (xp < 12_000) {
        type_id = if (r10 < 9) .alien else .spider_sp1;
    } else if (xp < 25_000) {
        type_id = if (r10 < 4) .zombie else .spider_sp1;
        if (8 < r10) type_id = .alien;
    } else if (xp < 42_000) {
        if (r10 < 5) {
            type_id = .alien;
        } else {
            type_id = if ((rng.randTagged(rng_callers.survival_spawn_creature_parity_pick) & 1) == 0) .spider_sp1 else .spider_sp2;
        }
    } else if (xp < 50_000) {
        type_id = .alien;
    } else if (xp < 90_000) {
        type_id = .spider_sp2;
    } else {
        if (109_999 < xp) {
            if (r10 < 6) {
                type_id = .alien;
            } else if (r10 < 9) {
                type_id = .spider_sp2;
            } else {
                type_id = .zombie;
            }
        } else {
            type_id = .zombie;
        }
    }

    if ((rng.randTagged(rng_callers.survival_spawn_creature_rare_override) & 0x1f) == 2) {
        type_id = .spider_sp1;
    }
    creature.type_id = type_id;

    const size = @as(f32, @floatFromInt(rng.randTagged(rng_callers.survival_spawn_creature_size) % 20 + 44));
    creature.size = size;
    {
        const heading_base: f32 = @floatFromInt(rng.randTagged(rng_callers.survival_spawn_creature_heading) % 314);
        const heading_scaled: f32 = heading_base * 0.01;
        creature.heading = heading_scaled;
    }

    const move_speed_xp: f32 = @floatFromInt(@divTrunc(xp, 4000));
    const move_speed_scaled = @as(f32, move_speed_xp * @as(f32, 0.045));
    var move_speed = narrowF32(move_speed_scaled + 0.9);
    if (creature.type_id == .spider_sp1) {
        creature.flags |= CreatureFlags.ai7_link_timer;
        move_speed = @as(f32, move_speed * @as(f32, 1.3));
    }

    const r_health = rng.randTagged(rng_callers.survival_spawn_creature_health);
    const health_xp: f32 = @floatFromInt(xp);
    const health_scaled = @as(f32, health_xp * @as(f32, 0.00125));
    const health_rand = @as(f32, @floatFromInt(r_health & 0xF));
    var health = narrowF32(health_scaled + health_rand + 52.0);

    if (creature.type_id == .zombie) {
        move_speed = @as(f32, move_speed * @as(f32, 0.6));
        if (move_speed < @as(f32, 1.3)) move_speed = 1.3;
        health = @as(f32, health * @as(f32, 1.5));
    }

    if (move_speed > @as(f32, 3.5)) move_speed = 3.5;

    creature.move_speed = move_speed;
    creature.health = health;
    creature.reward_value = 0.0;

    const tint_a: f32 = 1.0;
    var tint_r: f32 = 0.0;
    var tint_g: f32 = 0.0;
    var tint_b: f32 = 0.0;
    if (xp < 50_000) {
        const xp_1000: f32 = @floatFromInt(@divTrunc(xp, 1000));
        const xp_10k: f32 = @floatFromInt(@divTrunc(xp, 10_000));
        const rand_g: f32 = @floatFromInt(rng.randTagged(rng_callers.survival_spawn_creature_low_tint_g) % 10);
        const rand_b: f32 = @floatFromInt(rng.randTagged(rng_callers.survival_spawn_creature_low_tint_b) % 10);
        tint_r = narrowF32(1.0 - 1.0 / narrowF32(xp_1000 + 10.0));
        tint_g = narrowF32(rand_g * 0.01 + 0.9 - 1.0 / narrowF32(xp_10k + 10.0));
        tint_b = narrowF32(rand_b * 0.01 + 0.7);
    } else if (xp < 100_000) {
        const xp_1000: f32 = @floatFromInt(@divTrunc(xp, 1000));
        const xp_10k: f32 = @floatFromInt(@divTrunc(xp, 10_000));
        const xp_delta_50k: f32 = @floatFromInt(xp - 50_000);
        const rand_g: f32 = @floatFromInt(rng.randTagged(rng_callers.survival_spawn_creature_mid_tint_g) % 10);
        const rand_b: f32 = @floatFromInt(rng.randTagged(rng_callers.survival_spawn_creature_mid_tint_b) % 10);
        tint_r = narrowF32(0.9 - 1.0 / narrowF32(xp_1000 + 10.0));
        tint_g = narrowF32(rand_g * 0.01 + 0.8 - 1.0 / narrowF32(xp_10k + 10.0));
        tint_b = narrowF32(xp_delta_50k * 6e-06 + rand_b * 0.01 + 0.7);
    } else {
        const xp_1000: f32 = @floatFromInt(@divTrunc(xp, 1000));
        const xp_10k: f32 = @floatFromInt(@divTrunc(xp, 10_000));
        const xp_delta_100k: f32 = @floatFromInt(xp - 100_000);
        const rand_g: f32 = @floatFromInt(rng.randTagged(rng_callers.survival_spawn_creature_high_tint_g) % 10);
        const rand_b: f32 = @floatFromInt(rng.randTagged(rng_callers.survival_spawn_creature_high_tint_b) % 10);
        tint_r = narrowF32(1.0 - 1.0 / narrowF32(xp_1000 + 10.0));
        tint_g = narrowF32(rand_g * 0.01 + 0.9 - 1.0 / narrowF32(xp_10k + 10.0));
        tint_b = narrowF32(rand_b * 0.01 + 1.0 - xp_delta_100k * 3e-06);
        if (tint_b < 0.5) tint_b = 0.5;
    }
    creature.tint = .{
        tint_r,
        tint_g,
        tint_b,
        tint_a,
    };

    const contact_damage = native_math.pc24Mul(size, @as(f32, 0.0952381));
    creature.contact_damage = contact_damage;
    var reward_value = native_math.pc24Add(
        @as(f32, @floatFromInt(rng.randTagged(rng_callers.survival_spawn_creature_reward_bonus) % 10 + 10)),
        native_math.pc24Mul(move_speed, @as(f32, 5.0)),
    );
    reward_value = native_math.pc24Add(
        reward_value,
        native_math.pc24Mul(contact_damage, @as(f32, 0.8)),
    );
    reward_value = native_math.pc24Add(
        reward_value,
        native_math.pc24Mul(health, @as(f32, 0.4)),
    );
    creature.reward_value = reward_value;

    var r = rng.randTagged(rng_callers.survival_spawn_creature_rare_red);
    if ((r % 180) < 2) {
        applyTint(&creature, .{ 0.9, 0.4, 0.4, 1.0 });
        creature.health = 65.0;
        creature.reward_value = 320.0;
    } else {
        r = rng.randTagged(rng_callers.survival_spawn_creature_rare_green);
        if ((r % 240) < 2) {
            applyTint(&creature, .{ 0.4, 0.9, 0.4, 1.0 });
            creature.health = 85.0;
            creature.reward_value = 420.0;
        } else {
            r = rng.randTagged(rng_callers.survival_spawn_creature_rare_blue);
            if ((r % 360) < 2) {
                applyTint(&creature, .{ 0.4, 0.4, 0.9, 1.0 });
                creature.health = 125.0;
                creature.reward_value = 520.0;
            }
        }
    }

    r = rng.randTagged(rng_callers.survival_spawn_creature_rare_purple);
    if ((r % 1320) < 4) {
        applyTint(&creature, .{ 0.84, 0.24, 0.89, 1.0 });
        creature.size = 80.0;
        creature.reward_value = 600.0;
        creature.health += 230.0;
    } else {
        r = rng.randTagged(rng_callers.survival_spawn_creature_rare_yellow);
        if ((r % 1620) < 4) {
            applyTint(&creature, .{ 0.94, 0.84, 0.29, 1.0 });
            creature.size = 85.0;
            creature.reward_value = 900.0;
            creature.health += 2230.0;
        }
    }

    creature.max_health = creature.health;
    creature.reward_value = native_math.pc24Mul(creature.reward_value, @as(f32, 0.8));
    creature.tint = .{
        clamp01(creature.tint[0]),
        clamp01(creature.tint[1]),
        clamp01(creature.tint[2]),
        clamp01(creature.tint[3]),
    };

    return creature;
}

fn randSurvivalSpawnPos(
    rng: *Crand,
    terrain_width: i32,
    terrain_height: i32,
    callers: SurvivalSpawnPosCallers,
) Vec2 {
    const width: u32 = @intCast(@max(1, terrain_width));
    const height: u32 = @intCast(@max(1, terrain_height));

    return switch (rng.randTagged(callers.edge) & 3) {
        0 => .{ .x = @floatFromInt(rng.randTagged(callers.top_x) % width), .y = -40.0 },
        1 => .{
            .x = @floatFromInt(rng.randTagged(callers.bottom_x) % width),
            .y = @as(f32, @floatFromInt(terrain_height)) + 40.0,
        },
        2 => .{ .x = -40.0, .y = @floatFromInt(rng.randTagged(callers.left_y) % height) },
        else => .{
            .x = @as(f32, @floatFromInt(terrain_width)) + 40.0,
            .y = @floatFromInt(rng.randTagged(callers.right_y) % height),
        },
    };
}

pub fn buildRushModeSpawnCreature(
    pos: Vec2,
    tint_rgba: [4]f32,
    rng: *Crand,
    type_id: CreatureTypeId,
    survival_elapsed_ms: i32,
) CreatureInit {
    const elapsed_ms = survival_elapsed_ms;

    var creature = allocCreature(-1, pos, rng);
    creature.type_id = type_id;
    creature.ai_mode = CreatureAiMode.orbit_player;

    const elapsed_f32: f32 = @floatFromInt(elapsed_ms);
    creature.health = narrowF32(elapsed_f32 * 1e-4 + 10.0);
    {
        const heading_base: f32 = @floatFromInt(rng.randTagged(rng_callers.creature_spawn_heading) % 314);
        const heading_scaled: f32 = heading_base * 0.01;
        creature.heading = heading_scaled;
    }
    creature.move_speed = narrowF32(elapsed_f32 * native_math.native_creature_spawn_elapsed_scale + 2.5);
    creature.reward_value = @floatFromInt(rng.randTagged(rng_callers.creature_spawn_reward) % 30 + 140);

    creature.tint = .{
        tint_rgba[0],
        tint_rgba[1],
        tint_rgba[2],
        tint_rgba[3],
    };
    creature.contact_damage = 4.0;
    creature.max_health = creature.health;
    creature.size = narrowF32(elapsed_f32 * native_math.native_creature_spawn_elapsed_scale + 47.0);

    return creature;
}

pub fn tickRushModeSpawns(
    allocator: std.mem.Allocator,
    spawn_cooldown: f32,
    frame_dt_ms: f32,
    rng: *Crand,
    player_count: i32,
    survival_elapsed_ms: f32,
    terrain_width: i32,
    terrain_height: i32,
) !WaveSpawnResult {
    const result = tickRushModeSpawnsBatch(
        spawn_cooldown,
        frame_dt_ms,
        rng,
        player_count,
        survival_elapsed_ms,
        terrain_width,
        terrain_height,
    );
    var spawns: std.ArrayList(CreatureInit) = .empty;
    defer spawns.deinit(allocator);
    try spawns.appendSlice(allocator, result.slice());
    return .{
        .cooldown = result.cooldown,
        .spawns = try spawns.toOwnedSlice(allocator),
    };
}

pub fn tickRushModeSpawnsBatch(
    spawn_cooldown: f32,
    frame_dt_ms: f32,
    rng: *Crand,
    player_count: i32,
    survival_elapsed_ms: f32,
    terrain_width: i32,
    terrain_height: i32,
) WaveSpawnBatchResult {
    var result: WaveSpawnBatchResult = .{
        .cooldown = spawn_cooldown - @as(f32, @floatFromInt(player_count)) * frame_dt_ms,
        .count = 0,
    };

    while (result.cooldown < 0.0) {
        result.cooldown += 250.0;

        const t_i32: i32 = @intFromFloat(survival_elapsed_ms + 1.0);
        const t: f32 = @floatFromInt(t_i32);
        const tint = [4]f32{
            // Native 0x407336..0x407366: separate PC=24 arithmetic and f32 constants.
            clamp01(native_math.pc24Add(native_math.pc24Mul(t, @as(f32, 1.0 / 120000.0)), @as(f32, 0.3))),
            clamp01(native_math.pc24Add(native_math.pc24Mul(t, @as(f32, 10000.0)), @as(f32, 0.3))),
            clamp01(native_math.pc24Add(std.math.sin(@as(f64, native_math.pc24Mul(t, rush_tint_sin_scale))), @as(f32, 0.3))),
            1.0,
        };

        const elapsed_ms: i32 = @intFromFloat(survival_elapsed_ms);
        const theta = @as(f32, @floatFromInt(elapsed_ms)) * 0.001;
        const terrain_width_f: f32 = @floatFromInt(terrain_width);
        const terrain_height_f: f32 = @floatFromInt(terrain_height);
        const spawn_right: Vec2 = .{
            .x = narrowF32(terrain_width_f + 64.0),
            .y = narrowF32(terrain_height_f * 0.5 + std.math.cos(theta) * 256.0),
        };
        const spawn_left: Vec2 = .{
            .x = -64.0,
            .y = narrowF32(terrain_height_f * 0.5 + std.math.sin(theta) * 256.0),
        };

        var alien = buildRushModeSpawnCreature(
            spawn_right,
            tint,
            rng,
            .alien,
            elapsed_ms,
        );
        alien.ai_mode = CreatureAiMode.orbit_player_wide;
        if (result.count < result.spawns.len) {
            result.spawns[result.count] = alien;
            result.count += 1;
        }

        var spider = buildRushModeSpawnCreature(
            spawn_left,
            tint,
            rng,
            .spider_sp1,
            elapsed_ms,
        );
        spider.ai_mode = CreatureAiMode.orbit_player_wide;
        spider.flags |= CreatureFlags.ai7_link_timer;
        spider.move_speed *= 1.4;
        if (result.count < result.spawns.len) {
            result.spawns[result.count] = spider;
            result.count += 1;
        }
    }

    return result;
}

pub fn tickSurvivalWaveSpawns(
    allocator: std.mem.Allocator,
    spawn_cooldown: f32,
    frame_dt_ms: f32,
    rng: *Crand,
    player_count: i32,
    survival_elapsed_ms: f32,
    player_experience: i32,
    terrain_width: i32,
    terrain_height: i32,
) !WaveSpawnResult {
    var cooldown = spawn_cooldown - @as(f32, @floatFromInt(player_count)) * frame_dt_ms;

    var spawns: std.ArrayList(CreatureInit) = .empty;
    defer spawns.deinit(allocator);

    if (cooldown >= 0.0) {
        return .{
            .cooldown = cooldown,
            .spawns = try spawns.toOwnedSlice(allocator),
        };
    }

    while (cooldown < 0.0) {
        var interval_ms: i32 = 500 - @divTrunc(@as(i32, @intFromFloat(survival_elapsed_ms)), 1800);
        if (interval_ms < 0) {
            const extra: i32 = @divTrunc(1 - interval_ms, 2);
            interval_ms += extra * 2;
            for (0..@as(usize, @intCast(extra))) |_| {
                const pos = randSurvivalSpawnPos(rng, terrain_width, terrain_height, survival_spawn_pos_callers_extra);
                try spawns.append(allocator, buildSurvivalSpawnCreature(pos, rng, player_experience));
            }
        }

        if (interval_ms < 1) interval_ms = 1;
        cooldown += @floatFromInt(interval_ms);

        const pos = randSurvivalSpawnPos(rng, terrain_width, terrain_height, survival_spawn_pos_callers_main);
        try spawns.append(allocator, buildSurvivalSpawnCreature(pos, rng, player_experience));
    }

    return .{
        .cooldown = cooldown,
        .spawns = try spawns.toOwnedSlice(allocator),
    };
}

pub fn tickSurvivalWaveSpawnsCount(
    spawn_cooldown: f32,
    frame_dt_ms: f32,
    rng: *Crand,
    player_count: i32,
    survival_elapsed_ms: f32,
    player_experience: i32,
    terrain_width: i32,
    terrain_height: i32,
) WaveSpawnCountResult {
    var cooldown = spawn_cooldown - @as(f32, @floatFromInt(player_count)) * frame_dt_ms;
    var count: usize = 0;

    if (cooldown >= 0.0) {
        return .{
            .cooldown = cooldown,
            .spawn_count = count,
        };
    }

    while (cooldown < 0.0) {
        var interval_ms: i32 = 500 - @divTrunc(@as(i32, @intFromFloat(survival_elapsed_ms)), 1800);
        if (interval_ms < 0) {
            const extra: i32 = @divTrunc(1 - interval_ms, 2);
            interval_ms += extra * 2;
            for (0..@as(usize, @intCast(extra))) |_| {
                const pos = randSurvivalSpawnPos(rng, terrain_width, terrain_height, survival_spawn_pos_callers_extra);
                _ = buildSurvivalSpawnCreature(pos, rng, player_experience);
                count += 1;
            }
        }

        if (interval_ms < 1) interval_ms = 1;
        cooldown += @floatFromInt(interval_ms);

        const pos = randSurvivalSpawnPos(rng, terrain_width, terrain_height, survival_spawn_pos_callers_main);
        _ = buildSurvivalSpawnCreature(pos, rng, player_experience);
        count += 1;
    }

    return .{
        .cooldown = cooldown,
        .spawn_count = count,
    };
}

pub fn tickSurvivalWaveSpawnsBatch(
    spawn_cooldown: f32,
    frame_dt_ms: f32,
    rng: *Crand,
    player_count: i32,
    survival_elapsed_ms: f32,
    player_experience: i32,
    terrain_width: i32,
    terrain_height: i32,
) WaveSpawnBatchResult {
    var result: WaveSpawnBatchResult = .{
        .cooldown = spawn_cooldown - @as(f32, @floatFromInt(player_count)) * frame_dt_ms,
        .count = 0,
    };

    if (result.cooldown >= 0.0) {
        return result;
    }

    while (result.cooldown < 0.0) {
        var interval_ms: i32 = 500 - @divTrunc(@as(i32, @intFromFloat(survival_elapsed_ms)), 1800);
        if (interval_ms < 0) {
            const extra: i32 = @divTrunc(1 - interval_ms, 2);
            interval_ms += extra * 2;
            for (0..@as(usize, @intCast(extra))) |_| {
                const pos = randSurvivalSpawnPos(rng, terrain_width, terrain_height, survival_spawn_pos_callers_extra);
                const spawn = buildSurvivalSpawnCreature(pos, rng, player_experience);
                if (result.count < result.spawns.len) {
                    result.spawns[result.count] = spawn;
                    result.count += 1;
                }
            }
        }

        if (interval_ms < 1) interval_ms = 1;
        result.cooldown += @floatFromInt(interval_ms);

        const pos = randSurvivalSpawnPos(rng, terrain_width, terrain_height, survival_spawn_pos_callers_main);
        const spawn = buildSurvivalSpawnCreature(pos, rng, player_experience);
        if (result.count < result.spawns.len) {
            result.spawns[result.count] = spawn;
            result.count += 1;
        }
    }

    return result;
}

pub fn advanceSurvivalSpawnStage(
    stage_in: i32,
    player_level: i32,
) SpawnStageResult {
    var result: SpawnStageResult = .{
        .stage = stage_in,
    };
    var stage = stage_in;
    const heading = std.math.pi;
    const level = player_level;

    while (true) {
        if (stage == 0) {
            if (level < 5) break;
            stage = 1;
            appendSpawnCall(&result, SpawnId.formation_ring_alien_8_12, -164.0, 512.0, heading);
            appendSpawnCall(&result, SpawnId.formation_ring_alien_8_12, 1188.0, 512.0, heading);
            continue;
        }
        if (stage == 1) {
            if (level < 9) break;
            stage = 2;
            appendSpawnCall(&result, SpawnId.alien_const_red_boss_2c, 1088.0, 512.0, heading);
            continue;
        }
        if (stage == 2) {
            if (level < 11) break;
            stage = 3;
            const step: f32 = 42.666668;
            for (0..12) |idx| {
                appendSpawnCall(
                    &result,
                    SpawnId.spider_sp2_random_35,
                    1088.0,
                    @as(f32, @floatFromInt(idx)) * step + 256.0,
                    heading,
                );
            }
            continue;
        }
        if (stage == 3) {
            if (level < 13) break;
            stage = 4;
            for (0..4) |idx| {
                appendSpawnCall(
                    &result,
                    SpawnId.alien_deadly_fast_2b,
                    1088.0,
                    @as(f32, @floatFromInt(idx)) * 64.0 + 384.0,
                    heading,
                );
            }
            continue;
        }
        if (stage == 4) {
            if (level < 15) break;
            stage = 5;
            for (0..4) |idx| {
                appendSpawnCall(
                    &result,
                    SpawnId.spider_sp1_ai7_timer_38,
                    1088.0,
                    @as(f32, @floatFromInt(idx)) * 64.0 + 384.0,
                    heading,
                );
            }
            for (0..4) |idx| {
                appendSpawnCall(
                    &result,
                    SpawnId.spider_sp1_ai7_timer_38,
                    -64.0,
                    @as(f32, @floatFromInt(idx)) * 64.0 + 384.0,
                    heading,
                );
            }
            continue;
        }
        if (stage == 5) {
            if (level < 17) break;
            stage = 6;
            appendSpawnCall(&result, SpawnId.spider_boss_3a, 1088.0, 512.0, heading);
            continue;
        }
        if (stage == 6) {
            if (level < 19) break;
            stage = 7;
            appendSpawnCall(&result, SpawnId.spider_sp2_splitter_01, 640.0, 512.0, heading);
            continue;
        }
        if (stage == 7) {
            if (level < 21) break;
            stage = 8;
            appendSpawnCall(&result, SpawnId.spider_sp2_splitter_01, 384.0, 256.0, heading);
            appendSpawnCall(&result, SpawnId.spider_sp2_splitter_01, 640.0, 768.0, heading);
            continue;
        }
        if (stage == 8) {
            if (level < 26) break;
            stage = 9;
            for (0..4) |idx| {
                appendSpawnCall(
                    &result,
                    SpawnId.spider_plasma_shooter_3c,
                    1088.0,
                    @as(f32, @floatFromInt(idx)) * 64.0 + 384.0,
                    heading,
                );
            }
            for (0..4) |idx| {
                appendSpawnCall(
                    &result,
                    SpawnId.spider_plasma_shooter_3c,
                    -64.0,
                    @as(f32, @floatFromInt(idx)) * 64.0 + 384.0,
                    heading,
                );
            }
            continue;
        }
        if (stage == 9) {
            if (level <= 31) break;
            stage = 10;
            appendSpawnCall(&result, SpawnId.spider_boss_3a, 1088.0, 512.0, heading);
            appendSpawnCall(&result, SpawnId.spider_boss_3a, -64.0, 512.0, heading);
            for (0..4) |idx| {
                appendSpawnCall(
                    &result,
                    SpawnId.spider_plasma_shooter_3c,
                    @as(f32, @floatFromInt(idx)) * 64.0 + 384.0,
                    -64.0,
                    heading,
                );
            }
            for (0..4) |idx| {
                appendSpawnCall(
                    &result,
                    SpawnId.spider_plasma_shooter_3c,
                    @as(f32, @floatFromInt(idx)) * 64.0 + 384.0,
                    1088.0,
                    heading,
                );
            }
            continue;
        }
        break;
    }

    result.stage = stage;
    return result;
}

fn allocCreature(template_id: i32, pos: Vec2, rng: *Crand) CreatureInit {
    const phase_seed: i32 = @intCast(rng.randTagged(rng_callers.creature_alloc_slot_phase_seed) & 0x17f);
    return .{
        .origin_template_id = template_id,
        .pos = pos,
        .phase_seed = phase_seed,
    };
}

fn clamp01(value: f32) f32 {
    if (value < 0.0) return 0.0;
    if (value > 1.0) return 1.0;
    return value;
}

fn applyTint(creature: *CreatureInit, tint: [4]f32) void {
    creature.tint = .{
        tint[0],
        tint[1],
        tint[2],
        tint[3],
    };
}

fn appendSpawnCall(
    result: *SpawnStageResult,
    template_id: SpawnId,
    x: f32,
    y: f32,
    heading: f32,
) void {
    std.debug.assert(result.count < result.calls.len);
    result.calls[result.count] = .{
        .template_id = @intFromEnum(template_id),
        .pos = .{
            .x = x,
            .y = y,
        },
        .heading = heading,
    };
    result.count += 1;
}

fn expectFloatClose(expected: f32, actual: anytype) !void {
    try std.testing.expectApproxEqAbs(expected, @as(f32, @floatCast(actual)), 1e-6);
}

test "spawn slot tick behavior parity" {
    const cases = [_]struct {
        timer: f32,
        count: i32,
        dt: f32,
        expected_spawn: ?i32,
        expected_count: i32,
    }{
        .{ .timer = 1.0, .count = 0, .dt = 0.3, .expected_spawn = null, .expected_count = 0 },
        .{ .timer = 0.1, .count = 0, .dt = 0.3, .expected_spawn = 0x41, .expected_count = 1 },
        .{ .timer = 0.1, .count = 10, .dt = 0.3, .expected_spawn = null, .expected_count = 10 },
        .{ .timer = 0.1, .count = 0, .dt = 2.0, .expected_spawn = 0x41, .expected_count = 1 },
    };

    for (cases) |case| {
        var slot: SpawnSlotInit = .{
            .owner_creature = 0,
            .timer = narrowF32(case.timer),
            .count = case.count,
            .limit = 10,
            .interval = 0.7,
            .child_template_id = 0x41,
        };

        const spawned = tickSpawnSlot(&slot, case.dt);
        try std.testing.expectEqual(case.expected_spawn, spawned);

        var expected_timer = narrowF32(narrowF32(case.timer) - narrowF32(case.dt));
        if (expected_timer < 0.0) {
            expected_timer = narrowF32(expected_timer + narrowF32(slot.interval));
        }
        try expectFloatClose(expected_timer, slot.timer);
        try std.testing.expectEqual(case.expected_count, slot.count);
    }
}

test "spawn slot tick uses float32 cadence at boundary" {
    var slot: SpawnSlotInit = .{
        .owner_creature = 0,
        .timer = 2.4,
        .count = 0,
        .limit = 10,
        .interval = 2.4,
        .child_template_id = 0x41,
    };

    var spawn_ticks = [_]i32{0} ** 8;
    var spawn_count: usize = 0;

    for (1..26) |tick| {
        if (tickSpawnSlot(&slot, 0.1) != null) {
            spawn_ticks[spawn_count] = @intCast(tick);
            spawn_count += 1;
        }
    }

    try std.testing.expectEqual(@as(usize, 1), spawn_count);
    try std.testing.expectEqual(@as(i32, 25), spawn_ticks[0]);
}

test "tick quest mode spawns advances timeline when creatures active" {
    var entries: [0]QuestSpawnEntry = .{};
    const result = tickQuestModeSpawns(
        entries[0..],
        1000.0,
        16.0,
        1024.0,
        false,
        123.0,
    );

    try expectFloatClose(1016.0, result.quest_spawn_timeline_ms);
    try std.testing.expect(!result.creatures_none_active);
    try expectFloatClose(0.0, result.no_creatures_timer_ms);
    try std.testing.expectEqual(@as(usize, 0), result.spawn_count);
}

test "hardcore quest spawn table adjustment parity" {
    var entries = [_]QuestSpawnEntry{
        .{
            .pos = .{ .x = 0.0, .y = 0.0 },
            .heading = 0.0,
            .spawn_id = SpawnId.alien_deadly_fast_2b,
            .trigger_ms = 0,
            .count = 2,
        },
        .{
            .pos = .{ .x = 0.0, .y = 0.0 },
            .heading = 0.0,
            .spawn_id = SpawnId.spider_plasma_shooter_3c,
            .trigger_ms = 0,
            .count = 2,
        },
        .{
            .pos = .{ .x = 0.0, .y = 0.0 },
            .heading = 0.0,
            .spawn_id = .alien_small_gray_26,
            .trigger_ms = 0,
            .count = 1,
        },
    };

    applyHardcoreQuestSpawnTableAdjustment(entries[0..]);
    try std.testing.expectEqual(@as(i32, 4), entries[0].count);
    try std.testing.expectEqual(@as(i32, 2), entries[1].count);
    try std.testing.expectEqual(@as(i32, 1), entries[2].count);
}

test "tick quest mode spawns advances timeline when table not empty" {
    var entries = [_]QuestSpawnEntry{
        .{
            .pos = .{ .x = 512.0, .y = 512.0 },
            .heading = 0.0,
            .spawn_id = SpawnId.formation_ring_alien_8_12,
            .trigger_ms = 10_000,
            .count = 1,
        },
    };
    const result = tickQuestModeSpawns(
        entries[0..],
        1000.0,
        16.0,
        1024.0,
        true,
        0.0,
    );

    try expectFloatClose(1016.0, result.quest_spawn_timeline_ms);
    try std.testing.expect(result.creatures_none_active);
    try expectFloatClose(16.0, result.no_creatures_timer_ms);
    try std.testing.expectEqual(@as(i32, 1), entries[0].count);
    try std.testing.expectEqual(@as(usize, 0), result.spawn_count);
}

test "tick quest mode spawns freezes timeline when idle complete" {
    var entries: [0]QuestSpawnEntry = .{};
    const result = tickQuestModeSpawns(
        entries[0..],
        1000.0,
        16.0,
        1024.0,
        true,
        0.0,
    );

    try expectFloatClose(1000.0, result.quest_spawn_timeline_ms);
    try std.testing.expect(result.creatures_none_active);
    try expectFloatClose(16.0, result.no_creatures_timer_ms);
    try std.testing.expectEqual(@as(usize, 0), result.spawn_count);
}

test "tick quest mode spawns can fire entries after timeline advance" {
    var entries = [_]QuestSpawnEntry{
        .{
            .pos = .{ .x = 512.0, .y = 512.0 },
            .heading = 0.25,
            .spawn_id = SpawnId.formation_ring_alien_8_12,
            .trigger_ms = 1000,
            .count = 1,
        },
    };
    const result = tickQuestModeSpawns(
        entries[0..],
        999.0,
        2.0,
        1024.0,
        true,
        0.0,
    );

    try expectFloatClose(1001.0, result.quest_spawn_timeline_ms);
    try std.testing.expectEqual(@as(i32, 0), entries[0].count);
    try std.testing.expect(!result.creatures_none_active);
    try expectFloatClose(2.0, result.no_creatures_timer_ms);
    try std.testing.expectEqual(@as(usize, 1), result.spawn_count);
    try std.testing.expectEqual(@intFromEnum(SpawnId.formation_ring_alien_8_12), result.spawns[0].template_id);
}

test "tick quest completion transition resets when not idle complete" {
    const result = tickQuestCompletionTransition(
        500.0,
        16.0,
        false,
        true,
    );
    try expectFloatClose(-1.0, result.completion_transition_ms);
    try std.testing.expect(!result.completed);
    try std.testing.expect(!result.play_hit_sfx);
    try std.testing.expect(!result.play_completion_music);
}

test "tick quest completion transition completes after delay" {
    var timer: f32 = -1.0;
    for (0..26) |_| {
        const result = tickQuestCompletionTransition(
            timer,
            100.0,
            true,
            true,
        );
        timer = result.completion_transition_ms;
        try std.testing.expect(!result.completed);
    }

    try expectFloatClose(quest_completion_transition_ms + 100.0, timer);

    const result = tickQuestCompletionTransition(
        timer,
        100.0,
        true,
        true,
    );
    try expectFloatClose(quest_completion_transition_ms + 200.0, result.completion_transition_ms);
    try std.testing.expect(result.completed);
}

test "tick quest completion transition triggers hit sfx in native window" {
    const result = tickQuestCompletionTransition(
        801.0,
        16.0,
        true,
        true,
    );
    try expectFloatClose(851.0 + 16.0, result.completion_transition_ms);
    try std.testing.expect(!result.completed);
    try std.testing.expect(result.play_hit_sfx);
    try std.testing.expect(!result.play_completion_music);
}

test "tick quest completion transition triggers completion music in native window" {
    const result = tickQuestCompletionTransition(
        2001.0,
        16.0,
        true,
        true,
    );
    try expectFloatClose(2051.0 + 16.0, result.completion_transition_ms);
    try std.testing.expect(!result.completed);
    try std.testing.expect(!result.play_hit_sfx);
    try std.testing.expect(result.play_completion_music);
}

test "tick quest spawn timeline no trigger resets idle timer when creatures active" {
    var entries = [_]QuestSpawnEntry{
        .{
            .pos = .{ .x = 512.0, .y = 512.0 },
            .heading = 0.0,
            .spawn_id = SpawnId.formation_ring_alien_8_12,
            .trigger_ms = 1000,
            .count = 1,
        },
    };
    const result = tickQuestSpawnTimeline(
        entries[0..],
        0.0,
        16.0,
        1024.0,
        false,
        123.0,
    );

    try std.testing.expect(!result.creatures_none_active);
    try expectFloatClose(0.0, result.no_creatures_timer_ms);
    try std.testing.expectEqual(@as(i32, 1), entries[0].count);
    try std.testing.expectEqual(@as(usize, 0), result.spawn_count);
}

test "tick quest spawn timeline triggers horizontal spread when on screen" {
    var entries = [_]QuestSpawnEntry{
        .{
            .pos = .{ .x = 512.0, .y = 512.0 },
            .heading = 1.25,
            .spawn_id = SpawnId.formation_ring_alien_8_12,
            .trigger_ms = 1000,
            .count = 3,
        },
    };
    const result = tickQuestSpawnTimeline(
        entries[0..],
        1001.0,
        16.0,
        1024.0,
        true,
        0.0,
    );

    try std.testing.expectEqual(@as(i32, 0), entries[0].count);
    try std.testing.expect(!result.creatures_none_active);
    try expectFloatClose(16.0, result.no_creatures_timer_ms);
    try std.testing.expectEqual(@as(usize, 3), result.spawn_count);
    const expected = [_][2]f32{
        .{ 512.0, 512.0 },
        .{ 472.0, 512.0 },
        .{ 592.0, 512.0 },
    };
    for (result.slice(), expected) |spawn, expected_pos| {
        try expectFloatClose(expected_pos[0], spawn.pos.x);
        try expectFloatClose(expected_pos[1], spawn.pos.y);
        try expectFloatClose(1.25, spawn.heading);
    }
}

test "tick quest spawn timeline triggers vertical spread when offscreen x" {
    var entries = [_]QuestSpawnEntry{
        .{
            .pos = .{ .x = -50.0, .y = 512.0 },
            .heading = 0.25,
            .spawn_id = SpawnId.formation_ring_alien_8_12,
            .trigger_ms = 1000,
            .count = 3,
        },
    };
    const result = tickQuestSpawnTimeline(
        entries[0..],
        1001.0,
        0.0,
        1024.0,
        true,
        0.0,
    );

    const expected = [_][2]f32{
        .{ -50.0, 512.0 },
        .{ -50.0, 472.0 },
        .{ -50.0, 592.0 },
    };
    for (result.slice(), expected) |spawn, expected_pos| {
        try expectFloatClose(expected_pos[0], spawn.pos.x);
        try expectFloatClose(expected_pos[1], spawn.pos.y);
    }
}

test "tick quest spawn timeline fires only one trigger group per tick" {
    var entries = [_]QuestSpawnEntry{
        .{
            .pos = .{ .x = 512.0, .y = 512.0 },
            .heading = 0.0,
            .spawn_id = SpawnId.formation_ring_alien_8_12,
            .trigger_ms = 500,
            .count = 1,
        },
        .{
            .pos = .{ .x = 512.0, .y = 512.0 },
            .heading = 0.0,
            .spawn_id = SpawnId.alien_deadly_fast_2b,
            .trigger_ms = 500,
            .count = 1,
        },
        .{
            .pos = .{ .x = 512.0, .y = 512.0 },
            .heading = 0.0,
            .spawn_id = SpawnId.spider_boss_3a,
            .trigger_ms = 600,
            .count = 1,
        },
    };
    const result = tickQuestSpawnTimeline(
        entries[0..],
        10_000.0,
        0.0,
        1024.0,
        true,
        0.0,
    );

    try std.testing.expectEqual(@as(i32, 0), entries[0].count);
    try std.testing.expectEqual(@as(i32, 0), entries[1].count);
    try std.testing.expectEqual(@as(i32, 1), entries[2].count);
    try std.testing.expectEqual(@as(usize, 2), result.spawn_count);
    try std.testing.expectEqual(@intFromEnum(SpawnId.formation_ring_alien_8_12), result.spawns[0].template_id);
    try std.testing.expectEqual(@intFromEnum(SpawnId.alien_deadly_fast_2b), result.spawns[1].template_id);
}

test "tick quest spawn timeline force fires after idle timeout" {
    var entries = [_]QuestSpawnEntry{
        .{
            .pos = .{ .x = 512.0, .y = 512.0 },
            .heading = 0.0,
            .spawn_id = SpawnId.formation_ring_alien_8_12,
            .trigger_ms = 999_999,
            .count = 1,
        },
    };
    const result = tickQuestSpawnTimeline(
        entries[0..],
        2000.0,
        0.0,
        1024.0,
        true,
        3001.0,
    );

    try std.testing.expectEqual(@as(i32, 0), entries[0].count);
    try std.testing.expect(!result.creatures_none_active);
    try expectFloatClose(3001.0, result.no_creatures_timer_ms);
    try std.testing.expectEqual(@as(usize, 1), result.spawn_count);
}

test "survival wave no trigger" {
    var rng = Crand.init(123);
    const allocator = std.testing.allocator;
    const out = try tickSurvivalWaveSpawns(
        allocator,
        100.0,
        16.0,
        &rng,
        2,
        0.0,
        0,
        1024,
        1024,
    );
    defer out.deinit(allocator);

    try expectFloatClose(68.0, out.cooldown);
    try std.testing.expectEqual(@as(usize, 0), out.spawns.len);
    try std.testing.expectEqual(@as(u32, 123), rng.state);
}

test "survival wave single spawn" {
    var rng = Crand.init(1);
    const allocator = std.testing.allocator;
    const out = try tickSurvivalWaveSpawns(
        allocator,
        -1.0,
        0.0,
        &rng,
        1,
        0.0,
        0,
        1024,
        1024,
    );
    defer out.deinit(allocator);

    try expectFloatClose(499.0, out.cooldown);
    try std.testing.expectEqual(@as(usize, 1), out.spawns.len);
    const creature = out.spawns[0];
    try expectFloatClose(35.0, creature.pos.x);
    try expectFloatClose(1064.0, creature.pos.y);
    try std.testing.expect(creature.type_id == .alien);
    try expectFloatClose(85.0, creature.health);
    try expectFloatClose(336.0, creature.reward_value);
    try std.testing.expectEqual(@as(u32, 0xA6E9C9A6), rng.state);
}

test "survival wave extra spawns on negative interval" {
    var rng = Crand.init(1);
    const allocator = std.testing.allocator;
    const out = try tickSurvivalWaveSpawns(
        allocator,
        -1.0,
        0.0,
        &rng,
        1,
        905_400.0,
        0,
        1024,
        1024,
    );
    defer out.deinit(allocator);

    try expectFloatClose(0.0, out.cooldown);
    try std.testing.expectEqual(@as(usize, 3), out.spawns.len);
    const expected_pos = [_][2]f32{
        .{ 35.0, 1064.0 },
        .{ 1064.0, 947.0 },
        .{ -40.0, 435.0 },
    };
    for (out.spawns, expected_pos) |spawn, expected| {
        try expectFloatClose(expected[0], spawn.pos.x);
        try expectFloatClose(expected[1], spawn.pos.y);
    }
    try std.testing.expect(out.spawns[0].type_id == .alien);
    try std.testing.expect(out.spawns[1].type_id == .alien);
    try std.testing.expect(out.spawns[2].type_id == .spider_sp1);
    try std.testing.expectEqual(@as(u32, 0xBB25E9C6), rng.state);
}

test "rush wave no trigger" {
    var rng = Crand.init(1);
    const allocator = std.testing.allocator;
    const out = try tickRushModeSpawns(
        allocator,
        100.0,
        16.0,
        &rng,
        1,
        0.0,
        1024,
        1024,
    );
    defer out.deinit(allocator);

    try expectFloatClose(84.0, out.cooldown);
    try std.testing.expectEqual(@as(usize, 0), out.spawns.len);
    try std.testing.expectEqual(@as(u32, 1), rng.state);
}

test "rush spawn uses exact native elapsed scale" {
    var speed_rng = Crand.init(1);
    const speed = buildRushModeSpawnCreature(.{ .x = 0.0, .y = 0.0 }, .{ 1.0, 1.0, 1.0, 1.0 }, &speed_rng, .alien, 237);
    try std.testing.expectEqual(@as(u32, 0x402026D5), @as(u32, @bitCast(speed.move_speed)));

    var size_rng = Crand.init(1);
    const size = buildRushModeSpawnCreature(.{ .x = 0.0, .y = 0.0 }, .{ 1.0, 1.0, 1.0, 1.0 }, &size_rng, .alien, 2458);
    try std.testing.expectEqual(@as(u32, 0x423C192C), @as(u32, @bitCast(size.size)));
}

test "rush wave triggers two creatures" {
    var rng = Crand.init(1);
    const allocator = std.testing.allocator;
    const out = try tickRushModeSpawns(
        allocator,
        -1.0,
        0.0,
        &rng,
        1,
        0.0,
        1024,
        1024,
    );
    defer out.deinit(allocator);

    try expectFloatClose(249.0, out.cooldown);
    try std.testing.expectEqual(@as(usize, 2), out.spawns.len);

    const alien = out.spawns[0];
    const spider = out.spawns[1];
    const expected_tint_r = 0.3 + (1.0 / 120000.0);
    const expected_tint_g = 1.0;
    const expected_tint_b = 0.3 + std.math.sin(1e-4);

    try std.testing.expect(alien.type_id == .alien);
    try std.testing.expectEqual(CreatureAiMode.orbit_player_wide, alien.ai_mode);
    try std.testing.expectEqual(@as(u32, 0), alien.flags);
    try expectFloatClose(1088.0, alien.pos.x);
    try expectFloatClose(768.0, alien.pos.y);
    try expectFloatClose(10.0, alien.health);
    try expectFloatClose(10.0, alien.max_health);
    try expectFloatClose(2.5, alien.move_speed);
    try expectFloatClose(144.0, alien.reward_value);
    try expectFloatClose(47.0, alien.size);
    try expectFloatClose(expected_tint_r, alien.tint[0]);
    try expectFloatClose(expected_tint_g, alien.tint[1]);
    try expectFloatClose(expected_tint_b, alien.tint[2]);
    try expectFloatClose(1.0, alien.tint[3]);

    try std.testing.expect(spider.type_id == .spider_sp1);
    try std.testing.expectEqual(CreatureAiMode.orbit_player_wide, spider.ai_mode);
    try std.testing.expect((spider.flags & CreatureFlags.ai7_link_timer) != 0);
    try expectFloatClose(-64.0, spider.pos.x);
    try expectFloatClose(512.0, spider.pos.y);
    try expectFloatClose(10.0, spider.health);
    try expectFloatClose(10.0, spider.max_health);
    try expectFloatClose(3.5, spider.move_speed);
    try expectFloatClose(144.0, spider.reward_value);
    try expectFloatClose(47.0, spider.size);
    try expectFloatClose(expected_tint_r, spider.tint[0]);
    try expectFloatClose(expected_tint_g, spider.tint[1]);
    try expectFloatClose(expected_tint_b, spider.tint[2]);
    try expectFloatClose(1.0, spider.tint[3]);

    try std.testing.expectEqual(@as(u32, 0x3D6C1037), rng.state);
}

test "rush tint uses native upward-rounded sine scale" {
    var rng = Crand.init(1);
    const allocator = std.testing.allocator;
    const out = try tickRushModeSpawns(
        allocator,
        -1.0,
        0.0,
        &rng,
        1,
        63.0,
        1024,
        1024,
    );
    defer out.deinit(allocator);

    try std.testing.expectEqual(@as(u32, 0x3E9CE075), @as(u32, @bitCast(out.spawns[0].tint[2])));
}

test "rush wave loops when cooldown is very negative" {
    var rng = Crand.init(1);
    const allocator = std.testing.allocator;
    const out = try tickRushModeSpawns(
        allocator,
        -501.0,
        0.0,
        &rng,
        1,
        0.0,
        1024,
        1024,
    );
    defer out.deinit(allocator);

    try expectFloatClose(249.0, out.cooldown);
    try std.testing.expectEqual(@as(usize, 6), out.spawns.len);
    const expected_types = [_]CreatureTypeId{
        .alien,
        .spider_sp1,
        .alien,
        .spider_sp1,
        .alien,
        .spider_sp1,
    };
    for (out.spawns, expected_types) |spawn, expected| {
        try std.testing.expect(spawn.type_id == expected);
    }
    try std.testing.expectEqual(@as(u32, 0xAEA69ED3), rng.state);
}

test "survival spawn baseline seed1 xp0" {
    var rng = Crand.init(1);
    const creature = buildSurvivalSpawnCreature(.{ .x = 1.0, .y = 2.0 }, &rng, 0);

    try std.testing.expect(creature.type_id == .alien);
    try std.testing.expectEqual(@as(u32, 0), creature.flags);
    try std.testing.expectEqual(CreatureAiMode.orbit_player, creature.ai_mode);
    try expectFloatClose(44.0, creature.size);
    try expectFloatClose(@floatCast(@as(f32, @as(f32, 15.0) * @as(f32, 0.01))), creature.heading);
    try expectFloatClose(@floatCast(@as(f32, 0.9)), creature.move_speed);
    try expectFloatClose(64.0, creature.health);
    try expectFloatClose(64.0, creature.max_health);
    try std.testing.expectEqual(@as(u32, 0x40861862), @as(u32, @bitCast(creature.contact_damage)));
    try std.testing.expectEqual(@as(u32, 0x42117297), @as(u32, @bitCast(creature.reward_value)));
    try std.testing.expectEqual(@as(u32, 0x3F666666), @as(u32, @bitCast(creature.tint[0])));
    try std.testing.expectEqual(@as(u32, 0x3F6147AD), @as(u32, @bitCast(creature.tint[1])));
    try std.testing.expectEqual(@as(u32, 0x3F47AE14), @as(u32, @bitCast(creature.tint[2])));
    try std.testing.expectEqual(@as(u32, 0x3F800000), @as(u32, @bitCast(creature.tint[3])));
    try std.testing.expectEqual(@as(u32, 0xC1BBB05F), rng.state);
}

test "survival spawn reward follows native x87 association" {
    var rng = Crand.init(10);
    const creature = buildSurvivalSpawnCreature(.{ .x = 1.0, .y = 2.0 }, &rng, 0);

    try std.testing.expectEqual(@as(u32, 0x40B0C30C), @as(u32, @bitCast(creature.contact_damage)));
    try std.testing.expectEqual(@as(u32, 0x4220DC68), @as(u32, @bitCast(creature.reward_value)));
}

test "survival spawn xp threshold 25000 consumes extra rand" {
    var rng_24999 = Crand.init(1);
    const creature_24999 = buildSurvivalSpawnCreature(.{ .x = 1.0, .y = 2.0 }, &rng_24999, 24_999);
    try std.testing.expect(creature_24999.type_id == .spider_sp1);
    try std.testing.expect((creature_24999.flags & CreatureFlags.ai7_link_timer) != 0);
    try std.testing.expectEqual(@as(u32, 0xC1BBB05F), rng_24999.state);

    var rng_25000 = Crand.init(1);
    const creature_25000 = buildSurvivalSpawnCreature(.{ .x = 1.0, .y = 2.0 }, &rng_25000, 25_000);
    try std.testing.expect(creature_25000.type_id == .spider_sp1);
    try std.testing.expect((creature_25000.flags & CreatureFlags.ai7_link_timer) != 0);
    try std.testing.expectEqual(@as(u32, 0xA6E9C9A6), rng_25000.state);
}

test "survival spawn zombie speed floor and health scale" {
    var rng = Crand.init(1);
    const creature = buildSurvivalSpawnCreature(.{ .x = 1.0, .y = 2.0 }, &rng, 90_000);
    try std.testing.expect(creature.type_id == .zombie);
    try std.testing.expectEqual(@as(u32, 0), creature.flags);
    try expectFloatClose(@floatCast(@as(f32, 1.3)), creature.move_speed);
    try expectFloatClose(264.75, creature.health);
    try expectFloatClose(264.75, creature.max_health);
    try std.testing.expectEqual(@as(u32, 0xC1BBB05F), rng.state);
}

test "survival spawn rare variants" {
    const cases = [_]struct {
        seed: u32,
        expected_size: f32,
        expected_contact_damage: f32,
        expected_health: f32,
        expected_reward_value: f32,
        expected_tint_r: f32,
        expected_tint_g: f32,
        expected_tint_b: f32,
        expected_rng_state: u32,
    }{
        .{
            .seed = 0x66,
            .expected_size = 47.0,
            .expected_contact_damage = 4.476190476190476,
            .expected_health = 65.0,
            .expected_reward_value = 256.0,
            .expected_tint_r = 0.9,
            .expected_tint_g = 0.4,
            .expected_tint_b = 0.4,
            .expected_rng_state = 0xFF51C012,
        },
        .{
            .seed = 0x51,
            .expected_size = 57.0,
            .expected_contact_damage = 5.428571428571428,
            .expected_health = 85.0,
            .expected_reward_value = 336.0,
            .expected_tint_r = 0.4,
            .expected_tint_g = 0.9,
            .expected_tint_b = 0.4,
            .expected_rng_state = 0xE157C2DC,
        },
        .{
            .seed = 0x6A,
            .expected_size = 56.0,
            .expected_contact_damage = 5.333333333333333,
            .expected_health = 125.0,
            .expected_reward_value = 416.0,
            .expected_tint_r = 0.4,
            .expected_tint_g = 0.4,
            .expected_tint_b = 0.9,
            .expected_rng_state = 0x444FED00,
        },
        .{
            .seed = 0x422,
            .expected_size = 80.0,
            .expected_contact_damage = 4.857142857142857,
            .expected_health = 287.0,
            .expected_reward_value = 480.0,
            .expected_tint_r = 0.84,
            .expected_tint_g = 0.24,
            .expected_tint_b = 0.89,
            .expected_rng_state = 0xEC494E99,
        },
        .{
            .seed = 0x43,
            .expected_size = 85.0,
            .expected_contact_damage = 4.857142857142857,
            .expected_health = 2290.0,
            .expected_reward_value = 720.0,
            .expected_tint_r = 0.94,
            .expected_tint_g = 0.84,
            .expected_tint_b = 0.29,
            .expected_rng_state = 0x6B953591,
        },
    };

    for (cases) |case| {
        var rng = Crand.init(case.seed);
        const creature = buildSurvivalSpawnCreature(.{ .x = 1.0, .y = 2.0 }, &rng, 0);
        try std.testing.expect(creature.type_id == .alien);
        try std.testing.expectEqual(@as(u32, 0), creature.flags);
        try std.testing.expectEqual(CreatureAiMode.orbit_player, creature.ai_mode);
        try expectFloatClose(case.expected_size, creature.size);
        try expectFloatClose(case.expected_contact_damage, creature.contact_damage);
        try expectFloatClose(case.expected_health, creature.health);
        try expectFloatClose(case.expected_health, creature.max_health);
        try expectFloatClose(case.expected_reward_value, creature.reward_value);
        try expectFloatClose(case.expected_tint_r, creature.tint[0]);
        try expectFloatClose(case.expected_tint_g, creature.tint[1]);
        try expectFloatClose(case.expected_tint_b, creature.tint[2]);
        try expectFloatClose(1.0, creature.tint[3]);
        try std.testing.expectEqual(case.expected_rng_state, rng.state);
    }
}

test "survival milestone thresholds" {
    const cases = [_]struct {
        stage: i32,
        level: i32,
        expected_stage: i32,
        expected_count: usize,
    }{
        .{ .stage = 0, .level = 4, .expected_stage = 0, .expected_count = 0 },
        .{ .stage = 0, .level = 5, .expected_stage = 1, .expected_count = 2 },
        .{ .stage = 0, .level = 20, .expected_stage = 7, .expected_count = 29 },
        .{ .stage = 1, .level = 8, .expected_stage = 1, .expected_count = 0 },
        .{ .stage = 1, .level = 9, .expected_stage = 2, .expected_count = 1 },
        .{ .stage = 2, .level = 10, .expected_stage = 2, .expected_count = 0 },
        .{ .stage = 2, .level = 11, .expected_stage = 3, .expected_count = 12 },
        .{ .stage = 3, .level = 13, .expected_stage = 4, .expected_count = 4 },
        .{ .stage = 4, .level = 15, .expected_stage = 5, .expected_count = 8 },
        .{ .stage = 5, .level = 17, .expected_stage = 6, .expected_count = 1 },
        .{ .stage = 6, .level = 19, .expected_stage = 7, .expected_count = 1 },
        .{ .stage = 7, .level = 21, .expected_stage = 8, .expected_count = 2 },
        .{ .stage = 8, .level = 26, .expected_stage = 9, .expected_count = 8 },
        .{ .stage = 9, .level = 31, .expected_stage = 9, .expected_count = 0 },
        .{ .stage = 9, .level = 32, .expected_stage = 10, .expected_count = 10 },
    };

    for (cases) |case| {
        const out = advanceSurvivalSpawnStage(case.stage, case.level);
        try std.testing.expectEqual(case.expected_stage, out.stage);
        try std.testing.expectEqual(case.expected_count, out.count);
    }
}

test "survival milestone stage2 grid positions" {
    const out = advanceSurvivalSpawnStage(2, 11);
    try std.testing.expectEqual(@as(i32, 3), out.stage);
    try std.testing.expectEqual(@as(usize, 12), out.count);

    for (out.slice()) |spawn| {
        try std.testing.expectEqual(@intFromEnum(SpawnId.spider_sp2_random_35), spawn.template_id);
        try expectFloatClose(std.math.pi, spawn.heading);
    }
    try expectFloatClose(1088.0, out.calls[0].pos.x);
    try expectFloatClose(256.0, out.calls[0].pos.y);
    try expectFloatClose(1088.0, out.calls[out.count - 1].pos.x);
    const stage2_step: f32 = 42.666668;
    try expectFloatClose(256.0 + 11.0 * stage2_step, out.calls[out.count - 1].pos.y);
}

test "survival milestone stage9 final wave layout" {
    const out = advanceSurvivalSpawnStage(9, 32);
    try std.testing.expectEqual(@as(i32, 10), out.stage);
    try std.testing.expectEqual(@as(usize, 10), out.count);

    try std.testing.expectEqual(@intFromEnum(SpawnId.spider_boss_3a), out.calls[0].template_id);
    try std.testing.expectEqual(@intFromEnum(SpawnId.spider_boss_3a), out.calls[1].template_id);
    try expectFloatClose(1088.0, out.calls[0].pos.x);
    try expectFloatClose(512.0, out.calls[0].pos.y);
    try expectFloatClose(-64.0, out.calls[1].pos.x);
    try expectFloatClose(512.0, out.calls[1].pos.y);

    for (out.calls[2..6]) |spawn| {
        try std.testing.expectEqual(@intFromEnum(SpawnId.spider_plasma_shooter_3c), spawn.template_id);
        try expectFloatClose(-64.0, spawn.pos.y);
    }
    for (out.calls[6..10]) |spawn| {
        try std.testing.expectEqual(@intFromEnum(SpawnId.spider_plasma_shooter_3c), spawn.template_id);
        try expectFloatClose(1088.0, spawn.pos.y);
    }
}
