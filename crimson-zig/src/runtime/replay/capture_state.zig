const std = @import("std");
const game_ids = @import("../../game_ids.zig");
const replay_codec = @import("../../replay_codec.zig");
const rng_callers = @import("../../rng_caller_static.zig");

const runtime_bootstrap = @import("../bootstrap.zig");
const bonus_runtime = @import("../bonuses.zig");
const creature_lifecycle = @import("../lifecycle.zig").CreatureLifecycle;
const creatures_mod = @import("../creatures.zig");
const effects_mod = @import("../effects.zig");
const particles_mod = @import("../particles.zig");
const player_runtime = @import("../player.zig");
const projectiles_mod = @import("../projectiles.zig");
const secondary_projectiles_mod = @import("../secondary_projectiles.zig");
const spawn_mod = @import("../spawn.zig");
const state_mod = @import("../state.zig");
const weapon_data = @import("../weapon_data.zig");

pub const capture_state_reset_target: i32 = 12;
pub const ParsedQuestLevel = runtime_bootstrap.ParsedQuestLevel;

const ai7_link_timer_rollover_min: i32 = -1723;
const ai7_link_timer_rollover_max: i32 = -700;
const max_test_quest_spawn_entries: usize = 1024;

pub const CaptureStateError = error{
    InvalidCaptureEnumValue,
    InvalidSpawnTemplate,
};

pub fn parseQuestLevel(value: []const u8) ?ParsedQuestLevel {
    return runtime_bootstrap.parseQuestLevel(value);
}

pub fn resolveQuestLevelKey(header: replay_codec.ReplayHeader) ?i32 {
    return runtime_bootstrap.resolveQuestLevelKey(header);
}

pub fn applyQuestStageFromHeader(
    state: *state_mod.GameplayState,
    header: replay_codec.ReplayHeader,
) void {
    runtime_bootstrap.applyQuestStageFromHeader(state, header);
}

pub fn enforceRushLoadout(players: []state_mod.PlayerState) void {
    runtime_bootstrap.enforceRushLoadout(players);
}

pub fn applyCaptureBootstrapEvent(
    bootstrap: replay_codec.CaptureBootstrapEvent,
    state: *state_mod.GameplayState,
    players: []state_mod.PlayerState,
    quest_spawn_timeline_ms: *f32,
    quest_no_creatures_timer_ms: *f32,
    quest_completion_transition_ms: *f32,
) CaptureStateError!void {
    const player_count = @min(players.len, bootstrap.player_count);
    for (0..player_count) |idx| {
        const payload = bootstrap.players[idx];
        if (payload.weapon_id > 0) {
            const weapon_id = weapon_data.weaponIdFromInt(payload.weapon_id);
            if (players[idx].weapon.weapon_id != weapon_id) {
                player_runtime.weaponAssignPlayer(&players[idx], weapon_id);
            }
        }
        players[idx].pos.x = payload.pos_x;
        players[idx].pos.y = payload.pos_y;
        players[idx].health = payload.health;
        players[idx].weapon.ammo = payload.ammo;
        players[idx].experience = payload.experience;
        if (payload.level > 0) {
            players[idx].level = payload.level;
        }
        if (payload.clip_size) |clip_size| {
            if (clip_size >= 0) players[idx].weapon.clip_size = clip_size;
        }
        if (payload.reload_active) |reload_active| {
            players[idx].weapon.reload_active = reload_active;
        }
        if (payload.reload_timer) |reload_timer| {
            players[idx].weapon.reload_timer = @max(0.0, reload_timer);
        }
        if (payload.reload_timer_max) |reload_timer_max| {
            players[idx].weapon.reload_timer_max = @max(0.0, reload_timer_max);
        }
        if (payload.shot_cooldown) |shot_cooldown| {
            players[idx].weapon.shot_cooldown = @max(0.0, shot_cooldown);
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
            players[idx].alt_weapon = if (alt_weapon_id > 0)
                .{ .weapon_id = weapon_data.weaponIdFromInt(alt_weapon_id) }
            else
                null;
        }
        if (payload.alt_clip_size) |alt_clip_size| {
            if (alt_clip_size >= 0) {
                if (players[idx].alt_weapon == null) {
                    players[idx].alt_weapon = .{ .weapon_id = players[idx].weapon.weapon_id };
                }
                players[idx].alt_weapon.?.clip_size = alt_clip_size;
            }
        }
        if (payload.alt_ammo) |alt_ammo| {
            if (players[idx].alt_weapon == null) {
                players[idx].alt_weapon = .{ .weapon_id = players[idx].weapon.weapon_id };
            }
            players[idx].alt_weapon.?.ammo = alt_ammo;
        }
        if (payload.alt_reload_active) |alt_reload_active| {
            if (players[idx].alt_weapon == null) {
                players[idx].alt_weapon = .{ .weapon_id = players[idx].weapon.weapon_id };
            }
            players[idx].alt_weapon.?.reload_active = alt_reload_active;
        }
        if (payload.alt_reload_timer) |alt_reload_timer| {
            if (players[idx].alt_weapon == null) {
                players[idx].alt_weapon = .{ .weapon_id = players[idx].weapon.weapon_id };
            }
            players[idx].alt_weapon.?.reload_timer = @max(0.0, alt_reload_timer);
        }
        if (payload.alt_reload_timer_max) |alt_reload_timer_max| {
            if (players[idx].alt_weapon == null) {
                players[idx].alt_weapon = .{ .weapon_id = players[idx].weapon.weapon_id };
            }
            players[idx].alt_weapon.?.reload_timer_max = @max(0.0, alt_reload_timer_max);
        }
        if (payload.alt_shot_cooldown) |alt_shot_cooldown| {
            if (players[idx].alt_weapon == null) {
                players[idx].alt_weapon = .{ .weapon_id = players[idx].weapon.weapon_id };
            }
            players[idx].alt_weapon.?.shot_cooldown = @max(0.0, alt_shot_cooldown);
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
            std.enums.fromInt(game_ids.PerkId, bootstrap.perk_choices[idx]) orelse return error.InvalidCaptureEnumValue;
    }
    for (players, 0..) |*player, player_idx| {
        player.perk_counts = std.EnumArray(game_ids.PerkId, i32).initFill(0);
        const perk_counts = bootstrap.player_perk_counts[player_idx];
        for (0..perk_counts.pair_count) |pair_idx| {
            const pair = perk_counts.pairs[pair_idx];
            const perk_id = std.enums.fromInt(game_ids.PerkId, pair.perk_id) orelse return error.InvalidCaptureEnumValue;
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

fn parseCaptureCreatureAiMode(value: i32) CaptureStateError!spawn_mod.CreatureAiMode {
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

pub fn applyCaptureCreatureSpawnEvent(
    state: *state_mod.GameplayState,
    creatures: *creatures_mod.CreaturePool,
    event: replay_codec.CaptureCreatureSpawnEvent,
) CaptureStateError!void {
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
            error.InvalidSpawnTemplate => return error.InvalidSpawnTemplate,
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
            _ = state.rng.randTagged(rng_callers.creature_update_all_ai7_link_timer_reset);
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

pub fn applyCaptureStateReset(
    state: *state_mod.GameplayState,
    players: []state_mod.PlayerState,
    creatures: *creatures_mod.CreaturePool,
    effects: *effects_mod.EffectPool,
    sprite_effects: *effects_mod.SpriteEffectPool,
    particles: *particles_mod.ParticlePool,
    projectiles: *projectiles_mod.ProjectilePool,
    secondary_projectiles: *secondary_projectiles_mod.SecondaryProjectilePool,
    bonuses: *bonus_runtime.BonusPool,
    world_size: f32,
    quest_start_weapon_id: i32,
    gore_disabled: i32,
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
    const demo_mode_active = state.demo_mode_active;
    const quest_fail_retry_count = state.quest_fail_retry_count;
    const quest_stage_major = state.quest_stage_major;
    const quest_stage_minor = state.quest_stage_minor;
    const perk_pending_count = state.perk_selection.pending_count;
    const perk_choice_count = state.perk_selection.choice_count;
    const perk_choices_dirty = state.perk_selection.choices_dirty;
    const perk_choices = state.perk_selection.choices;
    const perk_interval_man_bomb = state.perk_interval_man_bomb;
    const perk_interval_fire_cough = state.perk_interval_fire_cough;
    const perk_interval_hot_tempered = state.perk_interval_hot_tempered;
    const rng_trace_ctx = state.rng.trace_ctx;
    const rng_trace_sink = state.rng.trace_sink;

    state.* = state_mod.GameplayState.init(rng_state);
    state.rng.setTraceSink(rng_trace_ctx, rng_trace_sink, false);
    state.status_quest_unlock_index = status_quest_unlock_index;
    state.status_quest_unlock_index_full = status_quest_unlock_index_full;
    state.status_weapon_usage_counts = status_weapon_usage_counts;
    state.gore_disabled = gore_disabled;
    state.game_mode = game_mode;
    state.hardcore = hardcore;
    state.demo_mode_active = demo_mode_active;
    state.quest_fail_retry_count = quest_fail_retry_count;
    state.quest_stage_major = quest_stage_major;
    state.quest_stage_minor = quest_stage_minor;
    state.perk_selection.pending_count = perk_pending_count;
    state.perk_selection.choice_count = perk_choice_count;
    state.perk_selection.choices_dirty = perk_choices_dirty;
    state.perk_selection.choices = perk_choices;
    state.perk_interval_man_bomb = perk_interval_man_bomb;
    state.perk_interval_fire_cough = perk_interval_fire_cough;
    state.perk_interval_hot_tempered = perk_interval_hot_tempered;

    player_runtime.resetPlayers(players, world_size, null, .{ .legacy_table_pistol_start = true });
    for (players) |*player| {
        const quest_weapon = weapon_data.weaponIdFromInt(quest_start_weapon_id);
        player_runtime.weaponAssignPlayer(player, quest_weapon);
        if (quest_start_weapon_id == @intFromEnum(game_ids.WeaponId.pistol)) {
            player.weapon.clip_size = @max(12, player.weapon.clip_size);
            if (player.weapon.ammo < 12.0) {
                player.weapon.ammo = 12.0;
            }
        }
    }

    creatures.reset();
    creatures.hardcore = hardcore;
    creatures.demo_mode_active = demo_mode_active;
    creatures.quest_fail_retry_count = quest_fail_retry_count;
    creatures.effects = effects;
    effects.reset();
    sprite_effects.reset();
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

fn makeTestHeader(quest_level: []const u8, seed: u32) replay_codec.ReplayHeader {
    return .{
        .game_mode_id = @intFromEnum(game_ids.GameModeId.quests),
        .seed = seed,
        .replay_format_version = replay_codec.replay_format_version,
        .quest_level = @constCast(quest_level),
        .bootstrap_kind = @constCast("none"),
        .bootstrap_seed = 0,
        .game_version = @constCast(""),
        .tick_rate = 60,
        .difficulty_level = 0,
        .hardcore = false,
        .preserve_bugs = false,
        .detail_preset = 5,
        .gore_disabled = 0,
        .world_size = 1024.0,
        .player_count = 1,
        .status = .{},
        .claimed_stats = .{},
        .input_quantization = @constCast("f32"),
    };
}

test "capture state reset clears transient pools and restores header fx toggle" {
    var state = state_mod.GameplayState.init(0x1234);
    state.game_mode = .quests;
    state.gore_disabled = 1;
    state.hardcore = true;
    state.perk_selection.pending_count = 2;

    var players_storage: [state_mod.max_players]state_mod.PlayerState = undefined;
    const players = players_storage[0..1];
    player_runtime.resetPlayers(players, 1024.0, null, .{});

    var creatures: creatures_mod.CreaturePool = .{};
    creatures.entries[0].active = true;
    creatures.entries[0].lifecycle_stage = creature_lifecycle.alive;

    var effects: effects_mod.EffectPool = .{};
    effects.entries[0].flags = 1;

    var sprite_effects: effects_mod.SpriteEffectPool = .{};
    sprite_effects.entries[0].active = true;

    var particles: particles_mod.ParticlePool = .{};
    particles.entries[0].active = true;

    var projectiles: projectiles_mod.ProjectilePool = .{};
    projectiles.entries[0].active = true;

    var secondary_projectiles: secondary_projectiles_mod.SecondaryProjectilePool = .{};
    secondary_projectiles.entries[0].active = true;

    var bonuses: bonus_runtime.BonusPool = .{};
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
        &effects,
        &sprite_effects,
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

    try std.testing.expectEqual(@as(i32, 0), state.gore_disabled);
    try std.testing.expectEqual(@as(i32, 2), state.perk_selection.pending_count);
    try std.testing.expect(!creatures.entries[0].active);
    try std.testing.expectEqual(@as(i32, 0), effects.entries[0].flags);
    try std.testing.expect(!sprite_effects.entries[0].active);
    try std.testing.expect(!particles.entries[0].active);
    try std.testing.expect(!projectiles.entries[0].active);
    try std.testing.expect(!secondary_projectiles.entries[0].active);
    try std.testing.expectEqual(game_ids.BonusId.unused, bonuses.entries[0].bonus_id);
    try std.testing.expect(creatures.capture_spawn_events_authoritative);
}

test "capture creature spawn event backfills ai7 rollover rng draw for spawned rows" {
    var base_state = state_mod.GameplayState.init(0x1234ABCD);
    var base_creatures: creatures_mod.CreaturePool = .{};
    base_creatures.reset();
    var base_event: replay_codec.CaptureCreatureSpawnEvent = .{
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
    var rollover_creatures: creatures_mod.CreaturePool = .{};
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
    _ = probe_rng.randTagged(rng_callers.creature_update_all_ai7_link_timer_reset);
    try std.testing.expectEqual(probe_rng.state, rng_after_rollover);
    try std.testing.expectEqual(@as(i32, -975), rollover_creatures.entries[0].link_index);
}

test "apply quest stage from header uses parsed quest level and safe seed fallback" {
    var state = state_mod.GameplayState.init(1234);

    const level_header = makeTestHeader("2.5", 999);
    applyQuestStageFromHeader(&state, level_header);
    try std.testing.expectEqual(@as(i32, 2), state.quest_stage_major);
    try std.testing.expectEqual(@as(i32, 5), state.quest_stage_minor);

    const fallback_header = makeTestHeader("bad", 307);
    applyQuestStageFromHeader(&state, fallback_header);
    try std.testing.expectEqual(@as(i32, 3), state.quest_stage_major);
    try std.testing.expectEqual(@as(i32, 7), state.quest_stage_minor);

    const overflow_header = makeTestHeader("bad", std.math.maxInt(u32));
    applyQuestStageFromHeader(&state, overflow_header);
    try std.testing.expectEqual(@as(i32, 0), state.quest_stage_major);
    try std.testing.expectEqual(@as(i32, 0), state.quest_stage_minor);
}
