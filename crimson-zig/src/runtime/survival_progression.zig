const std = @import("std");
const native_math = @import("native_math.zig");

const player_runtime = @import("player.zig");
const state_mod = @import("state.zig");

const narrowF32 = native_math.roundF32;

const WeaponId = state_mod.WeaponId;
const PlayerState = state_mod.PlayerState;
const GameplayState = state_mod.GameplayState;
const PerkSelectionState = state_mod.PerkSelectionState;
const Vec2 = state_mod.Vec2;
const PlayerShots = state_mod.PlayerShots;

const weaponAssignPlayer = player_runtime.weaponAssignPlayer;
const weaponAssignPlayerWithState = player_runtime.weaponAssignPlayerWithState;

pub fn player0Shots(state: GameplayState) PlayerShots {
    const fired: i32 = @max(0, state.shots_fired[0]);
    var hit: i32 = @max(0, state.shots_hit[0]);
    if (hit > fired) hit = fired;

    return .{
        .fired = fired,
        .hit = hit,
    };
}

pub fn mostUsedWeaponIdForPlayer(
    state: GameplayState,
    player_index: usize,
    fallback_weapon_id: WeaponId,
) WeaponId {
    if (player_index >= state.weapon_shots_fired.len) {
        return fallback_weapon_id;
    }

    const counts = state.weapon_shots_fired[player_index];
    if (counts.len == 0) return fallback_weapon_id;

    const start: usize = if (counts.len > 1) 1 else 0;
    var best = start;
    var best_count = counts[start];

    for (counts[start + 1 ..], start + 1..) |count, idx| {
        if (count > best_count) {
            best = idx;
            best_count = count;
        }
    }

    if (best_count > 0) return @enumFromInt(best);
    return fallback_weapon_id;
}

pub fn timeScaleReflexBoostBonus(
    reflex_boost_timer: f32,
    time_scale_active: bool,
    dt: f32,
) f32 {
    const dt_f32 = narrowF32(dt);
    if (!(dt_f32 > 0.0)) return dt_f32;
    if (!time_scale_active) return dt_f32;

    const time_scale_factor = reflexBoostTimeScaleFactor(reflex_boost_timer, true);
    return native_math.pc24Mul(dt_f32, time_scale_factor);
}

pub fn reflexBoostTimeScaleFactor(
    reflex_boost_timer: f32,
    time_scale_active: bool,
) f32 {
    if (!time_scale_active) return 1.0;

    const reflex_f32 = narrowF32(reflex_boost_timer);
    if (reflex_f32 >= 1.0) return narrowF32(0.3);
    return native_math.pc24Add(
        native_math.pc24Mul(
            native_math.pc24Sub(@as(f32, 1.0), reflex_f32),
            @as(f32, 0.7),
        ),
        @as(f32, 0.3),
    );
}

pub fn survivalLevelThreshold(level_in: i32) i32 {
    const level = @max(1, level_in);
    const level_f32: f32 = @floatFromInt(level);
    const value = 1000.0 + std.math.pow(f32, level_f32, 1.8) * 1000.0;
    return @intFromFloat(value);
}

pub fn survivalCheckLevelUp(
    player: *PlayerState,
    perk_state: *PerkSelectionState,
) i32 {
    if (player.experience > survivalLevelThreshold(player.level)) {
        player.level += 1;
        perk_state.pending_count += 1;
        perk_state.choices_dirty = true;
        return 1;
    }
    return 0;
}

pub fn survivalProgressionUpdate(
    state: *GameplayState,
    players: []PlayerState,
) i32 {
    if (players.len == 0) return 0;
    return survivalCheckLevelUp(&players[0], &state.perk_selection);
}

pub fn survivalRecordRecentDeath(
    state: *GameplayState,
    pos: Vec2,
) void {
    var recent_count = state.survival_recent_death_count;
    if (recent_count >= 6) return;

    if (recent_count < 3) {
        const idx: usize = @intCast(recent_count);
        state.survival_recent_death_pos[idx] = .{
            .x = narrowF32(pos.x),
            .y = narrowF32(pos.y),
        };
    }

    recent_count += 1;
    state.survival_recent_death_count = recent_count;
    if (recent_count == 3) {
        state.survival_reward_fire_seen = false;
        state.survival_reward_handout_enabled = false;
    }
}

pub fn survivalUpdateWeaponHandouts(
    state: *GameplayState,
    players: []PlayerState,
    survival_elapsed_ms: f32,
) void {
    if (players.len != 1) return;
    const player = &players[0];

    if (!state.survival_reward_damage_seen and
        !state.survival_reward_fire_seen and
        @as(i32, @intFromFloat(survival_elapsed_ms)) > 64_000 and
        state.survival_reward_handout_enabled)
    {
        if (player.weapon.weapon_id == WeaponId.pistol) {
            weaponAssignPlayerWithState(player, WeaponId.shrinkifier_5k, state);
            state.survival_reward_weapon_guard_id = WeaponId.shrinkifier_5k;
        }
        state.survival_reward_handout_enabled = false;
        state.survival_reward_damage_seen = true;
        state.survival_reward_fire_seen = true;
    }

    if (state.survival_recent_death_count == 3 and !state.survival_reward_fire_seen) {
        const pos0 = state.survival_recent_death_pos[0];
        const pos1 = state.survival_recent_death_pos[1];
        const pos2 = state.survival_recent_death_pos[2];

        const centroid_scale = narrowF32(0.33333334);
        const centroid_x = native_math.pc24Mul(
            native_math.pc24Add(native_math.pc24Add(pos0.x, pos1.x), pos2.x),
            centroid_scale,
        );
        const centroid_y = native_math.pc24Mul(
            native_math.pc24Add(native_math.pc24Add(pos0.y, pos1.y), pos2.y),
            centroid_scale,
        );

        const dx = native_math.pc24Sub(player.pos.x, centroid_x);
        const dy = native_math.pc24Sub(player.pos.y, centroid_y);
        const distance = native_math.pc24Hypot(dx, dy);
        if (distance < 16.0 and player.health < 15.0) {
            weaponAssignPlayerWithState(player, WeaponId.blade_gun, state);
            state.survival_reward_weapon_guard_id = WeaponId.blade_gun;
            state.survival_reward_fire_seen = true;
            state.survival_reward_handout_enabled = false;
        }
    }
}

pub fn survivalEnforceRewardWeaponGuard(
    state: *GameplayState,
    players: []PlayerState,
) void {
    const guard_id = state.survival_reward_weapon_guard_id;
    for (players) |*player| {
        if (player.weapon.weapon_id == WeaponId.blade_gun and guard_id != WeaponId.blade_gun) {
            weaponAssignPlayerWithState(player, WeaponId.pistol, state);
        }
        if (player.weapon.weapon_id == WeaponId.shrinkifier_5k and guard_id != WeaponId.shrinkifier_5k) {
            weaponAssignPlayerWithState(player, WeaponId.pistol, state);
        }
    }
}

pub fn gameplayEnforceWeaponGuards(
    state: *GameplayState,
    players: []PlayerState,
) void {
    // Native gameplay_render_world checks exactly the two fixed player slots.
    // Corrected mode extends the same entitlement policy to generalized co-op.
    const guarded_players = if (state.preserve_bugs) players[0..@min(players.len, 2)] else players;
    if (state.status_quest_unlock_index_full < 0x28) {
        for (guarded_players) |*player| {
            if (player.weapon.weapon_id == WeaponId.splitter_gun) {
                weaponAssignPlayerWithState(player, WeaponId.pistol, state);
            }
        }
    }

    survivalEnforceRewardWeaponGuard(state, guarded_players);
}

fn expectFloatClose(expected: f32, actual: f32) !void {
    try std.testing.expectApproxEqAbs(expected, actual, 1e-6);
}

test "survival level up advances one threshold per tick" {
    var player: PlayerState = .{
        .index = 0,
        .pos = .{},
        .level = 1,
        .experience = 5000,
    };
    var perks: PerkSelectionState = .{};

    const advanced_0 = survivalCheckLevelUp(&player, &perks);
    try std.testing.expectEqual(@as(i32, 1), advanced_0);
    try std.testing.expectEqual(@as(i32, 2), player.level);
    try std.testing.expectEqual(@as(i32, 1), perks.pending_count);
    try std.testing.expect(perks.choices_dirty);

    const advanced_1 = survivalCheckLevelUp(&player, &perks);
    try std.testing.expectEqual(@as(i32, 1), advanced_1);
    try std.testing.expectEqual(@as(i32, 3), player.level);
    try std.testing.expectEqual(@as(i32, 2), perks.pending_count);
}

test "survival level threshold smoke values" {
    try std.testing.expectEqual(@as(i32, 2000), survivalLevelThreshold(1));
    try std.testing.expectEqual(@as(i32, 4482), survivalLevelThreshold(2));
    try std.testing.expectEqual(@as(i32, 64095), survivalLevelThreshold(10));
}

test "survival handout time gate assigns shrinkifier" {
    var state = GameplayState.init(1);
    var players = [_]PlayerState{
        .{ .index = 0, .pos = .{ .x = 512.0, .y = 512.0 } },
    };
    weaponAssignPlayer(&players[0], WeaponId.pistol);

    survivalUpdateWeaponHandouts(&state, players[0..], 64_001.0);

    try std.testing.expectEqual(WeaponId.shrinkifier_5k, players[0].weapon.weapon_id);
    try std.testing.expectEqual(WeaponId.shrinkifier_5k, state.survival_reward_weapon_guard_id);
    try std.testing.expect(!state.survival_reward_handout_enabled);
    try std.testing.expect(state.survival_reward_damage_seen);
    try std.testing.expect(state.survival_reward_fire_seen);
}

test "survival handout time gate consumes without pistol" {
    var state = GameplayState.init(1);
    var players = [_]PlayerState{
        .{ .index = 0, .pos = .{ .x = 512.0, .y = 512.0 } },
    };
    weaponAssignPlayer(&players[0], WeaponId.assault_rifle);

    survivalUpdateWeaponHandouts(&state, players[0..], 64_001.0);

    try std.testing.expectEqual(WeaponId.assault_rifle, players[0].weapon.weapon_id);
    try std.testing.expectEqual(WeaponId.pistol, state.survival_reward_weapon_guard_id);
    try std.testing.expect(!state.survival_reward_handout_enabled);
    try std.testing.expect(state.survival_reward_damage_seen);
    try std.testing.expect(state.survival_reward_fire_seen);
}

test "survival handouts are single player only" {
    var state = GameplayState.init(1);
    var players = [_]PlayerState{
        .{ .index = 0, .pos = .{ .x = 512.0, .y = 512.0 } },
        .{ .index = 1, .pos = .{ .x = 512.0, .y = 512.0 } },
    };
    weaponAssignPlayer(&players[0], WeaponId.pistol);
    weaponAssignPlayer(&players[1], WeaponId.pistol);

    survivalUpdateWeaponHandouts(&state, players[0..], 64_001.0);

    try std.testing.expectEqual(WeaponId.pistol, players[0].weapon.weapon_id);
    try std.testing.expectEqual(WeaponId.pistol, players[1].weapon.weapon_id);
    try std.testing.expect(state.survival_reward_handout_enabled);
    try std.testing.expect(!state.survival_reward_damage_seen);
    try std.testing.expect(!state.survival_reward_fire_seen);
}

test "survival handout centroid gate assigns blade gun" {
    var state = GameplayState.init(1);
    var players = [_]PlayerState{
        .{ .index = 0, .pos = .{ .x = 100.0, .y = 100.0 }, .health = 14.0 },
    };
    weaponAssignPlayer(&players[0], WeaponId.pistol);

    state.survival_reward_handout_enabled = false;
    state.survival_reward_damage_seen = true;
    state.survival_reward_fire_seen = false;
    state.survival_recent_death_count = 3;
    state.survival_recent_death_pos = .{
        .{ .x = 90.0, .y = 100.0 },
        .{ .x = 100.0, .y = 90.0 },
        .{ .x = 110.0, .y = 110.0 },
    };

    survivalUpdateWeaponHandouts(&state, players[0..], 0.0);

    try std.testing.expectEqual(WeaponId.blade_gun, players[0].weapon.weapon_id);
    try std.testing.expectEqual(WeaponId.blade_gun, state.survival_reward_weapon_guard_id);
    try std.testing.expect(state.survival_reward_fire_seen);
    try std.testing.expect(!state.survival_reward_handout_enabled);
}

test "survival record recent death latches handout gate at 3" {
    var state = GameplayState.init(1);
    state.survival_reward_fire_seen = true;
    state.survival_reward_handout_enabled = true;

    survivalRecordRecentDeath(&state, .{ .x = 10.0, .y = 20.0 });
    survivalRecordRecentDeath(&state, .{ .x = 30.0, .y = 40.0 });
    survivalRecordRecentDeath(&state, .{ .x = 50.0, .y = 60.0 });

    try std.testing.expectEqual(@as(i32, 3), state.survival_recent_death_count);
    try expectFloatClose(10.0, state.survival_recent_death_pos[0].x);
    try expectFloatClose(20.0, state.survival_recent_death_pos[0].y);
    try expectFloatClose(30.0, state.survival_recent_death_pos[1].x);
    try expectFloatClose(40.0, state.survival_recent_death_pos[1].y);
    try expectFloatClose(50.0, state.survival_recent_death_pos[2].x);
    try expectFloatClose(60.0, state.survival_recent_death_pos[2].y);
    try std.testing.expect(!state.survival_reward_fire_seen);
    try std.testing.expect(!state.survival_reward_handout_enabled);
}

test "survival reward guard reverts temporary weapons" {
    var state = GameplayState.init(1);
    var players = [_]PlayerState{
        .{ .index = 0, .pos = .{} },
        .{ .index = 1, .pos = .{} },
    };
    weaponAssignPlayer(&players[0], WeaponId.shrinkifier_5k);
    weaponAssignPlayer(&players[1], WeaponId.blade_gun);
    state.survival_reward_weapon_guard_id = WeaponId.shrinkifier_5k;

    survivalEnforceRewardWeaponGuard(&state, players[0..]);

    try std.testing.expectEqual(WeaponId.shrinkifier_5k, players[0].weapon.weapon_id);
    try std.testing.expectEqual(WeaponId.pistol, players[1].weapon.weapon_id);
    try std.testing.expectEqual(@as(u32, 1), state.status_weapon_usage_counts.get(WeaponId.pistol));
}

test "gameplay weapon guard revokes locked splitter from native player slots" {
    var state = GameplayState.init(1);
    state.preserve_bugs = true;
    var players = [_]PlayerState{
        .{ .index = 0, .pos = .{} },
        .{ .index = 1, .pos = .{} },
        .{ .index = 2, .pos = .{} },
    };
    for (&players) |*player| {
        weaponAssignPlayer(player, WeaponId.splitter_gun);
    }

    gameplayEnforceWeaponGuards(&state, players[0..]);

    try std.testing.expectEqual(WeaponId.pistol, players[0].weapon.weapon_id);
    try std.testing.expectEqual(WeaponId.pistol, players[1].weapon.weapon_id);
    try std.testing.expectEqual(WeaponId.splitter_gun, players[2].weapon.weapon_id);
    try std.testing.expectEqual(@as(u32, 2), state.status_weapon_usage_counts.get(WeaponId.pistol));
}

test "gameplay weapon guard extends splitter policy in corrected mode" {
    var state = GameplayState.init(1);
    var players = [_]PlayerState{
        .{ .index = 0, .pos = .{} },
        .{ .index = 1, .pos = .{} },
        .{ .index = 2, .pos = .{} },
    };
    for (&players) |*player| {
        weaponAssignPlayer(player, WeaponId.splitter_gun);
    }

    gameplayEnforceWeaponGuards(&state, players[0..]);

    for (players) |player| {
        try std.testing.expectEqual(WeaponId.pistol, player.weapon.weapon_id);
    }
}

test "gameplay weapon guard keeps unlocked splitter" {
    var state = GameplayState.init(1);
    state.status_quest_unlock_index_full = 0x28;
    var player: PlayerState = .{ .index = 0, .pos = .{} };
    weaponAssignPlayer(&player, WeaponId.splitter_gun);
    var players = [_]PlayerState{player};

    gameplayEnforceWeaponGuards(&state, players[0..]);

    try std.testing.expectEqual(WeaponId.splitter_gun, players[0].weapon.weapon_id);
}

test "time scale reflex boost bonus mirrors f32 latch" {
    try expectFloatClose(0.01666666753590107, timeScaleReflexBoostBonus(0.0, false, 1.0 / 60.0));
    try expectFloatClose(0.01666666753590107, timeScaleReflexBoostBonus(0.0, true, 1.0 / 60.0));
    try expectFloatClose(0.010833333246409893, timeScaleReflexBoostBonus(0.5, true, 1.0 / 60.0));
    try std.testing.expectEqual(
        @as(u32, 0x3ec9246d),
        @as(u32, @bitCast(reflexBoostTimeScaleFactor(0.8673485517501831, true))),
    );
}
