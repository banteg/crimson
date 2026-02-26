const std = @import("std");
const native_math = @import("native_math.zig");

const state_mod = @import("state.zig");
const weapon_data = @import("weapon_data.zig");

const narrowF32 = native_math.roundF32;

const WeaponId = state_mod.WeaponId;
const PerkId = state_mod.PerkId;
const PlayerState = state_mod.PlayerState;
const GameplayState = state_mod.GameplayState;
const Vec2 = state_mod.Vec2;

const weapon_stats = weapon_data.weapon_stats;

pub fn weaponAssignPlayer(
    player: *PlayerState,
    weapon_id: WeaponId,
) void {
    var clip_size = @max(0, weapon_stats.get(weapon_id).clip_size);
    if (playerPerkActive(player, .ammo_maniac)) {
        clip_size += @max(1, @divTrunc(clip_size, 4));
    }
    if (playerPerkActive(player, .my_favourite_weapon)) {
        clip_size += 2;
    }

    player.weapon_id = weapon_id;
    player.clip_size = clip_size;
    player.ammo = @floatFromInt(clip_size);
    player.weapon_reset_latch = 0;
    player.reload_active = false;
    player.reload_timer = 0.0;
    player.reload_timer_max = 0.0;
    player.shot_cooldown = 0.0;
    player.aux_timer = 2.0;
}

pub fn incrementWeaponUsage(
    state: *GameplayState,
    weapon_id: WeaponId,
) void {
    if (state.demo_mode_active) return;
    const current = state.status_weapon_usage_counts.get(weapon_id);
    state.status_weapon_usage_counts.set(weapon_id, current +% 1);
}

pub fn weaponAssignPlayerWithState(
    player: *PlayerState,
    weapon_id: WeaponId,
    state: *GameplayState,
) void {
    incrementWeaponUsage(state, weapon_id);
    weaponAssignPlayer(player, weapon_id);
}

const WeaponSlotState = struct {
    weapon_id: WeaponId,
    clip_size: i32,
    ammo: f32,
    reload_active: bool,
    reload_timer: f32,
    reload_timer_max: f32,
    shot_cooldown: f32,
};

fn readPrimaryWeaponSlot(player: *const PlayerState) WeaponSlotState {
    return .{
        .weapon_id = player.weapon_id,
        .clip_size = player.clip_size,
        .ammo = player.ammo,
        .reload_active = player.reload_active,
        .reload_timer = player.reload_timer,
        .reload_timer_max = player.reload_timer_max,
        .shot_cooldown = player.shot_cooldown,
    };
}

fn writePrimaryWeaponSlot(player: *PlayerState, slot: WeaponSlotState) void {
    player.weapon_id = slot.weapon_id;
    player.clip_size = slot.clip_size;
    player.ammo = slot.ammo;
    player.reload_active = slot.reload_active;
    player.reload_timer = slot.reload_timer;
    player.reload_timer_max = slot.reload_timer_max;
    player.shot_cooldown = slot.shot_cooldown;
}

fn readAltWeaponSlot(player: *const PlayerState) ?WeaponSlotState {
    const alt_weapon_id = player.alt_weapon_id orelse return null;
    return .{
        .weapon_id = alt_weapon_id,
        .clip_size = player.alt_clip_size,
        .ammo = player.alt_ammo,
        .reload_active = player.alt_reload_active,
        .reload_timer = player.alt_reload_timer,
        .reload_timer_max = player.alt_reload_timer_max,
        .shot_cooldown = player.alt_shot_cooldown,
    };
}

fn writeAltWeaponSlot(player: *PlayerState, slot: WeaponSlotState) void {
    player.alt_weapon_id = slot.weapon_id;
    player.alt_clip_size = slot.clip_size;
    player.alt_ammo = slot.ammo;
    player.alt_reload_active = slot.reload_active;
    player.alt_reload_timer = slot.reload_timer;
    player.alt_reload_timer_max = slot.reload_timer_max;
    player.alt_shot_cooldown = slot.shot_cooldown;
}

pub fn playerSwapAltWeapon(player: *PlayerState) bool {
    const alt_slot = readAltWeaponSlot(player) orelse return false;
    const primary_slot = readPrimaryWeaponSlot(player);
    writePrimaryWeaponSlot(player, alt_slot);
    writeAltWeaponSlot(player, primary_slot);
    return true;
}

pub fn playerStartReload(player: *PlayerState, state: *GameplayState) void {
    var reload_time = weapon_stats.get(player.weapon_id).reload_time;
    if (player.reload_active and (playerPerkActive(player, .ammunition_within) or playerPerkActive(player, .regression_bullets))) {
        return;
    }
    if (!player.reload_active) {
        player.reload_active = true;
    }
    if (playerPerkActive(player, .fastloader)) {
        reload_time = narrowF32(reload_time * 0.7);
    }
    if (state.bonuses.weapon_power_up > 0.0) {
        reload_time = narrowF32(reload_time * 0.6);
    }
    player.reload_timer = @max(0.0, reload_time);
    player.reload_timer_max = player.reload_timer;
}

fn playerPerkActive(player: *const PlayerState, perk_id: PerkId) bool {
    return player.perk_counts.get(perk_id) > 0;
}

pub fn resetPlayers(
    players: []PlayerState,
    world_size: f32,
    spawn_pos: ?Vec2,
) void {
    if (players.len == 0) return;

    const base = spawn_pos orelse Vec2{
        .x = world_size * 0.5,
        .y = world_size * 0.5,
    };

    if (players.len == 1) {
        players[0] = .{
            .index = 0,
            .pos = base.clampRect(0.0, 0.0, world_size, world_size),
        };
        weaponAssignPlayer(&players[0], WeaponId.pistol);
        return;
    }

    const radius: f32 = 32.0;
    const step = std.math.tau / @as(f32, @floatFromInt(players.len));
    for (players, 0..) |*player, idx| {
        const offset = Vec2.fromAngle(@as(f32, @floatFromInt(idx)) * step).mul(radius);
        player.* = .{
            .index = @intCast(idx),
            .pos = Vec2.add(base, offset).clampRect(0.0, 0.0, world_size, world_size),
        };
        weaponAssignPlayer(player, WeaponId.pistol);
    }
}

fn expectFloatClose(expected: f32, actual: f32) !void {
    try std.testing.expectApproxEqAbs(expected, actual, 1e-6);
}

test "fastloader scales reload timer" {
    const weapon_id = WeaponId.assault_rifle;
    const reload_time = weapon_stats.get(weapon_id).reload_time;
    try std.testing.expect(reload_time > 0.0);

    var base_state = GameplayState.init(1);
    var perk_state = GameplayState.init(1);
    var base_player = PlayerState{
        .index = 0,
        .pos = .{},
        .weapon_id = weapon_id,
    };
    var perk_player = PlayerState{
        .index = 0,
        .pos = .{},
        .weapon_id = weapon_id,
    };
    perk_player.perk_counts.set(.fastloader, 1);

    playerStartReload(&base_player, &base_state);
    playerStartReload(&perk_player, &perk_state);

    try std.testing.expect(base_player.reload_active);
    try std.testing.expect(perk_player.reload_active);
    try expectFloatClose(reload_time, base_player.reload_timer);
    try expectFloatClose(narrowF32(reload_time * 0.7), perk_player.reload_timer);
    try expectFloatClose(perk_player.reload_timer, perk_player.reload_timer_max);
}

test "weapon assign with state resets latch, sets aux timer, and records usage" {
    var state = GameplayState.init(1);
    var player = PlayerState{
        .index = 0,
        .pos = .{},
    };
    player.weapon_reset_latch = 7;
    player.aux_timer = 0.0;

    weaponAssignPlayerWithState(&player, WeaponId.shotgun, &state);

    try std.testing.expectEqual(@as(i32, 0), player.weapon_reset_latch);
    try expectFloatClose(2.0, player.aux_timer);
    try std.testing.expectEqual(@as(u32, 1), state.status_weapon_usage_counts.get(WeaponId.shotgun));
}
