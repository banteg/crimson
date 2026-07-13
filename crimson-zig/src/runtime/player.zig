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

pub const GameInputFlags = struct {
    fire_down: bool,
    fire_pressed: bool,
    reload_pressed: bool,
    reload_down: bool = false,
    move_to_cursor_pressed: bool = false,
    move_mode: ?i32 = null,
    aim_scheme: ?i32 = null,
    move_forward_pressed: ?bool = null,
    move_backward_pressed: ?bool = null,
    turn_left_pressed: ?bool = null,
    turn_right_pressed: ?bool = null,
};

pub const GameInput = struct {
    move_x: f32,
    move_y: f32,
    aim_x: f32,
    aim_y: f32,
    flags: GameInputFlags,
};

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

    player.weapon.weapon_id = weapon_id;
    player.weapon.clip_size = clip_size;
    player.weapon.ammo = @floatFromInt(clip_size);
    player.weapon_reset_latch = 0;
    // Native resets only ammo, the reset latch, shot cooldown, reload timer,
    // and aux timer; reload_active and reload_timer_max keep their previous
    // values across a weapon pickup mid-reload.
    player.weapon.reload_timer = 0.0;
    player.weapon.shot_cooldown = 0.0;
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

pub fn playerSwapAltWeapon(player: *PlayerState) bool {
    const alt_slot = player.alt_weapon orelse return false;
    player.alt_weapon = player.weapon;
    player.weapon = alt_slot;
    return true;
}

pub fn initDefaultAltWeapon(player: *PlayerState) void {
    // Native reset preloads an alternate pistol slot before the perk is acquired.
    player.alt_weapon = .{
        .weapon_id = WeaponId.pistol,
        .clip_size = 12,
        .ammo = 12.0,
        .reload_active = false,
        .reload_timer = 0.0,
        .reload_timer_max = 1.2,
        .shot_cooldown = 0.0,
    };
}

pub fn playerStartReload(player: *PlayerState, state: *GameplayState) void {
    var reload_time = weapon_stats.get(player.weapon.weapon_id).reload_time;
    if (player.weapon.reload_active and (playerPerkActive(player, .ammunition_within) or playerPerkActive(player, .regression_bullets))) {
        return;
    }
    if (!player.weapon.reload_active) {
        player.weapon.reload_active = true;
    }
    if (playerPerkActive(player, .fastloader)) {
        reload_time = narrowF32(reload_time * 0.7);
    }
    if (state.bonuses.weapon_power_up > 0.0) {
        reload_time = narrowF32(reload_time * 0.6);
    }
    player.weapon.reload_timer = reload_time;
    player.weapon.reload_timer_max = player.weapon.reload_timer;
}

fn playerPerkActive(player: *const PlayerState, perk_id: PerkId) bool {
    // Keep this local in player runtime to avoid a player<->perks import cycle.
    return player.perk_counts.get(perk_id) > 0;
}

pub fn resetPlayerWeaponNative(player: *PlayerState) void {
    // Port of the weapon block in `player_reset_all` (0x41fc80): native
    // resets every run to a hardcoded 10-round pistol with a primed 1.0s
    // reload duration and a decaying 0.8s shot cooldown, without going
    // through weapon assignment.
    player.weapon = .{
        .weapon_id = WeaponId.pistol,
        .clip_size = 10,
        .ammo = 10.0,
        .reload_active = false,
        .reload_timer = 0.0,
        .reload_timer_max = 1.0,
        .shot_cooldown = 0.8,
    };
}

pub fn resetPlayers(
    players: []PlayerState,
    world_size: f32,
    spawn_pos: ?Vec2,
) void {
    if (players.len == 0) return;

    const base = spawn_pos orelse Vec2{
        .x = narrowF32(world_size * 0.5),
        .y = narrowF32(world_size * 0.5),
    };

    for (players, 0..) |*player, idx| {
        const offset: f32 = @floatFromInt(idx * 0x50);
        const pos = if (idx % 2 == 0)
            Vec2{
                .x = narrowF32(base.x + offset),
                .y = narrowF32(base.y + offset),
            }
        else
            Vec2{
                .x = narrowF32(base.x - offset),
                .y = narrowF32(base.y - offset),
            };
        player.* = .{
            .index = @intCast(idx),
            .pos = pos,
            .spread_heat = 0.0,
        };
        resetPlayerWeaponNative(player);
        initDefaultAltWeapon(player);
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
    var base_player: PlayerState = .{
        .index = 0,
        .pos = .{},
        .weapon = .{ .weapon_id = weapon_id },
    };
    var perk_player: PlayerState = .{
        .index = 0,
        .pos = .{},
        .weapon = .{ .weapon_id = weapon_id },
    };
    perk_player.perk_counts.set(.fastloader, 1);

    playerStartReload(&base_player, &base_state);
    playerStartReload(&perk_player, &perk_state);

    try std.testing.expect(base_player.weapon.reload_active);
    try std.testing.expect(perk_player.weapon.reload_active);
    try expectFloatClose(reload_time, base_player.weapon.reload_timer);
    try expectFloatClose(narrowF32(reload_time * 0.7), perk_player.weapon.reload_timer);
    try expectFloatClose(perk_player.weapon.reload_timer, perk_player.weapon.reload_timer_max);
}

test "weapon assign with state resets latch, sets aux timer, and records usage" {
    var state = GameplayState.init(1);
    var player: PlayerState = .{
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

test "reset players preloads alternate pistol slot" {
    var players = [_]PlayerState{
        .{
            .index = 0,
            .pos = .{},
        },
    };

    resetPlayers(players[0..], 1024.0, null);

    try std.testing.expect(players[0].alt_weapon != null);
    try std.testing.expectEqual(WeaponId.pistol, players[0].alt_weapon.?.weapon_id);
    try std.testing.expectEqual(@as(i32, 12), players[0].alt_weapon.?.clip_size);
    try std.testing.expectApproxEqAbs(@as(f32, 12.0), players[0].alt_weapon.?.ammo, 1e-6);
    try std.testing.expect(!players[0].alt_weapon.?.reload_active);
    try std.testing.expectApproxEqAbs(@as(f32, 1.2), players[0].alt_weapon.?.reload_timer_max, 1e-6);
}

test "reset players uses native alternating 80-unit layout" {
    var players = [_]PlayerState{
        .{ .index = 0, .pos = .{} },
        .{ .index = 1, .pos = .{} },
    };

    resetPlayers(players[0..], 1024.0, null);

    try std.testing.expectEqual(@as(state_mod.Vec2, .{ .x = 512.0, .y = 512.0 }), players[0].pos);
    try std.testing.expectEqual(@as(state_mod.Vec2, .{ .x = 432.0, .y = 432.0 }), players[1].pos);
    try std.testing.expectEqual(@as(f32, 0.0), players[0].spread_heat);
    try std.testing.expectEqual(@as(f32, 0.0), players[1].spread_heat);
}
