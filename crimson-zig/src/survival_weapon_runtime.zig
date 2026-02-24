const std = @import("std");

const survival_state = @import("survival_state.zig");

pub const TickInputFlags = struct {
    fire_down: bool = false,
    fire_pressed: bool = false,
    reload_pressed: bool = false,
};

pub fn stepPlayerForTick(
    state: *survival_state.GameplayState,
    player: *survival_state.PlayerState,
    input_flags: TickInputFlags,
    dt: f64,
) void {
    const dt_f32 = asF32F64(dt);
    if (!(dt_f32 > 0.0)) return;

    if (input_flags.fire_down) {
        state.survival_reward_fire_seen = true;
    }

    const cooldown_scale: f64 = if (state.bonuses.weapon_power_up > 0.0) 1.5 else 1.0;
    const cooldown_decay = asF32F64(dt_f32 * cooldown_scale);
    player.shot_cooldown = @max(0.0, asF32F64(player.shot_cooldown - cooldown_decay));
    if (player.shot_cooldown > 0.0 and player.shot_cooldown < 1e-6) {
        player.shot_cooldown = 0.0;
    }

    if (player.reload_timer > 0.0) {
        player.reload_timer = asF32F64(player.reload_timer - dt_f32);
        if (player.reload_timer < 0.0) {
            player.reload_timer = 0.0;
        }
        if (player.reload_active and player.reload_timer == 0.0) {
            player.reload_active = false;
            player.ammo = @floatFromInt(@max(0, player.clip_size));
        }
    }

    if (input_flags.reload_pressed and !state.demo_mode_active and player.reload_timer == 0.0) {
        const clip_size_f64: f64 = @floatFromInt(@max(0, player.clip_size));
        if (player.ammo < clip_size_f64) {
            survival_state.playerStartReload(player, state);
        }
    }

    if (input_flags.fire_down) {
        _ = tryFireWeapon(state, player);
    }
}

pub fn tryFireWeapon(
    state: *survival_state.GameplayState,
    player: *survival_state.PlayerState,
) bool {
    if (player.shot_cooldown > 0.0) return false;
    if (player.reload_timer > 0.0) return false;

    const shot_cooldown = survival_state.weaponShotCooldown(player.weapon_id);
    player.shot_cooldown = @max(0.0, shot_cooldown);

    const shot_count = computeShotCount(player.weapon_id, player.ammo);
    if (shot_count <= 0) return false;

    const player_idx = player.index;
    if (player_idx >= 0 and player_idx < state.shots_fired.len) {
        const idx: usize = @intCast(player_idx);
        state.shots_fired[idx] += shot_count;
        if (player.weapon_id >= 0 and player.weapon_id < survival_state.weapon_count_size) {
            state.weapon_shots_fired[idx][@intCast(player.weapon_id)] += shot_count;
        }
    }
    state.shots_fired_total += shot_count;

    const ammo_cost = computeAmmoCost(player.weapon_id, shot_count);
    if (state.bonuses.reflex_boost <= 0.0) {
        player.ammo -= ammo_cost;
    }

    player.shot_seq += 1;

    if (player.ammo <= 0.0 and player.reload_timer <= 0.0) {
        survival_state.playerStartReload(player, state);
    }

    return true;
}

fn computeShotCount(
    weapon_id: i32,
    ammo: f64,
) i32 {
    return switch (weapon_id) {
        10 => 5, // Multi-Plasma
        14 => 14, // Plasma Shotgun
        17 => @max(1, @as(i32, @intFromFloat(@floor(@max(0.0, ammo))))), // Mini-Rocket Swarmers
        30 => 6, // Gauss Shotgun
        31 => 8, // Ion Shotgun
        else => @max(1, survival_state.weaponPelletCount(weapon_id)),
    };
}

fn computeAmmoCost(
    weapon_id: i32,
    shot_count: i32,
) f64 {
    return switch (weapon_id) {
        8 => 0.1, // Flamethrower
        15 => 0.05, // Blow Torch
        16 => 0.1, // HR Flamer
        17 => @floatFromInt(shot_count), // Mini-Rocket Swarmers
        42 => 0.15, // Bubblegun
        else => 1.0,
    };
}

fn asF32F64(value: f64) f64 {
    const rounded: f32 = @floatCast(value);
    return @floatCast(rounded);
}

test "weapon usage tracks most used weapon" {
    var state = survival_state.GameplayState.init(1);
    var player = survival_state.PlayerState{
        .index = 0,
        .pos = .{},
    };

    survival_state.weaponAssignPlayer(&player, survival_state.WeaponId.pistol);
    try std.testing.expect(tryFireWeapon(&state, &player));
    try std.testing.expectEqual(@as(i32, 1), state.weapon_shots_fired[0][1]);

    survival_state.weaponAssignPlayer(&player, survival_state.WeaponId.assault_rifle);
    for (0..3) |_| {
        player.shot_cooldown = 0.0;
        try std.testing.expect(tryFireWeapon(&state, &player));
    }
    try std.testing.expectEqual(@as(i32, 3), state.weapon_shots_fired[0][2]);

    const most_used = survival_state.mostUsedWeaponIdForPlayer(state, 0, survival_state.WeaponId.pistol);
    try std.testing.expectEqual(survival_state.WeaponId.assault_rifle, most_used);
}

test "weapon runtime starts reload when ammo is depleted" {
    var state = survival_state.GameplayState.init(1);
    var player = survival_state.PlayerState{
        .index = 0,
        .pos = .{},
    };
    survival_state.weaponAssignPlayer(&player, survival_state.WeaponId.pistol);
    player.ammo = 1.0;

    try std.testing.expect(tryFireWeapon(&state, &player));
    try std.testing.expect(player.reload_active);
    try std.testing.expect(player.reload_timer > 0.0);
    try std.testing.expectEqual(@as(i32, 1), state.shots_fired[0]);

    const reload_time = player.reload_timer;
    stepPlayerForTick(
        &state,
        &player,
        .{},
        reload_time * 0.5,
    );
    try std.testing.expect(player.reload_active);
    try std.testing.expect(player.reload_timer > 0.0);

    stepPlayerForTick(
        &state,
        &player,
        .{},
        reload_time * 0.5 + 0.001,
    );
    try std.testing.expect(!player.reload_active);
    try std.testing.expectEqual(@as(f64, @floatFromInt(player.clip_size)), player.ammo);
}

test "multi plasma and mini rocket use special shot counts" {
    var state = survival_state.GameplayState.init(1);
    var player = survival_state.PlayerState{
        .index = 0,
        .pos = .{},
    };

    survival_state.weaponAssignPlayer(&player, 10);
    try std.testing.expect(tryFireWeapon(&state, &player));
    try std.testing.expectEqual(@as(i32, 5), state.shots_fired[0]);

    survival_state.weaponAssignPlayer(&player, 17);
    player.ammo = 4.0;
    player.shot_cooldown = 0.0;
    try std.testing.expect(tryFireWeapon(&state, &player));
    try std.testing.expectEqual(@as(i32, 9), state.shots_fired[0]);
    try std.testing.expect(player.reload_active);
}
