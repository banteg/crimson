const std = @import("std");

const survival_projectiles = @import("survival_projectiles.zig");
const survival_state = @import("survival_state.zig");

pub const WeaponRuntimeError = error{
    UnsupportedWeaponFirePath,
};

const perk_id_sharpshooter: i32 = 2;
const perk_id_fastshot: i32 = 14;

pub const TickInputFlags = struct {
    fire_down: bool = false,
    fire_pressed: bool = false,
    reload_pressed: bool = false,
};

pub fn stepPlayerForTick(
    state: *survival_state.GameplayState,
    player: *survival_state.PlayerState,
    projectiles: *survival_projectiles.ProjectilePool,
    input_flags: TickInputFlags,
    dt: f64,
) WeaponRuntimeError!void {
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

    if (perkActive(player.*, perk_id_sharpshooter)) {
        player.spread_heat = 0.02;
    } else {
        player.spread_heat = @max(0.01, asF32F64(player.spread_heat - dt_f32 * 0.4));
    }

    if (input_flags.fire_down) {
        _ = try tryFireWeapon(state, player, projectiles);
    }
}

pub fn tryFireWeapon(
    state: *survival_state.GameplayState,
    player: *survival_state.PlayerState,
    projectiles: *survival_projectiles.ProjectilePool,
) WeaponRuntimeError!bool {
    if (player.shot_cooldown > 0.0) return false;
    if (player.reload_timer > 0.0) return false;

    const weapon_id = player.weapon_id;
    const shot_cooldown_base = survival_state.weaponShotCooldown(weapon_id);
    const pellet_count = @max(0, survival_state.weaponPelletCount(weapon_id));
    const weapon_spread_heat = survival_state.weaponSpreadHeatInc(weapon_id);
    const fire_bullets_weapon_id = 45;
    const fire_bullets_spread_heat = survival_state.weaponSpreadHeatInc(fire_bullets_weapon_id);

    var shot_cooldown = shot_cooldown_base;

    const shot_count = computeShotCount(player.weapon_id, player.ammo);
    if (shot_count <= 0) return false;

    const aim_delta = survival_state.Vec2.sub(player.aim, player.pos);
    const aim_heading = if (aim_delta.lengthSq() > 1e-9)
        std.math.atan2(aim_delta.y, aim_delta.x)
    else
        std.math.atan2(player.aim_dir.y, player.aim_dir.x);
    const muzzle_dir = survival_state.Vec2.fromAngle(aim_heading - 0.150915);
    const muzzle = survival_state.Vec2.add(player.pos, muzzle_dir.mul(16.0));
    const projectile_owner_id: i32 = -100;
    const is_fire_bullets = player.fire_bullets_timer > 0.0;
    if (is_fire_bullets and pellet_count == 1) {
        shot_cooldown = survival_state.weaponShotCooldown(fire_bullets_weapon_id);
    }
    if (perkActive(player.*, perk_id_fastshot)) {
        shot_cooldown = asF32F64(shot_cooldown * 0.88);
    }
    if (perkActive(player.*, perk_id_sharpshooter)) {
        shot_cooldown = asF32F64(shot_cooldown * 1.05);
    }
    player.shot_cooldown = @max(0.0, shot_cooldown);

    const weapon_flags = survival_state.weaponFlags(player.weapon_id);

    if ((weapon_flags & 0x1) != 0) {
        // spawn_shell_casing randoms: angle speed rotation rotation_step.
        _ = state.rng.rand();
        _ = state.rng.rand();
        _ = state.rng.rand();
        _ = state.rng.rand();
    }

    const dist = aim_delta.length();
    const max_offset = dist * player.spread_heat * 0.5;
    const dir_angle = @as(f64, @floatFromInt(state.rng.rand() & 0x1ff)) * (std.math.tau / 512.0);
    const mag = @as(f64, @floatFromInt(state.rng.rand() & 0x1ff)) * (1.0 / 512.0);
    const offset = max_offset * mag;
    const aim_jitter = survival_state.Vec2.add(player.aim, survival_state.Vec2.fromAngle(dir_angle).mul(offset));
    const shot_angle = std.math.atan2(aim_jitter.y - player.pos.y, aim_jitter.x - player.pos.x);

    if (!is_fire_bullets) {
        // fire SFX variant selection.
        _ = state.rng.rand();
    }

    const spawn_muzzle_after_projectile = is_fire_bullets or
        player.weapon_id == survival_state.WeaponId.pistol or
        player.weapon_id == survival_state.WeaponId.shrinkifier_5k;
    if (!spawn_muzzle_after_projectile) {
        consumeMuzzleSpriteRng(state, player.weapon_id, is_fire_bullets);
    }

    if (is_fire_bullets) {
        const meta = survival_state.weaponProjectileMeta(survival_state.ProjectileTypeId.fire_bullets);
        var i: i32 = 0;
        while (i < shot_count) : (i += 1) {
            const jitter = @as(f64, @floatFromInt(@as(i32, @intCast(state.rng.rand() % 200)) - 100)) * 0.0015;
            _ = projectiles.spawn(
                muzzle,
                shot_angle + jitter,
                survival_state.ProjectileTypeId.fire_bullets,
                projectile_owner_id,
                meta,
                false,
            );
        }
    } else switch (player.weapon_id) {
        10 => {
            const spread_small = std.math.pi / 10.0;
            const spread_large = std.math.pi / 6.0;
            _ = projectiles.spawn(muzzle, shot_angle - spread_small, survival_state.ProjectileTypeId.plasma_rifle, projectile_owner_id, survival_state.weaponProjectileMeta(survival_state.ProjectileTypeId.plasma_rifle), false);
            _ = projectiles.spawn(muzzle, shot_angle - spread_large, survival_state.ProjectileTypeId.plasma_minigun, projectile_owner_id, survival_state.weaponProjectileMeta(survival_state.ProjectileTypeId.plasma_minigun), false);
            _ = projectiles.spawn(muzzle, shot_angle, survival_state.ProjectileTypeId.plasma_rifle, projectile_owner_id, survival_state.weaponProjectileMeta(survival_state.ProjectileTypeId.plasma_rifle), false);
            _ = projectiles.spawn(muzzle, shot_angle + spread_large, survival_state.ProjectileTypeId.plasma_minigun, projectile_owner_id, survival_state.weaponProjectileMeta(survival_state.ProjectileTypeId.plasma_minigun), false);
            _ = projectiles.spawn(muzzle, shot_angle + spread_small, survival_state.ProjectileTypeId.plasma_rifle, projectile_owner_id, survival_state.weaponProjectileMeta(survival_state.ProjectileTypeId.plasma_rifle), false);
        },
        14 => {
            const meta = survival_state.weaponProjectileMeta(survival_state.ProjectileTypeId.plasma_minigun);
            var i: i32 = 0;
            while (i < 14) : (i += 1) {
                const jitter = @as(f64, @floatFromInt(@as(i32, @intCast(state.rng.rand() & 0xff)) - 0x80)) * 0.002;
                const id = projectiles.spawn(
                    muzzle,
                    shot_angle + jitter,
                    survival_state.ProjectileTypeId.plasma_minigun,
                    projectile_owner_id,
                    meta,
                    false,
                );
                projectiles.entries[id].speed_scale = 1.0 + @as(f64, @floatFromInt(state.rng.rand() % 100)) * 0.01;
            }
        },
        30 => {
            const meta = survival_state.weaponProjectileMeta(survival_state.ProjectileTypeId.gauss_gun);
            var i: i32 = 0;
            while (i < 6) : (i += 1) {
                const jitter = @as(f64, @floatFromInt(@as(i32, @intCast(state.rng.rand() % 200)) - 100)) * 0.002;
                const id = projectiles.spawn(
                    muzzle,
                    shot_angle + jitter,
                    survival_state.ProjectileTypeId.gauss_gun,
                    projectile_owner_id,
                    meta,
                    false,
                );
                projectiles.entries[id].speed_scale = 1.4 + @as(f64, @floatFromInt(state.rng.rand() % 0x50)) * 0.01;
            }
        },
        31 => {
            const meta = survival_state.weaponProjectileMeta(survival_state.ProjectileTypeId.ion_minigun);
            var i: i32 = 0;
            while (i < 8) : (i += 1) {
                const jitter = @as(f64, @floatFromInt(@as(i32, @intCast(state.rng.rand() % 200)) - 100)) * 0.0026;
                const id = projectiles.spawn(
                    muzzle,
                    shot_angle + jitter,
                    survival_state.ProjectileTypeId.ion_minigun,
                    projectile_owner_id,
                    meta,
                    false,
                );
                projectiles.entries[id].speed_scale = 1.4 + @as(f64, @floatFromInt(state.rng.rand() % 0x50)) * 0.01;
            }
        },
        8, 12, 13, 15, 16, 17, 18, 42 => return error.UnsupportedWeaponFirePath,
        else => {
            const type_id = survival_state.projectileTypeIdFromWeaponId(player.weapon_id) orelse return error.UnsupportedWeaponFirePath;
            const meta = survival_state.weaponProjectileMeta(type_id);
            const pellets = @max(1, survival_state.weaponPelletCount(player.weapon_id));
            var i: i32 = 0;
            while (i < pellets) : (i += 1) {
                var angle = aim_heading;
                if (pellets > 1) {
                    const jitter_step = pelletJitterStep(player.weapon_id);
                    angle += @as(f64, @floatFromInt(@as(i32, @intCast(state.rng.rand() % 200)) - 100)) * jitter_step;
                } else {
                    angle = shot_angle;
                }
                const id = projectiles.spawn(
                    muzzle,
                    angle,
                    type_id,
                    projectile_owner_id,
                    meta,
                    false,
                );
                if (pellets > 1 and
                    (player.weapon_id == 3 or player.weapon_id == 4 or player.weapon_id == 20))
                {
                    projectiles.entries[id].speed_scale = 1.0 + @as(f64, @floatFromInt(state.rng.rand() % 100)) * 0.01;
                }
            }
        },
    }

    if (spawn_muzzle_after_projectile) {
        consumeMuzzleSpriteRng(state, player.weapon_id, is_fire_bullets);
    }

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

    if (!perkActive(player.*, perk_id_sharpshooter)) {
        const spread_heat_base = if (is_fire_bullets) fire_bullets_spread_heat else weapon_spread_heat;
        const spread_inc = asF32F64(spread_heat_base * 1.3);
        player.spread_heat = std.math.clamp(
            asF32F64(player.spread_heat + spread_inc),
            0.0,
            0.48,
        );
    }

    if (player.ammo <= 0.0 and player.reload_timer <= 0.0) {
        survival_state.playerStartReload(player, state);
    }

    return true;
}

fn pelletJitterStep(weapon_id: i32) f64 {
    return switch (weapon_id) {
        3, 20 => 0.0013,
        4 => 0.004,
        else => 0.0015,
    };
}

fn consumeMuzzleSpriteRng(
    state: *survival_state.GameplayState,
    weapon_id: i32,
    fire_bullets_active: bool,
) void {
    var count: usize = 0;
    if (fire_bullets_active) {
        count = 1;
    } else {
        count = switch (weapon_id) {
            1, 2, 3, 4, 5, 6, 12, 13, 17, 24, 30 => 2,
            18, 20 => 1,
            else => 0,
        };
    }
    for (0..count) |_| {
        _ = state.rng.rand();
    }
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

fn perkActive(player: survival_state.PlayerState, perk_id: i32) bool {
    if (perk_id < 0 or perk_id >= player.perk_counts.len) return false;
    return player.perk_counts[@intCast(perk_id)] > 0;
}

test "weapon usage tracks most used weapon" {
    var state = survival_state.GameplayState.init(1);
    var projectiles = survival_projectiles.ProjectilePool{};
    var player = survival_state.PlayerState{
        .index = 0,
        .pos = .{},
    };

    survival_state.weaponAssignPlayer(&player, survival_state.WeaponId.pistol);
    try std.testing.expect(try tryFireWeapon(&state, &player, &projectiles));
    try std.testing.expectEqual(@as(i32, 1), state.weapon_shots_fired[0][1]);

    survival_state.weaponAssignPlayer(&player, survival_state.WeaponId.assault_rifle);
    for (0..3) |_| {
        player.shot_cooldown = 0.0;
        try std.testing.expect(try tryFireWeapon(&state, &player, &projectiles));
    }
    try std.testing.expectEqual(@as(i32, 3), state.weapon_shots_fired[0][2]);

    const most_used = survival_state.mostUsedWeaponIdForPlayer(state, 0, survival_state.WeaponId.pistol);
    try std.testing.expectEqual(survival_state.WeaponId.assault_rifle, most_used);
}

test "weapon runtime starts reload when ammo is depleted" {
    var state = survival_state.GameplayState.init(1);
    var projectiles = survival_projectiles.ProjectilePool{};
    var player = survival_state.PlayerState{
        .index = 0,
        .pos = .{},
    };
    survival_state.weaponAssignPlayer(&player, survival_state.WeaponId.pistol);
    player.ammo = 1.0;

    try std.testing.expect(try tryFireWeapon(&state, &player, &projectiles));
    try std.testing.expect(player.reload_active);
    try std.testing.expect(player.reload_timer > 0.0);
    try std.testing.expectEqual(@as(i32, 1), state.shots_fired[0]);

    const reload_time = player.reload_timer;
    try stepPlayerForTick(
        &state,
        &player,
        &projectiles,
        .{},
        reload_time * 0.5,
    );
    try std.testing.expect(player.reload_active);
    try std.testing.expect(player.reload_timer > 0.0);

    try stepPlayerForTick(
        &state,
        &player,
        &projectiles,
        .{},
        reload_time * 0.5 + 0.001,
    );
    try std.testing.expect(!player.reload_active);
    try std.testing.expectEqual(@as(f64, @floatFromInt(player.clip_size)), player.ammo);
}

test "multi plasma and mini rocket use special shot counts" {
    var state = survival_state.GameplayState.init(1);
    var projectiles = survival_projectiles.ProjectilePool{};
    var player = survival_state.PlayerState{
        .index = 0,
        .pos = .{},
    };

    survival_state.weaponAssignPlayer(&player, 10);
    try std.testing.expect(try tryFireWeapon(&state, &player, &projectiles));
    try std.testing.expectEqual(@as(i32, 5), state.shots_fired[0]);

    survival_state.weaponAssignPlayer(&player, 17);
    player.ammo = 4.0;
    player.shot_cooldown = 0.0;
    try std.testing.expectError(
        error.UnsupportedWeaponFirePath,
        tryFireWeapon(&state, &player, &projectiles),
    );
}

test "pistol fire consumes native casing+jitter+sfx rng draws" {
    var state = survival_state.GameplayState.init(123);
    var player = survival_state.PlayerState{
        .index = 0,
        .pos = .{},
    };
    var projectiles = survival_projectiles.ProjectilePool{};
    survival_state.weaponAssignPlayer(&player, survival_state.WeaponId.pistol);
    try std.testing.expect(try tryFireWeapon(&state, &player, &projectiles));
    try std.testing.expect(projectiles.entries[0].active);
}
