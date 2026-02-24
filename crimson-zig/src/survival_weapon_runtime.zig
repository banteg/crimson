const std = @import("std");

const survival_creatures = @import("survival_creatures.zig");
const survival_particles = @import("survival_particles.zig");
const survival_projectiles = @import("survival_projectiles.zig");
const survival_secondary_projectiles = @import("survival_secondary_projectiles.zig");
const survival_state = @import("survival_state.zig");
const survival_math = @import("survival_math.zig");

pub const WeaponRuntimeError = error{
    UnsupportedWeaponFirePath,
};

const perk_id_sharpshooter: i32 = 2;
const perk_id_fastshot: i32 = 14;
const perk_id_regression_bullets: i32 = 23;
const perk_id_ammunition_within: i32 = 35;
const perk_id_alternate_weapon: i32 = 9;
const perk_id_hot_tempered: i32 = 31;
const perk_id_man_bomb: i32 = 53;
const perk_id_fire_caugh: i32 = 54;
const perk_id_living_fortress: i32 = 55;
const reload_preload_underflow_eps: f64 = 1e-7;
const movement_control_mouse_point_click: i32 = 4;

pub const TickInputFlags = struct {
    fire_down: bool = false,
    fire_pressed: bool = false,
    reload_pressed: bool = false,
    move_mode: i32 = 0,
};

pub fn stepPlayerForTick(
    state: *survival_state.GameplayState,
    player: *survival_state.PlayerState,
    projectiles: *survival_projectiles.ProjectilePool,
    secondary_projectiles: *survival_secondary_projectiles.SecondaryProjectilePool,
    creatures: *survival_creatures.CreaturePool,
    particles: *survival_particles.ParticlePool,
    input_flags: TickInputFlags,
    dt: f64,
) WeaponRuntimeError!void {
    const dt_f32 = asF32F64(dt);
    if (!(dt_f32 > 0.0)) return;

    if (player.health <= 0.0) {
        player.death_timer = asF32F64(player.death_timer - dt_f32 * 20.0);
        return;
    }

    if (player.low_health_timer != 100.0 and player.health < 20.0) {
        const next_low_health_timer = asF32F64(player.low_health_timer - dt_f32);
        player.low_health_timer = next_low_health_timer;
        if (next_low_health_timer < 0.0) {
            consumeLowHealthPulseRng(state);
            player.low_health_timer = 1.0;
        }
    }

    if (input_flags.fire_down) {
        state.survival_reward_fire_seen = true;
    }

    const cooldown_scale: f64 = if (state.bonuses.weapon_power_up > 0.0) 1.5 else 1.0;
    const cooldown_decay = asF32F64(dt_f32 * cooldown_scale);
    player.shot_cooldown = @max(0.0, asF32F64(player.shot_cooldown - cooldown_decay));
    if (player.shot_cooldown > 0.0 and player.shot_cooldown < 1e-6) {
        player.shot_cooldown = 0.0;
    }

    const reload_timer_now = asF32F64(player.reload_timer);
    const preload_dt = dt_f32;
    const reload_preload_underflow = asF32F64(reload_timer_now - preload_dt);
    const preload_crossed = reload_preload_underflow < -reload_preload_underflow_eps;
    const preload_fire_boundary = input_flags.fire_down and reload_preload_underflow <= reload_preload_underflow_eps;
    if (player.reload_active and reload_timer_now > 0.0 and (preload_crossed or preload_fire_boundary)) {
        player.ammo = @floatFromInt(@max(0, player.clip_size));
    }

    if (player.reload_timer > 0.0) {
        player.reload_timer = asF32F64(player.reload_timer - dt_f32);
        if (player.reload_timer < 0.0) {
            player.reload_timer = 0.0;
        }
    }

    const manual_reload_allowed =
        input_flags.reload_pressed and
        !state.demo_mode_active and
        !perkActive(player.*, perk_id_alternate_weapon) and
        input_flags.move_mode != movement_control_mouse_point_click and
        player.reload_timer == 0.0;
    if (manual_reload_allowed) {
        const clip_size_f64: f64 = @floatFromInt(@max(0, player.clip_size));
        if (player.ammo < clip_size_f64) {
            survival_state.playerStartReload(player, state);
        }
    }

    if (perkActive(player.*, perk_id_sharpshooter)) {
        player.spread_heat = 0.02;
    } else {
        player.spread_heat = @max(0.01, player.spread_heat - dt * 0.4);
    }

    if (player.shot_cooldown <= 0.0 and player.reload_timer == 0.0) {
        player.reload_active = false;
    }

    if (input_flags.fire_down) {
        _ = try tryFireWeapon(
            state,
            player,
            projectiles,
            secondary_projectiles,
            creatures,
            particles,
        );
    }
}

pub fn tryFireWeapon(
    state: *survival_state.GameplayState,
    player: *survival_state.PlayerState,
    projectiles: *survival_projectiles.ProjectilePool,
    secondary_projectiles: *survival_secondary_projectiles.SecondaryProjectilePool,
    creatures: *survival_creatures.CreaturePool,
    particles: *survival_particles.ParticlePool,
) WeaponRuntimeError!bool {
    if (player.shot_cooldown > 0.0) return false;
    const weapon_id = player.weapon_id;
    if (player.reload_timer > 0.0) {
        if (player.experience <= 0) return false;

        if (perkActive(player.*, perk_id_regression_bullets)) {
            const reload_time = survival_state.weaponReloadTime(weapon_id);
            const factor: f64 = if (weaponUsesFireAmmoClass(weapon_id)) 4.0 else 200.0;
            const drained = reload_time * factor;
            const before: f64 = @floatFromInt(player.experience);
            var after: i32 = @intFromFloat(before - drained);
            if (after < 0) after = 0;
            player.experience = after;
        } else if (perkActive(player.*, perk_id_ammunition_within)) {
            const health_cost: f64 = if (weaponUsesFireAmmoClass(weapon_id))
                @as(f64, 0.15)
            else
                @as(f64, 1.0);
            survival_creatures.applyPlayerContactDamage(
                state,
                player,
                health_cost,
                0.0,
            );
        } else {
            return false;
        }
    }

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
        aim_delta.toHeading()
    else
        player.aim_dir.toHeading();
    const muzzle_dir = rotateVec(directionFromHeading(aim_heading), -0.150915);
    const muzzle = survival_state.Vec2.add(player.pos, muzzle_dir.mul(16.0));
    const projectile_owner_id: i32 = -100;
    const secondary_owner_id: i32 = -1 - player.index;
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
    const shot_angle = survival_state.Vec2.sub(aim_jitter, player.pos).toHeading();
    var particle_angle = directionFromHeading(shot_angle).toAngle();
    if (player.weapon_id == 8 or player.weapon_id == 15 or player.weapon_id == 16) {
        particle_angle = directionFromHeading(aim_heading).toAngle();
    }

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
        8 => {
            _ = particles.spawnParticle(
                state,
                muzzle,
                particle_angle,
                1.0,
                -100,
            );
        },
        15 => {
            const particle_id = particles.spawnParticle(
                state,
                muzzle,
                particle_angle,
                1.0,
                -100,
            );
            particles.entries[particle_id].style_id = survival_particles.ParticleStyleId.blow_torch;
        },
        16 => {
            const particle_id = particles.spawnParticle(
                state,
                muzzle,
                particle_angle,
                1.0,
                -100,
            );
            particles.entries[particle_id].style_id = survival_particles.ParticleStyleId.hr_flamer;
        },
        42 => {
            _ = particles.spawnParticleSlow(
                state,
                muzzle,
                directionFromHeading(shot_angle).toAngle(),
                -100,
            );
        },
        12 => {
            _ = secondary_projectiles.spawn(
                muzzle,
                shot_angle,
                survival_secondary_projectiles.SecondaryProjectileTypeId.rocket,
                secondary_owner_id,
                2.0,
                null,
                creatures,
            );
        },
        13 => {
            _ = secondary_projectiles.spawn(
                muzzle,
                shot_angle,
                survival_secondary_projectiles.SecondaryProjectileTypeId.homing_rocket,
                secondary_owner_id,
                2.0,
                player.aim,
                creatures,
            );
        },
        17 => {
            const rocket_count = shot_count;
            const spread = std.math.pi * (2.0 / 3.0);
            const step = if (rocket_count <= 1)
                0.0
            else
                spread / @as(f64, @floatFromInt(rocket_count - 1));
            var angle = shot_angle - spread * 0.5;
            var i: i32 = 0;
            while (i < rocket_count) : (i += 1) {
                _ = secondary_projectiles.spawn(
                    muzzle,
                    angle,
                    survival_secondary_projectiles.SecondaryProjectileTypeId.homing_rocket,
                    secondary_owner_id,
                    2.0,
                    player.aim,
                    creatures,
                );
                angle = asF32F64(angle + step);
            }
        },
        18 => {
            _ = secondary_projectiles.spawn(
                muzzle,
                shot_angle,
                survival_secondary_projectiles.SecondaryProjectileTypeId.rocket_minigun,
                secondary_owner_id,
                2.0,
                null,
                creatures,
            );
        },
        else => {
            const type_id = survival_state.projectileTypeIdFromWeaponId(player.weapon_id) orelse return error.UnsupportedWeaponFirePath;
            const meta = survival_state.weaponProjectileMeta(type_id);
            const pellets = @max(1, survival_state.weaponPelletCount(player.weapon_id));
            var i: i32 = 0;
            while (i < pellets) : (i += 1) {
                var angle = shot_angle;
                if (pellets > 1) {
                    const jitter_step = pelletJitterStep(player.weapon_id);
                    angle += @as(f64, @floatFromInt(@as(i32, @intCast(state.rng.rand() % 200)) - 100)) * jitter_step;
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
    if (state.bonuses.reflex_boost <= 0.0 and !is_fire_bullets) {
        player.ammo -= ammo_cost;
    }

    player.shot_seq += 1;

    if (!perkActive(player.*, perk_id_sharpshooter)) {
        const spread_heat_base = if (is_fire_bullets) fire_bullets_spread_heat else weapon_spread_heat;
        const spread_inc = spread_heat_base * 1.3;
        player.spread_heat = std.math.clamp(
            player.spread_heat + spread_inc,
            0.0,
            0.48,
        );
    }

    if (player.ammo <= 0.0 and player.reload_timer <= 0.0) {
        survival_state.playerStartReload(player, state);
    }

    return true;
}

pub fn applyPlayerPerkTicks(
    state: *survival_state.GameplayState,
    player: *survival_state.PlayerState,
    projectiles: *survival_projectiles.ProjectilePool,
    dt: f64,
) void {
    tickManBomb(state, player, projectiles, dt);
    tickLivingFortress(player, dt);
    tickFireCaugh(state, player, projectiles, dt);
    tickHotTempered(state, player, projectiles, dt);
}

fn tickManBomb(
    state: *survival_state.GameplayState,
    player: *survival_state.PlayerState,
    projectiles: *survival_projectiles.ProjectilePool,
    dt: f64,
) void {
    if (!perkActive(player.*, perk_id_man_bomb)) {
        player.man_bomb_timer = 0.0;
        return;
    }

    player.man_bomb_timer += dt;
    if (player.man_bomb_timer <= state.perk_interval_man_bomb) return;

    const owner_id: i32 = if (!state.friendly_fire_enabled) -100 else -1 - player.index;
    for (0..8) |idx| {
        const type_id = if ((idx & 1) == 0)
            survival_state.ProjectileTypeId.ion_minigun
        else
            survival_state.ProjectileTypeId.ion_rifle;
        const angle =
            @as(f64, @floatFromInt(state.rng.rand() % 50)) * 0.01 +
            @as(f64, @floatFromInt(idx)) * (std.math.pi / 4.0) - 0.25;
        spawnPerkProjectile(
            state,
            player,
            projectiles,
            player.pos,
            angle,
            type_id,
            owner_id,
        );
    }
    player.man_bomb_timer -= state.perk_interval_man_bomb;
    state.perk_interval_man_bomb = 4.0;
}

fn tickLivingFortress(
    player: *survival_state.PlayerState,
    dt: f64,
) void {
    if (perkActive(player.*, perk_id_living_fortress)) {
        player.living_fortress_timer = @min(30.0, player.living_fortress_timer + dt);
    } else {
        player.living_fortress_timer = 0.0;
    }
}

fn tickFireCaugh(
    state: *survival_state.GameplayState,
    player: *survival_state.PlayerState,
    projectiles: *survival_projectiles.ProjectilePool,
    dt: f64,
) void {
    if (!perkActive(player.*, perk_id_fire_caugh)) {
        player.fire_cough_timer = 0.0;
        return;
    }

    player.fire_cough_timer += dt;
    if (player.fire_cough_timer <= state.perk_interval_fire_cough) return;

    const owner_id: i32 = if (!state.friendly_fire_enabled) -100 else -1 - player.index;
    const aim_heading = player.aim_heading;
    const origin_pos = player.pos;
    const muzzle = survival_state.Vec2.add(
        origin_pos,
        rotateVec(directionFromHeading(aim_heading), -0.150915).mul(16.0),
    );
    const aim_delta = survival_state.Vec2.sub(player.aim, origin_pos);
    const dist = aim_delta.length();
    const max_offset = dist * player.spread_heat * 0.5;
    const dir_angle = @as(f64, @floatFromInt(state.rng.rand() & 0x1ff)) * (std.math.tau / 512.0);
    const mag = @as(f64, @floatFromInt(state.rng.rand() & 0x1ff)) * (1.0 / 512.0);
    const offset = max_offset * mag;
    const jitter = survival_state.Vec2.add(
        player.aim,
        survival_state.Vec2.fromAngle(dir_angle).mul(offset),
    );
    const angle = survival_state.Vec2.sub(jitter, origin_pos).toHeading();
    spawnPerkProjectile(
        state,
        player,
        projectiles,
        muzzle,
        angle,
        survival_state.ProjectileTypeId.fire_bullets,
        owner_id,
    );

    // sprite_effects.spawn(...): slot scan + one rotation RNG draw in common case.
    _ = state.rng.rand() % 0x274;

    player.fire_cough_timer -= state.perk_interval_fire_cough;
    state.perk_interval_fire_cough = @as(f64, @floatFromInt(state.rng.rand() % 4)) + 2.0;
}

fn tickHotTempered(
    state: *survival_state.GameplayState,
    player: *survival_state.PlayerState,
    projectiles: *survival_projectiles.ProjectilePool,
    dt: f64,
) void {
    if (!perkActive(player.*, perk_id_hot_tempered)) {
        player.hot_tempered_timer = 0.0;
        return;
    }

    player.hot_tempered_timer += dt;
    if (player.hot_tempered_timer <= state.perk_interval_hot_tempered) return;

    const owner_id: i32 = if (state.friendly_fire_enabled) -1 - player.index else -100;
    for (0..8) |idx| {
        const type_id = if ((idx & 1) == 0)
            survival_state.ProjectileTypeId.plasma_minigun
        else
            survival_state.ProjectileTypeId.plasma_rifle;
        const angle = @as(f64, @floatFromInt(idx)) * (std.math.pi / 4.0);
        spawnPerkProjectile(
            state,
            player,
            projectiles,
            player.pos,
            angle,
            type_id,
            owner_id,
        );
    }

    player.hot_tempered_timer -= state.perk_interval_hot_tempered;
    state.perk_interval_hot_tempered = @as(f64, @floatFromInt(state.rng.rand() % 8)) + 2.0;
}

fn spawnPerkProjectile(
    state: *survival_state.GameplayState,
    player: *const survival_state.PlayerState,
    projectiles: *survival_projectiles.ProjectilePool,
    pos: survival_state.Vec2,
    angle: f64,
    type_id: i32,
    owner_id: i32,
) void {
    var spawn_type_id = type_id;
    var shot_credit: i32 = 0;
    const player_owned_spawn = owner_id == -100 or owner_id == -1 or owner_id == -2 or owner_id == -3;
    if (!state.bonus_spawn_guard and player_owned_spawn) {
        shot_credit = 1;
        if (spawn_type_id != survival_state.ProjectileTypeId.fire_bullets and player.fire_bullets_timer > 0.0) {
            // `projectile_spawn` Fire Bullets override loops once, crediting shots twice.
            spawn_type_id = survival_state.ProjectileTypeId.fire_bullets;
            shot_credit = 2;
        }
    }

    const meta = survival_state.weaponProjectileMeta(spawn_type_id);
    _ = projectiles.spawn(
        pos,
        angle,
        spawn_type_id,
        owner_id,
        meta,
        false,
    );
    if (shot_credit > 0 and owner_id < 0 and state.shots_fired.len > 0) {
        const shooter_idx: usize = if (owner_id == -100)
            0
        else
            @min(@as(usize, @intCast(-1 - owner_id)), state.shots_fired.len - 1);
        state.shots_fired[shooter_idx] += shot_credit;
        state.shots_fired_total += shot_credit;
        if (shooter_idx < state.weapon_shots_fired.len and
            spawn_type_id >= 0 and spawn_type_id < state.weapon_shots_fired[shooter_idx].len)
        {
            state.weapon_shots_fired[shooter_idx][@intCast(spawn_type_id)] += shot_credit;
        }
    }
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

fn consumeLowHealthPulseRng(state: *survival_state.GameplayState) void {
    // `player_update` low-health pulse: 3x `spawn_blood_splatter` (10 draws each)
    // plus one bloodspill SFX-variant draw.
    for (0..3) |_| {
        for (0..2) |_| {
            _ = state.rng.rand();
            _ = state.rng.rand();
            _ = state.rng.rand();
            _ = state.rng.rand();
            _ = state.rng.rand();
        }
    }
    _ = state.rng.rand() & 1;
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

fn weaponUsesFireAmmoClass(weapon_id: i32) bool {
    // Mirrors `weapon.ammo_class == 1` in the Python weapon table.
    return weapon_id == 8 or weapon_id == 15 or weapon_id == 16;
}

fn asF32F64(value: f64) f64 {
    const rounded: f32 = @floatCast(value);
    return @floatCast(rounded);
}

fn directionFromHeading(heading: f64) survival_state.Vec2 {
    const radians = heading - std.math.pi / 2.0;
    return .{
        .x = survival_math.cos(radians),
        .y = survival_math.sin(radians),
    };
}

fn rotateVec(vec: survival_state.Vec2, theta: f64) survival_state.Vec2 {
    const cos_theta = survival_math.cos(theta);
    const sin_theta = survival_math.sin(theta);
    return .{
        .x = vec.x * cos_theta - vec.y * sin_theta,
        .y = vec.x * sin_theta + vec.y * cos_theta,
    };
}

fn perkActive(player: survival_state.PlayerState, perk_id: i32) bool {
    if (perk_id < 0 or perk_id >= player.perk_counts.len) return false;
    return player.perk_counts[@intCast(perk_id)] > 0;
}

test "weapon usage tracks most used weapon" {
    var state = survival_state.GameplayState.init(1);
    var projectiles = survival_projectiles.ProjectilePool{};
    var secondary_projectiles = survival_secondary_projectiles.SecondaryProjectilePool{};
    var creatures = survival_creatures.CreaturePool{};
    var particles = survival_particles.ParticlePool{};
    var player = survival_state.PlayerState{
        .index = 0,
        .pos = .{},
    };

    survival_state.weaponAssignPlayer(&player, survival_state.WeaponId.pistol);
    try std.testing.expect(try tryFireWeapon(&state, &player, &projectiles, &secondary_projectiles, &creatures, &particles));
    try std.testing.expectEqual(@as(i32, 1), state.weapon_shots_fired[0][1]);

    survival_state.weaponAssignPlayer(&player, survival_state.WeaponId.assault_rifle);
    for (0..3) |_| {
        player.shot_cooldown = 0.0;
        try std.testing.expect(try tryFireWeapon(&state, &player, &projectiles, &secondary_projectiles, &creatures, &particles));
    }
    try std.testing.expectEqual(@as(i32, 3), state.weapon_shots_fired[0][2]);

    const most_used = survival_state.mostUsedWeaponIdForPlayer(state, 0, survival_state.WeaponId.pistol);
    try std.testing.expectEqual(survival_state.WeaponId.assault_rifle, most_used);
}

test "weapon runtime starts reload when ammo is depleted" {
    var state = survival_state.GameplayState.init(1);
    var projectiles = survival_projectiles.ProjectilePool{};
    var secondary_projectiles = survival_secondary_projectiles.SecondaryProjectilePool{};
    var creatures = survival_creatures.CreaturePool{};
    var particles = survival_particles.ParticlePool{};
    var player = survival_state.PlayerState{
        .index = 0,
        .pos = .{},
    };
    survival_state.weaponAssignPlayer(&player, survival_state.WeaponId.pistol);
    player.ammo = 1.0;

    try std.testing.expect(try tryFireWeapon(&state, &player, &projectiles, &secondary_projectiles, &creatures, &particles));
    try std.testing.expect(player.reload_active);
    try std.testing.expect(player.reload_timer > 0.0);
    try std.testing.expectEqual(@as(i32, 1), state.shots_fired[0]);

    const reload_time = player.reload_timer;
    try stepPlayerForTick(
        &state,
        &player,
        &projectiles,
        &secondary_projectiles,
        &creatures,
        &particles,
        .{},
        reload_time * 0.5,
    );
    try std.testing.expect(player.reload_active);
    try std.testing.expect(player.reload_timer > 0.0);

    try stepPlayerForTick(
        &state,
        &player,
        &projectiles,
        &secondary_projectiles,
        &creatures,
        &particles,
        .{},
        reload_time * 0.5 + 0.001,
    );
    try std.testing.expect(!player.reload_active);
    try std.testing.expectEqual(@as(f64, @floatFromInt(player.clip_size)), player.ammo);
}

test "multi plasma and mini rocket use special shot counts" {
    var state = survival_state.GameplayState.init(1);
    var projectiles = survival_projectiles.ProjectilePool{};
    var secondary_projectiles = survival_secondary_projectiles.SecondaryProjectilePool{};
    var creatures = survival_creatures.CreaturePool{};
    var particles = survival_particles.ParticlePool{};
    var player = survival_state.PlayerState{
        .index = 0,
        .pos = .{},
    };

    survival_state.weaponAssignPlayer(&player, 10);
    try std.testing.expect(try tryFireWeapon(&state, &player, &projectiles, &secondary_projectiles, &creatures, &particles));
    try std.testing.expectEqual(@as(i32, 5), state.shots_fired[0]);

    survival_state.weaponAssignPlayer(&player, 17);
    player.ammo = 4.0;
    player.shot_cooldown = 0.0;
    try std.testing.expect(try tryFireWeapon(&state, &player, &projectiles, &secondary_projectiles, &creatures, &particles));
    try std.testing.expectEqual(@as(i32, 9), state.shots_fired[0]);
}

test "pistol fire consumes native casing+jitter+sfx rng draws" {
    var state = survival_state.GameplayState.init(123);
    var player = survival_state.PlayerState{
        .index = 0,
        .pos = .{},
    };
    var projectiles = survival_projectiles.ProjectilePool{};
    var secondary_projectiles = survival_secondary_projectiles.SecondaryProjectilePool{};
    var creatures = survival_creatures.CreaturePool{};
    var particles = survival_particles.ParticlePool{};
    survival_state.weaponAssignPlayer(&player, survival_state.WeaponId.pistol);
    try std.testing.expect(try tryFireWeapon(&state, &player, &projectiles, &secondary_projectiles, &creatures, &particles));
    try std.testing.expect(projectiles.entries[0].active);
}
