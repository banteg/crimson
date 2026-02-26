const std = @import("std");
const game_ids = @import("../game_ids.zig");
const native_math = @import("native_math.zig");

const survival_creatures = @import("creatures.zig");
const survival_particles = @import("particles.zig");
const perks = @import("perks.zig");
const survival_projectiles = @import("projectiles.zig");
const survival_secondary_projectiles = @import("secondary_projectiles.zig");
const state_mod = @import("state.zig");
const survival_spawn = @import("spawn.zig");
const survival_math = @import("math.zig");

const narrowF32 = native_math.roundF32;

const WeaponId = game_ids.WeaponId;
const PerkId = perks.PerkId;

pub const WeaponRuntimeError = error{
    UnsupportedWeaponFirePath,
};

const reload_preload_underflow_eps: f64 = 1e-7;
const movement_control_mouse_point_click: i32 = 4;

inline fn weaponId(value: i32) WeaponId {
    return state_mod.weaponIdFromInt(value).?;
}

inline fn projectileMetaFromRawId(raw_id: i32) f32 {
    const weapon_id = state_mod.weaponIdFromInt(raw_id) orelse return 45.0;
    return state_mod.weaponProjectileMeta(weapon_id);
}

pub const TickInputFlags = struct {
    fire_down: bool = false,
    fire_pressed: bool = false,
    reload_pressed: bool = false,
    reload_active_any: bool = false,
    move_mode: i32 = 0,
    single_player_mode: bool = true,
    preprocessed_player_tick: bool = false,
};

pub fn preprocessPlayerForPerkTicks(
    state: *state_mod.GameplayState,
    player: *state_mod.PlayerState,
    dt: f64,
) bool {
    const dt_f32 = narrowF32(dt);
    if (!(dt_f32 > 0.0)) return false;

    if (player.health <= 0.0) {
        player.death_timer = narrowF32(player.death_timer - dt_f32 * 20.0);
        return false;
    }

    if (player.low_health_timer != 100.0 and player.health < 20.0) {
        const next_low_health_timer = narrowF32(player.low_health_timer - dt_f32);
        player.low_health_timer = next_low_health_timer;
        if (next_low_health_timer < 0.0) {
            consumeLowHealthPulseRng(state);
            player.low_health_timer = 1.0;
        }
    }

    return true;
}

pub fn stepPlayerForTick(
    state: *state_mod.GameplayState,
    player: *state_mod.PlayerState,
    projectiles: *survival_projectiles.ProjectilePool,
    secondary_projectiles: *survival_secondary_projectiles.SecondaryProjectilePool,
    creatures: *survival_creatures.CreaturePool,
    particles: *survival_particles.ParticlePool,
    input_flags: TickInputFlags,
    dt: f64,
) WeaponRuntimeError!void {
    const dt_f32 = narrowF32(dt);
    if (!(dt_f32 > 0.0)) return;

    if (!input_flags.preprocessed_player_tick) {
        if (!preprocessPlayerForPerkTicks(state, player, dt)) return;
    } else if (player.health <= 0.0) {
        return;
    }

    if (input_flags.fire_down) {
        state.survival_reward_fire_seen = true;
    }

    const cooldown_scale: f64 = if (state.bonuses.weapon_power_up > 0.0) 1.5 else 1.0;
    const cooldown_decay = narrowF32(dt_f32 * cooldown_scale);
    player.shot_cooldown = @max(0.0, narrowF32(player.shot_cooldown - cooldown_decay));
    if (player.shot_cooldown > 0.0 and player.shot_cooldown < 1e-6) {
        player.shot_cooldown = 0.0;
    }

    const reload_scale: f64 = if (player.reload_stationary_latch and perkActive(player.*, PerkId.stationary_reloader))
        3.0
    else
        1.0;
    if (perkActive(player.*, PerkId.anxious_loader) and input_flags.fire_pressed and player.reload_timer > 0.0) {
        const anxious_next = narrowF32(player.reload_timer - 0.05);
        player.reload_timer = anxious_next;
        if (anxious_next <= 0.0) {
            player.reload_timer = narrowF32(dt * 0.8);
        }
    }

    const reload_timer_now = narrowF32(player.reload_timer);
    var preload_dt = dt_f32;
    if (!state.preserve_bugs) {
        preload_dt = narrowF32(reload_scale * dt_f32);
    }
    const reload_preload_underflow = narrowF32(reload_timer_now - preload_dt);
    const preload_crossed = reload_preload_underflow < -reload_preload_underflow_eps;
    const preload_fire_boundary = input_flags.fire_down and reload_preload_underflow <= reload_preload_underflow_eps;
    if (player.reload_active and reload_timer_now > 0.0 and (preload_crossed or preload_fire_boundary)) {
        player.ammo = @floatFromInt(@max(0, player.clip_size));
    }

    if (player.reload_timer > 0.0) {
        if (perkActive(player.*, PerkId.angry_reloader) and
            player.reload_timer_max > 0.5 and
            player.reload_timer > player.reload_timer_max * 0.5)
        {
            const half_reload = narrowF32(player.reload_timer_max * 0.5);
            const next_timer = narrowF32(player.reload_timer - narrowF32(reload_scale * dt_f32));
            player.reload_timer = next_timer;
            if (next_timer <= half_reload) {
                const count = 7 + @as(i32, @intFromFloat(player.reload_timer_max * 4.0));
                const prev_spawn_guard = state.bonus_spawn_guard;
                state.bonus_spawn_guard = true;
                defer state.bonus_spawn_guard = prev_spawn_guard;

                const owner_id: i32 = if (!state.friendly_fire_enabled) -100 else -1 - player.index;
                if (count > 0) {
                    const step = std.math.tau / @as(f64, @floatFromInt(count));
                    var idx: i32 = 0;
                    while (idx < count) : (idx += 1) {
                        const angle = @as(f64, @floatFromInt(idx)) * step + 0.1;
                        const type_id = @intFromEnum(game_ids.ProjectileTypeId.plasma_minigun);
                        const meta = state_mod.weaponProjectileMeta(.plasma_minigun);
                        _ = projectiles.spawn(player.pos, angle, type_id, owner_id, meta, false);
                    }
                }
            }
        } else {
            player.reload_timer = narrowF32(player.reload_timer - narrowF32(reload_scale * dt_f32));
        }
        if (player.reload_timer < 0.0) {
            player.reload_timer = 0.0;
        }
    }

    const has_alt_weapon_perk = perkActive(player.*, PerkId.alternate_weapon);
    const manual_reload_allowed =
        input_flags.reload_pressed and
        !state.demo_mode_active and
        !has_alt_weapon_perk and
        input_flags.move_mode != movement_control_mouse_point_click and
        input_flags.single_player_mode and
        player.reload_timer == 0.0;
    if (manual_reload_allowed) {
        state_mod.playerStartReload(player, state);
    }

    if (perkActive(player.*, PerkId.sharpshooter)) {
        player.spread_heat = 0.02;
    } else {
        player.spread_heat = @max(0.01, player.spread_heat - narrowF32(dt) * 0.4);
    }

    if (player.shot_cooldown <= 0.0 and player.reload_timer == 0.0) {
        player.reload_active = false;
    }

    const fire_gate_open_pre_reload = player.shot_cooldown <= 0.0 and player.reload_timer == 0.0;
    var swapped_alt_weapon = false;
    const reload_key_active = input_flags.reload_pressed;
    const reload_key_released = !input_flags.reload_active_any;
    if (has_alt_weapon_perk) {
        var cooldown_ms = state.player_alt_weapon_swap_cooldown_ms;
        const dt_ms: i32 = if (dt > 0.0) @intFromFloat(@round(dt * 1000.0)) else 0;
        if (cooldown_ms < 1) {
            cooldown_ms = 0;
        } else {
            cooldown_ms -= dt_ms;
        }

        if (cooldown_ms < 1 and reload_key_active) {
            if (state_mod.playerSwapAltWeapon(player)) {
                swapped_alt_weapon = true;
                player.shot_cooldown = narrowF32(player.shot_cooldown + 0.1);
                state.player_alt_weapon_swap_cooldown_ms = 200;
            } else {
                state.player_alt_weapon_swap_cooldown_ms = 0;
            }
        } else {
            state.player_alt_weapon_swap_cooldown_ms = @max(0, cooldown_ms);
            if (reload_key_released) {
                state.player_alt_weapon_swap_cooldown_ms = 0;
            }
        }
    }

    const force_pre_swap_fire_gate = swapped_alt_weapon and fire_gate_open_pre_reload and input_flags.fire_down;
    if (force_pre_swap_fire_gate) {
        player.shot_cooldown = 0.0;
    }

    if (input_flags.fire_down) {
        _ = try tryFireWeaponWithForce(
            state,
            player,
            projectiles,
            secondary_projectiles,
            creatures,
            particles,
            force_pre_swap_fire_gate,
        );
    }
}

pub fn tryFireWeapon(
    state: *state_mod.GameplayState,
    player: *state_mod.PlayerState,
    projectiles: *survival_projectiles.ProjectilePool,
    secondary_projectiles: *survival_secondary_projectiles.SecondaryProjectilePool,
    creatures: *survival_creatures.CreaturePool,
    particles: *survival_particles.ParticlePool,
) WeaponRuntimeError!bool {
    return tryFireWeaponWithForce(
        state,
        player,
        projectiles,
        secondary_projectiles,
        creatures,
        particles,
        false,
    );
}

fn tryFireWeaponWithForce(
    state: *state_mod.GameplayState,
    player: *state_mod.PlayerState,
    projectiles: *survival_projectiles.ProjectilePool,
    secondary_projectiles: *survival_secondary_projectiles.SecondaryProjectilePool,
    creatures: *survival_creatures.CreaturePool,
    particles: *survival_particles.ParticlePool,
    force_pre_swap_fire_gate: bool,
) WeaponRuntimeError!bool {
    if (player.shot_cooldown > 0.0 and !force_pre_swap_fire_gate) return false;
    const weapon_id = player.weapon_id;
    if (player.reload_timer > 0.0 and !force_pre_swap_fire_gate) {
        if (player.experience <= 0) return false;

        if (perkActive(player.*, PerkId.regression_bullets)) {
            const reload_time = state_mod.weaponReloadTime(weapon_id);
            const factor: f64 = if (weaponUsesFireAmmoClass(weapon_id)) 4.0 else 200.0;
            const drained = reload_time * factor;
            const before: f64 = @floatFromInt(player.experience);
            var after: i32 = @intFromFloat(before - drained);
            if (after < 0) after = 0;
            player.experience = after;
        } else if (perkActive(player.*, PerkId.ammunition_within)) {
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

    const shot_cooldown_base = state_mod.weaponShotCooldown(weapon_id);
    const pellet_count = @max(0, state_mod.weaponPelletCount(weapon_id));
    const weapon_spread_heat = state_mod.weaponSpreadHeatInc(weapon_id);
    const fire_bullets_weapon_id = WeaponId.fire_bullets;
    const fire_bullets_spread_heat = state_mod.weaponSpreadHeatInc(fire_bullets_weapon_id);

    var shot_cooldown = shot_cooldown_base;

    const is_fire_bullets = player.fire_bullets_timer > 0.0;
    var shot_count = computeShotCount(player.weapon_id, player.ammo);
    if (is_fire_bullets) {
        shot_count = pellet_count;
    }
    if (shot_count <= 0) return false;

    const aim_delta = state_mod.Vec2.sub(player.aim, player.pos);
    const aim_heading = if (aim_delta.lengthSq() > 1e-9)
        aim_delta.toHeading()
    else
        player.aim_dir.toHeading();
    const muzzle_dir = rotateVec(directionFromHeading(aim_heading), -0.150915);
    const muzzle = state_mod.Vec2.add(player.pos, muzzle_dir.mul(16.0));
    const projectile_owner_id: i32 = -100;
    const secondary_owner_id: i32 = -1 - player.index;
    if (is_fire_bullets and pellet_count == 1) {
        shot_cooldown = state_mod.weaponShotCooldown(fire_bullets_weapon_id);
    }
    if (perkActive(player.*, PerkId.fastshot)) {
        shot_cooldown = narrowF32(shot_cooldown * 0.88);
    }
    if (perkActive(player.*, PerkId.sharpshooter)) {
        shot_cooldown = narrowF32(shot_cooldown * 1.05);
    }
    player.shot_cooldown = @max(0.0, shot_cooldown);

    const weapon_flags = state_mod.weaponFlags(player.weapon_id);

    if ((weapon_flags & 0x1) != 0) {
        // spawn_shell_casing randoms: angle speed rotation rotation_step.
        _ = state.rng.rand();
        _ = state.rng.rand();
        _ = state.rng.rand();
        _ = state.rng.rand();
    }

    const dist = aim_delta.length();
    const max_offset = dist * player.spread_heat * 0.5;
    const dir_roll = state.rng.rand();
    const dir_angle = @as(f64, @floatFromInt(dir_roll & 0x1ff)) * (std.math.tau / 512.0);
    const mag_roll = state.rng.rand();
    const mag = @as(f64, @floatFromInt(mag_roll & 0x1ff)) * (1.0 / 512.0);
    const offset = max_offset * mag;
    const aim_jitter = state_mod.Vec2.add(player.aim, state_mod.Vec2.fromAngle(narrowF32(dir_angle)).mul(narrowF32(offset)));
    const shot_angle = state_mod.Vec2.sub(aim_jitter, player.pos).toHeading();
    var particle_angle = directionFromHeading(shot_angle).toAngle();
    if (player.weapon_id == .flamethrower or player.weapon_id == .blow_torch or player.weapon_id == .hr_flamer) {
        particle_angle = directionFromHeading(aim_heading).toAngle();
    }

    if (!is_fire_bullets) {
        // fire SFX variant selection.
        _ = state.rng.rand();
    }

    const spawn_muzzle_after_projectile = is_fire_bullets or
        player.weapon_id == WeaponId.pistol or
        player.weapon_id == WeaponId.shrinkifier_5k;
    if (!spawn_muzzle_after_projectile) {
        consumeMuzzleSpriteRng(state, player.weapon_id, is_fire_bullets);
    }

    if (is_fire_bullets) {
        const meta = state_mod.weaponProjectileMeta(.fire_bullets);
        for (0..@as(usize, @intCast(shot_count))) |_| {
            const jitter_roll = state.rng.rand();
            const jitter = @as(f64, @floatFromInt(@as(i32, @intCast(jitter_roll % 200)) - 100)) * 0.0015;
            _ = projectiles.spawn(
                muzzle,
                shot_angle + jitter,
                @intFromEnum(game_ids.ProjectileTypeId.fire_bullets),
                projectile_owner_id,
                meta,
                false,
            );
        }
    } else switch (player.weapon_id) {
        .multi_plasma => {
            const spread_small = std.math.pi / 10.0;
            const spread_large = std.math.pi / 6.0;
            _ = projectiles.spawn(muzzle, shot_angle - spread_small, @intFromEnum(game_ids.ProjectileTypeId.plasma_rifle), projectile_owner_id, state_mod.weaponProjectileMeta(.plasma_rifle), false);
            _ = projectiles.spawn(muzzle, shot_angle - spread_large, @intFromEnum(game_ids.ProjectileTypeId.plasma_minigun), projectile_owner_id, state_mod.weaponProjectileMeta(.plasma_minigun), false);
            _ = projectiles.spawn(muzzle, shot_angle, @intFromEnum(game_ids.ProjectileTypeId.plasma_rifle), projectile_owner_id, state_mod.weaponProjectileMeta(.plasma_rifle), false);
            _ = projectiles.spawn(muzzle, shot_angle + spread_large, @intFromEnum(game_ids.ProjectileTypeId.plasma_minigun), projectile_owner_id, state_mod.weaponProjectileMeta(.plasma_minigun), false);
            _ = projectiles.spawn(muzzle, shot_angle + spread_small, @intFromEnum(game_ids.ProjectileTypeId.plasma_rifle), projectile_owner_id, state_mod.weaponProjectileMeta(.plasma_rifle), false);
        },
        .plasma_shotgun => {
            const meta = state_mod.weaponProjectileMeta(.plasma_minigun);
            for (0..14) |_| {
                const jitter = @as(f64, @floatFromInt(@as(i32, @intCast(state.rng.rand() & 0xff)) - 0x80)) * 0.002;
                const id = projectiles.spawn(
                    muzzle,
                    shot_angle + jitter,
                    @intFromEnum(game_ids.ProjectileTypeId.plasma_minigun),
                    projectile_owner_id,
                    meta,
                    false,
                );
                projectiles.entries[id].speed_scale = narrowF32(1.0 + @as(f64, @floatFromInt(state.rng.rand() % 100)) * 0.01);
            }
        },
        .gauss_shotgun => {
            const meta = state_mod.weaponProjectileMeta(.gauss_gun);
            for (0..6) |_| {
                const jitter = @as(f64, @floatFromInt(@as(i32, @intCast(state.rng.rand() % 200)) - 100)) * 0.002;
                const id = projectiles.spawn(
                    muzzle,
                    shot_angle + jitter,
                    @intFromEnum(game_ids.ProjectileTypeId.gauss_gun),
                    projectile_owner_id,
                    meta,
                    false,
                );
                projectiles.entries[id].speed_scale = narrowF32(1.4 + @as(f64, @floatFromInt(state.rng.rand() % 0x50)) * 0.01);
            }
        },
        .ion_shotgun => {
            const meta = state_mod.weaponProjectileMeta(.ion_minigun);
            for (0..8) |_| {
                const jitter = @as(f64, @floatFromInt(@as(i32, @intCast(state.rng.rand() % 200)) - 100)) * 0.0026;
                const id = projectiles.spawn(
                    muzzle,
                    shot_angle + jitter,
                    @intFromEnum(game_ids.ProjectileTypeId.ion_minigun),
                    projectile_owner_id,
                    meta,
                    false,
                );
                projectiles.entries[id].speed_scale = narrowF32(1.4 + @as(f64, @floatFromInt(state.rng.rand() % 0x50)) * 0.01);
            }
        },
        .flamethrower => {
            _ = particles.spawnParticle(
                state,
                muzzle,
                particle_angle,
                1.0,
                -100,
            );
        },
        .blow_torch => {
            const particle_id = particles.spawnParticle(
                state,
                muzzle,
                particle_angle,
                1.0,
                -100,
            );
            particles.entries[particle_id].style_id = survival_particles.ParticleStyleId.blow_torch;
        },
        .hr_flamer => {
            const particle_id = particles.spawnParticle(
                state,
                muzzle,
                particle_angle,
                1.0,
                -100,
            );
            particles.entries[particle_id].style_id = survival_particles.ParticleStyleId.hr_flamer;
        },
        .bubblegun => {
            _ = particles.spawnParticleSlow(
                state,
                muzzle,
                directionFromHeading(shot_angle).toAngle(),
                -100,
            );
        },
        .rocket_launcher => {
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
        .seeker_rockets => {
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
        .mini_rocket_swarmers => {
            const rocket_count = shot_count;
            const spread = std.math.pi * (2.0 / 3.0);
            const step = if (rocket_count <= 1)
                0.0
            else
                spread / @as(f64, @floatFromInt(rocket_count - 1));
            var angle = shot_angle - spread * 0.5;
            for (0..@as(usize, @intCast(rocket_count))) |_| {
                _ = secondary_projectiles.spawn(
                    muzzle,
                    angle,
                    survival_secondary_projectiles.SecondaryProjectileTypeId.homing_rocket,
                    secondary_owner_id,
                    2.0,
                    player.aim,
                    creatures,
                );
                angle = narrowF32(angle + step);
            }
        },
        .rocket_minigun => {
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
            const type_id = state_mod.projectileTypeIdFromWeaponId(player.weapon_id) orelse return error.UnsupportedWeaponFirePath;
            const type_id_i32 = @intFromEnum(type_id);
            const meta = projectileMetaFromRawId(type_id_i32);
            const pellets = @max(1, state_mod.weaponPelletCount(player.weapon_id));
            for (0..@as(usize, @intCast(pellets))) |_| {
                var angle = shot_angle;
                if (pellets > 1) {
                    const jitter_step = pelletJitterStep(player.weapon_id);
                    angle += narrowF32(@as(f64, @floatFromInt(@as(i32, @intCast(state.rng.rand() % 200)) - 100)) * jitter_step);
                }
                const id = projectiles.spawn(
                    muzzle,
                    angle,
                    type_id_i32,
                    projectile_owner_id,
                    meta,
                    false,
                );
                if (pellets > 1 and
                    (player.weapon_id == .shotgun or player.weapon_id == .sawed_off_shotgun or player.weapon_id == .jackhammer))
                {
                    projectiles.entries[id].speed_scale = narrowF32(1.0 + @as(f64, @floatFromInt(state.rng.rand() % 100)) * 0.01);
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
        const weapon_idx: usize = @intCast(@intFromEnum(player.weapon_id));
        if (weapon_idx < state.weapon_shots_fired[idx].len) {
            state.weapon_shots_fired[idx][weapon_idx] += shot_count;
        }
    }
    state.shots_fired_total += shot_count;

    const ammo_cost = computeAmmoCost(player.weapon_id, shot_count);
    if (state.bonuses.reflex_boost <= 0.0 and !is_fire_bullets) {
        player.ammo -= narrowF32(ammo_cost);
    }

    player.shot_seq += 1;

    if (!perkActive(player.*, PerkId.sharpshooter)) {
        const spread_heat_base = if (is_fire_bullets) fire_bullets_spread_heat else weapon_spread_heat;
        const spread_inc = spread_heat_base * 1.3;
        player.spread_heat = std.math.clamp(
            player.spread_heat + spread_inc,
            0.0,
            0.48,
        );
    }

    if (player.ammo <= 0.0 and (force_pre_swap_fire_gate or player.reload_timer <= 0.0)) {
        state_mod.playerStartReload(player, state);
    }

    return true;
}

pub fn applyPlayerPerkTicks(
    state: *state_mod.GameplayState,
    player: *state_mod.PlayerState,
    projectiles: *survival_projectiles.ProjectilePool,
    dt: f64,
) void {
    tickManBomb(state, player, projectiles, dt);
    tickLivingFortress(player, dt);
    tickFireCaugh(state, player, projectiles, dt);
    tickHotTempered(state, player, projectiles, dt);
}

fn tickManBomb(
    state: *state_mod.GameplayState,
    player: *state_mod.PlayerState,
    projectiles: *survival_projectiles.ProjectilePool,
    dt: f64,
) void {
    if (!perkActive(player.*, PerkId.man_bomb)) {
        player.man_bomb_timer = 0.0;
        return;
    }

    player.man_bomb_timer += narrowF32(dt);
    if (player.man_bomb_timer <= state.perk_interval_man_bomb) return;

    const owner_id: i32 = if (!state.friendly_fire_enabled) -100 else -1 - player.index;
    for (0..8) |idx| {
        const type_id = if ((idx & 1) == 0)
            @intFromEnum(game_ids.ProjectileTypeId.ion_minigun)
        else
            @intFromEnum(game_ids.ProjectileTypeId.ion_rifle);
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
    player: *state_mod.PlayerState,
    dt: f64,
) void {
    if (perkActive(player.*, PerkId.living_fortress)) {
        player.living_fortress_timer = @min(30.0, player.living_fortress_timer + narrowF32(dt));
    } else {
        player.living_fortress_timer = 0.0;
    }
}

fn tickFireCaugh(
    state: *state_mod.GameplayState,
    player: *state_mod.PlayerState,
    projectiles: *survival_projectiles.ProjectilePool,
    dt: f64,
) void {
    if (!perkActive(player.*, PerkId.fire_caugh)) {
        player.fire_cough_timer = 0.0;
        return;
    }

    player.fire_cough_timer += narrowF32(dt);
    if (player.fire_cough_timer <= state.perk_interval_fire_cough) return;

    const owner_id: i32 = if (!state.friendly_fire_enabled) -100 else -1 - player.index;
    const aim_heading = player.aim_heading;
    const origin_pos = player.pos;
    const muzzle = state_mod.Vec2.add(
        origin_pos,
        rotateVec(directionFromHeading(aim_heading), -0.150915).mul(16.0),
    );
    const aim_delta = state_mod.Vec2.sub(player.aim, origin_pos);
    const dist = aim_delta.length();
    const max_offset = dist * player.spread_heat * 0.5;
    const dir_roll = state.rng.rand();
    const dir_angle = @as(f64, @floatFromInt(dir_roll & 0x1ff)) * (std.math.tau / 512.0);
    const mag_roll = state.rng.rand();
    const mag = @as(f64, @floatFromInt(mag_roll & 0x1ff)) * (1.0 / 512.0);
    const offset = max_offset * mag;
    const jitter = state_mod.Vec2.add(
        player.aim,
        state_mod.Vec2.fromAngle(narrowF32(dir_angle)).mul(narrowF32(offset)),
    );
    const angle = state_mod.Vec2.sub(jitter, origin_pos).toHeading();
    spawnPerkProjectile(
        state,
        player,
        projectiles,
        muzzle,
        angle,
        @intFromEnum(game_ids.ProjectileTypeId.fire_bullets),
        owner_id,
    );

    // sprite_effects.spawn(...): slot scan + one rotation RNG draw in common case.
    _ = state.rng.rand() % 0x274;

    player.fire_cough_timer -= state.perk_interval_fire_cough;
    state.perk_interval_fire_cough = @as(f32, @floatFromInt(state.rng.rand() % 4)) + 2.0;
}

fn tickHotTempered(
    state: *state_mod.GameplayState,
    player: *state_mod.PlayerState,
    projectiles: *survival_projectiles.ProjectilePool,
    dt: f64,
) void {
    if (!perkActive(player.*, PerkId.hot_tempered)) {
        player.hot_tempered_timer = 0.0;
        return;
    }

    player.hot_tempered_timer += narrowF32(dt);
    if (player.hot_tempered_timer <= state.perk_interval_hot_tempered) return;

    const owner_id: i32 = if (state.friendly_fire_enabled) -1 - player.index else -100;
    for (0..8) |idx| {
        const type_id = if ((idx & 1) == 0)
            @intFromEnum(game_ids.ProjectileTypeId.plasma_minigun)
        else
            @intFromEnum(game_ids.ProjectileTypeId.plasma_rifle);
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
    state.perk_interval_hot_tempered = @as(f32, @floatFromInt(state.rng.rand() % 8)) + 2.0;
}

fn spawnPerkProjectile(
    state: *state_mod.GameplayState,
    player: *const state_mod.PlayerState,
    projectiles: *survival_projectiles.ProjectilePool,
    pos: state_mod.Vec2,
    angle: f64,
    type_id: i32,
    owner_id: i32,
) void {
    var spawn_type_id = type_id;
    var shot_credit: i32 = 0;
    const player_owned_spawn = owner_id == -100 or owner_id == -1 or owner_id == -2 or owner_id == -3;
    if (!state.bonus_spawn_guard and player_owned_spawn) {
        shot_credit = 1;
        if (spawn_type_id != @intFromEnum(game_ids.ProjectileTypeId.fire_bullets) and player.fire_bullets_timer > 0.0) {
            // `projectile_spawn` Fire Bullets override loops once, crediting shots twice.
            spawn_type_id = @intFromEnum(game_ids.ProjectileTypeId.fire_bullets);
            shot_credit = 2;
        }
    }

    const meta = projectileMetaFromRawId(spawn_type_id);
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

fn pelletJitterStep(weapon_id: WeaponId) f64 {
    return switch (weapon_id) {
        .shotgun, .jackhammer => 0.0013,
        .sawed_off_shotgun => 0.004,
        else => 0.0015,
    };
}

fn consumeMuzzleSpriteRng(
    state: *state_mod.GameplayState,
    weapon_id: WeaponId,
    fire_bullets_active: bool,
) void {
    var count: usize = 0;
    if (fire_bullets_active) {
        count = 1;
    } else {
        count = switch (weapon_id) {
            .pistol,
            .assault_rifle,
            .shotgun,
            .sawed_off_shotgun,
            .submachine_gun,
            .gauss_gun,
            .rocket_launcher,
            .seeker_rockets,
            .mini_rocket_swarmers,
            .shrinkifier_5k,
            .gauss_shotgun,
            => 2,
            .rocket_minigun, .jackhammer => 1,
            else => 0,
        };
    }
    for (0..count) |_| {
        _ = state.rng.rand();
    }
}

fn consumeLowHealthPulseRng(state: *state_mod.GameplayState) void {
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
    weapon_id: WeaponId,
    ammo: f64,
) i32 {
    return switch (weapon_id) {
        .multi_plasma => 5,
        .plasma_shotgun => 14,
        .mini_rocket_swarmers => @max(1, @as(i32, @intFromFloat(@floor(@max(0.0, ammo))))),
        .gauss_shotgun => 6,
        .ion_shotgun => 8,
        else => @max(1, state_mod.weaponPelletCount(weapon_id)),
    };
}

fn computeAmmoCost(
    weapon_id: WeaponId,
    shot_count: i32,
) f64 {
    return switch (weapon_id) {
        .flamethrower => 0.1,
        .blow_torch => 0.05,
        .hr_flamer => 0.1,
        .mini_rocket_swarmers => @floatFromInt(shot_count),
        .bubblegun => 0.15,
        else => 1.0,
    };
}

fn weaponUsesFireAmmoClass(weapon_id: game_ids.WeaponId) bool {
    // Mirrors `weapon.ammo_class == 1` in the Python weapon table.
    return weapon_id == .flamethrower or weapon_id == .blow_torch or weapon_id == .hr_flamer;
}

fn directionFromHeading(heading: f64) state_mod.Vec2 {
    const radians = narrowF32(heading - std.math.pi / 2.0);
    return .{
        .x = narrowF32(survival_math.cos(radians)),
        .y = narrowF32(survival_math.sin(radians)),
    };
}

fn rotateVec(vec: state_mod.Vec2, theta: f64) state_mod.Vec2 {
    const theta_f = narrowF32(theta);
    const cos_theta = narrowF32(survival_math.cos(theta_f));
    const sin_theta = narrowF32(survival_math.sin(theta_f));
    return .{
        .x = narrowF32(vec.x * cos_theta - vec.y * sin_theta),
        .y = narrowF32(vec.x * sin_theta + vec.y * cos_theta),
    };
}

fn perkActive(player: state_mod.PlayerState, perk_id: PerkId) bool {
    return player.perk_counts.get(perk_id) > 0;
}

fn expectFloatClose(expected: f64, actual: f64) !void {
    try std.testing.expectApproxEqAbs(expected, actual, 1e-6);
}

fn activeProjectileCount(projectiles: *const survival_projectiles.ProjectilePool) usize {
    var count: usize = 0;
    for (projectiles.entries) |entry| {
        if (entry.active) count += 1;
    }
    return count;
}

fn activeProjectileTypeCount(
    projectiles: *const survival_projectiles.ProjectilePool,
    type_id: i32,
) usize {
    var count: usize = 0;
    for (projectiles.entries) |entry| {
        if (entry.active and entry.type_id == type_id) count += 1;
    }
    return count;
}

fn activeSecondaryProjectileCount(
    secondary_projectiles: *const survival_secondary_projectiles.SecondaryProjectilePool,
) usize {
    var count: usize = 0;
    for (secondary_projectiles.entries) |entry| {
        if (entry.active) count += 1;
    }
    return count;
}

fn findSeedForNthRandValue(
    draw_index: usize,
    target: u32,
    search_limit: u32,
) ?u32 {
    for (0..search_limit) |seed_usize| {
        const seed: u32 = @intCast(seed_usize);
        var rng = survival_spawn.Crand.init(seed);
        var value: u32 = 0;
        for (0..draw_index) |_| {
            value = rng.rand();
        }
        if (value == target) return seed;
    }
    return null;
}

test "weapon usage tracks most used weapon" {
    var state = state_mod.GameplayState.init(1);
    var projectiles = survival_projectiles.ProjectilePool{};
    var secondary_projectiles = survival_secondary_projectiles.SecondaryProjectilePool{};
    var creatures = survival_creatures.CreaturePool{};
    var particles = survival_particles.ParticlePool{};
    var player = state_mod.PlayerState{
        .index = 0,
        .pos = .{},
    };

    state_mod.weaponAssignPlayer(&player, game_ids.WeaponId.pistol);
    try std.testing.expect(try tryFireWeapon(&state, &player, &projectiles, &secondary_projectiles, &creatures, &particles));
    try std.testing.expectEqual(@as(i32, 1), state.weapon_shots_fired[0][1]);

    state_mod.weaponAssignPlayer(&player, game_ids.WeaponId.assault_rifle);
    for (0..3) |_| {
        player.shot_cooldown = 0.0;
        try std.testing.expect(try tryFireWeapon(&state, &player, &projectiles, &secondary_projectiles, &creatures, &particles));
    }
    try std.testing.expectEqual(@as(i32, 3), state.weapon_shots_fired[0][2]);

    const most_used = state_mod.mostUsedWeaponIdForPlayer(state, 0, @intFromEnum(game_ids.WeaponId.pistol));
    try std.testing.expectEqual(@intFromEnum(game_ids.WeaponId.assault_rifle), most_used);
}

test "weapon runtime starts reload when ammo is depleted" {
    var state = state_mod.GameplayState.init(1);
    var projectiles = survival_projectiles.ProjectilePool{};
    var secondary_projectiles = survival_secondary_projectiles.SecondaryProjectilePool{};
    var creatures = survival_creatures.CreaturePool{};
    var particles = survival_particles.ParticlePool{};
    var player = state_mod.PlayerState{
        .index = 0,
        .pos = .{},
    };
    state_mod.weaponAssignPlayer(&player, game_ids.WeaponId.pistol);
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

test "manual reload starts even when clip is full" {
    var state = state_mod.GameplayState.init(1);
    var projectiles = survival_projectiles.ProjectilePool{};
    var secondary_projectiles = survival_secondary_projectiles.SecondaryProjectilePool{};
    var creatures = survival_creatures.CreaturePool{};
    var particles = survival_particles.ParticlePool{};
    var player = state_mod.PlayerState{
        .index = 0,
        .pos = .{},
    };
    state_mod.weaponAssignPlayer(&player, game_ids.WeaponId.pistol);
    player.ammo = @floatFromInt(player.clip_size);

    try stepPlayerForTick(
        &state,
        &player,
        &projectiles,
        &secondary_projectiles,
        &creatures,
        &particles,
        .{ .reload_pressed = true },
        1.0 / 60.0,
    );

    try std.testing.expect(player.reload_active);
    try std.testing.expect(player.reload_timer > 0.0);
}

test "manual reload requires single player mode" {
    var state = state_mod.GameplayState.init(1);
    var projectiles = survival_projectiles.ProjectilePool{};
    var secondary_projectiles = survival_secondary_projectiles.SecondaryProjectilePool{};
    var creatures = survival_creatures.CreaturePool{};
    var particles = survival_particles.ParticlePool{};
    var player = state_mod.PlayerState{
        .index = 0,
        .pos = .{},
    };
    state_mod.weaponAssignPlayer(&player, game_ids.WeaponId.pistol);
    player.ammo = 0.0;

    try stepPlayerForTick(
        &state,
        &player,
        &projectiles,
        &secondary_projectiles,
        &creatures,
        &particles,
        .{ .reload_pressed = true, .single_player_mode = false },
        1.0 / 60.0,
    );

    try std.testing.expect(!player.reload_active);
    try expectFloatClose(0.0, player.reload_timer);
}

test "anxious loader reduces reload timer on fire press" {
    var state = state_mod.GameplayState.init(1);
    var projectiles = survival_projectiles.ProjectilePool{};
    var secondary_projectiles = survival_secondary_projectiles.SecondaryProjectilePool{};
    var creatures = survival_creatures.CreaturePool{};
    var particles = survival_particles.ParticlePool{};

    var base_player = state_mod.PlayerState{
        .index = 0,
        .pos = .{},
        .weapon_id = game_ids.WeaponId.pistol,
        .reload_active = true,
        .reload_timer = 1.0,
        .reload_timer_max = 1.0,
    };
    var perk_player = state_mod.PlayerState{
        .index = 0,
        .pos = .{},
        .weapon_id = game_ids.WeaponId.pistol,
        .reload_active = true,
        .reload_timer = 1.0,
        .reload_timer_max = 1.0,
    };
    perk_player.perk_counts.set(PerkId.anxious_loader, 1);

    try stepPlayerForTick(
        &state,
        &base_player,
        &projectiles,
        &secondary_projectiles,
        &creatures,
        &particles,
        .{ .fire_pressed = true },
        0.1,
    );
    try stepPlayerForTick(
        &state,
        &perk_player,
        &projectiles,
        &secondary_projectiles,
        &creatures,
        &particles,
        .{ .fire_pressed = true },
        0.1,
    );

    try expectFloatClose(0.9, base_player.reload_timer);
    try expectFloatClose(0.85, perk_player.reload_timer);
}

test "angry reloader spawns plasma ring at half reload" {
    var state = state_mod.GameplayState.init(1);
    var projectiles = survival_projectiles.ProjectilePool{};
    var secondary_projectiles = survival_secondary_projectiles.SecondaryProjectilePool{};
    var creatures = survival_creatures.CreaturePool{};
    var particles = survival_particles.ParticlePool{};
    var player = state_mod.PlayerState{
        .index = 0,
        .pos = .{ .x = 100.0, .y = 100.0 },
        .weapon_id = game_ids.WeaponId.pistol,
        .reload_active = true,
        .reload_timer = 1.1,
        .reload_timer_max = 2.0,
        .clip_size = 10,
        .ammo = 0.0,
    };
    player.perk_counts.set(PerkId.angry_reloader, 1);

    try stepPlayerForTick(
        &state,
        &player,
        &projectiles,
        &secondary_projectiles,
        &creatures,
        &particles,
        .{},
        0.2,
    );

    try expectFloatClose(0.9, player.reload_timer);
    try std.testing.expectEqual(@as(usize, 15), activeProjectileCount(&projectiles));
    try std.testing.expect(!state.bonus_spawn_guard);
    try std.testing.expectEqual(@as(i32, 0), state.shots_fired[0]);
    for (projectiles.entries[0..15]) |proj| {
        try std.testing.expect(proj.active);
        try std.testing.expectEqual(@intFromEnum(game_ids.ProjectileTypeId.plasma_minigun), proj.type_id);
        try std.testing.expectEqual(@as(i32, -100), proj.owner_id);
    }
}

test "angry reloader does not trigger once reload is below half" {
    var state = state_mod.GameplayState.init(1);
    var projectiles = survival_projectiles.ProjectilePool{};
    var secondary_projectiles = survival_secondary_projectiles.SecondaryProjectilePool{};
    var creatures = survival_creatures.CreaturePool{};
    var particles = survival_particles.ParticlePool{};
    var player = state_mod.PlayerState{
        .index = 0,
        .pos = .{ .x = 100.0, .y = 100.0 },
        .weapon_id = game_ids.WeaponId.pistol,
        .reload_active = true,
        .reload_timer = 0.95,
        .reload_timer_max = 2.0,
    };
    player.perk_counts.set(PerkId.angry_reloader, 1);

    try stepPlayerForTick(
        &state,
        &player,
        &projectiles,
        &secondary_projectiles,
        &creatures,
        &particles,
        .{},
        0.1,
    );

    try expectFloatClose(0.85, player.reload_timer);
    try std.testing.expectEqual(@as(usize, 0), activeProjectileCount(&projectiles));
}

test "man bomb spawns eight ion projectiles and preserves bonus guard latch" {
    var state = state_mod.GameplayState.init(1);
    var projectiles = survival_projectiles.ProjectilePool{};
    var player = state_mod.PlayerState{
        .index = 0,
        .pos = .{ .x = 100.0, .y = 100.0 },
        .man_bomb_timer = 3.9,
    };
    player.perk_counts.set(PerkId.man_bomb, 1);
    state.bonus_spawn_guard = true;

    applyPlayerPerkTicks(&state, &player, &projectiles, 0.2);

    try std.testing.expect(state.bonus_spawn_guard);
    try std.testing.expectEqual(@as(usize, 8), activeProjectileCount(&projectiles));
    try std.testing.expectEqual(@as(usize, 4), activeProjectileTypeCount(&projectiles, @intFromEnum(game_ids.ProjectileTypeId.ion_minigun)));
    try std.testing.expectEqual(@as(usize, 4), activeProjectileTypeCount(&projectiles, @intFromEnum(game_ids.ProjectileTypeId.ion_rifle)));
    for (projectiles.entries[0..8]) |proj| {
        try std.testing.expect(proj.active);
        try std.testing.expectEqual(@as(i32, -100), proj.owner_id);
    }
}

test "hot tempered spawns alternating plasma projectiles when charged" {
    var state = state_mod.GameplayState.init(1);
    var projectiles = survival_projectiles.ProjectilePool{};
    var player = state_mod.PlayerState{
        .index = 0,
        .pos = .{ .x = 100.0, .y = 100.0 },
        .hot_tempered_timer = 1.95,
    };
    player.perk_counts.set(PerkId.hot_tempered, 1);

    applyPlayerPerkTicks(&state, &player, &projectiles, 0.1);

    try std.testing.expectEqual(@as(usize, 8), activeProjectileCount(&projectiles));
    try std.testing.expectEqual(@as(usize, 4), activeProjectileTypeCount(&projectiles, @intFromEnum(game_ids.ProjectileTypeId.plasma_minigun)));
    try std.testing.expectEqual(@as(usize, 4), activeProjectileTypeCount(&projectiles, @intFromEnum(game_ids.ProjectileTypeId.plasma_rifle)));
    for (projectiles.entries[0..8]) |proj| {
        try std.testing.expect(proj.active);
        try std.testing.expectEqual(@as(i32, -100), proj.owner_id);
    }
}

test "stationary reloader triples reload speed" {
    var state = state_mod.GameplayState.init(1);
    var projectiles = survival_projectiles.ProjectilePool{};
    var secondary_projectiles = survival_secondary_projectiles.SecondaryProjectilePool{};
    var creatures = survival_creatures.CreaturePool{};
    var particles = survival_particles.ParticlePool{};

    var base_player = state_mod.PlayerState{
        .index = 0,
        .pos = .{ .x = 100.0, .y = 100.0 },
        .weapon_id = game_ids.WeaponId.pistol,
        .reload_active = true,
        .reload_timer = 1.0,
        .reload_timer_max = 1.0,
    };
    var perk_player = state_mod.PlayerState{
        .index = 0,
        .pos = .{ .x = 100.0, .y = 100.0 },
        .weapon_id = game_ids.WeaponId.pistol,
        .reload_active = true,
        .reload_timer = 1.0,
        .reload_timer_max = 1.0,
    };
    perk_player.perk_counts.set(PerkId.stationary_reloader, 1);

    try stepPlayerForTick(
        &state,
        &base_player,
        &projectiles,
        &secondary_projectiles,
        &creatures,
        &particles,
        .{},
        0.1,
    );
    try stepPlayerForTick(
        &state,
        &perk_player,
        &projectiles,
        &secondary_projectiles,
        &creatures,
        &particles,
        .{},
        0.1,
    );

    try expectFloatClose(0.9, base_player.reload_timer);
    try expectFloatClose(0.7, perk_player.reload_timer);
}

test "alternate weapon reload press swaps and adds cooldown" {
    var state = state_mod.GameplayState.init(1);
    var projectiles = survival_projectiles.ProjectilePool{};
    var secondary_projectiles = survival_secondary_projectiles.SecondaryProjectilePool{};
    var creatures = survival_creatures.CreaturePool{};
    var particles = survival_particles.ParticlePool{};
    var player = state_mod.PlayerState{
        .index = 0,
        .pos = .{ .x = 512.0, .y = 512.0 },
        .aim = .{ .x = 700.0, .y = 512.0 },
    };
    player.perk_counts.set(PerkId.alternate_weapon, 1);
    state_mod.weaponAssignPlayer(&player, game_ids.WeaponId.assault_rifle);
    player.alt_weapon_id = game_ids.WeaponId.pistol;
    player.alt_clip_size = 10;
    player.alt_ammo = 10.0;
    player.alt_reload_active = false;
    player.alt_reload_timer = 0.0;
    player.alt_reload_timer_max = 0.0;
    player.alt_shot_cooldown = 0.0;
    player.shot_cooldown = 0.0;

    try stepPlayerForTick(
        &state,
        &player,
        &projectiles,
        &secondary_projectiles,
        &creatures,
        &particles,
        .{ .reload_pressed = true, .reload_active_any = true },
        0.1,
    );

    try std.testing.expectEqual(game_ids.WeaponId.pistol, player.weapon_id);
    try std.testing.expectEqual(game_ids.WeaponId.assault_rifle, player.alt_weapon_id.?);
    try expectFloatClose(0.1, player.shot_cooldown);
    try std.testing.expectEqual(@as(i32, 200), state.player_alt_weapon_swap_cooldown_ms);
}

test "alternate weapon held reload uses cooldown gate" {
    var state = state_mod.GameplayState.init(1);
    var projectiles = survival_projectiles.ProjectilePool{};
    var secondary_projectiles = survival_secondary_projectiles.SecondaryProjectilePool{};
    var creatures = survival_creatures.CreaturePool{};
    var particles = survival_particles.ParticlePool{};
    var player = state_mod.PlayerState{
        .index = 0,
        .pos = .{},
        .aim = .{ .x = 100.0, .y = 0.0 },
    };
    player.perk_counts.set(PerkId.alternate_weapon, 1);
    state_mod.weaponAssignPlayer(&player, game_ids.WeaponId.assault_rifle);
    player.alt_weapon_id = game_ids.WeaponId.pistol;
    player.alt_clip_size = 10;
    player.alt_ammo = 10.0;

    try stepPlayerForTick(
        &state,
        &player,
        &projectiles,
        &secondary_projectiles,
        &creatures,
        &particles,
        .{ .reload_pressed = true, .reload_active_any = true },
        0.05,
    );
    try std.testing.expectEqual(game_ids.WeaponId.pistol, player.weapon_id);
    try std.testing.expectEqual(@as(i32, 200), state.player_alt_weapon_swap_cooldown_ms);

    for (0..3) |_| {
        try stepPlayerForTick(
            &state,
            &player,
            &projectiles,
            &secondary_projectiles,
            &creatures,
            &particles,
            .{ .reload_pressed = true, .reload_active_any = true },
            0.05,
        );
        try std.testing.expectEqual(game_ids.WeaponId.pistol, player.weapon_id);
    }

    try stepPlayerForTick(
        &state,
        &player,
        &projectiles,
        &secondary_projectiles,
        &creatures,
        &particles,
        .{ .reload_pressed = true, .reload_active_any = true },
        0.05,
    );
    try std.testing.expectEqual(game_ids.WeaponId.assault_rifle, player.weapon_id);
    try std.testing.expectEqual(@as(i32, 200), state.player_alt_weapon_swap_cooldown_ms);
}

test "alternate weapon release resets cooldown gate" {
    var state = state_mod.GameplayState.init(1);
    var projectiles = survival_projectiles.ProjectilePool{};
    var secondary_projectiles = survival_secondary_projectiles.SecondaryProjectilePool{};
    var creatures = survival_creatures.CreaturePool{};
    var particles = survival_particles.ParticlePool{};
    var player = state_mod.PlayerState{
        .index = 0,
        .pos = .{},
        .aim = .{ .x = 100.0, .y = 0.0 },
    };
    player.perk_counts.set(PerkId.alternate_weapon, 1);
    state_mod.weaponAssignPlayer(&player, game_ids.WeaponId.assault_rifle);
    player.alt_weapon_id = game_ids.WeaponId.pistol;
    player.alt_clip_size = 10;
    player.alt_ammo = 10.0;

    try stepPlayerForTick(
        &state,
        &player,
        &projectiles,
        &secondary_projectiles,
        &creatures,
        &particles,
        .{ .reload_pressed = true, .reload_active_any = true },
        0.05,
    );
    try std.testing.expectEqual(game_ids.WeaponId.pistol, player.weapon_id);

    try stepPlayerForTick(
        &state,
        &player,
        &projectiles,
        &secondary_projectiles,
        &creatures,
        &particles,
        .{ .reload_pressed = false, .reload_active_any = false },
        0.05,
    );
    try std.testing.expectEqual(@as(i32, 0), state.player_alt_weapon_swap_cooldown_ms);

    try stepPlayerForTick(
        &state,
        &player,
        &projectiles,
        &secondary_projectiles,
        &creatures,
        &particles,
        .{ .reload_pressed = true, .reload_active_any = true },
        0.05,
    );
    try std.testing.expectEqual(game_ids.WeaponId.assault_rifle, player.weapon_id);
}

test "alternate weapon multiplayer hold is not cleared by other player" {
    var state = state_mod.GameplayState.init(1);
    var projectiles = survival_projectiles.ProjectilePool{};
    var secondary_projectiles = survival_secondary_projectiles.SecondaryProjectilePool{};
    var creatures = survival_creatures.CreaturePool{};
    var particles = survival_particles.ParticlePool{};
    var player0 = state_mod.PlayerState{
        .index = 0,
        .pos = .{},
        .aim = .{ .x = 100.0, .y = 0.0 },
    };
    var player1 = state_mod.PlayerState{
        .index = 1,
        .pos = .{},
        .aim = .{ .x = 100.0, .y = 0.0 },
    };
    player0.perk_counts.set(PerkId.alternate_weapon, 1);
    player1.perk_counts.set(PerkId.alternate_weapon, 1);
    state_mod.weaponAssignPlayer(&player0, game_ids.WeaponId.assault_rifle);
    player0.alt_weapon_id = game_ids.WeaponId.pistol;
    player0.alt_clip_size = 10;
    player0.alt_ammo = 10.0;
    state_mod.weaponAssignPlayer(&player1, game_ids.WeaponId.assault_rifle);
    player1.alt_weapon_id = game_ids.WeaponId.pistol;
    player1.alt_clip_size = 10;
    player1.alt_ammo = 10.0;

    try stepPlayerForTick(
        &state,
        &player0,
        &projectiles,
        &secondary_projectiles,
        &creatures,
        &particles,
        .{ .reload_pressed = true, .reload_active_any = true },
        0.05,
    );
    try std.testing.expectEqual(game_ids.WeaponId.pistol, player0.weapon_id);
    try std.testing.expectEqual(@as(i32, 200), state.player_alt_weapon_swap_cooldown_ms);

    try stepPlayerForTick(
        &state,
        &player1,
        &projectiles,
        &secondary_projectiles,
        &creatures,
        &particles,
        .{ .reload_pressed = false, .reload_active_any = true },
        0.05,
    );
    try std.testing.expect(state.player_alt_weapon_swap_cooldown_ms > 0);
}

test "alternate weapon swap preserves same-tick fire gate" {
    var state = state_mod.GameplayState.init(1);
    var projectiles = survival_projectiles.ProjectilePool{};
    var secondary_projectiles = survival_secondary_projectiles.SecondaryProjectilePool{};
    var creatures = survival_creatures.CreaturePool{};
    var particles = survival_particles.ParticlePool{};
    var player = state_mod.PlayerState{
        .index = 0,
        .pos = .{ .x = 512.0, .y = 512.0 },
        .aim = .{ .x = 700.0, .y = 512.0 },
    };
    player.perk_counts.set(PerkId.alternate_weapon, 1);
    state_mod.weaponAssignPlayer(&player, weaponId(11));
    player.alt_weapon_id = game_ids.WeaponId.pistol;
    player.alt_clip_size = 10;
    player.alt_ammo = 10.0;
    const starting_alt_ammo = player.alt_ammo;

    player.shot_cooldown = 0.05;
    try stepPlayerForTick(
        &state,
        &player,
        &projectiles,
        &secondary_projectiles,
        &creatures,
        &particles,
        .{ .fire_down = true, .reload_pressed = true, .reload_active_any = true },
        0.06,
    );

    try std.testing.expectEqual(game_ids.WeaponId.pistol, player.weapon_id);
    try std.testing.expect(player.ammo < starting_alt_ammo);
}

test "alternate weapon swap allows same-tick fire with swapped reload timer" {
    var state = state_mod.GameplayState.init(1);
    var projectiles = survival_projectiles.ProjectilePool{};
    var secondary_projectiles = survival_secondary_projectiles.SecondaryProjectilePool{};
    var creatures = survival_creatures.CreaturePool{};
    var particles = survival_particles.ParticlePool{};
    var player = state_mod.PlayerState{
        .index = 0,
        .pos = .{ .x = 512.0, .y = 512.0 },
        .aim = .{ .x = 700.0, .y = 512.0 },
    };
    player.perk_counts.set(PerkId.alternate_weapon, 1);
    state_mod.weaponAssignPlayer(&player, weaponId(29));
    player.ammo = 2.0;
    player.reload_active = false;
    player.reload_timer = 0.0;
    player.alt_weapon_id = weaponId(11);
    player.alt_ammo = 0.0;
    player.alt_clip_size = 30;
    player.alt_reload_active = true;
    player.alt_reload_timer = 0.85;
    player.alt_reload_timer_max = 1.3;
    player.alt_shot_cooldown = 0.0;

    player.shot_cooldown = 0.05;
    try stepPlayerForTick(
        &state,
        &player,
        &projectiles,
        &secondary_projectiles,
        &creatures,
        &particles,
        .{ .fire_down = true, .reload_pressed = true, .reload_active_any = true },
        0.06,
    );

    try std.testing.expectEqual(weaponId(11), player.weapon_id);
    try std.testing.expect(player.reload_timer > 0.0);
    try expectFloatClose(player.reload_timer_max, player.reload_timer);
    try std.testing.expect(player.ammo < 0.0);
    try std.testing.expect(player.shot_seq >= 1);
}

test "multi plasma and mini rocket use special shot counts" {
    var state = state_mod.GameplayState.init(1);
    var projectiles = survival_projectiles.ProjectilePool{};
    var secondary_projectiles = survival_secondary_projectiles.SecondaryProjectilePool{};
    var creatures = survival_creatures.CreaturePool{};
    var particles = survival_particles.ParticlePool{};
    var player = state_mod.PlayerState{
        .index = 0,
        .pos = .{},
    };

    state_mod.weaponAssignPlayer(&player, weaponId(10));
    try std.testing.expect(try tryFireWeapon(&state, &player, &projectiles, &secondary_projectiles, &creatures, &particles));
    try std.testing.expectEqual(@as(i32, 5), state.shots_fired[0]);

    state_mod.weaponAssignPlayer(&player, weaponId(17));
    player.ammo = 4.0;
    player.shot_cooldown = 0.0;
    try std.testing.expect(try tryFireWeapon(&state, &player, &projectiles, &secondary_projectiles, &creatures, &particles));
    try std.testing.expectEqual(@as(i32, 9), state.shots_fired[0]);
}

test "multi plasma fires five projectiles with fixed spread profile" {
    var state = state_mod.GameplayState.init(1);
    var projectiles = survival_projectiles.ProjectilePool{};
    var secondary_projectiles = survival_secondary_projectiles.SecondaryProjectilePool{};
    var creatures = survival_creatures.CreaturePool{};
    var particles = survival_particles.ParticlePool{};
    var player = state_mod.PlayerState{
        .index = 0,
        .pos = .{},
        .aim = .{ .x = 200.0, .y = 0.0 },
        .aim_dir = .{ .x = 1.0, .y = 0.0 },
        .spread_heat = 0.0,
    };

    state_mod.weaponAssignPlayer(&player, weaponId(10));
    try std.testing.expect(try tryFireWeapon(&state, &player, &projectiles, &secondary_projectiles, &creatures, &particles));

    try std.testing.expectEqual(@as(usize, 5), activeProjectileCount(&projectiles));
    try std.testing.expectEqual(@as(i32, 5), state.weapon_shots_fired[0][10]);

    const shot_angle = std.math.pi / 2.0;
    const spread_small = std.math.pi / 10.0;
    const spread_large = std.math.pi / 6.0;
    const expected = [_]struct {
        angle: f64,
        type_id: i32,
    }{
        .{ .angle = shot_angle - spread_small, .type_id = @intFromEnum(game_ids.ProjectileTypeId.plasma_rifle) },
        .{ .angle = shot_angle - spread_large, .type_id = @intFromEnum(game_ids.ProjectileTypeId.plasma_minigun) },
        .{ .angle = shot_angle, .type_id = @intFromEnum(game_ids.ProjectileTypeId.plasma_rifle) },
        .{ .angle = shot_angle + spread_large, .type_id = @intFromEnum(game_ids.ProjectileTypeId.plasma_minigun) },
        .{ .angle = shot_angle + spread_small, .type_id = @intFromEnum(game_ids.ProjectileTypeId.plasma_rifle) },
    };

    for (expected, 0..) |entry, idx| {
        const proj = projectiles.entries[idx];
        try std.testing.expect(proj.active);
        try std.testing.expectEqual(entry.type_id, proj.type_id);
        try expectFloatClose(entry.angle, proj.angle);
    }
}

test "plasma shotgun uses masked jitter and random speed scale" {
    const seed = findSeedForNthRandValue(4, 255, 200_000) orelse unreachable;

    var state = state_mod.GameplayState.init(seed);
    var projectiles = survival_projectiles.ProjectilePool{};
    var secondary_projectiles = survival_secondary_projectiles.SecondaryProjectilePool{};
    var creatures = survival_creatures.CreaturePool{};
    var particles = survival_particles.ParticlePool{};
    var player = state_mod.PlayerState{
        .index = 0,
        .pos = .{},
        .aim = .{ .x = 200.0, .y = 0.0 },
        .aim_dir = .{ .x = 1.0, .y = 0.0 },
        .spread_heat = 0.0,
    };

    state_mod.weaponAssignPlayer(&player, weaponId(14));
    try std.testing.expect(try tryFireWeapon(&state, &player, &projectiles, &secondary_projectiles, &creatures, &particles));

    try std.testing.expectEqual(@as(usize, 14), activeProjectileCount(&projectiles));
    try std.testing.expectEqual(@as(i32, 14), state.weapon_shots_fired[0][14]);

    const shot_angle = std.math.pi / 2.0;
    const expected_angle_masked = shot_angle + 127.0 * 0.002;
    const expected_angle_modulo = shot_angle + (@as(f64, @floatFromInt(@as(i32, @intCast(255 % 200)) - 100)) * 0.002);
    try expectFloatClose(expected_angle_masked, projectiles.entries[0].angle);
    try std.testing.expect(@abs(projectiles.entries[0].angle - expected_angle_modulo) > 1e-4);

    var rng = survival_spawn.Crand.init(seed);
    _ = rng.rand();
    _ = rng.rand();
    _ = rng.rand();
    _ = rng.rand();
    const speed_draw = rng.rand();
    const expected_speed = 1.0 + @as(f64, @floatFromInt(speed_draw % 100)) * 0.01;
    try expectFloatClose(expected_speed, projectiles.entries[0].speed_scale);

    for (projectiles.entries[0..14]) |proj| {
        try std.testing.expectEqual(@intFromEnum(game_ids.ProjectileTypeId.plasma_minigun), proj.type_id);
    }
}

test "plasma shotgun consumes one ammo per shot" {
    var state = state_mod.GameplayState.init(1);
    var projectiles = survival_projectiles.ProjectilePool{};
    var secondary_projectiles = survival_secondary_projectiles.SecondaryProjectilePool{};
    var creatures = survival_creatures.CreaturePool{};
    var particles = survival_particles.ParticlePool{};
    var player = state_mod.PlayerState{
        .index = 0,
        .pos = .{},
        .aim = .{ .x = 200.0, .y = 0.0 },
        .aim_dir = .{ .x = 1.0, .y = 0.0 },
        .spread_heat = 0.0,
    };

    state_mod.weaponAssignPlayer(&player, weaponId(14));
    const start_ammo = player.ammo;
    try std.testing.expect(try tryFireWeapon(&state, &player, &projectiles, &secondary_projectiles, &creatures, &particles));
    try expectFloatClose(start_ammo - 1.0, player.ammo);
}

test "shotgun family fires expected pellet counts and formulas" {
    const cases = [_]struct {
        weapon_id: i32,
        projectile_type_id: i32,
        expected_count: usize,
        jitter_scale: f64,
        speed_base: f64,
        speed_mod: u32,
    }{
        .{
            .weapon_id = 20,
            .projectile_type_id = @intFromEnum(game_ids.ProjectileTypeId.shotgun),
            .expected_count = 4,
            .jitter_scale = 0.0013,
            .speed_base = 1.0,
            .speed_mod = 100,
        },
        .{
            .weapon_id = 30,
            .projectile_type_id = @intFromEnum(game_ids.ProjectileTypeId.gauss_gun),
            .expected_count = 6,
            .jitter_scale = 0.002,
            .speed_base = 1.4,
            .speed_mod = 0x50,
        },
        .{
            .weapon_id = 31,
            .projectile_type_id = @intFromEnum(game_ids.ProjectileTypeId.ion_minigun),
            .expected_count = 8,
            .jitter_scale = 0.0026,
            .speed_base = 1.4,
            .speed_mod = 0x50,
        },
    };

    for (cases) |case| {
        var state = state_mod.GameplayState.init(0);
        var projectiles = survival_projectiles.ProjectilePool{};
        var secondary_projectiles = survival_secondary_projectiles.SecondaryProjectilePool{};
        var creatures = survival_creatures.CreaturePool{};
        var particles = survival_particles.ParticlePool{};
        var player = state_mod.PlayerState{
            .index = 0,
            .pos = .{},
            .aim = .{ .x = 200.0, .y = 0.0 },
            .aim_dir = .{ .x = 1.0, .y = 0.0 },
            .spread_heat = 0.0,
        };

        state_mod.weaponAssignPlayer(&player, weaponId(case.weapon_id));
        try std.testing.expect(try tryFireWeapon(&state, &player, &projectiles, &secondary_projectiles, &creatures, &particles));
        try std.testing.expectEqual(case.expected_count, activeProjectileCount(&projectiles));
        try std.testing.expectEqual(@as(i32, @intCast(case.expected_count)), state.weapon_shots_fired[0][@intCast(case.weapon_id)]);

        var rng = survival_spawn.Crand.init(0);
        if ((state_mod.weaponFlags(weaponId(case.weapon_id)) & 0x1) != 0) {
            _ = rng.rand();
            _ = rng.rand();
            _ = rng.rand();
            _ = rng.rand();
        }
        _ = rng.rand();
        _ = rng.rand();
        _ = rng.rand();
        const muzzle_rng_count: usize = switch (case.weapon_id) {
            20 => 1,
            30 => 2,
            else => 0,
        };
        for (0..muzzle_rng_count) |_| {
            _ = rng.rand();
        }

        const shot_angle = std.math.pi / 2.0;
        for (0..case.expected_count) |idx| {
            const jitter_draw = rng.rand();
            const expected_angle = shot_angle +
                @as(f64, @floatFromInt(@as(i32, @intCast(jitter_draw % 200)) - 100)) * case.jitter_scale;
            const speed_draw = rng.rand();
            const expected_speed = case.speed_base + @as(f64, @floatFromInt(speed_draw % case.speed_mod)) * 0.01;

            const proj = projectiles.entries[idx];
            try std.testing.expect(proj.active);
            try std.testing.expectEqual(case.projectile_type_id, proj.type_id);
            try expectFloatClose(expected_angle, proj.angle);
            try expectFloatClose(expected_speed, proj.speed_scale);
        }
    }
}

test "fire bullets on shotgun spawns pellet count projectiles and keeps ammo" {
    var state = state_mod.GameplayState.init(1);
    var projectiles = survival_projectiles.ProjectilePool{};
    var secondary_projectiles = survival_secondary_projectiles.SecondaryProjectilePool{};
    var creatures = survival_creatures.CreaturePool{};
    var particles = survival_particles.ParticlePool{};
    var player = state_mod.PlayerState{
        .index = 0,
        .pos = .{ .x = 100.0, .y = 100.0 },
        .aim = .{ .x = 101.0, .y = 100.0 },
        .aim_dir = .{ .x = 1.0, .y = 0.0 },
        .spread_heat = 0.01,
    };
    state_mod.weaponAssignPlayer(&player, weaponId(3));
    player.fire_bullets_timer = 1.0;
    const start_ammo = player.ammo;

    try std.testing.expect(try tryFireWeapon(&state, &player, &projectiles, &secondary_projectiles, &creatures, &particles));

    try std.testing.expectEqual(@as(usize, 12), activeProjectileCount(&projectiles));
    try std.testing.expectEqual(@as(usize, 0), activeSecondaryProjectileCount(&secondary_projectiles));
    try expectFloatClose(start_ammo, player.ammo);
    try expectFloatClose(0.296, player.spread_heat);
    for (projectiles.entries[0..12]) |proj| {
        try std.testing.expect(proj.active);
        try std.testing.expectEqual(@intFromEnum(game_ids.ProjectileTypeId.fire_bullets), proj.type_id);
    }
}

test "fire bullets overrides rocket family into primary projectile pool" {
    const rocket_weapon_ids = [_]i32{ 12, 13, 17, 18 };
    for (rocket_weapon_ids) |weapon_id| {
        var state = state_mod.GameplayState.init(1);
        var projectiles = survival_projectiles.ProjectilePool{};
        var secondary_projectiles = survival_secondary_projectiles.SecondaryProjectilePool{};
        var creatures = survival_creatures.CreaturePool{};
        var particles = survival_particles.ParticlePool{};
        var player = state_mod.PlayerState{
            .index = 0,
            .pos = .{},
            .aim = .{ .x = 200.0, .y = 0.0 },
            .aim_dir = .{ .x = 1.0, .y = 0.0 },
            .spread_heat = 0.0,
        };
        state_mod.weaponAssignPlayer(&player, weaponId(weapon_id));
        player.fire_bullets_timer = 1.0;

        try std.testing.expect(try tryFireWeapon(&state, &player, &projectiles, &secondary_projectiles, &creatures, &particles));

        const expected_count: usize = @intCast(@max(0, state_mod.weaponPelletCount(weaponId(weapon_id))));
        try std.testing.expectEqual(expected_count, activeProjectileCount(&projectiles));
        try std.testing.expectEqual(@as(usize, 0), activeSecondaryProjectileCount(&secondary_projectiles));
        for (0..expected_count) |idx| {
            const proj = projectiles.entries[idx];
            try std.testing.expect(proj.active);
            try std.testing.expectEqual(@intFromEnum(game_ids.ProjectileTypeId.fire_bullets), proj.type_id);
        }
    }
}

test "fire bullets can fire at zero ammo and then trigger reload" {
    var state = state_mod.GameplayState.init(1);
    var projectiles = survival_projectiles.ProjectilePool{};
    var secondary_projectiles = survival_secondary_projectiles.SecondaryProjectilePool{};
    var creatures = survival_creatures.CreaturePool{};
    var particles = survival_particles.ParticlePool{};
    var player = state_mod.PlayerState{
        .index = 0,
        .pos = .{ .x = 100.0, .y = 100.0 },
        .aim = .{ .x = 101.0, .y = 100.0 },
        .aim_dir = .{ .x = 1.0, .y = 0.0 },
    };
    state_mod.weaponAssignPlayer(&player, weaponId(3));
    player.ammo = 0.0;
    player.fire_bullets_timer = 1.0;

    try std.testing.expect(try tryFireWeapon(&state, &player, &projectiles, &secondary_projectiles, &creatures, &particles));

    try std.testing.expectEqual(@as(usize, 12), activeProjectileCount(&projectiles));
    for (projectiles.entries[0..12]) |proj| {
        try std.testing.expect(proj.active);
        try std.testing.expectEqual(@intFromEnum(game_ids.ProjectileTypeId.fire_bullets), proj.type_id);
    }
    try std.testing.expect(player.reload_active);
    try std.testing.expect(player.reload_timer > 0.0);
}

test "negative ammo still fires then enters reload for non fire bullets" {
    var state = state_mod.GameplayState.init(1);
    var projectiles = survival_projectiles.ProjectilePool{};
    var secondary_projectiles = survival_secondary_projectiles.SecondaryProjectilePool{};
    var creatures = survival_creatures.CreaturePool{};
    var particles = survival_particles.ParticlePool{};
    var player = state_mod.PlayerState{
        .index = 0,
        .pos = .{ .x = 100.0, .y = 100.0 },
        .aim = .{ .x = 200.0, .y = 100.0 },
        .aim_dir = .{ .x = 1.0, .y = 0.0 },
        .reload_active = false,
        .reload_timer = 0.0,
    };
    state_mod.weaponAssignPlayer(&player, game_ids.WeaponId.ion_cannon);
    player.ammo = -1.0;

    try std.testing.expect(try tryFireWeapon(&state, &player, &projectiles, &secondary_projectiles, &creatures, &particles));

    try std.testing.expect(projectiles.entries[0].active);
    try std.testing.expectEqual(@intFromEnum(game_ids.ProjectileTypeId.ion_cannon), projectiles.entries[0].type_id);
    try expectFloatClose(-2.0, player.ammo);
    try std.testing.expect(player.reload_active);
    try expectFloatClose(3.0, player.reload_timer);
}

test "pistol fire consumes native casing+jitter+sfx rng draws" {
    var state = state_mod.GameplayState.init(123);
    var player = state_mod.PlayerState{
        .index = 0,
        .pos = .{},
    };
    var projectiles = survival_projectiles.ProjectilePool{};
    var secondary_projectiles = survival_secondary_projectiles.SecondaryProjectilePool{};
    var creatures = survival_creatures.CreaturePool{};
    var particles = survival_particles.ParticlePool{};
    state_mod.weaponAssignPlayer(&player, game_ids.WeaponId.pistol);
    try std.testing.expect(try tryFireWeapon(&state, &player, &projectiles, &secondary_projectiles, &creatures, &particles));
    try std.testing.expect(projectiles.entries[0].active);
}

test "fastshot scales shot cooldown" {
    var base_state = state_mod.GameplayState.init(1);
    var base_projectiles = survival_projectiles.ProjectilePool{};
    var base_secondary_projectiles = survival_secondary_projectiles.SecondaryProjectilePool{};
    var base_creatures = survival_creatures.CreaturePool{};
    var base_particles = survival_particles.ParticlePool{};
    var base_player = state_mod.PlayerState{
        .index = 0,
        .pos = .{},
        .aim = .{ .x = 10.0, .y = 0.0 },
    };
    state_mod.weaponAssignPlayer(&base_player, game_ids.WeaponId.pistol);
    base_player.ammo = 2.0;
    try std.testing.expect(try tryFireWeapon(
        &base_state,
        &base_player,
        &base_projectiles,
        &base_secondary_projectiles,
        &base_creatures,
        &base_particles,
    ));
    const base_cooldown = base_player.shot_cooldown;

    var perk_state = state_mod.GameplayState.init(1);
    var perk_projectiles = survival_projectiles.ProjectilePool{};
    var perk_secondary_projectiles = survival_secondary_projectiles.SecondaryProjectilePool{};
    var perk_creatures = survival_creatures.CreaturePool{};
    var perk_particles = survival_particles.ParticlePool{};
    var perk_player = state_mod.PlayerState{
        .index = 0,
        .pos = .{},
        .aim = .{ .x = 10.0, .y = 0.0 },
    };
    state_mod.weaponAssignPlayer(&perk_player, game_ids.WeaponId.pistol);
    perk_player.ammo = 2.0;
    perk_player.perk_counts.set(PerkId.fastshot, 1);
    try std.testing.expect(try tryFireWeapon(
        &perk_state,
        &perk_player,
        &perk_projectiles,
        &perk_secondary_projectiles,
        &perk_creatures,
        &perk_particles,
    ));

    try expectFloatClose(narrowF32(base_cooldown * 0.88), perk_player.shot_cooldown);
}

test "sharpshooter forces spread heat and slows firing" {
    var state = state_mod.GameplayState.init(1);
    var projectiles = survival_projectiles.ProjectilePool{};
    var secondary_projectiles = survival_secondary_projectiles.SecondaryProjectilePool{};
    var creatures = survival_creatures.CreaturePool{};
    var particles = survival_particles.ParticlePool{};
    var player = state_mod.PlayerState{
        .index = 0,
        .pos = .{ .x = 100.0, .y = 100.0 },
        .aim = .{ .x = 200.0, .y = 100.0 },
        .spread_heat = 0.48,
    };
    state_mod.weaponAssignPlayer(&player, game_ids.WeaponId.assault_rifle);
    player.perk_counts.set(PerkId.sharpshooter, 1);

    try stepPlayerForTick(
        &state,
        &player,
        &projectiles,
        &secondary_projectiles,
        &creatures,
        &particles,
        .{},
        0.1,
    );
    try expectFloatClose(0.02, player.spread_heat);

    player.shot_cooldown = 0.0;
    try std.testing.expect(try tryFireWeapon(
        &state,
        &player,
        &projectiles,
        &secondary_projectiles,
        &creatures,
        &particles,
    ));
    try expectFloatClose(
        narrowF32(state_mod.weaponShotCooldown(game_ids.WeaponId.assault_rifle) * 1.05),
        player.shot_cooldown,
    );
    try expectFloatClose(0.02, player.spread_heat);
}

test "regression bullets fires during reload and costs experience" {
    var state = state_mod.GameplayState.init(1);
    var projectiles = survival_projectiles.ProjectilePool{};
    var secondary_projectiles = survival_secondary_projectiles.SecondaryProjectilePool{};
    var creatures = survival_creatures.CreaturePool{};
    var particles = survival_particles.ParticlePool{};
    var player = state_mod.PlayerState{
        .index = 0,
        .pos = .{},
        .aim = .{ .x = 10.0, .y = 0.0 },
        .experience = 1000,
    };
    state_mod.weaponAssignPlayer(&player, game_ids.WeaponId.pistol);
    player.perk_counts.set(PerkId.regression_bullets, 1);
    player.ammo = 0.0;
    player.reload_active = true;
    player.reload_timer = 0.5;

    try std.testing.expect(try tryFireWeapon(
        &state,
        &player,
        &projectiles,
        &secondary_projectiles,
        &creatures,
        &particles,
    ));

    try std.testing.expectEqual(@as(i32, 759), player.experience);
    try std.testing.expect(projectiles.entries[0].active);
    try expectFloatClose(-1.0, player.ammo);
}

test "regression bullets blocks fire when experience is zero" {
    var state = state_mod.GameplayState.init(1);
    var projectiles = survival_projectiles.ProjectilePool{};
    var secondary_projectiles = survival_secondary_projectiles.SecondaryProjectilePool{};
    var creatures = survival_creatures.CreaturePool{};
    var particles = survival_particles.ParticlePool{};
    var player = state_mod.PlayerState{
        .index = 0,
        .pos = .{},
        .aim = .{ .x = 10.0, .y = 0.0 },
        .experience = 0,
    };
    state_mod.weaponAssignPlayer(&player, game_ids.WeaponId.pistol);
    player.perk_counts.set(PerkId.regression_bullets, 1);
    player.ammo = 0.0;
    player.reload_active = true;
    player.reload_timer = 0.5;

    try std.testing.expect(!(try tryFireWeapon(
        &state,
        &player,
        &projectiles,
        &secondary_projectiles,
        &creatures,
        &particles,
    )));
    try std.testing.expect(!projectiles.entries[0].active);
}

test "regression bullets fire ammo class drains reduced xp and spends fractional ammo" {
    var state = state_mod.GameplayState.init(1);
    var projectiles = survival_projectiles.ProjectilePool{};
    var secondary_projectiles = survival_secondary_projectiles.SecondaryProjectilePool{};
    var creatures = survival_creatures.CreaturePool{};
    var particles = survival_particles.ParticlePool{};
    var player = state_mod.PlayerState{
        .index = 0,
        .pos = .{},
        .aim = .{ .x = 10.0, .y = 0.0 },
        .experience = 1000,
    };
    state_mod.weaponAssignPlayer(&player, game_ids.WeaponId.flamethrower);
    player.perk_counts.set(PerkId.regression_bullets, 1);
    player.ammo = 5.0;
    player.reload_active = true;
    player.reload_timer = 0.5;

    try std.testing.expect(try tryFireWeapon(
        &state,
        &player,
        &projectiles,
        &secondary_projectiles,
        &creatures,
        &particles,
    ));

    try std.testing.expectEqual(@as(i32, 992), player.experience);
    try std.testing.expect(particles.entries[0].active);
    try expectFloatClose(4.9, player.ammo);
}

test "ammunition within fires during reload and costs health" {
    var state = state_mod.GameplayState.init(1);
    var projectiles = survival_projectiles.ProjectilePool{};
    var secondary_projectiles = survival_secondary_projectiles.SecondaryProjectilePool{};
    var creatures = survival_creatures.CreaturePool{};
    var particles = survival_particles.ParticlePool{};
    var player = state_mod.PlayerState{
        .index = 0,
        .pos = .{},
        .aim = .{ .x = 10.0, .y = 0.0 },
        .health = 10.0,
        .experience = 1,
    };
    state_mod.weaponAssignPlayer(&player, game_ids.WeaponId.pistol);
    player.perk_counts.set(PerkId.ammunition_within, 1);
    player.ammo = 0.0;
    player.reload_active = true;
    player.reload_timer = 0.5;

    try std.testing.expect(try tryFireWeapon(
        &state,
        &player,
        &projectiles,
        &secondary_projectiles,
        &creatures,
        &particles,
    ));

    try expectFloatClose(9.0, player.health);
    try std.testing.expectEqual(@as(i32, 1), player.experience);
    try std.testing.expect(projectiles.entries[0].active);
    try expectFloatClose(-1.0, player.ammo);
}

test "ammunition within blocks fire when experience is zero" {
    var state = state_mod.GameplayState.init(1);
    var projectiles = survival_projectiles.ProjectilePool{};
    var secondary_projectiles = survival_secondary_projectiles.SecondaryProjectilePool{};
    var creatures = survival_creatures.CreaturePool{};
    var particles = survival_particles.ParticlePool{};
    var player = state_mod.PlayerState{
        .index = 0,
        .pos = .{},
        .aim = .{ .x = 10.0, .y = 0.0 },
        .health = 10.0,
        .experience = 0,
    };
    state_mod.weaponAssignPlayer(&player, game_ids.WeaponId.pistol);
    player.perk_counts.set(PerkId.ammunition_within, 1);
    player.ammo = 0.0;
    player.reload_active = true;
    player.reload_timer = 0.5;

    try std.testing.expect(!(try tryFireWeapon(
        &state,
        &player,
        &projectiles,
        &secondary_projectiles,
        &creatures,
        &particles,
    )));
    try expectFloatClose(10.0, player.health);
    try std.testing.expect(!projectiles.entries[0].active);
}

test "ammunition within fire ammo class costs less health and spends fractional ammo" {
    var state = state_mod.GameplayState.init(1);
    var projectiles = survival_projectiles.ProjectilePool{};
    var secondary_projectiles = survival_secondary_projectiles.SecondaryProjectilePool{};
    var creatures = survival_creatures.CreaturePool{};
    var particles = survival_particles.ParticlePool{};
    var player = state_mod.PlayerState{
        .index = 0,
        .pos = .{},
        .aim = .{ .x = 10.0, .y = 0.0 },
        .health = 10.0,
        .experience = 1,
    };
    state_mod.weaponAssignPlayer(&player, game_ids.WeaponId.flamethrower);
    player.perk_counts.set(PerkId.ammunition_within, 1);
    player.ammo = 5.0;
    player.reload_active = true;
    player.reload_timer = 0.5;

    try std.testing.expect(try tryFireWeapon(
        &state,
        &player,
        &projectiles,
        &secondary_projectiles,
        &creatures,
        &particles,
    ));

    try expectFloatClose(narrowF32(9.85), player.health);
    try std.testing.expect(particles.entries[0].active);
    try expectFloatClose(4.9, player.ammo);
}
