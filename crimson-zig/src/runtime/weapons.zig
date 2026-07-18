const std = @import("std");
const game_ids = @import("../game_ids.zig");
const native_math = @import("native_math.zig");

const creatures_mod = @import("creatures.zig");
const effects_mod = @import("effects.zig");
const fire_recipes = @import("fire_recipes.zig");
const owner_ref = @import("owner_ref.zig");
const particles_mod = @import("particles.zig");
const perks = @import("perks.zig");
const player_runtime = @import("player.zig");
const projectiles_mod = @import("projectiles.zig");
const rng_callers = @import("../rng_caller_static.zig");
const secondary_projectiles_mod = @import("secondary_projectiles.zig");
const state_mod = @import("state.zig");
const survival_progression = @import("survival_progression.zig");
const spawn_mod = @import("spawn.zig");
const weapon_data = @import("weapon_data.zig");
const math = @import("math.zig");
const timing = @import("timing.zig");

const narrowF32 = native_math.roundF32;
const native_pi: f32 = native_math.native_pi;
const native_tau: f32 = native_math.native_tau;

const WeaponId = game_ids.WeaponId;
const ProjectileTypeId = game_ids.ProjectileTypeId;
const PerkId = perks.PerkId;

pub const WeaponRuntimeError = error{};

pub const PlayerDamageRuntime = struct {
    context: ?*anyopaque = null,
    on_player_damage: *const fn (
        context: ?*anyopaque,
        player_index: i32,
        health_before: f32,
        player1_health_before: f32,
        dt: f32,
    ) void,
};

const movement_control_mouse_point_click: i32 = 4;

const MuzzleSpriteSpec = struct {
    speed: f32,
    scale: f32,
    alpha: f32,
};

const fire_bullets_muzzle_specs = [_]MuzzleSpriteSpec{
    .{ .speed = 25.0, .scale = 1.0, .alpha = 0.413 },
};

inline fn weaponId(value: i32) WeaponId {
    return weapon_data.weaponIdFromInt(value);
}

inline fn weaponIdFromProjectileTypeId(type_id: ProjectileTypeId) WeaponId {
    return switch (type_id) {
        .shrinkifier => .shrinkifier_5k,
        .plague_spreader => .plague_spreader_gun,
        else => @enumFromInt(@intFromEnum(type_id)),
    };
}

inline fn projectileTravelBudgetFromTypeId(type_id: ProjectileTypeId) f32 {
    return weapon_data.weapon_stats.get(weaponIdFromProjectileTypeId(type_id)).travel_budget;
}

fn projectileSpawnFireBulletsActive(
    state: *const state_mod.GameplayState,
    player: *const state_mod.PlayerState,
    all_players: ?[]const state_mod.PlayerState,
) bool {
    if (!state.preserve_bugs) return player.fire_bullets_timer > 0.0;

    const players = all_players orelse return player.fire_bullets_timer > 0.0;
    for (players[0..@min(players.len, 2)]) |candidate| {
        if (candidate.fire_bullets_timer > 0.0) return true;
    }
    return false;
}

inline fn projectileSpawnType(
    type_id: ProjectileTypeId,
    fire_bullets_override: bool,
) ProjectileTypeId {
    return if (fire_bullets_override and type_id != .fire_bullets)
        .fire_bullets
    else
        type_id;
}

fn playerUpdatePerkSource(
    state: *const state_mod.GameplayState,
    player: *const state_mod.PlayerState,
    all_players: ?[]const state_mod.PlayerState,
) *const state_mod.PlayerState {
    if (!state.preserve_bugs) return player;
    const players = all_players orelse return player;
    if (players.len == 0) return player;
    return &players[0];
}

pub const TickInputFlags = struct {
    fire_down: bool = false,
    fire_pressed: bool = false,
    reload_pressed: bool = false,
    reload_down: bool = false,
    reload_active_any: bool = false,
    move_mode: i32 = 0,
    single_player_mode: bool = true,
    preprocessed_player_tick: bool = false,
};

pub fn preprocessPlayerForPerkTicks(
    state: *state_mod.GameplayState,
    player: *state_mod.PlayerState,
    dt: f32,
) bool {
    var effects: effects_mod.EffectPool = .{};
    return preprocessPlayerForPerkTicksWithEffects(state, player, &effects, 5, dt);
}

pub fn preprocessPlayerForPerkTicksWithEffects(
    state: *state_mod.GameplayState,
    player: *state_mod.PlayerState,
    effects: *effects_mod.EffectPool,
    detail_preset: i32,
    dt: f32,
) bool {
    if (!(dt > 0.0)) return false;

    if (player.health <= 0.0) {
        player.death_timer = narrowF32(player.death_timer - dt * 20.0);
        return false;
    }

    if (player.low_health_timer != 100.0 and player.health < 20.0) {
        const next_low_health_timer = narrowF32(player.low_health_timer - dt);
        player.low_health_timer = next_low_health_timer;
        if (next_low_health_timer < 0.0) {
            const bleed_dir_angle = native_math.pc24Sub(
                native_math.pc24Add(player.aim_heading, native_math.native_half_pi),
                @as(f32, 0.5),
            );
            const bleed_pos: state_mod.Vec2 = .{
                .x = native_math.pc24Add(
                    native_math.pc24Mul(@cos(@as(f64, bleed_dir_angle)), @as(f32, -6.0)),
                    player.pos.x,
                ),
                .y = native_math.pc24Add(
                    native_math.pc24Mul(@sin(@as(f64, bleed_dir_angle)), @as(f32, -6.0)),
                    player.pos.y,
                ),
            };
            for (0..3) |_| {
                effects.spawnBloodSplatter(
                    state,
                    bleed_pos,
                    player.aim_heading,
                    0.0,
                    detail_preset,
                    state.gore_disabled,
                );
            }
            const bloodspill_roll = state.rng.randTagged(rng_callers.player_update_low_health_bloodspill) & 1;
            state.sfx_queue.append(if (bloodspill_roll == 0) .bloodspill_01 else .bloodspill_02);
            player.low_health_timer = 1.0;
        }
    }

    player.muzzle_flash_alpha = @max(0.0, narrowF32(player.muzzle_flash_alpha - dt * 2.0));

    return true;
}

test "dead player preprocessing only advances death timer" {
    var state = state_mod.GameplayState.init(1);
    var player: state_mod.PlayerState = .{
        .index = 0,
        .pos = .{},
        .health = 0.0,
        .death_timer = 16.0,
        .low_health_timer = 0.25,
        .muzzle_flash_alpha = 0.75,
        .weapon = .{ .weapon_id = .pistol, .shot_cooldown = 0.5 },
    };

    try std.testing.expect(!preprocessPlayerForPerkTicks(&state, &player, 0.1));
    try std.testing.expectEqual(narrowF32(16.0 - 0.1 * 20.0), player.death_timer);
    try std.testing.expectEqual(@as(f32, 0.25), player.low_health_timer);
    try std.testing.expectEqual(@as(f32, 0.75), player.muzzle_flash_alpha);
    try std.testing.expectEqual(@as(f32, 0.5), player.weapon.shot_cooldown);
}

test "low-health preprocessing offsets blood effects from the player" {
    var state = state_mod.GameplayState.init(1);
    var effects: effects_mod.EffectPool = .{};
    var player: state_mod.PlayerState = .{
        .index = 0,
        .pos = .{ .x = 100.0, .y = 200.0 },
        .health = 19.0,
        .low_health_timer = 0.0,
        .aim_heading = 1.25,
        .weapon = .{ .weapon_id = .pistol },
    };

    try std.testing.expect(preprocessPlayerForPerkTicksWithEffects(
        &state,
        &player,
        &effects,
        5,
        0.016,
    ));

    const bleed_dir_angle = native_math.pc24Sub(
        native_math.pc24Add(player.aim_heading, native_math.native_half_pi),
        @as(f32, 0.5),
    );
    const expected_pos: state_mod.Vec2 = .{
        .x = native_math.pc24Add(
            native_math.pc24Mul(@cos(@as(f64, bleed_dir_angle)), @as(f32, -6.0)),
            player.pos.x,
        ),
        .y = native_math.pc24Add(
            native_math.pc24Mul(@sin(@as(f64, bleed_dir_angle)), @as(f32, -6.0)),
            player.pos.y,
        ),
    };
    for (effects.entries[0..6]) |entry| {
        try std.testing.expectEqual(@intFromEnum(effects_mod.EffectId.blood_splatter), entry.effect_id);
        try std.testing.expectEqual(expected_pos.x, entry.pos.x);
        try std.testing.expectEqual(expected_pos.y, entry.pos.y);
    }
    try std.testing.expectEqual(@as(f32, 1.0), player.low_health_timer);
    try std.testing.expectEqual(@as(usize, 1), state.sfx_queue.len);
}

pub fn stepPlayerForTick(
    state: *state_mod.GameplayState,
    player: *state_mod.PlayerState,
    projectiles: *projectiles_mod.ProjectilePool,
    secondary_projectiles: *secondary_projectiles_mod.SecondaryProjectilePool,
    creatures: *creatures_mod.CreaturePool,
    particles: *particles_mod.ParticlePool,
    input_flags: TickInputFlags,
    dt: f32,
) WeaponRuntimeError!void {
    var effects: effects_mod.EffectPool = .{};
    var sprite_effects: effects_mod.SpriteEffectPool = .{};
    return stepPlayerForTickWithEffects(
        state,
        player,
        null,
        projectiles,
        secondary_projectiles,
        creatures,
        particles,
        &effects,
        &sprite_effects,
        null,
        5,
        input_flags,
        dt,
    );
}

pub fn stepPlayerForTickWithEffects(
    state: *state_mod.GameplayState,
    player: *state_mod.PlayerState,
    all_players: ?[]const state_mod.PlayerState,
    projectiles: *projectiles_mod.ProjectilePool,
    secondary_projectiles: *secondary_projectiles_mod.SecondaryProjectilePool,
    creatures: *creatures_mod.CreaturePool,
    particles: *particles_mod.ParticlePool,
    effects: *effects_mod.EffectPool,
    sprite_effects: *effects_mod.SpriteEffectPool,
    player_damage_runtime: ?PlayerDamageRuntime,
    detail_preset: i32,
    input_flags: TickInputFlags,
    dt: f32,
) WeaponRuntimeError!void {
    if (!(dt > 0.0)) return;

    if (!input_flags.preprocessed_player_tick) {
        if (!preprocessPlayerForPerkTicksWithEffects(state, player, effects, detail_preset, dt)) return;
    } else if (player.health <= 0.0) {
        return;
    }

    const perk_player = playerUpdatePerkSource(state, player, all_players);

    const cooldown_scale: f32 = if (state.bonuses.weapon_power_up > 0.0) 1.5 else 1.0;
    const cooldown_decay = narrowF32(
        @as(f64, @floatCast(dt)) * @as(f64, @floatCast(cooldown_scale)),
    );
    const next_shot_cooldown = narrowF32(
        @as(f64, @floatCast(player.weapon.shot_cooldown)) - @as(f64, @floatCast(cooldown_decay)),
    );
    player.weapon.shot_cooldown = @max(0.0, next_shot_cooldown);

    const reload_scale: f32 = if (player.reload_stationary_latch and perks.perkActive(perk_player, PerkId.stationary_reloader))
        3.0
    else
        1.0;
    if (perks.perkActive(perk_player, PerkId.anxious_loader) and input_flags.fire_pressed and player.weapon.reload_timer > 0.0) {
        const anxious_next = native_math.pc24Sub(player.weapon.reload_timer, @as(f32, 0.05));
        player.weapon.reload_timer = anxious_next;
        if (anxious_next <= 0.0) {
            player.weapon.reload_timer = native_math.pc24Mul(dt, @as(f32, 0.8));
        }
    }

    const reload_timer_now = narrowF32(player.weapon.reload_timer);
    const reload_step = native_math.pc24Mul(reload_scale, dt);
    var preload_dt = dt;
    if (!state.preserve_bugs) {
        preload_dt = reload_step;
    }
    const reload_preload_underflow = native_math.pc24Sub(reload_timer_now, preload_dt);
    if (reload_timer_now > 0.0 and reload_preload_underflow < 0.0) {
        player.weapon.ammo = @floatFromInt(@max(0, player.weapon.clip_size));
    }

    if (player.weapon.reload_timer > 0.0) {
        if (perks.perkActive(perk_player, PerkId.angry_reloader) and
            player.weapon.reload_timer_max > 0.5 and
            player.weapon.reload_timer > native_math.pc24Mul(player.weapon.reload_timer_max, @as(f32, 0.5)))
        {
            const half_reload = native_math.pc24Mul(player.weapon.reload_timer_max, @as(f32, 0.5));
            const next_timer = native_math.pc24Sub(player.weapon.reload_timer, reload_step);
            player.weapon.reload_timer = next_timer;
            if (next_timer <= half_reload) {
                const count = 7 + @as(i32, @intFromFloat(player.weapon.reload_timer_max * 4.0));
                state.bonus_spawn_guard = true;

                const owner = if (!state.friendly_fire_enabled)
                    owner_ref.OwnerRef.fromLocalPlayer(0)
                else
                    owner_ref.OwnerRef.fromPlayer(@intCast(player.index));
                if (count > 0) {
                    const step = native_tau / @as(f32, @floatFromInt(count));
                    for (0..@as(usize, @intCast(count))) |idx| {
                        const angle = @as(f32, @floatFromInt(idx)) * step + 0.1;
                        const type_id = @intFromEnum(game_ids.ProjectileTypeId.plasma_minigun);
                        const meta = weapon_data.weapon_stats.get(.plasma_minigun).travel_budget;
                        _ = projectiles.spawn(player.pos, angle, type_id, owner, meta, false);
                    }
                }
                state.bonus_spawn_guard = false;
            }
        } else {
            player.weapon.reload_timer = native_math.pc24Sub(player.weapon.reload_timer, reload_step);
        }
        if (player.weapon.reload_timer < 0.0) {
            player.weapon.reload_timer = 0.0;
        }
    }

    const has_alt_weapon_perk = perks.perkActive(perk_player, PerkId.alternate_weapon);
    // Native gates on grim_is_key_active (key held), so holding reload chains
    // reloads back-to-back as each one completes.
    const manual_reload_allowed =
        (input_flags.reload_down or input_flags.reload_pressed) and
        !state.demo_mode_active and
        !has_alt_weapon_perk and
        input_flags.move_mode != movement_control_mouse_point_click and
        input_flags.single_player_mode and
        player.weapon.reload_timer == 0.0;
    if (manual_reload_allowed) {
        player_runtime.playerStartReloadWithPlayers(player, state, all_players);
    }

    if (perks.perkActive(perk_player, PerkId.sharpshooter)) {
        player.spread_heat = 0.02;
    } else {
        player.spread_heat = @max(
            @as(f32, 0.01),
            native_math.pc24Sub(player.spread_heat, native_math.pc24Mul(dt, @as(f32, 0.4))),
        );
    }

    if (player.weapon.shot_cooldown <= 0.0 and player.weapon.reload_timer == 0.0) {
        player.weapon.reload_active = false;
    }

    const fire_gate_open_pre_reload = player.weapon.shot_cooldown <= 0.0 and player.weapon.reload_timer == 0.0;
    var swapped_alt_weapon = false;
    const reload_key_active = input_flags.reload_down or input_flags.reload_pressed;
    const reload_key_released = !input_flags.reload_active_any;
    if (has_alt_weapon_perk) {
        var cooldown_ms = state.player_alt_weapon_swap_cooldown_ms;
        const dt_ms: i32 = if (dt > 0.0) timing.ftolMsI32(dt) else 0;
        if (cooldown_ms < 1) {
            cooldown_ms = 0;
        } else {
            cooldown_ms -= dt_ms;
        }

        if (cooldown_ms < 1 and reload_key_active) {
            if (player_runtime.playerSwapAltWeapon(player)) {
                swapped_alt_weapon = true;
                player.weapon.shot_cooldown = narrowF32(player.weapon.shot_cooldown + 0.1);
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
        player.weapon.shot_cooldown = 0.0;
    }

    if (input_flags.fire_down) {
        _ = try tryFireWeaponWithForce(
            state,
            player,
            all_players,
            projectiles,
            secondary_projectiles,
            creatures,
            particles,
            effects,
            sprite_effects,
            player_damage_runtime,
            detail_preset,
            dt,
            force_pre_swap_fire_gate,
        );
    }
}

pub fn tryFireWeapon(
    state: *state_mod.GameplayState,
    player: *state_mod.PlayerState,
    projectiles: *projectiles_mod.ProjectilePool,
    secondary_projectiles: *secondary_projectiles_mod.SecondaryProjectilePool,
    creatures: *creatures_mod.CreaturePool,
    particles: *particles_mod.ParticlePool,
) WeaponRuntimeError!bool {
    var effects: effects_mod.EffectPool = .{};
    var sprite_effects: effects_mod.SpriteEffectPool = .{};
    return tryFireWeaponWithEffects(
        state,
        player,
        projectiles,
        secondary_projectiles,
        creatures,
        particles,
        &effects,
        &sprite_effects,
        5,
    );
}

pub fn tryFireWeaponWithEffects(
    state: *state_mod.GameplayState,
    player: *state_mod.PlayerState,
    projectiles: *projectiles_mod.ProjectilePool,
    secondary_projectiles: *secondary_projectiles_mod.SecondaryProjectilePool,
    creatures: *creatures_mod.CreaturePool,
    particles: *particles_mod.ParticlePool,
    effects: *effects_mod.EffectPool,
    sprite_effects: *effects_mod.SpriteEffectPool,
    detail_preset: i32,
) WeaponRuntimeError!bool {
    return tryFireWeaponWithForce(
        state,
        player,
        null,
        projectiles,
        secondary_projectiles,
        creatures,
        particles,
        effects,
        sprite_effects,
        null,
        detail_preset,
        0.0,
        false,
    );
}

fn tryFireWeaponWithForce(
    state: *state_mod.GameplayState,
    player: *state_mod.PlayerState,
    all_players: ?[]const state_mod.PlayerState,
    projectiles: *projectiles_mod.ProjectilePool,
    secondary_projectiles: *secondary_projectiles_mod.SecondaryProjectilePool,
    creatures: *creatures_mod.CreaturePool,
    particles: *particles_mod.ParticlePool,
    effects: *effects_mod.EffectPool,
    sprite_effects: *effects_mod.SpriteEffectPool,
    player_damage_runtime: ?PlayerDamageRuntime,
    detail_preset: i32,
    dt: f32,
    force_pre_swap_fire_gate: bool,
) WeaponRuntimeError!bool {
    const perk_player = playerUpdatePerkSource(state, player, all_players);
    if (player.weapon.shot_cooldown > 0.0 and !force_pre_swap_fire_gate) return false;
    const weapon_id = player.weapon.weapon_id;
    const perk_fire_ready = player.weapon.reload_timer > 0.0 and !force_pre_swap_fire_gate;
    var use_regression_bullets = false;
    var use_ammunition_within = false;
    if (perk_fire_ready) {
        if (player.experience <= 0) return false;

        use_regression_bullets = perks.perkActive(perk_player, PerkId.regression_bullets);
        use_ammunition_within = !use_regression_bullets and perks.perkActive(perk_player, PerkId.ammunition_within);
        if (!use_regression_bullets and !use_ammunition_within) return false;
    }

    // Native writes this after the ready/input gates, but before charging the
    // reload-bypass perk and dispatching the shot.
    state.survival_reward_fire_seen = true;

    if (perk_fire_ready) {
        if (use_regression_bullets) {
            const reload_time = weapon_data.weapon_stats.get(weapon_id).reload_time;
            const factor: f32 = if (weaponUsesFireAmmoClass(weapon_id)) 4.0 else 200.0;
            const drained = narrowF32(reload_time * factor);
            const before: f32 = @floatFromInt(player.experience);
            var after: i32 = @intFromFloat(before - drained);
            if (after < 0) after = 0;
            player.experience = after;
        } else if (use_ammunition_within) {
            const health_cost: f32 = if (weaponUsesFireAmmoClass(weapon_id))
                @as(f32, 0.15)
            else
                @as(f32, 1.0);
            const health_before = player.health;
            const player1_health_before = if (all_players) |players|
                if (players.len > 0) players[0].health else player.health
            else
                player.health;
            creatures_mod.applyPlayerContactDamageWithPlayers(
                state,
                player,
                all_players,
                health_cost,
                dt,
            );
            if (player_damage_runtime) |runtime| {
                runtime.on_player_damage(
                    runtime.context,
                    player.index,
                    health_before,
                    player1_health_before,
                    dt,
                );
            }
        }
    }

    const shot_cooldown_base = weapon_data.weapon_stats.get(weapon_id).shot_cooldown;
    const pellet_count = @max(0, weapon_data.weapon_stats.get(weapon_id).pellet_count);
    const weapon_spread_heat = weapon_data.weapon_stats.get(weapon_id).spread_heat_inc;
    const fire_bullets_weapon_id = WeaponId.fire_bullets;
    const fire_bullets_spread_heat = weapon_data.weapon_stats.get(fire_bullets_weapon_id).spread_heat_inc;

    var shot_cooldown = shot_cooldown_base;

    const is_fire_bullets = player.fire_bullets_timer > 0.0;
    var projectile_spawn_credit_multiplier: i32 = 1;
    var uses_primary_projectile_spawn = false;
    var shot_count = computeShotCount(player.weapon.weapon_id);
    // Native increments the accuracy counter only inside projectile_spawn /
    // fx_spawn_secondary_projectile; particle weapons never count toward
    // shots fired. Per-weapon usage keeps counting for most-used tracking.
    var counts_accuracy_shots = true;
    if (is_fire_bullets) {
        shot_count = pellet_count;
    }
    if (shot_count <= 0) return false;

    const aim_heading = player.aim_heading;
    const muzzle_xy = native_math.fireMuzzlePos(player.pos.x, player.pos.y, aim_heading);
    const muzzle: state_mod.Vec2 = .{
        .x = muzzle_xy[0],
        .y = muzzle_xy[1],
    };
    // Native encodes friendly fire in the owner id (-1 - player_index): with
    // the cvar enabled, primary player shots can hit other players.
    const projectile_owner = if (state.friendly_fire_enabled)
        owner_ref.OwnerRef.fromPlayer(@intCast(player.index))
    else
        owner_ref.OwnerRef.fromLocalPlayer(0);
    const uses_player_projectile_path = !state.preserve_bugs or
        projectile_owner.usesNativePlayerProjectilePath();
    const projectile_spawn_override = uses_player_projectile_path and
        !state.bonus_spawn_guard and
        !is_fire_bullets and
        projectileSpawnFireBulletsActive(state, player, all_players);
    const projectile_hits_players = state.friendly_fire_enabled;
    if (is_fire_bullets and pellet_count == 1) {
        shot_cooldown = weapon_data.weapon_stats.get(fire_bullets_weapon_id).shot_cooldown;
    }
    if (perks.perkActive(perk_player, PerkId.fastshot)) {
        shot_cooldown = narrowF32(shot_cooldown * 0.88);
    }
    if (perks.perkActive(perk_player, PerkId.sharpshooter)) {
        shot_cooldown = narrowF32(shot_cooldown * 1.05);
    }
    player.weapon.shot_cooldown = @max(0.0, shot_cooldown);

    const weapon_flags = weapon_data.weapon_stats.get(player.weapon.weapon_id).flags;

    if ((weapon_flags & 0x1) != 0) {
        const angle_draw = state.rng.randTagged(rng_callers.player_update_casing_angle);
        const speed_draw = state.rng.randTagged(rng_callers.player_update_casing_speed);
        const rotation_draw = state.rng.randTagged(rng_callers.player_update_casing_rotation);
        const rotation_step_draw = state.rng.randTagged(rng_callers.player_update_casing_rotation_step);
        effects.spawnShellCasing(
            detail_preset,
            player.pos,
            aim_heading,
            angle_draw,
            speed_draw,
            rotation_draw,
            rotation_step_draw,
        );
    }

    const dir_roll = state.rng.randTagged(rng_callers.player_update_shot_jitter_dir);
    const mag_roll = state.rng.randTagged(rng_callers.player_update_shot_jitter_mag);
    const shot_angle = native_math.shotAngleFromJitterDraws(
        player.aim.x,
        player.aim.y,
        player.pos.x,
        player.pos.y,
        player.spread_heat,
        dir_roll,
        mag_roll,
    );
    var particle_angle = directionFromHeading(shot_angle).toAngle();
    if (player.weapon.weapon_id == .flamethrower or player.weapon.weapon_id == .blow_torch or player.weapon.weapon_id == .hr_flamer) {
        particle_angle = directionFromHeading(aim_heading).toAngle();
    }

    if (!is_fire_bullets) {
        // fire SFX variant selection.
        _ = state.rng.randTagged(rng_callers.player_update_shot_sfx);
    }

    const spawn_muzzle_after_projectile = is_fire_bullets or
        player.weapon.weapon_id == WeaponId.pistol or
        player.weapon.weapon_id == WeaponId.shrinkifier_5k;
    if (!spawn_muzzle_after_projectile) {
        spawnNativeFireMuzzleSprites(state, sprite_effects, player.weapon.weapon_id, muzzle, aim_heading, is_fire_bullets);
    }

    const recipe = fire_recipes.resolveFireRecipe(
        player.weapon.weapon_id,
        pellet_count,
        is_fire_bullets,
    );
    var ammo_cost = recipe.ammo_cost;

    switch (recipe.mode) {
        .primary_pellets => |mode| {
            uses_primary_projectile_spawn = true;
            const type_id = projectileSpawnType(mode.type_id, projectile_spawn_override);
            if (type_id != mode.type_id) projectile_spawn_credit_multiplier = 2;
            const type_id_i32 = @intFromEnum(type_id);
            const pellets = @max(0, mode.count);
            shot_count = pellets;
            const meta = projectileTravelBudgetFromTypeId(type_id);
            for (0..@as(usize, @intCast(pellets))) |_| {
                const angle = applyPelletJitter(state, shot_angle, player.weapon.weapon_id, is_fire_bullets, mode.jitter);
                const id = projectiles.spawn(
                    muzzle,
                    angle,
                    type_id_i32,
                    projectile_owner,
                    meta,
                    projectile_hits_players,
                );
                applySpeedScaleRule(state, projectiles, id, player.weapon.weapon_id, is_fire_bullets, mode.speed_scale);
            }
        },
        .secondary_shot => |mode| {
            const target_hint = if (mode.targeting == .use_aim_target_hint) player.aim else null;
            _ = secondary_projectiles.spawn(
                muzzle,
                narrowF32(shot_angle),
                mode.type_id,
                projectile_owner,
                2.0,
                target_hint,
                if (target_hint != null) creatures else null,
            );
            shot_count = 1;
        },
        .particle_stream => |mode| {
            counts_accuracy_shots = false;
            if (mode.slow) {
                _ = particles.spawnParticleSlow(
                    state,
                    muzzle,
                    directionFromHeading(shot_angle).toAngle(),
                    owner_ref.OwnerRef.fromLocalPlayer(0),
                );
            } else {
                const particle_id = particles.spawnParticle(
                    state,
                    muzzle,
                    particle_angle,
                    1.0,
                    owner_ref.OwnerRef.fromLocalPlayer(0),
                );
                if (mode.style) |style| {
                    particles.entries[particle_id].style_id = style;
                }
            }
            shot_count = 1;
        },
        .multi_plasma_fan => {
            uses_primary_projectile_spawn = true;
            shot_count = 5;
            const spread_small: f32 = 0.31415927;
            const spread_large: f32 = 0.5235988;
            const rifle_type_id = projectileSpawnType(.plasma_rifle, projectile_spawn_override);
            const minigun_type_id = projectileSpawnType(.plasma_minigun, projectile_spawn_override);
            if (rifle_type_id != .plasma_rifle or minigun_type_id != .plasma_minigun) {
                projectile_spawn_credit_multiplier = 2;
            }
            const rifle_meta = projectileTravelBudgetFromTypeId(rifle_type_id);
            const minigun_meta = projectileTravelBudgetFromTypeId(minigun_type_id);
            _ = projectiles.spawn(muzzle, native_math.pc24Sub(shot_angle, spread_small), @intFromEnum(rifle_type_id), projectile_owner, rifle_meta, projectile_hits_players);
            _ = projectiles.spawn(muzzle, native_math.pc24Sub(shot_angle, spread_large), @intFromEnum(minigun_type_id), projectile_owner, minigun_meta, projectile_hits_players);
            _ = projectiles.spawn(muzzle, narrowF32(shot_angle), @intFromEnum(rifle_type_id), projectile_owner, rifle_meta, projectile_hits_players);
            _ = projectiles.spawn(muzzle, native_math.pc24Add(shot_angle, spread_large), @intFromEnum(minigun_type_id), projectile_owner, minigun_meta, projectile_hits_players);
            _ = projectiles.spawn(muzzle, native_math.pc24Add(shot_angle, spread_small), @intFromEnum(rifle_type_id), projectile_owner, rifle_meta, projectile_hits_players);
        },
        .swarmer_dump => {
            // Native spawns one rocket per integer counter step below the float
            // ammo value (ceil), and zero rockets when firing with an
            // empty/negative clip; the full clip value is subtracted either way.
            const clip_ammo = player.weapon.ammo;
            const rocket_count: i32 = if (clip_ammo > 0.0) @intFromFloat(@ceil(clip_ammo)) else 0;
            const step = if (state.preserve_bugs)
                narrowF32(clip_ammo * (native_pi / 3.0))
            else if (rocket_count <= 1)
                0.0
            else
                narrowF32((native_pi * (2.0 / 3.0)) / @as(f32, @floatFromInt(rocket_count - 1)));
            var angle = if (state.preserve_bugs)
                narrowF32((shot_angle - native_pi) - step * clip_ammo * 0.5)
            else
                narrowF32(shot_angle - native_pi * (1.0 / 3.0));
            for (0..@as(usize, @intCast(rocket_count))) |_| {
                _ = secondary_projectiles.spawn(
                    muzzle,
                    angle,
                    secondary_projectiles_mod.SecondaryProjectileTypeId.homing_rocket,
                    projectile_owner,
                    2.0,
                    player.aim,
                    creatures,
                );
                angle = narrowF32(angle + step);
            }
            ammo_cost = clip_ammo;
            shot_count = rocket_count;
        },
    }

    if (spawn_muzzle_after_projectile) {
        spawnNativeFireMuzzleSprites(state, sprite_effects, player.weapon.weapon_id, muzzle, aim_heading, is_fire_bullets);
    }

    const player_idx = player.index;
    const projectile_spawn_shot_count = if (uses_primary_projectile_spawn and !uses_player_projectile_path)
        0
    else
        shot_count * projectile_spawn_credit_multiplier;
    if (player_idx >= 0 and player_idx < state.shots_fired.len) {
        const idx: usize = @intCast(player_idx);
        if (counts_accuracy_shots) {
            state.shots_fired[idx] += projectile_spawn_shot_count;
        }
        const weapon_idx: usize = @intCast(@intFromEnum(player.weapon.weapon_id));
        if (weapon_idx < state.weapon_shots_fired[idx].len) {
            state.weapon_shots_fired[idx][weapon_idx] += shot_count;
        }
    }
    state.shots_fired_total += projectile_spawn_shot_count;

    if (state.bonuses.reflex_boost <= 0.0 and !is_fire_bullets) {
        player.weapon.ammo -= ammo_cost;
    }

    player.shot_seq += 1;

    if (!perks.perkActive(perk_player, PerkId.sharpshooter)) {
        const spread_heat_base = if (is_fire_bullets) fire_bullets_spread_heat else weapon_spread_heat;
        const spread_inc = native_math.pc24Mul(spread_heat_base, @as(f32, 1.3));
        player.spread_heat = std.math.clamp(
            native_math.pc24Add(player.spread_heat, spread_inc),
            0.0,
            0.48,
        );
    }

    const muzzle_inc = if (is_fire_bullets and pellet_count == 1) fire_bullets_spread_heat else weapon_spread_heat;
    player.muzzle_flash_alpha = @min(1.0, player.muzzle_flash_alpha);
    player.muzzle_flash_alpha = @min(1.0, player.muzzle_flash_alpha + muzzle_inc);
    player.muzzle_flash_alpha = @min(0.8, player.muzzle_flash_alpha);

    if (player.weapon.ammo <= 0.0 and (force_pre_swap_fire_gate or player.weapon.reload_timer <= 0.0)) {
        player_runtime.playerStartReloadWithPlayers(player, state, all_players);
    }

    return true;
}

pub fn applyPlayerPerkTicks(
    state: *state_mod.GameplayState,
    player: *state_mod.PlayerState,
    projectiles: *projectiles_mod.ProjectilePool,
    dt: f32,
) void {
    var sprite_effects: effects_mod.SpriteEffectPool = .{};
    applyPlayerPerkTicksWithEffects(state, player, null, projectiles, &sprite_effects, dt);
}

pub fn applyPlayerPerkTicksWithEffects(
    state: *state_mod.GameplayState,
    player: *state_mod.PlayerState,
    all_players: ?[]const state_mod.PlayerState,
    projectiles: *projectiles_mod.ProjectilePool,
    sprite_effects: *effects_mod.SpriteEffectPool,
    dt: f32,
) void {
    const perk_player = playerUpdatePerkSource(state, player, all_players);
    tickManBomb(state, player, perk_player, all_players, projectiles, dt);
    tickLivingFortress(player, perk_player, dt);
    tickFireCaugh(state, player, perk_player, all_players, projectiles, sprite_effects, dt);
    tickHotTempered(state, player, perk_player, all_players, projectiles, dt);
    tickPlayerSpreadDamping(state, dt);
}

fn tickManBomb(
    state: *state_mod.GameplayState,
    player: *state_mod.PlayerState,
    perk_player: *const state_mod.PlayerState,
    all_players: ?[]const state_mod.PlayerState,
    projectiles: *projectiles_mod.ProjectilePool,
    dt: f32,
) void {
    if (!perks.perkActive(perk_player, PerkId.man_bomb)) {
        player.man_bomb_timer = 0.0;
        return;
    }

    player.man_bomb_timer = native_math.pc24Add(player.man_bomb_timer, dt);
    if (player.man_bomb_timer <= state.perk_interval_man_bomb) return;

    const owner = if (!state.friendly_fire_enabled)
        owner_ref.OwnerRef.fromLocalPlayer(0)
    else
        owner_ref.OwnerRef.fromPlayer(@intCast(player.index));
    for (0..8) |idx| {
        const type_id: ProjectileTypeId = if ((idx & 1) == 0)
            .ion_minigun
        else
            .ion_rifle;
        const angle =
            @as(f32, @floatFromInt(state.rng.randTagged(if (type_id == .ion_minigun) rng_callers.player_update_man_bomb_ion_minigun_angle else rng_callers.player_update_man_bomb_ion_rifle_angle) % 50)) * 0.01 +
            @as(f32, @floatFromInt(idx)) * (native_pi / 4.0) - 0.25;
        spawnPerkProjectile(
            state,
            player,
            all_players,
            projectiles,
            player.pos,
            angle,
            type_id,
            owner,
        );
    }
    state.sfx_queue.append(.explosion_small);
    player.man_bomb_timer = native_math.pc24Sub(
        player.man_bomb_timer,
        state.perk_interval_man_bomb,
    );
    state.perk_interval_man_bomb = 4.0;
}

fn tickLivingFortress(
    player: *state_mod.PlayerState,
    perk_player: *const state_mod.PlayerState,
    dt: f32,
) void {
    if (perks.perkActive(perk_player, PerkId.living_fortress)) {
        player.living_fortress_timer = @min(
            @as(f32, 30.0),
            native_math.pc24Add(player.living_fortress_timer, dt),
        );
    } else {
        player.living_fortress_timer = 0.0;
    }
}

fn tickFireCaugh(
    state: *state_mod.GameplayState,
    player: *state_mod.PlayerState,
    perk_player: *const state_mod.PlayerState,
    all_players: ?[]const state_mod.PlayerState,
    projectiles: *projectiles_mod.ProjectilePool,
    sprite_effects: *effects_mod.SpriteEffectPool,
    dt: f32,
) void {
    if (!perks.perkActive(perk_player, PerkId.fire_caugh)) {
        player.fire_cough_timer = 0.0;
        return;
    }

    player.fire_cough_timer = native_math.pc24Add(player.fire_cough_timer, dt);
    if (player.fire_cough_timer <= state.perk_interval_fire_cough) return;

    const owner = if (!state.friendly_fire_enabled)
        owner_ref.OwnerRef.fromLocalPlayer(0)
    else
        owner_ref.OwnerRef.fromPlayer(@intCast(player.index));
    state.sfx_queue.append(.autorifle_fire);
    state.sfx_queue.append(.plasmaminigun_fire);
    const aim_heading = player.aim_heading;
    const origin_pos = player.pos;
    const muzzle_xy = native_math.fireMuzzlePos(origin_pos.x, origin_pos.y, aim_heading);
    const muzzle: state_mod.Vec2 = .{ .x = muzzle_xy[0], .y = muzzle_xy[1] };
    const dir_roll = state.rng.randTagged(rng_callers.player_update_fire_cough_spread_dir);
    const mag_roll = state.rng.randTagged(rng_callers.player_update_fire_cough_spread_mag);
    const angle = native_math.shotAngleFromJitterDraws(
        player.aim.x,
        player.aim.y,
        origin_pos.x,
        origin_pos.y,
        player.spread_heat,
        dir_roll,
        mag_roll,
    );
    spawnPerkProjectile(
        state,
        player,
        all_players,
        projectiles,
        muzzle,
        angle,
        .fire_bullets,
        owner,
    );

    _ = sprite_effects.spawn(
        state,
        muzzle,
        state_mod.Vec2.fromAngle(aim_heading).mul(25.0),
        1.0,
        .{ .r = 0.5, .g = 0.5, .b = 0.5, .a = 0.413 },
    );

    player.fire_cough_timer = native_math.pc24Sub(player.fire_cough_timer, state.perk_interval_fire_cough);
    state.perk_interval_fire_cough = @as(f32, @floatFromInt(state.rng.randTagged(rng_callers.player_update_fire_cough_interval_reset) % 4)) + 2.0;
}

fn tickHotTempered(
    state: *state_mod.GameplayState,
    player: *state_mod.PlayerState,
    perk_player: *const state_mod.PlayerState,
    all_players: ?[]const state_mod.PlayerState,
    projectiles: *projectiles_mod.ProjectilePool,
    dt: f32,
) void {
    if (!perks.perkActive(perk_player, PerkId.hot_tempered)) {
        player.hot_tempered_timer = 0.0;
        return;
    }

    player.hot_tempered_timer = native_math.pc24Add(player.hot_tempered_timer, dt);
    if (player.hot_tempered_timer <= state.perk_interval_hot_tempered) return;

    const owner = if (state.friendly_fire_enabled)
        owner_ref.OwnerRef.fromPlayer(@intCast(player.index))
    else
        owner_ref.OwnerRef.fromLocalPlayer(0);
    for (0..8) |idx| {
        const type_id: ProjectileTypeId = if ((idx & 1) == 0)
            .plasma_minigun
        else
            .plasma_rifle;
        const angle = native_math.pc24Mul(@as(f32, @floatFromInt(idx)), native_math.native_quarter_pi);
        spawnPerkProjectile(
            state,
            player,
            all_players,
            projectiles,
            player.pos,
            angle,
            type_id,
            owner,
        );
    }
    state.sfx_queue.append(.explosion_small);

    player.hot_tempered_timer = native_math.pc24Sub(player.hot_tempered_timer, state.perk_interval_hot_tempered);
    state.perk_interval_hot_tempered = @as(f32, @floatFromInt(state.rng.randTagged(rng_callers.player_update_hot_tempered_interval_reset) % 8)) + 2.0;
}

fn tickPlayerSpreadDamping(state: *state_mod.GameplayState, dt: f32) void {
    if (state.player_spread_damping_gate > 0.0) {
        const next_scalar = native_math.pc24Sub(state.player_spread_damping_scalar, dt);
        state.player_spread_damping_scalar = if (next_scalar < 0.3) 0.3 else next_scalar;
    } else {
        const recovery = native_math.pc24Mul(dt, @as(f32, 0.8));
        const next_scalar = native_math.pc24Add(recovery, state.player_spread_damping_scalar);
        state.player_spread_damping_scalar = if (next_scalar > 1.0) 1.0 else next_scalar;
    }
}

fn spawnPerkProjectile(
    state: *state_mod.GameplayState,
    player: *const state_mod.PlayerState,
    all_players: ?[]const state_mod.PlayerState,
    projectiles: *projectiles_mod.ProjectilePool,
    pos: state_mod.Vec2,
    angle: f32,
    type_id: ProjectileTypeId,
    owner: owner_ref.OwnerRef,
) void {
    var spawn_type_id = type_id;
    var shot_credit: i32 = 0;
    const player_owned_spawn = owner.playerIndexInBounds(state.shots_fired.len) != null and
        (!state.preserve_bugs or owner.usesNativePlayerProjectilePath());
    if (!state.bonus_spawn_guard and player_owned_spawn) {
        shot_credit = 1;
        if (spawn_type_id != .fire_bullets and
            projectileSpawnFireBulletsActive(state, player, all_players))
        {
            // `projectile_spawn` Fire Bullets override loops once, crediting shots twice.
            spawn_type_id = .fire_bullets;
            shot_credit = 2;
        }
    }

    const spawn_type_id_i32 = @intFromEnum(spawn_type_id);
    const meta = projectileTravelBudgetFromTypeId(spawn_type_id);
    _ = projectiles.spawn(
        pos,
        angle,
        spawn_type_id_i32,
        owner,
        meta,
        false,
    );
    if (shot_credit > 0 and state.shots_fired.len > 0) {
        const shooter_idx = owner.playerIndexInBounds(state.shots_fired.len) orelse return;
        state.shots_fired[shooter_idx] += shot_credit;
        state.shots_fired_total += shot_credit;
        if (shooter_idx < state.weapon_shots_fired.len and
            spawn_type_id_i32 >= 0 and spawn_type_id_i32 < state.weapon_shots_fired[shooter_idx].len)
        {
            state.weapon_shots_fired[shooter_idx][@intCast(spawn_type_id_i32)] += shot_credit;
        }
    }
}

fn applyPelletJitter(
    state: *state_mod.GameplayState,
    shot_angle: f32,
    weapon_id: WeaponId,
    fire_bullets_active: bool,
    rule: fire_recipes.PelletJitterRule,
) f32 {
    return switch (rule) {
        .none => shot_angle,
        .modulo_centered => |jitter| {
            const caller: rng_callers.Caller = if (fire_bullets_active)
                rng_callers.player_update_fire_bullets_pellet_jitter
            else switch (weapon_id) {
                .shotgun => rng_callers.player_update_shotgun_pellet_jitter,
                .sawed_off_shotgun => rng_callers.player_update_sawed_off_shotgun_pellet_jitter,
                .jackhammer => rng_callers.player_update_jackhammer_pellet_jitter,
                .ion_shotgun => rng_callers.player_update_ion_shotgun_pellet_jitter,
                .gauss_shotgun => rng_callers.player_update_gauss_shotgun_pellet_jitter,
                else => unreachable,
            };
            const jitter_roll = state.rng.randTagged(caller);
            return shot_angle + narrowF32(
                @as(f32, @floatFromInt(@as(i32, @intCast(jitter_roll % jitter.modulo)) - jitter.center)) * jitter.step,
            );
        },
        .mask_centered => |jitter| {
            const caller: rng_callers.Caller = if (fire_bullets_active)
                rng_callers.player_update_fire_bullets_pellet_jitter
            else switch (weapon_id) {
                .plasma_shotgun => rng_callers.player_update_plasma_shotgun_pellet_jitter,
                else => unreachable,
            };
            const jitter_roll = state.rng.randTagged(caller);
            return shot_angle + narrowF32(
                @as(f32, @floatFromInt(@as(i32, @intCast(jitter_roll & jitter.mask)) - jitter.center)) * jitter.step,
            );
        },
    };
}

fn applySpeedScaleRule(
    state: *state_mod.GameplayState,
    projectiles: *projectiles_mod.ProjectilePool,
    projectile_idx: usize,
    weapon_id: WeaponId,
    fire_bullets_active: bool,
    rule: fire_recipes.SpeedScaleRule,
) void {
    switch (rule) {
        .none => {},
        .modulo => |speed| {
            const speed_roll = if (fire_bullets_active)
                state.rng.rand()
            else blk: {
                const caller: rng_callers.Caller = switch (weapon_id) {
                    .shotgun => rng_callers.player_update_shotgun_pellet_speed_scale,
                    .sawed_off_shotgun => rng_callers.player_update_sawed_off_shotgun_pellet_speed_scale,
                    .jackhammer => rng_callers.player_update_jackhammer_pellet_speed_scale,
                    .ion_shotgun => rng_callers.player_update_ion_shotgun_pellet_speed_scale,
                    .gauss_shotgun => rng_callers.player_update_gauss_shotgun_pellet_speed_scale,
                    .plasma_shotgun => rng_callers.player_update_plasma_shotgun_pellet_speed_scale,
                    else => unreachable,
                };
                break :blk state.rng.randTagged(caller);
            };
            projectiles.entries[projectile_idx].speed_scale = narrowF32(
                speed.base + @as(f32, @floatFromInt(speed_roll % speed.modulo)) * speed.step,
            );
        },
    }
}

fn spawnNativeFireMuzzleSprites(
    state: *state_mod.GameplayState,
    sprite_effects: *effects_mod.SpriteEffectPool,
    weapon_id: WeaponId,
    muzzle: state_mod.Vec2,
    aim_heading: f32,
    fire_bullets_active: bool,
) void {
    const specs = if (fire_bullets_active)
        fire_bullets_muzzle_specs[0..]
    else
        muzzleSpriteSpecs(weapon_id);
    for (specs) |spec| {
        _ = sprite_effects.spawn(
            state,
            muzzle,
            state_mod.Vec2.fromAngle(aim_heading).mul(spec.speed),
            spec.scale,
            .{ .r = 0.5, .g = 0.5, .b = 0.5, .a = spec.alpha },
        );
    }
}

fn muzzleSpriteSpecs(weapon_id: WeaponId) []const MuzzleSpriteSpec {
    return switch (weapon_id) {
        .pistol,
        .assault_rifle,
        .submachine_gun,
        .shrinkifier_5k,
        => &.{
            .{ .speed = 25.0, .scale = 1.0, .alpha = 0.23 },
            .{ .speed = 15.0, .scale = 2.0, .alpha = 0.213 },
        },
        .shotgun => &.{
            .{ .speed = 25.0, .scale = 1.0, .alpha = 0.25 },
            .{ .speed = 15.0, .scale = 2.0, .alpha = 0.223 },
        },
        .sawed_off_shotgun => &.{
            .{ .speed = 25.0, .scale = 1.0, .alpha = 0.26 },
            .{ .speed = 15.0, .scale = 2.0, .alpha = 0.233 },
        },
        .gauss_gun, .gauss_shotgun => &.{
            .{ .speed = 25.0, .scale = 1.0, .alpha = 0.33 },
            .{ .speed = 15.0, .scale = 2.0, .alpha = 0.263 },
        },
        .rocket_launcher,
        .mini_rocket_swarmers,
        .rocket_minigun,
        => &.{
            .{ .speed = 25.0, .scale = 1.0, .alpha = 0.34 },
            .{ .speed = 15.0, .scale = 2.0, .alpha = 0.283 },
        },
        .seeker_rockets => &.{
            .{ .speed = 25.0, .scale = 1.0, .alpha = 0.31 },
            .{ .speed = 15.0, .scale = 2.0, .alpha = 0.243 },
        },
        .jackhammer => &.{
            .{ .speed = 15.0, .scale = 2.0, .alpha = 0.223 },
        },
        else => &.{},
    };
}

fn computeShotCount(weapon_id: WeaponId) i32 {
    return switch (weapon_id) {
        .multi_plasma => 5,
        .plasma_shotgun => 14,
        // The swarmer_dump branch derives the real rocket count from the live
        // clip value (zero rockets on an empty/negative clip, like native).
        .mini_rocket_swarmers => 1,
        .gauss_shotgun => 6,
        .ion_shotgun => 8,
        else => @max(1, weapon_data.weapon_stats.get(weapon_id).pellet_count),
    };
}

fn weaponUsesFireAmmoClass(weapon_id: game_ids.WeaponId) bool {
    // Mirrors `weapon.ammo_class == 1` in the Python weapon table.
    return weapon_id == .flamethrower or weapon_id == .blow_torch or weapon_id == .hr_flamer;
}

fn directionFromHeading(heading: f32) state_mod.Vec2 {
    const radians = narrowF32(heading - native_pi / 2.0);
    return .{
        .x = narrowF32(math.cos(radians)),
        .y = narrowF32(math.sin(radians)),
    };
}

fn expectFloatClose(expected: f32, actual: f32) !void {
    try std.testing.expectApproxEqAbs(expected, actual, 1e-6);
}

fn activeProjectileCount(projectiles: *const projectiles_mod.ProjectilePool) usize {
    var count: usize = 0;
    for (projectiles.entries) |entry| {
        if (entry.active) count += 1;
    }
    return count;
}

fn activeProjectileTypeCount(
    projectiles: *const projectiles_mod.ProjectilePool,
    type_id: i32,
) usize {
    var count: usize = 0;
    for (projectiles.entries) |entry| {
        if (entry.active and entry.type_id == type_id) count += 1;
    }
    return count;
}

fn activeSecondaryProjectileCount(
    secondary_projectiles: *const secondary_projectiles_mod.SecondaryProjectilePool,
) usize {
    var count: usize = 0;
    for (secondary_projectiles.entries) |entry| {
        if (entry.active) count += 1;
    }
    return count;
}

test "weapon usage tracks most used weapon" {
    var state = state_mod.GameplayState.init(1);
    var projectiles: projectiles_mod.ProjectilePool = .{};
    var secondary_projectiles: secondary_projectiles_mod.SecondaryProjectilePool = .{};
    var creatures: creatures_mod.CreaturePool = .{};
    var particles: particles_mod.ParticlePool = .{};
    var player: state_mod.PlayerState = .{
        .index = 0,
        .pos = .{},
    };

    player_runtime.weaponAssignPlayer(&player, game_ids.WeaponId.pistol);
    try std.testing.expect(try tryFireWeapon(&state, &player, &projectiles, &secondary_projectiles, &creatures, &particles));
    try std.testing.expectEqual(@as(i32, 1), state.weapon_shots_fired[0][1]);

    player_runtime.weaponAssignPlayer(&player, game_ids.WeaponId.assault_rifle);
    for (0..3) |_| {
        player.weapon.shot_cooldown = 0.0;
        try std.testing.expect(try tryFireWeapon(&state, &player, &projectiles, &secondary_projectiles, &creatures, &particles));
    }
    try std.testing.expectEqual(@as(i32, 3), state.weapon_shots_fired[0][2]);

    const most_used = survival_progression.mostUsedWeaponIdForPlayer(state, 0, game_ids.WeaponId.pistol);
    try std.testing.expectEqual(game_ids.WeaponId.assault_rifle, most_used);
}

test "weapon runtime starts reload when ammo is depleted" {
    var state = state_mod.GameplayState.init(1);
    var projectiles: projectiles_mod.ProjectilePool = .{};
    var secondary_projectiles: secondary_projectiles_mod.SecondaryProjectilePool = .{};
    var creatures: creatures_mod.CreaturePool = .{};
    var particles: particles_mod.ParticlePool = .{};
    var player: state_mod.PlayerState = .{
        .index = 0,
        .pos = .{},
    };
    player_runtime.weaponAssignPlayer(&player, game_ids.WeaponId.pistol);
    player.weapon.ammo = 1.0;

    try std.testing.expect(try tryFireWeapon(&state, &player, &projectiles, &secondary_projectiles, &creatures, &particles));
    try std.testing.expect(player.weapon.reload_active);
    try std.testing.expect(player.weapon.reload_timer > 0.0);
    try std.testing.expectEqual(@as(i32, 1), state.shots_fired[0]);

    const reload_time = player.weapon.reload_timer;
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
    try std.testing.expect(player.weapon.reload_active);
    try std.testing.expect(player.weapon.reload_timer > 0.0);

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
    try std.testing.expect(!player.weapon.reload_active);
    try std.testing.expectEqual(@as(f32, @floatFromInt(player.weapon.clip_size)), player.weapon.ammo);
}

test "reload preload gate ignores reload active byte" {
    var state = state_mod.GameplayState.init(1);
    var projectiles: projectiles_mod.ProjectilePool = .{};
    var secondary_projectiles: secondary_projectiles_mod.SecondaryProjectilePool = .{};
    var creatures: creatures_mod.CreaturePool = .{};
    var particles: particles_mod.ParticlePool = .{};
    var player: state_mod.PlayerState = .{
        .index = 0,
        .pos = .{},
        .weapon = .{
            .weapon_id = game_ids.WeaponId.ion_cannon,
            .clip_size = 6,
            .ammo = -1.0,
            .reload_active = false,
            .reload_timer = 0.01,
            .reload_timer_max = 3.0,
            .shot_cooldown = 0.5,
        },
    };

    try stepPlayerForTick(
        &state,
        &player,
        &projectiles,
        &secondary_projectiles,
        &creatures,
        &particles,
        .{},
        0.016,
    );

    try expectFloatClose(6.0, player.weapon.ammo);
}

test "manual reload starts even when clip is full" {
    var state = state_mod.GameplayState.init(1);
    var projectiles: projectiles_mod.ProjectilePool = .{};
    var secondary_projectiles: secondary_projectiles_mod.SecondaryProjectilePool = .{};
    var creatures: creatures_mod.CreaturePool = .{};
    var particles: particles_mod.ParticlePool = .{};
    var player: state_mod.PlayerState = .{
        .index = 0,
        .pos = .{},
    };
    player_runtime.weaponAssignPlayer(&player, game_ids.WeaponId.pistol);
    player.weapon.ammo = @floatFromInt(player.weapon.clip_size);

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

    try std.testing.expect(player.weapon.reload_active);
    try std.testing.expect(player.weapon.reload_timer > 0.0);
}

test "manual reload requires single player mode" {
    var state = state_mod.GameplayState.init(1);
    var projectiles: projectiles_mod.ProjectilePool = .{};
    var secondary_projectiles: secondary_projectiles_mod.SecondaryProjectilePool = .{};
    var creatures: creatures_mod.CreaturePool = .{};
    var particles: particles_mod.ParticlePool = .{};
    var player: state_mod.PlayerState = .{
        .index = 0,
        .pos = .{},
    };
    player_runtime.weaponAssignPlayer(&player, game_ids.WeaponId.pistol);
    player.weapon.ammo = 0.0;

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

    try std.testing.expect(!player.weapon.reload_active);
    try expectFloatClose(0.0, player.weapon.reload_timer);
}

test "anxious loader reduces reload timer on fire press" {
    var state = state_mod.GameplayState.init(1);
    var projectiles: projectiles_mod.ProjectilePool = .{};
    var secondary_projectiles: secondary_projectiles_mod.SecondaryProjectilePool = .{};
    var creatures: creatures_mod.CreaturePool = .{};
    var particles: particles_mod.ParticlePool = .{};

    var base_player: state_mod.PlayerState = .{
        .index = 0,
        .pos = .{},
        .weapon = .{
            .weapon_id = game_ids.WeaponId.pistol,
            .reload_active = true,
            .reload_timer = 1.0,
            .reload_timer_max = 1.0,
        },
    };
    var perk_player: state_mod.PlayerState = .{
        .index = 0,
        .pos = .{},
        .weapon = .{
            .weapon_id = game_ids.WeaponId.pistol,
            .reload_active = true,
            .reload_timer = 1.0,
            .reload_timer_max = 1.0,
        },
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

    try expectFloatClose(0.9, base_player.weapon.reload_timer);
    try expectFloatClose(0.85, perk_player.weapon.reload_timer);
}

test "angry reloader spawns plasma ring at half reload" {
    var state = state_mod.GameplayState.init(1);
    state.bonus_spawn_guard = true;
    var projectiles: projectiles_mod.ProjectilePool = .{};
    var secondary_projectiles: secondary_projectiles_mod.SecondaryProjectilePool = .{};
    var creatures: creatures_mod.CreaturePool = .{};
    var particles: particles_mod.ParticlePool = .{};
    var player: state_mod.PlayerState = .{
        .index = 0,
        .pos = .{ .x = 100.0, .y = 100.0 },
        .weapon = .{
            .weapon_id = game_ids.WeaponId.pistol,
            .reload_active = true,
            .reload_timer = 1.1,
            .reload_timer_max = 2.0,
            .clip_size = 10,
            .ammo = 0.0,
        },
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

    try expectFloatClose(0.9, player.weapon.reload_timer);
    try std.testing.expectEqual(@as(usize, 15), activeProjectileCount(&projectiles));
    try std.testing.expect(!state.bonus_spawn_guard);
    try std.testing.expectEqual(@as(i32, 0), state.shots_fired[0]);
    for (projectiles.entries[0..15]) |proj| {
        try std.testing.expect(proj.active);
        try std.testing.expectEqual(@intFromEnum(game_ids.ProjectileTypeId.plasma_minigun), proj.type_id);
        try std.testing.expectEqual(@as(i32, -100), proj.owner.toLegacy());
    }
}

test "angry reloader does not trigger once reload is below half" {
    var state = state_mod.GameplayState.init(1);
    var projectiles: projectiles_mod.ProjectilePool = .{};
    var secondary_projectiles: secondary_projectiles_mod.SecondaryProjectilePool = .{};
    var creatures: creatures_mod.CreaturePool = .{};
    var particles: particles_mod.ParticlePool = .{};
    var player: state_mod.PlayerState = .{
        .index = 0,
        .pos = .{ .x = 100.0, .y = 100.0 },
        .weapon = .{
            .weapon_id = game_ids.WeaponId.pistol,
            .reload_active = true,
            .reload_timer = 0.95,
            .reload_timer_max = 2.0,
        },
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

    try expectFloatClose(0.85, player.weapon.reload_timer);
    try std.testing.expectEqual(@as(usize, 0), activeProjectileCount(&projectiles));
}

test "man bomb spawns eight ion projectiles and preserves bonus guard latch" {
    var state = state_mod.GameplayState.init(1);
    var projectiles: projectiles_mod.ProjectilePool = .{};
    var player: state_mod.PlayerState = .{
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
        try std.testing.expectEqual(@as(i32, -100), proj.owner.toLegacy());
    }
}

test "man bomb and living fortress timers keep native stored cadence" {
    var state = state_mod.GameplayState.init(1);
    var projectiles: projectiles_mod.ProjectilePool = .{};
    var player: state_mod.PlayerState = .{
        .index = 0,
        .pos = .{ .x = 100.0, .y = 100.0 },
    };
    player.perk_counts.set(PerkId.man_bomb, 1);
    player.perk_counts.set(PerkId.living_fortress, 1);

    for (0..240) |_| {
        applyPlayerPerkTicks(&state, &player, &projectiles, 1.0 / 60.0);
    }

    try std.testing.expectEqual(@as(usize, 0), activeProjectileCount(&projectiles));
    try std.testing.expectEqual(@as(f32, 3.9999969005584717), player.man_bomb_timer);
    try std.testing.expectEqual(@as(f32, 3.9999969005584717), player.living_fortress_timer);

    applyPlayerPerkTicks(&state, &player, &projectiles, 1.0 / 60.0);

    try std.testing.expectEqual(@as(usize, 8), activeProjectileCount(&projectiles));
    try std.testing.expectEqual(@as(f32, 0.016663551330566406), player.man_bomb_timer);
    try std.testing.expectEqual(@as(f32, 4.016663551330566), player.living_fortress_timer);
}

test "player perk phase advances shared spread damping once per player update" {
    var state = state_mod.GameplayState.init(1);
    var projectiles: projectiles_mod.ProjectilePool = .{};
    var player: state_mod.PlayerState = .{ .index = 0, .pos = .{} };
    state.player_spread_damping_scalar = 0.5;

    applyPlayerPerkTicks(&state, &player, &projectiles, 0.5);

    try std.testing.expectEqual(@as(f32, 0.9), state.player_spread_damping_scalar);

    state.player_spread_damping_gate = 1.0;
    state.player_spread_damping_scalar = 0.35;

    applyPlayerPerkTicks(&state, &player, &projectiles, 0.1);

    try std.testing.expectEqual(@as(f32, 0.3), state.player_spread_damping_scalar);
}

test "hot tempered spawns alternating plasma projectiles when charged" {
    var state = state_mod.GameplayState.init(1);
    var projectiles: projectiles_mod.ProjectilePool = .{};
    var player: state_mod.PlayerState = .{
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
        try std.testing.expectEqual(@as(i32, -100), proj.owner.toLegacy());
    }
}

test "hot tempered preserves global fire bullets projectile override" {
    var state = state_mod.GameplayState.init(1);
    state.preserve_bugs = true;
    var projectiles: projectiles_mod.ProjectilePool = .{};
    var sprite_effects: effects_mod.SpriteEffectPool = .{};
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{ .x = 100.0, .y = 100.0 },
            .hot_tempered_timer = 1.95,
        },
        .{
            .index = 1,
            .pos = .{ .x = 200.0, .y = 200.0 },
            .fire_bullets_timer = 1.0,
        },
    };
    players[0].perk_counts.set(PerkId.hot_tempered, 1);

    applyPlayerPerkTicksWithEffects(
        &state,
        &players[0],
        players[0..],
        &projectiles,
        &sprite_effects,
        0.1,
    );

    try std.testing.expectEqual(@as(usize, 8), activeProjectileCount(&projectiles));
    try std.testing.expectEqual(@as(usize, 8), activeProjectileTypeCount(
        &projectiles,
        @intFromEnum(game_ids.ProjectileTypeId.fire_bullets),
    ));
    try std.testing.expectEqual(@as(i32, 16), state.shots_fired[0]);
    try std.testing.expectEqual(@as(i32, 16), state.shots_fired_total);
    try std.testing.expectEqual(
        @as(i32, 16),
        state.weapon_shots_fired[0][@intFromEnum(game_ids.ProjectileTypeId.fire_bullets)],
    );
}

test "stationary reloader triples reload speed" {
    var state = state_mod.GameplayState.init(1);
    var projectiles: projectiles_mod.ProjectilePool = .{};
    var secondary_projectiles: secondary_projectiles_mod.SecondaryProjectilePool = .{};
    var creatures: creatures_mod.CreaturePool = .{};
    var particles: particles_mod.ParticlePool = .{};

    var base_player: state_mod.PlayerState = .{
        .index = 0,
        .pos = .{ .x = 100.0, .y = 100.0 },
        .weapon = .{
            .weapon_id = game_ids.WeaponId.pistol,
            .reload_active = true,
            .reload_timer = 1.0,
            .reload_timer_max = 1.0,
        },
    };
    var perk_player: state_mod.PlayerState = .{
        .index = 0,
        .pos = .{ .x = 100.0, .y = 100.0 },
        .weapon = .{
            .weapon_id = game_ids.WeaponId.pistol,
            .reload_active = true,
            .reload_timer = 1.0,
            .reload_timer_max = 1.0,
        },
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

    try expectFloatClose(0.9, base_player.weapon.reload_timer);
    try expectFloatClose(0.7, perk_player.weapon.reload_timer);
}

test "stationary reload keeps native completion frame" {
    var state = state_mod.GameplayState.init(1);
    var projectiles: projectiles_mod.ProjectilePool = .{};
    var secondary_projectiles: secondary_projectiles_mod.SecondaryProjectilePool = .{};
    var creatures: creatures_mod.CreaturePool = .{};
    var particles: particles_mod.ParticlePool = .{};
    var player: state_mod.PlayerState = .{
        .index = 0,
        .pos = .{ .x = 50.0, .y = 50.0 },
        .weapon = .{
            .weapon_id = game_ids.WeaponId.pistol,
            .clip_size = 10,
            .ammo = 10.0,
            .reload_active = true,
            .reload_timer = 1.5,
            .reload_timer_max = 1.5,
        },
    };
    player.perk_counts.set(PerkId.stationary_reloader, 1);

    for (0..19) |_| {
        try stepPlayerForTick(
            &state,
            &player,
            &projectiles,
            &secondary_projectiles,
            &creatures,
            &particles,
            .{},
            1.0 / 38.0,
        );
    }

    try std.testing.expectEqual(@as(f32, 4.172325134277344e-07), player.weapon.reload_timer);

    try stepPlayerForTick(
        &state,
        &player,
        &projectiles,
        &secondary_projectiles,
        &creatures,
        &particles,
        .{},
        1.0 / 38.0,
    );

    try std.testing.expectEqual(@as(f32, 0.0), player.weapon.reload_timer);
}

test "alternate weapon reload press swaps and adds cooldown" {
    var state = state_mod.GameplayState.init(1);
    var projectiles: projectiles_mod.ProjectilePool = .{};
    var secondary_projectiles: secondary_projectiles_mod.SecondaryProjectilePool = .{};
    var creatures: creatures_mod.CreaturePool = .{};
    var particles: particles_mod.ParticlePool = .{};
    var player: state_mod.PlayerState = .{
        .index = 0,
        .pos = .{ .x = 512.0, .y = 512.0 },
        .aim = .{ .x = 700.0, .y = 512.0 },
    };
    player.perk_counts.set(PerkId.alternate_weapon, 1);
    player_runtime.weaponAssignPlayer(&player, game_ids.WeaponId.assault_rifle);
    player.alt_weapon = .{
        .weapon_id = game_ids.WeaponId.pistol,
        .clip_size = 10,
        .ammo = 10.0,
        .reload_active = false,
        .reload_timer = 0.0,
        .reload_timer_max = 0.0,
        .shot_cooldown = 0.0,
    };
    player.weapon.shot_cooldown = 0.0;

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

    try std.testing.expectEqual(game_ids.WeaponId.pistol, player.weapon.weapon_id);
    try std.testing.expect(player.alt_weapon != null);
    try std.testing.expectEqual(game_ids.WeaponId.assault_rifle, player.alt_weapon.?.weapon_id);
    try expectFloatClose(0.1, player.weapon.shot_cooldown);
    try std.testing.expectEqual(@as(i32, 200), state.player_alt_weapon_swap_cooldown_ms);
}

test "alternate weapon held reload swaps without a fresh press" {
    var state = state_mod.GameplayState.init(1);
    var projectiles: projectiles_mod.ProjectilePool = .{};
    var secondary_projectiles: secondary_projectiles_mod.SecondaryProjectilePool = .{};
    var creatures: creatures_mod.CreaturePool = .{};
    var particles: particles_mod.ParticlePool = .{};
    var player: state_mod.PlayerState = .{
        .index = 0,
        .pos = .{ .x = 512.0, .y = 512.0 },
        .aim = .{ .x = 700.0, .y = 512.0 },
    };
    player.perk_counts.set(PerkId.alternate_weapon, 1);
    player_runtime.weaponAssignPlayer(&player, game_ids.WeaponId.assault_rifle);
    player.alt_weapon = .{
        .weapon_id = game_ids.WeaponId.pistol,
        .clip_size = 10,
        .ammo = 10.0,
        .reload_active = false,
        .reload_timer = 0.0,
        .reload_timer_max = 0.0,
        .shot_cooldown = 0.0,
    };
    player.weapon.shot_cooldown = 0.0;

    try stepPlayerForTick(
        &state,
        &player,
        &projectiles,
        &secondary_projectiles,
        &creatures,
        &particles,
        .{ .reload_down = true, .reload_active_any = true },
        0.1,
    );

    try std.testing.expectEqual(game_ids.WeaponId.pistol, player.weapon.weapon_id);
    try std.testing.expect(player.alt_weapon != null);
    try std.testing.expectEqual(game_ids.WeaponId.assault_rifle, player.alt_weapon.?.weapon_id);
    try expectFloatClose(0.1, player.weapon.shot_cooldown);
    try std.testing.expectEqual(@as(i32, 200), state.player_alt_weapon_swap_cooldown_ms);
}

test "alternate weapon held reload uses cooldown gate" {
    var state = state_mod.GameplayState.init(1);
    var projectiles: projectiles_mod.ProjectilePool = .{};
    var secondary_projectiles: secondary_projectiles_mod.SecondaryProjectilePool = .{};
    var creatures: creatures_mod.CreaturePool = .{};
    var particles: particles_mod.ParticlePool = .{};
    var player: state_mod.PlayerState = .{
        .index = 0,
        .pos = .{},
        .aim = .{ .x = 100.0, .y = 0.0 },
    };
    player.perk_counts.set(PerkId.alternate_weapon, 1);
    player_runtime.weaponAssignPlayer(&player, game_ids.WeaponId.assault_rifle);
    player.alt_weapon = .{
        .weapon_id = game_ids.WeaponId.pistol,
        .clip_size = 10,
        .ammo = 10.0,
    };

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
    try std.testing.expectEqual(game_ids.WeaponId.pistol, player.weapon.weapon_id);
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
        try std.testing.expectEqual(game_ids.WeaponId.pistol, player.weapon.weapon_id);
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
    try std.testing.expectEqual(game_ids.WeaponId.assault_rifle, player.weapon.weapon_id);
    try std.testing.expectEqual(@as(i32, 200), state.player_alt_weapon_swap_cooldown_ms);
}

test "alternate weapon release resets cooldown gate" {
    var state = state_mod.GameplayState.init(1);
    var projectiles: projectiles_mod.ProjectilePool = .{};
    var secondary_projectiles: secondary_projectiles_mod.SecondaryProjectilePool = .{};
    var creatures: creatures_mod.CreaturePool = .{};
    var particles: particles_mod.ParticlePool = .{};
    var player: state_mod.PlayerState = .{
        .index = 0,
        .pos = .{},
        .aim = .{ .x = 100.0, .y = 0.0 },
    };
    player.perk_counts.set(PerkId.alternate_weapon, 1);
    player_runtime.weaponAssignPlayer(&player, game_ids.WeaponId.assault_rifle);
    player.alt_weapon = .{
        .weapon_id = game_ids.WeaponId.pistol,
        .clip_size = 10,
        .ammo = 10.0,
    };

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
    try std.testing.expectEqual(game_ids.WeaponId.pistol, player.weapon.weapon_id);

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
    try std.testing.expectEqual(game_ids.WeaponId.assault_rifle, player.weapon.weapon_id);
}

test "alternate weapon multiplayer hold is not cleared by other player" {
    var state = state_mod.GameplayState.init(1);
    var projectiles: projectiles_mod.ProjectilePool = .{};
    var secondary_projectiles: secondary_projectiles_mod.SecondaryProjectilePool = .{};
    var creatures: creatures_mod.CreaturePool = .{};
    var particles: particles_mod.ParticlePool = .{};
    var player0: state_mod.PlayerState = .{
        .index = 0,
        .pos = .{},
        .aim = .{ .x = 100.0, .y = 0.0 },
    };
    var player1: state_mod.PlayerState = .{
        .index = 1,
        .pos = .{},
        .aim = .{ .x = 100.0, .y = 0.0 },
    };
    player0.perk_counts.set(PerkId.alternate_weapon, 1);
    player1.perk_counts.set(PerkId.alternate_weapon, 1);
    player_runtime.weaponAssignPlayer(&player0, game_ids.WeaponId.assault_rifle);
    player0.alt_weapon = .{
        .weapon_id = game_ids.WeaponId.pistol,
        .clip_size = 10,
        .ammo = 10.0,
    };
    player_runtime.weaponAssignPlayer(&player1, game_ids.WeaponId.assault_rifle);
    player1.alt_weapon = .{
        .weapon_id = game_ids.WeaponId.pistol,
        .clip_size = 10,
        .ammo = 10.0,
    };

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
    try std.testing.expectEqual(game_ids.WeaponId.pistol, player0.weapon.weapon_id);
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
    var projectiles: projectiles_mod.ProjectilePool = .{};
    var secondary_projectiles: secondary_projectiles_mod.SecondaryProjectilePool = .{};
    var creatures: creatures_mod.CreaturePool = .{};
    var particles: particles_mod.ParticlePool = .{};
    var player: state_mod.PlayerState = .{
        .index = 0,
        .pos = .{ .x = 512.0, .y = 512.0 },
        .aim = .{ .x = 700.0, .y = 512.0 },
    };
    player.perk_counts.set(PerkId.alternate_weapon, 1);
    player_runtime.weaponAssignPlayer(&player, weaponId(11));
    player.alt_weapon = .{
        .weapon_id = game_ids.WeaponId.pistol,
        .clip_size = 10,
        .ammo = 10.0,
    };
    const starting_alt_ammo = player.alt_weapon.?.ammo;

    player.weapon.shot_cooldown = 0.05;
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

    try std.testing.expectEqual(game_ids.WeaponId.pistol, player.weapon.weapon_id);
    try std.testing.expect(player.weapon.ammo < starting_alt_ammo);
}

test "alternate weapon swap allows same-tick fire with swapped reload timer" {
    var state = state_mod.GameplayState.init(1);
    var projectiles: projectiles_mod.ProjectilePool = .{};
    var secondary_projectiles: secondary_projectiles_mod.SecondaryProjectilePool = .{};
    var creatures: creatures_mod.CreaturePool = .{};
    var particles: particles_mod.ParticlePool = .{};
    var player: state_mod.PlayerState = .{
        .index = 0,
        .pos = .{ .x = 512.0, .y = 512.0 },
        .aim = .{ .x = 700.0, .y = 512.0 },
    };
    player.perk_counts.set(PerkId.alternate_weapon, 1);
    player_runtime.weaponAssignPlayer(&player, weaponId(29));
    player.weapon.ammo = 2.0;
    player.weapon.reload_active = false;
    player.weapon.reload_timer = 0.0;
    player.alt_weapon = .{
        .weapon_id = weaponId(11),
        .clip_size = 30,
        .ammo = 0.0,
        .reload_active = true,
        .reload_timer = 0.85,
        .reload_timer_max = 1.3,
        .shot_cooldown = 0.0,
    };

    player.weapon.shot_cooldown = 0.05;
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

    try std.testing.expectEqual(weaponId(11), player.weapon.weapon_id);
    try std.testing.expect(player.weapon.reload_timer > 0.0);
    try expectFloatClose(player.weapon.reload_timer_max, player.weapon.reload_timer);
    try std.testing.expect(player.weapon.ammo < 0.0);
    try std.testing.expect(player.shot_seq >= 1);
}

test "multi plasma and mini rocket use special shot counts" {
    var state = state_mod.GameplayState.init(1);
    var projectiles: projectiles_mod.ProjectilePool = .{};
    var secondary_projectiles: secondary_projectiles_mod.SecondaryProjectilePool = .{};
    var creatures: creatures_mod.CreaturePool = .{};
    var particles: particles_mod.ParticlePool = .{};
    var player: state_mod.PlayerState = .{
        .index = 0,
        .pos = .{},
    };

    player_runtime.weaponAssignPlayer(&player, weaponId(10));
    try std.testing.expect(try tryFireWeapon(&state, &player, &projectiles, &secondary_projectiles, &creatures, &particles));
    try std.testing.expectEqual(@as(i32, 5), state.shots_fired[0]);

    player_runtime.weaponAssignPlayer(&player, weaponId(17));
    player.weapon.ammo = 4.0;
    player.weapon.shot_cooldown = 0.0;
    try std.testing.expect(try tryFireWeapon(&state, &player, &projectiles, &secondary_projectiles, &creatures, &particles));
    try std.testing.expectEqual(@as(i32, 9), state.shots_fired[0]);
}

test "multi plasma fires five projectiles with fixed spread profile" {
    var state = state_mod.GameplayState.init(1);
    var projectiles: projectiles_mod.ProjectilePool = .{};
    var secondary_projectiles: secondary_projectiles_mod.SecondaryProjectilePool = .{};
    var creatures: creatures_mod.CreaturePool = .{};
    var particles: particles_mod.ParticlePool = .{};
    var player: state_mod.PlayerState = .{
        .index = 0,
        .pos = .{},
        .aim = .{ .x = 200.0, .y = 0.0 },
        .aim_dir = .{ .x = 1.0, .y = 0.0 },
        .spread_heat = 0.0,
    };

    player_runtime.weaponAssignPlayer(&player, weaponId(10));
    try std.testing.expect(try tryFireWeapon(&state, &player, &projectiles, &secondary_projectiles, &creatures, &particles));

    try std.testing.expectEqual(@as(usize, 5), activeProjectileCount(&projectiles));
    try std.testing.expectEqual(@as(i32, 5), state.weapon_shots_fired[0][10]);

    const shot_angle = native_math.shotAngleFromJitterDraws(200.0, 0.0, 0.0, 0.0, 0.0, 0, 0);
    const spread_small: f32 = 0.31415927;
    const spread_large: f32 = 0.5235988;
    const expected = [_]struct {
        angle: f32,
        type_id: i32,
    }{
        .{ .angle = native_math.pc24Sub(shot_angle, spread_small), .type_id = @intFromEnum(game_ids.ProjectileTypeId.plasma_rifle) },
        .{ .angle = native_math.pc24Sub(shot_angle, spread_large), .type_id = @intFromEnum(game_ids.ProjectileTypeId.plasma_minigun) },
        .{ .angle = shot_angle, .type_id = @intFromEnum(game_ids.ProjectileTypeId.plasma_rifle) },
        .{ .angle = native_math.pc24Add(shot_angle, spread_large), .type_id = @intFromEnum(game_ids.ProjectileTypeId.plasma_minigun) },
        .{ .angle = native_math.pc24Add(shot_angle, spread_small), .type_id = @intFromEnum(game_ids.ProjectileTypeId.plasma_rifle) },
    };

    for (expected, 0..) |entry, idx| {
        const proj = projectiles.entries[idx];
        try std.testing.expect(proj.active);
        try std.testing.expectEqual(entry.type_id, proj.type_id);
        try std.testing.expectEqual(entry.angle, proj.angle);
    }
}

test "plasma shotgun uses masked jitter and random speed scale" {
    const seed: u32 = 53_165;

    var state = state_mod.GameplayState.init(seed);
    var projectiles: projectiles_mod.ProjectilePool = .{};
    var secondary_projectiles: secondary_projectiles_mod.SecondaryProjectilePool = .{};
    var creatures: creatures_mod.CreaturePool = .{};
    var particles: particles_mod.ParticlePool = .{};
    var player: state_mod.PlayerState = .{
        .index = 0,
        .pos = .{},
        .aim = .{ .x = 200.0, .y = 0.0 },
        .aim_dir = .{ .x = 1.0, .y = 0.0 },
        .spread_heat = 0.0,
    };

    player_runtime.weaponAssignPlayer(&player, weaponId(14));
    try std.testing.expect(try tryFireWeapon(&state, &player, &projectiles, &secondary_projectiles, &creatures, &particles));

    try std.testing.expectEqual(@as(usize, 14), activeProjectileCount(&projectiles));
    try std.testing.expectEqual(@as(i32, 14), state.weapon_shots_fired[0][14]);

    const shot_angle = std.math.pi / 2.0;
    const expected_angle_masked = shot_angle + 127.0 * 0.002;
    const expected_angle_modulo = shot_angle + (@as(f32, @floatFromInt(@as(i32, @intCast(255 % 200)) - 100)) * 0.002);
    try expectFloatClose(expected_angle_masked, projectiles.entries[0].angle);
    try std.testing.expect(@abs(projectiles.entries[0].angle - expected_angle_modulo) > 1e-4);

    var rng = spawn_mod.Crand.init(seed);
    _ = rng.rand();
    _ = rng.rand();
    _ = rng.rand();
    _ = rng.rand();
    const speed_draw = rng.rand();
    const expected_speed = 1.0 + @as(f32, @floatFromInt(speed_draw % 100)) * 0.01;
    try expectFloatClose(expected_speed, projectiles.entries[0].speed_scale);

    for (projectiles.entries[0..14]) |proj| {
        try std.testing.expectEqual(@intFromEnum(game_ids.ProjectileTypeId.plasma_minigun), proj.type_id);
    }
}

test "plasma shotgun consumes one ammo per shot" {
    var state = state_mod.GameplayState.init(1);
    var projectiles: projectiles_mod.ProjectilePool = .{};
    var secondary_projectiles: secondary_projectiles_mod.SecondaryProjectilePool = .{};
    var creatures: creatures_mod.CreaturePool = .{};
    var particles: particles_mod.ParticlePool = .{};
    var player: state_mod.PlayerState = .{
        .index = 0,
        .pos = .{},
        .aim = .{ .x = 200.0, .y = 0.0 },
        .aim_dir = .{ .x = 1.0, .y = 0.0 },
        .spread_heat = 0.0,
    };

    player_runtime.weaponAssignPlayer(&player, weaponId(14));
    const start_ammo = player.weapon.ammo;
    try std.testing.expect(try tryFireWeapon(&state, &player, &projectiles, &secondary_projectiles, &creatures, &particles));
    try expectFloatClose(start_ammo - 1.0, player.weapon.ammo);
}

test "spider plasma uses the native primary projectile mapping" {
    var state = state_mod.GameplayState.init(1);
    var projectiles: projectiles_mod.ProjectilePool = .{};
    var secondary_projectiles: secondary_projectiles_mod.SecondaryProjectilePool = .{};
    var creatures: creatures_mod.CreaturePool = .{};
    var particles: particles_mod.ParticlePool = .{};
    var player: state_mod.PlayerState = .{
        .index = 0,
        .pos = .{},
        .aim = .{ .x = 200.0, .y = 0.0 },
        .aim_dir = .{ .x = 1.0, .y = 0.0 },
        .spread_heat = 0.0,
    };

    player_runtime.weaponAssignPlayer(&player, .spider_plasma);
    try std.testing.expect(try tryFireWeapon(&state, &player, &projectiles, &secondary_projectiles, &creatures, &particles));

    try std.testing.expectEqual(@as(usize, 1), activeProjectileCount(&projectiles));
    try std.testing.expectEqual(@intFromEnum(game_ids.ProjectileTypeId.spider_plasma), projectiles.entries[0].type_id);
    try expectFloatClose(weapon_data.weapon_stats.get(.spider_plasma).travel_budget, projectiles.entries[0].travel_budget);
    try std.testing.expectEqual(@as(i32, 1), state.weapon_shots_fired[0][@intFromEnum(game_ids.WeaponId.spider_plasma)]);
}

test "shotgun family fires expected pellet counts and formulas" {
    const cases = [_]struct {
        weapon_id: i32,
        projectile_type_id: i32,
        expected_count: usize,
        jitter_scale: f32,
        speed_base: f32,
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
        var projectiles: projectiles_mod.ProjectilePool = .{};
        var secondary_projectiles: secondary_projectiles_mod.SecondaryProjectilePool = .{};
        var creatures: creatures_mod.CreaturePool = .{};
        var particles: particles_mod.ParticlePool = .{};
        var player: state_mod.PlayerState = .{
            .index = 0,
            .pos = .{},
            .aim = .{ .x = 200.0, .y = 0.0 },
            .aim_dir = .{ .x = 1.0, .y = 0.0 },
            .spread_heat = 0.0,
        };

        player_runtime.weaponAssignPlayer(&player, weaponId(case.weapon_id));
        try std.testing.expect(try tryFireWeapon(&state, &player, &projectiles, &secondary_projectiles, &creatures, &particles));
        try std.testing.expectEqual(case.expected_count, activeProjectileCount(&projectiles));
        try std.testing.expectEqual(@as(i32, @intCast(case.expected_count)), state.weapon_shots_fired[0][@intCast(case.weapon_id)]);

        var rng = spawn_mod.Crand.init(0);
        if ((weapon_data.weapon_stats.get(weaponId(case.weapon_id)).flags & 0x1) != 0) {
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
                @as(f32, @floatFromInt(@as(i32, @intCast(jitter_draw % 200)) - 100)) * case.jitter_scale;
            const speed_draw = rng.rand();
            const expected_speed = case.speed_base + @as(f32, @floatFromInt(speed_draw % case.speed_mod)) * 0.01;

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
    var projectiles: projectiles_mod.ProjectilePool = .{};
    var secondary_projectiles: secondary_projectiles_mod.SecondaryProjectilePool = .{};
    var creatures: creatures_mod.CreaturePool = .{};
    var particles: particles_mod.ParticlePool = .{};
    var player: state_mod.PlayerState = .{
        .index = 0,
        .pos = .{ .x = 100.0, .y = 100.0 },
        .aim = .{ .x = 101.0, .y = 100.0 },
        .aim_dir = .{ .x = 1.0, .y = 0.0 },
        .spread_heat = 0.01,
    };
    player_runtime.weaponAssignPlayer(&player, weaponId(3));
    player.fire_bullets_timer = 1.0;
    const start_ammo = player.weapon.ammo;

    try std.testing.expect(try tryFireWeapon(&state, &player, &projectiles, &secondary_projectiles, &creatures, &particles));

    try std.testing.expectEqual(@as(usize, 12), activeProjectileCount(&projectiles));
    try std.testing.expectEqual(@as(usize, 0), activeSecondaryProjectileCount(&secondary_projectiles));
    try expectFloatClose(start_ammo, player.weapon.ammo);
    try expectFloatClose(0.296, player.spread_heat);
    for (projectiles.entries[0..12]) |proj| {
        try std.testing.expect(proj.active);
        try std.testing.expectEqual(@intFromEnum(game_ids.ProjectileTypeId.fire_bullets), proj.type_id);
    }
}

test "projectile spawn preserves global fire bullets override and shot credit" {
    const cases = [_]struct {
        preserve_bugs: bool,
        player_index: usize,
        friendly_fire_enabled: bool,
        expected_type_id: ProjectileTypeId,
        expected_shots: i32,
    }{
        .{ .preserve_bugs = true, .player_index = 0, .friendly_fire_enabled = false, .expected_type_id = .fire_bullets, .expected_shots = 2 },
        .{ .preserve_bugs = false, .player_index = 0, .friendly_fire_enabled = false, .expected_type_id = .pistol, .expected_shots = 1 },
        .{ .preserve_bugs = true, .player_index = 3, .friendly_fire_enabled = true, .expected_type_id = .pistol, .expected_shots = 0 },
        .{ .preserve_bugs = false, .player_index = 3, .friendly_fire_enabled = true, .expected_type_id = .pistol, .expected_shots = 1 },
    };

    for (cases) |case| {
        var state = state_mod.GameplayState.init(1);
        state.preserve_bugs = case.preserve_bugs;
        state.friendly_fire_enabled = case.friendly_fire_enabled;
        var projectiles: projectiles_mod.ProjectilePool = .{};
        var secondary_projectiles: secondary_projectiles_mod.SecondaryProjectilePool = .{};
        var creatures: creatures_mod.CreaturePool = .{};
        var particles: particles_mod.ParticlePool = .{};
        var effects: effects_mod.EffectPool = .{};
        var sprite_effects: effects_mod.SpriteEffectPool = .{};
        var players = [_]state_mod.PlayerState{
            .{
                .index = 0,
                .pos = .{},
                .aim = .{ .x = 200.0, .y = 0.0 },
                .aim_dir = .{ .x = 1.0, .y = 0.0 },
                .spread_heat = 0.0,
            },
            .{
                .index = 1,
                .pos = .{ .x = 300.0, .y = 300.0 },
                .fire_bullets_timer = 1.0,
            },
            .{ .index = 2, .pos = .{ .x = 400.0, .y = 400.0 } },
            .{ .index = 3, .pos = .{ .x = 500.0, .y = 500.0 } },
        };
        const firing_idx = case.player_index;
        players[firing_idx].aim = players[firing_idx].pos.add(.{ .x = 200.0, .y = 0.0 });
        players[firing_idx].aim_dir = .{ .x = 1.0, .y = 0.0 };
        players[firing_idx].spread_heat = 0.0;
        player_runtime.weaponAssignPlayer(&players[firing_idx], .pistol);
        const ammo_before = players[firing_idx].weapon.ammo;

        try stepPlayerForTickWithEffects(
            &state,
            &players[firing_idx],
            players[0..],
            &projectiles,
            &secondary_projectiles,
            &creatures,
            &particles,
            &effects,
            &sprite_effects,
            null,
            5,
            .{ .fire_down = true, .preprocessed_player_tick = true },
            1.0 / 60.0,
        );

        try std.testing.expectEqual(@as(usize, 1), activeProjectileCount(&projectiles));
        try std.testing.expectEqual(@intFromEnum(case.expected_type_id), projectiles.entries[0].type_id);
        try expectFloatClose(ammo_before - 1.0, players[firing_idx].weapon.ammo);
        try std.testing.expectEqual(case.expected_shots, state.shots_fired[firing_idx]);
        try std.testing.expectEqual(case.expected_shots, state.shots_fired_total);
        try std.testing.expectEqual(
            @as(i32, 1),
            state.weapon_shots_fired[firing_idx][@intFromEnum(WeaponId.pistol)],
        );
    }
}

test "fire bullets overrides rocket family into primary projectile pool" {
    const rocket_weapon_ids = [_]i32{ 12, 13, 17, 18 };
    for (rocket_weapon_ids) |weapon_id| {
        var state = state_mod.GameplayState.init(1);
        var projectiles: projectiles_mod.ProjectilePool = .{};
        var secondary_projectiles: secondary_projectiles_mod.SecondaryProjectilePool = .{};
        var creatures: creatures_mod.CreaturePool = .{};
        var particles: particles_mod.ParticlePool = .{};
        var player: state_mod.PlayerState = .{
            .index = 0,
            .pos = .{},
            .aim = .{ .x = 200.0, .y = 0.0 },
            .aim_dir = .{ .x = 1.0, .y = 0.0 },
            .spread_heat = 0.0,
        };
        player_runtime.weaponAssignPlayer(&player, weaponId(weapon_id));
        player.fire_bullets_timer = 1.0;

        try std.testing.expect(try tryFireWeapon(&state, &player, &projectiles, &secondary_projectiles, &creatures, &particles));

        const expected_count: usize = @intCast(@max(0, weapon_data.weapon_stats.get(weaponId(weapon_id)).pellet_count));
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
    var projectiles: projectiles_mod.ProjectilePool = .{};
    var secondary_projectiles: secondary_projectiles_mod.SecondaryProjectilePool = .{};
    var creatures: creatures_mod.CreaturePool = .{};
    var particles: particles_mod.ParticlePool = .{};
    var player: state_mod.PlayerState = .{
        .index = 0,
        .pos = .{ .x = 100.0, .y = 100.0 },
        .aim = .{ .x = 101.0, .y = 100.0 },
        .aim_dir = .{ .x = 1.0, .y = 0.0 },
    };
    player_runtime.weaponAssignPlayer(&player, weaponId(3));
    player.weapon.ammo = 0.0;
    player.fire_bullets_timer = 1.0;

    try std.testing.expect(try tryFireWeapon(&state, &player, &projectiles, &secondary_projectiles, &creatures, &particles));

    try std.testing.expectEqual(@as(usize, 12), activeProjectileCount(&projectiles));
    for (projectiles.entries[0..12]) |proj| {
        try std.testing.expect(proj.active);
        try std.testing.expectEqual(@intFromEnum(game_ids.ProjectileTypeId.fire_bullets), proj.type_id);
    }
    try std.testing.expect(player.weapon.reload_active);
    try std.testing.expect(player.weapon.reload_timer > 0.0);
}

test "negative ammo still fires then enters reload for non fire bullets" {
    var state = state_mod.GameplayState.init(1);
    var projectiles: projectiles_mod.ProjectilePool = .{};
    var secondary_projectiles: secondary_projectiles_mod.SecondaryProjectilePool = .{};
    var creatures: creatures_mod.CreaturePool = .{};
    var particles: particles_mod.ParticlePool = .{};
    var player: state_mod.PlayerState = .{
        .index = 0,
        .pos = .{ .x = 100.0, .y = 100.0 },
        .aim = .{ .x = 200.0, .y = 100.0 },
        .aim_dir = .{ .x = 1.0, .y = 0.0 },
        .weapon = .{
            .weapon_id = .pistol,
            .reload_active = false,
            .reload_timer = 0.0,
        },
    };
    player_runtime.weaponAssignPlayer(&player, game_ids.WeaponId.ion_cannon);
    player.weapon.ammo = -1.0;

    try std.testing.expect(try tryFireWeapon(&state, &player, &projectiles, &secondary_projectiles, &creatures, &particles));

    try std.testing.expect(projectiles.entries[0].active);
    try std.testing.expectEqual(@intFromEnum(game_ids.ProjectileTypeId.ion_cannon), projectiles.entries[0].type_id);
    try expectFloatClose(-2.0, player.weapon.ammo);
    try std.testing.expect(player.weapon.reload_active);
    try expectFloatClose(3.0, player.weapon.reload_timer);
}

test "pistol fire consumes native casing+jitter+sfx rng draws" {
    var state = state_mod.GameplayState.init(123);
    var player: state_mod.PlayerState = .{
        .index = 0,
        .pos = .{},
    };
    var projectiles: projectiles_mod.ProjectilePool = .{};
    var secondary_projectiles: secondary_projectiles_mod.SecondaryProjectilePool = .{};
    var creatures: creatures_mod.CreaturePool = .{};
    var particles: particles_mod.ParticlePool = .{};
    player_runtime.weaponAssignPlayer(&player, game_ids.WeaponId.pistol);
    try std.testing.expect(try tryFireWeapon(&state, &player, &projectiles, &secondary_projectiles, &creatures, &particles));
    try std.testing.expect(projectiles.entries[0].active);
}

test "pellet jitter none does not require shotgun caller mapping" {
    var state = state_mod.GameplayState.init(1);
    const shot_angle: f32 = 1.25;
    const angle = applyPelletJitter(
        &state,
        shot_angle,
        .pistol,
        false,
        .none,
    );
    try expectFloatClose(shot_angle, angle);
}

test "fastshot scales shot cooldown" {
    var base_state = state_mod.GameplayState.init(1);
    var base_projectiles: projectiles_mod.ProjectilePool = .{};
    var base_secondary_projectiles: secondary_projectiles_mod.SecondaryProjectilePool = .{};
    var base_creatures: creatures_mod.CreaturePool = .{};
    var base_particles: particles_mod.ParticlePool = .{};
    var base_player: state_mod.PlayerState = .{
        .index = 0,
        .pos = .{},
        .aim = .{ .x = 10.0, .y = 0.0 },
    };
    player_runtime.weaponAssignPlayer(&base_player, game_ids.WeaponId.pistol);
    base_player.weapon.ammo = 2.0;
    try std.testing.expect(try tryFireWeapon(
        &base_state,
        &base_player,
        &base_projectiles,
        &base_secondary_projectiles,
        &base_creatures,
        &base_particles,
    ));
    const base_cooldown = base_player.weapon.shot_cooldown;

    var perk_state = state_mod.GameplayState.init(1);
    var perk_projectiles: projectiles_mod.ProjectilePool = .{};
    var perk_secondary_projectiles: secondary_projectiles_mod.SecondaryProjectilePool = .{};
    var perk_creatures: creatures_mod.CreaturePool = .{};
    var perk_particles: particles_mod.ParticlePool = .{};
    var perk_player: state_mod.PlayerState = .{
        .index = 0,
        .pos = .{},
        .aim = .{ .x = 10.0, .y = 0.0 },
    };
    player_runtime.weaponAssignPlayer(&perk_player, game_ids.WeaponId.pistol);
    perk_player.weapon.ammo = 2.0;
    perk_player.perk_counts.set(PerkId.fastshot, 1);
    try std.testing.expect(try tryFireWeapon(
        &perk_state,
        &perk_player,
        &perk_projectiles,
        &perk_secondary_projectiles,
        &perk_creatures,
        &perk_particles,
    ));

    try expectFloatClose(narrowF32(base_cooldown * 0.88), perk_player.weapon.shot_cooldown);
}

test "sharpshooter forces spread heat and slows firing" {
    var state = state_mod.GameplayState.init(1);
    var projectiles: projectiles_mod.ProjectilePool = .{};
    var secondary_projectiles: secondary_projectiles_mod.SecondaryProjectilePool = .{};
    var creatures: creatures_mod.CreaturePool = .{};
    var particles: particles_mod.ParticlePool = .{};
    var player: state_mod.PlayerState = .{
        .index = 0,
        .pos = .{ .x = 100.0, .y = 100.0 },
        .aim = .{ .x = 200.0, .y = 100.0 },
        .spread_heat = 0.48,
    };
    player_runtime.weaponAssignPlayer(&player, game_ids.WeaponId.assault_rifle);
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

    player.weapon.shot_cooldown = 0.0;
    try std.testing.expect(try tryFireWeapon(
        &state,
        &player,
        &projectiles,
        &secondary_projectiles,
        &creatures,
        &particles,
    ));
    try expectFloatClose(
        narrowF32(weapon_data.weapon_stats.get(game_ids.WeaponId.assault_rifle).shot_cooldown * 1.05),
        player.weapon.shot_cooldown,
    );
    try expectFloatClose(0.02, player.spread_heat);
}

test "regression bullets fires during reload and costs experience" {
    var state = state_mod.GameplayState.init(1);
    var projectiles: projectiles_mod.ProjectilePool = .{};
    var secondary_projectiles: secondary_projectiles_mod.SecondaryProjectilePool = .{};
    var creatures: creatures_mod.CreaturePool = .{};
    var particles: particles_mod.ParticlePool = .{};
    var player: state_mod.PlayerState = .{
        .index = 0,
        .pos = .{},
        .aim = .{ .x = 10.0, .y = 0.0 },
        .experience = 1000,
    };
    player_runtime.weaponAssignPlayer(&player, game_ids.WeaponId.pistol);
    player.perk_counts.set(PerkId.regression_bullets, 1);
    player.weapon.ammo = 0.0;
    player.weapon.reload_active = true;
    player.weapon.reload_timer = 0.5;

    try std.testing.expect(try tryFireWeapon(
        &state,
        &player,
        &projectiles,
        &secondary_projectiles,
        &creatures,
        &particles,
    ));

    try std.testing.expectEqual(@as(i32, 760), player.experience);
    try std.testing.expect(projectiles.entries[0].active);
    try expectFloatClose(-1.0, player.weapon.ammo);
}

test "regression bullets blocks fire when experience is zero" {
    var state = state_mod.GameplayState.init(1);
    var projectiles: projectiles_mod.ProjectilePool = .{};
    var secondary_projectiles: secondary_projectiles_mod.SecondaryProjectilePool = .{};
    var creatures: creatures_mod.CreaturePool = .{};
    var particles: particles_mod.ParticlePool = .{};
    var player: state_mod.PlayerState = .{
        .index = 0,
        .pos = .{},
        .aim = .{ .x = 10.0, .y = 0.0 },
        .experience = 0,
    };
    player_runtime.weaponAssignPlayer(&player, game_ids.WeaponId.pistol);
    player.perk_counts.set(PerkId.regression_bullets, 1);
    player.weapon.ammo = 0.0;
    player.weapon.reload_active = true;
    player.weapon.reload_timer = 0.5;

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
    var projectiles: projectiles_mod.ProjectilePool = .{};
    var secondary_projectiles: secondary_projectiles_mod.SecondaryProjectilePool = .{};
    var creatures: creatures_mod.CreaturePool = .{};
    var particles: particles_mod.ParticlePool = .{};
    var player: state_mod.PlayerState = .{
        .index = 0,
        .pos = .{},
        .aim = .{ .x = 10.0, .y = 0.0 },
        .experience = 1000,
    };
    player_runtime.weaponAssignPlayer(&player, game_ids.WeaponId.flamethrower);
    player.perk_counts.set(PerkId.regression_bullets, 1);
    player.weapon.ammo = 5.0;
    player.weapon.reload_active = true;
    player.weapon.reload_timer = 0.5;

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
    try expectFloatClose(4.9, player.weapon.ammo);
}

test "ammunition within fires during reload and costs health" {
    var state = state_mod.GameplayState.init(1);
    var projectiles: projectiles_mod.ProjectilePool = .{};
    var secondary_projectiles: secondary_projectiles_mod.SecondaryProjectilePool = .{};
    var creatures: creatures_mod.CreaturePool = .{};
    var particles: particles_mod.ParticlePool = .{};
    var player: state_mod.PlayerState = .{
        .index = 0,
        .pos = .{},
        .aim = .{ .x = 10.0, .y = 0.0 },
        .health = 10.0,
        .experience = 1,
    };
    player_runtime.weaponAssignPlayer(&player, game_ids.WeaponId.pistol);
    player.perk_counts.set(PerkId.ammunition_within, 1);
    player.weapon.ammo = 0.0;
    player.weapon.reload_active = true;
    player.weapon.reload_timer = 0.5;

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
    try expectFloatClose(-1.0, player.weapon.ammo);
}

test "ammunition within blocks fire when experience is zero" {
    var state = state_mod.GameplayState.init(1);
    var projectiles: projectiles_mod.ProjectilePool = .{};
    var secondary_projectiles: secondary_projectiles_mod.SecondaryProjectilePool = .{};
    var creatures: creatures_mod.CreaturePool = .{};
    var particles: particles_mod.ParticlePool = .{};
    var player: state_mod.PlayerState = .{
        .index = 0,
        .pos = .{},
        .aim = .{ .x = 10.0, .y = 0.0 },
        .health = 10.0,
        .experience = 0,
    };
    player_runtime.weaponAssignPlayer(&player, game_ids.WeaponId.pistol);
    player.perk_counts.set(PerkId.ammunition_within, 1);
    player.weapon.ammo = 0.0;
    player.weapon.reload_active = true;
    player.weapon.reload_timer = 0.5;

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
    var projectiles: projectiles_mod.ProjectilePool = .{};
    var secondary_projectiles: secondary_projectiles_mod.SecondaryProjectilePool = .{};
    var creatures: creatures_mod.CreaturePool = .{};
    var particles: particles_mod.ParticlePool = .{};
    var player: state_mod.PlayerState = .{
        .index = 0,
        .pos = .{},
        .aim = .{ .x = 10.0, .y = 0.0 },
        .health = 10.0,
        .experience = 1,
    };
    player_runtime.weaponAssignPlayer(&player, game_ids.WeaponId.flamethrower);
    player.perk_counts.set(PerkId.ammunition_within, 1);
    player.weapon.ammo = 5.0;
    player.weapon.reload_active = true;
    player.weapon.reload_timer = 0.5;

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
    try expectFloatClose(4.9, player.weapon.ammo);
}

test "same-id primary dev weapons fire through the main projectile pool" {
    const cases = [_]WeaponId{
        .evil_scythe,
        .flameburst,
        .raygun,
        .grim_weapon,
        .transmutator,
        .blaster_r_300,
        .lightning_rifle,
        .nuke_launcher,
    };

    for (cases) |weapon_id| {
        var state = state_mod.GameplayState.init(1);
        var projectiles: projectiles_mod.ProjectilePool = .{};
        var secondary_projectiles: secondary_projectiles_mod.SecondaryProjectilePool = .{};
        var creatures: creatures_mod.CreaturePool = .{};
        var particles: particles_mod.ParticlePool = .{};
        var player: state_mod.PlayerState = .{
            .index = 0,
            .pos = .{},
            .aim = .{ .x = 200.0, .y = 0.0 },
            .aim_dir = .{ .x = 1.0, .y = 0.0 },
            .spread_heat = 0.0,
        };

        player_runtime.weaponAssignPlayer(&player, weapon_id);
        try std.testing.expect(try tryFireWeapon(
            &state,
            &player,
            &projectiles,
            &secondary_projectiles,
            &creatures,
            &particles,
        ));

        try std.testing.expectEqual(@as(usize, 1), activeProjectileCount(&projectiles));
        try std.testing.expectEqual(@as(usize, 0), activeSecondaryProjectileCount(&secondary_projectiles));
        try std.testing.expect(!particles.entries[0].active);
        try std.testing.expectEqual(@intFromEnum(weapon_id), projectiles.entries[0].type_id);
        try std.testing.expectEqual(@as(i32, 1), state.weapon_shots_fired[0][@intCast(@intFromEnum(weapon_id))]);
    }
}

test "mini rocket swarmers preserve bugged spread when requested" {
    var fixed_state = state_mod.GameplayState.init(1);
    var fixed_projectiles: projectiles_mod.ProjectilePool = .{};
    var fixed_secondary_projectiles: secondary_projectiles_mod.SecondaryProjectilePool = .{};
    var fixed_creatures: creatures_mod.CreaturePool = .{};
    var fixed_particles: particles_mod.ParticlePool = .{};
    var fixed_player: state_mod.PlayerState = .{
        .index = 0,
        .pos = .{},
        .aim = .{ .x = 200.0, .y = 0.0 },
        .aim_dir = .{ .x = 1.0, .y = 0.0 },
        .spread_heat = 0.0,
    };

    player_runtime.weaponAssignPlayer(&fixed_player, .mini_rocket_swarmers);
    fixed_player.weapon.ammo = 6.0;
    try std.testing.expect(try tryFireWeapon(
        &fixed_state,
        &fixed_player,
        &fixed_projectiles,
        &fixed_secondary_projectiles,
        &fixed_creatures,
        &fixed_particles,
    ));

    var bug_state = state_mod.GameplayState.init(1);
    bug_state.preserve_bugs = true;
    var bug_projectiles: projectiles_mod.ProjectilePool = .{};
    var bug_secondary_projectiles: secondary_projectiles_mod.SecondaryProjectilePool = .{};
    var bug_creatures: creatures_mod.CreaturePool = .{};
    var bug_particles: particles_mod.ParticlePool = .{};
    var bug_player = fixed_player;
    bug_player.weapon.shot_cooldown = 0.0;
    bug_player.weapon.reload_timer = 0.0;
    bug_player.weapon.ammo = 6.0;
    bug_player.spread_heat = 0.0;

    try std.testing.expect(try tryFireWeapon(
        &bug_state,
        &bug_player,
        &bug_projectiles,
        &bug_secondary_projectiles,
        &bug_creatures,
        &bug_particles,
    ));

    const shot_angle = native_math.shotAngleFromJitterDraws(200.0, 0.0, 0.0, 0.0, 0.0, 0, 0);
    const rocket_count: f32 = 6.0;
    const fixed_step = (native_pi * (2.0 / 3.0)) / (rocket_count - 1.0);
    const fixed_first_angle = shot_angle - native_pi * (1.0 / 3.0);
    try expectFloatClose(fixed_first_angle, fixed_secondary_projectiles.entries[0].angle);
    try expectFloatClose(fixed_first_angle + fixed_step, fixed_secondary_projectiles.entries[1].angle);

    const bug_step = narrowF32(rocket_count * (native_pi / 3.0));
    const bug_first_angle = narrowF32((shot_angle - native_pi) - bug_step * rocket_count * 0.5);
    try expectFloatClose(bug_first_angle, bug_secondary_projectiles.entries[0].angle);
    try expectFloatClose(narrowF32(bug_first_angle + bug_step), bug_secondary_projectiles.entries[1].angle);
}
