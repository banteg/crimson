const std = @import("std");

const survival_bonuses = @import("survival_bonuses.zig");
const survival_perks = @import("survival_perks.zig");
const survival_spawn = @import("survival_spawn.zig");
const survival_state = @import("survival_state.zig");
const survival_math = @import("survival_math.zig");

pub const max_creatures: usize = 0x180;

const creature_lifecycle_stage_alive: f64 = 16.0;
const creature_speed_scale: f64 = 30.0;
const creature_turn_rate_scale: f64 = 1.3333333730697632;
const contact_damage_cooldown: f64 = 1.0;
const plague_collision_period: f64 = 0.5;
const owner_id_player_0: i32 = -100;
const native_half_pi: f64 = 1.5707963705062866;
const native_pi: f64 = 3.1415927410125732;
const native_tau: f64 = 6.2831854820251465;
const native_left_axis_heading_pos: f64 = 4.71238899230957;
const native_left_axis_heading_eps: f64 = 1e-6;
const native_left_axis_dy_eps: f64 = 5e-4;

pub const CreatureRuntimeError = error{
    UnsupportedSpawnTemplate,
};

pub const CreatureState = struct {
    active: bool = false,
    type_id: i32 = 0,
    pos: survival_state.Vec2 = .{},
    target: survival_state.Vec2 = .{},
    target_offset: survival_state.Vec2 = .{},
    heading: f64 = 0.0,
    target_heading: f64 = 0.0,
    phase_seed: f64 = 0.0,
    vel: survival_state.Vec2 = .{},
    move_scale: f64 = 1.0,
    force_target: i32 = 0,
    ai_mode: i32 = survival_spawn.CreatureAiMode.orbit_player,
    // Native keeps this stale across slot reuse for some spawn paths.
    link_index: i32 = -1,
    orbit_angle: f64 = 0.0,
    orbit_radius: f64 = 0.0,
    hp: f64 = 0.0,
    max_hp: f64 = 0.0,
    move_speed: f64 = 0.0,
    reward_value: f64 = 0.0,
    size: f64 = 0.0,
    contact_damage: f64 = 0.0,
    plague_infected: bool = false,
    collision_timer: f64 = plague_collision_period,
    lifecycle_stage: f64 = creature_lifecycle_stage_alive,
    attack_cooldown: f64 = 0.0,
    last_hit_owner_id: i32 = owner_id_player_0,
    flags: u32 = 0,
};

pub const ShotResolutionResult = struct {
    hits: i32 = 0,
    deaths: i32 = 0,
    xp_awarded: i32 = 0,
};

pub const CreaturePool = struct {
    entries: [max_creatures]CreatureState = [_]CreatureState{CreatureState{}} ** max_creatures,
    kill_count: i32 = 0,

    pub fn reset(self: *CreaturePool) void {
        self.entries = [_]CreatureState{CreatureState{}} ** max_creatures;
        self.kill_count = 0;
    }

    pub fn activeCount(self: *const CreaturePool) usize {
        var count: usize = 0;
        for (self.entries) |creature| {
            if (creature.active) count += 1;
        }
        return count;
    }

    pub fn spawnInits(
        self: *CreaturePool,
        inits: []const survival_spawn.CreatureInit,
    ) void {
        for (inits) |init| {
            _ = self.spawnInit(init);
        }
    }

    pub fn spawnInit(self: *CreaturePool, init: survival_spawn.CreatureInit) usize {
        var slot: usize = self.entries.len - 1;
        for (self.entries, 0..) |creature, idx| {
            if (!creature.active) {
                slot = idx;
                break;
            }
        }
        const stale_link_index = self.entries[slot].link_index;
        const stale_target_heading = self.entries[slot].target_heading;
        const stale_heading = self.entries[slot].heading;

        self.entries[slot] = .{
            .active = true,
            .type_id = @intFromEnum(init.type_id),
            .pos = .{
                .x = asF32F64(init.pos.x),
                .y = asF32F64(init.pos.y),
            },
            .target = .{
                .x = asF32F64(init.pos.x),
                .y = asF32F64(init.pos.y),
            },
            .heading = if (init.set_heading) asF32F64(init.heading) else stale_heading,
            .target_heading = stale_target_heading,
            .phase_seed = asF32F64(init.phase_seed),
            .vel = .{},
            .move_scale = 1.0,
            .force_target = 0,
            .ai_mode = init.ai_mode,
            .link_index = stale_link_index,
            .hp = asF32F64(init.health),
            .max_hp = asF32F64(init.max_health),
            .move_speed = asF32F64(init.move_speed),
            .reward_value = asF32F64(init.reward_value),
            .size = asF32F64(init.size),
            .contact_damage = asF32F64(init.contact_damage),
            .plague_infected = false,
            .collision_timer = 0.0,
            .lifecycle_stage = creature_lifecycle_stage_alive,
            .attack_cooldown = 0.0,
            .last_hit_owner_id = owner_id_player_0,
            .flags = init.flags,
        };
        return slot;
    }

    pub fn spawnTemplateCall(
        self: *CreaturePool,
        call: survival_spawn.SpawnTemplateCall,
        rng: *survival_spawn.Crand,
    ) CreatureRuntimeError!void {
        switch (call.template_id) {
            survival_spawn.SpawnId.formation_ring_alien_8_12 => {
                // Parent.
                const parent_idx = self.spawnFromStats(
                    rng,
                    .{ .x = call.pos.x, .y = call.pos.y },
                    call.heading,
                    .{
                        .type_id = @intFromEnum(survival_spawn.CreatureTypeId.alien),
                        .health = 200.0,
                        .move_speed = 2.2,
                        .reward_value = 600.0,
                        .size = 55.0,
                        .contact_damage = 14.0,
                    },
                );
                // Native template planning consumes a transient base-heading draw
                // after base allocation but before child allocations.
                const transient_heading = asF32F64(@as(f64, @floatFromInt(rng.rand() % 314)) * 0.01);
                self.entries[parent_idx].heading = transient_heading;

                const angle_step = std.math.pi / 4.0;
                var primary_child_idx: usize = parent_idx;
                for (0..8) |idx| {
                    const angle = @as(f64, @floatFromInt(idx)) * angle_step;
                    const offset = survival_state.Vec2.fromAngle(angle).mul(100.0);
                    const child_idx = self.spawnFromStatsWithFlags(
                        rng,
                        .{
                            .x = call.pos.x,
                            .y = call.pos.y,
                        },
                        call.heading,
                        .{
                            .type_id = @intFromEnum(survival_spawn.CreatureTypeId.alien),
                            .health = 40.0,
                            .move_speed = 2.4,
                            .reward_value = 60.0,
                            .size = 50.0,
                            .contact_damage = 4.0,
                        },
                        0,
                        false,
                    );
                    self.entries[child_idx].ai_mode = survival_spawn.CreatureAiMode.follow_link;
                    self.entries[child_idx].link_index = @intCast(parent_idx);
                    self.entries[child_idx].target_offset = .{
                        .x = asF32F64(offset.x),
                        .y = asF32F64(offset.y),
                    };
                    primary_child_idx = child_idx;
                }
                self.entries[primary_child_idx].heading = asF32F64(call.heading);
            },
            survival_spawn.SpawnId.alien_const_red_fast_2b => {
                _ = self.spawnFromStats(
                    rng,
                    .{ .x = call.pos.x, .y = call.pos.y },
                    call.heading,
                    .{
                        .type_id = @intFromEnum(survival_spawn.CreatureTypeId.alien),
                        .health = 30.0,
                        .move_speed = 3.6,
                        .reward_value = 450.0,
                        .size = 35.0,
                        .contact_damage = 20.0,
                    },
                );
                _ = rng.rand() % 314;
            },
            survival_spawn.SpawnId.alien_const_red_boss_2c => {
                _ = self.spawnFromStats(
                    rng,
                    .{ .x = call.pos.x, .y = call.pos.y },
                    call.heading,
                    .{
                        .type_id = @intFromEnum(survival_spawn.CreatureTypeId.alien),
                        .health = 3800.0,
                        .move_speed = 2.0,
                        .reward_value = 1500.0,
                        .size = 80.0,
                        .contact_damage = 40.0,
                    },
                );
                _ = rng.rand() % 314;
            },
            survival_spawn.SpawnId.spider_sp2_random_35 => {
                // Match Python/native plan builder ordering:
                // allocCreature phase seed, transient heading draw, then template randoms.
                const phase_seed = @as(f64, @floatFromInt(rng.rand() & 0x17f));
                _ = rng.rand() % 314;

                const size = randf(rng, 10, 1.0, 30.0);
                const move_speed = randf(rng, 18, 0.1, 1.1);
                const tint_g = randf(rng, 20, 0.01, 0.8);
                const contact_damage = randf(rng, 10, 1.0, 4.0);
                const health = asF32F64(size * (8.0 / 7.0) + 20.0);
                const reward_value = asF32F64(size + size + 50.0);

                _ = tint_g;
                _ = self.spawnInit(.{
                    .origin_template_id = -1,
                    .pos = .{ .x = call.pos.x, .y = call.pos.y },
                    .heading = call.heading,
                    .set_heading = true,
                    .phase_seed = phase_seed,
                    .type_id = survival_spawn.CreatureTypeId.spider_sp2,
                    .ai_mode = survival_spawn.CreatureAiMode.orbit_player,
                    .flags = 0,
                    .size = size,
                    .move_speed = move_speed,
                    .health = health,
                    .max_health = health,
                    .reward_value = reward_value,
                    .contact_damage = contact_damage,
                });
            },
            survival_spawn.SpawnId.spider_sp1_ai7_timer_38 => {
                const idx = self.spawnFromStatsWithFlags(
                    rng,
                    .{ .x = call.pos.x, .y = call.pos.y },
                    call.heading,
                    .{
                        .type_id = @intFromEnum(survival_spawn.CreatureTypeId.spider_sp1),
                        .health = 50.0,
                        .move_speed = 4.8,
                        .reward_value = 433.0,
                        .size = @as(f64, @floatFromInt((rng.rand() & 3) + 41)),
                        .contact_damage = 10.0,
                    },
                    survival_spawn.CreatureFlags.ai7_link_timer,
                    true,
                );
                self.entries[idx].link_index = 0;
                _ = rng.rand() % 314;
            },
            else => return error.UnsupportedSpawnTemplate,
        }
    }

    pub fn update(
        self: *CreaturePool,
        state: *survival_state.GameplayState,
        players: []survival_state.PlayerState,
        dt: f64,
        world_size: f64,
        bonus_pool: *survival_bonuses.BonusPool,
    ) void {
        if (players.len == 0) return;
        if (!(dt > 0.0)) return;

        const dt_ms = @max(@as(i32, 0), @as(i32, @intFromFloat(@round(dt * 1000.0))));
        const player = &players[0];

        for (&self.entries) |*creature| {
            if (!creature.active) continue;
            if (state.bonuses.freeze > 0.0) continue;
            if (!(creature.hp > 0.0)) {
                applySelfDamageTickToDead(creature, dt);
                tickAi7LinkTimer(creature, dt_ms, &state.rng);
                if (creature.lifecycle_stage == creature_lifecycle_stage_alive) {
                    creature.lifecycle_stage = asF32F64(creature.lifecycle_stage - dt);
                }
                tickDead(creature, dt, &self.kill_count, state);
                continue;
            }

            tickAi7LinkTimer(creature, dt_ms, &state.rng);
            creatureAiUpdateTarget(creature, player.pos, self.entries[0..], dt);
            if (creature.plague_infected) {
                creature.collision_timer -= dt;
                if (creature.collision_timer < 0.0) {
                    creature.collision_timer += plague_collision_period;
                    creature.hp = asF32F64(creature.hp - 15.0);
                    if (creature.hp < 0.0) {
                        state.plaguebearer_infection_count += 1;
                        consumeDeathSideEffectsRng(
                            state,
                            players,
                            bonus_pool,
                            creature.pos,
                            world_size,
                            false,
                        );
                        _ = awardExperienceFromReward(state, player, creature.reward_value);
                        creature.lifecycle_stage = asF32F64(creature.lifecycle_stage - dt);
                        consumeContactSfxRng(state, creature.type_id);
                    }
                    consumeAddRandomRng(state);
                }
            }
            if ((state.bonuses.energizer > 0.0 and creature.max_hp < 500.0) or creature.plague_infected) {
                creature.target_heading = asF32F64(creature.target_heading + native_pi);
            }
            const turn_rate = asF32F64(creature.move_speed * creature_turn_rate_scale);
            if (creature.ai_mode != survival_spawn.CreatureAiMode.hold_timer) {
                creature.heading = angleApproach(
                    creature.heading,
                    creature.target_heading,
                    turn_rate,
                    dt,
                );
                const move_delta = movementDeltaFromHeadingF32(
                    creature.heading,
                    dt,
                    creature.move_scale,
                    creature.move_speed,
                );
                creature.vel = move_delta;
                creature.pos = advancePosByDeltaF32(creature.pos, move_delta);
            }

            const eat_sq = survival_state.Vec2.sub(player.pos, creature.pos).lengthSq();
            if (eat_sq < 20.0 * 20.0) {
                var reverted_x = creature.pos.x - creature.vel.x;
                var reverted_y = creature.pos.y - creature.vel.y;
                if (reverted_x < 0.0) {
                    reverted_x = 0.0;
                } else if (reverted_x > world_size) {
                    reverted_x = world_size;
                }
                if (reverted_y < 0.0) {
                    reverted_y = 0.0;
                } else if (reverted_y > world_size) {
                    reverted_y = world_size;
                }
                creature.pos = .{
                    .x = reverted_x,
                    .y = reverted_y,
                };

                if (state.bonuses.energizer > 0.0 and creature.max_hp < 380.0) {
                    for (0..6) |_| {
                        _ = state.rng.rand();
                        _ = state.rng.rand();
                        _ = state.rng.rand();
                        _ = state.rng.rand();
                    }
                    creature.last_hit_owner_id = -1 - player.index;
                    const prev_spawn_guard = state.bonus_spawn_guard;
                    state.bonus_spawn_guard = true;
                    consumeDeathSideEffectsRng(
                        state,
                        players,
                        bonus_pool,
                        creature.pos,
                        world_size,
                        true,
                    );
                    state.bonus_spawn_guard = prev_spawn_guard;
                    _ = awardExperienceFromReward(state, player, creature.reward_value);
                    creature.active = false;
                    continue;
                }
            }
            if (perkActive(player, perk_id_plaguebearer) and state.plaguebearer_infection_count < 0x3c) {
                spreadPlagueInfection(self.entries[0..], creature);
            }

            if (creature.attack_cooldown <= 0.0) {
                creature.attack_cooldown = 0.0;
            } else {
                creature.attack_cooldown -= dt;
            }

            const contact_sq = survival_state.Vec2.sub(player.pos, creature.pos).lengthSq();
            if (creature.lifecycle_stage == creature_lifecycle_stage_alive and
                creature.size > 16.0 and
                contact_sq < 30.0 * 30.0 and
                creature.attack_cooldown <= 0.0 and
                player.health > 0.0 and
                state.bonuses.energizer <= 0.0)
            {
                consumeContactSfxRng(state, creature.type_id);
                applyPlayerContactDamage(state, player, creature.contact_damage, dt);
                consumeAddRandomRng(state);
                creature.attack_cooldown = asF32F64(creature.attack_cooldown + contact_damage_cooldown);
            }

            if (state.bonuses.energizer <= 0.0 and
                player.plaguebearer_active and
                creature.hp < 150.0 and
                state.plaguebearer_infection_count < 0x32 and
                contact_sq < 30.0 * 30.0)
            {
                creature.plague_infected = true;
            }
            if (creature.lifecycle_stage == creature_lifecycle_stage_alive and
                contact_sq < 30.0 * 30.0 and
                creature.size <= 30.0)
            {
                creature.hp = 0.0;
                creature.lifecycle_stage = asF32F64(creature.lifecycle_stage - dt);
                continue;
            }
        }
    }

    pub fn finalizePostRenderLifecycle(self: *CreaturePool) void {
        for (&self.entries) |*creature| {
            if (!creature.active) continue;
            if (creature.lifecycle_stage < -10.0) {
                creature.active = false;
            }
        }
    }

    pub fn resolvePlayerShots(
        self: *CreaturePool,
        state: *survival_state.GameplayState,
        players: []survival_state.PlayerState,
        bonus_pool: *survival_bonuses.BonusPool,
        player_index: usize,
        aim_target: survival_state.Vec2,
        shot_count: i32,
        weapon_id: i32,
        world_size: f64,
    ) ShotResolutionResult {
        if (players.len == 0) return .{};
        if (player_index >= players.len) return .{};
        if (shot_count <= 0) return .{};

        var player = &players[player_index];
        var aim_dir = survival_state.Vec2.sub(aim_target, player.pos);
        const aim_len_sq = aim_dir.lengthSq();
        if (aim_len_sq > 1e-9) {
            const inv_len = 1.0 / std.math.sqrt(aim_len_sq);
            aim_dir = aim_dir.mul(inv_len);
            player.aim_dir = .{
                .x = asF32F64(aim_dir.x),
                .y = asF32F64(aim_dir.y),
            };
        } else {
            aim_dir = player.aim_dir;
        }

        var result = ShotResolutionResult{};
        const projectile_type_id = survival_state.projectileTypeIdFromWeaponId(weapon_id) orelse weapon_id;
        const damage_scale = survival_state.weaponDamageScale(weapon_id);
        const owner_id: i32 = -1 - player.index;
        var hit_audio_game_tune_started = state.game_tune_started;

        var shot_idx: i32 = 0;
        while (shot_idx < shot_count) : (shot_idx += 1) {
            const hit_idx = self.findRayHitCreature(player.pos, aim_dir) orelse {
                continue;
            };

            if (perkActive(player, perk_id_poison_bullets)) {
                _ = state.rng.rand();
            }
            consumeProjectileHitPresentationPreRng(state, player, projectile_type_id);

            const hit_pos = self.entries[hit_idx].pos;
            const damage = projectileHitDamage(player.pos, hit_pos, damage_scale);

            result.hits += 1;
            if (player.index >= 0 and player.index < state.shots_hit.len) {
                state.shots_hit[@intCast(player.index)] += 1;
            }

            const xp_gained = self.applyDamage(
                state,
                players,
                bonus_pool,
                hit_idx,
                damage,
                .{},
                owner_id,
                1.0 / 60.0,
                world_size,
            );
            consumeProjectileHitPresentationPostRng(state, projectile_type_id);
            consumeHitSfxRng(state, &hit_audio_game_tune_started, projectile_type_id);
            if (xp_gained > 0) {
                result.deaths += 1;
                result.xp_awarded += xp_gained;
            }
        }
        state.game_tune_started = hit_audio_game_tune_started;

        return result;
    }

    pub fn applyProjectileDamage(
        self: *CreaturePool,
        state: *survival_state.GameplayState,
        players: []survival_state.PlayerState,
        bonus_pool: *survival_bonuses.BonusPool,
        creature_index: usize,
        damage: f64,
        impulse: survival_state.Vec2,
        owner_id: i32,
        dt: f64,
        world_size: f64,
    ) i32 {
        const jitter_rand = state.rng.rand();
        if (creature_index < self.entries.len) {
            var creature = &self.entries[creature_index];
            if ((creature.flags & survival_spawn.CreatureFlags.anim_ping_pong) == 0) {
                const jitter_i32: i32 = @as(i32, @intCast(jitter_rand & 0x7f)) - 0x40;
                const jitter = @as(f64, @floatFromInt(jitter_i32)) * 0.002;
                const size = @max(1e-6, creature.size);
                var turn = jitter / (size * 0.025);
                const half_pi = std.math.pi / 2.0;
                if (turn > half_pi) turn = half_pi;
                creature.heading += turn;
            }
        }
        var damage_amount = damage;
        if (anyPlayerHasPerk(players, perk_id_uranium_filled_bullets)) {
            damage_amount *= 2.0;
        }
        if (anyPlayerHasPerk(players, perk_id_barrel_greaser)) {
            damage_amount *= 1.4;
        }
        if (anyPlayerHasPerk(players, perk_id_doctor)) {
            damage_amount *= 1.2;
        }
        return self.applyDamage(
            state,
            players,
            bonus_pool,
            creature_index,
            damage_amount,
            impulse,
            owner_id,
            dt,
            world_size,
        );
    }

    pub fn applyIonDamage(
        self: *CreaturePool,
        state: *survival_state.GameplayState,
        players: []survival_state.PlayerState,
        bonus_pool: *survival_bonuses.BonusPool,
        creature_index: usize,
        damage: f64,
        impulse: survival_state.Vec2,
        owner_id: i32,
        dt: f64,
        world_size: f64,
    ) i32 {
        var damage_amount = damage;
        if (anyPlayerHasPerk(players, perk_id_ion_gun_master)) {
            damage_amount *= 1.2;
        }
        return self.applyDamage(
            state,
            players,
            bonus_pool,
            creature_index,
            damage_amount,
            impulse,
            owner_id,
            dt,
            world_size,
        );
    }

    pub fn applyExplosionDamage(
        self: *CreaturePool,
        state: *survival_state.GameplayState,
        players: []survival_state.PlayerState,
        bonus_pool: *survival_bonuses.BonusPool,
        creature_index: usize,
        damage: f64,
        impulse: survival_state.Vec2,
        owner_id: i32,
        dt: f64,
        world_size: f64,
    ) i32 {
        if (creature_index >= self.entries.len) return 0;
        if (players.len == 0) return 0;

        var creature = &self.entries[creature_index];
        if (!creature.active) return 0;
        creature.last_hit_owner_id = owner_id;

        // Native nuke path applies damage to active corpse entries as well.
        if (!(creature.hp > 0.0)) {
            if (dt > 0.0) {
                creature.lifecycle_stage -= dt * 15.0;
            }
            return 0;
        }

        creature.hp -= damage;
        creature.vel = .{
            .x = creature.vel.x - impulse.x,
            .y = creature.vel.y - impulse.y,
        };
        if (creature.hp > 0.0) return 0;

        if (dt > 0.0) {
            creature.lifecycle_stage -= dt;
        } else {
            creature.lifecycle_stage -= 0.001;
        }
        creature.vel = .{
            .x = creature.vel.x - impulse.x * 2.0,
            .y = creature.vel.y - impulse.y * 2.0,
        };

        consumeDeathSideEffectsRng(
            state,
            players,
            bonus_pool,
            creature.pos,
            world_size,
            true,
        );
        if (dt > 0.0) {
            creature.lifecycle_stage -= dt;
        }

        const owner_player_idx = ownerIdToPlayerIndex(owner_id) orelse 0;
        const slot: usize = if (owner_player_idx >= 0 and owner_player_idx < players.len)
            @intCast(owner_player_idx)
        else
            0;
        const xp_gained = awardExperienceFromReward(state, &players[slot], creature.reward_value);
        if (state.bonuses.freeze > 0.0) {
            self.kill_count += 1;
            creature.active = false;
        }
        return xp_gained;
    }

    pub fn killNoCorpse(
        self: *CreaturePool,
        state: *survival_state.GameplayState,
        players: []survival_state.PlayerState,
        bonus_pool: *survival_bonuses.BonusPool,
        creature_index: usize,
        owner_id: i32,
        dt: f64,
        world_size: f64,
    ) i32 {
        if (creature_index >= self.entries.len) return 0;
        if (players.len == 0) return 0;

        var creature = &self.entries[creature_index];
        if (!creature.active) return 0;
        if (!(creature.hp > 0.0)) return 0;

        creature.last_hit_owner_id = owner_id;

        consumeDeathSideEffectsRng(
            state,
            players,
            bonus_pool,
            creature.pos,
            world_size,
            true,
        );

        const owner_player_idx = ownerIdToPlayerIndex(owner_id) orelse 0;
        const slot: usize = if (owner_player_idx >= 0 and owner_player_idx < players.len)
            @intCast(owner_player_idx)
        else
            0;
        const xp_gained = awardExperienceFromReward(state, &players[slot], creature.reward_value);

        if (dt > 0.0 and state.bonuses.freeze > 0.0) {
            for (0..8) |_| {
                _ = state.rng.rand() % 0x264;
                for (0..6) |_| {
                    _ = state.rng.rand();
                }
            }
            _ = state.rng.rand() % 0x264;
            for (0..4) |_| {
                _ = state.rng.rand();
                _ = state.rng.rand();
            }
            for (0..4) |_| {
                _ = state.rng.rand() % 0x264;
                for (0..6) |_| {
                    _ = state.rng.rand();
                }
            }
            self.kill_count += 1;
        }

        creature.active = false;
        return xp_gained;
    }

    fn spawnFromStats(
        self: *CreaturePool,
        rng: *survival_spawn.Crand,
        pos: survival_state.Vec2,
        heading: f64,
        stats: SpawnStats,
    ) usize {
        return self.spawnFromStatsWithFlags(rng, pos, heading, stats, 0, true);
    }

    fn spawnFromStatsWithFlags(
        self: *CreaturePool,
        rng: *survival_spawn.Crand,
        pos: survival_state.Vec2,
        heading: f64,
        stats: SpawnStats,
        flags: u32,
        set_heading: bool,
    ) usize {
        const phase_seed = @as(f64, @floatFromInt(rng.rand() & 0x17f));
        return self.spawnInit(.{
            .origin_template_id = -1,
            .pos = .{
                .x = pos.x,
                .y = pos.y,
            },
            .heading = heading,
            .set_heading = set_heading,
            .phase_seed = phase_seed,
            .type_id = @enumFromInt(stats.type_id),
            .ai_mode = survival_spawn.CreatureAiMode.orbit_player,
            .flags = flags,
            .size = stats.size,
            .move_speed = stats.move_speed,
            .health = stats.health,
            .max_health = stats.health,
            .reward_value = stats.reward_value,
            .contact_damage = stats.contact_damage,
        });
    }

    fn findRayHitCreature(
        self: *CreaturePool,
        origin: survival_state.Vec2,
        dir: survival_state.Vec2,
    ) ?usize {
        var best_idx: ?usize = null;
        var best_along = std.math.inf(f64);

        for (self.entries, 0..) |creature, idx| {
            if (!creature.active) continue;
            if (!(creature.hp > 0.0)) continue;
            if (creature.lifecycle_stage <= 5.0) continue;

            const to_creature = survival_state.Vec2.sub(creature.pos, origin);
            const along = dot(to_creature, dir);
            if (!(along > 0.0)) continue;
            if (along >= best_along) continue;

            const proj = dir.mul(along);
            const perp = survival_state.Vec2.sub(to_creature, proj);
            const radius = hitRadiusFor(creature);
            if (perp.lengthSq() <= radius * radius) {
                best_idx = idx;
                best_along = along;
            }
        }

        return best_idx;
    }

    fn applyDamage(
        self: *CreaturePool,
        state: *survival_state.GameplayState,
        players: []survival_state.PlayerState,
        bonus_pool: *survival_bonuses.BonusPool,
        creature_index: usize,
        damage: f64,
        impulse: survival_state.Vec2,
        owner_id: i32,
        dt: f64,
        world_size: f64,
    ) i32 {
        if (creature_index >= self.entries.len) return 0;
        if (players.len == 0) return 0;

        var creature = &self.entries[creature_index];
        if (!creature.active) return 0;
        // Native damage path records the incoming owner even on corpse hits.
        creature.last_hit_owner_id = owner_id;
        if (!(creature.hp > 0.0)) {
            if (dt > 0.0) {
                creature.lifecycle_stage -= dt * 15.0;
            }
            return 0;
        }

        creature.hp -= damage;
        creature.vel = .{
            .x = creature.vel.x - impulse.x,
            .y = creature.vel.y - impulse.y,
        };
        if (creature.hp > 0.0) return 0;

        if (dt > 0.0) {
            creature.lifecycle_stage -= dt;
        } else {
            creature.lifecycle_stage -= 0.001;
        }
        creature.vel = .{
            .x = creature.vel.x - impulse.x * 2.0,
            .y = creature.vel.y - impulse.y * 2.0,
        };
        consumeDeathSideEffectsRng(
            state,
            players,
            bonus_pool,
            creature.pos,
            world_size,
            true,
        );
        if (dt > 0.0) {
            creature.lifecycle_stage -= dt;
        }

        const owner_player_idx = ownerIdToPlayerIndex(owner_id) orelse 0;
        const slot: usize = if (owner_player_idx >= 0 and owner_player_idx < players.len)
            @intCast(owner_player_idx)
        else
            0;
        const xp_gained = awardExperienceFromReward(state, &players[slot], creature.reward_value);
        if (state.bonuses.freeze > 0.0) {
            self.kill_count += 1;
            creature.active = false;
        }
        return xp_gained;
    }
};

fn creatureAiUpdateTarget(
    creature: *CreatureState,
    player_pos: survival_state.Vec2,
    creatures: []const CreatureState,
    dt: f64,
) void {
    const dist_to_player = distanceF32(creature.pos, player_pos);
    const phase_int: i32 = @intFromFloat(creature.phase_seed);
    const phase_scale = asF32F64(3.7);
    const orbit_phase = asF32F64(asF32F64(@as(f64, @floatFromInt(phase_int)) * phase_scale) * native_pi);

    creature.force_target = 0;
    var move_scale: f64 = 1.0;
    const ai_mode = creature.ai_mode;

    if (ai_mode == survival_spawn.CreatureAiMode.orbit_player) {
        if (dist_to_player > 800.0) {
            creature.target = .{
                .x = asF32F64(player_pos.x),
                .y = asF32F64(player_pos.y),
            };
        } else {
            creature.target = orbitTargetF32(player_pos, orbit_phase, dist_to_player, 0.85);
        }
    } else if (ai_mode == survival_spawn.CreatureAiMode.orbit_player_wide) {
        creature.target = orbitTargetF32(player_pos, orbit_phase, dist_to_player, 0.9);
    } else if (ai_mode == survival_spawn.CreatureAiMode.orbit_player_tight) {
        if (dist_to_player > 800.0) {
            creature.target = .{
                .x = asF32F64(player_pos.x),
                .y = asF32F64(player_pos.y),
            };
        } else {
            creature.target = orbitTargetF32(player_pos, orbit_phase, dist_to_player, 0.55);
        }
    } else if (ai_mode == survival_spawn.CreatureAiMode.follow_link) {
        if (resolveLiveLink(creatures, creature.link_index)) |link| {
            creature.target = linkTargetF32(link.pos, creature.target_offset);
        } else {
            creature.ai_mode = survival_spawn.CreatureAiMode.orbit_player;
        }
    } else if (ai_mode == survival_spawn.CreatureAiMode.follow_link_tethered) {
        if (resolveLiveLink(creatures, creature.link_index)) |link| {
            creature.target = linkTargetF32(link.pos, creature.target_offset);
            const dist_to_target = distanceF32(creature.pos, creature.target);
            if (dist_to_target <= 64.0) {
                move_scale = asF32F64(dist_to_target * 0.015625);
            }
        } else {
            creature.ai_mode = survival_spawn.CreatureAiMode.orbit_player;
        }
    }

    const ai_mode_after_primary = creature.ai_mode;
    if (ai_mode_after_primary == survival_spawn.CreatureAiMode.link_guard) {
        if (resolveLiveLink(creatures, creature.link_index) == null) {
            creature.ai_mode = survival_spawn.CreatureAiMode.orbit_player;
        } else if (dist_to_player > 800.0) {
            creature.target = .{
                .x = asF32F64(player_pos.x),
                .y = asF32F64(player_pos.y),
            };
        } else {
            creature.target = orbitTargetF32(player_pos, orbit_phase, dist_to_player, 0.85);
        }
    } else if (ai_mode_after_primary == survival_spawn.CreatureAiMode.hold_timer) {
        if ((creature.flags & survival_spawn.CreatureFlags.ai7_link_timer) != 0 and creature.link_index > 0) {
            creature.target = .{
                .x = asF32F64(creature.pos.x),
                .y = asF32F64(creature.pos.y),
            };
        } else if ((creature.flags & survival_spawn.CreatureFlags.ai7_link_timer) == 0 and creature.orbit_radius > 0.0) {
            creature.target = .{
                .x = asF32F64(creature.pos.x),
                .y = asF32F64(creature.pos.y),
            };
            creature.orbit_radius = asF32F64(creature.orbit_radius - dt);
        } else {
            creature.ai_mode = survival_spawn.CreatureAiMode.orbit_player;
        }
    } else if (ai_mode_after_primary == survival_spawn.CreatureAiMode.orbit_link) {
        if (resolveLiveLink(creatures, creature.link_index)) |link| {
            const angle = asF32F64(creature.orbit_angle + creature.heading);
            const orbit_radius = asF32F64(creature.orbit_radius);
            creature.target = .{
                .x = asF32F64(survival_math.cos(angle) * orbit_radius + link.pos.x),
                .y = asF32F64(survival_math.sin(angle) * orbit_radius + link.pos.y),
            };
        } else {
            creature.ai_mode = survival_spawn.CreatureAiMode.orbit_player;
        }
    }

    const dist_to_target = distanceF32(creature.pos, creature.target);
    if (dist_to_target < 40.0 or dist_to_target > 400.0) {
        creature.force_target = 1;
    }
    if (creature.force_target != 0 or creature.ai_mode == survival_spawn.CreatureAiMode.chase_player) {
        creature.target = .{
            .x = asF32F64(player_pos.x),
            .y = asF32F64(player_pos.y),
        };
    }

    const dx = asF32F64(creature.target.x - creature.pos.x);
    const dy = asF32F64(creature.target.y - creature.pos.y);
    creature.target_heading = headingFromDeltaF32(dx, dy);
    creature.move_scale = asF32F64(move_scale);
}

fn resolveLiveLink(
    creatures: []const CreatureState,
    link_index: i32,
) ?*const CreatureState {
    if (link_index < 0 or link_index >= creatures.len) return null;
    const idx: usize = @intCast(link_index);
    if (!(creatures[idx].hp > 0.0)) return null;
    return &creatures[idx];
}

fn linkTargetF32(
    link_pos: survival_state.Vec2,
    offset: survival_state.Vec2,
) survival_state.Vec2 {
    return .{
        .x = asF32F64(link_pos.x + offset.x),
        .y = asF32F64(link_pos.y + offset.y),
    };
}

fn distanceF32(a: survival_state.Vec2, b: survival_state.Vec2) f64 {
    const dx = asF32F64(b.x - a.x);
    const dy = asF32F64(b.y - a.y);
    const dist_sq = dx * dx + dy * dy;
    return asF32F64(std.math.sqrt(dist_sq));
}

fn orbitTargetF32(
    player_pos: survival_state.Vec2,
    orbit_phase: f64,
    dist: f64,
    scale: f64,
) survival_state.Vec2 {
    const orbit_dist = asF32F64(asF32F64(dist) * asF32F64(scale));
    const phase = asF32F64(orbit_phase);
    const px = asF32F64(player_pos.x);
    const py = asF32F64(player_pos.y);
    const orbit_x = asF32F64(survival_math.cos(phase));
    const orbit_y = asF32F64(survival_math.sin(phase));
    return .{
        .x = asF32F64(asF32F64(orbit_x * orbit_dist) + px),
        .y = asF32F64(asF32F64(orbit_y * orbit_dist) + py),
    };
}

fn headingFromDeltaF32(dx: f64, dy: f64) f64 {
    var heading = asF32F64(survival_math.atan2(dy, dx) + native_half_pi);
    if (dx < 0.0 and
        @abs(heading - native_left_axis_heading_pos) <= native_left_axis_heading_eps and
        @abs(dy) <= native_left_axis_dy_eps)
    {
        heading = asF32F64(heading - native_tau);
    }
    return heading;
}

fn angleApproach(
    current: f64,
    target: f64,
    rate: f64,
    dt: f64,
) f64 {
    var angle = asF32F64(current);
    const target_f = asF32F64(target);
    const rate_f = asF32F64(rate);
    const dt_f = asF32F64(dt);
    const tau = native_tau;

    while (angle < 0.0) {
        angle = asF32F64(angle + tau);
    }
    while (tau < angle) {
        angle = asF32F64(angle - tau);
    }

    const direct = asF32F64(@abs(asF32F64(target_f - angle)));
    const hi = if (angle < target_f) target_f else angle;
    const lo = if (target_f < angle) target_f else angle;
    const wrapped = asF32F64(@abs(asF32F64(asF32F64(tau - hi) + lo)));

    var step_scale = wrapped;
    if (direct < wrapped) {
        step_scale = direct;
    }
    if (step_scale > 1.0) {
        step_scale = 1.0;
    }
    step_scale = asF32F64(step_scale);

    const step_delta = asF32F64(asF32F64(dt_f * step_scale) * rate_f);
    if (direct <= wrapped) {
        if (angle < target_f) return asF32F64(angle + step_delta);
    } else {
        if (target_f < angle) return asF32F64(angle + step_delta);
    }
    return asF32F64(angle - step_delta);
}

fn movementDeltaFromHeadingF32(
    heading: f64,
    dt: f64,
    move_scale: f64,
    move_speed: f64,
) survival_state.Vec2 {
    const radians = asF32F64(heading) - native_half_pi;

    var vx = survival_math.cos(radians);
    vx *= dt;
    vx *= move_scale;
    vx *= move_speed;
    vx *= creature_speed_scale;

    var vy = survival_math.sin(radians);
    vy *= dt;
    vy *= move_scale;
    vy *= move_speed;
    vy *= creature_speed_scale;

    return .{
        .x = asF32F64(vx),
        .y = asF32F64(vy),
    };
}

fn advancePosByDeltaF32(
    pos: survival_state.Vec2,
    delta: survival_state.Vec2,
) survival_state.Vec2 {
    return .{
        .x = asF32F64(pos.x + delta.x),
        .y = asF32F64(pos.y + delta.y),
    };
}

const SpawnStats = struct {
    type_id: i32,
    health: f64,
    move_speed: f64,
    reward_value: f64,
    size: f64,
    contact_damage: f64,
};

fn randf(rng: *survival_spawn.Crand, mod: u32, scale: f64, base: f64) f64 {
    return asF32F64(@as(f64, @floatFromInt(rng.rand() % mod)) * scale + base);
}

fn hitRadiusFor(creature: CreatureState) f64 {
    return @max(0.0, creature.size * 0.14285715 + 3.0);
}

fn projectileHitDamage(origin: survival_state.Vec2, hit: survival_state.Vec2, damage_scale: f64) f64 {
    var dist = survival_state.Vec2.sub(hit, origin).length();
    if (dist < 50.0) dist = 50.0;
    const scaled = asF32F64((100.0 / dist) * damage_scale * 30.0 + 10.0);
    return asF32F64(scaled * 0.95);
}

fn perkActive(player: *const survival_state.PlayerState, perk_id: i32) bool {
    if (perk_id < 0 or perk_id >= player.perk_counts.len) return false;
    return player.perk_counts[@intCast(perk_id)] > 0;
}

fn anyPlayerHasPerk(players: []const survival_state.PlayerState, perk_id: i32) bool {
    for (players) |*player| {
        if (perkActive(player, perk_id)) return true;
    }
    return false;
}

pub fn consumeProjectileHitPresentationPreRng(
    state: *survival_state.GameplayState,
    player: *const survival_state.PlayerState,
    projectile_type_id: i32,
) void {
    const freeze_active = state.bonuses.freeze > 0.0;

    if (projectile_type_id == survival_state.ProjectileTypeId.blade_gun) {
        for (0..8) |_| {
            consumeSpawnBloodSplatterRng(state);
        }
    }

    if (perkActive(player, perk_id_bloody_mess_quick_learner)) {
        for (0..8) |_| {
            consumeSpawnBloodSplatterRng(state);
        }
        consumeSpawnBloodSplatterRng(state);

        var lo: i32 = -30;
        var hi: i32 = 30;
        while (lo > -60) {
            const span: u32 = @intCast(hi - lo);
            for (0..2) |_| {
                _ = state.rng.rand() % span;
                _ = state.rng.rand() % span;
                consumeAddRandomRng(state);
            }
            lo -= 10;
            hi += 10;
        }
    } else if (!freeze_active) {
        for (0..2) |_| {
            consumeSpawnBloodSplatterRng(state);
            if ((state.rng.rand() & 7) == 2) {
                consumeSpawnBloodSplatterRng(state);
            }
        }
    }

}

pub fn consumeProjectileHitPresentationPostRng(
    state: *survival_state.GameplayState,
    projectile_type_id: i32,
) void {
    const freeze_active = state.bonuses.freeze > 0.0;

    // Native consumes one draw before post-hit decal branching.
    _ = state.rng.rand();

    if (projectile_type_id == survival_state.ProjectileTypeId.gauss_gun or
        projectile_type_id == survival_state.ProjectileTypeId.fire_bullets)
    {
        consumeLargeHitStreakRng(state, freeze_active);
        return;
    }
    if (freeze_active) return;

    for (0..3) |_| {
        _ = state.rng.rand();
        consumeAddRandomRng(state);
        consumeAddRandomRng(state);
        consumeAddRandomRng(state);
        consumeAddRandomRng(state);
    }
}

fn consumeLargeHitStreakRng(
    state: *survival_state.GameplayState,
    freeze_active: bool,
) void {
    for (0..6) |_| {
        var dist = @as(i32, @intCast(state.rng.rand() % 100));
        if (dist > 40) {
            dist = @as(i32, @intCast(state.rng.rand() % 0x5A + 10));
        }
        if (dist > 70) {
            dist = @as(i32, @intCast(state.rng.rand() % 0x50 + 0x14));
        }
        _ = state.rng.rand();
        if (freeze_active) {
            _ = state.rng.rand();
            // freeze shard spawn RNG
            _ = state.rng.rand();
            _ = state.rng.rand();
            _ = state.rng.rand();
            _ = state.rng.rand();
            _ = state.rng.rand();
            _ = state.rng.rand();
        }
        consumeAddRandomRng(state);
    }
}

pub fn consumeHitSfxRng(
    state: *survival_state.GameplayState,
    game_tune_started: *bool,
    projectile_type_id: i32,
) void {
    // Mirrors plan_hit_sfx_keys: first eligible hit starts tune and consumes one RNG draw.
    if (!state.demo_mode_active and state.game_mode != game_mode_rush and !game_tune_started.*) {
        game_tune_started.* = true;
        _ = state.rng.rand();
        return;
    }
    if (projectile_type_id == survival_state.ProjectileTypeId.ion_rifle or
        projectile_type_id == survival_state.ProjectileTypeId.ion_minigun or
        projectile_type_id == survival_state.ProjectileTypeId.ion_cannon)
    {
        return;
    }
    _ = state.rng.rand();
}

fn consumeSpawnBloodSplatterRng(state: *survival_state.GameplayState) void {
    for (0..2) |_| {
        _ = state.rng.rand();
        _ = state.rng.rand();
        _ = state.rng.rand();
        _ = state.rng.rand();
        _ = state.rng.rand();
    }
}

fn consumeAddRandomRng(state: *survival_state.GameplayState) void {
    _ = state.rng.rand();
    _ = state.rng.rand();
    _ = state.rng.rand();
    _ = state.rng.rand();
}

fn spreadPlagueInfection(
    creatures: []CreatureState,
    origin: *CreatureState,
) void {
    for (creatures) |*target| {
        if (!target.active) continue;
        const dist_sq = survival_state.Vec2.sub(target.pos, origin.pos).lengthSq();
        if (dist_sq >= 45.0 * 45.0) continue;
        if (target.plague_infected and origin.hp < 150.0) {
            origin.plague_infected = true;
        }
        if (origin.plague_infected and target.hp < 150.0) {
            target.plague_infected = true;
        }
        return;
    }
}

fn tickAi7LinkTimer(
    creature: *CreatureState,
    dt_ms: i32,
    rng: *survival_spawn.Crand,
) void {
    if ((creature.flags & survival_spawn.CreatureFlags.ai7_link_timer) == 0) return;

    if (creature.link_index < 0) {
        creature.link_index += dt_ms;
        if (creature.link_index >= 0) {
            creature.ai_mode = survival_spawn.CreatureAiMode.hold_timer;
            creature.link_index = @as(i32, @intCast((rng.rand() & 0x1ff) + 500));
        }
        return;
    }

    creature.link_index -= dt_ms;
    if (creature.link_index < 1) {
        creature.link_index = -700 - @as(i32, @intCast(rng.rand() & 0x3ff));
    }
}

fn ownerIdToPlayerIndex(owner_id: i32) ?i32 {
    if (owner_id == owner_id_player_0) return 0;
    if (owner_id < 0) return -1 - owner_id;
    return null;
}

fn awardExperienceFromReward(
    state: *survival_state.GameplayState,
    player: *survival_state.PlayerState,
    reward_value: f64,
) i32 {
    var gained = awardExperienceOnceFromReward(player, reward_value);
    if (gained <= 0) return 0;
    if (state.bonuses.double_experience > 0.0) {
        gained += awardExperienceOnceFromReward(player, reward_value);
    }
    return gained;
}

fn consumeDeathSideEffectsRng(
    state: *survival_state.GameplayState,
    players: []survival_state.PlayerState,
    bonus_pool: *survival_bonuses.BonusPool,
    death_pos: survival_state.Vec2,
    world_size: f64,
    plan_death_sfx: bool,
) void {
    const spawned_bonus = bonus_pool.trySpawnOnKill(
        .{
            .x = asF32F64(death_pos.x),
            .y = asF32F64(death_pos.y),
        },
        state,
        players,
        world_size,
    );
    if (spawned_bonus) |_| {
        // effects.spawn_burst(count=16) -> 4 random draws per burst element.
        for (0..16) |_| {
            _ = state.rng.rand();
            _ = state.rng.rand();
            _ = state.rng.rand();
            _ = state.rng.rand();
        }
    }
    if (state.bonuses.freeze > 0.0) {
        for (0..8) |_| {
            _ = state.rng.rand() % 0x264;
            for (0..6) |_| {
                _ = state.rng.rand();
            }
        }
        _ = state.rng.rand() % 0x264;
        for (0..4) |_| {
            _ = state.rng.rand();
            _ = state.rng.rand();
        }
        for (0..4) |_| {
            _ = state.rng.rand() % 0x264;
            for (0..6) |_| {
                _ = state.rng.rand();
            }
        }
        consumeAddRandomRng(state);
    }
    if (plan_death_sfx) {
        // plan_death_sfx_keys chooses one death sample per death.
        _ = state.rng.rand();
    }
}

fn tickDead(
    creature: *CreatureState,
    dt: f64,
    kill_count: *i32,
    state: *survival_state.GameplayState,
) void {
    if (!(dt > 0.0)) return;
    const hitbox = asF32F64(creature.lifecycle_stage);
    if (hitbox <= 0.0) {
        creature.lifecycle_stage = asF32F64(hitbox - asF32F64(dt * 20.0));
        return;
    }
    const long_strip =
        (creature.flags & survival_spawn.CreatureFlags.anim_ping_pong) == 0 or
        (creature.flags & survival_spawn.CreatureFlags.anim_long_strip) != 0;
    const next_lifecycle_stage = asF32F64(hitbox - asF32F64(dt * 28.0));
    creature.lifecycle_stage = asF32F64(next_lifecycle_stage);
    if (next_lifecycle_stage > 0.0) {
        if (long_strip) {
            const slide = asF32F64(next_lifecycle_stage * asF32F64(dt) * asF32F64(9.0));
            const direction = headingDirectionF32(creature.heading);
            creature.vel = .{
                .x = asF32F64(direction.x * slide),
                .y = asF32F64(direction.y * slide),
            };
            creature.pos = .{
                .x = asF32F64(creature.pos.x - creature.vel.x),
                .y = asF32F64(creature.pos.y - creature.vel.y),
            };
        } else {
            creature.vel = .{};
        }
        return;
    }
    kill_count.* += 1;
    if (state.fx_toggle == 0 and
        (creature.flags & survival_spawn.CreatureFlags.anim_ping_pong) != 0)
    {
        const burst_counts = [_]usize{ 8, 6, 5 };
        for (burst_counts) |count| {
            for (0..count) |_| {
                _ = state.rng.rand() % 0x264;
                consumeSpawnBloodSplatterRng(state);
            }
        }
    }
}

fn selfDamageTickAmount(flags: u32, dt: f64) f64 {
    if (!(dt > 0.0)) return 0.0;
    if ((flags & survival_spawn.CreatureFlags.self_damage_tick_strong) != 0) {
        return asF32F64(dt * 180.0);
    }
    if ((flags & survival_spawn.CreatureFlags.self_damage_tick) != 0) {
        return asF32F64(dt * 60.0);
    }
    return 0.0;
}

fn applySelfDamageTickToDead(
    creature: *CreatureState,
    dt: f64,
) void {
    if (!(selfDamageTickAmount(creature.flags, dt) > 0.0)) return;
    if (dt > 0.0) {
        creature.lifecycle_stage = asF32F64(creature.lifecycle_stage - dt * 15.0);
    }
}

fn headingDirectionF32(heading: f64) survival_state.Vec2 {
    const radians = asF32F64(heading) - native_half_pi;
    return .{
        .x = asF32F64(survival_math.cos(radians)),
        .y = asF32F64(survival_math.sin(radians)),
    };
}

fn awardExperienceOnceFromReward(
    player: *survival_state.PlayerState,
    reward_value: f64,
) i32 {
    const reward_f32 = asF32F64(reward_value);
    if (!(reward_f32 > 0.0)) return 0;

    const before = player.experience;
    const before_f32: f64 = @floatFromInt(before);
    const total_f32 = asF32F64(asF32F64(before_f32) + reward_f32);
    const after: i32 = @intFromFloat(total_f32);
    player.experience = after;
    return after - before;
}

fn dot(a: survival_state.Vec2, b: survival_state.Vec2) f64 {
    return a.x * b.x + a.y * b.y;
}

fn asF32F64(value: f64) f64 {
    const rounded: f32 = @floatCast(value);
    return @floatCast(rounded);
}

const perk_id_bloody_mess_quick_learner: i32 = 1;
const perk_id_poison_bullets: i32 = 25;
const perk_id_plaguebearer: i32 = survival_perks.PerkId.plaguebearer;
const perk_id_uranium_filled_bullets: i32 = survival_perks.PerkId.uranium_filled_bullets;
const perk_id_doctor: i32 = survival_perks.PerkId.doctor;
const perk_id_barrel_greaser: i32 = survival_perks.PerkId.barrel_greaser;
const perk_id_ion_gun_master: i32 = survival_perks.PerkId.ion_gun_master;
const perk_id_final_revenge: i32 = survival_perks.PerkId.final_revenge;
const perk_id_unstoppable: i32 = survival_perks.PerkId.unstoppable;
const perk_id_tough_reloader: i32 = survival_perks.PerkId.tough_reloader;
const perk_id_thick_skinned: i32 = survival_perks.PerkId.thick_skinned;
const perk_id_ninja: i32 = survival_perks.PerkId.ninja;
const perk_id_dodger: i32 = survival_perks.PerkId.dodger;
const perk_id_highlander: i32 = survival_perks.PerkId.highlander;
const perk_id_death_clock: i32 = survival_perks.PerkId.death_clock;
const game_mode_rush: i32 = 2;
const thick_skinned_damage_scale_f32: f64 = 0.6660000085830688;

fn creatureTypeHasContactSfx(type_id: i32) bool {
    return type_id == @intFromEnum(survival_spawn.CreatureTypeId.zombie) or
        type_id == @intFromEnum(survival_spawn.CreatureTypeId.lizard) or
        type_id == @intFromEnum(survival_spawn.CreatureTypeId.alien) or
        type_id == @intFromEnum(survival_spawn.CreatureTypeId.spider_sp1) or
        type_id == @intFromEnum(survival_spawn.CreatureTypeId.spider_sp2);
}

fn consumeContactSfxRng(state: *survival_state.GameplayState, creature_type_id: i32) void {
    if (!creatureTypeHasContactSfx(creature_type_id)) return;
    _ = state.rng.rand() & 1;
}

pub fn applyPlayerContactDamage(
    state: *survival_state.GameplayState,
    player: *survival_state.PlayerState,
    damage: f64,
    dt: f64,
) void {
    if (!(damage > 0.0)) return;
    if (perkActive(player, perk_id_death_clock)) return;

    var damage_scaled = damage;
    if (perkActive(player, perk_id_tough_reloader) and player.reload_active) {
        damage_scaled = asF32F64(damage_scaled * 0.5);
    }
    const spread_heat_damage = damage_scaled;

    state.survival_reward_damage_seen = true;
    if (player.shield_timer > 0.0) return;

    var dodged = false;
    if (perkActive(player, perk_id_ninja)) {
        dodged = (state.rng.rand() % 3) == 0;
    } else if (perkActive(player, perk_id_dodger)) {
        dodged = (state.rng.rand() % 5) == 0;
    }

    if (perkActive(player, perk_id_thick_skinned)) {
        damage_scaled = asF32F64(damage_scaled * thick_skinned_damage_scale_f32);
    }

    if (!dodged) {
        if (perkActive(player, perk_id_highlander)) {
            if ((state.rng.rand() % 10) == 0) {
                player.health = 0.0;
            }
        } else {
            player.health = asF32F64(player.health - damage_scaled);
            if (player.health < 0.0 and dt > 0.0) {
                player.death_timer = asF32F64(player.death_timer - dt * 28.0);
            }
        }
    }

    if (player.health >= 0.0) {
        _ = state.rng.rand() % 3;
    } else if (!perkActive(player, perk_id_final_revenge)) {
        _ = state.rng.rand() & 1;
    }

    if (!dodged) {
        if (!perkActive(player, perk_id_unstoppable)) {
            const jitter_i32: i32 = @as(i32, @intCast(state.rng.rand() % 100)) - 50;
            player.heading = asF32F64(player.heading + @as(f64, @floatFromInt(jitter_i32)) * 0.04);
            player.spread_heat = asF32F64(@min(
                0.48,
                asF32F64(player.spread_heat + spread_heat_damage * 0.01),
            ));
        }
        if (player.health <= 20.0 and (state.rng.rand() & 7) == 3) {
            player.low_health_timer = 0.0;
        }
    }
}

fn expectFloatClose(expected: f64, actual: f64) !void {
    try std.testing.expectApproxEqAbs(expected, actual, 1e-6);
}

test "spawn init and shot resolution award xp on kill" {
    var pool = CreaturePool{};
    var state = survival_state.GameplayState.init(1234);
    var bonuses = survival_bonuses.BonusPool{};
    var players = [_]survival_state.PlayerState{
        .{
            .index = 0,
            .pos = .{ .x = 100.0, .y = 100.0 },
        },
    };

    _ = pool.spawnInit(.{
        .origin_template_id = -1,
        .pos = .{ .x = 200.0, .y = 100.0 },
        .heading = 0.0,
        .phase_seed = 0.0,
        .type_id = .alien,
        .size = 44.0,
        .move_speed = 1.0,
        .health = 5.0,
        .max_health = 5.0,
        .reward_value = 80.0,
        .contact_damage = 4.0,
    });

    const before_xp = players[0].experience;
    const result = pool.resolvePlayerShots(
        &state,
        players[0..],
        &bonuses,
        0,
        .{ .x = 300.0, .y = 100.0 },
        1,
        survival_state.WeaponId.pistol,
        1024.0,
    );
    try std.testing.expectEqual(@as(i32, 1), result.hits);
    try std.testing.expectEqual(@as(i32, 1), result.deaths);
    try std.testing.expect(result.xp_awarded > 0);
    try std.testing.expect(players[0].experience > before_xp);
    try std.testing.expectEqual(@as(i32, 1), state.shots_hit[0]);
}

test "template spawn supports survival early-stage templates" {
    var pool = CreaturePool{};
    var rng = survival_spawn.Crand.init(7);

    try pool.spawnTemplateCall(
        .{
            .template_id = survival_spawn.SpawnId.formation_ring_alien_8_12,
            .pos = .{ .x = 512.0, .y = 512.0 },
            .heading = std.math.pi,
        },
        &rng,
    );
    try std.testing.expectEqual(@as(usize, 9), pool.activeCount());
}

test "template spawn rejects unsupported template ids" {
    var pool = CreaturePool{};
    var rng = survival_spawn.Crand.init(1);

    try std.testing.expectError(
        error.UnsupportedSpawnTemplate,
        pool.spawnTemplateCall(
            .{
                .template_id = survival_spawn.SpawnId.spider_sp1_const_shock_boss_3a,
                .pos = .{ .x = 0.0, .y = 0.0 },
                .heading = 0.0,
            },
            &rng,
        ),
    );
}

test "creature update applies contact damage and movement" {
    var pool = CreaturePool{};
    var state = survival_state.GameplayState.init(1);
    var bonuses = survival_bonuses.BonusPool{};
    var players = [_]survival_state.PlayerState{
        .{
            .index = 0,
            .pos = .{ .x = 100.0, .y = 100.0 },
            .health = 100.0,
        },
    };
    _ = pool.spawnInit(.{
        .origin_template_id = -1,
        .pos = .{ .x = 120.0, .y = 100.0 },
        .heading = 0.0,
        .phase_seed = 0.0,
        .type_id = .alien,
        .size = 44.0,
        .move_speed = 1.0,
        .health = 40.0,
        .max_health = 40.0,
        .reward_value = 60.0,
        .contact_damage = 7.0,
    });

    pool.update(&state, players[0..], 1.0 / 60.0, 1024.0, &bonuses);
    try std.testing.expect(players[0].health < 100.0);
    try std.testing.expect(state.survival_reward_damage_seen);
    try expectFloatClose(@as(f64, 1.0), pool.entries[0].attack_cooldown);
}

test "ai7 link timer consumes rng when timer crosses zero" {
    var pool = CreaturePool{};
    var state = survival_state.GameplayState.init(99);
    var bonuses = survival_bonuses.BonusPool{};
    var players = [_]survival_state.PlayerState{
        .{
            .index = 0,
            .pos = .{ .x = 512.0, .y = 512.0 },
            .health = 100.0,
        },
    };

    _ = pool.spawnInit(.{
        .origin_template_id = -1,
        .pos = .{ .x = 100.0, .y = 100.0 },
        .heading = 0.0,
        .phase_seed = 0.0,
        .type_id = .spider_sp1,
        .ai_mode = survival_spawn.CreatureAiMode.orbit_player,
        .flags = survival_spawn.CreatureFlags.ai7_link_timer,
        .size = 44.0,
        .move_speed = 0.0,
        .health = 25.0,
        .max_health = 25.0,
        .reward_value = 50.0,
        .contact_damage = 3.0,
    });

    var expected_rng = state.rng;
    _ = expected_rng.rand();

    pool.update(&state, players[0..], 0.017, 1024.0, &bonuses);

    try std.testing.expectEqual(expected_rng.state, state.rng.state);
    try std.testing.expectEqual(survival_spawn.CreatureAiMode.hold_timer, pool.entries[0].ai_mode);
    try std.testing.expect(pool.entries[0].link_index >= 500);
    try std.testing.expect(pool.entries[0].link_index <= 1011);
}

test "tough reloader halves damage while reloading" {
    var state = survival_state.GameplayState.init(1);
    var player = survival_state.PlayerState{
        .index = 0,
        .pos = .{},
        .health = 100.0,
        .reload_active = true,
    };
    player.perk_counts[@intCast(perk_id_tough_reloader)] = 1;

    applyPlayerContactDamage(
        &state,
        &player,
        10.0,
        0.1,
    );

    try expectFloatClose(95.0, player.health);
}

test "tough reloader spread heat uses post-reload damage before thick skinned" {
    var state = survival_state.GameplayState.init(1);
    var player = survival_state.PlayerState{
        .index = 0,
        .pos = .{},
        .health = 100.0,
        .reload_active = true,
        .spread_heat = 0.1,
    };
    player.perk_counts[@intCast(perk_id_tough_reloader)] = 1;
    player.perk_counts[@intCast(perk_id_thick_skinned)] = 1;

    applyPlayerContactDamage(
        &state,
        &player,
        10.0,
        0.1,
    );

    try expectFloatClose(0.15, player.spread_heat);
}

test "doctor increases projectile damage by 20 percent" {
    var pool = CreaturePool{};
    var state = survival_state.GameplayState.init(1);
    var bonuses = survival_bonuses.BonusPool{};
    var players = [_]survival_state.PlayerState{
        .{ .index = 0, .pos = .{} },
    };
    players[0].perk_counts[@intCast(perk_id_doctor)] = 1;

    _ = pool.spawnInit(.{
        .origin_template_id = -1,
        .pos = .{ .x = 10.0, .y = 0.0 },
        .heading = 0.0,
        .phase_seed = 0.0,
        .type_id = .alien,
        .size = 50.0,
        .move_speed = 0.0,
        .health = 100.0,
        .max_health = 100.0,
        .reward_value = 50.0,
        .contact_damage = 4.0,
    });

    _ = pool.applyProjectileDamage(
        &state,
        players[0..],
        &bonuses,
        0,
        10.0,
        .{},
        -100,
        0.016,
        10_000.0,
    );
    try expectFloatClose(88.0, pool.entries[0].hp);
}

test "barrel greaser increases projectile damage by 40 percent" {
    var pool = CreaturePool{};
    var state = survival_state.GameplayState.init(1);
    var bonuses = survival_bonuses.BonusPool{};
    var players = [_]survival_state.PlayerState{
        .{ .index = 0, .pos = .{} },
    };
    players[0].perk_counts[@intCast(perk_id_barrel_greaser)] = 1;

    _ = pool.spawnInit(.{
        .origin_template_id = -1,
        .pos = .{ .x = 10.0, .y = 0.0 },
        .heading = 0.0,
        .phase_seed = 0.0,
        .type_id = .alien,
        .size = 50.0,
        .move_speed = 0.0,
        .health = 100.0,
        .max_health = 100.0,
        .reward_value = 50.0,
        .contact_damage = 4.0,
    });

    _ = pool.applyProjectileDamage(
        &state,
        players[0..],
        &bonuses,
        0,
        10.0,
        .{},
        -100,
        0.016,
        10_000.0,
    );
    try expectFloatClose(86.0, pool.entries[0].hp);
}

test "ion gun master increases ion damage by 20 percent" {
    var pool = CreaturePool{};
    var state = survival_state.GameplayState.init(1);
    var bonuses = survival_bonuses.BonusPool{};
    var players = [_]survival_state.PlayerState{
        .{ .index = 0, .pos = .{} },
    };
    players[0].perk_counts[@intCast(perk_id_ion_gun_master)] = 1;

    _ = pool.spawnInit(.{
        .origin_template_id = -1,
        .pos = .{ .x = 10.0, .y = 0.0 },
        .heading = 0.0,
        .phase_seed = 0.0,
        .type_id = .alien,
        .size = 50.0,
        .move_speed = 0.0,
        .health = 100.0,
        .max_health = 100.0,
        .reward_value = 50.0,
        .contact_damage = 4.0,
    });

    _ = pool.applyIonDamage(
        &state,
        players[0..],
        &bonuses,
        0,
        10.0,
        .{},
        -100,
        0.016,
        10_000.0,
    );
    try expectFloatClose(88.0, pool.entries[0].hp);
}

test "freeze stops creature movement" {
    var pool = CreaturePool{};
    var state = survival_state.GameplayState.init(1);
    var bonuses = survival_bonuses.BonusPool{};
    var players = [_]survival_state.PlayerState{
        .{
            .index = 0,
            .pos = .{ .x = 512.0, .y = 512.0 },
            .health = 100.0,
        },
    };

    _ = pool.spawnInit(.{
        .origin_template_id = -1,
        .pos = .{ .x = 100.0, .y = 200.0 },
        .heading = 0.0,
        .phase_seed = 0.0,
        .type_id = .alien,
        .size = 44.0,
        .move_speed = 1.0,
        .health = 10.0,
        .max_health = 10.0,
        .reward_value = 50.0,
        .contact_damage = 4.0,
    });

    pool.update(&state, players[0..], 0.2, 1024.0, &bonuses);
    const moved_x = pool.entries[0].pos.x;
    const moved_y = pool.entries[0].pos.y;
    try std.testing.expect(!(moved_x == 100.0 and moved_y == 200.0));

    state.bonuses.freeze = 5.0;
    pool.update(&state, players[0..], 0.2, 1024.0, &bonuses);
    try expectFloatClose(moved_x, pool.entries[0].pos.x);
    try expectFloatClose(moved_y, pool.entries[0].pos.y);
}
