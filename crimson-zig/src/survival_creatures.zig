const std = @import("std");

const survival_spawn = @import("survival_spawn.zig");
const survival_state = @import("survival_state.zig");

pub const max_creatures: usize = 0x180;

const creature_hitbox_alive: f64 = 16.0;
const creature_speed_scale: f64 = 30.0;
const contact_damage_period: f64 = 0.5;
const owner_id_player_0: i32 = -100;

pub const CreatureRuntimeError = error{
    UnsupportedSpawnTemplate,
};

pub const CreatureState = struct {
    active: bool = false,
    type_id: i32 = 0,
    pos: survival_state.Vec2 = .{},
    heading: f64 = 0.0,
    ai_mode: i32 = survival_spawn.CreatureAiMode.orbit_player,
    // Native keeps this stale across slot reuse for some spawn paths.
    link_index: i32 = -1,
    hp: f64 = 0.0,
    max_hp: f64 = 0.0,
    move_speed: f64 = 0.0,
    reward_value: f64 = 0.0,
    size: f64 = 0.0,
    contact_damage: f64 = 0.0,
    hitbox_size: f64 = creature_hitbox_alive,
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
            self.spawnInit(init);
        }
    }

    pub fn spawnInit(self: *CreaturePool, init: survival_spawn.CreatureInit) void {
        var slot: usize = self.entries.len - 1;
        for (self.entries, 0..) |creature, idx| {
            if (!creature.active) {
                slot = idx;
                break;
            }
        }
        const stale_link_index = self.entries[slot].link_index;

        self.entries[slot] = .{
            .active = true,
            .type_id = @intFromEnum(init.type_id),
            .pos = .{
                .x = asF32F64(init.pos.x),
                .y = asF32F64(init.pos.y),
            },
            .heading = asF32F64(init.heading),
            .ai_mode = init.ai_mode,
            .link_index = stale_link_index,
            .hp = asF32F64(init.health),
            .max_hp = asF32F64(init.max_health),
            .move_speed = asF32F64(init.move_speed),
            .reward_value = asF32F64(init.reward_value),
            .size = asF32F64(init.size),
            .contact_damage = asF32F64(init.contact_damage),
            .hitbox_size = creature_hitbox_alive,
            .attack_cooldown = 0.0,
            .last_hit_owner_id = owner_id_player_0,
            .flags = init.flags,
        };
    }

    pub fn spawnTemplateCall(
        self: *CreaturePool,
        call: survival_spawn.SpawnTemplateCall,
        rng: *survival_spawn.Crand,
    ) CreatureRuntimeError!void {
        switch (call.template_id) {
            survival_spawn.SpawnId.formation_ring_alien_8_12 => {
                // Parent.
                self.spawnFromStats(
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

                const angle_step = std.math.pi / 4.0;
                for (0..8) |idx| {
                    const angle = @as(f64, @floatFromInt(idx)) * angle_step;
                    const offset = survival_state.Vec2.fromAngle(angle).mul(100.0);
                    self.spawnFromStats(
                        rng,
                        .{
                            .x = asF32F64(call.pos.x + offset.x),
                            .y = asF32F64(call.pos.y + offset.y),
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
                    );
                }
            },
            survival_spawn.SpawnId.alien_const_red_fast_2b => {
                self.spawnFromStats(
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
            },
            survival_spawn.SpawnId.alien_const_red_boss_2c => {
                self.spawnFromStats(
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
            },
            survival_spawn.SpawnId.spider_sp2_random_35 => {
                const size = randf(rng, 10, 1.0, 30.0);
                self.spawnFromStats(
                    rng,
                    .{ .x = call.pos.x, .y = call.pos.y },
                    call.heading,
                    .{
                        .type_id = @intFromEnum(survival_spawn.CreatureTypeId.spider_sp2),
                        .health = asF32F64(size * (8.0 / 7.0) + 20.0),
                        .move_speed = randf(rng, 18, 0.1, 1.1),
                        .reward_value = asF32F64(size + size + 50.0),
                        .size = size,
                        .contact_damage = randf(rng, 10, 1.0, 4.0),
                    },
                );
            },
            survival_spawn.SpawnId.spider_sp1_ai7_timer_38 => {
                self.spawnFromStatsWithFlags(
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
                );
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
    ) void {
        if (players.len == 0) return;
        if (!(dt > 0.0)) return;

        const dt_ms = @max(@as(i32, 0), @as(i32, @intFromFloat(@round(dt * 1000.0))));
        const min_bound = -64.0;
        const max_bound = world_size + 64.0;
        var player = &players[0];

        for (&self.entries) |*creature| {
            if (!creature.active) continue;
            if (!(creature.hp > 0.0)) {
                creature.active = false;
                continue;
            }

            creature.attack_cooldown = @max(0.0, asF32F64(creature.attack_cooldown - dt));
            tickAi7LinkTimer(creature, dt_ms, &state.rng);

            const to_player = survival_state.Vec2.sub(player.pos, creature.pos);
            const distance_sq = to_player.lengthSq();
            if (distance_sq > 1e-9) {
                const distance = std.math.sqrt(distance_sq);
                const inv_distance = 1.0 / distance;
                const dir = to_player.mul(inv_distance);
                const speed_step = asF32F64(creature.move_speed * creature_speed_scale * dt);
                const delta = dir.mul(speed_step);
                const next_pos = survival_state.Vec2.add(creature.pos, delta).clampRect(
                    min_bound,
                    min_bound,
                    max_bound,
                    max_bound,
                );
                creature.pos = .{
                    .x = asF32F64(next_pos.x),
                    .y = asF32F64(next_pos.y),
                };
                creature.heading = asF32F64(std.math.atan2(dir.y, dir.x) + std.math.pi / 2.0);
            }

            const contact_sq = survival_state.Vec2.sub(player.pos, creature.pos).lengthSq();
            if (contact_sq < 30.0 * 30.0 and
                creature.attack_cooldown <= 0.0 and
                player.health > 0.0 and
                state.bonuses.energizer <= 0.0)
            {
                player.health = asF32F64(player.health - creature.contact_damage);
                state.survival_reward_damage_seen = true;
                creature.attack_cooldown = contact_damage_period;
            }
        }
    }

    pub fn resolvePlayerShots(
        self: *CreaturePool,
        state: *survival_state.GameplayState,
        players: []survival_state.PlayerState,
        player_index: usize,
        aim_target: survival_state.Vec2,
        shot_count: i32,
        weapon_id: i32,
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
        const base_damage = weaponDamagePerShot(weapon_id);
        const owner_id: i32 = -1 - player.index;

        var shot_idx: i32 = 0;
        while (shot_idx < shot_count) : (shot_idx += 1) {
            const hit_idx = self.findRayHitCreature(player.pos, aim_dir) orelse {
                _ = state.rng.rand();
                continue;
            };

            const rand_scale = 0.85 + @as(f64, @floatFromInt(state.rng.rand() & 7)) * 0.05;
            const damage = asF32F64(base_damage * rand_scale);

            result.hits += 1;
            if (player.index >= 0 and player.index < state.shots_hit.len) {
                state.shots_hit[@intCast(player.index)] += 1;
            }

            const xp_gained = self.applyDamage(
                state,
                players,
                hit_idx,
                damage,
                owner_id,
            );
            if (xp_gained > 0) {
                result.deaths += 1;
                result.xp_awarded += xp_gained;
            }
        }

        return result;
    }

    fn spawnFromStats(
        self: *CreaturePool,
        rng: *survival_spawn.Crand,
        pos: survival_state.Vec2,
        heading: f64,
        stats: SpawnStats,
    ) void {
        self.spawnFromStatsWithFlags(rng, pos, heading, stats, 0);
    }

    fn spawnFromStatsWithFlags(
        self: *CreaturePool,
        rng: *survival_spawn.Crand,
        pos: survival_state.Vec2,
        heading: f64,
        stats: SpawnStats,
        flags: u32,
    ) void {
        const phase_seed = @as(f64, @floatFromInt(rng.rand() & 0x17f));
        self.spawnInit(.{
            .origin_template_id = -1,
            .pos = .{
                .x = pos.x,
                .y = pos.y,
            },
            .heading = heading,
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
            if (creature.hitbox_size <= 5.0) continue;

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
        creature_index: usize,
        damage: f64,
        owner_id: i32,
    ) i32 {
        if (creature_index >= self.entries.len) return 0;
        if (players.len == 0) return 0;

        var creature = &self.entries[creature_index];
        if (!creature.active) return 0;
        if (!(creature.hp > 0.0)) return 0;

        creature.hp = asF32F64(creature.hp - damage);
        creature.last_hit_owner_id = owner_id;
        if (creature.hp > 0.0) return 0;

        creature.hp = 0.0;
        creature.hitbox_size = -20.0;
        creature.active = false;
        self.kill_count += 1;

        const owner_player_idx = ownerIdToPlayerIndex(owner_id) orelse 0;
        const slot: usize = if (owner_player_idx >= 0 and owner_player_idx < players.len)
            @intCast(owner_player_idx)
        else
            0;
        return awardExperienceFromReward(state, &players[slot], creature.reward_value);
    }
};

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

fn weaponDamagePerShot(weapon_id: i32) f64 {
    const projectile_meta = survival_state.weaponProjectileMeta(weapon_id);
    const damage_scale = survival_state.weaponDamageScale(weapon_id);
    return @max(0.1, asF32F64(projectile_meta * damage_scale * 0.1));
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

fn expectFloatClose(expected: f64, actual: f64) !void {
    try std.testing.expectApproxEqAbs(expected, actual, 1e-6);
}

test "spawn init and shot resolution award xp on kill" {
    var pool = CreaturePool{};
    var state = survival_state.GameplayState.init(1234);
    var players = [_]survival_state.PlayerState{
        .{
            .index = 0,
            .pos = .{ .x = 100.0, .y = 100.0 },
        },
    };

    pool.spawnInit(.{
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
        0,
        .{ .x = 300.0, .y = 100.0 },
        1,
        survival_state.WeaponId.pistol,
    );
    try std.testing.expectEqual(@as(i32, 1), result.hits);
    try std.testing.expectEqual(@as(i32, 1), result.deaths);
    try std.testing.expect(result.xp_awarded > 0);
    try std.testing.expect(players[0].experience > before_xp);
    try std.testing.expectEqual(@as(i32, 1), state.shots_hit[0]);
    try std.testing.expectEqual(@as(i32, 1), pool.kill_count);
    try std.testing.expectEqual(@as(usize, 0), pool.activeCount());
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
    var players = [_]survival_state.PlayerState{
        .{
            .index = 0,
            .pos = .{ .x = 100.0, .y = 100.0 },
            .health = 100.0,
        },
    };
    pool.spawnInit(.{
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

    pool.update(&state, players[0..], 1.0 / 60.0, 1024.0);
    try std.testing.expect(players[0].health < 100.0);
    try std.testing.expect(state.survival_reward_damage_seen);
    try expectFloatClose(@as(f64, 0.5), pool.entries[0].attack_cooldown);
}

test "ai7 link timer consumes rng when timer crosses zero" {
    var pool = CreaturePool{};
    var state = survival_state.GameplayState.init(99);
    var players = [_]survival_state.PlayerState{
        .{
            .index = 0,
            .pos = .{ .x = 512.0, .y = 512.0 },
            .health = 100.0,
        },
    };

    pool.spawnInit(.{
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

    pool.update(&state, players[0..], 0.017, 1024.0);

    try std.testing.expectEqual(expected_rng.state, state.rng.state);
    try std.testing.expectEqual(survival_spawn.CreatureAiMode.hold_timer, pool.entries[0].ai_mode);
    try std.testing.expect(pool.entries[0].link_index >= 500);
    try std.testing.expect(pool.entries[0].link_index <= 1011);
}
