const std = @import("std");
const game_ids = @import("../game_ids.zig");
const native_math = @import("native_math.zig");

const creatures_mod = @import("creatures.zig");
const effects_mod = @import("effects.zig");
const owner_id_mod = @import("owner_id.zig");
const perks = @import("perks.zig");
const player_runtime = @import("player.zig");
const projectiles_mod = @import("projectiles.zig");
const rng_callers = @import("../rng_caller_static.zig");
const state_mod = @import("state.zig");
const terrain_fx_mod = @import("terrain_fx.zig");
const timing = @import("timing.zig");
const weapon_data = @import("weapon_data.zig");

const narrowF32 = native_math.roundF32;
const PerkId = perks.PerkId;
const BonusId = game_ids.BonusId;
const GameModeId = game_ids.GameModeId;

pub const BonusRuntimeError = error{};

pub const bonus_pool_size: usize = 16;
pub const BonusPickupRecord = struct {
    bonus_id: BonusId = .unused,
    amount: i32 = 0,
    player_index: i32 = -1,
    pos: state_mod.Vec2 = .{},
};
pub const BonusPickupBuffer = struct {
    items: [bonus_pool_size]BonusPickupRecord = [_]BonusPickupRecord{.{}} ** bonus_pool_size,
    len: usize = 0,

    pub fn append(self: *BonusPickupBuffer, record: BonusPickupRecord) error{OutOfSpace}!void {
        if (self.len >= self.items.len) return error.OutOfSpace;
        self.items[self.len] = record;
        self.len += 1;
    }

    pub fn constSlice(self: *const BonusPickupBuffer) []const BonusPickupRecord {
        return self.items[0..self.len];
    }
};
const weapon_drop_id_count: u32 = 0x21;

const bonus_spawn_margin: f32 = 32.0;
const bonus_spawn_min_distance: f32 = 32.0;
const bonus_pickup_radius: f32 = 26.0;
const bonus_pickup_decay_rate: f32 = 3.0;
const bonus_pickup_linger: f32 = 0.5;
const bonus_time_max: f32 = 10.0;
const bonus_weapon_near_radius: f32 = 56.0;
const bonus_aim_hover_radius: f32 = 24.0;
const bonus_telekinetic_pickup_ms: f32 = 650.0;

inline fn weaponIdIndex(weapon_id: game_ids.WeaponId) usize {
    return @intCast(@intFromEnum(weapon_id));
}

pub const BonusEntry = struct {
    generation: i32 = 0,
    bonus_id: BonusId = .unused,
    picked: bool = false,
    time_left: f32 = 0.0,
    time_max: f32 = 0.0,
    pos: state_mod.Vec2 = .{},
    amount: i32 = 0,
};

const AllocSlot = union(enum) {
    sentinel,
    index: usize,
};

pub fn clampSpawnPosition(pos: state_mod.Vec2, world_size: f32) state_mod.Vec2 {
    var clamped = pos;
    if (clamped.x < bonus_spawn_margin) clamped.x = bonus_spawn_margin;
    if (clamped.y < bonus_spawn_margin) clamped.y = bonus_spawn_margin;
    if (world_size - bonus_spawn_margin < clamped.x) clamped.x = world_size - bonus_spawn_margin;
    if (world_size - bonus_spawn_margin < clamped.y) clamped.y = world_size - bonus_spawn_margin;
    return clamped;
}

pub const BonusPool = struct {
    entries: [bonus_pool_size]BonusEntry = [_]BonusEntry{.{}} ** bonus_pool_size,
    sentinel: BonusEntry = .{},

    pub fn reset(self: *BonusPool) void {
        self.entries = [_]BonusEntry{.{}} ** bonus_pool_size;
        self.sentinel = .{};
    }

    pub fn activeCount(self: *const BonusPool) usize {
        var count: usize = 0;
        for (self.entries) |entry| {
            if (entry.bonus_id != .unused) count += 1;
        }
        return count;
    }

    pub fn trySpawnOnKill(
        self: *BonusPool,
        pos: state_mod.Vec2,
        state: *state_mod.GameplayState,
        players: []const state_mod.PlayerState,
        world_size: f32,
    ) ?*BonusEntry {
        if (state.game_mode == .rush or state.game_mode == .typo or state.game_mode == .tutorial) return null;
        if (state.bonus_spawn_guard) return null;
        if (players.len == 0) return null;

        const has_pistol = anyPlayerHasPistol(players);
        const force_drop_has_pistol = if (state.preserve_bugs)
            nativeForceDropHasPistol(players)
        else
            has_pistol;

        if (force_drop_has_pistol and (state.rng.randTagged(rng_callers.bonus_try_spawn_on_kill_pistol_force_weapon) & 3) < 3) {
            const slot = spawnAtPos(self, pos, state, players, world_size);
            var entry = slotPtr(self, slot);
            entry.bonus_id = .weapon;

            var weapon_id = weaponPickRandomAvailable(state);
            entry.amount = weapon_data.weaponIdToInt(weapon_id);
            if (weapon_id == game_ids.WeaponId.pistol) {
                weapon_id = weaponPickRandomAvailable(state);
                entry.amount = weapon_data.weaponIdToInt(weapon_id);
            }

            if (countMatches(self, entry.bonus_id) > 1) {
                clearEntry(self, entry);
                return null;
            }

            if (entry.amount == weapon_data.weaponIdToInt(.pistol) or
                perkActiveByBugPolicy(players, PerkId.my_favourite_weapon, state.preserve_bugs))
            {
                clearEntry(self, entry);
                return null;
            }

            if (slot == .sentinel) return null;
            return entry;
        }

        const base_roll = state.rng.randTagged(rng_callers.bonus_try_spawn_on_kill_base_gate);
        if ((base_roll % 9) != 1) {
            var allow_without_magnet = false;
            const fallback_gate_has_pistol = if (state.preserve_bugs)
                players[0].weapon.weapon_id == .pistol
            else
                has_pistol;
            if (fallback_gate_has_pistol) {
                allow_without_magnet = (state.rng.randTagged(rng_callers.bonus_try_spawn_on_kill_pistol_allow_without_magnet) % 5) == 1;
            }
            if (!allow_without_magnet) {
                if (!perkActiveByBugPolicy(players, PerkId.bonus_magnet, state.preserve_bugs)) {
                    return null;
                }
                if ((state.rng.randTagged(rng_callers.bonus_try_spawn_on_kill_bonus_magnet) % 10) != 2) return null;
            }
        }

        const slot = spawnAtPos(self, pos, state, players, world_size);
        var entry = slotPtr(self, slot);

        if (entry.bonus_id == .weapon and weaponDropNearPlayer(pos, players, state.preserve_bugs)) {
            entry.bonus_id = .points;
            entry.amount = 100;
        }

        if (entry.bonus_id != .points and countMatches(self, entry.bonus_id) > 1) {
            clearEntry(self, entry);
            return null;
        }

        if (suppressSpawnedBonusForCarriedWeapon(entry.*, players, state.preserve_bugs)) {
            clearEntry(self, entry);
            return null;
        }

        if (slot == .sentinel) return null;
        return entry;
    }

    pub fn spawnAt(
        self: *BonusPool,
        pos: state_mod.Vec2,
        bonus_id: BonusId,
        duration_override: i32,
        state: *state_mod.GameplayState,
        world_size: f32,
    ) ?*BonusEntry {
        const clamped_pos = clampSpawnPosition(pos, world_size);
        if (state.game_mode == .rush) return null;

        const slot = allocSlotOrSentinel(self);

        var entry = slotPtr(self, slot);
        entry.generation += 1;
        entry.bonus_id = bonus_id;
        entry.picked = false;
        entry.pos = clamped_pos;
        entry.time_left = narrowF32(bonus_time_max);
        entry.time_max = narrowF32(bonus_time_max);
        entry.amount = if (duration_override == -1) defaultBonusAmount(bonus_id) else duration_override;

        return if (slot == .sentinel) null else entry;
    }

    pub fn seedTutorialEntry(
        self: *BonusPool,
        index: usize,
        pos: state_mod.Vec2,
        bonus_id: BonusId,
        amount: i32,
    ) *BonusEntry {
        const entry = &self.entries[index];
        entry.generation += 1;
        entry.bonus_id = bonus_id;
        entry.time_left = 100.0;
        entry.time_max = 100.0;
        entry.picked = false;
        entry.amount = amount;
        entry.pos = pos;
        return entry;
    }

    pub fn update(
        self: *BonusPool,
        state: *state_mod.GameplayState,
        players: []state_mod.PlayerState,
        step: BonusStep,
        pickup_records: ?*BonusPickupBuffer,
    ) BonusRuntimeError!void {
        if (!(step.dt > 0.0)) return;

        for (&self.entries) |*entry| {
            if (isEmpty(entry.*)) continue;

            const decay = step.dt * (if (entry.picked) bonus_pickup_decay_rate else 1.0);
            entry.time_left -= decay;
            if (!entry.picked and state.game_mode == .tutorial) {
                entry.time_left = 5.0;
            }

            var expired_to_unused = false;
            if (entry.time_left < 0.0) {
                if (entry.picked) {
                    clearEntry(self, entry);
                    continue;
                }
                entry.bonus_id = .unused;
                expired_to_unused = true;
            }

            if (entry.picked) continue;

            // Native's player loop has no break: every player inside the
            // pickup radius applies the bonus this tick.
            var picked_now = false;
            for (players) |*player| {
                if (!withinNativeRadius(entry.pos, player.pos, bonus_pickup_radius)) continue;

                try applyBonus(state, self, step, player, players, entry.bonus_id, entry.amount, entry.pos);
                appendPickupRecord(pickup_records, .{
                    .bonus_id = entry.bonus_id,
                    .amount = entry.amount,
                    .player_index = player.index,
                    .pos = entry.pos,
                });
                entry.picked = true;
                entry.time_left = narrowF32(bonus_pickup_linger);
                picked_now = true;
            }

            if (expired_to_unused and !picked_now) {
                clearEntry(self, entry);
            }
        }
    }
};

pub fn updatePrePickupTimers(
    state: *state_mod.GameplayState,
    dt: f32,
) void {
    if (!(dt > 0.0)) return;

    if (state.bonuses.weapon_power_up > 0.0) {
        state.bonuses.weapon_power_up -= dt;
    }
    if (state.bonuses.energizer > 0.0) {
        state.bonuses.energizer -= dt;
    }
    if (state.bonuses.reflex_boost > 0.0) {
        state.bonuses.reflex_boost = native_math.pc24Sub(
            state.bonuses.reflex_boost,
            dt,
        );
    }
}

/// The world step state that pickups and `bonus_apply` reach beyond the
/// gameplay state.
pub const BonusStep = struct {
    creatures: *creatures_mod.CreaturePool,
    projectiles: *projectiles_mod.ProjectilePool,
    effects: *effects_mod.EffectPool,
    terrain_fx: *terrain_fx_mod.TerrainFxScratch,
    dt: f32,
    world_size: f32,
    detail_preset: i32,
};

/// Telekinetic pickups, which native applies in `bonus_render`, ahead of the
/// level-up check and `bonus_update`.
pub fn telekineticUpdate(
    pool: *BonusPool,
    state: *state_mod.GameplayState,
    players: []state_mod.PlayerState,
    step: BonusStep,
    pickup_records: ?*BonusPickupBuffer,
) BonusRuntimeError!void {
    if (!(step.dt > 0.0)) return;
    // bonus_render (0x004295f0) accumulates the int `frame_dt_ms`.
    const dt_ms: f32 = @floatFromInt(timing.ftolMsI32(step.dt));
    for (players) |*player| {
        if (!(player.health > 0.0)) continue;

        const hovered = bonusFindAimHoverEntry(player.*, pool) orelse {
            player.bonus_aim_hover_index = -1;
            player.bonus_aim_hover_timer_ms = 0.0;
            continue;
        };

        player.bonus_aim_hover_index = @intCast(hovered.index);
        player.bonus_aim_hover_timer_ms += dt_ms;

        if (player.bonus_aim_hover_timer_ms <= bonus_telekinetic_pickup_ms) continue;
        // Native calls the singleton perk_count_get here, so player zero owns
        // the perk gate even though the iterated player receives the pickup.
        const perk_player = if (state.preserve_bugs and players.len > 0) players[0] else player.*;
        if (!perkActive(perk_player, PerkId.telekinetic)) continue;

        var entry = &pool.entries[hovered.index];
        if (entry.picked or entry.bonus_id == .unused) continue;

        try applyBonus(state, pool, step, player, players, entry.bonus_id, entry.amount, entry.pos);
        appendPickupRecord(pickup_records, .{
            .bonus_id = entry.bonus_id,
            .amount = entry.amount,
            .player_index = player.index,
            .pos = entry.pos,
        });
        entry.picked = true;
        entry.time_left = narrowF32(bonus_pickup_linger);
        player.bonus_aim_hover_index = -1;
        player.bonus_aim_hover_timer_ms = 0.0;
        break;
    }
}

pub fn bonusUpdate(
    pool: *BonusPool,
    state: *state_mod.GameplayState,
    players: []state_mod.PlayerState,
    step: BonusStep,
    pickup_records: ?*BonusPickupBuffer,
) BonusRuntimeError!void {
    try pool.update(state, players, step, pickup_records);

    if (step.dt > 0.0) {
        if (state.bonuses.double_experience <= 0.0) {
            state.bonuses.double_experience = 0.0;
        } else {
            state.bonuses.double_experience -= step.dt;
        }

        if (state.bonuses.freeze <= 0.0) {
            state.bonuses.freeze = 0.0;
        } else {
            state.bonuses.freeze -= step.dt;
        }
    }
}

pub fn applyPendingCreatureProjectiles(
    state: *state_mod.GameplayState,
    projectiles: *projectiles_mod.ProjectilePool,
) void {
    if (state.pending_creature_projectile_count <= 0) {
        state.pending_creature_projectile_count = 0;
        return;
    }

    const pending_count_i32 = @min(
        state.pending_creature_projectile_count,
        @as(i32, @intCast(state.pending_creature_projectiles.len)),
    );

    var idx_i32: i32 = 0;
    while (idx_i32 < pending_count_i32) : (idx_i32 += 1) {
        const idx: usize = @intCast(idx_i32);
        const pending = state.pending_creature_projectiles[idx];
        const type_id = pending.type_id;
        if (type_id <= 0) continue;
        const meta = projectileTravelBudgetFromRawId(type_id);
        _ = projectiles.spawn(pending.pos, narrowF32(pending.angle), type_id, pending.owner_id, meta);
    }
    state.pending_creature_projectile_count = 0;
}

fn bonusFindAimHoverEntry(
    player: state_mod.PlayerState,
    pool: *const BonusPool,
) ?struct { index: usize } {
    const radius_sq = bonus_aim_hover_radius * bonus_aim_hover_radius;
    for (pool.entries, 0..) |entry, idx| {
        if (entry.bonus_id == .unused) continue;
        if (distanceSq(player.aim, entry.pos) < radius_sq) {
            return .{ .index = idx };
        }
    }
    return null;
}

/// Port of `bonus_apply` (0x00409890).
fn applyBonus(
    state: *state_mod.GameplayState,
    pool: *BonusPool,
    step: BonusStep,
    player: *state_mod.PlayerState,
    players: []state_mod.PlayerState,
    bonus_id: BonusId,
    amount: i32,
    origin: state_mod.Vec2,
) BonusRuntimeError!void {
    const player_index: usize = @intCast(player.index);
    // Native perk_count_get always reads player slot zero, even when player one
    // is the pickup owner. Corrected mode keeps intuitive per-player ownership.
    const perk_player = if (state.preserve_bugs) players[0] else player.*;
    const multiplier: f32 = if (perkActive(perk_player, PerkId.bonus_economist)) 1.5 else 1.0;
    // Native encodes friendly fire in the owner id (-1 - player_index).
    const player_owner_id = owner_id_mod.playerProjectileOwnerId(state.friendly_fire_enabled, player.index);

    switch (bonus_id) {
        .weapon => {
            // The old weapon is never stashed: the alt slot is preloaded with
            // a pistol at player reset.
            player_runtime.weaponAssignPlayerWithState(player, weapon_data.weaponIdFromInt(amount), state);
        },
        .medikit => {
            if (player.health < 100.0) {
                player.health = @min(100.0, player.health + 10.0);
            }
        },
        .reflex_boost => {
            state.bonuses.reflex_boost = narrowF32(state.bonuses.reflex_boost + @as(f32, @floatFromInt(amount)) * multiplier);
            for (players) |*target| {
                target.weapon.ammo = @floatFromInt(target.weapon.clip_size);
                target.weapon.reload_timer = 0.0;
            }
            step.effects.spawnRing(origin, step.detail_preset, .{ .r = 0.6, .g = 0.6, .b = 1.0, .a = 1.0 });
        },
        .weapon_power_up => {
            state.bonuses.weapon_power_up = narrowF32(state.bonuses.weapon_power_up + @as(f32, @floatFromInt(amount)) * multiplier);
            player.weapon_reset_latch = 0;
            player.weapon.shot_cooldown = 0.0;
            player.weapon.reload_timer = 0.0;
            player.weapon.ammo = @floatFromInt(player.weapon.clip_size);
        },
        .speed => {
            player.speed_bonus_timer = narrowF32(player.speed_bonus_timer + @as(f32, @floatFromInt(amount)) * multiplier);
        },
        .freeze => {
            state.bonuses.freeze = narrowF32(state.bonuses.freeze + @as(f32, @floatFromInt(amount)) * multiplier);
            // Every active corpse shatters, including kills earlier in this
            // tick and entries below the normal despawn threshold.
            for (&step.creatures.entries) |*creature| {
                if (!creature.active or creature.hp > 0.0) continue;
                for (0..8) |_| {
                    const angle = @as(f32, @floatFromInt(state.rng.randTagged(rng_callers.bonus_apply_freeze_shard_angle) % 612)) * 0.01;
                    step.effects.spawnFreezeShard(state, creature.pos, angle, step.detail_preset);
                }
                const angle = @as(f32, @floatFromInt(state.rng.randTagged(rng_callers.bonus_apply_freeze_shatter_angle) % 612)) * 0.01;
                step.effects.spawnFreezeShatter(state, creature.pos, angle, step.detail_preset);
                creature.active = false;
            }
            step.effects.spawnRing(origin, step.detail_preset, .{ .r = 0.3, .g = 0.5, .b = 0.8, .a = 1.0 });
            state.sfx_queue.append(.shockwave);
        },
        .shield => {
            player.shield_timer = narrowF32(player.shield_timer + @as(f32, @floatFromInt(amount)) * multiplier);
        },
        .shock_chain => {
            if (projectiles_mod.creatureFindNearestAlive(step.creatures, origin, state.preserve_bugs)) |target_idx| {
                const target = step.creatures.entries[target_idx];
                const angle = projectiles_mod.chainAngleFromDelta(.{
                    .x = native_math.pc24Sub(target.pos.x, origin.x),
                    .y = native_math.pc24Sub(target.pos.y, origin.y),
                });
                const type_id = @intFromEnum(game_ids.ProjectileTypeId.ion_rifle);
                state.bonus_spawn_guard = true;
                state.shock_chain_links_left = 0x20;
                const proj_idx = step.projectiles.spawn(origin, angle, type_id, player_owner_id, projectileTravelBudgetFromRawId(type_id));
                state.shock_chain_projectile_id = @intCast(proj_idx);
                state.bonus_spawn_guard = false;
                state.sfx_queue.append(.shock_hit_01);
            }
        },
        .fireblast => {
            const type_id = @intFromEnum(game_ids.ProjectileTypeId.plasma_rifle);
            state.bonus_spawn_guard = true;
            for (0..16) |ring_idx| {
                const angle = @as(f32, @floatFromInt(ring_idx)) * 0.39269909;
                _ = step.projectiles.spawn(origin, angle, type_id, player_owner_id, projectileTravelBudgetFromRawId(type_id));
            }
            state.bonus_spawn_guard = false;
            state.sfx_queue.append(.explosion_medium);
        },
        .fire_bullets => {
            player.fire_bullets_timer = narrowF32(player.fire_bullets_timer + 5.0 * multiplier);
            player.weapon_reset_latch = 0;
            player.weapon.shot_cooldown = 0.0;
            player.weapon.reload_timer = 0.0;
            player.weapon.ammo = @floatFromInt(player.weapon.clip_size);
        },
        .energizer => {
            state.bonuses.energizer = narrowF32(state.bonuses.energizer + 8.0 * multiplier);
        },
        .double_experience => {
            state.bonuses.double_experience = narrowF32(state.bonuses.double_experience + 6.0 * multiplier);
        },
        .nuke => {
            const projectile_owner_id = owner_id_mod.owner_local_player;
            const bullet_count = (state.rng.randTagged(rng_callers.bonus_apply_nuke_bullet_count) & 3) + 4;
            for (0..bullet_count) |_| {
                const angle = native_math.pc24Mul(
                    @as(f32, @floatFromInt(state.rng.randTagged(rng_callers.bonus_apply_nuke_pistol_angle) % 628)),
                    @as(f32, 0.01),
                );
                var type_id = @intFromEnum(game_ids.ProjectileTypeId.pistol);
                applyPlayerProjectileSpawnRules(state, players, projectile_owner_id, player_index, &type_id);
                const proj_idx = step.projectiles.spawn(origin, angle, type_id, projectile_owner_id, projectileTravelBudgetFromRawId(type_id));
                const speed_scale = native_math.pc24Add(
                    native_math.pc24Mul(
                        @as(f32, @floatFromInt(state.rng.randTagged(rng_callers.bonus_apply_nuke_pistol_speed_scale) % 50)),
                        @as(f32, 0.01),
                    ),
                    @as(f32, 0.5),
                );
                step.projectiles.entries[proj_idx].speed_scale = native_math.pc24Mul(
                    step.projectiles.entries[proj_idx].speed_scale,
                    speed_scale,
                );
            }
            inline for (.{ rng_callers.bonus_apply_nuke_gauss_angle_1, rng_callers.bonus_apply_nuke_gauss_angle_2 }) |angle_caller| {
                const angle = native_math.pc24Mul(
                    @as(f32, @floatFromInt(state.rng.randTagged(angle_caller) % 628)),
                    @as(f32, 0.01),
                );
                var type_id = @intFromEnum(game_ids.ProjectileTypeId.gauss_gun);
                applyPlayerProjectileSpawnRules(state, players, projectile_owner_id, player_index, &type_id);
                _ = step.projectiles.spawn(origin, angle, type_id, projectile_owner_id, projectileTravelBudgetFromRawId(type_id));
            }
            step.effects.spawnExplosionBurst(state, origin, 1.0, step.detail_preset);
            state.camera_shake_pulses = 0x14;
            state.camera_shake_timer = 0.2;

            state.bonus_spawn_guard = true;
            const damage_owner_id = owner_id_mod.playerOwnerId(player.index);
            for (step.creatures.entries, 0..) |creature, idx| {
                // Corpses take the blast too, which shrinks them faster.
                if (!creature.active) continue;
                const dx = native_math.pc24Sub(creature.pos.x, origin.x);
                const dy = native_math.pc24Sub(creature.pos.y, origin.y);
                if (@abs(dx) > 256.0 or @abs(dy) > 256.0) continue;
                const distance = native_math.pc24Sqrt(native_math.pc24Add(
                    native_math.pc24Mul(dx, dx),
                    native_math.pc24Mul(dy, dy),
                ));
                const damage_base = native_math.pc24Sub(@as(f32, 256.0), distance);
                if (!(damage_base > 0.0)) continue;
                _ = step.creatures.applyDamage(
                    state,
                    players,
                    pool,
                    step.terrain_fx,
                    idx,
                    native_math.pc24Mul(damage_base, @as(f32, 5.0)),
                    .explosion,
                    .{},
                    damage_owner_id,
                    step.dt,
                    step.world_size,
                );
            }
            state.bonus_spawn_guard = false;
            state.sfx_queue.append(.explosion_large);
            state.sfx_queue.append(.shockwave);
        },
        .points => {
            players[0].experience += amount;
        },
        .unused => {},
    }

    // The pickup burst draws RNG before `bonus_apply` returns, so it precedes
    // any later pickup applied in the same pass.
    if (bonus_id != .nuke) {
        step.effects.spawnBurstWithCallers(
            state,
            origin,
            12,
            step.detail_preset,
            0.4,
            0.1,
            .{ .r = 0.4, .g = 0.5, .b = 1.0, .a = 0.5 },
            effects_mod.EffectPool.bonus_pickup_burst_callers,
        );
    }
}

fn defaultBonusAmount(bonus_id: BonusId) i32 {
    return switch (bonus_id) {
        .unused => 0,
        .points => 500,
        .energizer => 8,
        .weapon => 3,
        .weapon_power_up => 10,
        .nuke => 1,
        .double_experience => 1,
        .shock_chain => 1,
        .fireblast => 1,
        .reflex_boost => 3,
        .shield => 7,
        .freeze => 5,
        .medikit => 10,
        .speed => 8,
        .fire_bullets => 4,
    };
}

fn perkActive(player: state_mod.PlayerState, perk_id: PerkId) bool {
    return player.perk_counts.get(perk_id) > 0;
}

fn anyPerkActive(players: []const state_mod.PlayerState, perk_id: PerkId) bool {
    for (players) |player| {
        if (perkActive(player, perk_id)) return true;
    }
    return false;
}

fn anyPlayerHasPistol(players: []const state_mod.PlayerState) bool {
    for (players) |player| {
        if (player.weapon.weapon_id == .pistol) return true;
    }
    return false;
}

fn nativeForceDropHasPistol(players: []const state_mod.PlayerState) bool {
    if (players.len == 0) return false;
    if (players[0].weapon.weapon_id == .pistol) return true;
    return players.len == 2 and players[1].weapon.weapon_id == .pistol;
}

fn perkActiveByBugPolicy(
    players: []const state_mod.PlayerState,
    perk_id: PerkId,
    preserve_bugs: bool,
) bool {
    if (preserve_bugs) return primaryPlayerPerkActive(players, perk_id);
    return anyPerkActive(players, perk_id);
}

fn carriedWeaponId(players: []const state_mod.PlayerState, weapon_id: game_ids.WeaponId) bool {
    for (players) |player| {
        if (player.weapon.weapon_id == weapon_id) return true;
        if (player.alt_weapon) |alt_slot| {
            if (alt_slot.weapon_id == weapon_id) return true;
        }
    }
    return false;
}

fn suppressSpawnedBonusForCarriedWeapon(
    entry: BonusEntry,
    players: []const state_mod.PlayerState,
    preserve_bugs: bool,
) bool {
    if (preserve_bugs) {
        if (players.len == 0) return false;
        const amount_weapon_id = std.enums.fromInt(game_ids.WeaponId, entry.amount) orelse return false;
        return players[0].weapon.weapon_id == amount_weapon_id;
    }
    if (entry.bonus_id != .weapon) return false;
    const weapon_id = std.enums.fromInt(game_ids.WeaponId, entry.amount) orelse return false;
    return carriedWeaponId(players, weapon_id);
}

test "preserved bonus suppression treats amount as weapon id" {
    const players = [_]state_mod.PlayerState{.{
        .index = 0,
        .pos = .{},
        .weapon = .{ .weapon_id = .multi_plasma },
    }};
    const entry: BonusEntry = .{
        .bonus_id = .weapon_power_up,
        .amount = 10,
    };

    try std.testing.expect(suppressSpawnedBonusForCarriedWeapon(entry, players[0..], true));
    try std.testing.expect(!suppressSpawnedBonusForCarriedWeapon(entry, players[0..], false));
}

fn weaponRefreshAvailable(state: *state_mod.GameplayState) void {
    const unlock_index = state.status_quest_unlock_index;
    const unlock_index_full = state.status_quest_unlock_index_full;
    const game_mode = state.game_mode;

    if (state.weapon_available_game_mode != null and
        state.weapon_available_game_mode.? == game_mode and
        state.weapon_available_unlock_index == unlock_index and
        state.weapon_available_unlock_index_full == unlock_index_full)
    {
        return;
    }

    state.weapon_available = state_mod.WeaponAvailability.initFill(false);
    state.weapon_available.set(.pistol, true);

    if (unlock_index > 0) {
        const limit: usize = @min(@as(usize, @intCast(unlock_index)), quest_unlock_weapon_by_index.len);
        for (quest_unlock_weapon_by_index[0..limit]) |weapon_id| {
            if (weapon_id > 0 and weapon_id < state_mod.weapon_count_size) {
                state.weapon_available.set(weapon_data.weaponIdFromInt(weapon_id), true);
            }
        }
    }

    if (game_mode == .survival) {
        state.weapon_available.set(.assault_rifle, true);
        state.weapon_available.set(.shotgun, true);
        state.weapon_available.set(.submachine_gun, true);
    }

    if (unlock_index_full >= 0x28) {
        state.weapon_available.set(.splitter_gun, true);
    }

    state.weapon_available_game_mode = game_mode;
    state.weapon_available_unlock_index = unlock_index;
    state.weapon_available_unlock_index_full = unlock_index_full;
}

pub fn buildWeaponAvailabilityForStatus(
    game_mode: game_ids.GameModeId,
    quest_unlock_index: i32,
    quest_unlock_index_full: i32,
) state_mod.WeaponAvailability {
    var availability = state_mod.WeaponAvailability.initFill(false);
    availability.set(.pistol, true);

    if (quest_unlock_index > 0) {
        const limit: usize = @min(@as(usize, @intCast(quest_unlock_index)), quest_unlock_weapon_by_index.len);
        for (quest_unlock_weapon_by_index[0..limit]) |weapon_id| {
            if (weapon_id > 0 and weapon_id < state_mod.weapon_count_size) {
                availability.set(weapon_data.weaponIdFromInt(weapon_id), true);
            }
        }
    }

    if (game_mode == .survival) {
        availability.set(.assault_rifle, true);
        availability.set(.shotgun, true);
        availability.set(.submachine_gun, true);
    }

    if (quest_unlock_index_full >= 0x28) {
        availability.set(.splitter_gun, true);
    }

    return availability;
}

pub fn questUnlockWeaponForIndex(global_index: i32) ?game_ids.WeaponId {
    if (global_index < 0 or global_index >= quest_unlock_weapon_by_index.len) return null;
    const raw_id = quest_unlock_weapon_by_index[@intCast(global_index)];
    if (raw_id <= 0 or raw_id >= state_mod.weapon_count_size) return null;
    return weapon_data.weaponIdFromInt(raw_id);
}

pub fn weaponPickRandomAvailable(state: *state_mod.GameplayState) game_ids.WeaponId {
    weaponRefreshAvailable(state);

    while (true) {
        var base_rand = state.rng.randTagged(rng_callers.weapon_pick_random_available_pick);
        var weapon_id: i32 = @intCast(base_rand % weapon_drop_id_count + 1);
        var weapon_enum = weapon_data.weaponIdFromInt(weapon_id);

        if (state.status_weapon_usage_counts.get(weapon_enum) != 0 and
            (state.rng.randTagged(rng_callers.weapon_pick_random_available_reroll_gate) & 1) == 0)
        {
            base_rand = state.rng.randTagged(rng_callers.weapon_pick_random_available_reroll_pick);
            weapon_id = @intCast(base_rand % weapon_drop_id_count + 1);
            weapon_enum = weapon_data.weaponIdFromInt(weapon_id);
        }

        if (!state.weapon_available.get(weapon_enum)) continue;

        if (state.game_mode == .quests and
            state.quest_stage_major == 5 and
            state.quest_stage_minor == 10 and
            weapon_enum == game_ids.WeaponId.ion_cannon)
        {
            continue;
        }
        return weapon_enum;
    }
}

fn bonusPickRandomType(
    pool: *const BonusPool,
    state: *state_mod.GameplayState,
    players: []const state_mod.PlayerState,
) BonusId {
    var has_fire_bullets_drop = false;
    for (pool.entries) |entry| {
        if (entry.bonus_id == .fire_bullets and !entry.picked) {
            has_fire_bullets_drop = true;
            break;
        }
    }

    for (0..101) |_| {
        const roll: i32 = @intCast(state.rng.randTagged(rng_callers.bonus_pick_random_type_roll) % 162 + 1);
        const bonus_id = bonusIdFromRoll(roll, state) orelse continue;
        if (bonusPickSuppressed(state, players, bonus_id, has_fire_bullets_drop)) continue;

        return bonus_id;
    }
    return .points;
}

fn bonusPickSuppressed(
    state: *state_mod.GameplayState,
    players: []const state_mod.PlayerState,
    bonus_id: BonusId,
    has_fire_bullets_drop: bool,
) bool {
    if (state.shock_chain_links_left > 0 and bonus_id == .shock_chain) return true;

    if (state.game_mode == .quests and state.quest_stage_minor == 10) {
        const major = state.quest_stage_major;
        if (bonus_id == .nuke) {
            if (major == 2 or major == 4 or major == 5) return true;
            if (state.hardcore and major == 3) return true;
        }
        if (bonus_id == .freeze) {
            if (major == 4) return true;
            if (state.hardcore and major == 2) return true;
        }
    }

    if (bonus_id == .freeze and state.bonuses.freeze > 0.0) return true;
    // Native reads both shield slots directly, but perk_count_get reads only
    // player 0. Preserve that asymmetry for larger port-side player slices.
    if (bonus_id == .shield and nativeShieldActive(players)) return true;
    if (bonus_id == .weapon and has_fire_bullets_drop) return true;
    if (bonus_id == .weapon and primaryPlayerPerkActive(players, PerkId.my_favourite_weapon)) return true;
    if (bonus_id == .medikit and primaryPlayerPerkActive(players, PerkId.death_clock)) return true;
    if (bonus_id == .unused) return true;
    return false;
}

fn nativeShieldActive(players: []const state_mod.PlayerState) bool {
    for (players[0..@min(players.len, 2)]) |player| {
        if (player.shield_timer > 0.0) return true;
    }
    return false;
}

fn primaryPlayerPerkActive(players: []const state_mod.PlayerState, perk_id: PerkId) bool {
    if (players.len == 0) return false;
    return players[0].perk_counts.get(perk_id) > 0;
}

fn bonusIdFromRoll(
    roll: i32,
    state: *state_mod.GameplayState,
) ?BonusId {
    if (roll < 1 or roll > 162) return null;
    if (roll <= 13) return .points;
    if (roll == 14) {
        if ((state.rng.randTagged(rng_callers.bonus_pick_random_type_energizer) & 0x3f) == 0) return .energizer;
        return .weapon;
    }

    const index = @divFloor(roll - 15, 10);
    return switch (index) {
        0 => .weapon,
        1 => .weapon_power_up,
        2 => .nuke,
        3 => .double_experience,
        4 => .shock_chain,
        5 => .fireblast,
        6 => .reflex_boost,
        7 => .shield,
        8 => .freeze,
        9 => .medikit,
        10 => .speed,
        11 => .fire_bullets,
        else => null,
    };
}

fn isEmpty(entry: BonusEntry) bool {
    return entry.bonus_id == .unused and !entry.picked and entry.time_left <= 0.0 and entry.time_max <= 0.0 and entry.amount == 0;
}

fn distanceSq(a: state_mod.Vec2, b: state_mod.Vec2) f32 {
    const dx = a.x - b.x;
    const dy = a.y - b.y;
    return dx * dx + dy * dy;
}

fn withinNativeRadius(a: state_mod.Vec2, b: state_mod.Vec2, radius: f32) bool {
    return native_math.pc24Hypot(
        native_math.pc24Sub(a.x, b.x),
        native_math.pc24Sub(a.y, b.y),
    ) < radius;
}

fn weaponDropNearPlayer(
    pos: state_mod.Vec2,
    players: []const state_mod.PlayerState,
    preserve_bugs: bool,
) bool {
    const candidates = if (preserve_bugs and players.len > 0) players[0..1] else players;
    for (candidates) |player| {
        if (withinNativeRadius(pos, player.pos, bonus_weapon_near_radius)) return true;
    }
    return false;
}

test "weapon drop near check uses native pc24 boundary and player slot" {
    const players = [_]state_mod.PlayerState{
        .{ .index = 0, .pos = .{} },
        .{ .index = 1, .pos = .{ .x = 500.0, .y = 500.0 } },
    };

    try std.testing.expect(!weaponDropNearPlayer(
        .{ .x = 43.35334777832031, .y = 35.44696044921875 },
        players[0..1],
        true,
    ));
    try std.testing.expect(!weaponDropNearPlayer(.{ .x = 500.0, .y = 500.0 }, players[0..], true));
    try std.testing.expect(weaponDropNearPlayer(.{ .x = 500.0, .y = 500.0 }, players[0..], false));
}

fn projectileTravelBudgetFromRawId(raw_id: i32) f32 {
    const weapon_id = weapon_data.weaponIdFromInt(raw_id);
    return weapon_data.weapon_stats.get(weapon_id).travel_budget;
}

fn applyPlayerProjectileSpawnRules(
    state: *state_mod.GameplayState,
    players: []const state_mod.PlayerState,
    owner_id: i32,
    owner_player_index: usize,
    type_id: *i32,
) void {
    if (state.bonus_spawn_guard) return;
    if (!owner_id_mod.projectileSpawnUsesPlayerPath(owner_id, state.preserve_bugs)) return;

    var shot_credit: i32 = 1;
    // Native reads both players' timers whoever fired; the rewrite reads the shooter's.
    const fire_bullets_active = if (state.preserve_bugs) blk: {
        for (players[0..@min(players.len, 2)]) |player| {
            if (player.fire_bullets_timer > 0.0) break :blk true;
        }
        break :blk false;
    } else players[owner_player_index].fire_bullets_timer > 0.0;
    if (type_id.* != @intFromEnum(game_ids.ProjectileTypeId.fire_bullets) and
        fire_bullets_active)
    {
        type_id.* = @intFromEnum(game_ids.ProjectileTypeId.fire_bullets);
        shot_credit = 2;
    }
    state.shots_fired += shot_credit;
}

test "player projectile spawn rules preserve global fire bullets timer" {
    const players = [_]state_mod.PlayerState{
        .{ .index = 0, .pos = .{} },
        .{ .index = 1, .pos = .{}, .fire_bullets_timer = 1.0 },
    };
    const owner_id = owner_id_mod.owner_local_player;

    var preserved_state = state_mod.GameplayState.init(1);
    preserved_state.preserve_bugs = true;
    var preserved_type_id = @intFromEnum(game_ids.ProjectileTypeId.pistol);
    applyPlayerProjectileSpawnRules(
        &preserved_state,
        players[0..],
        owner_id,
        0,
        &preserved_type_id,
    );
    try std.testing.expectEqual(
        @intFromEnum(game_ids.ProjectileTypeId.fire_bullets),
        preserved_type_id,
    );
    try std.testing.expectEqual(@as(i32, 2), preserved_state.shots_fired);

    var corrected_state = state_mod.GameplayState.init(1);
    corrected_state.preserve_bugs = false;
    var corrected_type_id = @intFromEnum(game_ids.ProjectileTypeId.pistol);
    applyPlayerProjectileSpawnRules(
        &corrected_state,
        players[0..],
        owner_id,
        0,
        &corrected_type_id,
    );
    try std.testing.expectEqual(
        @intFromEnum(game_ids.ProjectileTypeId.pistol),
        corrected_type_id,
    );
    try std.testing.expectEqual(@as(i32, 1), corrected_state.shots_fired);
}

fn appendPickupRecord(
    pickup_records: ?*BonusPickupBuffer,
    record: BonusPickupRecord,
) void {
    var records = pickup_records orelse return;
    records.append(record) catch |err| switch (err) {
        error.OutOfSpace => {},
    };
}

const quest_unlock_weapon_by_index = [_]i32{
    2,  3,  0, 8,  0, 5,  0, 6,  0, 12,
    0,  9,  0, 21, 0, 7,  0, 4,  0, 11,
    0,  10, 0, 13, 0, 15, 0, 18, 0, 20,
    0,  19, 0, 14, 0, 17, 0, 22, 0, 23,
    31, 0,  0, 30, 0, 0,  0, 0,  0, 28,
};

fn allocSlot(self: *BonusPool) ?usize {
    for (self.entries, 0..) |entry, idx| {
        // Native bonus_alloc_slot tests only the id; linger fields may be stale.
        if (entry.bonus_id == .unused) return idx;
    }
    return null;
}

fn allocSlotOrSentinel(self: *BonusPool) AllocSlot {
    if (allocSlot(self)) |idx| {
        return .{ .index = idx };
    }
    return .sentinel;
}

fn slotPtr(self: *BonusPool, slot: AllocSlot) *BonusEntry {
    return switch (slot) {
        .sentinel => &self.sentinel,
        .index => |idx| &self.entries[idx],
    };
}

fn clearEntry(self: *BonusPool, entry: *BonusEntry) void {
    _ = self;
    entry.* = .{ .generation = entry.generation };
}

fn countMatches(self: *const BonusPool, bonus_id: BonusId) usize {
    var matches: usize = 0;
    for (self.entries) |entry| {
        if (entry.bonus_id == bonus_id) {
            matches += 1;
        }
    }
    return matches;
}

fn spawnAtPos(
    self: *BonusPool,
    pos: state_mod.Vec2,
    state: *state_mod.GameplayState,
    players: []const state_mod.PlayerState,
    world_size: f32,
) AllocSlot {
    if (state.game_mode == .rush) return .sentinel;
    if (pos.x < bonus_spawn_margin or pos.y < bonus_spawn_margin or
        pos.x > world_size - bonus_spawn_margin or pos.y > world_size - bonus_spawn_margin)
    {
        return .sentinel;
    }

    var slot = allocSlotOrSentinel(self);
    const bonus_id = bonusPickRandomType(self, state, players);

    for (self.entries) |active| {
        if (active.bonus_id == .unused) continue;
        const distance = native_math.pc24Hypot(
            native_math.pc24Sub(pos.x, active.pos.x),
            native_math.pc24Sub(pos.y, active.pos.y),
        );
        if (distance < bonus_spawn_min_distance) {
            slot = .sentinel;
            break;
        }
    }

    var entry = slotPtr(self, slot);
    entry.generation += 1;
    entry.bonus_id = bonus_id;
    entry.picked = false;
    entry.pos = pos;
    entry.time_left = narrowF32(bonus_time_max);
    entry.time_max = narrowF32(bonus_time_max);

    if (bonus_id == .weapon) {
        entry.amount = weapon_data.weaponIdToInt(weaponPickRandomAvailable(state));
    } else if (bonus_id == .points) {
        entry.amount = if ((state.rng.randTagged(rng_callers.bonus_spawn_at_pos_points_amount) & 7) < 3) 1000 else 500;
    } else {
        entry.amount = defaultBonusAmount(bonus_id);
    }

    return slot;
}

test "bonus spawn spacing uses native pc24 hypotenuse boundary" {
    var state = state_mod.GameplayState.init(1);
    var pool: BonusPool = .{};
    pool.entries[0].bonus_id = .points;
    pool.entries[0].pos = .{ .x = 100.0, .y = 100.0 };

    const slot = spawnAtPos(
        &pool,
        .{ .x = 123.16073417663574, .y = 122.08122253417969 },
        &state,
        &.{},
        1024.0,
    );

    try std.testing.expect(switch (slot) {
        .index => true,
        .sentinel => false,
    });
}

test "bonus pool spawn-on-kill can materialize weapon drop" {
    var state = state_mod.GameplayState.init(1234);
    state.game_mode = .survival;
    state.status_quest_unlock_index = 49;
    state.status_quest_unlock_index_full = 49;

    var pool: BonusPool = .{};
    var players = [_]state_mod.PlayerState{
        .{ .index = 0, .pos = .{ .x = 512.0, .y = 512.0 } },
    };
    player_runtime.weaponAssignPlayer(&players[0], game_ids.WeaponId.pistol);

    var spawned = false;
    for (0..512) |_| {
        if (pool.trySpawnOnKill(.{ .x = 420.0, .y = 420.0 }, &state, players[0..], 1024.0)) |_| {
            spawned = true;
            break;
        }
    }
    try std.testing.expect(spawned);
}

test "bonus spawn-on-kill is suppressed in typo rush and tutorial modes" {
    var players = [_]state_mod.PlayerState{
        .{ .index = 0, .pos = .{ .x = 256.0, .y = 256.0 } },
    };

    for ([_]GameModeId{ .typo, .rush, .tutorial }) |game_mode| {
        var state = state_mod.GameplayState.init(123);
        state.game_mode = game_mode;
        var pool: BonusPool = .{};
        const spawned = pool.trySpawnOnKill(
            .{ .x = 300.0, .y = 300.0 },
            &state,
            players[0..],
            1024.0,
        );
        try std.testing.expect(spawned == null);
    }
}

test "bonus update pre-pickup decrements timers" {
    var state = state_mod.GameplayState.init(1);
    state.bonuses.weapon_power_up = 2.0;
    state.bonuses.energizer = 2.0;
    state.bonuses.reflex_boost = 0.5;

    updatePrePickupTimers(&state, 0.1);

    try std.testing.expect(state.bonuses.weapon_power_up < 2.0);
    try std.testing.expect(state.bonuses.energizer < 2.0);
    try std.testing.expect(state.bonuses.reflex_boost < 0.5);
}

test "bonus pickup uses native pc24 radius boundary" {
    var state = state_mod.GameplayState.init(1);
    var pool: BonusPool = .{};
    pool.entries[0] = .{
        .bonus_id = .shield,
        .time_left = 1.0,
        .time_max = 1.0,
        .pos = .{},
    };
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{ .x = 25.999998092651367, .y = 0.009600000455975533 },
        },
    };
    var world: TestBonusWorld = .{};
    var pickups: BonusPickupBuffer = .{};

    try pool.update(&state, players[0..], world.step(0.01), &pickups);

    try std.testing.expectEqual(@as(usize, 0), pickups.len);
    try std.testing.expect(!pool.entries[0].picked);
    try std.testing.expectEqual(@as(f32, 0.0), players[0].shield_timer);
}

test "tutorial bonus seed overwrites its fixed slot with the native timer" {
    var pool: BonusPool = .{};
    pool.entries[1].bonus_id = .nuke;
    pool.entries[1].time_left = 7.0;

    const entry = pool.seedTutorialEntry(
        1,
        .{ .x = 600.0, .y = 400.0 },
        .points,
        1000,
    );

    try std.testing.expect(entry == &pool.entries[1]);
    try std.testing.expectEqual(BonusId.unused, pool.entries[0].bonus_id);
    try std.testing.expectEqual(BonusId.points, entry.bonus_id);
    try std.testing.expectApproxEqAbs(@as(f32, 100.0), entry.time_left, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 100.0), entry.time_max, 1e-6);
    try std.testing.expect(!entry.picked);
    try std.testing.expectEqual(@as(i32, 1000), entry.amount);
    try std.testing.expectApproxEqAbs(@as(f32, 600.0), entry.pos.x, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 400.0), entry.pos.y, 1e-6);
}

test "bonus spawn-on-kill rng cadence matches observed pistol path" {
    var state = state_mod.GameplayState.init(1);
    state.rng.state = 3_857_056_479;
    state.game_mode = .survival;
    state.status_quest_unlock_index = 49;
    state.status_quest_unlock_index_full = 50;
    state.status_weapon_usage_counts.set(.splitter_gun, 10);

    var pool: BonusPool = .{};
    var players = [_]state_mod.PlayerState{
        .{ .index = 0, .pos = .{ .x = 512.0, .y = 512.0 } },
    };
    player_runtime.weaponAssignPlayer(&players[0], game_ids.WeaponId.pistol);

    const spawned = pool.trySpawnOnKill(.{ .x = 420.0, .y = 420.0 }, &state, players[0..], 1024.0);
    try std.testing.expect(spawned != null);
    try std.testing.expectEqual(BonusId.weapon, spawned.?.bonus_id);
    try std.testing.expectEqual(@as(i32, 11), spawned.?.amount);
    try std.testing.expectEqual(@as(u32, 258_047_690), state.rng.state);
}

test "spawn-on-kill preserve bugs keeps native player slot policy" {
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{},
            .weapon = .{ .weapon_id = .assault_rifle },
        },
        .{
            .index = 1,
            .pos = .{},
            .weapon = .{ .weapon_id = .pistol },
        },
        .{
            .index = 2,
            .pos = .{},
            .weapon = .{ .weapon_id = .pistol },
        },
    };
    players[1].perk_counts.set(PerkId.my_favourite_weapon, 1);
    players[1].perk_counts.set(PerkId.bonus_magnet, 1);

    try std.testing.expect(anyPlayerHasPistol(players[0..]));
    try std.testing.expect(nativeForceDropHasPistol(players[0..2]));
    try std.testing.expect(!nativeForceDropHasPistol(players[0..]));
    try std.testing.expect(perkActiveByBugPolicy(players[0..], PerkId.my_favourite_weapon, false));
    try std.testing.expect(!perkActiveByBugPolicy(players[0..], PerkId.my_favourite_weapon, true));
    try std.testing.expect(perkActiveByBugPolicy(players[0..], PerkId.bonus_magnet, false));
    try std.testing.expect(!perkActiveByBugPolicy(players[0..], PerkId.bonus_magnet, true));
}

test "native forced weapon drop ignores player two favourite weapon" {
    var state = state_mod.GameplayState.init(1);
    state.preserve_bugs = true;
    state.rng.state = 3_857_056_479;
    state.game_mode = .survival;
    state.status_quest_unlock_index = 49;
    state.status_quest_unlock_index_full = 50;
    state.status_weapon_usage_counts.set(.splitter_gun, 10);

    var pool: BonusPool = .{};
    var players = [_]state_mod.PlayerState{
        .{ .index = 0, .pos = .{ .x = 512.0, .y = 512.0 } },
        .{
            .index = 1,
            .pos = .{ .x = 512.0, .y = 512.0 },
            .weapon = .{ .weapon_id = .assault_rifle },
        },
    };
    player_runtime.weaponAssignPlayer(&players[0], .pistol);
    players[1].perk_counts.set(PerkId.my_favourite_weapon, 1);

    const spawned = pool.trySpawnOnKill(
        .{ .x = 420.0, .y = 420.0 },
        &state,
        players[0..],
        1024.0,
    );

    try std.testing.expect(spawned != null);
    try std.testing.expectEqual(BonusId.weapon, spawned.?.bonus_id);
    try std.testing.expectEqual(@as(i32, 11), spawned.?.amount);
}

test "bonus economist extends double experience timer" {
    var base_state = state_mod.GameplayState.init(1);
    var base_player: state_mod.PlayerState = .{
        .index = 0,
        .pos = .{},
    };
    var base_players = [_]state_mod.PlayerState{base_player};
    try applyTestBonus(
        &base_state,
        &base_player,
        base_players[0..],
        .double_experience,
        10,
    );
    try std.testing.expectApproxEqAbs(@as(f32, 6.0), base_state.bonuses.double_experience, 1e-6);

    var perk_state = state_mod.GameplayState.init(1);
    var perk_player: state_mod.PlayerState = .{
        .index = 0,
        .pos = .{},
    };
    perk_player.perk_counts.set(PerkId.bonus_economist, 1);
    var perk_players = [_]state_mod.PlayerState{perk_player};
    try applyTestBonus(
        &perk_state,
        &perk_player,
        perk_players[0..],
        .double_experience,
        10,
    );
    try std.testing.expectApproxEqAbs(@as(f32, 9.0), perk_state.bonuses.double_experience, 1e-6);
}

test "bonus economist keeps native player zero ownership in bug mode" {
    var state = state_mod.GameplayState.init(1);
    state.preserve_bugs = true;
    var players = [_]state_mod.PlayerState{
        .{ .index = 0, .pos = .{} },
        .{ .index = 1, .pos = .{} },
    };
    players[0].perk_counts.set(PerkId.bonus_economist, 1);

    try applyTestBonus(
        &state,
        &players[1],
        players[0..],
        .double_experience,
        10,
    );
    try std.testing.expectApproxEqAbs(@as(f32, 9.0), state.bonuses.double_experience, 1e-6);

    state.bonuses.double_experience = 0.0;
    players[0].perk_counts.set(PerkId.bonus_economist, 0);
    players[1].perk_counts.set(PerkId.bonus_economist, 1);
    try applyTestBonus(
        &state,
        &players[1],
        players[0..],
        .double_experience,
        10,
    );
    try std.testing.expectApproxEqAbs(@as(f32, 6.0), state.bonuses.double_experience, 1e-6);
}

test "bonus economist keeps pickup owner in corrected mode" {
    var state = state_mod.GameplayState.init(1);
    var players = [_]state_mod.PlayerState{
        .{ .index = 0, .pos = .{} },
        .{ .index = 1, .pos = .{} },
    };
    players[1].perk_counts.set(PerkId.bonus_economist, 1);

    try applyTestBonus(
        &state,
        &players[1],
        players[0..],
        .double_experience,
        10,
    );
    try std.testing.expectApproxEqAbs(@as(f32, 9.0), state.bonuses.double_experience, 1e-6);
}

test "alternate weapon starts with preloaded pistol alt slot" {
    var state = state_mod.GameplayState.init(1);
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{},
        },
    };
    player_runtime.resetPlayers(players[0..], 1024.0, null);
    const player = &players[0];
    player.perk_counts.set(PerkId.alternate_weapon, 1);

    try applyTestBonus(
        &state,
        player,
        players[0..],
        .weapon,
        @intFromEnum(game_ids.WeaponId.assault_rifle),
    );

    try std.testing.expectEqual(game_ids.WeaponId.assault_rifle, player.weapon.weapon_id);
    try std.testing.expect(player.alt_weapon != null);
    try std.testing.expectEqual(game_ids.WeaponId.pistol, player.alt_weapon.?.weapon_id);
    try std.testing.expectEqual(@as(i32, 12), player.alt_weapon.?.clip_size);
}

test "bonus magnet allows spawn on secondary roll" {
    var base_state = state_mod.GameplayState.init(7);
    base_state.game_mode = .survival;
    var base_pool: BonusPool = .{};
    var base_players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{},
            .weapon = .{ .weapon_id = game_ids.WeaponId.assault_rifle },
        },
    };

    const base_spawned = base_pool.trySpawnOnKill(
        .{ .x = 100.0, .y = 100.0 },
        &base_state,
        base_players[0..],
        1024.0,
    );
    try std.testing.expect(base_spawned == null);

    var perk_state = state_mod.GameplayState.init(7);
    perk_state.game_mode = .survival;
    var perk_pool: BonusPool = .{};
    var perk_players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{},
            .weapon = .{ .weapon_id = game_ids.WeaponId.assault_rifle },
        },
    };
    perk_players[0].perk_counts.set(PerkId.bonus_magnet, 1);

    const perk_spawned = perk_pool.trySpawnOnKill(
        .{ .x = 100.0, .y = 100.0 },
        &perk_state,
        perk_players[0..],
        1024.0,
    );
    try std.testing.expect(perk_spawned != null);

    var native_state = state_mod.GameplayState.init(7);
    native_state.game_mode = .survival;
    native_state.preserve_bugs = true;
    var native_pool: BonusPool = .{};
    var native_players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{},
            .weapon = .{ .weapon_id = game_ids.WeaponId.assault_rifle },
        },
        .{
            .index = 1,
            .pos = .{},
            .weapon = .{ .weapon_id = game_ids.WeaponId.assault_rifle },
        },
    };
    native_players[1].perk_counts.set(PerkId.bonus_magnet, 1);

    const native_spawned = native_pool.trySpawnOnKill(
        .{ .x = 100.0, .y = 100.0 },
        &native_state,
        native_players[0..],
        1024.0,
    );
    try std.testing.expect(native_spawned == null);
}

test "bonus pick random type quest suppression parity" {
    const suppression_seed: u32 = 282_697;

    try runQuestSuppressionCase(
        suppression_seed,
        false,
        2,
        10,
        .freeze,
    );
    try runQuestSuppressionCase(
        suppression_seed,
        true,
        2,
        10,
        .points,
    );
    try runQuestSuppressionCase(
        suppression_seed,
        false,
        4,
        10,
        .points,
    );
    try runQuestSuppressionCase(
        suppression_seed,
        false,
        5,
        10,
        .freeze,
    );
    try runQuestSuppressionCase(
        suppression_seed,
        true,
        3,
        10,
        .freeze,
    );
}

test "bonus suppression keeps native player slot asymmetry" {
    var state = state_mod.GameplayState.init(1);
    var players = [_]state_mod.PlayerState{
        .{ .index = 0, .pos = .{} },
        .{ .index = 1, .pos = .{} },
        .{ .index = 2, .pos = .{}, .shield_timer = 1.0 },
    };

    players[1].perk_counts.set(PerkId.my_favourite_weapon, 1);
    players[1].perk_counts.set(PerkId.death_clock, 1);
    try std.testing.expect(!bonusPickSuppressed(&state, players[0..], .weapon, false));
    try std.testing.expect(!bonusPickSuppressed(&state, players[0..], .medikit, false));
    try std.testing.expect(!bonusPickSuppressed(&state, players[0..], .shield, false));

    players[0].perk_counts.set(PerkId.my_favourite_weapon, 1);
    players[0].perk_counts.set(PerkId.death_clock, 1);
    try std.testing.expect(bonusPickSuppressed(&state, players[0..], .weapon, false));
    try std.testing.expect(bonusPickSuppressed(&state, players[0..], .medikit, false));

    players[1].shield_timer = 1.0;
    try std.testing.expect(bonusPickSuppressed(&state, players[0..], .shield, false));
}

test "weapon refresh available includes survival defaults" {
    var state = state_mod.GameplayState.init(1);
    state.game_mode = .survival;

    weaponRefreshAvailable(&state);

    try std.testing.expect(state.weapon_available.get(.pistol));
    try std.testing.expect(state.weapon_available.get(.assault_rifle));
    try std.testing.expect(state.weapon_available.get(.shotgun));
    try std.testing.expect(state.weapon_available.get(.submachine_gun));
    try std.testing.expect(!state.weapon_available.get(.flamethrower));
}

test "weapon refresh available unlocks quest weapon ids by unlock index" {
    var state = state_mod.GameplayState.init(1);
    state.game_mode = .quests;
    state.status_quest_unlock_index = 1;
    state.status_quest_unlock_index_full = 0;

    weaponRefreshAvailable(&state);

    try std.testing.expect(state.weapon_available.get(.pistol));
    try std.testing.expect(state.weapon_available.get(.assault_rifle));
    try std.testing.expect(!state.weapon_available.get(.shotgun));
}

test "weapon refresh available uses the full version unlock index outside quests" {
    var state = state_mod.GameplayState.init(1);
    state.status_quest_unlock_index_full = 0x28;

    weaponRefreshAvailable(&state);

    try std.testing.expect(state.weapon_available.get(.splitter_gun));
}

test "weapon pick random available enforces unlock table in quests" {
    var state = state_mod.GameplayState.init(1);
    state.game_mode = .quests;
    state.status_quest_unlock_index = 0;
    state.status_quest_unlock_index_full = 0;

    const picked = weaponPickRandomAvailable(&state);
    try std.testing.expectEqual(game_ids.WeaponId.pistol, picked);
}

test "quest unlock weapon lookup exposes exact reward table rows" {
    try std.testing.expectEqual(game_ids.WeaponId.assault_rifle, questUnlockWeaponForIndex(0).?);
    try std.testing.expectEqual(game_ids.WeaponId.ion_shotgun, questUnlockWeaponForIndex(40).?);
    try std.testing.expectEqual(@as(?game_ids.WeaponId, null), questUnlockWeaponForIndex(2));
    try std.testing.expectEqual(@as(?game_ids.WeaponId, null), questUnlockWeaponForIndex(-1));
    try std.testing.expectEqual(@as(?game_ids.WeaponId, null), questUnlockWeaponForIndex(50));
}

test "weapon pick random available rerolls used weapons on even gate" {
    // CRT rand draws 4917, 9518, 4390: pistol, even reroll gate,
    // then assault rifle.
    const seed: u32 = 1494;
    var state = state_mod.GameplayState.init(seed);
    state.game_mode = .quests;
    state.status_quest_unlock_index = 1;
    state.status_quest_unlock_index_full = 0;
    state.status_weapon_usage_counts.set(.pistol, 1);

    const picked = weaponPickRandomAvailable(&state);
    try std.testing.expectEqual(game_ids.WeaponId.assault_rifle, picked);
}
fn setTestBonusEntry(
    pool: *BonusPool,
    idx: usize,
    bonus_id: BonusId,
    pos: state_mod.Vec2,
    amount: i32,
) void {
    pool.entries[idx] = .{
        .bonus_id = bonus_id,
        .picked = false,
        .time_left = narrowF32(bonus_time_max),
        .time_max = narrowF32(bonus_time_max),
        .pos = pos,
        .amount = amount,
    };
}

const TestBonusWorld = struct {
    creatures: creatures_mod.CreaturePool = .{},
    projectiles: projectiles_mod.ProjectilePool = .{},
    effects: effects_mod.EffectPool = .{},
    terrain_fx: terrain_fx_mod.TerrainFxScratch = .{},

    fn step(self: *TestBonusWorld, dt: f32) BonusStep {
        self.creatures.effects = &self.effects;
        return .{
            .creatures = &self.creatures,
            .projectiles = &self.projectiles,
            .effects = &self.effects,
            .terrain_fx = &self.terrain_fx,
            .dt = dt,
            .world_size = 1024.0,
            .detail_preset = 5,
        };
    }

    fn activeProjectileCount(self: *const TestBonusWorld, type_id: game_ids.ProjectileTypeId) usize {
        var count: usize = 0;
        for (self.projectiles.entries) |entry| {
            if (entry.active and entry.type_id == @intFromEnum(type_id)) count += 1;
        }
        return count;
    }
};

fn applyTestBonus(
    state: *state_mod.GameplayState,
    player: *state_mod.PlayerState,
    players: []state_mod.PlayerState,
    bonus_id: BonusId,
    amount: i32,
) !void {
    var world: TestBonusWorld = .{};
    var pool: BonusPool = .{};
    try applyBonus(state, &pool, world.step(0.016), player, players, bonus_id, amount, player.pos);
}

fn runTelekineticUpdate(
    pool: *BonusPool,
    state: *state_mod.GameplayState,
    players: []state_mod.PlayerState,
    dt: f32,
) BonusRuntimeError!void {
    var world: TestBonusWorld = .{};
    try telekineticUpdate(pool, state, players, world.step(dt), null);
}

test "telekinetic picks up bonus after hover timer threshold" {
    var state = state_mod.GameplayState.init(1);
    var pool: BonusPool = .{};
    setTestBonusEntry(
        &pool,
        0,
        .points,
        .{ .x = 100.0, .y = 100.0 },
        500,
    );

    const base_player: state_mod.PlayerState = .{
        .index = 0,
        .pos = .{},
        .health = 100.0,
        .aim = .{ .x = 100.0, .y = 100.0 },
    };
    var base_players = [_]state_mod.PlayerState{base_player};
    try runTelekineticUpdate(&pool, &state, base_players[0..], 0.7);
    try std.testing.expect(!pool.entries[0].picked);

    var perk_player: state_mod.PlayerState = .{
        .index = 0,
        .pos = .{},
        .health = 100.0,
        .aim = .{ .x = 100.0, .y = 100.0 },
    };
    perk_player.perk_counts.set(PerkId.telekinetic, 1);
    var perk_players = [_]state_mod.PlayerState{perk_player};
    try runTelekineticUpdate(&pool, &state, perk_players[0..], 0.7);

    try std.testing.expect(pool.entries[0].picked);
    try std.testing.expectEqual(@as(i32, 500), perk_players[0].experience);
}

test "telekinetic hover timer accumulates whole frame milliseconds" {
    var state = state_mod.GameplayState.init(1);
    var pool: BonusPool = .{};
    setTestBonusEntry(&pool, 0, .points, .{ .x = 100.0, .y = 100.0 }, 0);
    var player: state_mod.PlayerState = .{
        .index = 0,
        .pos = .{},
        .health = 100.0,
        .aim = .{ .x = 100.0, .y = 100.0 },
    };
    player.perk_counts.set(PerkId.telekinetic, 1);
    var players = [_]state_mod.PlayerState{player};

    // 60 Hz frames add __ftol(16.67) = 16 ms, so the > 650 ms gate passes on
    // frame 41 (656 ms), not frame 39 as with fractional milliseconds.
    for (0..40) |_| {
        try runTelekineticUpdate(&pool, &state, players[0..], 1.0 / 60.0);
    }
    try std.testing.expect(!pool.entries[0].picked);
    try std.testing.expectEqual(@as(f32, 640.0), players[0].bonus_aim_hover_timer_ms);
    try runTelekineticUpdate(&pool, &state, players[0..], 1.0 / 60.0);
    try std.testing.expect(pool.entries[0].picked);
}

test "telekinetic keeps native player zero ownership in bug mode" {
    var state = state_mod.GameplayState.init(1);
    state.preserve_bugs = true;
    var pool: BonusPool = .{};
    setTestBonusEntry(
        &pool,
        0,
        .points,
        .{ .x = 100.0, .y = 100.0 },
        500,
    );

    var players = [_]state_mod.PlayerState{
        .{ .index = 0, .pos = .{}, .health = 100.0, .aim = .{} },
        .{ .index = 1, .pos = .{}, .health = 100.0, .aim = .{ .x = 100.0, .y = 100.0 } },
    };
    players[0].perk_counts.set(PerkId.telekinetic, 1);

    try runTelekineticUpdate(&pool, &state, players[0..], 0.7);

    try std.testing.expect(pool.entries[0].picked);
    try std.testing.expectEqual(@as(i32, 500), players[0].experience);
    try std.testing.expectEqual(@as(i32, 0), players[1].experience);
}

test "telekinetic ignores secondary player perk in bug mode" {
    var state = state_mod.GameplayState.init(1);
    state.preserve_bugs = true;
    var pool: BonusPool = .{};
    setTestBonusEntry(
        &pool,
        0,
        .points,
        .{ .x = 100.0, .y = 100.0 },
        500,
    );

    var players = [_]state_mod.PlayerState{
        .{ .index = 0, .pos = .{}, .health = 100.0, .aim = .{} },
        .{ .index = 1, .pos = .{}, .health = 100.0, .aim = .{ .x = 100.0, .y = 100.0 } },
    };
    players[1].perk_counts.set(PerkId.telekinetic, 1);

    try runTelekineticUpdate(&pool, &state, players[0..], 0.7);

    try std.testing.expect(!pool.entries[0].picked);
    try std.testing.expectEqual(@as(i32, 0), players[1].experience);
}

test "telekinetic keeps secondary player ownership in corrected mode" {
    var state = state_mod.GameplayState.init(1);
    var pool: BonusPool = .{};
    setTestBonusEntry(
        &pool,
        0,
        .points,
        .{ .x = 100.0, .y = 100.0 },
        500,
    );

    var players = [_]state_mod.PlayerState{
        .{ .index = 0, .pos = .{}, .health = 100.0, .aim = .{} },
        .{ .index = 1, .pos = .{}, .health = 100.0, .aim = .{ .x = 100.0, .y = 100.0 } },
    };
    players[1].perk_counts.set(PerkId.telekinetic, 1);

    try runTelekineticUpdate(&pool, &state, players[0..], 0.7);

    try std.testing.expect(pool.entries[0].picked);
    try std.testing.expectEqual(@as(i32, 500), players[0].experience);
    try std.testing.expectEqual(@as(i32, 0), players[1].experience);
}

test "telekinetic nuke detonates inline at the bonus position" {
    var state = state_mod.GameplayState.init(1);
    var pool: BonusPool = .{};
    setTestBonusEntry(&pool, 0, .nuke, .{ .x = 100.0, .y = 100.0 }, 1);

    var player: state_mod.PlayerState = .{
        .index = 0,
        .pos = .{},
        .health = 100.0,
        .aim = .{ .x = 100.0, .y = 100.0 },
    };
    player.perk_counts.set(PerkId.telekinetic, 1);
    var players = [_]state_mod.PlayerState{player};

    var world: TestBonusWorld = .{};
    try telekineticUpdate(&pool, &state, players[0..], world.step(0.7), null);
    try std.testing.expect(pool.entries[0].picked);
    try std.testing.expectEqual(@as(usize, 2), world.activeProjectileCount(.gauss_gun));
    for (world.projectiles.entries) |entry| {
        if (!entry.active) continue;
        try std.testing.expectEqual(@as(f32, 100.0), entry.origin.x);
        try std.testing.expectEqual(@as(f32, 100.0), entry.origin.y);
    }
}

test "telekinetic picks only one bonus per frame across players" {
    var state = state_mod.GameplayState.init(1);
    var pool: BonusPool = .{};
    setTestBonusEntry(
        &pool,
        0,
        .points,
        .{ .x = 100.0, .y = 100.0 },
        500,
    );
    setTestBonusEntry(
        &pool,
        1,
        .points,
        .{ .x = 200.0, .y = 200.0 },
        500,
    );

    var player0: state_mod.PlayerState = .{
        .index = 0,
        .pos = .{},
        .health = 100.0,
        .aim = .{ .x = 100.0, .y = 100.0 },
    };
    var player1: state_mod.PlayerState = .{
        .index = 1,
        .pos = .{},
        .health = 100.0,
        .aim = .{ .x = 200.0, .y = 200.0 },
    };
    player0.perk_counts.set(PerkId.telekinetic, 1);
    player1.perk_counts.set(PerkId.telekinetic, 1);
    var players = [_]state_mod.PlayerState{ player0, player1 };

    try runTelekineticUpdate(&pool, &state, players[0..], 0.7);
    try std.testing.expect(pool.entries[0].picked);
    try std.testing.expect(!pool.entries[1].picked);
    try std.testing.expectEqual(@as(i32, 500), players[0].experience);
    try std.testing.expectEqual(@as(i32, 0), players[1].experience);
}

test "telekinetic hover timer carries across bonus switch" {
    var state = state_mod.GameplayState.init(1);
    var pool: BonusPool = .{};
    setTestBonusEntry(
        &pool,
        0,
        .points,
        .{ .x = 100.0, .y = 100.0 },
        500,
    );
    setTestBonusEntry(
        &pool,
        1,
        .points,
        .{ .x = 130.0, .y = 100.0 },
        500,
    );

    var player: state_mod.PlayerState = .{
        .index = 0,
        .pos = .{},
        .health = 100.0,
        .aim = .{ .x = 100.0, .y = 100.0 },
    };
    player.perk_counts.set(PerkId.telekinetic, 1);
    var players = [_]state_mod.PlayerState{player};

    try runTelekineticUpdate(&pool, &state, players[0..], 0.4);
    try std.testing.expect(!pool.entries[0].picked);
    try std.testing.expect(!pool.entries[1].picked);

    players[0].aim = .{ .x = 130.0, .y = 100.0 };
    try runTelekineticUpdate(&pool, &state, players[0..], 0.3);

    try std.testing.expect(!pool.entries[0].picked);
    try std.testing.expect(pool.entries[1].picked);
    try std.testing.expectEqual(@as(i32, -1), players[0].bonus_aim_hover_index);
    try std.testing.expectApproxEqAbs(@as(f32, 0.0), players[0].bonus_aim_hover_timer_ms, 1e-6);
}

fn runQuestSuppressionCase(
    seed: u32,
    hardcore: bool,
    quest_stage_major: i32,
    quest_stage_minor: i32,
    expected_bonus_id: BonusId,
) !void {
    var state = state_mod.GameplayState.init(seed);
    state.game_mode = .quests;
    state.hardcore = hardcore;
    state.quest_stage_major = quest_stage_major;
    state.quest_stage_minor = quest_stage_minor;

    var pool: BonusPool = .{};
    var players = [_]state_mod.PlayerState{
        .{ .index = 0, .pos = .{} },
    };

    const bonus_id = bonusPickRandomType(&pool, &state, players[0..]);
    try std.testing.expectEqual(expected_bonus_id, bonus_id);
}

test "fireblast spawns sixteen plasma rifle projectiles owned by the picker under friendly fire" {
    var state = state_mod.GameplayState.init(1);
    state.friendly_fire_enabled = true;
    var players = [_]state_mod.PlayerState{
        .{ .index = 0, .pos = .{} },
        .{ .index = 1, .pos = .{ .x = 512.0, .y = 512.0 } },
    };
    var world: TestBonusWorld = .{};
    var pool: BonusPool = .{};

    try applyBonus(&state, &pool, world.step(0.016), &players[1], players[0..], .fireblast, 1, players[1].pos);

    try std.testing.expectEqual(@as(usize, 16), world.activeProjectileCount(.plasma_rifle));
    for (world.projectiles.entries) |entry| {
        if (!entry.active) continue;
        try std.testing.expectEqual(owner_id_mod.playerOwnerId(1), entry.owner_id);
    }
    try std.testing.expectEqual(@as(i32, 0), state.shots_fired);
    try std.testing.expect(!state.bonus_spawn_guard);
}

test "shock chain targets the nearest live creature and clears the native guard" {
    var state = state_mod.GameplayState.init(1);
    var players = [_]state_mod.PlayerState{
        .{ .index = 0, .pos = .{ .x = 512.0, .y = 512.0 } },
    };
    var world: TestBonusWorld = .{};
    var pool: BonusPool = .{};
    world.creatures.entries[0] = .{ .active = true, .pos = .{ .x = 700.0, .y = 512.0 }, .hp = 100.0 };
    world.creatures.entries[1] = .{ .active = true, .pos = .{ .x = 600.0, .y = 512.0 }, .hp = 100.0 };
    world.creatures.entries[2] = .{ .active = true, .pos = .{ .x = 520.0, .y = 512.0 }, .hp = 0.0, .lifecycle_stage = 5.0 };

    try applyBonus(&state, &pool, world.step(0.016), &players[0], players[0..], .shock_chain, 1, players[0].pos);

    const projectile_id: usize = @intCast(state.shock_chain_projectile_id);
    const projectile = world.projectiles.entries[projectile_id];
    try std.testing.expect(projectile.active);
    try std.testing.expectEqual(@intFromEnum(game_ids.ProjectileTypeId.ion_rifle), projectile.type_id);
    try std.testing.expectEqual(
        projectiles_mod.chainAngleFromDelta(.{ .x = 88.0, .y = 0.0 }),
        projectile.angle,
    );
    try std.testing.expectEqual(@as(i32, 0x20), state.shock_chain_links_left);
    try std.testing.expect(!state.bonus_spawn_guard);
}

test "nuke spawns pistol and gauss projectiles and credits the picker's shots" {
    var state = state_mod.GameplayState.init(1);
    var players = [_]state_mod.PlayerState{
        .{ .index = 0, .pos = .{} },
        .{ .index = 1, .pos = .{ .x = 512.0, .y = 512.0 } },
    };
    var world: TestBonusWorld = .{};
    var pool: BonusPool = .{};

    try applyBonus(&state, &pool, world.step(0.016), &players[1], players[0..], .nuke, 1, players[1].pos);

    const pistol_count = world.activeProjectileCount(.pistol);
    try std.testing.expect(pistol_count >= 4 and pistol_count <= 7);
    try std.testing.expectEqual(@as(usize, 2), world.activeProjectileCount(.gauss_gun));
    for (world.projectiles.entries) |entry| {
        if (!entry.active) continue;
        try std.testing.expectEqual(owner_id_mod.owner_local_player, entry.owner_id);
        if (entry.type_id == @intFromEnum(game_ids.ProjectileTypeId.pistol)) {
            try std.testing.expectApproxEqAbs(@as(f32, 55.0), entry.travel_budget, 1e-6);
            try std.testing.expect(entry.speed_scale >= 0.5 and entry.speed_scale < 1.0);
        } else {
            try std.testing.expectApproxEqAbs(@as(f32, 215.0), entry.travel_budget, 1e-6);
            try std.testing.expectEqual(@as(f32, 1.0), entry.speed_scale);
        }
    }
    const shots: i32 = @intCast(pistol_count + 2);
    try std.testing.expectEqual(shots, state.shots_fired);
    try std.testing.expect(!state.bonus_spawn_guard);
}

test "nuke then freeze in one pickup pass shatters the nuke's kill" {
    // Mirrors the Python port driving `bonus_update` over the same state
    // (seed 0x1234, Nuke slot 0, Freeze slot 1, dt 0.016).
    var state = state_mod.GameplayState.init(0x1234);
    var players = [_]state_mod.PlayerState{
        .{ .index = 0, .pos = .{ .x = 512.0, .y = 512.0 }, .health = 100.0 },
    };
    var world: TestBonusWorld = .{};
    var pool: BonusPool = .{};
    world.creatures.entries[0] = .{ .active = true, .pos = .{ .x = 600.0, .y = 512.0 }, .hp = 10.0, .max_hp = 10.0, .size = 50.0 };
    world.creatures.entries[1] = .{ .active = true, .pos = .{ .x = 400.0, .y = 512.0 }, .hp = 0.0, .size = 50.0, .lifecycle_stage = 5.0 };
    setTestBonusEntry(&pool, 0, .nuke, .{ .x = 512.0, .y = 512.0 }, 1);
    setTestBonusEntry(&pool, 1, .freeze, .{ .x = 520.0, .y = 512.0 }, 5);

    var pickups: BonusPickupBuffer = .{};
    try bonusUpdate(&pool, &state, players[0..], world.step(0.016), &pickups);

    try std.testing.expectEqual(@as(usize, 2), pickups.len);
    try std.testing.expect(!world.creatures.entries[0].active);
    try std.testing.expect(!world.creatures.entries[1].active);
    try std.testing.expectEqual(@as(f32, -830.0), world.creatures.entries[0].hp);
    try std.testing.expectEqual(@as(f32, 4.984000205993652), state.bonuses.freeze);
    try std.testing.expectEqual(@as(i32, 6), state.shots_fired);
    try std.testing.expectEqual(@as(u32, 0x40db2b34), state.rng.state);
}

test "pending creature projectile queue materializes hostile shots before projectile step" {
    var state = state_mod.GameplayState.init(1);
    var projectiles: projectiles_mod.ProjectilePool = .{};

    state.pending_creature_projectile_count = 1;
    state.pending_creature_projectiles[0] = .{
        .type_id = @intFromEnum(game_ids.ProjectileTypeId.plasma_rifle),
        .owner_id = 17,
        .angle = std.math.pi / 2.0,
        .pos = .{ .x = 100.0, .y = 200.0 },
    };

    applyPendingCreatureProjectiles(&state, &projectiles);

    try std.testing.expectEqual(@as(i32, 0), state.pending_creature_projectile_count);
    try std.testing.expect(projectiles.entries[0].active);
    try std.testing.expectEqual(@intFromEnum(game_ids.ProjectileTypeId.plasma_rifle), projectiles.entries[0].type_id);
    try std.testing.expectEqual(@as(i32, 17), projectiles.entries[0].owner_id);
    try std.testing.expectApproxEqAbs(@as(f32, 100.0), projectiles.entries[0].pos.x, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 200.0), projectiles.entries[0].pos.y, 1e-6);
}

test "Freeze shatters every current active corpse regardless of lifecycle" {
    var state = state_mod.GameplayState.init(1);
    var players = [_]state_mod.PlayerState{.{ .index = 0, .pos = .{} }};
    var world: TestBonusWorld = .{};
    var pool: BonusPool = .{};
    world.creatures.entries[0].active = true;
    world.creatures.entries[0].hp = 0.0;
    world.creatures.entries[1].active = true;
    world.creatures.entries[1].hp = -1.0;
    world.creatures.entries[1].lifecycle_stage = -100.0;
    world.creatures.entries[2].active = true;
    world.creatures.entries[2].hp = 10.0;
    try applyBonus(&state, &pool, world.step(0.016), &players[0], players[0..], .freeze, 5, players[0].pos);
    try std.testing.expect(!world.creatures.entries[0].active);
    try std.testing.expect(!world.creatures.entries[1].active);
    try std.testing.expect(world.creatures.entries[2].active);
    // Two corpses of 16 shard/shatter effects, the ring and the pickup burst.
    try std.testing.expectEqual(@as(usize, 2 * 16 + 1 + 12), world.effects.entries.len - world.effects.free_len);
}
