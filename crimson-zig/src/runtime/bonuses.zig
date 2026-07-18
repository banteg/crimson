const std = @import("std");
const game_ids = @import("../game_ids.zig");
const native_math = @import("native_math.zig");

const creature_lifecycle = @import("lifecycle.zig").CreatureLifecycle;
const creatures_mod = @import("creatures.zig");
const effects_mod = @import("effects.zig");
const owner_ref = @import("owner_ref.zig");
const perks = @import("perks.zig");
const player_runtime = @import("player.zig");
const projectiles_mod = @import("projectiles.zig");
const rng_callers = @import("../rng_caller_static.zig");
const state_mod = @import("state.zig");
const terrain_fx_mod = @import("terrain_fx.zig");
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
        if (state.demo_mode_active) return null;
        if (state.game_mode == .rush or state.game_mode == .typo or state.game_mode == .tutorial) return null;
        if (state.bonus_spawn_guard) return null;
        if (players.len == 0) return null;

        var has_pistol = false;
        for (players) |player| {
            if (player.weapon.weapon_id == game_ids.WeaponId.pistol) {
                has_pistol = true;
                break;
            }
        }

        if (has_pistol and (state.rng.randTagged(rng_callers.bonus_try_spawn_on_kill_pistol_force_weapon) & 3) < 3) {
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

            if (entry.amount == weapon_data.weaponIdToInt(.pistol) or anyPerkActive(players, PerkId.my_favourite_weapon)) {
                clearEntry(self, entry);
                return null;
            }

            if (slot == .sentinel) return null;
            return entry;
        }

        const base_roll = state.rng.randTagged(rng_callers.bonus_try_spawn_on_kill_base_gate);
        if ((base_roll % 9) != 1) {
            var allow_without_magnet = false;
            if (has_pistol) {
                allow_without_magnet = (state.rng.randTagged(rng_callers.bonus_try_spawn_on_kill_pistol_allow_without_magnet) % 5) == 1;
            }
            if (!allow_without_magnet) {
                if (!anyPerkActive(players, PerkId.bonus_magnet)) {
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
        entry.bonus_id = bonus_id;
        entry.picked = false;
        entry.pos = clamped_pos;
        entry.time_left = narrowF32(bonus_time_max);
        entry.time_max = narrowF32(bonus_time_max);
        entry.amount = if (duration_override == -1) defaultBonusAmount(bonus_id) else duration_override;

        return if (slot == .sentinel) null else entry;
    }

    pub fn update(
        self: *BonusPool,
        state: *state_mod.GameplayState,
        players: []state_mod.PlayerState,
        dt: f32,
        pickup_bonus_ids: *[bonus_pool_size]BonusId,
        pickup_count: *usize,
        pickup_records: ?*BonusPickupBuffer,
    ) BonusRuntimeError!void {
        if (!(dt > 0.0)) return;

        const pickup_sq = bonus_pickup_radius * bonus_pickup_radius;

        for (&self.entries) |*entry| {
            if (isEmpty(entry.*)) continue;

            const decay = dt * (if (entry.picked) bonus_pickup_decay_rate else 1.0);
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
                if (distanceSq(entry.pos, player.pos) >= pickup_sq) continue;

                try applyBonus(state, player, players, entry.bonus_id, entry.amount, entry.pos);
                appendPickupBonusId(pickup_bonus_ids, pickup_count, entry.bonus_id);
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

pub fn bonusUpdate(
    pool: *BonusPool,
    state: *state_mod.GameplayState,
    players: []state_mod.PlayerState,
    dt: f32,
    pickup_records: ?*BonusPickupBuffer,
) BonusRuntimeError!void {
    if (pickup_records) |records| records.* = BonusPickupBuffer{};

    var pickup_bonus_ids = [_]BonusId{.unused} ** bonus_pool_size;
    var pickup_count: usize = 0;

    try bonusTelekineticUpdate(pool, state, players, dt, &pickup_bonus_ids, &pickup_count, pickup_records);
    try pool.update(state, players, dt, &pickup_bonus_ids, &pickup_count, pickup_records);

    if (dt > 0.0) {
        if (state.bonuses.double_experience <= 0.0) {
            state.bonuses.double_experience = 0.0;
        } else {
            state.bonuses.double_experience -= dt;
        }

        if (state.bonuses.freeze <= 0.0) {
            state.bonuses.freeze = 0.0;
        } else {
            state.bonuses.freeze -= dt;
        }
    }
}

pub fn applyPendingBonusEffects(
    state: *state_mod.GameplayState,
    players: []state_mod.PlayerState,
    projectiles: *projectiles_mod.ProjectilePool,
    creatures: *creatures_mod.CreaturePool,
    bonuses: *BonusPool,
    terrain_fx: *terrain_fx_mod.TerrainFxScratch,
    dt: f32,
    world_size: f32,
) void {
    var effects: effects_mod.EffectPool = .{};
    applyPendingBonusEffectsWithEffects(
        state,
        players,
        projectiles,
        creatures,
        bonuses,
        &effects,
        terrain_fx,
        dt,
        world_size,
    );
}

pub fn applyPendingBonusEffectsWithEffects(
    state: *state_mod.GameplayState,
    players: []state_mod.PlayerState,
    projectiles: *projectiles_mod.ProjectilePool,
    creatures: *creatures_mod.CreaturePool,
    bonuses: *BonusPool,
    effects: *effects_mod.EffectPool,
    terrain_fx: *terrain_fx_mod.TerrainFxScratch,
    dt: f32,
    world_size: f32,
) void {
    const pending_fireblast_count_i32 = @min(state.pending_fireblast_count, @as(i32, @intCast(state.pending_fireblast_origins.len)));
    var pending_fireblast_idx: i32 = 0;
    while (pending_fireblast_idx < pending_fireblast_count_i32) : (pending_fireblast_idx += 1) {
        const origin = state.pending_fireblast_origins[@intCast(pending_fireblast_idx)];
        applyFireblastBonus(state, projectiles, origin);
    }
    state.pending_fireblast_count = 0;

    const pending_shock_chain_count_i32 = @min(state.pending_shock_chain_count, @as(i32, @intCast(state.pending_shock_chain_origins.len)));
    var pending_shock_chain_idx: i32 = 0;
    while (pending_shock_chain_idx < pending_shock_chain_count_i32) : (pending_shock_chain_idx += 1) {
        const origin = state.pending_shock_chain_origins[@intCast(pending_shock_chain_idx)];
        applyShockChainBonus(state, projectiles, creatures, origin);
    }
    state.pending_shock_chain_count = 0;

    const pending_count_i32 = @min(state.pending_nuke_count, @as(i32, @intCast(state.pending_nuke_origins.len)));
    var pending_idx: i32 = 0;
    while (pending_idx < pending_count_i32) : (pending_idx += 1) {
        const origin = state.pending_nuke_origins[@intCast(pending_idx)];
        applyNukeBonus(
            state,
            players,
            projectiles,
            creatures,
            bonuses,
            effects,
            terrain_fx,
            origin,
            dt,
            world_size,
        );
    }
    state.pending_nuke_count = 0;
}

pub fn emitBonusPickupEffects(
    state: *state_mod.GameplayState,
    pickups: []const BonusPickupRecord,
    effects: *effects_mod.EffectPool,
    detail_preset: i32,
) void {
    for (pickups) |pickup| {
        if (pickup.bonus_id != .nuke) {
            effects.spawnBurstWithCallers(
                state,
                pickup.pos,
                12,
                detail_preset,
                0.4,
                0.1,
                .{ .r = 0.4, .g = 0.5, .b = 1.0, .a = 0.5 },
                effects_mod.EffectPool.bonus_pickup_burst_callers,
            );
        }
        switch (pickup.bonus_id) {
            .reflex_boost => effects.spawnRing(
                pickup.pos,
                detail_preset,
                .{ .r = 0.6, .g = 0.6, .b = 1.0, .a = 1.0 },
                1.0,
                45.0,
            ),
            .freeze => effects.spawnRing(
                pickup.pos,
                detail_preset,
                .{ .r = 0.3, .g = 0.5, .b = 0.8, .a = 1.0 },
                1.0,
                45.0,
            ),
            else => {},
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
        _ = projectiles.spawn(pending.pos, narrowF32(pending.angle), type_id, pending.owner, meta, true);
    }
    state.pending_creature_projectile_count = 0;
}

pub fn applyFreezePickupCorpseEffects(
    state: *state_mod.GameplayState,
    creatures: *creatures_mod.CreaturePool,
    effects: *effects_mod.EffectPool,
    detail_preset: i32,
    freeze_corpse_at_tick_start: []const bool,
) void {
    for (&creatures.entries, 0..) |*creature, idx| {
        if (!creature.active) continue;
        if (creature.hp > 0.0) continue;

        if (creature_lifecycle.isDespawned(creature.lifecycle_stage)) {
            creature.active = false;
            continue;
        }

        if (idx < freeze_corpse_at_tick_start.len and freeze_corpse_at_tick_start[idx]) {
            for (0..8) |_| {
                const angle = @as(f32, @floatFromInt(state.rng.randTagged(rng_callers.bonus_apply_freeze_shard_angle) % 612)) * 0.01;
                effects.spawnFreezeShard(state, creature.pos, angle, detail_preset);
            }
            const shatter_angle = @as(f32, @floatFromInt(state.rng.randTagged(rng_callers.bonus_apply_freeze_shatter_angle) % 612)) * 0.01;
            effects.spawnFreezeShatter(state, creature.pos, shatter_angle, detail_preset);
        }

        creature.active = false;
    }
}

fn bonusTelekineticUpdate(
    pool: *BonusPool,
    state: *state_mod.GameplayState,
    players: []state_mod.PlayerState,
    dt: f32,
    pickup_bonus_ids: *[bonus_pool_size]BonusId,
    pickup_count: *usize,
    pickup_records: ?*BonusPickupBuffer,
) BonusRuntimeError!void {
    if (!(dt > 0.0)) return;
    const dt_ms = dt * 1000.0;
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
        if (!perkActive(player.*, PerkId.telekinetic)) continue;

        var entry = &pool.entries[hovered.index];
        if (entry.picked or entry.bonus_id == .unused) continue;

        try applyBonus(state, player, players, entry.bonus_id, entry.amount, entry.pos);
        appendPickupBonusId(pickup_bonus_ids, pickup_count, entry.bonus_id);
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

fn applyFireblastBonus(
    state: *state_mod.GameplayState,
    projectiles: *projectiles_mod.ProjectilePool,
    origin: state_mod.Vec2,
) void {
    const projectile_owner = owner_ref.OwnerRef.fromLocalPlayer(0);
    const prev_spawn_guard = state.bonus_spawn_guard;
    state.bonus_spawn_guard = true;
    defer state.bonus_spawn_guard = prev_spawn_guard;

    const count: usize = 16;
    const step = std.math.tau / @as(f32, @floatFromInt(count));
    for (0..count) |idx| {
        const angle = @as(f32, @floatFromInt(idx)) * step;
        const type_id = @intFromEnum(game_ids.ProjectileTypeId.plasma_rifle);
        const meta = projectileTravelBudgetFromRawId(type_id);
        _ = projectiles.spawn(origin, narrowF32(angle), type_id, projectile_owner, meta, false);
    }
}

fn applyShockChainBonus(
    state: *state_mod.GameplayState,
    projectiles: *projectiles_mod.ProjectilePool,
    creatures: *creatures_mod.CreaturePool,
    origin: state_mod.Vec2,
) void {
    if (creatures.entries.len == 0) return;

    var best_idx: ?usize = null;
    var best_dist_sq: f32 = 1e12;
    for (creatures.entries, 0..) |creature, idx| {
        if (!creature.active) continue;
        if (!creature_lifecycle.isAlive(creature.lifecycle_stage)) continue;
        const d_sq = distanceSq(origin, creature.pos);
        if (d_sq < best_dist_sq) {
            best_dist_sq = d_sq;
            best_idx = idx;
        }
    }
    const target_idx = best_idx orelse return;

    const target = creatures.entries[target_idx];
    // Native stores (float)(atan2(dy, dx) - 1.5707964 - 3.1415927) with a
    // single f32 spill (differs from toHeading() by 2*pi).
    const delta = state_mod.Vec2.sub(target.pos, origin);
    const angle: f32 = @floatCast(std.math.atan2(@as(f64, delta.y), @as(f64, delta.x)) -
        @as(f64, native_math.roundF32(native_math.native_half_pi)) -
        @as(f64, native_math.roundF32(native_math.native_pi)));
    const projectile_owner = owner_ref.OwnerRef.fromLocalPlayer(0);
    const type_id = @intFromEnum(game_ids.ProjectileTypeId.ion_rifle);
    const meta = projectileTravelBudgetFromRawId(type_id);

    const prev_spawn_guard = state.bonus_spawn_guard;
    state.bonus_spawn_guard = true;
    defer state.bonus_spawn_guard = prev_spawn_guard;

    state.shock_chain_links_left = 0x20;
    const proj_idx = projectiles.spawn(origin, narrowF32(angle), type_id, projectile_owner, meta, false);
    state.shock_chain_projectile_id = @intCast(proj_idx);
}

fn applyNukeBonus(
    state: *state_mod.GameplayState,
    players: []state_mod.PlayerState,
    projectiles: *projectiles_mod.ProjectilePool,
    creatures: *creatures_mod.CreaturePool,
    bonuses: *BonusPool,
    effects: *effects_mod.EffectPool,
    terrain_fx: *terrain_fx_mod.TerrainFxScratch,
    origin: state_mod.Vec2,
    dt: f32,
    world_size: f32,
) void {
    if (players.len == 0) return;
    const player = &players[0];
    const projectile_owner = owner_ref.OwnerRef.fromLocalPlayer(0);
    const damage_owner = owner_ref.OwnerRef.fromPlayer(@intCast(player.index));
    var nuke_kill_count: i32 = 0;
    state.camera_shake_pulses = 0x14;
    state.camera_shake_timer = 0.2;

    var bullet_count: i32 = @intCast(state.rng.randTagged(rng_callers.bonus_apply_nuke_bullet_count) & 3);
    bullet_count += 4;
    var bullet_idx: i32 = 0;
    while (bullet_idx < bullet_count) : (bullet_idx += 1) {
        const angle = native_math.pc24Mul(
            @as(f32, @floatFromInt(state.rng.randTagged(rng_callers.bonus_apply_nuke_pistol_angle) % 0x274)),
            @as(f32, 0.01),
        );
        var type_id = @intFromEnum(game_ids.ProjectileTypeId.pistol);
        applyPlayerProjectileSpawnRules(state, players, projectile_owner, &type_id);
        const meta = projectileTravelBudgetFromRawId(type_id);
        const proj_idx = projectiles.spawn(origin, narrowF32(angle), type_id, projectile_owner, meta, false);
        const speed_scale = native_math.pc24Add(
            native_math.pc24Mul(
                @as(f32, @floatFromInt(state.rng.randTagged(rng_callers.bonus_apply_nuke_pistol_speed_scale) % 0x32)),
                @as(f32, 0.01),
            ),
            @as(f32, 0.5),
        );
        projectiles.entries[proj_idx].speed_scale = native_math.pc24Mul(
            projectiles.entries[proj_idx].speed_scale,
            speed_scale,
        );
    }

    for (0..2) |gauss_idx| {
        const angle_caller = if (gauss_idx == 0) rng_callers.bonus_apply_nuke_gauss_angle_1 else rng_callers.bonus_apply_nuke_gauss_angle_2;
        const angle = native_math.pc24Mul(
            @as(f32, @floatFromInt(state.rng.randTagged(angle_caller) % 0x274)),
            @as(f32, 0.01),
        );
        var type_id = @intFromEnum(game_ids.ProjectileTypeId.gauss_gun);
        applyPlayerProjectileSpawnRules(state, players, projectile_owner, &type_id);
        const meta = projectileTravelBudgetFromRawId(type_id);
        _ = projectiles.spawn(origin, narrowF32(angle), type_id, projectile_owner, meta, false);
    }

    effects.spawnExplosionBurst(state, origin, 1.0, 5);

    const prev_spawn_guard = state.bonus_spawn_guard;
    state.bonus_spawn_guard = true;
    defer state.bonus_spawn_guard = prev_spawn_guard;

    for (creatures.entries, 0..) |creature, idx| {
        if (!creature.active) continue;
        const dx = native_math.pc24Sub(creature.pos.x, origin.x);
        const dy = native_math.pc24Sub(creature.pos.y, origin.y);
        if (@abs(dx) > 256.0 or @abs(dy) > 256.0) continue;
        const distance_sq = native_math.pc24Add(
            native_math.pc24Mul(dx, dx),
            native_math.pc24Mul(dy, dy),
        );
        const distance = native_math.pc24Sqrt(distance_sq);
        const damage_base = native_math.pc24Sub(@as(f32, 256.0), distance);
        if (!(damage_base > 0.0)) continue;
        const damage = native_math.pc24Mul(damage_base, @as(f32, 5.0));
        const xp = creatures.applyExplosionDamage(
            state,
            players,
            bonuses,
            terrain_fx,
            idx,
            damage,
            .{},
            damage_owner,
            dt,
            world_size,
            null,
        );
        if (xp > 0) nuke_kill_count += 1;
    }
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

fn applyBonus(
    state: *state_mod.GameplayState,
    player: *state_mod.PlayerState,
    players: []state_mod.PlayerState,
    bonus_id: BonusId,
    amount: i32,
    origin_pos: ?state_mod.Vec2,
) BonusRuntimeError!void {
    if (bonus_id == .unused) return;

    var effective_amount = amount;
    if (effective_amount < 0) effective_amount = 0;
    if (effective_amount == 0) {
        effective_amount = defaultBonusAmount(bonus_id);
    }

    const economist_multiplier: f32 = if (perkActive(player.*, PerkId.bonus_economist)) 1.5 else 1.0;
    state.sfx_queue.append(.ui_bonus);

    switch (bonus_id) {
        .points => {
            const target = if (players.len > 0) &players[0] else player;
            if (effective_amount > 0) {
                target.experience += effective_amount;
            }
        },
        .energizer => {
            state.bonuses.energizer = narrowF32(state.bonuses.energizer + bonusApplySeconds(bonus_id, effective_amount) * economist_multiplier);
        },
        .weapon_power_up => {
            state.bonuses.weapon_power_up = narrowF32(state.bonuses.weapon_power_up + @as(f32, @floatFromInt(effective_amount)) * economist_multiplier);
            player.weapon_reset_latch = 0;
            player.weapon.shot_cooldown = 0.0;
            player.weapon.reload_timer = 0.0;
            player.weapon.ammo = @floatFromInt(player.weapon.clip_size);
        },
        .double_experience => {
            state.bonuses.double_experience = narrowF32(state.bonuses.double_experience + bonusApplySeconds(bonus_id, effective_amount) * economist_multiplier);
        },
        .reflex_boost => {
            state.bonuses.reflex_boost = narrowF32(state.bonuses.reflex_boost + @as(f32, @floatFromInt(effective_amount)) * economist_multiplier);
            for (players) |*target| {
                target.weapon.ammo = @floatFromInt(target.weapon.clip_size);
                target.weapon.reload_timer = 0.0;
            }
        },
        .shield => {
            player.shield_timer = narrowF32(player.shield_timer + @as(f32, @floatFromInt(effective_amount)) * economist_multiplier);
        },
        .freeze => {
            state.bonuses.freeze = narrowF32(state.bonuses.freeze + @as(f32, @floatFromInt(effective_amount)) * economist_multiplier);
            state.sfx_queue.append(.shockwave);
        },
        .medikit => {
            if (player.health < 100.0) {
                player.health = @min(100.0, player.health + 10.0);
            }
        },
        .speed => {
            player.speed_bonus_timer = narrowF32(player.speed_bonus_timer + @as(f32, @floatFromInt(effective_amount)) * economist_multiplier);
        },
        .fire_bullets => {
            player.fire_bullets_timer = narrowF32(player.fire_bullets_timer + bonusApplySeconds(bonus_id, effective_amount) * economist_multiplier);
            player.weapon_reset_latch = 0;
            player.weapon.shot_cooldown = 0.0;
            player.weapon.reload_timer = 0.0;
            player.weapon.ammo = @floatFromInt(player.weapon.clip_size);
        },
        .weapon => {
            // Native weapon pickup is just weapon_assign_player: the old
            // weapon is never stashed (the alt slot is preloaded with a
            // pistol at player reset).
            const weapon_id = weapon_data.weaponIdFromInt(effective_amount);
            player_runtime.weaponAssignPlayerWithState(player, weapon_id, state);
        },
        .nuke => {
            if (state.pending_nuke_count < state.pending_nuke_origins.len) {
                const slot: usize = @intCast(state.pending_nuke_count);
                state.pending_nuke_origins[slot] = origin_pos orelse player.pos;
                state.pending_nuke_count += 1;
            }
            state.sfx_queue.append(.explosion_large);
            state.sfx_queue.append(.shockwave);
        },
        .shock_chain => {
            if (state.pending_shock_chain_count < state.pending_shock_chain_origins.len) {
                const slot: usize = @intCast(state.pending_shock_chain_count);
                state.pending_shock_chain_origins[slot] = origin_pos orelse player.pos;
                state.pending_shock_chain_count += 1;
            }
            state.sfx_queue.append(.shock_hit_01);
        },
        .fireblast => {
            if (state.pending_fireblast_count < state.pending_fireblast_origins.len) {
                const slot: usize = @intCast(state.pending_fireblast_count);
                state.pending_fireblast_origins[slot] = origin_pos orelse player.pos;
                state.pending_fireblast_count += 1;
            }
            state.sfx_queue.append(.explosion_medium);
        },
        .unused => {},
    }
}

fn bonusApplySeconds(bonus_id: BonusId, amount: i32) f32 {
    return switch (bonus_id) {
        .energizer => 8.0,
        .double_experience => 6.0,
        .fire_bullets => 5.0,
        else => @as(f32, @floatFromInt(amount)),
    };
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
    owner: owner_ref.OwnerRef,
    type_id: *i32,
) void {
    if (state.bonus_spawn_guard) return;
    const player_ref = switch (owner) {
        .player => |ref| ref,
        else => return,
    };
    const player_index: ?usize = if (player_ref.local_host and player_ref.index == 0)
        if (players.len == 1) @as(?usize, 0) else null
    else if (player_ref.index < players.len)
        player_ref.index
    else
        null;

    var shot_credit: i32 = 1;
    if (player_index) |idx| {
        if (type_id.* != @intFromEnum(game_ids.ProjectileTypeId.fire_bullets) and
            players[idx].fire_bullets_timer > 0.0)
        {
            type_id.* = @intFromEnum(game_ids.ProjectileTypeId.fire_bullets);
            shot_credit = 2;
        }
        if (idx < state.shots_fired.len) {
            state.shots_fired[idx] += shot_credit;
        }
    }
    state.shots_fired_total += shot_credit;
}

fn appendPickupBonusId(
    pickup_bonus_ids: *[bonus_pool_size]BonusId,
    pickup_count: *usize,
    bonus_id: BonusId,
) void {
    if (pickup_count.* >= pickup_bonus_ids.len) return;
    pickup_bonus_ids[pickup_count.*] = bonus_id;
    pickup_count.* += 1;
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
        if (isEmpty(entry)) return idx;
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
    entry.* = .{};
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

test "bonus spawn-on-kill is suppressed in typo rush tutorial and demo modes" {
    var players = [_]state_mod.PlayerState{
        .{ .index = 0, .pos = .{ .x = 256.0, .y = 256.0 } },
    };

    const cases = [_]struct {
        game_mode: GameModeId,
        demo_mode_active: bool,
    }{
        .{ .game_mode = .typo, .demo_mode_active = false },
        .{ .game_mode = .rush, .demo_mode_active = false },
        .{ .game_mode = .tutorial, .demo_mode_active = false },
        .{ .game_mode = .survival, .demo_mode_active = true },
    };

    for (cases) |case| {
        var state = state_mod.GameplayState.init(123);
        state.game_mode = case.game_mode;
        state.demo_mode_active = case.demo_mode_active;
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

test "bonus economist extends double experience timer" {
    var base_state = state_mod.GameplayState.init(1);
    var base_player: state_mod.PlayerState = .{
        .index = 0,
        .pos = .{},
    };
    var base_players = [_]state_mod.PlayerState{base_player};
    try applyBonus(
        &base_state,
        &base_player,
        base_players[0..],
        .double_experience,
        10,
        null,
    );
    try std.testing.expectApproxEqAbs(@as(f32, 6.0), base_state.bonuses.double_experience, 1e-6);

    var perk_state = state_mod.GameplayState.init(1);
    var perk_player: state_mod.PlayerState = .{
        .index = 0,
        .pos = .{},
    };
    perk_player.perk_counts.set(PerkId.bonus_economist, 1);
    var perk_players = [_]state_mod.PlayerState{perk_player};
    try applyBonus(
        &perk_state,
        &perk_player,
        perk_players[0..],
        .double_experience,
        10,
        null,
    );
    try std.testing.expectApproxEqAbs(@as(f32, 9.0), perk_state.bonuses.double_experience, 1e-6);
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

    try applyBonus(
        &state,
        player,
        players[0..],
        .weapon,
        @intFromEnum(game_ids.WeaponId.assault_rifle),
        null,
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

test "weapon refresh keeps full version unlocks in demo mode" {
    var state = state_mod.GameplayState.init(1);
    state.demo_mode_active = true;
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
    try std.testing.expectEqual(game_ids.WeaponId.flameburst, questUnlockWeaponForIndex(40).?);
    try std.testing.expectEqual(@as(?game_ids.WeaponId, null), questUnlockWeaponForIndex(2));
    try std.testing.expectEqual(@as(?game_ids.WeaponId, null), questUnlockWeaponForIndex(-1));
    try std.testing.expectEqual(@as(?game_ids.WeaponId, null), questUnlockWeaponForIndex(50));
}

test "weapon pick random available rerolls used weapons on even gate" {
    const seed: u32 = 160;
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

fn runTelekineticUpdate(
    pool: *BonusPool,
    state: *state_mod.GameplayState,
    players: []state_mod.PlayerState,
    dt: f32,
) BonusRuntimeError!void {
    var pickup_bonus_ids = [_]BonusId{.unused} ** bonus_pool_size;
    var pickup_count: usize = 0;
    try bonusTelekineticUpdate(
        pool,
        state,
        players,
        dt,
        &pickup_bonus_ids,
        &pickup_count,
        null,
    );
}

test "telekinetic picks up bonus after hover timer threshold" {
    var state = state_mod.GameplayState.init(1);
    var pool: BonusPool = .{};
    setTestBonusEntry(
        &pool,
        0,
        .points,
        .{ .x = 100.0, .y = 100.0 },
        0,
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

test "telekinetic nuke stores pending origin from bonus position" {
    var state = state_mod.GameplayState.init(1);
    var pool: BonusPool = .{};
    setTestBonusEntry(
        &pool,
        0,
        .nuke,
        .{ .x = 100.0, .y = 100.0 },
        1,
    );

    var player: state_mod.PlayerState = .{
        .index = 0,
        .pos = .{},
        .health = 100.0,
        .aim = .{ .x = 100.0, .y = 100.0 },
    };
    player.perk_counts.set(PerkId.telekinetic, 1);
    var players = [_]state_mod.PlayerState{player};

    try runTelekineticUpdate(&pool, &state, players[0..], 0.7);
    try std.testing.expectEqual(@as(i32, 1), state.pending_nuke_count);
    try std.testing.expectApproxEqAbs(@as(f32, 100.0), state.pending_nuke_origins[0].x, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 100.0), state.pending_nuke_origins[0].y, 1e-6);
}

test "telekinetic shock chain stores pending origin from bonus position" {
    var state = state_mod.GameplayState.init(1);
    var pool: BonusPool = .{};
    setTestBonusEntry(
        &pool,
        0,
        .shock_chain,
        .{ .x = 100.0, .y = 100.0 },
        1,
    );

    var player: state_mod.PlayerState = .{
        .index = 0,
        .pos = .{},
        .health = 100.0,
        .aim = .{ .x = 100.0, .y = 100.0 },
    };
    player.perk_counts.set(PerkId.telekinetic, 1);
    var players = [_]state_mod.PlayerState{player};

    try runTelekineticUpdate(&pool, &state, players[0..], 0.7);
    try std.testing.expectEqual(@as(i32, 1), state.pending_shock_chain_count);
    try std.testing.expectApproxEqAbs(@as(f32, 100.0), state.pending_shock_chain_origins[0].x, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 100.0), state.pending_shock_chain_origins[0].y, 1e-6);
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

test "pending fireblast spawns sixteen plasma rifle projectiles" {
    var state = state_mod.GameplayState.init(1);
    var players = [_]state_mod.PlayerState{
        .{ .index = 0, .pos = .{ .x = 512.0, .y = 512.0 } },
    };
    var projectiles: projectiles_mod.ProjectilePool = .{};
    var creatures: creatures_mod.CreaturePool = .{};
    var bonuses: BonusPool = .{};
    var terrain_fx: terrain_fx_mod.TerrainFxScratch = .{};

    state.pending_fireblast_origins[0] = players[0].pos;
    state.pending_fireblast_count = 1;

    applyPendingBonusEffects(
        &state,
        players[0..],
        &projectiles,
        &creatures,
        &bonuses,
        &terrain_fx,
        0.016,
        1024.0,
    );

    var active_count: i32 = 0;
    for (projectiles.entries) |entry| {
        if (!entry.active) continue;
        active_count += 1;
        try std.testing.expectEqual(@intFromEnum(game_ids.ProjectileTypeId.plasma_rifle), entry.type_id);
    }
    try std.testing.expectEqual(@as(i32, 16), active_count);
    try std.testing.expectEqual(@as(i32, 0), state.pending_fireblast_count);
}

test "pending nuke spawns pistol and gauss projectiles with native meta ranges" {
    var state = state_mod.GameplayState.init(1);
    var players = [_]state_mod.PlayerState{
        .{ .index = 0, .pos = .{ .x = 512.0, .y = 512.0 } },
    };
    var projectiles: projectiles_mod.ProjectilePool = .{};
    var creatures: creatures_mod.CreaturePool = .{};
    var bonuses: BonusPool = .{};
    var terrain_fx: terrain_fx_mod.TerrainFxScratch = .{};

    state.pending_nuke_origins[0] = players[0].pos;
    state.pending_nuke_count = 1;

    applyPendingBonusEffects(
        &state,
        players[0..],
        &projectiles,
        &creatures,
        &bonuses,
        &terrain_fx,
        0.016,
        1024.0,
    );

    var pistol_count: i32 = 0;
    var gauss_count: i32 = 0;
    for (projectiles.entries) |entry| {
        if (!entry.active) continue;
        if (entry.type_id == @intFromEnum(game_ids.ProjectileTypeId.pistol)) {
            pistol_count += 1;
            try std.testing.expectApproxEqAbs(@as(f32, 55.0), entry.travel_budget, 1e-6);
            try std.testing.expect(entry.speed_scale >= 0.5);
            try std.testing.expect(entry.speed_scale < 1.0);
        } else if (entry.type_id == @intFromEnum(game_ids.ProjectileTypeId.gauss_gun)) {
            gauss_count += 1;
            try std.testing.expectApproxEqAbs(@as(f32, 215.0), entry.travel_budget, 1e-6);
            try std.testing.expectApproxEqAbs(@as(f32, 1.0), entry.speed_scale, 1e-6);
        }
    }

    try std.testing.expect(pistol_count >= 4);
    try std.testing.expect(pistol_count <= 7);
    try std.testing.expectEqual(@as(i32, 2), gauss_count);
}

test "pending creature projectile queue materializes hostile shots before projectile step" {
    var state = state_mod.GameplayState.init(1);
    var projectiles: projectiles_mod.ProjectilePool = .{};

    state.pending_creature_projectile_count = 1;
    state.pending_creature_projectiles[0] = .{
        .type_id = @intFromEnum(game_ids.ProjectileTypeId.plasma_rifle),
        .owner = owner_ref.OwnerRef.fromCreature(17),
        .angle = std.math.pi / 2.0,
        .pos = .{ .x = 100.0, .y = 200.0 },
    };

    applyPendingCreatureProjectiles(&state, &projectiles);

    try std.testing.expectEqual(@as(i32, 0), state.pending_creature_projectile_count);
    try std.testing.expect(projectiles.entries[0].active);
    try std.testing.expect(projectiles.entries[0].hits_players);
    try std.testing.expectEqual(@intFromEnum(game_ids.ProjectileTypeId.plasma_rifle), projectiles.entries[0].type_id);
    try std.testing.expectEqual(@as(i32, 17), projectiles.entries[0].owner.toLegacy());
    try std.testing.expectApproxEqAbs(@as(f32, 100.0), projectiles.entries[0].pos.x, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 200.0), projectiles.entries[0].pos.y, 1e-6);
}
