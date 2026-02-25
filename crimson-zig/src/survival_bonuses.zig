const std = @import("std");

const survival_perks = @import("survival_perks.zig");
const survival_state = @import("survival_state.zig");

pub const BonusRuntimeError = error{
    UnsupportedBonusApplyPath,
};

pub const bonus_pool_size: usize = 16;
const weapon_drop_id_count: u32 = 0x21;

const bonus_spawn_margin: f64 = 32.0;
const bonus_spawn_min_distance: f64 = 32.0;
const bonus_pickup_radius: f64 = 26.0;
const bonus_pickup_decay_rate: f64 = 3.0;
const bonus_pickup_linger: f64 = 0.5;
const bonus_time_max: f64 = 10.0;
const bonus_weapon_near_radius: f64 = 56.0;
const bonus_aim_hover_radius: f64 = 24.0;
const bonus_telekinetic_pickup_ms: f64 = 650.0;
const reflex_timer_subtract_bias: f64 = 4e-9;

const game_mode_survival: i32 = 1;
const game_mode_rush: i32 = 2;
const game_mode_quests: i32 = 3;
const game_mode_typo: i32 = 4;
const game_mode_tutorial: i32 = 8;

pub const BonusEntry = struct {
    bonus_id: i32 = 0,
    picked: bool = false,
    time_left: f64 = 0.0,
    time_max: f64 = 0.0,
    pos: survival_state.Vec2 = .{},
    amount: i32 = 0,
};

const AllocSlot = union(enum) {
    sentinel,
    index: usize,
};

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
            if (entry.bonus_id != 0) count += 1;
        }
        return count;
    }

    pub fn trySpawnOnKill(
        self: *BonusPool,
        pos: survival_state.Vec2,
        state: *survival_state.GameplayState,
        players: []const survival_state.PlayerState,
        world_size: f64,
    ) ?*BonusEntry {
        if (state.demo_mode_active) return null;
        if (state.game_mode == game_mode_rush or state.game_mode == game_mode_typo or state.game_mode == game_mode_tutorial) return null;
        if (state.bonus_spawn_guard) return null;
        if (players.len == 0) return null;

        var has_pistol = false;
        for (players) |player| {
            if (player.weapon_id == survival_state.WeaponId.pistol) {
                has_pistol = true;
                break;
            }
        }

        if (has_pistol and (state.rng.rand() & 3) < 3) {
            const slot = spawnAtPos(self, pos, state, players, world_size);
            var entry = slotPtr(self, slot);
            entry.bonus_id = survival_state.BonusId.weapon;

            var weapon_id = weaponPickRandomAvailable(state);
            entry.amount = weapon_id;
            if (weapon_id == survival_state.WeaponId.pistol) {
                weapon_id = weaponPickRandomAvailable(state);
                entry.amount = weapon_id;
            }

            if (countMatches(self, entry.bonus_id) > 1) {
                clearEntry(self, entry);
                return null;
            }

            if (entry.amount == survival_state.WeaponId.pistol or anyPerkActive(players, survival_perks.PerkId.my_favourite_weapon)) {
                clearEntry(self, entry);
                return null;
            }

            if (slot == .sentinel) return null;
            return entry;
        }

        const base_roll = state.rng.rand();
        if ((base_roll % 9) != 1) {
            var allow_without_magnet = false;
            if (has_pistol) {
                allow_without_magnet = (state.rng.rand() % 5) == 1;
            }
            if (!allow_without_magnet) {
                if (!anyPerkActive(players, survival_perks.PerkId.bonus_magnet)) {
                    return null;
                }
                if ((state.rng.rand() % 10) != 2) return null;
            }
        }

        const slot = spawnAtPos(self, pos, state, players, world_size);
        var entry = slotPtr(self, slot);

        if (entry.bonus_id == survival_state.BonusId.weapon) {
            const near_sq = bonus_weapon_near_radius * bonus_weapon_near_radius;
            var near_player = false;
            for (players) |player| {
                if (distanceSq(pos, player.pos) < near_sq) {
                    near_player = true;
                    break;
                }
            }
            if (near_player) {
                entry.bonus_id = survival_state.BonusId.points;
                entry.amount = 100;
            }
        }

        if (entry.bonus_id != survival_state.BonusId.points and countMatches(self, entry.bonus_id) > 1) {
            clearEntry(self, entry);
            return null;
        }

        if (entry.bonus_id == survival_state.BonusId.weapon and carriedWeaponId(players, entry.amount)) {
            clearEntry(self, entry);
            return null;
        }

        if (slot == .sentinel) return null;
        return entry;
    }

    pub fn update(
        self: *BonusPool,
        state: *survival_state.GameplayState,
        players: []survival_state.PlayerState,
        dt: f64,
        pickup_bonus_ids: *[bonus_pool_size]i32,
        pickup_count: *usize,
    ) BonusRuntimeError!void {
        if (!(dt > 0.0)) return;

        const pickup_sq = bonus_pickup_radius * bonus_pickup_radius;

        for (&self.entries) |*entry| {
            if (isEmpty(entry.*)) continue;

            const decay = asF32F64(dt * (if (entry.picked) bonus_pickup_decay_rate else 1.0));
            entry.time_left = asF32F64(entry.time_left - decay);
            if (!entry.picked and state.game_mode == game_mode_tutorial) {
                entry.time_left = 5.0;
            }

            var expired_to_unused = false;
            if (entry.time_left < 0.0) {
                if (entry.picked) {
                    clearEntry(self, entry);
                    continue;
                }
                entry.bonus_id = survival_state.BonusId.unused;
                expired_to_unused = true;
            }

            if (entry.picked) continue;

            var picked_now = false;
            for (players) |*player| {
                if (distanceSq(entry.pos, player.pos) >= pickup_sq) continue;

                try applyBonus(state, player, players, entry.bonus_id, entry.amount, entry.pos);
                state.debug_last_picked_bonus_id = entry.bonus_id;
                state.debug_last_picked_bonus_amount = entry.amount;
                appendPickupBonusId(pickup_bonus_ids, pickup_count, entry.bonus_id);
                entry.picked = true;
                entry.time_left = bonus_pickup_linger;
                picked_now = true;
                break;
            }

            if (expired_to_unused and !picked_now) {
                clearEntry(self, entry);
            }
        }
    }
};

pub fn updatePrePickupTimers(
    state: *survival_state.GameplayState,
    dt: f64,
) void {
    if (!(dt > 0.0)) return;

    if (state.bonuses.weapon_power_up > 0.0) {
        state.bonuses.weapon_power_up = asF32F64(state.bonuses.weapon_power_up - dt);
    }
    if (state.bonuses.energizer > 0.0) {
        state.bonuses.energizer = asF32F64(state.bonuses.energizer - dt);
    }
    if (state.bonuses.reflex_boost > 0.0) {
        const reflex_before = state.bonuses.reflex_boost;
        var subtract = dt;
        if (reflex_before > 0.0 and reflex_before < 1.0) {
            subtract += reflex_timer_subtract_bias;
        }
        state.bonuses.reflex_boost = asF32F64(reflex_before - subtract);
    }
}

pub fn bonusUpdate(
    pool: *BonusPool,
    state: *survival_state.GameplayState,
    players: []survival_state.PlayerState,
    dt: f64,
) BonusRuntimeError!void {
    state.debug_last_picked_bonus_id = 0;
    state.debug_last_picked_bonus_amount = 0;

    var pickup_bonus_ids = [_]i32{0} ** bonus_pool_size;
    var pickup_count: usize = 0;

    try bonusTelekineticUpdate(pool, state, players, dt, &pickup_bonus_ids, &pickup_count);
    try pool.update(state, players, dt, &pickup_bonus_ids, &pickup_count);

    if (dt > 0.0) {
        if (state.bonuses.double_experience <= 0.0) {
            state.bonuses.double_experience = 0.0;
        } else {
            state.bonuses.double_experience = asF32F64(state.bonuses.double_experience - dt);
        }

        if (state.bonuses.freeze <= 0.0) {
            state.bonuses.freeze = 0.0;
        } else {
            state.bonuses.freeze = asF32F64(state.bonuses.freeze - dt);
        }
    }

    for (pickup_bonus_ids[0..pickup_count]) |bonus_id| {
        consumeBonusPickupEffectsRng(state, bonus_id);
    }
}

fn bonusTelekineticUpdate(
    pool: *BonusPool,
    state: *survival_state.GameplayState,
    players: []survival_state.PlayerState,
    dt: f64,
    pickup_bonus_ids: *[bonus_pool_size]i32,
    pickup_count: *usize,
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
        player.bonus_aim_hover_timer_ms = asF32F64(player.bonus_aim_hover_timer_ms + dt_ms);

        if (player.bonus_aim_hover_timer_ms <= bonus_telekinetic_pickup_ms) continue;
        if (!perkActive(player.*, survival_perks.PerkId.telekinetic)) continue;

        var entry = &pool.entries[hovered.index];
        if (entry.picked or entry.bonus_id == 0) continue;

        try applyBonus(state, player, players, entry.bonus_id, entry.amount, entry.pos);
        appendPickupBonusId(pickup_bonus_ids, pickup_count, entry.bonus_id);
        entry.picked = true;
        entry.time_left = bonus_pickup_linger;
        player.bonus_aim_hover_index = -1;
        player.bonus_aim_hover_timer_ms = 0.0;
        break;
    }
}

fn bonusFindAimHoverEntry(
    player: survival_state.PlayerState,
    pool: *const BonusPool,
) ?struct { index: usize } {
    const radius_sq = bonus_aim_hover_radius * bonus_aim_hover_radius;
    for (pool.entries, 0..) |entry, idx| {
        if (entry.bonus_id == 0) continue;
        if (distanceSq(player.aim, entry.pos) < radius_sq) {
            return .{ .index = idx };
        }
    }
    return null;
}

fn applyBonus(
    state: *survival_state.GameplayState,
    player: *survival_state.PlayerState,
    players: []survival_state.PlayerState,
    bonus_id: i32,
    amount: i32,
    origin_pos: ?survival_state.Vec2,
) BonusRuntimeError!void {
    if (bonus_id == survival_state.BonusId.unused) return;

    var effective_amount = amount;
    if (effective_amount < 0) effective_amount = 0;
    if (effective_amount == 0) {
        effective_amount = defaultBonusAmount(bonus_id);
    }

    const economist_multiplier: f64 = if (perkActive(player.*, survival_perks.PerkId.bonus_economist)) 1.5 else 1.0;

    switch (bonus_id) {
        survival_state.BonusId.points => {
            const target = if (players.len > 0) &players[0] else player;
            if (effective_amount > 0) {
                target.experience += effective_amount;
            }
        },
        survival_state.BonusId.energizer => {
            state.bonuses.energizer = asF32F64(state.bonuses.energizer + bonusApplySeconds(bonus_id, effective_amount) * economist_multiplier);
        },
        survival_state.BonusId.weapon_power_up => {
            state.bonuses.weapon_power_up = asF32F64(state.bonuses.weapon_power_up + @as(f64, @floatFromInt(effective_amount)) * economist_multiplier);
            player.weapon_reset_latch = 0;
            player.shot_cooldown = 0.0;
            player.reload_active = false;
            player.reload_timer = 0.0;
            player.reload_timer_max = 0.0;
            player.ammo = @floatFromInt(player.clip_size);
        },
        survival_state.BonusId.double_experience => {
            state.bonuses.double_experience = asF32F64(state.bonuses.double_experience + bonusApplySeconds(bonus_id, effective_amount) * economist_multiplier);
        },
        survival_state.BonusId.reflex_boost => {
            state.bonuses.reflex_boost = asF32F64(state.bonuses.reflex_boost + @as(f64, @floatFromInt(effective_amount)) * economist_multiplier);
            for (players) |*target| {
                target.ammo = @floatFromInt(target.clip_size);
                target.reload_active = false;
                target.reload_timer = 0.0;
                target.reload_timer_max = 0.0;
            }
        },
        survival_state.BonusId.shield => {
            player.shield_timer = asF32F64(player.shield_timer + @as(f64, @floatFromInt(effective_amount)) * economist_multiplier);
        },
        survival_state.BonusId.freeze => {
            state.bonuses.freeze = asF32F64(state.bonuses.freeze + @as(f64, @floatFromInt(effective_amount)) * economist_multiplier);
        },
        survival_state.BonusId.medikit => {
            if (player.health < 100.0) {
                player.health = @min(100.0, player.health + 10.0);
            }
        },
        survival_state.BonusId.speed => {
            player.speed_bonus_timer = asF32F64(player.speed_bonus_timer + @as(f64, @floatFromInt(effective_amount)) * economist_multiplier);
        },
        survival_state.BonusId.fire_bullets => {
            player.fire_bullets_timer = asF32F64(player.fire_bullets_timer + bonusApplySeconds(bonus_id, effective_amount) * economist_multiplier);
            player.weapon_reset_latch = 0;
            player.shot_cooldown = 0.0;
            player.reload_active = false;
            player.reload_timer = 0.0;
            player.reload_timer_max = 0.0;
            player.ammo = @floatFromInt(player.clip_size);
        },
        survival_state.BonusId.weapon => {
            if (perkActive(player.*, survival_perks.PerkId.alternate_weapon) and player.alt_weapon_id == null) {
                player.alt_weapon_id = player.weapon_id;
                player.alt_clip_size = player.clip_size;
                player.alt_ammo = player.ammo;
                player.alt_reload_active = player.reload_active;
                player.alt_reload_timer = player.reload_timer;
                player.alt_shot_cooldown = player.shot_cooldown;
                player.alt_reload_timer_max = player.reload_timer_max;
            }
            survival_state.weaponAssignPlayerWithState(player, effective_amount, state);
        },
        survival_state.BonusId.nuke => {
            if (state.pending_nuke_count < state.pending_nuke_origins.len) {
                const slot: usize = @intCast(state.pending_nuke_count);
                state.pending_nuke_origins[slot] = origin_pos orelse player.pos;
                state.pending_nuke_count += 1;
            }
        },
        survival_state.BonusId.shock_chain => {
            if (state.pending_shock_chain_count < state.pending_shock_chain_origins.len) {
                const slot: usize = @intCast(state.pending_shock_chain_count);
                state.pending_shock_chain_origins[slot] = origin_pos orelse player.pos;
                state.pending_shock_chain_count += 1;
            }
        },
        survival_state.BonusId.fireblast => {
            if (state.pending_fireblast_count < state.pending_fireblast_origins.len) {
                const slot: usize = @intCast(state.pending_fireblast_count);
                state.pending_fireblast_origins[slot] = origin_pos orelse player.pos;
                state.pending_fireblast_count += 1;
            }
        },
        else => {},
    }
}

fn bonusApplySeconds(bonus_id: i32, amount: i32) f64 {
    return switch (bonus_id) {
        survival_state.BonusId.energizer => 8.0,
        survival_state.BonusId.double_experience => 6.0,
        survival_state.BonusId.fire_bullets => 5.0,
        else => @as(f64, @floatFromInt(amount)),
    };
}

fn defaultBonusAmount(bonus_id: i32) i32 {
    return switch (bonus_id) {
        survival_state.BonusId.unused => 0,
        survival_state.BonusId.points => 500,
        survival_state.BonusId.energizer => 8,
        survival_state.BonusId.weapon => 3,
        survival_state.BonusId.weapon_power_up => 10,
        survival_state.BonusId.nuke => 1,
        survival_state.BonusId.double_experience => 1,
        survival_state.BonusId.shock_chain => 1,
        survival_state.BonusId.fireblast => 1,
        survival_state.BonusId.reflex_boost => 3,
        survival_state.BonusId.shield => 7,
        survival_state.BonusId.freeze => 5,
        survival_state.BonusId.medikit => 10,
        survival_state.BonusId.speed => 8,
        survival_state.BonusId.fire_bullets => 4,
        else => 0,
    };
}

fn perkActive(player: survival_state.PlayerState, perk_id: i32) bool {
    if (perk_id < 0 or perk_id >= player.perk_counts.len) return false;
    return player.perk_counts[@intCast(perk_id)] > 0;
}

fn anyPerkActive(players: []const survival_state.PlayerState, perk_id: i32) bool {
    for (players) |player| {
        if (perkActive(player, perk_id)) return true;
    }
    return false;
}

fn carriedWeaponId(players: []const survival_state.PlayerState, weapon_id: i32) bool {
    for (players) |player| {
        if (player.weapon_id == weapon_id) return true;
        if (player.alt_weapon_id) |alt_id| {
            if (alt_id == weapon_id) return true;
        }
    }
    return false;
}

fn weaponRefreshAvailable(state: *survival_state.GameplayState) void {
    const unlock_index = state.status_quest_unlock_index;
    const unlock_index_full = state.status_quest_unlock_index_full;
    const game_mode = state.game_mode;

    if (state.weapon_available_game_mode == game_mode and
        state.weapon_available_unlock_index == unlock_index and
        state.weapon_available_unlock_index_full == unlock_index_full)
    {
        return;
    }

    state.weapon_available = [_]bool{false} ** survival_state.weapon_count_size;
    state.weapon_available[@intCast(survival_state.WeaponId.pistol)] = true;

    if (unlock_index > 0) {
        const limit: usize = @min(@as(usize, @intCast(unlock_index)), quest_unlock_weapon_by_index.len);
        for (quest_unlock_weapon_by_index[0..limit]) |weapon_id| {
            if (weapon_id > 0 and weapon_id < state.weapon_available.len) {
                state.weapon_available[@intCast(weapon_id)] = true;
            }
        }
    }

    if (game_mode == game_mode_survival) {
        state.weapon_available[@intCast(survival_state.WeaponId.assault_rifle)] = true;
        state.weapon_available[@intCast(survival_state.WeaponId.shotgun)] = true;
        state.weapon_available[@intCast(survival_state.WeaponId.submachine_gun)] = true;
    }

    if (!state.demo_mode_active and unlock_index_full >= 0x28) {
        state.weapon_available[@intCast(survival_state.WeaponId.splitter_gun)] = true;
    }

    state.weapon_available_game_mode = game_mode;
    state.weapon_available_unlock_index = unlock_index;
    state.weapon_available_unlock_index_full = unlock_index_full;
}

pub fn weaponPickRandomAvailable(state: *survival_state.GameplayState) i32 {
    weaponRefreshAvailable(state);

    for (0..1000) |_| {
        var base_rand = state.rng.rand();
        var weapon_id: i32 = @intCast(base_rand % weapon_drop_id_count + 1);

        if (weapon_id >= 0 and weapon_id < state.status_weapon_usage_counts.len and
            state.status_weapon_usage_counts[@intCast(weapon_id)] != 0 and
            (state.rng.rand() & 1) == 0)
        {
            base_rand = state.rng.rand();
            weapon_id = @intCast(base_rand % weapon_drop_id_count + 1);
        }

        if (weapon_id < 0 or weapon_id >= state.weapon_available.len) continue;
        if (!state.weapon_available[@intCast(weapon_id)]) continue;

        if (state.game_mode == game_mode_quests and
            state.quest_stage_major == 5 and
            state.quest_stage_minor == 10 and
            weapon_id == survival_state.WeaponId.ion_cannon)
        {
            continue;
        }
        return weapon_id;
    }
    return survival_state.WeaponId.pistol;
}

fn bonusPickRandomType(
    pool: *const BonusPool,
    state: *survival_state.GameplayState,
    players: []const survival_state.PlayerState,
) i32 {
    var has_fire_bullets_drop = false;
    for (pool.entries) |entry| {
        if (entry.bonus_id == survival_state.BonusId.fire_bullets and !entry.picked) {
            has_fire_bullets_drop = true;
            break;
        }
    }

    for (0..101) |_| {
        const roll: i32 = @intCast(state.rng.rand() % 162 + 1);
        const bonus_id = bonusIdFromRoll(roll, state);
        if (bonus_id <= 0) continue;
        if (bonusPickSuppressed(state, players, bonus_id, has_fire_bullets_drop)) continue;

        return bonus_id;
    }
    return survival_state.BonusId.points;
}

fn bonusPickSuppressed(
    state: *survival_state.GameplayState,
    players: []const survival_state.PlayerState,
    bonus_id: i32,
    has_fire_bullets_drop: bool,
) bool {
    if (state.shock_chain_links_left > 0 and bonus_id == survival_state.BonusId.shock_chain) return true;

    if (state.game_mode == game_mode_quests and state.quest_stage_minor == 10) {
        const major = state.quest_stage_major;
        if (bonus_id == survival_state.BonusId.nuke) {
            if (major == 2 or major == 4 or major == 5) return true;
            if (state.hardcore and major == 3) return true;
        }
        if (bonus_id == survival_state.BonusId.freeze) {
            if (major == 4) return true;
            if (state.hardcore and major == 2) return true;
        }
    }

    if (bonus_id == survival_state.BonusId.freeze and state.bonuses.freeze > 0.0) return true;
    if (bonus_id == survival_state.BonusId.shield and anyShieldActive(players)) return true;
    if (bonus_id == survival_state.BonusId.weapon and has_fire_bullets_drop) return true;
    if (bonus_id == survival_state.BonusId.weapon and anyPerkActive(players, survival_perks.PerkId.my_favourite_weapon)) return true;
    if (bonus_id == survival_state.BonusId.medikit and anyPerkActive(players, survival_perks.PerkId.death_clock)) return true;
    if (bonus_id == survival_state.BonusId.unused) return true;
    return false;
}

fn anyShieldActive(players: []const survival_state.PlayerState) bool {
    for (players) |player| {
        if (player.shield_timer > 0.0) return true;
    }
    return false;
}

fn bonusIdFromRoll(
    roll: i32,
    state: *survival_state.GameplayState,
) i32 {
    if (roll < 1 or roll > 162) return 0;
    if (roll <= 13) return survival_state.BonusId.points;
    if (roll == 14) {
        if ((state.rng.rand() & 0x3f) == 0) return survival_state.BonusId.energizer;
        return survival_state.BonusId.weapon;
    }

    var v5 = roll - 14;
    var v6 = survival_state.BonusId.weapon;
    while (v5 > 10) {
        v5 -= 10;
        v6 += 1;
        if (v6 >= 15) return 0;
    }
    return v6;
}

fn isEmpty(entry: BonusEntry) bool {
    return entry.bonus_id == 0 and !entry.picked and entry.time_left <= 0.0 and entry.time_max <= 0.0 and entry.amount == 0;
}

fn distanceSq(a: survival_state.Vec2, b: survival_state.Vec2) f64 {
    const dx = a.x - b.x;
    const dy = a.y - b.y;
    return dx * dx + dy * dy;
}

fn asF32F64(value: f64) f64 {
    const rounded: f32 = @floatCast(value);
    return @floatCast(rounded);
}

fn appendPickupBonusId(
    pickup_bonus_ids: *[bonus_pool_size]i32,
    pickup_count: *usize,
    bonus_id: i32,
) void {
    if (pickup_count.* >= pickup_bonus_ids.len) return;
    pickup_bonus_ids[pickup_count.*] = bonus_id;
    pickup_count.* += 1;
}

fn consumeBonusPickupEffectsRng(
    state: *survival_state.GameplayState,
    bonus_id: i32,
) void {
    if (bonus_id != survival_state.BonusId.nuke) {
        // emit_bonus_pickup_effects -> spawn_burst(count=12, scale_step set).
        for (0..12) |_| {
            _ = state.rng.rand();
            _ = state.rng.rand();
            _ = state.rng.rand();
        }
    }
}

const quest_unlock_weapon_by_index = [_]i32{
    2, 3, 0, 8, 0, 5, 0, 6, 0, 12,
    0, 9, 0, 21, 0, 7, 0, 4, 0, 11,
    0, 10, 0, 13, 0, 15, 0, 18, 0, 20,
    0, 19, 0, 14, 0, 17, 0, 22, 0, 23,
    31, 0, 0, 30, 0, 0, 0, 0, 0, 28,
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

fn countMatches(self: *const BonusPool, bonus_id: i32) usize {
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
    pos: survival_state.Vec2,
    state: *survival_state.GameplayState,
    players: []const survival_state.PlayerState,
    world_size: f64,
) AllocSlot {
    if (state.game_mode == game_mode_rush) return .sentinel;
    if (pos.x < bonus_spawn_margin or pos.y < bonus_spawn_margin or
        pos.x > world_size - bonus_spawn_margin or pos.y > world_size - bonus_spawn_margin)
    {
        return .sentinel;
    }

    var slot = allocSlotOrSentinel(self);
    const bonus_id = bonusPickRandomType(self, state, players);

    const min_dist_sq = bonus_spawn_min_distance * bonus_spawn_min_distance;
    for (self.entries) |active| {
        if (active.bonus_id == 0) continue;
        if (distanceSq(pos, active.pos) < min_dist_sq) {
            slot = .sentinel;
            break;
        }
    }

    var entry = slotPtr(self, slot);
    entry.bonus_id = bonus_id;
    entry.picked = false;
    entry.pos = pos;
    entry.time_left = bonus_time_max;
    entry.time_max = bonus_time_max;

    if (bonus_id == survival_state.BonusId.weapon) {
        entry.amount = weaponPickRandomAvailable(state);
    } else if (bonus_id == survival_state.BonusId.points) {
        entry.amount = if ((state.rng.rand() & 7) < 3) 1000 else 500;
    } else {
        entry.amount = defaultBonusAmount(bonus_id);
    }

    return slot;
}

test "bonus pool spawn-on-kill can materialize weapon drop" {
    var state = survival_state.GameplayState.init(1234);
    state.game_mode = game_mode_survival;
    state.status_quest_unlock_index = 49;
    state.status_quest_unlock_index_full = 49;

    var pool = BonusPool{};
    var players = [_]survival_state.PlayerState{
        .{ .index = 0, .pos = .{ .x = 512.0, .y = 512.0 } },
    };
    survival_state.weaponAssignPlayer(&players[0], survival_state.WeaponId.pistol);

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
    var players = [_]survival_state.PlayerState{
        .{ .index = 0, .pos = .{ .x = 256.0, .y = 256.0 } },
    };

    const cases = [_]struct {
        game_mode: i32,
        demo_mode_active: bool,
    }{
        .{ .game_mode = game_mode_typo, .demo_mode_active = false },
        .{ .game_mode = game_mode_rush, .demo_mode_active = false },
        .{ .game_mode = game_mode_tutorial, .demo_mode_active = false },
        .{ .game_mode = game_mode_survival, .demo_mode_active = true },
    };

    for (cases) |case| {
        var state = survival_state.GameplayState.init(123);
        state.game_mode = case.game_mode;
        state.demo_mode_active = case.demo_mode_active;
        var pool = BonusPool{};
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
    var state = survival_state.GameplayState.init(1);
    state.bonuses.weapon_power_up = 2.0;
    state.bonuses.energizer = 2.0;
    state.bonuses.reflex_boost = 0.5;

    updatePrePickupTimers(&state, 0.1);

    try std.testing.expect(state.bonuses.weapon_power_up < 2.0);
    try std.testing.expect(state.bonuses.energizer < 2.0);
    try std.testing.expect(state.bonuses.reflex_boost < 0.5);
}

test "bonus spawn-on-kill rng cadence matches observed pistol path" {
    var state = survival_state.GameplayState.init(1);
    state.rng.state = 3_857_056_479;
    state.game_mode = game_mode_survival;
    state.status_quest_unlock_index = 49;
    state.status_quest_unlock_index_full = 50;
    state.status_weapon_usage_counts[29] = 10;

    var pool = BonusPool{};
    var players = [_]survival_state.PlayerState{
        .{ .index = 0, .pos = .{ .x = 512.0, .y = 512.0 } },
    };
    survival_state.weaponAssignPlayer(&players[0], survival_state.WeaponId.pistol);

    const spawned = pool.trySpawnOnKill(.{ .x = 420.0, .y = 420.0 }, &state, players[0..], 1024.0);
    try std.testing.expect(spawned != null);
    try std.testing.expectEqual(survival_state.BonusId.weapon, spawned.?.bonus_id);
    try std.testing.expectEqual(@as(i32, 11), spawned.?.amount);
    try std.testing.expectEqual(@as(u32, 258_047_690), state.rng.state);
}

test "bonus economist extends double experience timer" {
    var base_state = survival_state.GameplayState.init(1);
    var base_player = survival_state.PlayerState{
        .index = 0,
        .pos = .{},
    };
    var base_players = [_]survival_state.PlayerState{base_player};
    try applyBonus(
        &base_state,
        &base_player,
        base_players[0..],
        survival_state.BonusId.double_experience,
        10,
        null,
    );
    try std.testing.expectApproxEqAbs(@as(f64, 6.0), base_state.bonuses.double_experience, 1e-6);

    var perk_state = survival_state.GameplayState.init(1);
    var perk_player = survival_state.PlayerState{
        .index = 0,
        .pos = .{},
    };
    perk_player.perk_counts[@intCast(survival_perks.PerkId.bonus_economist)] = 1;
    var perk_players = [_]survival_state.PlayerState{perk_player};
    try applyBonus(
        &perk_state,
        &perk_player,
        perk_players[0..],
        survival_state.BonusId.double_experience,
        10,
        null,
    );
    try std.testing.expectApproxEqAbs(@as(f64, 9.0), perk_state.bonuses.double_experience, 1e-6);
}

test "alternate weapon stashes previous weapon on first pickup" {
    var state = survival_state.GameplayState.init(1);
    var player = survival_state.PlayerState{
        .index = 0,
        .pos = .{},
    };
    var players = [_]survival_state.PlayerState{player};
    survival_state.weaponAssignPlayer(&player, survival_state.WeaponId.pistol);
    player.perk_counts[@intCast(survival_perks.PerkId.alternate_weapon)] = 1;

    try applyBonus(
        &state,
        &player,
        players[0..],
        survival_state.BonusId.weapon,
        survival_state.WeaponId.assault_rifle,
        null,
    );

    try std.testing.expectEqual(survival_state.WeaponId.assault_rifle, player.weapon_id);
    try std.testing.expect(player.alt_weapon_id != null);
    try std.testing.expectEqual(survival_state.WeaponId.pistol, player.alt_weapon_id.?);
    try std.testing.expectEqual(@as(i32, 10), player.alt_clip_size);
}

test "bonus magnet allows spawn on secondary roll" {
    var base_state = survival_state.GameplayState.init(7);
    base_state.game_mode = game_mode_survival;
    var base_pool = BonusPool{};
    var base_players = [_]survival_state.PlayerState{
        .{
            .index = 0,
            .pos = .{},
            .weapon_id = survival_state.WeaponId.assault_rifle,
        },
    };

    const base_spawned = base_pool.trySpawnOnKill(
        .{ .x = 100.0, .y = 100.0 },
        &base_state,
        base_players[0..],
        1024.0,
    );
    try std.testing.expect(base_spawned == null);

    var perk_state = survival_state.GameplayState.init(7);
    perk_state.game_mode = game_mode_survival;
    var perk_pool = BonusPool{};
    var perk_players = [_]survival_state.PlayerState{
        .{
            .index = 0,
            .pos = .{},
            .weapon_id = survival_state.WeaponId.assault_rifle,
        },
    };
    perk_players[0].perk_counts[@intCast(survival_perks.PerkId.bonus_magnet)] = 1;

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
        survival_state.BonusId.freeze,
    );
    try runQuestSuppressionCase(
        suppression_seed,
        true,
        2,
        10,
        survival_state.BonusId.points,
    );
    try runQuestSuppressionCase(
        suppression_seed,
        false,
        4,
        10,
        survival_state.BonusId.points,
    );
    try runQuestSuppressionCase(
        suppression_seed,
        false,
        5,
        10,
        survival_state.BonusId.freeze,
    );
    try runQuestSuppressionCase(
        suppression_seed,
        true,
        3,
        10,
        survival_state.BonusId.freeze,
    );
}

fn setTestBonusEntry(
    pool: *BonusPool,
    idx: usize,
    bonus_id: i32,
    pos: survival_state.Vec2,
    amount: i32,
) void {
    pool.entries[idx] = .{
        .bonus_id = bonus_id,
        .picked = false,
        .time_left = bonus_time_max,
        .time_max = bonus_time_max,
        .pos = pos,
        .amount = amount,
    };
}

fn runTelekineticUpdate(
    pool: *BonusPool,
    state: *survival_state.GameplayState,
    players: []survival_state.PlayerState,
    dt: f64,
) BonusRuntimeError!void {
    var pickup_bonus_ids = [_]i32{0} ** bonus_pool_size;
    var pickup_count: usize = 0;
    try bonusTelekineticUpdate(
        pool,
        state,
        players,
        dt,
        &pickup_bonus_ids,
        &pickup_count,
    );
}

test "telekinetic picks up bonus after hover timer threshold" {
    var state = survival_state.GameplayState.init(1);
    var pool = BonusPool{};
    setTestBonusEntry(
        &pool,
        0,
        survival_state.BonusId.points,
        .{ .x = 100.0, .y = 100.0 },
        0,
    );

    const base_player = survival_state.PlayerState{
        .index = 0,
        .pos = .{},
        .health = 100.0,
        .aim = .{ .x = 100.0, .y = 100.0 },
    };
    var base_players = [_]survival_state.PlayerState{base_player};
    try runTelekineticUpdate(&pool, &state, base_players[0..], 0.7);
    try std.testing.expect(!pool.entries[0].picked);

    var perk_player = survival_state.PlayerState{
        .index = 0,
        .pos = .{},
        .health = 100.0,
        .aim = .{ .x = 100.0, .y = 100.0 },
    };
    perk_player.perk_counts[@intCast(survival_perks.PerkId.telekinetic)] = 1;
    var perk_players = [_]survival_state.PlayerState{perk_player};
    try runTelekineticUpdate(&pool, &state, perk_players[0..], 0.7);

    try std.testing.expect(pool.entries[0].picked);
    try std.testing.expectEqual(@as(i64, 500), perk_players[0].experience);
}

test "telekinetic nuke stores pending origin from bonus position" {
    var state = survival_state.GameplayState.init(1);
    var pool = BonusPool{};
    setTestBonusEntry(
        &pool,
        0,
        survival_state.BonusId.nuke,
        .{ .x = 100.0, .y = 100.0 },
        1,
    );

    var player = survival_state.PlayerState{
        .index = 0,
        .pos = .{},
        .health = 100.0,
        .aim = .{ .x = 100.0, .y = 100.0 },
    };
    player.perk_counts[@intCast(survival_perks.PerkId.telekinetic)] = 1;
    var players = [_]survival_state.PlayerState{player};

    try runTelekineticUpdate(&pool, &state, players[0..], 0.7);
    try std.testing.expectEqual(@as(i32, 1), state.pending_nuke_count);
    try std.testing.expectApproxEqAbs(@as(f64, 100.0), state.pending_nuke_origins[0].x, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f64, 100.0), state.pending_nuke_origins[0].y, 1e-6);
}

test "telekinetic shock chain stores pending origin from bonus position" {
    var state = survival_state.GameplayState.init(1);
    var pool = BonusPool{};
    setTestBonusEntry(
        &pool,
        0,
        survival_state.BonusId.shock_chain,
        .{ .x = 100.0, .y = 100.0 },
        1,
    );

    var player = survival_state.PlayerState{
        .index = 0,
        .pos = .{},
        .health = 100.0,
        .aim = .{ .x = 100.0, .y = 100.0 },
    };
    player.perk_counts[@intCast(survival_perks.PerkId.telekinetic)] = 1;
    var players = [_]survival_state.PlayerState{player};

    try runTelekineticUpdate(&pool, &state, players[0..], 0.7);
    try std.testing.expectEqual(@as(i32, 1), state.pending_shock_chain_count);
    try std.testing.expectApproxEqAbs(@as(f64, 100.0), state.pending_shock_chain_origins[0].x, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f64, 100.0), state.pending_shock_chain_origins[0].y, 1e-6);
}

test "telekinetic picks only one bonus per frame across players" {
    var state = survival_state.GameplayState.init(1);
    var pool = BonusPool{};
    setTestBonusEntry(
        &pool,
        0,
        survival_state.BonusId.points,
        .{ .x = 100.0, .y = 100.0 },
        500,
    );
    setTestBonusEntry(
        &pool,
        1,
        survival_state.BonusId.points,
        .{ .x = 200.0, .y = 200.0 },
        500,
    );

    var player0 = survival_state.PlayerState{
        .index = 0,
        .pos = .{},
        .health = 100.0,
        .aim = .{ .x = 100.0, .y = 100.0 },
    };
    var player1 = survival_state.PlayerState{
        .index = 1,
        .pos = .{},
        .health = 100.0,
        .aim = .{ .x = 200.0, .y = 200.0 },
    };
    player0.perk_counts[@intCast(survival_perks.PerkId.telekinetic)] = 1;
    player1.perk_counts[@intCast(survival_perks.PerkId.telekinetic)] = 1;
    var players = [_]survival_state.PlayerState{ player0, player1 };

    try runTelekineticUpdate(&pool, &state, players[0..], 0.7);
    try std.testing.expect(pool.entries[0].picked);
    try std.testing.expect(!pool.entries[1].picked);
    try std.testing.expectEqual(@as(i64, 500), players[0].experience);
    try std.testing.expectEqual(@as(i64, 0), players[1].experience);
}

test "telekinetic hover timer carries across bonus switch" {
    var state = survival_state.GameplayState.init(1);
    var pool = BonusPool{};
    setTestBonusEntry(
        &pool,
        0,
        survival_state.BonusId.points,
        .{ .x = 100.0, .y = 100.0 },
        500,
    );
    setTestBonusEntry(
        &pool,
        1,
        survival_state.BonusId.points,
        .{ .x = 130.0, .y = 100.0 },
        500,
    );

    var player = survival_state.PlayerState{
        .index = 0,
        .pos = .{},
        .health = 100.0,
        .aim = .{ .x = 100.0, .y = 100.0 },
    };
    player.perk_counts[@intCast(survival_perks.PerkId.telekinetic)] = 1;
    var players = [_]survival_state.PlayerState{player};

    try runTelekineticUpdate(&pool, &state, players[0..], 0.4);
    try std.testing.expect(!pool.entries[0].picked);
    try std.testing.expect(!pool.entries[1].picked);

    players[0].aim = .{ .x = 130.0, .y = 100.0 };
    try runTelekineticUpdate(&pool, &state, players[0..], 0.3);

    try std.testing.expect(!pool.entries[0].picked);
    try std.testing.expect(pool.entries[1].picked);
    try std.testing.expectEqual(@as(i32, -1), players[0].bonus_aim_hover_index);
    try std.testing.expectApproxEqAbs(@as(f64, 0.0), players[0].bonus_aim_hover_timer_ms, 1e-6);
}

fn runQuestSuppressionCase(
    seed: u32,
    hardcore: bool,
    quest_stage_major: i32,
    quest_stage_minor: i32,
    expected_bonus_id: i32,
) !void {
    var state = survival_state.GameplayState.init(seed);
    state.game_mode = game_mode_quests;
    state.hardcore = hardcore;
    state.quest_stage_major = quest_stage_major;
    state.quest_stage_minor = quest_stage_minor;

    var pool = BonusPool{};
    var players = [_]survival_state.PlayerState{
        .{ .index = 0, .pos = .{} },
    };

    const bonus_id = bonusPickRandomType(&pool, &state, players[0..]);
    try std.testing.expectEqual(expected_bonus_id, bonus_id);
}
