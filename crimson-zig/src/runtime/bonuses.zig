const std = @import("std");
const game_ids = @import("../game_ids.zig");
const native_math = @import("native_math.zig");

const perks = @import("perks.zig");
const player_runtime = @import("player.zig");
const state_mod = @import("state.zig");
const weapon_data = @import("weapon_data.zig");

const narrowF32 = native_math.roundF32;
const PerkId = perks.PerkId;
const BonusId = game_ids.BonusId;
const GameModeId = game_ids.GameModeId;

pub const BonusRuntimeError = error{
    UnsupportedBonusApplyPath,
};

pub const bonus_pool_size: usize = 16;
pub const BonusPickupRecord = struct {
    bonus_id: BonusId = .unused,
    amount: i32 = 0,
    player_index: i32 = -1,
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
const reflex_timer_subtract_bias: f32 = 4e-9;

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

        if (has_pistol and (state.rng.rand() & 3) < 3) {
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

        const base_roll = state.rng.rand();
        if ((base_roll % 9) != 1) {
            var allow_without_magnet = false;
            if (has_pistol) {
                allow_without_magnet = (state.rng.rand() % 5) == 1;
            }
            if (!allow_without_magnet) {
                if (!anyPerkActive(players, PerkId.bonus_magnet)) {
                    return null;
                }
                if ((state.rng.rand() % 10) != 2) return null;
            }
        }

        const slot = spawnAtPos(self, pos, state, players, world_size);
        var entry = slotPtr(self, slot);

        if (entry.bonus_id == .weapon) {
            const near_sq = bonus_weapon_near_radius * bonus_weapon_near_radius;
            var near_player = false;
            for (players) |player| {
                if (distanceSq(pos, player.pos) < near_sq) {
                    near_player = true;
                    break;
                }
            }
            if (near_player) {
                entry.bonus_id = .points;
                entry.amount = 100;
            }
        }

        if (entry.bonus_id != .points and countMatches(self, entry.bonus_id) > 1) {
            clearEntry(self, entry);
            return null;
        }

        if (entry.bonus_id == .weapon) {
            const weapon_id = weapon_data.weaponIdFromInt(entry.amount);
            if (carriedWeaponId(players, weapon_id)) {
                clearEntry(self, entry);
                return null;
            }
        }

        if (slot == .sentinel) return null;
        return entry;
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

            var picked_now = false;
            for (players) |*player| {
                if (distanceSq(entry.pos, player.pos) >= pickup_sq) continue;

                try applyBonus(state, player, players, entry.bonus_id, entry.amount, entry.pos);
                state.debug_last_picked_bonus_id = entry.bonus_id;
                state.debug_last_picked_bonus_amount = entry.amount;
                appendPickupBonusId(pickup_bonus_ids, pickup_count, entry.bonus_id);
                appendPickupRecord(pickup_records, .{
                    .bonus_id = entry.bonus_id,
                    .amount = entry.amount,
                    .player_index = player.index,
                });
                entry.picked = true;
                entry.time_left = narrowF32(bonus_pickup_linger);
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
        const reflex_before = state.bonuses.reflex_boost;
        var subtract = dt;
        if (reflex_before > 0.0 and reflex_before < 1.0) {
            subtract += reflex_timer_subtract_bias;
        }
        state.bonuses.reflex_boost = reflex_before - subtract;
    }
}

pub fn bonusUpdate(
    pool: *BonusPool,
    state: *state_mod.GameplayState,
    players: []state_mod.PlayerState,
    dt: f32,
    pickup_records: ?*BonusPickupBuffer,
) BonusRuntimeError!void {
    state.debug_last_picked_bonus_id = .unused;
    state.debug_last_picked_bonus_amount = 0;
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

    for (pickup_bonus_ids[0..pickup_count]) |bonus_id| {
        consumeBonusPickupEffectsRng(state, bonus_id);
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
        });
        entry.picked = true;
        entry.time_left = narrowF32(bonus_pickup_linger);
        player.bonus_aim_hover_index = -1;
        player.bonus_aim_hover_timer_ms = 0.0;
        break;
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
            player.weapon.reload_active = false;
            player.weapon.reload_timer = 0.0;
            player.weapon.reload_timer_max = 0.0;
            player.weapon.ammo = @floatFromInt(player.weapon.clip_size);
        },
        .double_experience => {
            state.bonuses.double_experience = narrowF32(state.bonuses.double_experience + bonusApplySeconds(bonus_id, effective_amount) * economist_multiplier);
        },
        .reflex_boost => {
            state.bonuses.reflex_boost = narrowF32(state.bonuses.reflex_boost + @as(f32, @floatFromInt(effective_amount)) * economist_multiplier);
            for (players) |*target| {
                target.weapon.ammo = @floatFromInt(target.weapon.clip_size);
                target.weapon.reload_active = false;
                target.weapon.reload_timer = 0.0;
                target.weapon.reload_timer_max = 0.0;
            }
        },
        .shield => {
            player.shield_timer = narrowF32(player.shield_timer + @as(f32, @floatFromInt(effective_amount)) * economist_multiplier);
        },
        .freeze => {
            state.bonuses.freeze = narrowF32(state.bonuses.freeze + @as(f32, @floatFromInt(effective_amount)) * economist_multiplier);
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
            player.weapon.reload_active = false;
            player.weapon.reload_timer = 0.0;
            player.weapon.reload_timer_max = 0.0;
            player.weapon.ammo = @floatFromInt(player.weapon.clip_size);
        },
        .weapon => {
            if (perkActive(player.*, PerkId.alternate_weapon) and player.alt_weapon == null) {
                player.alt_weapon = player.weapon;
            }
            const weapon_id = weapon_data.weaponIdFromInt(effective_amount);
            player_runtime.weaponAssignPlayerWithState(player, weapon_id, state);
        },
        .nuke => {
            if (state.pending_nuke_count < state.pending_nuke_origins.len) {
                const slot: usize = @intCast(state.pending_nuke_count);
                state.pending_nuke_origins[slot] = origin_pos orelse player.pos;
                state.pending_nuke_count += 1;
            }
        },
        .shock_chain => {
            if (state.pending_shock_chain_count < state.pending_shock_chain_origins.len) {
                const slot: usize = @intCast(state.pending_shock_chain_count);
                state.pending_shock_chain_origins[slot] = origin_pos orelse player.pos;
                state.pending_shock_chain_count += 1;
            }
        },
        .fireblast => {
            if (state.pending_fireblast_count < state.pending_fireblast_origins.len) {
                const slot: usize = @intCast(state.pending_fireblast_count);
                state.pending_fireblast_origins[slot] = origin_pos orelse player.pos;
                state.pending_fireblast_count += 1;
            }
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

    if (!state.demo_mode_active and unlock_index_full >= 0x28) {
        state.weapon_available.set(.splitter_gun, true);
    }

    state.weapon_available_game_mode = game_mode;
    state.weapon_available_unlock_index = unlock_index;
    state.weapon_available_unlock_index_full = unlock_index_full;
}

pub fn weaponPickRandomAvailable(state: *state_mod.GameplayState) game_ids.WeaponId {
    weaponRefreshAvailable(state);

    for (0..1000) |_| {
        var base_rand = state.rng.rand();
        var weapon_id: i32 = @intCast(base_rand % weapon_drop_id_count + 1);
        var weapon_enum = weapon_data.weaponIdFromInt(weapon_id);

        if (state.status_weapon_usage_counts.get(weapon_enum) != 0 and
            (state.rng.rand() & 1) == 0)
        {
            base_rand = state.rng.rand();
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
    return .pistol;
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
        const roll: i32 = @intCast(state.rng.rand() % 162 + 1);
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
    if (bonus_id == .shield and anyShieldActive(players)) return true;
    if (bonus_id == .weapon and has_fire_bullets_drop) return true;
    if (bonus_id == .weapon and anyPerkActive(players, PerkId.my_favourite_weapon)) return true;
    if (bonus_id == .medikit and anyPerkActive(players, PerkId.death_clock)) return true;
    if (bonus_id == .unused) return true;
    return false;
}

fn anyShieldActive(players: []const state_mod.PlayerState) bool {
    for (players) |player| {
        if (player.shield_timer > 0.0) return true;
    }
    return false;
}

fn bonusIdFromRoll(
    roll: i32,
    state: *state_mod.GameplayState,
) ?BonusId {
    if (roll < 1 or roll > 162) return null;
    if (roll <= 13) return .points;
    if (roll == 14) {
        if ((state.rng.rand() & 0x3f) == 0) return .energizer;
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

fn consumeBonusPickupEffectsRng(
    state: *state_mod.GameplayState,
    bonus_id: BonusId,
) void {
    if (bonus_id != .nuke) {
        // emit_bonus_pickup_effects -> spawn_burst(count=12, scale_step set).
        for (0..12) |_| {
            _ = state.rng.rand();
            _ = state.rng.rand();
            _ = state.rng.rand();
        }
    }
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

    const min_dist_sq = bonus_spawn_min_distance * bonus_spawn_min_distance;
    for (self.entries) |active| {
        if (active.bonus_id == .unused) continue;
        if (distanceSq(pos, active.pos) < min_dist_sq) {
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
        entry.amount = if ((state.rng.rand() & 7) < 3) 1000 else 500;
    } else {
        entry.amount = defaultBonusAmount(bonus_id);
    }

    return slot;
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

test "weapon pick random available enforces unlock table in quests" {
    var state = state_mod.GameplayState.init(1);
    state.game_mode = .quests;
    state.status_quest_unlock_index = 0;
    state.status_quest_unlock_index_full = 0;

    const picked = weaponPickRandomAvailable(&state);
    try std.testing.expectEqual(game_ids.WeaponId.pistol, picked);
}

test "weapon pick random available rerolls used weapons on even gate" {
    const seed = findSeedForWeaponReroll(2_000_000) orelse unreachable;
    var state = state_mod.GameplayState.init(seed);
    state.game_mode = .quests;
    state.status_quest_unlock_index = 1;
    state.status_quest_unlock_index_full = 0;
    state.status_weapon_usage_counts.set(.pistol, 1);

    const picked = weaponPickRandomAvailable(&state);
    try std.testing.expectEqual(game_ids.WeaponId.assault_rifle, picked);
}

fn findSeedForWeaponReroll(max_seed: u32) ?u32 {
    var seed: u32 = 0;
    while (seed < max_seed) : (seed += 1) {
        var state = state_mod.GameplayState.init(seed);
        if ((state.rng.rand() % weapon_drop_id_count) != @as(u32, weaponIdIndex(.pistol))) continue;
        if ((state.rng.rand() & 1) != 0) continue;
        if ((state.rng.rand() % weapon_drop_id_count) != @as(u32, weaponIdIndex(.assault_rifle))) continue;
        return seed;
    }
    return null;
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
