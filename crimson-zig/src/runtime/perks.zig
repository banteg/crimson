const std = @import("std");
const game_ids = @import("../game_ids.zig");
const runtime_helpers = @import("helpers.zig");
const native_math = @import("native_math.zig");

const bonus_runtime = @import("bonuses.zig");
const creature_lifecycle = @import("lifecycle.zig").CreatureLifecycle;
const creatures_mod = @import("creatures.zig");
const effects_mod = @import("effects.zig");
const owner_ref = @import("owner_ref.zig");
const particles_mod = @import("particles.zig");
const player_runtime = @import("player.zig");
const rng_callers = @import("../rng_caller_static.zig");
const spawn_mod = @import("spawn.zig");
const state_mod = @import("state.zig");
const terrain_fx_mod = @import("terrain_fx.zig");

const narrowF32 = native_math.roundF32;

pub const PerkApplyError = error{};

pub const PerkId = game_ids.PerkId;
pub const GameModeId = game_ids.GameModeId;

pub const PerkApplyContext = struct {
    creatures: ?*creatures_mod.CreaturePool = null,
    dt_frame: ?f32 = null,
};

const PerkFlag = enum {
    quest_mode_allowed,
    two_player_allowed,
    stackable,
};
const PerkFlagSet = std.EnumSet(PerkFlag);

pub const perk_id_max: i32 = @intCast(state_mod.perk_count_size - 1);
const perk_id_max_usize: usize = state_mod.perk_count_size - 1;
const perk_base_available_max_id: i32 = 27;
const grim_deal_xp_scale: f32 = @bitCast(@as(u32, 0x3E3851EC));
const breathing_room_fraction: f32 = @bitCast(@as(u32, 0x3F2AAAAB));

inline fn perkIdIndex(perk_id: PerkId) usize {
    return @intCast(@intFromEnum(perk_id));
}

const all_perk_ids = blk: {
    var ids: [state_mod.perk_count_size]PerkId = undefined;
    for (@typeInfo(PerkId).@"enum".fields, 0..) |field, idx| {
        ids[idx] = @enumFromInt(field.value);
    }
    break :blk ids;
};

inline fn perkFlagSet(comptime flags: []const PerkFlag) PerkFlagSet {
    var set = PerkFlagSet.initEmpty();
    inline for (flags) |flag| {
        set.insert(flag);
    }
    return set;
}

const default_perk_flags = perkFlagSet(&.{ .quest_mode_allowed, .two_player_allowed });

const perk_flags_by_id = std.EnumArray(PerkId, PerkFlagSet).initDefault(default_perk_flags, .{
    .instant_winner = perkFlagSet(&.{ .quest_mode_allowed, .two_player_allowed, .stackable }),
    .grim_deal = PerkFlagSet.initEmpty(),
    .alternate_weapon = perkFlagSet(&.{.quest_mode_allowed}),
    .fatal_lottery = perkFlagSet(&.{.stackable}),
    .random_weapon = perkFlagSet(&.{ .quest_mode_allowed, .stackable }),
    .final_revenge = PerkFlagSet.initEmpty(),
    .highlander = PerkFlagSet.initEmpty(),
    .breathing_room = perkFlagSet(&.{.two_player_allowed}),
});

const QuestUnlockPair = struct {
    unlock_index: usize,
    perk_id: PerkId,
};

fn buildQuestUnlockTable(
    comptime entry_count: usize,
    comptime pairs: []const QuestUnlockPair,
) [entry_count]?PerkId {
    var table = [_]?PerkId{null} ** entry_count;
    inline for (pairs) |pair| {
        if (pair.unlock_index >= entry_count) {
            @compileError(std.fmt.comptimePrint(
                "quest unlock index {d} out of range {d}",
                .{ pair.unlock_index, entry_count },
            ));
        }
        if (table[pair.unlock_index] != null) {
            @compileError(std.fmt.comptimePrint(
                "duplicate quest unlock index {d}",
                .{pair.unlock_index},
            ));
        }
        table[pair.unlock_index] = pair.perk_id;
    }
    return table;
}

const quest_unlock_pairs = [_]QuestUnlockPair{
    .{ .unlock_index = 2, .perk_id = .uranium_filled_bullets },
    .{ .unlock_index = 4, .perk_id = .doctor },
    .{ .unlock_index = 6, .perk_id = .monster_vision },
    .{ .unlock_index = 8, .perk_id = .hot_tempered },
    .{ .unlock_index = 10, .perk_id = .bonus_economist },
    .{ .unlock_index = 12, .perk_id = .thick_skinned },
    .{ .unlock_index = 14, .perk_id = .barrel_greaser },
    .{ .unlock_index = 16, .perk_id = .ammunition_within },
    .{ .unlock_index = 18, .perk_id = .veins_of_poison },
    .{ .unlock_index = 20, .perk_id = .toxic_avenger },
    .{ .unlock_index = 22, .perk_id = .regeneration },
    .{ .unlock_index = 24, .perk_id = .pyromaniac },
    .{ .unlock_index = 26, .perk_id = .ninja },
    .{ .unlock_index = 28, .perk_id = .highlander },
    .{ .unlock_index = 30, .perk_id = .jinxed },
    .{ .unlock_index = 32, .perk_id = .perk_master },
    .{ .unlock_index = 34, .perk_id = .reflex_boosted },
    .{ .unlock_index = 36, .perk_id = .greater_regeneration },
    .{ .unlock_index = 38, .perk_id = .breathing_room },
    .{ .unlock_index = 41, .perk_id = .death_clock },
    .{ .unlock_index = 42, .perk_id = .my_favourite_weapon },
    .{ .unlock_index = 44, .perk_id = .bandage },
    .{ .unlock_index = 45, .perk_id = .angry_reloader },
    .{ .unlock_index = 47, .perk_id = .ion_gun_master },
    .{ .unlock_index = 48, .perk_id = .stationary_reloader },
};

const quest_unlock_perk_by_index = buildQuestUnlockTable(50, &quest_unlock_pairs);

const perk_always_available = [_]PerkId{
    PerkId.man_bomb,
    PerkId.living_fortress,
    PerkId.fire_caugh,
    PerkId.tough_reloader,
};

pub fn perksRebuildAvailable(
    state: *state_mod.GameplayState,
    quest_unlock_index: i32,
) void {
    state.perk_available = state_mod.PerkAvailability.initFill(false);

    var perk_id: i32 = 1;
    while (perk_id <= perk_base_available_max_id) : (perk_id += 1) {
        if (perk_id >= state_mod.perk_count_size) break;
        state.perk_available.set(@enumFromInt(perk_id), true);
    }

    for (perk_always_available) |always_id| {
        state.perk_available.set(always_id, true);
    }

    if (quest_unlock_index > 0) {
        const limit: usize = @min(
            @as(usize, @intCast(quest_unlock_index)),
            quest_unlock_perk_by_index.len,
        );
        for (quest_unlock_perk_by_index[0..limit]) |maybe_perk_id| {
            if (maybe_perk_id) |perk_unlock_id| {
                state.perk_available.set(perk_unlock_id, true);
            }
        }
    }

    state.perk_available.set(PerkId.antiperk, false);
    state.perk_available_unlock_index = quest_unlock_index;
}

pub fn buildPerkAvailabilityForUnlockIndex(quest_unlock_index: i32) state_mod.PerkAvailability {
    var availability = state_mod.PerkAvailability.initFill(false);

    var perk_id: i32 = 1;
    while (perk_id <= perk_base_available_max_id) : (perk_id += 1) {
        if (perk_id >= state_mod.perk_count_size) break;
        availability.set(@enumFromInt(perk_id), true);
    }

    for (perk_always_available) |always_id| {
        availability.set(always_id, true);
    }

    if (quest_unlock_index > 0) {
        const limit: usize = @min(
            @as(usize, @intCast(quest_unlock_index)),
            quest_unlock_perk_by_index.len,
        );
        for (quest_unlock_perk_by_index[0..limit]) |maybe_perk_id| {
            if (maybe_perk_id) |perk_unlock_id| {
                availability.set(perk_unlock_id, true);
            }
        }
    }

    availability.set(PerkId.antiperk, false);
    return availability;
}

pub fn questUnlockPerkForIndex(global_index: i32) ?PerkId {
    if (global_index < 0 or global_index >= quest_unlock_perk_by_index.len) return null;
    return quest_unlock_perk_by_index[@intCast(global_index)];
}

pub fn perkChoiceCount(player: *const state_mod.PlayerState) i32 {
    if (perkCountGet(player, PerkId.perk_master) > 0) return 7;
    if (perkCountGet(player, PerkId.perk_expert) > 0) return 6;
    return 5;
}

pub fn perkSelectionPreparedChoices(
    players: []state_mod.PlayerState,
    perk_selection: *const state_mod.PerkSelectionState,
) []const PerkId {
    if (players.len == 0) return &.{};
    if (perk_selection.choices_dirty or perk_selection.choice_count == 0) return &.{};
    const visible_count: usize = @intCast(std.math.clamp(
        perkChoiceCount(&players[0]),
        1,
        @as(i32, @intCast(perk_selection.choice_count)),
    ));
    return perk_selection.choices[0..visible_count];
}

pub fn perkSelectionOpenChoices(
    state: *state_mod.GameplayState,
    players: []state_mod.PlayerState,
    game_mode: GameModeId,
    player_count: i32,
    quest_unlock_index: i32,
) []const PerkId {
    _ = perkSelectionCurrentChoices(
        state,
        players,
        game_mode,
        player_count,
        quest_unlock_index,
    );
    return perkSelectionPreparedChoices(players, &state.perk_selection);
}

pub fn perkSelectionCurrentChoices(
    state: *state_mod.GameplayState,
    players: []state_mod.PlayerState,
    game_mode: GameModeId,
    player_count: i32,
    quest_unlock_index: i32,
) []const PerkId {
    if (players.len == 0) return &.{};
    const player = &players[0];

    if (state.perk_selection.choices_dirty or state.perk_selection.choice_count == 0) {
        state.perk_selection.choices = perkGenerateChoices(
            state,
            players,
            player,
            game_mode,
            player_count,
            quest_unlock_index,
        );
        state.perk_selection.choice_count = state.perk_selection.choices.len;
        state.perk_selection.choices_dirty = false;
    }

    const visible_count: usize = @intCast(std.math.clamp(
        perkChoiceCount(player),
        1,
        @as(i32, @intCast(state.perk_selection.choice_count)),
    ));
    return state.perk_selection.choices[0..visible_count];
}

pub fn perkSelectionPick(
    state: *state_mod.GameplayState,
    players: []state_mod.PlayerState,
    choice_index: i32,
    game_mode: GameModeId,
    player_count: i32,
    quest_unlock_index: i32,
) PerkApplyError!?PerkId {
    return perkSelectionPickWithContext(
        state,
        players,
        choice_index,
        game_mode,
        player_count,
        quest_unlock_index,
        .{},
    );
}

pub fn perkSelectionPickWithContext(
    state: *state_mod.GameplayState,
    players: []state_mod.PlayerState,
    choice_index: i32,
    game_mode: GameModeId,
    player_count: i32,
    quest_unlock_index: i32,
    context: PerkApplyContext,
) PerkApplyError!?PerkId {
    if (players.len == 0) return null;
    if (state.perk_selection.pending_count <= 0) return null;

    const choices = perkSelectionCurrentChoices(
        state,
        players,
        game_mode,
        player_count,
        quest_unlock_index,
    );
    if (choices.len == 0) return null;
    if (choice_index < 0 or choice_index >= choices.len) return null;

    const perk_id = choices[@intCast(choice_index)];
    try applyPerkWithContext(state, players, perk_id, context);

    state.perk_selection.pending_count = @max(0, state.perk_selection.pending_count - 1);
    state.perk_selection.choices_dirty = true;

    _ = perkSelectionCurrentChoices(
        state,
        players,
        game_mode,
        player_count,
        quest_unlock_index,
    );
    return perk_id;
}

/// Apply a replayed pick from the choices prepared by an earlier menu-open.
///
/// Native capture order matters: picking marks the cache dirty, but does not
/// generate the next offer. A later explicit menu-open owns that RNG work.
pub fn perkSelectionPickPreparedWithContext(
    state: *state_mod.GameplayState,
    players: []state_mod.PlayerState,
    choice_index: i32,
    context: PerkApplyContext,
) PerkApplyError!?PerkId {
    if (players.len == 0) return null;
    if (state.perk_selection.pending_count <= 0) return null;

    const choices = perkSelectionPreparedChoices(players, &state.perk_selection);
    if (choices.len == 0) return null;
    if (choice_index < 0 or choice_index >= choices.len) return null;

    const perk_id = choices[@intCast(choice_index)];
    try applyPerkWithContext(state, players, perk_id, context);
    state.perk_selection.pending_count = @max(0, state.perk_selection.pending_count - 1);
    state.perk_selection.choices_dirty = true;
    return perk_id;
}

pub fn applyPerk(
    state: *state_mod.GameplayState,
    players: []state_mod.PlayerState,
    perk_id: PerkId,
) PerkApplyError!void {
    return applyPerkWithContext(state, players, perk_id, .{});
}

pub fn applyPerkWithContext(
    state: *state_mod.GameplayState,
    players: []state_mod.PlayerState,
    perk_id: PerkId,
    context: PerkApplyContext,
) PerkApplyError!void {
    if (players.len == 0) return;
    players[0].perk_counts.set(perk_id, players[0].perk_counts.get(perk_id) + 1);
    if (players.len > 1) {
        const shared = players[0].perk_counts;
        for (players[1..]) |*player| {
            player.perk_counts = shared;
        }
    }

    switch (perk_id) {
        PerkId.instant_winner => {
            players[0].experience += 2500;
        },
        PerkId.grim_deal => {
            const experience = players[0].experience;
            const bonus: i32 = @intFromFloat(native_math.pc24Mul(
                @as(f64, @floatFromInt(experience)),
                grim_deal_xp_scale,
            ));
            players[0].health = -1.0;
            players[0].experience = experience + bonus;
        },
        PerkId.plaguebearer => {
            const plaguebearer_players = if (state.preserve_bugs) players[0..1] else players;
            for (plaguebearer_players) |*player| {
                player.plaguebearer_active = true;
            }
        },
        PerkId.ammo_maniac => {
            for (players) |*player| {
                player_runtime.weaponAssignPlayerWithState(player, player.weapon.weapon_id, state);
            }
        },
        PerkId.fatal_lottery => {
            if ((state.rng.randTagged(rng_callers.perk_apply_fatal_lottery) & 1) != 0) {
                players[0].health = -1.0;
            } else {
                players[0].experience += 10_000;
            }
        },
        PerkId.infernal_contract => {
            players[0].level += 3;
            state.perk_selection.pending_count += 3;
            state.perk_selection.choices_dirty = true;
            const contract_players = if (state.preserve_bugs)
                players[0..@min(players.len, 2)]
            else
                players;
            for (contract_players) |*player| {
                if (player.health > 0.0) player.health = 0.1;
            }
        },
        PerkId.thick_skinned => {
            for (players) |*player| {
                if (player.health > 0.0) {
                    // Native computes `h - h * 0.33333334f` and stores f32. Its
                    // `= 1.0` clamp only fires when the result is <= 0, which
                    // cannot happen for positive health - dead code, no floor.
                    player.health = native_math.pc24Sub(
                        player.health,
                        native_math.pc24Mul(player.health, 0.33333334),
                    );
                }
            }
        },
        PerkId.death_clock => {
            adjustPerkCount(&players[0], PerkId.regeneration, -perkCountGet(&players[0], PerkId.regeneration));
            adjustPerkCount(&players[0], PerkId.greater_regeneration, -perkCountGet(&players[0], PerkId.greater_regeneration));
            if (players.len > 1) {
                const shared = players[0].perk_counts;
                for (players[1..]) |*player| {
                    player.perk_counts = shared;
                }
            }
            for (players) |*player| {
                if (player.health > 0.0) player.health = 100.0;
            }
        },
        PerkId.my_favourite_weapon => {
            for (players) |*player| {
                player.weapon.clip_size += 2;
            }
        },
        PerkId.random_weapon => {
            const current = players[0].weapon.weapon_id;
            var selected = current;
            for (0..100) |_| {
                const candidate = bonus_runtime.weaponPickRandomAvailable(state);
                selected = candidate;
                if (candidate != game_ids.WeaponId.pistol and candidate != current) break;
            }
            player_runtime.weaponAssignPlayerWithState(&players[0], selected, state);
        },
        PerkId.breathing_room => {
            for (players) |*player| {
                const reduction = native_math.pc24Mul(player.health, breathing_room_fraction);
                player.health = native_math.pc24Sub(player.health, reduction);
            }
            applyPerkImmediateCreatureEffects(perk_id, state, context);
            state.bonus_spawn_guard = false;
        },
        PerkId.bandage => {
            var effects: effects_mod.EffectPool = .{};
            for (players) |*player| {
                // The native loop has no alive gate: dead players consume the
                // rand, have their negative health multiplied, and spawn a burst
                // at the corpse. Default mode keeps the documented fix of
                // healing only alive players (original-bugs.md item 3).
                if (!state.preserve_bugs and player.health <= 0.0) continue;
                const amount: f32 = @floatFromInt(state.rng.randTagged(rng_callers.perk_apply_bandage_heal) % 50 + 1);
                if (state.preserve_bugs) {
                    player.health = @min(100.0, native_math.pc24Mul(player.health, amount));
                } else {
                    player.health = @min(100.0, native_math.pc24Add(player.health, amount));
                }
                effects.spawnBurst(
                    state,
                    player.pos,
                    8,
                    5,
                    0.4,
                    null,
                    .{ .r = 1.0, .g = 1.0, .b = 1.0, .a = 1.0 },
                );
            }
        },
        PerkId.lifeline_50_50 => applyPerkImmediateCreatureEffects(perk_id, state, context),
        else => {},
    }
}

pub fn applyReplayPerkCreatureEffects(
    perk_id: PerkId,
    state: *state_mod.GameplayState,
    creatures: *creatures_mod.CreaturePool,
    dt_frame: f32,
) void {
    var effects: effects_mod.EffectPool = .{};
    applyPerkImmediateCreatureEffectsWithEffects(perk_id, state, &effects, 5, .{
        .creatures = creatures,
        .dt_frame = dt_frame,
    });
}

fn applyPerkImmediateCreatureEffects(
    perk_id: PerkId,
    state: *state_mod.GameplayState,
    context: PerkApplyContext,
) void {
    var effects: effects_mod.EffectPool = .{};
    applyPerkImmediateCreatureEffectsWithEffects(perk_id, state, &effects, 5, context);
}

fn applyPerkImmediateCreatureEffectsWithEffects(
    perk_id: PerkId,
    state: *state_mod.GameplayState,
    effects: *effects_mod.EffectPool,
    detail_preset: i32,
    context: PerkApplyContext,
) void {
    const creatures = context.creatures orelse return;
    const dt_frame = context.dt_frame orelse 0.0;
    switch (perk_id) {
        PerkId.breathing_room => {
            for (&creatures.entries) |*creature| {
                if (!creature.active) continue;
                creature.lifecycle_stage = native_math.pc24Sub(creature.lifecycle_stage, dt_frame);
            }
        },
        PerkId.lifeline_50_50 => {
            var kill_toggle = false;
            for (&creatures.entries) |*creature| {
                if (kill_toggle and
                    creature.active and
                    creature.hp <= 500.0 and
                    (creature.flags & spawn_mod.CreatureFlags.anim_ping_pong) == 0)
                {
                    creature.active = false;
                    effects.spawnBurst(
                        state,
                        creature.pos,
                        4,
                        detail_preset,
                        0.4,
                        null,
                        .{ .r = 1.0, .g = 1.0, .b = 1.0, .a = 1.0 },
                    );
                }
                kill_toggle = !kill_toggle;
            }
        },
        else => {},
    }
}

pub fn updatePerkEffects(
    state: *state_mod.GameplayState,
    players: []state_mod.PlayerState,
    dt: f32,
) void {
    if (dt > 0.0) {
        for (players) |*player| {
            if (player.shield_timer <= 0.0) {
                player.shield_timer = 0.0;
            } else {
                player.shield_timer = native_math.pc24Sub(player.shield_timer, dt);
            }

            if (player.fire_bullets_timer <= 0.0) {
                player.fire_bullets_timer = 0.0;
            } else {
                player.fire_bullets_timer = native_math.pc24Sub(player.fire_bullets_timer, dt);
            }

            if (player.speed_bonus_timer <= 0.0) {
                player.speed_bonus_timer = 0.0;
            } else {
                player.speed_bonus_timer = native_math.pc24Sub(player.speed_bonus_timer, dt);
            }
        }
    }

    if (players.len == 0) return;

    if (dt > 0.0 and
        perkActive(&players[0], PerkId.regeneration) and
        (state.rng.randTagged(rng_callers.perks_update_effects_regeneration_gate) & 1) != 0)
    {
        if (state.preserve_bugs) {
            var repeat: usize = 0;
            while (repeat < players.len) : (repeat += 1) {
                if (players[0].health <= 0.0 or players[0].health >= 100.0) continue;
                players[0].health = native_math.pc24Add(players[0].health, dt);
                if (players[0].health > 100.0) {
                    players[0].health = 100.0;
                }
            }
        } else {
            var heal_amount = dt;
            if (perkActive(&players[0], PerkId.greater_regeneration)) {
                heal_amount = native_math.pc24Mul(dt, @as(f32, 2.0));
            }
            for (players) |*player| {
                if (player.health <= 0.0 or player.health >= 100.0) continue;
                player.health = native_math.pc24Add(player.health, heal_amount);
                if (player.health > 100.0) {
                    player.health = 100.0;
                }
            }
        }
    }

    state.lean_mean_exp_timer = native_math.pc24Sub(state.lean_mean_exp_timer, dt);
    if (state.lean_mean_exp_timer < 0.0) {
        state.lean_mean_exp_timer = 0.25;
        const perk_count = perkCountGet(&players[0], PerkId.lean_mean_exp_machine);
        if (perk_count > 0) {
            players[0].experience += perk_count * 10;
        }
    }

    if (!perkActive(&players[0], PerkId.death_clock)) return;

    const death_clock_drain = native_math.pc24Mul(dt, @as(f32, 3.33333325));
    for (players) |*player| {
        if (player.health <= 0.0) {
            player.health = 0.0;
        } else {
            player.health = native_math.pc24Sub(player.health, death_clock_drain);
        }
    }
}

pub fn updateEvilEyesTargets(
    preserve_bugs: bool,
    players: []state_mod.PlayerState,
    creatures: []const creatures_mod.CreatureState,
) void {
    if (players.len == 0) return;
    const effect_players = if (preserve_bugs) players[0..1] else players;
    for (effect_players) |*player| {
        if ((!preserve_bugs and player.health <= 0.0) or !perkActive(player, PerkId.evil_eyes)) {
            player.evil_eyes_target_creature = -1;
            continue;
        }
        player.evil_eyes_target_creature = creatureFindInRadius(creatures, player.aim, 12.0, 0);
    }
}

pub fn applyPyrokineticEffects(
    state: *state_mod.GameplayState,
    players: []state_mod.PlayerState,
    creatures: *creatures_mod.CreaturePool,
    particles: *particles_mod.ParticlePool,
    terrain_fx: *terrain_fx_mod.TerrainFxScratch,
    dt: f32,
) void {
    if (!(dt > 0.0)) return;
    if (players.len == 0) return;

    const burn_intensities = [_]f32{ 0.8, 0.6, 0.4, 0.3, 0.2 };

    const effect_players = if (state.preserve_bugs) players[0..1] else players;
    for (effect_players) |*player| {
        if (!state.preserve_bugs and player.health <= 0.0) continue;
        if (!perkActive(player, PerkId.pyrokinetic)) continue;

        const target_idx = creatureFindInRadius(creatures.entries[0..], player.aim, 12.0, 0);
        if (target_idx == -1) continue;

        var creature = &creatures.entries[@intCast(target_idx)];
        creature.collision_timer = narrowF32(creature.collision_timer - dt);
        if (creature.collision_timer >= 0.0) continue;

        creature.collision_timer = 0.5;
        for (burn_intensities, 0..) |intensity, burn_idx| {
            const caller = switch (burn_idx) {
                0 => rng_callers.perks_update_effects_pyrokinetic_angle_0p8,
                1 => rng_callers.perks_update_effects_pyrokinetic_angle_0p6,
                2 => rng_callers.perks_update_effects_pyrokinetic_angle_0p4,
                3 => rng_callers.perks_update_effects_pyrokinetic_angle_0p3,
                else => rng_callers.perks_update_effects_pyrokinetic_angle_0p2,
            };
            const angle = narrowF32(@as(f32, @floatFromInt(state.rng.randTagged(caller) % 0x274)) * 0.01);
            _ = particles.spawnParticle(
                state,
                creature.pos,
                angle,
                intensity,
                owner_ref.OwnerRef.fromLocalPlayer(0),
            );
        }
        _ = terrain_fx.decals.addRandom(state, creature.pos);
    }
}

pub fn applyJinxedEffects(
    state: *state_mod.GameplayState,
    players: []state_mod.PlayerState,
    creatures: *creatures_mod.CreaturePool,
    terrain_fx: *terrain_fx_mod.TerrainFxScratch,
    dt: f32,
) void {
    if (state.jinxed_timer >= 0.0) {
        state.jinxed_timer = narrowF32(state.jinxed_timer - dt);
    }
    if (state.jinxed_timer >= 0.0) return;
    if (players.len == 0) return;
    if (!perkActive(&players[0], PerkId.jinxed)) return;

    if ((state.rng.randTagged(rng_callers.perks_update_effects_jinxed_accident_gate) % 10) == 3) {
        const target_idx = selectJinxedAccidentTarget(state, players);
        players[target_idx].health = narrowF32(players[target_idx].health - 5.0);
        _ = terrain_fx.decals.addRandom(state, players[target_idx].pos);
        _ = terrain_fx.decals.addRandom(state, players[target_idx].pos);
    }

    const timer_roll = @as(f32, @floatFromInt(state.rng.randTagged(rng_callers.perks_update_effects_jinxed_timer_reset) % 0x14));
    state.jinxed_timer = narrowF32(narrowF32(timer_roll * 0.1) + state.jinxed_timer + 2.0);

    if (state.bonuses.freeze > 0.0) return;

    const pool_mod = jinxedCreaturePoolMod(
        state.preserve_bugs,
        creatures.entries.len,
    );
    if (pool_mod == 0) return;

    var idx: usize = @intCast(state.rng.randTagged(rng_callers.perks_update_effects_jinxed_creature_pick) % @as(u32, @intCast(pool_mod)));
    var attempts: usize = 0;
    while (attempts < 10 and !creatures.entries[idx].active) : (attempts += 1) {
        idx = @intCast(state.rng.randTagged(rng_callers.perks_update_effects_jinxed_creature_retry) % @as(u32, @intCast(pool_mod)));
    }
    if (!creatures.entries[idx].active) return;

    creatures.entries[idx].hp = -1.0;
    creatures.entries[idx].lifecycle_stage = narrowF32(
        creatures.entries[idx].lifecycle_stage - dt * 20.0,
    );
    // Native awards the reward exactly once: the Jinxed kill branch has no
    // Double Experience handling, unlike creature_handle_death.
    _ = awardExperienceOnceFromReward(&players[0], creatures.entries[idx].reward_value);
    state.sfx_queue.append(.trooper_inpain_01);
}

fn jinxedCreaturePoolMod(preserve_bugs: bool, creature_count: usize) usize {
    const pool_limit: usize = if (preserve_bugs) 0x17f else 0x180;
    return @min(pool_limit, creature_count);
}

pub fn applyFinalRevengeOnDeathTransition(
    state: *state_mod.GameplayState,
    players: []state_mod.PlayerState,
    player_index: usize,
    health_before: f32,
    player1_health_before: f32,
    creatures: *creatures_mod.CreaturePool,
    bonuses: *bonus_runtime.BonusPool,
    dt: f32,
    world_size: f32,
    detail_preset: i32,
) void {
    var effects: effects_mod.EffectPool = .{};
    var terrain_fx: terrain_fx_mod.TerrainFxScratch = .{};
    applyFinalRevengeOnDeathTransitionWithEffects(
        state,
        players,
        player_index,
        health_before,
        player1_health_before,
        creatures,
        bonuses,
        &effects,
        &terrain_fx,
        dt,
        world_size,
        detail_preset,
    );
}

pub fn applyFinalRevengeOnDeathTransitionWithEffects(
    state: *state_mod.GameplayState,
    players: []state_mod.PlayerState,
    player_index: usize,
    health_before: f32,
    player1_health_before: f32,
    creatures: *creatures_mod.CreaturePool,
    bonuses: *bonus_runtime.BonusPool,
    effects: *effects_mod.EffectPool,
    terrain_fx: *terrain_fx_mod.TerrainFxScratch,
    dt: f32,
    world_size: f32,
    detail_preset: i32,
) void {
    if (player_index >= players.len) return;
    const player = &players[player_index];
    const perk_player = if (state.preserve_bugs) &players[0] else player;
    const was_alive = if (state.preserve_bugs) player1_health_before > 0.0 else health_before > 0.0;
    const lethal = if (state.preserve_bugs) player.health < 0.0 else player.health <= 0.0;
    if (!was_alive or !lethal) return;
    if (!perkActive(perk_player, PerkId.final_revenge)) return;

    effects.spawnExplosionBurst(state, player.pos, 1.8, detail_preset);
    state.bonus_spawn_guard = true;

    const owner = owner_ref.OwnerRef.fromPlayer(@intCast(player.index));
    for (creatures.entries, 0..) |creature, idx| {
        if (!creature.active) continue;
        const dx = native_math.pc24Sub(creature.pos.x, player.pos.x);
        const dy = native_math.pc24Sub(creature.pos.y, player.pos.y);
        if (@abs(dx) > 512.0 or @abs(dy) > 512.0) continue;
        const distance = native_math.pc24Hypot(dx, dy);
        const remaining = native_math.pc24Sub(512.0, distance);
        if (!(remaining > 0.0)) continue;
        const damage = native_math.pc24Mul(remaining, 5.0);
        _ = creatures.applyExplosionDamage(
            state,
            players,
            bonuses,
            terrain_fx,
            idx,
            damage,
            .{},
            owner,
            dt,
            world_size,
            null,
        );
    }
    state.bonus_spawn_guard = false;
    state.sfx_queue.append(.explosion_large);
    state.sfx_queue.append(.shockwave);
}

pub fn creatureFindInRadius(
    creatures: []const creatures_mod.CreatureState,
    pos: state_mod.Vec2,
    radius: f32,
    start_index: usize,
) i32 {
    var idx = start_index;
    const max_index = @min(creatures.len, creatures_mod.max_creatures);
    while (idx < max_index) : (idx += 1) {
        const creature = creatures[idx];
        if (!creature.active) continue;
        if (!creature_lifecycle.isCollidable(creature.lifecycle_stage)) continue;
        if (!runtime_helpers.withinNativeFindRadius(pos, creature.pos, radius, creature.size)) continue;
        return @intCast(idx);
    }
    return -1;
}

fn selectJinxedAccidentTarget(
    state: *state_mod.GameplayState,
    players: []const state_mod.PlayerState,
) usize {
    if (players.len == 0) return 0;

    var alive_indices = [_]usize{0} ** state_mod.max_players;
    var alive_count: usize = 0;
    for (players, 0..) |player, idx| {
        if (player.health <= 0.0) continue;
        if (alive_count >= alive_indices.len) break;
        alive_indices[alive_count] = idx;
        alive_count += 1;
    }
    if (alive_count == 0) return 0;
    if (alive_count == 1) return alive_indices[0];
    const pick = state.rng.randTagged(rng_callers.rewrite_jinxed_accident_target_pick) % @as(u32, @intCast(alive_count));
    return alive_indices[@intCast(pick)];
}

fn awardExperienceFromReward(
    state: *state_mod.GameplayState,
    player: *state_mod.PlayerState,
    reward_value: f32,
) void {
    const first_gain = awardExperienceOnceFromReward(player, reward_value);
    if (first_gain <= 0) return;
    if (state.bonuses.double_experience > 0.0) {
        _ = awardExperienceOnceFromReward(player, reward_value);
    }
}

fn awardExperienceOnceFromReward(
    player: *state_mod.PlayerState,
    reward_value: f32,
) i32 {
    if (reward_value <= 0.0) return 0;

    const before = player.experience;
    const before_f32 = narrowF32(@as(f32, @floatFromInt(before)));
    const total_f32 = narrowF32(before_f32 + reward_value);
    const after: i32 = @intFromFloat(total_f32);
    player.experience = after;
    return after - before;
}

fn perkGenerateChoices(
    state: *state_mod.GameplayState,
    players: []const state_mod.PlayerState,
    player: *const state_mod.PlayerState,
    game_mode: GameModeId,
    player_count: i32,
    quest_unlock_index: i32,
) [7]PerkId {
    perksRebuildAvailable(state, quest_unlock_index);

    var offerable = [_]bool{false} ** (perk_id_max_usize + 1);
    for (all_perk_ids[1..]) |perk_id| {
        const perk_idx = perkIdIndex(perk_id);
        if (!state.perk_available.get(perk_id)) continue;
        if (perkCanOffer(state, player, perk_id, game_mode, player_count)) {
            offerable[perk_idx] = true;
        }
    }

    const death_clock_active = perkActive(player, PerkId.death_clock);
    const pyromaniac_allowed = pyromaniacAllowed(state, players, player, player_count);

    var choices = [_]PerkId{.antiperk} ** 7;
    var choice_index: usize = 0;

    if (state.quest_stage_major == 3 and state.quest_stage_minor == 4 and !perkActive(player, PerkId.monster_vision)) {
        choices[0] = .monster_vision;
        choice_index = 1;
    }

    while (choice_index < choices.len) : (choice_index += 1) {
        var attempts: i32 = 0;
        var selected: PerkId = .instant_winner;
        while (true) {
            attempts += 1;
            const candidate = selectRandomOffer(state, &offerable);

            if (candidate == PerkId.pyromaniac and !pyromaniac_allowed) continue;
            if (death_clock_active and isDeathClockBlocked(candidate)) continue;
            if (isRarityGate(candidate) and ((state.rng.randTagged(rng_callers.perks_generate_choices_rarity_gate) & 3) == 1)) continue;

            const flags = perkFlags(candidate);
            const stackable = flags.contains(.stackable);
            if (attempts > 10_000 and stackable) {
                selected = candidate;
                break;
            }
            if (containsPerkId(choices[0..choice_index], candidate)) continue;
            if (stackable or perkCountGet(player, candidate) < 1 or attempts > 29_999) {
                selected = candidate;
                break;
            }
        }
        choices[choice_index] = selected;
    }

    if (game_mode == .tutorial) {
        choices = .{
            .sharpshooter,
            .long_distance_runner,
            .evil_eyes,
            .radioactive,
            .fastshot,
            .fastshot,
            .fastshot,
        };
    }

    return choices;
}

fn pyromaniacAllowed(
    state: *const state_mod.GameplayState,
    players: []const state_mod.PlayerState,
    player: *const state_mod.PlayerState,
    player_count: i32,
) bool {
    if (player.weapon.weapon_id == game_ids.WeaponId.flamethrower) return true;
    if (state.preserve_bugs or player_count <= 1) return false;

    for (players) |source_player| {
        if (source_player.health <= 0.0) continue;
        if (source_player.weapon.weapon_id == game_ids.WeaponId.flamethrower) return true;
    }
    return false;
}

fn selectRandomOffer(state: *state_mod.GameplayState, offerable: []const bool) PerkId {
    var draws: i32 = 0;
    while (draws < 1000) : (draws += 1) {
        const candidate_raw: i32 = @intCast(state.rng.randTagged(rng_callers.perk_select_random) % @as(u32, @intCast(perk_id_max)) + 1);
        if (candidate_raw >= 0 and candidate_raw < offerable.len and offerable[@intCast(candidate_raw)]) {
            return @enumFromInt(candidate_raw);
        }
    }
    return .instant_winner;
}

fn perkCanOffer(
    state: *const state_mod.GameplayState,
    player: *const state_mod.PlayerState,
    perk_id: PerkId,
    game_mode: GameModeId,
    player_count: i32,
) bool {
    if (game_mode == .quests and
        state.hardcore and
        state.quest_stage_major == 2 and
        state.quest_stage_minor == 10 and
        (perk_id == .poison_bullets or perk_id == .veins_of_poison or perk_id == .plaguebearer))
    {
        return false;
    }

    const flags = perkFlags(perk_id);
    if (game_mode == .quests and !flags.contains(.quest_mode_allowed)) {
        return false;
    }
    if (player_count == 2 and !flags.contains(.two_player_allowed)) {
        return false;
    }
    if (!prereqSatisfied(player, perk_id)) return false;
    return true;
}

fn prereqSatisfied(player: *const state_mod.PlayerState, perk_id: PerkId) bool {
    return switch (perk_id) {
        PerkId.toxic_avenger => perkCountGet(player, PerkId.veins_of_poison) > 0,
        PerkId.ninja => perkCountGet(player, PerkId.dodger) > 0,
        PerkId.perk_master => perkCountGet(player, PerkId.perk_expert) > 0,
        PerkId.greater_regeneration => perkCountGet(player, PerkId.regeneration) > 0,
        else => true,
    };
}

fn perkFlags(perk_id: PerkId) PerkFlagSet {
    return perk_flags_by_id.get(perk_id);
}

fn perkCountGet(player: *const state_mod.PlayerState, perk_id: PerkId) i32 {
    return player.perk_counts.get(perk_id);
}

fn adjustPerkCount(player: *state_mod.PlayerState, perk_id: PerkId, amount: i32) void {
    const current = player.perk_counts.get(perk_id);
    player.perk_counts.set(perk_id, @max(0, current + amount));
}

pub fn perkActive(player: *const state_mod.PlayerState, perk_id: PerkId) bool {
    return perkCountGet(player, perk_id) > 0;
}

fn containsPerkId(values: []const PerkId, needle: PerkId) bool {
    for (values) |value| {
        if (value == needle) return true;
    }
    return false;
}

fn isRarityGate(perk_id: PerkId) bool {
    return perk_id == PerkId.jinxed or
        perk_id == PerkId.ammunition_within or
        perk_id == PerkId.anxious_loader or
        perk_id == PerkId.monster_vision;
}

fn isDeathClockBlocked(perk_id: PerkId) bool {
    return perk_id == PerkId.jinxed or
        perk_id == PerkId.breathing_room or
        perk_id == PerkId.grim_deal or
        perk_id == PerkId.highlander or
        perk_id == PerkId.fatal_lottery or
        perk_id == PerkId.ammunition_within or
        perk_id == PerkId.infernal_contract or
        perk_id == PerkId.regeneration or
        perk_id == PerkId.greater_regeneration or
        perk_id == PerkId.thick_skinned or
        perk_id == PerkId.bandage;
}

test "perk menu open consumes rng and caches choices" {
    var state = state_mod.GameplayState.init(0x1234);
    var players = [_]state_mod.PlayerState{
        .{ .index = 0, .pos = .{} },
    };
    const before = state.rng.state;
    const choices = perkSelectionCurrentChoices(
        &state,
        players[0..],
        .survival,
        1,
        49,
    );
    try std.testing.expect(choices.len > 0);
    try std.testing.expect(before != state.rng.state);
    try std.testing.expect(!state.perk_selection.choices_dirty);
}

test "quest unlock perk lookup exposes exact reward table rows" {
    try std.testing.expectEqual(PerkId.uranium_filled_bullets, questUnlockPerkForIndex(2).?);
    try std.testing.expectEqual(PerkId.death_clock, questUnlockPerkForIndex(41).?);
    try std.testing.expectEqual(@as(?PerkId, null), questUnlockPerkForIndex(0));
    try std.testing.expectEqual(@as(?PerkId, null), questUnlockPerkForIndex(-1));
    try std.testing.expectEqual(@as(?PerkId, null), questUnlockPerkForIndex(50));
}

test "antiperk is excluded by availability rather than offer predicate" {
    var state = state_mod.GameplayState.init(1);
    const player: state_mod.PlayerState = .{
        .index = 0,
        .pos = .{},
    };
    try std.testing.expect(perkCanOffer(
        &state,
        &player,
        PerkId.antiperk,
        .survival,
        1,
    ));
    try std.testing.expect(!buildPerkAvailabilityForUnlockIndex(0).get(.antiperk));
}

test "hardcore quest 2-10 blocks poison perks" {
    var state = state_mod.GameplayState.init(1);
    const player: state_mod.PlayerState = .{
        .index = 0,
        .pos = .{},
    };
    state.hardcore = true;
    state.quest_stage_major = 2;
    state.quest_stage_minor = 10;

    try std.testing.expect(!perkCanOffer(&state, &player, .poison_bullets, .quests, 1));
    try std.testing.expect(!perkCanOffer(&state, &player, .veins_of_poison, .quests, 1));
    try std.testing.expect(!perkCanOffer(&state, &player, .plaguebearer, .quests, 1));

    state.quest_stage_minor = 9;
    try std.testing.expect(perkCanOffer(&state, &player, .poison_bullets, .quests, 1));
}

test "perk availability rebuild clears stale state at the same unlock index" {
    var state = state_mod.GameplayState.init(1);
    state.perk_available_unlock_index = 0;
    state.perk_available.set(PerkId.antiperk, true);
    state.perk_available.set(PerkId.sharpshooter, false);

    perksRebuildAvailable(&state, 0);

    try std.testing.expect(!state.perk_available.get(PerkId.antiperk));
    try std.testing.expect(state.perk_available.get(PerkId.sharpshooter));
}

test "perk pick decrements pending and refreshes choices" {
    var state = state_mod.GameplayState.init(0x1234);
    var players = [_]state_mod.PlayerState{
        .{ .index = 0, .pos = .{} },
    };
    state.perk_selection.pending_count = 1;
    state.perk_selection.choices_dirty = true;

    _ = perkSelectionCurrentChoices(
        &state,
        players[0..],
        .survival,
        1,
        49,
    );
    const picked = try perkSelectionPick(
        &state,
        players[0..],
        0,
        .survival,
        1,
        49,
    );
    try std.testing.expect(picked != null);
    try std.testing.expectEqual(@as(i32, 0), state.perk_selection.pending_count);
    try std.testing.expect(!state.perk_selection.choices_dirty);
}

test "perk generate choices forces monster vision first on quest 3-4" {
    var state = state_mod.GameplayState.init(0x1234);
    state.quest_stage_major = 3;
    state.quest_stage_minor = 4;
    var players = [_]state_mod.PlayerState{
        .{ .index = 0, .pos = .{} },
    };

    const choices = perkSelectionCurrentChoices(
        &state,
        players[0..],
        .quests,
        1,
        49,
    );
    try std.testing.expect(choices.len >= 1);
    try std.testing.expectEqual(PerkId.monster_vision, choices[0]);
}

test "pyromaniac multiplayer gate matches default and preserve-bugs behavior" {
    var state = state_mod.GameplayState.init(0x1234);
    var players = [_]state_mod.PlayerState{
        .{ .index = 0, .pos = .{}, .weapon = .{ .weapon_id = game_ids.WeaponId.pistol } },
        .{ .index = 1, .pos = .{}, .weapon = .{ .weapon_id = game_ids.WeaponId.flamethrower } },
    };

    try std.testing.expect(pyromaniacAllowed(&state, players[0..], &players[0], 2));

    players[1].health = 0.0;
    try std.testing.expect(!pyromaniacAllowed(&state, players[0..], &players[0], 2));

    players[0].weapon.weapon_id = game_ids.WeaponId.flamethrower;
    try std.testing.expect(pyromaniacAllowed(&state, players[0..], &players[0], 2));

    state.preserve_bugs = true;
    players[0].weapon.weapon_id = game_ids.WeaponId.pistol;
    players[1].health = 100.0;
    try std.testing.expect(!pyromaniacAllowed(&state, players[0..], &players[0], 2));
}

test "perk generate choices rejects pyromaniac when no player has flamethrower" {
    var state = state_mod.GameplayState.init(0x1234);
    var players = [_]state_mod.PlayerState{
        .{ .index = 0, .pos = .{}, .weapon = .{ .weapon_id = game_ids.WeaponId.pistol } },
    };
    const choices = perkSelectionCurrentChoices(
        &state,
        players[0..],
        .survival,
        1,
        49,
    );
    for (choices) |perk_id| {
        try std.testing.expect(perk_id != PerkId.pyromaniac);
    }
}

test "perk generate choices blocks jinxed when death clock is active" {
    var state = state_mod.GameplayState.init(0x1234);
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{},
        },
    };
    players[0].perk_counts.set(PerkId.death_clock, 1);
    const choices = perkSelectionCurrentChoices(
        &state,
        players[0..],
        .survival,
        1,
        49,
    );
    for (choices) |perk_id| {
        try std.testing.expect(perk_id != PerkId.jinxed);
    }
}

test "jinxed preserve bugs excludes the last native creature slot" {
    try std.testing.expectEqual(
        @as(usize, 0x17f),
        jinxedCreaturePoolMod(true, creatures_mod.max_creatures),
    );
    try std.testing.expectEqual(
        creatures_mod.max_creatures,
        jinxedCreaturePoolMod(false, creatures_mod.max_creatures),
    );
    try std.testing.expectEqual(
        @as(usize, 16),
        jinxedCreaturePoolMod(true, 16),
    );
}

test "death clock apply and update mirror runtime hooks" {
    var state = state_mod.GameplayState.init(1);
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{},
            .health = 25.0,
        },
    };
    players[0].perk_counts.set(PerkId.regeneration, 2);
    players[0].perk_counts.set(PerkId.greater_regeneration, 1);

    try applyPerk(&state, players[0..], PerkId.death_clock);
    try std.testing.expectEqual(@as(i32, 0), players[0].perk_counts.get(PerkId.regeneration));
    try std.testing.expectEqual(@as(i32, 0), players[0].perk_counts.get(PerkId.greater_regeneration));
    try std.testing.expectEqual(@as(f32, 100.0), players[0].health);

    updatePerkEffects(&state, players[0..], 1.0 / 60.0);
    try std.testing.expectApproxEqAbs(@as(f32, 99.944444445), players[0].health, 1e-5);
}

test "death clock reaches native zero crossing at 30hz" {
    var state = state_mod.GameplayState.init(1);
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{},
            .health = 100.0,
        },
    };
    players[0].perk_counts.set(PerkId.death_clock, 1);

    for (0..900) |_| {
        updatePerkEffects(&state, players[0..], 1.0 / 30.0);
    }

    try std.testing.expectEqual(@as(f32, -0.0008849054574966431), players[0].health);

    updatePerkEffects(&state, players[0..], 1.0 / 30.0);

    try std.testing.expectEqual(@as(f32, 0.0), players[0].health);
}

test "regeneration heals when rng allows" {
    var state = state_mod.GameplayState.init(1);
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{ .x = 10.0, .y = 20.0 },
            .health = 90.0,
        },
    };
    players[0].perk_counts.set(PerkId.regeneration, 1);

    updatePerkEffects(&state, players[0..], 0.2);
    try std.testing.expectApproxEqAbs(@as(f32, 90.2), players[0].health, 1e-5);
}

test "regeneration skips when rng blocks" {
    var state = state_mod.GameplayState.init(0);
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{ .x = 10.0, .y = 20.0 },
            .health = 90.0,
        },
    };
    players[0].perk_counts.set(PerkId.regeneration, 1);

    updatePerkEffects(&state, players[0..], 0.2);
    try std.testing.expectApproxEqAbs(@as(f32, 90.0), players[0].health, 1e-6);
}

test "greater regeneration doubles heal by default" {
    var state = state_mod.GameplayState.init(1);
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{ .x = 10.0, .y = 20.0 },
            .health = 90.0,
        },
    };
    players[0].perk_counts.set(PerkId.regeneration, 1);
    players[0].perk_counts.set(PerkId.greater_regeneration, 1);

    updatePerkEffects(&state, players[0..], 0.2);
    try std.testing.expectApproxEqAbs(@as(f32, 90.4), players[0].health, 1e-5);
}

test "greater regeneration remains no-op in preserve bugs mode" {
    var state = state_mod.GameplayState.init(1);
    state.preserve_bugs = true;
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{ .x = 10.0, .y = 20.0 },
            .health = 90.0,
        },
    };
    players[0].perk_counts.set(PerkId.regeneration, 1);
    players[0].perk_counts.set(PerkId.greater_regeneration, 1);

    updatePerkEffects(&state, players[0..], 0.2);
    try std.testing.expectApproxEqAbs(@as(f32, 90.2), players[0].health, 1e-5);
}

test "regeneration multiplayer targets all alive players by default" {
    var state = state_mod.GameplayState.init(1);
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{ .x = 10.0, .y = 20.0 },
            .health = 90.0,
        },
        .{
            .index = 1,
            .pos = .{ .x = 30.0, .y = 40.0 },
            .health = 80.0,
        },
    };
    players[0].perk_counts.set(PerkId.regeneration, 1);

    updatePerkEffects(&state, players[0..], 0.2);
    try std.testing.expectApproxEqAbs(@as(f32, 90.2), players[0].health, 1e-5);
    try std.testing.expectApproxEqAbs(@as(f32, 80.2), players[1].health, 1e-5);
}

test "regeneration preserve bugs repeats write to player zero only" {
    var state = state_mod.GameplayState.init(1);
    state.preserve_bugs = true;
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{ .x = 10.0, .y = 20.0 },
            .health = 90.0,
        },
        .{
            .index = 1,
            .pos = .{ .x = 30.0, .y = 40.0 },
            .health = 80.0,
        },
    };
    players[0].perk_counts.set(PerkId.regeneration, 1);

    updatePerkEffects(&state, players[0..], 0.2);
    try std.testing.expectApproxEqAbs(@as(f32, 90.4), players[0].health, 1e-5);
    try std.testing.expectApproxEqAbs(@as(f32, 80.0), players[1].health, 1e-6);
}

test "bandage adds random amount and clamps in default mode" {
    var state = state_mod.GameplayState.init(20_072);
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{ .x = 10.0, .y = 20.0 },
            .health = 3.0,
        },
    };

    try applyPerk(&state, players[0..], PerkId.bandage);
    try std.testing.expectApproxEqAbs(@as(f32, 53.0), players[0].health, 1e-6);
}

test "bandage preserve bugs multiplies instead of adds" {
    var state = state_mod.GameplayState.init(20_072);
    state.preserve_bugs = true;
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{ .x = 10.0, .y = 20.0 },
            .health = 3.0,
        },
    };

    try applyPerk(&state, players[0..], PerkId.bandage);
    try std.testing.expectApproxEqAbs(@as(f32, 100.0), players[0].health, 1e-6);
}

test "random weapon assigns non-pistol weapon from pistol baseline" {
    var state = state_mod.GameplayState.init(1);
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{},
            .weapon = .{ .weapon_id = game_ids.WeaponId.pistol },
        },
    };

    try applyPerk(&state, players[0..], PerkId.random_weapon);
    try std.testing.expectEqual(game_ids.WeaponId.assault_rifle, players[0].weapon.weapon_id);
}

test "random weapon rerolls pistol when current weapon is not pistol" {
    var state = state_mod.GameplayState.init(25);
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{},
            .weapon = .{ .weapon_id = game_ids.WeaponId.shotgun },
        },
    };

    try applyPerk(&state, players[0..], PerkId.random_weapon);
    try std.testing.expectEqual(game_ids.WeaponId.assault_rifle, players[0].weapon.weapon_id);
}

test "random weapon retry cap applies last roll after 100 attempts" {
    var state = state_mod.GameplayState.init(1234);
    state.game_mode = .quests;

    var expected = state;
    for (0..100) |_| {
        _ = bonus_runtime.weaponPickRandomAvailable(&expected);
    }

    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{},
            .weapon = .{ .weapon_id = game_ids.WeaponId.pistol },
        },
    };

    try applyPerk(&state, players[0..], PerkId.random_weapon);
    try std.testing.expectEqual(game_ids.WeaponId.pistol, players[0].weapon.weapon_id);
    try std.testing.expectEqual(expected.rng.state, state.rng.state);
}

test "fatal lottery grants xp when rng is even" {
    var state = state_mod.GameplayState.init(0);
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{},
            .experience = 123,
        },
        .{
            .index = 1,
            .pos = .{},
            .experience = 456,
        },
    };

    try applyPerk(&state, players[0..], PerkId.fatal_lottery);
    try std.testing.expectEqual(@as(i32, 10_123), players[0].experience);
    try std.testing.expectEqual(@as(f32, 100.0), players[0].health);
    try std.testing.expectEqual(@as(i32, 456), players[1].experience);
    try std.testing.expectEqual(@as(f32, 100.0), players[1].health);
}

test "fatal lottery kills owner only when rng is odd" {
    var state = state_mod.GameplayState.init(1);
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{},
        },
        .{
            .index = 1,
            .pos = .{},
        },
    };

    try applyPerk(&state, players[0..], PerkId.fatal_lottery);
    try std.testing.expect(players[0].health < 0.0);
    try std.testing.expectEqual(@as(f32, 100.0), players[1].health);
}

test "grim deal kills owner and boosts experience" {
    var state = state_mod.GameplayState.init(1);
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{},
            .health = 100.0,
            .experience = 12_345,
        },
        .{
            .index = 1,
            .pos = .{},
            .health = 100.0,
            .experience = 7,
        },
    };

    try applyPerk(&state, players[0..], PerkId.grim_deal);
    try std.testing.expect(players[0].health < 0.0);
    try std.testing.expectEqual(@as(i32, 14_567), players[0].experience);
    try std.testing.expectEqual(@as(f32, 100.0), players[1].health);
    try std.testing.expectEqual(@as(i32, 7), players[1].experience);
}

test "grim deal uses native float scale before truncation" {
    var state = state_mod.GameplayState.init(1);
    var players = [_]state_mod.PlayerState{
        .{ .index = 0, .pos = .{}, .experience = 1_456_361 },
    };

    try applyPerk(&state, players[0..], PerkId.grim_deal);
    try std.testing.expectEqual(@as(i32, 1_718_506), players[0].experience);
}

test "instant winner grants xp to owner only" {
    var state = state_mod.GameplayState.init(1);
    var players = [_]state_mod.PlayerState{
        .{ .index = 0, .pos = .{}, .experience = 123 },
        .{ .index = 1, .pos = .{}, .experience = 456 },
    };

    try applyPerk(&state, players[0..], PerkId.instant_winner);
    try std.testing.expectEqual(@as(i32, 2623), players[0].experience);
    try std.testing.expectEqual(@as(i32, 456), players[1].experience);
}

test "infernal contract grants levels and forces low health" {
    var state = state_mod.GameplayState.init(1);
    var players = [_]state_mod.PlayerState{
        .{ .index = 0, .pos = .{}, .level = 5, .health = 100.0 },
        .{ .index = 1, .pos = .{}, .level = 1, .health = 80.0 },
    };

    try applyPerk(&state, players[0..], PerkId.infernal_contract);
    try std.testing.expectEqual(@as(i32, 8), players[0].level);
    try std.testing.expectEqual(@as(i32, 3), state.perk_selection.pending_count);
    try std.testing.expect(state.perk_selection.choices_dirty);
    try std.testing.expectApproxEqAbs(@as(f32, 0.1), players[0].health, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 0.1), players[1].health, 1e-6);
}

test "ammo maniac reassigns weapons and boosts clip size for all players" {
    var state = state_mod.GameplayState.init(1);
    var players = [_]state_mod.PlayerState{
        .{ .index = 0, .pos = .{}, .weapon = .{ .weapon_id = game_ids.WeaponId.assault_rifle } },
        .{ .index = 1, .pos = .{}, .weapon = .{ .weapon_id = game_ids.WeaponId.pistol } },
    };
    player_runtime.weaponAssignPlayerWithState(&players[0], players[0].weapon.weapon_id, &state);
    player_runtime.weaponAssignPlayerWithState(&players[1], players[1].weapon.weapon_id, &state);

    const base_clip0 = players[0].weapon.clip_size;
    const base_clip1 = players[1].weapon.clip_size;
    players[0].weapon.ammo = 1.0;
    players[1].weapon.ammo = 2.0;

    try applyPerk(&state, players[0..], PerkId.ammo_maniac);

    try std.testing.expect(players[0].weapon.clip_size > base_clip0);
    try std.testing.expect(players[1].weapon.clip_size > base_clip1);
    try std.testing.expectEqual(@as(f32, @floatFromInt(players[0].weapon.clip_size)), players[0].weapon.ammo);
    try std.testing.expectEqual(@as(f32, @floatFromInt(players[1].weapon.clip_size)), players[1].weapon.ammo);
    try std.testing.expect(!players[0].weapon.reload_active);
    try std.testing.expect(!players[1].weapon.reload_active);
    try std.testing.expectEqual(@as(f32, 0.0), players[0].weapon.reload_timer);
    try std.testing.expectEqual(@as(f32, 0.0), players[1].weapon.reload_timer);
    try std.testing.expectEqual(@as(i32, 1), players[1].perk_counts.get(PerkId.ammo_maniac));
}

test "my favourite weapon increases clip size and keeps current ammo on apply" {
    var state = state_mod.GameplayState.init(1);
    var players = [_]state_mod.PlayerState{
        .{ .index = 0, .pos = .{}, .weapon = .{ .weapon_id = game_ids.WeaponId.pistol } },
    };
    player_runtime.weaponAssignPlayerWithState(&players[0], players[0].weapon.weapon_id, &state);

    const base_clip = players[0].weapon.clip_size;
    players[0].weapon.ammo = 5.0;
    try applyPerk(&state, players[0..], PerkId.my_favourite_weapon);

    try std.testing.expectEqual(base_clip + 2, players[0].weapon.clip_size);
    try std.testing.expectEqual(@as(f32, 5.0), players[0].weapon.ammo);

    player_runtime.weaponAssignPlayerWithState(&players[0], players[0].weapon.weapon_id, &state);
    try std.testing.expectEqual(base_clip + 2, players[0].weapon.clip_size);
    try std.testing.expectEqual(@as(f32, @floatFromInt(base_clip + 2)), players[0].weapon.ammo);
}

test "breathing room reduces player health and clears bonus spawn guard" {
    var state = state_mod.GameplayState.init(1);
    state.bonus_spawn_guard = true;
    var players = [_]state_mod.PlayerState{
        .{ .index = 0, .pos = .{}, .health = 90.0 },
        .{ .index = 1, .pos = .{}, .health = 45.0 },
    };

    try applyPerk(&state, players[0..], PerkId.breathing_room);
    try std.testing.expectApproxEqAbs(@as(f32, 30.0), players[0].health, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 15.0), players[1].health, 1e-6);
    try std.testing.expect(!state.bonus_spawn_guard);
}

test "breathing room rounds each native float operation" {
    var state = state_mod.GameplayState.init(1);
    var players = [_]state_mod.PlayerState{
        .{ .index = 0, .pos = .{}, .health = 1.0 },
    };

    try applyPerk(&state, players[0..], PerkId.breathing_room);
    try std.testing.expectEqual(@as(f32, @bitCast(@as(u32, 0x3EAAAAAA))), players[0].health);
}

test "breathing room applies immediate creature lifecycle step when context is provided" {
    var state = state_mod.GameplayState.init(1);
    var players = [_]state_mod.PlayerState{
        .{ .index = 0, .pos = .{}, .health = 90.0 },
    };
    var creatures: creatures_mod.CreaturePool = .{};
    creatures.entries[0].active = true;
    creatures.entries[0].lifecycle_stage = 3.5;

    try applyPerkWithContext(&state, players[0..], PerkId.breathing_room, .{
        .creatures = &creatures,
        .dt_frame = 0.2,
    });
    try std.testing.expectApproxEqAbs(@as(f32, 3.3), creatures.entries[0].lifecycle_stage, 1e-6);
}

test "thick skinned keeps two thirds without a health floor" {
    var state = state_mod.GameplayState.init(1);
    var players = [_]state_mod.PlayerState{
        .{ .index = 0, .pos = .{}, .health = 90.0 },
        .{ .index = 1, .pos = .{}, .health = 1.2 },
    };

    try applyPerk(&state, players[0..], PerkId.thick_skinned);
    try std.testing.expectApproxEqAbs(@as(f32, 60.0), players[0].health, 1e-4);
    // Native has no health floor: low-health players keep 2/3 of their health.
    try std.testing.expectApproxEqAbs(@as(f32, 0.8), players[1].health, 1e-4);
}

test "thick skinned rounds multiply before health subtraction" {
    var state = state_mod.GameplayState.init(1);
    var players = [_]state_mod.PlayerState{
        .{ .index = 0, .pos = .{}, .health = @bitCast(@as(u32, 0x41CC0E4A)) },
    };

    try applyPerk(&state, players[0..], PerkId.thick_skinned);
    try std.testing.expectEqual(
        @as(f32, @bitCast(@as(u32, 0x41880986))),
        players[0].health,
    );
}

test "plaguebearer apply marks all players active" {
    var state = state_mod.GameplayState.init(1);
    var players = [_]state_mod.PlayerState{
        .{ .index = 0, .pos = .{} },
        .{ .index = 1, .pos = .{} },
    };

    try applyPerk(&state, players[0..], PerkId.plaguebearer);
    try std.testing.expect(players[0].plaguebearer_active);
    try std.testing.expect(players[1].plaguebearer_active);
}

test "plaguebearer preserve bugs marks only player zero active" {
    var state = state_mod.GameplayState.init(1);
    state.preserve_bugs = true;
    var players = [_]state_mod.PlayerState{
        .{ .index = 0, .pos = .{} },
        .{ .index = 1, .pos = .{} },
    };

    try applyPerk(&state, players[0..], PerkId.plaguebearer);
    try std.testing.expect(players[0].plaguebearer_active);
    try std.testing.expect(!players[1].plaguebearer_active);
}

test "lean mean exp machine ticks xp and ignores double experience multiplier" {
    var state = state_mod.GameplayState.init(1);
    state.bonuses.double_experience = 5.0;
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{ .x = 10.0, .y = 20.0 },
        },
    };
    players[0].perk_counts.set(PerkId.lean_mean_exp_machine, 2);

    updatePerkEffects(&state, players[0..], 0.2);
    try std.testing.expectEqual(@as(i32, 0), players[0].experience);

    updatePerkEffects(&state, players[0..], 0.1);
    try std.testing.expectEqual(@as(i32, 20), players[0].experience);
    try std.testing.expectApproxEqAbs(@as(f32, 0.25), state.lean_mean_exp_timer, 1e-6);
}

test "lean mean exp machine tick awards player zero only in multiplayer" {
    var state = state_mod.GameplayState.init(1);
    state.lean_mean_exp_timer = 0.05;
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{ .x = 10.0, .y = 20.0 },
        },
        .{
            .index = 1,
            .pos = .{ .x = 30.0, .y = 40.0 },
        },
    };
    players[0].perk_counts.set(PerkId.lean_mean_exp_machine, 2);
    players[1].perk_counts.set(PerkId.lean_mean_exp_machine, 2);

    updatePerkEffects(&state, players[0..], 0.1);
    try std.testing.expectEqual(@as(i32, 20), players[0].experience);
    try std.testing.expectEqual(@as(i32, 0), players[1].experience);
}

test "perk effect timers keep native 36hz cadence" {
    var state = state_mod.GameplayState.init(1);
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{ .x = 10.0, .y = 20.0 },
            .shield_timer = 0.25,
            .fire_bullets_timer = 0.25,
            .speed_bonus_timer = 0.25,
        },
    };
    players[0].perk_counts.set(PerkId.lean_mean_exp_machine, 1);

    for (0..9) |_| {
        updatePerkEffects(&state, players[0..], 1.0 / 36.0);
    }

    try std.testing.expectEqual(@as(f32, 1.1175870895385742e-08), state.lean_mean_exp_timer);
    try std.testing.expectEqual(@as(f32, 1.1175870895385742e-08), players[0].shield_timer);
    try std.testing.expectEqual(@as(f32, 1.1175870895385742e-08), players[0].fire_bullets_timer);
    try std.testing.expectEqual(@as(f32, 1.1175870895385742e-08), players[0].speed_bonus_timer);
    try std.testing.expectEqual(@as(i32, 0), players[0].experience);

    updatePerkEffects(&state, players[0..], 1.0 / 36.0);

    try std.testing.expectEqual(@as(f32, 0.25), state.lean_mean_exp_timer);
    try std.testing.expectEqual(@as(i32, 10), players[0].experience);
}

test "lifeline 50-50 replay perk effect deactivates every other eligible creature slot" {
    var state = state_mod.GameplayState.init(1);
    const before_rng = state.rng.state;
    var creatures: creatures_mod.CreaturePool = .{};

    for (0..8) |idx| {
        creatures.entries[idx].active = true;
        creatures.entries[idx].hp = 100.0;
        creatures.entries[idx].pos = .{
            .x = @floatFromInt(idx),
            .y = @as(f32, @floatFromInt(idx)) * 10.0,
        };
        creatures.entries[idx].flags = 0;
    }
    creatures.entries[3].flags = spawn_mod.CreatureFlags.anim_ping_pong;
    creatures.entries[5].hp = 600.0;

    applyReplayPerkCreatureEffects(
        PerkId.lifeline_50_50,
        &state,
        &creatures,
        0.016,
    );

    const expected = [_]bool{ true, false, true, true, true, true, true, false };
    for (expected, 0..) |active_expected, idx| {
        try std.testing.expectEqual(active_expected, creatures.entries[idx].active);
    }
    try std.testing.expect(before_rng != state.rng.state);
}

test "lifeline 50-50 immediate apply uses shared creature-effect path" {
    var state = state_mod.GameplayState.init(1);
    var players = [_]state_mod.PlayerState{
        .{ .index = 0, .pos = .{} },
    };
    var creatures: creatures_mod.CreaturePool = .{};

    for (0..4) |idx| {
        creatures.entries[idx].active = true;
        creatures.entries[idx].hp = 100.0;
        creatures.entries[idx].flags = 0;
    }

    try applyPerkWithContext(&state, players[0..], PerkId.lifeline_50_50, .{
        .creatures = &creatures,
        .dt_frame = 0.016,
    });
    try std.testing.expect(creatures.entries[0].active);
    try std.testing.expect(!creatures.entries[1].active);
    try std.testing.expect(creatures.entries[2].active);
    try std.testing.expect(!creatures.entries[3].active);
}

test "evil eyes targeting defaults to alive player slot" {
    var players = [_]state_mod.PlayerState{
        .{ .index = 0, .pos = .{}, .health = 0.0 },
        .{
            .index = 1,
            .pos = .{},
            .health = 100.0,
            .aim = .{ .x = 100.0, .y = 200.0 },
        },
    };
    players[1].perk_counts.set(PerkId.evil_eyes, 1);

    var creatures = [_]creatures_mod.CreatureState{
        .{
            .active = true,
            .pos = .{ .x = 100.0, .y = 200.0 },
            .lifecycle_stage = creature_lifecycle.alive,
            .size = 50.0,
            .hp = 100.0,
        },
    };

    updateEvilEyesTargets(false, players[0..], creatures[0..]);
    try std.testing.expectEqual(@as(i32, -1), players[0].evil_eyes_target_creature);
    try std.testing.expectEqual(@as(i32, 0), players[1].evil_eyes_target_creature);
}

test "evil eyes targeting assigns each alive owner" {
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{},
            .health = 100.0,
            .aim = .{ .x = 100.0, .y = 200.0 },
        },
        .{
            .index = 1,
            .pos = .{},
            .health = 100.0,
            .aim = .{ .x = 140.0, .y = 200.0 },
        },
    };
    players[0].perk_counts.set(PerkId.evil_eyes, 1);
    players[1].perk_counts.set(PerkId.evil_eyes, 1);

    var creatures = [_]creatures_mod.CreatureState{
        .{
            .active = true,
            .pos = .{ .x = 100.0, .y = 200.0 },
            .lifecycle_stage = creature_lifecycle.alive,
            .size = 50.0,
            .hp = 100.0,
        },
        .{
            .active = true,
            .pos = .{ .x = 140.0, .y = 200.0 },
            .lifecycle_stage = creature_lifecycle.alive,
            .size = 50.0,
            .hp = 100.0,
        },
    };

    updateEvilEyesTargets(false, players[0..], creatures[0..]);
    try std.testing.expectEqual(@as(i32, 0), players[0].evil_eyes_target_creature);
    try std.testing.expectEqual(@as(i32, 1), players[1].evil_eyes_target_creature);
}

test "final revenge uses native blast arithmetic and explosion scale" {
    var state = state_mod.GameplayState.init(1);
    state.bonus_spawn_guard = true;
    var players = [_]state_mod.PlayerState{
        .{ .index = 0, .pos = .{}, .health = 0.0 },
    };
    players[0].perk_counts.set(PerkId.final_revenge, 1);

    var creatures: creatures_mod.CreaturePool = .{};
    creatures.entries[0] = .{
        .active = true,
        .pos = .{ .x = 155.231201171875, .y = 295.6527099609375 },
        .hp = 10000.0,
    };
    var bonuses: bonus_runtime.BonusPool = .{};
    var effects: effects_mod.EffectPool = .{};
    var terrain_fx: terrain_fx_mod.TerrainFxScratch = .{};

    applyFinalRevengeOnDeathTransitionWithEffects(
        &state,
        players[0..],
        0,
        1.0,
        1.0,
        &creatures,
        &bonuses,
        &effects,
        &terrain_fx,
        0.0,
        1024.0,
        5,
    );

    try std.testing.expectEqual(@as(u32, 0x460e568a), @as(u32, @bitCast(creatures.entries[0].hp)));
    try std.testing.expectEqual(@as(f32, 45.0), effects.entries[0].scale_step);
    try std.testing.expect(!state.bonus_spawn_guard);
}

test "final revenge preserve mode uses player one source and strict lethal boundary" {
    var state = state_mod.GameplayState.init(1);
    state.preserve_bugs = true;
    var players = [_]state_mod.PlayerState{
        .{ .index = 0, .pos = .{}, .health = 100.0 },
        .{ .index = 1, .pos = .{}, .health = -1.0 },
    };
    players[0].perk_counts.set(PerkId.final_revenge, 1);
    var creatures: creatures_mod.CreaturePool = .{};
    var bonuses: bonus_runtime.BonusPool = .{};
    var effects: effects_mod.EffectPool = .{};
    var terrain_fx: terrain_fx_mod.TerrainFxScratch = .{};

    applyFinalRevengeOnDeathTransitionWithEffects(
        &state,
        players[0..],
        1,
        1.0,
        100.0,
        &creatures,
        &bonuses,
        &effects,
        &terrain_fx,
        0.0,
        1024.0,
        5,
    );
    try std.testing.expectEqual(@as(usize, 2), state.sfx_queue.len);

    var exact_zero_state = state_mod.GameplayState.init(1);
    exact_zero_state.preserve_bugs = true;
    players[1].health = 0.0;
    applyFinalRevengeOnDeathTransitionWithEffects(
        &exact_zero_state,
        players[0..],
        1,
        1.0,
        100.0,
        &creatures,
        &bonuses,
        &effects,
        &terrain_fx,
        0.0,
        1024.0,
        5,
    );
    try std.testing.expectEqual(@as(usize, 0), exact_zero_state.sfx_queue.len);

    var dead_player1_state = state_mod.GameplayState.init(1);
    dead_player1_state.preserve_bugs = true;
    players[1].health = -1.0;
    applyFinalRevengeOnDeathTransitionWithEffects(
        &dead_player1_state,
        players[0..],
        1,
        1.0,
        -1.0,
        &creatures,
        &bonuses,
        &effects,
        &terrain_fx,
        0.0,
        1024.0,
        5,
    );
    try std.testing.expectEqual(@as(usize, 0), dead_player1_state.sfx_queue.len);
}
