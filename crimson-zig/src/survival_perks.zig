const std = @import("std");

const survival_bonuses = @import("survival_bonuses.zig");
const survival_state = @import("survival_state.zig");

pub const PerkApplyError = error{
    UnsupportedPerkApplyHandler,
};

pub const PerkId = struct {
    pub const antiperk: i32 = 0;
    pub const bloody_mess_quick_learner: i32 = 1;
    pub const sharpshooter: i32 = 2;
    pub const fastloader: i32 = 3;
    pub const lean_mean_exp_machine: i32 = 4;
    pub const long_distance_runner: i32 = 5;
    pub const pyrokinetic: i32 = 6;
    pub const instant_winner: i32 = 7;
    pub const grim_deal: i32 = 8;
    pub const alternate_weapon: i32 = 9;
    pub const plaguebearer: i32 = 10;
    pub const evil_eyes: i32 = 11;
    pub const ammo_maniac: i32 = 12;
    pub const radioactive: i32 = 13;
    pub const fastshot: i32 = 14;
    pub const fatal_lottery: i32 = 15;
    pub const random_weapon: i32 = 16;
    pub const mr_melee: i32 = 17;
    pub const anxious_loader: i32 = 18;
    pub const final_revenge: i32 = 19;
    pub const telekinetic: i32 = 20;
    pub const perk_expert: i32 = 21;
    pub const unstoppable: i32 = 22;
    pub const regression_bullets: i32 = 23;
    pub const infernal_contract: i32 = 24;
    pub const poison_bullets: i32 = 25;
    pub const dodger: i32 = 26;
    pub const bonus_magnet: i32 = 27;
    pub const uranium_filled_bullets: i32 = 28;
    pub const doctor: i32 = 29;
    pub const monster_vision: i32 = 30;
    pub const hot_tempered: i32 = 31;
    pub const bonus_economist: i32 = 32;
    pub const thick_skinned: i32 = 33;
    pub const barrel_greaser: i32 = 34;
    pub const ammunition_within: i32 = 35;
    pub const veins_of_poison: i32 = 36;
    pub const toxic_avenger: i32 = 37;
    pub const regeneration: i32 = 38;
    pub const pyromaniac: i32 = 39;
    pub const ninja: i32 = 40;
    pub const highlander: i32 = 41;
    pub const jinxed: i32 = 42;
    pub const perk_master: i32 = 43;
    pub const reflex_boosted: i32 = 44;
    pub const greater_regeneration: i32 = 45;
    pub const breathing_room: i32 = 46;
    pub const death_clock: i32 = 47;
    pub const my_favourite_weapon: i32 = 48;
    pub const bandage: i32 = 49;
    pub const angry_reloader: i32 = 50;
    pub const ion_gun_master: i32 = 51;
    pub const stationary_reloader: i32 = 52;
    pub const man_bomb: i32 = 53;
    pub const fire_caugh: i32 = 54;
    pub const living_fortress: i32 = 55;
    pub const tough_reloader: i32 = 56;
    pub const lifeline_50_50: i32 = 57;
};

const PerkFlags = struct {
    pub const quest_mode_allowed: u32 = 0x1;
    pub const two_player_allowed: u32 = 0x2;
    pub const stackable: u32 = 0x4;
};

pub const perk_id_max: i32 = 57;
const perk_id_max_usize: usize = 57;
const perk_base_available_max_id: i32 = 27;
const game_mode_quests: i32 = 3;
const game_mode_tutorial: i32 = 8;

const perk_flags_by_id = [_]u32{
    3, 3, 3, 3, 3, 3, 3, 7, 0, 1, 3, 3, 3, 3, 3, 4, 5, 3, 3, 0, 3, 3, 3, 3, 3, 3, 3, 3, 3,
    3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 0, 3, 3, 3, 3, 2, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
};

const quest_unlock_perk_by_index = [_]?i32{
    null,                   null,               PerkId.uranium_filled_bullets, null, PerkId.doctor,         null,                  PerkId.monster_vision,       null,                  PerkId.hot_tempered,        null,
    PerkId.bonus_economist, null,               PerkId.thick_skinned,          null, PerkId.barrel_greaser, null,                  PerkId.ammunition_within,    null,                  PerkId.veins_of_poison,     null,
    PerkId.toxic_avenger,   null,               PerkId.regeneration,           null, PerkId.pyromaniac,     null,                  PerkId.ninja,                null,                  PerkId.highlander,          null,
    PerkId.jinxed,          null,               PerkId.perk_master,            null, PerkId.reflex_boosted, null,                  PerkId.greater_regeneration, null,                  PerkId.breathing_room,      null,
    null,                   PerkId.death_clock, PerkId.my_favourite_weapon,    null, PerkId.bandage,        PerkId.angry_reloader, null,                        PerkId.ion_gun_master, PerkId.stationary_reloader, null,
};

const perk_always_available = [_]i32{
    PerkId.man_bomb,
    PerkId.living_fortress,
    PerkId.fire_caugh,
    PerkId.tough_reloader,
};

pub fn perksRebuildAvailable(
    state: *survival_state.GameplayState,
    quest_unlock_index: i32,
) void {
    if (state.perk_available_unlock_index == quest_unlock_index) return;

    state.perk_available = [_]bool{false} ** survival_state.perk_count_size;

    var perk_id: i32 = 1;
    while (perk_id <= perk_base_available_max_id) : (perk_id += 1) {
        if (perk_id < state.perk_available.len) {
            state.perk_available[@intCast(perk_id)] = true;
        }
    }

    for (perk_always_available) |always_id| {
        if (always_id >= 0 and always_id < state.perk_available.len) {
            state.perk_available[@intCast(always_id)] = true;
        }
    }

    if (quest_unlock_index > 0) {
        const limit: usize = @min(
            @as(usize, @intCast(quest_unlock_index)),
            quest_unlock_perk_by_index.len,
        );
        for (quest_unlock_perk_by_index[0..limit]) |maybe_perk_id| {
            if (maybe_perk_id) |perk_unlock_id| {
                if (perk_unlock_id > 0 and perk_unlock_id < state.perk_available.len) {
                    state.perk_available[@intCast(perk_unlock_id)] = true;
                }
            }
        }
    }

    state.perk_available[@intCast(PerkId.antiperk)] = false;
    state.perk_available_unlock_index = quest_unlock_index;
}

pub fn perkChoiceCount(player: *const survival_state.PlayerState) i32 {
    if (perkCountGet(player, PerkId.perk_master) > 0) return 7;
    if (perkCountGet(player, PerkId.perk_expert) > 0) return 6;
    return 5;
}

pub fn perkSelectionCurrentChoices(
    state: *survival_state.GameplayState,
    players: []survival_state.PlayerState,
    game_mode: i32,
    player_count: i32,
    quest_unlock_index: i32,
) []const i32 {
    if (players.len == 0) return &.{};
    const player = &players[0];

    if (state.perk_selection.choices_dirty or state.perk_selection.choice_count == 0) {
        state.perk_selection.choices = perkGenerateChoices(
            state,
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
    state: *survival_state.GameplayState,
    players: []survival_state.PlayerState,
    choice_index: i32,
    game_mode: i32,
    player_count: i32,
    quest_unlock_index: i32,
) PerkApplyError!?i32 {
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
    try applyPerk(state, players, perk_id);

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

pub fn applyPerk(
    state: *survival_state.GameplayState,
    players: []survival_state.PlayerState,
    perk_id: i32,
) PerkApplyError!void {
    if (players.len == 0) return;
    if (perk_id < 0 or perk_id >= survival_state.perk_count_size) return;

    players[0].perk_counts[@intCast(perk_id)] += 1;
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
            players[0].health = -1.0;
            players[0].experience += @intFromFloat(@as(f64, @floatFromInt(players[0].experience)) * 0.18);
        },
        PerkId.plaguebearer => {
            for (players) |*player| {
                player.plaguebearer_active = true;
            }
        },
        PerkId.ammo_maniac => {
            for (players) |*player| {
                survival_state.weaponAssignPlayerWithState(player, player.weapon_id, state);
            }
        },
        PerkId.fatal_lottery => {
            if ((state.rng.rand() & 1) != 0) {
                players[0].health = -1.0;
            } else {
                players[0].experience += 10_000;
            }
        },
        PerkId.infernal_contract => {
            players[0].level += 3;
            state.perk_selection.pending_count += 3;
            state.perk_selection.choices_dirty = true;
            for (players) |*player| {
                if (player.health > 0.0) player.health = 0.1;
            }
        },
        PerkId.thick_skinned => {
            for (players) |*player| {
                if (player.health > 0.0) {
                    player.health = @max(1.0, player.health * (2.0 / 3.0));
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
                player.clip_size += 2;
            }
        },
        PerkId.random_weapon => {
            const current = players[0].weapon_id;
            var selected = current;
            for (0..100) |_| {
                const candidate = survival_bonuses.weaponPickRandomAvailable(state);
                selected = candidate;
                if (candidate != survival_state.WeaponId.pistol and candidate != current) break;
            }
            survival_state.weaponAssignPlayerWithState(&players[0], selected, state);
        },
        PerkId.breathing_room => {
            for (players) |*player| {
                const reduction = asF32F64(player.health * (2.0 / 3.0));
                player.health = asF32F64(player.health - reduction);
            }
            state.bonus_spawn_guard = false;
        },
        PerkId.bandage => {
            for (players) |*player| {
                if (player.health > 0.0) {
                    const amount: f64 = @floatFromInt(state.rng.rand() % 50 + 1);
                    if (state.preserve_bugs) {
                        player.health = @min(100.0, asF32F64(player.health * amount));
                    } else {
                        player.health = @min(100.0, asF32F64(player.health + amount));
                    }
                    consumeSpawnBurstRng(state, 8);
                }
            }
        },
        PerkId.lifeline_50_50 => {},
        else => {},
    }
}

fn consumeSpawnBurstRng(
    state: *survival_state.GameplayState,
    count: usize,
) void {
    for (0..count) |_| {
        _ = state.rng.rand();
        _ = state.rng.rand();
        _ = state.rng.rand();
        _ = state.rng.rand();
    }
}

fn asF32F64(value: f64) f64 {
    const rounded: f32 = @floatCast(value);
    return @floatCast(rounded);
}

pub fn updatePerkEffects(
    state: *survival_state.GameplayState,
    players: []survival_state.PlayerState,
    dt: f64,
) void {
    if (dt > 0.0) {
        for (players) |*player| {
            if (player.shield_timer <= 0.0) {
                player.shield_timer = 0.0;
            } else {
                player.shield_timer -= dt;
            }

            if (player.fire_bullets_timer <= 0.0) {
                player.fire_bullets_timer = 0.0;
            } else {
                player.fire_bullets_timer -= dt;
            }

            if (player.speed_bonus_timer <= 0.0) {
                player.speed_bonus_timer = 0.0;
            } else {
                player.speed_bonus_timer -= dt;
            }
        }
    }

    if (players.len == 0) return;

    if (dt > 0.0 and
        perkActive(&players[0], PerkId.regeneration) and
        (state.rng.rand() & 1) != 0)
    {
        if (state.preserve_bugs) {
            var repeat: usize = 0;
            while (repeat < players.len) : (repeat += 1) {
                if (players[0].health <= 0.0 or players[0].health >= 100.0) continue;
                players[0].health += dt;
                if (players[0].health > 100.0) {
                    players[0].health = 100.0;
                }
            }
        } else {
            var heal_amount = dt;
            if (perkActive(&players[0], PerkId.greater_regeneration)) {
                heal_amount = dt * 2.0;
            }
            for (players) |*player| {
                if (player.health <= 0.0 or player.health >= 100.0) continue;
                player.health += heal_amount;
                if (player.health > 100.0) {
                    player.health = 100.0;
                }
            }
        }
    }

    if (!perkActive(&players[0], PerkId.death_clock)) return;

    for (players) |*player| {
        if (player.health <= 0.0) {
            player.health = 0.0;
        } else {
            player.health -= dt * 3.3333333;
        }
    }
}

fn perkGenerateChoices(
    state: *survival_state.GameplayState,
    player: *const survival_state.PlayerState,
    game_mode: i32,
    player_count: i32,
    quest_unlock_index: i32,
) [7]i32 {
    perksRebuildAvailable(state, quest_unlock_index);

    var offerable = [_]bool{false} ** (perk_id_max_usize + 1);
    var perk_id: i32 = 1;
    while (perk_id <= perk_id_max) : (perk_id += 1) {
        if (perk_id >= state.perk_available.len) continue;
        if (!state.perk_available[@intCast(perk_id)]) continue;
        if (perkCanOffer(state, player, perk_id, game_mode, player_count)) {
            offerable[@intCast(perk_id)] = true;
        }
    }

    const death_clock_active = perkActive(player, PerkId.death_clock);
    const pyromaniac_allowed = player.weapon_id == survival_state.WeaponId.flamethrower;

    var choices = [_]i32{PerkId.antiperk} ** 7;
    var choice_index: usize = 0;

    if (state.quest_stage_major == 3 and state.quest_stage_minor == 4 and !perkActive(player, PerkId.monster_vision)) {
        choices[0] = PerkId.monster_vision;
        choice_index = 1;
    }

    while (choice_index < choices.len) : (choice_index += 1) {
        var attempts: i32 = 0;
        var selected: i32 = PerkId.instant_winner;
        while (true) {
            attempts += 1;
            const candidate = selectRandomOffer(state, &offerable);

            if (candidate == PerkId.pyromaniac and !pyromaniac_allowed) continue;
            if (death_clock_active and isDeathClockBlocked(candidate)) continue;
            if (isRarityGate(candidate) and ((state.rng.rand() & 3) == 1)) continue;

            const flags = perkFlags(candidate);
            const stackable = (flags & PerkFlags.stackable) != 0;
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

    if (game_mode == game_mode_tutorial) {
        choices = .{
            PerkId.sharpshooter,
            PerkId.long_distance_runner,
            PerkId.evil_eyes,
            PerkId.radioactive,
            PerkId.fastshot,
            PerkId.fastshot,
            PerkId.fastshot,
        };
    }

    return choices;
}

fn selectRandomOffer(state: *survival_state.GameplayState, offerable: []const bool) i32 {
    var draws: i32 = 0;
    while (draws < 1000) : (draws += 1) {
        const candidate: i32 = @intCast(state.rng.rand() % @as(u32, @intCast(perk_id_max)) + 1);
        if (candidate >= 0 and candidate < offerable.len and offerable[@intCast(candidate)]) {
            return candidate;
        }
    }
    return PerkId.instant_winner;
}

fn perkCanOffer(
    state: *const survival_state.GameplayState,
    player: *const survival_state.PlayerState,
    perk_id: i32,
    game_mode: i32,
    player_count: i32,
) bool {
    _ = state;
    if (perk_id == PerkId.antiperk) return false;
    if (perk_id < 0 or perk_id > perk_id_max) return false;

    const flags = perkFlags(perk_id);
    if (game_mode == game_mode_quests and (flags & PerkFlags.quest_mode_allowed) == 0) {
        return false;
    }
    if (player_count == 2 and (flags & PerkFlags.two_player_allowed) == 0) {
        return false;
    }
    if (!prereqSatisfied(player, perk_id)) return false;
    return true;
}

fn prereqSatisfied(player: *const survival_state.PlayerState, perk_id: i32) bool {
    return switch (perk_id) {
        PerkId.toxic_avenger => perkCountGet(player, PerkId.veins_of_poison) > 0,
        PerkId.ninja => perkCountGet(player, PerkId.dodger) > 0,
        PerkId.perk_master => perkCountGet(player, PerkId.perk_expert) > 0,
        PerkId.greater_regeneration => perkCountGet(player, PerkId.regeneration) > 0,
        else => true,
    };
}

fn perkFlags(perk_id: i32) u32 {
    if (perk_id < 0 or perk_id >= perk_flags_by_id.len) return 0;
    return perk_flags_by_id[@intCast(perk_id)];
}

fn perkCountGet(player: *const survival_state.PlayerState, perk_id: i32) i32 {
    if (perk_id < 0 or perk_id >= player.perk_counts.len) return 0;
    return player.perk_counts[@intCast(perk_id)];
}

fn adjustPerkCount(player: *survival_state.PlayerState, perk_id: i32, amount: i32) void {
    if (perk_id < 0 or perk_id >= player.perk_counts.len) return;
    const current = player.perk_counts[@intCast(perk_id)];
    player.perk_counts[@intCast(perk_id)] = @max(0, current + amount);
}

fn perkActive(player: *const survival_state.PlayerState, perk_id: i32) bool {
    return perkCountGet(player, perk_id) > 0;
}

fn containsPerkId(values: []const i32, needle: i32) bool {
    for (values) |value| {
        if (value == needle) return true;
    }
    return false;
}

fn isRarityGate(perk_id: i32) bool {
    return perk_id == PerkId.jinxed or
        perk_id == PerkId.ammunition_within or
        perk_id == PerkId.anxious_loader or
        perk_id == PerkId.monster_vision;
}

fn isDeathClockBlocked(perk_id: i32) bool {
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
    var state = survival_state.GameplayState.init(0x1234);
    var players = [_]survival_state.PlayerState{
        .{ .index = 0, .pos = .{} },
    };
    const before = state.rng.state;
    const choices = perkSelectionCurrentChoices(
        &state,
        players[0..],
        1,
        1,
        49,
    );
    try std.testing.expect(choices.len > 0);
    try std.testing.expect(before != state.rng.state);
    try std.testing.expect(!state.perk_selection.choices_dirty);
}

test "perk pick decrements pending and refreshes choices" {
    var state = survival_state.GameplayState.init(0x1234);
    var players = [_]survival_state.PlayerState{
        .{ .index = 0, .pos = .{} },
    };
    state.perk_selection.pending_count = 1;
    state.perk_selection.choices_dirty = true;

    _ = perkSelectionCurrentChoices(
        &state,
        players[0..],
        1,
        1,
        49,
    );
    const picked = try perkSelectionPick(
        &state,
        players[0..],
        0,
        1,
        1,
        49,
    );
    try std.testing.expect(picked != null);
    try std.testing.expectEqual(@as(i32, 0), state.perk_selection.pending_count);
    try std.testing.expect(!state.perk_selection.choices_dirty);
}

test "death clock apply and update mirror runtime hooks" {
    var state = survival_state.GameplayState.init(1);
    var players = [_]survival_state.PlayerState{
        .{
            .index = 0,
            .pos = .{},
            .health = 25.0,
        },
    };
    players[0].perk_counts[@intCast(PerkId.regeneration)] = 2;
    players[0].perk_counts[@intCast(PerkId.greater_regeneration)] = 1;

    try applyPerk(&state, players[0..], PerkId.death_clock);
    try std.testing.expectEqual(@as(i32, 0), players[0].perk_counts[@intCast(PerkId.regeneration)]);
    try std.testing.expectEqual(@as(i32, 0), players[0].perk_counts[@intCast(PerkId.greater_regeneration)]);
    try std.testing.expectEqual(@as(f64, 100.0), players[0].health);

    updatePerkEffects(&state, players[0..], 1.0 / 60.0);
    try std.testing.expectApproxEqAbs(@as(f64, 99.944444445), players[0].health, 1e-6);
}

test "regeneration heals when rng allows" {
    var state = survival_state.GameplayState.init(1);
    var players = [_]survival_state.PlayerState{
        .{
            .index = 0,
            .pos = .{ .x = 10.0, .y = 20.0 },
            .health = 90.0,
        },
    };
    players[0].perk_counts[@intCast(PerkId.regeneration)] = 1;

    updatePerkEffects(&state, players[0..], 0.2);
    try std.testing.expectApproxEqAbs(@as(f64, 90.2), players[0].health, 1e-6);
}

test "regeneration skips when rng blocks" {
    var state = survival_state.GameplayState.init(0);
    var players = [_]survival_state.PlayerState{
        .{
            .index = 0,
            .pos = .{ .x = 10.0, .y = 20.0 },
            .health = 90.0,
        },
    };
    players[0].perk_counts[@intCast(PerkId.regeneration)] = 1;

    updatePerkEffects(&state, players[0..], 0.2);
    try std.testing.expectApproxEqAbs(@as(f64, 90.0), players[0].health, 1e-6);
}

test "greater regeneration doubles heal by default" {
    var state = survival_state.GameplayState.init(1);
    var players = [_]survival_state.PlayerState{
        .{
            .index = 0,
            .pos = .{ .x = 10.0, .y = 20.0 },
            .health = 90.0,
        },
    };
    players[0].perk_counts[@intCast(PerkId.regeneration)] = 1;
    players[0].perk_counts[@intCast(PerkId.greater_regeneration)] = 1;

    updatePerkEffects(&state, players[0..], 0.2);
    try std.testing.expectApproxEqAbs(@as(f64, 90.4), players[0].health, 1e-6);
}

test "greater regeneration remains no-op in preserve bugs mode" {
    var state = survival_state.GameplayState.init(1);
    state.preserve_bugs = true;
    var players = [_]survival_state.PlayerState{
        .{
            .index = 0,
            .pos = .{ .x = 10.0, .y = 20.0 },
            .health = 90.0,
        },
    };
    players[0].perk_counts[@intCast(PerkId.regeneration)] = 1;
    players[0].perk_counts[@intCast(PerkId.greater_regeneration)] = 1;

    updatePerkEffects(&state, players[0..], 0.2);
    try std.testing.expectApproxEqAbs(@as(f64, 90.2), players[0].health, 1e-6);
}

test "regeneration multiplayer targets all alive players by default" {
    var state = survival_state.GameplayState.init(1);
    var players = [_]survival_state.PlayerState{
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
    players[0].perk_counts[@intCast(PerkId.regeneration)] = 1;

    updatePerkEffects(&state, players[0..], 0.2);
    try std.testing.expectApproxEqAbs(@as(f64, 90.2), players[0].health, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f64, 80.2), players[1].health, 1e-6);
}

test "regeneration preserve bugs repeats write to player zero only" {
    var state = survival_state.GameplayState.init(1);
    state.preserve_bugs = true;
    var players = [_]survival_state.PlayerState{
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
    players[0].perk_counts[@intCast(PerkId.regeneration)] = 1;

    updatePerkEffects(&state, players[0..], 0.2);
    try std.testing.expectApproxEqAbs(@as(f64, 90.4), players[0].health, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f64, 80.0), players[1].health, 1e-6);
}

test "bandage adds random amount and clamps in default mode" {
    var state = survival_state.GameplayState.init(20_072);
    var players = [_]survival_state.PlayerState{
        .{
            .index = 0,
            .pos = .{ .x = 10.0, .y = 20.0 },
            .health = 3.0,
        },
    };

    try applyPerk(&state, players[0..], PerkId.bandage);
    try std.testing.expectApproxEqAbs(@as(f64, 53.0), players[0].health, 1e-6);
}

test "bandage preserve bugs multiplies instead of adds" {
    var state = survival_state.GameplayState.init(20_072);
    state.preserve_bugs = true;
    var players = [_]survival_state.PlayerState{
        .{
            .index = 0,
            .pos = .{ .x = 10.0, .y = 20.0 },
            .health = 3.0,
        },
    };

    try applyPerk(&state, players[0..], PerkId.bandage);
    try std.testing.expectApproxEqAbs(@as(f64, 100.0), players[0].health, 1e-6);
}

test "random weapon assigns non-pistol weapon from pistol baseline" {
    var state = survival_state.GameplayState.init(1);
    var players = [_]survival_state.PlayerState{
        .{
            .index = 0,
            .pos = .{},
            .weapon_id = survival_state.WeaponId.pistol,
        },
    };

    try applyPerk(&state, players[0..], PerkId.random_weapon);
    try std.testing.expectEqual(survival_state.WeaponId.assault_rifle, players[0].weapon_id);
}

test "random weapon rerolls pistol when current weapon is not pistol" {
    var state = survival_state.GameplayState.init(25);
    var players = [_]survival_state.PlayerState{
        .{
            .index = 0,
            .pos = .{},
            .weapon_id = survival_state.WeaponId.shotgun,
        },
    };

    try applyPerk(&state, players[0..], PerkId.random_weapon);
    try std.testing.expectEqual(survival_state.WeaponId.assault_rifle, players[0].weapon_id);
}

test "random weapon retry cap applies last roll after 100 attempts" {
    var state = survival_state.GameplayState.init(1234);
    state.game_mode = 3;

    var expected = state;
    for (0..100) |_| {
        _ = survival_bonuses.weaponPickRandomAvailable(&expected);
    }

    var players = [_]survival_state.PlayerState{
        .{
            .index = 0,
            .pos = .{},
            .weapon_id = survival_state.WeaponId.pistol,
        },
    };

    try applyPerk(&state, players[0..], PerkId.random_weapon);
    try std.testing.expectEqual(survival_state.WeaponId.pistol, players[0].weapon_id);
    try std.testing.expectEqual(expected.rng.state, state.rng.state);
}

test "fatal lottery grants xp when rng is even" {
    var state = survival_state.GameplayState.init(0);
    var players = [_]survival_state.PlayerState{
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
    try std.testing.expectEqual(@as(f64, 100.0), players[0].health);
    try std.testing.expectEqual(@as(i32, 456), players[1].experience);
    try std.testing.expectEqual(@as(f64, 100.0), players[1].health);
}

test "fatal lottery kills owner only when rng is odd" {
    var state = survival_state.GameplayState.init(1);
    var players = [_]survival_state.PlayerState{
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
    try std.testing.expectEqual(@as(f64, 100.0), players[1].health);
}

test "grim deal kills owner and boosts experience" {
    var state = survival_state.GameplayState.init(1);
    var players = [_]survival_state.PlayerState{
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
    try std.testing.expectEqual(@as(f64, 100.0), players[1].health);
    try std.testing.expectEqual(@as(i32, 7), players[1].experience);
}
