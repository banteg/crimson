const std = @import("std");
const game_ids = @import("../game_ids.zig");
const native_math = @import("native_math.zig");

const bonus_runtime = @import("bonuses.zig");
const state_mod = @import("state.zig");

const narrowF32 = native_math.roundF32;

pub const PerkApplyError = error{
    UnsupportedPerkApplyHandler,
};

pub const PerkId = game_ids.PerkId;
pub const GameModeId = game_ids.GameModeId;

const PerkFlag = enum {
    quest_mode_allowed,
    two_player_allowed,
    stackable,
};
const PerkFlagSet = std.EnumSet(PerkFlag);

pub const perk_id_max: i32 = @intCast(state_mod.perk_count_size - 1);
const perk_id_max_usize: usize = state_mod.perk_count_size - 1;
const perk_base_available_max_id: i32 = 27;

inline fn perkIdInt(perk_id: PerkId) i32 {
    return @intFromEnum(perk_id);
}

inline fn perkIdIndex(perk_id: PerkId) usize {
    return @intCast(@intFromEnum(perk_id));
}

fn perkIdFromInt(value: i32) ?PerkId {
    return std.meta.intToEnum(PerkId, value) catch null;
}

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
    if (state.perk_available_unlock_index == quest_unlock_index) return;

    state.perk_available = [_]bool{false} ** state_mod.perk_count_size;

    var perk_id: i32 = 1;
    while (perk_id <= perk_base_available_max_id) : (perk_id += 1) {
        if (perk_id < state.perk_available.len) {
            state.perk_available[@intCast(perk_id)] = true;
        }
    }

    for (perk_always_available) |always_id| {
        state.perk_available[perkIdIndex(always_id)] = true;
    }

    if (quest_unlock_index > 0) {
        const limit: usize = @min(
            @as(usize, @intCast(quest_unlock_index)),
            quest_unlock_perk_by_index.len,
        );
        for (quest_unlock_perk_by_index[0..limit]) |maybe_perk_id| {
            if (maybe_perk_id) |perk_unlock_id| {
                state.perk_available[perkIdIndex(perk_unlock_id)] = true;
            }
        }
    }

    state.perk_available[perkIdIndex(PerkId.antiperk)] = false;
    state.perk_available_unlock_index = quest_unlock_index;
}

pub fn perkChoiceCount(player: *const state_mod.PlayerState) i32 {
    if (perkCountGet(player, PerkId.perk_master) > 0) return 7;
    if (perkCountGet(player, PerkId.perk_expert) > 0) return 6;
    return 5;
}

pub fn perkSelectionCurrentChoices(
    state: *state_mod.GameplayState,
    players: []state_mod.PlayerState,
    game_mode: GameModeId,
    player_count: i32,
    quest_unlock_index: i32,
) []const i32 {
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

    const perk_id_raw = choices[@intCast(choice_index)];
    const perk_id = perkIdFromInt(perk_id_raw) orelse return null;
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
    state: *state_mod.GameplayState,
    players: []state_mod.PlayerState,
    perk_id: PerkId,
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
                state_mod.weaponAssignPlayerWithState(player, player.weapon_id, state);
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
                const candidate = bonus_runtime.weaponPickRandomAvailable(state);
                selected = candidate;
                if (candidate != game_ids.WeaponId.pistol and candidate != current) break;
            }
            state_mod.weaponAssignPlayerWithState(&players[0], selected, state);
        },
        PerkId.breathing_room => {
            for (players) |*player| {
                const reduction = narrowF32(player.health * (2.0 / 3.0));
                player.health = narrowF32(player.health - reduction);
            }
            state.bonus_spawn_guard = false;
        },
        PerkId.bandage => {
            for (players) |*player| {
                if (player.health > 0.0) {
                    const amount: f64 = @floatFromInt(state.rng.rand() % 50 + 1);
                    if (state.preserve_bugs) {
                        player.health = @min(100.0, narrowF32(player.health * amount));
                    } else {
                        player.health = @min(100.0, narrowF32(player.health + amount));
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
    state: *state_mod.GameplayState,
    count: usize,
) void {
    for (0..count) |_| {
        _ = state.rng.rand();
        _ = state.rng.rand();
        _ = state.rng.rand();
        _ = state.rng.rand();
    }
}

pub fn updatePerkEffects(
    state: *state_mod.GameplayState,
    players: []state_mod.PlayerState,
    dt: f64,
) void {
    if (dt > 0.0) {
        for (players) |*player| {
            if (player.shield_timer <= 0.0) {
                player.shield_timer = 0.0;
            } else {
                player.shield_timer -= narrowF32(dt);
            }

            if (player.fire_bullets_timer <= 0.0) {
                player.fire_bullets_timer = 0.0;
            } else {
                player.fire_bullets_timer -= narrowF32(dt);
            }

            if (player.speed_bonus_timer <= 0.0) {
                player.speed_bonus_timer = 0.0;
            } else {
                player.speed_bonus_timer -= narrowF32(dt);
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
                players[0].health += narrowF32(dt);
                if (players[0].health > 100.0) {
                    players[0].health = 100.0;
                }
            }
        } else {
            var heal_amount = narrowF32(dt);
            if (perkActive(&players[0], PerkId.greater_regeneration)) {
                heal_amount = narrowF32(dt) * 2.0;
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

    state.lean_mean_exp_timer = narrowF32(state.lean_mean_exp_timer - dt);
    if (state.lean_mean_exp_timer < 0.0) {
        state.lean_mean_exp_timer = 0.25;
        const perk_count = perkCountGet(&players[0], PerkId.lean_mean_exp_machine);
        if (perk_count > 0) {
            players[0].experience += perk_count * 10;
        }
    }

    if (!perkActive(&players[0], PerkId.death_clock)) return;

    for (players) |*player| {
        if (player.health <= 0.0) {
            player.health = 0.0;
        } else {
            player.health -= narrowF32(dt) * 3.3333333;
        }
    }
}

fn perkGenerateChoices(
    state: *state_mod.GameplayState,
    players: []const state_mod.PlayerState,
    player: *const state_mod.PlayerState,
    game_mode: GameModeId,
    player_count: i32,
    quest_unlock_index: i32,
) [7]i32 {
    perksRebuildAvailable(state, quest_unlock_index);

    var offerable = [_]bool{false} ** (perk_id_max_usize + 1);
    var perk_id_raw: i32 = 1;
    while (perk_id_raw <= perk_id_max) : (perk_id_raw += 1) {
        const perk_id = perkIdFromInt(perk_id_raw) orelse continue;
        if (perk_id_raw >= state.perk_available.len) continue;
        if (!state.perk_available[@intCast(perk_id_raw)]) continue;
        if (perkCanOffer(state, player, perk_id, game_mode, player_count)) {
            offerable[@intCast(perk_id_raw)] = true;
        }
    }

    const death_clock_active = perkActive(player, PerkId.death_clock);
    const pyromaniac_allowed = pyromaniacAllowed(state, players, player, player_count);

    var choices = [_]i32{perkIdInt(PerkId.antiperk)} ** 7;
    var choice_index: usize = 0;

    if (state.quest_stage_major == 3 and state.quest_stage_minor == 4 and !perkActive(player, PerkId.monster_vision)) {
        choices[0] = perkIdInt(PerkId.monster_vision);
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
            if (isRarityGate(candidate) and ((state.rng.rand() & 3) == 1)) continue;

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
        choices[choice_index] = perkIdInt(selected);
    }

    if (game_mode == .tutorial) {
        choices = .{
            perkIdInt(PerkId.sharpshooter),
            perkIdInt(PerkId.long_distance_runner),
            perkIdInt(PerkId.evil_eyes),
            perkIdInt(PerkId.radioactive),
            perkIdInt(PerkId.fastshot),
            perkIdInt(PerkId.fastshot),
            perkIdInt(PerkId.fastshot),
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
    if (player.weapon_id == game_ids.WeaponId.flamethrower) return true;
    if (state.preserve_bugs or player_count <= 1) return false;

    for (players) |source_player| {
        if (source_player.health <= 0.0) continue;
        if (source_player.weapon_id == game_ids.WeaponId.flamethrower) return true;
    }
    return false;
}

fn selectRandomOffer(state: *state_mod.GameplayState, offerable: []const bool) PerkId {
    var draws: i32 = 0;
    while (draws < 1000) : (draws += 1) {
        const candidate_raw: i32 = @intCast(state.rng.rand() % @as(u32, @intCast(perk_id_max)) + 1);
        if (candidate_raw >= 0 and candidate_raw < offerable.len and offerable[@intCast(candidate_raw)]) {
            const candidate = perkIdFromInt(candidate_raw) orelse continue;
            return candidate;
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
    _ = state;
    if (perk_id == .antiperk) return false;

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

fn perkActive(player: *const state_mod.PlayerState, perk_id: PerkId) bool {
    return perkCountGet(player, perk_id) > 0;
}

fn containsPerkId(values: []const i32, needle: PerkId) bool {
    const needle_raw = perkIdInt(needle);
    for (values) |value| {
        if (value == needle_raw) return true;
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

fn setOnlyPerksAvailable(
    state: *state_mod.GameplayState,
    unlock_index: i32,
    perk_ids: []const PerkId,
) void {
    state.perk_available = [_]bool{false} ** state_mod.perk_count_size;
    for (perk_ids) |perk_id| {
        state.perk_available[perkIdIndex(perk_id)] = true;
    }
    state.perk_available_unlock_index = unlock_index;
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

test "antiperk is never offerable" {
    var state = state_mod.GameplayState.init(1);
    const player = state_mod.PlayerState{
        .index = 0,
        .pos = .{},
    };
    try std.testing.expect(!perkCanOffer(
        &state,
        &player,
        PerkId.antiperk,
        .survival,
        1,
    ));
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
    try std.testing.expectEqual(perkIdInt(PerkId.monster_vision), choices[0]);
}

test "pyromaniac multiplayer gate matches default and preserve-bugs behavior" {
    var state = state_mod.GameplayState.init(0x1234);
    var players = [_]state_mod.PlayerState{
        .{ .index = 0, .pos = .{}, .weapon_id = game_ids.WeaponId.pistol },
        .{ .index = 1, .pos = .{}, .weapon_id = game_ids.WeaponId.flamethrower },
    };

    try std.testing.expect(pyromaniacAllowed(&state, players[0..], &players[0], 2));

    players[1].health = 0.0;
    try std.testing.expect(!pyromaniacAllowed(&state, players[0..], &players[0], 2));

    players[0].weapon_id = game_ids.WeaponId.flamethrower;
    try std.testing.expect(pyromaniacAllowed(&state, players[0..], &players[0], 2));

    state.preserve_bugs = true;
    players[0].weapon_id = game_ids.WeaponId.pistol;
    players[1].health = 100.0;
    try std.testing.expect(!pyromaniacAllowed(&state, players[0..], &players[0], 2));
}

test "perk generate choices rejects pyromaniac when no player has flamethrower" {
    var state = state_mod.GameplayState.init(0x1234);
    var players = [_]state_mod.PlayerState{
        .{ .index = 0, .pos = .{}, .weapon_id = game_ids.WeaponId.pistol },
    };
    setOnlyPerksAvailable(&state, 0, &.{
        PerkId.pyromaniac,
        PerkId.sharpshooter,
        PerkId.fastloader,
        PerkId.lean_mean_exp_machine,
        PerkId.long_distance_runner,
        PerkId.pyrokinetic,
        PerkId.instant_winner,
        PerkId.grim_deal,
    });

    const choices = perkSelectionCurrentChoices(
        &state,
        players[0..],
        .survival,
        1,
        0,
    );
    for (choices) |perk_id| {
        try std.testing.expect(perk_id != perkIdInt(PerkId.pyromaniac));
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
    setOnlyPerksAvailable(&state, 0, &.{
        PerkId.jinxed,
        PerkId.sharpshooter,
        PerkId.fastloader,
        PerkId.lean_mean_exp_machine,
        PerkId.long_distance_runner,
        PerkId.pyrokinetic,
        PerkId.instant_winner,
        PerkId.pyromaniac,
    });

    const choices = perkSelectionCurrentChoices(
        &state,
        players[0..],
        .survival,
        1,
        0,
    );
    for (choices) |perk_id| {
        try std.testing.expect(perk_id != perkIdInt(PerkId.jinxed));
    }
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
    try std.testing.expectEqual(@as(f64, 100.0), players[0].health);

    updatePerkEffects(&state, players[0..], 1.0 / 60.0);
    try std.testing.expectApproxEqAbs(@as(f64, 99.944444445), players[0].health, 1e-5);
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
    try std.testing.expectApproxEqAbs(@as(f64, 90.2), players[0].health, 1e-5);
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
    try std.testing.expectApproxEqAbs(@as(f64, 90.0), players[0].health, 1e-6);
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
    try std.testing.expectApproxEqAbs(@as(f64, 90.4), players[0].health, 1e-5);
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
    try std.testing.expectApproxEqAbs(@as(f64, 90.2), players[0].health, 1e-5);
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
    try std.testing.expectApproxEqAbs(@as(f64, 90.2), players[0].health, 1e-5);
    try std.testing.expectApproxEqAbs(@as(f64, 80.2), players[1].health, 1e-5);
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
    try std.testing.expectApproxEqAbs(@as(f64, 90.4), players[0].health, 1e-5);
    try std.testing.expectApproxEqAbs(@as(f64, 80.0), players[1].health, 1e-6);
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
    try std.testing.expectApproxEqAbs(@as(f64, 53.0), players[0].health, 1e-6);
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
    try std.testing.expectApproxEqAbs(@as(f64, 100.0), players[0].health, 1e-6);
}

test "random weapon assigns non-pistol weapon from pistol baseline" {
    var state = state_mod.GameplayState.init(1);
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{},
            .weapon_id = game_ids.WeaponId.pistol,
        },
    };

    try applyPerk(&state, players[0..], PerkId.random_weapon);
    try std.testing.expectEqual(game_ids.WeaponId.assault_rifle, players[0].weapon_id);
}

test "random weapon rerolls pistol when current weapon is not pistol" {
    var state = state_mod.GameplayState.init(25);
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{},
            .weapon_id = game_ids.WeaponId.shotgun,
        },
    };

    try applyPerk(&state, players[0..], PerkId.random_weapon);
    try std.testing.expectEqual(game_ids.WeaponId.assault_rifle, players[0].weapon_id);
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
            .weapon_id = game_ids.WeaponId.pistol,
        },
    };

    try applyPerk(&state, players[0..], PerkId.random_weapon);
    try std.testing.expectEqual(game_ids.WeaponId.pistol, players[0].weapon_id);
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
    try std.testing.expectEqual(@as(f64, 100.0), players[0].health);
    try std.testing.expectEqual(@as(i32, 456), players[1].experience);
    try std.testing.expectEqual(@as(f64, 100.0), players[1].health);
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
    try std.testing.expectEqual(@as(f64, 100.0), players[1].health);
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
    try std.testing.expectEqual(@as(f64, 100.0), players[1].health);
    try std.testing.expectEqual(@as(i32, 7), players[1].experience);
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
    try std.testing.expectApproxEqAbs(@as(f64, 0.1), players[0].health, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f64, 0.1), players[1].health, 1e-6);
}

test "ammo maniac reassigns weapons and boosts clip size for all players" {
    var state = state_mod.GameplayState.init(1);
    var players = [_]state_mod.PlayerState{
        .{ .index = 0, .pos = .{}, .weapon_id = game_ids.WeaponId.assault_rifle },
        .{ .index = 1, .pos = .{}, .weapon_id = game_ids.WeaponId.pistol },
    };
    state_mod.weaponAssignPlayerWithState(&players[0], players[0].weapon_id, &state);
    state_mod.weaponAssignPlayerWithState(&players[1], players[1].weapon_id, &state);

    const base_clip0 = players[0].clip_size;
    const base_clip1 = players[1].clip_size;
    players[0].ammo = 1.0;
    players[1].ammo = 2.0;

    try applyPerk(&state, players[0..], PerkId.ammo_maniac);

    try std.testing.expect(players[0].clip_size > base_clip0);
    try std.testing.expect(players[1].clip_size > base_clip1);
    try std.testing.expectEqual(@as(f64, @floatFromInt(players[0].clip_size)), players[0].ammo);
    try std.testing.expectEqual(@as(f64, @floatFromInt(players[1].clip_size)), players[1].ammo);
    try std.testing.expect(!players[0].reload_active);
    try std.testing.expect(!players[1].reload_active);
    try std.testing.expectEqual(@as(f64, 0.0), players[0].reload_timer);
    try std.testing.expectEqual(@as(f64, 0.0), players[1].reload_timer);
    try std.testing.expectEqual(@as(i32, 1), players[1].perk_counts.get(PerkId.ammo_maniac));
}

test "my favourite weapon increases clip size and keeps current ammo on apply" {
    var state = state_mod.GameplayState.init(1);
    var players = [_]state_mod.PlayerState{
        .{ .index = 0, .pos = .{}, .weapon_id = game_ids.WeaponId.pistol },
    };
    state_mod.weaponAssignPlayerWithState(&players[0], players[0].weapon_id, &state);

    const base_clip = players[0].clip_size;
    players[0].ammo = 5.0;
    try applyPerk(&state, players[0..], PerkId.my_favourite_weapon);

    try std.testing.expectEqual(base_clip + 2, players[0].clip_size);
    try std.testing.expectEqual(@as(f64, 5.0), players[0].ammo);

    state_mod.weaponAssignPlayerWithState(&players[0], players[0].weapon_id, &state);
    try std.testing.expectEqual(base_clip + 2, players[0].clip_size);
    try std.testing.expectEqual(@as(f64, @floatFromInt(base_clip + 2)), players[0].ammo);
}

test "breathing room reduces player health and clears bonus spawn guard" {
    var state = state_mod.GameplayState.init(1);
    state.bonus_spawn_guard = true;
    var players = [_]state_mod.PlayerState{
        .{ .index = 0, .pos = .{}, .health = 90.0 },
        .{ .index = 1, .pos = .{}, .health = 45.0 },
    };

    try applyPerk(&state, players[0..], PerkId.breathing_room);
    try std.testing.expectApproxEqAbs(@as(f64, 30.0), players[0].health, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f64, 15.0), players[1].health, 1e-6);
    try std.testing.expect(!state.bonus_spawn_guard);
}

test "thick skinned clamps health floor at one" {
    var state = state_mod.GameplayState.init(1);
    var players = [_]state_mod.PlayerState{
        .{ .index = 0, .pos = .{}, .health = 90.0 },
        .{ .index = 1, .pos = .{}, .health = 1.2 },
    };

    try applyPerk(&state, players[0..], PerkId.thick_skinned);
    try std.testing.expectApproxEqAbs(@as(f64, 60.0), players[0].health, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f64, 1.0), players[1].health, 1e-6);
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
    try std.testing.expectApproxEqAbs(@as(f64, 0.25), state.lean_mean_exp_timer, 1e-6);
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
