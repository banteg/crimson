const std = @import("std");
const game_ids = @import("../game_ids.zig");
const replay_codec = @import("../replay_codec.zig");

const player_runtime = @import("player.zig");
const quest_spawn_logic = @import("../quest_spawn/logic_full.zig");
const runtime_session = @import("session.zig");
const spawn_mod = @import("spawn.zig");
const tutorial_state = @import("../tutorial/state.zig");
const weapon_data = @import("weapon_data.zig");

pub const BuildSessionOptions = runtime_session.SessionInitOptions;

pub const BuildQuestSessionOptions = struct {
    session_options: BuildSessionOptions = .{},
    quest_spawn_entries: []const spawn_mod.QuestSpawnEntry,
    quest_start_weapon_id: i32 = @intFromEnum(game_ids.WeaponId.pistol),
};

pub const BuildTypoSessionOptions = struct {
    session_options: BuildSessionOptions = .{},
    dictionary_words: []const []const u8 = &.{},
    highscore_names: []const []const u8 = &.{},
};

pub const BuildReplaySessionOptions = struct {
    quest_spawn_entries: ?[]const spawn_mod.QuestSpawnEntry = null,
    quest_start_weapon_id: ?i32 = null,
};

pub fn buildSurvivalSession(
    config: runtime_session.SessionConfig,
    options: BuildSessionOptions,
) runtime_session.DeterministicSessionError!runtime_session.DeterministicSession {
    if (config.game_mode != .survival) {
        return error.UnsupportedGameMode;
    }
    return runtime_session.DeterministicSession.init(config, options);
}

pub fn buildRushSession(
    config: runtime_session.SessionConfig,
    options: BuildSessionOptions,
) runtime_session.DeterministicSessionError!runtime_session.DeterministicSession {
    if (config.game_mode != .rush) {
        return error.UnsupportedGameMode;
    }
    return runtime_session.DeterministicSession.init(config, options);
}

pub fn buildQuestSession(
    config: runtime_session.SessionConfig,
    options: BuildQuestSessionOptions,
) runtime_session.DeterministicSessionError!runtime_session.DeterministicSession {
    if (config.game_mode != .quests) {
        return error.UnsupportedGameMode;
    }

    var session_options = options.session_options;
    session_options.quest_spawn_entries = options.quest_spawn_entries;

    var session = try runtime_session.DeterministicSession.init(config, session_options);
    assignQuestStartWeapon(&session, options.quest_start_weapon_id);
    return session;
}

fn assignQuestStartWeapon(session: *runtime_session.DeterministicSession, start_weapon_id: i32) void {
    const weapon_id = weapon_data.weaponIdFromInt(@max(1, start_weapon_id));
    for (session.players()) |*player| {
        player_runtime.weaponAssignPlayerWithState(player, weapon_id, &session.state);
    }
}

pub fn buildTypoSession(
    config: runtime_session.SessionConfig,
    options: BuildTypoSessionOptions,
) runtime_session.DeterministicSessionError!runtime_session.DeterministicSession {
    if (config.game_mode != .typo) {
        return error.UnsupportedGameMode;
    }
    if (config.player_count != 1) {
        return error.InvalidPlayerCount;
    }
    var session = try runtime_session.DeterministicSession.init(config, options.session_options);
    session.state.typo.reset(options.dictionary_words, options.highscore_names);
    return session;
}

pub fn buildTutorialSession(
    config: runtime_session.SessionConfig,
    options: BuildSessionOptions,
) runtime_session.DeterministicSessionError!runtime_session.DeterministicSession {
    if (config.game_mode != .tutorial) {
        return error.UnsupportedGameMode;
    }
    if (config.player_count != 1) {
        return error.InvalidPlayerCount;
    }
    var session = try runtime_session.DeterministicSession.init(config, options);
    player_runtime.weaponAssignPlayerWithState(&session.players()[0], .pistol, &session.state);
    tutorial_state.resetTutorialState(
        &session.state.tutorial,
        &session.state.tutorial_overlay,
        config.preserve_bugs,
    );
    return session;
}

/// Build the session a replay's run spec starts from.
pub fn buildReplaySession(
    run: replay_codec.RunSpec,
    options: BuildReplaySessionOptions,
) runtime_session.DeterministicSessionError!runtime_session.DeterministicSession {
    const config = runtime_session.SessionConfig.fromRunSpec(run);
    var session = switch (run.game_mode) {
        .quests => return buildQuestReplaySession(run, config, options),
        .tutorial => return buildTutorialSession(config, .{}),
        .survival => try buildSurvivalSession(config, .{}),
        .rush => try buildRushSession(config, .{}),
        .typo => try buildTypoSession(config, .{
            .dictionary_words = run.typo_dictionary_words,
            .highscore_names = run.typo_highscore_names,
        }),
    };
    // Only quest and tutorial sessions carry a run's demo flag into gameplay
    // state; the creature spawn environment keeps it in every mode.
    session.state.demo_mode_active = false;
    return session;
}

/// Quest startup builds the spawn table from the world RNG left by terrain
/// setup, so the builder's draws advance the run's RNG.
fn buildQuestReplaySession(
    run: replay_codec.RunSpec,
    config: runtime_session.SessionConfig,
    options: BuildReplaySessionOptions,
) runtime_session.DeterministicSessionError!runtime_session.DeterministicSession {
    var session = try runtime_session.DeterministicSession.init(config, .{});
    var start_weapon_id: i32 = options.quest_start_weapon_id orelse @intFromEnum(game_ids.WeaponId.pistol);
    var entries_storage: [runtime_session.max_sim_quest_spawn_entries]spawn_mod.QuestSpawnEntry = undefined;
    var entries: []spawn_mod.QuestSpawnEntry = undefined;
    if (options.quest_spawn_entries) |override| {
        if (override.len > entries_storage.len) return error.InvalidQuestSpawnTable;
        @memcpy(entries_storage[0..override.len], override);
        entries = entries_storage[0..override.len];
    } else {
        const level = run.quest_level orelse return error.InvalidQuestSpawnTable;
        const built = quest_spawn_logic.buildQuestSpawnTableWithHardcore(
            @as(i32, level.major) * 100 + level.minor,
            run.player_count,
            session.state.rng.state,
            replay_codec.world_size,
            run.hardcore,
            entries_storage[0..],
        ) catch return error.InvalidQuestSpawnTable;
        if (built.entries.len == 0) return error.InvalidQuestSpawnTable;
        entries = entries_storage[0..built.entries.len];
        session.state.rng.srand(built.rng_state);
        if (options.quest_start_weapon_id == null) start_weapon_id = @intFromEnum(built.start_weapon_id);
    }
    if (run.hardcore) spawn_mod.applyHardcoreQuestSpawnTableAdjustment(entries);
    try session.setQuestSpawnEntries(entries);
    assignQuestStartWeapon(&session, start_weapon_id);
    return session;
}

fn testConfig(game_mode: game_ids.GameModeId) runtime_session.SessionConfig {
    return .{
        .seed = 0x1234,
        .game_mode = game_mode,
        .player_count = 1,
        .world_size = 1024.0,
        .tick_rate = 60,
    };
}

test "only quest and tutorial replay sessions keep the demo flag in gameplay state" {
    const survival = try buildReplaySession(.{ .game_mode = .survival, .seed = 1, .demo = true }, .{});
    try std.testing.expect(!survival.state.demo_mode_active);
    try std.testing.expect(survival.creatures.demo_mode_active);

    const tutorial = try buildReplaySession(.{ .game_mode = .tutorial, .seed = 1, .demo = true }, .{});
    try std.testing.expect(tutorial.state.demo_mode_active);
    const quest = try buildReplaySession(.{ .game_mode = .quests, .seed = 1, .quest_level = .{ .major = 1, .minor = 1 }, .demo = true }, .{});
    try std.testing.expect(quest.state.demo_mode_active);
}

test "build tutorial session primes the same pistol for live play and replay" {
    var session = try buildTutorialSession(testConfig(.tutorial), .{});
    const player = session.players()[0];
    try std.testing.expectEqual(game_ids.WeaponId.pistol, player.weapon.weapon_id);
    try std.testing.expectEqual(@as(i32, 12), player.weapon.clip_size);
    try std.testing.expectEqual(@as(f32, 12), player.weapon.ammo);
    try std.testing.expectEqual(@as(f32, 0), player.weapon.shot_cooldown);
}

test "build rush session enforces assault rifle loadout" {
    var session = try buildRushSession(testConfig(.rush), .{});
    const player = session.players()[0];
    try std.testing.expectEqual(game_ids.WeaponId.assault_rifle, player.weapon.weapon_id);
    try std.testing.expectEqual(@as(f32, 30.0), player.weapon.ammo);
}

test "build quest session assigns requested start weapon and spawn table" {
    var entries = [_]spawn_mod.QuestSpawnEntry{
        .{
            .pos = .{ .x = 10.0, .y = 20.0 },
            .heading = 1.5,
            .spawn_id = .zombie_boss_spawner_00,
            .trigger_ms = 50,
            .count = 2,
        },
    };
    var session = try buildQuestSession(
        testConfig(.quests),
        .{
            .quest_spawn_entries = entries[0..],
            .quest_start_weapon_id = @intFromEnum(game_ids.WeaponId.shotgun),
        },
    );
    const player = session.players()[0];
    try std.testing.expectEqual(game_ids.WeaponId.shotgun, player.weapon.weapon_id);
    try std.testing.expectEqual(@as(usize, 1), session.questSpawnEntries().len);
    try std.testing.expectEqual(entries[0].spawn_id, session.questSpawnEntries()[0].spawn_id);
    const copy = try std.testing.allocator.create(runtime_session.DeterministicSession);
    defer std.testing.allocator.destroy(copy);
    copy.* = session;
    copy.questSpawnEntries()[0].count = 7;
    try std.testing.expectEqual(@as(i32, 2), session.questSpawnEntries()[0].count);
    try std.testing.expectEqual(@as(i32, 7), copy.questSpawnEntries()[0].count);
}

test "build typo session copies replay dictionary sources" {
    var session = try buildTypoSession(
        testConfig(.typo),
        .{
            .dictionary_words = &.{"amber"},
            .highscore_names = &.{"Alpha"},
        },
    );
    try std.testing.expectEqualStrings("amber", session.state.typo.dictionaryWordSlice(0));
    try std.testing.expectEqualStrings("Alpha", session.state.typo.highscoreNameSlice(0));
}

test "quest startup adds each assigned weapon to the pre-start usage counts" {
    var config = testConfig(.quests);
    config.player_count = 2;
    config.status_weapon_usage_counts[@intFromEnum(game_ids.WeaponId.shotgun)] = 7;
    const session = try buildQuestSession(config, .{
        .quest_spawn_entries = &.{},
        .quest_start_weapon_id = @intFromEnum(game_ids.WeaponId.shotgun),
    });
    try std.testing.expectEqual(@as(u32, 9), session.state.status_weapon_usage_counts.get(.shotgun));
}
