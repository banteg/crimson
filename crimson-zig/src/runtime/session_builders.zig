const std = @import("std");
const game_ids = @import("../game_ids.zig");
const replay_codec = @import("../replay_codec.zig");

const runtime_bootstrap = @import("bootstrap.zig");
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
    strict_events: bool = true,
    quest_spawn_entries: ?[]const spawn_mod.QuestSpawnEntry = null,
    quest_start_weapon_id: ?i32 = null,
};

pub const ReplayExecutionMode = struct {
    capture_spawn_events_authoritative: bool,
    apply_world_dt_steps: bool,
    defer_menu_open_events: bool,
};

pub fn deriveReplayExecutionMode(events: []const replay_codec.ReplayEvent) ReplayExecutionMode {
    var original_capture_replay = false;
    var has_capture_creature_spawn_events = false;
    for (events) |event| {
        switch (event) {
            .capture_bootstrap => original_capture_replay = true,
            .capture_creature_spawn => has_capture_creature_spawn_events = true,
            else => {},
        }
    }

    const capture_spawn_events_authoritative = original_capture_replay and has_capture_creature_spawn_events;
    return .{
        .capture_spawn_events_authoritative = capture_spawn_events_authoritative,
        .apply_world_dt_steps = !original_capture_replay,
        .defer_menu_open_events = original_capture_replay,
    };
}

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
    session_options.quest_start_weapon_id_for_reset = options.quest_start_weapon_id;
    session_options.quest_spawn_entries = options.quest_spawn_entries;

    var session = try runtime_session.DeterministicSession.init(config, session_options);

    const weapon_id = @max(1, options.quest_start_weapon_id);
    for (session.players()) |*player| {
        player_runtime.weaponAssignPlayer(player, weapon_data.weaponIdFromInt(weapon_id));
    }

    return session;
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

pub fn buildReplaySession(
    game_mode: game_ids.GameModeId,
    header: replay_codec.ReplayHeader,
    events: []const replay_codec.ReplayEvent,
    options: BuildReplaySessionOptions,
) runtime_session.DeterministicSessionError!runtime_session.DeterministicSession {
    const mode = deriveReplayExecutionMode(events);

    var quest_start_weapon_id_for_reset: i32 = options.quest_start_weapon_id orelse @intFromEnum(game_ids.WeaponId.pistol);
    var quest_spawn_entries_storage: [runtime_session.max_sim_quest_spawn_entries]spawn_mod.QuestSpawnEntry = undefined;
    var quest_spawn_entries: []spawn_mod.QuestSpawnEntry = quest_spawn_entries_storage[0..0];

    if (game_mode == .quests) {
        if (options.quest_spawn_entries) |entries| {
            if (entries.len > quest_spawn_entries_storage.len) {
                return error.InvalidQuestSpawnTable;
            }
            @memcpy(quest_spawn_entries_storage[0..entries.len], entries);
            quest_spawn_entries = quest_spawn_entries_storage[0..entries.len];
        } else {
            const level_key = runtime_bootstrap.resolveQuestLevelKey(header) orelse return error.InvalidQuestSpawnTable;
            const built = quest_spawn_logic.buildQuestSpawnTableWithHardcore(
                level_key,
                header.player_count,
                header.seed,
                header.world_size,
                header.hardcore,
                quest_spawn_entries_storage[0..],
            ) catch |build_err| switch (build_err) {
                error.InvalidQuestSpawnTable => return error.InvalidQuestSpawnTable,
                error.OutOfSpace => return error.InvalidQuestSpawnTable,
            };
            quest_spawn_entries = quest_spawn_entries_storage[0..built.entries.len];
            if (options.quest_start_weapon_id == null) {
                quest_start_weapon_id_for_reset = @intFromEnum(built.start_weapon_id);
            }
            if (quest_spawn_entries.len == 0) {
                return error.InvalidQuestSpawnTable;
            }
        }

        if (header.hardcore) {
            spawn_mod.applyHardcoreQuestSpawnTableAdjustment(quest_spawn_entries);
        }
        if (mode.capture_spawn_events_authoritative) {
            quest_spawn_entries = quest_spawn_entries_storage[0..0];
        }
    }

    const config = try runtime_session.SessionConfig.fromReplayHeader(header);
    const session_options: BuildSessionOptions = .{
        .strict_events = options.strict_events,
        .defer_menu_open_events = mode.defer_menu_open_events,
        .apply_world_dt_steps = mode.apply_world_dt_steps,
        .capture_spawn_events_authoritative = mode.capture_spawn_events_authoritative,
    };

    return switch (game_mode) {
        .survival => buildSurvivalSession(config, session_options),
        .rush => buildRushSession(config, session_options),
        .typo => buildTypoSession(
            config,
            .{
                .session_options = session_options,
                .dictionary_words = header.typo_dictionary_words,
                .highscore_names = header.typo_highscore_names,
            },
        ),
        .tutorial => buildTutorialSession(config, session_options),
        .quests => buildQuestSession(
            config,
            .{
                .session_options = .{
                    .strict_events = session_options.strict_events,
                    .defer_menu_open_events = session_options.defer_menu_open_events,
                    .apply_world_dt_steps = session_options.apply_world_dt_steps,
                    .capture_spawn_events_authoritative = session_options.capture_spawn_events_authoritative,
                },
                .quest_spawn_entries = if (!mode.capture_spawn_events_authoritative) quest_spawn_entries else quest_spawn_entries_storage[0..0],
                .quest_start_weapon_id = quest_start_weapon_id_for_reset,
            },
        ),
    };
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
