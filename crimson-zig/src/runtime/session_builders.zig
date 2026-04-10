const game_ids = @import("../game_ids.zig");
const replay_codec = @import("../replay_codec.zig");

const runtime_bootstrap = @import("bootstrap.zig");
const player_runtime = @import("player.zig");
const quest_spawn_logic = @import("../quest_spawn/logic_full.zig");
const runtime_session = @import("session.zig");
const spawn_mod = @import("spawn.zig");
const weapon_data = @import("weapon_data.zig");

pub const BuildReplaySessionOptions = struct {
    strict_events: bool = true,
    inter_tick_rand_draws: i32 = 0,
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
                return error.UnsupportedQuestSpawnTable;
            }
            @memcpy(quest_spawn_entries_storage[0..entries.len], entries);
            quest_spawn_entries = quest_spawn_entries_storage[0..entries.len];
        } else {
            const level_key = runtime_bootstrap.resolveQuestLevelKey(header) orelse return error.UnsupportedQuestSpawnTable;
            const built = quest_spawn_logic.buildQuestSpawnTable(
                level_key,
                header.player_count,
                header.seed,
                header.world_size,
                quest_spawn_entries_storage[0..],
            ) catch |build_err| switch (build_err) {
                error.UnsupportedQuestSpawnTable => return error.UnsupportedQuestSpawnTable,
                error.OutOfSpace => return error.UnsupportedQuestSpawnTable,
            };
            quest_spawn_entries = quest_spawn_entries_storage[0..built.entries.len];
            if (options.quest_start_weapon_id == null) {
                quest_start_weapon_id_for_reset = @intFromEnum(built.start_weapon_id);
            }
            if (quest_spawn_entries.len == 0) {
                return error.UnsupportedQuestSpawnTable;
            }
        }

        if (header.hardcore) {
            spawn_mod.applyHardcoreQuestSpawnTableAdjustment(quest_spawn_entries);
        }
        if (mode.capture_spawn_events_authoritative) {
            quest_spawn_entries = quest_spawn_entries_storage[0..0];
        }
    }

    var session = try runtime_session.DeterministicSession.initFromReplayHeader(
        header,
        .{
            .strict_events = options.strict_events,
            .inter_tick_rand_draws = options.inter_tick_rand_draws,
            .defer_menu_open_events = mode.defer_menu_open_events,
            .apply_world_dt_steps = mode.apply_world_dt_steps,
            .capture_spawn_events_authoritative = mode.capture_spawn_events_authoritative,
            .quest_start_weapon_id_for_reset = quest_start_weapon_id_for_reset,
            .quest_spawn_entries = if (game_mode == .quests and !mode.capture_spawn_events_authoritative)
                quest_spawn_entries
            else
                null,
        },
    );
    session.rebindQuestSpawnEntries();

    if (game_mode == .quests) {
        const weapon_id = @max(1, quest_start_weapon_id_for_reset);
        for (session.players()) |*player| {
            player_runtime.weaponAssignPlayer(player, weapon_data.weaponIdFromInt(weapon_id));
        }
    }

    return session;
}
