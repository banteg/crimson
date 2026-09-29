const std = @import("std");
const game_ids = @import("../game_ids.zig");

const highscores = @import("highscores.zig");
const state_mod = @import("../runtime/state.zig");
const survival_progression = @import("../runtime/survival_progression.zig");

pub const BuildRecordOptions = struct {
    hardcore: bool = false,
};

pub fn buildHighscoreRecordForGameOver(
    state: state_mod.GameplayState,
    player: state_mod.PlayerState,
    survival_elapsed_ms: i32,
    creature_kill_count: i32,
    game_mode_id: game_ids.GameModeId,
    options: BuildRecordOptions,
) highscores.HighScoreRecord {
    const player_index: usize = if (player.index < 0) 0 else @intCast(player.index);

    var record_rng = state.rng;
    var record = highscores.HighScoreRecord.blankWithRandValue(record_rng.rand());
    record.setScoreXp(@intCast(@max(0, state.highscore_score_xp)));
    record.setSurvivalElapsedMs(if (game_mode_id == .quests) survival_elapsed_ms else @max(0, survival_elapsed_ms));
    record.setCreatureKillCount(@intCast(@max(0, creature_kill_count)));
    record.setMostUsedWeaponId(
        survival_progression.mostUsedWeaponIdForPlayer(
            state,
            player_index,
            player.weapon.weapon_id,
        ),
    );
    record.setGameModeId(game_mode_id);

    const shots = survival_progression.runShotCounts(state);
    record.setShotsFired(@intCast(shots.fired));
    record.setShotsHit(@intCast(shots.hit));
    record.setHardcoreMarker(if (options.hardcore) 0x75 else 0);
    return record;
}

fn expectRunShots(state: state_mod.GameplayState, fired: i32, hit: i32) !void {
    const shots = survival_progression.runShotCounts(state);
    try std.testing.expectEqual(fired, shots.fired);
    try std.testing.expectEqual(hit, shots.hit);
}

test "run shot counts clamp hits to nonnegative shots fired" {
    var state = state_mod.GameplayState.init(0);
    state.shots_fired = -5;
    state.shots_hit = 10;
    try expectRunShots(state, 0, 0);
    state.shots_fired = 5;
    state.shots_hit = -1;
    try expectRunShots(state, 5, 0);
    state.shots_hit = 10;
    try expectRunShots(state, 5, 5);
}

test "build highscore record uses weapon stats and shots" {
    var state = state_mod.GameplayState.init(0);
    var player: state_mod.PlayerState = .{
        .index = 0,
        .pos = .{},
    };
    player.experience = 9999;
    player.weapon.weapon_id = .pistol;

    state.highscore_score_xp = 1234;
    state.weapon_usage_time[2] = 10;
    state.shots_fired = 20;
    state.shots_hit = 15;

    const record = buildHighscoreRecordForGameOver(
        state,
        player,
        5000,
        7,
        .survival,
        .{},
    );

    try std.testing.expectEqual(@as(u32, 1234), record.scoreXp());
    try std.testing.expectEqual(@as(i32, 5000), record.survivalElapsedMs());
    try std.testing.expectEqual(@as(u32, 7), record.creatureKillCount());
    try std.testing.expectEqual(game_ids.WeaponId.assault_rifle, record.mostUsedWeaponId());
    try std.testing.expectEqual(@as(u32, 20), record.shotsFired());
    try std.testing.expectEqual(@as(u32, 15), record.shotsHit());
    try std.testing.expectEqual(@as(?game_ids.GameModeId, .survival), record.gameModeId());
    try std.testing.expectEqual(@as(u8, 0), record.hardcoreMarker());
    try std.testing.expectEqual(@as(u32, 6), record.uniNum());
}

test "typo highscore records keep typed and matched words unclamped" {
    var state = state_mod.GameplayState.init(0);
    state.game_mode = .typo;
    state.typo.typing.submit_count = 3;
    state.typo.typing.match_count = 5;
    const player: state_mod.PlayerState = .{
        .index = 0,
        .pos = .{},
    };

    const record = buildHighscoreRecordForGameOver(
        state,
        player,
        0,
        0,
        .typo,
        .{},
    );

    try std.testing.expectEqual(@as(u32, 3), record.shotsFired());
    try std.testing.expectEqual(@as(u32, 5), record.shotsHit());
}

test "build highscore record marks hardcore" {
    const state = state_mod.GameplayState.init(0);
    const player: state_mod.PlayerState = .{
        .index = 0,
        .pos = .{},
    };

    const record = buildHighscoreRecordForGameOver(
        state,
        player,
        0,
        0,
        .quests,
        .{ .hardcore = true },
    );

    try std.testing.expectEqual(@as(u8, 0x75), record.hardcoreMarker());
}

test "completed quest records preserve negative final times" {
    const record = buildHighscoreRecordForGameOver(
        state_mod.GameplayState.init(0),
        .{ .index = 0, .pos = .{} },
        -500,
        1,
        .quests,
        .{},
    );
    try std.testing.expectEqual(@as(i32, -500), record.survivalElapsedMs());
}
