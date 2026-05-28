const std = @import("std");
const game_ids = @import("../game_ids.zig");

const highscores = @import("highscores.zig");
const state_mod = @import("../runtime/state.zig");
const survival_progression = @import("../runtime/survival_progression.zig");

pub const ShotCounts = struct {
    fired: i32,
    hit: i32,
};

pub const BuildRecordOptions = struct {
    shots_fired: ?i32 = null,
    shots_hit: ?i32 = null,
    clamp_shots_hit: bool = true,
    hardcore: bool = false,
};

pub fn clampShots(fired: i32, hit: i32) ShotCounts {
    const safe_fired = @max(0, fired);
    const safe_hit = std.math.clamp(hit, @as(i32, 0), safe_fired);
    return .{
        .fired = safe_fired,
        .hit = safe_hit,
    };
}

pub fn shotsFromState(state: state_mod.GameplayState, player_index: usize) ShotCounts {
    if (player_index >= state.shots_fired.len or player_index >= state.shots_hit.len) {
        return .{ .fired = 0, .hit = 0 };
    }
    return clampShots(state.shots_fired[player_index], state.shots_hit[player_index]);
}

pub fn buildHighscoreRecordForGameOver(
    state: state_mod.GameplayState,
    player: state_mod.PlayerState,
    survival_elapsed_ms: i32,
    creature_kill_count: i32,
    game_mode_id: game_ids.GameModeId,
    options: BuildRecordOptions,
) highscores.HighScoreRecord {
    const player_index: usize = if (player.index < 0) 0 else @intCast(player.index);

    var record = highscores.HighScoreRecord.blank();
    record.setScoreXp(@intCast(@max(0, player.experience)));
    record.setSurvivalElapsedMs(@intCast(@max(0, survival_elapsed_ms)));
    record.setCreatureKillCount(@intCast(@max(0, creature_kill_count)));
    record.setMostUsedWeaponId(
        survival_progression.mostUsedWeaponIdForPlayer(
            state,
            player_index,
            player.weapon.weapon_id,
        ),
    );
    record.setGameModeId(game_mode_id);

    const shot_counts: ShotCounts = blk: {
        if (options.shots_fired == null or options.shots_hit == null) {
            break :blk shotsFromState(state, player_index);
        }

        if (options.clamp_shots_hit) {
            break :blk clampShots(options.shots_fired.?, options.shots_hit.?);
        }

        break :blk ShotCounts{
            .fired = options.shots_fired.?,
            .hit = options.shots_hit.?,
        };
    };
    record.setShotsFired(@intCast(@max(0, shot_counts.fired)));
    record.setShotsHit(@intCast(@max(0, shot_counts.hit)));
    record.setHardcoreMarker(if (options.hardcore) 0x75 else 0);
    return record;
}

test "clamp shots clamps hit and nonnegative" {
    const a = clampShots(-5, 10);
    try std.testing.expectEqual(@as(i32, 0), a.fired);
    try std.testing.expectEqual(@as(i32, 0), a.hit);

    const b = clampShots(5, -1);
    try std.testing.expectEqual(@as(i32, 5), b.fired);
    try std.testing.expectEqual(@as(i32, 0), b.hit);

    const c = clampShots(5, 10);
    try std.testing.expectEqual(@as(i32, 5), c.fired);
    try std.testing.expectEqual(@as(i32, 5), c.hit);
}

test "shots from state handles out of bounds player" {
    const state = state_mod.GameplayState.init(0);
    const counts = shotsFromState(state, 99);
    try std.testing.expectEqual(@as(i32, 0), counts.fired);
    try std.testing.expectEqual(@as(i32, 0), counts.hit);
}

test "build highscore record uses weapon stats and shots" {
    var state = state_mod.GameplayState.init(0);
    var player: state_mod.PlayerState = .{
        .index = 0,
        .pos = .{},
    };
    player.experience = 1234;
    player.weapon.weapon_id = .pistol;

    state.weapon_shots_fired[0][2] = 10;
    state.shots_fired[0] = 20;
    state.shots_hit[0] = 15;

    const record = buildHighscoreRecordForGameOver(
        state,
        player,
        5000,
        7,
        .survival,
        .{},
    );

    try std.testing.expectEqual(@as(u32, 1234), record.scoreXp());
    try std.testing.expectEqual(@as(u32, 5000), record.survivalElapsedMs());
    try std.testing.expectEqual(@as(u32, 7), record.creatureKillCount());
    try std.testing.expectEqual(game_ids.WeaponId.assault_rifle, record.mostUsedWeaponId());
    try std.testing.expectEqual(@as(u32, 20), record.shotsFired());
    try std.testing.expectEqual(@as(u32, 15), record.shotsHit());
    try std.testing.expectEqual(@as(?game_ids.GameModeId, .survival), record.gameModeId());
    try std.testing.expectEqual(@as(u8, 0), record.hardcoreMarker());
}

test "build highscore record can skip clamp" {
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
        .typo,
        .{
            .shots_fired = 3,
            .shots_hit = 5,
            .clamp_shots_hit = false,
        },
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
