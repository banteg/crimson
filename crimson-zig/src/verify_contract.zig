const std = @import("std");
const game_ids = @import("game_ids.zig");

pub const replay_schema_version: i32 = 1;
pub const reference_replay_sha256 = "1cb9ec12b25b0a5b3529689751ef1f5a5707cbd90b5657e0e74837e55a1bf790";

pub const ReferenceRunResult = struct {
    pub const game_mode_id: i32 = 1;
    pub const tick_rate: i32 = 60;
    pub const ticks: i32 = 25_803;
    pub const elapsed_ms: i64 = 398_030;
    pub const score_xp: i64 = 76_661;
    pub const creature_kill_count: i32 = 951;
    pub const most_used_weapon_id: i32 = 14;
    pub const shots_fired: i32 = 4_566;
    pub const shots_hit: i32 = 1_467;
    pub const rng_state: u64 = 2_889_720_653;
};

pub const ScoreMetric = enum {
    auto,
    score_xp,
    elapsed_ms,
};

pub fn scoreMetricFromString(raw: []const u8) ?ScoreMetric {
    if (std.mem.eql(u8, raw, "auto")) return .auto;
    if (std.mem.eql(u8, raw, "score_xp")) return .score_xp;
    if (std.mem.eql(u8, raw, "elapsed_ms")) return .elapsed_ms;
    return null;
}

pub fn resolveScoreMetric(metric: ScoreMetric, game_mode_id: i32) []const u8 {
    return switch (metric) {
        .score_xp => "score_xp",
        .elapsed_ms => "elapsed_ms",
        .auto => switch (std.meta.intToEnum(game_ids.GameModeId, game_mode_id) catch return "score_xp") {
            .rush, .quests => "elapsed_ms",
            else => "score_xp",
        },
    };
}

test "resolve metric for survival stays score_xp" {
    try std.testing.expectEqualStrings(
        "score_xp",
        resolveScoreMetric(.auto, ReferenceRunResult.game_mode_id),
    );
}

test "resolve metric for rush auto selects elapsed_ms" {
    try std.testing.expectEqualStrings(
        "elapsed_ms",
        resolveScoreMetric(.auto, @intFromEnum(game_ids.GameModeId.rush)),
    );
}

test "resolve metric for quests auto selects elapsed_ms" {
    try std.testing.expectEqualStrings(
        "elapsed_ms",
        resolveScoreMetric(.auto, @intFromEnum(game_ids.GameModeId.quests)),
    );
}

test "resolve metric for unknown mode defaults auto to score_xp" {
    try std.testing.expectEqualStrings(
        "score_xp",
        resolveScoreMetric(.auto, 999),
    );
}

test "score metric parser accepts explicit values and rejects unknowns" {
    try std.testing.expectEqual(ScoreMetric.auto, scoreMetricFromString("auto").?);
    try std.testing.expectEqual(ScoreMetric.score_xp, scoreMetricFromString("score_xp").?);
    try std.testing.expectEqual(ScoreMetric.elapsed_ms, scoreMetricFromString("elapsed_ms").?);
    try std.testing.expect(scoreMetricFromString("bad_metric") == null);
}
