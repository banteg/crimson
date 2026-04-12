const std = @import("std");

pub const QuestFinalTime = struct {
    base_time_ms: i32,
    life_bonus_ms: i32,
    unpicked_perk_bonus_ms: i32,
    final_time_ms: i32,
};

pub fn computeQuestFinalTime(
    base_time_ms: i32,
    player_health_values: []const f32,
    pending_perk_count: i32,
) QuestFinalTime {
    const base_ms = base_time_ms;
    var life_bonus_ms: i32 = 0;
    for (player_health_values) |health| {
        life_bonus_ms += @intFromFloat(@round(health));
    }
    const unpicked_perk_bonus_ms = @max(0, pending_perk_count) * 1000;
    const final_time_ms = @max(1, base_ms - life_bonus_ms - unpicked_perk_bonus_ms);
    return .{
        .base_time_ms = base_ms,
        .life_bonus_ms = life_bonus_ms,
        .unpicked_perk_bonus_ms = unpicked_perk_bonus_ms,
        .final_time_ms = final_time_ms,
    };
}

test "compute quest final time mirrors python formula" {
    const breakdown = computeQuestFinalTime(32_500, &.{ 83.6, 41.2 }, 2);
    try std.testing.expectEqual(@as(i32, 32_500), breakdown.base_time_ms);
    try std.testing.expectEqual(@as(i32, 125), breakdown.life_bonus_ms);
    try std.testing.expectEqual(@as(i32, 2_000), breakdown.unpicked_perk_bonus_ms);
    try std.testing.expectEqual(@as(i32, 30_375), breakdown.final_time_ms);
}

test "compute quest final time clamps to one millisecond" {
    const breakdown = computeQuestFinalTime(100, &.{ 60.0, 60.0 }, 5);
    try std.testing.expectEqual(@as(i32, 1), breakdown.final_time_ms);
}
