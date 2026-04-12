const std = @import("std");

pub const quest_status_games_offset: i32 = 11;
pub const quest_status_completed_offset: i32 = 51;
pub const quest_status_tracked_count: i32 = 40;

pub fn questGlobalIndex(stage: i32, minor: i32) ?i32 {
    if (stage < 1 or stage > 5) return null;
    if (minor < 1 or minor > 10) return null;
    return (stage - 1) * 10 + (minor - 1);
}

pub fn questLevelKeyGlobalIndex(level_key: i32) ?i32 {
    return questGlobalIndex(@divTrunc(level_key, 100), @mod(level_key, 100));
}

pub fn questTrackedInStatusGlobalIndex(global_index: i32) bool {
    return global_index >= 0 and global_index < quest_status_tracked_count;
}

pub fn trackedQuestGamesCounterIndex(level_key: i32) ?usize {
    const global_index = questLevelKeyGlobalIndex(level_key) orelse return null;
    if (!questTrackedInStatusGlobalIndex(global_index)) return null;
    return @intCast(global_index + quest_status_games_offset);
}

pub fn trackedQuestCompletedCounterIndex(level_key: i32) ?usize {
    const global_index = questLevelKeyGlobalIndex(level_key) orelse return null;
    if (!questTrackedInStatusGlobalIndex(global_index)) return null;
    return @intCast(global_index + quest_status_completed_offset);
}

test "tracked quest counters mirror python offsets" {
    try std.testing.expectEqual(@as(?usize, 11), trackedQuestGamesCounterIndex(101));
    try std.testing.expectEqual(@as(?usize, 50), trackedQuestGamesCounterIndex(410));
    try std.testing.expectEqual(@as(?usize, 51), trackedQuestCompletedCounterIndex(101));
    try std.testing.expectEqual(@as(?usize, 90), trackedQuestCompletedCounterIndex(410));
    try std.testing.expectEqual(@as(?usize, null), trackedQuestGamesCounterIndex(501));
    try std.testing.expectEqual(@as(?usize, null), trackedQuestCompletedCounterIndex(510));
}
