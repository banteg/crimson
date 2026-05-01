const std = @import("std");

pub const quest_stage_count: i32 = 5;
pub const quests_per_stage: i32 = 10;
pub const quest_count: i32 = quest_stage_count * quests_per_stage;

pub const QuestLevelError = error{
    InvalidQuestLevel,
};

pub const QuestLevel = struct {
    major: i32,
    minor: i32,

    pub fn init(major: i32, minor: i32) QuestLevelError!QuestLevel {
        if (major < 1 or major > quest_stage_count) return error.InvalidQuestLevel;
        if (minor < 1 or minor > quests_per_stage) return error.InvalidQuestLevel;
        return .{ .major = major, .minor = minor };
    }

    pub fn parse(value: []const u8) QuestLevelError!QuestLevel {
        const trimmed = std.mem.trim(u8, value, " \t\r\n");
        var parts = std.mem.splitScalar(u8, trimmed, '.');
        const major_text = parts.next() orelse return error.InvalidQuestLevel;
        const minor_text = parts.next() orelse return error.InvalidQuestLevel;
        if (parts.next() != null) return error.InvalidQuestLevel;
        if (major_text.len == 0 or minor_text.len == 0) return error.InvalidQuestLevel;

        const major = std.fmt.parseInt(i32, major_text, 10) catch return error.InvalidQuestLevel;
        const minor = std.fmt.parseInt(i32, minor_text, 10) catch return error.InvalidQuestLevel;
        return init(major, minor);
    }

    pub fn fromGlobalIndex(index: i32) QuestLevelError!QuestLevel {
        if (index < 0 or index >= quest_count) return error.InvalidQuestLevel;
        return .{
            .major = @divTrunc(index, quests_per_stage) + 1,
            .minor = @mod(index, quests_per_stage) + 1,
        };
    }

    pub fn fromLevelKey(level_key: i32) QuestLevelError!QuestLevel {
        return init(@divTrunc(level_key, 100), @mod(level_key, 100));
    }

    pub fn globalIndex(self: QuestLevel) i32 {
        return (self.major - 1) * quests_per_stage + (self.minor - 1);
    }

    pub fn levelKey(self: QuestLevel) i32 {
        return self.major * 100 + self.minor;
    }

    pub fn text(self: QuestLevel, buf: []u8) ![]const u8 {
        return std.fmt.bufPrint(buf, "{d}.{d}", .{ self.major, self.minor });
    }
};

pub fn questGlobalIndex(stage: i32, minor: i32) ?i32 {
    const level = QuestLevel.init(stage, minor) catch return null;
    return level.globalIndex();
}

pub fn questLevelKeyGlobalIndex(level_key: i32) ?i32 {
    const level = QuestLevel.fromLevelKey(level_key) catch return null;
    return level.globalIndex();
}

test "quest level parses text and exposes python-compatible properties" {
    var buf: [8]u8 = undefined;
    const level = try QuestLevel.parse(" 5.10\n");
    try std.testing.expectEqual(@as(i32, 5), level.major);
    try std.testing.expectEqual(@as(i32, 10), level.minor);
    try std.testing.expectEqual(@as(i32, 49), level.globalIndex());
    try std.testing.expectEqual(@as(i32, 510), level.levelKey());
    try std.testing.expectEqualStrings("5.10", try level.text(&buf));
}

test "quest level rejects invalid text" {
    try std.testing.expectError(error.InvalidQuestLevel, QuestLevel.parse(""));
    try std.testing.expectError(error.InvalidQuestLevel, QuestLevel.parse("1"));
    try std.testing.expectError(error.InvalidQuestLevel, QuestLevel.parse("1.2.3"));
    try std.testing.expectError(error.InvalidQuestLevel, QuestLevel.parse("0.1"));
    try std.testing.expectError(error.InvalidQuestLevel, QuestLevel.parse("1.11"));
    try std.testing.expectError(error.InvalidQuestLevel, QuestLevel.parse("1.x"));
}

test "quest level converts from global index" {
    const first = try QuestLevel.fromGlobalIndex(0);
    try std.testing.expectEqual(@as(i32, 1), first.major);
    try std.testing.expectEqual(@as(i32, 1), first.minor);
    const last = try QuestLevel.fromGlobalIndex(49);
    try std.testing.expectEqual(@as(i32, 5), last.major);
    try std.testing.expectEqual(@as(i32, 10), last.minor);
    try std.testing.expectError(error.InvalidQuestLevel, QuestLevel.fromGlobalIndex(-1));
    try std.testing.expectError(error.InvalidQuestLevel, QuestLevel.fromGlobalIndex(50));
}

test "quest level key conversion mirrors existing runtime keys" {
    const first = try QuestLevel.fromLevelKey(101);
    try std.testing.expectEqual(@as(i32, 1), first.major);
    try std.testing.expectEqual(@as(i32, 1), first.minor);
    const fourth_stage_last = try QuestLevel.fromLevelKey(410);
    try std.testing.expectEqual(@as(i32, 4), fourth_stage_last.major);
    try std.testing.expectEqual(@as(i32, 10), fourth_stage_last.minor);
    try std.testing.expectError(error.InvalidQuestLevel, QuestLevel.fromLevelKey(511));
    try std.testing.expectEqual(@as(?i32, 0), questLevelKeyGlobalIndex(101));
    try std.testing.expectEqual(@as(?i32, 49), questLevelKeyGlobalIndex(510));
    try std.testing.expectEqual(@as(?i32, null), questLevelKeyGlobalIndex(611));
}
