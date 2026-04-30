const std = @import("std");
const game_ids = @import("game_ids.zig");

pub const demo_total_play_time_ms: i32 = 2_400_000;
pub const demo_quest_grace_time_ms: i32 = 300_000;

pub const OverlayKind = enum {
    none,
    quest_tier_limit,
    quest_grace_left,
    time_up,
};

pub const OverlayInfo = struct {
    visible: bool = false,
    kind: OverlayKind = .none,
    remaining_ms: i32 = 0,
    show_remaining_line: bool = false,
};

pub const TimerTickResult = struct {
    global_playtime_ms: u32,
    quest_grace_elapsed_ms: i32,
};

pub fn formatDemoTrialTime(ms: i32, buf: []u8) []const u8 {
    var value = ms;
    if (value < 0) value = 0;
    const minutes = @divTrunc(value, 60_000);
    const seconds = @mod(@divTrunc(value, 1_000), 60);
    const centiseconds = @divTrunc(@mod(value, 1_000), 10);
    return std.fmt.bufPrint(buf, "{d}:{d:0>2}.{d:0>2}", .{ minutes, seconds, centiseconds }) catch "0:00.00";
}

pub fn tickDemoTrialTimers(
    demo_build: bool,
    game_mode_id: game_ids.GameModeId,
    overlay_visible: bool,
    global_playtime_ms: u32,
    quest_grace_elapsed_ms: i32,
    dt_ms: i32,
) TimerTickResult {
    if (!demo_build) {
        return .{
            .global_playtime_ms = global_playtime_ms,
            .quest_grace_elapsed_ms = quest_grace_elapsed_ms,
        };
    }

    if (game_mode_id == .tutorial) {
        return .{
            .global_playtime_ms = global_playtime_ms,
            .quest_grace_elapsed_ms = quest_grace_elapsed_ms,
        };
    }

    var used_ms = clampedDemoPlaytimeMs(global_playtime_ms);
    var grace_ms: i32 = quest_grace_elapsed_ms;
    if (grace_ms < 0) grace_ms = 0;
    if (used_ms >= demo_total_play_time_ms and grace_ms < 1) grace_ms = 1;

    const delta_ms = @max(dt_ms, 0);
    if (overlay_visible or delta_ms <= 0) {
        return .{
            .global_playtime_ms = @intCast(used_ms),
            .quest_grace_elapsed_ms = grace_ms,
        };
    }

    used_ms = @min(addClampedI32(used_ms, delta_ms), demo_total_play_time_ms);
    if (used_ms >= demo_total_play_time_ms and grace_ms < 1) grace_ms = 1;
    if (grace_ms > 0 and game_mode_id == .quests) {
        grace_ms = addClampedI32(grace_ms, delta_ms);
    }

    return .{
        .global_playtime_ms = @intCast(used_ms),
        .quest_grace_elapsed_ms = grace_ms,
    };
}

pub fn demoTrialOverlayInfo(
    demo_build: bool,
    game_mode_id: game_ids.GameModeId,
    global_playtime_ms: u32,
    quest_grace_elapsed_ms: i32,
    quest_level_key: ?i32,
) OverlayInfo {
    if (!demo_build or game_mode_id == .tutorial) return .{};

    const used_ms = clampedDemoPlaytimeMs(global_playtime_ms);
    const grace_ms = @max(quest_grace_elapsed_ms, 0);
    const global_remaining_ms = @max(@as(i32, 0), demo_total_play_time_ms - used_ms);
    const grace_remaining_ms = @max(@as(i32, 0), demo_quest_grace_time_ms - grace_ms);

    const tier_locked = blk: {
        if (game_mode_id != .quests) break :blk false;
        const level_key = quest_level_key orelse break :blk false;
        const major = @divTrunc(level_key, 100);
        const minor = @mod(level_key, 100);
        break :blk major > 1 or minor > 10;
    };

    if (grace_ms > 0) {
        if (grace_remaining_ms <= 0) {
            return .{
                .visible = true,
                .kind = .time_up,
            };
        }
        if (tier_locked) {
            return .{
                .visible = true,
                .kind = .quest_tier_limit,
                .remaining_ms = grace_remaining_ms,
            };
        }
        if (game_mode_id != .quests) {
            return .{
                .visible = true,
                .kind = .quest_grace_left,
                .remaining_ms = grace_remaining_ms,
            };
        }
        return .{
            .visible = false,
            .kind = .none,
            .remaining_ms = grace_remaining_ms,
        };
    }

    if (global_remaining_ms <= 0) {
        return .{
            .visible = true,
            .kind = .time_up,
        };
    }

    if (tier_locked) {
        return .{
            .visible = true,
            .kind = .quest_tier_limit,
            .remaining_ms = global_remaining_ms,
            .show_remaining_line = true,
        };
    }

    return .{
        .visible = false,
        .kind = .none,
        .remaining_ms = global_remaining_ms,
    };
}

fn clampedDemoPlaytimeMs(global_playtime_ms: u32) i32 {
    return @intCast(@min(global_playtime_ms, demo_total_play_time_ms));
}

fn addClampedI32(left: i32, right: i32) i32 {
    const result = @as(i64, left) + @as(i64, right);
    if (result > std.math.maxInt(i32)) return std.math.maxInt(i32);
    if (result < std.math.minInt(i32)) return std.math.minInt(i32);
    return @intCast(result);
}

test "demo trial timers stop while overlay visible" {
    const result = tickDemoTrialTimers(true, .survival, true, 1000, 0, 500);
    try std.testing.expectEqual(@as(u32, 1000), result.global_playtime_ms);
    try std.testing.expectEqual(@as(i32, 0), result.quest_grace_elapsed_ms);
}

test "demo trial overlay blocks quest grace left on non-quest modes" {
    const info = demoTrialOverlayInfo(true, .survival, demo_total_play_time_ms, 1, null);
    try std.testing.expect(info.visible);
    try std.testing.expectEqual(OverlayKind.quest_grace_left, info.kind);
}

test "demo trial overlay blocks later quest tiers in demo" {
    const info = demoTrialOverlayInfo(true, .quests, 1000, 0, 201);
    try std.testing.expect(info.visible);
    try std.testing.expectEqual(OverlayKind.quest_tier_limit, info.kind);
    try std.testing.expect(info.show_remaining_line);
}

test "demo trial timers saturate oversized frame deltas" {
    const result = tickDemoTrialTimers(true, .quests, false, std.math.maxInt(u32), std.math.maxInt(i32) - 1, std.math.maxInt(i32));
    try std.testing.expectEqual(@as(u32, @intCast(demo_total_play_time_ms)), result.global_playtime_ms);
    try std.testing.expectEqual(@as(i32, std.math.maxInt(i32)), result.quest_grace_elapsed_ms);
}

test "demo trial timers clamp oversized saved playtime" {
    const result = tickDemoTrialTimers(true, .survival, false, std.math.maxInt(u32), 0, 500);
    try std.testing.expectEqual(@as(u32, @intCast(demo_total_play_time_ms)), result.global_playtime_ms);
    try std.testing.expectEqual(@as(i32, 1), result.quest_grace_elapsed_ms);
}

test "demo trial overlay clamps oversized saved playtime" {
    const info = demoTrialOverlayInfo(true, .survival, std.math.maxInt(u32), 0, null);
    try std.testing.expect(info.visible);
    try std.testing.expectEqual(OverlayKind.time_up, info.kind);
}
