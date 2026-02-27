const std = @import("std");
const common = @import("logic_common.zig");
const tier1 = @import("logic_tier1.zig");
const tier2 = @import("logic_tier2.zig");
const tier3 = @import("logic_tier3.zig");
const tier4 = @import("logic_tier4.zig");
const tier5 = @import("logic_tier5.zig");
const spawn_runtime = @import("../runtime/spawn.zig");

pub const QuestSpawnBuildError = common.QuestSpawnBuildError;
pub const QuestSpawnBuildResult = common.QuestSpawnBuildResult;
pub const LevelBuilder = common.LevelBuilder;
pub const BuildContext = common.BuildContext;

pub const level_builders = tier1.tier1_builders ++
    tier2.tier2_builders ++
    tier3.tier3_builders ++
    tier4.tier4_builders ++
    tier5.tier5_builders;

pub fn buildQuestSpawnTable(
    level_key: i32,
    player_count: i32,
    seed: u32,
    world_size: f64,
    out_entries: []spawn_runtime.QuestSpawnEntry,
) QuestSpawnBuildError!QuestSpawnBuildResult {
    if (player_count < 1 or player_count > 4) return error.UnsupportedQuestSpawnTable;
    const descriptor = lookupLevelBuilder(level_key) orelse return error.UnsupportedQuestSpawnTable;

    const ctx = BuildContext{
        .width = world_size,
        .height = world_size,
        .player_count = player_count,
    };
    var rng = common.PythonRandom.init(seed);
    var len: usize = 0;
    try descriptor.build(ctx, &rng, out_entries, &len);

    return .{
        .entries = out_entries[0..len],
        .start_weapon_id = descriptor.start_weapon_id,
    };
}

pub fn lookupLevelBuilder(level_key: i32) ?LevelBuilder {
    for (level_builders) |descriptor| {
        if (descriptor.level_key == level_key) return descriptor;
    }
    return null;
}

fn summaryHashMix(seed: u64, value: u64) u64 {
    return (seed ^ value) *% 1099511628211;
}

fn summarizeQuestEntries(entries: []const spawn_runtime.QuestSpawnEntry) u64 {
    var hash: u64 = 1469598103934665603;
    for (entries, 0..) |entry, idx| {
        hash = summaryHashMix(hash, @as(u64, @intCast(idx)));
        hash = summaryHashMix(hash, @as(u64, @intCast(@intFromEnum(entry.spawn_id))));
        hash = summaryHashMix(hash, @as(u64, @bitCast(entry.pos.x)));
        hash = summaryHashMix(hash, @as(u64, @bitCast(entry.pos.y)));
        hash = summaryHashMix(hash, @as(u64, @as(u32, @bitCast(entry.heading))));
        hash = summaryHashMix(hash, @as(u64, @bitCast(@as(i64, entry.trigger_ms))));
        hash = summaryHashMix(hash, @as(u64, @bitCast(@as(i64, entry.count))));
    }
    return hash;
}

test "level 1-10 rectangular spawn summary stays stable" {
    const descriptor = lookupLevelBuilder(110) orelse unreachable;
    var rng = common.PythonRandom.init(0x1A2B3C4D);
    var out_entries = [_]spawn_runtime.QuestSpawnEntry{undefined} ** 128;
    var len: usize = 0;

    try descriptor.build(
        .{
            .width = 1600.0,
            .height = 900.0,
            .player_count = 3,
        },
        &rng,
        out_entries[0..],
        &len,
    );

    const entries = out_entries[0..len];
    try std.testing.expectEqual(@as(usize, 57), entries.len);
    try std.testing.expectEqual(@as(f64, 450.0), entries[0].pos.y);
    try std.testing.expectEqual(@as(u64, 1409422335643109472), summarizeQuestEntries(entries));
}

test "level 5-1 rectangular spawn summary stays stable" {
    const descriptor = lookupLevelBuilder(501) orelse unreachable;
    var rng = common.PythonRandom.init(0x55667788);
    var out_entries = [_]spawn_runtime.QuestSpawnEntry{undefined} ** 128;
    var len: usize = 0;

    try descriptor.build(
        .{
            .width = 1600.0,
            .height = 900.0,
            .player_count = 2,
        },
        &rng,
        out_entries[0..],
        &len,
    );

    const entries = out_entries[0..len];
    try std.testing.expectEqual(@as(usize, 31), entries.len);
    try std.testing.expectEqual(@as(f64, 944.0), entries[25].pos.y);
    try std.testing.expectEqual(@as(f64, 1104.0), entries[30].pos.y);
    try std.testing.expectEqual(@as(u64, 5508488500531934324), summarizeQuestEntries(entries));
}

test "append radial spawns rejects non-positive radius step" {
    var out_entries = [_]spawn_runtime.QuestSpawnEntry{undefined} ** 8;
    var len: usize = 0;

    try std.testing.expectError(
        error.UnsupportedQuestSpawnTable,
        common.appendRadialSpawns(
            out_entries[0..],
            &len,
            .{ .x = 512.0, .y = 384.0 },
            1.0,
            84.0,
            252.0,
            0.0,
            .zero,
            common.SpawnId.alien_const_pale_green_26,
            2000,
            1,
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), len);
}

test "append radial spawns rejects inverted radius range" {
    var out_entries = [_]spawn_runtime.QuestSpawnEntry{undefined} ** 8;
    var len: usize = 0;

    try std.testing.expectError(
        error.UnsupportedQuestSpawnTable,
        common.appendRadialSpawns(
            out_entries[0..],
            &len,
            .{ .x = 512.0, .y = 384.0 },
            1.0,
            252.0,
            84.0,
            42.0,
            .from_center,
            common.SpawnId.alien_const_pale_green_26,
            2000,
            1,
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), len);
}
