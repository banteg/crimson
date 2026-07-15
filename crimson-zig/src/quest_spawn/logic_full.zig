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
    world_size: f32,
    out_entries: []spawn_runtime.QuestSpawnEntry,
) QuestSpawnBuildError!QuestSpawnBuildResult {
    return buildQuestSpawnTableWithHardcore(
        level_key,
        player_count,
        seed,
        world_size,
        false,
        out_entries,
    );
}

pub fn buildQuestSpawnTableWithHardcore(
    level_key: i32,
    player_count: i32,
    seed: u32,
    world_size: f32,
    hardcore: bool,
    out_entries: []spawn_runtime.QuestSpawnEntry,
) QuestSpawnBuildError!QuestSpawnBuildResult {
    if (player_count < 1 or player_count > 4) return error.InvalidQuestSpawnTable;
    const descriptor = lookupLevelBuilder(level_key) orelse return error.InvalidQuestSpawnTable;

    const ctx: BuildContext = .{
        .width = world_size,
        .height = world_size,
        .player_count = player_count,
        .hardcore = hardcore,
    };
    var rng = common.QuestRng.init(seed);
    var len: usize = 0;
    try descriptor.build(ctx, &rng, out_entries, &len);

    return .{
        .entries = out_entries[0..len],
        .start_weapon_id = descriptor.start_weapon_id,
    };
}

test "builder-specific hardcore quest branches use context flag" {
    const Case = struct {
        level_key: i32,
        normal_count: usize,
        hardcore_count: usize,
    };
    const cases = [_]Case{
        .{ .level_key = 210, .normal_count = 3, .hardcore_count = 6 },
        .{ .level_key = 407, .normal_count = 68, .hardcore_count = 92 },
        .{ .level_key = 408, .normal_count = 40, .hardcore_count = 56 },
    };

    for (cases) |case| {
        const descriptor = lookupLevelBuilder(case.level_key) orelse unreachable;
        var out_entries = [_]spawn_runtime.QuestSpawnEntry{undefined} ** 128;
        var rng = common.QuestRng.init(0);
        var len: usize = 0;
        try descriptor.build(
            .{
                .width = 1024.0,
                .height = 1024.0,
                .player_count = 1,
            },
            &rng,
            out_entries[0..],
            &len,
        );
        try std.testing.expectEqual(case.normal_count, len);

        rng = common.QuestRng.init(0);
        len = 0;
        try descriptor.build(
            .{
                .width = 1024.0,
                .height = 1024.0,
                .player_count = 1,
                .hardcore = true,
            },
            &rng,
            out_entries[0..],
            &len,
        );
        try std.testing.expectEqual(case.hardcore_count, len);
    }
}

pub fn lookupLevelBuilder(level_key: i32) ?LevelBuilder {
    for (level_builders) |descriptor| {
        if (descriptor.level_key == level_key) return descriptor;
    }
    return null;
}

fn expectQuestEntryEqual(expected: spawn_runtime.QuestSpawnEntry, actual: spawn_runtime.QuestSpawnEntry) !void {
    try std.testing.expectApproxEqAbs(expected.pos.x, actual.pos.x, 1e-6);
    try std.testing.expectApproxEqAbs(expected.pos.y, actual.pos.y, 1e-6);
    try std.testing.expectApproxEqAbs(expected.heading, actual.heading, 1e-6);
    try std.testing.expectEqual(expected.spawn_id, actual.spawn_id);
    try std.testing.expectEqual(expected.trigger_ms, actual.trigger_ms);
    try std.testing.expectEqual(expected.count, actual.count);
}

test "everred bonus bottom y stays at native constant" {
    var out_entries = [_]spawn_runtime.QuestSpawnEntry{undefined} ** 64;
    const built = try buildQuestSpawnTable(201, 1, 0, 2048.0, out_entries[0..]);

    try std.testing.expectEqual(@as(usize, 34), built.entries.len);
    try std.testing.expectApproxEqAbs(@as(f32, 1024.0), built.entries[16].pos.x, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, -64.0), built.entries[16].pos.y, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 1024.0), built.entries[17].pos.x, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 1088.0), built.entries[17].pos.y, 1e-6);
}

test "level 1-10 rectangular spawn summary stays stable" {
    const descriptor = lookupLevelBuilder(110) orelse unreachable;
    var rng = common.QuestRng.init(0x1A2B3C4D);
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
    var expected: [57]spawn_runtime.QuestSpawnEntry = undefined;
    var expected_len: usize = 0;
    expected[expected_len] = .{
        .pos = .{ .x = 1344.0, .y = 450.0 },
        .heading = 0.0,
        .spawn_id = @enumFromInt(58),
        .trigger_ms = 1000,
        .count = 1,
    };
    expected_len += 1;

    var trigger: i32 = 6000;
    while (trigger <= 34_600) : (trigger += 2200) {
        const edge_spawns = [_]spawn_runtime.QuestSpawnEntry{
            .{
                .pos = .{ .x = -25.0, .y = -25.0 },
                .heading = 0.0,
                .spawn_id = @enumFromInt(61),
                .trigger_ms = trigger,
                .count = 3,
            },
            .{
                .pos = .{ .x = 1625.0, .y = -25.0 },
                .heading = 0.0,
                .spawn_id = @enumFromInt(61),
                .trigger_ms = trigger,
                .count = 1,
            },
            .{
                .pos = .{ .x = -25.0, .y = 925.0 },
                .heading = 0.0,
                .spawn_id = @enumFromInt(61),
                .trigger_ms = trigger,
                .count = 3,
            },
            .{
                .pos = .{ .x = 1625.0, .y = 925.0 },
                .heading = 0.0,
                .spawn_id = @enumFromInt(61),
                .trigger_ms = trigger,
                .count = 1,
            },
        };
        @memcpy(expected[expected_len .. expected_len + edge_spawns.len], &edge_spawns);
        expected_len += edge_spawns.len;
    }

    try std.testing.expectEqual(expected_len, entries.len);
    for (expected[0..expected_len], entries) |want, got| {
        try expectQuestEntryEqual(want, got);
    }
}

test "level 5-1 rectangular spawn summary stays stable" {
    const descriptor = lookupLevelBuilder(501) orelse unreachable;
    var rng = common.QuestRng.init(0x55667788);
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
    var expected: [31]spawn_runtime.QuestSpawnEntry = undefined;
    var expected_len: usize = 0;
    expected[expected_len] = .{
        .pos = .{ .x = 256.0, .y = 256.0 },
        .heading = 0.0,
        .spawn_id = @enumFromInt(39),
        .trigger_ms = 500,
        .count = 1,
    };
    expected_len += 1;
    expected[expected_len] = .{
        .pos = .{ .x = 1632.0, .y = 450.0 },
        .heading = 0.0,
        .spawn_id = @enumFromInt(41),
        .trigger_ms = 8000,
        .count = 3,
    };
    expected_len += 1;

    for (0..8) |i| {
        expected[expected_len] = .{
            .pos = .{ .x = @as(f32, @floatFromInt(@as(i32, @intCast(i)) * 32 + 1664)), .y = 450.0 },
            .heading = 0.0,
            .spawn_id = @enumFromInt(37),
            .trigger_ms = @as(i32, @intCast(i * 100)) + 10_000,
            .count = 8,
        };
        expected_len += 1;
    }

    expected[expected_len] = .{
        .pos = .{ .x = -32.0, .y = 450.0 },
        .heading = 0.0,
        .spawn_id = @enumFromInt(41),
        .trigger_ms = 18_000,
        .count = 3,
    };
    expected_len += 1;

    for (0..8) |i| {
        expected[expected_len] = .{
            .pos = .{ .x = -@as(f32, @floatFromInt(@as(i32, @intCast(i)) * 32 + 64)), .y = 450.0 },
            .heading = 0.0,
            .spawn_id = @enumFromInt(37),
            .trigger_ms = @as(i32, @intCast(i * 100)) + 20_000,
            .count = 8,
        };
        expected_len += 1;
    }

    for (0..6) |i| {
        expected[expected_len] = .{
            .pos = .{ .x = 800.0, .y = -(@as(f32, @floatFromInt(@as(i32, @intCast(i)) * 42 + 64))) },
            .heading = 0.0,
            .spawn_id = @enumFromInt(15),
            .trigger_ms = @as(i32, @intCast(i * 100)) + 40_000,
            .count = 4,
        };
        expected_len += 1;
    }
    for (0..6) |i| {
        expected[expected_len] = .{
            .pos = .{ .x = 800.0, .y = @as(f32, @floatFromInt(@as(i32, @intCast(i)) * 32 + 944)) },
            .heading = 0.0,
            .spawn_id = @enumFromInt(18),
            .trigger_ms = @as(i32, @intCast(i * 100)) + 40_000,
            .count = 2,
        };
        expected_len += 1;
    }

    try std.testing.expectEqual(expected_len, entries.len);
    for (expected[0..expected_len], entries) |want, got| {
        try expectQuestEntryEqual(want, got);
    }
}

test "append radial spawns rejects non-positive radius step" {
    var out_entries = [_]spawn_runtime.QuestSpawnEntry{undefined} ** 8;
    var len: usize = 0;

    try std.testing.expectError(
        error.InvalidQuestSpawnTable,
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
        error.InvalidQuestSpawnTable,
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
