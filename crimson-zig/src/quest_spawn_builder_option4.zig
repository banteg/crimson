const std = @import("std");

const quest_spawn_builder = @import("quest_spawn_builder.zig");
const quest_spawn_tables = @import("quest_spawn_tables.zig");
const survival_spawn = @import("survival_spawn.zig");

pub const QuestSpawnBuildError = quest_spawn_builder.QuestSpawnBuildError;
pub const QuestSpawnBuildResult = quest_spawn_builder.QuestSpawnBuildResult;

const dynamic_level_target_practice: i32 = 103;
const dynamic_level_random_factor: i32 = 106;
const dynamic_level_sweep_stakes: i32 = 205;
const dynamic_level_the_killing: i32 = 303;
const dynamic_level_deja_vu: i32 = 309;

const quest_level_count: usize = 50;

const LevelPatternKind = enum {
    shared,
    per_player,
};

const LevelPattern = struct {
    level_key: i32,
    start_weapon_id: i32,
    kind: LevelPatternKind,
    shared_entries: []const survival_spawn.QuestSpawnEntry = &.{},
    entries_by_player: [4][]const survival_spawn.QuestSpawnEntry = .{ &.{}, &.{}, &.{}, &.{} },
};

const level_patterns = buildLevelPatterns();

pub fn buildQuestSpawnTable(
    level_key: i32,
    player_count: i32,
    seed: u32,
    world_size: f64,
    out_entries: []survival_spawn.QuestSpawnEntry,
) QuestSpawnBuildError!QuestSpawnBuildResult {
    if (player_count < 1 or player_count > 4) return error.UnsupportedQuestSpawnTable;

    if (isDynamicSeedLevel(level_key)) {
        return quest_spawn_builder.buildQuestSpawnTable(
            level_key,
            player_count,
            seed,
            world_size,
            out_entries,
        );
    }

    const pattern = lookupLevelPattern(level_key) orelse {
        return error.UnsupportedQuestSpawnTable;
    };

    const entries = switch (pattern.kind) {
        .shared => pattern.shared_entries,
        .per_player => pattern.entries_by_player[@as(usize, @intCast(player_count - 1))],
    };
    if (entries.len > out_entries.len) return error.OutOfSpace;
    @memcpy(out_entries[0..entries.len], entries);

    return .{
        .entries = out_entries[0..entries.len],
        .start_weapon_id = pattern.start_weapon_id,
    };
}

fn isDynamicSeedLevel(level_key: i32) bool {
    return switch (level_key) {
        dynamic_level_target_practice,
        dynamic_level_random_factor,
        dynamic_level_sweep_stakes,
        dynamic_level_the_killing,
        dynamic_level_deja_vu,
        => true,
        else => false,
    };
}

fn lookupLevelPattern(level_key: i32) ?*const LevelPattern {
    for (&level_patterns) |*pattern| {
        if (pattern.level_key == level_key) return pattern;
    }
    return null;
}

fn buildLevelPatterns() [quest_level_count]LevelPattern {
    @setEvalBranchQuota(2_000_000);
    var patterns: [quest_level_count]LevelPattern = undefined;
    var idx: usize = 0;

    var major: i32 = 1;
    while (major <= 5) : (major += 1) {
        var minor: i32 = 1;
        while (minor <= 10) : (minor += 1) {
            const level_key = major * 100 + minor;
            const p1 = requirePreset(level_key, 1);
            const p2 = requirePreset(level_key, 2);
            const p3 = requirePreset(level_key, 3);
            const p4 = requirePreset(level_key, 4);

            if (p1.start_weapon_id != p2.start_weapon_id or
                p1.start_weapon_id != p3.start_weapon_id or
                p1.start_weapon_id != p4.start_weapon_id)
            {
                @compileError(std.fmt.comptimePrint(
                    "start_weapon_id diverged across players for level_key={d}",
                    .{level_key},
                ));
            }

            const all_equal = questEntriesEqual(p1.entries, p2.entries) and
                questEntriesEqual(p1.entries, p3.entries) and
                questEntriesEqual(p1.entries, p4.entries);
            patterns[idx] = if (all_equal)
                .{
                    .level_key = level_key,
                    .start_weapon_id = p1.start_weapon_id,
                    .kind = .shared,
                    .shared_entries = p1.entries,
                }
            else
                .{
                    .level_key = level_key,
                    .start_weapon_id = p1.start_weapon_id,
                    .kind = .per_player,
                    .entries_by_player = .{ p1.entries, p2.entries, p3.entries, p4.entries },
                };
            idx += 1;
        }
    }
    return patterns;
}

fn requirePreset(level_key: i32, player_count: i32) quest_spawn_tables.QuestPreset {
    return quest_spawn_tables.lookupPreset(level_key, player_count) orelse
        @compileError(std.fmt.comptimePrint(
            "missing quest preset level_key={d} player_count={d}",
            .{ level_key, player_count },
        ));
}

fn questEntriesEqual(
    left: []const survival_spawn.QuestSpawnEntry,
    right: []const survival_spawn.QuestSpawnEntry,
) bool {
    if (left.len != right.len) return false;
    for (left, right) |a, b| {
        if (@as(u64, @bitCast(a.pos.x)) != @as(u64, @bitCast(b.pos.x))) return false;
        if (@as(u64, @bitCast(a.pos.y)) != @as(u64, @bitCast(b.pos.y))) return false;
        if (@as(u64, @bitCast(a.heading)) != @as(u64, @bitCast(b.heading))) return false;
        if (a.spawn_id != b.spawn_id) return false;
        if (a.trigger_ms != b.trigger_ms) return false;
        if (a.count != b.count) return false;
    }
    return true;
}

fn expectEntryApproxEqual(
    expected: survival_spawn.QuestSpawnEntry,
    actual: survival_spawn.QuestSpawnEntry,
) !void {
    try std.testing.expectApproxEqAbs(expected.pos.x, actual.pos.x, 1e-6);
    try std.testing.expectApproxEqAbs(expected.pos.y, actual.pos.y, 1e-6);
    try std.testing.expectApproxEqAbs(expected.heading, actual.heading, 1e-6);
    try std.testing.expectEqual(expected.spawn_id, actual.spawn_id);
    try std.testing.expectEqual(expected.trigger_ms, actual.trigger_ms);
    try std.testing.expectEqual(expected.count, actual.count);
}

fn expectResultApproxEqual(
    expected: QuestSpawnBuildResult,
    actual: QuestSpawnBuildResult,
) !void {
    try std.testing.expectEqual(expected.start_weapon_id, actual.start_weapon_id);
    try std.testing.expectEqual(expected.entries.len, actual.entries.len);
    for (expected.entries, actual.entries) |left, right| {
        try expectEntryApproxEqual(left, right);
    }
}

test "option4 quest builder matches legacy builder across all quest levels" {
    var storage_a = [_]survival_spawn.QuestSpawnEntry{undefined} ** 4096;
    var storage_b = [_]survival_spawn.QuestSpawnEntry{undefined} ** 4096;

    const dynamic_seeds = [_]u32{ 0, 1, 205, 999 };
    const static_seed: u32 = 205;

    var major: i32 = 1;
    while (major <= 5) : (major += 1) {
        var minor: i32 = 1;
        while (minor <= 10) : (minor += 1) {
            const level_key = major * 100 + minor;
            var player_count: i32 = 1;
            while (player_count <= 4) : (player_count += 1) {
                if (isDynamicSeedLevel(level_key)) {
                    for (dynamic_seeds) |seed| {
                        const expected = try quest_spawn_builder.buildQuestSpawnTable(
                            level_key,
                            player_count,
                            seed,
                            1024.0,
                            storage_a[0..],
                        );
                        const actual = try buildQuestSpawnTable(
                            level_key,
                            player_count,
                            seed,
                            1024.0,
                            storage_b[0..],
                        );
                        try expectResultApproxEqual(expected, actual);
                    }
                } else {
                    const expected = try quest_spawn_builder.buildQuestSpawnTable(
                        level_key,
                        player_count,
                        static_seed,
                        1024.0,
                        storage_a[0..],
                    );
                    const actual = try buildQuestSpawnTable(
                        level_key,
                        player_count,
                        static_seed,
                        1024.0,
                        storage_b[0..],
                    );
                    try expectResultApproxEqual(expected, actual);
                }
            }
        }
    }
}
