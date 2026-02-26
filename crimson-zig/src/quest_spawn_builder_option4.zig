const std = @import("std");

const quest_spawn_option4_data = @import("quest_spawn_option4_data.zig");
const quest_spawn_builder = @import("quest_spawn_builder.zig");
const survival_spawn = @import("survival_spawn.zig");

pub const QuestSpawnBuildError = quest_spawn_builder.QuestSpawnBuildError;
pub const QuestSpawnBuildResult = quest_spawn_builder.QuestSpawnBuildResult;

const dynamic_level_target_practice: i32 = 103;
const dynamic_level_random_factor: i32 = 106;
const dynamic_level_sweep_stakes: i32 = 205;
const dynamic_level_the_killing: i32 = 303;
const dynamic_level_deja_vu: i32 = 309;

const level_patterns = quest_spawn_option4_data.level_patterns;

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

fn lookupLevelPattern(level_key: i32) ?*const quest_spawn_option4_data.LevelPattern {
    for (&level_patterns) |*pattern| {
        if (pattern.level_key == level_key) return pattern;
    }
    return null;
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
