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

const PackedEntry = struct {
    pos_x_bits: u64,
    pos_y_bits: u64,
    heading_bits: u64,
    spawn_id: i32,
    trigger_ms: i32,
    count: i32,
};

const StaticPreset = struct {
    level_key: i32,
    player_count: i32,
    start_weapon_id: i32,
    offset: u32,
    len: u32,
};

const static_preset_count = staticPresetCount();
const static_entry_count = staticEntryCount();

const StaticDatabase = struct {
    presets: [static_preset_count]StaticPreset,
    entries: [static_entry_count]PackedEntry,
};

const static_database = buildStaticDatabase();

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

    const preset = lookupStaticPreset(level_key, player_count) orelse {
        return error.UnsupportedQuestSpawnTable;
    };
    if (preset.len > out_entries.len) return error.OutOfSpace;

    const base = @as(usize, @intCast(preset.offset));
    const len = @as(usize, @intCast(preset.len));
    var idx: usize = 0;
    while (idx < len) : (idx += 1) {
        out_entries[idx] = unpackEntry(static_database.entries[base + idx]);
    }

    return .{
        .entries = out_entries[0..len],
        .start_weapon_id = preset.start_weapon_id,
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

fn staticPresetCount() comptime_int {
    var count: usize = 0;
    for (quest_spawn_tables.presets) |preset| {
        if (isDynamicSeedLevel(preset.level_key)) continue;
        count += 1;
    }
    return count;
}

fn staticEntryCount() comptime_int {
    var count: usize = 0;
    for (quest_spawn_tables.presets) |preset| {
        if (isDynamicSeedLevel(preset.level_key)) continue;
        count += preset.entries.len;
    }
    return count;
}

fn buildStaticDatabase() StaticDatabase {
    @setEvalBranchQuota(2_000_000);
    var db: StaticDatabase = undefined;
    var preset_idx: usize = 0;
    var entry_idx: usize = 0;

    for (quest_spawn_tables.presets) |preset| {
        if (isDynamicSeedLevel(preset.level_key)) continue;

        if (entry_idx > std.math.maxInt(u32)) {
            @compileError("static quest entry offset exceeds u32");
        }
        if (preset.entries.len > std.math.maxInt(u32)) {
            @compileError("static quest entry length exceeds u32");
        }
        db.presets[preset_idx] = .{
            .level_key = preset.level_key,
            .player_count = preset.player_count,
            .start_weapon_id = preset.start_weapon_id,
            .offset = @intCast(entry_idx),
            .len = @intCast(preset.entries.len),
        };
        preset_idx += 1;

        for (preset.entries) |entry| {
            db.entries[entry_idx] = packEntry(entry);
            entry_idx += 1;
        }
    }
    return db;
}

fn lookupStaticPreset(level_key: i32, player_count: i32) ?StaticPreset {
    for (static_database.presets) |preset| {
        if (preset.level_key == level_key and preset.player_count == player_count) {
            return preset;
        }
    }
    return null;
}

fn packEntry(entry: survival_spawn.QuestSpawnEntry) PackedEntry {
    return .{
        .pos_x_bits = @bitCast(entry.pos.x),
        .pos_y_bits = @bitCast(entry.pos.y),
        .heading_bits = @bitCast(entry.heading),
        .spawn_id = entry.spawn_id,
        .trigger_ms = entry.trigger_ms,
        .count = entry.count,
    };
}

fn unpackEntry(entry: PackedEntry) survival_spawn.QuestSpawnEntry {
    return .{
        .pos = .{
            .x = @bitCast(entry.pos_x_bits),
            .y = @bitCast(entry.pos_y_bits),
        },
        .heading = @bitCast(entry.heading_bits),
        .spawn_id = entry.spawn_id,
        .trigger_ms = entry.trigger_ms,
        .count = entry.count,
    };
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

test "option6 quest builder matches legacy builder across all quest levels" {
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
