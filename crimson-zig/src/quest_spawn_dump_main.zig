const std = @import("std");
const crimson_zig = @import("crimson_zig");

const quest_spawn_builder = crimson_zig.quest_spawn_builder;
const quest_spawn_builder_option4 = crimson_zig.quest_spawn_builder_option4;
const quest_spawn_builder_option6 = crimson_zig.quest_spawn_builder_option6;
const survival_spawn = crimson_zig.survival_spawn;

const usage =
    \\Usage:
    \\  crimson-zig-quest-spawn-dump <impl> <level_key> <player_count> <seed> [world_size]
    \\
    \\Args:
    \\  impl: legacy | option4 | option6
    \\  level_key: quest level key (for example 101 for quest 1.1)
    \\  player_count: 1..4
    \\  seed: quest spawn RNG seed (u32)
    \\  world_size: optional map width/height (default 1024)
    \\
;

pub fn main() !void {
    var gpa_state: std.heap.GeneralPurposeAllocator(.{}) = .{};
    defer _ = gpa_state.deinit();
    const allocator = gpa_state.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 5 or args.len > 6) {
        try writeStderr(usage);
        std.process.exit(1);
    }

    const impl = args[1];
    const level_key = std.fmt.parseInt(i32, args[2], 10) catch {
        try writeStderr("invalid level_key\n");
        std.process.exit(1);
    };
    const player_count = std.fmt.parseInt(i32, args[3], 10) catch {
        try writeStderr("invalid player_count\n");
        std.process.exit(1);
    };
    const seed = std.fmt.parseInt(u32, args[4], 10) catch {
        try writeStderr("invalid seed\n");
        std.process.exit(1);
    };
    const world_size: f64 = if (args.len == 6)
        std.fmt.parseFloat(f64, args[5]) catch {
            try writeStderr("invalid world_size\n");
            std.process.exit(1);
        }
    else
        1024.0;

    var storage = [_]survival_spawn.QuestSpawnEntry{undefined} ** 4096;
    const result = buildByImpl(
        impl,
        level_key,
        player_count,
        seed,
        world_size,
        storage[0..],
    ) catch |err| {
        var buffer: [128]u8 = undefined;
        const msg = std.fmt.bufPrint(
            &buffer,
            "{s}\n",
            .{@errorName(err)},
        ) catch "build failed\n";
        try writeStderr(msg);
        std.process.exit(1);
    };

    var out_buffer: [8192]u8 = undefined;
    var writer = std.fs.File.stdout().writer(&out_buffer);
    const out = &writer.interface;
    try out.print("{{\"start_weapon_id\":{d},\"entries\":[", .{result.start_weapon_id});
    for (result.entries, 0..) |entry, idx| {
        if (idx > 0) try out.writeAll(",");
        try out.print(
            "{{\"pos\":{{\"x\":{d:.12},\"y\":{d:.12}}},\"heading\":{d:.12},\"spawn_id\":{d},\"trigger_ms\":{d},\"count\":{d}}}",
            .{
                entry.pos.x,
                entry.pos.y,
                entry.heading,
                entry.spawn_id,
                entry.trigger_ms,
                entry.count,
            },
        );
    }
    try out.writeAll("]}\n");
    try out.flush();
}

fn buildByImpl(
    impl: []const u8,
    level_key: i32,
    player_count: i32,
    seed: u32,
    world_size: f64,
    out_entries: []survival_spawn.QuestSpawnEntry,
) !quest_spawn_builder.QuestSpawnBuildResult {
    if (std.mem.eql(u8, impl, "legacy")) {
        return quest_spawn_builder.buildQuestSpawnTable(
            level_key,
            player_count,
            seed,
            world_size,
            out_entries,
        );
    }
    if (std.mem.eql(u8, impl, "option4")) {
        return quest_spawn_builder_option4.buildQuestSpawnTable(
            level_key,
            player_count,
            seed,
            world_size,
            out_entries,
        );
    }
    if (std.mem.eql(u8, impl, "option6")) {
        return quest_spawn_builder_option6.buildQuestSpawnTable(
            level_key,
            player_count,
            seed,
            world_size,
            out_entries,
        );
    }
    return error.InvalidImplementation;
}

fn writeStderr(bytes: []const u8) !void {
    var buffer: [4096]u8 = undefined;
    var writer = std.fs.File.stderr().writer(&buffer);
    const err = &writer.interface;
    if (bytes.len > 0) {
        try err.writeAll(bytes);
    }
    try err.flush();
}
