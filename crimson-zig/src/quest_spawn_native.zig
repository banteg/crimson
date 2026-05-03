const std = @import("std");

const bootstrap = @import("runtime/bootstrap.zig");
const creatures_runtime = @import("runtime/creatures.zig");
const quest_spawn_common = @import("quest_spawn/logic_common.zig");
const quest_spawn_logic_full = @import("quest_spawn/logic_full.zig");
const spawn_runtime = @import("runtime/spawn.zig");
const verify_native = @import("verify_native.zig");

pub const CommandOutput = verify_native.CommandOutput;

const quest_dump_schema_version: i32 = 1;
const max_quest_spawn_entries: usize = 4096;
const spawn_plan_summary_cache_len: usize = @as(usize, @intCast(@intFromEnum(spawn_runtime.SpawnId.zombie_const_green_brute_43))) + 1;
const SpawnPlanSummaryCache = [spawn_plan_summary_cache_len]?SpawnPlanSummary;

const OutputFormat = enum {
    human,
    json,
};

const QuestDumpRequest = struct {
    level_arg: []const u8,
    output_format: OutputFormat = .human,
    width: f32 = 1024.0,
    height: f32 = 1024.0,
    player_count: i32 = 1,
    seed: u32 = 0,
    sort: bool = false,
    show_plan: bool = false,
};

const ParseOutcome = union(enum) {
    ok: QuestDumpRequest,
    invalid: []const u8,
};

const QuestLevel = struct {
    key: i32,
    label: [4]u8,
    label_len: usize,

    fn labelSlice(self: *const QuestLevel) []const u8 {
        return self.label[0..self.label_len];
    }
};

const QuestSpawnEntryPayload = struct {
    pos: struct {
        x: f32,
        y: f32,
    },
    heading: f32,
    spawn_id: i32,
    trigger_ms: i32,
    count: i32,
};

const QuestDumpPayload = struct {
    schema_version: i32,
    status: []const u8,
    level: []const u8,
    level_key: i32,
    width: f32,
    height: f32,
    player_count: i32,
    seed: u32,
    start_weapon_id: i32,
    entry_count: usize,
    entries: []const QuestSpawnEntryPayload,
};

const SpawnPlanSummary = struct {
    creature_count: usize,
    spawn_slot_count: usize,
};

pub fn runQuests(
    allocator: std.mem.Allocator,
    args: []const []const u8,
) !CommandOutput {
    switch (parseNativeSubset(args)) {
        .ok => |request| return runQuestDump(allocator, request),
        .invalid => |detail| return buildInvalidQuestArgsOutput(allocator, detail),
    }
}

fn runQuestDump(
    allocator: std.mem.Allocator,
    request: QuestDumpRequest,
) !CommandOutput {
    const level = parseQuestLevelArg(request.level_arg) orelse
        return buildInvalidQuestArgsOutput(allocator, "invalid quest level");

    const descriptor = quest_spawn_logic_full.lookupLevelBuilder(level.key) orelse
        return buildInvalidQuestArgsOutput(allocator, "unknown quest level");

    if (request.player_count < 1 or request.player_count > 4) {
        return buildInvalidQuestArgsOutput(allocator, "player_count must be 1..4");
    }
    if (!std.math.isFinite(request.width) or request.width <= 0.0 or !std.math.isFinite(request.height) or request.height <= 0.0) {
        return buildInvalidQuestArgsOutput(allocator, "width and height must be positive finite values");
    }
    if (request.show_plan and request.output_format == .json) {
        return buildInvalidQuestArgsOutput(allocator, "--show-plan requires human format");
    }

    var entries_storage = [_]spawn_runtime.QuestSpawnEntry{undefined} ** max_quest_spawn_entries;
    var entry_len: usize = 0;
    var rng = quest_spawn_common.QuestRng.init(request.seed);
    try descriptor.build(
        .{
            .width = request.width,
            .height = request.height,
            .player_count = request.player_count,
        },
        &rng,
        entries_storage[0..],
        &entry_len,
    );

    const entries = entries_storage[0..entry_len];
    if (request.sort) {
        std.mem.sort(spawn_runtime.QuestSpawnEntry, entries, {}, questEntryLessThan);
    }

    const stdout = switch (request.output_format) {
        .human => buildHumanQuestOutput(allocator, level, @intFromEnum(descriptor.start_weapon_id), entries, request.show_plan) catch |err| switch (err) {
            error.InvalidSpawnTemplate => return buildInvalidQuestArgsOutput(allocator, "invalid spawn template id in quest plan"),
            else => return err,
        },
        .json => try buildJsonQuestOutput(allocator, request, level, @intFromEnum(descriptor.start_weapon_id), entries),
    };
    errdefer allocator.free(stdout);

    return .{
        .stdout = stdout,
        .stderr = try allocator.dupe(u8, ""),
        .exit_code = 0,
    };
}

fn buildHumanQuestOutput(
    allocator: std.mem.Allocator,
    level: QuestLevel,
    start_weapon_id: i32,
    entries: []const spawn_runtime.QuestSpawnEntry,
    show_plan: bool,
) ![]u8 {
    var stdout_buf: std.Io.Writer.Allocating = .init(allocator);
    defer stdout_buf.deinit();
    const writer = &stdout_buf.writer;

    try writer.print(
        "Quest {s} ({d} entries)\n",
        .{ level.labelSlice(), entries.len },
    );
    try writer.print("Meta: start_weapon_id={d}\n", .{start_weapon_id});
    var plan_summaries: SpawnPlanSummaryCache = [_]?SpawnPlanSummary{null} ** spawn_plan_summary_cache_len;
    if (show_plan) {
        const summary = try summarizeQuestPlan(entries, &plan_summaries);
        try writer.print(
            "Plan: total_alloc={d} total_spawn_slots={d}\n",
            .{ summary.creature_count, summary.spawn_slot_count },
        );
    }
    for (entries, 0..) |entry, idx| {
        const spawn_summary_index = @as(usize, @intCast(@intFromEnum(entry.spawn_id)));
        const plan_summary = if (show_plan and spawn_summary_index < plan_summaries.len) plan_summaries[spawn_summary_index] else null;
        try writer.print(
            "{d:0>2}  t={d}  id=0x{x:0>2} ({d})  count={d}  x={d: >7.1}  y={d: >7.1}  heading={d: >7.3}",
            .{
                idx + 1,
                entry.trigger_ms,
                @as(u32, @intCast(@intFromEnum(entry.spawn_id))),
                @intFromEnum(entry.spawn_id),
                entry.count,
                entry.pos.x,
                entry.pos.y,
                entry.heading,
            },
        );
        if (plan_summary) |summary| {
            try writer.print(
                "  alloc={d: >3} (x{d: >2})  slots={d}",
                .{
                    @as(usize, @intCast(@max(entry.count, 0))) * summary.creature_count,
                    summary.creature_count,
                    summary.spawn_slot_count,
                },
            );
        }
        try writer.writeByte('\n');
    }
    return stdout_buf.toOwnedSlice();
}

fn buildJsonQuestOutput(
    allocator: std.mem.Allocator,
    request: QuestDumpRequest,
    level: QuestLevel,
    start_weapon_id: i32,
    entries: []const spawn_runtime.QuestSpawnEntry,
) ![]u8 {
    const payload_entries = try allocator.alloc(QuestSpawnEntryPayload, entries.len);
    defer allocator.free(payload_entries);

    for (entries, payload_entries) |entry, *payload_entry| {
        payload_entry.* = .{
            .pos = .{
                .x = entry.pos.x,
                .y = entry.pos.y,
            },
            .heading = entry.heading,
            .spawn_id = @intFromEnum(entry.spawn_id),
            .trigger_ms = entry.trigger_ms,
            .count = entry.count,
        };
    }

    const payload: QuestDumpPayload = .{
        .schema_version = quest_dump_schema_version,
        .status = "ok",
        .level = level.labelSlice(),
        .level_key = level.key,
        .width = request.width,
        .height = request.height,
        .player_count = request.player_count,
        .seed = request.seed,
        .start_weapon_id = start_weapon_id,
        .entry_count = entries.len,
        .entries = payload_entries,
    };

    var payload_writer: std.Io.Writer.Allocating = .init(allocator);
    defer payload_writer.deinit();
    try std.json.Stringify.value(payload, .{}, &payload_writer.writer);
    try payload_writer.writer.writeByte('\n');
    return payload_writer.toOwnedSlice();
}

fn parseNativeSubset(args: []const []const u8) ParseOutcome {
    var level_arg: ?[]const u8 = null;
    var request: QuestDumpRequest = .{
        .level_arg = "",
    };

    var idx: usize = 0;
    while (idx < args.len) : (idx += 1) {
        const arg = args[idx];

        if (std.mem.eql(u8, arg, "--format")) {
            if (idx + 1 >= args.len) return .{ .invalid = "missing value for --format" };
            idx += 1;
            request.output_format = parseOutputFormat(args[idx]) orelse return .{ .invalid = "invalid --format value" };
            continue;
        }
        if (std.mem.startsWith(u8, arg, "--format=")) {
            request.output_format = parseOutputFormat(arg["--format=".len..]) orelse return .{ .invalid = "invalid --format value" };
            continue;
        }
        if (std.mem.eql(u8, arg, "--width")) {
            if (idx + 1 >= args.len) return .{ .invalid = "missing value for --width" };
            idx += 1;
            request.width = parsePositiveFloat(args[idx]) orelse return .{ .invalid = "invalid --width value" };
            continue;
        }
        if (std.mem.startsWith(u8, arg, "--width=")) {
            request.width = parsePositiveFloat(arg["--width=".len..]) orelse return .{ .invalid = "invalid --width value" };
            continue;
        }
        if (std.mem.eql(u8, arg, "--height")) {
            if (idx + 1 >= args.len) return .{ .invalid = "missing value for --height" };
            idx += 1;
            request.height = parsePositiveFloat(args[idx]) orelse return .{ .invalid = "invalid --height value" };
            continue;
        }
        if (std.mem.startsWith(u8, arg, "--height=")) {
            request.height = parsePositiveFloat(arg["--height=".len..]) orelse return .{ .invalid = "invalid --height value" };
            continue;
        }
        if (std.mem.eql(u8, arg, "--player-count")) {
            if (idx + 1 >= args.len) return .{ .invalid = "missing value for --player-count" };
            idx += 1;
            request.player_count = parsePlayerCount(args[idx]) orelse return .{ .invalid = "invalid --player-count value" };
            continue;
        }
        if (std.mem.startsWith(u8, arg, "--player-count=")) {
            request.player_count = parsePlayerCount(arg["--player-count=".len..]) orelse return .{ .invalid = "invalid --player-count value" };
            continue;
        }
        if (std.mem.eql(u8, arg, "--seed")) {
            if (idx + 1 >= args.len) return .{ .invalid = "missing value for --seed" };
            idx += 1;
            request.seed = parseSeed(args[idx]) orelse return .{ .invalid = "invalid --seed value" };
            continue;
        }
        if (std.mem.startsWith(u8, arg, "--seed=")) {
            request.seed = parseSeed(arg["--seed=".len..]) orelse return .{ .invalid = "invalid --seed value" };
            continue;
        }
        if (std.mem.eql(u8, arg, "--sort")) {
            request.sort = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--show-plan")) {
            request.show_plan = true;
            continue;
        }
        if (std.mem.startsWith(u8, arg, "-")) {
            return .{ .invalid = arg };
        }
        if (level_arg == null) {
            level_arg = arg;
            continue;
        }
        return .{ .invalid = "too many positional arguments" };
    }

    const level = level_arg orelse return .{ .invalid = "missing quest level argument" };
    request.level_arg = level;
    return .{ .ok = request };
}

fn parseOutputFormat(raw: []const u8) ?OutputFormat {
    if (std.mem.eql(u8, raw, "human")) return .human;
    if (std.mem.eql(u8, raw, "json")) return .json;
    return null;
}

fn parseQuestLevelArg(raw: []const u8) ?QuestLevel {
    if (bootstrap.parseQuestLevel(raw)) |parsed| {
        if (parsed.major < 1 or parsed.major > 5 or parsed.minor < 1 or parsed.minor > 10) return null;
        return buildQuestLevel(parsed.major, parsed.minor);
    }

    const key = std.fmt.parseInt(i32, raw, 10) catch return null;
    const major = @divTrunc(key, 100);
    const minor = @mod(key, 100);
    if (major < 1 or major > 5 or minor < 1 or minor > 10) return null;
    return buildQuestLevel(major, minor);
}

fn buildQuestLevel(major: i32, minor: i32) QuestLevel {
    var label: [4]u8 = undefined;
    const written = std.fmt.bufPrint(&label, "{d}.{d}", .{ major, minor }) catch unreachable;
    return .{
        .key = major * 100 + minor,
        .label = label,
        .label_len = written.len,
    };
}

fn parsePositiveFloat(raw: []const u8) ?f32 {
    const value = std.fmt.parseFloat(f32, raw) catch return null;
    if (!std.math.isFinite(value) or value <= 0.0) return null;
    return value;
}

fn parsePlayerCount(raw: []const u8) ?i32 {
    const value = std.fmt.parseInt(i32, raw, 10) catch return null;
    if (value < 1 or value > 4) return null;
    return value;
}

fn parseSeed(raw: []const u8) ?u32 {
    const value = std.fmt.parseInt(u64, raw, 0) catch return null;
    if (value > std.math.maxInt(u32)) return null;
    return @intCast(value);
}

fn questEntryLessThan(
    _: void,
    lhs: spawn_runtime.QuestSpawnEntry,
    rhs: spawn_runtime.QuestSpawnEntry,
) bool {
    if (lhs.trigger_ms != rhs.trigger_ms) return lhs.trigger_ms < rhs.trigger_ms;
    if (@intFromEnum(lhs.spawn_id) != @intFromEnum(rhs.spawn_id)) return @intFromEnum(lhs.spawn_id) < @intFromEnum(rhs.spawn_id);
    if (lhs.pos.x != rhs.pos.x) return lhs.pos.x < rhs.pos.x;
    if (lhs.pos.y != rhs.pos.y) return lhs.pos.y < rhs.pos.y;
    return lhs.count < rhs.count;
}

fn summarizeQuestPlan(
    entries: []const spawn_runtime.QuestSpawnEntry,
    cached_summaries: *SpawnPlanSummaryCache,
) !SpawnPlanSummary {
    var total_creatures: usize = 0;
    var total_spawn_slots: usize = 0;
    for (entries) |entry| {
        const summary = try cachedSpawnTemplateSummary(cached_summaries, entry.spawn_id);
        const count: usize = @intCast(@max(entry.count, 0));
        total_creatures += count * summary.creature_count;
        total_spawn_slots += count * summary.spawn_slot_count;
    }
    return .{
        .creature_count = total_creatures,
        .spawn_slot_count = total_spawn_slots,
    };
}

fn cachedSpawnTemplateSummary(
    cached_summaries: *SpawnPlanSummaryCache,
    spawn_id: spawn_runtime.SpawnId,
) !SpawnPlanSummary {
    const index = @as(usize, @intCast(@intFromEnum(spawn_id)));
    if (index >= cached_summaries.len) return error.InvalidSpawnTemplate;
    if (cached_summaries[index]) |summary| return summary;
    const summary = try summarizeSpawnTemplate(@intFromEnum(spawn_id));
    cached_summaries[index] = summary;
    return summary;
}

fn summarizeSpawnTemplate(template_id: i32) !SpawnPlanSummary {
    var pool: creatures_runtime.CreaturePool = .{};
    var rng = spawn_runtime.Crand.init(0);
    try pool.spawnTemplateCall(
        .{
            .template_id = template_id,
            .pos = .{ .x = 512.0, .y = 512.0 },
            .heading = 0.0,
        },
        &rng,
    );
    return .{
        .creature_count = pool.activeCount(),
        .spawn_slot_count = pool.spawn_slot_count,
    };
}

fn buildInvalidQuestArgsOutput(
    allocator: std.mem.Allocator,
    detail: []const u8,
) !CommandOutput {
    const stdout = try allocator.dupe(u8, "");
    errdefer allocator.free(stdout);
    const stderr = try std.fmt.allocPrint(allocator, "invalid quests args: {s}\n", .{detail});
    return .{
        .stdout = stdout,
        .stderr = stderr,
        .exit_code = 1,
    };
}

test "quest level parser accepts dotted and numeric forms" {
    const dotted = parseQuestLevelArg("2.5") orelse return error.TestExpectedQuestLevel;
    try std.testing.expectEqual(@as(i32, 205), dotted.key);
    try std.testing.expectEqualStrings("2.5", dotted.labelSlice());

    const numeric = parseQuestLevelArg("510") orelse return error.TestExpectedQuestLevel;
    try std.testing.expectEqual(@as(i32, 510), numeric.key);
    try std.testing.expectEqualStrings("5.10", numeric.labelSlice());
}

test "quest level parser rejects out of range levels" {
    try std.testing.expect(parseQuestLevelArg("0.1") == null);
    try std.testing.expect(parseQuestLevelArg("5.11") == null);
    try std.testing.expect(parseQuestLevelArg("999") == null);
}

test "quests parser accepts json dump options" {
    const parsed = parseNativeSubset(&.{ "1.6", "--format", "json", "--width", "1600", "--height=900", "--player-count", "3", "--seed=0x1234", "--sort", "--show-plan" });
    switch (parsed) {
        .ok => |request| {
            try std.testing.expectEqualStrings("1.6", request.level_arg);
            try std.testing.expectEqual(OutputFormat.json, request.output_format);
            try std.testing.expectEqual(@as(f32, 1600.0), request.width);
            try std.testing.expectEqual(@as(f32, 900.0), request.height);
            try std.testing.expectEqual(@as(i32, 3), request.player_count);
            try std.testing.expectEqual(@as(u32, 0x1234), request.seed);
            try std.testing.expect(request.sort);
            try std.testing.expect(request.show_plan);
        },
        else => return error.TestExpectedValidArgs,
    }
}

test "quest plan summary counts template allocations" {
    var entries = [_]spawn_runtime.QuestSpawnEntry{
        .{
            .pos = .{ .x = 512.0, .y = 512.0 },
            .heading = 0.0,
            .spawn_id = .formation_ring_alien_8_12,
            .trigger_ms = 0,
            .count = 2,
        },
        .{
            .pos = .{ .x = 512.0, .y = 512.0 },
            .heading = 0.0,
            .spawn_id = .alien_spawner_child_1d_fast_07,
            .trigger_ms = 100,
            .count = 3,
        },
    };

    var cache: SpawnPlanSummaryCache = [_]?SpawnPlanSummary{null} ** spawn_plan_summary_cache_len;
    const summary = try summarizeQuestPlan(entries[0..], &cache);
    try std.testing.expectEqual(@as(usize, 21), summary.creature_count);
    try std.testing.expectEqual(@as(usize, 3), summary.spawn_slot_count);
}

test "quests show plan prints per-entry allocation details" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var entries = [_]spawn_runtime.QuestSpawnEntry{
        .{
            .pos = .{ .x = 512.0, .y = 512.0 },
            .heading = 0.0,
            .spawn_id = .formation_ring_alien_8_12,
            .trigger_ms = 0,
            .count = 2,
        },
    };

    const summary = try summarizeSpawnTemplate(@intFromEnum(entries[0].spawn_id));
    const expected = try std.fmt.allocPrint(
        arena.allocator(),
        "alloc={d: >3} (x{d: >2})  slots={d}",
        .{
            @as(usize, @intCast(entries[0].count)) * summary.creature_count,
            summary.creature_count,
            summary.spawn_slot_count,
        },
    );
    const output = try buildHumanQuestOutput(arena.allocator(), .{ .key = 201, .label = .{ '2', '.', '1', 0 }, .label_len = 3 }, 0, entries[0..], true);
    try std.testing.expect(std.mem.indexOf(u8, output, expected) != null);
}

test "quests invalid quest plan detail avoids unsupported wording" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const output = try buildInvalidQuestArgsOutput(arena.allocator(), "invalid spawn template id in quest plan");
    try std.testing.expectEqualStrings("invalid quests args: invalid spawn template id in quest plan\n", output.stderr);
    try std.testing.expect(std.mem.indexOf(u8, output.stderr, "unsupported") == null);
}
