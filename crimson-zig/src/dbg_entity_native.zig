const std = @import("std");

const cdt_trace = @import("cdt_trace.zig");
const dbg_record_native = @import("dbg_record_native.zig");
const replay_codec = @import("replay_codec.zig");
const verify_native = @import("verify_native.zig");

pub const CommandOutput = verify_native.CommandOutput;

const Request = struct {
    trace_path: []const u8,
    entity_uid: i32,
    tick_start: ?i32 = null,
    tick_end: ?i32 = null,
    json: bool = false,
    json_out: ?[]const u8 = null,
};

const ParseOutcome = union(enum) {
    ok: Request,
    help,
    invalid: []const u8,
};

const EntityJsonPayload = struct {
    schema_version: i32 = 1,
    trace: []const u8,
    entity_uid: i32,
    pool_kind: []const u8,
    spawn_tick: i32,
    despawn_tick: i32,
    samples: []const cdt_trace.EntitySampleSummary,
};

const usage =
    \\Usage:
    \\  crimson-zig dbg entity <trace.cdt> <entity_uid> [entity options]
    \\
    \\Options:
    \\  --ticks <range>    Tick range: START..END, START.., ..END, or TICK.
    \\  --json             Print JSON payload to stdout.
    \\  --json-out <path>  Also write the JSON report to a file.
    \\  -h, --help         Show this help.
    \\
;

pub fn runDbgEntity(
    allocator: std.mem.Allocator,
    args: []const []const u8,
) !CommandOutput {
    switch (parseArgs(args)) {
        .ok => |request| {
            var summary = cdt_trace.summarizeTraceEntityFile(
                allocator,
                std.Io.Threaded.global_single_threaded.io(),
                request.trace_path,
                request.entity_uid,
                .{
                    .tick_start = request.tick_start,
                    .tick_end = request.tick_end,
                },
            ) catch |err| return buildEntityFailedOutput(allocator, traceEntityErrorDetail(err));
            defer summary.deinit(allocator);
            return buildEntityOutput(allocator, request, summary);
        },
        .help => return buildUsageOutput(allocator, 0, ""),
        .invalid => |detail| return buildUsageOutput(allocator, 2, detail),
    }
}

fn buildEntityOutput(
    allocator: std.mem.Allocator,
    request: Request,
    summary: cdt_trace.EntityHistorySummary,
) !CommandOutput {
    const json_payload = try buildEntityJson(allocator, request.trace_path, summary);
    errdefer allocator.free(json_payload);

    if (request.json_out) |json_out_path| {
        writeFileWithParents(json_out_path, json_payload) catch |err| {
            allocator.free(json_payload);
            return buildEntityFailedOutput(allocator, traceEntityErrorDetail(err));
        };
    }

    const stdout = if (request.json) json_payload else stdout: {
        const human = try buildEntityHuman(allocator, summary, request.json_out);
        allocator.free(json_payload);
        break :stdout human;
    };
    errdefer allocator.free(stdout);

    return .{
        .stdout = stdout,
        .stderr = try allocator.dupe(u8, ""),
        .exit_code = 0,
    };
}

fn buildEntityJson(
    allocator: std.mem.Allocator,
    trace_path: []const u8,
    summary: cdt_trace.EntityHistorySummary,
) ![]u8 {
    const payload: EntityJsonPayload = .{
        .trace = trace_path,
        .entity_uid = summary.entity_uid,
        .pool_kind = summary.pool_kind,
        .spawn_tick = summary.spawn_tick,
        .despawn_tick = summary.despawn_tick,
        .samples = summary.samples,
    };

    var writer: std.Io.Writer.Allocating = .init(allocator);
    errdefer writer.deinit();
    try std.json.Stringify.value(payload, .{}, &writer.writer);
    try writer.writer.writeByte('\n');
    return writer.toOwnedSlice();
}

fn buildEntityHuman(
    allocator: std.mem.Allocator,
    summary: cdt_trace.EntityHistorySummary,
    json_out: ?[]const u8,
) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(allocator);
    errdefer out.deinit();
    const writer = &out.writer;

    try writer.print(
        "uid={d} pool_kind={s} spawn_tick={d} despawn_tick={d} samples={d}\n",
        .{
            summary.entity_uid,
            summary.pool_kind,
            summary.spawn_tick,
            summary.despawn_tick,
            summary.samples.len,
        },
    );
    for (summary.samples[0..@min(summary.samples.len, 32)]) |sample| {
        try writer.print(
            "sample tick={d} index={d} type_id=",
            .{ sample.tick_index, sample.index },
        );
        try writeOptionalI32(writer, sample.type_id);
        try writer.writeAll(" hp=");
        try writeOptionalF32(writer, sample.hp);
        try writer.print(" pos=({d},{d})\n", .{ sample.pos.x, sample.pos.y });
    }
    if (json_out) |path| {
        try writer.print("json_report={s}\n", .{path});
    }
    return out.toOwnedSlice();
}

fn writeOptionalI32(writer: *std.Io.Writer, value: ?i32) !void {
    if (value) |int_value| {
        try writer.print("{d}", .{int_value});
    } else {
        try writer.writeAll("null");
    }
}

fn writeOptionalF32(writer: *std.Io.Writer, value: ?f32) !void {
    if (value) |float_value| {
        try writer.print("{d}", .{float_value});
    } else {
        try writer.writeAll("null");
    }
}

fn parseArgs(args: []const []const u8) ParseOutcome {
    var trace_path: ?[]const u8 = null;
    var entity_uid: ?i32 = null;
    var request: Request = .{
        .trace_path = "",
        .entity_uid = 0,
    };

    var idx: usize = 0;
    while (idx < args.len) : (idx += 1) {
        const arg = args[idx];
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) return .help;
        if (std.mem.eql(u8, arg, "--json")) {
            request.json = true;
            continue;
        }
        if (takeValue(args, &idx, arg, "--json-out")) |value| {
            if (value.len == 0) return .{ .invalid = "missing value for --json-out" };
            request.json_out = value;
            continue;
        }
        if (takeValue(args, &idx, arg, "--ticks")) |value| {
            const range = parseTickRange(value) orelse return .{ .invalid = "invalid --ticks value" };
            request.tick_start = range.start;
            request.tick_end = range.end;
            continue;
        }
        if (trace_path == null) {
            if (std.mem.startsWith(u8, arg, "-")) return .{ .invalid = arg };
            trace_path = arg;
            continue;
        }
        if (entity_uid == null) {
            entity_uid = parseNonNegativeI32(arg) orelse return .{ .invalid = "invalid entity uid value" };
            continue;
        }
        if (std.mem.startsWith(u8, arg, "-")) return .{ .invalid = arg };
        return .{ .invalid = "too many positional arguments" };
    }

    request.trace_path = trace_path orelse return .{ .invalid = "missing trace file argument" };
    request.entity_uid = entity_uid orelse return .{ .invalid = "missing entity uid argument" };
    if (request.tick_start != null and request.tick_end != null and request.tick_start.? > request.tick_end.?) {
        return .{ .invalid = "tick range start must be <= end" };
    }
    return .{ .ok = request };
}

fn takeValue(args: []const []const u8, idx: *usize, arg: []const u8, name: []const u8) ?[]const u8 {
    if (std.mem.eql(u8, arg, name)) {
        if (idx.* + 1 >= args.len) return "";
        idx.* += 1;
        return args[idx.*];
    }
    if (arg.len > name.len and arg[name.len] == '=' and std.mem.startsWith(u8, arg, name)) {
        return arg[name.len + 1 ..];
    }
    return null;
}

const TickRangeArg = struct {
    start: ?i32 = null,
    end: ?i32 = null,
};

fn parseTickRange(value: []const u8) ?TickRangeArg {
    if (value.len == 0) return null;
    if (std.mem.indexOf(u8, value, "..")) |split| {
        const left = std.mem.trim(u8, value[0..split], " \t");
        const right = std.mem.trim(u8, value[split + 2 ..], " \t");
        const start = if (left.len == 0) null else parseNonNegativeI32(left) orelse return null;
        const end = if (right.len == 0) null else parseNonNegativeI32(right) orelse return null;
        return .{ .start = start, .end = end };
    }
    const tick = parseNonNegativeI32(std.mem.trim(u8, value, " \t")) orelse return null;
    return .{ .start = tick, .end = tick };
}

fn parseNonNegativeI32(value: []const u8) ?i32 {
    if (value.len == 0) return null;
    const parsed = std.fmt.parseInt(i32, value, 10) catch return null;
    if (parsed < 0) return null;
    return parsed;
}

fn buildUsageOutput(allocator: std.mem.Allocator, exit_code: u8, detail: []const u8) !CommandOutput {
    const stdout = try allocator.dupe(u8, "");
    errdefer allocator.free(stdout);
    const stderr = if (detail.len == 0)
        try allocator.dupe(u8, usage)
    else
        try std.fmt.allocPrint(allocator, "{s}\n{s}", .{ detail, usage });
    return .{ .stdout = stdout, .stderr = stderr, .exit_code = exit_code };
}

fn buildEntityFailedOutput(allocator: std.mem.Allocator, detail: []const u8) !CommandOutput {
    return .{
        .stdout = try allocator.dupe(u8, ""),
        .stderr = try std.fmt.allocPrint(allocator, "dbg entity failed: {s}\n", .{detail}),
        .exit_code = 1,
    };
}

fn traceEntityErrorDetail(err: anyerror) []const u8 {
    return switch (err) {
        error.FileNotFound => "trace file not found",
        error.AccessDenied => "trace file access denied",
        error.EntityNotFound => "entity uid not found in requested range",
        error.InvalidTickRange => "invalid tick range",
        error.InvalidTraceMagic,
        error.InvalidTraceHeader,
        error.InvalidTraceChunkHeader,
        error.InvalidTraceChunkFlags,
        error.InvalidTracePayload,
        error.InvalidTraceTrailer,
        error.InvalidTraceFooterOffset,
        error.InvalidTraceFooterChunk,
        error.InvalidTraceTickChunk,
        error.InvalidTraceTickBlock,
        error.InvalidTraceBlockOffset,
        error.InvalidTraceChecksum,
        => "invalid CDT trace",
        error.UnsupportedTraceFormatVersion => "unsupported CDT trace format version",
        error.UnsupportedTraceCompression => "compressed CDT trace chunks are not supported",
        error.OutOfMemory => "out of memory",
        else => @errorName(err),
    };
}

fn writeFileWithParents(path: []const u8, bytes: []const u8) !void {
    const io = std.Io.Threaded.global_single_threaded.io();
    if (std.fs.path.dirname(path)) |dir| {
        if (dir.len > 0) try std.Io.Dir.cwd().createDirPath(io, dir);
    }
    try std.Io.Dir.cwd().writeFile(io, .{
        .sub_path = path,
        .data = bytes,
    });
}

test "dbg entity parser accepts uid range and JSON output" {
    const parsed = parseArgs(&.{ "sample.cdt", "4", "--ticks=1..8", "--json", "--json-out=out/entity.json" });
    switch (parsed) {
        .ok => |request| {
            try std.testing.expectEqualStrings("sample.cdt", request.trace_path);
            try std.testing.expectEqual(@as(i32, 4), request.entity_uid);
            try std.testing.expectEqual(@as(?i32, 1), request.tick_start);
            try std.testing.expectEqual(@as(?i32, 8), request.tick_end);
            try std.testing.expect(request.json);
            try std.testing.expectEqualStrings("out/entity.json", request.json_out.?);
        },
        else => return error.TestExpectedValidArgs,
    }
}

test "dbg entity rejects inverted range" {
    const parsed = parseArgs(&.{ "sample.cdt", "4", "--ticks", "8..1" });
    switch (parsed) {
        .invalid => |detail| try std.testing.expectEqualStrings("tick range start must be <= end", detail),
        else => return error.TestExpectedInvalidArgs,
    }
}

test "dbg entity summarizes native CDT trace" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base_dir = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer allocator.free(base_dir);
    const replay_path = try std.fs.path.join(allocator, &.{ base_dir, "sample.crd" });
    defer allocator.free(replay_path);
    const trace_path = try std.fs.path.join(allocator, &.{ base_dir, "sample.cdt" });
    defer allocator.free(trace_path);
    const json_path = try std.fs.path.join(allocator, &.{ base_dir, "reports", "entity.json" });
    defer allocator.free(json_path);

    const replay_bytes = try replay_codec.buildSmokeTestReplayPayload(allocator);
    defer allocator.free(replay_bytes);

    const io = std.Io.Threaded.global_single_threaded.io();
    try std.Io.Dir.cwd().writeFile(io, .{
        .sub_path = replay_path,
        .data = replay_bytes,
    });

    const record_output = try dbg_record_native.runDbgRecord(allocator, &.{ replay_path, "--out", trace_path });
    defer record_output.deinit(allocator);
    try std.testing.expectEqual(@as(u8, 0), record_output.exit_code);
    try std.testing.expect(std.mem.indexOf(u8, record_output.stdout, "trace=") != null);

    const entity_output = try runDbgEntity(allocator, &.{ trace_path, "0", "--json", "--json-out", json_path });
    defer entity_output.deinit(allocator);
    try std.testing.expectEqual(@as(u8, 0), entity_output.exit_code);
    try std.testing.expectEqualStrings("", entity_output.stderr);
    try std.testing.expect(std.mem.indexOf(u8, entity_output.stdout, "\"entity_uid\":0") != null);
    try std.testing.expect(std.mem.indexOf(u8, entity_output.stdout, "\"samples\":") != null);
    try std.testing.expect(std.mem.indexOf(u8, entity_output.stdout, "\"pool_kind\":\"creature\"") != null);

    const artifact = try std.Io.Dir.cwd().readFileAlloc(io, json_path, allocator, .limited(64 * 1024));
    defer allocator.free(artifact);
    try std.testing.expectEqualStrings(entity_output.stdout, artifact);
}
