const std = @import("std");

const cdt_trace = @import("cdt_trace.zig");
const dbg_record_native = @import("dbg_record_native.zig");
const replay_codec = @import("replay_codec.zig");
const verify_native = @import("verify_native.zig");

pub const CommandOutput = verify_native.CommandOutput;

const Request = struct {
    trace_path: []const u8,
    tick_index: i32,
    json: bool = false,
    json_out: ?[]const u8 = null,
};

const ParseOutcome = union(enum) {
    ok: Request,
    help,
    invalid: []const u8,
};

const TickJsonPayload = struct {
    schema_version: i32 = 1,
    trace: []const u8,
    tick_index: i32,
    elapsed_ms: i64,
    dt_ms_i32: i32,
    mode_id: i32,
    checkpoint: cdt_trace.TickCheckpointSummary,
    entity_counts: cdt_trace.TickEntityCounts,
    rng_stream_count: i32,
    timing_samples_count: i32,
    event_count_total: i32,
    top_event_types: []const []const u8,
};

const usage =
    \\Usage:
    \\  crimson-zig dbg tick <trace.cdt> <tick> [tick options]
    \\
    \\Options:
    \\  --json             Print JSON payload to stdout.
    \\  --json-out <path>  Also write the JSON report to a file.
    \\  -h, --help         Show this help.
    \\
;

pub fn runDbgTick(
    allocator: std.mem.Allocator,
    args: []const []const u8,
) !CommandOutput {
    switch (parseArgs(args)) {
        .ok => |request| {
            var summary = cdt_trace.summarizeTraceTickFile(
                allocator,
                std.Io.Threaded.global_single_threaded.io(),
                request.trace_path,
                request.tick_index,
            ) catch |err| return buildTickFailedOutput(allocator, traceTickErrorDetail(err));
            defer summary.deinit(allocator);
            return buildTickOutput(allocator, request, summary);
        },
        .help => return buildUsageOutput(allocator, 0, ""),
        .invalid => |detail| return buildUsageOutput(allocator, 2, detail),
    }
}

fn buildTickOutput(
    allocator: std.mem.Allocator,
    request: Request,
    summary: cdt_trace.TickSummary,
) !CommandOutput {
    const json_payload = try buildTickJson(allocator, request.trace_path, summary);
    errdefer allocator.free(json_payload);

    if (request.json_out) |json_out_path| {
        writeFileWithParents(json_out_path, json_payload) catch |err| {
            allocator.free(json_payload);
            return buildTickFailedOutput(allocator, traceTickErrorDetail(err));
        };
    }

    const stdout = if (request.json) json_payload else stdout: {
        const human = try buildTickHuman(allocator, summary, request.json_out);
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

fn buildTickJson(
    allocator: std.mem.Allocator,
    trace_path: []const u8,
    summary: cdt_trace.TickSummary,
) ![]u8 {
    const payload: TickJsonPayload = .{
        .trace = trace_path,
        .tick_index = summary.tick_index,
        .elapsed_ms = summary.elapsed_ms,
        .dt_ms_i32 = summary.dt_ms_i32,
        .mode_id = summary.mode_id,
        .checkpoint = summary.checkpoint,
        .entity_counts = summary.entity_counts,
        .rng_stream_count = summary.rng_stream_count,
        .timing_samples_count = summary.timing_samples_count,
        .event_count_total = summary.event_count_total,
        .top_event_types = summary.top_event_types,
    };

    var writer: std.Io.Writer.Allocating = .init(allocator);
    errdefer writer.deinit();
    try std.json.Stringify.value(payload, .{}, &writer.writer);
    try writer.writer.writeByte('\n');
    return writer.toOwnedSlice();
}

fn buildTickHuman(
    allocator: std.mem.Allocator,
    summary: cdt_trace.TickSummary,
    json_out: ?[]const u8,
) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(allocator);
    errdefer out.deinit();
    const writer = &out.writer;

    try writer.print(
        "tick={d} elapsed_ms={d} dt_ms_i32={d} mode_id={d}\n",
        .{ summary.tick_index, summary.elapsed_ms, summary.dt_ms_i32, summary.mode_id },
    );
    try writer.print(
        "checkpoint score_xp={d} kills={d} creature_count={d} perk_pending={d}\n",
        .{
            summary.checkpoint.score_xp,
            summary.checkpoint.kills,
            summary.checkpoint.creature_count,
            summary.checkpoint.perk_pending,
        },
    );
    try writer.print(
        "entity_counts creatures={d} projectiles={d} secondary_projectiles={d} bonuses={d}\n",
        .{
            summary.entity_counts.creatures,
            summary.entity_counts.projectiles,
            summary.entity_counts.secondary_projectiles,
            summary.entity_counts.bonuses,
        },
    );
    try writer.print(
        "trace_rows rng_stream={d} timing_samples={d}\n",
        .{ summary.rng_stream_count, summary.timing_samples_count },
    );
    try writer.print("event_count_total={d}\n", .{summary.event_count_total});
    if (summary.top_event_types.len > 0) {
        try writer.writeAll("top_event_types=");
        for (summary.top_event_types, 0..) |entry, idx| {
            if (idx != 0) try writer.writeByte(',');
            try writer.writeAll(entry);
        }
        try writer.writeByte('\n');
    }
    if (json_out) |path| {
        try writer.print("json_report={s}\n", .{path});
    }
    return out.toOwnedSlice();
}

fn parseArgs(args: []const []const u8) ParseOutcome {
    var trace_path: ?[]const u8 = null;
    var tick_index: ?i32 = null;
    var request: Request = .{
        .trace_path = "",
        .tick_index = 0,
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
        if (trace_path == null) {
            if (std.mem.startsWith(u8, arg, "-")) return .{ .invalid = arg };
            trace_path = arg;
            continue;
        }
        if (tick_index == null) {
            tick_index = parseTick(arg) orelse return .{ .invalid = "invalid tick value" };
            continue;
        }
        if (std.mem.startsWith(u8, arg, "-")) return .{ .invalid = arg };
        return .{ .invalid = "too many positional arguments" };
    }

    request.trace_path = trace_path orelse return .{ .invalid = "missing trace file argument" };
    request.tick_index = tick_index orelse return .{ .invalid = "missing tick argument" };
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

fn parseTick(value: []const u8) ?i32 {
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

fn buildTickFailedOutput(allocator: std.mem.Allocator, detail: []const u8) !CommandOutput {
    return .{
        .stdout = try allocator.dupe(u8, ""),
        .stderr = try std.fmt.allocPrint(allocator, "dbg tick failed: {s}\n", .{detail}),
        .exit_code = 1,
    };
}

fn traceTickErrorDetail(err: anyerror) []const u8 {
    return switch (err) {
        error.FileNotFound => "trace file not found",
        error.AccessDenied => "trace file access denied",
        error.TickNotFound => "tick not found",
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

test "dbg tick parser accepts trace tick and JSON output" {
    const parsed = parseArgs(&.{ "sample.cdt", "12", "--json", "--json-out=out/tick.json" });
    switch (parsed) {
        .ok => |request| {
            try std.testing.expectEqualStrings("sample.cdt", request.trace_path);
            try std.testing.expectEqual(@as(i32, 12), request.tick_index);
            try std.testing.expect(request.json);
            try std.testing.expectEqualStrings("out/tick.json", request.json_out.?);
        },
        else => return error.TestExpectedValidArgs,
    }
}

test "dbg tick rejects invalid tick" {
    const parsed = parseArgs(&.{ "sample.cdt", "-1" });
    switch (parsed) {
        .invalid => |detail| try std.testing.expectEqualStrings("invalid tick value", detail),
        else => return error.TestExpectedInvalidArgs,
    }
}

test "dbg tick summarizes native CDT trace" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base_dir = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer allocator.free(base_dir);
    const replay_path = try std.fs.path.join(allocator, &.{ base_dir, "sample.crd" });
    defer allocator.free(replay_path);
    const trace_path = try std.fs.path.join(allocator, &.{ base_dir, "sample.cdt" });
    defer allocator.free(trace_path);
    const json_path = try std.fs.path.join(allocator, &.{ base_dir, "reports", "tick.json" });
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

    const tick_output = try runDbgTick(allocator, &.{ trace_path, "0", "--json", "--json-out", json_path });
    defer tick_output.deinit(allocator);
    try std.testing.expectEqual(@as(u8, 0), tick_output.exit_code);
    try std.testing.expectEqualStrings("", tick_output.stderr);
    try std.testing.expect(std.mem.indexOf(u8, tick_output.stdout, "\"tick_index\":0") != null);
    try std.testing.expect(std.mem.indexOf(u8, tick_output.stdout, "\"checkpoint\":") != null);
    try std.testing.expect(std.mem.indexOf(u8, tick_output.stdout, "\"entity_counts\":") != null);
    try std.testing.expect(std.mem.indexOf(u8, tick_output.stdout, "\"rng_stream_count\":") != null);

    const artifact = try std.Io.Dir.cwd().readFileAlloc(io, json_path, allocator, .limited(64 * 1024));
    defer allocator.free(artifact);
    try std.testing.expectEqualStrings(tick_output.stdout, artifact);
}
