const std = @import("std");

const cdt_trace = @import("cdt_trace.zig");
const dbg_record_native = @import("dbg_record_native.zig");
const replay_codec = @import("replay_codec.zig");
const verify_native = @import("verify_native.zig");

pub const CommandOutput = verify_native.CommandOutput;

const OutputFormat = enum {
    human,
    json,
};

const Request = struct {
    trace_path: []const u8,
    output_format: OutputFormat = .human,
    json_out: ?[]const u8 = null,
    tick_start: ?i32 = null,
    tick_end: ?i32 = null,
};

const ParseOutcome = union(enum) {
    ok: Request,
    help,
    invalid: []const u8,
};

const HealthJsonPayload = struct {
    schema_version: i32 = 1,
    status: []const u8,
    trace: []const u8,
    trace_format_version: i32,
    trace_schema_version: i32,
    tick_window: cdt_trace.TickWindowSummary,
    channels_present: cdt_trace.ChannelCounts,
    channel_row_counts: cdt_trace.ChannelRowCounts,
    metrics: cdt_trace.HealthMetrics,
    issues: []const []const u8,
    ok_for_parity_analysis: bool,
};

const usage =
    \\Usage:
    \\  crimson-zig dbg health <trace.cdt> [health options]
    \\
    \\Options:
    \\  --tick-start <n>   First tick to inspect.
    \\  --tick-end <n>     Last tick to inspect.
    \\  --format <fmt>     Output format: human or json.
    \\  --json             Alias for --format json.
    \\  --json-out <path>  Also write the JSON report to a file.
    \\  -h, --help         Show this help.
    \\
;

pub fn runDbgHealth(
    allocator: std.mem.Allocator,
    args: []const []const u8,
) !CommandOutput {
    switch (parseArgs(args)) {
        .ok => |request| {
            var summary = cdt_trace.summarizeTraceHealthFile(
                allocator,
                std.Io.Threaded.global_single_threaded.io(),
                request.trace_path,
                .{
                    .tick_start = request.tick_start,
                    .tick_end = request.tick_end,
                },
            ) catch |err| return buildHealthFailedOutput(allocator, traceHealthErrorDetail(err));
            defer summary.deinit(allocator);
            return buildHealthOutput(allocator, request, summary);
        },
        .help => return buildUsageOutput(allocator, 0, ""),
        .invalid => |detail| return buildUsageOutput(allocator, 2, detail),
    }
}

fn buildHealthOutput(
    allocator: std.mem.Allocator,
    request: Request,
    summary: cdt_trace.HealthSummary,
) !CommandOutput {
    const json_payload = try buildHealthJson(allocator, request.trace_path, summary);
    errdefer allocator.free(json_payload);

    if (request.json_out) |json_out_path| {
        writeFileWithParents(json_out_path, json_payload) catch |err| {
            allocator.free(json_payload);
            return buildHealthFailedOutput(allocator, traceHealthErrorDetail(err));
        };
    }

    const stdout = switch (request.output_format) {
        .json => json_payload,
        .human => stdout: {
            const human = try buildHealthHuman(allocator, request, summary);
            allocator.free(json_payload);
            break :stdout human;
        },
    };
    errdefer allocator.free(stdout);

    return .{
        .stdout = stdout,
        .stderr = try allocator.dupe(u8, ""),
        .exit_code = if (summary.ok_for_parity_analysis) 0 else 1,
    };
}

fn buildHealthJson(
    allocator: std.mem.Allocator,
    trace_path: []const u8,
    summary: cdt_trace.HealthSummary,
) ![]u8 {
    const payload: HealthJsonPayload = .{
        .status = if (summary.ok_for_parity_analysis) "ok" else "failed",
        .trace = trace_path,
        .trace_format_version = summary.trace_format_version,
        .trace_schema_version = summary.trace_schema_version,
        .tick_window = summary.tick_window,
        .channels_present = summary.channels_present,
        .channel_row_counts = summary.channel_row_counts,
        .metrics = summary.metrics,
        .issues = summary.issues,
        .ok_for_parity_analysis = summary.ok_for_parity_analysis,
    };

    var writer: std.Io.Writer.Allocating = .init(allocator);
    errdefer writer.deinit();
    try std.json.Stringify.value(payload, .{}, &writer.writer);
    try writer.writer.writeByte('\n');
    return writer.toOwnedSlice();
}

fn buildHealthHuman(
    allocator: std.mem.Allocator,
    request: Request,
    summary: cdt_trace.HealthSummary,
) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(allocator);
    errdefer out.deinit();
    const writer = &out.writer;

    try writer.print("trace={s}\n", .{request.trace_path});
    try writer.print("trace_format_version={d}\n", .{summary.trace_format_version});
    try writer.print("trace_schema_version={d}\n", .{summary.trace_schema_version});
    try writer.writeAll("tick_window requested_start=");
    try writeOptionalI32(writer, summary.tick_window.requested_start);
    try writer.writeAll(" requested_end=");
    try writeOptionalI32(writer, summary.tick_window.requested_end);
    try writer.writeAll(" actual_start=");
    try writeOptionalI32(writer, summary.tick_window.actual_start);
    try writer.writeAll(" actual_end=");
    try writeOptionalI32(writer, summary.tick_window.actual_end);
    try writer.print(" ticks_in_window={d}\n", .{summary.tick_window.ticks_in_window});
    try writer.print(
        "channels=checkpoint:{d},entity_samples:{d},rng_stream:{d},sim_state:{d},timing_samples:{d}\n",
        .{
            summary.channels_present.checkpoint,
            summary.channels_present.entity_samples,
            summary.channels_present.rng_stream,
            summary.channels_present.sim_state,
            summary.channels_present.timing_samples,
        },
    );
    try writer.print(
        "channel_rows=rng_stream:{d},timing_samples:{d}\n",
        .{
            summary.channel_row_counts.rng_stream,
            summary.channel_row_counts.timing_samples,
        },
    );
    try writer.print("ticks_with_dt_ms_i32={d}\n", .{summary.metrics.ticks_with_dt_ms_i32});
    try writer.print("rng_stream_rows={d}\n", .{summary.metrics.rng_stream_rows});
    try writer.print("sim_state_rows={d}\n", .{summary.metrics.sim_state_rows});
    try writer.print("sample_creature_rows={d}\n", .{summary.metrics.sample_creature_rows});
    try writer.print("sample_projectile_rows={d}\n", .{summary.metrics.sample_projectile_rows});
    try writer.print("sample_secondary_projectile_rows={d}\n", .{summary.metrics.sample_secondary_projectile_rows});
    try writer.print("sample_bonus_rows={d}\n", .{summary.metrics.sample_bonus_rows});
    try writer.print("timing_samples_rows={d}\n", .{summary.metrics.timing_samples_rows});
    try writer.print("ok_for_parity_analysis={}\n", .{summary.ok_for_parity_analysis});
    try writer.print("parity_analysis_ready={}\n", .{summary.ok_for_parity_analysis});
    for (summary.issues) |issue| {
        try writer.print("issue={s}\n", .{issue});
    }
    if (request.json_out) |path| {
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

fn parseArgs(args: []const []const u8) ParseOutcome {
    var trace_path: ?[]const u8 = null;
    var request: Request = .{ .trace_path = "" };

    var idx: usize = 0;
    while (idx < args.len) : (idx += 1) {
        const arg = args[idx];
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) return .help;
        if (std.mem.eql(u8, arg, "--json")) {
            request.output_format = .json;
            continue;
        }
        if (takeValue(args, &idx, arg, "--format")) |value| {
            request.output_format = parseOutputFormat(value) orelse return .{ .invalid = "invalid --format value" };
            continue;
        }
        if (takeValue(args, &idx, arg, "--json-out")) |value| {
            if (value.len == 0) return .{ .invalid = "missing value for --json-out" };
            request.json_out = value;
            continue;
        }
        if (takeValue(args, &idx, arg, "--tick-start")) |value| {
            request.tick_start = parseTick(value) orelse return .{ .invalid = "invalid --tick-start value" };
            continue;
        }
        if (takeValue(args, &idx, arg, "--tick-end")) |value| {
            request.tick_end = parseTick(value) orelse return .{ .invalid = "invalid --tick-end value" };
            continue;
        }
        if (std.mem.startsWith(u8, arg, "-")) return .{ .invalid = arg };
        if (trace_path != null) return .{ .invalid = "too many positional arguments" };
        trace_path = arg;
    }

    request.trace_path = trace_path orelse return .{ .invalid = "missing trace file argument" };
    if (request.tick_start != null and request.tick_end != null and request.tick_start.? > request.tick_end.?) {
        return .{ .invalid = "tick-start must be <= tick-end" };
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

fn parseOutputFormat(value: []const u8) ?OutputFormat {
    if (std.mem.eql(u8, value, "human")) return .human;
    if (std.mem.eql(u8, value, "json")) return .json;
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

fn buildHealthFailedOutput(allocator: std.mem.Allocator, detail: []const u8) !CommandOutput {
    return .{
        .stdout = try allocator.dupe(u8, ""),
        .stderr = try std.fmt.allocPrint(allocator, "dbg health failed: {s}\n", .{detail}),
        .exit_code = 1,
    };
}

fn traceHealthErrorDetail(err: anyerror) []const u8 {
    return switch (err) {
        error.FileNotFound => "trace file not found",
        error.AccessDenied => "trace file access denied",
        error.InvalidTraceMagic,
        error.InvalidTraceHeader,
        error.InvalidTraceChunkHeader,
        error.InvalidTraceChunkFlags,
        error.InvalidTracePayload,
        error.InvalidTraceTrailer,
        error.InvalidTraceFooterOffset,
        error.InvalidTraceMetaChunk,
        error.InvalidTraceFooterChunk,
        error.InvalidTraceTickChunk,
        error.InvalidTraceTickBlock,
        error.InvalidTraceFooter,
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

test "dbg health parser accepts trace path and JSON options" {
    const parsed = parseArgs(&.{ "sample.cdt", "--format", "json", "--json-out=out/health.json", "--tick-start", "2", "--tick-end=4" });
    switch (parsed) {
        .ok => |request| {
            try std.testing.expectEqualStrings("sample.cdt", request.trace_path);
            try std.testing.expectEqual(OutputFormat.json, request.output_format);
            try std.testing.expectEqualStrings("out/health.json", request.json_out.?);
            try std.testing.expectEqual(@as(?i32, 2), request.tick_start);
            try std.testing.expectEqual(@as(?i32, 4), request.tick_end);
        },
        else => return error.TestExpectedValidArgs,
    }
}

test "dbg health rejects inverted tick window" {
    const parsed = parseArgs(&.{ "sample.cdt", "--tick-start", "5", "--tick-end", "4" });
    switch (parsed) {
        .invalid => |detail| try std.testing.expectEqualStrings("tick-start must be <= tick-end", detail),
        else => return error.TestExpectedInvalidArgs,
    }
}

test "dbg health summarizes native CDT trace" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base_dir = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer allocator.free(base_dir);
    const replay_path = try std.fs.path.join(allocator, &.{ base_dir, "sample.crd" });
    defer allocator.free(replay_path);
    const trace_path = try std.fs.path.join(allocator, &.{ base_dir, "sample.cdt" });
    defer allocator.free(trace_path);
    const json_path = try std.fs.path.join(allocator, &.{ base_dir, "reports", "health.json" });
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

    const health_output = try runDbgHealth(allocator, &.{ trace_path, "--format", "json", "--json-out", json_path });
    defer health_output.deinit(allocator);
    try std.testing.expectEqual(@as(u8, 0), health_output.exit_code);
    try std.testing.expectEqualStrings("", health_output.stderr);
    try std.testing.expect(std.mem.indexOf(u8, health_output.stdout, "\"status\":\"ok\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, health_output.stdout, "\"trace_schema_version\":12") != null);
    try std.testing.expect(std.mem.indexOf(u8, health_output.stdout, "\"ticks_in_window\":") != null);
    try std.testing.expect(std.mem.indexOf(u8, health_output.stdout, "\"ok_for_parity_analysis\":true") != null);

    const artifact = try std.Io.Dir.cwd().readFileAlloc(io, json_path, allocator, .limited(64 * 1024));
    defer allocator.free(artifact);
    try std.testing.expectEqualStrings(health_output.stdout, artifact);
}
