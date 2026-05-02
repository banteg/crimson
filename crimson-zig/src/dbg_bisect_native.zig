const std = @import("std");

const cdt_trace = @import("cdt_trace.zig");
const verify_native = @import("verify_native.zig");

pub const CommandOutput = verify_native.CommandOutput;

const OutputFormat = enum {
    human,
    json,
};

const Request = struct {
    expected_trace: []const u8 = "",
    actual_trace: []const u8 = "",
    output_format: OutputFormat = .human,
    json_out: ?[]const u8 = null,
    tick_start: ?i32 = null,
    tick_end: ?i32 = null,
    window_before: i32 = 12,
    window_after: i32 = 6,
};

const ParseOutcome = union(enum) {
    ok: Request,
    help,
    invalid: []const u8,
};

const BisectJsonPayload = struct {
    schema_version: i32 = 1,
    status: []const u8,
    expected_trace: []const u8,
    actual_trace: []const u8,
    checked_count: usize,
    first_bad_tick: ?i32,
    mismatch: ?cdt_trace.TraceDiffMismatch,
    window_start: ?i32,
    window_end: ?i32,
};

const usage =
    \\Usage:
    \\  crimson-zig dbg bisect <expected.cdt> <actual.cdt> [bisect options]
    \\
    \\Options:
    \\  --tick-start <n>      First tick to compare.
    \\  --tick-end <n>        Last tick to compare.
    \\  --window-before <n>   Ticks before first bad tick in the focus window.
    \\  --window-after <n>    Ticks after first bad tick in the focus window.
    \\  --format <fmt>        Output format: human or json.
    \\  --json                Alias for --format json.
    \\  --json-out <path>     Also write the JSON report to a file.
    \\  -h, --help            Show this help.
    \\
;

pub fn runDbgBisect(
    allocator: std.mem.Allocator,
    args: []const []const u8,
) !CommandOutput {
    switch (parseArgs(args)) {
        .ok => |request| {
            const report = cdt_trace.bisectTraceFiles(
                allocator,
                std.Io.Threaded.global_single_threaded.io(),
                request.expected_trace,
                request.actual_trace,
                .{
                    .tick_start = request.tick_start,
                    .tick_end = request.tick_end,
                },
                request.window_before,
                request.window_after,
            ) catch |err| return buildBisectFailedOutput(allocator, traceErrorDetail(err));
            return buildBisectOutput(allocator, request, report);
        },
        .help => return buildUsageOutput(allocator, 0, ""),
        .invalid => |detail| return buildUsageOutput(allocator, 2, detail),
    }
}

fn buildBisectOutput(
    allocator: std.mem.Allocator,
    request: Request,
    report: cdt_trace.TraceBisectReport,
) !CommandOutput {
    const json_payload = try buildBisectJson(allocator, request, report);
    errdefer allocator.free(json_payload);

    if (request.json_out) |json_out_path| {
        writeFileWithParents(json_out_path, json_payload) catch |err| {
            allocator.free(json_payload);
            return buildBisectFailedOutput(allocator, traceErrorDetail(err));
        };
    }

    if (request.output_format == .json) {
        return .{
            .stdout = json_payload,
            .stderr = try allocator.dupe(u8, ""),
            .exit_code = 0,
        };
    }
    allocator.free(json_payload);

    var stdout: std.Io.Writer.Allocating = .init(allocator);
    errdefer stdout.deinit();
    if (report.ok) {
        try stdout.writer.print("result=ok checked={d}\n", .{report.checked_count});
    } else {
        const mismatch = report.mismatch.?;
        try stdout.writer.print(
            "result=diverged first_bad_tick={d} kind={s} checked={d} window={d}..{d}\n",
            .{
                report.first_bad_tick.?,
                mismatch.kind,
                report.checked_count,
                report.window_start.?,
                report.window_end.?,
            },
        );
    }
    if (request.json_out) |path| {
        try stdout.writer.print("json_report={s}\n", .{path});
    }

    return .{
        .stdout = try stdout.toOwnedSlice(),
        .stderr = try allocator.dupe(u8, ""),
        .exit_code = 0,
    };
}

fn buildBisectJson(
    allocator: std.mem.Allocator,
    request: Request,
    report: cdt_trace.TraceBisectReport,
) ![]u8 {
    const payload: BisectJsonPayload = .{
        .status = if (report.ok) "ok" else "diverged",
        .expected_trace = request.expected_trace,
        .actual_trace = request.actual_trace,
        .checked_count = report.checked_count,
        .first_bad_tick = report.first_bad_tick,
        .mismatch = report.mismatch,
        .window_start = report.window_start,
        .window_end = report.window_end,
    };

    var writer: std.Io.Writer.Allocating = .init(allocator);
    errdefer writer.deinit();
    try std.json.Stringify.value(payload, .{}, &writer.writer);
    try writer.writer.writeByte('\n');
    return writer.toOwnedSlice();
}

fn parseArgs(args: []const []const u8) ParseOutcome {
    var request: Request = .{};
    var path_count: usize = 0;
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
        if (takeValue(args, &idx, arg, "--window-before")) |value| {
            request.window_before = parseTick(value) orelse return .{ .invalid = "invalid --window-before value" };
            continue;
        }
        if (takeValue(args, &idx, arg, "--window-after")) |value| {
            request.window_after = parseTick(value) orelse return .{ .invalid = "invalid --window-after value" };
            continue;
        }
        if (std.mem.startsWith(u8, arg, "-")) return .{ .invalid = arg };
        switch (path_count) {
            0 => request.expected_trace = arg,
            1 => request.actual_trace = arg,
            else => return .{ .invalid = "too many positional arguments" },
        }
        path_count += 1;
    }

    if (path_count != 2) return .{ .invalid = "expected <expected.cdt> <actual.cdt>" };
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

fn buildBisectFailedOutput(allocator: std.mem.Allocator, detail: []const u8) !CommandOutput {
    return .{
        .stdout = try allocator.dupe(u8, ""),
        .stderr = try std.fmt.allocPrint(allocator, "dbg bisect failed: {s}\n", .{detail}),
        .exit_code = 1,
    };
}

fn traceErrorDetail(err: anyerror) []const u8 {
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
        error.FileBusy => @errorName(err),
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

test "dbg bisect parser accepts trace pair and window options" {
    const parsed = parseArgs(&.{ "golden.cdt", "candidate.cdt", "--format", "json", "--json-out=out/bisect.json", "--tick-start", "2", "--tick-end=4", "--window-before=3", "--window-after", "5" });
    switch (parsed) {
        .ok => |request| {
            try std.testing.expectEqualStrings("golden.cdt", request.expected_trace);
            try std.testing.expectEqualStrings("candidate.cdt", request.actual_trace);
            try std.testing.expectEqual(OutputFormat.json, request.output_format);
            try std.testing.expectEqualStrings("out/bisect.json", request.json_out.?);
            try std.testing.expectEqual(@as(?i32, 2), request.tick_start);
            try std.testing.expectEqual(@as(?i32, 4), request.tick_end);
            try std.testing.expectEqual(@as(i32, 3), request.window_before);
            try std.testing.expectEqual(@as(i32, 5), request.window_after);
        },
        else => return error.TestExpectedValidArgs,
    }
}

test "dbg bisect rejects inverted tick window" {
    const parsed = parseArgs(&.{ "a.cdt", "b.cdt", "--tick-start", "5", "--tick-end", "4" });
    switch (parsed) {
        .invalid => |detail| try std.testing.expectEqualStrings("tick-start must be <= tick-end", detail),
        else => return error.TestExpectedInvalidArgs,
    }
}
