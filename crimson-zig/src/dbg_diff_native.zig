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
    expected_trace: []const u8 = "",
    actual_trace: []const u8 = "",
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

const DiffJsonPayload = struct {
    schema_version: i32 = 1,
    status: []const u8,
    expected_trace: []const u8,
    actual_trace: []const u8,
    checked_count: usize,
    tick_start: ?i32,
    tick_end: ?i32,
    mismatch: ?cdt_trace.TraceDiffMismatch,
};

const usage =
    \\Usage:
    \\  crimson-zig dbg diff <expected.cdt> <actual.cdt> [diff options]
    \\
    \\Options:
    \\  --tick-start <n>   First tick to compare.
    \\  --tick-end <n>     Last tick to compare.
    \\  --format <fmt>     Output format: human or json.
    \\  --json             Alias for --format json.
    \\  --json-out <path>  Also write the JSON report to a file.
    \\  -h, --help         Show this help.
    \\
;

pub fn runDbgDiff(
    allocator: std.mem.Allocator,
    args: []const []const u8,
) !CommandOutput {
    switch (parseArgs(args)) {
        .ok => |request| {
            const report = cdt_trace.diffTraceFiles(
                allocator,
                std.Io.Threaded.global_single_threaded.io(),
                request.expected_trace,
                request.actual_trace,
                .{
                    .tick_start = request.tick_start,
                    .tick_end = request.tick_end,
                },
            ) catch |err| return buildDiffFailedOutput(allocator, traceDiffErrorDetail(err));
            return buildDiffOutput(allocator, request, report);
        },
        .help => return buildUsageOutput(allocator, 0, ""),
        .invalid => |detail| return buildUsageOutput(allocator, 2, detail),
    }
}

fn buildDiffOutput(
    allocator: std.mem.Allocator,
    request: Request,
    report: cdt_trace.TraceDiffReport,
) !CommandOutput {
    const json_payload = try buildDiffJson(allocator, request, report);
    errdefer allocator.free(json_payload);

    if (request.json_out) |json_out_path| {
        writeFileWithParents(json_out_path, json_payload) catch |err| {
            allocator.free(json_payload);
            return buildDiffFailedOutput(allocator, traceDiffErrorDetail(err));
        };
    }

    if (request.output_format == .json) {
        return .{
            .stdout = json_payload,
            .stderr = try allocator.dupe(u8, ""),
            .exit_code = if (report.ok) 0 else 1,
        };
    }
    allocator.free(json_payload);

    if (report.ok) {
        var stdout: std.Io.Writer.Allocating = .init(allocator);
        errdefer stdout.deinit();
        try stdout.writer.print("result=ok checked={d}\n", .{report.checked_count});
        if (request.json_out) |path| {
            try stdout.writer.print("json_report={s}\n", .{path});
        }
        return .{
            .stdout = try stdout.toOwnedSlice(),
            .stderr = try allocator.dupe(u8, ""),
            .exit_code = 0,
        };
    }

    const mismatch = report.mismatch.?;
    var stderr: std.Io.Writer.Allocating = .init(allocator);
    errdefer stderr.deinit();
    try stderr.writer.print(
        "result=diverged kind={s} tick={d} checked={d}\n",
        .{ mismatch.kind, mismatch.tick_index, report.checked_count },
    );
    if (mismatch.field) |field| {
        try stderr.writer.print(
            "detail=field={s} expected=",
            .{field},
        );
        try writeOptionalI64(&stderr.writer, mismatch.expected);
        try stderr.writer.writeAll(" actual=");
        try writeOptionalI64(&stderr.writer, mismatch.actual);
        try stderr.writer.writeByte('\n');
    }

    var stdout: std.Io.Writer.Allocating = .init(allocator);
    errdefer stdout.deinit();
    if (request.json_out) |path| {
        try stdout.writer.print("json_report={s}\n", .{path});
    }

    return .{
        .stdout = try stdout.toOwnedSlice(),
        .stderr = try stderr.toOwnedSlice(),
        .exit_code = 1,
    };
}

fn buildDiffJson(
    allocator: std.mem.Allocator,
    request: Request,
    report: cdt_trace.TraceDiffReport,
) ![]u8 {
    const payload: DiffJsonPayload = .{
        .status = if (report.ok) "ok" else "diverged",
        .expected_trace = request.expected_trace,
        .actual_trace = request.actual_trace,
        .checked_count = report.checked_count,
        .tick_start = report.tick_start,
        .tick_end = report.tick_end,
        .mismatch = report.mismatch,
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

fn writeOptionalI64(writer: *std.Io.Writer, value: ?i64) !void {
    if (value) |int_value| {
        try writer.print("{d}", .{int_value});
    } else {
        try writer.writeAll("null");
    }
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

fn buildDiffFailedOutput(allocator: std.mem.Allocator, detail: []const u8) !CommandOutput {
    return .{
        .stdout = try allocator.dupe(u8, ""),
        .stderr = try std.fmt.allocPrint(allocator, "dbg diff failed: {s}\n", .{detail}),
        .exit_code = 1,
    };
}

fn traceDiffErrorDetail(err: anyerror) []const u8 {
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

test "dbg diff parser accepts trace pair and JSON options" {
    const parsed = parseArgs(&.{ "golden.cdt", "candidate.cdt", "--format", "json", "--json-out=out/diff.json", "--tick-start", "2", "--tick-end=4" });
    switch (parsed) {
        .ok => |request| {
            try std.testing.expectEqualStrings("golden.cdt", request.expected_trace);
            try std.testing.expectEqualStrings("candidate.cdt", request.actual_trace);
            try std.testing.expectEqual(OutputFormat.json, request.output_format);
            try std.testing.expectEqualStrings("out/diff.json", request.json_out.?);
            try std.testing.expectEqual(@as(?i32, 2), request.tick_start);
            try std.testing.expectEqual(@as(?i32, 4), request.tick_end);
        },
        else => return error.TestExpectedValidArgs,
    }
}

test "dbg diff rejects inverted tick window" {
    const parsed = parseArgs(&.{ "a.cdt", "b.cdt", "--tick-start", "5", "--tick-end", "4" });
    switch (parsed) {
        .invalid => |detail| try std.testing.expectEqualStrings("tick-start must be <= tick-end", detail),
        else => return error.TestExpectedInvalidArgs,
    }
}

test "dbg diff summarizes matching native CDT traces" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base_dir = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer allocator.free(base_dir);

    const replay_bytes = try replay_codec.buildSmokeTestReplayPayload(allocator);
    defer allocator.free(replay_bytes);
    const replay_path = try std.fs.path.join(allocator, &.{ base_dir, "smoke.crd" });
    defer allocator.free(replay_path);
    try std.Io.Dir.cwd().writeFile(std.testing.io, .{ .sub_path = replay_path, .data = replay_bytes });

    const trace_path = try std.fs.path.join(allocator, &.{ base_dir, "smoke.cdt" });
    defer allocator.free(trace_path);
    const record_output = try dbg_record_native.runDbgRecord(allocator, &.{ replay_path, "--out", trace_path });
    defer record_output.deinit(allocator);
    try std.testing.expectEqual(@as(u8, 0), record_output.exit_code);

    const json_path = try std.fs.path.join(allocator, &.{ base_dir, "reports", "diff.json" });
    defer allocator.free(json_path);
    const diff_output = try runDbgDiff(allocator, &.{ trace_path, trace_path, "--json", "--json-out", json_path });
    defer diff_output.deinit(allocator);
    try std.testing.expectEqual(@as(u8, 0), diff_output.exit_code);
    try std.testing.expectEqualStrings("", diff_output.stderr);
    try std.testing.expect(std.mem.indexOf(u8, diff_output.stdout, "\"status\":\"ok\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, diff_output.stdout, "\"checked_count\":2") != null);

    const artifact = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, json_path, allocator, .limited(1024 * 1024));
    defer allocator.free(artifact);
    try std.testing.expectEqualStrings(diff_output.stdout, artifact);
}
