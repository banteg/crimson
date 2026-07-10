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
    tick_index: ?i32 = null,
    output_format: OutputFormat = .human,
    json_out: ?[]const u8 = null,
};

const ParseOutcome = union(enum) {
    ok: Request,
    help,
    invalid: []const u8,
};

const FocusJsonPayload = struct {
    schema_version: i32 = 1,
    status: []const u8,
    expected_trace: []const u8,
    actual_trace: []const u8,
    tick_index: i32,
    diverged: bool,
    checkpoint_diff_count: usize,
    mismatch: ?cdt_trace.TraceDiffMismatch,
};

const usage =
    \\Usage:
    \\  crimson-zig dbg focus <expected.cdt> <actual.cdt> --tick <n> [focus options]
    \\
    \\Options:
    \\  --tick <n>        Tick index to inspect.
    \\  --format <fmt>    Output format: human or json.
    \\  --json            Alias for --format json.
    \\  --json-out <path> Also write the JSON report to a file.
    \\  -h, --help        Show this help.
    \\
;

pub fn runDbgFocus(
    allocator: std.mem.Allocator,
    args: []const []const u8,
) !CommandOutput {
    switch (parseArgs(args)) {
        .ok => |request| {
            const report = cdt_trace.focusTraceFiles(
                allocator,
                std.Io.Threaded.global_single_threaded.io(),
                request.expected_trace,
                request.actual_trace,
                request.tick_index.?,
            ) catch |err| return buildFocusFailedOutput(allocator, traceErrorDetail(err));
            return buildFocusOutput(allocator, request, report);
        },
        .help => return buildUsageOutput(allocator, 0, ""),
        .invalid => |detail| return buildUsageOutput(allocator, 2, detail),
    }
}

fn buildFocusOutput(
    allocator: std.mem.Allocator,
    request: Request,
    report: cdt_trace.TraceFocusReport,
) !CommandOutput {
    const json_payload = try buildFocusJson(allocator, request, report);
    errdefer allocator.free(json_payload);

    if (request.json_out) |json_out_path| {
        writeFileWithParents(json_out_path, json_payload) catch |err| {
            allocator.free(json_payload);
            return buildFocusFailedOutput(allocator, traceErrorDetail(err));
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
    try stdout.writer.print(
        "result={s} tick={d} checkpoint_diff_count={d}\n",
        .{
            if (report.diverged) "diverged" else "ok",
            report.tick_index,
            report.checkpoint_diff_count,
        },
    );
    if (report.mismatch) |mismatch| {
        if (mismatch.field) |field| {
            try stdout.writer.print("mismatch kind={s} field={s}\n", .{ mismatch.kind, field });
        } else {
            try stdout.writer.print("mismatch kind={s}\n", .{mismatch.kind});
        }
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

fn buildFocusJson(
    allocator: std.mem.Allocator,
    request: Request,
    report: cdt_trace.TraceFocusReport,
) ![]u8 {
    const payload: FocusJsonPayload = .{
        .status = if (report.diverged) "diverged" else "ok",
        .expected_trace = request.expected_trace,
        .actual_trace = request.actual_trace,
        .tick_index = report.tick_index,
        .diverged = report.diverged,
        .checkpoint_diff_count = report.checkpoint_diff_count,
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
        if (takeValue(args, &idx, arg, "--tick")) |value| {
            request.tick_index = parseTick(value) orelse return .{ .invalid = "invalid --tick value" };
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
    if (request.tick_index == null) return .{ .invalid = "missing --tick" };
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

fn buildFocusFailedOutput(allocator: std.mem.Allocator, detail: []const u8) !CommandOutput {
    return .{
        .stdout = try allocator.dupe(u8, ""),
        .stderr = try std.fmt.allocPrint(allocator, "dbg focus failed: {s}\n", .{detail}),
        .exit_code = 1,
    };
}

fn traceErrorDetail(err: anyerror) []const u8 {
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
        error.InvalidTraceMetaChunk,
        error.InvalidTraceFooterChunk,
        error.InvalidTraceTickChunk,
        error.InvalidTraceTickBlock,
        error.InvalidTraceFooter,
        error.InvalidTraceBlockOffset,
        error.InvalidTraceChecksum,
        error.InvalidTraceChunkLayout,
        => "invalid CDT trace",
        error.UnsupportedTraceFormatVersion => "unsupported CDT trace format version",
        error.UnsupportedTraceSchemaVersion => "unsupported CDT trace schema version",
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

test "dbg focus parser accepts trace pair and tick" {
    const parsed = parseArgs(&.{ "golden.cdt", "candidate.cdt", "--tick", "4", "--format", "json", "--json-out=out/focus.json" });
    switch (parsed) {
        .ok => |request| {
            try std.testing.expectEqualStrings("golden.cdt", request.expected_trace);
            try std.testing.expectEqualStrings("candidate.cdt", request.actual_trace);
            try std.testing.expectEqual(@as(?i32, 4), request.tick_index);
            try std.testing.expectEqual(OutputFormat.json, request.output_format);
            try std.testing.expectEqualStrings("out/focus.json", request.json_out.?);
        },
        else => return error.TestExpectedValidArgs,
    }
}

test "dbg focus rejects missing tick" {
    const parsed = parseArgs(&.{ "a.cdt", "b.cdt" });
    switch (parsed) {
        .invalid => |detail| try std.testing.expectEqualStrings("missing --tick", detail),
        else => return error.TestExpectedInvalidArgs,
    }
}
