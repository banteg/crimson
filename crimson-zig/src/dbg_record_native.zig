const std = @import("std");

const verify_native = @import("verify_native.zig");

pub const CommandOutput = verify_native.CommandOutput;

const trace_channels = "checkpoint,sim_state,entity_samples,rng_stream,timing_samples";

const DbgRecordRequest = struct {
    replay_file: []const u8,
    out_path: []const u8,
    base_dir: ?[]const u8 = null,
    trace_rng: bool = false,
};

const ParseOutcome = union(enum) {
    ok: DbgRecordRequest,
    invalid: []const u8,
};

const VerifyRecordPayload = struct {
    run_result: struct {
        ticks: i32,
    },
};

pub fn runDbgRecord(
    allocator: std.mem.Allocator,
    args: []const []const u8,
) !CommandOutput {
    switch (parseNativeSubset(args)) {
        .ok => |request| return runNativeRecord(allocator, request),
        .invalid => |detail| return buildInvalidRecordArgsOutput(allocator, detail),
    }
}

fn runNativeRecord(
    allocator: std.mem.Allocator,
    request: DbgRecordRequest,
) !CommandOutput {
    var verify_args: std.ArrayList([]const u8) = .empty;
    defer verify_args.deinit(allocator);

    try verify_args.append(allocator, request.replay_file);
    try verify_args.append(allocator, "--debug-trace-cdt");
    try verify_args.append(allocator, request.out_path);
    try verify_args.append(allocator, "--format");
    try verify_args.append(allocator, "json");
    if (request.trace_rng) {
        try verify_args.append(allocator, "--trace-rng");
    }
    if (request.base_dir) |base_dir| {
        try verify_args.append(allocator, "--base-dir");
        try verify_args.append(allocator, base_dir);
    }

    const verify_output = try verify_native.runReplayVerify(allocator, verify_args.items);
    defer verify_output.deinit(allocator);

    const parsed = std.json.parseFromSlice(
        VerifyRecordPayload,
        allocator,
        verify_output.stdout,
        .{ .ignore_unknown_fields = true },
    ) catch {
        return buildRecordFailedOutput(allocator, verify_output);
    };
    defer parsed.deinit();

    var stdout_buf: std.Io.Writer.Allocating = .init(allocator);
    defer stdout_buf.deinit();
    const writer = &stdout_buf.writer;

    const ticks = parsed.value.run_result.ticks;
    const end_tick = if (ticks > 0) ticks - 1 else -1;
    try writer.print("trace={s}\n", .{request.out_path});
    try writer.print("ticks start=0 end={d} count={d}\n", .{ end_tick, ticks });
    try writer.print("channels={s}\n", .{trace_channels});

    const stderr = if (verify_output.exit_code == 0)
        try allocator.dupe(u8, "")
    else
        try buildRecordWarning(allocator, verify_output);

    return .{
        .stdout = try stdout_buf.toOwnedSlice(),
        .stderr = stderr,
        .exit_code = 0,
    };
}

fn buildRecordWarning(
    allocator: std.mem.Allocator,
    verify_output: CommandOutput,
) ![]u8 {
    var stderr_buf: std.Io.Writer.Allocating = .init(allocator);
    defer stderr_buf.deinit();
    const writer = &stderr_buf.writer;

    try writer.print(
        "warning: zig replay verify exited {d}; continuing with emitted trace",
        .{verify_output.exit_code},
    );
    const detail = firstLine(verify_output.stderr);
    if (detail.len > 0) {
        try writer.print(": {s}", .{detail});
    }
    try writer.writeByte('\n');
    return stderr_buf.toOwnedSlice();
}

fn buildInvalidRecordArgsOutput(
    allocator: std.mem.Allocator,
    detail: []const u8,
) !CommandOutput {
    const stdout = try allocator.dupe(u8, "");
    errdefer allocator.free(stdout);
    const stderr = try std.fmt.allocPrint(allocator, "invalid dbg record args: {s}\n", .{detail});
    return .{
        .stdout = stdout,
        .stderr = stderr,
        .exit_code = 1,
    };
}

fn buildRecordFailedOutput(
    allocator: std.mem.Allocator,
    verify_output: CommandOutput,
) !CommandOutput {
    const stdout = try allocator.dupe(u8, "");
    errdefer allocator.free(stdout);

    var stderr_buf: std.Io.Writer.Allocating = .init(allocator);
    defer stderr_buf.deinit();
    const writer = &stderr_buf.writer;
    try writer.writeAll("dbg record failed");
    const detail = firstLine(verify_output.stderr);
    if (detail.len > 0) {
        try writer.print(": {s}", .{detail});
    } else {
        const stdout_detail = firstLine(verify_output.stdout);
        if (stdout_detail.len > 0) {
            try writer.print(": {s}", .{stdout_detail});
        }
    }
    try writer.writeByte('\n');

    return .{
        .stdout = stdout,
        .stderr = try stderr_buf.toOwnedSlice(),
        .exit_code = if (verify_output.exit_code == 0) 1 else verify_output.exit_code,
    };
}

fn parseNativeSubset(args: []const []const u8) ParseOutcome {
    var replay_file: ?[]const u8 = null;
    var out_path: ?[]const u8 = null;
    var request: DbgRecordRequest = .{
        .replay_file = "",
        .out_path = "",
    };

    var idx: usize = 0;
    while (idx < args.len) : (idx += 1) {
        const arg = args[idx];

        if (std.mem.eql(u8, arg, "--out")) {
            if (idx + 1 >= args.len) return .{ .invalid = "missing value for --out" };
            idx += 1;
            out_path = args[idx];
            continue;
        }
        if (std.mem.startsWith(u8, arg, "--out=")) {
            out_path = arg["--out=".len..];
            continue;
        }
        if (std.mem.eql(u8, arg, "--trace-rng")) {
            request.trace_rng = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--base-dir") or std.mem.eql(u8, arg, "--runtime-dir")) {
            if (idx + 1 >= args.len) return .{ .invalid = "missing value for --base-dir/--runtime-dir" };
            idx += 1;
            request.base_dir = args[idx];
            continue;
        }
        if (std.mem.startsWith(u8, arg, "--base-dir=")) {
            request.base_dir = arg["--base-dir=".len..];
            continue;
        }
        if (std.mem.startsWith(u8, arg, "--runtime-dir=")) {
            request.base_dir = arg["--runtime-dir=".len..];
            continue;
        }
        if (std.mem.eql(u8, arg, "--impl")) {
            if (idx + 1 >= args.len) return .{ .invalid = "missing value for --impl" };
            idx += 1;
            if (!std.mem.eql(u8, args[idx], "zig")) return .{ .invalid = "native dbg record only supports --impl zig" };
            continue;
        }
        if (std.mem.startsWith(u8, arg, "--impl=")) {
            if (!std.mem.eql(u8, arg["--impl=".len..], "zig")) return .{ .invalid = "native dbg record only supports --impl zig" };
            continue;
        }
        if (std.mem.startsWith(u8, arg, "-")) {
            return .{ .invalid = arg };
        }

        if (replay_file == null) {
            replay_file = arg;
            continue;
        }
        return .{ .invalid = "too many positional arguments" };
    }

    const replay = replay_file orelse return .{ .invalid = "missing replay file argument" };
    const out = out_path orelse return .{ .invalid = "missing --out" };
    request.replay_file = replay;
    request.out_path = out;
    return .{ .ok = request };
}

fn firstLine(bytes: []const u8) []const u8 {
    const trimmed = std.mem.trim(u8, bytes, " \t\r\n");
    if (std.mem.indexOfAny(u8, trimmed, "\r\n")) |idx| return trimmed[0..idx];
    return trimmed;
}

test "dbg record parser accepts replay and out path" {
    const parsed = parseNativeSubset(&.{ "sample.crd", "--out", "sample.cdt", "--impl", "zig" });
    switch (parsed) {
        .ok => |request| {
            try std.testing.expectEqualStrings("sample.crd", request.replay_file);
            try std.testing.expectEqualStrings("sample.cdt", request.out_path);
        },
        else => return error.TestExpectedValidArgs,
    }
}

test "dbg record parser rejects missing out path" {
    const parsed = parseNativeSubset(&.{"sample.crd"});
    switch (parsed) {
        .invalid => |detail| try std.testing.expectEqualStrings("missing --out", detail),
        else => return error.TestExpectedInvalidArgs,
    }
}

test "dbg record warning mirrors python wrapper wording" {
    const allocator = std.testing.allocator;
    const stdout = try allocator.dupe(u8, "");
    defer allocator.free(stdout);
    const stderr = try allocator.dupe(u8, "first line\nsecond line\n");
    defer allocator.free(stderr);

    const warning = try buildRecordWarning(allocator, .{
        .stdout = stdout,
        .stderr = stderr,
        .exit_code = 3,
    });
    defer allocator.free(warning);
    try std.testing.expectEqualStrings(
        "warning: zig replay verify exited 3; continuing with emitted trace: first line\n",
        warning,
    );
}
