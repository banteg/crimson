const builtin = @import("builtin");
const std = @import("std");

const cdt_trace = @import("cdt_trace.zig");
const hash = @import("hash.zig");
const replay_codec = @import("replay_codec.zig");
const replay_runner = @import("runtime/replay_runner.zig");
const runtime_paths = @import("runtime_paths.zig");

const replay_schema_version: i32 = 3;

pub const CommandOutput = struct {
    stdout: []u8,
    stderr: []u8,
    exit_code: u8,

    pub fn deinit(self: CommandOutput, allocator: std.mem.Allocator) void {
        allocator.free(self.stdout);
        allocator.free(self.stderr);
    }
};

const OutputFormat = enum {
    human,
    json,
};

const VerifyRequest = struct {
    replay_file: []const u8,
    output_format: OutputFormat = .human,
    json_out: ?[]const u8 = null,
    base_dir: ?[]const u8 = null,
    max_ticks: ?usize = null,
    trace_rng: bool = false,
    debug_trace_cdt: ?[]const u8 = null,
};

const ParseOutcome = union(enum) {
    ok: VerifyRequest,
    invalid: []const u8,
};

const ReplayResolution = struct {
    resolved_path: []u8,
    tried_primary: []u8,
    tried_secondary: ?[]u8,
    exists: bool,

    fn deinit(self: ReplayResolution, allocator: std.mem.Allocator) void {
        allocator.free(self.resolved_path);
        allocator.free(self.tried_primary);
        if (self.tried_secondary) |secondary| allocator.free(secondary);
    }
};

const VerifyStatus = enum { ok, result_mismatch, partial };

const VerifyPayload = struct {
    schema_version: i32 = replay_schema_version,
    status: VerifyStatus,
    replay: []const u8,
    payload_sha256: []const u8,
    game_version: []const u8,
    ticks: usize,
    ticks_simulated: usize,
    result: replay_codec.RunResult,
    recorded: replay_codec.RunResult,
    mismatched_fields: []const []const u8,
};

pub fn runReplayVerify(
    allocator: std.mem.Allocator,
    verify_args: []const []const u8,
) !CommandOutput {
    switch (parseNativeSubset(verify_args)) {
        .ok => |request| return runNativeVerify(allocator, request),
        .invalid => |detail| return buildInvalidVerifyArgsOutput(allocator, detail),
    }
}

pub fn runReplayVerifyBytesJson(
    allocator: std.mem.Allocator,
    replay_name: []const u8,
    replay_bytes: []const u8,
    max_ticks: ?usize,
) !CommandOutput {
    return runVerifyWithReplayBytes(allocator, .{
        .replay_file = replay_name,
        .output_format = .json,
        .max_ticks = max_ticks,
    }, replay_name, replay_bytes);
}

fn runNativeVerify(
    allocator: std.mem.Allocator,
    request: VerifyRequest,
) !CommandOutput {
    if (builtin.os.tag == .freestanding) {
        return buildVerifyFailedOutput(allocator, "native file replay verify is unavailable on freestanding targets");
    }

    var default_base_dir: ?[]u8 = null;
    defer if (default_base_dir) |path| allocator.free(path);

    const base_dir = if (request.base_dir) |value|
        value
    else blk: {
        const resolved = try defaultRuntimeDir(allocator);
        default_base_dir = resolved;
        break :blk resolved;
    };

    const resolution = resolveReplayPath(allocator, request.replay_file, base_dir) catch |err| {
        return buildVerifyFailedOutput(allocator, verifySetupErrorDetail(err));
    };
    defer resolution.deinit(allocator);

    if (!resolution.exists) {
        return buildReplayNotFoundOutput(allocator, resolution);
    }

    if (!std.mem.endsWith(u8, resolution.resolved_path, ".crd")) {
        return buildVerifyFailedOutput(allocator, "replay file must use .crd extension");
    }

    const io = std.Io.Threaded.global_single_threaded.io();
    const replay_bytes = std.Io.Dir.cwd().readFileAlloc(
        io,
        resolution.resolved_path,
        allocator,
        .limited(replay_codec.max_replay_file_bytes),
    ) catch |err| {
        return buildVerifyFailedOutput(allocator, verifyReplayReadErrorDetail(err));
    };
    defer allocator.free(replay_bytes);

    return runVerifyWithReplayBytes(allocator, request, resolution.resolved_path, replay_bytes);
}

fn runVerifyWithReplayBytes(
    allocator: std.mem.Allocator,
    request: VerifyRequest,
    replay_path: []const u8,
    replay_bytes: []const u8,
) !CommandOutput {
    var diagnostic: replay_codec.Diagnostic = .{};
    const payload = replay_codec.inflateReplayFile(allocator, replay_bytes, &diagnostic) catch |err| switch (err) {
        error.InvalidReplay => return buildVerifyFailedOutput(allocator, diagnostic.message()),
        error.OutOfMemory => return err,
    };
    defer allocator.free(payload);
    const replay = replay_codec.decodePayload(allocator, payload, &diagnostic) catch |err| switch (err) {
        error.InvalidReplay => return buildVerifyFailedOutput(allocator, diagnostic.message()),
        error.OutOfMemory => return err,
    };
    defer replay.deinit(allocator);

    const trace_requested = request.trace_rng or request.debug_trace_cdt != null;
    var tick_trace: std.ArrayList(replay_runner.ReplayTickTrace) = .empty;
    defer {
        replay_runner.deinitReplayTickTraceRows(allocator, tick_trace.items);
        tick_trace.deinit(allocator);
    }
    var failure: replay_runner.RunFailure = .{};
    const run_or_err = replay_runner.runReplayWithTrace(
        allocator,
        replay,
        if (trace_requested) &tick_trace else null,
        .{
            .max_ticks = request.max_ticks,
            .trace_rng = trace_requested,
            .trace_timing = request.debug_trace_cdt != null,
            .failure = &failure,
        },
    );
    // A failed run still writes the ticks it simulated, for debugging.
    if (trace_requested and (!std.meta.isError(run_or_err) or tick_trace.items.len > 0)) {
        writeRequestedDebugTraceOutputs(allocator, request, replay_path, replay_bytes, replay, tick_trace.items) catch |trace_err| {
            return buildVerifyFailedOutput(allocator, verifyDebugTraceErrorDetail(trace_err));
        };
    }
    const run = run_or_err catch |err| {
        var detail: std.Io.Writer.Allocating = .init(allocator);
        defer detail.deinit();
        try failure.write(&detail.writer, err);
        return buildVerifyFailedOutput(allocator, detail.written());
    };

    var arena: std.heap.ArenaAllocator = .init(allocator);
    defer arena.deinit();
    const mismatched_fields: []const []const u8 = if (run.complete)
        try replay.result.mismatches(arena.allocator(), &run.result)
    else
        &.{};
    const status: VerifyStatus = if (!run.complete)
        .partial
    else if (mismatched_fields.len > 0)
        .result_mismatch
    else
        .ok;

    var payload_sha256: [64]u8 = undefined;
    hash.sha256HexLower(payload, &payload_sha256);
    const payload_report: VerifyPayload = .{
        .status = status,
        .replay = replay_path,
        .payload_sha256 = &payload_sha256,
        .game_version = replay.game_version,
        .ticks = replay.tickCount(),
        .ticks_simulated = run.ticks_simulated,
        .result = run.result,
        .recorded = replay.result,
        .mismatched_fields = mismatched_fields,
    };
    const report = try std.json.Stringify.valueAlloc(allocator, payload_report, .{});
    defer allocator.free(report);

    if (request.json_out) |json_out_path| {
        writeFileWithParents(json_out_path, report) catch |err| {
            return buildVerifyFailedOutput(allocator, verifyJsonOutErrorDetail(err));
        };
    }

    var stdout_buf: std.Io.Writer.Allocating = .init(allocator);
    defer stdout_buf.deinit();
    const writer = &stdout_buf.writer;
    if (request.output_format == .json) {
        try writer.writeAll(report);
        try writer.writeByte('\n');
    } else {
        if (request.json_out) |json_out_path| try writer.print("json_report={s}\n", .{json_out_path});
        const result = run.result;
        try writer.print(
            "{s}: outcome={s} ticks={d}/{d} elapsed_ms={d} score_xp={d} kills={d} rng_state={d}",
            .{
                @tagName(status),
                @tagName(result.outcome),
                run.ticks_simulated,
                replay.tickCount(),
                result.elapsed_ms,
                result.players()[0].experience,
                result.kills,
                result.rng_state,
            },
        );
        if (result.quest_final_ms) |quest_final_ms| try writer.print(" quest_final_ms={d}", .{quest_final_ms});
        if (mismatched_fields.len > 0) {
            try writer.writeAll("; mismatches=");
            for (mismatched_fields, 0..) |field, index| {
                if (index != 0) try writer.writeByte(',');
                try writer.writeAll(field);
            }
        }
        try writer.writeByte('\n');
    }

    return .{
        .stdout = try stdout_buf.toOwnedSlice(),
        .stderr = try allocator.dupe(u8, ""),
        .exit_code = if (status == .result_mismatch) 3 else 0,
    };
}

fn writeRequestedDebugTraceOutputs(
    allocator: std.mem.Allocator,
    request: VerifyRequest,
    replay_path: []const u8,
    replay_bytes: []const u8,
    replay: replay_codec.Replay,
    tick_trace: []const replay_runner.ReplayTickTrace,
) !void {
    if (builtin.os.tag == .freestanding) {
        return error.UnsupportedTarget;
    }

    if (request.debug_trace_cdt) |trace_path| {
        try cdt_trace.writeReplayTickTraceCdt(
            allocator,
            trace_path,
            replay_path,
            replay_bytes,
            replay,
            tick_trace,
        );
    }
}

fn writeFileWithParents(path: []const u8, bytes: []const u8) !void {
    if (builtin.os.tag == .freestanding) {
        return error.UnsupportedTarget;
    }

    const io = std.Io.Threaded.global_single_threaded.io();
    if (std.fs.path.dirname(path)) |dir| {
        if (dir.len > 0) try std.Io.Dir.cwd().createDirPath(io, dir);
    }
    try std.Io.Dir.cwd().writeFile(io, .{
        .sub_path = path,
        .data = bytes,
    });
}

fn buildReplayNotFoundOutput(
    allocator: std.mem.Allocator,
    resolution: ReplayResolution,
) !CommandOutput {
    var stderr_buf: std.Io.Writer.Allocating = .init(allocator);
    defer stderr_buf.deinit();
    const writer = &stderr_buf.writer;
    try writer.print("replay file not found: {s}", .{resolution.tried_primary});
    if (resolution.tried_secondary) |secondary| {
        try writer.print(" (also tried: {s})", .{secondary});
    }
    try writer.writeByte('\n');

    const stderr = try stderr_buf.toOwnedSlice();
    errdefer allocator.free(stderr);
    const stdout = try allocator.dupe(u8, "");

    return .{
        .stdout = stdout,
        .stderr = stderr,
        .exit_code = 1,
    };
}

fn buildVerifyFailedOutput(
    allocator: std.mem.Allocator,
    detail: []const u8,
) !CommandOutput {
    var stderr_buf: std.Io.Writer.Allocating = .init(allocator);
    defer stderr_buf.deinit();
    const writer = &stderr_buf.writer;
    try writer.print("replay verification failed: {s}\n", .{detail});

    const stderr = try stderr_buf.toOwnedSlice();
    errdefer allocator.free(stderr);
    const stdout = try allocator.dupe(u8, "");

    return .{
        .stdout = stdout,
        .stderr = stderr,
        .exit_code = 1,
    };
}

fn buildInvalidVerifyArgsOutput(
    allocator: std.mem.Allocator,
    detail: []const u8,
) !CommandOutput {
    var stderr_buf: std.Io.Writer.Allocating = .init(allocator);
    defer stderr_buf.deinit();
    const writer = &stderr_buf.writer;
    try writer.print("invalid replay verify args: {s}\n", .{detail});

    const stderr = try stderr_buf.toOwnedSlice();
    errdefer allocator.free(stderr);
    const stdout = try allocator.dupe(u8, "");

    return .{
        .stdout = stdout,
        .stderr = stderr,
        .exit_code = 1,
    };
}

fn verifySetupErrorDetail(err: anyerror) []const u8 {
    return switch (err) {
        error.AccessDenied => "unable to inspect replay path: access denied",
        error.OutOfMemory => "native replay verifier ran out of memory while resolving paths",
        else => @errorName(err),
    };
}

fn verifyReplayReadErrorDetail(err: anyerror) []const u8 {
    return switch (err) {
        error.FileNotFound => "replay file not found",
        error.AccessDenied => "unable to read replay file: access denied",
        error.FileTooBig => "replay zstd envelope exceeds max file size",
        error.PayloadTooLarge => "replay payload exceeds max decompressed size",
        error.OutOfMemory => "native replay verifier ran out of memory while reading replay",
        else => @errorName(err),
    };
}

fn verifyDebugTraceErrorDetail(err: anyerror) []const u8 {
    return switch (err) {
        error.UnsupportedTarget => "debug trace output is unavailable on this target",
        error.AccessDenied => "unable to write debug trace output: access denied",
        error.OutOfMemory => "native replay verifier ran out of memory while writing debug trace output",
        else => @errorName(err),
    };
}

fn verifyJsonOutErrorDetail(err: anyerror) []const u8 {
    return switch (err) {
        error.UnsupportedTarget => "json output file is unavailable on this target",
        error.AccessDenied => "unable to write replay verify JSON: access denied",
        error.OutOfMemory => "native replay verifier ran out of memory while writing JSON",
        else => @errorName(err),
    };
}

fn parseNativeSubset(args: []const []const u8) ParseOutcome {
    var replay_file: ?[]const u8 = null;
    var request: VerifyRequest = .{
        .replay_file = "",
    };

    var idx: usize = 0;
    while (idx < args.len) : (idx += 1) {
        const arg = args[idx];

        if (std.mem.eql(u8, arg, "--strict-events")) {
            return .{ .invalid = "--strict-events" };
        }

        if (std.mem.eql(u8, arg, "--trace-rng")) {
            request.trace_rng = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--max-ticks")) {
            if (idx + 1 >= args.len) return .{ .invalid = "missing value for --max-ticks" };
            idx += 1;
            const parsed = std.fmt.parseInt(i64, args[idx], 10) catch return .{ .invalid = "invalid --max-ticks value" };
            if (parsed < 0) return .{ .invalid = "invalid --max-ticks value" };
            request.max_ticks = @intCast(parsed);
            continue;
        }
        if (std.mem.startsWith(u8, arg, "--max-ticks=")) {
            const parsed = std.fmt.parseInt(i64, arg["--max-ticks=".len..], 10) catch return .{ .invalid = "invalid --max-ticks value" };
            if (parsed < 0) return .{ .invalid = "invalid --max-ticks value" };
            request.max_ticks = @intCast(parsed);
            continue;
        }
        if (std.mem.eql(u8, arg, "--debug-trace-cdt")) {
            if (idx + 1 >= args.len) return .{ .invalid = "missing value for --debug-trace-cdt" };
            idx += 1;
            request.debug_trace_cdt = args[idx];
            continue;
        }
        if (std.mem.startsWith(u8, arg, "--debug-trace-cdt=")) {
            request.debug_trace_cdt = arg["--debug-trace-cdt=".len..];
            continue;
        }
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

        if (std.mem.eql(u8, arg, "--json-out")) {
            if (idx + 1 >= args.len) return .{ .invalid = "missing value for --json-out" };
            idx += 1;
            request.json_out = args[idx];
            continue;
        }
        if (std.mem.startsWith(u8, arg, "--json-out=")) {
            request.json_out = arg["--json-out=".len..];
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
    request.replay_file = replay;
    return .{ .ok = request };
}

fn parseOutputFormat(raw: []const u8) ?OutputFormat {
    if (std.mem.eql(u8, raw, "human")) return .human;
    if (std.mem.eql(u8, raw, "json")) return .json;
    return null;
}

fn resolveReplayPath(
    allocator: std.mem.Allocator,
    replay_file: []const u8,
    base_dir: []const u8,
) !ReplayResolution {
    if (builtin.os.tag == .freestanding) {
        return error.UnsupportedTarget;
    }

    const primary_exists = try isFile(replay_file);
    if (primary_exists) {
        const resolved_path = try allocator.dupe(u8, replay_file);
        errdefer allocator.free(resolved_path);
        const tried_primary = try allocator.dupe(u8, replay_file);
        errdefer allocator.free(tried_primary);

        return .{
            .resolved_path = resolved_path,
            .tried_primary = tried_primary,
            .tried_secondary = null,
            .exists = true,
        };
    }

    if (!std.fs.path.isAbsolute(replay_file) and isSingleSegmentPath(replay_file)) {
        const secondary = try std.fs.path.join(allocator, &.{ base_dir, "replays", replay_file });
        errdefer allocator.free(secondary);
        const secondary_exists = try isFile(secondary);

        const resolved_path = if (secondary_exists)
            try allocator.dupe(u8, secondary)
        else
            try allocator.dupe(u8, replay_file);
        errdefer allocator.free(resolved_path);
        const tried_primary = try allocator.dupe(u8, replay_file);
        errdefer allocator.free(tried_primary);

        return .{
            .resolved_path = resolved_path,
            .tried_primary = tried_primary,
            .tried_secondary = secondary,
            .exists = secondary_exists,
        };
    }

    const resolved_path = try allocator.dupe(u8, replay_file);
    errdefer allocator.free(resolved_path);
    const tried_primary = try allocator.dupe(u8, replay_file);
    errdefer allocator.free(tried_primary);

    return .{
        .resolved_path = resolved_path,
        .tried_primary = tried_primary,
        .tried_secondary = null,
        .exists = false,
    };
}

fn isSingleSegmentPath(path: []const u8) bool {
    return std.mem.indexOfAny(u8, path, "/\\") == null;
}

fn isFile(path: []const u8) !bool {
    if (builtin.os.tag == .freestanding) {
        return error.UnsupportedTarget;
    }

    const io = std.Io.Threaded.global_single_threaded.io();
    const file = std.Io.Dir.cwd().openFile(io, path, .{}) catch |err| switch (err) {
        error.FileNotFound, error.NotDir, error.IsDir => return false,
        else => return err,
    };
    defer file.close(io);
    return true;
}

fn defaultRuntimeDir(allocator: std.mem.Allocator) ![]u8 {
    if (builtin.os.tag == .freestanding) {
        return error.UnsupportedTarget;
    }
    return (try runtime_paths.defaultRuntimeDir(allocator)) orelse allocator.dupe(u8, ".");
}

test "parse native subset for reference verify options" {
    const parsed = parseNativeSubset(&.{
        "survival_20260224_041009_score76661.crd",
        "--format",
        "json",
        "--json-out",
        "verify.json",
    });
    const req = switch (parsed) {
        .ok => |request| request,
        else => return error.TestExpectedNativeRequest,
    };

    try std.testing.expectEqualStrings("survival_20260224_041009_score76661.crd", req.replay_file);
    try std.testing.expect(req.output_format == .json);
    try std.testing.expect(req.json_out != null);
    try std.testing.expectEqualStrings("verify.json", req.json_out.?);
}

test "parse native subset accepts debug trace cdt option" {
    const parsed = parseNativeSubset(&.{
        "survival_20260224_041009_score76661.crd",
        "--debug-trace-cdt",
        "trace.cdt",
    });
    const req = switch (parsed) {
        .ok => |request| request,
        else => return error.TestExpectedNativeRequest,
    };
    try std.testing.expect(req.debug_trace_cdt != null);
    try std.testing.expectEqualStrings("trace.cdt", req.debug_trace_cdt.?);
}

test "parse native subset reports missing debug trace cdt argument" {
    const parsed = parseNativeSubset(&.{
        "survival_20260224_041009_score76661.crd",
        "--debug-trace-cdt",
    });
    switch (parsed) {
        .invalid => |detail| try std.testing.expectEqualStrings("missing value for --debug-trace-cdt", detail),
        else => return error.TestExpectedInvalidOption,
    }
}

test "parse native subset accepts trace rng option" {
    const parsed = parseNativeSubset(&.{
        "survival_20260224_041009_score76661.crd",
        "--trace-rng",
    });
    switch (parsed) {
        .ok => |request| try std.testing.expect(request.trace_rng),
        else => return error.TestExpectedValidOption,
    }
}

test "parse native subset reports unknown option as invalid" {
    const parsed = parseNativeSubset(&.{
        "survival_20260224_041009_score76661.crd",
        "--unknown-option",
    });
    switch (parsed) {
        .invalid => |detail| try std.testing.expectEqualStrings("--unknown-option", detail),
        else => return error.TestExpectedInvalidOption,
    }
}

test "parse native subset reports removed strict events option as invalid" {
    const parsed = parseNativeSubset(&.{
        "survival_20260224_041009_score76661.crd",
        "--strict-events",
    });
    switch (parsed) {
        .invalid => |detail| try std.testing.expectEqualStrings("--strict-events", detail),
        else => return error.TestExpectedInvalidOption,
    }
}

test "parse native subset reports removed lenient events option as invalid" {
    const parsed = parseNativeSubset(&.{
        "survival_20260224_041009_score76661.crd",
        "--lenient-events",
    });
    switch (parsed) {
        .invalid => |detail| try std.testing.expectEqualStrings("--lenient-events", detail),
        else => return error.TestExpectedInvalidOption,
    }
}

test "parse native subset accepts max ticks option" {
    const parsed = parseNativeSubset(&.{
        "survival_20260224_041009_score76661.crd",
        "--max-ticks=1000",
    });
    switch (parsed) {
        .ok => |request| try std.testing.expectEqual(@as(?usize, 1000), request.max_ticks),
        else => return error.TestExpectedValidOption,
    }
}

test "parse native subset rejects invalid max ticks value" {
    const parsed = parseNativeSubset(&.{
        "survival_20260224_041009_score76661.crd",
        "--max-ticks=-1",
    });
    switch (parsed) {
        .invalid => |detail| try std.testing.expectEqualStrings("invalid --max-ticks value", detail),
        else => return error.TestExpectedInvalidOption,
    }
}

test "parse native subset reports removed submitted score option as invalid" {
    const parsed = parseNativeSubset(&.{
        "survival_20260224_041009_score76661.crd",
        "--submitted-score=76661",
    });
    switch (parsed) {
        .invalid => |detail| try std.testing.expectEqualStrings("--submitted-score=76661", detail),
        else => return error.TestExpectedInvalidOption,
    }
}

test "replay verify file and output errors use user-facing details" {
    try std.testing.expectEqualStrings(
        "native replay verifier ran out of memory while resolving paths",
        verifySetupErrorDetail(error.OutOfMemory),
    );
    try std.testing.expectEqualStrings(
        "replay payload exceeds max decompressed size",
        verifyReplayReadErrorDetail(error.PayloadTooLarge),
    );
    try std.testing.expectEqualStrings(
        "debug trace output is unavailable on this target",
        verifyDebugTraceErrorDetail(error.UnsupportedTarget),
    );
    try std.testing.expectEqualStrings(
        "unable to write replay verify JSON: access denied",
        verifyJsonOutErrorDetail(error.AccessDenied),
    );
    try std.testing.expectEqualStrings(
        "FileBusy",
        verifyReplayReadErrorDetail(error.FileBusy),
    );
}

fn verifyBytes(replay_bytes: []const u8, max_ticks: ?usize) !CommandOutput {
    return runReplayVerifyBytesJson(std.testing.allocator, "smoke.crd", replay_bytes, max_ticks);
}

test "verify reports ok, the payload hash and both results for a matching replay" {
    const allocator = std.testing.allocator;
    const replay_bytes = try replay_runner.buildSmokeTestReplayFile(allocator);
    defer allocator.free(replay_bytes);

    const output = try verifyBytes(replay_bytes, null);
    defer output.deinit(allocator);
    try std.testing.expectEqual(@as(u8, 0), output.exit_code);
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, output.stdout, .{});
    defer parsed.deinit();
    const object = parsed.value.object;
    try std.testing.expectEqual(@as(i64, 3), object.get("schema_version").?.integer);
    try std.testing.expectEqualStrings("ok", object.get("status").?.string);
    try std.testing.expectEqual(@as(usize, 64), object.get("payload_sha256").?.string.len);
    try std.testing.expectEqual(@as(i64, 2), object.get("ticks").?.integer);
    try std.testing.expectEqual(@as(i64, 2), object.get("ticks_simulated").?.integer);
    try std.testing.expectEqualStrings("incomplete", object.get("result").?.object.get("outcome").?.string);
    try std.testing.expectEqual(@as(usize, 0), object.get("mismatched_fields").?.array.items.len);
}

test "verify reports a result mismatch with exit code 3 and a partial prefix without comparison" {
    const allocator = std.testing.allocator;
    const payload = try replay_runner.buildSmokeTestReplayPayload(allocator);
    defer allocator.free(payload);
    var diagnostic: replay_codec.Diagnostic = .{};
    var replay = try replay_codec.decodePayload(allocator, payload, &diagnostic);
    defer replay.deinit(allocator);
    replay.result.kills = 7;
    const tampered = try replay_codec.encodePayload(allocator, replay);
    defer allocator.free(tampered);
    const tampered_file = try replay_codec.wrapZstdFilePayload(allocator, tampered);
    defer allocator.free(tampered_file);

    const mismatch = try verifyBytes(tampered_file, null);
    defer mismatch.deinit(allocator);
    try std.testing.expectEqual(@as(u8, 3), mismatch.exit_code);
    try std.testing.expect(std.mem.indexOf(u8, mismatch.stdout, "\"status\":\"result_mismatch\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, mismatch.stdout, "\"mismatched_fields\":[\"kills\"]") != null);

    const partial = try verifyBytes(tampered_file, 1);
    defer partial.deinit(allocator);
    try std.testing.expectEqual(@as(u8, 0), partial.exit_code);
    try std.testing.expect(std.mem.indexOf(u8, partial.stdout, "\"status\":\"partial\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, partial.stdout, "\"ticks_simulated\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, partial.stdout, "\"mismatched_fields\":[]") != null);
}

test "verify failures name the invalid field" {
    const allocator = std.testing.allocator;
    const not_msgpack = try replay_codec.wrapZstdFilePayload(allocator, "not msgpack");
    defer allocator.free(not_msgpack);
    const output = try verifyBytes(not_msgpack, null);
    defer output.deinit(allocator);
    try std.testing.expectEqual(@as(u8, 1), output.exit_code);
    try std.testing.expectEqualStrings("", output.stdout);
    try std.testing.expect(std.mem.startsWith(u8, output.stderr, "replay verification failed: "));

    const raw = try verifyBytes("raw bytes", null);
    defer raw.deinit(allocator);
    try std.testing.expectEqualStrings("replay verification failed: replay must use the zstd envelope\n", raw.stderr);
}
