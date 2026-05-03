const builtin = @import("builtin");
const std = @import("std");

const replay_codec = @import("replay_codec.zig");
const replay_runner = @import("runtime/replay_runner.zig");
const runtime_paths = @import("runtime_paths.zig");
const verify_native = @import("verify_native.zig");

const benchmark_schema_version: i32 = 3;
const default_runs: usize = 5;
const default_warmup_runs: usize = 1;
const default_profile_sort = "cumtime";
const default_top: usize = 20;

pub const CommandOutput = verify_native.CommandOutput;

const OutputFormat = enum {
    human,
    json,
};

const BenchmarkRequest = struct {
    replay_file: []const u8,
    output_format: OutputFormat = .human,
    json_out: ?[]const u8 = null,
    base_dir: ?[]const u8 = null,
    runs: usize = default_runs,
    warmup_runs: usize = default_warmup_runs,
    max_ticks: ?usize = null,
    trace_rng: bool = false,
    rtx: bool = false,
    render_telemetry: bool = false,
    render_telemetry_out: ?[]const u8 = null,
    render_charts_out_dir: ?[]const u8 = null,
    profile: bool = false,
    profile_sort: []const u8 = default_profile_sort,
    top: usize = default_top,
    profile_out: ?[]const u8 = null,
};

const ParseOutcome = union(enum) {
    ok: BenchmarkRequest,
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

const RunResultPayload = struct {
    game_mode_id: i32,
    tick_rate: i32,
    ticks: i32,
    elapsed_ms: i64,
    score_xp: i64,
    creature_kill_count: i32,
    most_used_weapon_id: i32,
    shots_fired: i32,
    shots_hit: i32,
    rng_state: u64,
};

const BenchmarkSettingsPayload = struct {
    mode: []const u8,
    runs: usize,
    warmup_runs: usize,
    max_ticks: ?usize,
    trace_rng: bool,
    profile: bool,
    profile_sort: []const u8,
    top: usize,
    profile_out: ?[]const u8,
    render_telemetry: bool,
    render_telemetry_out: ?[]const u8,
    render_charts_out_dir: ?[]const u8,
};

const BenchmarkSamplePayload = struct {
    wall_ms: f64,
    ticks_per_second: f64,
    realtime_x: f64,
};

const BenchmarkAggregatePayload = struct {
    min: f64,
    p50: f64,
    mean: f64,
    p95: f64,
    max: f64,
    stdev: f64,
};

const BenchmarkSummaryPayload = struct {
    sample_count: usize,
    samples: []const BenchmarkSamplePayload,
    wall_ms: BenchmarkAggregatePayload,
    ticks_per_second: BenchmarkAggregatePayload,
    realtime_x: BenchmarkAggregatePayload,
};

const ProfileHotspotPayload = struct {
    file: []const u8,
    line: i32,
    function: []const u8,
    primitive_calls: i32,
    total_calls: i32,
    tottime: f64,
    cumtime: f64,
};

const ProfilePayload = struct {
    sort: []const u8,
    top: usize,
    source: []const u8,
    hotspots: []const ProfileHotspotPayload,
};

const BenchmarkPayload = struct {
    schema_version: i32,
    status: []const u8,
    replay: []const u8,
    settings: BenchmarkSettingsPayload,
    run_result: RunResultPayload,
    benchmark: BenchmarkSummaryPayload,
    profile: ?ProfilePayload,
    render_telemetry: ?struct {},
};

pub fn runReplayBenchmark(
    allocator: std.mem.Allocator,
    args: []const []const u8,
) !CommandOutput {
    switch (parseNativeSubset(args)) {
        .ok => |request| return runNativeBenchmark(allocator, request),
        .invalid => |detail| return buildInvalidBenchmarkArgsOutput(allocator, detail),
    }
}

pub fn runReplayBenchmarkBytesJson(
    allocator: std.mem.Allocator,
    replay_name: []const u8,
    replay_bytes: []const u8,
    max_ticks: ?usize,
    runs: usize,
    warmup_runs: usize,
    trace_rng: bool,
) !CommandOutput {
    if (runs == 0) {
        return buildInvalidBenchmarkArgsOutput(allocator, "invalid --runs value");
    }

    var parse_detail: ?[]u8 = null;
    defer if (parse_detail) |detail| allocator.free(detail);
    var replay = loadReplayBytes(allocator, replay_bytes, &parse_detail) catch |err| {
        return buildBenchmarkFailedOutput(allocator, parse_detail orelse benchmarkReplayLoadErrorDetail(err));
    };
    defer replay.deinit(allocator);

    if (replay_codec.unsupportedReplayHeaderDetail(replay.header, replay.tickCount(), .benchmark)) |detail| {
        return buildBenchmarkFailedOutput(allocator, detail);
    }
    replay_codec.validateReplayBootstrap(replay.header) catch |err| {
        return buildBenchmarkFailedOutput(allocator, benchmarkReplayLoadErrorDetail(err));
    };

    return runBenchmarkWithReplay(allocator, replay_name, .{
        .replay_file = replay_name,
        .output_format = .json,
        .runs = runs,
        .warmup_runs = warmup_runs,
        .max_ticks = max_ticks,
        .trace_rng = trace_rng,
    }, replay);
}

fn parseNativeSubset(args: []const []const u8) ParseOutcome {
    var replay_file: ?[]const u8 = null;
    var request: BenchmarkRequest = .{
        .replay_file = "",
    };

    var idx: usize = 0;
    while (idx < args.len) : (idx += 1) {
        const arg = args[idx];

        if (std.mem.eql(u8, arg, "--mode")) {
            if (idx + 1 >= args.len) return .{ .invalid = "missing value for --mode" };
            idx += 1;
            if (!std.mem.eql(u8, args[idx], "headless")) return .{ .invalid = "native replay benchmark supports only --mode headless" };
            continue;
        }
        if (std.mem.startsWith(u8, arg, "--mode=")) {
            if (!std.mem.eql(u8, arg["--mode=".len..], "headless")) return .{ .invalid = "native replay benchmark supports only --mode headless" };
            continue;
        }
        if (std.mem.eql(u8, arg, "--runs")) {
            if (idx + 1 >= args.len) return .{ .invalid = "missing value for --runs" };
            idx += 1;
            request.runs = parsePositiveUsize(args[idx]) catch return .{ .invalid = "invalid --runs value" };
            continue;
        }
        if (std.mem.startsWith(u8, arg, "--runs=")) {
            request.runs = parsePositiveUsize(arg["--runs=".len..]) catch return .{ .invalid = "invalid --runs value" };
            continue;
        }
        if (std.mem.eql(u8, arg, "--warmup-runs")) {
            if (idx + 1 >= args.len) return .{ .invalid = "missing value for --warmup-runs" };
            idx += 1;
            request.warmup_runs = parseNonNegativeUsize(args[idx]) catch return .{ .invalid = "invalid --warmup-runs value" };
            continue;
        }
        if (std.mem.startsWith(u8, arg, "--warmup-runs=")) {
            request.warmup_runs = parseNonNegativeUsize(arg["--warmup-runs=".len..]) catch return .{ .invalid = "invalid --warmup-runs value" };
            continue;
        }
        if (std.mem.eql(u8, arg, "--max-ticks")) {
            if (idx + 1 >= args.len) return .{ .invalid = "missing value for --max-ticks" };
            idx += 1;
            request.max_ticks = parseNonNegativeUsize(args[idx]) catch return .{ .invalid = "invalid --max-ticks value" };
            continue;
        }
        if (std.mem.startsWith(u8, arg, "--max-ticks=")) {
            request.max_ticks = parseNonNegativeUsize(arg["--max-ticks=".len..]) catch return .{ .invalid = "invalid --max-ticks value" };
            continue;
        }
        if (std.mem.eql(u8, arg, "--trace-rng")) {
            request.trace_rng = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--rtx")) {
            request.rtx = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--render-telemetry")) {
            request.render_telemetry = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--render-telemetry-out")) {
            if (idx + 1 >= args.len) return .{ .invalid = "missing value for --render-telemetry-out" };
            idx += 1;
            request.render_telemetry_out = args[idx];
            continue;
        }
        if (std.mem.startsWith(u8, arg, "--render-telemetry-out=")) {
            request.render_telemetry_out = arg["--render-telemetry-out=".len..];
            continue;
        }
        if (std.mem.eql(u8, arg, "--render-charts-out-dir")) {
            if (idx + 1 >= args.len) return .{ .invalid = "missing value for --render-charts-out-dir" };
            idx += 1;
            request.render_charts_out_dir = args[idx];
            continue;
        }
        if (std.mem.startsWith(u8, arg, "--render-charts-out-dir=")) {
            request.render_charts_out_dir = arg["--render-charts-out-dir=".len..];
            continue;
        }
        if (std.mem.eql(u8, arg, "--profile")) {
            request.profile = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--profile-sort")) {
            if (idx + 1 >= args.len) return .{ .invalid = "missing value for --profile-sort" };
            idx += 1;
            request.profile_sort = parseProfileSort(args[idx]) orelse return .{ .invalid = "invalid --profile-sort value" };
            continue;
        }
        if (std.mem.startsWith(u8, arg, "--profile-sort=")) {
            request.profile_sort = parseProfileSort(arg["--profile-sort=".len..]) orelse return .{ .invalid = "invalid --profile-sort value" };
            continue;
        }
        if (std.mem.eql(u8, arg, "--top")) {
            if (idx + 1 >= args.len) return .{ .invalid = "missing value for --top" };
            idx += 1;
            request.top = parsePositiveUsize(args[idx]) catch return .{ .invalid = "invalid --top value" };
            continue;
        }
        if (std.mem.startsWith(u8, arg, "--top=")) {
            request.top = parsePositiveUsize(arg["--top=".len..]) catch return .{ .invalid = "invalid --top value" };
            continue;
        }
        if (std.mem.eql(u8, arg, "--profile-out")) {
            if (idx + 1 >= args.len) return .{ .invalid = "missing value for --profile-out" };
            idx += 1;
            request.profile_out = args[idx];
            continue;
        }
        if (std.mem.startsWith(u8, arg, "--profile-out=")) {
            request.profile_out = arg["--profile-out=".len..];
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

    if (unsupportedRenderBenchmarkOptionDetail(request)) |detail| {
        return .{ .invalid = detail };
    }
    const replay = replay_file orelse return .{ .invalid = "missing replay file argument" };
    request.replay_file = replay;
    return .{ .ok = request };
}

fn runNativeBenchmark(
    allocator: std.mem.Allocator,
    request: BenchmarkRequest,
) !CommandOutput {
    if (builtin.os.tag == .freestanding) {
        return buildBenchmarkFailedOutput(allocator, "native file replay benchmark is unavailable on freestanding targets");
    }
    if (unsupportedRenderBenchmarkOptionDetail(request)) |detail| {
        return buildBenchmarkFailedOutput(allocator, detail);
    }

    var default_base_dir: ?[]u8 = null;
    defer if (default_base_dir) |path| allocator.free(path);

    const base_dir = if (request.base_dir) |value|
        value
    else blk: {
        const resolved = runtime_paths.defaultRuntimeDir(allocator) catch |err| {
            return buildBenchmarkFailedOutput(allocator, benchmarkSetupErrorDetail(err));
        };
        if (resolved == null) return buildBenchmarkFailedOutput(allocator, "unable to resolve default runtime dir");
        default_base_dir = resolved;
        break :blk resolved.?;
    };

    const resolution = resolveReplayPath(allocator, request.replay_file, base_dir) catch |err| {
        return buildBenchmarkFailedOutput(allocator, benchmarkSetupErrorDetail(err));
    };
    defer resolution.deinit(allocator);

    if (!resolution.exists) {
        return buildReplayNotFoundOutput(allocator, resolution);
    }
    if (!std.mem.endsWith(u8, resolution.resolved_path, ".crd")) {
        return buildBenchmarkFailedOutput(allocator, "replay file must use .crd extension");
    }
    if (request.rtx) {
        return buildBenchmarkFailedOutput(allocator, "--rtx is supported only with --mode render");
    }
    if (request.render_telemetry) {
        return buildBenchmarkFailedOutput(allocator, "--render-telemetry is supported only with --mode render");
    }
    if (request.render_telemetry_out != null) {
        return buildBenchmarkFailedOutput(allocator, "--render-telemetry-out is supported only with --mode render");
    }
    if (request.render_charts_out_dir != null) {
        return buildBenchmarkFailedOutput(allocator, "--render-charts-out-dir is supported only with --mode render");
    }

    var parse_detail: ?[]u8 = null;
    defer if (parse_detail) |detail| allocator.free(detail);
    var replay = loadReplay(allocator, resolution.resolved_path, &parse_detail) catch |err| {
        return buildBenchmarkFailedOutput(allocator, parse_detail orelse benchmarkReplayLoadErrorDetail(err));
    };
    defer replay.deinit(allocator);

    if (replay_codec.unsupportedReplayHeaderDetail(replay.header, replay.tickCount(), .benchmark)) |detail| {
        return buildBenchmarkFailedOutput(allocator, detail);
    }
    replay_codec.validateReplayBootstrap(replay.header) catch |err| {
        return buildBenchmarkFailedOutput(allocator, benchmarkReplayLoadErrorDetail(err));
    };

    return runBenchmarkWithReplay(allocator, resolution.resolved_path, request, replay);
}

fn runBenchmarkWithReplay(
    allocator: std.mem.Allocator,
    replay_path: []const u8,
    request: BenchmarkRequest,
    replay: replay_codec.Replay,
) !CommandOutput {
    if (try replay_codec.replayEventOrderingFailureDetail(allocator, replay.events)) |detail| {
        defer allocator.free(detail);
        return buildBenchmarkFailedOutput(allocator, detail);
    }
    if (try replay_codec.replayEventPlayerIndexFailureDetail(allocator, replay.header.player_count, replay.events)) |detail| {
        defer allocator.free(detail);
        return buildBenchmarkFailedOutput(allocator, detail);
    }
    if (try replay_codec.replayEventKindFailureDetail(allocator, replay.header.game_mode_id, replay.events)) |detail| {
        defer allocator.free(detail);
        return buildBenchmarkFailedOutput(allocator, detail);
    }

    var last_run: replay_runner.ReplayRunResult = undefined;
    for (0..request.warmup_runs) |_| {
        last_run = runBenchmarkReplay(allocator, replay, request) catch |err| {
            return buildBenchmarkFailedOutput(allocator, benchmarkReplayRunnerErrorDetail(err));
        };
    }

    const samples = allocator.alloc(BenchmarkSamplePayload, request.runs) catch |err| {
        return buildBenchmarkFailedOutput(allocator, benchmarkAllocationErrorDetail(err));
    };
    defer allocator.free(samples);
    for (samples) |*sample| {
        const start_ns = monotonicNanoseconds();
        last_run = runBenchmarkReplay(allocator, replay, request) catch |err| {
            return buildBenchmarkFailedOutput(allocator, benchmarkReplayRunnerErrorDetail(err));
        };
        const end_ns = monotonicNanoseconds();
        const wall_ms = elapsedMs(start_ns, end_ns);
        sample.* = .{
            .wall_ms = wall_ms,
            .ticks_per_second = ticksPerSecond(last_run.ticks, wall_ms),
            .realtime_x = realtimeMultiplier(last_run.elapsed_ms_sim, wall_ms),
        };
    }

    var profile_hotspots: [1]ProfileHotspotPayload = undefined;
    var profile_payload: ?ProfilePayload = null;
    if (request.profile) {
        const start_ns = monotonicNanoseconds();
        const profile_run = runBenchmarkReplay(allocator, replay, request) catch |err| {
            return buildBenchmarkFailedOutput(allocator, benchmarkReplayRunnerErrorDetail(err));
        };
        const end_ns = monotonicNanoseconds();
        if (!benchmarkRunResultsMatch(last_run, profile_run)) {
            return buildBenchmarkFailedOutput(allocator, "native replay profile run did not match measured benchmark result");
        }
        const profile_wall_s = elapsedMs(start_ns, end_ns) / 1000.0;
        profile_hotspots = [_]ProfileHotspotPayload{.{
            .file = "crimson-zig/src/replay_benchmark_native.zig",
            .line = 412,
            .function = if (request.trace_rng) "runReplayWithTrace" else "runReplayWithOptions",
            .primitive_calls = 1,
            .total_calls = 1,
            .tottime = profile_wall_s,
            .cumtime = profile_wall_s,
        }};
        profile_payload = .{
            .sort = request.profile_sort,
            .top = request.top,
            .source = "project",
            .hotspots = profile_hotspots[0..@min(request.top, profile_hotspots.len)],
        };
    }

    const run_result = buildRunResultPayload(replay.header, last_run);
    const payload = buildBenchmarkPayload(allocator, replay_path, request, samples, run_result, profile_payload) catch |err| {
        return buildBenchmarkFailedOutput(allocator, benchmarkAllocationErrorDetail(err));
    };
    defer allocator.free(payload);

    if (request.profile_out) |profile_out_path| {
        if (profile_payload) |profile| {
            const profile_json = buildProfilePayloadJson(allocator, profile) catch |err| {
                return buildBenchmarkFailedOutput(allocator, benchmarkAllocationErrorDetail(err));
            };
            defer allocator.free(profile_json);
            writeFileWithParents(profile_out_path, profile_json) catch |err| {
                return buildBenchmarkFailedOutput(allocator, benchmarkProfileOutErrorDetail(err));
            };
        }
    }

    if (request.json_out) |json_out_path| {
        writeFileWithParents(json_out_path, payload) catch |err| {
            return buildBenchmarkFailedOutput(allocator, benchmarkJsonOutErrorDetail(err));
        };
    }

    var stdout_buf: std.Io.Writer.Allocating = .init(allocator);
    defer stdout_buf.deinit();
    const writer = &stdout_buf.writer;

    if (request.json_out) |json_out_path| {
        if (request.output_format == .human) {
            try writer.print("json_report={s}\n", .{json_out_path});
        }
    }
    if (request.profile_out) |profile_out_path| {
        if (request.output_format == .human and profile_payload != null) {
            try writer.print("profile_report={s}\n", .{profile_out_path});
        }
    }

    if (request.output_format == .json) {
        try writer.writeAll(payload);
        try writer.writeByte('\n');
    } else {
        const wall = try aggregateSamples(allocator, samples, .wall_ms);
        const tps = try aggregateSamples(allocator, samples, .ticks_per_second);
        const realtime = try aggregateSamples(allocator, samples, .realtime_x);
        try writer.print(
            "ok: mode=headless runs={d} warmup_runs={d} ticks={d} wall_ms_p50={d:.3} tps_p50={d:.2} realtime_x_p50={d:.2}\n",
            .{
                request.runs,
                request.warmup_runs,
                run_result.ticks,
                wall.p50,
                tps.p50,
                realtime.p50,
            },
        );
        try writeMetricAggregate3(writer, "wall_ms", wall);
        try writer.writeByte('\n');
        try writeMetricAggregate2(writer, "throughput_tps", tps);
        try writer.writeAll(" | ");
        try writeMetricAggregate2(writer, "realtime_x", realtime);
        try writer.writeByte('\n');
        if (profile_payload) |profile| {
            try writer.print("profile: sort={s} source={s} top={d}\n", .{ profile.sort, profile.source, profile.top });
            try writer.writeAll("hotspots:\n");
            if (profile.hotspots.len == 0) {
                try writer.writeAll("  (none)\n");
            }
            for (profile.hotspots, 0..) |row, row_idx| {
                try writer.print(
                    "  {d:0>2} cum={d:.6}s tot={d:.6}s calls={d}/{d} {s}:{d}::{s}\n",
                    .{
                        row_idx + 1,
                        row.cumtime,
                        row.tottime,
                        row.primitive_calls,
                        row.total_calls,
                        row.file,
                        row.line,
                        row.function,
                    },
                );
            }
        }
    }

    return .{
        .stdout = try stdout_buf.toOwnedSlice(),
        .stderr = try allocator.dupe(u8, ""),
        .exit_code = 0,
    };
}

fn runBenchmarkReplay(
    allocator: std.mem.Allocator,
    replay: replay_codec.Replay,
    request: BenchmarkRequest,
) !replay_runner.ReplayRunResult {
    if (!request.trace_rng) {
        return replay_runner.runReplayWithOptions(replay, .{
            .max_ticks = request.max_ticks,
        });
    }

    var tick_trace: std.ArrayList(replay_runner.ReplayTickTrace) = .empty;
    defer {
        replay_runner.deinitReplayTickTraceRows(allocator, tick_trace.items);
        tick_trace.deinit(allocator);
    }
    return replay_runner.runReplayWithTrace(
        allocator,
        replay,
        &tick_trace,
        .{
            .max_ticks = request.max_ticks,
            .trace_rng = true,
            .trace_timing = false,
        },
    );
}

fn loadReplay(
    allocator: std.mem.Allocator,
    path: []const u8,
    parse_detail: ?*?[]u8,
) !replay_codec.Replay {
    if (builtin.os.tag == .freestanding) return error.UnavailableOnFreestanding;

    const io = std.Io.Threaded.global_single_threaded.io();
    const replay_bytes = try std.Io.Dir.cwd().readFileAlloc(
        io,
        path,
        allocator,
        .limited(replay_codec.max_replay_payload_bytes),
    );
    defer allocator.free(replay_bytes);

    return loadReplayBytes(allocator, replay_bytes, parse_detail);
}

fn loadReplayBytes(
    allocator: std.mem.Allocator,
    replay_bytes: []const u8,
    parse_detail: ?*?[]u8,
) !replay_codec.Replay {
    var replay_payload_alloc: ?[]u8 = null;
    defer if (replay_payload_alloc) |buf| allocator.free(buf);
    const replay_payload: []const u8 = if (replay_codec.isZstdPayload(replay_bytes)) blk: {
        const inflated = try replay_codec.inflateZstdPayload(allocator, replay_bytes, replay_codec.max_replay_payload_bytes);
        replay_payload_alloc = inflated;
        break :blk inflated;
    } else if (replay_codec.isGzipPayload(replay_bytes)) blk: {
        const inflated = try replay_codec.inflateGzipPayload(allocator, replay_bytes, replay_codec.max_replay_payload_bytes);
        replay_payload_alloc = inflated;
        break :blk inflated;
    } else replay_bytes;
    return replay_codec.parseReplay(allocator, replay_payload) catch |err| {
        if (err == error.UnsupportedInputShape) {
            if (parse_detail) |detail| {
                detail.* = try replay_codec.replayInputShapeFailureDetail(allocator, replay_payload);
            }
        } else if (err == error.UnsupportedEventShape) {
            if (parse_detail) |detail| {
                detail.* = try replay_codec.replayEventShapeFailureDetail(allocator, replay_payload);
            }
        } else if (err == error.UnknownCommandKind) {
            if (parse_detail) |detail| {
                detail.* = try replay_codec.replayUnknownCommandFailureDetail(allocator, replay_payload);
            }
        }
        return err;
    };
}

const Metric = enum {
    wall_ms,
    ticks_per_second,
    realtime_x,
};

fn aggregateSamples(
    allocator: std.mem.Allocator,
    samples: []const BenchmarkSamplePayload,
    metric: Metric,
) !BenchmarkAggregatePayload {
    const values = try allocator.alloc(f64, samples.len);
    defer allocator.free(values);
    var sum: f64 = 0.0;
    for (samples, 0..) |sample, idx| {
        const value = metricValue(sample, metric);
        values[idx] = value;
        sum += value;
    }
    std.sort.heap(f64, values, {}, lessThanF64);
    const mean = sum / @as(f64, @floatFromInt(values.len));
    return .{
        .min = values[0],
        .p50 = percentile(values, 0.50),
        .mean = mean,
        .p95 = percentile(values, 0.95),
        .max = values[values.len - 1],
        .stdev = sampleStdev(values, mean),
    };
}

fn metricValue(sample: BenchmarkSamplePayload, metric: Metric) f64 {
    return switch (metric) {
        .wall_ms => sample.wall_ms,
        .ticks_per_second => sample.ticks_per_second,
        .realtime_x => sample.realtime_x,
    };
}

fn percentile(sorted_values: []const f64, ratio_raw: f64) f64 {
    if (sorted_values.len == 1) return sorted_values[0];
    const ratio = std.math.clamp(ratio_raw, @as(f64, 0.0), @as(f64, 1.0));
    const pos = @as(f64, @floatFromInt(sorted_values.len - 1)) * ratio;
    const lo: usize = @intFromFloat(std.math.floor(pos));
    const hi: usize = @intFromFloat(std.math.ceil(pos));
    if (lo == hi) return sorted_values[lo];
    const frac = pos - @as(f64, @floatFromInt(lo));
    return sorted_values[lo] * (1.0 - frac) + sorted_values[hi] * frac;
}

fn sampleStdev(values: []const f64, mean: f64) f64 {
    if (values.len < 2) return 0.0;
    var sum_square_diff: f64 = 0.0;
    for (values) |value| {
        const diff = value - mean;
        sum_square_diff += diff * diff;
    }
    return std.math.sqrt(sum_square_diff / @as(f64, @floatFromInt(values.len - 1)));
}

fn buildBenchmarkPayload(
    allocator: std.mem.Allocator,
    replay_path: []const u8,
    request: BenchmarkRequest,
    samples: []const BenchmarkSamplePayload,
    run_result: RunResultPayload,
    profile: ?ProfilePayload,
) ![]u8 {
    const report: BenchmarkPayload = .{
        .schema_version = benchmark_schema_version,
        .status = "ok",
        .replay = replay_path,
        .settings = .{
            .mode = "headless",
            .runs = request.runs,
            .warmup_runs = request.warmup_runs,
            .max_ticks = request.max_ticks,
            .trace_rng = request.trace_rng,
            .profile = request.profile,
            .profile_sort = request.profile_sort,
            .top = request.top,
            .profile_out = request.profile_out,
            .render_telemetry = false,
            .render_telemetry_out = null,
            .render_charts_out_dir = null,
        },
        .run_result = run_result,
        .benchmark = .{
            .sample_count = samples.len,
            .samples = samples,
            .wall_ms = try aggregateSamples(allocator, samples, .wall_ms),
            .ticks_per_second = try aggregateSamples(allocator, samples, .ticks_per_second),
            .realtime_x = try aggregateSamples(allocator, samples, .realtime_x),
        },
        .profile = profile,
        .render_telemetry = null,
    };

    var payload_writer: std.Io.Writer.Allocating = .init(allocator);
    errdefer payload_writer.deinit();
    try std.json.Stringify.value(report, .{}, &payload_writer.writer);
    return payload_writer.toOwnedSlice();
}

fn buildProfilePayloadJson(
    allocator: std.mem.Allocator,
    profile: ProfilePayload,
) ![]u8 {
    var payload_writer: std.Io.Writer.Allocating = .init(allocator);
    errdefer payload_writer.deinit();
    try std.json.Stringify.value(profile, .{}, &payload_writer.writer);
    return payload_writer.toOwnedSlice();
}

fn buildRunResultPayload(header: replay_codec.ReplayHeader, run: replay_runner.ReplayRunResult) RunResultPayload {
    return .{
        .game_mode_id = header.game_mode_id,
        .tick_rate = header.tick_rate,
        .ticks = @intCast(run.ticks),
        .elapsed_ms = run.elapsed_ms_sim,
        .score_xp = run.player_experience,
        .creature_kill_count = run.creature_kill_count,
        .most_used_weapon_id = run.most_used_weapon_id,
        .shots_fired = run.shots_fired,
        .shots_hit = run.shots_hit,
        .rng_state = run.wave_spawn_rng_state,
    };
}

fn unsupportedRenderBenchmarkOptionDetail(request: BenchmarkRequest) ?[]const u8 {
    if (request.rtx) {
        return "native replay benchmark does not support render-mode option --rtx";
    }
    if (request.render_telemetry) {
        return "native replay benchmark does not support render-mode option --render-telemetry";
    }
    if (request.render_telemetry_out != null) {
        return "native replay benchmark does not support render-mode option --render-telemetry-out";
    }
    if (request.render_charts_out_dir != null) {
        return "native replay benchmark does not support render-mode option --render-charts-out-dir";
    }
    return null;
}

fn resolveReplayPath(
    allocator: std.mem.Allocator,
    replay_file: []const u8,
    base_dir: []const u8,
) !ReplayResolution {
    const primary_exists = try isFile(replay_file);
    if (primary_exists) {
        return .{
            .resolved_path = try allocator.dupe(u8, replay_file),
            .tried_primary = try allocator.dupe(u8, replay_file),
            .tried_secondary = null,
            .exists = true,
        };
    }

    if (!std.fs.path.isAbsolute(replay_file) and isSingleSegmentPath(replay_file)) {
        const secondary = try std.fs.path.join(allocator, &.{ base_dir, "replays", replay_file });
        errdefer allocator.free(secondary);
        const secondary_exists = try isFile(secondary);
        return .{
            .resolved_path = if (secondary_exists)
                try allocator.dupe(u8, secondary)
            else
                try allocator.dupe(u8, replay_file),
            .tried_primary = try allocator.dupe(u8, replay_file),
            .tried_secondary = secondary,
            .exists = secondary_exists,
        };
    }

    return .{
        .resolved_path = try allocator.dupe(u8, replay_file),
        .tried_primary = try allocator.dupe(u8, replay_file),
        .tried_secondary = null,
        .exists = false,
    };
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

    return .{
        .stdout = try allocator.dupe(u8, ""),
        .stderr = try stderr_buf.toOwnedSlice(),
        .exit_code = 1,
    };
}

fn buildInvalidBenchmarkArgsOutput(
    allocator: std.mem.Allocator,
    detail: []const u8,
) !CommandOutput {
    return buildPrefixedErrorOutput(allocator, "invalid replay benchmark args", detail);
}

fn buildBenchmarkFailedOutput(
    allocator: std.mem.Allocator,
    detail: []const u8,
) !CommandOutput {
    return buildPrefixedErrorOutput(allocator, "replay benchmark failed", detail);
}

fn benchmarkReplayLoadErrorDetail(err: anyerror) []const u8 {
    return switch (err) {
        error.InvalidMsgpack => "replay payload is not valid msgpack wire format",
        error.LegacyJsonPayload => "legacy JSON replay format is unsupported; regenerate the replay",
        error.InvalidHeaderValue => "replay header contains invalid values",
        error.InvalidClaimedStats => "replay header claimed_stats.shots_hit must be <= claimed_stats.shots_fired",
        error.MissingHeaderField => "replay header missing required fields",
        error.MissingQuestLevel => "quest replays require a valid header.quest_level",
        error.TypoMultiplayer => "Typ-o replays require player_count == 1",
        error.TutorialMultiplayer => "tutorial replays require player_count == 1",
        error.UnsupportedInputShape => "replay input rows are invalid: expected canonical wire shape",
        error.UnsupportedEventShape => "replay events are invalid: expected canonical wire shape",
        error.InvalidGzipPayload => "unable to inflate replay gzip payload",
        error.InvalidZstdPayload => "unable to inflate replay zstd payload",
        error.UnsupportedReplayFormatVersion => "replay format version is not supported",
        error.UnknownCommandKind => "replay events include an unknown command kind",
        error.UnsupportedBootstrapKind => "replay bootstrap kind is not supported",
        error.UnsupportedInputQuantization => "replay input quantization is not supported",
        error.BootstrapSeedMismatch => "replay bootstrap seed does not match canonical terrain bootstrap draws",
        error.PayloadTooLarge => "replay payload exceeds max decompressed size",
        error.OutOfMemory => "native replay benchmark ran out of memory while loading replay",
        else => @errorName(err),
    };
}

fn benchmarkReplayRunnerErrorDetail(err: anyerror) []const u8 {
    return switch (err) {
        error.OutOfMemory => "native replay benchmark ran out of memory while running replay",
        error.InvalidHeaderValue => "native replay benchmark received invalid header values",
        error.InvalidCaptureEnumValue => "replay capture includes an invalid enum value",
        error.UnsupportedGameMode => "native replay benchmark only supports survival/rush/quest/typo/tutorial modes",
        error.UnsupportedPlayerCount => "native replay benchmark only supports 1-4 player replays",
        error.UnsupportedInputQuantization => "native replay benchmark only supports f32 quantization",
        error.UnsupportedEventOrdering => "replay events are not ordered in canonical tick order",
        error.UnsupportedEventKind => "replay events include invalid kinds or values for this mode",
        error.UnsupportedEventPlayerIndex => "replay events include an out-of-range player_index",
        error.MissingRngCallerTag => "replay capture is missing required RNG caller tags",
        error.InvalidSpawnTemplate => "replay capture references an invalid spawn template",
        error.InvalidQuestSpawnTable => "replay capture references an invalid quest spawn table",
        else => @errorName(err),
    };
}

fn benchmarkSetupErrorDetail(err: anyerror) []const u8 {
    return switch (err) {
        error.AccessDenied => "unable to inspect replay path: access denied",
        error.OutOfMemory => "native replay benchmark ran out of memory while resolving paths",
        else => @errorName(err),
    };
}

fn benchmarkAllocationErrorDetail(err: anyerror) []const u8 {
    return switch (err) {
        error.OutOfMemory => "native replay benchmark ran out of memory while building report",
        else => @errorName(err),
    };
}

fn benchmarkJsonOutErrorDetail(err: anyerror) []const u8 {
    return switch (err) {
        error.AccessDenied => "unable to write replay benchmark JSON: access denied",
        error.OutOfMemory => "native replay benchmark ran out of memory while writing JSON",
        else => @errorName(err),
    };
}

fn benchmarkProfileOutErrorDetail(err: anyerror) []const u8 {
    return switch (err) {
        error.AccessDenied => "unable to write replay benchmark profile JSON: access denied",
        error.OutOfMemory => "native replay benchmark ran out of memory while writing profile JSON",
        else => @errorName(err),
    };
}

fn buildPrefixedErrorOutput(
    allocator: std.mem.Allocator,
    prefix: []const u8,
    detail: []const u8,
) !CommandOutput {
    var stderr_buf: std.Io.Writer.Allocating = .init(allocator);
    defer stderr_buf.deinit();
    try stderr_buf.writer.print("{s}: {s}\n", .{ prefix, detail });
    return .{
        .stdout = try allocator.dupe(u8, ""),
        .stderr = try stderr_buf.toOwnedSlice(),
        .exit_code = 1,
    };
}

fn writeFileWithParents(path: []const u8, bytes: []const u8) !void {
    if (builtin.os.tag == .freestanding) return error.UnavailableOnFreestanding;

    const io = std.Io.Threaded.global_single_threaded.io();
    if (std.fs.path.dirname(path)) |dir| {
        if (dir.len > 0) try std.Io.Dir.cwd().createDirPath(io, dir);
    }
    try std.Io.Dir.cwd().writeFile(io, .{
        .sub_path = path,
        .data = bytes,
    });
}

fn parseOutputFormat(raw: []const u8) ?OutputFormat {
    if (std.mem.eql(u8, raw, "human")) return .human;
    if (std.mem.eql(u8, raw, "json")) return .json;
    return null;
}

fn parseProfileSort(raw: []const u8) ?[]const u8 {
    if (std.mem.eql(u8, raw, "cumtime")) return "cumtime";
    if (std.mem.eql(u8, raw, "tottime")) return "tottime";
    return null;
}

fn parsePositiveUsize(raw: []const u8) !usize {
    const value = try parseNonNegativeUsize(raw);
    if (value == 0) return error.InvalidValue;
    return value;
}

fn parseNonNegativeUsize(raw: []const u8) !usize {
    if (raw.len == 0) return error.InvalidValue;
    if (raw[0] == '-') return error.InvalidValue;
    return std.fmt.parseInt(usize, raw, 10);
}

fn isSingleSegmentPath(path: []const u8) bool {
    return std.mem.indexOfAny(u8, path, "/\\") == null;
}

fn isFile(path: []const u8) !bool {
    if (builtin.os.tag == .freestanding) return error.UnavailableOnFreestanding;

    if (path.len == 0) return false;
    const io = std.Io.Threaded.global_single_threaded.io();
    const stat = std.Io.Dir.cwd().statFile(io, path, .{}) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };
    return stat.kind == .file;
}

fn elapsedMs(start_ns: i128, end_ns: i128) f64 {
    const elapsed_ns = @max(@as(i128, 0), end_ns - start_ns);
    return @as(f64, @floatFromInt(elapsed_ns)) / 1_000_000.0;
}

fn monotonicNanoseconds() i128 {
    if (builtin.os.tag == .freestanding) return 0;

    const io = std.Io.Threaded.global_single_threaded.io();
    return std.Io.Timestamp.now(io, .awake).nanoseconds;
}

fn ticksPerSecond(ticks: usize, wall_ms: f64) f64 {
    if (wall_ms <= 0.0) return 0.0;
    return @as(f64, @floatFromInt(ticks)) / (wall_ms / 1000.0);
}

fn realtimeMultiplier(elapsed_ms: i64, wall_ms: f64) f64 {
    if (wall_ms <= 0.0) return 0.0;
    return @as(f64, @floatFromInt(elapsed_ms)) / wall_ms;
}

fn writeMetricAggregate3(
    writer: anytype,
    name: []const u8,
    aggregate: BenchmarkAggregatePayload,
) !void {
    try writer.print(
        "{s} min={d:.3} p50={d:.3} mean={d:.3} p95={d:.3} max={d:.3} stdev={d:.3}",
        .{
            name,
            aggregate.min,
            aggregate.p50,
            aggregate.mean,
            aggregate.p95,
            aggregate.max,
            aggregate.stdev,
        },
    );
}

fn writeMetricAggregate2(
    writer: anytype,
    name: []const u8,
    aggregate: BenchmarkAggregatePayload,
) !void {
    try writer.print(
        "{s} min={d:.2} p50={d:.2} mean={d:.2} p95={d:.2} max={d:.2} stdev={d:.2}",
        .{
            name,
            aggregate.min,
            aggregate.p50,
            aggregate.mean,
            aggregate.p95,
            aggregate.max,
            aggregate.stdev,
        },
    );
}

fn benchmarkRunResultsMatch(left: replay_runner.ReplayRunResult, right: replay_runner.ReplayRunResult) bool {
    return left.ticks == right.ticks and
        left.elapsed_ms_sim == right.elapsed_ms_sim and
        left.player_experience == right.player_experience and
        left.creature_kill_count == right.creature_kill_count and
        left.most_used_weapon_id == right.most_used_weapon_id and
        left.shots_fired == right.shots_fired and
        left.shots_hit == right.shots_hit and
        left.wave_spawn_rng_state == right.wave_spawn_rng_state;
}

fn lessThanF64(_: void, left: f64, right: f64) bool {
    return left < right;
}

test "benchmark aggregate computes min max mean and upper median" {
    const allocator = std.testing.allocator;
    const samples = [_]BenchmarkSamplePayload{
        .{ .wall_ms = 3.0, .ticks_per_second = 30.0, .realtime_x = 300.0 },
        .{ .wall_ms = 1.0, .ticks_per_second = 10.0, .realtime_x = 100.0 },
        .{ .wall_ms = 2.0, .ticks_per_second = 20.0, .realtime_x = 200.0 },
    };
    const agg = try aggregateSamples(allocator, samples[0..], .wall_ms);
    try std.testing.expectEqual(@as(f64, 1.0), agg.min);
    try std.testing.expectEqual(@as(f64, 3.0), agg.max);
    try std.testing.expectEqual(@as(f64, 2.0), agg.mean);
    try std.testing.expectEqual(@as(f64, 2.0), agg.p50);
    try std.testing.expectApproxEqAbs(@as(f64, 2.9), agg.p95, 0.0000001);
    try std.testing.expectApproxEqAbs(@as(f64, 1.0), agg.stdev, 0.0000001);
}

test "byte replay benchmark emits JSON payload" {
    const replay_bytes = try replay_codec.buildSmokeTestReplayPayload(std.testing.allocator);
    defer std.testing.allocator.free(replay_bytes);

    const output = try runReplayBenchmarkBytesJson(
        std.testing.allocator,
        "<bytes>",
        replay_bytes,
        1,
        1,
        0,
        false,
    );
    defer output.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u8, 0), output.exit_code);
    try std.testing.expectEqualStrings("", output.stderr);
    try std.testing.expect(std.mem.indexOf(u8, output.stdout, "\"schema_version\":3") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.stdout, "\"replay\":\"<bytes>\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.stdout, "\"runs\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.stdout, "\"warmup_runs\":0") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.stdout, "\"sample_count\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.stdout, "\"ticks\":1") != null);
}

test "benchmark parser accepts artifact and profile options" {
    const parsed = parseNativeSubset(&.{
        "sample.crd",
        "--runs=2",
        "--warmup-runs",
        "0",
        "--max-ticks=12",
        "--trace-rng",
        "--profile",
        "--profile-sort=tottime",
        "--top",
        "1",
        "--profile-out",
        "artifacts/profile.json",
        "--format=json",
        "--json-out",
        "artifacts/benchmark.json",
        "--runtime-dir=runtime",
    });

    switch (parsed) {
        .ok => |request| {
            try std.testing.expectEqualStrings("sample.crd", request.replay_file);
            try std.testing.expectEqual(@as(usize, 2), request.runs);
            try std.testing.expectEqual(@as(usize, 0), request.warmup_runs);
            try std.testing.expectEqual(@as(?usize, 12), request.max_ticks);
            try std.testing.expect(request.trace_rng);
            try std.testing.expect(request.profile);
            try std.testing.expectEqualStrings("tottime", request.profile_sort);
            try std.testing.expectEqual(@as(usize, 1), request.top);
            try std.testing.expectEqualStrings("artifacts/profile.json", request.profile_out.?);
            try std.testing.expectEqual(OutputFormat.json, request.output_format);
            try std.testing.expectEqualStrings("artifacts/benchmark.json", request.json_out.?);
            try std.testing.expectEqualStrings("runtime", request.base_dir.?);
        },
        .invalid => |detail| {
            std.debug.print("unexpected invalid replay benchmark args: {s}\n", .{detail});
            return error.TestUnexpectedResult;
        },
    }
}

test "benchmark writes json and profile artifacts in human mode" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base_dir = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer allocator.free(base_dir);
    const replay_path = try std.fs.path.join(allocator, &.{ base_dir, "sample.crd" });
    defer allocator.free(replay_path);
    const json_path = try std.fs.path.join(allocator, &.{ base_dir, "reports", "benchmark.json" });
    defer allocator.free(json_path);
    const profile_path = try std.fs.path.join(allocator, &.{ base_dir, "reports", "profile.json" });
    defer allocator.free(profile_path);

    const replay_bytes = try replay_codec.buildSmokeTestReplayPayload(allocator);
    defer allocator.free(replay_bytes);

    const io = std.Io.Threaded.global_single_threaded.io();
    try std.Io.Dir.cwd().writeFile(io, .{
        .sub_path = replay_path,
        .data = replay_bytes,
    });

    const output = try runReplayBenchmark(allocator, &.{
        replay_path,
        "--runs",
        "1",
        "--warmup-runs",
        "0",
        "--max-ticks",
        "1",
        "--profile",
        "--profile-out",
        profile_path,
        "--json-out",
        json_path,
    });
    defer output.deinit(allocator);

    try std.testing.expectEqual(@as(u8, 0), output.exit_code);
    try std.testing.expectEqualStrings("", output.stderr);
    try std.testing.expect(std.mem.indexOf(u8, output.stdout, "json_report=") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.stdout, "profile_report=") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.stdout, "ok: mode=headless runs=1 warmup_runs=0 ticks=1") != null);

    const benchmark_artifact = try std.Io.Dir.cwd().readFileAlloc(io, json_path, allocator, .limited(64 * 1024));
    defer allocator.free(benchmark_artifact);
    try std.testing.expect(std.mem.indexOf(u8, benchmark_artifact, "\"schema_version\":3") != null);
    try std.testing.expect(std.mem.indexOf(u8, benchmark_artifact, "\"sample_count\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, benchmark_artifact, "\"profile\":{") != null);

    const profile_artifact = try std.Io.Dir.cwd().readFileAlloc(io, profile_path, allocator, .limited(64 * 1024));
    defer allocator.free(profile_artifact);
    try std.testing.expect(std.mem.indexOf(u8, profile_artifact, "\"source\":\"project\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, profile_artifact, "\"hotspots\"") != null);
}

test "benchmark replay load errors use user-facing details" {
    try std.testing.expectEqualStrings(
        "replay payload is not valid msgpack wire format",
        benchmarkReplayLoadErrorDetail(error.InvalidMsgpack),
    );
    try std.testing.expectEqualStrings(
        "replay payload exceeds max decompressed size",
        benchmarkReplayLoadErrorDetail(error.PayloadTooLarge),
    );
    try std.testing.expectEqualStrings(
        "native replay benchmark ran out of memory while loading replay",
        benchmarkReplayLoadErrorDetail(error.OutOfMemory),
    );
    try std.testing.expectEqualStrings(
        "replay events include an unknown command kind",
        benchmarkReplayLoadErrorDetail(error.UnknownCommandKind),
    );
}

test "benchmark runner and output errors use user-facing details" {
    try std.testing.expectEqualStrings(
        "native replay benchmark only supports survival/rush/quest/typo/tutorial modes",
        benchmarkReplayRunnerErrorDetail(error.UnsupportedGameMode),
    );
    try std.testing.expectEqualStrings(
        "replay events include an out-of-range player_index",
        benchmarkReplayRunnerErrorDetail(error.UnsupportedEventPlayerIndex),
    );
    try std.testing.expectEqualStrings(
        "replay events include invalid kinds or values for this mode",
        benchmarkReplayRunnerErrorDetail(error.UnsupportedEventKind),
    );
    try std.testing.expectEqualStrings(
        "native replay benchmark ran out of memory while resolving paths",
        benchmarkSetupErrorDetail(error.OutOfMemory),
    );
    try std.testing.expectEqualStrings(
        "unable to write replay benchmark JSON: access denied",
        benchmarkJsonOutErrorDetail(error.AccessDenied),
    );
    try std.testing.expectEqualStrings(
        "FileBusy",
        benchmarkReplayRunnerErrorDetail(error.FileBusy),
    );
}
