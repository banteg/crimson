const std = @import("std");

const replay_codec = @import("replay_codec.zig");
const replay_info_mod = @import("runtime/replay_info.zig");
const verify_native = @import("verify_native.zig");

const replay_info_schema_version: i32 = 2;

pub const CommandOutput = verify_native.CommandOutput;

const OutputFormat = enum {
    human,
    json,
};

const ReplayInfoRequest = struct {
    replay_file: []const u8,
    output_format: OutputFormat = .human,
    json_out: ?[]const u8 = null,
    max_ticks: ?usize = null,
    verbose: bool = false,
    player_index: ?i32 = null,
    base_dir: ?[]const u8 = null,
};

const ParseOutcome = union(enum) {
    ok: ReplayInfoRequest,
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

const ReplayInfoSummaryPayload = struct {
    game_mode_id: i32,
    tick_rate: i32,
    ticks_simulated: i32,
    elapsed_ms: i64,
    player_count: i32,
    event_count: usize,
    event_counts_by_kind: replay_info_mod.EventCountsByKind,
};

const ReplayInfoPayload = struct {
    schema_version: i32,
    status: []const u8,
    replay: []const u8,
    summary: ReplayInfoSummaryPayload,
    timeline: []const replay_info_mod.TimelineEvent,
};

pub fn runReplayInfo(
    allocator: std.mem.Allocator,
    info_args: []const []const u8,
) !CommandOutput {
    switch (parseNativeSubset(info_args)) {
        .ok => |request| return runNativeInfo(allocator, request),
        .invalid => |detail| return buildInvalidInfoArgsOutput(allocator, detail),
    }
}

fn runNativeInfo(
    allocator: std.mem.Allocator,
    request: ReplayInfoRequest,
) !CommandOutput {
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
        return buildInfoFailedOutput(allocator, @errorName(err));
    };
    defer resolution.deinit(allocator);

    if (!resolution.exists) {
        return buildReplayNotFoundOutput(allocator, resolution);
    }
    if (!std.mem.endsWith(u8, resolution.resolved_path, ".crd")) {
        return buildInfoFailedOutput(allocator, "only .crd replay files are currently supported");
    }

    const replay_bytes = std.fs.cwd().readFileAlloc(
        allocator,
        resolution.resolved_path,
        replay_codec.max_replay_payload_bytes,
    ) catch |err| {
        return buildInfoFailedOutput(allocator, @errorName(err));
    };
    defer allocator.free(replay_bytes);

    var replay_payload_alloc: ?[]u8 = null;
    defer if (replay_payload_alloc) |buf| allocator.free(buf);

    const replay_payload: []const u8 = if (replay_codec.isZstdPayload(replay_bytes)) blk: {
        const inflated = replay_codec.inflateZstdPayload(
            allocator,
            replay_bytes,
            replay_codec.max_replay_payload_bytes,
        ) catch |err| {
            return buildInfoFailedOutputForReplayCodecError(allocator, err);
        };
        replay_payload_alloc = inflated;
        break :blk inflated;
    } else if (replay_codec.isGzipPayload(replay_bytes)) blk: {
        const inflated = replay_codec.inflateGzipPayload(
            allocator,
            replay_bytes,
            replay_codec.max_replay_payload_bytes,
        ) catch |err| {
            return buildInfoFailedOutputForReplayCodecError(allocator, err);
        };
        replay_payload_alloc = inflated;
        break :blk inflated;
    } else replay_bytes;

    var replay = replay_codec.parseReplay(allocator, replay_payload) catch |err| {
        return buildInfoFailedOutputForReplayCodecError(allocator, err);
    };
    defer replay.deinit(allocator);

    if (unsupportedReplayHeaderDetail(replay.header, replay.tickCount())) |detail| {
        return buildInfoFailedOutput(allocator, detail);
    }
    replay_codec.validateReplayBootstrap(replay.header) catch |err| {
        return buildInfoFailedOutputForReplayCodecError(allocator, err);
    };

    if (request.player_index) |player_index| {
        if (player_index < 0) {
            const detail = try std.fmt.allocPrint(allocator, "invalid player_index filter: {d}", .{player_index});
            defer allocator.free(detail);
            return buildInfoFailedOutput(allocator, detail);
        }
        if (replay.header.player_count > 0 and player_index >= replay.header.player_count) {
            const detail = try std.fmt.allocPrint(
                allocator,
                "player_index filter out of range: {d} (player_count={d})",
                .{ player_index, replay.header.player_count },
            );
            defer allocator.free(detail);
            return buildInfoFailedOutput(allocator, detail);
        }
    }

    const result = replay_info_mod.collect(
        allocator,
        replay,
        .{
            .max_ticks = request.max_ticks,
            .player_index = request.player_index,
            .include_extra_events = request.verbose,
        },
    ) catch |err| {
        return buildInfoFailedOutputForReplayInfoError(allocator, err);
    };
    defer result.deinit(allocator);

    const summary: ReplayInfoSummaryPayload = .{
        .game_mode_id = result.game_mode_id,
        .tick_rate = result.tick_rate,
        .ticks_simulated = result.ticks_simulated,
        .elapsed_ms = result.elapsed_ms,
        .player_count = result.player_count,
        .event_count = result.timeline.len,
        .event_counts_by_kind = replay_info_mod.eventCountsByKind(result.timeline),
    };
    const payload: ReplayInfoPayload = .{
        .schema_version = replay_info_schema_version,
        .status = "ok",
        .replay = resolution.resolved_path,
        .summary = summary,
        .timeline = result.timeline,
    };

    var payload_writer: std.Io.Writer.Allocating = .init(allocator);
    defer payload_writer.deinit();
    try std.json.Stringify.value(payload, .{}, &payload_writer.writer);
    const payload_json = payload_writer.written();

    if (request.json_out) |json_out_path| {
        writeFileWithParents(json_out_path, payload_json) catch |err| {
            return buildInfoFailedOutput(allocator, @errorName(err));
        };
    }

    var stdout_buf: std.ArrayList(u8) = .empty;
    defer stdout_buf.deinit(allocator);
    var writer = stdout_buf.writer(allocator);

    if (request.output_format == .json) {
        try writer.writeAll(payload_json);
        try writer.writeByte('\n');
    } else {
        try writer.print(
            "ok: replay={s} mode={s} ticks={d} elapsed_ms={d} events={d}\n",
            .{
                resolution.resolved_path,
                replayModeLabel(summary.game_mode_id),
                summary.ticks_simulated,
                summary.elapsed_ms,
                summary.event_count,
            },
        );
        for (result.timeline) |event| {
            if (event.player_index) |player_index| {
                try writer.print(
                    "t={d:.3} tick={d} [p{d}] {s} {s}\n",
                    .{ event.elapsed_s, event.tick_index, player_index, @tagName(event.kind), event.detail },
                );
            } else {
                try writer.print(
                    "t={d:.3} tick={d} {s} {s}\n",
                    .{ event.elapsed_s, event.tick_index, @tagName(event.kind), event.detail },
                );
            }
        }
        try writer.print("events={d}", .{summary.event_count});
        if (request.json_out) |json_out_path| {
            try writer.print(" json_report={s}", .{json_out_path});
        }
        try writer.writeByte('\n');
    }

    return .{
        .stdout = try stdout_buf.toOwnedSlice(allocator),
        .stderr = try allocator.dupe(u8, ""),
        .exit_code = 0,
    };
}

fn buildReplayNotFoundOutput(
    allocator: std.mem.Allocator,
    resolution: ReplayResolution,
) !CommandOutput {
    var stderr_buf: std.ArrayList(u8) = .empty;
    defer stderr_buf.deinit(allocator);

    var writer = stderr_buf.writer(allocator);
    try writer.print("replay file not found: {s}", .{resolution.tried_primary});
    if (resolution.tried_secondary) |secondary| {
        try writer.print(" (also tried: {s})", .{secondary});
    }
    try writer.writeByte('\n');

    return .{
        .stdout = try allocator.dupe(u8, ""),
        .stderr = try stderr_buf.toOwnedSlice(allocator),
        .exit_code = 1,
    };
}

fn buildInvalidInfoArgsOutput(
    allocator: std.mem.Allocator,
    detail: []const u8,
) !CommandOutput {
    var stderr_buf: std.ArrayList(u8) = .empty;
    defer stderr_buf.deinit(allocator);
    var writer = stderr_buf.writer(allocator);
    try writer.print("invalid replay info args: {s}\n", .{detail});
    return .{
        .stdout = try allocator.dupe(u8, ""),
        .stderr = try stderr_buf.toOwnedSlice(allocator),
        .exit_code = 1,
    };
}

fn buildInfoFailedOutput(
    allocator: std.mem.Allocator,
    detail: []const u8,
) !CommandOutput {
    var stderr_buf: std.ArrayList(u8) = .empty;
    defer stderr_buf.deinit(allocator);
    var writer = stderr_buf.writer(allocator);
    try writer.print("replay info failed: {s}\n", .{detail});
    return .{
        .stdout = try allocator.dupe(u8, ""),
        .stderr = try stderr_buf.toOwnedSlice(allocator),
        .exit_code = 1,
    };
}

fn buildInfoFailedOutputForReplayCodecError(
    allocator: std.mem.Allocator,
    err: replay_codec.ReplayCodecError,
) !CommandOutput {
    const detail = switch (err) {
        error.InvalidMsgpack => "replay payload is not valid msgpack wire format",
        error.InvalidHeaderValue => "replay header contains invalid values",
        error.MissingHeaderField => "replay header missing required fields",
        error.UnsupportedInputShape => "replay input rows are not in the canonical wire shape",
        error.UnsupportedEventShape => "replay events are not in the canonical wire shape",
        error.InvalidGzipPayload => "unable to inflate replay gzip payload",
        error.InvalidZstdPayload => "unable to inflate replay zstd payload",
        error.UnsupportedReplayFormatVersion => "replay format version is not supported",
        error.UnsupportedEventKind => "replay events include kinds not yet ported",
        error.UnsupportedBootstrapKind => "replay bootstrap kind is not supported",
        error.UnsupportedInputQuantization => "replay input quantization is not supported",
        error.BootstrapSeedMismatch => "replay bootstrap seed does not match canonical terrain bootstrap draws",
        error.PayloadTooLarge => "replay payload exceeds max decompressed size",
        error.OutOfMemory => "native replay msgpack decode ran out of memory",
    };
    return buildInfoFailedOutput(allocator, detail);
}

fn buildInfoFailedOutputForReplayInfoError(
    allocator: std.mem.Allocator,
    err: replay_info_mod.ReplayInfoError,
) !CommandOutput {
    const detail = switch (err) {
        error.OutOfMemory => "replay info collector ran out of memory",
        error.InvalidHeaderValue => "replay info collector received invalid header values",
        error.UnsupportedGameMode => "replay info collector only supports survival/rush/quest modes",
        error.UnsupportedPlayerCount => "replay info collector only supports 1-4 player replays",
        error.UnsupportedInputQuantization => "replay info collector only supports f32 quantization",
        error.UnsupportedDemoMode => "replay info collector does not support demo_mode_active=true",
        error.UnsupportedEventOrdering => "replay events are not ordered in canonical tick order",
        error.UnsupportedEventKind => "replay events include kinds unsupported for this mode",
        error.UnsupportedEventPlayerIndex => "replay info collector encountered an out-of-range player_index event",
        error.InvalidPerkPickEvent => "replay perk_pick event could not be applied in current perk state",
        error.InvalidCaptureEnumValue => "replay capture payload contains an invalid enum value",
        error.UnsupportedSpawnTemplate => "replay triggered survival template spawns not yet ported in native creature runtime",
        error.UnsupportedQuestSpawnTable => "quest replay requires a quest spawn table variant not yet ported in native runtime",
        error.UnsupportedWeaponFirePath => "replay triggered weapon fire path not yet ported in native projectile runtime",
    };
    return buildInfoFailedOutput(allocator, detail);
}

fn parseNativeSubset(args: []const []const u8) ParseOutcome {
    var replay_file: ?[]const u8 = null;
    var request: ReplayInfoRequest = .{
        .replay_file = "",
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
        if (std.mem.eql(u8, arg, "--verbose")) {
            request.verbose = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--player-index")) {
            if (idx + 1 >= args.len) return .{ .invalid = "missing value for --player-index" };
            idx += 1;
            request.player_index = std.fmt.parseInt(i32, args[idx], 10) catch return .{ .invalid = "invalid --player-index value" };
            continue;
        }
        if (std.mem.startsWith(u8, arg, "--player-index=")) {
            request.player_index = std.fmt.parseInt(i32, arg["--player-index=".len..], 10) catch return .{ .invalid = "invalid --player-index value" };
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

fn replayModeLabel(game_mode_id: i32) []const u8 {
    return switch (game_mode_id) {
        1 => "survival",
        2 => "rush",
        3 => "quests",
        else => "unknown",
    };
}

fn unsupportedReplayHeaderDetail(
    header: replay_codec.ReplayHeader,
    tick_count: usize,
) ?[]const u8 {
    if (header.game_mode_id != 1 and header.game_mode_id != 2 and header.game_mode_id != 3) {
        return "only survival/rush/quest replays are currently ported";
    }
    if (header.player_count < 1 or header.player_count > 4) {
        return "only 1-4 player replays are currently ported";
    }
    if (!std.mem.eql(u8, header.input_quantization, "f32")) {
        return "only f32 input quantization is currently ported";
    }
    if (tick_count > std.math.maxInt(i32)) {
        return "replay has too many ticks for current native verifier";
    }
    if (!header.preserve_bugs and !replay_codec.isLatestRulesetGameVersion(header.game_version)) {
        return "only latest ruleset replays are currently ported";
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

fn defaultRuntimeDir(allocator: std.mem.Allocator) ![]u8 {
    if (std.posix.getenv("CRIMSON_RUNTIME_DIR")) |value| {
        return allocator.dupe(u8, std.mem.sliceTo(value, 0));
    }
    const home = std.posix.getenv("HOME") orelse return error.EnvironmentVariableNotFound;
    return std.fs.path.join(allocator, &.{ std.mem.sliceTo(home, 0), "Library", "Application Support", "crimson" });
}

fn isSingleSegmentPath(path: []const u8) bool {
    return std.mem.indexOfScalar(u8, path, std.fs.path.sep) == null and
        std.mem.indexOfScalar(u8, path, '/') == null;
}

fn isFile(path: []const u8) !bool {
    std.fs.cwd().access(path, .{}) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };
    return true;
}

fn writeFileWithParents(path: []const u8, bytes: []const u8) !void {
    if (std.fs.path.dirname(path)) |dir| {
        if (dir.len > 0) try std.fs.cwd().makePath(dir);
    }
    try std.fs.cwd().writeFile(.{
        .sub_path = path,
        .data = bytes,
    });
}
