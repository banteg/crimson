const std = @import("std");

const replay_codec = @import("replay_codec.zig");
const replay_info_mod = @import("runtime/replay_info.zig");
const runtime_paths = @import("runtime_paths.zig");
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

pub fn runReplayInfoBytesJson(
    allocator: std.mem.Allocator,
    replay_name: []const u8,
    replay_bytes: []const u8,
    max_ticks: ?usize,
    player_index: ?i32,
    include_extra_events: bool,
) !CommandOutput {
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

    if (replay_codec.unsupportedReplayHeaderDetail(replay.header, replay.tickCount(), .replay_info)) |detail| {
        return buildInfoFailedOutput(allocator, detail);
    }
    replay_codec.validateReplayBootstrap(replay.header) catch |err| {
        return buildInfoFailedOutputForReplayCodecError(allocator, err);
    };
    if (try playerFilterValidationDetail(allocator, replay.header, player_index)) |detail| {
        defer allocator.free(detail);
        return buildInfoFailedOutput(allocator, detail);
    }
    if (try replay_codec.replayEventOrderingFailureDetail(allocator, replay.events)) |detail| {
        defer allocator.free(detail);
        return buildInfoFailedOutput(allocator, detail);
    }
    if (try replay_codec.replayEventPlayerIndexFailureDetail(allocator, replay.header.player_count, replay.events)) |detail| {
        defer allocator.free(detail);
        return buildInfoFailedOutput(allocator, detail);
    }

    const result = replay_info_mod.collect(
        allocator,
        replay,
        .{
            .max_ticks = max_ticks,
            .player_index = player_index,
            .include_extra_events = include_extra_events,
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
        .replay = replay_name,
        .summary = summary,
        .timeline = result.timeline,
    };

    var stdout_buf: std.Io.Writer.Allocating = .init(allocator);
    defer stdout_buf.deinit();
    try std.json.Stringify.value(payload, .{}, &stdout_buf.writer);
    try stdout_buf.writer.writeByte('\n');

    return .{
        .stdout = try stdout_buf.toOwnedSlice(),
        .stderr = try allocator.dupe(u8, ""),
        .exit_code = 0,
    };
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
        return buildInfoFailedOutput(allocator, infoResolutionErrorDetail(err));
    };
    defer resolution.deinit(allocator);

    if (!resolution.exists) {
        return buildReplayNotFoundOutput(allocator, resolution);
    }
    if (!std.mem.endsWith(u8, resolution.resolved_path, ".crd")) {
        return buildInfoFailedOutput(allocator, "only .crd replay files are currently supported");
    }

    const io = std.Io.Threaded.global_single_threaded.io();
    const replay_bytes = std.Io.Dir.cwd().readFileAlloc(
        io,
        resolution.resolved_path,
        allocator,
        .limited(replay_codec.max_replay_payload_bytes),
    ) catch |err| {
        return buildInfoFailedOutput(allocator, infoReplayReadErrorDetail(err));
    };
    defer allocator.free(replay_bytes);

    return runInfoWithReplayBytes(allocator, request, resolution.resolved_path, replay_bytes);
}

fn runInfoWithReplayBytes(
    allocator: std.mem.Allocator,
    request: ReplayInfoRequest,
    replay_path: []const u8,
    replay_bytes: []const u8,
) !CommandOutput {
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

    if (replay_codec.unsupportedReplayHeaderDetail(replay.header, replay.tickCount(), .replay_info)) |detail| {
        return buildInfoFailedOutput(allocator, detail);
    }
    replay_codec.validateReplayBootstrap(replay.header) catch |err| {
        return buildInfoFailedOutputForReplayCodecError(allocator, err);
    };

    if (try playerFilterValidationDetail(allocator, replay.header, request.player_index)) |detail| {
        defer allocator.free(detail);
        return buildInfoFailedOutput(allocator, detail);
    }
    if (try replay_codec.replayEventOrderingFailureDetail(allocator, replay.events)) |detail| {
        defer allocator.free(detail);
        return buildInfoFailedOutput(allocator, detail);
    }
    if (try replay_codec.replayEventPlayerIndexFailureDetail(allocator, replay.header.player_count, replay.events)) |detail| {
        defer allocator.free(detail);
        return buildInfoFailedOutput(allocator, detail);
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
        .replay = replay_path,
        .summary = summary,
        .timeline = result.timeline,
    };

    var payload_writer: std.Io.Writer.Allocating = .init(allocator);
    defer payload_writer.deinit();
    try std.json.Stringify.value(payload, .{}, &payload_writer.writer);
    const payload_json = payload_writer.written();

    if (request.json_out) |json_out_path| {
        writeFileWithParents(json_out_path, payload_json) catch |err| {
            return buildInfoFailedOutput(allocator, infoJsonOutErrorDetail(err));
        };
    }

    var stdout_buf: std.Io.Writer.Allocating = .init(allocator);
    defer stdout_buf.deinit();
    const writer = &stdout_buf.writer;

    if (request.output_format == .json) {
        try writer.writeAll(payload_json);
        try writer.writeByte('\n');
    } else {
        try writer.print(
            "ok: replay={s} mode={s} ticks={d} elapsed_ms={d} events={d}\n",
            .{
                replay_path,
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
        .stdout = try stdout_buf.toOwnedSlice(),
        .stderr = try allocator.dupe(u8, ""),
        .exit_code = 0,
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

fn playerFilterValidationDetail(
    allocator: std.mem.Allocator,
    header: replay_codec.ReplayHeader,
    player_index: ?i32,
) !?[]u8 {
    const index = player_index orelse return null;
    if (index < 0) {
        const detail = try std.fmt.allocPrint(allocator, "invalid player_index filter: {d}", .{index});
        return detail;
    }
    if (header.player_count > 0 and index >= header.player_count) {
        const detail = try std.fmt.allocPrint(
            allocator,
            "player_index filter out of range: {d} (player_count={d})",
            .{ index, header.player_count },
        );
        return detail;
    }
    return null;
}

fn buildInvalidInfoArgsOutput(
    allocator: std.mem.Allocator,
    detail: []const u8,
) !CommandOutput {
    var stderr_buf: std.Io.Writer.Allocating = .init(allocator);
    defer stderr_buf.deinit();
    const writer = &stderr_buf.writer;
    try writer.print("invalid replay info args: {s}\n", .{detail});
    return .{
        .stdout = try allocator.dupe(u8, ""),
        .stderr = try stderr_buf.toOwnedSlice(),
        .exit_code = 1,
    };
}

fn buildInfoFailedOutput(
    allocator: std.mem.Allocator,
    detail: []const u8,
) !CommandOutput {
    var stderr_buf: std.Io.Writer.Allocating = .init(allocator);
    defer stderr_buf.deinit();
    const writer = &stderr_buf.writer;
    try writer.print("replay info failed: {s}\n", .{detail});
    return .{
        .stdout = try allocator.dupe(u8, ""),
        .stderr = try stderr_buf.toOwnedSlice(),
        .exit_code = 1,
    };
}

fn buildInfoFailedOutputForReplayCodecError(
    allocator: std.mem.Allocator,
    err: replay_codec.ReplayCodecError,
) !CommandOutput {
    return buildInfoFailedOutput(allocator, replayCodecErrorDetail(err));
}

fn buildInfoFailedOutputForReplayInfoError(
    allocator: std.mem.Allocator,
    err: replay_info_mod.ReplayInfoError,
) !CommandOutput {
    return buildInfoFailedOutput(allocator, replayInfoErrorDetail(err));
}

fn infoResolutionErrorDetail(err: anyerror) []const u8 {
    return switch (err) {
        error.AccessDenied => "unable to inspect replay path: access denied",
        error.OutOfMemory => "native replay info path resolution ran out of memory",
        else => @errorName(err),
    };
}

fn infoReplayReadErrorDetail(err: anyerror) []const u8 {
    return switch (err) {
        error.FileNotFound => "replay file not found",
        error.AccessDenied => "unable to read replay file: access denied",
        error.FileTooBig, error.PayloadTooLarge => "replay payload exceeds max decompressed size",
        error.OutOfMemory => "native replay info ran out of memory while reading replay",
        else => @errorName(err),
    };
}

fn infoJsonOutErrorDetail(err: anyerror) []const u8 {
    return switch (err) {
        error.AccessDenied => "unable to write replay info JSON: access denied",
        error.OutOfMemory => "native replay info ran out of memory while writing JSON",
        else => @errorName(err),
    };
}

fn replayCodecErrorDetail(err: replay_codec.ReplayCodecError) []const u8 {
    return switch (err) {
        error.InvalidMsgpack => "replay payload is not valid msgpack wire format",
        error.InvalidHeaderValue => "replay header contains invalid values",
        error.MissingHeaderField => "replay header missing required fields",
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
        error.OutOfMemory => "native replay msgpack decode ran out of memory",
    };
}

fn replayInfoErrorDetail(err: replay_info_mod.ReplayInfoError) []const u8 {
    return switch (err) {
        error.OutOfMemory => "replay info collector ran out of memory",
        error.InvalidHeaderValue => "replay info collector received invalid header values",
        error.UnsupportedGameMode => "replay info collector only supports survival/rush/quest/typo/tutorial modes",
        error.UnsupportedPlayerCount => "replay info collector only supports 1-4 player replays",
        error.InvalidPlayerFilter => "replay info collector received invalid player_index filter",
        error.PlayerFilterOutOfRange => "replay info collector received out-of-range player_index filter",
        error.UnsupportedInputQuantization => "replay info collector only supports f32 quantization",
        error.UnsupportedEventOrdering => "replay events are not ordered in canonical tick order",
        error.UnsupportedEventKind => "replay events include invalid kinds or values for this mode",
        error.UnsupportedEventPlayerIndex => "replay events include an out-of-range player_index",
        error.InvalidCaptureEnumValue => "replay capture payload contains an invalid enum value",
        error.InvalidSpawnTemplate => "replay capture payload references an invalid creature spawn template",
        error.InvalidQuestSpawnTable => "quest replay/session payload resolves to an invalid quest spawn table",
        error.MissingRngCallerTag => "native replay trace hit an untagged gameplay RNG draw",
    };
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
        4 => "typo",
        8 => "tutorial",
        else => "unknown",
    };
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
    return (try runtime_paths.defaultRuntimeDir(allocator)) orelse allocator.dupe(u8, ".");
}

fn isSingleSegmentPath(path: []const u8) bool {
    return std.mem.indexOfScalar(u8, path, std.fs.path.sep) == null and
        std.mem.indexOfScalar(u8, path, '/') == null;
}

fn isFile(path: []const u8) !bool {
    const io = std.Io.Threaded.global_single_threaded.io();
    std.Io.Dir.cwd().access(io, path, .{}) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };
    return true;
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

test "replay info maps file and json output errors to user details" {
    try std.testing.expectEqualStrings(
        "replay payload exceeds max decompressed size",
        infoReplayReadErrorDetail(error.PayloadTooLarge),
    );
    try std.testing.expectEqualStrings(
        "native replay info path resolution ran out of memory",
        infoResolutionErrorDetail(error.OutOfMemory),
    );
    try std.testing.expectEqualStrings(
        "unable to write replay info JSON: access denied",
        infoJsonOutErrorDetail(error.AccessDenied),
    );
    try std.testing.expectEqualStrings(
        "FileBusy",
        infoReplayReadErrorDetail(error.FileBusy),
    );
}

test "replay info parser accepts artifact and filter options" {
    const parsed = parseNativeSubset(&.{
        "sample.crd",
        "--format=json",
        "--json-out",
        "artifacts/info.json",
        "--max-ticks=12",
        "--verbose",
        "--player-index",
        "0",
        "--runtime-dir=runtime",
    });

    switch (parsed) {
        .ok => |request| {
            try std.testing.expectEqualStrings("sample.crd", request.replay_file);
            try std.testing.expectEqual(OutputFormat.json, request.output_format);
            try std.testing.expectEqualStrings("artifacts/info.json", request.json_out.?);
            try std.testing.expectEqual(@as(?usize, 12), request.max_ticks);
            try std.testing.expect(request.verbose);
            try std.testing.expectEqual(@as(?i32, 0), request.player_index);
            try std.testing.expectEqualStrings("runtime", request.base_dir.?);
        },
        .invalid => |detail| {
            std.debug.print("unexpected invalid replay info args: {s}\n", .{detail});
            return error.TestUnexpectedResult;
        },
    }
}

test "replay info writes json artifact while preserving json stdout" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base_dir = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer allocator.free(base_dir);
    const replay_path = try std.fs.path.join(allocator, &.{ base_dir, "sample.crd" });
    defer allocator.free(replay_path);
    const json_path = try std.fs.path.join(allocator, &.{ base_dir, "reports", "info.json" });
    defer allocator.free(json_path);

    const replay_bytes = try replay_codec.buildSmokeTestReplayPayload(allocator);
    defer allocator.free(replay_bytes);

    const io = std.Io.Threaded.global_single_threaded.io();
    try std.Io.Dir.cwd().writeFile(io, .{
        .sub_path = replay_path,
        .data = replay_bytes,
    });

    const output = try runReplayInfo(allocator, &.{
        replay_path,
        "--format",
        "json",
        "--json-out",
        json_path,
        "--max-ticks",
        "1",
    });
    defer output.deinit(allocator);

    try std.testing.expectEqual(@as(u8, 0), output.exit_code);
    try std.testing.expectEqualStrings("", output.stderr);
    try std.testing.expect(std.mem.indexOf(u8, output.stdout, "\"schema_version\":2") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.stdout, "\"ticks_simulated\":1") != null);

    const artifact = try std.Io.Dir.cwd().readFileAlloc(io, json_path, allocator, .limited(64 * 1024));
    defer allocator.free(artifact);
    const stdout_json = std.mem.trimRight(u8, output.stdout, "\n");
    try std.testing.expectEqualStrings(stdout_json, artifact);
}

test "byte replay info emits JSON payload" {
    const allocator = std.testing.allocator;
    const replay_bytes = try replay_codec.buildSmokeTestReplayPayload(allocator);
    defer allocator.free(replay_bytes);

    const output = try runReplayInfoBytesJson(
        allocator,
        "<bytes>",
        replay_bytes,
        1,
        null,
        false,
    );
    defer output.deinit(allocator);

    try std.testing.expectEqual(@as(u8, 0), output.exit_code);
    try std.testing.expectEqualStrings("", output.stderr);
    try std.testing.expect(std.mem.indexOf(u8, output.stdout, "\"schema_version\":2") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.stdout, "\"replay\":\"<bytes>\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.stdout, "\"ticks_simulated\":1") != null);
}

test "byte replay info returns detailed codec failure output" {
    const allocator = std.testing.allocator;
    const output = try runReplayInfoBytesJson(
        allocator,
        "<bytes>",
        "not msgpack",
        null,
        null,
        false,
    );
    defer output.deinit(allocator);

    try std.testing.expectEqual(@as(u8, 1), output.exit_code);
    try std.testing.expectEqualStrings("", output.stdout);
    try std.testing.expectEqualStrings(
        "replay info failed: replay payload is not valid msgpack wire format\n",
        output.stderr,
    );
}

test "byte replay info forwards player filter to collector" {
    const allocator = std.testing.allocator;
    const replay_bytes = try replay_codec.buildSmokeTestReplayPayload(allocator);
    defer allocator.free(replay_bytes);

    const output = try runReplayInfoBytesJson(
        allocator,
        "<bytes>",
        replay_bytes,
        null,
        1,
        true,
    );
    defer output.deinit(allocator);

    try std.testing.expectEqual(@as(u8, 1), output.exit_code);
    try std.testing.expectEqualStrings("", output.stdout);
    try std.testing.expectEqualStrings(
        "replay info failed: player_index filter out of range: 1 (player_count=1)\n",
        output.stderr,
    );
}

test "byte replay info rejects negative player filter with CLI detail" {
    const allocator = std.testing.allocator;
    const replay_bytes = try replay_codec.buildSmokeTestReplayPayload(allocator);
    defer allocator.free(replay_bytes);

    const output = try runReplayInfoBytesJson(
        allocator,
        "<bytes>",
        replay_bytes,
        null,
        -1,
        false,
    );
    defer output.deinit(allocator);

    try std.testing.expectEqual(@as(u8, 1), output.exit_code);
    try std.testing.expectEqualStrings("", output.stdout);
    try std.testing.expectEqualStrings(
        "replay info failed: invalid player_index filter: -1\n",
        output.stderr,
    );
}

test "replay info exposes codec and collector detail helpers" {
    try std.testing.expectEqualStrings(
        "replay payload is not valid msgpack wire format",
        replayCodecErrorDetail(error.InvalidMsgpack),
    );
    try std.testing.expectEqualStrings(
        "replay bootstrap seed does not match canonical terrain bootstrap draws",
        replayCodecErrorDetail(error.BootstrapSeedMismatch),
    );
    try std.testing.expectEqualStrings(
        "replay events include an unknown command kind",
        replayCodecErrorDetail(error.UnknownCommandKind),
    );
    try std.testing.expectEqualStrings(
        "replay info collector only supports survival/rush/quest/typo/tutorial modes",
        replayInfoErrorDetail(error.UnsupportedGameMode),
    );
    try std.testing.expectEqualStrings(
        "replay info collector received invalid player_index filter",
        replayInfoErrorDetail(error.InvalidPlayerFilter),
    );
    try std.testing.expectEqualStrings(
        "replay info collector received out-of-range player_index filter",
        replayInfoErrorDetail(error.PlayerFilterOutOfRange),
    );
    try std.testing.expectEqualStrings(
        "replay events include an out-of-range player_index",
        replayInfoErrorDetail(error.UnsupportedEventPlayerIndex),
    );
    try std.testing.expectEqualStrings(
        "replay events include invalid kinds or values for this mode",
        replayInfoErrorDetail(error.UnsupportedEventKind),
    );
}

test "replay info header tick limit uses info-specific detail" {
    const allocator = std.testing.allocator;
    var header = try makeReplayInfoTestHeader(allocator);
    defer header.deinit(allocator);

    try std.testing.expectEqualStrings(
        "replay has too many ticks for current native replay info",
        replay_codec.unsupportedReplayHeaderDetail(header, @as(usize, std.math.maxInt(i32)) + 1, .replay_info).?,
    );
}

fn makeReplayInfoTestHeader(
    allocator: std.mem.Allocator,
) !replay_codec.ReplayHeader {
    return .{
        .game_mode_id = 1,
        .seed = 1,
        .replay_format_version = replay_codec.replay_format_version,
        .quest_level = try allocator.dupe(u8, ""),
        .bootstrap_kind = try allocator.dupe(u8, "none"),
        .bootstrap_seed = 0,
        .game_version = try allocator.dupe(u8, "0.9.0"),
        .tick_rate = 60,
        .difficulty_level = 0,
        .hardcore = false,
        .preserve_bugs = true,
        .detail_preset = 5,
        .gore_disabled = 0,
        .world_size = 1024.0,
        .player_count = 1,
        .status = .{
            .quest_unlock_index = 0,
            .quest_unlock_index_full = 0,
            .weapon_usage_counts = [_]u32{0} ** replay_codec.weapon_usage_count,
        },
        .input_quantization = try allocator.dupe(u8, "f32"),
    };
}
