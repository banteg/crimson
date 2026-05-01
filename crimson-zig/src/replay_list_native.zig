const builtin = @import("builtin");
const std = @import("std");

const replay_codec = @import("replay_codec.zig");
const runtime_paths = @import("runtime_paths.zig");

pub const CommandOutput = struct {
    stdout: []u8,
    stderr: []u8,
    exit_code: u8,

    pub fn deinit(self: CommandOutput, allocator: std.mem.Allocator) void {
        allocator.free(self.stdout);
        allocator.free(self.stderr);
    }
};

const ListRequest = struct {
    base_dir: ?[]const u8 = null,
};

const ParseOutcome = union(enum) {
    ok: ListRequest,
    invalid: []const u8,
};

const ReplayListRow = struct {
    replay: []u8,
    mode: []u8,
    game_version: []u8,
    ticks: []u8,
    duration: []u8,
    score_xp: []u8,
    kills: []u8,
    modified_ns: i128,
    parse_error: ?[]u8 = null,

    fn deinit(self: ReplayListRow, allocator: std.mem.Allocator) void {
        allocator.free(self.replay);
        allocator.free(self.mode);
        allocator.free(self.game_version);
        allocator.free(self.ticks);
        allocator.free(self.duration);
        allocator.free(self.score_xp);
        allocator.free(self.kills);
        if (self.parse_error) |parse_error| allocator.free(parse_error);
    }
};

pub fn runReplayList(
    allocator: std.mem.Allocator,
    args: []const []const u8,
) !CommandOutput {
    switch (parseNativeSubset(args)) {
        .ok => |request| return runNativeList(allocator, request),
        .invalid => |detail| return buildListFailedOutput(allocator, detail),
    }
}

fn parseNativeSubset(args: []const []const u8) ParseOutcome {
    var request: ListRequest = .{};
    var idx: usize = 0;
    while (idx < args.len) : (idx += 1) {
        const arg = args[idx];

        if (std.mem.eql(u8, arg, "--color") or std.mem.eql(u8, arg, "--no-color")) {
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
        return .{ .invalid = "too many positional arguments" };
    }
    return .{ .ok = request };
}

fn runNativeList(
    allocator: std.mem.Allocator,
    request: ListRequest,
) !CommandOutput {
    if (builtin.os.tag == .freestanding) {
        return buildListFailedOutput(allocator, "native file replay list is unavailable on freestanding targets");
    }

    var default_base_dir: ?[]u8 = null;
    defer if (default_base_dir) |path| allocator.free(path);

    const base_dir = if (request.base_dir) |value|
        value
    else blk: {
        const resolved = runtime_paths.defaultRuntimeDir(allocator) catch |err| {
            return buildListFailedOutput(allocator, replayListScanErrorDetail(err));
        };
        if (resolved == null) return buildListFailedOutput(allocator, "unable to resolve default runtime dir");
        default_base_dir = resolved;
        break :blk resolved.?;
    };

    const replays_dir = std.fs.path.join(allocator, &.{ base_dir, "replays" }) catch |err| {
        return buildListFailedOutput(allocator, replayListScanErrorDetail(err));
    };
    defer allocator.free(replays_dir);

    var rows: std.ArrayList(ReplayListRow) = .empty;
    defer {
        for (rows.items) |row| row.deinit(allocator);
        rows.deinit(allocator);
    }

    collectReplayRows(allocator, replays_dir, "", &rows) catch |err| {
        return buildListFailedOutput(allocator, replayListScanErrorDetail(err));
    };
    std.sort.heap(ReplayListRow, rows.items, {}, compareRows);

    var stdout_buf: std.Io.Writer.Allocating = .init(allocator);
    defer stdout_buf.deinit();
    const stdout = &stdout_buf.writer;

    if (rows.items.len == 0) {
        try stdout.print("no replay files found under {s}\n", .{replays_dir});
    } else {
        try stdout.writeAll("replay mode version ticks duration score kills modified_ns\n");
        var parse_errors: usize = 0;
        for (rows.items) |row| {
            if (row.parse_error != null) parse_errors += 1;
            try stdout.print(
                "{s} {s} {s} {s} {s} {s} {s} {d}\n",
                .{
                    row.replay,
                    row.mode,
                    row.game_version,
                    row.ticks,
                    row.duration,
                    row.score_xp,
                    row.kills,
                    row.modified_ns,
                },
            );
        }
        try stdout.print("count={d} parsed={d} errors={d}\n", .{ rows.items.len, rows.items.len - parse_errors, parse_errors });
        try stdout.print("replays_dir={s}\n", .{replays_dir});
        for (rows.items) |row| {
            if (row.parse_error) |parse_error| {
                try stdout.print("warning: {s}: {s}\n", .{ row.replay, parse_error });
            }
        }
    }

    return .{
        .stdout = try stdout_buf.toOwnedSlice(),
        .stderr = try allocator.dupe(u8, ""),
        .exit_code = 0,
    };
}

fn collectReplayRows(
    allocator: std.mem.Allocator,
    dir_path: []const u8,
    rel_prefix: []const u8,
    rows: *std.ArrayList(ReplayListRow),
) !void {
    const io = std.Io.Threaded.global_single_threaded.io();
    var dir = std.Io.Dir.openDirAbsolute(io, dir_path, .{ .iterate = true }) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    defer dir.close(io);

    var iter = dir.iterate();
    while (try iter.next(io)) |entry| {
        const rel_path = if (rel_prefix.len == 0)
            try allocator.dupe(u8, entry.name)
        else
            try std.fs.path.join(allocator, &.{ rel_prefix, entry.name });
        errdefer allocator.free(rel_path);

        const abs_path = try std.fs.path.join(allocator, &.{ dir_path, entry.name });
        defer allocator.free(abs_path);

        switch (entry.kind) {
            .directory => {
                try collectReplayRows(allocator, abs_path, rel_path, rows);
                allocator.free(rel_path);
            },
            .file => {
                if (!std.mem.endsWith(u8, entry.name, ".crd")) {
                    allocator.free(rel_path);
                    continue;
                }
                {
                    var row = try buildReplayListRow(allocator, abs_path, rel_path);
                    errdefer row.deinit(allocator);
                    try rows.append(allocator, row);
                }
            },
            else => allocator.free(rel_path),
        }
    }
}

fn buildReplayListRow(
    allocator: std.mem.Allocator,
    replay_path: []const u8,
    rel_path: []u8,
) !ReplayListRow {
    const io = std.Io.Threaded.global_single_threaded.io();
    const stat = std.Io.Dir.cwd().statFile(io, replay_path, .{}) catch |err| {
        return buildInvalidReplayListRow(allocator, rel_path, 0, replayListRowErrorDetail(err));
    };
    const modified_ns = stat.mtime.nanoseconds;

    const replay_bytes = std.Io.Dir.cwd().readFileAlloc(
        io,
        replay_path,
        allocator,
        .limited(replay_codec.max_replay_payload_bytes),
    ) catch |err| {
        return buildInvalidReplayListRow(allocator, rel_path, modified_ns, replayListRowErrorDetail(err));
    };
    defer allocator.free(replay_bytes);

    var replay_payload_alloc: ?[]u8 = null;
    defer if (replay_payload_alloc) |buf| allocator.free(buf);
    const replay_payload: []const u8 = if (replay_codec.isZstdPayload(replay_bytes)) blk: {
        const inflated = replay_codec.inflateZstdPayload(allocator, replay_bytes, replay_codec.max_replay_payload_bytes) catch |err| {
            return buildInvalidReplayListRow(allocator, rel_path, modified_ns, replayListRowErrorDetail(err));
        };
        replay_payload_alloc = inflated;
        break :blk inflated;
    } else if (replay_codec.isGzipPayload(replay_bytes)) blk: {
        const inflated = replay_codec.inflateGzipPayload(allocator, replay_bytes, replay_codec.max_replay_payload_bytes) catch |err| {
            return buildInvalidReplayListRow(allocator, rel_path, modified_ns, replayListRowErrorDetail(err));
        };
        replay_payload_alloc = inflated;
        break :blk inflated;
    } else replay_bytes;

    var summary = replay_codec.parseReplaySummary(allocator, replay_payload) catch |err| {
        return buildInvalidReplayListRow(allocator, rel_path, modified_ns, replayListRowErrorDetail(err));
    };
    defer summary.deinit(allocator);

    const header = summary.header;
    const mode = try modeLabel(allocator, header);
    errdefer allocator.free(mode);
    const game_version = try nonEmptyVersion(allocator, header.game_version);
    errdefer allocator.free(game_version);
    const ticks = try std.fmt.allocPrint(allocator, "{d}", .{summary.tick_count});
    errdefer allocator.free(ticks);
    const duration = try formatDuration(allocator, summary.tick_count, header.tick_rate);
    errdefer allocator.free(duration);
    const score_xp = try std.fmt.allocPrint(allocator, "{d}", .{header.claimed_stats.score_xp});
    errdefer allocator.free(score_xp);
    const kills = try std.fmt.allocPrint(allocator, "{d}", .{header.claimed_stats.kills});
    errdefer allocator.free(kills);

    return .{
        .replay = rel_path,
        .mode = mode,
        .game_version = game_version,
        .ticks = ticks,
        .duration = duration,
        .score_xp = score_xp,
        .kills = kills,
        .modified_ns = modified_ns,
    };
}

fn buildInvalidReplayListRow(
    allocator: std.mem.Allocator,
    rel_path: []u8,
    modified_ns: i128,
    parse_error: []const u8,
) !ReplayListRow {
    const mode = try allocator.dupe(u8, "invalid");
    errdefer allocator.free(mode);
    const game_version = try allocator.dupe(u8, "-");
    errdefer allocator.free(game_version);
    const ticks = try allocator.dupe(u8, "-");
    errdefer allocator.free(ticks);
    const duration = try allocator.dupe(u8, "-");
    errdefer allocator.free(duration);
    const score_xp = try allocator.dupe(u8, "-");
    errdefer allocator.free(score_xp);
    const kills = try allocator.dupe(u8, "-");
    errdefer allocator.free(kills);
    const parse_error_owned = try allocator.dupe(u8, parse_error);
    errdefer allocator.free(parse_error_owned);

    return .{
        .replay = rel_path,
        .mode = mode,
        .game_version = game_version,
        .ticks = ticks,
        .duration = duration,
        .score_xp = score_xp,
        .kills = kills,
        .modified_ns = modified_ns,
        .parse_error = parse_error_owned,
    };
}

fn modeLabel(allocator: std.mem.Allocator, header: replay_codec.ReplayHeader) ![]u8 {
    const base = switch (header.game_mode_id) {
        1 => "survival",
        2 => "rush",
        3 => "quest",
        4 => "typo",
        8 => "tutorial",
        else => "unknown",
    };
    if (header.game_mode_id == 3 and header.quest_level.len > 0) {
        if (header.player_count > 1) {
            return std.fmt.allocPrint(allocator, "{s} {s} {d}p", .{ base, header.quest_level, header.player_count });
        }
        return std.fmt.allocPrint(allocator, "{s} {s}", .{ base, header.quest_level });
    }
    if (header.player_count > 1) {
        return std.fmt.allocPrint(allocator, "{s} {d}p", .{ base, header.player_count });
    }
    return allocator.dupe(u8, base);
}

fn nonEmptyVersion(allocator: std.mem.Allocator, game_version: []const u8) ![]u8 {
    if (std.mem.trim(u8, game_version, " \t\r\n").len == 0) return allocator.dupe(u8, "-");
    return allocator.dupe(u8, game_version);
}

fn formatDuration(allocator: std.mem.Allocator, ticks: usize, tick_rate: i32) ![]u8 {
    if (tick_rate <= 0) return allocator.dupe(u8, "n/a");
    const total_seconds = @as(f64, @floatFromInt(ticks)) / @as(f64, @floatFromInt(tick_rate));
    if (total_seconds >= 3600.0) {
        const hours: i64 = @intFromFloat(@floor(total_seconds / 3600.0));
        const minutes: i64 = @intFromFloat(@floor(@mod(total_seconds, 3600.0) / 60.0));
        const seconds: i64 = @intFromFloat(@floor(@mod(total_seconds, 60.0)));
        return std.fmt.allocPrint(allocator, "{d}:{d:0>2}:{d:0>2}", .{ hours, minutes, seconds });
    }
    if (total_seconds >= 60.0) {
        const minutes: i64 = @intFromFloat(@floor(total_seconds / 60.0));
        const seconds: i64 = @intFromFloat(@floor(@mod(total_seconds, 60.0)));
        return std.fmt.allocPrint(allocator, "{d}:{d:0>2}", .{ minutes, seconds });
    }
    return std.fmt.allocPrint(allocator, "{d:.1}s", .{total_seconds});
}

fn compareRows(_: void, left: ReplayListRow, right: ReplayListRow) bool {
    if (left.modified_ns != right.modified_ns) return left.modified_ns > right.modified_ns;
    return std.mem.lessThan(u8, left.replay, right.replay);
}

fn buildListFailedOutput(allocator: std.mem.Allocator, detail: []const u8) !CommandOutput {
    const stdout = try allocator.dupe(u8, "");
    errdefer allocator.free(stdout);
    const stderr = try std.fmt.allocPrint(allocator, "replay list failed: {s}\n", .{detail});
    return .{
        .stdout = stdout,
        .stderr = stderr,
        .exit_code = 1,
    };
}

fn replayListRowErrorDetail(err: anyerror) []const u8 {
    return switch (err) {
        error.FileNotFound => "replay file not found",
        error.AccessDenied => "unable to read replay file: access denied",
        error.FileTooBig, error.PayloadTooLarge => "replay payload exceeds max decompressed size",
        error.InvalidMsgpack => "replay payload is not valid msgpack wire format",
        error.InvalidHeaderValue => "replay header contains invalid values",
        error.MissingHeaderField => "replay header missing required fields",
        error.UnsupportedInputShape => "replay input rows are not in the canonical wire shape",
        error.UnsupportedEventShape => "replay events are not in the canonical wire shape",
        error.InvalidGzipPayload => "unable to inflate replay gzip payload",
        error.InvalidZstdPayload => "unable to inflate replay zstd payload",
        error.UnsupportedReplayFormatVersion => "replay format version is not supported",
        error.UnsupportedEventKind => "replay events include command kinds unsupported by the current replay format",
        error.UnsupportedBootstrapKind => "replay bootstrap kind is not supported",
        error.UnsupportedInputQuantization => "replay input quantization is not supported",
        error.BootstrapSeedMismatch => "replay bootstrap seed does not match canonical terrain bootstrap draws",
        error.OutOfMemory => "native replay list ran out of memory while reading replay",
        else => @errorName(err),
    };
}

fn replayListScanErrorDetail(err: anyerror) []const u8 {
    return switch (err) {
        error.AccessDenied => "unable to scan replay directory: access denied",
        error.FileNotFound => "replay directory not found",
        error.OutOfMemory => "native replay list ran out of memory while scanning",
        else => @errorName(err),
    };
}

test "duration formatting mirrors replay list display" {
    const allocator = std.testing.allocator;
    const short = try formatDuration(allocator, 1, 60);
    defer allocator.free(short);
    try std.testing.expectEqualStrings("0.0s", short);

    const minutes = try formatDuration(allocator, 60 * 70, 60);
    defer allocator.free(minutes);
    try std.testing.expectEqualStrings("1:10", minutes);

    const hours = try formatDuration(allocator, 60 * 3670, 60);
    defer allocator.free(hours);
    try std.testing.expectEqualStrings("1:01:10", hours);
}

test "replay list maps invalid row errors to user details" {
    try std.testing.expectEqualStrings(
        "replay payload is not valid msgpack wire format",
        replayListRowErrorDetail(error.InvalidMsgpack),
    );
    try std.testing.expectEqualStrings(
        "replay payload exceeds max decompressed size",
        replayListRowErrorDetail(error.PayloadTooLarge),
    );
    try std.testing.expectEqualStrings(
        "replay events include command kinds unsupported by the current replay format",
        replayListRowErrorDetail(error.UnsupportedEventKind),
    );
    try std.testing.expectEqualStrings(
        "FileBusy",
        replayListRowErrorDetail(error.FileBusy),
    );
}

test "replay list maps scan errors to user details" {
    try std.testing.expectEqualStrings(
        "unable to scan replay directory: access denied",
        replayListScanErrorDetail(error.AccessDenied),
    );
    try std.testing.expectEqualStrings(
        "native replay list ran out of memory while scanning",
        replayListScanErrorDetail(error.OutOfMemory),
    );
    try std.testing.expectEqualStrings(
        "FileBusy",
        replayListScanErrorDetail(error.FileBusy),
    );
}
