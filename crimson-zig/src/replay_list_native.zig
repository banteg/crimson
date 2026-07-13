const builtin = @import("builtin");
const std = @import("std");

const replay_codec = @import("replay_codec.zig");
const runtime_paths = @import("runtime_paths.zig");

const replay_list_schema_version: i32 = 1;

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

const ListRequest = struct {
    base_dir: ?[]const u8 = null,
    output_format: OutputFormat = .human,
    json_out: ?[]const u8 = null,
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
    modified: []u8,
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
        allocator.free(self.modified);
        if (self.parse_error) |parse_error| allocator.free(parse_error);
    }
};

const ReplayListSummaryPayload = struct {
    count: usize,
    parsed: usize,
    errors: usize,
};

const ReplayListRowPayload = struct {
    replay: []const u8,
    mode: []const u8,
    game_version: []const u8,
    ticks: []const u8,
    duration: []const u8,
    score_xp: []const u8,
    kills: []const u8,
    modified: []const u8,
    modified_ns: i64,
    parse_error: ?[]const u8,
};

const ReplayListPayload = struct {
    schema_version: i32,
    status: []const u8,
    replays_dir: []const u8,
    summary: ReplayListSummaryPayload,
    rows: []const ReplayListRowPayload,
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

    var parse_errors: usize = 0;
    for (rows.items) |row| {
        if (row.parse_error != null) parse_errors += 1;
    }

    var payload_json: ?[]u8 = null;
    defer if (payload_json) |payload| allocator.free(payload);
    if (request.output_format == .json or request.json_out != null) {
        const payload = buildListJsonPayload(allocator, replays_dir, rows.items, parse_errors) catch |err| {
            return buildListFailedOutput(allocator, replayListJsonOutErrorDetail(err));
        };
        payload_json = payload;
        if (request.json_out) |json_out_path| {
            writeFileWithParents(json_out_path, payload) catch |err| {
                return buildListFailedOutput(allocator, replayListJsonOutErrorDetail(err));
            };
        }
    }

    var stdout_buf: std.Io.Writer.Allocating = .init(allocator);
    defer stdout_buf.deinit();
    const stdout = &stdout_buf.writer;

    if (request.output_format == .json) {
        try stdout.writeAll(payload_json.?);
        try stdout.writeByte('\n');
    } else if (rows.items.len == 0) {
        try stdout.print("no replay files found under {s}\n", .{replays_dir});
        if (request.json_out) |json_out_path| {
            try stdout.print("json_report={s}\n", .{json_out_path});
        }
    } else {
        try stdout.writeAll("replay mode version ticks duration score kills modified\n");
        for (rows.items) |row| {
            try stdout.print(
                "{s} {s} {s} {s} {s} {s} {s} {s}\n",
                .{
                    row.replay,
                    row.mode,
                    row.game_version,
                    row.ticks,
                    row.duration,
                    row.score_xp,
                    row.kills,
                    row.modified,
                },
            );
        }
        try stdout.print("count={d} parsed={d} errors={d}\n", .{ rows.items.len, rows.items.len - parse_errors, parse_errors });
        try stdout.print("replays_dir={s}\n", .{replays_dir});
        if (request.json_out) |json_out_path| {
            try stdout.print("json_report={s}\n", .{json_out_path});
        }
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

fn buildListJsonPayload(
    allocator: std.mem.Allocator,
    replays_dir: []const u8,
    rows: []const ReplayListRow,
    parse_errors: usize,
) ![]u8 {
    const row_payloads = try allocator.alloc(ReplayListRowPayload, rows.len);
    defer allocator.free(row_payloads);
    for (rows, row_payloads) |row, *payload_row| {
        payload_row.* = .{
            .replay = row.replay,
            .mode = row.mode,
            .game_version = row.game_version,
            .ticks = row.ticks,
            .duration = row.duration,
            .score_xp = row.score_xp,
            .kills = row.kills,
            .modified = row.modified,
            .modified_ns = modifiedNsForJson(row.modified_ns),
            .parse_error = row.parse_error,
        };
    }

    const payload: ReplayListPayload = .{
        .schema_version = replay_list_schema_version,
        .status = "ok",
        .replays_dir = replays_dir,
        .summary = .{
            .count = rows.len,
            .parsed = rows.len - parse_errors,
            .errors = parse_errors,
        },
        .rows = row_payloads,
    };

    var payload_writer: std.Io.Writer.Allocating = .init(allocator);
    errdefer payload_writer.deinit();
    try std.json.Stringify.value(payload, .{}, &payload_writer.writer);
    return payload_writer.toOwnedSlice();
}

fn collectReplayRows(
    allocator: std.mem.Allocator,
    dir_path: []const u8,
    rel_prefix: []const u8,
    rows: *std.ArrayList(ReplayListRow),
) !void {
    const io = std.Io.Threaded.global_single_threaded.io();
    var dir = std.Io.Dir.cwd().openDir(io, dir_path, .{ .iterate = true }) catch |err| switch (err) {
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
        .limited(replay_codec.max_replay_file_bytes),
    ) catch |err| {
        return buildInvalidReplayListRow(allocator, rel_path, modified_ns, replayListRowErrorDetail(err));
    };
    defer allocator.free(replay_bytes);

    var replay_payload_alloc: ?[]u8 = null;
    defer if (replay_payload_alloc) |buf| allocator.free(buf);
    const replay_payload = replay_codec.inflateZstdFilePayload(
        allocator,
        replay_bytes,
        replay_codec.max_replay_payload_bytes,
    ) catch |err| {
        return buildInvalidReplayListRow(allocator, rel_path, modified_ns, replayListRowErrorDetail(err));
    };
    replay_payload_alloc = replay_payload;

    var parse_detail: ?[]u8 = null;
    defer if (parse_detail) |detail| allocator.free(detail);
    var summary = replay_codec.parseReplaySummary(allocator, replay_payload) catch |err| {
        if (err == error.UnsupportedInputShape) {
            parse_detail = try replay_codec.replayInputShapeFailureDetail(allocator, replay_payload);
        } else if (err == error.UnsupportedEventShape) {
            parse_detail = try replay_codec.replayEventShapeFailureDetail(allocator, replay_payload);
        } else if (err == error.UnknownCommandKind) {
            parse_detail = try replay_codec.replayUnknownCommandFailureDetail(allocator, replay_payload);
        } else if (err == error.UnsupportedEventKind) {
            parse_detail = try replay_codec.replayCommandKindFailureDetail(allocator, replay_payload);
        }
        return buildInvalidReplayListRow(
            allocator,
            rel_path,
            modified_ns,
            parse_detail orelse replayListRowErrorDetail(err),
        );
    };
    defer summary.deinit(allocator);

    const header = summary.header;
    if (replay_codec.unsupportedReplayHeaderDetail(header, summary.tick_count, .replay_list)) |detail| {
        return buildInvalidReplayListRow(allocator, rel_path, modified_ns, detail);
    }
    if (summary.events.total_count > 0) {
        var replay = replay_codec.parseReplay(allocator, replay_payload) catch |err| {
            if (err == error.UnsupportedInputShape) {
                parse_detail = try replay_codec.replayInputShapeFailureDetail(allocator, replay_payload);
            } else if (err == error.UnsupportedEventShape) {
                parse_detail = try replay_codec.replayEventShapeFailureDetail(allocator, replay_payload);
            } else if (err == error.UnknownCommandKind) {
                parse_detail = try replay_codec.replayUnknownCommandFailureDetail(allocator, replay_payload);
            } else if (err == error.UnsupportedEventKind) {
                parse_detail = try replay_codec.replayCommandKindFailureDetail(allocator, replay_payload);
            }
            return buildInvalidReplayListRow(
                allocator,
                rel_path,
                modified_ns,
                parse_detail orelse replayListRowErrorDetail(err),
            );
        };
        defer replay.deinit(allocator);
        if (try replay_codec.replayEventOrderingFailureDetail(allocator, replay.events)) |detail| {
            defer allocator.free(detail);
            return buildInvalidReplayListRow(allocator, rel_path, modified_ns, detail);
        }
        if (try replay_codec.replayEventPlayerIndexFailureDetail(allocator, header.player_count, replay.events)) |detail| {
            defer allocator.free(detail);
            return buildInvalidReplayListRow(allocator, rel_path, modified_ns, detail);
        }
        if (try replay_codec.replayEventKindFailureDetail(allocator, header.game_mode_id, replay.events)) |detail| {
            defer allocator.free(detail);
            return buildInvalidReplayListRow(allocator, rel_path, modified_ns, detail);
        }
    }

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
    const modified = try formatModified(allocator, modified_ns);
    errdefer allocator.free(modified);

    return .{
        .replay = rel_path,
        .mode = mode,
        .game_version = game_version,
        .ticks = ticks,
        .duration = duration,
        .score_xp = score_xp,
        .kills = kills,
        .modified = modified,
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
    const modified = try formatModified(allocator, modified_ns);
    errdefer allocator.free(modified);
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
        .modified = modified,
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

fn formatModified(allocator: std.mem.Allocator, modified_ns: i128) ![]u8 {
    const ns_per_s: i128 = std.time.ns_per_s;
    const seconds_i128 = @divFloor(modified_ns, ns_per_s);
    const seconds: u64 = @intCast(@max(seconds_i128, 0));
    const epoch_seconds: std.time.epoch.EpochSeconds = .{ .secs = seconds };
    const year_day = epoch_seconds.getEpochDay().calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    const day_seconds = epoch_seconds.getDaySeconds();
    return std.fmt.allocPrint(
        allocator,
        "{d:0>4}-{d:0>2}-{d:0>2} {d:0>2}:{d:0>2}",
        .{
            year_day.year,
            month_day.month.numeric(),
            month_day.day_index + 1,
            day_seconds.getHoursIntoDay(),
            day_seconds.getMinutesIntoHour(),
        },
    );
}

fn compareRows(_: void, left: ReplayListRow, right: ReplayListRow) bool {
    if (left.modified_ns != right.modified_ns) return left.modified_ns > right.modified_ns;
    return std.mem.lessThan(u8, left.replay, right.replay);
}

fn modifiedNsForJson(modified_ns: i128) i64 {
    if (modified_ns < std.math.minInt(i64)) return std.math.minInt(i64);
    if (modified_ns > std.math.maxInt(i64)) return std.math.maxInt(i64);
    return @intCast(modified_ns);
}

fn parseOutputFormat(raw: []const u8) ?OutputFormat {
    if (std.mem.eql(u8, raw, "human")) return .human;
    if (std.mem.eql(u8, raw, "json")) return .json;
    return null;
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

fn replayListJsonOutErrorDetail(err: anyerror) []const u8 {
    return switch (err) {
        error.AccessDenied => "unable to write replay list JSON: access denied",
        error.OutOfMemory => "native replay list ran out of memory while writing JSON",
        else => @errorName(err),
    };
}

fn replayListRowErrorDetail(err: anyerror) []const u8 {
    return switch (err) {
        error.FileNotFound => "replay file not found",
        error.AccessDenied => "unable to read replay file: access denied",
        error.FileTooBig => "replay zstd envelope exceeds max file size",
        error.PayloadTooLarge => "replay payload exceeds max decompressed size",
        error.InvalidMsgpack => "replay payload does not match format 16 msgpack schema",
        error.InvalidHeaderValue => "replay header contains invalid values",
        error.InvalidClaimedStats => "replay header claimed_stats.shots_hit must be <= claimed_stats.shots_fired",
        error.MissingHeaderField => "replay header missing required fields",
        error.MissingQuestLevel => "quest replays require a valid header.quest_level",
        error.TypoMultiplayer => "Typ-o replays require player_count == 1",
        error.TutorialMultiplayer => "tutorial replays require player_count == 1",
        error.UnsupportedGameMode => "replay game mode is not supported",
        error.UnsupportedInputShape => "replay tick inputs do not match format 16",
        error.UnsupportedEventShape => "replay tick operations do not match format 16",
        error.UnsupportedEventKind => "replay tick commands are invalid for this game mode",
        error.InvalidZstdPayload => "unable to inflate replay zstd payload",
        error.UnsupportedReplayFormatVersion => "replay format version is not supported",
        error.UnknownCommandKind => "replay tick operations do not match format 16",
        error.UnsupportedInputQuantization => "replay input quantization is not supported",
        error.OutOfMemory => "native replay list ran out of memory while reading replay",
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

test "replay list parser accepts artifact output options" {
    const parsed = parseNativeSubset(&.{
        "--format=json",
        "--json-out",
        "artifacts/list.json",
        "--runtime-dir=runtime",
        "--no-color",
    });

    switch (parsed) {
        .ok => |request| {
            try std.testing.expectEqual(OutputFormat.json, request.output_format);
            try std.testing.expectEqualStrings("artifacts/list.json", request.json_out.?);
            try std.testing.expectEqualStrings("runtime", request.base_dir.?);
        },
        .invalid => |detail| {
            std.debug.print("unexpected invalid replay list args: {s}\n", .{detail});
            return error.TestUnexpectedResult;
        },
    }
}

test "replay list writes json artifact while preserving json stdout" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base_dir = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer allocator.free(base_dir);
    const replays_dir = try std.fs.path.join(allocator, &.{ base_dir, "replays" });
    defer allocator.free(replays_dir);
    const replay_path = try std.fs.path.join(allocator, &.{ replays_dir, "sample.crd" });
    defer allocator.free(replay_path);
    const json_path = try std.fs.path.join(allocator, &.{ base_dir, "reports", "list.json" });
    defer allocator.free(json_path);

    const replay_bytes = try replay_codec.buildSmokeTestReplayFile(allocator);
    defer allocator.free(replay_bytes);

    const io = std.Io.Threaded.global_single_threaded.io();
    try std.Io.Dir.cwd().createDirPath(io, replays_dir);
    try std.Io.Dir.cwd().writeFile(io, .{
        .sub_path = replay_path,
        .data = replay_bytes,
    });

    const output = try runReplayList(allocator, &.{
        "--base-dir",
        base_dir,
        "--format",
        "json",
        "--json-out",
        json_path,
    });
    defer output.deinit(allocator);

    try std.testing.expectEqual(@as(u8, 0), output.exit_code);
    try std.testing.expectEqualStrings("", output.stderr);
    try std.testing.expect(std.mem.indexOf(u8, output.stdout, "\"schema_version\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.stdout, "\"replay\":\"sample.crd\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.stdout, "\"count\":1") != null);

    const artifact = try std.Io.Dir.cwd().readFileAlloc(io, json_path, allocator, .limited(64 * 1024));
    defer allocator.free(artifact);
    const stdout_json = std.mem.trimRight(u8, output.stdout, "\n");
    try std.testing.expectEqualStrings(stdout_json, artifact);
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

test "modified formatting mirrors replay list display shape" {
    const allocator = std.testing.allocator;
    const epoch = try formatModified(allocator, 0);
    defer allocator.free(epoch);
    try std.testing.expectEqualStrings("1970-01-01 00:00", epoch);

    const later = try formatModified(allocator, (2021 * std.time.s_per_hour + 4 * std.time.s_per_min) * std.time.ns_per_s);
    defer allocator.free(later);
    try std.testing.expectEqualStrings("1970-03-26 05:04", later);
}

test "replay list maps invalid row errors to user details" {
    try std.testing.expectEqualStrings(
        "replay payload does not match format 16 msgpack schema",
        replayListRowErrorDetail(error.InvalidMsgpack),
    );
    try std.testing.expectEqualStrings(
        "replay payload exceeds max decompressed size",
        replayListRowErrorDetail(error.PayloadTooLarge),
    );
    try std.testing.expectEqualStrings(
        "replay tick operations do not match format 16",
        replayListRowErrorDetail(error.UnknownCommandKind),
    );
    try std.testing.expectEqualStrings(
        "replay tick inputs do not match format 16",
        replayListRowErrorDetail(error.UnsupportedInputShape),
    );
    try std.testing.expectEqualStrings(
        "replay tick operations do not match format 16",
        replayListRowErrorDetail(error.UnsupportedEventShape),
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
