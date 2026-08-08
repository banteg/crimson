const std = @import("std");

const game_cfg = @import("formats/game_cfg.zig");
const runtime_paths = @import("runtime_paths.zig");
const verify_native = @import("verify_native.zig");

pub const CommandOutput = verify_native.CommandOutput;

const status_schema_version: i32 = 2;
const game_cfg_name = "game.cfg";

const OutputFormat = enum {
    human,
    json,
};

const StatusRequest = struct {
    path: ?[]const u8 = null,
    base_dir: ?[]const u8 = null,
    output_format: OutputFormat = .human,
    json_out: ?[]const u8 = null,
};

const ParseOutcome = union(enum) {
    ok: StatusRequest,
    invalid: []const u8,
};

const ChecksumPayload = struct {
    stored: u32,
    expected: u32,
    valid: bool,
};

const StatusSummaryPayload = struct {
    quest_unlock_index: u16,
    quest_unlock_index_full: u16,
    total_weapon_usage: u64,
    total_quest_plays: u64,
    mode_play_survival: u32,
    mode_play_rush: u32,
    mode_play_typo: u32,
    mode_play_other: u32,
    play_time_ms: u32,
};

const StatusPayload = struct {
    schema_version: i32,
    status: []const u8,
    path: []const u8,
    checksum: ChecksumPayload,
    summary: StatusSummaryPayload,
    fields: StatusFieldsPayload,
};

const StatusFieldsPayload = struct {
    quest_unlock_index: u16,
    quest_unlock_index_full: u16,
    weapon_usage_counts: [game_cfg.weapon_usage_count]u32,
    quest_play_counts: [game_cfg.quest_play_count]u32,
    mode_play_survival: u32,
    mode_play_rush: u32,
    mode_play_typo: u32,
    mode_play_other: u32,
    play_time_ms: u32,
    reserved_seed_words: ByteArrayPayload,
};

pub const ByteArrayPayload = struct {
    bytes: [game_cfg.reserved_seed_words_byte_size]u8,

    pub fn jsonStringify(self: ByteArrayPayload, jws: anytype) !void {
        try jws.beginArray();
        for (self.bytes) |byte| try jws.write(byte);
        try jws.endArray();
    }
};

pub fn runStatus(
    allocator: std.mem.Allocator,
    args: []const []const u8,
) !CommandOutput {
    switch (parseNativeSubset(args)) {
        .ok => |request| return runNativeStatus(allocator, request),
        .invalid => |detail| return buildInvalidStatusArgsOutput(allocator, detail),
    }
}

fn runNativeStatus(
    allocator: std.mem.Allocator,
    request: StatusRequest,
) !CommandOutput {
    var default_base_dir: ?[]u8 = null;
    defer if (default_base_dir) |path| allocator.free(path);

    var status_path_owned: ?[]u8 = null;
    defer if (status_path_owned) |path| allocator.free(path);

    const status_path = if (request.path) |path| path else blk: {
        const base_dir = if (request.base_dir) |value|
            value
        else resolved: {
            const resolved = try defaultRuntimeDir(allocator);
            default_base_dir = resolved;
            break :resolved resolved;
        };
        const joined = try std.fs.path.join(allocator, &.{ base_dir, game_cfg_name });
        status_path_owned = joined;
        break :blk joined;
    };

    const io = std.Io.Threaded.global_single_threaded.io();
    const status_bytes = std.Io.Dir.cwd().readFileAlloc(
        io,
        status_path,
        allocator,
        .limited(game_cfg.file_size + 1),
    ) catch |err| {
        return buildStatusFailedOutput(allocator, statusReadErrorDetail(err));
    };
    defer allocator.free(status_bytes);

    return runStatusWithBytes(allocator, request, status_path, status_bytes);
}

fn runStatusWithBytes(
    allocator: std.mem.Allocator,
    request: StatusRequest,
    status_path: []const u8,
    status_bytes: []const u8,
) !CommandOutput {
    const parsed = game_cfg.parseFile(status_bytes) catch |err| {
        return buildStatusFailedOutput(allocator, statusDecodeErrorDetail(err));
    };
    if (!parsed.checksumValid()) {
        return buildStatusFailedOutput(allocator, "game.cfg checksum mismatch");
    }
    const decoded_status = game_cfg.parseStatusBlob(parsed.decoded[0..]) catch |err| {
        return buildStatusFailedOutput(allocator, statusDecodeErrorDetail(err));
    };

    const payload: StatusPayload = .{
        .schema_version = status_schema_version,
        .status = "ok",
        .path = status_path,
        .checksum = .{
            .stored = parsed.checksum,
            .expected = parsed.checksum_expected,
            .valid = true,
        },
        .summary = summaryPayload(decoded_status),
        .fields = fieldsPayload(decoded_status),
    };

    var payload_writer: std.Io.Writer.Allocating = .init(allocator);
    defer payload_writer.deinit();
    try std.json.Stringify.value(payload, .{}, &payload_writer.writer);
    const payload_json = payload_writer.written();

    if (request.json_out) |json_out_path| {
        writeFileWithParents(json_out_path, payload_json) catch |err| {
            return buildStatusFailedOutput(allocator, statusJsonOutErrorDetail(err));
        };
    }

    var stdout_buf: std.Io.Writer.Allocating = .init(allocator);
    defer stdout_buf.deinit();
    const writer = &stdout_buf.writer;

    switch (request.output_format) {
        .json => {
            try writer.writeAll(payload_json);
            try writer.writeByte('\n');
        },
        .human => {
            try buildHumanStatusOutput(writer, status_path, parsed, decoded_status, request.json_out);
        },
    }

    return .{
        .stdout = try stdout_buf.toOwnedSlice(),
        .stderr = try allocator.dupe(u8, ""),
        .exit_code = 0,
    };
}

fn buildHumanStatusOutput(
    writer: *std.Io.Writer,
    status_path: []const u8,
    parsed: game_cfg.ParsedFile,
    status: game_cfg.Status,
    json_out: ?[]const u8,
) !void {
    const summary = summaryPayload(status);
    try writer.print("path: {s}\n", .{status_path});
    try writer.print("checksum: ok stored=0x{x:0>8} expected=0x{x:0>8}\n", .{ parsed.checksum, parsed.checksum_expected });
    try writer.print("quest_unlock_index: {d}\n", .{summary.quest_unlock_index});
    try writer.print("quest_unlock_index_full: {d}\n", .{summary.quest_unlock_index_full});
    try writer.print("mode_plays: survival={d} rush={d} typo={d} other={d}\n", .{
        summary.mode_play_survival,
        summary.mode_play_rush,
        summary.mode_play_typo,
        summary.mode_play_other,
    });
    try writer.print("total_weapon_usage: {d}\n", .{summary.total_weapon_usage});
    try writer.print("total_quest_plays: {d}\n", .{summary.total_quest_plays});
    try writer.print("play_time_ms: {d}\n", .{summary.play_time_ms});
    if (json_out) |json_out_path| {
        try writer.print("json_report: {s}\n", .{json_out_path});
    }
    try writer.writeAll("fields:\n");
    inline for (@typeInfo(game_cfg.Status).@"struct".fields) |field| {
        try writer.print("{s}: ", .{field.name});
        try writeStatusValue(writer, @field(status, field.name));
        try writer.writeByte('\n');
    }
}

fn writeStatusValue(writer: *std.Io.Writer, value: anytype) !void {
    const T = @TypeOf(value);
    switch (@typeInfo(T)) {
        .int, .comptime_int => try writer.print("{d}", .{value}),
        .array => |array_info| {
            if (array_info.child == u8) {
                try writeByteArrayValue(writer, value[0..]);
            } else {
                try writer.writeByte('[');
                for (value, 0..) |item, idx| {
                    if (idx != 0) try writer.writeAll(", ");
                    try writeStatusValue(writer, item);
                }
                try writer.writeByte(']');
            }
        },
        else => try writer.print("{any}", .{value}),
    }
}

fn writeByteArrayValue(writer: *std.Io.Writer, bytes: []const u8) !void {
    try writer.writeAll("0x");
    for (bytes) |byte| {
        const hex = "0123456789abcdef";
        try writer.writeByte(hex[(byte >> 4) & 0x0f]);
        try writer.writeByte(hex[byte & 0x0f]);
    }
    try writer.print(" (len={d})", .{bytes.len});
}

fn summaryPayload(status: game_cfg.Status) StatusSummaryPayload {
    return .{
        .quest_unlock_index = status.quest_unlock_index,
        .quest_unlock_index_full = status.quest_unlock_index_full,
        .total_weapon_usage = sumU32(status.weapon_usage_counts[0..]),
        .total_quest_plays = sumU32(status.quest_play_counts[0..]),
        .mode_play_survival = status.mode_play_survival,
        .mode_play_rush = status.mode_play_rush,
        .mode_play_typo = status.mode_play_typo,
        .mode_play_other = status.mode_play_other,
        .play_time_ms = status.play_time_ms,
    };
}

fn fieldsPayload(status: game_cfg.Status) StatusFieldsPayload {
    return .{
        .quest_unlock_index = status.quest_unlock_index,
        .quest_unlock_index_full = status.quest_unlock_index_full,
        .weapon_usage_counts = status.weapon_usage_counts,
        .quest_play_counts = status.quest_play_counts,
        .mode_play_survival = status.mode_play_survival,
        .mode_play_rush = status.mode_play_rush,
        .mode_play_typo = status.mode_play_typo,
        .mode_play_other = status.mode_play_other,
        .play_time_ms = status.play_time_ms,
        .reserved_seed_words = .{ .bytes = status.reserved_seed_words },
    };
}

fn sumU32(values: []const u32) u64 {
    var total: u64 = 0;
    for (values) |value| total += value;
    return total;
}

fn parseNativeSubset(args: []const []const u8) ParseOutcome {
    var request: StatusRequest = .{};
    var positional_path: ?[]const u8 = null;

    var idx: usize = 0;
    while (idx < args.len) : (idx += 1) {
        const arg = args[idx];

        if (std.mem.eql(u8, arg, "--path")) {
            if (idx + 1 >= args.len) return .{ .invalid = "missing value for --path" };
            idx += 1;
            request.path = args[idx];
            continue;
        }
        if (std.mem.startsWith(u8, arg, "--path=")) {
            request.path = arg["--path=".len..];
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
        if (std.mem.startsWith(u8, arg, "-")) {
            return .{ .invalid = arg };
        }
        if (positional_path == null) {
            positional_path = arg;
            continue;
        }
        return .{ .invalid = "too many positional arguments" };
    }

    if (request.path == null) {
        request.path = positional_path;
    } else if (positional_path != null) {
        return .{ .invalid = "path specified more than once" };
    }

    return .{ .ok = request };
}

fn parseOutputFormat(raw: []const u8) ?OutputFormat {
    if (std.mem.eql(u8, raw, "human")) return .human;
    if (std.mem.eql(u8, raw, "json")) return .json;
    return null;
}

fn buildInvalidStatusArgsOutput(
    allocator: std.mem.Allocator,
    detail: []const u8,
) !CommandOutput {
    const stderr = try std.fmt.allocPrint(allocator, "invalid status args: {s}\n", .{detail});
    errdefer allocator.free(stderr);
    return .{
        .stdout = try allocator.dupe(u8, ""),
        .stderr = stderr,
        .exit_code = 1,
    };
}

fn buildStatusFailedOutput(
    allocator: std.mem.Allocator,
    detail: []const u8,
) !CommandOutput {
    const stderr = try std.fmt.allocPrint(allocator, "status failed: {s}\n", .{detail});
    errdefer allocator.free(stderr);
    return .{
        .stdout = try allocator.dupe(u8, ""),
        .stderr = stderr,
        .exit_code = 1,
    };
}

fn statusReadErrorDetail(err: anyerror) []const u8 {
    return switch (err) {
        error.FileNotFound => "game.cfg not found",
        error.AccessDenied => "unable to read game.cfg: access denied",
        error.FileTooBig, error.StreamTooLong => "game.cfg is larger than expected",
        error.OutOfMemory => "native status inspection ran out of memory while reading game.cfg",
        else => @errorName(err),
    };
}

fn statusDecodeErrorDetail(err: game_cfg.GameCfgError) []const u8 {
    return switch (err) {
        error.InvalidSize => "game.cfg has unexpected size",
        error.UnexpectedEof => "game.cfg ended before all fields were decoded",
    };
}

fn statusJsonOutErrorDetail(err: anyerror) []const u8 {
    return switch (err) {
        error.AccessDenied => "unable to write status JSON: access denied",
        error.OutOfMemory => "native status inspection ran out of memory while writing JSON",
        else => @errorName(err),
    };
}

fn defaultRuntimeDir(allocator: std.mem.Allocator) ![]u8 {
    return (try runtime_paths.defaultRuntimeDir(allocator)) orelse allocator.dupe(u8, ".");
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
