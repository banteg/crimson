const std = @import("std");

const crimson_cfg = @import("formats/crimson_cfg.zig");
const runtime_paths = @import("runtime_paths.zig");
const verify_native = @import("verify_native.zig");

pub const CommandOutput = verify_native.CommandOutput;

const config_schema_version: i32 = 1;
const crimson_cfg_name = "crimson.cfg";

const OutputFormat = enum {
    human,
    json,
};

const ConfigRequest = struct {
    path: ?[]const u8 = null,
    base_dir: ?[]const u8 = null,
    output_format: OutputFormat = .human,
    json_out: ?[]const u8 = null,
};

const ParseOutcome = union(enum) {
    ok: ConfigRequest,
    invalid: []const u8,
};

const ConfigSummaryPayload = struct {
    screen_width: u32,
    screen_height: u32,
    windowed: bool,
    bpp: u32,
    texture_scale: f32,
    player_count: u32,
    game_mode: u32,
    detail_preset: u32,
    sfx_volume: f32,
    music_volume: f32,
};

const ConfigPayload = struct {
    schema_version: i32,
    status: []const u8,
    path: []const u8,
    summary: ConfigSummaryPayload,
    fields: crimson_cfg.CrimsonCfg,
};

pub fn runConfig(
    allocator: std.mem.Allocator,
    args: []const []const u8,
) !CommandOutput {
    switch (parseNativeSubset(args)) {
        .ok => |request| return runNativeConfig(allocator, request),
        .invalid => |detail| return buildInvalidConfigArgsOutput(allocator, detail),
    }
}

fn runNativeConfig(
    allocator: std.mem.Allocator,
    request: ConfigRequest,
) !CommandOutput {
    var default_base_dir: ?[]u8 = null;
    defer if (default_base_dir) |path| allocator.free(path);

    var cfg_path_owned: ?[]u8 = null;
    defer if (cfg_path_owned) |path| allocator.free(path);

    const cfg_path = if (request.path) |path| path else blk: {
        const base_dir = if (request.base_dir) |value|
            value
        else resolved: {
            const resolved = try defaultRuntimeDir(allocator);
            default_base_dir = resolved;
            break :resolved resolved;
        };
        const joined = try std.fs.path.join(allocator, &.{ base_dir, crimson_cfg_name });
        cfg_path_owned = joined;
        break :blk joined;
    };

    const io = std.Io.Threaded.global_single_threaded.io();
    const cfg_bytes = std.Io.Dir.cwd().readFileAlloc(
        io,
        cfg_path,
        allocator,
        .limited(crimson_cfg.file_size + 1),
    ) catch |err| {
        return buildConfigFailedOutput(allocator, configReadErrorDetail(err));
    };
    defer allocator.free(cfg_bytes);

    return runConfigWithBytes(allocator, request, cfg_path, cfg_bytes);
}

fn runConfigWithBytes(
    allocator: std.mem.Allocator,
    request: ConfigRequest,
    cfg_path: []const u8,
    cfg_bytes: []const u8,
) !CommandOutput {
    const cfg = crimson_cfg.decode(cfg_bytes) catch |err| {
        return buildConfigFailedOutput(allocator, configDecodeErrorDetail(err));
    };

    const payload: ConfigPayload = .{
        .schema_version = config_schema_version,
        .status = "ok",
        .path = cfg_path,
        .summary = summaryPayload(cfg),
        .fields = cfg,
    };

    var payload_writer: std.Io.Writer.Allocating = .init(allocator);
    defer payload_writer.deinit();
    try std.json.Stringify.value(payload, .{}, &payload_writer.writer);
    const payload_json = payload_writer.written();

    if (request.json_out) |json_out_path| {
        writeFileWithParents(json_out_path, payload_json) catch |err| {
            return buildConfigFailedOutput(allocator, configJsonOutErrorDetail(err));
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
            try buildHumanConfigOutput(writer, cfg_path, cfg, request.json_out);
        },
    }

    return .{
        .stdout = try stdout_buf.toOwnedSlice(),
        .stderr = try allocator.dupe(u8, ""),
        .exit_code = 0,
    };
}

fn buildHumanConfigOutput(
    writer: *std.Io.Writer,
    cfg_path: []const u8,
    cfg: crimson_cfg.CrimsonCfg,
    json_out: ?[]const u8,
) !void {
    try writer.print("path: {s}\n", .{cfg_path});
    try writer.print("screen: {d}x{d}\n", .{ cfg.screen_width, cfg.screen_height });
    try writer.print("windowed: {}\n", .{cfg.windowed_flag != 0});
    try writer.print("bpp: {d}\n", .{cfg.screen_bpp});
    try writer.print("texture_scale: {d}\n", .{cfg.texture_scale});
    if (json_out) |json_out_path| {
        try writer.print("json_report: {s}\n", .{json_out_path});
    }
    try writer.writeAll("fields:\n");
    inline for (@typeInfo(crimson_cfg.CrimsonCfg).@"struct".fields) |field| {
        try writer.print("{s}: ", .{field.name});
        try writeConfigValue(writer, @field(cfg, field.name));
        try writer.writeByte('\n');
    }
}

fn writeConfigValue(writer: *std.Io.Writer, value: anytype) !void {
    const T = @TypeOf(value);
    switch (@typeInfo(T)) {
        .int, .comptime_int => try writer.print("{d}", .{value}),
        .float, .comptime_float => try writer.print("{d}", .{value}),
        .bool => try writer.print("{}", .{value}),
        .array => |array_info| {
            if (array_info.child == u8) {
                try writeByteArrayValue(writer, value[0..]);
            } else {
                try writer.writeByte('[');
                for (value, 0..) |item, idx| {
                    if (idx != 0) try writer.writeAll(", ");
                    try writeConfigValue(writer, item);
                }
                try writer.writeByte(']');
            }
        },
        else => try writer.print("{any}", .{value}),
    }
}

fn writeByteArrayValue(writer: *std.Io.Writer, bytes: []const u8) !void {
    const zero_index = std.mem.indexOfScalar(u8, bytes, 0) orelse bytes.len;
    const prefix = bytes[0..zero_index];
    if (prefix.len > 0 and isPrintableAscii(prefix)) {
        try writer.writeByte('\'');
        for (prefix) |byte| {
            switch (byte) {
                '\'', '\\' => {
                    try writer.writeByte('\\');
                    try writer.writeByte(byte);
                },
                else => try writer.writeByte(byte),
            }
        }
        try writer.print("' (len={d})", .{bytes.len});
        return;
    }
    try writer.writeAll("0x");
    for (bytes) |byte| {
        const hex = "0123456789abcdef";
        try writer.writeByte(hex[(byte >> 4) & 0x0f]);
        try writer.writeByte(hex[byte & 0x0f]);
    }
    try writer.print(" (len={d})", .{bytes.len});
}

fn isPrintableAscii(bytes: []const u8) bool {
    for (bytes) |byte| {
        if (byte < 32 or byte >= 127) return false;
    }
    return true;
}

fn summaryPayload(cfg: crimson_cfg.CrimsonCfg) ConfigSummaryPayload {
    return .{
        .screen_width = cfg.screen_width,
        .screen_height = cfg.screen_height,
        .windowed = cfg.windowed_flag != 0,
        .bpp = cfg.screen_bpp,
        .texture_scale = cfg.texture_scale,
        .player_count = cfg.player_count,
        .game_mode = cfg.game_mode,
        .detail_preset = cfg.detail_preset,
        .sfx_volume = cfg.sfx_volume,
        .music_volume = cfg.music_volume,
    };
}

fn parseNativeSubset(args: []const []const u8) ParseOutcome {
    var request: ConfigRequest = .{};
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

fn buildInvalidConfigArgsOutput(
    allocator: std.mem.Allocator,
    detail: []const u8,
) !CommandOutput {
    const stderr = try std.fmt.allocPrint(allocator, "invalid config args: {s}\n", .{detail});
    errdefer allocator.free(stderr);
    return .{
        .stdout = try allocator.dupe(u8, ""),
        .stderr = stderr,
        .exit_code = 1,
    };
}

fn buildConfigFailedOutput(
    allocator: std.mem.Allocator,
    detail: []const u8,
) !CommandOutput {
    const stderr = try std.fmt.allocPrint(allocator, "config failed: {s}\n", .{detail});
    errdefer allocator.free(stderr);
    return .{
        .stdout = try allocator.dupe(u8, ""),
        .stderr = stderr,
        .exit_code = 1,
    };
}

fn configReadErrorDetail(err: anyerror) []const u8 {
    return switch (err) {
        error.FileNotFound => "crimson.cfg not found",
        error.AccessDenied => "unable to read crimson.cfg: access denied",
        error.FileTooBig, error.StreamTooLong => "crimson.cfg is larger than expected",
        error.OutOfMemory => "native config inspection ran out of memory while reading crimson.cfg",
        else => @errorName(err),
    };
}

fn configDecodeErrorDetail(err: crimson_cfg.CrimsonCfgError) []const u8 {
    return switch (err) {
        error.InvalidSize => "crimson.cfg has unexpected size",
        error.UnexpectedEof => "crimson.cfg ended before all fields were decoded",
    };
}

fn configJsonOutErrorDetail(err: anyerror) []const u8 {
    return switch (err) {
        error.AccessDenied => "unable to write config JSON: access denied",
        error.OutOfMemory => "native config inspection ran out of memory while writing JSON",
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

test "config parser accepts path, runtime dir, json, and json-out" {
    const parsed = parseNativeSubset(&.{ "--path", "custom.cfg", "--runtime-dir=.", "--format", "json", "--json-out", "out/config.json" });
    switch (parsed) {
        .ok => |request| {
            try std.testing.expectEqualStrings("custom.cfg", request.path.?);
            try std.testing.expectEqualStrings(".", request.base_dir.?);
            try std.testing.expectEqual(OutputFormat.json, request.output_format);
            try std.testing.expectEqualStrings("out/config.json", request.json_out.?);
        },
        else => return error.TestExpectedValidArgs,
    }
}

test "config human output reports summary and raw fields" {
    const allocator = std.testing.allocator;
    const bytes = crimson_cfg.encode(crimson_cfg.defaultConfig());
    const output = try runConfigWithBytes(allocator, .{}, "crimson.cfg", bytes[0..]);
    defer output.deinit(allocator);

    try std.testing.expectEqual(@as(u8, 0), output.exit_code);
    try std.testing.expect(std.mem.indexOf(u8, output.stdout, "screen: 1024x768\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.stdout, "windowed: true\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.stdout, "player_name: '10tons' (len=32)\n") != null);
}

test "config json output exposes stable summary" {
    const allocator = std.testing.allocator;
    const bytes = crimson_cfg.encode(crimson_cfg.defaultConfig());
    const output = try runConfigWithBytes(allocator, .{ .output_format = .json }, "crimson.cfg", bytes[0..]);
    defer output.deinit(allocator);

    try std.testing.expectEqual(@as(u8, 0), output.exit_code);
    try std.testing.expect(std.mem.indexOf(u8, output.stdout, "\"schema_version\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.stdout, "\"screen_width\":1024") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.stdout, "\"windowed\":true") != null);
}
