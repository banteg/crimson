const std = @import("std");

const game_ids = @import("game_ids.zig");
const quest_level_mod = @import("quest_level.zig");
const room_code = @import("net/room_code.zig");
const verify_native = @import("verify_native.zig");

pub const CommandOutput = verify_native.CommandOutput;

const NetcodeMode = enum {
    rollback,
    lockstep,
};

const Role = enum {
    host,
    join,
};

const OutputFormat = enum {
    human,
    json,
};

const EndpointKind = enum {
    rollback,
    lockstep,
};

const Request = struct {
    role: Role,
    mode_id: i32 = @intFromEnum(game_ids.GameModeId.survival),
    mode_name: []const u8 = "survival",
    player_count: i32 = 1,
    quest_level: ?quest_level_mod.QuestLevel = null,
    netcode_mode: NetcodeMode = .rollback,
    bind_host: []const u8 = "0.0.0.0",
    host: []const u8 = "",
    lockstep_port: u16 = 31993,
    relay_host: []const u8 = "127.0.0.1",
    relay_port: u16 = 31993,
    room_code: ?room_code.RoomCode = null,
    rollback_max_ticks: i32 = 8,
    reconnect_timeout_ms: i32 = 15_000,
    input_delay_ticks: i32 = 1,
    output_format: OutputFormat = .human,
};

const ParseOutcome = union(enum) {
    ok: Request,
    help,
    invalid: []const u8,
};

const SessionPayload = struct {
    schema_version: i32 = 1,
    status: []const u8 = "ok",
    role: []const u8,
    auto_start: bool = true,
    runtime_supported: bool = false,
    mode: []const u8,
    mode_id: i32,
    player_count: i32,
    quest_level: ?[]const u8,
    netcode_mode: []const u8,
    rollback_max_ticks: i32,
    reconnect_timeout_ms: i32,
    input_delay_ticks: i32,
    preserve_bugs: bool = false,
    endpoint: EndpointPayload,
};

const EndpointPayload = struct {
    kind: []const u8,
    bind_host: ?[]const u8 = null,
    host: ?[]const u8 = null,
    port: ?u16 = null,
    relay_host: ?[]const u8 = null,
    relay_port: ?u16 = null,
    room_code: ?[]const u8 = null,
};

pub fn runNet(allocator: std.mem.Allocator, args: []const []const u8) !CommandOutput {
    switch (parseArgs(args)) {
        .ok => |request| return buildSessionOutput(allocator, request),
        .help => return buildUsageOutput(allocator, 0, ""),
        .invalid => |detail| return buildUsageOutput(allocator, 2, detail),
    }
}

fn parseArgs(args: []const []const u8) ParseOutcome {
    if (args.len == 0) return .help;
    if (std.mem.eql(u8, args[0], "--help") or std.mem.eql(u8, args[0], "-h")) return .help;

    var request: Request = if (std.mem.eql(u8, args[0], "host"))
        .{ .role = .host, .host = "127.0.0.1" }
    else if (std.mem.eql(u8, args[0], "join"))
        .{ .role = .join }
    else
        return .{ .invalid = "unsupported net command" };

    var saw_mode = false;
    var saw_players = false;
    var idx: usize = 1;
    while (idx < args.len) : (idx += 1) {
        const arg = args[idx];
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) return .help;
        if (takeValue(args, &idx, arg, "--mode")) |value| {
            const mode = parseMode(value) orelse return .{ .invalid = "unsupported mode; expected one of: survival, rush, quests" };
            request.mode_name = mode.name;
            request.mode_id = mode.mode_id;
            saw_mode = true;
        } else if (takeValue(args, &idx, arg, "--quest-level")) |value| {
            request.quest_level = quest_level_mod.QuestLevel.parse(value) catch return .{ .invalid = "invalid --quest-level value" };
        } else if (takeValue(args, &idx, arg, "--players")) |value| {
            request.player_count = parseRangeI32(value, 1, 4) catch return .{ .invalid = "invalid --players value" };
            saw_players = true;
        } else if (takeValue(args, &idx, arg, "--bind")) |value| {
            request.bind_host = normalizeDefault(value, "0.0.0.0");
        } else if (takeValue(args, &idx, arg, "--host")) |value| {
            request.host = std.mem.trim(u8, value, " \t\r\n");
        } else if (takeValue(args, &idx, arg, "--port")) |value| {
            request.lockstep_port = parsePort(value) catch return .{ .invalid = "invalid --port value" };
        } else if (takeValue(args, &idx, arg, "--relay-host")) |value| {
            request.relay_host = normalizeDefault(value, "127.0.0.1");
        } else if (takeValue(args, &idx, arg, "--relay-port")) |value| {
            request.relay_port = parsePort(value) catch return .{ .invalid = "invalid --relay-port value" };
        } else if (takeValue(args, &idx, arg, "--room-code")) |value| {
            request.room_code = room_code.parseOptionalRoomCode(value) catch return .{ .invalid = "invalid --room-code value" };
        } else if (takeValue(args, &idx, arg, "--code")) |value| {
            request.room_code = room_code.parseOptionalRoomCode(value) catch return .{ .invalid = "invalid --code value" };
        } else if (takeValue(args, &idx, arg, "--netcode")) |value| {
            request.netcode_mode = parseNetcode(value) orelse return .{ .invalid = "unsupported netcode; expected rollback|lockstep" };
        } else if (takeValue(args, &idx, arg, "--rollback-max-ticks")) |value| {
            request.rollback_max_ticks = parseRangeI32(value, 1, 64) catch return .{ .invalid = "invalid --rollback-max-ticks value" };
        } else if (takeValue(args, &idx, arg, "--reconnect-timeout-ms")) |value| {
            request.reconnect_timeout_ms = parseRangeI32(value, 1000, 120_000) catch return .{ .invalid = "invalid --reconnect-timeout-ms value" };
        } else if (takeValue(args, &idx, arg, "--input-delay-ticks")) |value| {
            request.input_delay_ticks = parseRangeI32(value, 0, 8) catch return .{ .invalid = "invalid --input-delay-ticks value" };
        } else if (takeValue(args, &idx, arg, "--format")) |value| {
            request.output_format = parseOutputFormat(value) orelse return .{ .invalid = "invalid --format value" };
        } else if (std.mem.eql(u8, arg, "--json")) {
            request.output_format = .json;
        } else {
            return .{ .invalid = arg };
        }
    }

    if (request.role == .host and !saw_mode) return .{ .invalid = "missing required --mode" };
    if (request.role == .host and !saw_players) return .{ .invalid = "missing required --players" };
    if (std.mem.eql(u8, request.mode_name, "quests") and request.quest_level == null) {
        return .{ .invalid = "quest level is required for quests mode" };
    }

    switch (request.netcode_mode) {
        .lockstep => {
            if (request.room_code != null) return .{ .invalid = "room code is not used in lockstep mode" };
            if (!std.mem.eql(u8, request.relay_host, "127.0.0.1") or request.relay_port != 31993) {
                return .{ .invalid = "relay flags are not used in lockstep mode; use --host/--port" };
            }
            if (request.role == .join and request.host.len == 0) return .{ .invalid = "host is required in lockstep mode" };
            if (request.role == .host and request.host.len == 0) request.host = "127.0.0.1";
        },
        .rollback => {
            if (request.role == .join and request.room_code == null) return .{ .invalid = "room code is required in rollback mode" };
            if (request.role == .join and request.host.len != 0) return .{ .invalid = "--host is lockstep-only" };
            if (request.role == .join and request.lockstep_port != 31993) return .{ .invalid = "--port is lockstep-only" };
            if (request.role == .host and (!std.mem.eql(u8, request.host, "127.0.0.1") or request.lockstep_port != 31993)) {
                return .{ .invalid = "--host/--port are lockstep-only; use --relay-host/--relay-port for rollback" };
            }
        },
    }

    return .{ .ok = request };
}

fn buildSessionOutput(allocator: std.mem.Allocator, request: Request) !CommandOutput {
    var quest_buf: [16]u8 = undefined;
    const quest_text: ?[]const u8 = if (request.quest_level) |level| try level.text(&quest_buf) else null;
    const endpoint = switch (endpointKind(request)) {
        .rollback => EndpointPayload{
            .kind = "rollback",
            .relay_host = request.relay_host,
            .relay_port = request.relay_port,
            .room_code = if (request.room_code) |code| code.bytes[0..] else null,
        },
        .lockstep => EndpointPayload{
            .kind = "lockstep",
            .bind_host = request.bind_host,
            .host = request.host,
            .port = request.lockstep_port,
        },
    };
    const payload: SessionPayload = .{
        .role = roleName(request.role),
        .mode = request.mode_name,
        .mode_id = request.mode_id,
        .player_count = request.player_count,
        .quest_level = quest_text,
        .netcode_mode = netcodeName(request.netcode_mode),
        .rollback_max_ticks = request.rollback_max_ticks,
        .reconnect_timeout_ms = request.reconnect_timeout_ms,
        .input_delay_ticks = request.input_delay_ticks,
        .endpoint = endpoint,
    };

    const stdout = switch (request.output_format) {
        .json => try buildSessionJson(allocator, payload),
        .human => try buildSessionHuman(allocator, payload),
    };
    errdefer allocator.free(stdout);
    return .{
        .stdout = stdout,
        .stderr = try allocator.dupe(u8, ""),
        .exit_code = 0,
    };
}

fn buildSessionJson(allocator: std.mem.Allocator, payload: SessionPayload) ![]u8 {
    var writer: std.Io.Writer.Allocating = .init(allocator);
    errdefer writer.deinit();
    try std.json.Stringify.value(payload, .{ .whitespace = .indent_2 }, &writer.writer);
    try writer.writer.writeByte('\n');
    return writer.toOwnedSlice();
}

fn buildSessionHuman(allocator: std.mem.Allocator, payload: SessionPayload) ![]u8 {
    var writer: std.Io.Writer.Allocating = .init(allocator);
    errdefer writer.deinit();
    try writer.writer.print(
        "native net session role={s} mode={s} players={d} netcode={s} runtime_supported=false\n",
        .{ payload.role, payload.mode, payload.player_count, payload.netcode_mode },
    );
    switch (std.meta.stringToEnum(EndpointKind, payload.endpoint.kind).?) {
        .rollback => try writer.writer.print("relay={s}:{d}", .{ payload.endpoint.relay_host.?, payload.endpoint.relay_port.? }),
        .lockstep => try writer.writer.print("host={s}:{d} bind={s}", .{ payload.endpoint.host.?, payload.endpoint.port.?, payload.endpoint.bind_host.? }),
    }
    if (payload.endpoint.room_code) |code| try writer.writer.print(" room_code={s}", .{code});
    if (payload.quest_level) |level| try writer.writer.print(" quest_level={s}", .{level});
    try writer.writer.writeByte('\n');
    return writer.toOwnedSlice();
}

fn endpointKind(request: Request) EndpointKind {
    return switch (request.netcode_mode) {
        .rollback => .rollback,
        .lockstep => .lockstep,
    };
}

fn takeValue(args: []const []const u8, idx: *usize, arg: []const u8, flag: []const u8) ?[]const u8 {
    if (std.mem.eql(u8, arg, flag)) {
        idx.* += 1;
        if (idx.* >= args.len) return "";
        return args[idx.*];
    }
    if (std.mem.startsWith(u8, arg, flag) and arg.len > flag.len and arg[flag.len] == '=') {
        return arg[flag.len + 1 ..];
    }
    return null;
}

fn normalizeDefault(value: []const u8, default_value: []const u8) []const u8 {
    const trimmed = std.mem.trim(u8, value, " \t\r\n");
    return if (trimmed.len == 0) default_value else trimmed;
}

fn parseMode(value: []const u8) ?struct { name: []const u8, mode_id: i32 } {
    const text = std.mem.trim(u8, value, " \t\r\n");
    if (std.ascii.eqlIgnoreCase(text, "survival")) return .{ .name = "survival", .mode_id = @intFromEnum(game_ids.GameModeId.survival) };
    if (std.ascii.eqlIgnoreCase(text, "rush")) return .{ .name = "rush", .mode_id = @intFromEnum(game_ids.GameModeId.rush) };
    if (std.ascii.eqlIgnoreCase(text, "quests")) return .{ .name = "quests", .mode_id = @intFromEnum(game_ids.GameModeId.quests) };
    return null;
}

fn parseNetcode(value: []const u8) ?NetcodeMode {
    const text = std.mem.trim(u8, value, " \t\r\n");
    if (std.ascii.eqlIgnoreCase(text, "rollback") or std.ascii.eqlIgnoreCase(text, "rb")) return .rollback;
    if (std.ascii.eqlIgnoreCase(text, "lockstep")) return .lockstep;
    return null;
}

fn parseOutputFormat(value: []const u8) ?OutputFormat {
    const text = std.mem.trim(u8, value, " \t\r\n");
    if (std.ascii.eqlIgnoreCase(text, "human")) return .human;
    if (std.ascii.eqlIgnoreCase(text, "json")) return .json;
    return null;
}

fn parsePort(value: []const u8) !u16 {
    const parsed = try std.fmt.parseInt(u16, value, 10);
    if (parsed == 0) return error.InvalidPort;
    return parsed;
}

fn parseRangeI32(value: []const u8, min_value: i32, max_value: i32) !i32 {
    const parsed = try std.fmt.parseInt(i32, value, 10);
    if (parsed < min_value or parsed > max_value) return error.InvalidRange;
    return parsed;
}

fn roleName(role: Role) []const u8 {
    return switch (role) {
        .host => "host",
        .join => "join",
    };
}

fn netcodeName(mode: NetcodeMode) []const u8 {
    return switch (mode) {
        .rollback => "rollback",
        .lockstep => "lockstep",
    };
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

const usage =
    \\Usage:
    \\  crimson-zig net host --mode <survival|rush|quests> --players <1..4> [net options]
    \\  crimson-zig net join --code <room> [net options]
    \\
    \\Options:
    \\  --netcode rollback|lockstep
    \\  --format human|json
    \\  --relay-host <host> --relay-port <port>
    \\  --host <host> --port <port>
    \\  --quest-level <major.minor>
    \\
;

test "native net host builds rollback session payload" {
    const output = try runNet(std.testing.allocator, &.{
        "host", "--mode", "rush", "--players", "3", "--relay-host", "203.0.113.10", "--relay-port", "32011", "--room-code", "AB12", "--format", "json",
    });
    defer output.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u8, 0), output.exit_code);
    try std.testing.expect(std.mem.indexOf(u8, output.stdout, "\"role\": \"host\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.stdout, "\"mode\": \"rush\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.stdout, "\"player_count\": 3") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.stdout, "\"relay_host\": \"203.0.113.10\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.stdout, "\"room_code\": \"ab12\"") != null);
}

test "native net join validates lockstep host" {
    const output = try runNet(std.testing.allocator, &.{ "join", "--netcode", "lockstep", "--format", "json" });
    defer output.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u8, 2), output.exit_code);
    try std.testing.expect(std.mem.indexOf(u8, output.stderr, "host is required in lockstep mode") != null);
}

test "native net join builds lockstep session payload" {
    const output = try runNet(std.testing.allocator, &.{
        "join", "--netcode", "lockstep", "--host", "192.168.1.42", "--port", "32001", "--format", "json",
    });
    defer output.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u8, 0), output.exit_code);
    try std.testing.expect(std.mem.indexOf(u8, output.stdout, "\"role\": \"join\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.stdout, "\"netcode_mode\": \"lockstep\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.stdout, "\"host\": \"192.168.1.42\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.stdout, "\"port\": 32001") != null);
}
