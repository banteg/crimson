const std = @import("std");

const relay_protocol = @import("relay_protocol.zig");
const relay_service = @import("relay_service.zig");

const Io = std.Io;
const IpAddress = std.Io.net.IpAddress;
const Socket = std.Io.net.Socket;

pub const Config = struct {
    bind_host: []const u8 = "0.0.0.0",
    bind_port: u16 = relay_protocol.default_port,
    tick_ms: i64 = 8,
    max_packets: usize = 512,
    link_timeout_ms: i64 = relay_protocol.link_timeout_ms,
};

pub const CommandOutput = struct {
    stdout: []u8,
    stderr: []u8,
    exit_code: u8,

    pub fn deinit(self: CommandOutput, allocator: std.mem.Allocator) void {
        allocator.free(self.stdout);
        allocator.free(self.stderr);
    }
};

const ParseOutcome = union(enum) {
    ok: Config,
    help,
    invalid: []const u8,
};

pub fn runRelayServe(
    allocator: std.mem.Allocator,
    io: Io,
    args: []const []const u8,
) !CommandOutput {
    switch (parseArgs(args)) {
        .ok => |config| {
            try serve(allocator, io, config);
            return emptyOutput(allocator, 0);
        },
        .help => return buildUsageOutput(allocator, 0, ""),
        .invalid => |detail| return buildUsageOutput(allocator, 2, detail),
    }
}

pub fn serve(allocator: std.mem.Allocator, io: Io, config: Config) !void {
    var service: relay_service.RelayService = .{};
    defer service.deinit(allocator);

    var bind_addr = try IpAddress.parse(config.bind_host, config.bind_port);
    const socket = try bind_addr.bind(io, .{
        .mode = .dgram,
        .protocol = .udp,
    });
    defer socket.close(io);

    try printOpen(io, socket.address, config);

    var recv_buffer: [64 * 1024]u8 = undefined;
    while (true) {
        const now_ms = monotonicMs(io);
        try drainPackets(allocator, io, &service, socket, &recv_buffer, now_ms, config.max_packets, config.tick_ms);
        try flushOutbox(allocator, io, socket, try service.pollResends(allocator, now_ms));
        try flushOutbox(allocator, io, socket, try service.pruneTimeouts(allocator, now_ms, config.link_timeout_ms));
    }
}

fn drainPackets(
    allocator: std.mem.Allocator,
    io: Io,
    service: *relay_service.RelayService,
    socket: Socket,
    recv_buffer: []u8,
    now_ms: i64,
    max_packets: usize,
    tick_ms: i64,
) !void {
    var remaining = max_packets;
    while (remaining > 0) : (remaining -= 1) {
        const timeout: Io.Timeout = if (remaining == max_packets)
            .{ .duration = .{ .raw = .fromMilliseconds(tick_ms), .clock = .awake } }
        else
            .{ .duration = .{ .raw = .zero, .clock = .awake } };
        const incoming = socket.receiveTimeout(io, recv_buffer, timeout) catch |err| switch (err) {
            error.Timeout => return,
            else => return err,
        };
        if (incoming.flags.trunc) continue;
        const addr = peerAddrFromIp(incoming.from) orelse continue;
        const decoded = relay_protocol.decodePacket(allocator, incoming.data) catch continue;
        defer decoded.deinit();
        try flushOutbox(allocator, io, socket, try service.receivePacket(allocator, addr, decoded.value, .{
            .dispatch = .{ .now_ms = now_ms },
        }));
    }
}

fn flushOutbox(allocator: std.mem.Allocator, io: Io, socket: Socket, outbox: relay_service.AddressedOutbox) !void {
    var mutable_outbox = outbox;
    defer mutable_outbox.deinit(allocator);
    for (mutable_outbox.items.items) |item| {
        const encoded = try relay_protocol.encodePacket(allocator, item.packet);
        defer allocator.free(encoded);
        const addr = ipFromPeerAddr(item.addr);
        try socket.send(io, &addr, encoded);
    }
}

fn parseArgs(args: []const []const u8) ParseOutcome {
    var config: Config = .{};
    var idx: usize = 0;
    while (idx < args.len) : (idx += 1) {
        const arg = args[idx];
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            return .help;
        } else if (std.mem.eql(u8, arg, "--bind")) {
            idx += 1;
            if (idx >= args.len) return .{ .invalid = "missing value for --bind" };
            config.bind_host = args[idx];
        } else if (std.mem.startsWith(u8, arg, "--bind=")) {
            config.bind_host = arg["--bind=".len..];
        } else if (std.mem.eql(u8, arg, "--port")) {
            idx += 1;
            if (idx >= args.len) return .{ .invalid = "missing value for --port" };
            config.bind_port = parsePort(args[idx]) catch return .{ .invalid = "invalid --port value" };
        } else if (std.mem.startsWith(u8, arg, "--port=")) {
            config.bind_port = parsePort(arg["--port=".len..]) catch return .{ .invalid = "invalid --port value" };
        } else if (std.mem.eql(u8, arg, "--tick-ms")) {
            idx += 1;
            if (idx >= args.len) return .{ .invalid = "missing value for --tick-ms" };
            config.tick_ms = parsePositiveI64(args[idx]) catch return .{ .invalid = "invalid --tick-ms value" };
        } else if (std.mem.startsWith(u8, arg, "--tick-ms=")) {
            config.tick_ms = parsePositiveI64(arg["--tick-ms=".len..]) catch return .{ .invalid = "invalid --tick-ms value" };
        } else if (std.mem.eql(u8, arg, "--max-packets")) {
            idx += 1;
            if (idx >= args.len) return .{ .invalid = "missing value for --max-packets" };
            config.max_packets = parsePositiveUsize(args[idx]) catch return .{ .invalid = "invalid --max-packets value" };
        } else if (std.mem.startsWith(u8, arg, "--max-packets=")) {
            config.max_packets = parsePositiveUsize(arg["--max-packets=".len..]) catch return .{ .invalid = "invalid --max-packets value" };
        } else {
            return .{ .invalid = arg };
        }
    }
    return .{ .ok = config };
}

fn parsePort(value: []const u8) !u16 {
    return std.fmt.parseInt(u16, value, 10);
}

fn parsePositiveI64(value: []const u8) !i64 {
    const parsed = try std.fmt.parseInt(i64, value, 10);
    if (parsed <= 0) return error.InvalidPositiveInteger;
    return parsed;
}

fn parsePositiveUsize(value: []const u8) !usize {
    const parsed = try std.fmt.parseInt(usize, value, 10);
    if (parsed == 0) return error.InvalidPositiveInteger;
    return parsed;
}

fn peerAddrFromIp(addr: IpAddress) ?relay_service.PeerAddr {
    return switch (addr) {
        .ip4 => |ip4| .{ .host = ip4.bytes, .port = ip4.port },
        .ip6 => null,
    };
}

fn ipFromPeerAddr(addr: relay_service.PeerAddr) IpAddress {
    return .{ .ip4 = .{ .bytes = addr.host, .port = addr.port } };
}

fn monotonicMs(io: Io) i64 {
    return Io.Timestamp.now(io, .awake).toMilliseconds();
}

fn printOpen(io: Io, addr: IpAddress, config: Config) !void {
    var buffer: [512]u8 = undefined;
    var writer = Io.File.stderr().writer(io, &buffer);
    const stderr = &writer.interface;
    try stderr.print("crimson-zig relay listening on ", .{});
    try addr.format(stderr);
    try stderr.print(" tick_ms={d} max_packets={d}\n", .{ config.tick_ms, config.max_packets });
    try stderr.flush();
}

fn buildUsageOutput(allocator: std.mem.Allocator, exit_code: u8, detail: []const u8) !CommandOutput {
    const stdout: []u8 = try allocator.dupe(u8, "");
    errdefer allocator.free(stdout);
    var stderr: []u8 = undefined;
    if (detail.len == 0) {
        stderr = try allocator.dupe(u8, usage);
    } else {
        stderr = try std.fmt.allocPrint(allocator, "{s}\n{s}", .{ detail, usage });
    }
    return .{ .stdout = stdout, .stderr = stderr, .exit_code = exit_code };
}

fn emptyOutput(allocator: std.mem.Allocator, exit_code: u8) !CommandOutput {
    const stdout = try allocator.dupe(u8, "");
    errdefer allocator.free(stdout);
    const stderr = try allocator.dupe(u8, "");
    return .{ .stdout = stdout, .stderr = stderr, .exit_code = exit_code };
}

const usage =
    \\Usage:
    \\  crimson-zig relay serve [--bind ADDR] [--port PORT] [--tick-ms MS] [--max-packets N]
    \\
    \\Options:
    \\  --bind ADDR       relay bind address (default: 0.0.0.0)
    \\  --port PORT       relay UDP port (default: 31993)
    \\  --tick-ms MS      relay update tick interval (default: 8)
    \\  --max-packets N   max packets drained per tick (default: 512)
    \\
;

test "relay udp server parses defaults and inline options" {
    const parsed = parseArgs(&.{ "--bind=127.0.0.1", "--port=32000", "--tick-ms=2", "--max-packets=3" });
    const config = switch (parsed) {
        .ok => |config| config,
        else => return error.TestExpectedConfig,
    };
    try std.testing.expectEqualStrings("127.0.0.1", config.bind_host);
    try std.testing.expectEqual(@as(u16, 32000), config.bind_port);
    try std.testing.expectEqual(@as(i64, 2), config.tick_ms);
    try std.testing.expectEqual(@as(usize, 3), config.max_packets);
}

test "relay udp server accepts ephemeral port before binding" {
    switch (parseArgs(&.{ "--port", "0" })) {
        .ok => |config| try std.testing.expectEqual(@as(u16, 0), config.bind_port),
        else => return error.TestExpectedConfig,
    }
}

test "relay udp server rejects invalid values before binding" {
    switch (parseArgs(&.{ "--port", "-1" })) {
        .invalid => |detail| try std.testing.expectEqualStrings("invalid --port value", detail),
        else => return error.TestExpectedInvalidArgs,
    }
    switch (parseArgs(&.{"--tick-ms=-1"})) {
        .invalid => |detail| try std.testing.expectEqualStrings("invalid --tick-ms value", detail),
        else => return error.TestExpectedInvalidArgs,
    }
    switch (parseArgs(&.{"--max-packets=0"})) {
        .invalid => |detail| try std.testing.expectEqualStrings("invalid --max-packets value", detail),
        else => return error.TestExpectedInvalidArgs,
    }
}

test "relay udp server usage output is command scoped" {
    const output = try runRelayServe(std.testing.allocator, std.testing.io, &.{"--help"});
    defer output.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u8, 0), output.exit_code);
    try std.testing.expectEqualStrings("", output.stdout);
    try std.testing.expect(std.mem.indexOf(u8, output.stderr, "crimson-zig relay serve") != null);
}
