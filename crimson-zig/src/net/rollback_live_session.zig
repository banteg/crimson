const std = @import("std");

const packed_input = @import("packed_input.zig");
const relay_reliable = @import("relay_reliable.zig");
const relay_transport = @import("relay_transport.zig");
const rollback_runtime = @import("rollback_runtime.zig");
const rollback_session = @import("rollback_session.zig");
const room_code = @import("room_code.zig");

const Io = std.Io;

pub const Options = struct {
    session: rollback_session.Options,
    server_addr: relay_transport.PeerAddr,
    bind_host: []const u8 = "0.0.0.0",
    bind_port: u16 = 0,
    max_packets_per_update: usize = 64,
};

pub const LiveSession = struct {
    transport: relay_transport.UdpTransport,
    server_addr: relay_transport.PeerAddr,
    session: rollback_session.Session,
    max_packets_per_update: usize,

    pub fn init(options: Options) LiveSession {
        return .{
            .transport = .{
                .bind_host = options.bind_host,
                .bind_port = options.bind_port,
            },
            .server_addr = options.server_addr,
            .session = rollback_session.Session.init(options.session),
            .max_packets_per_update = @max(@as(usize, 1), options.max_packets_per_update),
        };
    }

    pub fn deinit(self: *LiveSession, allocator: std.mem.Allocator, io: Io) void {
        self.close(io);
        self.session.deinit(allocator);
        self.* = undefined;
    }

    pub fn open(self: *LiveSession, io: Io) !void {
        try self.transport.open(io);
    }

    pub fn close(self: *LiveSession, io: Io) void {
        self.transport.close(io);
    }

    pub fn boundPort(self: LiveSession) u16 {
        return self.transport.boundPort();
    }

    pub fn update(self: *LiveSession, allocator: std.mem.Allocator, io: Io, now_ms: i64) !void {
        try self.open(io);
        try self.drainIncoming(allocator, io, now_ms);
        try self.session.update(allocator, now_ms);
        try self.flushSessionOutbox(allocator, io);
    }

    pub fn queueLocalInput(
        self: *LiveSession,
        allocator: std.mem.Allocator,
        io: Io,
        input: packed_input.PackedPlayerInput,
        now_ms: i64,
    ) !void {
        try self.session.queueLocalInput(allocator, input, now_ms);
        try self.flushSessionOutbox(allocator, io);
    }

    pub fn popFrame(self: *LiveSession) ?rollback_runtime.TickFrame {
        return self.session.popFrame();
    }

    fn drainIncoming(self: *LiveSession, allocator: std.mem.Allocator, io: Io, now_ms: i64) !void {
        var packets = try self.transport.recvPackets(allocator, io, self.max_packets_per_update, 0);
        defer packets.deinit(allocator);
        for (packets.items.items) |*received| {
            if (!received.addr.eql(self.server_addr)) continue;
            try self.session.handlePacket(allocator, received.packet(), now_ms);
        }
    }

    fn flushSessionOutbox(self: *LiveSession, allocator: std.mem.Allocator, io: Io) !void {
        defer self.session.clearOutbox(allocator);
        for (self.session.outbox.items.items) |packet| {
            try self.transport.sendPacket(allocator, io, self.server_addr, packet);
        }
    }
};

test "rollback live session sends hello to relay endpoint" {
    const allocator = std.testing.allocator;
    const io = std.Io.Threaded.global_single_threaded.io();

    var relay_receiver: relay_transport.UdpTransport = .{ .bind_host = "127.0.0.1", .bind_port = 0 };
    try relay_receiver.open(io);
    defer relay_receiver.close(io);

    var live = LiveSession.init(.{
        .server_addr = relay_transport.PeerAddr.loopback(relay_receiver.boundPort()),
        .bind_host = "127.0.0.1",
        .session = .{
            .role = .host,
            .mode_id = 2,
            .player_count = 2,
            .build_id = "0.1.0",
            .peer_name = "host",
        },
    });
    defer live.deinit(allocator, io);

    try live.update(allocator, io, 1000);

    var packets = try relay_receiver.recvPackets(allocator, io, 4, 100);
    defer packets.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), packets.items.items.len);
    switch (packets.items.items[0].packet().message) {
        .client_hello => |hello| {
            try std.testing.expectEqualStrings("0.1.0", hello.build_id);
            try std.testing.expectEqualStrings("host", hello.peer_name);
        },
        else => return error.ExpectedClientHello,
    }
}

test "rollback live session receives room start and packetizes local input" {
    const allocator = std.testing.allocator;
    const io = std.Io.Threaded.global_single_threaded.io();

    var relay_sender: relay_transport.UdpTransport = .{ .bind_host = "127.0.0.1", .bind_port = 0 };
    try relay_sender.open(io);
    defer relay_sender.close(io);

    var relay_receiver: relay_transport.UdpTransport = .{ .bind_host = "127.0.0.1", .bind_port = 0 };
    try relay_receiver.open(io);
    defer relay_receiver.close(io);

    var live = LiveSession.init(.{
        .server_addr = relay_transport.PeerAddr.loopback(relay_sender.boundPort()),
        .bind_host = "127.0.0.1",
        .session = .{
            .role = .host,
            .mode_id = 2,
            .player_count = 1,
            .build_id = "0.1.0",
            .input_delay_ticks = 0,
        },
    });
    defer live.deinit(allocator, io);
    try live.open(io);

    var server_link: relay_reliable.RelayReliableLink = .{};
    defer server_link.deinit(allocator);
    const code = try room_code.parseRoomCode("ABCD");
    try relay_sender.sendPacket(allocator, io, relay_transport.PeerAddr.loopback(live.boundPort()), try server_link.buildPacket(allocator, .{ .room_start = .{
        .room_code = code,
        .session_id = "s1",
        .player_count = 1,
        .slot_index = 0,
        .input_delay_ticks = 0,
        .rollback_max_ticks = 8,
    } }, true, 1000));

    try live.update(allocator, io, 1001);
    try std.testing.expect(live.session.started);
    try live.queueLocalInput(allocator, io, .{ .flags = 7 }, 1002);

    var packets = try relay_sender.recvPackets(allocator, io, 8, 100);
    defer packets.deinit(allocator);
    var saw_input = false;
    for (packets.items.items) |*received| {
        switch (received.packet().message) {
            .rb_input_sample => |batch| {
                saw_input = true;
                try std.testing.expectEqual(@as(i32, 0), batch.slot_index);
                try std.testing.expectEqual(@as(u32, 7), batch.samples[0].packed_input.flags);
            },
            else => {},
        }
    }
    try std.testing.expect(saw_input);

    const frame = live.popFrame() orelse return error.ExpectedFrame;
    try std.testing.expectEqual(@as(u32, 7), frame.input(0).flags);
}
