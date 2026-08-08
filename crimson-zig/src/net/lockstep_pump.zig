const std = @import("std");

const game_cfg = @import("../formats/game_cfg.zig");
const lockstep_client_runtime = @import("lockstep_client_runtime.zig");
const lockstep_host_runtime = @import("lockstep_host_runtime.zig");
const lockstep_outbox = @import("lockstep_outbox.zig");
const lockstep_transport = @import("lockstep_transport.zig");

const Io = std.Io;

pub const PumpOptions = struct {
    max_recv_packets: usize = 512,
    first_timeout_ms: i64 = 0,
};

pub fn drainHost(
    allocator: std.mem.Allocator,
    io: Io,
    transport: lockstep_transport.UdpTransport,
    runtime: *lockstep_host_runtime.HostRuntime,
    now_ms: i64,
    outbox: *lockstep_outbox.Outbox,
    options: PumpOptions,
) !usize {
    var packets = try transport.recvPackets(allocator, io, options.max_recv_packets, options.first_timeout_ms);
    defer packets.deinit(allocator);

    for (packets.items.items) |*item| {
        try runtime.handlePacket(allocator, item.addr, item.packet(), now_ms, outbox);
    }
    return packets.items.items.len;
}

pub fn drainClient(
    allocator: std.mem.Allocator,
    io: Io,
    transport: lockstep_transport.UdpTransport,
    runtime: *lockstep_client_runtime.ClientRuntime,
    now_ms: i64,
    outbox: *lockstep_outbox.Outbox,
    options: PumpOptions,
) !usize {
    var packets = try transport.recvPackets(allocator, io, options.max_recv_packets, options.first_timeout_ms);
    defer packets.deinit(allocator);

    for (packets.items.items) |*item| {
        try runtime.handlePacket(allocator, item.addr, item.packet(), now_ms, outbox);
    }
    return packets.items.items.len;
}

pub fn flushOutbox(
    allocator: std.mem.Allocator,
    io: Io,
    transport: lockstep_transport.UdpTransport,
    outbox: *lockstep_outbox.Outbox,
) !usize {
    defer {
        outbox.deinit(allocator);
        outbox.* = .{};
    }

    var sent: usize = 0;
    for (outbox.packets.items) |outgoing| {
        try transport.sendPacket(allocator, io, outgoing.addr, outgoing.packet);
        sent += 1;
    }
    return sent;
}

test "lockstep pump moves hello ready and match start over udp" {
    const allocator = std.testing.allocator;
    const io = std.Io.Threaded.global_single_threaded.io();

    var host_transport: lockstep_transport.UdpTransport = .{ .bind_host = "127.0.0.1", .bind_port = 0 };
    try host_transport.open(io);
    defer host_transport.close(io);

    var client_transport: lockstep_transport.UdpTransport = .{ .bind_host = "127.0.0.1", .bind_port = 0 };
    try client_transport.open(io);
    defer client_transport.close(io);

    var status = std.mem.zeroes(game_cfg.Status);
    status.play_time_ms = 42;
    var host = lockstep_host_runtime.HostRuntime.init(.{
        .mode_id = 2,
        .player_count = 2,
        .build_id = "0.1.0",
        .session_id = "session",
        .seed = 123,
        .status = status,
    });
    defer host.deinit(allocator);

    var client = lockstep_client_runtime.ClientRuntime.init(.{
        .mode_id = 2,
        .player_count = 2,
        .build_id = "0.1.0",
        .host_addr = lockstep_transport.PeerAddr.loopback(host_transport.boundPort()),
    });
    defer client.deinit(allocator);

    var client_outbox: lockstep_outbox.Outbox = .{};
    try client.sendHello(allocator, 10, &client_outbox);
    try std.testing.expectEqual(@as(usize, 1), try flushOutbox(allocator, io, client_transport, &client_outbox));

    var host_outbox: lockstep_outbox.Outbox = .{};
    const host_seen_hello = try drainHost(allocator, io, host_transport, &host, 20, &host_outbox, .{ .first_timeout_ms = 100 });
    try std.testing.expectEqual(@as(usize, 1), host_seen_hello);
    try std.testing.expectEqual(@as(usize, 1), host.peerCount());
    try std.testing.expect(host_outbox.packets.items.len >= 2);
    _ = try flushOutbox(allocator, io, host_transport, &host_outbox);

    var ready_outbox: lockstep_outbox.Outbox = .{};
    const client_seen_lobby = try drainClient(allocator, io, client_transport, &client, 30, &ready_outbox, .{
        .max_recv_packets = 4,
        .first_timeout_ms = 100,
    });
    try std.testing.expect(client_seen_lobby >= 2);
    try std.testing.expect(client.lobby.joined());
    try std.testing.expectEqual(@as(i32, 1), client.lobby.slotIndex());
    try std.testing.expect(client.lobby.lobby_state_latest != null);
    try std.testing.expectEqual(@as(usize, 1), try flushOutbox(allocator, io, client_transport, &ready_outbox));

    var start_outbox: lockstep_outbox.Outbox = .{};
    const host_seen_ready = try drainHost(allocator, io, host_transport, &host, 40, &start_outbox, .{ .first_timeout_ms = 100 });
    try std.testing.expectEqual(@as(usize, 1), host_seen_ready);
    try std.testing.expect(host.started);
    try std.testing.expect(host.lockstep != null);
    _ = try flushOutbox(allocator, io, host_transport, &start_outbox);

    var final_client_outbox: lockstep_outbox.Outbox = .{};
    defer final_client_outbox.deinit(allocator);
    const client_seen_start = try drainClient(allocator, io, client_transport, &client, 50, &final_client_outbox, .{
        .max_recv_packets = 4,
        .first_timeout_ms = 100,
    });
    try std.testing.expect(client_seen_start >= 1);
    try std.testing.expect(client.started);
    try std.testing.expect(client.lockstep != null);
    try std.testing.expectEqual(@as(usize, 0), final_client_outbox.packets.items.len);
}

test "lockstep pump flush clears sent outbox packets" {
    const allocator = std.testing.allocator;
    const io = std.Io.Threaded.global_single_threaded.io();

    var sender: lockstep_transport.UdpTransport = .{ .bind_host = "127.0.0.1", .bind_port = 0 };
    try sender.open(io);
    defer sender.close(io);

    var receiver: lockstep_transport.UdpTransport = .{ .bind_host = "127.0.0.1", .bind_port = 0 };
    try receiver.open(io);
    defer receiver.close(io);

    var outbox: lockstep_outbox.Outbox = .{};
    try outbox.appendPacket(allocator, lockstep_transport.PeerAddr.loopback(receiver.boundPort()), .{
        .seq = 1,
        .reliable = true,
        .message = .{ .welcome = .{
            .accepted = true,
            .session_id = "session",
            .build_id = "0.1.0",
        } },
    });

    try std.testing.expectEqual(@as(usize, 1), try flushOutbox(allocator, io, sender, &outbox));
    try std.testing.expectEqual(@as(usize, 0), outbox.packets.items.len);

    var packets = try receiver.recvPackets(allocator, io, 1, 100);
    defer packets.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), packets.items.items.len);
    switch (packets.items.items[0].packet().message) {
        .welcome => |welcome| try std.testing.expectEqualStrings("session", welcome.session_id),
        else => return error.TestExpectedEqual,
    }
}
