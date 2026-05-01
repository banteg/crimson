const std = @import("std");
const msgpack = @import("msgpack");

const relay_protocol = @import("relay_protocol.zig");

const Io = std.Io;
const IpAddress = std.Io.net.IpAddress;
const Socket = std.Io.net.Socket;

pub const PeerAddr = struct {
    host: [4]u8 = .{ 127, 0, 0, 1 },
    port: u16 = 0,

    pub fn loopback(port: u16) PeerAddr {
        return .{ .host = .{ 127, 0, 0, 1 }, .port = port };
    }

    pub fn eql(self: PeerAddr, other: PeerAddr) bool {
        return std.mem.eql(u8, &self.host, &other.host) and self.port == other.port;
    }
};

pub const ReceivedPacket = struct {
    addr: PeerAddr,
    decoded: msgpack.Decoded(relay_protocol.RelayPacket),

    pub fn packet(self: *const ReceivedPacket) relay_protocol.RelayPacket {
        return self.decoded.value;
    }

    pub fn deinit(self: *ReceivedPacket) void {
        self.decoded.deinit();
        self.* = undefined;
    }
};

pub const ReceivedPackets = struct {
    items: std.ArrayList(ReceivedPacket) = .empty,

    pub fn deinit(self: *ReceivedPackets, allocator: std.mem.Allocator) void {
        for (self.items.items) |*item| item.deinit();
        self.items.deinit(allocator);
        self.* = undefined;
    }
};

pub const UdpTransport = struct {
    bind_host: []const u8 = "0.0.0.0",
    bind_port: u16 = 0,
    recv_buffer_size: usize = 64 * 1024,
    socket: ?Socket = null,
    bound_port: u16 = 0,

    pub fn open(self: *UdpTransport, io: Io) !void {
        if (self.socket != null) return;
        var bind_addr = try IpAddress.parse(self.bind_host, self.bind_port);
        const socket = try bind_addr.bind(io, .{
            .mode = .dgram,
            .protocol = .udp,
        });
        errdefer socket.close(io);
        const bound_addr = peerAddrFromIp(socket.address) orelse return error.UnsupportedAddressFamily;
        self.bound_port = bound_addr.port;
        self.socket = socket;
    }

    pub fn close(self: *UdpTransport, io: Io) void {
        if (self.socket) |socket| socket.close(io);
        self.socket = null;
        self.bound_port = 0;
    }

    pub fn boundPort(self: UdpTransport) u16 {
        return if (self.socket != null) self.bound_port else self.bind_port;
    }

    pub fn sendPacket(
        self: UdpTransport,
        allocator: std.mem.Allocator,
        io: Io,
        addr: PeerAddr,
        packet: relay_protocol.RelayPacket,
    ) !void {
        const socket = self.socket orelse return error.TransportNotOpen;
        const encoded = try relay_protocol.encodePacket(allocator, packet);
        defer allocator.free(encoded);
        try socket.send(io, &ipFromPeerAddr(addr), encoded);
    }

    pub fn recvPackets(
        self: UdpTransport,
        allocator: std.mem.Allocator,
        io: Io,
        max_packets: usize,
        first_timeout_ms: i64,
    ) !ReceivedPackets {
        var out: ReceivedPackets = .{};
        errdefer out.deinit(allocator);
        const socket = self.socket orelse return out;
        if (max_packets == 0) return out;

        const recv_buffer = try allocator.alloc(u8, self.recv_buffer_size);
        defer allocator.free(recv_buffer);

        var remaining = max_packets;
        while (remaining > 0) : (remaining -= 1) {
            const timeout_ms: i64 = if (remaining == max_packets) @max(0, first_timeout_ms) else 0;
            const incoming = socket.receiveTimeout(io, recv_buffer, timeoutFromMs(timeout_ms)) catch |err| switch (err) {
                error.Timeout => return out,
                else => return err,
            };
            if (incoming.flags.trunc) continue;
            const addr = peerAddrFromIp(incoming.from) orelse continue;
            var decoded = relay_protocol.decodePacket(allocator, incoming.data) catch continue;
            errdefer decoded.deinit();
            try out.items.append(allocator, .{ .addr = addr, .decoded = decoded });
        }

        return out;
    }
};

pub fn peerAddrFromIp(addr: IpAddress) ?PeerAddr {
    return switch (addr) {
        .ip4 => |ip4| .{ .host = ip4.bytes, .port = ip4.port },
        .ip6 => null,
    };
}

pub fn ipFromPeerAddr(addr: PeerAddr) IpAddress {
    return .{ .ip4 = .{ .bytes = addr.host, .port = addr.port } };
}

fn timeoutFromMs(milliseconds: i64) Io.Timeout {
    return .{ .duration = .{ .raw = .fromMilliseconds(milliseconds), .clock = .awake } };
}

test "relay peer addr maps ipv4 endpoints" {
    const addr = PeerAddr.loopback(relay_protocol.default_port);
    const ip = ipFromPeerAddr(addr);
    const roundtrip = peerAddrFromIp(ip).?;
    try std.testing.expect(addr.eql(roundtrip));
    try std.testing.expectEqual(@as(u16, relay_protocol.default_port), roundtrip.port);
}

test "relay udp transport sends and receives msgpack packets" {
    const allocator = std.testing.allocator;
    const io = std.Io.Threaded.global_single_threaded.io();

    var receiver: UdpTransport = .{ .bind_host = "127.0.0.1", .bind_port = 0 };
    try receiver.open(io);
    defer receiver.close(io);

    var sender: UdpTransport = .{ .bind_host = "127.0.0.1", .bind_port = 0 };
    try sender.open(io);
    defer sender.close(io);

    try sender.sendPacket(allocator, io, PeerAddr.loopback(receiver.boundPort()), .{
        .seq = 7,
        .ack = 3,
        .reliable = true,
        .message = .{ .rb_input_sample = .{
            .slot_index = 1,
            .samples = &[_]relay_protocol.RbInputSample{.{ .tick_index = 4, .packed_input = .{ .flags = 9 } }},
        } },
    });

    var packets = try receiver.recvPackets(allocator, io, 4, 100);
    defer packets.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), packets.items.items.len);
    try std.testing.expect(packets.items.items[0].addr.port != 0);

    const packet = packets.items.items[0].packet();
    try std.testing.expectEqual(@as(i32, 7), packet.seq);
    try std.testing.expectEqual(@as(i32, 3), packet.ack);
    try std.testing.expect(packet.reliable);
    switch (packet.message) {
        .rb_input_sample => |batch| {
            try std.testing.expectEqual(@as(i32, 1), batch.slot_index);
            try std.testing.expectEqual(@as(usize, 1), batch.samples.len);
            try std.testing.expectEqual(@as(i32, 4), batch.samples[0].tick_index);
            try std.testing.expectEqual(@as(u32, 9), batch.samples[0].packed_input.flags);
        },
        else => return error.ExpectedInputBatch,
    }
}
