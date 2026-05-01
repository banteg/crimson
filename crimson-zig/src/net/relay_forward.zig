const std = @import("std");

const relay_protocol = @import("relay_protocol.zig");
const relay_room = @import("relay_room.zig");
const room_code = @import("room_code.zig");
const session_settings = @import("session_settings.zig");

pub const ForwardPlan = struct {
    reliable: bool,
};

pub const ForwardDecision = union(enum) {
    forward: ForwardPlan,
    reject: []const u8,
};

pub fn decide(room: relay_room.Room, sender_slot: i32, message: relay_protocol.NetMessage) ForwardDecision {
    if (relay_room.slotIndex(room.slots, sender_slot) == null) {
        return .{ .reject = "bad_sender_slot" };
    }

    return switch (message) {
        .rb_resync_request => if (sender_slot == 0)
            .{ .reject = "invalid_resync_sender" }
        else
            .{ .forward = .{ .reliable = true } },
        .rb_resync_begin, .rb_resync_chunk, .rb_resync_commit => if (sender_slot != 0)
            .{ .reject = "invalid_resync_sender" }
        else
            .{ .forward = .{ .reliable = true } },
        .lockstep_state_tick_frame, .lockstep_state_control => .{ .forward = .{ .reliable = true } },
        .rb_input_sample, .lockstep_state_input_batch => .{ .forward = .{ .reliable = false } },
        else => .{ .reject = "unsupported_forward_message" },
    };
}

pub fn recipientCount(room: relay_room.Room, sender_peer_id: []const u8) usize {
    var count: usize = 0;
    for (room.slots) |slot| {
        if (!slot.connected()) continue;
        if (std.mem.eql(u8, slot.peer_id, sender_peer_id)) continue;
        count += 1;
    }
    return count;
}

test "relay forward policy rejects bad sender slot" {
    const allocator = std.testing.allocator;
    const slots = try relay_room.allocSlots(allocator, 2);
    defer allocator.free(slots);
    const room: relay_room.Room = .{
        .room_code = try room_code.parseRoomCode("ABCD"),
        .session_id = "session",
        .settings = session_settings.forRelay(.{ .player_count = 2 }),
        .slots = slots,
    };

    const decision = decide(room, 4, .{ .rb_input_sample = .{} });
    switch (decision) {
        .reject => |reason| try std.testing.expectEqualStrings("bad_sender_slot", reason),
        else => return error.TestExpectedEqual,
    }
}

test "relay forward policy validates rollback resync sender roles" {
    const allocator = std.testing.allocator;
    const slots = try relay_room.allocSlots(allocator, 2);
    defer allocator.free(slots);
    const room: relay_room.Room = .{
        .room_code = try room_code.parseRoomCode("ABCD"),
        .session_id = "session",
        .settings = session_settings.forRelay(.{ .player_count = 2 }),
        .slots = slots,
    };

    switch (decide(room, 0, .{ .rb_resync_request = .{ .request_id = "rq" } })) {
        .reject => |reason| try std.testing.expectEqualStrings("invalid_resync_sender", reason),
        else => return error.TestExpectedEqual,
    }
    switch (decide(room, 1, .{ .rb_resync_request = .{ .request_id = "rq" } })) {
        .forward => |plan| try std.testing.expect(plan.reliable),
        else => return error.TestExpectedEqual,
    }
    switch (decide(room, 1, .{ .rb_resync_begin = .{ .request_id = "rq" } })) {
        .reject => |reason| try std.testing.expectEqualStrings("invalid_resync_sender", reason),
        else => return error.TestExpectedEqual,
    }
    switch (decide(room, 0, .{ .rb_resync_chunk = .{ .request_id = "rq", .payload = .{ .data = "abc" } } })) {
        .forward => |plan| try std.testing.expect(plan.reliable),
        else => return error.TestExpectedEqual,
    }
}

test "relay forward policy marks input batches unreliable and control streams reliable" {
    const allocator = std.testing.allocator;
    const slots = try relay_room.allocSlots(allocator, 2);
    defer allocator.free(slots);
    const room: relay_room.Room = .{
        .room_code = try room_code.parseRoomCode("ABCD"),
        .session_id = "session",
        .settings = session_settings.forRelay(.{ .player_count = 2 }),
        .slots = slots,
    };

    switch (decide(room, 1, .{ .rb_input_sample = .{} })) {
        .forward => |plan| try std.testing.expect(!plan.reliable),
        else => return error.TestExpectedEqual,
    }
    switch (decide(room, 1, .{ .lockstep_state_input_batch = .{} })) {
        .forward => |plan| try std.testing.expect(!plan.reliable),
        else => return error.TestExpectedEqual,
    }
    switch (decide(room, 1, .{ .lockstep_state_tick_frame = .{} })) {
        .forward => |plan| try std.testing.expect(plan.reliable),
        else => return error.TestExpectedEqual,
    }
    switch (decide(room, 1, .{ .lockstep_state_control = .{} })) {
        .forward => |plan| try std.testing.expect(plan.reliable),
        else => return error.TestExpectedEqual,
    }
}

test "relay forward recipient count skips disconnected slots and sender" {
    const allocator = std.testing.allocator;
    const slots = try relay_room.allocSlots(allocator, 4);
    defer allocator.free(slots);
    slots[0].peer_id = "host";
    slots[1].peer_id = "guest";
    slots[3].peer_id = "spectator";
    const room: relay_room.Room = .{
        .room_code = try room_code.parseRoomCode("ABCD"),
        .session_id = "session",
        .settings = session_settings.forRelay(.{ .player_count = 4 }),
        .slots = slots,
    };

    try std.testing.expectEqual(@as(usize, 2), recipientCount(room, "host"));
    try std.testing.expectEqual(@as(usize, 3), recipientCount(room, "missing"));
}
