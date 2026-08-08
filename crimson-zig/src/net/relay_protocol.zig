const std = @import("std");
const msgpack = @import("msgpack");

const game_cfg = @import("../formats/game_cfg.zig");
const lockstep_protocol = @import("lockstep_protocol.zig");
const packed_input = @import("packed_input.zig");
const quest_level = @import("../quest_level.zig");
const room_code = @import("room_code.zig");
const schema_shared = @import("schema_shared.zig");

pub const protocol_version: i32 = 6;
pub const default_port: u16 = 31993;
pub const tick_rate: i32 = lockstep_protocol.tick_rate;
pub const max_players: i32 = lockstep_protocol.max_players;
pub const reliable_resend_ms: i32 = lockstep_protocol.reliable_resend_ms;
pub const input_delay_ticks: i32 = 1;
pub const rollback_max_ticks: i32 = 8;
pub const reconnect_timeout_ms: i32 = 15_000;
pub const link_timeout_ms: i32 = 5_000;
pub const ping_interval_ms: i32 = 250;
pub const resync_chunk_payload_bytes: i32 = 1_024;
pub const resync_max_snapshot_bytes: i32 = 2_097_152;

pub const NetcodeMode = struct {
    pub const Tag = enum {
        rollback,
        lockstep,
    };

    pub const rollback: NetcodeMode = .{ .value = .rollback };
    pub const lockstep: NetcodeMode = .{ .value = .lockstep };

    value: Tag,

    pub fn msgpackWrite(self: NetcodeMode, packer: anytype) !void {
        try packer.writeString(@tagName(self.value));
    }

    pub fn msgpackRead(unpacker: anytype) !NetcodeMode {
        const text = try unpacker.readString();
        if (std.mem.eql(u8, text, "rollback")) return rollback;
        if (std.mem.eql(u8, text, "lockstep")) return lockstep;
        return error.InvalidNetcodeMode;
    }
};

pub const RelaySlot = schema_shared.SlotState;

pub const ClientHello = struct {
    protocol_version: i32 = protocol_version,
    build_id: []const u8 = "",
    peer_name: []const u8 = "",
};

pub const ClientWelcome = struct {
    accepted: bool = false,
    reason: []const u8 = "",
    protocol_version: i32 = protocol_version,
    build_id: []const u8 = "",
    peer_id: []const u8 = "",
};

pub const RoomCreate = struct {
    mode_id: i32 = 0,
    player_count: i32 = 1,
    quest_level: ?quest_level.QuestLevel = null,
    preserve_bugs: bool = false,
    tick_rate: i32 = tick_rate,
    input_delay_ticks: i32 = input_delay_ticks,
    rollback_max_ticks: i32 = rollback_max_ticks,
    netcode_mode: NetcodeMode = NetcodeMode.rollback,
    status: ?game_cfg.Status = null,
};

pub const RoomJoin = struct {
    room_code: ?room_code.RoomCode = null,
    reconnect_token: []const u8 = "",
};

pub const RoomReady = struct {
    slot_index: i32 = -1,
    ready: bool = false,
};

pub const RoomState = struct {
    room_code: room_code.RoomCode,
    session_id: []const u8 = "",
    mode_id: i32 = 0,
    player_count: i32 = 1,
    quest_level: ?quest_level.QuestLevel = null,
    preserve_bugs: bool = false,
    tick_rate: i32 = tick_rate,
    input_delay_ticks: i32 = input_delay_ticks,
    rollback_max_ticks: i32 = rollback_max_ticks,
    netcode_mode: NetcodeMode = NetcodeMode.rollback,
    slots: []const RelaySlot = &.{},
    all_ready: bool = false,
    started: bool = false,
};

pub const RoomStart = struct {
    room_code: room_code.RoomCode,
    session_id: []const u8 = "",
    seed: i32 = 0,
    start_tick: i32 = 0,
    mode_id: i32 = 0,
    player_count: i32 = 1,
    quest_level: ?quest_level.QuestLevel = null,
    preserve_bugs: bool = false,
    tick_rate: i32 = tick_rate,
    input_delay_ticks: i32 = input_delay_ticks,
    rollback_max_ticks: i32 = rollback_max_ticks,
    netcode_mode: NetcodeMode = NetcodeMode.rollback,
    slot_index: i32 = -1,
    host_slot_index: i32 = 0,
    reconnect_token: []const u8 = "",
    status: ?game_cfg.Status = null,
};

pub const PeerDisconnect = struct {
    slot_index: i32 = -1,
    reason: []const u8 = "",
};

pub const RelayError = struct {
    reason: []const u8 = "",
};

pub const Ping = struct {
    stamp_ms: i32 = 0,
};

pub const Pong = struct {
    stamp_ms: i32 = 0,
};

pub const RbInputSample = struct {
    tick_index: i32 = 0,
    packed_input: packed_input.PackedPlayerInput = .{},
};

pub const RbInputBatch = struct {
    slot_index: i32 = -1,
    samples: []const RbInputSample = &.{},
};

pub const RbResyncRequest = struct {
    request_id: []const u8 = "",
    from_tick: i32 = 0,
    reason: []const u8 = "",
    requested_by_slot: i32 = -1,
};

pub const RbResyncBegin = struct {
    request_id: []const u8 = "",
    snapshot_tick: i32 = 0,
    codec: []const u8 = "msgpack_state_v1",
    total_chunks: i32 = 0,
    compressed_size: i32 = 0,
    uncompressed_size: i32 = 0,
};

pub const RbResyncChunk = struct {
    request_id: []const u8 = "",
    chunk_index: i32 = 0,
    payload: schema_shared.WireBytes = .{},
};

pub const RbResyncCommit = struct {
    request_id: []const u8 = "",
    snapshot_tick: i32 = 0,
};

pub const LockstepInputBatch = struct {
    payload: schema_shared.WireBytes = .{},
};

pub const LockstepTickFrame = struct {
    payload: schema_shared.WireBytes = .{},
};

pub const LockstepControl = struct {
    payload: schema_shared.WireBytes = .{},
};

pub const NetMessage = union(enum) {
    client_hello: ClientHello,
    client_welcome: ClientWelcome,
    room_create: RoomCreate,
    room_join: RoomJoin,
    room_ready: RoomReady,
    room_state: RoomState,
    room_start: RoomStart,
    peer_disconnect: PeerDisconnect,
    relay_error: RelayError,
    ping: Ping,
    pong: Pong,
    rb_input_sample: RbInputBatch,
    rb_resync_request: RbResyncRequest,
    rb_resync_begin: RbResyncBegin,
    rb_resync_chunk: RbResyncChunk,
    rb_resync_commit: RbResyncCommit,
    lockstep_state_input_batch: LockstepInputBatch,
    lockstep_state_tick_frame: LockstepTickFrame,
    lockstep_state_control: LockstepControl,

    pub fn msgpackFormat() msgpack.UnionFormat {
        return .{ .as_tagged = .{
            .tag_field = "type",
            .tag_value = .field_name,
        } };
    }
};

pub const RelayPacket = struct {
    seq: i32 = 0,
    ack: i32 = 0,
    reliable: bool = false,
    message: NetMessage = .{ .ping = .{} },
};

pub fn encodePacket(allocator: std.mem.Allocator, packet: RelayPacket) ![]u8 {
    var writer: std.Io.Writer.Allocating = .init(allocator);
    errdefer writer.deinit();
    try msgpack.encode(packet, &writer.writer);
    return writer.toOwnedSlice();
}

pub fn decodePacket(allocator: std.mem.Allocator, blob: []const u8) !msgpack.Decoded(RelayPacket) {
    return msgpack.decodeFromSlice(RelayPacket, allocator, blob);
}

/// Deep-copy packet payload slices so reliable resend buffers can outlive decoded or dispatch-owned storage.
pub fn clonePacket(allocator: std.mem.Allocator, packet: RelayPacket) !RelayPacket {
    return .{
        .seq = packet.seq,
        .ack = packet.ack,
        .reliable = packet.reliable,
        .message = try cloneMessage(allocator, packet.message),
    };
}

/// Free packet payload slices allocated by clonePacket.
pub fn deinitPacket(allocator: std.mem.Allocator, packet: *RelayPacket) void {
    deinitMessage(allocator, &packet.message);
    packet.* = undefined;
}

/// Deep-copy message payload slices so packets can be retained across relay ticks.
pub fn cloneMessage(allocator: std.mem.Allocator, message: NetMessage) !NetMessage {
    return switch (message) {
        .client_hello => |hello| .{ .client_hello = .{
            .protocol_version = hello.protocol_version,
            .build_id = try dupeBytes(allocator, hello.build_id),
            .peer_name = try dupeBytes(allocator, hello.peer_name),
        } },
        .client_welcome => |welcome| .{ .client_welcome = .{
            .accepted = welcome.accepted,
            .reason = try dupeBytes(allocator, welcome.reason),
            .protocol_version = welcome.protocol_version,
            .build_id = try dupeBytes(allocator, welcome.build_id),
            .peer_id = try dupeBytes(allocator, welcome.peer_id),
        } },
        .room_create => |create| .{ .room_create = create },
        .room_join => |join| .{ .room_join = .{
            .room_code = join.room_code,
            .reconnect_token = try dupeBytes(allocator, join.reconnect_token),
        } },
        .room_ready => |ready| .{ .room_ready = ready },
        .room_state => |state| .{ .room_state = try cloneRoomState(allocator, state) },
        .room_start => |start| .{ .room_start = .{
            .room_code = start.room_code,
            .session_id = try dupeBytes(allocator, start.session_id),
            .seed = start.seed,
            .start_tick = start.start_tick,
            .mode_id = start.mode_id,
            .player_count = start.player_count,
            .quest_level = start.quest_level,
            .preserve_bugs = start.preserve_bugs,
            .tick_rate = start.tick_rate,
            .input_delay_ticks = start.input_delay_ticks,
            .rollback_max_ticks = start.rollback_max_ticks,
            .netcode_mode = start.netcode_mode,
            .slot_index = start.slot_index,
            .host_slot_index = start.host_slot_index,
            .reconnect_token = try dupeBytes(allocator, start.reconnect_token),
            .status = start.status,
        } },
        .peer_disconnect => |disconnect| .{ .peer_disconnect = .{
            .slot_index = disconnect.slot_index,
            .reason = try dupeBytes(allocator, disconnect.reason),
        } },
        .relay_error => |err| .{ .relay_error = .{ .reason = try dupeBytes(allocator, err.reason) } },
        .ping => |ping| .{ .ping = ping },
        .pong => |pong| .{ .pong = pong },
        .rb_input_sample => |batch| .{ .rb_input_sample = try cloneInputBatch(allocator, batch) },
        .rb_resync_request => |request| .{ .rb_resync_request = .{
            .request_id = try dupeBytes(allocator, request.request_id),
            .from_tick = request.from_tick,
            .reason = try dupeBytes(allocator, request.reason),
            .requested_by_slot = request.requested_by_slot,
        } },
        .rb_resync_begin => |begin| .{ .rb_resync_begin = .{
            .request_id = try dupeBytes(allocator, begin.request_id),
            .snapshot_tick = begin.snapshot_tick,
            .codec = try dupeBytes(allocator, begin.codec),
            .total_chunks = begin.total_chunks,
            .compressed_size = begin.compressed_size,
            .uncompressed_size = begin.uncompressed_size,
        } },
        .rb_resync_chunk => |chunk| .{ .rb_resync_chunk = .{
            .request_id = try dupeBytes(allocator, chunk.request_id),
            .chunk_index = chunk.chunk_index,
            .payload = .{ .data = try dupeBytes(allocator, chunk.payload.data) },
        } },
        .rb_resync_commit => |commit| .{ .rb_resync_commit = .{
            .request_id = try dupeBytes(allocator, commit.request_id),
            .snapshot_tick = commit.snapshot_tick,
        } },
        .lockstep_state_input_batch => |batch| .{ .lockstep_state_input_batch = .{ .payload = .{ .data = try dupeBytes(allocator, batch.payload.data) } } },
        .lockstep_state_tick_frame => |frame| .{ .lockstep_state_tick_frame = .{ .payload = .{ .data = try dupeBytes(allocator, frame.payload.data) } } },
        .lockstep_state_control => |control| .{ .lockstep_state_control = .{ .payload = .{ .data = try dupeBytes(allocator, control.payload.data) } } },
    };
}

/// Free message payload slices allocated by cloneMessage.
pub fn deinitMessage(allocator: std.mem.Allocator, message: *NetMessage) void {
    switch (message.*) {
        .client_hello => |hello| {
            freeBytes(allocator, hello.build_id);
            freeBytes(allocator, hello.peer_name);
        },
        .client_welcome => |welcome| {
            freeBytes(allocator, welcome.reason);
            freeBytes(allocator, welcome.build_id);
            freeBytes(allocator, welcome.peer_id);
        },
        .room_create => {},
        .room_join => |join| freeBytes(allocator, join.reconnect_token),
        .room_ready => {},
        .room_state => |state| deinitRoomState(allocator, state),
        .room_start => |start| {
            freeBytes(allocator, start.session_id);
            freeBytes(allocator, start.reconnect_token);
        },
        .peer_disconnect => |disconnect| freeBytes(allocator, disconnect.reason),
        .relay_error => |err| freeBytes(allocator, err.reason),
        .ping, .pong => {},
        .rb_input_sample => |batch| freeSamples(allocator, batch.samples),
        .rb_resync_request => |request| {
            freeBytes(allocator, request.request_id);
            freeBytes(allocator, request.reason);
        },
        .rb_resync_begin => |begin| {
            freeBytes(allocator, begin.request_id);
            freeBytes(allocator, begin.codec);
        },
        .rb_resync_chunk => |chunk| {
            freeBytes(allocator, chunk.request_id);
            freeBytes(allocator, chunk.payload.data);
        },
        .rb_resync_commit => |commit| freeBytes(allocator, commit.request_id),
        .lockstep_state_input_batch => |batch| freeBytes(allocator, batch.payload.data),
        .lockstep_state_tick_frame => |frame| freeBytes(allocator, frame.payload.data),
        .lockstep_state_control => |control| freeBytes(allocator, control.payload.data),
    }
    message.* = undefined;
}

fn cloneRoomState(allocator: std.mem.Allocator, state: RoomState) !RoomState {
    const slots = try cloneSlots(allocator, state.slots);
    errdefer deinitSlots(allocator, slots);
    return .{
        .room_code = state.room_code,
        .session_id = try dupeBytes(allocator, state.session_id),
        .mode_id = state.mode_id,
        .player_count = state.player_count,
        .quest_level = state.quest_level,
        .preserve_bugs = state.preserve_bugs,
        .tick_rate = state.tick_rate,
        .input_delay_ticks = state.input_delay_ticks,
        .rollback_max_ticks = state.rollback_max_ticks,
        .netcode_mode = state.netcode_mode,
        .slots = slots,
        .all_ready = state.all_ready,
        .started = state.started,
    };
}

fn deinitRoomState(allocator: std.mem.Allocator, state: RoomState) void {
    freeBytes(allocator, state.session_id);
    deinitSlots(allocator, state.slots);
}

fn cloneSlots(allocator: std.mem.Allocator, slots: []const RelaySlot) ![]RelaySlot {
    if (slots.len == 0) return &.{};
    const out = try allocator.alloc(RelaySlot, slots.len);
    errdefer allocator.free(out);
    var initialized: usize = 0;
    errdefer {
        for (out[0..initialized]) |slot| freeBytes(allocator, slot.peer_name);
    }
    for (slots, 0..) |slot, idx| {
        out[idx] = .{
            .slot_index = slot.slot_index,
            .connected = slot.connected,
            .ready = slot.ready,
            .is_host = slot.is_host,
            .peer_name = try dupeBytes(allocator, slot.peer_name),
        };
        initialized += 1;
    }
    return out;
}

fn deinitSlots(allocator: std.mem.Allocator, slots: []const RelaySlot) void {
    for (slots) |slot| freeBytes(allocator, slot.peer_name);
    if (slots.len != 0) allocator.free(slots);
}

fn cloneInputBatch(allocator: std.mem.Allocator, batch: RbInputBatch) !RbInputBatch {
    return .{
        .slot_index = batch.slot_index,
        .samples = try dupeSamples(allocator, batch.samples),
    };
}

fn dupeSamples(allocator: std.mem.Allocator, samples: []const RbInputSample) ![]RbInputSample {
    if (samples.len == 0) return &.{};
    return allocator.dupe(RbInputSample, samples);
}

fn freeSamples(allocator: std.mem.Allocator, samples: []const RbInputSample) void {
    if (samples.len != 0) allocator.free(samples);
}

fn dupeBytes(allocator: std.mem.Allocator, value: []const u8) ![]const u8 {
    if (value.len == 0) return "";
    return allocator.dupe(u8, value);
}

fn freeBytes(allocator: std.mem.Allocator, value: []const u8) void {
    if (value.len != 0) allocator.free(value);
}

test "relay protocol constants mirror python defaults" {
    try std.testing.expectEqual(@as(i32, 6), protocol_version);
    try std.testing.expectEqual(@as(u16, 31993), default_port);
    try std.testing.expectEqual(@as(i32, 60), tick_rate);
    try std.testing.expectEqual(@as(i32, 4), max_players);
    try std.testing.expectEqual(@as(i32, 40), reliable_resend_ms);
    try std.testing.expectEqual(@as(i32, 1), input_delay_ticks);
    try std.testing.expectEqual(@as(i32, 8), rollback_max_ticks);
    try std.testing.expectEqual(@as(i32, 15_000), reconnect_timeout_ms);
    try std.testing.expectEqual(@as(i32, 5_000), link_timeout_ms);
    try std.testing.expectEqual(@as(i32, 250), ping_interval_ms);
    try std.testing.expectEqual(@as(i32, 1_024), resync_chunk_payload_bytes);
    try std.testing.expectEqual(@as(i32, 2_097_152), resync_max_snapshot_bytes);
}

test "relay client handshake messages mirror python defaults" {
    const hello: ClientHello = .{};
    try std.testing.expectEqual(@as(i32, protocol_version), hello.protocol_version);
    try std.testing.expectEqualStrings("", hello.build_id);
    try std.testing.expectEqualStrings("", hello.peer_name);

    const welcome: ClientWelcome = .{};
    try std.testing.expect(!welcome.accepted);
    try std.testing.expectEqualStrings("", welcome.reason);
    try std.testing.expectEqual(@as(i32, protocol_version), welcome.protocol_version);
    try std.testing.expectEqualStrings("", welcome.build_id);
    try std.testing.expectEqualStrings("", welcome.peer_id);
}

test "relay room control messages mirror python defaults" {
    const join: RoomJoin = .{};
    try std.testing.expect(join.room_code == null);
    try std.testing.expectEqualStrings("", join.reconnect_token);

    const ready: RoomReady = .{};
    try std.testing.expectEqual(@as(i32, -1), ready.slot_index);
    try std.testing.expect(!ready.ready);

    const disconnect: PeerDisconnect = .{};
    try std.testing.expectEqual(@as(i32, -1), disconnect.slot_index);
    try std.testing.expectEqualStrings("", disconnect.reason);

    const err: RelayError = .{};
    try std.testing.expectEqualStrings("", err.reason);
}

test "relay room session messages mirror python defaults" {
    const code = try room_code.parseRoomCode("ABCD");
    const create: RoomCreate = .{};
    try std.testing.expectEqual(@as(i32, 0), create.mode_id);
    try std.testing.expectEqual(@as(i32, 1), create.player_count);
    try std.testing.expect(create.quest_level == null);
    try std.testing.expect(!create.preserve_bugs);
    try std.testing.expectEqual(@as(i32, tick_rate), create.tick_rate);
    try std.testing.expectEqual(@as(i32, input_delay_ticks), create.input_delay_ticks);
    try std.testing.expectEqual(@as(i32, rollback_max_ticks), create.rollback_max_ticks);
    try std.testing.expectEqual(NetcodeMode.rollback, create.netcode_mode);
    try std.testing.expect(create.status == null);

    const state: RoomState = .{ .room_code = code };
    try std.testing.expectEqualStrings("abcd", room_code.roomCodeSlice(&state.room_code));
    try std.testing.expectEqualStrings("", state.session_id);
    try std.testing.expectEqual(@as(usize, 0), state.slots.len);
    try std.testing.expect(!state.all_ready);
    try std.testing.expect(!state.started);

    const start: RoomStart = .{ .room_code = code };
    try std.testing.expectEqualStrings("abcd", room_code.roomCodeSlice(&start.room_code));
    try std.testing.expectEqual(@as(i32, 0), start.seed);
    try std.testing.expectEqual(@as(i32, 0), start.start_tick);
    try std.testing.expectEqual(@as(i32, -1), start.slot_index);
    try std.testing.expectEqual(@as(i32, 0), start.host_slot_index);
    try std.testing.expectEqualStrings("", start.reconnect_token);
    try std.testing.expect(start.status == null);
}

test "relay ping messages mirror python defaults and carry stamps" {
    const ping: Ping = .{};
    try std.testing.expectEqual(@as(i32, 0), ping.stamp_ms);
    const pong: Pong = .{ .stamp_ms = 1234 };
    try std.testing.expectEqual(@as(i32, 1234), pong.stamp_ms);
}

test "relay rollback input messages carry packed player input" {
    const sample: RbInputSample = .{
        .tick_index = 7,
        .packed_input = .{
            .move_x = 1.0,
            .move_y = -1.0,
            .aim_x = 2.5,
            .aim_y = 3.5,
            .flags = 9,
        },
    };
    const samples = [_]RbInputSample{sample};
    const batch: RbInputBatch = .{ .slot_index = 2, .samples = samples[0..] };
    try std.testing.expectEqual(@as(i32, 2), batch.slot_index);
    try std.testing.expectEqual(@as(usize, 1), batch.samples.len);
    try std.testing.expectEqual(@as(i32, 7), batch.samples[0].tick_index);
    try std.testing.expectEqual(@as(f32, 1.0), batch.samples[0].packed_input.move_x);
    try std.testing.expectEqual(@as(f32, -1.0), batch.samples[0].packed_input.move_y);
    try std.testing.expectEqual(@as(u32, 9), batch.samples[0].packed_input.flags);

    const empty: RbInputBatch = .{};
    try std.testing.expectEqual(@as(i32, -1), empty.slot_index);
    try std.testing.expectEqual(@as(usize, 0), empty.samples.len);
}

test "relay rollback resync messages mirror python defaults" {
    const request: RbResyncRequest = .{};
    try std.testing.expectEqualStrings("", request.request_id);
    try std.testing.expectEqual(@as(i32, 0), request.from_tick);
    try std.testing.expectEqualStrings("", request.reason);
    try std.testing.expectEqual(@as(i32, -1), request.requested_by_slot);

    const begin: RbResyncBegin = .{};
    try std.testing.expectEqualStrings("", begin.request_id);
    try std.testing.expectEqual(@as(i32, 0), begin.snapshot_tick);
    try std.testing.expectEqualStrings("msgpack_state_v1", begin.codec);
    try std.testing.expectEqual(@as(i32, 0), begin.total_chunks);
    try std.testing.expectEqual(@as(i32, 0), begin.compressed_size);
    try std.testing.expectEqual(@as(i32, 0), begin.uncompressed_size);

    const chunk: RbResyncChunk = .{ .request_id = "r1", .chunk_index = 2, .payload = .{ .data = "abc" } };
    try std.testing.expectEqualStrings("r1", chunk.request_id);
    try std.testing.expectEqual(@as(i32, 2), chunk.chunk_index);
    try std.testing.expectEqualStrings("abc", chunk.payload.data);

    const commit: RbResyncCommit = .{ .request_id = "r1", .snapshot_tick = 42 };
    try std.testing.expectEqualStrings("r1", commit.request_id);
    try std.testing.expectEqual(@as(i32, 42), commit.snapshot_tick);
}

test "relay lockstep payload wrappers mirror python defaults" {
    const input_batch: LockstepInputBatch = .{};
    try std.testing.expectEqualStrings("", input_batch.payload.data);
    const tick_frame: LockstepTickFrame = .{ .payload = .{ .data = "frame" } };
    try std.testing.expectEqualStrings("frame", tick_frame.payload.data);
    const control: LockstepControl = .{ .payload = .{ .data = "control" } };
    try std.testing.expectEqualStrings("control", control.payload.data);
}

test "relay packet encodes and decodes tagged ping message" {
    const packet: RelayPacket = .{
        .seq = 7,
        .ack = 6,
        .reliable = true,
        .message = .{ .ping = .{ .stamp_ms = 1234 } },
    };
    const encoded = try encodePacket(std.testing.allocator, packet);
    defer std.testing.allocator.free(encoded);

    const decoded = try decodePacket(std.testing.allocator, encoded);
    defer decoded.deinit();
    try std.testing.expectEqual(@as(i32, 7), decoded.value.seq);
    try std.testing.expectEqual(@as(i32, 6), decoded.value.ack);
    try std.testing.expect(decoded.value.reliable);
    switch (decoded.value.message) {
        .ping => |ping| try std.testing.expectEqual(@as(i32, 1234), ping.stamp_ms),
        else => return error.TestExpectedEqual,
    }
}

test "relay packet encodes and decodes status-bearing room start" {
    const code = try room_code.parseRoomCode("ABCD");
    var status = std.mem.zeroes(game_cfg.Status);
    status.play_time_ms = 99;
    const packet: RelayPacket = .{
        .message = .{ .room_start = .{
            .room_code = code,
            .session_id = "session",
            .seed = 42,
            .status = status,
        } },
    };
    const encoded = try encodePacket(std.testing.allocator, packet);
    defer std.testing.allocator.free(encoded);

    const decoded = try decodePacket(std.testing.allocator, encoded);
    defer decoded.deinit();
    switch (decoded.value.message) {
        .room_start => |start| {
            try std.testing.expectEqualStrings("abcd", room_code.roomCodeSlice(&start.room_code));
            try std.testing.expectEqualStrings("session", start.session_id);
            try std.testing.expectEqual(@as(i32, 42), start.seed);
            try std.testing.expectEqual(@as(u32, 99), start.status.?.play_time_ms);
        },
        else => return error.TestExpectedEqual,
    }
}

test "relay packet decodes python msgspec rollback resync chunk fixture" {
    const fixture =
        "84a373657104a361636b03a872656c6961626c65c3a76d65737361676584a474797065af72625f726573796e635f6368756e6baa726571756573745f6964a172ab6368756e6b5f696e64657802a77061796c6f6164c403616263";
    var bytes: [fixture.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&bytes, fixture);

    const decoded = try decodePacket(std.testing.allocator, &bytes);
    defer decoded.deinit();
    try std.testing.expectEqual(@as(i32, 4), decoded.value.seq);
    try std.testing.expectEqual(@as(i32, 3), decoded.value.ack);
    try std.testing.expect(decoded.value.reliable);
    switch (decoded.value.message) {
        .rb_resync_chunk => |chunk| {
            try std.testing.expectEqualStrings("r", chunk.request_id);
            try std.testing.expectEqual(@as(i32, 2), chunk.chunk_index);
            try std.testing.expectEqualStrings("abc", chunk.payload.data);
        },
        else => return error.TestExpectedEqual,
    }
}

test "relay packet decodes python msgspec lockstep payload fixture" {
    const fixture =
        "84a373657105a361636b04a872656c6961626c65c3a76d65737361676582a474797065ba6c6f636b737465705f73746174655f696e7075745f6261746368a77061796c6f6164c4077061796c6f6164";
    var bytes: [fixture.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&bytes, fixture);

    const decoded = try decodePacket(std.testing.allocator, &bytes);
    defer decoded.deinit();
    try std.testing.expectEqual(@as(i32, 5), decoded.value.seq);
    try std.testing.expectEqual(@as(i32, 4), decoded.value.ack);
    try std.testing.expect(decoded.value.reliable);
    switch (decoded.value.message) {
        .lockstep_state_input_batch => |batch| try std.testing.expectEqualStrings("payload", batch.payload.data),
        else => return error.TestExpectedEqual,
    }
}

test "relay packet decodes python msgspec room create fixture" {
    const fixture =
        "84a373657102a361636b01a872656c6961626c65c3a76d6573736167658aa474797065ab726f6f6d5f637265617465a76d6f64655f696400ac706c617965725f636f756e7402ab71756573745f6c6576656cc0ad70726573657276655f62756773c2a97469636b5f726174653cb1696e7075745f64656c61795f7469636b7301b2726f6c6c6261636b5f6d61785f7469636b7308ac6e6574636f64655f6d6f6465a8726f6c6c6261636ba6737461747573c0";
    var bytes: [fixture.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&bytes, fixture);

    const decoded = try decodePacket(std.testing.allocator, &bytes);
    defer decoded.deinit();
    try std.testing.expectEqual(@as(i32, 2), decoded.value.seq);
    try std.testing.expectEqual(@as(i32, 1), decoded.value.ack);
    try std.testing.expect(decoded.value.reliable);
    switch (decoded.value.message) {
        .room_create => |create| {
            try std.testing.expectEqual(@as(i32, 2), create.player_count);
            try std.testing.expectEqual(NetcodeMode.rollback, create.netcode_mode);
        },
        else => return error.TestExpectedEqual,
    }
}

test "relay packet clone owns decoded room state slices" {
    const code = try room_code.parseRoomCode("ABCD");
    const slots = [_]RelaySlot{
        .{ .slot_index = 0, .connected = true, .ready = true, .is_host = true, .peer_name = "host" },
        .{ .slot_index = 1, .connected = true, .ready = false, .peer_name = "guest" },
    };
    const packet: RelayPacket = .{
        .seq = 3,
        .ack = 2,
        .reliable = true,
        .message = .{ .room_state = .{
            .room_code = code,
            .session_id = "session",
            .slots = slots[0..],
            .all_ready = false,
            .started = false,
        } },
    };
    const encoded = try encodePacket(std.testing.allocator, packet);
    defer std.testing.allocator.free(encoded);

    var clone: RelayPacket = undefined;
    {
        const decoded = try decodePacket(std.testing.allocator, encoded);
        defer decoded.deinit();
        clone = try clonePacket(std.testing.allocator, decoded.value);
    }
    defer deinitPacket(std.testing.allocator, &clone);

    try std.testing.expectEqual(@as(i32, 3), clone.seq);
    switch (clone.message) {
        .room_state => |state| {
            try std.testing.expectEqualStrings("session", state.session_id);
            try std.testing.expectEqual(@as(usize, 2), state.slots.len);
            try std.testing.expectEqualStrings("host", state.slots[0].peer_name);
            try std.testing.expectEqualStrings("guest", state.slots[1].peer_name);
        },
        else => return error.TestExpectedEqual,
    }
}

test "relay packet clone owns binary and string payloads" {
    const packet: RelayPacket = .{
        .seq = 4,
        .ack = 3,
        .reliable = true,
        .message = .{ .rb_resync_chunk = .{
            .request_id = "request",
            .chunk_index = 1,
            .payload = .{ .data = "payload" },
        } },
    };
    const encoded = try encodePacket(std.testing.allocator, packet);
    defer std.testing.allocator.free(encoded);

    var clone: RelayPacket = undefined;
    {
        const decoded = try decodePacket(std.testing.allocator, encoded);
        defer decoded.deinit();
        clone = try clonePacket(std.testing.allocator, decoded.value);
    }
    defer deinitPacket(std.testing.allocator, &clone);

    switch (clone.message) {
        .rb_resync_chunk => |chunk| {
            try std.testing.expectEqualStrings("request", chunk.request_id);
            try std.testing.expectEqual(@as(i32, 1), chunk.chunk_index);
            try std.testing.expectEqualStrings("payload", chunk.payload.data);
        },
        else => return error.TestExpectedEqual,
    }
}

fn clonePacketAllocationFailureImpl(allocator: std.mem.Allocator) !void {
    const code = try room_code.parseRoomCode("ABCD");
    const slots = [_]RelaySlot{
        .{ .slot_index = 0, .connected = true, .ready = true, .is_host = true, .peer_name = "host" },
        .{ .slot_index = 1, .connected = true, .ready = false, .peer_name = "guest" },
    };
    var clone = try clonePacket(allocator, .{
        .message = .{ .room_state = .{
            .room_code = code,
            .session_id = "session",
            .slots = slots[0..],
        } },
    });
    defer deinitPacket(allocator, &clone);
}

test "relay packet clone is allocation failure safe" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, clonePacketAllocationFailureImpl, .{});
}
