const std = @import("std");

const game_cfg = @import("../formats/game_cfg.zig");
const lockstep_protocol = @import("lockstep_protocol.zig");
const quest_level = @import("../quest_level.zig");
const relay_protocol = @import("relay_protocol.zig");
const room_code = @import("room_code.zig");

pub const game_mode_demo_id: i32 = 0;
pub const max_players: i32 = 4;

pub const LockstepSessionSettings = struct {
    mode_id: i32 = game_mode_demo_id,
    player_count: i32 = 1,
    quest_level: ?quest_level.QuestLevel = null,
    preserve_bugs: bool = false,
    tick_rate: i32 = lockstep_protocol.tick_rate,
    input_delay_ticks: i32 = lockstep_protocol.input_delay_ticks,
    netcode_mode: relay_protocol.NetcodeMode = relay_protocol.NetcodeMode.lockstep,
};

pub const RelaySessionSettings = struct {
    mode_id: i32 = game_mode_demo_id,
    player_count: i32 = 1,
    quest_level: ?quest_level.QuestLevel = null,
    preserve_bugs: bool = false,
    tick_rate: i32 = relay_protocol.tick_rate,
    input_delay_ticks: i32 = relay_protocol.input_delay_ticks,
    rollback_max_ticks: i32 = relay_protocol.rollback_max_ticks,
    netcode_mode: relay_protocol.NetcodeMode = relay_protocol.NetcodeMode.rollback,
};

pub const LockstepOptions = struct {
    mode_id: i32 = game_mode_demo_id,
    player_count: i32 = 1,
    quest_level: ?quest_level.QuestLevel = null,
    preserve_bugs: bool = false,
    tick_rate: i32 = lockstep_protocol.tick_rate,
    input_delay_ticks: i32 = lockstep_protocol.input_delay_ticks,
};

pub const RelayOptions = struct {
    mode_id: i32 = game_mode_demo_id,
    player_count: i32 = 1,
    quest_level: ?quest_level.QuestLevel = null,
    preserve_bugs: bool = false,
    tick_rate: i32 = relay_protocol.tick_rate,
    input_delay_ticks: i32 = relay_protocol.input_delay_ticks,
    rollback_max_ticks: i32 = relay_protocol.rollback_max_ticks,
    netcode_mode: relay_protocol.NetcodeMode = relay_protocol.NetcodeMode.rollback,
};

pub const HelloOptions = struct {
    protocol_version: i32,
    build_id: []const u8,
    host: bool,
};

pub const WelcomeOptions = struct {
    accepted: bool,
    reason: []const u8 = "",
    session_id: []const u8 = "",
    protocol_version: i32 = lockstep_protocol.protocol_version,
    build_id: []const u8 = "",
    slot_index: i32 = -1,
    host_slot_index: i32 = 0,
    seed: i32 = 0,
    started: bool = false,
};

pub const MatchStartSettingsOptions = struct {
    tick_rate: i32 = lockstep_protocol.tick_rate,
    input_delay_ticks: i32 = lockstep_protocol.input_delay_ticks,
};

pub const MatchStartOptions = struct {
    session_id: []const u8,
    seed: i32,
    start_tick: i32 = 0,
    status: ?game_cfg.Status = null,
};

pub const RoomCreateOptions = struct {
    status: ?game_cfg.Status = null,
};

pub const RoomStateOptions = struct {
    room_code: room_code.RoomCode,
    session_id: []const u8,
    slots: []const relay_protocol.RelaySlot,
    all_ready: bool,
    started: bool,
};

pub const RoomStartOptions = struct {
    room_code: room_code.RoomCode,
    session_id: []const u8,
    seed: i32,
    start_tick: i32,
    slot_index: i32,
    host_slot_index: i32,
    reconnect_token: []const u8,
    status: ?game_cfg.Status = null,
};

pub fn forLockstep(options: LockstepOptions) LockstepSessionSettings {
    return .{
        .mode_id = options.mode_id,
        .player_count = clampPlayerCount(options.player_count),
        .quest_level = options.quest_level,
        .preserve_bugs = options.preserve_bugs,
        .tick_rate = clampMin(options.tick_rate, 1),
        .input_delay_ticks = clampMin(options.input_delay_ticks, 0),
    };
}

pub fn fromHello(message: lockstep_protocol.Hello) LockstepSessionSettings {
    return forLockstep(.{
        .mode_id = message.mode_id,
        .player_count = message.player_count,
        .quest_level = message.quest_level,
        .preserve_bugs = message.preserve_bugs,
        .tick_rate = message.tick_rate,
        .input_delay_ticks = message.input_delay_ticks,
    });
}

pub fn fromWelcome(message: lockstep_protocol.Welcome) LockstepSessionSettings {
    return forLockstep(.{
        .mode_id = message.mode_id,
        .player_count = message.player_count,
        .quest_level = message.quest_level,
        .preserve_bugs = message.preserve_bugs,
        .tick_rate = message.tick_rate,
        .input_delay_ticks = message.input_delay_ticks,
    });
}

pub fn fromMatchStart(message: lockstep_protocol.MatchStart, options: MatchStartSettingsOptions) LockstepSessionSettings {
    return forLockstep(.{
        .mode_id = message.mode_id,
        .player_count = message.player_count,
        .quest_level = message.quest_level,
        .preserve_bugs = message.preserve_bugs,
        .tick_rate = options.tick_rate,
        .input_delay_ticks = options.input_delay_ticks,
    });
}

pub fn helloFromSettings(settings: LockstepSessionSettings, options: HelloOptions) lockstep_protocol.Hello {
    return .{
        .protocol_version = options.protocol_version,
        .build_id = options.build_id,
        .mode_id = settings.mode_id,
        .player_count = settings.player_count,
        .tick_rate = settings.tick_rate,
        .input_delay_ticks = settings.input_delay_ticks,
        .quest_level = settings.quest_level,
        .preserve_bugs = settings.preserve_bugs,
        .host = options.host,
    };
}

pub fn welcomeFromSettings(settings: LockstepSessionSettings, options: WelcomeOptions) lockstep_protocol.Welcome {
    return .{
        .accepted = options.accepted,
        .reason = options.reason,
        .session_id = options.session_id,
        .protocol_version = options.protocol_version,
        .build_id = options.build_id,
        .mode_id = settings.mode_id,
        .player_count = settings.player_count,
        .slot_index = options.slot_index,
        .host_slot_index = options.host_slot_index,
        .tick_rate = settings.tick_rate,
        .input_delay_ticks = settings.input_delay_ticks,
        .seed = options.seed,
        .quest_level = settings.quest_level,
        .preserve_bugs = settings.preserve_bugs,
        .started = options.started,
    };
}

pub fn matchStartFromSettings(settings: LockstepSessionSettings, options: MatchStartOptions) lockstep_protocol.MatchStart {
    return .{
        .session_id = options.session_id,
        .mode_id = settings.mode_id,
        .player_count = settings.player_count,
        .seed = options.seed,
        .start_tick = options.start_tick,
        .quest_level = settings.quest_level,
        .preserve_bugs = settings.preserve_bugs,
        .status = options.status,
    };
}

pub fn forRelay(options: RelayOptions) RelaySessionSettings {
    return .{
        .mode_id = options.mode_id,
        .player_count = clampPlayerCount(options.player_count),
        .quest_level = options.quest_level,
        .preserve_bugs = options.preserve_bugs,
        .tick_rate = clampMin(options.tick_rate, 1),
        .input_delay_ticks = clampMin(options.input_delay_ticks, 0),
        .rollback_max_ticks = clampMin(options.rollback_max_ticks, 1),
        .netcode_mode = options.netcode_mode,
    };
}

pub fn fromRoomCreate(message: relay_protocol.RoomCreate) RelaySessionSettings {
    return forRelay(.{
        .mode_id = message.mode_id,
        .player_count = message.player_count,
        .quest_level = message.quest_level,
        .preserve_bugs = message.preserve_bugs,
        .tick_rate = message.tick_rate,
        .input_delay_ticks = message.input_delay_ticks,
        .rollback_max_ticks = message.rollback_max_ticks,
        .netcode_mode = message.netcode_mode,
    });
}

pub fn roomCreateFromSettings(settings: RelaySessionSettings, options: RoomCreateOptions) relay_protocol.RoomCreate {
    return .{
        .mode_id = settings.mode_id,
        .player_count = settings.player_count,
        .quest_level = settings.quest_level,
        .preserve_bugs = settings.preserve_bugs,
        .tick_rate = settings.tick_rate,
        .input_delay_ticks = settings.input_delay_ticks,
        .rollback_max_ticks = settings.rollback_max_ticks,
        .netcode_mode = settings.netcode_mode,
        .status = options.status,
    };
}

pub fn roomStateFromSettings(settings: RelaySessionSettings, options: RoomStateOptions) relay_protocol.RoomState {
    return .{
        .room_code = options.room_code,
        .session_id = options.session_id,
        .mode_id = settings.mode_id,
        .player_count = settings.player_count,
        .quest_level = settings.quest_level,
        .preserve_bugs = settings.preserve_bugs,
        .tick_rate = settings.tick_rate,
        .input_delay_ticks = settings.input_delay_ticks,
        .rollback_max_ticks = settings.rollback_max_ticks,
        .netcode_mode = settings.netcode_mode,
        .slots = options.slots,
        .all_ready = options.all_ready,
        .started = options.started,
    };
}

pub fn roomStartFromSettings(settings: RelaySessionSettings, options: RoomStartOptions) relay_protocol.RoomStart {
    return .{
        .room_code = options.room_code,
        .session_id = options.session_id,
        .seed = options.seed,
        .start_tick = options.start_tick,
        .mode_id = settings.mode_id,
        .player_count = settings.player_count,
        .quest_level = settings.quest_level,
        .preserve_bugs = settings.preserve_bugs,
        .tick_rate = settings.tick_rate,
        .input_delay_ticks = settings.input_delay_ticks,
        .rollback_max_ticks = settings.rollback_max_ticks,
        .netcode_mode = settings.netcode_mode,
        .slot_index = options.slot_index,
        .host_slot_index = options.host_slot_index,
        .reconnect_token = options.reconnect_token,
        .status = options.status,
    };
}

fn clampPlayerCount(value: i32) i32 {
    return std.math.clamp(value, 1, max_players);
}

fn clampMin(value: i32, minimum: i32) i32 {
    return @max(value, minimum);
}

test "lockstep session settings clamp python-compatible numeric fields" {
    const settings = forLockstep(.{
        .mode_id = 3,
        .player_count = 99,
        .quest_level = try quest_level.QuestLevel.parse("2.5"),
        .preserve_bugs = true,
        .tick_rate = 0,
        .input_delay_ticks = -4,
    });

    try std.testing.expectEqual(@as(i32, 3), settings.mode_id);
    try std.testing.expectEqual(@as(i32, 4), settings.player_count);
    try std.testing.expectEqual(@as(i32, 2), settings.quest_level.?.major);
    try std.testing.expectEqual(@as(i32, 5), settings.quest_level.?.minor);
    try std.testing.expect(settings.preserve_bugs);
    try std.testing.expectEqual(@as(i32, 1), settings.tick_rate);
    try std.testing.expectEqual(@as(i32, 0), settings.input_delay_ticks);
    try std.testing.expectEqual(relay_protocol.NetcodeMode.lockstep, settings.netcode_mode);
}

test "lockstep session settings preserve defaults" {
    const settings = forLockstep(.{});
    try std.testing.expectEqual(@as(i32, game_mode_demo_id), settings.mode_id);
    try std.testing.expectEqual(@as(i32, 1), settings.player_count);
    try std.testing.expect(settings.quest_level == null);
    try std.testing.expect(!settings.preserve_bugs);
    try std.testing.expectEqual(@as(i32, lockstep_protocol.tick_rate), settings.tick_rate);
    try std.testing.expectEqual(@as(i32, lockstep_protocol.input_delay_ticks), settings.input_delay_ticks);
    try std.testing.expectEqual(relay_protocol.NetcodeMode.lockstep, settings.netcode_mode);
}

test "lockstep session settings convert from hello and welcome messages" {
    const level = try quest_level.QuestLevel.parse("3.7");
    const hello_settings = fromHello(.{
        .mode_id = 3,
        .player_count = 9,
        .quest_level = level,
        .preserve_bugs = true,
        .tick_rate = 0,
        .input_delay_ticks = -3,
    });
    try std.testing.expectEqual(@as(i32, 3), hello_settings.mode_id);
    try std.testing.expectEqual(@as(i32, 4), hello_settings.player_count);
    try std.testing.expectEqual(@as(i32, 3), hello_settings.quest_level.?.major);
    try std.testing.expectEqual(@as(i32, 7), hello_settings.quest_level.?.minor);
    try std.testing.expect(hello_settings.preserve_bugs);
    try std.testing.expectEqual(@as(i32, 1), hello_settings.tick_rate);
    try std.testing.expectEqual(@as(i32, 0), hello_settings.input_delay_ticks);

    const welcome_settings = fromWelcome(.{
        .mode_id = 2,
        .player_count = -1,
        .tick_rate = 120,
        .input_delay_ticks = 2,
    });
    try std.testing.expectEqual(@as(i32, 2), welcome_settings.mode_id);
    try std.testing.expectEqual(@as(i32, 1), welcome_settings.player_count);
    try std.testing.expectEqual(@as(i32, 120), welcome_settings.tick_rate);
    try std.testing.expectEqual(@as(i32, 2), welcome_settings.input_delay_ticks);
}

test "lockstep session settings build hello and welcome messages" {
    const settings = forLockstep(.{
        .mode_id = 3,
        .player_count = 2,
        .quest_level = try quest_level.QuestLevel.parse("4.1"),
        .preserve_bugs = true,
        .tick_rate = 30,
        .input_delay_ticks = 4,
    });

    const hello = helloFromSettings(settings, .{
        .protocol_version = 7,
        .build_id = "0.1.0+gabcdef1",
        .host = true,
    });
    try std.testing.expectEqual(@as(i32, 7), hello.protocol_version);
    try std.testing.expectEqualStrings("0.1.0+gabcdef1", hello.build_id);
    try std.testing.expectEqual(@as(i32, 3), hello.mode_id);
    try std.testing.expectEqual(@as(i32, 2), hello.player_count);
    try std.testing.expectEqual(@as(i32, 4), hello.quest_level.?.major);
    try std.testing.expectEqual(@as(i32, 1), hello.quest_level.?.minor);
    try std.testing.expect(hello.preserve_bugs);
    try std.testing.expect(hello.host);

    const welcome = welcomeFromSettings(settings, .{
        .accepted = true,
        .reason = "ok",
        .session_id = "session-1",
        .build_id = "0.1.0",
        .slot_index = 1,
        .host_slot_index = 0,
        .seed = 123,
        .started = true,
    });
    try std.testing.expect(welcome.accepted);
    try std.testing.expectEqualStrings("ok", welcome.reason);
    try std.testing.expectEqualStrings("session-1", welcome.session_id);
    try std.testing.expectEqual(@as(i32, lockstep_protocol.protocol_version), welcome.protocol_version);
    try std.testing.expectEqualStrings("0.1.0", welcome.build_id);
    try std.testing.expectEqual(@as(i32, 1), welcome.slot_index);
    try std.testing.expectEqual(@as(i32, 0), welcome.host_slot_index);
    try std.testing.expectEqual(@as(i32, 123), welcome.seed);
    try std.testing.expect(welcome.started);
}

test "lockstep session settings roundtrip match start messages" {
    var status = std.mem.zeroes(game_cfg.Status);
    status.game_sequence_id = 42;
    const settings = forLockstep(.{
        .mode_id = 3,
        .player_count = 2,
        .quest_level = try quest_level.QuestLevel.parse("2.9"),
        .preserve_bugs = true,
        .tick_rate = 60,
        .input_delay_ticks = 3,
    });

    const start = matchStartFromSettings(settings, .{
        .session_id = "lockstep-session",
        .seed = 98765,
        .start_tick = 12,
        .status = status,
    });
    try std.testing.expectEqualStrings("lockstep-session", start.session_id);
    try std.testing.expectEqual(@as(i32, 3), start.mode_id);
    try std.testing.expectEqual(@as(i32, 2), start.player_count);
    try std.testing.expectEqual(@as(i32, 98765), start.seed);
    try std.testing.expectEqual(@as(i32, 12), start.start_tick);
    try std.testing.expectEqual(@as(i32, 2), start.quest_level.?.major);
    try std.testing.expectEqual(@as(i32, 9), start.quest_level.?.minor);
    try std.testing.expect(start.preserve_bugs);
    try std.testing.expectEqual(@as(u32, 42), start.status.?.game_sequence_id);

    const roundtrip = fromMatchStart(start, .{ .tick_rate = 60, .input_delay_ticks = 3 });
    try std.testing.expectEqual(@as(i32, 3), roundtrip.mode_id);
    try std.testing.expectEqual(@as(i32, 2), roundtrip.player_count);
    try std.testing.expectEqual(@as(i32, 2), roundtrip.quest_level.?.major);
    try std.testing.expectEqual(@as(i32, 9), roundtrip.quest_level.?.minor);
    try std.testing.expect(roundtrip.preserve_bugs);
    try std.testing.expectEqual(@as(i32, 60), roundtrip.tick_rate);
    try std.testing.expectEqual(@as(i32, 3), roundtrip.input_delay_ticks);
    try std.testing.expectEqual(relay_protocol.NetcodeMode.lockstep, roundtrip.netcode_mode);
}

test "relay session settings clamp python-compatible numeric fields" {
    const settings = forRelay(.{
        .mode_id = 1,
        .player_count = -10,
        .tick_rate = -2,
        .input_delay_ticks = -1,
        .rollback_max_ticks = 0,
        .netcode_mode = relay_protocol.NetcodeMode.lockstep,
    });

    try std.testing.expectEqual(@as(i32, 1), settings.mode_id);
    try std.testing.expectEqual(@as(i32, 1), settings.player_count);
    try std.testing.expectEqual(@as(i32, 1), settings.tick_rate);
    try std.testing.expectEqual(@as(i32, 0), settings.input_delay_ticks);
    try std.testing.expectEqual(@as(i32, 1), settings.rollback_max_ticks);
    try std.testing.expectEqual(relay_protocol.NetcodeMode.lockstep, settings.netcode_mode);
}

test "relay session settings preserve defaults" {
    const settings = forRelay(.{});
    try std.testing.expectEqual(@as(i32, game_mode_demo_id), settings.mode_id);
    try std.testing.expectEqual(@as(i32, 1), settings.player_count);
    try std.testing.expect(settings.quest_level == null);
    try std.testing.expect(!settings.preserve_bugs);
    try std.testing.expectEqual(@as(i32, relay_protocol.tick_rate), settings.tick_rate);
    try std.testing.expectEqual(@as(i32, relay_protocol.input_delay_ticks), settings.input_delay_ticks);
    try std.testing.expectEqual(@as(i32, relay_protocol.rollback_max_ticks), settings.rollback_max_ticks);
    try std.testing.expectEqual(relay_protocol.NetcodeMode.rollback, settings.netcode_mode);
}

test "relay session settings convert from room create messages" {
    const settings = fromRoomCreate(.{
        .mode_id = 3,
        .player_count = 9,
        .quest_level = try quest_level.QuestLevel.parse("5.2"),
        .preserve_bugs = true,
        .tick_rate = 0,
        .input_delay_ticks = -1,
        .rollback_max_ticks = 0,
        .netcode_mode = relay_protocol.NetcodeMode.lockstep,
    });
    try std.testing.expectEqual(@as(i32, 3), settings.mode_id);
    try std.testing.expectEqual(@as(i32, 4), settings.player_count);
    try std.testing.expectEqual(@as(i32, 5), settings.quest_level.?.major);
    try std.testing.expectEqual(@as(i32, 2), settings.quest_level.?.minor);
    try std.testing.expect(settings.preserve_bugs);
    try std.testing.expectEqual(@as(i32, 1), settings.tick_rate);
    try std.testing.expectEqual(@as(i32, 0), settings.input_delay_ticks);
    try std.testing.expectEqual(@as(i32, 1), settings.rollback_max_ticks);
    try std.testing.expectEqual(relay_protocol.NetcodeMode.lockstep, settings.netcode_mode);
}

test "relay session settings build room messages" {
    const code = try room_code.parseRoomCode("WXYZ");
    const slots = [_]relay_protocol.RelaySlot{
        .{ .slot_index = 0, .connected = true, .ready = true, .is_host = true, .peer_name = "host" },
        .{ .slot_index = 1, .connected = true, .ready = false, .is_host = false, .peer_name = "guest" },
    };
    var status = std.mem.zeroes(game_cfg.Status);
    status.game_sequence_id = 99;
    const settings = forRelay(.{
        .mode_id = 3,
        .player_count = 2,
        .quest_level = try quest_level.QuestLevel.parse("4.4"),
        .preserve_bugs = true,
        .tick_rate = 30,
        .input_delay_ticks = 2,
        .rollback_max_ticks = 6,
    });

    const create = roomCreateFromSettings(settings, .{ .status = status });
    try std.testing.expectEqual(@as(i32, 3), create.mode_id);
    try std.testing.expectEqual(@as(i32, 2), create.player_count);
    try std.testing.expectEqual(@as(i32, 4), create.quest_level.?.major);
    try std.testing.expectEqual(@as(i32, 4), create.quest_level.?.minor);
    try std.testing.expect(create.preserve_bugs);
    try std.testing.expectEqual(@as(i32, 30), create.tick_rate);
    try std.testing.expectEqual(@as(i32, 2), create.input_delay_ticks);
    try std.testing.expectEqual(@as(i32, 6), create.rollback_max_ticks);
    try std.testing.expectEqual(relay_protocol.NetcodeMode.rollback, create.netcode_mode);
    try std.testing.expectEqual(@as(u32, 99), create.status.?.game_sequence_id);

    const state = roomStateFromSettings(settings, .{
        .room_code = code,
        .session_id = "room-session",
        .slots = slots[0..],
        .all_ready = false,
        .started = true,
    });
    try std.testing.expectEqualStrings("wxyz", room_code.roomCodeSlice(&state.room_code));
    try std.testing.expectEqualStrings("room-session", state.session_id);
    try std.testing.expectEqual(@as(usize, 2), state.slots.len);
    try std.testing.expectEqualStrings("guest", state.slots[1].peer_name);
    try std.testing.expect(!state.all_ready);
    try std.testing.expect(state.started);

    const start = roomStartFromSettings(settings, .{
        .room_code = code,
        .session_id = "room-session",
        .seed = 123,
        .start_tick = 9,
        .slot_index = 1,
        .host_slot_index = 0,
        .reconnect_token = "token",
        .status = status,
    });
    try std.testing.expectEqualStrings("wxyz", room_code.roomCodeSlice(&start.room_code));
    try std.testing.expectEqual(@as(i32, 123), start.seed);
    try std.testing.expectEqual(@as(i32, 9), start.start_tick);
    try std.testing.expectEqual(@as(i32, 1), start.slot_index);
    try std.testing.expectEqual(@as(i32, 0), start.host_slot_index);
    try std.testing.expectEqualStrings("token", start.reconnect_token);
    try std.testing.expectEqual(@as(u32, 99), start.status.?.game_sequence_id);
}
