const std = @import("std");
const msgpack = @import("msgpack");

const game_cfg = @import("../formats/game_cfg.zig");
const packed_input = @import("packed_input.zig");
const quest_level = @import("../quest_level.zig");
const schema_shared = @import("schema_shared.zig");

pub const protocol_version: i32 = 6;
pub const default_port: u16 = 31993;
pub const tick_rate: i32 = 60;
pub const input_delay_ticks: i32 = 1;
pub const max_players: i32 = 4;
pub const reliable_resend_ms: i32 = 40;
pub const link_timeout_ms: i32 = 1000;
pub const input_stall_timeout_ms: i32 = 250;

const default_protocol_version: i32 = protocol_version;
const default_tick_rate: i32 = tick_rate;
const default_input_delay_ticks: i32 = input_delay_ticks;
const trim_chars = " \t\r\n";

pub const Hello = struct {
    protocol_version: i32 = default_protocol_version,
    build_id: []const u8 = "",
    mode_id: i32 = 0,
    player_count: i32 = 1,
    tick_rate: i32 = default_tick_rate,
    input_delay_ticks: i32 = default_input_delay_ticks,
    quest_level: ?quest_level.QuestLevel = null,
    preserve_bugs: bool = false,
    host: bool = false,
};

pub const Welcome = struct {
    accepted: bool = false,
    reason: []const u8 = "",
    session_id: []const u8 = "",
    protocol_version: i32 = default_protocol_version,
    build_id: []const u8 = "",
    mode_id: i32 = 0,
    player_count: i32 = 1,
    slot_index: i32 = -1,
    host_slot_index: i32 = 0,
    tick_rate: i32 = default_tick_rate,
    input_delay_ticks: i32 = default_input_delay_ticks,
    seed: i32 = 0,
    quest_level: ?quest_level.QuestLevel = null,
    preserve_bugs: bool = false,
    started: bool = false,
};

pub const LobbySlot = schema_shared.SlotState;

pub const LobbyState = struct {
    session_id: []const u8 = "",
    mode_id: i32 = 0,
    player_count: i32 = 1,
    slots: []const LobbySlot = &.{},
    all_ready: bool = false,
    started: bool = false,
    quest_level: ?quest_level.QuestLevel = null,
};

pub const Ready = struct {
    slot_index: i32 = -1,
    ready: bool = false,
};

pub const MatchStart = struct {
    session_id: []const u8 = "",
    mode_id: i32 = 0,
    player_count: i32 = 1,
    seed: i32 = 0,
    start_tick: i32 = 0,
    quest_level: ?quest_level.QuestLevel = null,
    preserve_bugs: bool = false,
    status: ?game_cfg.Status = null,
};

pub const PerkMenuOpenCommand = struct {
    player_index: i32 = 0,
};

pub const PerkPickCommand = struct {
    player_index: i32 = 0,
    choice_index: i32 = 0,
};

pub const TypoCharCommand = struct {
    player_index: i32 = 0,
    ch: []const u8 = "",
};

pub const TypoBackspaceCommand = struct {
    player_index: i32 = 0,
};

pub const TypoSubmitCommand = struct {
    player_index: i32 = 0,
};

pub const GameCommand = union(enum) {
    perk_menu_open: PerkMenuOpenCommand,
    perk_pick: PerkPickCommand,
    typo_char: TypoCharCommand,
    typo_backspace: TypoBackspaceCommand,
    typo_submit: TypoSubmitCommand,

    pub fn msgpackFormat() msgpack.UnionFormat {
        return .{ .as_tagged = .{
            .tag_field = "type",
            .tag_value = .field_name,
        } };
    }
};

pub const InputSample = struct {
    tick_index: i32 = 0,
    packed_input: packed_input.PackedPlayerInput = .{},
};

pub const InputBatch = struct {
    slot_index: i32 = -1,
    samples: []const InputSample = &.{},
};

pub const TickFrame = struct {
    tick_index: i32 = 0,
    frame_inputs: []const packed_input.PackedPlayerInput = &.{},
    commands: []const GameCommand = &.{},
};

pub const PauseState = struct {
    paused: bool = false,
    reason: []const u8 = "",
};

pub const KeepAlive = struct {
    tick_index: i32 = 0,
};

pub const DebugLogBatch = struct {
    slot_index: i32 = -1,
    lines: []const []const u8 = &.{},
};

pub const ResyncBegin = struct {
    stream_id: []const u8 = "",
    total_chunks: i32 = 0,
    compressed_size: i32 = 0,
    replay_size: i32 = 0,
    checkpoints_size: i32 = 0,
};

pub const ResyncChunk = struct {
    stream_id: []const u8 = "",
    chunk_index: i32 = 0,
    payload: schema_shared.WireBytes = .{},
};

pub const ResyncCommit = struct {
    stream_id: []const u8 = "",
    tick_index: i32 = -1,
};

pub const Disconnect = struct {
    reason: []const u8 = "",
};

pub const NetMessage = union(enum) {
    hello: Hello,
    welcome: Welcome,
    lobby_state: LobbyState,
    ready: Ready,
    match_start: MatchStart,
    tick_frame: TickFrame,
    pause_state: PauseState,
    keep_alive: KeepAlive,
    debug_log_batch: DebugLogBatch,
    resync_begin: ResyncBegin,
    resync_chunk: ResyncChunk,
    resync_commit: ResyncCommit,
    disconnect: Disconnect,
    input_batch: InputBatch,

    pub fn msgpackFormat() msgpack.UnionFormat {
        return .{ .as_tagged = .{
            .tag_field = "type",
            .tag_value = .field_name,
        } };
    }
};

pub const LockstepPacket = struct {
    seq: i32 = 0,
    ack: i32 = 0,
    reliable: bool = false,
    message: NetMessage = .{ .pause_state = .{} },
};

pub fn encodePacket(allocator: std.mem.Allocator, packet: LockstepPacket) ![]u8 {
    var writer: std.Io.Writer.Allocating = .init(allocator);
    errdefer writer.deinit();
    try msgpack.encode(packet, &writer.writer);
    return writer.toOwnedSlice();
}

pub fn decodePacket(allocator: std.mem.Allocator, blob: []const u8) !msgpack.Decoded(LockstepPacket) {
    return msgpack.decodeFromSlice(LockstepPacket, allocator, blob);
}

/// Deep-copy packet payload slices so reliable queues and runtime state can retain packets.
pub fn clonePacket(allocator: std.mem.Allocator, packet: LockstepPacket) !LockstepPacket {
    return .{
        .seq = packet.seq,
        .ack = packet.ack,
        .reliable = packet.reliable,
        .message = try cloneMessage(allocator, packet.message),
    };
}

/// Free packet payload slices allocated by clonePacket.
pub fn deinitPacket(allocator: std.mem.Allocator, packet: *LockstepPacket) void {
    deinitMessage(allocator, &packet.message);
    packet.* = undefined;
}

/// Deep-copy message payload slices so decoded packet storage can be released.
pub fn cloneMessage(allocator: std.mem.Allocator, message: NetMessage) !NetMessage {
    return switch (message) {
        .hello => |hello| .{ .hello = .{
            .protocol_version = hello.protocol_version,
            .build_id = try dupeBytes(allocator, hello.build_id),
            .mode_id = hello.mode_id,
            .player_count = hello.player_count,
            .tick_rate = hello.tick_rate,
            .input_delay_ticks = hello.input_delay_ticks,
            .quest_level = hello.quest_level,
            .preserve_bugs = hello.preserve_bugs,
            .host = hello.host,
        } },
        .welcome => |welcome| .{ .welcome = try cloneWelcome(allocator, welcome) },
        .lobby_state => |state| .{ .lobby_state = try cloneLobbyState(allocator, state) },
        .ready => |ready| .{ .ready = ready },
        .match_start => |start| .{ .match_start = .{
            .session_id = try dupeBytes(allocator, start.session_id),
            .mode_id = start.mode_id,
            .player_count = start.player_count,
            .seed = start.seed,
            .start_tick = start.start_tick,
            .quest_level = start.quest_level,
            .preserve_bugs = start.preserve_bugs,
            .status = start.status,
        } },
        .tick_frame => |frame| .{ .tick_frame = try cloneTickFrame(allocator, frame) },
        .pause_state => |pause| .{ .pause_state = .{
            .paused = pause.paused,
            .reason = try dupeBytes(allocator, pause.reason),
        } },
        .keep_alive => |keep_alive| .{ .keep_alive = keep_alive },
        .debug_log_batch => |batch| .{ .debug_log_batch = try cloneDebugLogBatch(allocator, batch) },
        .resync_begin => |begin| .{ .resync_begin = .{
            .stream_id = try dupeBytes(allocator, begin.stream_id),
            .total_chunks = begin.total_chunks,
            .compressed_size = begin.compressed_size,
            .replay_size = begin.replay_size,
            .checkpoints_size = begin.checkpoints_size,
        } },
        .resync_chunk => |chunk| .{ .resync_chunk = try cloneResyncChunk(allocator, chunk) },
        .resync_commit => |commit| .{ .resync_commit = .{
            .stream_id = try dupeBytes(allocator, commit.stream_id),
            .tick_index = commit.tick_index,
        } },
        .disconnect => |disconnect| .{ .disconnect = .{ .reason = try dupeBytes(allocator, disconnect.reason) } },
        .input_batch => |batch| .{ .input_batch = .{
            .slot_index = batch.slot_index,
            .samples = try dupeInputSamples(allocator, batch.samples),
        } },
    };
}

/// Free message payload slices allocated by cloneMessage.
pub fn deinitMessage(allocator: std.mem.Allocator, message: *NetMessage) void {
    switch (message.*) {
        .hello => |hello| freeBytes(allocator, hello.build_id),
        .welcome => |welcome| {
            freeBytes(allocator, welcome.reason);
            freeBytes(allocator, welcome.session_id);
            freeBytes(allocator, welcome.build_id);
        },
        .lobby_state => |state| deinitLobbyState(allocator, state),
        .ready => {},
        .match_start => |start| freeBytes(allocator, start.session_id),
        .tick_frame => |frame| deinitTickFrame(allocator, frame),
        .pause_state => |pause| freeBytes(allocator, pause.reason),
        .keep_alive => {},
        .debug_log_batch => |batch| deinitDebugLogBatch(allocator, batch),
        .resync_begin => |begin| freeBytes(allocator, begin.stream_id),
        .resync_chunk => |chunk| {
            freeBytes(allocator, chunk.stream_id);
            freeBytes(allocator, chunk.payload.data);
        },
        .resync_commit => |commit| freeBytes(allocator, commit.stream_id),
        .disconnect => |disconnect| freeBytes(allocator, disconnect.reason),
        .input_batch => |batch| freeInputSamples(allocator, batch.samples),
    }
    message.* = undefined;
}

pub fn buildPublicVersion(buf: []u8, build_id: []const u8) ?[]const u8 {
    const raw = std.mem.trim(u8, build_id, trim_chars);
    if (raw.len == 0) return null;

    const base_with_prefix = if (std.mem.indexOfScalar(u8, raw, '+')) |idx| raw[0..idx] else raw;
    const base = if (base_with_prefix.len > 0 and (base_with_prefix[0] == 'v' or base_with_prefix[0] == 'V'))
        base_with_prefix[1..]
    else
        base_with_prefix;
    if (!looksLikePublicVersion(base)) return null;
    if (base.len > buf.len) return null;
    @memcpy(buf[0..base.len], base);
    return buf[0..base.len];
}

pub fn buildGitHash(buf: []u8, build_id: []const u8) ?[]const u8 {
    const raw = std.mem.trim(u8, build_id, trim_chars);
    if (raw.len == 0) return null;

    if (isLowerHexRun(raw) and raw.len >= 7 and raw.len <= 40) {
        return copyLower(buf, raw);
    }

    var idx: usize = 0;
    while (idx + 2 < raw.len) : (idx += 1) {
        if (raw[idx] != '+' and raw[idx] != '.') continue;
        if (raw[idx + 1] != 'g' and raw[idx + 1] != 'G') continue;
        const start = idx + 2;
        var end = start;
        while (end < raw.len and std.ascii.isHex(raw[end])) : (end += 1) {}
        const len = end - start;
        if (len < 7 or len > 40) continue;
        if (end < raw.len and isAsciiWord(raw[end])) continue;
        return copyLower(buf, raw[start..end]);
    }
    return null;
}

pub fn buildsCompatible(peer_build_id: []const u8, host_build_id: []const u8) bool {
    if (std.mem.eql(u8, peer_build_id, host_build_id)) return true;

    var peer_hash_buf: [40]u8 = undefined;
    var host_hash_buf: [40]u8 = undefined;
    const peer_hash = buildGitHash(&peer_hash_buf, peer_build_id);
    const host_hash = buildGitHash(&host_hash_buf, host_build_id);
    if (peer_hash != null and host_hash != null) {
        return std.mem.eql(u8, peer_hash.?, host_hash.?);
    }

    var peer_version_buf: [64]u8 = undefined;
    var host_version_buf: [64]u8 = undefined;
    const peer_version = buildPublicVersion(&peer_version_buf, peer_build_id);
    const host_version = buildPublicVersion(&host_version_buf, host_build_id);
    if (peer_version != null and host_version != null and std.mem.eql(u8, peer_version.?, host_version.?)) {
        return true;
    }
    return false;
}

fn looksLikePublicVersion(value: []const u8) bool {
    if (value.len == 0 or !std.ascii.isDigit(value[0])) return false;

    var idx: usize = 0;
    var numeric_components: usize = 0;
    while (idx < value.len) {
        const start = idx;
        while (idx < value.len and std.ascii.isDigit(value[idx])) : (idx += 1) {}
        if (idx == start) return false;
        numeric_components += 1;
        if (idx >= value.len or value[idx] != '.') break;
        idx += 1;
        if (idx >= value.len or !std.ascii.isDigit(value[idx])) return false;
    }
    if (numeric_components < 2) return false;
    while (idx < value.len) : (idx += 1) {
        const ch = value[idx];
        if (!(std.ascii.isAlphanumeric(ch) or ch == '.' or ch == '-' or ch == '_')) return false;
    }
    return true;
}

fn copyLower(buf: []u8, value: []const u8) ?[]const u8 {
    if (value.len > buf.len) return null;
    for (value, 0..) |ch, idx| buf[idx] = std.ascii.toLower(ch);
    return buf[0..value.len];
}

fn isLowerHexRun(value: []const u8) bool {
    if (value.len == 0) return false;
    for (value) |ch| {
        if (!std.ascii.isDigit(ch) and !(ch >= 'a' and ch <= 'f')) return false;
    }
    return true;
}

fn isAsciiWord(ch: u8) bool {
    return std.ascii.isAlphanumeric(ch) or ch == '_';
}

fn cloneWelcome(allocator: std.mem.Allocator, welcome: Welcome) !Welcome {
    const reason = try dupeBytes(allocator, welcome.reason);
    errdefer freeBytes(allocator, reason);
    const session_id = try dupeBytes(allocator, welcome.session_id);
    errdefer freeBytes(allocator, session_id);
    const build_id = try dupeBytes(allocator, welcome.build_id);
    errdefer freeBytes(allocator, build_id);
    return .{
        .accepted = welcome.accepted,
        .reason = reason,
        .session_id = session_id,
        .protocol_version = welcome.protocol_version,
        .build_id = build_id,
        .mode_id = welcome.mode_id,
        .player_count = welcome.player_count,
        .slot_index = welcome.slot_index,
        .host_slot_index = welcome.host_slot_index,
        .tick_rate = welcome.tick_rate,
        .input_delay_ticks = welcome.input_delay_ticks,
        .seed = welcome.seed,
        .quest_level = welcome.quest_level,
        .preserve_bugs = welcome.preserve_bugs,
        .started = welcome.started,
    };
}

fn cloneLobbyState(allocator: std.mem.Allocator, state: LobbyState) !LobbyState {
    const slots = try cloneSlots(allocator, state.slots);
    errdefer deinitSlots(allocator, slots);
    return .{
        .session_id = try dupeBytes(allocator, state.session_id),
        .mode_id = state.mode_id,
        .player_count = state.player_count,
        .slots = slots,
        .all_ready = state.all_ready,
        .started = state.started,
        .quest_level = state.quest_level,
    };
}

fn deinitLobbyState(allocator: std.mem.Allocator, state: LobbyState) void {
    freeBytes(allocator, state.session_id);
    deinitSlots(allocator, state.slots);
}

fn cloneSlots(allocator: std.mem.Allocator, slots: []const LobbySlot) ![]LobbySlot {
    if (slots.len == 0) return &.{};
    const out = try allocator.alloc(LobbySlot, slots.len);
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

fn deinitSlots(allocator: std.mem.Allocator, slots: []const LobbySlot) void {
    for (slots) |slot| freeBytes(allocator, slot.peer_name);
    if (slots.len != 0) allocator.free(slots);
}

fn cloneTickFrame(allocator: std.mem.Allocator, frame: TickFrame) !TickFrame {
    const frame_inputs = try dupePlayerInputs(allocator, frame.frame_inputs);
    errdefer freePlayerInputs(allocator, frame_inputs);
    const commands = try cloneCommands(allocator, frame.commands);
    errdefer deinitCommands(allocator, commands);
    return .{
        .tick_index = frame.tick_index,
        .frame_inputs = frame_inputs,
        .commands = commands,
    };
}

fn deinitTickFrame(allocator: std.mem.Allocator, frame: TickFrame) void {
    freePlayerInputs(allocator, frame.frame_inputs);
    deinitCommands(allocator, frame.commands);
}

fn cloneCommands(allocator: std.mem.Allocator, commands: []const GameCommand) ![]GameCommand {
    if (commands.len == 0) return &.{};
    const out = try allocator.alloc(GameCommand, commands.len);
    var initialized: usize = 0;
    errdefer {
        for (out[0..initialized]) |command| deinitCommand(allocator, command);
        allocator.free(out);
    }
    for (commands, 0..) |command, idx| {
        out[idx] = try cloneCommand(allocator, command);
        initialized += 1;
    }
    return out;
}

fn cloneCommand(allocator: std.mem.Allocator, command: GameCommand) !GameCommand {
    return switch (command) {
        .perk_menu_open => |value| .{ .perk_menu_open = value },
        .perk_pick => |value| .{ .perk_pick = value },
        .typo_char => |value| .{ .typo_char = .{
            .player_index = value.player_index,
            .ch = try dupeBytes(allocator, value.ch),
        } },
        .typo_backspace => |value| .{ .typo_backspace = value },
        .typo_submit => |value| .{ .typo_submit = value },
    };
}

fn deinitCommands(allocator: std.mem.Allocator, commands: []const GameCommand) void {
    for (commands) |command| deinitCommand(allocator, command);
    if (commands.len != 0) allocator.free(commands);
}

fn deinitCommand(allocator: std.mem.Allocator, command: GameCommand) void {
    switch (command) {
        .typo_char => |value| freeBytes(allocator, value.ch),
        else => {},
    }
}

fn cloneDebugLogBatch(allocator: std.mem.Allocator, batch: DebugLogBatch) !DebugLogBatch {
    return .{
        .slot_index = batch.slot_index,
        .lines = try cloneLines(allocator, batch.lines),
    };
}

fn deinitDebugLogBatch(allocator: std.mem.Allocator, batch: DebugLogBatch) void {
    for (batch.lines) |line| freeBytes(allocator, line);
    if (batch.lines.len != 0) allocator.free(batch.lines);
}

fn cloneResyncChunk(allocator: std.mem.Allocator, chunk: ResyncChunk) !ResyncChunk {
    const stream_id = try dupeBytes(allocator, chunk.stream_id);
    errdefer freeBytes(allocator, stream_id);
    const data = try dupeBytes(allocator, chunk.payload.data);
    errdefer freeBytes(allocator, data);
    return .{
        .stream_id = stream_id,
        .chunk_index = chunk.chunk_index,
        .payload = .{ .data = data },
    };
}

fn cloneLines(allocator: std.mem.Allocator, lines: []const []const u8) ![]const []const u8 {
    if (lines.len == 0) return &.{};
    const out = try allocator.alloc([]const u8, lines.len);
    var initialized: usize = 0;
    errdefer {
        for (out[0..initialized]) |line| freeBytes(allocator, line);
        allocator.free(out);
    }
    for (lines, 0..) |line, idx| {
        out[idx] = try dupeBytes(allocator, line);
        initialized += 1;
    }
    return out;
}

fn dupeInputSamples(allocator: std.mem.Allocator, samples: []const InputSample) ![]InputSample {
    if (samples.len == 0) return &.{};
    return allocator.dupe(InputSample, samples);
}

fn freeInputSamples(allocator: std.mem.Allocator, samples: []const InputSample) void {
    if (samples.len != 0) allocator.free(samples);
}

fn dupePlayerInputs(allocator: std.mem.Allocator, inputs: []const packed_input.PackedPlayerInput) ![]packed_input.PackedPlayerInput {
    if (inputs.len == 0) return &.{};
    return allocator.dupe(packed_input.PackedPlayerInput, inputs);
}

fn freePlayerInputs(allocator: std.mem.Allocator, inputs: []const packed_input.PackedPlayerInput) void {
    if (inputs.len != 0) allocator.free(inputs);
}

fn dupeBytes(allocator: std.mem.Allocator, value: []const u8) ![]const u8 {
    if (value.len == 0) return "";
    return allocator.dupe(u8, value);
}

fn freeBytes(allocator: std.mem.Allocator, value: []const u8) void {
    if (value.len != 0) allocator.free(value);
}

test "lockstep build public version strips local metadata and v prefix" {
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("0.1.0", buildPublicVersion(&buf, "0.1.0+gabcdef1").?);
    try std.testing.expectEqualStrings("1.2.3-rc1", buildPublicVersion(&buf, "v1.2.3-rc1").?);
    try std.testing.expect(buildPublicVersion(&buf, "dev-build") == null);
    try std.testing.expect(buildPublicVersion(&buf, "1") == null);
}

test "lockstep build git hash extracts exact and version metadata hashes" {
    var buf: [40]u8 = undefined;
    try std.testing.expectEqualStrings("abcdef1", buildGitHash(&buf, "abcdef1").?);
    try std.testing.expectEqualStrings("123abcd", buildGitHash(&buf, "0.1.0+g123ABCD").?);
    try std.testing.expectEqualStrings("123abcd", buildGitHash(&buf, "0.1.0.g123ABCD").?);
    try std.testing.expect(buildGitHash(&buf, "ABCDEF1") == null);
    try std.testing.expect(buildGitHash(&buf, "0.1.0+g123abc_") == null);
    try std.testing.expect(buildGitHash(&buf, "0.1.0+g123") == null);
}

test "lockstep builds compatible by exact hash before public version" {
    try std.testing.expect(buildsCompatible("0.1.0+gabcdef1", "abcdef1"));
    try std.testing.expect(!buildsCompatible("0.1.0+gabcdef1", "0.1.0+gabcdef2"));
}

test "lockstep builds compatible by public version when hashes are absent" {
    try std.testing.expect(buildsCompatible("0.1.0", "0.1.0+local"));
    try std.testing.expect(buildsCompatible("v1.2.0", "1.2.0"));
    try std.testing.expect(!buildsCompatible("0.1.0", "0.2.0"));
    try std.testing.expect(!buildsCompatible("dev-a", "dev-b"));
}

test "lockstep lobby and ready messages mirror python defaults" {
    const lobby: LobbyState = .{};
    try std.testing.expectEqualStrings("", lobby.session_id);
    try std.testing.expectEqual(@as(i32, 0), lobby.mode_id);
    try std.testing.expectEqual(@as(i32, 1), lobby.player_count);
    try std.testing.expectEqual(@as(usize, 0), lobby.slots.len);
    try std.testing.expect(!lobby.all_ready);
    try std.testing.expect(!lobby.started);
    try std.testing.expect(lobby.quest_level == null);

    const ready: Ready = .{};
    try std.testing.expectEqual(@as(i32, -1), ready.slot_index);
    try std.testing.expect(!ready.ready);
}

test "lockstep match start and input messages carry typed payloads" {
    var status = std.mem.zeroes(game_cfg.Status);
    status.mode_play_survival = 12;
    const start: MatchStart = .{
        .session_id = "s1",
        .mode_id = 3,
        .player_count = 2,
        .seed = 1234,
        .start_tick = 5,
        .quest_level = try quest_level.QuestLevel.parse("1.9"),
        .preserve_bugs = true,
        .status = status,
    };
    try std.testing.expectEqualStrings("s1", start.session_id);
    try std.testing.expectEqual(@as(i32, 3), start.mode_id);
    try std.testing.expectEqual(@as(i32, 2), start.player_count);
    try std.testing.expectEqual(@as(i32, 1234), start.seed);
    try std.testing.expectEqual(@as(i32, 5), start.start_tick);
    try std.testing.expectEqual(@as(i32, 1), start.quest_level.?.major);
    try std.testing.expectEqual(@as(i32, 9), start.quest_level.?.minor);
    try std.testing.expect(start.preserve_bugs);
    try std.testing.expectEqual(@as(u32, 12), start.status.?.mode_play_survival);

    const sample: InputSample = .{
        .tick_index = 8,
        .packed_input = .{ .move_x = 1.0, .flags = 3 },
    };
    const samples = [_]InputSample{sample};
    const batch: InputBatch = .{ .slot_index = 1, .samples = samples[0..] };
    try std.testing.expectEqual(@as(i32, 1), batch.slot_index);
    try std.testing.expectEqual(@as(usize, 1), batch.samples.len);
    try std.testing.expectEqual(@as(i32, 8), batch.samples[0].tick_index);
    try std.testing.expectEqual(@as(f32, 1.0), batch.samples[0].packed_input.move_x);
    try std.testing.expectEqual(@as(u32, 3), batch.samples[0].packed_input.flags);
}

test "lockstep tick frame carries inputs and commands" {
    const inputs = [_]packed_input.PackedPlayerInput{
        .{ .aim_x = 1.0, .aim_y = 2.0, .flags = 3 },
    };
    const commands = [_]GameCommand{
        .{ .perk_menu_open = .{ .player_index = 0 } },
        .{ .perk_pick = .{ .player_index = 0, .choice_index = 2 } },
        .{ .typo_char = .{ .player_index = 1, .ch = "a" } },
        .{ .typo_backspace = .{ .player_index = 1 } },
        .{ .typo_submit = .{ .player_index = 1 } },
    };
    const frame: TickFrame = .{
        .tick_index = 123,
        .frame_inputs = inputs[0..],
        .commands = commands[0..],
    };

    try std.testing.expectEqual(@as(i32, 123), frame.tick_index);
    try std.testing.expectEqual(@as(usize, 1), frame.frame_inputs.len);
    try std.testing.expectEqual(@as(u32, 3), frame.frame_inputs[0].flags);
    try std.testing.expectEqual(@as(usize, 5), frame.commands.len);
    switch (frame.commands[1]) {
        .perk_pick => |cmd| try std.testing.expectEqual(@as(i32, 2), cmd.choice_index),
        else => return error.TestExpectedEqual,
    }
    switch (frame.commands[2]) {
        .typo_char => |cmd| try std.testing.expectEqualStrings("a", cmd.ch),
        else => return error.TestExpectedEqual,
    }
}

test "lockstep pause keepalive debug and resync messages mirror python defaults" {
    const pause: PauseState = .{};
    try std.testing.expect(!pause.paused);
    try std.testing.expectEqualStrings("", pause.reason);

    const keepalive: KeepAlive = .{};
    try std.testing.expectEqual(@as(i32, 0), keepalive.tick_index);

    const debug: DebugLogBatch = .{};
    try std.testing.expectEqual(@as(i32, -1), debug.slot_index);
    try std.testing.expectEqual(@as(usize, 0), debug.lines.len);

    const resync: ResyncBegin = .{};
    try std.testing.expectEqualStrings("", resync.stream_id);
    try std.testing.expectEqual(@as(i32, 0), resync.total_chunks);
    try std.testing.expectEqual(@as(i32, 0), resync.compressed_size);
    try std.testing.expectEqual(@as(i32, 0), resync.replay_size);
    try std.testing.expectEqual(@as(i32, 0), resync.checkpoints_size);

    const chunk: ResyncChunk = .{ .stream_id = "s1", .chunk_index = 3, .payload = .{ .data = "chunk" } };
    try std.testing.expectEqualStrings("s1", chunk.stream_id);
    try std.testing.expectEqual(@as(i32, 3), chunk.chunk_index);
    try std.testing.expectEqualStrings("chunk", chunk.payload.data);

    const commit: ResyncCommit = .{ .stream_id = "s1", .tick_index = 42 };
    try std.testing.expectEqualStrings("s1", commit.stream_id);
    try std.testing.expectEqual(@as(i32, 42), commit.tick_index);

    const disconnect: Disconnect = .{};
    try std.testing.expectEqualStrings("", disconnect.reason);
}

test "lockstep packet encodes and decodes tagged tick frame" {
    const inputs = [_]packed_input.PackedPlayerInput{
        .{ .move_x = 0.5, .aim_x = 1.0, .aim_y = 2.0, .flags = 3 },
    };
    const commands = [_]GameCommand{
        .{ .perk_menu_open = .{ .player_index = 0 } },
        .{ .perk_pick = .{ .player_index = 0, .choice_index = 2 } },
    };
    const packet: LockstepPacket = .{
        .seq = 11,
        .ack = 10,
        .reliable = true,
        .message = .{ .tick_frame = .{
            .tick_index = 123,
            .frame_inputs = inputs[0..],
            .commands = commands[0..],
        } },
    };

    const encoded = try encodePacket(std.testing.allocator, packet);
    defer std.testing.allocator.free(encoded);

    const decoded = try decodePacket(std.testing.allocator, encoded);
    defer decoded.deinit();
    try std.testing.expectEqual(@as(i32, 11), decoded.value.seq);
    try std.testing.expectEqual(@as(i32, 10), decoded.value.ack);
    try std.testing.expect(decoded.value.reliable);
    switch (decoded.value.message) {
        .tick_frame => |frame| {
            try std.testing.expectEqual(@as(i32, 123), frame.tick_index);
            try std.testing.expectEqual(@as(usize, 1), frame.frame_inputs.len);
            try std.testing.expectEqual(@as(u32, 3), frame.frame_inputs[0].flags);
            try std.testing.expectEqual(@as(usize, 2), frame.commands.len);
            switch (frame.commands[1]) {
                .perk_pick => |cmd| try std.testing.expectEqual(@as(i32, 2), cmd.choice_index),
                else => return error.TestExpectedEqual,
            }
        },
        else => return error.TestExpectedEqual,
    }
}

test "lockstep packet clone owns lobby state slots" {
    const slots = [_]LobbySlot{
        .{ .slot_index = 0, .connected = true, .ready = true, .is_host = true, .peer_name = "host" },
        .{ .slot_index = 1, .connected = true, .ready = false, .is_host = false, .peer_name = "joiner" },
    };
    var cloned = try clonePacket(std.testing.allocator, .{
        .seq = 3,
        .ack = 2,
        .reliable = true,
        .message = .{ .lobby_state = .{
            .session_id = "session",
            .mode_id = 2,
            .player_count = 2,
            .slots = slots[0..],
            .all_ready = false,
            .started = false,
        } },
    });
    defer deinitPacket(std.testing.allocator, &cloned);

    try std.testing.expectEqual(@as(i32, 3), cloned.seq);
    try std.testing.expect(cloned.reliable);
    switch (cloned.message) {
        .lobby_state => |state| {
            try std.testing.expectEqualStrings("session", state.session_id);
            try std.testing.expectEqual(@as(usize, 2), state.slots.len);
            try std.testing.expectEqualStrings("host", state.slots[0].peer_name);
            try std.testing.expectEqualStrings("joiner", state.slots[1].peer_name);
            try std.testing.expect(state.session_id.ptr != "session".ptr);
            try std.testing.expect(state.slots[0].peer_name.ptr != "host".ptr);
            try std.testing.expect(state.slots[1].peer_name.ptr != "joiner".ptr);
        },
        else => return error.TestExpectedEqual,
    }
}

test "lockstep message clone owns tick frame commands and debug lines" {
    const inputs = [_]packed_input.PackedPlayerInput{.{ .flags = 9 }};
    const commands = [_]GameCommand{
        .{ .typo_char = .{ .player_index = 1, .ch = "x" } },
    };
    var tick_message = try cloneMessage(std.testing.allocator, .{ .tick_frame = .{
        .tick_index = 4,
        .frame_inputs = inputs[0..],
        .commands = commands[0..],
    } });
    defer deinitMessage(std.testing.allocator, &tick_message);
    switch (tick_message) {
        .tick_frame => |frame| {
            try std.testing.expectEqual(@as(i32, 4), frame.tick_index);
            try std.testing.expectEqual(@as(u32, 9), frame.frame_inputs[0].flags);
            switch (frame.commands[0]) {
                .typo_char => |cmd| {
                    try std.testing.expectEqualStrings("x", cmd.ch);
                    try std.testing.expect(cmd.ch.ptr != "x".ptr);
                },
                else => return error.TestExpectedEqual,
            }
        },
        else => return error.TestExpectedEqual,
    }

    const lines = [_][]const u8{ "alpha", "beta" };
    var debug_message = try cloneMessage(std.testing.allocator, .{ .debug_log_batch = .{
        .slot_index = 1,
        .lines = lines[0..],
    } });
    defer deinitMessage(std.testing.allocator, &debug_message);
    switch (debug_message) {
        .debug_log_batch => |batch| {
            try std.testing.expectEqual(@as(i32, 1), batch.slot_index);
            try std.testing.expectEqualStrings("alpha", batch.lines[0]);
            try std.testing.expectEqualStrings("beta", batch.lines[1]);
            try std.testing.expect(batch.lines[0].ptr != "alpha".ptr);
            try std.testing.expect(batch.lines[1].ptr != "beta".ptr);
        },
        else => return error.TestExpectedEqual,
    }
}

test "lockstep message clone owns input and resync payloads" {
    const samples = [_]InputSample{
        .{ .tick_index = 8, .packed_input = .{ .flags = 1 } },
        .{ .tick_index = 9, .packed_input = .{ .flags = 2 } },
    };
    var input_message = try cloneMessage(std.testing.allocator, .{ .input_batch = .{
        .slot_index = 2,
        .samples = samples[0..],
    } });
    defer deinitMessage(std.testing.allocator, &input_message);
    switch (input_message) {
        .input_batch => |batch| {
            try std.testing.expectEqual(@as(i32, 2), batch.slot_index);
            try std.testing.expectEqual(@as(usize, 2), batch.samples.len);
            try std.testing.expectEqual(@as(i32, 8), batch.samples[0].tick_index);
            try std.testing.expect(batch.samples.ptr != samples[0..].ptr);
        },
        else => return error.TestExpectedEqual,
    }

    var resync_message = try cloneMessage(std.testing.allocator, .{ .resync_chunk = .{
        .stream_id = "stream",
        .chunk_index = 5,
        .payload = .{ .data = "payload" },
    } });
    defer deinitMessage(std.testing.allocator, &resync_message);
    switch (resync_message) {
        .resync_chunk => |chunk| {
            try std.testing.expectEqualStrings("stream", chunk.stream_id);
            try std.testing.expectEqualStrings("payload", chunk.payload.data);
            try std.testing.expect(chunk.stream_id.ptr != "stream".ptr);
            try std.testing.expect(chunk.payload.data.ptr != "payload".ptr);
        },
        else => return error.TestExpectedEqual,
    }
}

test "lockstep packet encodes byte payloads as msgpack bin" {
    const packet: LockstepPacket = .{
        .message = .{ .resync_chunk = .{
            .stream_id = "stream",
            .chunk_index = 1,
            .payload = .{ .data = "abc" },
        } },
    };

    const encoded = try encodePacket(std.testing.allocator, packet);
    defer std.testing.allocator.free(encoded);
    try std.testing.expect(std.mem.indexOf(u8, encoded, &.{ 0xc4, 0x03, 'a', 'b', 'c' }) != null);

    const decoded = try decodePacket(std.testing.allocator, encoded);
    defer decoded.deinit();
    switch (decoded.value.message) {
        .resync_chunk => |chunk| try std.testing.expectEqualStrings("abc", chunk.payload.data),
        else => return error.TestExpectedEqual,
    }
}

test "lockstep packet decodes python msgspec resync chunk fixture" {
    const fixture =
        "84a373657101a361636b00a872656c6961626c65c3a76d65737361676584a474797065ac726573796e635f6368756e6ba973747265616d5f6964a173ab6368756e6b5f696e64657802a77061796c6f6164c403616263";
    var bytes: [fixture.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&bytes, fixture);

    const decoded = try decodePacket(std.testing.allocator, &bytes);
    defer decoded.deinit();
    try std.testing.expectEqual(@as(i32, 1), decoded.value.seq);
    try std.testing.expect(decoded.value.reliable);
    switch (decoded.value.message) {
        .resync_chunk => |chunk| {
            try std.testing.expectEqualStrings("s", chunk.stream_id);
            try std.testing.expectEqual(@as(i32, 2), chunk.chunk_index);
            try std.testing.expectEqualStrings("abc", chunk.payload.data);
        },
        else => return error.TestExpectedEqual,
    }
}

test "lockstep packet decodes python msgspec tick frame fixture" {
    const fixture =
        "84a373657103a361636b02a872656c6961626c65c3a76d65737361676584a474797065aa7469636b5f6672616d65aa7469636b5f696e64657805ac6672616d655f696e707574739195cb3fe0000000000000cb0000000000000000cb3ff0000000000000cb400000000000000003a8636f6d6d616e64739183a474797065a97065726b5f7069636bac706c617965725f696e64657800ac63686f6963655f696e64657802";
    var bytes: [fixture.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&bytes, fixture);

    const decoded = try decodePacket(std.testing.allocator, &bytes);
    defer decoded.deinit();
    try std.testing.expectEqual(@as(i32, 3), decoded.value.seq);
    try std.testing.expectEqual(@as(i32, 2), decoded.value.ack);
    switch (decoded.value.message) {
        .tick_frame => |frame| {
            try std.testing.expectEqual(@as(i32, 5), frame.tick_index);
            try std.testing.expectEqual(@as(usize, 1), frame.frame_inputs.len);
            try std.testing.expectEqual(@as(f32, 0.5), frame.frame_inputs[0].move_x);
            try std.testing.expectEqual(@as(f32, 1.0), frame.frame_inputs[0].aim_x);
            try std.testing.expectEqual(@as(f32, 2.0), frame.frame_inputs[0].aim_y);
            try std.testing.expectEqual(@as(u32, 3), frame.frame_inputs[0].flags);
            try std.testing.expectEqual(@as(usize, 1), frame.commands.len);
            switch (frame.commands[0]) {
                .perk_pick => |cmd| {
                    try std.testing.expectEqual(@as(i32, 0), cmd.player_index);
                    try std.testing.expectEqual(@as(i32, 2), cmd.choice_index);
                },
                else => return error.TestExpectedEqual,
            }
        },
        else => return error.TestExpectedEqual,
    }
}
