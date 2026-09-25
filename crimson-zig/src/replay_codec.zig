//! Replay format v20 (`docs/formats/replay.md`): one zstd frame holding a
//! canonical msgpack payload.
//!
//! The reader accepts exactly the byte strings that equal the canonical
//! encoding of the value they decode to: keys in declared order, minimal
//! integer and length headers, float64 floats holding exact f32 values.
const std = @import("std");
const game_ids = @import("game_ids.zig");

pub const replay_format_version: i32 = 20;
pub const tick_rate: i32 = 60;
/// Every replay tick advances the simulation by this delta.
pub const tick_dt: f32 = 1.0 / @as(f32, @floatFromInt(tick_rate));
/// Every run plays in the native 1024x1024 arena.
pub const world_size: f32 = 1024.0;
pub const weapon_usage_count: usize = 53;
pub const max_players: usize = 4;
pub const perk_choice_slot_count: usize = 7;
pub const zstd_magic = [_]u8{ 0x28, 0xB5, 0x2F, 0xFD };
pub const max_replay_payload_bytes: usize = 64 * 1024 * 1024;
pub const max_replay_file_bytes: usize = 65 * 1024 * 1024;
/// Largest decompression window a replay's zstd frame may declare.
pub const max_zstd_window_bytes: u64 = std.compress.zstd.default_window_len;
/// Typ-o name sources are plain ASCII with capped counts and lengths, so every
/// port agrees on them and can use fixed storage.
pub const max_typo_dictionary_words: usize = 2048;
pub const max_typo_highscore_names: usize = 512;
/// Creature names must be shorter than this; dictionary words are too.
pub const typo_name_max_chars: usize = 16;
/// Score-table names hold up to 31 bytes.
pub const typo_highscore_name_max_chars: usize = 31;

pub const fire_down_flag: u32 = 1 << 0;
pub const fire_pressed_flag: u32 = 1 << 1;
pub const reload_pressed_flag: u32 = 1 << 2;
pub const reload_down_flag: u32 = 1 << 16;
pub const fire_bullets_key_down_flag: u32 = 1 << 17;
pub const move_keys_present_flag: u32 = 1 << 3;
pub const move_forward_flag: u32 = 1 << 4;
pub const move_backward_flag: u32 = 1 << 5;
pub const turn_left_flag: u32 = 1 << 6;
pub const turn_right_flag: u32 = 1 << 7;
pub const move_mode_present_flag: u32 = 1 << 8;
pub const move_mode_shift: u5 = 9;
pub const move_mode_mask: u32 = 0x7;
pub const aim_scheme_present_flag: u32 = 1 << 12;
pub const aim_scheme_shift: u5 = 13;
pub const aim_scheme_mask: u32 = 0x7;
const supported_input_flags_mask: u32 = fire_down_flag |
    fire_pressed_flag |
    reload_pressed_flag |
    reload_down_flag |
    fire_bullets_key_down_flag |
    move_keys_present_flag |
    move_forward_flag |
    move_backward_flag |
    turn_left_flag |
    turn_right_flag |
    move_mode_present_flag |
    (move_mode_mask << move_mode_shift) |
    aim_scheme_present_flag |
    (aim_scheme_mask << aim_scheme_shift);

/// Full msgpack integer range (i64 min through u64 max); unconstrained
/// integer fields keep it so every canonical value round-trips.
pub const Int = std.meta.Int(.signed, 65);

pub const QuestLevel = struct {
    major: u8,
    minor: u8,
};

pub const RunStatus = struct {
    quest_unlock_index: i32 = 0,
    quest_unlock_index_full: i32 = 0,
    weapon_usage_counts: [weapon_usage_count]u32 = [_]u32{0} ** weapon_usage_count,
};

pub const RunSpec = struct {
    game_mode: game_ids.GameModeId,
    seed: u32,
    quest_level: ?QuestLevel = null,
    player_count: u8 = 1,
    hardcore: bool = false,
    preserve_bugs: bool = false,
    demo: bool = false,
    quest_fail_retry_count: i32 = 0,
    detail_preset: i32 = 5,
    violence_disabled: i32 = 0,
    status: RunStatus = .{},
    typo_dictionary_words: []const []const u8 = &.{},
    typo_highscore_names: []const []const u8 = &.{},
};

pub const RunOutcome = enum {
    death,
    quest_completed,
    tutorial_completed,
    incomplete,
};

pub const PlayerResult = struct {
    experience: Int,
    health: f32,
    shots_fired: Int,
    shots_hit: Int,
    most_used_weapon_id: game_ids.WeaponId,
};

pub const RunResult = struct {
    outcome: RunOutcome,
    elapsed_ms: Int,
    kills: Int,
    rng_state: u32,
    pending_perks: Int,
    quest_final_ms: ?Int,
    player_count: usize,
    players_buffer: [max_players]PlayerResult = undefined,

    pub fn players(self: *const RunResult) []const PlayerResult {
        return self.players_buffer[0..self.player_count];
    }

    /// JSON with the wire keys and order; `health` prints the exact f32 value.
    pub fn jsonStringify(self: RunResult, jws: anytype) !void {
        try jws.beginObject();
        try jws.objectField("outcome");
        try jws.write(@tagName(self.outcome));
        try jws.objectField("elapsed_ms");
        try jws.write(self.elapsed_ms);
        try jws.objectField("kills");
        try jws.write(self.kills);
        try jws.objectField("rng_state");
        try jws.write(self.rng_state);
        try jws.objectField("pending_perks");
        try jws.write(self.pending_perks);
        try jws.objectField("quest_final_ms");
        try jws.write(self.quest_final_ms);
        try jws.objectField("players");
        try jws.beginArray();
        for (self.players()) |player| {
            try jws.beginObject();
            try jws.objectField("experience");
            try jws.write(player.experience);
            try jws.objectField("health");
            // Integral values keep a fractional part, as Python prints floats.
            const health: f64 = player.health;
            if (@trunc(health) == health and @abs(health) < 1e16) {
                try jws.print("{d}.0", .{health});
            } else {
                try jws.print("{d}", .{health});
            }
            try jws.objectField("shots_fired");
            try jws.write(player.shots_fired);
            try jws.objectField("shots_hit");
            try jws.write(player.shots_hit);
            try jws.objectField("most_used_weapon_id");
            try jws.write(@intFromEnum(player.most_used_weapon_id));
            try jws.endObject();
        }
        try jws.endArray();
        try jws.endObject();
    }

    pub fn eql(self: *const RunResult, other: *const RunResult) bool {
        inline for (.{ "outcome", "elapsed_ms", "kills", "rng_state", "pending_perks", "quest_final_ms", "player_count" }) |field| {
            if (!std.meta.eql(@field(self, field), @field(other, field))) return false;
        }
        for (self.players(), other.players()) |expected, actual| {
            if (!std.meta.eql(expected, actual)) return false;
        }
        return true;
    }

    /// Field paths where two results differ, in declared order (`players`
    /// alone when the counts differ). Paths are allocated from `arena`.
    pub fn mismatches(self: *const RunResult, arena: std.mem.Allocator, other: *const RunResult) ![]const []const u8 {
        var paths: std.ArrayList([]const u8) = .empty;
        inline for (.{ "outcome", "elapsed_ms", "kills", "rng_state", "pending_perks", "quest_final_ms" }) |field| {
            if (!std.meta.eql(@field(self, field), @field(other, field))) try paths.append(arena, field);
        }
        if (self.player_count != other.player_count) {
            try paths.append(arena, "players");
            return paths.items;
        }
        for (self.players(), other.players(), 0..) |expected, actual, index| {
            inline for (std.meta.fields(PlayerResult)) |field| {
                if (!std.meta.eql(@field(expected, field.name), @field(actual, field.name))) {
                    try paths.append(arena, try std.fmt.allocPrint(arena, "players[{d}]." ++ field.name, .{index}));
                }
            }
        }
        return paths.items;
    }
};

pub const PlayerInput = struct {
    move_x: f32 = 0.0,
    move_y: f32 = 0.0,
    aim_x: f32 = 0.0,
    aim_y: f32 = 0.0,
    flags: u32 = 0,
};

pub const Command = union(enum) {
    perk_menu_open: struct { player_index: u8 },
    perk_pick: struct { player_index: u8, choice_index: u8 },
    /// `ch` is exactly one UTF-8 encoded code point.
    typo_char: struct { player_index: u8, ch: []const u8 },
    typo_backspace: struct { player_index: u8 },
    typo_submit: struct { player_index: u8 },

    pub fn playerIndex(self: Command) u8 {
        return switch (self) {
            inline else => |command| command.player_index,
        };
    }

    pub fn isTypo(self: Command) bool {
        return switch (self) {
            .typo_char, .typo_backspace, .typo_submit => true,
            .perk_menu_open, .perk_pick => false,
        };
    }
};

pub const Replay = struct {
    game_version: []const u8,
    run: RunSpec,
    result: RunResult,
    /// Tick-major, `run.player_count` inputs per tick.
    inputs: []const PlayerInput,
    commands: []const Command = &.{},
    /// Exclusive end of each tick's slice of `commands`.
    command_ends: []const u32,
    /// Owns every decoded slice; hand-built replays leave it empty.
    arena: std.heap.ArenaAllocator.State = .init,

    pub fn deinit(self: Replay, allocator: std.mem.Allocator) void {
        self.arena.promote(allocator).deinit();
    }

    pub fn tickCount(self: Replay) usize {
        return self.command_ends.len;
    }

    pub fn tickInputs(self: Replay, tick_index: usize) []const PlayerInput {
        const count: usize = self.run.player_count;
        return self.inputs[tick_index * count ..][0..count];
    }

    pub fn tickCommands(self: Replay, tick_index: usize) []const Command {
        const start = if (tick_index == 0) 0 else self.command_ends[tick_index - 1];
        return self.commands[start..self.command_ends[tick_index]];
    }
};

/// Human-readable reason for the last `error.InvalidReplay`.
pub const Diagnostic = struct {
    buffer: [256]u8 = undefined,
    len: usize = 0,

    pub fn message(self: *const Diagnostic) []const u8 {
        return self.buffer[0..self.len];
    }

    pub fn set(self: *Diagnostic, comptime fmt: []const u8, args: anytype) error{InvalidReplay} {
        // An overlong message keeps its truncated prefix.
        self.len = (std.fmt.bufPrint(&self.buffer, fmt, args) catch @as([]u8, &self.buffer)).len;
        return error.InvalidReplay;
    }
};

pub const DecodeError = error{ InvalidReplay, OutOfMemory };
pub const InflateError = error{ InvalidZstdPayload, PayloadTooLarge, OutOfMemory };

pub const InputFlags = struct {
    fire_down: bool,
    fire_pressed: bool,
    reload_pressed: bool,
    reload_down: bool,
    fire_bullets_key_down: bool,
    move_mode: ?i32 = null,
    aim_scheme: ?i32 = null,
    move_forward_pressed: ?bool = null,
    move_backward_pressed: ?bool = null,
    turn_left_pressed: ?bool = null,
    turn_right_pressed: ?bool = null,
};

pub fn unpackInputFlags(flags: u32) InputFlags {
    var decoded: InputFlags = .{
        .fire_down = (flags & fire_down_flag) != 0,
        .fire_pressed = (flags & fire_pressed_flag) != 0,
        .reload_pressed = (flags & reload_pressed_flag) != 0,
        .reload_down = (flags & reload_down_flag) != 0,
        .fire_bullets_key_down = (flags & fire_bullets_key_down_flag) != 0,
    };

    if ((flags & move_keys_present_flag) != 0) {
        decoded.move_forward_pressed = (flags & move_forward_flag) != 0;
        decoded.move_backward_pressed = (flags & move_backward_flag) != 0;
        decoded.turn_left_pressed = (flags & turn_left_flag) != 0;
        decoded.turn_right_pressed = (flags & turn_right_flag) != 0;
    }
    if ((flags & move_mode_present_flag) != 0) {
        decoded.move_mode = @intCast((flags >> move_mode_shift) & move_mode_mask);
    }
    if ((flags & aim_scheme_present_flag) != 0) {
        const raw: i32 = @intCast((flags >> aim_scheme_shift) & aim_scheme_mask);
        decoded.aim_scheme = if (raw == @as(i32, @intCast(aim_scheme_mask))) -1 else raw;
    }
    return decoded;
}

/// Reason a packed flag word is invalid, phrased like the Python validator.
pub fn inputFlagsError(flags: Int) ?[]const u8 {
    if (flags < 0 or flags > std.math.maxInt(u32)) return "contain unsupported bits";
    const value: u32 = @intCast(flags);
    if ((value & ~supported_input_flags_mask) != 0) return "contain unsupported bits";
    const move_key_bits = move_forward_flag | move_backward_flag | turn_left_flag | turn_right_flag;
    if ((value & move_keys_present_flag) == 0 and (value & move_key_bits) != 0) {
        return "set movement-key values without MOVE_KEYS_PRESENT";
    }
    const move_mode_value = (value >> move_mode_shift) & move_mode_mask;
    if ((value & move_mode_present_flag) == 0 and move_mode_value != 0) {
        return "set a movement mode without MOVE_MODE_PRESENT";
    }
    if ((value & move_mode_present_flag) != 0 and move_mode_value > 5) return "contain an invalid movement mode";
    const aim_scheme_value = (value >> aim_scheme_shift) & aim_scheme_mask;
    if ((value & aim_scheme_present_flag) == 0 and aim_scheme_value != 0) {
        return "set an aim scheme without AIM_SCHEME_PRESENT";
    }
    if ((value & aim_scheme_present_flag) != 0 and aim_scheme_value == 6) return "contain an invalid aim scheme";
    return null;
}

pub fn isTypoDictionaryWord(text: []const u8) bool {
    if (text.len == 0 or text.len >= typo_name_max_chars) return false;
    for (text) |ch| {
        if (ch < 0x20 or ch > 0x7e) return false;
    }
    return true;
}

pub fn isTypoHighscoreName(text: []const u8) bool {
    if (text.len == 0 or text.len > typo_highscore_name_max_chars) return false;
    for (text) |ch| {
        if (!std.ascii.isAlphabetic(ch) and ch != '.') return false;
    }
    return true;
}

pub fn outcomeAllowed(game_mode: game_ids.GameModeId, outcome: RunOutcome) bool {
    return switch (outcome) {
        .incomplete => true,
        .death => game_mode != .tutorial,
        .quest_completed => game_mode == .quests,
        .tutorial_completed => game_mode == .tutorial,
    };
}

// ---------------------------------------------------------------------------
// Envelope
// ---------------------------------------------------------------------------

pub fn isZstdPayload(bytes: []const u8) bool {
    return std.mem.startsWith(u8, bytes, &zstd_magic);
}

/// Inflate every zstd frame in `compressed` (checkpoint sidecars).
pub fn inflateZstdPayload(
    allocator: std.mem.Allocator,
    compressed: []const u8,
    max_output_bytes: usize,
) InflateError![]u8 {
    var input: std.Io.Reader = .fixed(compressed);
    var window: [std.compress.zstd.default_window_len + std.compress.zstd.block_size_max]u8 = undefined;
    var decompress: std.compress.zstd.Decompress = .init(&input, &window, .{ .verify_checksum = false });

    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);

    var chunk: [8192]u8 = undefined;
    var total: usize = 0;
    while (true) {
        const n = decompress.reader.readSliceShort(&chunk) catch {
            _ = decompress.err;
            return error.InvalidZstdPayload;
        };
        if (n == 0) break;
        total += n;
        if (total > max_output_bytes) return error.PayloadTooLarge;
        try out.appendSlice(allocator, chunk[0..n]);
    }

    return out.toOwnedSlice(allocator);
}

fn inflateSingleZstdFramePayload(
    allocator: std.mem.Allocator,
    compressed: []const u8,
    max_output_bytes: usize,
) InflateError![]u8 {
    var input: std.Io.Reader = .fixed(compressed);
    var window: [std.compress.zstd.default_window_len + std.compress.zstd.block_size_max]u8 = undefined;
    var decompress: std.compress.zstd.Decompress = .init(&input, &window, .{ .verify_checksum = false });
    var output: std.ArrayList(u8) = .empty;
    defer output.deinit(allocator);

    var frame_started = false;
    while (true) {
        const frame_finished = switch (decompress.state) {
            .new_frame => frame_started and decompress.reader.bufferedLen() == 0,
            else => false,
        };
        if (frame_finished) break;
        frame_started = true;

        var chunk: [8192]u8 = undefined;
        var chunk_writer: std.Io.Writer = .fixed(&chunk);
        _ = decompress.reader.stream(&chunk_writer, .limited(chunk.len)) catch |err| switch (err) {
            error.WriteFailed => unreachable,
            error.ReadFailed, error.EndOfStream => {
                _ = decompress.err;
                return error.InvalidZstdPayload;
            },
        };
        if (chunk_writer.end > max_output_bytes - output.items.len) return error.PayloadTooLarge;
        try output.appendSlice(allocator, chunk[0..chunk_writer.end]);
    }

    if (input.seek != compressed.len) return error.InvalidZstdPayload;
    const has_checksum = compressed.len > zstd_magic.len and
        (compressed[zstd_magic.len] & 0b0000_0100) != 0;
    if (has_checksum) {
        if (input.seek < @sizeOf(u32)) return error.InvalidZstdPayload;
        const expected = std.mem.readInt(
            u32,
            compressed[input.seek - @sizeOf(u32) ..][0..@sizeOf(u32)],
            .little,
        );
        const actual: u32 = @truncate(std.hash.XxHash64.hash(0, output.items));
        if (actual != expected) return error.InvalidZstdPayload;
    }
    return output.toOwnedSlice(allocator);
}

/// Decode the only supported on-disk envelope: exactly one zstd frame.
pub fn inflateZstdFilePayload(
    allocator: std.mem.Allocator,
    compressed: []const u8,
    max_output_bytes: usize,
) InflateError![]u8 {
    if (!isZstdPayload(compressed)) return error.InvalidZstdPayload;
    return inflateSingleZstdFramePayload(allocator, compressed, max_output_bytes);
}

/// Return the msgpack payload of a replay file.
pub fn inflateReplayFile(
    allocator: std.mem.Allocator,
    file_bytes: []const u8,
    diagnostic: *Diagnostic,
) DecodeError![]u8 {
    if (file_bytes.len > max_replay_file_bytes) {
        return diagnostic.set("replay file too large (> {d} bytes)", .{max_replay_file_bytes});
    }
    if (!isZstdPayload(file_bytes)) return diagnostic.set("replay must use the zstd envelope", .{});
    var header_reader: std.Io.Reader = .fixed(file_bytes[zstd_magic.len..]);
    if (std.compress.zstd.Decompress.Frame.Zstandard.Header.decode(&header_reader)) |header| {
        if ((header.windowSize() orelse 0) > max_zstd_window_bytes) {
            return diagnostic.set("replay zstd frame window exceeds {d} MiB", .{max_zstd_window_bytes / (1024 * 1024)});
        }
    } else |_| {}
    return inflateSingleZstdFramePayload(allocator, file_bytes, max_replay_payload_bytes) catch |err| switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.InvalidZstdPayload => diagnostic.set("invalid replay zstd payload", .{}),
        error.PayloadTooLarge => diagnostic.set("replay payload too large (> {d} bytes)", .{max_replay_payload_bytes}),
    };
}

pub fn loadReplay(
    allocator: std.mem.Allocator,
    file_bytes: []const u8,
    diagnostic: *Diagnostic,
) DecodeError!Replay {
    const payload = try inflateReplayFile(allocator, file_bytes, diagnostic);
    defer allocator.free(payload);
    return decodePayload(allocator, payload, diagnostic);
}

/// Build a valid zstd file envelope using raw blocks.
///
/// This keeps tests and embedding callers independent of a zstd compressor
/// while exercising the same mandatory envelope as real `.crd` files.
pub fn wrapZstdFilePayload(
    allocator: std.mem.Allocator,
    payload: []const u8,
) ![]u8 {
    if (payload.len > std.math.maxInt(u32)) return error.PayloadTooLarge;

    var writer: std.Io.Writer.Allocating = .init(allocator);
    errdefer writer.deinit();
    try writer.writer.writeAll(&zstd_magic);

    if (payload.len <= std.math.maxInt(u8)) {
        try writer.writer.writeByte(0x20);
        try writer.writer.writeByte(@intCast(payload.len));
    } else if (payload.len <= 65_791) {
        try writer.writer.writeByte(0x60);
        try writer.writer.writeInt(u16, @intCast(payload.len - 256), .little);
    } else {
        try writer.writer.writeByte(0xA0);
        try writer.writer.writeInt(u32, @intCast(payload.len), .little);
    }

    const max_raw_block_len: usize = 128 * 1024;
    var offset: usize = 0;
    while (true) {
        const block_len = @min(payload.len - offset, max_raw_block_len);
        const last = offset + block_len == payload.len;
        const block_header: u24 = @intFromBool(last) | (@as(u24, @intCast(block_len)) << 3);
        try writer.writer.writeInt(u24, block_header, .little);
        try writer.writer.writeAll(payload[offset .. offset + block_len]);
        offset += block_len;
        if (last) break;
    }

    return writer.toOwnedSlice();
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

const replay_keys = [_][]const u8{ "format_version", "game_version", "run", "result", "ticks" };
const run_keys = [_][]const u8{
    "game_mode_id",  "seed",                   "quest_level",           "player_count",
    "hardcore",      "preserve_bugs",          "demo",                  "quest_fail_retry_count",
    "detail_preset", "violence_disabled",      "status",                "typo_dictionary_words",
    "typo_highscore_names",
};
const quest_level_keys = [_][]const u8{ "major", "minor" };
const status_keys = [_][]const u8{ "quest_unlock_index", "quest_unlock_index_full", "weapon_usage_counts" };
const result_keys = [_][]const u8{ "outcome", "elapsed_ms", "kills", "rng_state", "pending_perks", "quest_final_ms", "players" };
const player_result_keys = [_][]const u8{ "experience", "health", "shots_fired", "shots_hit", "most_used_weapon_id" };
const axis_names = [_][]const u8{ "move_x", "move_y", "aim_x", "aim_y" };

// Smallest possible encodings, used to bound declared lengths by the bytes left.
const min_player_input_bytes = 1 + 4 * 9 + 1;
const min_tick_bytes = 1 + 1 + 1;
const min_command_bytes = 1 + 5 + 10 + 13 + 1;

const Reader = struct {
    bytes: []const u8,
    pos: usize = 0,
    arena: std.mem.Allocator,
    diagnostic: *Diagnostic,
    /// Field path of the value being read (`run.seed`), for error messages.
    path: [96]u8 = undefined,
    path_len: usize = 0,

    fn fail(self: *Reader, comptime fmt: []const u8, args: anytype) error{InvalidReplay} {
        return self.diagnostic.set(fmt, args);
    }

    /// Fail with a message about the current field path.
    fn failAt(self: *Reader, comptime detail: []const u8, args: anytype) error{InvalidReplay} {
        const path = if (self.path_len == 0) "replay payload" else self.path[0..self.path_len];
        return self.diagnostic.set("{s}" ++ detail, .{path} ++ args);
    }

    fn noncanonical(self: *Reader) error{InvalidReplay} {
        return self.fail("replay payload is not canonically encoded", .{});
    }

    /// Point the path at a child of the path prefix `base`.
    fn at(self: *Reader, comptime fmt: []const u8, base: usize, args: anytype) void {
        const tail = self.path[base..];
        self.path_len = base + (std.fmt.bufPrint(tail, fmt, args) catch tail).len;
    }

    fn take(self: *Reader, n: usize) error{InvalidReplay}![]const u8 {
        if (n > self.bytes.len - self.pos) return self.fail("invalid replay payload: truncated msgpack data", .{});
        const result = self.bytes[self.pos..][0..n];
        self.pos += n;
        return result;
    }

    fn byte(self: *Reader) error{InvalidReplay}!u8 {
        return (try self.take(1))[0];
    }

    fn uint(self: *Reader, comptime T: type) error{InvalidReplay}!T {
        return std.mem.readInt(T, (try self.take(@sizeOf(T)))[0..@sizeOf(T)], .big);
    }

    fn int(self: *Reader) error{InvalidReplay}!Int {
        const tag = try self.byte();
        const value: Int = switch (tag) {
            0x00...0x7f => tag,
            0xe0...0xff => @as(i8, @bitCast(tag)),
            0xcc => try self.uint(u8),
            0xcd => try self.uint(u16),
            0xce => try self.uint(u32),
            0xcf => try self.uint(u64),
            0xd0 => @as(i8, @bitCast(try self.uint(u8))),
            0xd1 => try self.uint(i16),
            0xd2 => try self.uint(i32),
            0xd3 => try self.uint(i64),
            else => return self.failAt(" must be an integer", .{}),
        };
        if (intTag(value) != tag) return self.noncanonical();
        return value;
    }

    fn intIn(self: *Reader, comptime T: type) error{InvalidReplay}!T {
        return std.math.cast(T, try self.int()) orelse
            self.failAt(" must be in {d}..{d}", .{ std.math.minInt(T), std.math.maxInt(T) });
    }

    fn intBetween(self: *Reader, low: i32, high: i32) error{InvalidReplay}!i32 {
        const value = try self.int();
        if (value < low or value > high) return self.failAt(" must be in {d}..{d}", .{ low, high });
        return @intCast(value);
    }

    fn float32(self: *Reader) error{InvalidReplay}!f32 {
        switch (try self.byte()) {
            0xcb => {},
            // Integers and float32 decode as floats but never re-encode canonically.
            0x00...0x7f, 0xe0...0xff, 0xca, 0xcc...0xd3 => return self.noncanonical(),
            else => return self.failAt(" must be a float", .{}),
        }
        const value: f64 = @bitCast(try self.uint(u64));
        if (!std.math.isFinite(value)) return self.failAt(" must be finite", .{});
        if (@abs(value) > std.math.floatMax(f32)) return self.failAt(" is outside the f32 range", .{});
        const narrowed: f32 = @floatCast(value);
        if (@as(f64, narrowed) != value) return self.failAt(" must be a canonical f32", .{});
        return narrowed;
    }

    fn boolean(self: *Reader) error{InvalidReplay}!bool {
        return switch (try self.byte()) {
            0xc2 => false,
            0xc3 => true,
            else => self.failAt(" must be a bool", .{}),
        };
    }

    fn nil(self: *Reader) error{InvalidReplay}!bool {
        if (self.pos == self.bytes.len or self.bytes[self.pos] != 0xc0) return false;
        self.pos += 1;
        return true;
    }

    /// Length from a str/array/map header, which must be the shortest one.
    fn length(self: *Reader, comptime header: LengthHeader) error{InvalidReplay}!usize {
        const tag = try self.byte();
        const len: usize = if (tag >= header.fix and tag < header.fix + header.fix_limit)
            tag - header.fix
        else if (header.tag8 != null and tag == header.tag8.?)
            try self.uint(u8)
        else if (tag == header.tag16)
            try self.uint(u16)
        else if (tag == header.tag32)
            try self.uint(u32)
        else
            return self.failAt(" must be " ++ header.noun, .{});
        if (header.tag(len) != tag) return self.noncanonical();
        return len;
    }

    fn string(self: *Reader) error{InvalidReplay}![]const u8 {
        const bytes = try self.take(try self.length(string_header));
        if (!std.unicode.utf8ValidateSlice(bytes)) return self.failAt(" is not valid UTF-8", .{});
        return bytes;
    }

    /// Array length, bounded by the bytes left before any allocation.
    fn array(self: *Reader, min_element_bytes: usize) error{InvalidReplay}!usize {
        const len = try self.length(array_header);
        if (len > (self.bytes.len - self.pos) / min_element_bytes) {
            return self.fail("invalid replay payload: truncated msgpack data", .{});
        }
        return len;
    }

    fn arrayOf(self: *Reader, len: usize) error{InvalidReplay}!void {
        const actual = try self.array(1);
        if (actual != len) return self.failAt(" must have {d} items, got {d}", .{ len, actual });
    }

    /// Enter a map whose keys must be exactly `keys`, in order; returns the
    /// path prefix its fields extend.
    fn map(self: *Reader, comptime keys: []const []const u8) error{InvalidReplay}!usize {
        if (try self.length(map_header) != keys.len) {
            return self.failAt(" must have exactly the keys {s}", .{comptime keyList(keys)});
        }
        return self.path_len;
    }

    fn key(self: *Reader, comptime expected: []const u8, base: usize) error{InvalidReplay}!void {
        self.path_len = base;
        const actual = try self.string();
        if (!std.mem.eql(u8, actual, expected)) {
            return self.failAt(" has key `{s}` where `{s}` belongs", .{ actual, expected });
        }
        self.at("{s}" ++ expected, base, .{if (base == 0) "" else "."});
    }
};

fn keyList(comptime keys: []const []const u8) []const u8 {
    var text: []const u8 = keys[0];
    for (keys[1..]) |name| text = text ++ ", " ++ name;
    return text;
}

fn intTag(value: Int) u8 {
    if (value >= 0) {
        if (value <= 0x7f) return @intCast(value);
        if (value <= std.math.maxInt(u8)) return 0xcc;
        if (value <= std.math.maxInt(u16)) return 0xcd;
        if (value <= std.math.maxInt(u32)) return 0xce;
        return 0xcf;
    }
    if (value >= -32) return @bitCast(@as(i8, @intCast(value)));
    if (value >= std.math.minInt(i8)) return 0xd0;
    if (value >= std.math.minInt(i16)) return 0xd1;
    if (value >= std.math.minInt(i32)) return 0xd2;
    return 0xd3;
}

/// The msgpack header family of a string, array or map.
const LengthHeader = struct {
    fix: u8,
    fix_limit: usize,
    tag8: ?u8,
    tag16: u8,
    tag32: u8,
    noun: []const u8,

    /// The shortest header tag for `len`.
    fn tag(comptime self: LengthHeader, len: usize) u8 {
        if (len < self.fix_limit) return self.fix + @as(u8, @intCast(len));
        if (self.tag8 != null and len <= std.math.maxInt(u8)) return self.tag8.?;
        if (len <= std.math.maxInt(u16)) return self.tag16;
        return self.tag32;
    }
};
const string_header: LengthHeader = .{ .fix = 0xa0, .fix_limit = 32, .tag8 = 0xd9, .tag16 = 0xda, .tag32 = 0xdb, .noun = "a string" };
const array_header: LengthHeader = .{ .fix = 0x90, .fix_limit = 16, .tag8 = null, .tag16 = 0xdc, .tag32 = 0xdd, .noun = "an array" };
const map_header: LengthHeader = .{ .fix = 0x80, .fix_limit = 16, .tag8 = null, .tag16 = 0xde, .tag32 = 0xdf, .noun = "a map" };

/// Decode and validate a canonical replay payload.
pub fn decodePayload(
    allocator: std.mem.Allocator,
    payload: []const u8,
    diagnostic: *Diagnostic,
) DecodeError!Replay {
    var arena: std.heap.ArenaAllocator = .init(allocator);
    errdefer arena.deinit();
    // Decoded strings slice into this copy, so the replay outlives `payload`.
    const bytes = try arena.allocator().dupe(u8, payload);
    var reader: Reader = .{ .bytes = bytes, .arena = arena.allocator(), .diagnostic = diagnostic };
    var replay = try readReplay(&reader);
    if (reader.pos != bytes.len) return diagnostic.set("invalid replay payload: trailing bytes after the replay", .{});
    replay.arena = arena.state;
    return replay;
}

fn readReplay(r: *Reader) DecodeError!Replay {
    const base = try r.map(&replay_keys);
    try r.key("format_version", base);
    const version = try r.int();
    if (version != replay_format_version) return r.fail("unsupported replay format version: {d}", .{version});
    try r.key("game_version", base);
    const game_version = try r.string();
    if (game_version.len == 0) return r.fail("game_version must be non-empty", .{});
    try r.key("run", base);
    const run = try readRun(r);
    try r.key("result", base);
    const result = try readResult(r, run);
    try r.key("ticks", base);
    const player_count: usize = run.player_count;
    const tick_count = try r.array(min_tick_bytes);
    if (tick_count == 0) return r.fail("replay must contain at least one tick", .{});

    const command_ends = try r.arena.alloc(u32, tick_count);
    // Inputs and commands grow as they are read, so memory stays
    // proportional to the payload rather than to declared lengths.
    var inputs: std.ArrayList(PlayerInput) = .empty;
    var commands: std.ArrayList(Command) = .empty;
    for (0..tick_count) |tick_index| {
        r.at("ticks[{d}]", 0, .{tick_index});
        try readTick(r, run, try inputs.addManyAsSlice(r.arena, player_count), &commands);
        command_ends[tick_index] = @intCast(commands.items.len);
    }
    return .{
        .game_version = game_version,
        .run = run,
        .result = result,
        .inputs = inputs.items,
        .commands = commands.items,
        .command_ends = command_ends,
    };
}

fn readRun(r: *Reader) DecodeError!RunSpec {
    const base = try r.map(&run_keys);
    var run: RunSpec = .{ .game_mode = .survival, .seed = 0 };

    try r.key("game_mode_id", base);
    const mode_id = try r.int();
    run.game_mode = std.enums.fromInt(game_ids.GameModeId, mode_id) orelse
        return r.failAt(" {d} is not a replayable mode", .{mode_id});
    try r.key("seed", base);
    run.seed = try r.intIn(u32);
    try r.key("quest_level", base);
    if (!try r.nil()) {
        const level_base = try r.map(&quest_level_keys);
        try r.key("major", level_base);
        const major = try r.int();
        try r.key("minor", level_base);
        const minor = try r.int();
        r.path_len = level_base;
        if (major < 1 or major > 5 or minor < 1 or minor > 10) return r.failAt(" must be 1..5 / 1..10", .{});
        run.quest_level = .{ .major = @intCast(major), .minor = @intCast(minor) };
    }
    if ((run.quest_level != null) != (run.game_mode == .quests)) {
        return r.fail("run.quest_level must be set for quests and only for quests", .{});
    }
    try r.key("player_count", base);
    const player_count = try r.int();
    if (player_count < 1 or player_count > max_players) return r.failAt(" must be in 1..{d}", .{max_players});
    run.player_count = @intCast(player_count);
    if ((run.game_mode == .typo or run.game_mode == .tutorial) and run.player_count != 1) {
        return r.fail("{s} replays require player_count == 1", .{@tagName(run.game_mode)});
    }
    try r.key("hardcore", base);
    run.hardcore = try r.boolean();
    try r.key("preserve_bugs", base);
    run.preserve_bugs = try r.boolean();
    try r.key("demo", base);
    run.demo = try r.boolean();
    try r.key("quest_fail_retry_count", base);
    run.quest_fail_retry_count = try r.intBetween(0, std.math.maxInt(i32));
    try r.key("detail_preset", base);
    run.detail_preset = try r.intBetween(1, 5);
    try r.key("violence_disabled", base);
    run.violence_disabled = try r.intBetween(0, std.math.maxInt(u8));

    try r.key("status", base);
    const status_base = try r.map(&status_keys);
    try r.key("quest_unlock_index", status_base);
    run.status.quest_unlock_index = try r.intIn(i32);
    try r.key("quest_unlock_index_full", status_base);
    run.status.quest_unlock_index_full = try r.intIn(i32);
    try r.key("weapon_usage_counts", status_base);
    try r.arrayOf(weapon_usage_count);
    const counts_base = r.path_len;
    for (&run.status.weapon_usage_counts, 0..) |*count, index| {
        r.at("[{d}]", counts_base, .{index});
        count.* = try r.intIn(u32);
    }

    try r.key("typo_dictionary_words", base);
    run.typo_dictionary_words = try readStrings(isTypoDictionaryWord, " must be 1..15 printable ASCII characters", r, max_typo_dictionary_words);
    try r.key("typo_highscore_names", base);
    run.typo_highscore_names = try readStrings(isTypoHighscoreName, " must be 1..31 ASCII letters or '.'", r, max_typo_highscore_names);
    return run;
}

fn readStrings(
    comptime valid: fn ([]const u8) bool,
    comptime invalid_detail: []const u8,
    r: *Reader,
    max_count: usize,
) DecodeError![]const []const u8 {
    const count = try r.array(1);
    if (count > max_count) return r.failAt(" has {d} entries, expected at most {d}", .{ count, max_count });
    const base = r.path_len;
    const items = try r.arena.alloc([]const u8, count);
    for (items, 0..) |*item, index| {
        r.at("[{d}]", base, .{index});
        item.* = try r.string();
        if (!valid(item.*)) return r.failAt(invalid_detail, .{});
    }
    return items;
}

fn readResult(r: *Reader, run: RunSpec) DecodeError!RunResult {
    const base = try r.map(&result_keys);
    var result: RunResult = undefined;

    try r.key("outcome", base);
    const outcome = try r.string();
    result.outcome = std.meta.stringToEnum(RunOutcome, outcome) orelse
        return r.failAt(" '{s}' is not a run outcome", .{outcome});
    if (!outcomeAllowed(run.game_mode, result.outcome)) {
        return r.failAt(" '{s}' is invalid for {s}", .{ outcome, @tagName(run.game_mode) });
    }
    try r.key("elapsed_ms", base);
    result.elapsed_ms = try r.int();
    try r.key("kills", base);
    result.kills = try r.int();
    try r.key("rng_state", base);
    result.rng_state = try r.intIn(u32);
    try r.key("pending_perks", base);
    result.pending_perks = try r.int();
    try r.key("quest_final_ms", base);
    result.quest_final_ms = if (try r.nil()) null else try r.int();
    if ((result.quest_final_ms != null) != (result.outcome == .quest_completed)) {
        return r.failAt(" must be set only for completed quests", .{});
    }
    try r.key("players", base);
    result.player_count = try r.array(1);
    if (result.player_count != run.player_count) {
        return r.failAt(" has {d} entries, expected {d}", .{ result.player_count, run.player_count });
    }
    const players_base = r.path_len;
    for (result.players_buffer[0..result.player_count], 0..) |*player, index| {
        r.at("[{d}]", players_base, .{index});
        const player_base = try r.map(&player_result_keys);
        try r.key("experience", player_base);
        player.experience = try r.int();
        try r.key("health", player_base);
        player.health = try r.float32();
        try r.key("shots_fired", player_base);
        player.shots_fired = try r.int();
        try r.key("shots_hit", player_base);
        player.shots_hit = try r.int();
        try r.key("most_used_weapon_id", player_base);
        const weapon_id = try r.int();
        player.most_used_weapon_id = std.enums.fromInt(game_ids.WeaponId, weapon_id) orelse
            return r.failAt(" {d} is not a weapon id", .{weapon_id});
    }
    return result;
}

fn readTick(r: *Reader, run: RunSpec, inputs: []PlayerInput, commands: *std.ArrayList(Command)) DecodeError!void {
    const base = r.path_len;
    try r.arrayOf(2);
    const input_count = try r.array(min_player_input_bytes);
    if (input_count != inputs.len) {
        return r.failAt(" has {d} player inputs, expected {d}", .{ input_count, inputs.len });
    }
    for (inputs, 0..) |*input, player_index| {
        r.at(".inputs[{d}]", base, .{player_index});
        const input_base = r.path_len;
        try r.arrayOf(5);
        var axes: [4]f32 = undefined;
        for (&axes, axis_names) |*axis, name| {
            r.at(".{s}", input_base, .{name});
            axis.* = try r.float32();
        }
        r.at(".flags", input_base, .{});
        const flags = try r.int();
        if (inputFlagsError(flags)) |detail| {
            return r.failAt(" {s}: {s}0x{x}", .{ detail, if (flags < 0) "-" else "", @abs(flags) });
        }
        input.* = .{ .move_x = axes[0], .move_y = axes[1], .aim_x = axes[2], .aim_y = axes[3], .flags = @intCast(flags) };
    }

    r.path_len = base;
    for (0..try r.array(min_command_bytes)) |command_index| {
        r.at(".commands[{d}]", base, .{command_index});
        try commands.append(r.arena, try readCommand(r, run));
    }
}

fn readCommand(r: *Reader, run: RunSpec) DecodeError!Command {
    // Peek the `type` tag first: it decides which keys the map must hold.
    const start = r.pos;
    const base = r.path_len;
    _ = try r.length(map_header);
    try r.key("type", base);
    const type_name = try r.string();
    r.path_len = base;
    const tag = std.meta.stringToEnum(std.meta.Tag(Command), type_name) orelse
        return r.failAt(" has unknown type '{s}'", .{type_name});
    r.pos = start;

    const command: Command = switch (tag) {
        inline .perk_menu_open, .typo_backspace, .typo_submit => |kind| blk: {
            _ = try r.map(&.{ "type", "player_index" });
            break :blk @unionInit(Command, @tagName(kind), .{ .player_index = try readCommandPlayer(r, run, base) });
        },
        .perk_pick => blk: {
            _ = try r.map(&.{ "type", "player_index", "choice_index" });
            const player_index = try readCommandPlayer(r, run, base);
            try r.key("choice_index", base);
            const choice_index = try r.int();
            if (choice_index < 0 or choice_index >= perk_choice_slot_count) {
                return r.failAt(" must be in 0..{d}", .{perk_choice_slot_count - 1});
            }
            break :blk .{ .perk_pick = .{ .player_index = player_index, .choice_index = @intCast(choice_index) } };
        },
        .typo_char => blk: {
            _ = try r.map(&.{ "type", "player_index", "ch" });
            const player_index = try readCommandPlayer(r, run, base);
            try r.key("ch", base);
            const ch = try r.string();
            if ((std.unicode.utf8CountCodepoints(ch) catch unreachable) != 1) {
                return r.failAt(" must be exactly one character", .{});
            }
            break :blk .{ .typo_char = .{ .player_index = player_index, .ch = ch } };
        },
    };
    r.path_len = base;
    if (command.isTypo() and run.game_mode != .typo) return r.failAt(" Typ-o commands require game_mode_id=TYPO", .{});
    return command;
}

fn readCommandPlayer(r: *Reader, run: RunSpec, base: usize) DecodeError!u8 {
    try r.key("type", base);
    _ = try r.string();
    try r.key("player_index", base);
    const player_index = try r.int();
    if (player_index < 0 or player_index >= run.player_count) {
        return r.failAt(" {d} is outside 0..{d}", .{ player_index, run.player_count - 1 });
    }
    return @intCast(player_index);
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

const Writer = struct {
    out: *std.Io.Writer,

    fn int(self: Writer, value: Int) std.Io.Writer.Error!void {
        const tag = intTag(value);
        try self.out.writeByte(tag);
        switch (tag) {
            0xcc => try self.out.writeInt(u8, @intCast(value), .big),
            0xcd => try self.out.writeInt(u16, @intCast(value), .big),
            0xce => try self.out.writeInt(u32, @intCast(value), .big),
            0xcf => try self.out.writeInt(u64, @intCast(value), .big),
            0xd0 => try self.out.writeInt(i8, @intCast(value), .big),
            0xd1 => try self.out.writeInt(i16, @intCast(value), .big),
            0xd2 => try self.out.writeInt(i32, @intCast(value), .big),
            0xd3 => try self.out.writeInt(i64, @intCast(value), .big),
            else => {},
        }
    }

    fn float(self: Writer, value: f32) std.Io.Writer.Error!void {
        try self.out.writeByte(0xcb);
        try self.out.writeInt(u64, @bitCast(@as(f64, value)), .big);
    }

    fn boolean(self: Writer, value: bool) std.Io.Writer.Error!void {
        try self.out.writeByte(if (value) 0xc3 else 0xc2);
    }

    fn nil(self: Writer) std.Io.Writer.Error!void {
        try self.out.writeByte(0xc0);
    }

    fn length(self: Writer, comptime header: LengthHeader, len: usize) std.Io.Writer.Error!void {
        const tag = header.tag(len);
        try self.out.writeByte(tag);
        if (header.tag8 != null and tag == header.tag8.?) {
            try self.out.writeInt(u8, @intCast(len), .big);
        } else if (tag == header.tag16) {
            try self.out.writeInt(u16, @intCast(len), .big);
        } else if (tag == header.tag32) {
            try self.out.writeInt(u32, @intCast(len), .big);
        }
    }

    fn string(self: Writer, value: []const u8) std.Io.Writer.Error!void {
        try self.length(string_header, value.len);
        try self.out.writeAll(value);
    }

    fn array(self: Writer, len: usize) std.Io.Writer.Error!void {
        try self.length(array_header, len);
    }

    fn map(self: Writer, len: usize) std.Io.Writer.Error!void {
        try self.length(map_header, len);
    }

    fn strings(self: Writer, values: []const []const u8) std.Io.Writer.Error!void {
        try self.array(values.len);
        for (values) |value| try self.string(value);
    }
};

/// Canonical msgpack encoding of `replay` (which must already be valid).
pub fn encodePayload(allocator: std.mem.Allocator, replay: Replay) ![]u8 {
    var buffer: std.Io.Writer.Allocating = .init(allocator);
    errdefer buffer.deinit();
    const w: Writer = .{ .out = &buffer.writer };
    const run = replay.run;

    try w.map(replay_keys.len);
    try w.string("format_version");
    try w.int(replay_format_version);
    try w.string("game_version");
    try w.string(replay.game_version);

    try w.string("run");
    try w.map(run_keys.len);
    try w.string("game_mode_id");
    try w.int(@intFromEnum(run.game_mode));
    try w.string("seed");
    try w.int(run.seed);
    try w.string("quest_level");
    if (run.quest_level) |level| {
        try w.map(2);
        try w.string("major");
        try w.int(level.major);
        try w.string("minor");
        try w.int(level.minor);
    } else try w.nil();
    try w.string("player_count");
    try w.int(run.player_count);
    try w.string("hardcore");
    try w.boolean(run.hardcore);
    try w.string("preserve_bugs");
    try w.boolean(run.preserve_bugs);
    try w.string("demo");
    try w.boolean(run.demo);
    try w.string("quest_fail_retry_count");
    try w.int(run.quest_fail_retry_count);
    try w.string("detail_preset");
    try w.int(run.detail_preset);
    try w.string("violence_disabled");
    try w.int(run.violence_disabled);
    try w.string("status");
    try w.map(status_keys.len);
    try w.string("quest_unlock_index");
    try w.int(run.status.quest_unlock_index);
    try w.string("quest_unlock_index_full");
    try w.int(run.status.quest_unlock_index_full);
    try w.string("weapon_usage_counts");
    try w.array(weapon_usage_count);
    for (run.status.weapon_usage_counts) |count| try w.int(count);
    try w.string("typo_dictionary_words");
    try w.strings(run.typo_dictionary_words);
    try w.string("typo_highscore_names");
    try w.strings(run.typo_highscore_names);

    try w.string("result");
    const result = replay.result;
    try w.map(result_keys.len);
    try w.string("outcome");
    try w.string(@tagName(result.outcome));
    try w.string("elapsed_ms");
    try w.int(result.elapsed_ms);
    try w.string("kills");
    try w.int(result.kills);
    try w.string("rng_state");
    try w.int(result.rng_state);
    try w.string("pending_perks");
    try w.int(result.pending_perks);
    try w.string("quest_final_ms");
    if (result.quest_final_ms) |value| try w.int(value) else try w.nil();
    try w.string("players");
    try w.array(result.player_count);
    for (result.players()) |player| {
        try w.map(player_result_keys.len);
        try w.string("experience");
        try w.int(player.experience);
        try w.string("health");
        try w.float(player.health);
        try w.string("shots_fired");
        try w.int(player.shots_fired);
        try w.string("shots_hit");
        try w.int(player.shots_hit);
        try w.string("most_used_weapon_id");
        try w.int(@intFromEnum(player.most_used_weapon_id));
    }

    try w.string("ticks");
    try w.array(replay.tickCount());
    for (0..replay.tickCount()) |tick_index| {
        try w.array(2);
        const inputs = replay.tickInputs(tick_index);
        try w.array(inputs.len);
        for (inputs) |input| {
            try w.array(5);
            for ([_]f32{ input.move_x, input.move_y, input.aim_x, input.aim_y }) |axis| try w.float(axis);
            try w.int(input.flags);
        }
        const commands = replay.tickCommands(tick_index);
        try w.array(commands.len);
        for (commands) |command| {
            switch (command) {
                .perk_pick => |pick| {
                    try w.map(3);
                    try w.string("type");
                    try w.string("perk_pick");
                    try w.string("player_index");
                    try w.int(pick.player_index);
                    try w.string("choice_index");
                    try w.int(pick.choice_index);
                },
                .typo_char => |typed| {
                    try w.map(3);
                    try w.string("type");
                    try w.string("typo_char");
                    try w.string("player_index");
                    try w.int(typed.player_index);
                    try w.string("ch");
                    try w.string(typed.ch);
                },
                inline .perk_menu_open, .typo_backspace, .typo_submit => |payload, tag| {
                    try w.map(2);
                    try w.string("type");
                    try w.string(@tagName(tag));
                    try w.string("player_index");
                    try w.int(payload.player_index);
                },
            }
        }
    }
    return buffer.toOwnedSlice();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn testReplay(game_mode: game_ids.GameModeId, inputs: []const PlayerInput, commands: []const Command, command_ends: []const u32) Replay {
    var result: RunResult = .{
        .outcome = .incomplete,
        .elapsed_ms = 16,
        .kills = 0,
        .rng_state = 0x1234,
        .pending_perks = 0,
        .quest_final_ms = null,
        .player_count = 1,
    };
    result.players_buffer[0] = .{
        .experience = 0,
        .health = 100.0,
        .shots_fired = 0,
        .shots_hit = 0,
        .most_used_weapon_id = .pistol,
    };
    return .{
        .game_version = "0.10.0",
        .run = .{
            .game_mode = game_mode,
            .seed = 0xBEEF,
            .quest_level = if (game_mode == .quests) .{ .major = 1, .minor = 1 } else null,
        },
        .result = result,
        .inputs = inputs,
        .commands = commands,
        .command_ends = command_ends,
    };
}

fn expectRoundTrip(replay: Replay) ![]u8 {
    const payload = try encodePayload(testing.allocator, replay);
    errdefer testing.allocator.free(payload);
    var diagnostic: Diagnostic = .{};
    const decoded = decodePayload(testing.allocator, payload, &diagnostic) catch |err| {
        std.debug.print("decode failed: {s}\n", .{diagnostic.message()});
        return err;
    };
    defer decoded.deinit(testing.allocator);
    const reencoded = try encodePayload(testing.allocator, decoded);
    defer testing.allocator.free(reencoded);
    try testing.expectEqualSlices(u8, payload, reencoded);
    return payload;
}

fn expectRejected(payload: []const u8, expected: []const u8) !void {
    var diagnostic: Diagnostic = .{};
    try testing.expectError(error.InvalidReplay, decodePayload(testing.allocator, payload, &diagnostic));
    try testing.expectEqualStrings(expected, diagnostic.message());
}

/// Replace the first occurrence of `needle` in `payload`.
fn patched(payload: []const u8, needle: []const u8, replacement: []const u8) ![]u8 {
    const index = std.mem.indexOf(u8, payload, needle) orelse return error.TestNeedleMissing;
    return std.mem.concat(testing.allocator, u8, &.{ payload[0..index], replacement, payload[index + needle.len ..] });
}

test "canonical payload round-trips byte for byte" {
    const inputs = [_]PlayerInput{ .{ .aim_x = 512.0, .aim_y = 512.0 }, .{ .move_x = -1.0, .flags = fire_down_flag | fire_pressed_flag } };
    const commands = [_]Command{
        .{ .typo_char = .{ .player_index = 0, .ch = "é" } },
        .{ .typo_submit = .{ .player_index = 0 } },
    };
    var replay = testReplay(.typo, &inputs, &commands, &.{ 1, 2 });
    replay.game_version = "0.10.0+g" ++ "a" ** 40;
    replay.run.typo_dictionary_words = &.{ "amber", "~ x" };
    replay.run.typo_highscore_names = &.{ "A." ** 15 ++ "B", "zed" };
    replay.result.elapsed_ms = -(1 << 40);
    replay.result.kills = std.math.maxInt(u64);
    const payload = try expectRoundTrip(replay);
    defer testing.allocator.free(payload);

    var diagnostic: Diagnostic = .{};
    const decoded = try decodePayload(testing.allocator, payload, &diagnostic);
    defer decoded.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 2), decoded.tickCount());
    try testing.expectEqual(@as(f32, -1.0), decoded.tickInputs(1)[0].move_x);
    try testing.expectEqualStrings("é", decoded.tickCommands(0)[0].typo_char.ch);
    try testing.expectEqual(@as(usize, 1), decoded.tickCommands(1).len);
    try testing.expectEqualStrings("amber", decoded.run.typo_dictionary_words[0]);
    try testing.expectEqual(@as(Int, std.math.maxInt(u64)), decoded.result.kills);
}

test "reader rejects non-canonical encodings of an otherwise valid replay" {
    const inputs = [_]PlayerInput{.{ .aim_x = 512.0, .aim_y = 512.0 }};
    const commands = [_]Command{.{ .perk_menu_open = .{ .player_index = 0 } }};
    const payload = try expectRoundTrip(testReplay(.survival, &inputs, &commands, &.{1}));
    defer testing.allocator.free(payload);

    const not_canonical = "replay payload is not canonically encoded";
    const cases = [_]struct { needle: []const u8, replacement: []const u8, message: []const u8 }{
        // Integer where a float belongs (health 100.0 -> 100).
        .{ .needle = "\xa6health\xcb\x40\x59\x00\x00\x00\x00\x00\x00", .replacement = "\xa6health\x64", .message = not_canonical },
        // float32 encoding of an exact f32 value.
        .{ .needle = "\xa6health\xcb\x40\x59\x00\x00\x00\x00\x00\x00", .replacement = "\xa6health\xca\x42\xc8\x00\x00", .message = not_canonical },
        // Non-minimal integer (player_count 1 as uint8, then as int8).
        .{ .needle = "\xacplayer_count\x01", .replacement = "\xacplayer_count\xcc\x01", .message = not_canonical },
        .{ .needle = "\xacplayer_count\x01", .replacement = "\xacplayer_count\xd0\x01", .message = not_canonical },
        // Non-minimal string header.
        .{ .needle = "\xa4seed", .replacement = "\xd9\x04seed", .message = not_canonical },
        // Reordered keys.
        .{ .needle = "\xa8hardcore\xc2\xadpreserve_bugs\xc2", .replacement = "\xadpreserve_bugs\xc2\xa8hardcore\xc2", .message = "run has key `preserve_bugs` where `hardcore` belongs" },
        // Duplicate key in place of another.
        .{ .needle = "\xa4demo\xc2", .replacement = "\xa8hardcore\xc2", .message = "run has key `hardcore` where `demo` belongs" },
        // Command map with an extra key.
        .{ .needle = "\x82\xa4type\xaeperk_menu_open\xacplayer_index\x00", .replacement = "\x83\xa4type\xaeperk_menu_open\xacplayer_index\x00\xa1x\x00", .message = "ticks[0].commands[0] must have exactly the keys type, player_index" },
    };
    for (cases) |case| {
        const bad = try patched(payload, case.needle, case.replacement);
        defer testing.allocator.free(bad);
        try expectRejected(bad, case.message);
    }

    // Missing key: drop `demo` from the run map.
    const without_demo = try patched(payload, "\xa4demo\xc2", "");
    defer testing.allocator.free(without_demo);
    without_demo[std.mem.indexOf(u8, without_demo, "\xacgame_mode_id").? - 1] = 0x8c;
    try expectRejected(without_demo, "run must have exactly the keys game_mode_id, seed, quest_level, player_count, hardcore, preserve_bugs, demo, quest_fail_retry_count, detail_preset, violence_disabled, status, typo_dictionary_words, typo_highscore_names");

    const trailing = try std.mem.concat(testing.allocator, u8, &.{ payload, "\xc0" });
    defer testing.allocator.free(trailing);
    try expectRejected(trailing, "invalid replay payload: trailing bytes after the replay");
}

test "reader applies the replay validation rules" {
    const inputs = [_]PlayerInput{.{ .aim_x = 512.0, .aim_y = 512.0 }};
    const commands = [_]Command{.{ .perk_pick = .{ .player_index = 0, .choice_index = 2 } }};
    const payload = try expectRoundTrip(testReplay(.survival, &inputs, &commands, &.{1}));
    defer testing.allocator.free(payload);

    const cases = [_]struct { needle: []const u8, replacement: []const u8, message: []const u8 }{
        .{ .needle = "\xaeformat_version\x14", .replacement = "\xaeformat_version\x13", .message = "unsupported replay format version: 19" },
        .{ .needle = "\xacgame_mode_id\x01", .replacement = "\xacgame_mode_id\x00", .message = "run.game_mode_id 0 is not a replayable mode" },
        .{ .needle = "\xacgame_mode_id\x01", .replacement = "\xacgame_mode_id\x03", .message = "run.quest_level must be set for quests and only for quests" },
        .{ .needle = "\xaddetail_preset\x05", .replacement = "\xaddetail_preset\x00", .message = "run.detail_preset must be in 1..5" },
        .{ .needle = "\xb1violence_disabled\x00", .replacement = "\xb1violence_disabled\xcd\x01\x00", .message = "run.violence_disabled must be in 0..255" },
        .{ .needle = "\xa7outcome\xaaincomplete", .replacement = "\xa7outcome\xb2tutorial_completed", .message = "result.outcome 'tutorial_completed' is invalid for survival" },
        .{ .needle = "\xaequest_final_ms\xc0", .replacement = "\xaequest_final_ms\x05", .message = "result.quest_final_ms must be set only for completed quests" },
        .{ .needle = "\xa6health\xcb\x40\x59\x00\x00\x00\x00\x00\x00", .replacement = "\xa6health\xcb\x3f\xb9\x99\x99\x99\x99\x99\x9a", .message = "result.players[0].health must be a canonical f32" },
        .{ .needle = "\xacchoice_index\x02", .replacement = "\xacchoice_index\x07", .message = "ticks[0].commands[0].choice_index must be in 0..6" },
        .{ .needle = "\xacplayer_index\x00\xac", .replacement = "\xacplayer_index\x01\xac", .message = "ticks[0].commands[0].player_index 1 is outside 0..0" },
        .{ .needle = "\xa9perk_pick", .replacement = "\xacnetwork_ping", .message = "ticks[0].commands[0] has unknown type 'network_ping'" },
    };
    for (cases) |case| {
        const bad = try patched(payload, case.needle, case.replacement);
        defer testing.allocator.free(bad);
        try expectRejected(bad, case.message);
    }
}

test "reader rejects Typ-o commands outside Typ-o and bad flags and inputs" {
    const inputs = [_]PlayerInput{.{ .aim_x = 512.0, .aim_y = 512.0 }};
    const commands = [_]Command{.{ .typo_backspace = .{ .player_index = 0 } }};
    const payload = try expectRoundTrip(testReplay(.typo, &inputs, &commands, &.{1}));
    defer testing.allocator.free(payload);

    const survival = try patched(payload, "\xacgame_mode_id\x04", "\xacgame_mode_id\x01");
    defer testing.allocator.free(survival);
    try expectRejected(survival, "ticks[0].commands[0] Typ-o commands require game_mode_id=TYPO");

    // Flags word 0x10 sets a movement key without MOVE_KEYS_PRESENT.
    const flags = try patched(payload, "\x00\x00\x00\x00\x00\x00\x00\x00\xcb\x40\x80\x00\x00\x00\x00\x00\x00\xcb\x40\x80\x00\x00\x00\x00\x00\x00\x00", "\x00\x00\x00\x00\x00\x00\x00\x00\xcb\x40\x80\x00\x00\x00\x00\x00\x00\xcb\x40\x80\x00\x00\x00\x00\x00\x00\x10");
    defer testing.allocator.free(flags);
    try expectRejected(flags, "ticks[0].inputs[0].flags set movement-key values without MOVE_KEYS_PRESENT: 0x10");

    // An empty input list for a one-player run.
    const start = std.mem.indexOf(u8, payload, "\xa5ticks\x91\x92\x91").? + 8;
    const no_inputs = try std.mem.concat(testing.allocator, u8, &.{ payload[0..start], "\x90", payload[start + 1 + 1 + 4 * 9 + 1 ..] });
    defer testing.allocator.free(no_inputs);
    try expectRejected(no_inputs, "ticks[0] has 0 player inputs, expected 1");
}

test "Typ-o name sources must be capped plain ASCII" {
    const inputs = [_]PlayerInput{.{}};
    const base_replay = testReplay(.typo, &inputs, &.{}, &.{0});
    var long_list: [max_typo_highscore_names + 1][]const u8 = undefined;
    @memset(&long_list, "Name");
    const cases = [_]struct { words: []const []const u8, names: []const []const u8, message: []const u8 }{
        .{ .words = &.{ "ok", "x" ** 16 }, .names = &.{}, .message = "run.typo_dictionary_words[1] must be 1..15 printable ASCII characters" },
        .{ .words = &.{""}, .names = &.{}, .message = "run.typo_dictionary_words[0] must be 1..15 printable ASCII characters" },
        .{ .words = &.{"tab\t"}, .names = &.{}, .message = "run.typo_dictionary_words[0] must be 1..15 printable ASCII characters" },
        .{ .words = &.{}, .names = &.{"A" ** 32}, .message = "run.typo_highscore_names[0] must be 1..31 ASCII letters or '.'" },
        .{ .words = &.{}, .names = &.{ "Ok", "no space" }, .message = "run.typo_highscore_names[1] must be 1..31 ASCII letters or '.'" },
        .{ .words = &.{}, .names = &long_list, .message = "run.typo_highscore_names has 513 entries, expected at most 512" },
    };
    for (cases) |case| {
        var replay = base_replay;
        replay.run.typo_dictionary_words = case.words;
        replay.run.typo_highscore_names = case.names;
        const payload = try encodePayload(testing.allocator, replay);
        defer testing.allocator.free(payload);
        try expectRejected(payload, case.message);
    }
}

test "declared lengths are bounded by the bytes left before allocating" {
    const inputs = [_]PlayerInput{.{}};
    const payload = try expectRoundTrip(testReplay(.survival, &inputs, &.{}, &.{0}));
    defer testing.allocator.free(payload);
    const index = std.mem.indexOf(u8, payload, "\xa5ticks\x91").? + 6;
    const bomb = try std.mem.concat(testing.allocator, u8, &.{ payload[0..index], "\xdd\xff\xff\xff\xff", payload[index + 1 ..] });
    defer testing.allocator.free(bomb);
    try expectRejected(bomb, "invalid replay payload: truncated msgpack data");
}

test "zstd file envelope rejects trailing bytes and concatenated frames" {
    const allocator = testing.allocator;
    const raw = "canonical payload bytes";
    const frame = try wrapZstdFilePayload(allocator, raw);
    defer allocator.free(frame);
    const inflated = try inflateZstdFilePayload(allocator, frame, max_replay_payload_bytes);
    defer allocator.free(inflated);
    try testing.expectEqualSlices(u8, raw, inflated);
    try testing.expectError(error.InvalidZstdPayload, inflateZstdFilePayload(allocator, raw, max_replay_payload_bytes));

    const with_trailing_byte = try std.mem.concat(allocator, u8, &.{ frame, &.{0} });
    defer allocator.free(with_trailing_byte);
    try testing.expectError(
        error.InvalidZstdPayload,
        inflateZstdFilePayload(allocator, with_trailing_byte, max_replay_payload_bytes),
    );

    const concatenated_frames = try std.mem.concat(allocator, u8, &.{ frame, frame });
    defer allocator.free(concatenated_frames);
    try testing.expectError(
        error.InvalidZstdPayload,
        inflateZstdFilePayload(allocator, concatenated_frames, max_replay_payload_bytes),
    );

    const checksum_frame = try allocator.alloc(u8, frame.len + @sizeOf(u32));
    defer allocator.free(checksum_frame);
    @memcpy(checksum_frame[0..frame.len], frame);
    checksum_frame[zstd_magic.len] |= 0b0000_0100;
    const checksum: u32 = @truncate(std.hash.XxHash64.hash(0, raw));
    std.mem.writeInt(u32, checksum_frame[frame.len..][0..@sizeOf(u32)], checksum, .little);

    const checksum_inflated = try inflateZstdFilePayload(allocator, checksum_frame, max_replay_payload_bytes);
    defer allocator.free(checksum_inflated);
    try testing.expectEqualSlices(u8, raw, checksum_inflated);

    checksum_frame[checksum_frame.len - 1] ^= 0x80;
    try testing.expectError(
        error.InvalidZstdPayload,
        inflateZstdFilePayload(allocator, checksum_frame, max_replay_payload_bytes),
    );

    var diagnostic: Diagnostic = .{};
    try testing.expectError(error.InvalidReplay, inflateReplayFile(allocator, raw, &diagnostic));
    try testing.expectEqualStrings("replay must use the zstd envelope", diagnostic.message());

    // Window descriptor 0x78: 2^25 bytes (32 MiB).
    const wide_window = [_]u8{ 0x28, 0xB5, 0x2F, 0xFD, 0x00, 0x78, 0x01, 0x00, 0x00 };
    try testing.expectError(error.InvalidReplay, inflateReplayFile(allocator, &wide_window, &diagnostic));
    try testing.expectEqualStrings("replay zstd frame window exceeds 8 MiB", diagnostic.message());
}

test "single-frame file inflater handles empty and multi-block payloads within the size ceiling" {
    const allocator = testing.allocator;

    const empty_frame = try wrapZstdFilePayload(allocator, &.{});
    defer allocator.free(empty_frame);
    const empty = try inflateZstdFilePayload(allocator, empty_frame, 0);
    defer allocator.free(empty);
    try testing.expectEqual(@as(usize, 0), empty.len);

    const raw = try allocator.alloc(u8, 128 * 1024 + 17);
    defer allocator.free(raw);
    for (raw, 0..) |*byte, index| byte.* = @truncate(index);
    const frame = try wrapZstdFilePayload(allocator, raw);
    defer allocator.free(frame);
    const inflated = try inflateZstdFilePayload(allocator, frame, raw.len);
    defer allocator.free(inflated);
    try testing.expectEqualSlices(u8, raw, inflated);
    try testing.expectError(error.PayloadTooLarge, inflateZstdFilePayload(allocator, frame, raw.len - 1));
    try testing.expectError(error.PayloadTooLarge, inflateZstdPayload(allocator, frame, raw.len - 1));
}

test "unpack input flags decodes packed fields" {
    const packed_flags: u32 = fire_down_flag |
        reload_pressed_flag |
        reload_down_flag |
        fire_bullets_key_down_flag |
        move_keys_present_flag |
        move_forward_flag |
        turn_right_flag |
        move_mode_present_flag |
        (@as(u32, 2) << move_mode_shift) |
        aim_scheme_present_flag |
        (aim_scheme_mask << aim_scheme_shift);
    const flags = unpackInputFlags(packed_flags);
    try testing.expect(flags.fire_down);
    try testing.expect(!flags.fire_pressed);
    try testing.expect(flags.reload_pressed);
    try testing.expect(flags.reload_down);
    try testing.expect(flags.fire_bullets_key_down);
    try testing.expectEqual(@as(?bool, true), flags.move_forward_pressed);
    try testing.expectEqual(@as(?bool, false), flags.move_backward_pressed);
    try testing.expectEqual(@as(?bool, true), flags.turn_right_pressed);
    try testing.expectEqual(@as(?i32, 2), flags.move_mode);
    try testing.expectEqual(@as(?i32, -1), flags.aim_scheme);
    try testing.expect(inputFlagsError(packed_flags) == null);
    try testing.expectEqualStrings("contain an invalid aim scheme", inputFlagsError(aim_scheme_present_flag | (6 << aim_scheme_shift)).?);
    try testing.expectEqualStrings("contain unsupported bits", inputFlagsError(-1).?);
}

test "result mismatches list differing fields in declared order" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const inputs = [_]PlayerInput{.{}};
    const recorded = testReplay(.survival, &inputs, &.{}, &.{0}).result;
    var simulated = recorded;
    try testing.expectEqual(@as(usize, 0), (try recorded.mismatches(arena.allocator(), &simulated)).len);
    simulated.kills = 3;
    simulated.players_buffer[0].health = 97.5;
    simulated.players_buffer[0].shots_hit = 1;
    const paths = try recorded.mismatches(arena.allocator(), &simulated);
    try testing.expectEqual(@as(usize, 3), paths.len);
    try testing.expectEqualStrings("kills", paths[0]);
    try testing.expectEqualStrings("players[0].health", paths[1]);
    try testing.expectEqualStrings("players[0].shots_hit", paths[2]);
    simulated.player_count = 2;
    try testing.expectEqualStrings("players", (try recorded.mismatches(arena.allocator(), &simulated))[1]);

    const json = try std.json.Stringify.valueAlloc(testing.allocator, simulated, .{});
    defer testing.allocator.free(json);
    try testing.expect(std.mem.startsWith(u8, json, "{\"outcome\":\"incomplete\",\"elapsed_ms\":16,\"kills\":3,"));
    try testing.expect(std.mem.indexOf(u8, json, "\"quest_final_ms\":null,\"players\":[{\"experience\":0,\"health\":97.5,") != null);
    simulated.players_buffer[0].health = 100.0;
    const integral = try std.json.Stringify.valueAlloc(testing.allocator, simulated, .{});
    defer testing.allocator.free(integral);
    try testing.expect(std.mem.indexOf(u8, integral, "\"health\":100.0,") != null);
}
