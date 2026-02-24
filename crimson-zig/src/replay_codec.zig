const std = @import("std");

pub const replay_format_version: i32 = 4;
pub const gzip_magic = [_]u8{ 0x1f, 0x8b };

pub const max_replay_payload_bytes: usize = 64 * 1024 * 1024;

const terrain_density_base: i64 = 800;
const terrain_density_overlay: i64 = 0x23;
const terrain_density_detail: i64 = 0x0F;
const terrain_density_shift: u6 = 19;
const terrain_rand_draws_per_stamp: i64 = 3;

const crt_rand_mult: u32 = 214_013;
const crt_rand_inc: u32 = 2_531_011;

pub const ReplayCodecError = error{
    UnexpectedEof,
    InvalidMsgpack,
    InvalidType,
    InvalidHeaderValue,
    MissingHeader,
    MissingInputs,
    MissingHeaderField,
    UnsupportedReplayFormatVersion,
    UnsupportedInputShape,
    UnsupportedEventShape,
    UnsupportedEventKind,
    UnsupportedBootstrapKind,
    BootstrapSeedMismatch,
    InvalidGzipPayload,
    PayloadTooLarge,
};

pub const ReplayStatus = struct {
    quest_unlock_index: i32 = 0,
    quest_unlock_index_full: i32 = 0,
};

pub const ReplayHeader = struct {
    game_mode_id: i32,
    seed: u32,
    replay_format_version: i32,
    quest_level: []const u8,
    bootstrap_kind: []const u8,
    bootstrap_seed: u32,
    game_version: []const u8,
    tick_rate: i32,
    difficulty_level: i32,
    hardcore: bool,
    preserve_bugs: bool,
    detail_preset: i32,
    fx_toggle: i32,
    world_size: f32,
    player_count: i32,
    status: ReplayStatus,
    input_quantization: []const u8,
};

pub const ReplayEventSummary = struct {
    total_count: usize = 0,
    perk_menu_open_count: usize = 0,
    perk_pick_count: usize = 0,
};

pub const ReplaySummary = struct {
    header: ReplayHeader,
    tick_count: usize,
    events: ReplayEventSummary,
};

const TerrainRule = struct {
    threshold: i32,
};

const terrain_unlock_rules = [_]TerrainRule{
    .{ .threshold = 0x28 },
    .{ .threshold = 0x1E },
    .{ .threshold = 0x14 },
};

const MsgpackReader = struct {
    bytes: []const u8,
    pos: usize = 0,

    fn init(bytes: []const u8) MsgpackReader {
        return .{ .bytes = bytes, .pos = 0 };
    }

    fn readByte(self: *MsgpackReader) ReplayCodecError!u8 {
        if (self.pos >= self.bytes.len) return error.UnexpectedEof;
        const value = self.bytes[self.pos];
        self.pos += 1;
        return value;
    }

    fn advance(self: *MsgpackReader, count: usize) ReplayCodecError![]const u8 {
        if (self.pos + count > self.bytes.len) return error.UnexpectedEof;
        const out = self.bytes[self.pos .. self.pos + count];
        self.pos += count;
        return out;
    }

    fn readU8(self: *MsgpackReader) ReplayCodecError!u8 {
        return self.readByte();
    }

    fn readU16BE(self: *MsgpackReader) ReplayCodecError!u16 {
        const raw = try self.advance(2);
        return (@as(u16, raw[0]) << 8) | @as(u16, raw[1]);
    }

    fn readU32BE(self: *MsgpackReader) ReplayCodecError!u32 {
        const raw = try self.advance(4);
        return (@as(u32, raw[0]) << 24) |
            (@as(u32, raw[1]) << 16) |
            (@as(u32, raw[2]) << 8) |
            @as(u32, raw[3]);
    }

    fn readU64BE(self: *MsgpackReader) ReplayCodecError!u64 {
        const raw = try self.advance(8);
        return (@as(u64, raw[0]) << 56) |
            (@as(u64, raw[1]) << 48) |
            (@as(u64, raw[2]) << 40) |
            (@as(u64, raw[3]) << 32) |
            (@as(u64, raw[4]) << 24) |
            (@as(u64, raw[5]) << 16) |
            (@as(u64, raw[6]) << 8) |
            @as(u64, raw[7]);
    }

    fn readI8(self: *MsgpackReader) ReplayCodecError!i8 {
        const raw = try self.readU8();
        return @as(i8, @bitCast(raw));
    }

    fn readI16BE(self: *MsgpackReader) ReplayCodecError!i16 {
        const raw = try self.readU16BE();
        return @as(i16, @bitCast(raw));
    }

    fn readI32BE(self: *MsgpackReader) ReplayCodecError!i32 {
        const raw = try self.readU32BE();
        return @as(i32, @bitCast(raw));
    }

    fn readI64BE(self: *MsgpackReader) ReplayCodecError!i64 {
        const raw = try self.readU64BE();
        return @as(i64, @bitCast(raw));
    }

    fn readMapLen(self: *MsgpackReader) ReplayCodecError!usize {
        const tag = try self.readByte();
        return self.readMapLenFromTag(tag);
    }

    fn readMapLenFromTag(self: *MsgpackReader, tag: u8) ReplayCodecError!usize {
        if (tag >= 0x80 and tag <= 0x8f) {
            return @intCast(tag & 0x0f);
        }
        return switch (tag) {
            0xde => @intCast(try self.readU16BE()),
            0xdf => @intCast(try self.readU32BE()),
            else => error.InvalidType,
        };
    }

    fn readArrayLen(self: *MsgpackReader) ReplayCodecError!usize {
        const tag = try self.readByte();
        return self.readArrayLenFromTag(tag);
    }

    fn readArrayLenFromTag(self: *MsgpackReader, tag: u8) ReplayCodecError!usize {
        if (tag >= 0x90 and tag <= 0x9f) {
            return @intCast(tag & 0x0f);
        }
        return switch (tag) {
            0xdc => @intCast(try self.readU16BE()),
            0xdd => @intCast(try self.readU32BE()),
            else => error.InvalidType,
        };
    }

    fn readString(self: *MsgpackReader) ReplayCodecError![]const u8 {
        const tag = try self.readByte();
        return self.readStringFromTag(tag);
    }

    fn readStringFromTag(self: *MsgpackReader, tag: u8) ReplayCodecError![]const u8 {
        var len: usize = 0;
        if (tag >= 0xa0 and tag <= 0xbf) {
            len = @intCast(tag & 0x1f);
        } else {
            len = switch (tag) {
                0xd9 => @intCast(try self.readU8()),
                0xda => @intCast(try self.readU16BE()),
                0xdb => @intCast(try self.readU32BE()),
                else => return error.InvalidType,
            };
        }
        return self.advance(len);
    }

    fn readBool(self: *MsgpackReader) ReplayCodecError!bool {
        const tag = try self.readByte();
        return switch (tag) {
            0xc2 => false,
            0xc3 => true,
            else => error.InvalidType,
        };
    }

    fn readInt(self: *MsgpackReader) ReplayCodecError!i64 {
        const tag = try self.readByte();
        return self.readIntFromTag(tag);
    }

    fn readIntFromTag(self: *MsgpackReader, tag: u8) ReplayCodecError!i64 {
        if (tag <= 0x7f) {
            return @intCast(tag);
        }
        if (tag >= 0xe0) {
            return @as(i64, @as(i8, @bitCast(tag)));
        }
        return switch (tag) {
            0xcc => @intCast(try self.readU8()),
            0xcd => @intCast(try self.readU16BE()),
            0xce => @intCast(try self.readU32BE()),
            0xcf => blk: {
                const value = try self.readU64BE();
                if (value > std.math.maxInt(i64)) return error.InvalidType;
                break :blk @intCast(value);
            },
            0xd0 => @intCast(try self.readI8()),
            0xd1 => @intCast(try self.readI16BE()),
            0xd2 => @intCast(try self.readI32BE()),
            0xd3 => try self.readI64BE(),
            else => error.InvalidType,
        };
    }

    fn readNumberF64(self: *MsgpackReader) ReplayCodecError!f64 {
        const tag = try self.readByte();
        return switch (tag) {
            0xca => blk: {
                const bits = try self.readU32BE();
                const value: f32 = @bitCast(bits);
                break :blk @as(f64, value);
            },
            0xcb => blk: {
                const bits = try self.readU64BE();
                const value: f64 = @bitCast(bits);
                break :blk value;
            },
            else => blk: {
                const value = try self.readIntFromTag(tag);
                break :blk @floatFromInt(value);
            },
        };
    }

    fn skipValue(self: *MsgpackReader) ReplayCodecError!void {
        const tag = try self.readByte();
        return self.skipValueFromTag(tag);
    }

    fn skipValueFromTag(self: *MsgpackReader, tag: u8) ReplayCodecError!void {
        if (tag <= 0x7f or tag >= 0xe0) {
            return;
        }
        if (tag >= 0xa0 and tag <= 0xbf) {
            const len: usize = @intCast(tag & 0x1f);
            _ = try self.advance(len);
            return;
        }
        if (tag >= 0x90 and tag <= 0x9f) {
            const len: usize = @intCast(tag & 0x0f);
            for (0..len) |_| try self.skipValue();
            return;
        }
        if (tag >= 0x80 and tag <= 0x8f) {
            const len: usize = @intCast(tag & 0x0f);
            for (0..len) |_| {
                try self.skipValue();
                try self.skipValue();
            }
            return;
        }

        switch (tag) {
            0xc0, 0xc2, 0xc3 => return,
            0xc4 => {
                const len = try self.readU8();
                _ = try self.advance(@intCast(len));
            },
            0xc5 => {
                const len = try self.readU16BE();
                _ = try self.advance(@intCast(len));
            },
            0xc6 => {
                const len = try self.readU32BE();
                _ = try self.advance(@intCast(len));
            },
            0xc7 => {
                const len = try self.readU8();
                _ = try self.readByte(); // ext type
                _ = try self.advance(@intCast(len));
            },
            0xc8 => {
                const len = try self.readU16BE();
                _ = try self.readByte();
                _ = try self.advance(@intCast(len));
            },
            0xc9 => {
                const len = try self.readU32BE();
                _ = try self.readByte();
                _ = try self.advance(@intCast(len));
            },
            0xca => _ = try self.advance(4),
            0xcb => _ = try self.advance(8),
            0xcc, 0xd0 => _ = try self.advance(1),
            0xcd, 0xd1 => _ = try self.advance(2),
            0xce, 0xd2 => _ = try self.advance(4),
            0xcf, 0xd3 => _ = try self.advance(8),
            0xd4 => {
                _ = try self.readByte();
                _ = try self.advance(1);
            },
            0xd5 => {
                _ = try self.readByte();
                _ = try self.advance(2);
            },
            0xd6 => {
                _ = try self.readByte();
                _ = try self.advance(4);
            },
            0xd7 => {
                _ = try self.readByte();
                _ = try self.advance(8);
            },
            0xd8 => {
                _ = try self.readByte();
                _ = try self.advance(16);
            },
            0xd9 => {
                const len = try self.readU8();
                _ = try self.advance(@intCast(len));
            },
            0xda => {
                const len = try self.readU16BE();
                _ = try self.advance(@intCast(len));
            },
            0xdb => {
                const len = try self.readU32BE();
                _ = try self.advance(@intCast(len));
            },
            0xdc => {
                const len = try self.readU16BE();
                for (0..@as(usize, @intCast(len))) |_| try self.skipValue();
            },
            0xdd => {
                const len = try self.readU32BE();
                for (0..@as(usize, @intCast(len))) |_| try self.skipValue();
            },
            0xde => {
                const len = try self.readU16BE();
                for (0..@as(usize, @intCast(len))) |_| {
                    try self.skipValue();
                    try self.skipValue();
                }
            },
            0xdf => {
                const len = try self.readU32BE();
                for (0..@as(usize, @intCast(len))) |_| {
                    try self.skipValue();
                    try self.skipValue();
                }
            },
            else => return error.InvalidMsgpack,
        }
    }
};

const Crand = struct {
    state: u32 = 0,

    fn srand(self: *Crand, seed: u32) void {
        self.state = seed;
    }

    fn rand(self: *Crand) u32 {
        self.state = self.state *% crt_rand_mult +% crt_rand_inc;
        return (self.state >> 16) & 0x7fff;
    }
};

pub fn isGzipPayload(bytes: []const u8) bool {
    if (bytes.len < gzip_magic.len) return false;
    return std.mem.eql(u8, bytes[0..gzip_magic.len], gzip_magic[0..]);
}

pub fn inflateGzipPayload(
    allocator: std.mem.Allocator,
    compressed: []const u8,
    max_output_bytes: usize,
) ReplayCodecError![]u8 {
    var input: std.Io.Reader = .fixed(compressed);
    var window: [std.compress.flate.max_window_len]u8 = undefined;
    var decompress: std.compress.flate.Decompress = .init(&input, .gzip, &window);

    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);

    var chunk: [8192]u8 = undefined;
    var total: usize = 0;
    while (true) {
        const n = decompress.reader.readSliceShort(&chunk) catch return error.InvalidGzipPayload;
        if (n == 0) break;
        total += n;
        if (total > max_output_bytes) return error.PayloadTooLarge;
        out.appendSlice(allocator, chunk[0..n]) catch return error.PayloadTooLarge;
        if (n < chunk.len) break;
    }

    return out.toOwnedSlice(allocator) catch return error.PayloadTooLarge;
}

pub fn parseReplaySummary(payload: []const u8) ReplayCodecError!ReplaySummary {
    var reader = MsgpackReader.init(payload);
    const top_fields = try reader.readMapLen();

    var header: ?ReplayHeader = null;
    var tick_count: ?usize = null;
    var events = ReplayEventSummary{};

    for (0..top_fields) |_| {
        const key = try reader.readString();
        if (std.mem.eql(u8, key, "header")) {
            header = try parseHeader(&reader);
            continue;
        }
        if (std.mem.eql(u8, key, "inputs")) {
            const expected_players = if (header) |value| value.player_count else null;
            tick_count = try parseInputs(&reader, expected_players);
            continue;
        }
        if (std.mem.eql(u8, key, "events")) {
            events = try parseEvents(&reader);
            continue;
        }
        try reader.skipValue();
    }

    const resolved_header = header orelse return error.MissingHeader;
    const resolved_ticks = tick_count orelse return error.MissingInputs;

    if (resolved_header.replay_format_version != replay_format_version) {
        return error.UnsupportedReplayFormatVersion;
    }

    return .{
        .header = resolved_header,
        .tick_count = resolved_ticks,
        .events = events,
    };
}

pub fn validateReplayBootstrap(header: ReplayHeader) ReplayCodecError!void {
    if (std.mem.eql(u8, header.bootstrap_kind, "none")) {
        return;
    }
    if (!std.mem.eql(u8, header.bootstrap_kind, "terrain_v1")) {
        return error.UnsupportedBootstrapKind;
    }

    var rng = Crand{};
    rng.srand(header.bootstrap_seed);
    _ = chooseTerrainIds(header.status.quest_unlock_index, &rng);

    const width_i32 = @max(@as(i32, 1), floatToPositiveI32(header.world_size));
    const height_i32 = width_i32;
    const draws = terrainStampingDraws(width_i32, height_i32, 3);
    for (0..@as(usize, @intCast(draws))) |_| {
        _ = rng.rand();
    }

    if (rng.state != header.seed) {
        return error.BootstrapSeedMismatch;
    }
}

fn chooseTerrainIds(quest_unlock_index: i32, rng: *Crand) i32 {
    _ = i32;
    for (terrain_unlock_rules) |rule| {
        if (quest_unlock_index >= rule.threshold and ((rng.rand() & 7) == 3)) {
            return 1;
        }
    }
    return 0;
}

fn terrainStampingDraws(width: i32, height: i32, layers: i32) i64 {
    const clamped_layers = std.math.clamp(layers, 0, 3);
    const area = @as(i64, width) * @as(i64, height);

    var stamps: i64 = 0;
    if (clamped_layers >= 1) {
        stamps += (area * terrain_density_base) >> terrain_density_shift;
    }
    if (clamped_layers >= 2) {
        stamps += (area * terrain_density_overlay) >> terrain_density_shift;
    }
    if (clamped_layers >= 3) {
        stamps += (area * terrain_density_detail) >> terrain_density_shift;
    }
    return stamps * terrain_rand_draws_per_stamp;
}

fn floatToPositiveI32(value: f32) i32 {
    if (!(std.math.isFinite(value))) return 1;
    const clamped = std.math.clamp(value, 0.0, @as(f32, @floatFromInt(std.math.maxInt(i32))));
    return @intFromFloat(clamped);
}

fn parseHeader(reader: *MsgpackReader) ReplayCodecError!ReplayHeader {
    const field_count = try reader.readMapLen();

    var header = ReplayHeader{
        .game_mode_id = 0,
        .seed = 0,
        .replay_format_version = 0,
        .quest_level = "",
        .bootstrap_kind = "none",
        .bootstrap_seed = 0,
        .game_version = "",
        .tick_rate = 60,
        .difficulty_level = 0,
        .hardcore = false,
        .preserve_bugs = false,
        .detail_preset = 5,
        .fx_toggle = 0,
        .world_size = 1024.0,
        .player_count = 1,
        .status = .{},
        .input_quantization = "raw",
    };

    var has_game_mode = false;
    var has_seed = false;
    var has_format = false;
    var has_tick_rate = false;
    var has_game_version = false;
    var has_player_count = false;

    for (0..field_count) |_| {
        const key = try reader.readString();
        if (std.mem.eql(u8, key, "game_mode_id")) {
            header.game_mode_id = try parseI32(try reader.readInt());
            has_game_mode = true;
            continue;
        }
        if (std.mem.eql(u8, key, "seed")) {
            header.seed = try parseU32(try reader.readInt());
            has_seed = true;
            continue;
        }
        if (std.mem.eql(u8, key, "replay_format_version")) {
            header.replay_format_version = try parseI32(try reader.readInt());
            has_format = true;
            continue;
        }
        if (std.mem.eql(u8, key, "quest_level")) {
            header.quest_level = try reader.readString();
            continue;
        }
        if (std.mem.eql(u8, key, "bootstrap_kind")) {
            header.bootstrap_kind = try reader.readString();
            continue;
        }
        if (std.mem.eql(u8, key, "bootstrap_seed")) {
            header.bootstrap_seed = try parseU32(try reader.readInt());
            continue;
        }
        if (std.mem.eql(u8, key, "game_version")) {
            header.game_version = try reader.readString();
            has_game_version = true;
            continue;
        }
        if (std.mem.eql(u8, key, "tick_rate")) {
            header.tick_rate = try parseI32(try reader.readInt());
            has_tick_rate = true;
            continue;
        }
        if (std.mem.eql(u8, key, "difficulty_level")) {
            header.difficulty_level = try parseI32(try reader.readInt());
            continue;
        }
        if (std.mem.eql(u8, key, "hardcore")) {
            header.hardcore = try reader.readBool();
            continue;
        }
        if (std.mem.eql(u8, key, "preserve_bugs")) {
            header.preserve_bugs = try reader.readBool();
            continue;
        }
        if (std.mem.eql(u8, key, "detail_preset")) {
            header.detail_preset = try parseI32(try reader.readInt());
            continue;
        }
        if (std.mem.eql(u8, key, "fx_toggle")) {
            header.fx_toggle = try parseI32(try reader.readInt());
            continue;
        }
        if (std.mem.eql(u8, key, "world_size")) {
            const world_size = try reader.readNumberF64();
            if (!std.math.isFinite(world_size) or world_size <= 0.0) return error.InvalidHeaderValue;
            header.world_size = @floatCast(world_size);
            continue;
        }
        if (std.mem.eql(u8, key, "player_count")) {
            header.player_count = try parseI32(try reader.readInt());
            has_player_count = true;
            continue;
        }
        if (std.mem.eql(u8, key, "status")) {
            header.status = try parseStatus(reader);
            continue;
        }
        if (std.mem.eql(u8, key, "input_quantization")) {
            header.input_quantization = try reader.readString();
            continue;
        }
        try reader.skipValue();
    }

    if (!has_game_mode or !has_seed or !has_format or !has_tick_rate or !has_game_version or !has_player_count) {
        return error.MissingHeaderField;
    }
    if (header.tick_rate <= 0 or header.player_count <= 0) {
        return error.InvalidHeaderValue;
    }

    return header;
}

fn parseStatus(reader: *MsgpackReader) ReplayCodecError!ReplayStatus {
    const field_count = try reader.readMapLen();
    var status = ReplayStatus{};

    for (0..field_count) |_| {
        const key = try reader.readString();
        if (std.mem.eql(u8, key, "quest_unlock_index")) {
            status.quest_unlock_index = try parseI32(try reader.readInt());
            continue;
        }
        if (std.mem.eql(u8, key, "quest_unlock_index_full")) {
            status.quest_unlock_index_full = try parseI32(try reader.readInt());
            continue;
        }
        if (std.mem.eql(u8, key, "weapon_usage_counts")) {
            // Present in header wire; currently not needed for native verify.
            try reader.skipValue();
            continue;
        }
        try reader.skipValue();
    }

    return status;
}

fn parseInputs(reader: *MsgpackReader, expected_players: ?i32) ReplayCodecError!usize {
    const tick_count = try reader.readArrayLen();
    var observed_players: ?usize = null;

    for (0..tick_count) |_| {
        const player_count = try reader.readArrayLen();
        if (expected_players) |expected| {
            if (expected < 0) return error.InvalidHeaderValue;
            if (player_count != @as(usize, @intCast(expected))) return error.UnsupportedInputShape;
        }
        if (observed_players == null) {
            observed_players = player_count;
        } else if (observed_players.? != player_count) {
            return error.UnsupportedInputShape;
        }

        for (0..player_count) |_| {
            const field_count = try reader.readArrayLen();
            if (field_count < 5) return error.UnsupportedInputShape;

            _ = try reader.readNumberF64();
            _ = try reader.readNumberF64();
            _ = try reader.readNumberF64();
            _ = try reader.readNumberF64();
            _ = try reader.readInt();

            if (field_count > 5) {
                for (0..field_count - 5) |_| {
                    try reader.skipValue();
                }
            }
        }
    }

    return tick_count;
}

fn parseEvents(reader: *MsgpackReader) ReplayCodecError!ReplayEventSummary {
    const event_count = try reader.readArrayLen();
    var summary = ReplayEventSummary{ .total_count = event_count };

    for (0..event_count) |_| {
        const field_count = try reader.readArrayLen();
        if (field_count < 2) return error.UnsupportedEventShape;

        const tick_index = try reader.readInt();
        if (tick_index < 0) return error.UnsupportedEventShape;

        const kind = try reader.readString();
        var consumed: usize = 2;

        var player_index: i64 = -1;
        if (field_count >= 3) {
            player_index = try reader.readInt();
            consumed += 1;
        }

        var choice_index: i64 = -1;
        if (field_count >= 4) {
            choice_index = try reader.readInt();
            consumed += 1;
        }

        if (field_count >= 5) {
            try reader.skipValue();
            consumed += 1;
        }

        if (consumed < field_count) {
            for (0..field_count - consumed) |_| {
                try reader.skipValue();
            }
        }

        if (std.mem.eql(u8, kind, "perk_pick")) {
            if (player_index < 0 or choice_index < 0) return error.UnsupportedEventShape;
            summary.perk_pick_count += 1;
            continue;
        }
        if (std.mem.eql(u8, kind, "perk_menu_open")) {
            if (player_index < 0) return error.UnsupportedEventShape;
            summary.perk_menu_open_count += 1;
            continue;
        }

        return error.UnsupportedEventKind;
    }

    return summary;
}

fn parseI32(value: i64) ReplayCodecError!i32 {
    if (value < std.math.minInt(i32) or value > std.math.maxInt(i32)) return error.InvalidHeaderValue;
    return @intCast(value);
}

fn parseU32(value: i64) ReplayCodecError!u32 {
    if (value < 0 or value > std.math.maxInt(u32)) return error.InvalidHeaderValue;
    return @intCast(value);
}

test "validate terrain bootstrap matches known latest survival header" {
    const header = ReplayHeader{
        .game_mode_id = 1,
        .seed = 1_764_335_965,
        .replay_format_version = replay_format_version,
        .quest_level = "",
        .bootstrap_kind = "terrain_v1",
        .bootstrap_seed = 702_897_212,
        .game_version = "0.7.0",
        .tick_rate = 60,
        .difficulty_level = 0,
        .hardcore = false,
        .preserve_bugs = false,
        .detail_preset = 5,
        .fx_toggle = 0,
        .world_size = 1024.0,
        .player_count = 1,
        .status = .{
            .quest_unlock_index = 49,
            .quest_unlock_index_full = 0,
        },
        .input_quantization = "raw",
    };

    try validateReplayBootstrap(header);
}

test "bootstrap mismatch is rejected" {
    const header = ReplayHeader{
        .game_mode_id = 1,
        .seed = 1234,
        .replay_format_version = replay_format_version,
        .quest_level = "",
        .bootstrap_kind = "terrain_v1",
        .bootstrap_seed = 1,
        .game_version = "0.7.0",
        .tick_rate = 60,
        .difficulty_level = 0,
        .hardcore = false,
        .preserve_bugs = false,
        .detail_preset = 5,
        .fx_toggle = 0,
        .world_size = 1024.0,
        .player_count = 1,
        .status = .{
            .quest_unlock_index = 0,
            .quest_unlock_index_full = 0,
        },
        .input_quantization = "raw",
    };

    try std.testing.expectError(error.BootstrapSeedMismatch, validateReplayBootstrap(header));
}
