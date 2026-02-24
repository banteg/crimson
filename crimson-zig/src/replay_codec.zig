const std = @import("std");
const msgpack = @import("msgpack");

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
    InvalidMsgpack,
    InvalidHeaderValue,
    MissingHeaderField,
    UnsupportedReplayFormatVersion,
    UnsupportedInputShape,
    UnsupportedEventShape,
    UnsupportedEventKind,
    UnsupportedBootstrapKind,
    BootstrapSeedMismatch,
    InvalidGzipPayload,
    PayloadTooLarge,
    OutOfMemory,
};

pub const ReplayStatus = struct {
    quest_unlock_index: i32 = 0,
    quest_unlock_index_full: i32 = 0,
};

pub const ReplayHeader = struct {
    game_mode_id: i32,
    seed: u32,
    replay_format_version: i32,
    quest_level: []u8,
    bootstrap_kind: []u8,
    bootstrap_seed: u32,
    game_version: []u8,
    tick_rate: i32,
    difficulty_level: i32,
    hardcore: bool,
    preserve_bugs: bool,
    detail_preset: i32,
    fx_toggle: i32,
    world_size: f32,
    player_count: i32,
    status: ReplayStatus,
    input_quantization: []u8,

    pub fn deinit(self: ReplayHeader, allocator: std.mem.Allocator) void {
        allocator.free(self.quest_level);
        allocator.free(self.bootstrap_kind);
        allocator.free(self.game_version);
        allocator.free(self.input_quantization);
    }
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

    pub fn deinit(self: ReplaySummary, allocator: std.mem.Allocator) void {
        self.header.deinit(allocator);
    }
};

const ReplayStatusWire = struct {
    quest_unlock_index: i64 = 0,
    quest_unlock_index_full: i64 = 0,
    weapon_usage_counts: []const i64 = &.{},
};

const ReplayHeaderWire = struct {
    game_mode_id: i64,
    seed: i64,
    replay_format_version: i64,
    quest_level: []const u8 = "",
    bootstrap_kind: []const u8 = "none",
    bootstrap_seed: i64 = 0,
    game_version: []const u8 = "",
    tick_rate: i64 = 60,
    difficulty_level: i64 = 0,
    hardcore: bool = false,
    preserve_bugs: bool = false,
    detail_preset: i64 = 5,
    fx_toggle: i64 = 0,
    world_size: f64 = 1024.0,
    player_count: i64 = 1,
    status: ReplayStatusWire = .{},
    input_quantization: []const u8 = "raw",
};

const ReplayInputWire = struct {
    move_x: f32,
    move_y: f32,
    aim_x: f32,
    aim_y: f32,
    flags: i64,

    pub fn msgpackFormat() msgpack.StructFormat {
        return .{ .as_array = .{} };
    }
};

const ReplayEventWire = struct {
    tick_index: i64,
    kind: []const u8,
    player_index: i64 = -1,
    choice_index: i64 = -1,
    payload: []const i64 = &.{},

    pub fn msgpackFormat() msgpack.StructFormat {
        return .{ .as_array = .{} };
    }
};

const ReplayWire = struct {
    header: ReplayHeaderWire,
    inputs: []const []const ReplayInputWire,
    events: []const ReplayEventWire = &.{},
};

const TerrainRule = struct {
    threshold: i32,
};

const terrain_unlock_rules = [_]TerrainRule{
    .{ .threshold = 0x28 },
    .{ .threshold = 0x1E },
    .{ .threshold = 0x14 },
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
        out.appendSlice(allocator, chunk[0..n]) catch return error.OutOfMemory;
        if (n < chunk.len) break;
    }

    return out.toOwnedSlice(allocator) catch return error.OutOfMemory;
}

pub fn parseReplaySummary(
    allocator: std.mem.Allocator,
    payload: []const u8,
) ReplayCodecError!ReplaySummary {
    var decoded = msgpack.decodeFromSlice(ReplayWire, allocator, payload) catch {
        return error.InvalidMsgpack;
    };
    defer decoded.deinit();

    const wire = decoded.value;
    const header = try buildHeader(allocator, wire.header);
    errdefer header.deinit(allocator);

    if (header.replay_format_version != replay_format_version) {
        return error.UnsupportedReplayFormatVersion;
    }

    var observed_players: ?usize = null;
    for (wire.inputs) |tick| {
        if (tick.len == 0) return error.UnsupportedInputShape;
        if (observed_players == null) {
            observed_players = tick.len;
        } else if (observed_players.? != tick.len) {
            return error.UnsupportedInputShape;
        }
        if (tick.len != @as(usize, @intCast(header.player_count))) {
            return error.UnsupportedInputShape;
        }
    }

    var events = ReplayEventSummary{
        .total_count = wire.events.len,
    };
    for (wire.events) |event| {
        if (event.tick_index < 0) return error.UnsupportedEventShape;
        if (std.mem.eql(u8, event.kind, "perk_pick")) {
            if (event.player_index < 0 or event.choice_index < 0) return error.UnsupportedEventShape;
            events.perk_pick_count += 1;
            continue;
        }
        if (std.mem.eql(u8, event.kind, "perk_menu_open")) {
            if (event.player_index < 0) return error.UnsupportedEventShape;
            events.perk_menu_open_count += 1;
            continue;
        }
        return error.UnsupportedEventKind;
    }

    return .{
        .header = header,
        .tick_count = wire.inputs.len,
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

fn buildHeader(
    allocator: std.mem.Allocator,
    wire: ReplayHeaderWire,
) ReplayCodecError!ReplayHeader {
    if (!std.math.isFinite(wire.world_size) or wire.world_size <= 0.0) {
        return error.InvalidHeaderValue;
    }

    const game_mode_id = try parseI32(wire.game_mode_id);
    const seed = try parseU32(wire.seed);
    const format_version = try parseI32(wire.replay_format_version);
    const bootstrap_seed = try parseU32(wire.bootstrap_seed);
    const tick_rate = try parseI32(wire.tick_rate);
    const difficulty_level = try parseI32(wire.difficulty_level);
    const detail_preset = try parseI32(wire.detail_preset);
    const fx_toggle = try parseI32(wire.fx_toggle);
    const player_count = try parseI32(wire.player_count);
    const quest_unlock_index = try parseI32(wire.status.quest_unlock_index);
    const quest_unlock_index_full = try parseI32(wire.status.quest_unlock_index_full);

    if (tick_rate <= 0 or player_count <= 0) {
        return error.InvalidHeaderValue;
    }
    if (wire.game_version.len == 0) {
        return error.MissingHeaderField;
    }

    return .{
        .game_mode_id = game_mode_id,
        .seed = seed,
        .replay_format_version = format_version,
        .quest_level = try allocator.dupe(u8, wire.quest_level),
        .bootstrap_kind = try allocator.dupe(u8, wire.bootstrap_kind),
        .bootstrap_seed = bootstrap_seed,
        .game_version = try allocator.dupe(u8, wire.game_version),
        .tick_rate = tick_rate,
        .difficulty_level = difficulty_level,
        .hardcore = wire.hardcore,
        .preserve_bugs = wire.preserve_bugs,
        .detail_preset = detail_preset,
        .fx_toggle = fx_toggle,
        .world_size = @floatCast(wire.world_size),
        .player_count = player_count,
        .status = .{
            .quest_unlock_index = quest_unlock_index,
            .quest_unlock_index_full = quest_unlock_index_full,
        },
        .input_quantization = try allocator.dupe(u8, wire.input_quantization),
    };
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
    if (!std.math.isFinite(value)) return 1;
    const clamped = std.math.clamp(value, 0.0, @as(f32, @floatFromInt(std.math.maxInt(i32))));
    return @intFromFloat(clamped);
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
    const allocator = std.testing.allocator;
    const header = ReplayHeader{
        .game_mode_id = 1,
        .seed = 1_764_335_965,
        .replay_format_version = replay_format_version,
        .quest_level = try allocator.dupe(u8, ""),
        .bootstrap_kind = try allocator.dupe(u8, "terrain_v1"),
        .bootstrap_seed = 702_897_212,
        .game_version = try allocator.dupe(u8, "0.7.0"),
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
        .input_quantization = try allocator.dupe(u8, "raw"),
    };
    defer header.deinit(allocator);

    try validateReplayBootstrap(header);
}

test "bootstrap mismatch is rejected" {
    const allocator = std.testing.allocator;
    const header = ReplayHeader{
        .game_mode_id = 1,
        .seed = 1234,
        .replay_format_version = replay_format_version,
        .quest_level = try allocator.dupe(u8, ""),
        .bootstrap_kind = try allocator.dupe(u8, "terrain_v1"),
        .bootstrap_seed = 1,
        .game_version = try allocator.dupe(u8, "0.7.0"),
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
        .input_quantization = try allocator.dupe(u8, "raw"),
    };
    defer header.deinit(allocator);

    try std.testing.expectError(error.BootstrapSeedMismatch, validateReplayBootstrap(header));
}
