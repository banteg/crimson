const std = @import("std");
const msgpack = @import("msgpack");

pub const replay_format_version: i32 = 4;
pub const weapon_usage_count: usize = 53;
pub const gzip_magic = [_]u8{ 0x1f, 0x8b };
pub const max_replay_payload_bytes: usize = 64 * 1024 * 1024;

pub const fire_down_flag: u32 = 1 << 0;
pub const fire_pressed_flag: u32 = 1 << 1;
pub const reload_pressed_flag: u32 = 1 << 2;
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
    UnsupportedInputQuantization,
    BootstrapSeedMismatch,
    InvalidGzipPayload,
    PayloadTooLarge,
    OutOfMemory,
};

pub const ReplayStatus = struct {
    quest_unlock_index: i32 = 0,
    quest_unlock_index_full: i32 = 0,
    weapon_usage_counts: [weapon_usage_count]u32 = [_]u32{0} ** weapon_usage_count,
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

pub const ReplayPlayerInput = struct {
    move_x: f64,
    move_y: f64,
    aim_x: f64,
    aim_y: f64,
    flags: u32,
};

pub const ReplayTickInputs = []ReplayPlayerInput;

pub const InputFlags = struct {
    fire_down: bool,
    fire_pressed: bool,
    reload_pressed: bool,
    move_mode: ?i32 = null,
    aim_scheme: ?i32 = null,
    move_forward_pressed: ?bool = null,
    move_backward_pressed: ?bool = null,
    turn_left_pressed: ?bool = null,
    turn_right_pressed: ?bool = null,
};

pub fn unpackInputFlags(flags: u32) InputFlags {
    var decoded = InputFlags{
        .fire_down = (flags & fire_down_flag) != 0,
        .fire_pressed = (flags & fire_pressed_flag) != 0,
        .reload_pressed = (flags & reload_pressed_flag) != 0,
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

pub const PerkPickEvent = struct {
    tick_index: usize,
    player_index: i32,
    choice_index: i32,
};

pub const PerkMenuOpenEvent = struct {
    tick_index: usize,
    player_index: i32,
};

pub const ReplayEvent = union(enum) {
    perk_pick: PerkPickEvent,
    perk_menu_open: PerkMenuOpenEvent,

    pub fn tickIndex(self: ReplayEvent) usize {
        return switch (self) {
            .perk_pick => |event| event.tick_index,
            .perk_menu_open => |event| event.tick_index,
        };
    }
};

pub const ReplayEventSummary = struct {
    total_count: usize = 0,
    perk_menu_open_count: usize = 0,
    perk_pick_count: usize = 0,
};

pub const Replay = struct {
    header: ReplayHeader,
    inputs: []ReplayTickInputs,
    events: []ReplayEvent,

    pub fn deinit(self: Replay, allocator: std.mem.Allocator) void {
        self.header.deinit(allocator);
        for (self.inputs) |tick| allocator.free(tick);
        allocator.free(self.inputs);
        allocator.free(self.events);
    }

    pub fn tickCount(self: Replay) usize {
        return self.inputs.len;
    }

    pub fn summarizeEvents(self: Replay) ReplayEventSummary {
        var summary = ReplayEventSummary{
            .total_count = self.events.len,
        };
        for (self.events) |event| {
            switch (event) {
                .perk_pick => summary.perk_pick_count += 1,
                .perk_menu_open => summary.perk_menu_open_count += 1,
            }
        }
        return summary;
    }
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
    move_x: f64,
    move_y: f64,
    aim_x: f64,
    aim_y: f64,
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

    try validateInputShape(wire.inputs, header.player_count);
    const events = try parseEventSummary(wire.events, wire.inputs.len);

    return .{
        .header = header,
        .tick_count = wire.inputs.len,
        .events = events,
    };
}

pub fn parseReplay(
    allocator: std.mem.Allocator,
    payload: []const u8,
) ReplayCodecError!Replay {
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

    try validateInputShape(wire.inputs, header.player_count);

    const inputs = try buildInputs(allocator, wire.inputs, header.input_quantization);
    errdefer freeInputs(allocator, inputs);

    const events = try buildEvents(allocator, wire.events, wire.inputs.len);
    errdefer allocator.free(events);

    return .{
        .header = header,
        .inputs = inputs,
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

fn parseEventSummary(
    wire_events: []const ReplayEventWire,
    input_len: usize,
) ReplayCodecError!ReplayEventSummary {
    var summary = ReplayEventSummary{
        .total_count = wire_events.len,
    };
    for (wire_events) |wire_event| {
        const event = try parseReplayEvent(wire_event, input_len);
        switch (event) {
            .perk_pick => summary.perk_pick_count += 1,
            .perk_menu_open => summary.perk_menu_open_count += 1,
        }
    }
    return summary;
}

fn buildInputs(
    allocator: std.mem.Allocator,
    wire_inputs: []const []const ReplayInputWire,
    input_quantization: []const u8,
) ReplayCodecError![]ReplayTickInputs {
    const out = allocator.alloc(ReplayTickInputs, wire_inputs.len) catch return error.OutOfMemory;
    var built: usize = 0;
    errdefer {
        for (0..built) |idx| allocator.free(out[idx]);
        allocator.free(out);
    }

    for (wire_inputs, 0..) |wire_tick, tick_idx| {
        const tick_inputs = allocator.alloc(ReplayPlayerInput, wire_tick.len) catch return error.OutOfMemory;
        for (wire_tick, 0..) |wire_input, player_idx| {
            tick_inputs[player_idx] = .{
                .move_x = try normalizeInputValue(wire_input.move_x, input_quantization),
                .move_y = try normalizeInputValue(wire_input.move_y, input_quantization),
                .aim_x = try normalizeInputValue(wire_input.aim_x, input_quantization),
                .aim_y = try normalizeInputValue(wire_input.aim_y, input_quantization),
                .flags = try parseInputFlagsValue(wire_input.flags),
            };
        }
        out[tick_idx] = tick_inputs;
        built += 1;
    }

    return out;
}

fn buildEvents(
    allocator: std.mem.Allocator,
    wire_events: []const ReplayEventWire,
    input_len: usize,
) ReplayCodecError![]ReplayEvent {
    const events = allocator.alloc(ReplayEvent, wire_events.len) catch return error.OutOfMemory;
    for (wire_events, 0..) |wire_event, idx| {
        events[idx] = try parseReplayEvent(wire_event, input_len);
    }
    return events;
}

fn freeInputs(allocator: std.mem.Allocator, inputs: []ReplayTickInputs) void {
    for (inputs) |tick| allocator.free(tick);
    allocator.free(inputs);
}

fn parseReplayEvent(
    wire_event: ReplayEventWire,
    input_len: usize,
) ReplayCodecError!ReplayEvent {
    if (wire_event.tick_index < 0) return error.UnsupportedEventShape;

    const tick_index: usize = @intCast(wire_event.tick_index);
    if (tick_index > input_len) return error.UnsupportedEventShape;

    if (std.mem.eql(u8, wire_event.kind, "perk_pick")) {
        if (wire_event.player_index < 0 or wire_event.choice_index < 0) {
            return error.UnsupportedEventShape;
        }
        if (wire_event.payload.len != 0) {
            return error.UnsupportedEventShape;
        }
        return .{
            .perk_pick = .{
                .tick_index = tick_index,
                .player_index = try parseEventI32(wire_event.player_index),
                .choice_index = try parseEventI32(wire_event.choice_index),
            },
        };
    }

    if (std.mem.eql(u8, wire_event.kind, "perk_menu_open")) {
        if (wire_event.player_index < 0) {
            return error.UnsupportedEventShape;
        }
        if (wire_event.payload.len != 0) {
            return error.UnsupportedEventShape;
        }
        return .{
            .perk_menu_open = .{
                .tick_index = tick_index,
                .player_index = try parseEventI32(wire_event.player_index),
            },
        };
    }

    return error.UnsupportedEventKind;
}

fn validateInputShape(
    wire_inputs: []const []const ReplayInputWire,
    player_count: i32,
) ReplayCodecError!void {
    const expected_players: usize = @intCast(player_count);
    for (wire_inputs) |tick| {
        if (tick.len == 0) return error.UnsupportedInputShape;
        if (tick.len != expected_players) return error.UnsupportedInputShape;
    }
}

fn buildHeader(
    allocator: std.mem.Allocator,
    wire: ReplayHeaderWire,
) ReplayCodecError!ReplayHeader {
    if (!std.math.isFinite(wire.world_size) or wire.world_size <= 0.0) {
        return error.InvalidHeaderValue;
    }
    if (!std.mem.eql(u8, wire.bootstrap_kind, "none") and !std.mem.eql(u8, wire.bootstrap_kind, "terrain_v1")) {
        return error.UnsupportedBootstrapKind;
    }
    if (!std.mem.eql(u8, wire.input_quantization, "raw") and !std.mem.eql(u8, wire.input_quantization, "f32")) {
        return error.UnsupportedInputQuantization;
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
    if (wire.status.weapon_usage_counts.len != weapon_usage_count) {
        return error.InvalidHeaderValue;
    }

    var usage_counts: [weapon_usage_count]u32 = [_]u32{0} ** weapon_usage_count;
    for (wire.status.weapon_usage_counts, 0..) |value, idx| {
        usage_counts[idx] = try parseU32(value);
    }

    return .{
        .game_mode_id = game_mode_id,
        .seed = seed,
        .replay_format_version = format_version,
        .quest_level = allocator.dupe(u8, wire.quest_level) catch return error.OutOfMemory,
        .bootstrap_kind = allocator.dupe(u8, wire.bootstrap_kind) catch return error.OutOfMemory,
        .bootstrap_seed = bootstrap_seed,
        .game_version = allocator.dupe(u8, wire.game_version) catch return error.OutOfMemory,
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
            .weapon_usage_counts = usage_counts,
        },
        .input_quantization = allocator.dupe(u8, wire.input_quantization) catch return error.OutOfMemory,
    };
}

fn normalizeInputValue(value: f64, input_quantization: []const u8) ReplayCodecError!f64 {
    if (std.mem.eql(u8, input_quantization, "raw")) {
        return value;
    }
    if (std.mem.eql(u8, input_quantization, "f32")) {
        const value_f32: f32 = @floatCast(value);
        return @floatCast(value_f32);
    }
    return error.UnsupportedInputQuantization;
}

fn parseInputFlagsValue(value: i64) ReplayCodecError!u32 {
    if (value < 0 or value > std.math.maxInt(u32)) return error.UnsupportedInputShape;
    return @intCast(value);
}

fn parseEventI32(value: i64) ReplayCodecError!i32 {
    if (value < std.math.minInt(i32) or value > std.math.maxInt(i32)) return error.UnsupportedEventShape;
    return @intCast(value);
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

test "unpack input flags decodes packed fields" {
    const packed_flags: u32 = fire_down_flag |
        reload_pressed_flag |
        move_keys_present_flag |
        move_forward_flag |
        turn_left_flag |
        move_mode_present_flag |
        (@as(u32, 3) << move_mode_shift) |
        aim_scheme_present_flag |
        (aim_scheme_mask << aim_scheme_shift);

    const decoded = unpackInputFlags(packed_flags);
    try std.testing.expect(decoded.fire_down);
    try std.testing.expect(!decoded.fire_pressed);
    try std.testing.expect(decoded.reload_pressed);
    try std.testing.expectEqual(@as(?i32, 3), decoded.move_mode);
    try std.testing.expectEqual(@as(?i32, -1), decoded.aim_scheme);
    try std.testing.expect(decoded.move_forward_pressed != null and decoded.move_forward_pressed.?);
    try std.testing.expect(decoded.move_backward_pressed != null and !decoded.move_backward_pressed.?);
    try std.testing.expect(decoded.turn_left_pressed != null and decoded.turn_left_pressed.?);
    try std.testing.expect(decoded.turn_right_pressed != null and !decoded.turn_right_pressed.?);
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
            .weapon_usage_counts = [_]u32{0} ** weapon_usage_count,
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
            .weapon_usage_counts = [_]u32{0} ** weapon_usage_count,
        },
        .input_quantization = try allocator.dupe(u8, "raw"),
    };
    defer header.deinit(allocator);

    try std.testing.expectError(error.BootstrapSeedMismatch, validateReplayBootstrap(header));
}
