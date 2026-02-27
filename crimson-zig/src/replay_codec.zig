const std = @import("std");
const msgpack = @import("msgpack");

pub const replay_format_version: i32 = 4;
pub const weapon_usage_count: usize = 53;
pub const max_players: usize = 4;
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
    move_x: f32,
    move_y: f32,
    aim_x: f32,
    aim_y: f32,
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

pub const max_capture_spawns_per_event: usize = 256;
pub const max_capture_added_head_rows_per_event: usize = 256;
pub const max_capture_state_transition_rows_per_event: usize = 64;
pub const max_capture_bootstrap_perk_pairs_per_player: usize = 96;

pub const CaptureBootstrapQuestSession = struct {
    spawn_timeline_ms: f32 = 0.0,
    no_creatures_timer_ms: f32 = 0.0,
    completion_transition_ms: f32 = -1.0,
};

pub const CaptureBootstrapPlayerPerkPair = struct {
    perk_id: i32 = 0,
    count: i32 = 0,
};

pub const CaptureBootstrapPlayerPerkCounts = struct {
    pair_count: usize = 0,
    pairs: [max_capture_bootstrap_perk_pairs_per_player]CaptureBootstrapPlayerPerkPair = [_]CaptureBootstrapPlayerPerkPair{
        .{},
    } ** max_capture_bootstrap_perk_pairs_per_player,
};

pub const CaptureBootstrapPlayer = struct {
    weapon_id: i32 = 1,
    pos_x: f32 = 0.0,
    pos_y: f32 = 0.0,
    health: f32 = 100.0,
    ammo: f32 = 0.0,
    experience: i32 = 0,
    level: i32 = 1,
    clip_size: ?i32 = null,
    reload_active: ?bool = null,
    reload_timer: ?f32 = null,
    reload_timer_max: ?f32 = null,
    shot_cooldown: ?f32 = null,
    spread_heat: ?f32 = null,
    aim_x: ?f32 = null,
    aim_y: ?f32 = null,
    aim_heading: ?f32 = null,
    alt_weapon_id: ?i32 = null,
    alt_clip_size: ?i32 = null,
    alt_ammo: ?f32 = null,
    alt_reload_active: ?bool = null,
    alt_reload_timer: ?f32 = null,
    alt_reload_timer_max: ?f32 = null,
    alt_shot_cooldown: ?f32 = null,
    shield_ms: ?i32 = null,
    fire_bullets_ms: ?i32 = null,
    speed_bonus_ms: ?i32 = null,
    hot_tempered_timer: ?f32 = null,
    man_bomb_timer: ?f32 = null,
    living_fortress_timer: ?f32 = null,
    fire_cough_timer: ?f32 = null,
};

pub const CaptureBootstrapEvent = struct {
    tick_index: usize,
    elapsed_ms: i32 = 0,
    score_xp: i32 = 0,
    perk_pending: i32 = 0,
    perk_pending_count: i32 = 0,
    perk_choices_dirty: bool = false,
    perk_choice_count: usize = 0,
    perk_choices: [7]i32 = [_]i32{0} ** 7,
    player_count: usize = 0,
    players: [max_players]CaptureBootstrapPlayer = [_]CaptureBootstrapPlayer{
        .{},
    } ** max_players,
    digital_move_enabled_by_player: [max_players]bool = [_]bool{false} ** max_players,
    player_perk_counts: [max_players]CaptureBootstrapPlayerPerkCounts = [_]CaptureBootstrapPlayerPerkCounts{
        .{},
    } ** max_players,
    weapon_power_up_ms: ?i32 = null,
    reflex_boost_ms: ?i32 = null,
    energizer_ms: ?i32 = null,
    double_experience_ms: ?i32 = null,
    freeze_ms: ?i32 = null,
    perk_interval_man_bomb: ?f32 = null,
    perk_interval_fire_cough: ?f32 = null,
    perk_interval_hot_tempered: ?f32 = null,
    quest_session: ?CaptureBootstrapQuestSession = null,
};

pub const CapturePerkApplyEvent = struct {
    tick_index: usize,
    perk_id: i32,
    outside_before: bool = false,
    pending_before: ?i32 = null,
    pending_after: ?i32 = null,
};

pub const CapturePerkPendingEvent = struct {
    tick_index: usize,
    perk_pending: i32,
};

pub const CaptureCreatureSpawnRow = struct {
    template_id: i32 = 0,
    pos_x: f32 = 0.0,
    pos_y: f32 = 0.0,
    heading: f32 = 0.0,
};

pub const CaptureCreatureAddedHeadRow = struct {
    index: i32 = -1,
    has_heading: bool = false,
    heading: f32 = 0.0,
    has_target_heading: bool = false,
    target_heading: f32 = 0.0,
    has_ai_mode: bool = false,
    ai_mode: i32 = 0,
    has_link_index: bool = false,
    link_index: i32 = 0,
    has_hp: bool = false,
    hp: f32 = 0.0,
    has_lifecycle_stage: bool = false,
    lifecycle_stage: f32 = 0.0,
    has_orbit_angle: bool = false,
    orbit_angle: f32 = 0.0,
    has_orbit_radius: bool = false,
    orbit_radius: f32 = 0.0,
    has_flags: bool = false,
    flags: i32 = 0,
    has_type_id: bool = false,
    type_id: i32 = 0,
    has_pos: bool = false,
    pos_x: f32 = 0.0,
    pos_y: f32 = 0.0,
};

pub const CaptureCreatureSpawnEvent = struct {
    tick_index: usize,
    spawn_count: usize = 0,
    spawns: [max_capture_spawns_per_event]CaptureCreatureSpawnRow = [_]CaptureCreatureSpawnRow{
        .{},
    } ** max_capture_spawns_per_event,
    added_head_count: usize = 0,
    added_head: [max_capture_added_head_rows_per_event]CaptureCreatureAddedHeadRow = [_]CaptureCreatureAddedHeadRow{
        .{},
    } ** max_capture_added_head_rows_per_event,
};

pub const CaptureStateTransitionRow = struct {
    target_state: i32,
    has_before_state: bool = false,
    before_state: i32 = 0,
    has_after_state: bool = false,
    after_state: i32 = 0,
};

pub const CaptureStateTransitionEvent = struct {
    tick_index: usize,
    transition_count: usize = 0,
    transitions: [max_capture_state_transition_rows_per_event]CaptureStateTransitionRow = [_]CaptureStateTransitionRow{
        .{ .target_state = 0 },
    } ** max_capture_state_transition_rows_per_event,
};

pub const ReplayEvent = union(enum) {
    perk_pick: PerkPickEvent,
    perk_menu_open: PerkMenuOpenEvent,
    capture_bootstrap: CaptureBootstrapEvent,
    capture_perk_apply: CapturePerkApplyEvent,
    capture_perk_pending: CapturePerkPendingEvent,
    capture_creature_spawn: CaptureCreatureSpawnEvent,
    capture_state_transition: CaptureStateTransitionEvent,

    pub fn tickIndex(self: ReplayEvent) usize {
        return switch (self) {
            .perk_pick => |event| event.tick_index,
            .perk_menu_open => |event| event.tick_index,
            .capture_bootstrap => |event| event.tick_index,
            .capture_perk_apply => |event| event.tick_index,
            .capture_perk_pending => |event| event.tick_index,
            .capture_creature_spawn => |event| event.tick_index,
            .capture_state_transition => |event| event.tick_index,
        };
    }
};

pub const ReplayEventSummary = struct {
    total_count: usize = 0,
    perk_menu_open_count: usize = 0,
    perk_pick_count: usize = 0,
    capture_bootstrap_count: usize = 0,
    capture_perk_apply_count: usize = 0,
    capture_perk_pending_count: usize = 0,
    capture_creature_spawn_count: usize = 0,
    capture_state_transition_count: usize = 0,
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
                .capture_bootstrap => summary.capture_bootstrap_count += 1,
                .capture_perk_apply => summary.capture_perk_apply_count += 1,
                .capture_perk_pending => summary.capture_perk_pending_count += 1,
                .capture_creature_spawn => summary.capture_creature_spawn_count += 1,
                .capture_state_transition => summary.capture_state_transition_count += 1,
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
    world_size: f32 = 1024.0,
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

const CaptureVec2Wire = struct {
    x: f32,
    y: f32,
};

fn StringMapWire(comptime Value: type) type {
    return struct {
        map: std.StringArrayHashMapUnmanaged(Value) = .{},

        pub fn msgpackRead(unpacker: anytype) !@This() {
            var value: @This() = .{};
            const len = try unpacker.readMapHeader(usize);
            try value.map.ensureTotalCapacity(unpacker.allocator, len);
            for (0..len) |_| {
                const key = try unpacker.read([]const u8);
                const entry_value = try unpacker.read(Value);
                value.map.putAssumeCapacity(key, entry_value);
            }
            return value;
        }

        pub fn get(self: @This(), key: []const u8) ?Value {
            return self.map.get(key);
        }
    };
}

const StringI64Map = StringMapWire(i64);
const StringF32Map = StringMapWire(f32);

const CaptureBootstrapPerkWire = struct {
    pending_count: i64 = 0,
    choices_dirty: bool = false,
    choices: []const i64 = &.{},
    player_nonzero_counts: []const []const []const i64 = &.{},
};

const CaptureBootstrapPlayerAimWire = struct {
    x: f32,
    y: f32,
    heading: ?f32 = null,
};

const CaptureBootstrapPlayerAltWeaponWire = struct {
    weapon_id: ?i64 = null,
    clip_size: ?i64 = null,
    ammo: ?f32 = null,
    reload_active: ?bool = null,
    reload_timer: ?f32 = null,
    reload_timer_max: ?f32 = null,
    shot_cooldown: ?f32 = null,
};

const CaptureBootstrapPlayerWire = struct {
    weapon_id: i64,
    pos: CaptureVec2Wire,
    health: f32,
    ammo: f32,
    experience: i64,
    level: i64,
    clip_size: ?i64 = null,
    reload_active: ?bool = null,
    reload_timer: ?f32 = null,
    reload_timer_max: ?f32 = null,
    shot_cooldown: ?f32 = null,
    spread_heat: ?f32 = null,
    aim: ?CaptureBootstrapPlayerAimWire = null,
    alt_weapon: ?CaptureBootstrapPlayerAltWeaponWire = null,
    bonus_timers_ms: StringI64Map = .{},
    perk_timers: StringF32Map = .{},
};

const CaptureBootstrapQuestSessionWire = struct {
    spawn_timeline_ms: f32,
    no_creatures_timer_ms: f32,
    completion_transition_ms: f32,
};

const CaptureCreatureSpawnRowWire = struct {
    template_id: i64,
    pos: CaptureVec2Wire,
    heading: f32,
};

const CaptureCreatureSpawnAddedHeadRowWire = struct {
    index: i64,
    heading: ?f32 = null,
    target_heading: ?f32 = null,
    ai_mode: ?i64 = null,
    link_index: ?i64 = null,
    hp: ?f32 = null,
    lifecycle_stage: ?f32 = null,
    orbit_angle: ?f32 = null,
    orbit_radius: ?f32 = null,
    flags: ?i64 = null,
    type_id: ?i64 = null,
    pos: ?CaptureVec2Wire = null,
};

const CaptureStateTransitionRowWire = struct {
    target_state: i64,
    before_state: ?i64 = null,
    after_state: ?i64 = null,
};

const ReplayEventPayloadWire = struct {
    tick_index: ?i64 = null,
    elapsed_ms: ?i64 = null,
    score_xp: ?i64 = null,
    perk_pending: ?i64 = null,
    perk: ?CaptureBootstrapPerkWire = null,
    bonus_timers_ms: StringI64Map = .{},
    players: []const CaptureBootstrapPlayerWire = &.{},
    digital_move_enabled_by_player: []const bool = &.{},
    perk_intervals: StringF32Map = .{},
    quest_session: ?CaptureBootstrapQuestSessionWire = null,
    perk_id: ?i64 = null,
    outside_before: bool = false,
    pending_before: ?i64 = null,
    pending_after: ?i64 = null,
    spawns: []const CaptureCreatureSpawnRowWire = &.{},
    added_head: []const CaptureCreatureSpawnAddedHeadRowWire = &.{},
    transitions: []const CaptureStateTransitionRowWire = &.{},
};

const ReplayEventWire = struct {
    tick_index: i64,
    kind: []const u8,
    player_index: i64 = -1,
    choice_index: i64 = -1,
    payload: []const ReplayEventPayloadWire = &.{},

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
    var decoded = msgpack.decodeFromSlice(ReplayWire, allocator, payload) catch |err| {
        return switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            else => error.InvalidMsgpack,
        };
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
    var decoded = msgpack.decodeFromSlice(ReplayWire, allocator, payload) catch |err| {
        return switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            else => error.InvalidMsgpack,
        };
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
            .capture_bootstrap => summary.capture_bootstrap_count += 1,
            .capture_perk_apply => summary.capture_perk_apply_count += 1,
            .capture_perk_pending => summary.capture_perk_pending_count += 1,
            .capture_creature_spawn => summary.capture_creature_spawn_count += 1,
            .capture_state_transition => summary.capture_state_transition_count += 1,
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
        errdefer allocator.free(tick_inputs);
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
    errdefer allocator.free(events);
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

    if (std.mem.eql(u8, wire_event.kind, "orig_capture_bootstrap")) {
        if (wire_event.payload.len != 1) return error.UnsupportedEventShape;
        return .{
            .capture_bootstrap = try parseCaptureBootstrapEvent(
                tick_index,
                wire_event.payload[0],
            ),
        };
    }

    if (std.mem.eql(u8, wire_event.kind, "orig_capture_perk_apply")) {
        if (wire_event.payload.len != 1) return error.UnsupportedEventShape;
        return .{
            .capture_perk_apply = try parseCapturePerkApplyEvent(
                tick_index,
                wire_event.payload[0],
            ),
        };
    }

    if (std.mem.eql(u8, wire_event.kind, "orig_capture_perk_pending")) {
        if (wire_event.payload.len != 1) return error.UnsupportedEventShape;
        return .{
            .capture_perk_pending = try parseCapturePerkPendingEvent(
                tick_index,
                wire_event.payload[0],
            ),
        };
    }

    if (std.mem.eql(u8, wire_event.kind, "orig_capture_creature_spawn")) {
        if (wire_event.payload.len != 1) return error.UnsupportedEventShape;
        return .{
            .capture_creature_spawn = try parseCaptureCreatureSpawnEvent(
                tick_index,
                wire_event.payload[0],
            ),
        };
    }

    if (std.mem.eql(u8, wire_event.kind, "orig_capture_state_transition")) {
        if (wire_event.payload.len != 1) return error.UnsupportedEventShape;
        return .{
            .capture_state_transition = try parseCaptureStateTransitionEvent(
                tick_index,
                wire_event.payload[0],
            ),
        };
    }

    return error.UnsupportedEventKind;
}

fn parseCaptureBootstrapEvent(
    tick_index: usize,
    payload: ReplayEventPayloadWire,
) ReplayCodecError!CaptureBootstrapEvent {
    var event = CaptureBootstrapEvent{
        .tick_index = tick_index,
    };

    if (payload.elapsed_ms) |value| {
        event.elapsed_ms = try parseEventI32(value);
    }
    if (payload.score_xp) |value| {
        event.score_xp = try parseEventI32(value);
    }
    if (payload.perk_pending) |value| {
        event.perk_pending = try parseEventI32(value);
        event.perk_pending_count = event.perk_pending;
    }

    if (payload.perk) |perk| {
        event.perk_pending_count = try parseEventI32(perk.pending_count);
        event.perk_choices_dirty = perk.choices_dirty;
        const choice_count = @min(perk.choices.len, event.perk_choices.len);
        event.perk_choice_count = choice_count;
        for (perk.choices[0..choice_count], 0..) |choice_id, idx| {
            event.perk_choices[idx] = try parseEventI32(choice_id);
        }

        const player_count = perk.player_nonzero_counts.len;
        if (player_count > max_players) {
            return error.UnsupportedEventShape;
        }
        for (0..player_count) |player_idx| {
            const raw_pairs = perk.player_nonzero_counts[player_idx];
            if (raw_pairs.len > max_capture_bootstrap_perk_pairs_per_player) {
                return error.UnsupportedEventShape;
            }
            event.player_perk_counts[player_idx].pair_count = raw_pairs.len;
            for (raw_pairs, 0..) |raw_pair, pair_idx| {
                if (raw_pair.len != 2) return error.UnsupportedEventShape;
                event.player_perk_counts[player_idx].pairs[pair_idx] = .{
                    .perk_id = try parseEventI32(raw_pair[0]),
                    .count = try parseEventI32(raw_pair[1]),
                };
            }
        }
    }

    const player_count = payload.players.len;
    if (player_count > max_players) {
        return error.UnsupportedEventShape;
    }
    event.player_count = player_count;
    for (payload.players, 0..) |player_wire, idx| {
        event.players[idx] = .{
            .weapon_id = try parseEventI32(player_wire.weapon_id),
            .pos_x = player_wire.pos.x,
            .pos_y = player_wire.pos.y,
            .health = player_wire.health,
            .ammo = player_wire.ammo,
            .experience = try parseEventI32(player_wire.experience),
            .level = try parseEventI32(player_wire.level),
            .clip_size = if (player_wire.clip_size) |clip_size| try parseEventI32(clip_size) else null,
            .reload_active = player_wire.reload_active,
            .reload_timer = player_wire.reload_timer,
            .reload_timer_max = player_wire.reload_timer_max,
            .shot_cooldown = player_wire.shot_cooldown,
            .spread_heat = player_wire.spread_heat,
            .shield_ms = if (player_wire.bonus_timers_ms.get("shield")) |value| try parseEventI32(value) else null,
            .fire_bullets_ms = if (player_wire.bonus_timers_ms.get("fire_bullets")) |value| try parseEventI32(value) else null,
            .speed_bonus_ms = if (player_wire.bonus_timers_ms.get("speed_bonus")) |value| try parseEventI32(value) else null,
            .hot_tempered_timer = parseMapF32(player_wire.perk_timers, "hot_tempered"),
            .man_bomb_timer = parseMapF32(player_wire.perk_timers, "man_bomb"),
            .living_fortress_timer = parseMapF32(player_wire.perk_timers, "living_fortress"),
            .fire_cough_timer = parseMapF32(player_wire.perk_timers, "fire_cough"),
        };
        if (player_wire.aim) |aim| {
            event.players[idx].aim_x = aim.x;
            event.players[idx].aim_y = aim.y;
            event.players[idx].aim_heading = aim.heading;
        }
        if (player_wire.alt_weapon) |alt_weapon| {
            event.players[idx].alt_weapon_id = if (alt_weapon.weapon_id) |value| try parseEventI32(value) else null;
            event.players[idx].alt_clip_size = if (alt_weapon.clip_size) |value| try parseEventI32(value) else null;
            event.players[idx].alt_ammo = alt_weapon.ammo;
            event.players[idx].alt_reload_active = alt_weapon.reload_active;
            event.players[idx].alt_reload_timer = alt_weapon.reload_timer;
            event.players[idx].alt_reload_timer_max = alt_weapon.reload_timer_max;
            event.players[idx].alt_shot_cooldown = alt_weapon.shot_cooldown;
        }
    }

    if (payload.digital_move_enabled_by_player.len > max_players) {
        return error.UnsupportedEventShape;
    }
    for (payload.digital_move_enabled_by_player, 0..) |enabled, idx| {
        event.digital_move_enabled_by_player[idx] = enabled;
    }

    event.weapon_power_up_ms = try parseMapI32(payload.bonus_timers_ms, "4");
    event.reflex_boost_ms = try parseMapI32(payload.bonus_timers_ms, "9");
    event.energizer_ms = try parseMapI32(payload.bonus_timers_ms, "2");
    event.double_experience_ms = try parseMapI32(payload.bonus_timers_ms, "6");
    event.freeze_ms = try parseMapI32(payload.bonus_timers_ms, "11");
    event.perk_interval_man_bomb = parseMapF32(payload.perk_intervals, "man_bomb");
    event.perk_interval_fire_cough = parseMapF32(payload.perk_intervals, "fire_cough");
    event.perk_interval_hot_tempered = parseMapF32(payload.perk_intervals, "hot_tempered");
    if (payload.quest_session) |quest_session| {
        event.quest_session = .{
            .spawn_timeline_ms = quest_session.spawn_timeline_ms,
            .no_creatures_timer_ms = quest_session.no_creatures_timer_ms,
            .completion_transition_ms = quest_session.completion_transition_ms,
        };
    }

    return event;
}

fn parseCapturePerkApplyEvent(
    tick_index: usize,
    payload: ReplayEventPayloadWire,
) ReplayCodecError!CapturePerkApplyEvent {
    const perk_id_raw = payload.perk_id orelse return error.UnsupportedEventShape;
    const perk_id = try parseEventI32(perk_id_raw);
    if (perk_id <= 0) return error.UnsupportedEventShape;
    return .{
        .tick_index = tick_index,
        .perk_id = perk_id,
        .outside_before = payload.outside_before,
        .pending_before = if (payload.pending_before) |value|
            (if (value >= 0) try parseEventI32(value) else null)
        else
            null,
        .pending_after = if (payload.pending_after) |value|
            (if (value >= 0) try parseEventI32(value) else null)
        else
            null,
    };
}

fn parseCapturePerkPendingEvent(
    tick_index: usize,
    payload: ReplayEventPayloadWire,
) ReplayCodecError!CapturePerkPendingEvent {
    const pending_raw = payload.perk_pending orelse return error.UnsupportedEventShape;
    const pending = try parseEventI32(pending_raw);
    if (pending < 0) return error.UnsupportedEventShape;
    return .{
        .tick_index = tick_index,
        .perk_pending = pending,
    };
}

fn parseCaptureCreatureSpawnEvent(
    tick_index: usize,
    payload: ReplayEventPayloadWire,
) ReplayCodecError!CaptureCreatureSpawnEvent {
    var event = CaptureCreatureSpawnEvent{
        .tick_index = tick_index,
    };
    if (payload.spawns.len > event.spawns.len) return error.UnsupportedEventShape;
    if (payload.added_head.len > event.added_head.len) return error.UnsupportedEventShape;

    event.spawn_count = payload.spawns.len;
    for (payload.spawns, 0..) |spawn_row, idx| {
        event.spawns[idx] = .{
            .template_id = try parseEventI32(spawn_row.template_id),
            .pos_x = spawn_row.pos.x,
            .pos_y = spawn_row.pos.y,
            .heading = spawn_row.heading,
        };
    }

    event.added_head_count = payload.added_head.len;
    for (payload.added_head, 0..) |row, idx| {
        event.added_head[idx] = .{
            .index = try parseEventI32(row.index),
            .has_heading = row.heading != null,
            .heading = row.heading orelse 0.0,
            .has_target_heading = row.target_heading != null,
            .target_heading = row.target_heading orelse 0.0,
            .has_ai_mode = row.ai_mode != null,
            .ai_mode = if (row.ai_mode) |value| try parseEventI32(value) else 0,
            .has_link_index = row.link_index != null,
            .link_index = if (row.link_index) |value| try parseEventI32(value) else 0,
            .has_hp = row.hp != null,
            .hp = row.hp orelse 0.0,
            .has_lifecycle_stage = row.lifecycle_stage != null,
            .lifecycle_stage = row.lifecycle_stage orelse 0.0,
            .has_orbit_angle = row.orbit_angle != null,
            .orbit_angle = row.orbit_angle orelse 0.0,
            .has_orbit_radius = row.orbit_radius != null,
            .orbit_radius = row.orbit_radius orelse 0.0,
            .has_flags = row.flags != null,
            .flags = if (row.flags) |value| try parseEventI32(value) else 0,
            .has_type_id = row.type_id != null,
            .type_id = if (row.type_id) |value| try parseEventI32(value) else 0,
            .has_pos = row.pos != null,
            .pos_x = if (row.pos) |pos| pos.x else 0.0,
            .pos_y = if (row.pos) |pos| pos.y else 0.0,
        };
    }

    return event;
}

fn parseCaptureStateTransitionEvent(
    tick_index: usize,
    payload: ReplayEventPayloadWire,
) ReplayCodecError!CaptureStateTransitionEvent {
    var event = CaptureStateTransitionEvent{
        .tick_index = tick_index,
    };
    if (payload.transitions.len > event.transitions.len) return error.UnsupportedEventShape;
    event.transition_count = payload.transitions.len;
    for (payload.transitions, 0..) |row, idx| {
        event.transitions[idx] = .{
            .target_state = try parseEventI32(row.target_state),
            .has_before_state = row.before_state != null,
            .before_state = if (row.before_state) |value| try parseEventI32(value) else 0,
            .has_after_state = row.after_state != null,
            .after_state = if (row.after_state) |value| try parseEventI32(value) else 0,
        };
    }
    return event;
}

fn parseMapI32(
    map: anytype,
    key: []const u8,
) ReplayCodecError!?i32 {
    if (map.get(key)) |value| {
        return try parseEventI32(value);
    }
    return null;
}

fn parseMapF32(map: anytype, key: []const u8) ?f32 {
    return map.get(key);
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
    const max_world_size_i32_f32: f32 = @floatFromInt(std.math.maxInt(i32));
    if (!std.math.isFinite(wire.world_size) or wire.world_size <= 0.0 or wire.world_size > max_world_size_i32_f32) {
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
        .world_size = wire.world_size,
        .player_count = player_count,
        .status = .{
            .quest_unlock_index = quest_unlock_index,
            .quest_unlock_index_full = quest_unlock_index_full,
            .weapon_usage_counts = usage_counts,
        },
        .input_quantization = allocator.dupe(u8, wire.input_quantization) catch return error.OutOfMemory,
    };
}

fn normalizeInputValue(value: f32, input_quantization: []const u8) ReplayCodecError!f32 {
    if (std.mem.eql(u8, input_quantization, "raw")) {
        return value;
    }
    if (std.mem.eql(u8, input_quantization, "f32")) {
        return value;
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

test "parse replay event supports capture payload kinds" {
    const bootstrap_players = [_]CaptureBootstrapPlayerWire{
        .{
            .weapon_id = 1,
            .pos = .{ .x = 512.0, .y = 512.0 },
            .health = 100.0,
            .ammo = 11.0,
            .experience = 0,
            .level = 1,
        },
    };
    const bootstrap_payload = [_]ReplayEventPayloadWire{
        .{
            .elapsed_ms = 0,
            .score_xp = 0,
            .perk_pending = 0,
            .players = bootstrap_players[0..],
            .digital_move_enabled_by_player = &.{false},
        },
    };
    const perk_apply_payload = [_]ReplayEventPayloadWire{
        .{
            .perk_id = 44,
            .outside_before = true,
        },
    };
    const perk_pending_payload = [_]ReplayEventPayloadWire{
        .{
            .perk_pending = 2,
        },
    };
    const spawn_rows = [_]CaptureCreatureSpawnRowWire{
        .{
            .template_id = 0x12,
            .pos = .{ .x = 512.0, .y = 512.0 },
            .heading = 0.0,
        },
    };
    const spawn_payload = [_]ReplayEventPayloadWire{
        .{
            .spawns = spawn_rows[0..],
        },
    };
    const transitions = [_]CaptureStateTransitionRowWire{
        .{
            .target_state = 12,
            .before_state = 9,
            .after_state = 12,
        },
    };
    const transition_payload = [_]ReplayEventPayloadWire{
        .{
            .transitions = transitions[0..],
        },
    };

    const wire_events = [_]ReplayEventWire{
        .{
            .tick_index = 0,
            .kind = "orig_capture_bootstrap",
            .payload = bootstrap_payload[0..],
        },
        .{
            .tick_index = 0,
            .kind = "orig_capture_perk_apply",
            .payload = perk_apply_payload[0..],
        },
        .{
            .tick_index = 0,
            .kind = "orig_capture_perk_pending",
            .payload = perk_pending_payload[0..],
        },
        .{
            .tick_index = 0,
            .kind = "orig_capture_creature_spawn",
            .payload = spawn_payload[0..],
        },
        .{
            .tick_index = 0,
            .kind = "orig_capture_state_transition",
            .payload = transition_payload[0..],
        },
    };

    const parsed0 = try parseReplayEvent(wire_events[0], 1);
    const parsed1 = try parseReplayEvent(wire_events[1], 1);
    const parsed2 = try parseReplayEvent(wire_events[2], 1);
    const parsed3 = try parseReplayEvent(wire_events[3], 1);
    const parsed4 = try parseReplayEvent(wire_events[4], 1);
    try std.testing.expect(parsed0 == .capture_bootstrap);
    try std.testing.expect(parsed1 == .capture_perk_apply);
    try std.testing.expect(parsed2 == .capture_perk_pending);
    try std.testing.expect(parsed3 == .capture_creature_spawn);
    try std.testing.expect(parsed4 == .capture_state_transition);
}

test "parse replay event rejects capture payload arrays that are not singleton" {
    const payload = [_]ReplayEventPayloadWire{
        .{},
        .{},
    };
    const capture_kinds = [_][]const u8{
        "orig_capture_bootstrap",
        "orig_capture_perk_apply",
        "orig_capture_perk_pending",
        "orig_capture_creature_spawn",
        "orig_capture_state_transition",
    };
    for (capture_kinds) |kind| {
        const wire = ReplayEventWire{
            .tick_index = 0,
            .kind = kind,
            .payload = payload[0..],
        };
        try std.testing.expectError(error.UnsupportedEventShape, parseReplayEvent(wire, 1));
    }
}

test "build header rejects world_size above i32 range" {
    const usage_counts = [_]i64{0} ** weapon_usage_count;
    const too_large_world_size: f32 = @as(f32, @floatFromInt(std.math.maxInt(i32))) + 1024.0;
    const wire = ReplayHeaderWire{
        .game_mode_id = 1,
        .seed = 1,
        .replay_format_version = replay_format_version,
        .quest_level = "",
        .bootstrap_kind = "none",
        .bootstrap_seed = 0,
        .game_version = "0.7.0",
        .tick_rate = 60,
        .difficulty_level = 0,
        .hardcore = false,
        .preserve_bugs = false,
        .detail_preset = 5,
        .fx_toggle = 0,
        .world_size = too_large_world_size,
        .player_count = 1,
        .status = .{
            .quest_unlock_index = 0,
            .quest_unlock_index_full = 0,
            .weapon_usage_counts = usage_counts[0..],
        },
        .input_quantization = "raw",
    };
    try std.testing.expectError(error.InvalidHeaderValue, buildHeader(std.testing.allocator, wire));
}

test "build inputs frees tick allocations on parse error" {
    const wire_tick = [_]ReplayInputWire{
        .{
            .move_x = 0.0,
            .move_y = 0.0,
            .aim_x = 0.0,
            .aim_y = 0.0,
            .flags = -1,
        },
    };
    const wire_inputs = [_][]const ReplayInputWire{wire_tick[0..]};
    try std.testing.expectError(error.UnsupportedInputShape, buildInputs(std.testing.allocator, wire_inputs[0..], "raw"));
}

test "build events frees allocation on parse error" {
    const wire_events = [_]ReplayEventWire{
        .{
            .tick_index = 0,
            .kind = "unknown_event_kind",
        },
    };
    try std.testing.expectError(error.UnsupportedEventKind, buildEvents(std.testing.allocator, wire_events[0..], 1));
}

test "parse replay decode errors preserve oom and map invalid msgpack" {
    const empty_payload = [_]u8{};

    var no_mem_summary: [0]u8 = .{};
    var summary_allocator = std.heap.FixedBufferAllocator.init(no_mem_summary[0..]);
    try std.testing.expectError(error.OutOfMemory, parseReplaySummary(summary_allocator.allocator(), empty_payload[0..]));

    var no_mem_replay: [0]u8 = .{};
    var replay_allocator = std.heap.FixedBufferAllocator.init(no_mem_replay[0..]);
    try std.testing.expectError(error.OutOfMemory, parseReplay(replay_allocator.allocator(), empty_payload[0..]));

    const invalid_payload = [_]u8{0xc1};
    try std.testing.expectError(error.InvalidMsgpack, parseReplaySummary(std.testing.allocator, invalid_payload[0..]));
    try std.testing.expectError(error.InvalidMsgpack, parseReplay(std.testing.allocator, invalid_payload[0..]));
}

test "capture bootstrap rejects perk nonzero counts above max players" {
    const empty_pairs = [_][]const i64{};
    const player_nonzero_counts = [_][]const []const i64{empty_pairs[0..]} ** (max_players + 1);
    const payload = [_]ReplayEventPayloadWire{
        .{
            .perk = .{
                .player_nonzero_counts = player_nonzero_counts[0..],
            },
        },
    };
    const wire = ReplayEventWire{
        .tick_index = 0,
        .kind = "orig_capture_bootstrap",
        .payload = payload[0..],
    };
    try std.testing.expectError(error.UnsupportedEventShape, parseReplayEvent(wire, 1));
}

test "capture bootstrap rejects players above max players" {
    const players = [_]CaptureBootstrapPlayerWire{
        .{
            .weapon_id = 1,
            .pos = .{ .x = 0.0, .y = 0.0 },
            .health = 100.0,
            .ammo = 0.0,
            .experience = 0,
            .level = 1,
        },
    } ** (max_players + 1);
    const payload = [_]ReplayEventPayloadWire{
        .{
            .players = players[0..],
        },
    };
    const wire = ReplayEventWire{
        .tick_index = 0,
        .kind = "orig_capture_bootstrap",
        .payload = payload[0..],
    };
    try std.testing.expectError(error.UnsupportedEventShape, parseReplayEvent(wire, 1));
}

test "capture bootstrap rejects digital move flags above max players" {
    const digital_move_enabled_by_player = [_]bool{false} ** (max_players + 1);
    const payload = [_]ReplayEventPayloadWire{
        .{
            .digital_move_enabled_by_player = digital_move_enabled_by_player[0..],
        },
    };
    const wire = ReplayEventWire{
        .tick_index = 0,
        .kind = "orig_capture_bootstrap",
        .payload = payload[0..],
    };
    try std.testing.expectError(error.UnsupportedEventShape, parseReplayEvent(wire, 1));
}
