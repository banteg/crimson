const std = @import("std");
const msgpack = @import("msgpack");
const rng_callers = @import("rng_caller_static.zig");
const game_ids = @import("game_ids.zig");

pub const replay_format_version: i32 = 11;
pub const legacy_replay_format_version: i32 = 8;
pub const weapon_usage_count: usize = 53;
pub const max_players: usize = 4;
pub const gzip_magic = [_]u8{ 0x1f, 0x8b };
pub const zstd_magic = [_]u8{ 0x28, 0xB5, 0x2F, 0xFD };
pub const max_replay_payload_bytes: usize = 64 * 1024 * 1024;
pub const latest_ruleset_game_version_prefix = "0.9.";
const msgpack_bin8: u8 = 0xC4;
const msgpack_bin16: u8 = 0xC5;
const msgpack_bin32: u8 = 0xC6;

pub const fire_down_flag: u32 = 1 << 0;
pub const fire_pressed_flag: u32 = 1 << 1;
pub const reload_pressed_flag: u32 = 1 << 2;
pub const reload_down_flag: u32 = 1 << 16;
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
    UnknownCommandKind,
    UnsupportedBootstrapKind,
    UnsupportedInputQuantization,
    BootstrapSeedMismatch,
    InvalidGzipPayload,
    InvalidZstdPayload,
    PayloadTooLarge,
    OutOfMemory,
};

pub const ReplayStatus = struct {
    quest_unlock_index: i32 = 0,
    quest_unlock_index_full: i32 = 0,
    weapon_usage_counts: [weapon_usage_count]u32 = [_]u32{0} ** weapon_usage_count,
};

pub const ReplayClaimedStats = struct {
    complete: bool = false,
    ticks: i32 = 0,
    elapsed_ms: i64 = 0,
    score_xp: i64 = 0,
    kills: i32 = 0,
    most_used_weapon_id: i32 = 0,
    shots_fired: i32 = 0,
    shots_hit: i32 = 0,
};

pub const ReplayHeader = struct {
    game_mode_id: i32,
    seed: u32,
    replay_format_version: i32,
    quest_level: []u8,
    typo_dictionary_words: []const []const u8 = &.{},
    typo_highscore_names: []const []const u8 = &.{},
    bootstrap_kind: []u8,
    bootstrap_seed: u32,
    game_version: []u8,
    tick_rate: i32,
    difficulty_level: i32,
    hardcore: bool,
    preserve_bugs: bool,
    detail_preset: i32,
    gore_disabled: i32,
    world_size: f32,
    player_count: i32,
    status: ReplayStatus,
    claimed_stats: ReplayClaimedStats = .{},
    input_quantization: []u8,

    pub fn deinit(self: ReplayHeader, allocator: std.mem.Allocator) void {
        allocator.free(self.quest_level);
        freeStringSliceList(allocator, self.typo_dictionary_words);
        freeStringSliceList(allocator, self.typo_highscore_names);
        allocator.free(self.bootstrap_kind);
        allocator.free(self.game_version);
        allocator.free(self.input_quantization);
    }
};

fn dupStringSliceList(
    allocator: std.mem.Allocator,
    values: []const []const u8,
) ReplayCodecError![]const []const u8 {
    if (values.len == 0) return &.{};

    const out = allocator.alloc([]const u8, values.len) catch return error.OutOfMemory;
    var built: usize = 0;
    errdefer {
        for (out[0..built]) |entry| allocator.free(entry);
        allocator.free(out);
    }

    for (values, 0..) |value, idx| {
        out[idx] = allocator.dupe(u8, value) catch return error.OutOfMemory;
        built += 1;
    }
    return out;
}

fn freeStringSliceList(
    allocator: std.mem.Allocator,
    values: []const []const u8,
) void {
    if (values.len == 0) return;
    for (values) |value| allocator.free(value);
    allocator.free(values);
}

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
    reload_down: bool,
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

pub fn isLatestRulesetGameVersion(game_version: []const u8) bool {
    return std.mem.startsWith(u8, game_version, latest_ruleset_game_version_prefix);
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

pub const TypoCharEvent = struct {
    tick_index: usize,
    player_index: i32,
    ch: u8,
};

pub const TypoBackspaceEvent = struct {
    tick_index: usize,
    player_index: i32,
};

pub const TypoSubmitEvent = struct {
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
    typo_char: TypoCharEvent,
    typo_backspace: TypoBackspaceEvent,
    typo_submit: TypoSubmitEvent,
    capture_bootstrap: CaptureBootstrapEvent,
    capture_perk_apply: CapturePerkApplyEvent,
    capture_perk_pending: CapturePerkPendingEvent,
    capture_creature_spawn: CaptureCreatureSpawnEvent,
    capture_state_transition: CaptureStateTransitionEvent,

    pub fn tickIndex(self: ReplayEvent) usize {
        return switch (self) {
            .perk_pick => |event| event.tick_index,
            .perk_menu_open => |event| event.tick_index,
            .typo_char => |event| event.tick_index,
            .typo_backspace => |event| event.tick_index,
            .typo_submit => |event| event.tick_index,
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
    dt: []f32,
    events: []ReplayEvent,

    pub fn deinit(self: Replay, allocator: std.mem.Allocator) void {
        self.header.deinit(allocator);
        for (self.inputs) |tick| allocator.free(tick);
        allocator.free(self.inputs);
        allocator.free(self.dt);
        allocator.free(self.events);
    }

    pub fn tickCount(self: Replay) usize {
        return self.inputs.len;
    }

    pub fn summarizeEvents(self: Replay) ReplayEventSummary {
        var summary: ReplayEventSummary = .{
            .total_count = self.events.len,
        };
        for (self.events) |event| {
            switch (event) {
                .perk_pick => summary.perk_pick_count += 1,
                .perk_menu_open => summary.perk_menu_open_count += 1,
                .typo_char, .typo_backspace, .typo_submit => {},
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
    quest_unlock_index: i32 = 0,
    quest_unlock_index_full: i32 = 0,
    weapon_usage_counts: []const u32 = &.{},
};

pub const ReplayStatusCurrentWire = struct {
    quest_unlock_index: i32 = 0,
    quest_unlock_index_full: i32 = 0,
    weapon_usage_counts: []const u32 = &.{},
    quest_play_counts: []const u32 = &.{},
    mode_play_survival: i32 = 0,
    mode_play_rush: i32 = 0,
    mode_play_typo: i32 = 0,
    mode_play_other: i32 = 0,
    game_sequence_id: i32 = 0,
    unknown_tail: BinaryBytes = .{ .data = "" },

    pub fn msgpackRead(unpacker: anytype) !ReplayStatusCurrentWire {
        const field_count = try unpacker.readMapHeader(u16);
        var field_name_buf: [64]u8 = undefined;
        var status: ReplayStatusCurrentWire = .{};

        for (0..field_count) |_| {
            const field_name = try unpacker.readStringInto(&field_name_buf);
            if (std.mem.eql(u8, field_name, "quest_unlock_index")) {
                status.quest_unlock_index = try unpacker.readInt(i32);
            } else if (std.mem.eql(u8, field_name, "quest_unlock_index_full")) {
                status.quest_unlock_index_full = try unpacker.readInt(i32);
            } else if (std.mem.eql(u8, field_name, "weapon_usage_counts")) {
                status.weapon_usage_counts = try readExactU32Array(unpacker);
            } else if (std.mem.eql(u8, field_name, "quest_play_counts")) {
                status.quest_play_counts = try readExactU32Array(unpacker);
            } else if (std.mem.eql(u8, field_name, "mode_play_survival")) {
                status.mode_play_survival = try unpacker.readInt(i32);
            } else if (std.mem.eql(u8, field_name, "mode_play_rush")) {
                status.mode_play_rush = try unpacker.readInt(i32);
            } else if (std.mem.eql(u8, field_name, "mode_play_typo")) {
                status.mode_play_typo = try unpacker.readInt(i32);
            } else if (std.mem.eql(u8, field_name, "mode_play_other")) {
                status.mode_play_other = try unpacker.readInt(i32);
            } else if (std.mem.eql(u8, field_name, "game_sequence_id")) {
                status.game_sequence_id = try unpacker.readInt(i32);
            } else if (std.mem.eql(u8, field_name, "unknown_tail")) {
                status.unknown_tail = .{ .data = try readExactBinary(unpacker) };
            } else {
                return error.UnknownStructField;
            }
        }

        return status;
    }
};

const ReplayClaimedStatsWire = struct {
    complete: bool = false,
    ticks: i32 = 0,
    elapsed_ms: i64 = 0,
    score_xp: i64 = 0,
    kills: i32 = 0,
    most_used_weapon_id: i32 = 0,
    shots_fired: i32 = 0,
    shots_hit: i32 = 0,
};

const ReplayHeaderWire = struct {
    game_mode_id: i32,
    seed: u32,
    replay_format_version: i32,
    quest_level: []const u8 = "",
    bootstrap_kind: []const u8 = "none",
    bootstrap_seed: u32 = 0,
    game_version: []const u8 = "",
    tick_rate: i32 = 60,
    difficulty_level: i32 = 0,
    hardcore: bool = false,
    preserve_bugs: bool = false,
    detail_preset: i32 = 5,
    gore_disabled: i32 = 0,
    world_size: f32 = 1024.0,
    player_count: i32 = 1,
    status: ReplayStatusWire = .{},
    claimed_stats: ReplayClaimedStatsWire,
    input_quantization: []const u8 = "f32",
};

const QuestLevelCurrentWire = struct {
    major: i32,
    minor: i32,
};

const ReplayHeaderCurrentWire = struct {
    game_mode_id: i32,
    seed: u32,
    replay_format_version: i32,
    quest_level: ?QuestLevelCurrentWire = null,
    typo_dictionary_words: []const []const u8 = &.{},
    typo_highscore_names: []const []const u8 = &.{},
    game_version: []const u8 = "",
    tick_rate: i32 = 60,
    quest_fail_retry_count: i32 = 0,
    hardcore: bool = false,
    preserve_bugs: bool = false,
    detail_preset: i32 = 5,
    violence_disabled: i32 = 0,
    world_size: f32 = 1024.0,
    player_count: i32 = 1,
    status: ReplayStatusCurrentWire = .{},
    claimed_stats: ReplayClaimedStatsWire,
    input_quantization: []const u8 = "f32",
};

const ReplayInputWire = struct {
    move_x: f32,
    move_y: f32,
    aim_x: f32,
    aim_y: f32,
    flags: i32,

    pub fn msgpackFormat() msgpack.StructFormat {
        return .{ .as_array = .{} };
    }
};

const PerkPickEventWire = struct {
    tick_index: i32,
    player_index: i32,
    choice_index: i32,
};

const PerkMenuOpenEventWire = struct {
    tick_index: i32,
    player_index: i32,
};

const ReplayCommandCurrentWire = struct {
    type: []const u8,
    player_index: i32 = 0,
    choice_index: ?i32 = null,
    ch: ?[]const u8 = null,
};

pub const BinaryBytes = struct {
    data: []const u8,

    pub fn msgpackRead(unpacker: anytype) !BinaryBytes {
        return .{ .data = try readExactBinary(unpacker) };
    }
};

fn readExactBinary(unpacker: anytype) ![]const u8 {
    const header = try unpacker.reader.takeByte();
    const len = switch (header) {
        msgpack_bin8 => try readPackedInt(u8, unpacker.reader),
        msgpack_bin16 => try readPackedInt(u16, unpacker.reader),
        msgpack_bin32 => try readPackedInt(u32, unpacker.reader),
        else => return error.InvalidFormat,
    };

    const bytes = try unpacker.allocator.alloc(u8, len);
    errdefer unpacker.allocator.free(bytes);
    try unpacker.reader.readSliceAll(bytes);
    return bytes;
}

fn readExactU32Array(unpacker: anytype) ![]const u32 {
    const len = try msgpack.unpackArrayHeader(unpacker.reader, u32);
    const out = try unpacker.allocator.alloc(u32, len);
    errdefer unpacker.allocator.free(out);
    for (out) |*item| {
        item.* = try unpacker.readInt(u32);
    }
    return out;
}

fn readPackedInt(comptime T: type, reader: *std.Io.Reader) !T {
    var buf: [@sizeOf(T)]u8 = undefined;
    try reader.readSliceAll(&buf);
    return std.mem.readInt(T, &buf, .big);
}

const CaptureBootstrapQuestSessionWire = struct {
    spawn_timeline_ms: ?f32,
    no_creatures_timer_ms: ?f32,
    completion_transition_ms: ?f32,
};

const CaptureBootstrapPlayerWire = struct {
    weapon_id: i32,
    pos_x: f32,
    pos_y: f32,
    health: f32,
    ammo: f32,
    experience: i32,
    level: i32,
    clip_size: ?i32,
    reload_active: ?bool,
    reload_timer: ?f32,
    reload_timer_max: ?f32,
    shot_cooldown: ?f32,
    spread_heat: ?f32,
    aim_x: ?f32,
    aim_y: ?f32,
    aim_heading: ?f32,
    alt_weapon_id: ?i32,
    alt_clip_size: ?i32,
    alt_ammo: ?f32,
    alt_reload_active: ?bool,
    alt_reload_timer: ?f32,
    alt_reload_timer_max: ?f32,
    alt_shot_cooldown: ?f32,
    shield_ms: ?i32,
    fire_bullets_ms: ?i32,
    speed_bonus_ms: ?i32,
    hot_tempered_timer: ?f32,
    man_bomb_timer: ?f32,
    living_fortress_timer: ?f32,
    fire_cough_timer: ?f32,
};

const CaptureBootstrapEventWire = struct {
    tick_index: i32,
    elapsed_ms: i32,
    score_xp: i32,
    perk_pending: i32,
    perk_pending_count: i32,
    perk_choices_dirty: bool,
    perk_choices: []const i32,
    player_nonzero_counts: []const []const []const i32,
    players: []const CaptureBootstrapPlayerWire,
    digital_move_enabled_by_player: []const bool,
    weapon_power_up_ms: i32,
    reflex_boost_ms: i32,
    energizer_ms: i32,
    double_experience_ms: i32,
    freeze_ms: i32,
    perk_interval_man_bomb: ?f32,
    perk_interval_fire_cough: ?f32,
    perk_interval_hot_tempered: ?f32,
    quest_session: ?CaptureBootstrapQuestSessionWire,
};

const CapturePerkApplyEventWire = struct {
    tick_index: i32,
    perk_id: i32,
    outside_before: bool,
    pending_before: ?i32,
    pending_after: ?i32,
};

const CapturePerkPendingEventWire = struct {
    tick_index: i32,
    perk_pending: i32,
};

const CaptureCreatureSpawnRowWire = struct {
    template_id: i32,
    pos_x: f32,
    pos_y: f32,
    heading: f32,
};

const CaptureCreatureSpawnAddedHeadRowWire = struct {
    index: i32,
    heading: ?f32,
    target_heading: ?f32,
    ai_mode: ?i32,
    link_index: ?i32,
    hp: ?f32,
    lifecycle_stage: ?f32,
    orbit_angle: ?f32,
    orbit_radius: ?f32,
    flags: ?i32,
    type_id: ?i32,
    pos_x: ?f32,
    pos_y: ?f32,
};

const CaptureCreatureSpawnEventWire = struct {
    tick_index: i32,
    spawns: []const CaptureCreatureSpawnRowWire,
    added_head: []const CaptureCreatureSpawnAddedHeadRowWire,
};

const CaptureStateTransitionRowWire = struct {
    target_state: i32,
    before_state: ?i32,
    after_state: ?i32,
};

const CaptureStateTransitionEventWire = struct {
    tick_index: i32,
    transitions: []const CaptureStateTransitionRowWire,
};

const ReplayEventWire = union(enum) {
    perk_pick: PerkPickEventWire,
    perk_menu_open: PerkMenuOpenEventWire,
    orig_capture_bootstrap: CaptureBootstrapEventWire,
    orig_capture_perk_apply: CapturePerkApplyEventWire,
    orig_capture_perk_pending: CapturePerkPendingEventWire,
    orig_capture_creature_spawn: CaptureCreatureSpawnEventWire,
    orig_capture_state_transition: CaptureStateTransitionEventWire,

    pub fn msgpackFormat() msgpack.UnionFormat {
        return .{ .as_tagged = .{
            .tag_field = "type",
            .tag_value = .field_name,
        } };
    }
};

const ReplayWire = struct {
    header: ReplayHeaderWire,
    inputs: []const []const ReplayInputWire,
    dt: []const f32 = &.{},
    events: []const ReplayEventWire = &.{},
};

const ReplayTickCurrentWire = struct {
    dt: f32,
    inputs: []const ReplayInputWire,
    commands: []const ReplayCommandCurrentWire = &.{},
};

const ReplayCurrentWire = struct {
    header: ReplayHeaderCurrentWire,
    ticks: []const ReplayTickCurrentWire,
};

const TerrainRule = struct {
    threshold: i32,
};

const terrain_unlock_rules = [_]TerrainRule{
    .{ .threshold = 0x28 },
    .{ .threshold = 0x1E },
    .{ .threshold = 0x14 },
};

const unlock_random_terrain_prelude_callers = [_]rng_callers.Caller{
    rng_callers.terrain_generate_random_prelude_1,
    rng_callers.terrain_generate_random_prelude_2,
    rng_callers.terrain_generate_random_prelude_3,
};

const unlock_random_terrain_stamp_callers = [_][3]rng_callers.Caller{
    .{
        rng_callers.terrain_generate_random_base_rotation,
        rng_callers.terrain_generate_random_base_y,
        rng_callers.terrain_generate_random_base_x,
    },
    .{
        rng_callers.terrain_generate_random_overlay_rotation,
        rng_callers.terrain_generate_random_overlay_y,
        rng_callers.terrain_generate_random_overlay_x,
    },
    .{
        rng_callers.terrain_generate_random_detail_rotation,
        rng_callers.terrain_generate_random_detail_y,
        rng_callers.terrain_generate_random_detail_x,
    },
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

    fn randTagged(self: *Crand, _: rng_callers.Caller) u32 {
        return self.rand();
    }
};

pub fn isGzipPayload(bytes: []const u8) bool {
    if (bytes.len < gzip_magic.len) return false;
    return std.mem.eql(u8, bytes[0..gzip_magic.len], gzip_magic[0..]);
}

pub fn isZstdPayload(bytes: []const u8) bool {
    if (bytes.len < zstd_magic.len) return false;
    return std.mem.eql(u8, bytes[0..zstd_magic.len], zstd_magic[0..]);
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
    }

    return out.toOwnedSlice(allocator) catch return error.OutOfMemory;
}

pub fn inflateZstdPayload(
    allocator: std.mem.Allocator,
    compressed: []const u8,
    max_output_bytes: usize,
) ReplayCodecError![]u8 {
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
        out.appendSlice(allocator, chunk[0..n]) catch return error.OutOfMemory;
    }

    return out.toOwnedSlice(allocator) catch return error.OutOfMemory;
}

pub fn parseReplaySummary(
    allocator: std.mem.Allocator,
    payload: []const u8,
) ReplayCodecError!ReplaySummary {
    if (try tryParseCurrentReplaySummary(allocator, payload)) |summary| {
        return summary;
    }

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

    if (!isSupportedReplayFormatVersion(header.replay_format_version)) {
        return error.UnsupportedReplayFormatVersion;
    }

    try validateInputShape(wire.inputs, header.player_count);
    try validateDtRows(wire.dt, wire.inputs.len);
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
    if (try tryParseCurrentReplay(allocator, payload)) |replay| {
        return replay;
    }

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

    if (!isSupportedReplayFormatVersion(header.replay_format_version)) {
        return error.UnsupportedReplayFormatVersion;
    }

    try validateInputShape(wire.inputs, header.player_count);
    try validateDtRows(wire.dt, wire.inputs.len);

    const inputs = try buildInputs(allocator, wire.inputs);
    errdefer freeInputs(allocator, inputs);

    const dt = try buildDt(allocator, wire.dt, wire.inputs.len);
    errdefer allocator.free(dt);

    const events = try buildEvents(allocator, wire.events, wire.inputs.len);
    errdefer allocator.free(events);

    return .{
        .header = header,
        .inputs = inputs,
        .dt = dt,
        .events = events,
    };
}

pub fn buildSmokeTestReplayPayload(allocator: std.mem.Allocator) ![]u8 {
    // Small canonical replay payload used by ABI/tests that need real msgpack replay bytes
    // without depending on checked-in fixture encodings.
    const usage_counts = [_]u32{0} ** weapon_usage_count;
    const tick0 = [_]ReplayInputWire{
        .{
            .move_x = 0.0,
            .move_y = 0.0,
            .aim_x = 0.0,
            .aim_y = 0.0,
            .flags = 0,
        },
    };
    const tick1 = [_]ReplayInputWire{
        .{
            .move_x = 0.0,
            .move_y = 0.0,
            .aim_x = 0.0,
            .aim_y = 0.0,
            .flags = 0,
        },
    };
    const inputs = [_][]const ReplayInputWire{
        tick0[0..],
        tick1[0..],
    };
    const dt = [_]f32{
        1.0 / 60.0,
        1.0 / 60.0,
    };
    const replay: ReplayWire = .{
        .header = .{
            .game_mode_id = 1,
            .seed = 1,
            .replay_format_version = replay_format_version,
            .quest_level = "",
            .bootstrap_kind = "none",
            .bootstrap_seed = 0,
            .game_version = "0.9.0",
            .tick_rate = 60,
            .difficulty_level = 0,
            .hardcore = false,
            .preserve_bugs = false,
            .detail_preset = 5,
            .gore_disabled = 0,
            .world_size = 1024.0,
            .player_count = 1,
            .status = .{
                .quest_unlock_index = 0,
                .quest_unlock_index_full = 0,
                .weapon_usage_counts = usage_counts[0..],
            },
            .claimed_stats = .{},
            .input_quantization = "f32",
        },
        .inputs = inputs[0..],
        .dt = dt[0..],
        .events = &.{},
    };

    var writer: std.Io.Writer.Allocating = .init(allocator);
    errdefer writer.deinit();
    try msgpack.encode(replay, &writer.writer);
    return writer.toOwnedSlice();
}

pub fn validateReplayBootstrap(header: ReplayHeader) ReplayCodecError!void {
    if (std.mem.eql(u8, header.bootstrap_kind, "none")) {
        return;
    }
    if (!std.mem.eql(u8, header.bootstrap_kind, "terrain_v1")) {
        return error.UnsupportedBootstrapKind;
    }

    var rng: Crand = .{};
    rng.srand(header.bootstrap_seed);
    advanceRandomTerrainPreludeRng(&rng);
    _ = chooseTerrainIds(header.status.quest_unlock_index, &rng);

    const width_i32 = @max(@as(i32, 1), floatToPositiveI32(header.world_size));
    const height_i32 = width_i32;
    advanceTerrainStampingRng(&rng, width_i32, height_i32);

    if (rng.state != header.seed) {
        return error.BootstrapSeedMismatch;
    }
}

fn parseEventSummary(
    wire_events: []const ReplayEventWire,
    input_len: usize,
) ReplayCodecError!ReplayEventSummary {
    var summary: ReplayEventSummary = .{
        .total_count = wire_events.len,
    };
    for (wire_events) |wire_event| {
        const event = try parseReplayEvent(wire_event, input_len);
        switch (event) {
            .perk_pick => summary.perk_pick_count += 1,
            .perk_menu_open => summary.perk_menu_open_count += 1,
            .typo_char, .typo_backspace, .typo_submit => {},
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
                .move_x = normalizeInputValue(wire_input.move_x),
                .move_y = normalizeInputValue(wire_input.move_y),
                .aim_x = normalizeInputValue(wire_input.aim_x),
                .aim_y = normalizeInputValue(wire_input.aim_y),
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

fn buildDt(
    allocator: std.mem.Allocator,
    wire_dt: []const f32,
    input_len: usize,
) ReplayCodecError![]f32 {
    try validateDtRows(wire_dt, input_len);
    const out = allocator.alloc(f32, wire_dt.len) catch return error.OutOfMemory;
    for (wire_dt, 0..) |value, idx| {
        out[idx] = value;
    }
    return out;
}

fn validateCurrentTicks(
    wire_ticks: []const ReplayTickCurrentWire,
    player_count: i32,
) ReplayCodecError!void {
    const expected_players: usize = @intCast(player_count);
    for (wire_ticks) |tick| {
        if (!std.math.isFinite(tick.dt) or tick.dt < 0.0) return error.UnsupportedInputShape;
        if (tick.inputs.len != expected_players) return error.UnsupportedInputShape;
    }
}

fn parseCurrentEventSummary(
    wire_ticks: []const ReplayTickCurrentWire,
    input_len: usize,
) ReplayCodecError!ReplayEventSummary {
    var summary: ReplayEventSummary = .{};
    for (wire_ticks, 0..) |tick, tick_index| {
        for (tick.commands) |command| {
            const event = try parseCurrentCommand(command, tick_index, input_len);
            summary.total_count += 1;
            switch (event) {
                .perk_pick => summary.perk_pick_count += 1,
                .perk_menu_open => summary.perk_menu_open_count += 1,
                .typo_char, .typo_backspace, .typo_submit => {},
                .capture_bootstrap => summary.capture_bootstrap_count += 1,
                .capture_perk_apply => summary.capture_perk_apply_count += 1,
                .capture_perk_pending => summary.capture_perk_pending_count += 1,
                .capture_creature_spawn => summary.capture_creature_spawn_count += 1,
                .capture_state_transition => summary.capture_state_transition_count += 1,
            }
        }
    }
    return summary;
}

fn buildInputsCurrent(
    allocator: std.mem.Allocator,
    wire_ticks: []const ReplayTickCurrentWire,
) ReplayCodecError![]ReplayTickInputs {
    const out = allocator.alloc(ReplayTickInputs, wire_ticks.len) catch return error.OutOfMemory;
    var built: usize = 0;
    errdefer {
        for (0..built) |idx| allocator.free(out[idx]);
        allocator.free(out);
    }

    for (wire_ticks, 0..) |tick, tick_idx| {
        const tick_inputs = allocator.alloc(ReplayPlayerInput, tick.inputs.len) catch return error.OutOfMemory;
        errdefer allocator.free(tick_inputs);
        for (tick.inputs, 0..) |wire_input, player_idx| {
            tick_inputs[player_idx] = .{
                .move_x = normalizeInputValue(wire_input.move_x),
                .move_y = normalizeInputValue(wire_input.move_y),
                .aim_x = normalizeInputValue(wire_input.aim_x),
                .aim_y = normalizeInputValue(wire_input.aim_y),
                .flags = try parseInputFlagsValue(wire_input.flags),
            };
        }
        out[tick_idx] = tick_inputs;
        built += 1;
    }
    return out;
}

fn buildEventsCurrent(
    allocator: std.mem.Allocator,
    wire_ticks: []const ReplayTickCurrentWire,
    input_len: usize,
) ReplayCodecError![]ReplayEvent {
    var total_count: usize = 0;
    for (wire_ticks) |tick| total_count += tick.commands.len;

    const events = allocator.alloc(ReplayEvent, total_count) catch return error.OutOfMemory;
    errdefer allocator.free(events);

    var event_index: usize = 0;
    for (wire_ticks, 0..) |tick, tick_index| {
        for (tick.commands) |command| {
            events[event_index] = try parseCurrentCommand(command, tick_index, input_len);
            event_index += 1;
        }
    }
    return events;
}

fn buildDtCurrent(
    allocator: std.mem.Allocator,
    wire_ticks: []const ReplayTickCurrentWire,
) ReplayCodecError![]f32 {
    const out = allocator.alloc(f32, wire_ticks.len) catch return error.OutOfMemory;
    for (wire_ticks, 0..) |tick, idx| {
        out[idx] = tick.dt;
    }
    return out;
}

fn parseCurrentCommand(
    command: ReplayCommandCurrentWire,
    tick_index: usize,
    input_len: usize,
) ReplayCodecError!ReplayEvent {
    _ = input_len;
    if (std.mem.eql(u8, command.type, "perk_menu_open")) {
        return .{ .perk_menu_open = .{
            .tick_index = tick_index,
            .player_index = command.player_index,
        } };
    }
    if (std.mem.eql(u8, command.type, "perk_pick")) {
        return .{ .perk_pick = .{
            .tick_index = tick_index,
            .player_index = command.player_index,
            .choice_index = command.choice_index orelse return error.UnsupportedEventShape,
        } };
    }
    if (std.mem.eql(u8, command.type, "typo_char")) {
        const raw = command.ch orelse return error.UnsupportedEventShape;
        if (raw.len != 1) return error.UnsupportedEventShape;
        return .{ .typo_char = .{
            .tick_index = tick_index,
            .player_index = command.player_index,
            .ch = raw[0],
        } };
    }
    if (std.mem.eql(u8, command.type, "typo_backspace")) {
        return .{ .typo_backspace = .{
            .tick_index = tick_index,
            .player_index = command.player_index,
        } };
    }
    if (std.mem.eql(u8, command.type, "typo_submit")) {
        return .{ .typo_submit = .{
            .tick_index = tick_index,
            .player_index = command.player_index,
        } };
    }
    return error.UnknownCommandKind;
}

fn validateDtRows(
    wire_dt: []const f32,
    input_len: usize,
) ReplayCodecError!void {
    if (wire_dt.len != input_len) return error.UnsupportedInputShape;
    for (wire_dt) |value| {
        if (!std.math.isFinite(value) or value < 0.0) return error.UnsupportedInputShape;
    }
}

fn freeInputs(allocator: std.mem.Allocator, inputs: []ReplayTickInputs) void {
    for (inputs) |tick| allocator.free(tick);
    allocator.free(inputs);
}

fn parseReplayEvent(
    wire_event: ReplayEventWire,
    input_len: usize,
) ReplayCodecError!ReplayEvent {
    const raw_tick_index = switch (wire_event) {
        .perk_pick => |event| event.tick_index,
        .perk_menu_open => |event| event.tick_index,
        .orig_capture_bootstrap => |event| event.tick_index,
        .orig_capture_perk_apply => |event| event.tick_index,
        .orig_capture_perk_pending => |event| event.tick_index,
        .orig_capture_creature_spawn => |event| event.tick_index,
        .orig_capture_state_transition => |event| event.tick_index,
    };
    if (raw_tick_index < 0) return error.UnsupportedEventShape;

    const tick_index: usize = @intCast(raw_tick_index);
    if (tick_index > input_len) return error.UnsupportedEventShape;

    return switch (wire_event) {
        .perk_pick => |event| blk: {
            if (event.player_index < 0 or event.choice_index < 0) {
                return error.UnsupportedEventShape;
            }
            break :blk .{
                .perk_pick = .{
                    .tick_index = tick_index,
                    .player_index = try parseEventI32(event.player_index),
                    .choice_index = try parseEventI32(event.choice_index),
                },
            };
        },
        .perk_menu_open => |event| blk: {
            if (event.player_index < 0) {
                return error.UnsupportedEventShape;
            }
            break :blk .{
                .perk_menu_open = .{
                    .tick_index = tick_index,
                    .player_index = try parseEventI32(event.player_index),
                },
            };
        },
        .orig_capture_bootstrap => |event| .{
            .capture_bootstrap = try parseCaptureBootstrapEvent(tick_index, event),
        },
        .orig_capture_perk_apply => |event| .{
            .capture_perk_apply = try parseCapturePerkApplyEvent(tick_index, event),
        },
        .orig_capture_perk_pending => |event| .{
            .capture_perk_pending = try parseCapturePerkPendingEvent(tick_index, event),
        },
        .orig_capture_creature_spawn => |event| .{
            .capture_creature_spawn = try parseCaptureCreatureSpawnEvent(tick_index, event),
        },
        .orig_capture_state_transition => |event| .{
            .capture_state_transition = try parseCaptureStateTransitionEvent(tick_index, event),
        },
    };
}

fn parseCaptureBootstrapEvent(
    tick_index: usize,
    payload: CaptureBootstrapEventWire,
) ReplayCodecError!CaptureBootstrapEvent {
    var event: CaptureBootstrapEvent = .{
        .tick_index = tick_index,
    };

    event.elapsed_ms = try parseEventI32(payload.elapsed_ms);
    event.score_xp = try parseEventI32(payload.score_xp);
    event.perk_pending = try parseEventI32(payload.perk_pending);
    event.perk_pending_count = try parseEventI32(payload.perk_pending_count);
    event.perk_choices_dirty = payload.perk_choices_dirty;

    if (payload.perk_choices.len > event.perk_choices.len) {
        return error.UnsupportedEventShape;
    }
    event.perk_choice_count = payload.perk_choices.len;
    for (payload.perk_choices, 0..) |choice_id, idx| {
        event.perk_choices[idx] = try parseEventI32(choice_id);
    }

    const player_perk_count = payload.player_nonzero_counts.len;
    if (player_perk_count > max_players) {
        return error.UnsupportedEventShape;
    }
    for (0..player_perk_count) |player_idx| {
        const raw_pairs = payload.player_nonzero_counts[player_idx];
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

    const player_count = payload.players.len;
    if (player_count > max_players) {
        return error.UnsupportedEventShape;
    }
    event.player_count = player_count;
    for (payload.players, 0..) |player_wire, idx| {
        event.players[idx] = .{
            .weapon_id = try parseEventI32(player_wire.weapon_id),
            .pos_x = player_wire.pos_x,
            .pos_y = player_wire.pos_y,
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
            .aim_x = player_wire.aim_x,
            .aim_y = player_wire.aim_y,
            .aim_heading = player_wire.aim_heading,
            .alt_weapon_id = if (player_wire.alt_weapon_id) |value| try parseEventI32(value) else null,
            .alt_clip_size = if (player_wire.alt_clip_size) |value| try parseEventI32(value) else null,
            .alt_ammo = player_wire.alt_ammo,
            .alt_reload_active = player_wire.alt_reload_active,
            .alt_reload_timer = player_wire.alt_reload_timer,
            .alt_reload_timer_max = player_wire.alt_reload_timer_max,
            .alt_shot_cooldown = player_wire.alt_shot_cooldown,
            .shield_ms = if (player_wire.shield_ms) |value| try parseEventI32(value) else null,
            .fire_bullets_ms = if (player_wire.fire_bullets_ms) |value| try parseEventI32(value) else null,
            .speed_bonus_ms = if (player_wire.speed_bonus_ms) |value| try parseEventI32(value) else null,
            .hot_tempered_timer = player_wire.hot_tempered_timer,
            .man_bomb_timer = player_wire.man_bomb_timer,
            .living_fortress_timer = player_wire.living_fortress_timer,
            .fire_cough_timer = player_wire.fire_cough_timer,
        };
    }

    if (payload.digital_move_enabled_by_player.len > max_players) {
        return error.UnsupportedEventShape;
    }
    for (payload.digital_move_enabled_by_player, 0..) |enabled, idx| {
        event.digital_move_enabled_by_player[idx] = enabled;
    }

    event.weapon_power_up_ms = try parseEventI32(payload.weapon_power_up_ms);
    event.reflex_boost_ms = try parseEventI32(payload.reflex_boost_ms);
    event.energizer_ms = try parseEventI32(payload.energizer_ms);
    event.double_experience_ms = try parseEventI32(payload.double_experience_ms);
    event.freeze_ms = try parseEventI32(payload.freeze_ms);
    event.perk_interval_man_bomb = payload.perk_interval_man_bomb;
    event.perk_interval_fire_cough = payload.perk_interval_fire_cough;
    event.perk_interval_hot_tempered = payload.perk_interval_hot_tempered;
    if (payload.quest_session) |quest_session| {
        const spawn_timeline_ms = quest_session.spawn_timeline_ms orelse return error.UnsupportedEventShape;
        const no_creatures_timer_ms = quest_session.no_creatures_timer_ms orelse return error.UnsupportedEventShape;
        const completion_transition_ms = quest_session.completion_transition_ms orelse return error.UnsupportedEventShape;
        event.quest_session = .{
            .spawn_timeline_ms = spawn_timeline_ms,
            .no_creatures_timer_ms = no_creatures_timer_ms,
            .completion_transition_ms = completion_transition_ms,
        };
    }

    return event;
}

fn parseCapturePerkApplyEvent(
    tick_index: usize,
    payload: CapturePerkApplyEventWire,
) ReplayCodecError!CapturePerkApplyEvent {
    const perk_id = try parseEventI32(payload.perk_id);
    if (perk_id <= 0) return error.UnsupportedEventShape;
    if (payload.pending_before) |value| {
        if (value < 0) return error.UnsupportedEventShape;
    }
    if (payload.pending_after) |value| {
        if (value < 0) return error.UnsupportedEventShape;
    }
    return .{
        .tick_index = tick_index,
        .perk_id = perk_id,
        .outside_before = payload.outside_before,
        .pending_before = if (payload.pending_before) |value|
            try parseEventI32(value)
        else
            null,
        .pending_after = if (payload.pending_after) |value|
            try parseEventI32(value)
        else
            null,
    };
}

fn parseCapturePerkPendingEvent(
    tick_index: usize,
    payload: CapturePerkPendingEventWire,
) ReplayCodecError!CapturePerkPendingEvent {
    const pending = try parseEventI32(payload.perk_pending);
    if (pending < 0) return error.UnsupportedEventShape;
    return .{
        .tick_index = tick_index,
        .perk_pending = pending,
    };
}

fn parseCaptureCreatureSpawnEvent(
    tick_index: usize,
    payload: CaptureCreatureSpawnEventWire,
) ReplayCodecError!CaptureCreatureSpawnEvent {
    var event: CaptureCreatureSpawnEvent = .{
        .tick_index = tick_index,
    };
    if (payload.spawns.len > event.spawns.len) return error.UnsupportedEventShape;
    if (payload.added_head.len > event.added_head.len) return error.UnsupportedEventShape;

    event.spawn_count = payload.spawns.len;
    for (payload.spawns, 0..) |spawn_row, idx| {
        event.spawns[idx] = .{
            .template_id = try parseEventI32(spawn_row.template_id),
            .pos_x = spawn_row.pos_x,
            .pos_y = spawn_row.pos_y,
            .heading = spawn_row.heading,
        };
    }

    event.added_head_count = payload.added_head.len;
    for (payload.added_head, 0..) |row, idx| {
        const has_pos_x = row.pos_x != null;
        const has_pos_y = row.pos_y != null;
        if (has_pos_x != has_pos_y) return error.UnsupportedEventShape;
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
            .has_pos = has_pos_x and has_pos_y,
            .pos_x = row.pos_x orelse 0.0,
            .pos_y = row.pos_y orelse 0.0,
        };
    }

    return event;
}

fn parseCaptureStateTransitionEvent(
    tick_index: usize,
    payload: CaptureStateTransitionEventWire,
) ReplayCodecError!CaptureStateTransitionEvent {
    var event: CaptureStateTransitionEvent = .{
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

fn isSupportedReplayFormatVersion(version: i32) bool {
    return version == legacy_replay_format_version or version == replay_format_version;
}

fn tryParseCurrentReplaySummary(
    allocator: std.mem.Allocator,
    payload: []const u8,
) ReplayCodecError!?ReplaySummary {
    var decoded = msgpack.decodeFromSlice(ReplayCurrentWire, allocator, payload) catch |err| {
        return switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            else => null,
        };
    };
    defer decoded.deinit();

    const wire = decoded.value;
    const header = try buildHeaderCurrent(allocator, wire.header);
    errdefer header.deinit(allocator);
    if (!isSupportedReplayFormatVersion(header.replay_format_version)) {
        return error.UnsupportedReplayFormatVersion;
    }

    const tick_count = wire.ticks.len;
    try validateCurrentTicks(wire.ticks, header.player_count);
    return .{
        .header = header,
        .tick_count = tick_count,
        .events = try parseCurrentEventSummary(wire.ticks, tick_count),
    };
}

fn tryParseCurrentReplay(
    allocator: std.mem.Allocator,
    payload: []const u8,
) ReplayCodecError!?Replay {
    var decoded = msgpack.decodeFromSlice(ReplayCurrentWire, allocator, payload) catch |err| {
        return switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            else => null,
        };
    };
    defer decoded.deinit();

    const wire = decoded.value;
    const header = try buildHeaderCurrent(allocator, wire.header);
    errdefer header.deinit(allocator);
    if (!isSupportedReplayFormatVersion(header.replay_format_version)) {
        return error.UnsupportedReplayFormatVersion;
    }

    try validateCurrentTicks(wire.ticks, header.player_count);
    const inputs = try buildInputsCurrent(allocator, wire.ticks);
    errdefer freeInputs(allocator, inputs);
    const dt = try buildDtCurrent(allocator, wire.ticks);
    errdefer allocator.free(dt);
    const events = try buildEventsCurrent(allocator, wire.ticks, wire.ticks.len);
    errdefer allocator.free(events);

    return .{
        .header = header,
        .inputs = inputs,
        .dt = dt,
        .events = events,
    };
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
    if (!std.mem.eql(u8, wire.input_quantization, "f32")) {
        return error.UnsupportedInputQuantization;
    }

    const game_mode_id = try parseI32(wire.game_mode_id);
    const seed = try parseU32(wire.seed);
    const format_version = try parseI32(wire.replay_format_version);
    const bootstrap_seed = try parseU32(wire.bootstrap_seed);
    const tick_rate = try parseI32(wire.tick_rate);
    const difficulty_level = try parseI32(wire.difficulty_level);
    const detail_preset = try parseI32(wire.detail_preset);
    const gore_disabled = try parseI32(wire.gore_disabled);
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

    const claimed_stats: ReplayClaimedStats = .{
        .complete = wire.claimed_stats.complete,
        .ticks = try parseI32(wire.claimed_stats.ticks),
        .elapsed_ms = try parseI64(wire.claimed_stats.elapsed_ms),
        .score_xp = try parseI64(wire.claimed_stats.score_xp),
        .kills = try parseI32(wire.claimed_stats.kills),
        .most_used_weapon_id = try parseI32(wire.claimed_stats.most_used_weapon_id),
        .shots_fired = try parseI32(wire.claimed_stats.shots_fired),
        .shots_hit = try parseI32(wire.claimed_stats.shots_hit),
    };
    if (claimed_stats.ticks < 0 or
        claimed_stats.elapsed_ms < 0 or
        claimed_stats.score_xp < 0 or
        claimed_stats.kills < 0 or
        claimed_stats.shots_fired < 0 or
        claimed_stats.shots_hit < 0 or
        claimed_stats.shots_hit > claimed_stats.shots_fired)
    {
        return error.InvalidHeaderValue;
    }

    return .{
        .game_mode_id = game_mode_id,
        .seed = seed,
        .replay_format_version = format_version,
        .quest_level = allocator.dupe(u8, wire.quest_level) catch return error.OutOfMemory,
        .typo_dictionary_words = &.{},
        .typo_highscore_names = &.{},
        .bootstrap_kind = allocator.dupe(u8, wire.bootstrap_kind) catch return error.OutOfMemory,
        .bootstrap_seed = bootstrap_seed,
        .game_version = allocator.dupe(u8, wire.game_version) catch return error.OutOfMemory,
        .tick_rate = tick_rate,
        .difficulty_level = difficulty_level,
        .hardcore = wire.hardcore,
        .preserve_bugs = wire.preserve_bugs,
        .detail_preset = detail_preset,
        .gore_disabled = gore_disabled,
        .world_size = wire.world_size,
        .player_count = player_count,
        .status = .{
            .quest_unlock_index = quest_unlock_index,
            .quest_unlock_index_full = quest_unlock_index_full,
            .weapon_usage_counts = usage_counts,
        },
        .claimed_stats = claimed_stats,
        .input_quantization = allocator.dupe(u8, wire.input_quantization) catch return error.OutOfMemory,
    };
}

fn buildHeaderCurrent(
    allocator: std.mem.Allocator,
    wire: ReplayHeaderCurrentWire,
) ReplayCodecError!ReplayHeader {
    const max_world_size_i32_f32: f32 = @floatFromInt(std.math.maxInt(i32));
    if (!std.math.isFinite(wire.world_size) or wire.world_size <= 0.0 or wire.world_size > max_world_size_i32_f32) {
        return error.InvalidHeaderValue;
    }
    if (!std.mem.eql(u8, wire.input_quantization, "f32")) {
        return error.UnsupportedInputQuantization;
    }

    const tick_rate = try parseI32(wire.tick_rate);
    const player_count = try parseI32(wire.player_count);
    const quest_fail_retry_count = try parseI32(wire.quest_fail_retry_count);
    const detail_preset = try parseI32(wire.detail_preset);
    const violence_disabled = try parseI32(wire.violence_disabled);
    const quest_unlock_index = try parseI32(wire.status.quest_unlock_index);
    const quest_unlock_index_full = try parseI32(wire.status.quest_unlock_index_full);

    if (tick_rate <= 0 or player_count <= 0) return error.InvalidHeaderValue;
    if (wire.game_version.len == 0) return error.MissingHeaderField;
    if (wire.status.weapon_usage_counts.len != weapon_usage_count) return error.InvalidHeaderValue;

    var usage_counts: [weapon_usage_count]u32 = [_]u32{0} ** weapon_usage_count;
    for (wire.status.weapon_usage_counts, 0..) |value, idx| {
        usage_counts[idx] = try parseU32(value);
    }

    const claimed_stats: ReplayClaimedStats = .{
        .complete = wire.claimed_stats.complete,
        .ticks = try parseI32(wire.claimed_stats.ticks),
        .elapsed_ms = try parseI64(wire.claimed_stats.elapsed_ms),
        .score_xp = try parseI64(wire.claimed_stats.score_xp),
        .kills = try parseI32(wire.claimed_stats.kills),
        .most_used_weapon_id = try parseI32(wire.claimed_stats.most_used_weapon_id),
        .shots_fired = try parseI32(wire.claimed_stats.shots_fired),
        .shots_hit = try parseI32(wire.claimed_stats.shots_hit),
    };
    if (claimed_stats.ticks < 0 or
        claimed_stats.elapsed_ms < 0 or
        claimed_stats.score_xp < 0 or
        claimed_stats.kills < 0 or
        claimed_stats.shots_fired < 0 or
        claimed_stats.shots_hit < 0 or
        claimed_stats.shots_hit > claimed_stats.shots_fired)
    {
        return error.InvalidHeaderValue;
    }

    const quest_level = if (wire.quest_level) |level|
        std.fmt.allocPrint(allocator, "{d}.{d}", .{ level.major, level.minor }) catch return error.OutOfMemory
    else
        allocator.dupe(u8, "") catch return error.OutOfMemory;
    errdefer allocator.free(quest_level);

    return .{
        .game_mode_id = wire.game_mode_id,
        .seed = wire.seed,
        .replay_format_version = wire.replay_format_version,
        .quest_level = quest_level,
        .typo_dictionary_words = try dupStringSliceList(allocator, wire.typo_dictionary_words),
        .typo_highscore_names = try dupStringSliceList(allocator, wire.typo_highscore_names),
        .bootstrap_kind = allocator.dupe(u8, "none") catch return error.OutOfMemory,
        .bootstrap_seed = 0,
        .game_version = allocator.dupe(u8, wire.game_version) catch return error.OutOfMemory,
        .tick_rate = tick_rate,
        .difficulty_level = quest_fail_retry_count,
        .hardcore = wire.hardcore,
        .preserve_bugs = wire.preserve_bugs,
        .detail_preset = detail_preset,
        .gore_disabled = violence_disabled,
        .world_size = wire.world_size,
        .player_count = player_count,
        .status = .{
            .quest_unlock_index = quest_unlock_index,
            .quest_unlock_index_full = quest_unlock_index_full,
            .weapon_usage_counts = usage_counts,
        },
        .claimed_stats = claimed_stats,
        .input_quantization = allocator.dupe(u8, wire.input_quantization) catch return error.OutOfMemory,
    };
}

fn normalizeInputValue(value: f32) f32 {
    return value;
}

fn parseInputFlagsValue(value: i32) ReplayCodecError!u32 {
    if (value < 0 or value > std.math.maxInt(u32)) return error.UnsupportedInputShape;
    return @intCast(value);
}

fn parseEventI32(value: i32) ReplayCodecError!i32 {
    return value;
}

fn chooseTerrainIds(quest_unlock_index: i32, rng: *Crand) i32 {
    _ = i32;
    for (terrain_unlock_rules) |rule| {
        const caller = switch (rule.threshold) {
            0x28 => rng_callers.unlock_terrain_q4,
            0x1E => rng_callers.unlock_terrain_q3,
            0x14 => rng_callers.unlock_terrain_q2,
            else => unreachable,
        };
        if (quest_unlock_index >= rule.threshold and ((rng.randTagged(caller) & 7) == 3)) {
            return 1;
        }
    }
    return 0;
}

fn advanceRandomTerrainPreludeRng(rng: *Crand) void {
    for (unlock_random_terrain_prelude_callers) |caller| {
        _ = rng.randTagged(caller);
    }
}

fn advanceTerrainStampingRng(rng: *Crand, width: i32, height: i32) void {
    const area = @as(i64, @max(width, 0)) * @as(i64, @max(height, 0));
    const densities = [_]i64{ terrain_density_base, terrain_density_overlay, terrain_density_detail };
    for (unlock_random_terrain_stamp_callers, densities) |callers, density| {
        const count = (area * density) >> terrain_density_shift;
        for (0..@as(usize, @intCast(count))) |_| {
            _ = rng.randTagged(callers[0]);
            _ = rng.randTagged(callers[1]);
            _ = rng.randTagged(callers[2]);
        }
    }
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

fn parseI32(value: i32) ReplayCodecError!i32 {
    return value;
}

fn parseU32(value: u32) ReplayCodecError!u32 {
    return value;
}

fn parseI64(value: i64) ReplayCodecError!i64 {
    return value;
}

test "unpack input flags decodes packed fields" {
    const packed_flags: u32 = fire_down_flag |
        reload_pressed_flag |
        reload_down_flag |
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
    try std.testing.expect(decoded.reload_down);
    try std.testing.expectEqual(@as(?i32, 3), decoded.move_mode);
    try std.testing.expectEqual(@as(?i32, -1), decoded.aim_scheme);
    try std.testing.expect(decoded.move_forward_pressed != null and decoded.move_forward_pressed.?);
    try std.testing.expect(decoded.move_backward_pressed != null and !decoded.move_backward_pressed.?);
    try std.testing.expect(decoded.turn_left_pressed != null and decoded.turn_left_pressed.?);
    try std.testing.expect(decoded.turn_right_pressed != null and !decoded.turn_right_pressed.?);
}

test "validate terrain bootstrap matches known latest survival header" {
    const allocator = std.testing.allocator;
    const header: ReplayHeader = .{
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
        .gore_disabled = 0,
        .world_size = 1024.0,
        .player_count = 1,
        .status = .{
            .quest_unlock_index = 49,
            .quest_unlock_index_full = 0,
            .weapon_usage_counts = [_]u32{0} ** weapon_usage_count,
        },
        .input_quantization = try allocator.dupe(u8, "f32"),
    };
    defer header.deinit(allocator);

    try validateReplayBootstrap(header);
}

test "bootstrap mismatch is rejected" {
    const allocator = std.testing.allocator;
    const header: ReplayHeader = .{
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
        .gore_disabled = 0,
        .world_size = 1024.0,
        .player_count = 1,
        .status = .{
            .quest_unlock_index = 0,
            .quest_unlock_index_full = 0,
            .weapon_usage_counts = [_]u32{0} ** weapon_usage_count,
        },
        .input_quantization = try allocator.dupe(u8, "f32"),
    };
    defer header.deinit(allocator);

    try std.testing.expectError(error.BootstrapSeedMismatch, validateReplayBootstrap(header));
}

test "parse replay event supports capture payload kinds" {
    const empty_pairs: [0][]const i32 = .{};
    const player_nonzero_counts = [_][]const []const i32{empty_pairs[0..]};
    const bootstrap_players = [_]CaptureBootstrapPlayerWire{
        .{
            .weapon_id = 1,
            .pos_x = 512.0,
            .pos_y = 512.0,
            .health = 100.0,
            .ammo = 11.0,
            .experience = 0,
            .level = 1,
            .clip_size = null,
            .reload_active = null,
            .reload_timer = null,
            .reload_timer_max = null,
            .shot_cooldown = null,
            .spread_heat = null,
            .aim_x = null,
            .aim_y = null,
            .aim_heading = null,
            .alt_weapon_id = null,
            .alt_clip_size = null,
            .alt_ammo = null,
            .alt_reload_active = null,
            .alt_reload_timer = null,
            .alt_reload_timer_max = null,
            .alt_shot_cooldown = null,
            .shield_ms = null,
            .fire_bullets_ms = null,
            .speed_bonus_ms = null,
            .hot_tempered_timer = null,
            .man_bomb_timer = null,
            .living_fortress_timer = null,
            .fire_cough_timer = null,
        },
    };
    const spawn_rows = [_]CaptureCreatureSpawnRowWire{
        .{
            .template_id = 0x12,
            .pos_x = 512.0,
            .pos_y = 512.0,
            .heading = 0.0,
        },
    };
    const transitions = [_]CaptureStateTransitionRowWire{
        .{
            .target_state = 12,
            .before_state = 9,
            .after_state = 12,
        },
    };

    const wire_events = [_]ReplayEventWire{
        .{ .orig_capture_bootstrap = .{
            .tick_index = 0,
            .elapsed_ms = 0,
            .score_xp = 0,
            .perk_pending = 0,
            .perk_pending_count = 0,
            .perk_choices_dirty = false,
            .perk_choices = &.{},
            .player_nonzero_counts = player_nonzero_counts[0..],
            .players = bootstrap_players[0..],
            .digital_move_enabled_by_player = &.{false},
            .weapon_power_up_ms = 0,
            .reflex_boost_ms = 0,
            .energizer_ms = 0,
            .double_experience_ms = 0,
            .freeze_ms = 0,
            .perk_interval_man_bomb = null,
            .perk_interval_fire_cough = null,
            .perk_interval_hot_tempered = null,
            .quest_session = null,
        } },
        .{ .orig_capture_perk_apply = .{
            .tick_index = 0,
            .perk_id = 44,
            .outside_before = true,
            .pending_before = null,
            .pending_after = null,
        } },
        .{ .orig_capture_perk_pending = .{
            .tick_index = 0,
            .perk_pending = 2,
        } },
        .{ .orig_capture_creature_spawn = .{
            .tick_index = 0,
            .spawns = spawn_rows[0..],
            .added_head = &.{},
        } },
        .{ .orig_capture_state_transition = .{
            .tick_index = 0,
            .transitions = transitions[0..],
        } },
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

test "parse replay event rejects invalid perk pick indexes" {
    const wire: ReplayEventWire = .{
        .perk_pick = .{
            .tick_index = 0,
            .player_index = -1,
            .choice_index = 0,
        },
    };
    try std.testing.expectError(error.UnsupportedEventShape, parseReplayEvent(wire, 1));
}

test "inflate zstd payload consumes replay fixture through eof" {
    const compressed = @embedFile("../../tests/fixtures/replays/quest_1.5_20260303_211620_completed_t40512.crd");
    const inflated = try inflateZstdPayload(std.testing.allocator, compressed, max_replay_payload_bytes);
    defer std.testing.allocator.free(inflated);

    try std.testing.expectEqual(@as(usize, 191445), inflated.len);
    try std.testing.expectEqualSlices(u8, &.{ 0x82, 0xa6, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72 }, inflated[0..8]);
}

test "inflate zstd payload enforces max output size" {
    const compressed = @embedFile("../../tests/fixtures/replays/quest_1.5_20260303_211620_completed_t40512.crd");
    try std.testing.expectError(
        error.PayloadTooLarge,
        inflateZstdPayload(std.testing.allocator, compressed, 1024),
    );
}

test "parse current replay preserves typo metadata and commands" {
    const allocator = std.testing.allocator;

    const tick_inputs = [_]ReplayInputWire{
        .{
            .move_x = 0.0,
            .move_y = 0.0,
            .aim_x = 0.0,
            .aim_y = 0.0,
            .flags = 0,
        },
    };
    const ticks = [_]ReplayTickCurrentWire{
        .{
            .dt = 1.0 / 60.0,
            .inputs = tick_inputs[0..],
            .commands = &.{
                .{
                    .type = "typo_char",
                    .player_index = 0,
                    .ch = "a",
                },
                .{
                    .type = "typo_submit",
                    .player_index = 0,
                },
            },
        },
    };

    const wire: ReplayCurrentWire = .{
        .header = .{
            .game_mode_id = @intFromEnum(game_ids.GameModeId.typo),
            .seed = 7,
            .replay_format_version = replay_format_version,
            .typo_dictionary_words = &.{ "amber", "basil" },
            .typo_highscore_names = &.{"ALPHA"},
            .game_version = "0.9.0",
            .tick_rate = 60,
            .player_count = 1,
            .status = .{
                .weapon_usage_counts = &([_]u32{0} ** weapon_usage_count),
            },
            .claimed_stats = .{},
            .input_quantization = "f32",
        },
        .ticks = ticks[0..],
    };

    var writer: std.Io.Writer.Allocating = .init(allocator);
    defer writer.deinit();
    try msgpack.encode(wire, &writer.writer);

    const replay = try parseReplay(allocator, writer.written());
    defer replay.deinit(allocator);

    try std.testing.expectEqual(@as(i32, @intFromEnum(game_ids.GameModeId.typo)), replay.header.game_mode_id);
    try std.testing.expectEqualStrings("amber", replay.header.typo_dictionary_words[0]);
    try std.testing.expectEqualStrings("ALPHA", replay.header.typo_highscore_names[0]);
    try std.testing.expectEqual(@as(usize, 2), replay.events.len);
    try std.testing.expect(replay.events[0] == .typo_char);
    try std.testing.expectEqual(@as(u8, 'a'), replay.events[0].typo_char.ch);
    try std.testing.expect(replay.events[1] == .typo_submit);
}

test "build header rejects world_size above i32 range" {
    const usage_counts = [_]u32{0} ** weapon_usage_count;
    const too_large_world_size: f32 = @as(f32, @floatFromInt(std.math.maxInt(i32))) + 1024.0;
    const wire: ReplayHeaderWire = .{
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
        .gore_disabled = 0,
        .world_size = too_large_world_size,
        .player_count = 1,
        .status = .{
            .quest_unlock_index = 0,
            .quest_unlock_index_full = 0,
            .weapon_usage_counts = usage_counts[0..],
        },
        .claimed_stats = .{},
        .input_quantization = "f32",
    };
    try std.testing.expectError(error.InvalidHeaderValue, buildHeader(std.testing.allocator, wire));
}

test "build header parses claimed stats snapshot" {
    const usage_counts = [_]u32{0} ** weapon_usage_count;
    const wire: ReplayHeaderWire = .{
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
        .gore_disabled = 0,
        .world_size = 1024.0,
        .player_count = 1,
        .status = .{
            .quest_unlock_index = 0,
            .quest_unlock_index_full = 0,
            .weapon_usage_counts = usage_counts[0..],
        },
        .claimed_stats = .{
            .complete = true,
            .ticks = 12,
            .elapsed_ms = 200,
            .score_xp = 1234,
            .kills = 56,
            .most_used_weapon_id = 7,
            .shots_fired = 10,
            .shots_hit = 8,
        },
        .input_quantization = "f32",
    };
    const header = try buildHeader(std.testing.allocator, wire);
    defer header.deinit(std.testing.allocator);

    const claimed = header.claimed_stats;
    try std.testing.expect(claimed.complete);
    try std.testing.expectEqual(@as(i32, 12), claimed.ticks);
    try std.testing.expectEqual(@as(i64, 200), claimed.elapsed_ms);
    try std.testing.expectEqual(@as(i64, 1234), claimed.score_xp);
    try std.testing.expectEqual(@as(i32, 56), claimed.kills);
    try std.testing.expectEqual(@as(i32, 7), claimed.most_used_weapon_id);
    try std.testing.expectEqual(@as(i32, 10), claimed.shots_fired);
    try std.testing.expectEqual(@as(i32, 8), claimed.shots_hit);
}

test "build header rejects invalid claimed stats snapshot" {
    const usage_counts = [_]u32{0} ** weapon_usage_count;
    const wire: ReplayHeaderWire = .{
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
        .gore_disabled = 0,
        .world_size = 1024.0,
        .player_count = 1,
        .status = .{
            .quest_unlock_index = 0,
            .quest_unlock_index_full = 0,
            .weapon_usage_counts = usage_counts[0..],
        },
        .claimed_stats = .{
            .complete = false,
            .ticks = 1,
            .elapsed_ms = 16,
            .score_xp = 0,
            .kills = 0,
            .most_used_weapon_id = 1,
            .shots_fired = 1,
            .shots_hit = 2,
        },
        .input_quantization = "f32",
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
    try std.testing.expectError(error.UnsupportedInputShape, buildInputs(std.testing.allocator, wire_inputs[0..]));
}

test "build events frees allocation on parse error" {
    const wire_events = [_]ReplayEventWire{
        .{ .perk_pick = .{
            .tick_index = -1,
            .player_index = 0,
            .choice_index = 0,
        } },
    };
    try std.testing.expectError(error.UnsupportedEventShape, buildEvents(std.testing.allocator, wire_events[0..], 1));
}

test "parse replay decode errors preserve oom and map invalid msgpack" {
    const empty_payload: [0]u8 = .{};

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

test "binary bytes reader accepts msgpack bin8 payloads" {
    const payload = [_]u8{ 0xC4, 0x04, 0xDE, 0xAD, 0xBE, 0xEF };
    var decoded = try msgpack.decodeFromSlice(BinaryBytes, std.testing.allocator, &payload);
    defer decoded.deinit();

    try std.testing.expectEqualSlices(u8, &.{ 0xDE, 0xAD, 0xBE, 0xEF }, decoded.value.data);
}

test "capture bootstrap rejects perk nonzero counts above max players" {
    const empty_pairs: [0][]const i32 = .{};
    const player_nonzero_counts = [_][]const []const i32{empty_pairs[0..]} ** (max_players + 1);
    const wire: ReplayEventWire = .{
        .orig_capture_bootstrap = .{
            .tick_index = 0,
            .elapsed_ms = 0,
            .score_xp = 0,
            .perk_pending = 0,
            .perk_pending_count = 0,
            .perk_choices_dirty = false,
            .perk_choices = &.{},
            .player_nonzero_counts = player_nonzero_counts[0..],
            .players = &.{},
            .digital_move_enabled_by_player = &.{},
            .weapon_power_up_ms = 0,
            .reflex_boost_ms = 0,
            .energizer_ms = 0,
            .double_experience_ms = 0,
            .freeze_ms = 0,
            .perk_interval_man_bomb = null,
            .perk_interval_fire_cough = null,
            .perk_interval_hot_tempered = null,
            .quest_session = null,
        },
    };
    try std.testing.expectError(error.UnsupportedEventShape, parseReplayEvent(wire, 1));
}

test "capture bootstrap rejects players above max players" {
    const player: CaptureBootstrapPlayerWire = .{
        .weapon_id = 1,
        .pos_x = 0.0,
        .pos_y = 0.0,
        .health = 100.0,
        .ammo = 0.0,
        .experience = 0,
        .level = 1,
        .clip_size = null,
        .reload_active = null,
        .reload_timer = null,
        .reload_timer_max = null,
        .shot_cooldown = null,
        .spread_heat = null,
        .aim_x = null,
        .aim_y = null,
        .aim_heading = null,
        .alt_weapon_id = null,
        .alt_clip_size = null,
        .alt_ammo = null,
        .alt_reload_active = null,
        .alt_reload_timer = null,
        .alt_reload_timer_max = null,
        .alt_shot_cooldown = null,
        .shield_ms = null,
        .fire_bullets_ms = null,
        .speed_bonus_ms = null,
        .hot_tempered_timer = null,
        .man_bomb_timer = null,
        .living_fortress_timer = null,
        .fire_cough_timer = null,
    };
    const players = [_]CaptureBootstrapPlayerWire{player} ** (max_players + 1);
    const empty_pairs: [0][]const i32 = .{};
    const player_nonzero_counts = [_][]const []const i32{empty_pairs[0..]} ** (max_players + 1);
    const wire: ReplayEventWire = .{
        .orig_capture_bootstrap = .{
            .tick_index = 0,
            .elapsed_ms = 0,
            .score_xp = 0,
            .perk_pending = 0,
            .perk_pending_count = 0,
            .perk_choices_dirty = false,
            .perk_choices = &.{},
            .player_nonzero_counts = player_nonzero_counts[0..],
            .players = players[0..],
            .digital_move_enabled_by_player = &.{},
            .weapon_power_up_ms = 0,
            .reflex_boost_ms = 0,
            .energizer_ms = 0,
            .double_experience_ms = 0,
            .freeze_ms = 0,
            .perk_interval_man_bomb = null,
            .perk_interval_fire_cough = null,
            .perk_interval_hot_tempered = null,
            .quest_session = null,
        },
    };
    try std.testing.expectError(error.UnsupportedEventShape, parseReplayEvent(wire, 1));
}

test "capture bootstrap rejects digital move flags above max players" {
    const digital_move_enabled_by_player = [_]bool{false} ** (max_players + 1);
    const empty_pairs: [0][]const i32 = .{};
    const player_nonzero_counts = [_][]const []const i32{empty_pairs[0..]};
    const wire: ReplayEventWire = .{
        .orig_capture_bootstrap = .{
            .tick_index = 0,
            .elapsed_ms = 0,
            .score_xp = 0,
            .perk_pending = 0,
            .perk_pending_count = 0,
            .perk_choices_dirty = false,
            .perk_choices = &.{},
            .player_nonzero_counts = player_nonzero_counts[0..],
            .players = &.{},
            .digital_move_enabled_by_player = digital_move_enabled_by_player[0..],
            .weapon_power_up_ms = 0,
            .reflex_boost_ms = 0,
            .energizer_ms = 0,
            .double_experience_ms = 0,
            .freeze_ms = 0,
            .perk_interval_man_bomb = null,
            .perk_interval_fire_cough = null,
            .perk_interval_hot_tempered = null,
            .quest_session = null,
        },
    };
    try std.testing.expectError(error.UnsupportedEventShape, parseReplayEvent(wire, 1));
}
