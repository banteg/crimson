const std = @import("std");
const msgpack = @import("msgpack");
const game_ids = @import("game_ids.zig");

pub const replay_format_version: i32 = 16;
pub const weapon_usage_count: usize = 53;
pub const quest_play_count: usize = 91;
pub const status_unknown_tail_size: usize = 16;
pub const max_players: usize = 4;
pub const perk_choice_slot_count: usize = 7;
pub const zstd_magic = [_]u8{ 0x28, 0xB5, 0x2F, 0xFD };
pub const max_replay_payload_bytes: usize = 64 * 1024 * 1024;
pub const max_replay_file_bytes: usize = 65 * 1024 * 1024;
const canonical_tick_dt_f64: f64 = @as(f32, 1.0 / 60.0);
pub const latest_ruleset_game_version_prefixes = [_][]const u8{
    "0.9.",
    "0.10.",
};
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
const supported_input_flags_mask: u32 = fire_down_flag |
    fire_pressed_flag |
    reload_pressed_flag |
    reload_down_flag |
    move_keys_present_flag |
    move_forward_flag |
    move_backward_flag |
    turn_left_flag |
    turn_right_flag |
    move_mode_present_flag |
    (move_mode_mask << move_mode_shift) |
    aim_scheme_present_flag |
    (aim_scheme_mask << aim_scheme_shift);

pub const ReplayCodecError = error{
    InvalidMsgpack,
    InvalidHeaderValue,
    InvalidClaimedStats,
    MissingHeaderField,
    MissingQuestLevel,
    TypoMultiplayer,
    TutorialMultiplayer,
    UnsupportedGameMode,
    UnsupportedReplayFormatVersion,
    UnsupportedInputShape,
    UnsupportedEventShape,
    UnsupportedEventKind,
    UnknownCommandKind,
    UnsupportedInputQuantization,
    InvalidZstdPayload,
    PayloadTooLarge,
    OutOfMemory,
};

pub const ReplayStatus = struct {
    quest_unlock_index: i32 = 0,
    quest_unlock_index_full: i32 = 0,
    weapon_usage_counts: [weapon_usage_count]u32 = [_]u32{0} ** weapon_usage_count,
    quest_play_counts: [quest_play_count]u32 = [_]u32{0} ** quest_play_count,
    mode_play_survival: i32 = 0,
    mode_play_rush: i32 = 0,
    mode_play_typo: i32 = 0,
    mode_play_other: i32 = 0,
    game_sequence_id: i32 = 0,
    unknown_tail: [status_unknown_tail_size]u8 = [_]u8{0} ** status_unknown_tail_size,

    pub fn msgpackWrite(self: ReplayStatus, packer: anytype) !void {
        try packer.writeMapHeader(10);
        try packer.writeString("quest_unlock_index");
        try packer.writeInt(self.quest_unlock_index);
        try packer.writeString("quest_unlock_index_full");
        try packer.writeInt(self.quest_unlock_index_full);
        try packer.writeString("weapon_usage_counts");
        try packer.writeArray(u32, self.weapon_usage_counts[0..]);
        try packer.writeString("quest_play_counts");
        try packer.writeArray(u32, self.quest_play_counts[0..]);
        try packer.writeString("mode_play_survival");
        try packer.writeInt(self.mode_play_survival);
        try packer.writeString("mode_play_rush");
        try packer.writeInt(self.mode_play_rush);
        try packer.writeString("mode_play_typo");
        try packer.writeInt(self.mode_play_typo);
        try packer.writeString("mode_play_other");
        try packer.writeInt(self.mode_play_other);
        try packer.writeString("game_sequence_id");
        try packer.writeInt(self.game_sequence_id);
        try packer.writeString("unknown_tail");
        try packer.writeBinary(self.unknown_tail[0..]);
    }
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
    game_version: []u8,
    tick_rate: i32,
    quest_fail_retry_count: i32,
    hardcore: bool,
    preserve_bugs: bool,
    detail_preset: i32,
    violence_disabled: i32,
    world_size: f32,
    player_count: i32,
    status: ReplayStatus,
    claimed_stats: ReplayClaimedStats = .{},
    input_quantization: []u8,
    // Preserve the v15 wire distinction: null means no captured residue,
    // while an empty array is an explicit captured empty pool.
    initial_creature_pool: ?[]const ReplayCreatureSlotResidue = null,

    pub fn deinit(self: ReplayHeader, allocator: std.mem.Allocator) void {
        allocator.free(self.quest_level);
        freeStringSliceList(allocator, self.typo_dictionary_words);
        freeStringSliceList(allocator, self.typo_highscore_names);
        allocator.free(self.game_version);
        allocator.free(self.input_quantization);
        if (self.initial_creature_pool) |pool| {
            if (pool.len > 0) allocator.free(pool);
        }
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
    for (latest_ruleset_game_version_prefixes) |prefix| {
        if (std.mem.startsWith(u8, game_version, prefix)) return true;
    }
    return false;
}

pub const ReplayToolKind = enum {
    verifier,
    replay_list,
    replay_info,
    benchmark,
};

pub fn unsupportedReplayHeaderDetail(
    header: ReplayHeader,
    tick_count: usize,
    tool_kind: ReplayToolKind,
) ?[]const u8 {
    if (header.game_mode_id != 1 and header.game_mode_id != 2 and header.game_mode_id != 3 and header.game_mode_id != 4 and header.game_mode_id != 8) {
        return "native replay tools support only survival/rush/quest/typo/tutorial modes";
    }
    if (header.game_mode_id == @intFromEnum(game_ids.GameModeId.typo) and header.player_count != 1) {
        return "Typ-o replays require player_count == 1";
    }
    if (header.game_mode_id == @intFromEnum(game_ids.GameModeId.tutorial) and header.player_count != 1) {
        return "tutorial replays require player_count == 1";
    }
    if (isMissingQuestLevel(header.game_mode_id, header.quest_level)) {
        return "quest replays require a valid header.quest_level";
    }
    if (header.player_count < 1 or header.player_count > 4) {
        return "native replay tools support only 1-4 player replays";
    }
    if (!std.mem.eql(u8, header.input_quantization, "f32")) {
        return "native replay tools support only f32 input quantization";
    }
    if (tick_count > std.math.maxInt(i32)) {
        return switch (tool_kind) {
            .verifier => "replay has too many ticks for current native verifier",
            .replay_list => "replay has too many ticks for current native replay list",
            .replay_info => "replay has too many ticks for current native replay info",
            .benchmark => "replay has too many ticks for current native benchmark",
        };
    }
    if (!header.preserve_bugs and !isLatestRulesetGameVersion(header.game_version)) {
        return "native replay tools require latest ruleset replays unless preserve_bugs is set";
    }
    return null;
}

fn isMissingQuestLevel(game_mode_id: i32, quest_level: []const u8) bool {
    return game_mode_id == @intFromEnum(game_ids.GameModeId.quests) and
        std.mem.trim(u8, quest_level, " \t\r\n").len == 0;
}

fn validateModePlayerCount(game_mode_id: i32, player_count: i32) ReplayCodecError!void {
    const game_mode = std.enums.fromInt(game_ids.GameModeId, game_mode_id) orelse return error.UnsupportedGameMode;
    switch (game_mode) {
        .typo => if (player_count != 1) return error.TypoMultiplayer,
        .tutorial => if (player_count != 1) return error.TutorialMultiplayer,
        .survival, .rush, .quests => {},
    }
}

fn validateClaimedStats(claimed_stats: ReplayClaimedStats) ReplayCodecError!void {
    if (claimed_stats.ticks < 0 or
        claimed_stats.elapsed_ms < 0 or
        claimed_stats.score_xp < 0 or
        claimed_stats.kills < 0 or
        std.enums.fromInt(game_ids.WeaponId, claimed_stats.most_used_weapon_id) == null or
        claimed_stats.shots_fired < 0 or
        claimed_stats.shots_hit < 0)
    {
        return error.InvalidHeaderValue;
    }
    if (claimed_stats.shots_hit > claimed_stats.shots_fired) {
        return error.InvalidClaimedStats;
    }
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

pub const GameFrameRngAdvancePrelude = struct {
    tick_index: usize,
    frames: u32,
};

pub const PerkMenuOpenPrelude = struct {
    tick_index: usize,
    player_index: i32,
};

pub const PerkPickPrelude = struct {
    tick_index: usize,
    player_index: i32,
    choice_index: i32,
};

pub const ReplayPreludeOp = union(enum) {
    game_frame_rng_advance: GameFrameRngAdvancePrelude,
    perk_menu_open: PerkMenuOpenPrelude,
    perk_pick: PerkPickPrelude,

    pub fn tickIndex(self: ReplayPreludeOp) usize {
        return switch (self) {
            inline else => |op| op.tick_index,
        };
    }
};

pub const ReplayPostludeOp = struct {
    tick_index: usize,
    player_index: i32,

    pub fn tickIndex(self: ReplayPostludeOp) usize {
        return self.tick_index;
    }
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

pub fn replayEventPlayerIndexFailureDetail(
    allocator: std.mem.Allocator,
    player_count: i32,
    events: []const ReplayEvent,
) !?[]u8 {
    for (events) |event| {
        const player_index = replayEventPlayerIndex(event) orelse continue;
        if (player_index < 0 or player_index >= player_count) {
            const detail = try std.fmt.allocPrint(
                allocator,
                "replay event player_index out of range: {d} (player_count={d}, tick={d}, event={s})",
                .{ player_index, player_count, event.tickIndex(), replayEventKindName(event) },
            );
            return detail;
        }
    }
    return null;
}

pub fn replayEventOrderingFailureDetail(
    allocator: std.mem.Allocator,
    events: []const ReplayEvent,
) !?[]u8 {
    var previous_tick: ?usize = null;
    for (events, 0..) |event, event_index| {
        const tick_index = event.tickIndex();
        if (previous_tick) |prev_tick| {
            if (tick_index < prev_tick) {
                const detail = try std.fmt.allocPrint(
                    allocator,
                    "replay events are not ordered in canonical tick order: tick={d} follows tick={d} (event_index={d}, event={s})",
                    .{ tick_index, prev_tick, event_index, replayEventKindName(event) },
                );
                return detail;
            }
        }
        previous_tick = tick_index;
    }
    return null;
}

pub fn replayEventKindFailureDetail(
    allocator: std.mem.Allocator,
    game_mode_id: i32,
    events: []const ReplayEvent,
) !?[]u8 {
    const game_mode = std.enums.fromInt(game_ids.GameModeId, game_mode_id) orelse return null;
    for (events, 0..) |event, event_index| {
        if (replayEventKindAllowedInMode(event, game_mode)) continue;
        const detail = try std.fmt.allocPrint(
            allocator,
            "replay event kind invalid for game mode: event={s} tick={d} event_index={d} game_mode={s}",
            .{ replayEventKindName(event), event.tickIndex(), event_index, @tagName(game_mode) },
        );
        return detail;
    }
    return null;
}

pub fn replayInputShapeFailureDetail(
    allocator: std.mem.Allocator,
    payload: []const u8,
) ReplayCodecError!?[]u8 {
    return currentReplayInputShapeFailureDetail(allocator, payload);
}

pub fn replayEventShapeFailureDetail(
    allocator: std.mem.Allocator,
    payload: []const u8,
) ReplayCodecError!?[]u8 {
    return currentReplayEventShapeFailureDetail(allocator, payload);
}

pub fn replayUnknownCommandFailureDetail(
    allocator: std.mem.Allocator,
    payload: []const u8,
) ReplayCodecError!?[]u8 {
    var decoded = msgpack.decodeFromSlice(ReplayCurrentWire, allocator, payload) catch |err| {
        return switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            else => null,
        };
    };
    defer decoded.deinit();

    for (decoded.value.ticks, 0..) |tick, tick_index| {
        for (tick.commands, 0..) |command, command_index| {
            if (currentCommandKindKnown(command.type)) continue;
            return std.fmt.allocPrint(
                allocator,
                "replay command type is unknown: type={s} tick={d} command_index={d}",
                .{ command.type, tick_index, command_index },
            ) catch return error.OutOfMemory;
        }
    }

    return null;
}

pub fn replayCommandKindFailureDetail(
    allocator: std.mem.Allocator,
    payload: []const u8,
) ReplayCodecError!?[]u8 {
    var decoded = msgpack.decodeFromSlice(ReplayCurrentWire, allocator, payload) catch |err| {
        return switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            else => null,
        };
    };
    defer decoded.deinit();

    const game_mode = std.enums.fromInt(game_ids.GameModeId, decoded.value.header.game_mode_id) orelse return null;
    for (decoded.value.ticks, 0..) |tick, tick_index| {
        for (tick.commands, 0..) |command, command_index| {
            if (!currentCommandKindKnown(command.type)) {
                return std.fmt.allocPrint(
                    allocator,
                    "replay command type is unknown: type={s} tick={d} command_index={d}",
                    .{ command.type, tick_index, command_index },
                ) catch return error.OutOfMemory;
            }
            if (game_mode == .typo) continue;
            return std.fmt.allocPrint(
                allocator,
                "replay command invalid for game mode: type={s} tick={d} command_index={d} game_mode={s}",
                .{ command.type, tick_index, command_index, @tagName(game_mode) },
            ) catch return error.OutOfMemory;
        }
    }
    return null;
}

fn replayEventKindAllowedInMode(event: ReplayEvent, game_mode: game_ids.GameModeId) bool {
    return switch (event) {
        .typo_char,
        .typo_backspace,
        .typo_submit,
        => game_mode == .typo,
        .capture_perk_apply,
        .capture_perk_pending,
        => game_mode != .rush,
        .perk_pick,
        .perk_menu_open,
        .capture_bootstrap,
        .capture_creature_spawn,
        .capture_state_transition,
        => true,
    };
}

fn replayEventPlayerIndex(event: ReplayEvent) ?i32 {
    return switch (event) {
        .perk_pick => |payload| payload.player_index,
        .perk_menu_open => |payload| payload.player_index,
        .typo_char => |payload| payload.player_index,
        .typo_backspace => |payload| payload.player_index,
        .typo_submit => |payload| payload.player_index,
        .capture_bootstrap,
        .capture_perk_apply,
        .capture_perk_pending,
        .capture_creature_spawn,
        .capture_state_transition,
        => null,
    };
}

fn replayEventKindName(event: ReplayEvent) []const u8 {
    return switch (event) {
        .perk_pick => "perk_pick",
        .perk_menu_open => "perk_menu_open",
        .typo_char => "typo_char",
        .typo_backspace => "typo_backspace",
        .typo_submit => "typo_submit",
        .capture_bootstrap => "capture_bootstrap",
        .capture_perk_apply => "capture_perk_apply",
        .capture_perk_pending => "capture_perk_pending",
        .capture_creature_spawn => "capture_creature_spawn",
        .capture_state_transition => "capture_state_transition",
    };
}

pub const ReplayEventSummary = struct {
    total_count: usize = 0,
    game_frame_rng_advance_count: usize = 0,
    perk_menu_open_count: usize = 0,
    perk_pick_count: usize = 0,
    typo_char_count: usize = 0,
    typo_backspace_count: usize = 0,
    typo_submit_count: usize = 0,
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
    prelude: []ReplayPreludeOp = &.{},
    postlude: []ReplayPostludeOp = &.{},
    events: []ReplayEvent,

    pub fn deinit(self: Replay, allocator: std.mem.Allocator) void {
        self.header.deinit(allocator);
        for (self.inputs) |tick| allocator.free(tick);
        allocator.free(self.inputs);
        allocator.free(self.dt);
        if (self.prelude.len > 0) allocator.free(self.prelude);
        if (self.postlude.len > 0) allocator.free(self.postlude);
        allocator.free(self.events);
    }

    pub fn tickCount(self: Replay) usize {
        return self.inputs.len;
    }

    pub fn summarizeEvents(self: Replay) ReplayEventSummary {
        var summary: ReplayEventSummary = .{
            .total_count = self.prelude.len + self.postlude.len + self.events.len,
        };
        for (self.prelude) |op| countReplayPrelude(&summary, op);
        summary.perk_menu_open_count += self.postlude.len;
        for (self.events) |event| {
            countReplayEvent(&summary, event);
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

pub const ReplayStatusCurrentWire = struct {
    quest_unlock_index: i32 = 0,
    quest_unlock_index_full: i32 = 0,
    weapon_usage_counts: []const u32 = &.{},
    quest_play_counts: []const u32 = &([_]u32{0} ** quest_play_count),
    mode_play_survival: i32 = 0,
    mode_play_rush: i32 = 0,
    mode_play_typo: i32 = 0,
    mode_play_other: i32 = 0,
    game_sequence_id: i32 = 0,
    unknown_tail: BinaryBytes = .{ .data = &([_]u8{0} ** status_unknown_tail_size) },

    pub fn msgpackRead(unpacker: anytype) !ReplayStatusCurrentWire {
        const field_count = try unpacker.readMapHeader(u16);
        if (field_count != 10) return error.InvalidFormat;
        var field_name_buf: [64]u8 = undefined;
        var status: ReplayStatusCurrentWire = .{};
        var fields_seen: u16 = 0;

        for (0..field_count) |_| {
            const field_name = try unpacker.readStringInto(&field_name_buf);
            if (std.mem.eql(u8, field_name, "quest_unlock_index")) {
                fields_seen |= 1 << 0;
                status.quest_unlock_index = try unpacker.readInt(i32);
            } else if (std.mem.eql(u8, field_name, "quest_unlock_index_full")) {
                fields_seen |= 1 << 1;
                status.quest_unlock_index_full = try unpacker.readInt(i32);
            } else if (std.mem.eql(u8, field_name, "weapon_usage_counts")) {
                fields_seen |= 1 << 2;
                status.weapon_usage_counts = try readExactU32Array(unpacker);
            } else if (std.mem.eql(u8, field_name, "quest_play_counts")) {
                fields_seen |= 1 << 3;
                status.quest_play_counts = try readExactU32Array(unpacker);
            } else if (std.mem.eql(u8, field_name, "mode_play_survival")) {
                fields_seen |= 1 << 4;
                status.mode_play_survival = try unpacker.readInt(i32);
            } else if (std.mem.eql(u8, field_name, "mode_play_rush")) {
                fields_seen |= 1 << 5;
                status.mode_play_rush = try unpacker.readInt(i32);
            } else if (std.mem.eql(u8, field_name, "mode_play_typo")) {
                fields_seen |= 1 << 6;
                status.mode_play_typo = try unpacker.readInt(i32);
            } else if (std.mem.eql(u8, field_name, "mode_play_other")) {
                fields_seen |= 1 << 7;
                status.mode_play_other = try unpacker.readInt(i32);
            } else if (std.mem.eql(u8, field_name, "game_sequence_id")) {
                fields_seen |= 1 << 8;
                status.game_sequence_id = try unpacker.readInt(i32);
            } else if (std.mem.eql(u8, field_name, "unknown_tail")) {
                fields_seen |= 1 << 9;
                status.unknown_tail = .{ .data = try readExactBinary(unpacker) };
            } else {
                return error.UnknownStructField;
            }
        }

        if (fields_seen != (1 << 10) - 1) return error.MissingStructFields;
        return status;
    }
};

pub const ReplayClaimedStatsWire = struct {
    complete: bool = false,
    ticks: i32 = 0,
    elapsed_ms: i64 = 0,
    score_xp: i64 = 0,
    kills: i32 = 0,
    most_used_weapon_id: i32 = 0,
    shots_fired: i32 = 0,
    shots_hit: i32 = 0,

    pub fn msgpackRead(unpacker: anytype) !ReplayClaimedStatsWire {
        const field_count = try unpacker.readMapHeader(u16);
        if (field_count != 8) return error.InvalidFormat;
        var field_name_buf: [64]u8 = undefined;
        var stats: ReplayClaimedStatsWire = .{};
        var fields_seen: u8 = 0;

        for (0..field_count) |_| {
            const field_name = try unpacker.readStringInto(&field_name_buf);
            if (std.mem.eql(u8, field_name, "complete")) {
                fields_seen |= 1 << 0;
                stats.complete = try unpacker.readBool(bool);
            } else if (std.mem.eql(u8, field_name, "ticks")) {
                fields_seen |= 1 << 1;
                stats.ticks = try unpacker.readInt(i32);
            } else if (std.mem.eql(u8, field_name, "elapsed_ms")) {
                fields_seen |= 1 << 2;
                stats.elapsed_ms = try unpacker.readInt(i64);
            } else if (std.mem.eql(u8, field_name, "score_xp")) {
                fields_seen |= 1 << 3;
                stats.score_xp = try unpacker.readInt(i64);
            } else if (std.mem.eql(u8, field_name, "kills")) {
                fields_seen |= 1 << 4;
                stats.kills = try unpacker.readInt(i32);
            } else if (std.mem.eql(u8, field_name, "most_used_weapon_id")) {
                fields_seen |= 1 << 5;
                stats.most_used_weapon_id = try unpacker.readInt(i32);
            } else if (std.mem.eql(u8, field_name, "shots_fired")) {
                fields_seen |= 1 << 6;
                stats.shots_fired = try unpacker.readInt(i32);
            } else if (std.mem.eql(u8, field_name, "shots_hit")) {
                fields_seen |= 1 << 7;
                stats.shots_hit = try unpacker.readInt(i32);
            } else {
                return error.UnknownStructField;
            }
        }

        if (fields_seen != std.math.maxInt(u8)) return error.MissingStructFields;
        return stats;
    }
};

const ReplayVec2Wire = struct {
    x: f64,
    y: f64,
};

pub const ReplayVec2 = struct {
    x: f32 = 0.0,
    y: f32 = 0.0,
};

const ReplayCreatureSlotResidueWire = struct {
    index: i32,
    phase_seed: f64,
    state_flag: i32,
    collision_flag: i32,
    collision_timer: f64,
    lifecycle_stage: f64,
    pos: ReplayVec2Wire,
    vel: ReplayVec2Wire,
    hp: f64,
    max_hp: f64,
    heading: f64,
    target_heading: f64,
    size: f64,
    hit_flash_timer: f64,
    tint_r: f64,
    tint_g: f64,
    tint_b: f64,
    tint_a: f64,
    force_target: i32,
    target: ReplayVec2Wire,
    contact_damage: f64,
    move_speed: f64,
    attack_cooldown: f64,
    reward_value: f64,
    type_id: i32,
    target_player: i32,
    link_index: i32,
    target_offset: ReplayVec2Wire,
    orbit_angle: f64,
    orbit_radius_u32: u32,
    flags: i32,
    ai_mode: i32,
    anim_phase: f64,
};

pub const ReplayCreatureSlotResidue = struct {
    index: i32,
    phase_seed: f32 = 0.0,
    state_flag: i32 = 0,
    collision_flag: i32 = 0,
    collision_timer: f32 = 0.0,
    lifecycle_stage: f32 = 0.0,
    pos: ReplayVec2 = .{},
    vel: ReplayVec2 = .{},
    hp: f32 = 0.0,
    max_hp: f32 = 0.0,
    heading: f32 = 0.0,
    target_heading: f32 = 0.0,
    size: f32 = 0.0,
    hit_flash_timer: f32 = 0.0,
    tint_r: f32 = 0.0,
    tint_g: f32 = 0.0,
    tint_b: f32 = 0.0,
    tint_a: f32 = 0.0,
    force_target: i32 = 0,
    target: ReplayVec2 = .{},
    contact_damage: f32 = 0.0,
    move_speed: f32 = 0.0,
    attack_cooldown: f32 = 0.0,
    reward_value: f32 = 0.0,
    type_id: i32 = 0,
    target_player: i32 = 0,
    link_index: i32 = 0,
    target_offset: ReplayVec2 = .{},
    orbit_angle: f32 = 0.0,
    orbit_radius_u32: u32 = 0,
    flags: i32 = 0,
    ai_mode: i32 = 0,
    anim_phase: f32 = 0.0,
};

const QuestLevelCurrentWire = struct {
    major: i32,
    minor: i32,
};

pub const ReplayHeaderCurrentWire = struct {
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
    world_size: f64 = 1024.0,
    player_count: i32 = 1,
    status: ReplayStatusCurrentWire = .{},
    claimed_stats: ReplayClaimedStatsWire,
    input_quantization: []const u8 = "f32",
    initial_creature_pool: ?[]const ReplayCreatureSlotResidueWire = null,

    pub fn msgpackFormat() msgpack.StructFormat {
        return .{ .as_map = .{ .key = .field_name, .omit_nulls = false } };
    }

    pub fn msgpackRead(unpacker: anytype) !ReplayHeaderCurrentWire {
        const field_count = try unpacker.readMapHeader(u16);
        if (field_count != 19) return error.InvalidFormat;
        var field_name_buf: [64]u8 = undefined;
        var header: ReplayHeaderCurrentWire = undefined;
        var fields_seen: u32 = 0;

        for (0..field_count) |_| {
            const field_name = try unpacker.readStringInto(&field_name_buf);
            if (std.mem.eql(u8, field_name, "game_mode_id")) {
                fields_seen |= 1 << 0;
                header.game_mode_id = try unpacker.readInt(i32);
            } else if (std.mem.eql(u8, field_name, "seed")) {
                fields_seen |= 1 << 1;
                header.seed = try unpacker.readInt(u32);
            } else if (std.mem.eql(u8, field_name, "replay_format_version")) {
                fields_seen |= 1 << 2;
                header.replay_format_version = try unpacker.readInt(i32);
            } else if (std.mem.eql(u8, field_name, "quest_level")) {
                fields_seen |= 1 << 3;
                header.quest_level = try unpacker.read(?QuestLevelCurrentWire);
            } else if (std.mem.eql(u8, field_name, "typo_dictionary_words")) {
                fields_seen |= 1 << 4;
                header.typo_dictionary_words = try unpacker.read([]const []const u8);
            } else if (std.mem.eql(u8, field_name, "typo_highscore_names")) {
                fields_seen |= 1 << 5;
                header.typo_highscore_names = try unpacker.read([]const []const u8);
            } else if (std.mem.eql(u8, field_name, "game_version")) {
                fields_seen |= 1 << 6;
                header.game_version = try unpacker.read([]const u8);
            } else if (std.mem.eql(u8, field_name, "tick_rate")) {
                fields_seen |= 1 << 7;
                header.tick_rate = try unpacker.readInt(i32);
            } else if (std.mem.eql(u8, field_name, "quest_fail_retry_count")) {
                fields_seen |= 1 << 8;
                header.quest_fail_retry_count = try unpacker.readInt(i32);
            } else if (std.mem.eql(u8, field_name, "hardcore")) {
                fields_seen |= 1 << 9;
                header.hardcore = try unpacker.readBool(bool);
            } else if (std.mem.eql(u8, field_name, "preserve_bugs")) {
                fields_seen |= 1 << 10;
                header.preserve_bugs = try unpacker.readBool(bool);
            } else if (std.mem.eql(u8, field_name, "detail_preset")) {
                fields_seen |= 1 << 11;
                header.detail_preset = try unpacker.readInt(i32);
            } else if (std.mem.eql(u8, field_name, "violence_disabled")) {
                fields_seen |= 1 << 12;
                header.violence_disabled = try unpacker.readInt(i32);
            } else if (std.mem.eql(u8, field_name, "world_size")) {
                fields_seen |= 1 << 13;
                header.world_size = try unpacker.readFloat(f64);
            } else if (std.mem.eql(u8, field_name, "player_count")) {
                fields_seen |= 1 << 14;
                header.player_count = try unpacker.readInt(i32);
            } else if (std.mem.eql(u8, field_name, "status")) {
                fields_seen |= 1 << 15;
                header.status = try unpacker.read(ReplayStatusCurrentWire);
            } else if (std.mem.eql(u8, field_name, "claimed_stats")) {
                fields_seen |= 1 << 16;
                header.claimed_stats = try unpacker.read(ReplayClaimedStatsWire);
            } else if (std.mem.eql(u8, field_name, "input_quantization")) {
                fields_seen |= 1 << 17;
                header.input_quantization = try unpacker.read([]const u8);
            } else if (std.mem.eql(u8, field_name, "initial_creature_pool")) {
                fields_seen |= 1 << 18;
                header.initial_creature_pool = try unpacker.read(?[]const ReplayCreatureSlotResidueWire);
            } else {
                return error.UnknownStructField;
            }
        }

        if (fields_seen != (1 << 19) - 1) return error.MissingStructFields;
        return header;
    }
};

const ReplayInputWire = struct {
    move_x: f64,
    move_y: f64,
    aim_x: f64,
    aim_y: f64,
    flags: i32,

    pub fn msgpackFormat() msgpack.StructFormat {
        return .{ .as_array = .{} };
    }
};

const GameFrameRngAdvancePreludeWire = struct {
    frames: i32,
};

const PerkMenuOpenPreludeWire = struct {
    player_index: i32,
};

const PerkPickPreludeWire = struct {
    player_index: i32,
    choice_index: ?i32 = null,
};

const ReplayPreludeCurrentWire = union(enum) {
    game_frame_rng_advance: GameFrameRngAdvancePreludeWire,
    perk_menu_open: PerkMenuOpenPreludeWire,
    perk_pick: PerkPickPreludeWire,

    pub fn msgpackFormat() msgpack.UnionFormat {
        return .{ .as_tagged = .{
            .tag_field = "type",
            .tag_value = .field_name,
        } };
    }
};

const ReplayPostludeCurrentWire = union(enum) {
    perk_menu_open: PerkMenuOpenPreludeWire,

    pub fn msgpackFormat() msgpack.UnionFormat {
        return .{ .as_tagged = .{
            .tag_field = "type",
            .tag_value = .field_name,
        } };
    }
};

pub const ReplayCommandCurrentWire = struct {
    type: []const u8,
    player_index: i32 = 0,
    choice_index: ?i32 = null,
    ch: ?[]const u8 = null,

    pub fn msgpackWrite(self: ReplayCommandCurrentWire, packer: anytype) !void {
        const has_choice = self.choice_index != null;
        const has_ch = self.ch != null;
        if (has_choice and has_ch) return error.InvalidFormat;
        try packer.writeMapHeader(if (has_choice or has_ch) 3 else 2);
        try packer.writeString("type");
        try packer.writeString(self.type);
        try packer.writeString("player_index");
        try packer.writeInt(self.player_index);
        if (self.choice_index) |choice_index| {
            try packer.writeString("choice_index");
            try packer.writeInt(choice_index);
        } else if (self.ch) |ch| {
            try packer.writeString("ch");
            try packer.writeString(ch);
        }
    }

    pub fn msgpackRead(unpacker: anytype) !ReplayCommandCurrentWire {
        const field_count = try unpacker.readMapHeader(u16);
        if (field_count != 2 and field_count != 3) return error.InvalidFormat;
        var field_name_buf: [32]u8 = undefined;
        var command: ReplayCommandCurrentWire = .{ .type = "" };
        var fields_seen: u8 = 0;

        for (0..field_count) |_| {
            const field_name = try unpacker.readStringInto(&field_name_buf);
            if (std.mem.eql(u8, field_name, "type")) {
                fields_seen |= 1 << 0;
                command.type = try unpacker.read([]const u8);
            } else if (std.mem.eql(u8, field_name, "player_index")) {
                fields_seen |= 1 << 1;
                command.player_index = try unpacker.readInt(i32);
            } else if (std.mem.eql(u8, field_name, "choice_index")) {
                fields_seen |= 1 << 2;
                command.choice_index = try unpacker.readInt(i32);
            } else if (std.mem.eql(u8, field_name, "ch")) {
                fields_seen |= 1 << 3;
                command.ch = try unpacker.read([]const u8);
            } else {
                return error.UnknownStructField;
            }
        }

        if ((fields_seen & 0b0011) != 0b0011) return error.MissingStructFields;
        if (std.mem.eql(u8, command.type, "perk_pick")) {
            if (fields_seen != 0b0011 and fields_seen != 0b0111) return error.InvalidFormat;
        } else if (std.mem.eql(u8, command.type, "typo_char")) {
            if (fields_seen != 0b0011 and fields_seen != 0b1011) return error.InvalidFormat;
        } else if (currentCommandKindKnown(command.type)) {
            if (fields_seen != 0b0011) return error.InvalidFormat;
        } else if ((fields_seen & 0b1100) == 0b1100) {
            return error.InvalidFormat;
        }
        return command;
    }
};

pub const BinaryBytes = struct {
    data: []const u8,

    pub fn msgpackWrite(self: BinaryBytes, packer: anytype) !void {
        try packer.writeBinary(self.data);
    }

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

const ReplayTickCurrentWire = struct {
    dt: f64,
    inputs: []const ReplayInputWire,
    prelude: []const ReplayPreludeCurrentWire,
    postlude: []const ReplayPostludeCurrentWire,
    commands: []const ReplayCommandCurrentWire,
};

const ReplayCurrentWire = struct {
    header: ReplayHeaderCurrentWire,
    ticks: []const ReplayTickCurrentWire,
};

pub fn isZstdPayload(bytes: []const u8) bool {
    if (bytes.len < zstd_magic.len) return false;
    return std.mem.eql(u8, bytes[0..zstd_magic.len], zstd_magic[0..]);
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

fn inflateSingleZstdFramePayload(
    allocator: std.mem.Allocator,
    compressed: []const u8,
    max_output_bytes: usize,
) ReplayCodecError![]u8 {
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
        output.appendSlice(allocator, chunk[0..chunk_writer.end]) catch return error.OutOfMemory;
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
        const actual: u32 = @truncate(std.hash.XxHash64.hash(
            0,
            output.items,
        ));
        if (actual != expected) return error.InvalidZstdPayload;
    }
    return output.toOwnedSlice(allocator) catch return error.OutOfMemory;
}

/// Decode the only supported on-disk replay envelope.
///
/// `parseReplay` and `parseReplaySummary` intentionally continue to accept raw
/// msgpack payloads for in-memory callers and tests. File-facing commands must
/// pass through this function so raw or otherwise non-zstd payloads cannot be mistaken for
/// current replay files.
pub fn inflateZstdFilePayload(
    allocator: std.mem.Allocator,
    compressed: []const u8,
    max_output_bytes: usize,
) ReplayCodecError![]u8 {
    if (!isZstdPayload(compressed)) return error.InvalidZstdPayload;
    return inflateSingleZstdFramePayload(allocator, compressed, max_output_bytes);
}

pub fn parseReplaySummary(
    allocator: std.mem.Allocator,
    payload: []const u8,
) ReplayCodecError!ReplaySummary {
    if (try tryParseCurrentReplaySummary(allocator, payload)) |summary| {
        return summary;
    }
    return error.InvalidMsgpack;
}

pub fn parseReplay(
    allocator: std.mem.Allocator,
    payload: []const u8,
) ReplayCodecError!Replay {
    if (try tryParseCurrentReplay(allocator, payload)) |replay| {
        return replay;
    }
    return error.InvalidMsgpack;
}

pub fn buildSmokeTestReplayPayload(allocator: std.mem.Allocator) ![]u8 {
    return buildSmokeTestReplayPayloadForMode(allocator, @intFromEnum(game_ids.GameModeId.survival));
}

fn buildSmokeTestReplayPayloadForMode(allocator: std.mem.Allocator, game_mode_id: i32) ![]u8 {
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
    const ticks = [_]ReplayTickCurrentWire{
        .{ .dt = canonical_tick_dt_f64, .inputs = tick0[0..], .prelude = &.{}, .postlude = &.{}, .commands = &.{} },
        .{ .dt = canonical_tick_dt_f64, .inputs = tick1[0..], .prelude = &.{}, .postlude = &.{}, .commands = &.{} },
    };
    const replay: ReplayCurrentWire = .{
        .header = .{
            .game_mode_id = game_mode_id,
            .seed = 1,
            .replay_format_version = replay_format_version,
            .quest_level = null,
            .game_version = "0.9.0",
            .tick_rate = 60,
            .quest_fail_retry_count = 0,
            .hardcore = false,
            .preserve_bugs = false,
            .detail_preset = 5,
            .violence_disabled = 0,
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
        .ticks = ticks[0..],
    };

    var writer: std.Io.Writer.Allocating = .init(allocator);
    errdefer writer.deinit();
    try msgpack.encode(replay, &writer.writer);
    return writer.toOwnedSlice();
}

/// Build a valid zstd file envelope using raw blocks.
///
/// This keeps test and embedding callers independent of a zstd compressor
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
        var content_size: [2]u8 = undefined;
        std.mem.writeInt(u16, &content_size, @intCast(payload.len - 256), .little);
        try writer.writer.writeAll(&content_size);
    } else {
        try writer.writer.writeByte(0xA0);
        var content_size: [4]u8 = undefined;
        std.mem.writeInt(u32, &content_size, @intCast(payload.len), .little);
        try writer.writer.writeAll(&content_size);
    }

    const max_raw_block_len: usize = 128 * 1024;
    var offset: usize = 0;
    while (offset < payload.len or (payload.len == 0 and offset == 0)) {
        const remaining = payload.len - offset;
        const block_len = @min(remaining, max_raw_block_len);
        const last: u32 = @intFromBool(offset + block_len == payload.len);
        const block_header: u32 = last | (@as(u32, @intCast(block_len)) << 3);
        const header_bytes = [_]u8{
            @truncate(block_header),
            @truncate(block_header >> 8),
            @truncate(block_header >> 16),
        };
        try writer.writer.writeAll(&header_bytes);
        try writer.writer.writeAll(payload[offset .. offset + block_len]);
        offset += block_len;
        if (last != 0) break;
    }

    return writer.toOwnedSlice();
}

pub fn buildSmokeTestReplayFile(allocator: std.mem.Allocator) ![]u8 {
    const payload = try buildSmokeTestReplayPayload(allocator);
    defer allocator.free(payload);
    return wrapZstdFilePayload(allocator, payload);
}

fn currentReplayInputShapeFailureDetail(
    allocator: std.mem.Allocator,
    payload: []const u8,
) ReplayCodecError!?[]u8 {
    var decoded = msgpack.decodeFromSlice(ReplayCurrentWire, allocator, payload) catch |err| {
        return switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            else => null,
        };
    };
    defer decoded.deinit();

    const wire = decoded.value;
    const player_count = try parseI32(wire.header.player_count);
    if (player_count <= 0) return null;
    const expected_players: usize = @intCast(player_count);

    for (wire.ticks, 0..) |tick, tick_idx| {
        if (tick.inputs.len != expected_players) {
            return std.fmt.allocPrint(
                allocator,
                "replay tick {d} has {d} players, expected {d}",
                .{ tick_idx, tick.inputs.len, expected_players },
            ) catch return error.OutOfMemory;
        }
        const dt = canonicalF32(tick.dt) orelse {
            return std.fmt.allocPrint(
                allocator,
                "replay tick {d} dt must already be exactly representable as f32",
                .{tick_idx},
            ) catch return error.OutOfMemory;
        };
        if (dt < 0.0) {
            return std.fmt.allocPrint(
                allocator,
                "replay tick {d} dt must be finite and >= 0",
                .{tick_idx},
            ) catch return error.OutOfMemory;
        }
        for (tick.inputs, 0..) |input, player_idx| {
            const fields = [_]struct { name: []const u8, value: f64 }{
                .{ .name = "move_x", .value = input.move_x },
                .{ .name = "move_y", .value = input.move_y },
                .{ .name = "aim_x", .value = input.aim_x },
                .{ .name = "aim_y", .value = input.aim_y },
            };
            for (fields) |field| {
                _ = canonicalF32(field.value) orelse {
                    return std.fmt.allocPrint(
                        allocator,
                        "replay tick {d} player {d} {s} must already be exactly representable as f32",
                        .{ tick_idx, player_idx, field.name },
                    ) catch return error.OutOfMemory;
                };
            }
        }
    }

    return null;
}

fn validateCurrentTicks(
    wire_ticks: []const ReplayTickCurrentWire,
    player_count: i32,
    game_mode_id: i32,
) ReplayCodecError!void {
    if (wire_ticks.len == 0) return error.UnsupportedInputShape;
    const expected_players: usize = @intCast(player_count);
    for (wire_ticks) |tick| {
        if (tick.commands.len > 0 and game_mode_id != @intFromEnum(game_ids.GameModeId.typo)) {
            return error.UnsupportedEventKind;
        }
        const dt = canonicalF32(tick.dt) orelse return error.UnsupportedInputShape;
        if (dt < 0.0) return error.UnsupportedInputShape;
        if (tick.inputs.len != expected_players) return error.UnsupportedInputShape;
        for (tick.inputs) |input| {
            _ = canonicalF32(input.move_x) orelse return error.UnsupportedInputShape;
            _ = canonicalF32(input.move_y) orelse return error.UnsupportedInputShape;
            _ = canonicalF32(input.aim_x) orelse return error.UnsupportedInputShape;
            _ = canonicalF32(input.aim_y) orelse return error.UnsupportedInputShape;
            _ = try parseInputFlagsValue(input.flags);
        }
    }
}

fn parseCurrentEventSummary(
    wire_ticks: []const ReplayTickCurrentWire,
    player_count: i32,
) ReplayCodecError!ReplayEventSummary {
    var summary: ReplayEventSummary = .{};
    for (wire_ticks, 0..) |tick, tick_index| {
        for (tick.prelude) |wire_op| {
            const op = try parseCurrentPrelude(wire_op, tick_index, player_count);
            summary.total_count += 1;
            countReplayPrelude(&summary, op);
        }
        for (tick.postlude) |wire_op| {
            _ = try parseCurrentPostlude(wire_op, tick_index, player_count);
            summary.total_count += 1;
            summary.perk_menu_open_count += 1;
        }
        for (tick.commands) |command| {
            const event = try parseCurrentCommand(command, tick_index, player_count);
            summary.total_count += 1;
            countReplayEvent(&summary, event);
        }
    }
    return summary;
}

fn countReplayPrelude(summary: *ReplayEventSummary, op: ReplayPreludeOp) void {
    switch (op) {
        .game_frame_rng_advance => summary.game_frame_rng_advance_count += 1,
        .perk_menu_open => summary.perk_menu_open_count += 1,
        .perk_pick => summary.perk_pick_count += 1,
    }
}

fn countReplayEvent(summary: *ReplayEventSummary, event: ReplayEvent) void {
    switch (event) {
        .perk_pick => summary.perk_pick_count += 1,
        .perk_menu_open => summary.perk_menu_open_count += 1,
        .typo_char => summary.typo_char_count += 1,
        .typo_backspace => summary.typo_backspace_count += 1,
        .typo_submit => summary.typo_submit_count += 1,
        .capture_bootstrap => summary.capture_bootstrap_count += 1,
        .capture_perk_apply => summary.capture_perk_apply_count += 1,
        .capture_perk_pending => summary.capture_perk_pending_count += 1,
        .capture_creature_spawn => summary.capture_creature_spawn_count += 1,
        .capture_state_transition => summary.capture_state_transition_count += 1,
    }
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
                .move_x = canonicalF32(wire_input.move_x) orelse return error.UnsupportedInputShape,
                .move_y = canonicalF32(wire_input.move_y) orelse return error.UnsupportedInputShape,
                .aim_x = canonicalF32(wire_input.aim_x) orelse return error.UnsupportedInputShape,
                .aim_y = canonicalF32(wire_input.aim_y) orelse return error.UnsupportedInputShape,
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
    player_count: i32,
) ReplayCodecError![]ReplayEvent {
    var total_count: usize = 0;
    for (wire_ticks) |tick| total_count += tick.commands.len;

    const events = allocator.alloc(ReplayEvent, total_count) catch return error.OutOfMemory;
    errdefer allocator.free(events);

    var event_index: usize = 0;
    for (wire_ticks, 0..) |tick, tick_index| {
        for (tick.commands) |command| {
            events[event_index] = try parseCurrentCommand(command, tick_index, player_count);
            event_index += 1;
        }
    }
    return events;
}

fn buildPreludeCurrent(
    allocator: std.mem.Allocator,
    wire_ticks: []const ReplayTickCurrentWire,
    player_count: i32,
) ReplayCodecError![]ReplayPreludeOp {
    var total_count: usize = 0;
    for (wire_ticks) |tick| total_count += tick.prelude.len;
    if (total_count == 0) return &.{};

    const prelude = allocator.alloc(ReplayPreludeOp, total_count) catch return error.OutOfMemory;
    errdefer allocator.free(prelude);

    var op_index: usize = 0;
    for (wire_ticks, 0..) |tick, tick_index| {
        for (tick.prelude) |wire_op| {
            prelude[op_index] = try parseCurrentPrelude(wire_op, tick_index, player_count);
            op_index += 1;
        }
    }
    return prelude;
}

fn buildPostludeCurrent(
    allocator: std.mem.Allocator,
    wire_ticks: []const ReplayTickCurrentWire,
    player_count: i32,
) ReplayCodecError![]ReplayPostludeOp {
    var total_count: usize = 0;
    for (wire_ticks) |tick| total_count += tick.postlude.len;
    if (total_count == 0) return &.{};

    const postlude = allocator.alloc(ReplayPostludeOp, total_count) catch return error.OutOfMemory;
    errdefer allocator.free(postlude);

    var op_index: usize = 0;
    for (wire_ticks, 0..) |tick, tick_index| {
        for (tick.postlude) |wire_op| {
            postlude[op_index] = try parseCurrentPostlude(wire_op, tick_index, player_count);
            op_index += 1;
        }
    }
    return postlude;
}

fn buildDtCurrent(
    allocator: std.mem.Allocator,
    wire_ticks: []const ReplayTickCurrentWire,
) ReplayCodecError![]f32 {
    const out = allocator.alloc(f32, wire_ticks.len) catch return error.OutOfMemory;
    errdefer allocator.free(out);
    for (wire_ticks, 0..) |tick, idx| {
        out[idx] = canonicalF32(tick.dt) orelse return error.UnsupportedInputShape;
    }
    return out;
}

fn parseCurrentPrelude(
    wire_op: ReplayPreludeCurrentWire,
    tick_index: usize,
    player_count: i32,
) ReplayCodecError!ReplayPreludeOp {
    return switch (wire_op) {
        .game_frame_rng_advance => |op| blk: {
            if (op.frames <= 0) return error.UnsupportedEventShape;
            break :blk .{ .game_frame_rng_advance = .{
                .tick_index = tick_index,
                .frames = @intCast(op.frames),
            } };
        },
        .perk_menu_open => |op| blk: {
            if (op.player_index < 0 or op.player_index >= player_count) {
                return error.UnsupportedEventShape;
            }
            break :blk .{ .perk_menu_open = .{
                .tick_index = tick_index,
                .player_index = op.player_index,
            } };
        },
        .perk_pick => |op| blk: {
            if (op.player_index < 0 or op.player_index >= player_count) {
                return error.UnsupportedEventShape;
            }
            const choice_index = op.choice_index orelse return error.UnsupportedEventShape;
            if (choice_index < 0 or choice_index >= @as(i32, @intCast(perk_choice_slot_count))) {
                return error.UnsupportedEventShape;
            }
            break :blk .{ .perk_pick = .{
                .tick_index = tick_index,
                .player_index = op.player_index,
                .choice_index = choice_index,
            } };
        },
    };
}

fn parseCurrentPostlude(
    wire_op: ReplayPostludeCurrentWire,
    tick_index: usize,
    player_count: i32,
) ReplayCodecError!ReplayPostludeOp {
    return switch (wire_op) {
        .perk_menu_open => |op| {
            if (op.player_index < 0 or op.player_index >= player_count) {
                return error.UnsupportedEventShape;
            }
            return .{
                .tick_index = tick_index,
                .player_index = op.player_index,
            };
        },
    };
}

fn parseCurrentCommand(
    command: ReplayCommandCurrentWire,
    tick_index: usize,
    player_count: i32,
) ReplayCodecError!ReplayEvent {
    if (command.player_index < 0 or command.player_index >= player_count) {
        return error.UnsupportedEventShape;
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

fn currentCommandKindKnown(command_type: []const u8) bool {
    return std.mem.eql(u8, command_type, "typo_char") or
        std.mem.eql(u8, command_type, "typo_backspace") or
        std.mem.eql(u8, command_type, "typo_submit");
}

fn currentReplayEventShapeFailureDetail(
    allocator: std.mem.Allocator,
    payload: []const u8,
) ReplayCodecError!?[]u8 {
    var decoded = msgpack.decodeFromSlice(ReplayCurrentWire, allocator, payload) catch |err| {
        return switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            else => null,
        };
    };
    defer decoded.deinit();

    const player_count = decoded.value.header.player_count;
    for (decoded.value.ticks, 0..) |tick, tick_index| {
        for (tick.prelude, 0..) |wire_op, operation_index| {
            switch (wire_op) {
                .game_frame_rng_advance => |op| {
                    if (op.frames <= 0) {
                        return std.fmt.allocPrint(
                            allocator,
                            "replay prelude game_frame_rng_advance frames must be > 0: frames={d} tick={d} operation_index={d}",
                            .{ op.frames, tick_index, operation_index },
                        ) catch return error.OutOfMemory;
                    }
                },
                .perk_menu_open => |op| {
                    if (op.player_index < 0 or op.player_index >= player_count) {
                        return std.fmt.allocPrint(
                            allocator,
                            "replay prelude player_index out of range: {d} (player_count={d}, tick={d}, event=perk_menu_open)",
                            .{ op.player_index, player_count, tick_index },
                        ) catch return error.OutOfMemory;
                    }
                },
                .perk_pick => |op| {
                    if (op.player_index < 0 or op.player_index >= player_count) {
                        return std.fmt.allocPrint(
                            allocator,
                            "replay prelude player_index out of range: {d} (player_count={d}, tick={d}, event=perk_pick)",
                            .{ op.player_index, player_count, tick_index },
                        ) catch return error.OutOfMemory;
                    }
                    const choice_index = op.choice_index orelse {
                        return std.fmt.allocPrint(
                            allocator,
                            "replay prelude perk_pick missing choice_index: tick={d} operation_index={d}",
                            .{ tick_index, operation_index },
                        ) catch return error.OutOfMemory;
                    };
                    if (choice_index < 0 or choice_index >= @as(i32, @intCast(perk_choice_slot_count))) {
                        return std.fmt.allocPrint(
                            allocator,
                            "replay prelude perk_pick choice_index must be in 0..6: choice_index={d} tick={d} operation_index={d}",
                            .{ choice_index, tick_index, operation_index },
                        ) catch return error.OutOfMemory;
                    }
                },
            }
        }
        for (tick.postlude) |wire_op| {
            switch (wire_op) {
                .perk_menu_open => |op| {
                    if (op.player_index < 0 or op.player_index >= player_count) {
                        return std.fmt.allocPrint(
                            allocator,
                            "replay postlude player_index out of range: {d} (player_count={d}, tick={d}, event=perk_menu_open)",
                            .{ op.player_index, player_count, tick_index },
                        ) catch return error.OutOfMemory;
                    }
                },
            }
        }
        for (tick.commands, 0..) |command, command_index| {
            if (command.player_index < 0 or command.player_index >= player_count) {
                return std.fmt.allocPrint(
                    allocator,
                    "replay command player_index out of range: {d} (player_count={d}, tick={d}, type={s})",
                    .{ command.player_index, player_count, tick_index, command.type },
                ) catch return error.OutOfMemory;
            }
            if (std.mem.eql(u8, command.type, "typo_char")) {
                const raw = command.ch orelse {
                    return std.fmt.allocPrint(
                        allocator,
                        "replay command typo_char missing ch: tick={d} command_index={d}",
                        .{ tick_index, command_index },
                    ) catch return error.OutOfMemory;
                };
                if (raw.len != 1) {
                    return std.fmt.allocPrint(
                        allocator,
                        "replay command typo_char ch must be exactly one byte: tick={d} command_index={d} length={d}",
                        .{ tick_index, command_index, raw.len },
                    ) catch return error.OutOfMemory;
                }
            }
        }
    }

    return null;
}

fn freeInputs(allocator: std.mem.Allocator, inputs: []ReplayTickInputs) void {
    for (inputs) |tick| allocator.free(tick);
    allocator.free(inputs);
}

fn isSupportedReplayFormatVersion(version: i32) bool {
    return version == replay_format_version;
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
    try validateCurrentTicks(wire.ticks, header.player_count, header.game_mode_id);
    return .{
        .header = header,
        .tick_count = tick_count,
        .events = try parseCurrentEventSummary(wire.ticks, header.player_count),
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

    try validateCurrentTicks(wire.ticks, header.player_count, header.game_mode_id);
    const prelude = try buildPreludeCurrent(allocator, wire.ticks, header.player_count);
    errdefer if (prelude.len > 0) allocator.free(prelude);
    const postlude = try buildPostludeCurrent(allocator, wire.ticks, header.player_count);
    errdefer if (postlude.len > 0) allocator.free(postlude);
    const inputs = try buildInputsCurrent(allocator, wire.ticks);
    errdefer freeInputs(allocator, inputs);
    const dt = try buildDtCurrent(allocator, wire.ticks);
    errdefer allocator.free(dt);
    const events = try buildEventsCurrent(allocator, wire.ticks, header.player_count);
    errdefer allocator.free(events);

    return .{
        .header = header,
        .inputs = inputs,
        .dt = dt,
        .prelude = prelude,
        .postlude = postlude,
        .events = events,
    };
}

fn buildHeaderCurrent(
    allocator: std.mem.Allocator,
    wire: ReplayHeaderCurrentWire,
) ReplayCodecError!ReplayHeader {
    const game_mode = std.enums.fromInt(game_ids.GameModeId, wire.game_mode_id) orelse return error.UnsupportedGameMode;
    switch (game_mode) {
        .quests => {
            const level = wire.quest_level orelse return error.MissingQuestLevel;
            if (level.major < 1 or level.major > 5 or level.minor < 1 or level.minor > 10) {
                return error.InvalidHeaderValue;
            }
        },
        .survival, .rush, .typo, .tutorial => {
            if (wire.quest_level != null) return error.InvalidHeaderValue;
        },
    }
    var quest_level_buf: [32]u8 = undefined;
    const quest_level = if (wire.quest_level) |level|
        std.fmt.bufPrint(quest_level_buf[0..], "{d}.{d}", .{ level.major, level.minor }) catch return error.InvalidHeaderValue
    else
        "";
    return buildHeaderCurrentWithQuestLevelText(allocator, wire, quest_level);
}

fn buildHeaderCurrentWithQuestLevelText(
    allocator: std.mem.Allocator,
    wire: anytype,
    quest_level: []const u8,
) ReplayCodecError!ReplayHeader {
    const max_world_size_i32_f32: f32 = @floatFromInt(std.math.maxInt(i32));
    const world_size = canonicalF32(wire.world_size) orelse return error.InvalidHeaderValue;
    if (world_size <= 0.0 or world_size > max_world_size_i32_f32) {
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

    if (tick_rate <= 0 or
        player_count <= 0 or
        player_count > max_players or
        quest_fail_retry_count < 0 or
        detail_preset < 0 or
        violence_disabled < 0)
    {
        return error.InvalidHeaderValue;
    }
    try validateModePlayerCount(wire.game_mode_id, player_count);
    if (wire.game_version.len == 0) return error.MissingHeaderField;
    if (isMissingQuestLevel(wire.game_mode_id, quest_level)) return error.MissingQuestLevel;
    if (wire.status.weapon_usage_counts.len != weapon_usage_count or
        wire.status.quest_play_counts.len != quest_play_count or
        wire.status.unknown_tail.data.len != status_unknown_tail_size)
    {
        return error.InvalidHeaderValue;
    }

    var usage_counts: [weapon_usage_count]u32 = [_]u32{0} ** weapon_usage_count;
    for (wire.status.weapon_usage_counts, 0..) |value, idx| {
        usage_counts[idx] = try parseU32(value);
    }
    var quest_play_counts: [quest_play_count]u32 = [_]u32{0} ** quest_play_count;
    for (wire.status.quest_play_counts, 0..) |value, idx| {
        quest_play_counts[idx] = try parseU32(value);
    }
    var unknown_tail: [status_unknown_tail_size]u8 = undefined;
    @memcpy(unknown_tail[0..], wire.status.unknown_tail.data);

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
    try validateClaimedStats(claimed_stats);

    const quest_level_owned = allocator.dupe(u8, quest_level) catch return error.OutOfMemory;
    errdefer allocator.free(quest_level_owned);
    const initial_creature_pool: ?[]const ReplayCreatureSlotResidue = if (wire.initial_creature_pool) |pool|
        try buildCreaturePoolResidue(allocator, pool)
    else
        null;
    errdefer if (initial_creature_pool) |pool| {
        if (pool.len > 0) allocator.free(pool);
    };

    return .{
        .game_mode_id = wire.game_mode_id,
        .seed = wire.seed,
        .replay_format_version = wire.replay_format_version,
        .quest_level = quest_level_owned,
        .typo_dictionary_words = try dupStringSliceList(allocator, wire.typo_dictionary_words),
        .typo_highscore_names = try dupStringSliceList(allocator, wire.typo_highscore_names),
        .game_version = allocator.dupe(u8, wire.game_version) catch return error.OutOfMemory,
        .tick_rate = tick_rate,
        .quest_fail_retry_count = quest_fail_retry_count,
        .hardcore = wire.hardcore,
        .preserve_bugs = wire.preserve_bugs,
        .detail_preset = detail_preset,
        .violence_disabled = violence_disabled,
        .world_size = world_size,
        .player_count = player_count,
        .status = .{
            .quest_unlock_index = quest_unlock_index,
            .quest_unlock_index_full = quest_unlock_index_full,
            .weapon_usage_counts = usage_counts,
            .quest_play_counts = quest_play_counts,
            .mode_play_survival = wire.status.mode_play_survival,
            .mode_play_rush = wire.status.mode_play_rush,
            .mode_play_typo = wire.status.mode_play_typo,
            .mode_play_other = wire.status.mode_play_other,
            .game_sequence_id = wire.status.game_sequence_id,
            .unknown_tail = unknown_tail,
        },
        .claimed_stats = claimed_stats,
        .input_quantization = allocator.dupe(u8, wire.input_quantization) catch return error.OutOfMemory,
        .initial_creature_pool = initial_creature_pool,
    };
}

fn buildCreaturePoolResidue(
    allocator: std.mem.Allocator,
    wire_pool: []const ReplayCreatureSlotResidueWire,
) ReplayCodecError![]ReplayCreatureSlotResidue {
    if (wire_pool.len == 0) return &.{};
    const pool = allocator.alloc(ReplayCreatureSlotResidue, wire_pool.len) catch return error.OutOfMemory;
    errdefer allocator.free(pool);

    for (wire_pool, 0..) |wire, idx| {
        if (idx > 0 and wire.index <= wire_pool[idx - 1].index) return error.InvalidHeaderValue;
        pool[idx] = .{
            .index = wire.index,
            .phase_seed = canonicalF32(wire.phase_seed) orelse return error.InvalidHeaderValue,
            .state_flag = wire.state_flag,
            .collision_flag = wire.collision_flag,
            .collision_timer = canonicalF32(wire.collision_timer) orelse return error.InvalidHeaderValue,
            .lifecycle_stage = canonicalF32(wire.lifecycle_stage) orelse return error.InvalidHeaderValue,
            .pos = .{
                .x = canonicalF32(wire.pos.x) orelse return error.InvalidHeaderValue,
                .y = canonicalF32(wire.pos.y) orelse return error.InvalidHeaderValue,
            },
            .vel = .{
                .x = canonicalF32(wire.vel.x) orelse return error.InvalidHeaderValue,
                .y = canonicalF32(wire.vel.y) orelse return error.InvalidHeaderValue,
            },
            .hp = canonicalF32(wire.hp) orelse return error.InvalidHeaderValue,
            .max_hp = canonicalF32(wire.max_hp) orelse return error.InvalidHeaderValue,
            .heading = canonicalF32(wire.heading) orelse return error.InvalidHeaderValue,
            .target_heading = canonicalF32(wire.target_heading) orelse return error.InvalidHeaderValue,
            .size = canonicalF32(wire.size) orelse return error.InvalidHeaderValue,
            .hit_flash_timer = canonicalF32(wire.hit_flash_timer) orelse return error.InvalidHeaderValue,
            .tint_r = canonicalF32(wire.tint_r) orelse return error.InvalidHeaderValue,
            .tint_g = canonicalF32(wire.tint_g) orelse return error.InvalidHeaderValue,
            .tint_b = canonicalF32(wire.tint_b) orelse return error.InvalidHeaderValue,
            .tint_a = canonicalF32(wire.tint_a) orelse return error.InvalidHeaderValue,
            .force_target = wire.force_target,
            .target = .{
                .x = canonicalF32(wire.target.x) orelse return error.InvalidHeaderValue,
                .y = canonicalF32(wire.target.y) orelse return error.InvalidHeaderValue,
            },
            .contact_damage = canonicalF32(wire.contact_damage) orelse return error.InvalidHeaderValue,
            .move_speed = canonicalF32(wire.move_speed) orelse return error.InvalidHeaderValue,
            .attack_cooldown = canonicalF32(wire.attack_cooldown) orelse return error.InvalidHeaderValue,
            .reward_value = canonicalF32(wire.reward_value) orelse return error.InvalidHeaderValue,
            .type_id = wire.type_id,
            .target_player = wire.target_player,
            .link_index = wire.link_index,
            .target_offset = .{
                .x = canonicalF32(wire.target_offset.x) orelse return error.InvalidHeaderValue,
                .y = canonicalF32(wire.target_offset.y) orelse return error.InvalidHeaderValue,
            },
            .orbit_angle = canonicalF32(wire.orbit_angle) orelse return error.InvalidHeaderValue,
            .orbit_radius_u32 = wire.orbit_radius_u32,
            .flags = wire.flags,
            .ai_mode = wire.ai_mode,
            .anim_phase = canonicalF32(wire.anim_phase) orelse return error.InvalidHeaderValue,
        };
    }
    return pool;
}

fn canonicalF32(value: f64) ?f32 {
    if (!std.math.isFinite(value)) return null;
    const max_f32: f64 = std.math.floatMax(f32);
    if (value < -max_f32 or value > max_f32) return null;
    const narrowed: f32 = @floatCast(value);
    if (@as(f64, narrowed) != value) return null;
    return narrowed;
}

fn parseInputFlagsValue(value: i32) ReplayCodecError!u32 {
    if (value < 0) return error.UnsupportedInputShape;
    const flags: u32 = @intCast(value);
    if ((flags & ~supported_input_flags_mask) != 0) return error.UnsupportedInputShape;

    const move_key_bits = move_forward_flag | move_backward_flag | turn_left_flag | turn_right_flag;
    if ((flags & move_keys_present_flag) == 0 and (flags & move_key_bits) != 0) {
        return error.UnsupportedInputShape;
    }

    const move_mode_value = (flags >> move_mode_shift) & move_mode_mask;
    if ((flags & move_mode_present_flag) == 0 and move_mode_value != 0) {
        return error.UnsupportedInputShape;
    }
    if ((flags & move_mode_present_flag) != 0 and move_mode_value > 5) {
        return error.UnsupportedInputShape;
    }

    const aim_scheme_value = (flags >> aim_scheme_shift) & aim_scheme_mask;
    if ((flags & aim_scheme_present_flag) == 0 and aim_scheme_value != 0) {
        return error.UnsupportedInputShape;
    }
    if ((flags & aim_scheme_present_flag) != 0 and aim_scheme_value == 6) {
        return error.UnsupportedInputShape;
    }
    return flags;
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

test "event player index failure detail identifies first invalid command event" {
    const allocator = std.testing.allocator;
    const events = [_]ReplayEvent{
        .{ .perk_menu_open = .{
            .tick_index = 7,
            .player_index = 1,
        } },
        .{ .typo_submit = .{
            .tick_index = 8,
            .player_index = 3,
        } },
    };

    const detail = (try replayEventPlayerIndexFailureDetail(allocator, 1, events[0..])) orelse return error.TestExpectedDetail;
    defer allocator.free(detail);

    try std.testing.expectEqualStrings(
        "replay event player_index out of range: 1 (player_count=1, tick=7, event=perk_menu_open)",
        detail,
    );
}

test "event ordering failure detail identifies first descending tick" {
    const allocator = std.testing.allocator;
    const events = [_]ReplayEvent{
        .{ .perk_menu_open = .{
            .tick_index = 2,
            .player_index = 0,
        } },
        .{ .perk_pick = .{
            .tick_index = 1,
            .player_index = 0,
            .choice_index = 0,
        } },
    };

    const detail = (try replayEventOrderingFailureDetail(allocator, events[0..])) orelse return error.TestExpectedDetail;
    defer allocator.free(detail);

    try std.testing.expectEqualStrings(
        "replay events are not ordered in canonical tick order: tick=1 follows tick=2 (event_index=1, event=perk_pick)",
        detail,
    );
}

test "event kind failure detail identifies first mode-incompatible event" {
    const allocator = std.testing.allocator;
    const events = [_]ReplayEvent{
        .{ .typo_char = .{
            .tick_index = 0,
            .player_index = 0,
            .ch = 'x',
        } },
    };

    const detail = (try replayEventKindFailureDetail(allocator, @intFromEnum(game_ids.GameModeId.survival), events[0..])) orelse return error.TestExpectedDetail;
    defer allocator.free(detail);

    try std.testing.expectEqualStrings(
        "replay event kind invalid for game mode: event=typo_char tick=0 event_index=0 game_mode=survival",
        detail,
    );
}

test "inflate zstd payload consumes replay fixture through eof" {
    const compressed = @embedFile("../../tests/fixtures/replays/quest_1.5_20260303_211620_completed_t40512.crd");
    const inflated = try inflateZstdPayload(std.testing.allocator, compressed, max_replay_payload_bytes);
    defer std.testing.allocator.free(inflated);

    try std.testing.expectEqual(@as(usize, 191445), inflated.len);
    try std.testing.expectEqualSlices(u8, &.{ 0x82, 0xa6, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72 }, inflated[0..8]);
}

test "smoke replay retains raw parser API and requires zstd file envelope" {
    const allocator = std.testing.allocator;
    const raw = try buildSmokeTestReplayPayload(allocator);
    defer allocator.free(raw);

    var replay = try parseReplay(allocator, raw);
    defer replay.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 2), replay.tickCount());
    try std.testing.expectError(
        error.InvalidZstdPayload,
        inflateZstdFilePayload(allocator, raw, max_replay_payload_bytes),
    );

    const file_bytes = try wrapZstdFilePayload(allocator, raw);
    defer allocator.free(file_bytes);
    const inflated = try inflateZstdFilePayload(allocator, file_bytes, max_replay_payload_bytes);
    defer allocator.free(inflated);
    try std.testing.expectEqualSlices(u8, raw, inflated);
}

test "zstd file envelope rejects trailing bytes and concatenated frames" {
    const allocator = std.testing.allocator;
    const raw = try buildSmokeTestReplayPayload(allocator);
    defer allocator.free(raw);
    const frame = try wrapZstdFilePayload(allocator, raw);
    defer allocator.free(frame);

    const with_trailing_byte = try std.mem.concat(allocator, u8, &.{ frame, &.{0} });
    defer allocator.free(with_trailing_byte);
    try std.testing.expectError(
        error.InvalidZstdPayload,
        inflateZstdFilePayload(allocator, with_trailing_byte, max_replay_payload_bytes),
    );

    const concatenated_frames = try std.mem.concat(allocator, u8, &.{ frame, frame });
    defer allocator.free(concatenated_frames);
    try std.testing.expectError(
        error.InvalidZstdPayload,
        inflateZstdFilePayload(allocator, concatenated_frames, max_replay_payload_bytes),
    );

    const checksum_frame = try allocator.alloc(u8, frame.len + @sizeOf(u32));
    defer allocator.free(checksum_frame);
    @memcpy(checksum_frame[0..frame.len], frame);
    checksum_frame[zstd_magic.len] |= 0b0000_0100;
    const checksum: u32 = @truncate(std.hash.XxHash64.hash(0, raw));
    std.mem.writeInt(u32, checksum_frame[frame.len..][0..@sizeOf(u32)], checksum, .little);

    const checksum_inflated = try inflateZstdFilePayload(
        allocator,
        checksum_frame,
        max_replay_payload_bytes,
    );
    defer allocator.free(checksum_inflated);
    try std.testing.expectEqualSlices(u8, raw, checksum_inflated);

    checksum_frame[checksum_frame.len - 1] ^= 0x80;
    try std.testing.expectError(
        error.InvalidZstdPayload,
        inflateZstdFilePayload(allocator, checksum_frame, max_replay_payload_bytes),
    );
}

test "single-frame file inflater handles empty and multi-block payloads within the size ceiling" {
    const allocator = std.testing.allocator;

    const empty_frame = try wrapZstdFilePayload(allocator, &.{});
    defer allocator.free(empty_frame);
    const empty = try inflateZstdFilePayload(allocator, empty_frame, 0);
    defer allocator.free(empty);
    try std.testing.expectEqual(@as(usize, 0), empty.len);

    const raw = try allocator.alloc(u8, 128 * 1024 + 17);
    defer allocator.free(raw);
    for (raw, 0..) |*byte, index| byte.* = @truncate(index);
    const frame = try wrapZstdFilePayload(allocator, raw);
    defer allocator.free(frame);
    const inflated = try inflateZstdFilePayload(allocator, frame, raw.len);
    defer allocator.free(inflated);
    try std.testing.expectEqualSlices(u8, raw, inflated);
    try std.testing.expectError(
        error.PayloadTooLarge,
        inflateZstdFilePayload(allocator, frame, raw.len - 1),
    );
}

test "current replay parser rejects non-executable game modes" {
    const allocator = std.testing.allocator;
    for ([_]i32{ 0, 5, 999 }) |game_mode_id| {
        const raw = try buildSmokeTestReplayPayloadForMode(allocator, game_mode_id);
        defer allocator.free(raw);
        try std.testing.expectError(error.UnsupportedGameMode, parseReplay(allocator, raw));
        try std.testing.expectError(error.UnsupportedGameMode, parseReplaySummary(allocator, raw));
    }
}

test "parse current replay rejects hybrid string quest level fixture" {
    const compressed = @embedFile("../../tests/fixtures/replays/quest_1.5_20260303_211620_completed_t40512.crd");
    const inflated = try inflateZstdPayload(std.testing.allocator, compressed, max_replay_payload_bytes);
    defer std.testing.allocator.free(inflated);

    try std.testing.expectError(error.InvalidMsgpack, parseReplaySummary(std.testing.allocator, inflated));
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
            .dt = canonical_tick_dt_f64,
            .inputs = tick_inputs[0..],
            .prelude = &.{.{ .game_frame_rng_advance = .{ .frames = 2 } }},
            .postlude = &.{.{ .perk_menu_open = .{ .player_index = 0 } }},
            .commands = &.{
                .{
                    .type = "typo_char",
                    .player_index = 0,
                    .ch = "a",
                },
                .{
                    .type = "typo_backspace",
                    .player_index = 0,
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
    try std.testing.expectEqual(@as(usize, 1), replay.prelude.len);
    try std.testing.expect(replay.prelude[0] == .game_frame_rng_advance);
    try std.testing.expectEqual(@as(u32, 2), replay.prelude[0].game_frame_rng_advance.frames);
    try std.testing.expectEqual(@as(usize, 1), replay.postlude.len);
    try std.testing.expectEqual(@as(i32, 0), replay.postlude[0].player_index);
    try std.testing.expectEqual(@as(usize, 3), replay.events.len);
    try std.testing.expect(replay.events[0] == .typo_char);
    try std.testing.expectEqual(@as(u8, 'a'), replay.events[0].typo_char.ch);
    try std.testing.expect(replay.events[1] == .typo_backspace);
    try std.testing.expect(replay.events[2] == .typo_submit);

    const replay_summary = replay.summarizeEvents();
    try std.testing.expectEqual(@as(usize, 5), replay_summary.total_count);
    try std.testing.expectEqual(@as(usize, 1), replay_summary.game_frame_rng_advance_count);
    try std.testing.expectEqual(@as(usize, 1), replay_summary.perk_menu_open_count);
    try std.testing.expectEqual(@as(usize, 1), replay_summary.typo_char_count);
    try std.testing.expectEqual(@as(usize, 1), replay_summary.typo_backspace_count);
    try std.testing.expectEqual(@as(usize, 1), replay_summary.typo_submit_count);

    const parsed_summary = try parseReplaySummary(allocator, writer.written());
    defer parsed_summary.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 5), parsed_summary.events.total_count);
    try std.testing.expectEqual(@as(usize, 1), parsed_summary.events.game_frame_rng_advance_count);
    try std.testing.expectEqual(@as(usize, 1), parsed_summary.events.perk_menu_open_count);
    try std.testing.expectEqual(@as(usize, 1), parsed_summary.events.typo_char_count);
    try std.testing.expectEqual(@as(usize, 1), parsed_summary.events.typo_backspace_count);
    try std.testing.expectEqual(@as(usize, 1), parsed_summary.events.typo_submit_count);
}

test "unknown current replay command detail names command type and position" {
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
            .dt = canonical_tick_dt_f64,
            .inputs = tick_inputs[0..],
            .prelude = &.{},
            .postlude = &.{},
            .commands = &.{
                .{
                    .type = "network_ping",
                    .player_index = 0,
                },
            },
        },
    };

    const wire: ReplayCurrentWire = .{
        .header = .{
            .game_mode_id = @intFromEnum(game_ids.GameModeId.survival),
            .seed = 7,
            .replay_format_version = replay_format_version,
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

    try std.testing.expectError(error.UnknownCommandKind, parseReplay(allocator, writer.written()));
    const detail = (try replayUnknownCommandFailureDetail(allocator, writer.written())) orelse return error.TestExpectedDetail;
    defer allocator.free(detail);
    try std.testing.expectEqualStrings(
        "replay command type is unknown: type=network_ping tick=0 command_index=0",
        detail,
    );
}

test "current replay separates ordered prelude from typo commands" {
    try std.testing.expectError(
        error.UnsupportedEventShape,
        parseCurrentPrelude(.{ .perk_menu_open = .{ .player_index = 1 } }, 0, 1),
    );
    try std.testing.expectError(
        error.UnsupportedEventShape,
        parseCurrentPrelude(.{ .perk_pick = .{ .player_index = 0, .choice_index = 7 } }, 0, 1),
    );
    try std.testing.expectError(
        error.UnsupportedEventShape,
        parseCurrentPrelude(.{ .game_frame_rng_advance = .{ .frames = 0 } }, 0, 1),
    );
    try std.testing.expectError(
        error.UnsupportedEventShape,
        parseCurrentPostlude(.{ .perk_menu_open = .{ .player_index = 1 } }, 0, 1),
    );
    try std.testing.expectError(
        error.UnknownCommandKind,
        parseCurrentCommand(.{ .type = "perk_menu_open", .player_index = 0 }, 0, 1),
    );
}

test "current replay rejects noncanonical f32 wire values" {
    try std.testing.expect(canonicalF32(@as(f64, @as(f32, 0.1))) != null);
    try std.testing.expect(canonicalF32(@as(f64, 0.1)) == null);

    const bad_input = [_]ReplayInputWire{.{
        .move_x = 0.1,
        .move_y = 0.0,
        .aim_x = 0.0,
        .aim_y = 0.0,
        .flags = 0,
    }};
    const bad_input_ticks = [_]ReplayTickCurrentWire{.{
        .dt = canonical_tick_dt_f64,
        .inputs = bad_input[0..],
        .prelude = &.{},
        .postlude = &.{},
        .commands = &.{},
    }};
    try std.testing.expectError(error.UnsupportedInputShape, validateCurrentTicks(bad_input_ticks[0..], 1, @intFromEnum(game_ids.GameModeId.survival)));

    const good_input = [_]ReplayInputWire{.{
        .move_x = 0.0,
        .move_y = 0.0,
        .aim_x = 0.0,
        .aim_y = 0.0,
        .flags = 0,
    }};
    const bad_dt_ticks = [_]ReplayTickCurrentWire{.{
        .dt = 1.0 / 60.0,
        .inputs = good_input[0..],
        .prelude = &.{},
        .postlude = &.{},
        .commands = &.{},
    }};
    try std.testing.expectError(error.UnsupportedInputShape, validateCurrentTicks(bad_dt_ticks[0..], 1, @intFromEnum(game_ids.GameModeId.survival)));

    const usage_counts = [_]u32{0} ** weapon_usage_count;
    const header: ReplayHeaderCurrentWire = .{
        .game_mode_id = @intFromEnum(game_ids.GameModeId.survival),
        .seed = 1,
        .replay_format_version = replay_format_version,
        .quest_level = null,
        .game_version = "0.9.0",
        .world_size = 0.1,
        .player_count = 1,
        .status = .{ .weapon_usage_counts = usage_counts[0..] },
        .claimed_stats = .{},
    };
    try std.testing.expectError(error.InvalidHeaderValue, buildHeaderCurrent(std.testing.allocator, header));

    const residue: ReplayCreatureSlotResidueWire = .{
        .index = 0,
        .phase_seed = 0.1,
        .state_flag = 0,
        .collision_flag = 0,
        .collision_timer = 0.0,
        .lifecycle_stage = 0.0,
        .pos = .{ .x = 0.0, .y = 0.0 },
        .vel = .{ .x = 0.0, .y = 0.0 },
        .hp = 0.0,
        .max_hp = 0.0,
        .heading = 0.0,
        .target_heading = 0.0,
        .size = 0.0,
        .hit_flash_timer = 0.0,
        .tint_r = 0.0,
        .tint_g = 0.0,
        .tint_b = 0.0,
        .tint_a = 0.0,
        .force_target = 0,
        .target = .{ .x = 0.0, .y = 0.0 },
        .contact_damage = 0.0,
        .move_speed = 0.0,
        .attack_cooldown = 0.0,
        .reward_value = 0.0,
        .type_id = 0,
        .target_player = 0,
        .link_index = 0,
        .target_offset = .{ .x = 0.0, .y = 0.0 },
        .orbit_angle = 0.0,
        .orbit_radius_u32 = 0,
        .flags = 0,
        .ai_mode = 0,
        .anim_phase = 0.0,
    };
    try std.testing.expectError(
        error.InvalidHeaderValue,
        buildCreaturePoolResidue(std.testing.allocator, &.{residue}),
    );

    var first = residue;
    first.index = 1;
    first.phase_seed = 0.0;
    var duplicate = first;
    duplicate.index = 1;
    try std.testing.expectError(
        error.InvalidHeaderValue,
        buildCreaturePoolResidue(std.testing.allocator, &.{ first, duplicate }),
    );
}

fn testCurrentHeaderWire() ReplayHeaderCurrentWire {
    return .{
        .game_mode_id = @intFromEnum(game_ids.GameModeId.survival),
        .seed = 1,
        .replay_format_version = replay_format_version,
        .quest_level = null,
        .game_version = "0.9.0",
        .tick_rate = 60,
        .quest_fail_retry_count = 0,
        .hardcore = false,
        .preserve_bugs = false,
        .detail_preset = 5,
        .violence_disabled = 0,
        .world_size = 1024.0,
        .player_count = 1,
        .status = .{
            .weapon_usage_counts = &([_]u32{0} ** weapon_usage_count),
        },
        .claimed_stats = .{},
        .input_quantization = "f32",
    };
}

test "current header enforces latest semantic constraints" {
    var wire = testCurrentHeaderWire();

    wire.quest_level = .{ .major = 1, .minor = 1 };
    try std.testing.expectError(error.InvalidHeaderValue, buildHeaderCurrent(std.testing.allocator, wire));

    wire.game_mode_id = @intFromEnum(game_ids.GameModeId.quests);
    wire.quest_level = .{ .major = 0, .minor = 1 };
    try std.testing.expectError(error.InvalidHeaderValue, buildHeaderCurrent(std.testing.allocator, wire));
    wire.quest_level = .{ .major = 1, .minor = 11 };
    try std.testing.expectError(error.InvalidHeaderValue, buildHeaderCurrent(std.testing.allocator, wire));

    wire = testCurrentHeaderWire();
    wire.player_count = max_players + 1;
    try std.testing.expectError(error.InvalidHeaderValue, buildHeaderCurrent(std.testing.allocator, wire));
    wire = testCurrentHeaderWire();
    wire.quest_fail_retry_count = -1;
    try std.testing.expectError(error.InvalidHeaderValue, buildHeaderCurrent(std.testing.allocator, wire));
    wire = testCurrentHeaderWire();
    wire.detail_preset = -1;
    try std.testing.expectError(error.InvalidHeaderValue, buildHeaderCurrent(std.testing.allocator, wire));
    wire = testCurrentHeaderWire();
    wire.violence_disabled = -1;
    try std.testing.expectError(error.InvalidHeaderValue, buildHeaderCurrent(std.testing.allocator, wire));
    wire = testCurrentHeaderWire();
    wire.claimed_stats.most_used_weapon_id = -1;
    try std.testing.expectError(error.InvalidHeaderValue, buildHeaderCurrent(std.testing.allocator, wire));
    wire = testCurrentHeaderWire();
    wire.claimed_stats.most_used_weapon_id = 54;
    try std.testing.expectError(error.InvalidHeaderValue, buildHeaderCurrent(std.testing.allocator, wire));
}

test "current input flags enforce the shared packed-bit contract" {
    const invalid = [_]i32{
        -1,
        1 << 17,
        move_forward_flag,
        1 << move_mode_shift,
        move_mode_present_flag | (6 << move_mode_shift),
        1 << aim_scheme_shift,
        aim_scheme_present_flag | (6 << aim_scheme_shift),
    };
    for (invalid) |flags| {
        try std.testing.expectError(error.UnsupportedInputShape, parseInputFlagsValue(flags));
    }

    try std.testing.expectEqual(
        aim_scheme_present_flag | (7 << aim_scheme_shift),
        try parseInputFlagsValue(aim_scheme_present_flag | (7 << aim_scheme_shift)),
    );
}

test "build current header rejects quest replay without quest level" {
    const usage_counts = [_]u32{0} ** weapon_usage_count;
    const wire: ReplayHeaderCurrentWire = .{
        .game_mode_id = @intFromEnum(game_ids.GameModeId.quests),
        .seed = 1,
        .replay_format_version = replay_format_version,
        .quest_level = null,
        .game_version = "0.9.0",
        .tick_rate = 60,
        .quest_fail_retry_count = 0,
        .hardcore = false,
        .preserve_bugs = false,
        .detail_preset = 5,
        .violence_disabled = 0,
        .world_size = 1024.0,
        .player_count = 1,
        .status = .{
            .quest_unlock_index = 0,
            .quest_unlock_index_full = 0,
            .weapon_usage_counts = usage_counts[0..],
        },
        .claimed_stats = .{},
        .input_quantization = "f32",
    };
    try std.testing.expectError(error.MissingQuestLevel, buildHeaderCurrent(std.testing.allocator, wire));
}

test "current header rejects multiplayer Typ-o and tutorial replays" {
    const usage_counts = [_]u32{0} ** weapon_usage_count;
    const cases = [_]struct {
        game_mode_id: i32,
        expected_error: ReplayCodecError,
    }{
        .{
            .game_mode_id = @intFromEnum(game_ids.GameModeId.typo),
            .expected_error = error.TypoMultiplayer,
        },
        .{
            .game_mode_id = @intFromEnum(game_ids.GameModeId.tutorial),
            .expected_error = error.TutorialMultiplayer,
        },
    };

    for (cases) |case| {
        const current_wire: ReplayHeaderCurrentWire = .{
            .game_mode_id = case.game_mode_id,
            .seed = 1,
            .replay_format_version = replay_format_version,
            .quest_level = null,
            .game_version = "0.9.0",
            .tick_rate = 60,
            .quest_fail_retry_count = 0,
            .hardcore = false,
            .preserve_bugs = false,
            .detail_preset = 5,
            .violence_disabled = 0,
            .world_size = 1024.0,
            .player_count = 2,
            .status = .{
                .quest_unlock_index = 0,
                .quest_unlock_index_full = 0,
                .weapon_usage_counts = usage_counts[0..],
            },
            .claimed_stats = .{},
            .input_quantization = "f32",
        };
        try std.testing.expectError(case.expected_error, buildHeaderCurrent(std.testing.allocator, current_wire));
    }
}

test "unsupported replay header detail reports missing quest level" {
    const allocator = std.testing.allocator;
    const header: ReplayHeader = .{
        .game_mode_id = @intFromEnum(game_ids.GameModeId.quests),
        .seed = 1,
        .replay_format_version = replay_format_version,
        .quest_level = try allocator.dupe(u8, ""),
        .game_version = try allocator.dupe(u8, "0.9.0"),
        .tick_rate = 60,
        .quest_fail_retry_count = 0,
        .hardcore = false,
        .preserve_bugs = false,
        .detail_preset = 5,
        .violence_disabled = 0,
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

    try std.testing.expectEqualStrings(
        "quest replays require a valid header.quest_level",
        unsupportedReplayHeaderDetail(header, 1, .verifier).?,
    );
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

test "parse replay rejects non-msgpack payload generically" {
    const payload = " \n{\"header\":{\"game_mode_id\":1,\"seed\":1}}";

    try std.testing.expectError(error.InvalidMsgpack, parseReplaySummary(std.testing.allocator, payload));
    try std.testing.expectError(error.InvalidMsgpack, parseReplay(std.testing.allocator, payload));
}

test "binary bytes reader accepts msgpack bin8 payloads" {
    const payload = [_]u8{ 0xC4, 0x04, 0xDE, 0xAD, 0xBE, 0xEF };
    var decoded = try msgpack.decodeFromSlice(BinaryBytes, std.testing.allocator, &payload);
    defer decoded.deinit();

    try std.testing.expectEqualSlices(u8, &.{ 0xDE, 0xAD, 0xBE, 0xEF }, decoded.value.data);
}
