const builtin = @import("builtin");
const std = @import("std");
const msgpack = @import("msgpack");

const game_ids = @import("game_ids.zig");
const hash = @import("hash.zig");
const replay_codec = @import("replay_codec.zig");
const replay_runner = @import("runtime/replay_runner.zig");
const state_mod = @import("runtime/state.zig");

const trace_magic = "crimson_debug_trace_v1\n";
pub const trace_format_version: u32 = 1;
pub const trace_schema_version: i32 = 12;
pub const trace_required_channels = "checkpoint,sim_state,entity_samples,rng_stream,timing_samples";
const trace_chunk_ticks: usize = 256;

const chunk_kind_meta = "META";
const chunk_kind_tick = "TICK";
const chunk_kind_footer = "FOTR";
const trailer_magic = "CDTFTR1\n";

const chunk_flag_msgpack: u32 = 1 << 1;
const chunk_header_len: usize = 4 + 4 + 4 + 4 + 4 + 4 + 8;

const empty_strings: []const []const u8 = &.{};
const quest_reload_sfx_head: []const []const u8 = &.{"sfx_pistol_reload"};

const empty_rng_stream: []const RngStreamRow = &.{};
const empty_timing_samples: []const TimingSampleRow = &.{};
const empty_i32: []const i32 = &.{};
const empty_perk_pairs: []const [2]i32 = &.{};
const empty_deaths: []const ReplayDeathLedgerEntry = &.{};

const TraceDomainError = error{
    EmptyTrace,
    InvalidTickIndex,
    InvalidTickOrder,
    InvalidReplayDt,
    RngTransitionNotReconstructable,
    TickIndexTooLarge,
    TickValueTooLarge,
    PayloadTooLarge,
    NumericOverflow,
};

const TraceFsError = std.Io.Dir.CreateDirPathError || std.Io.Dir.StatFileError || std.Io.File.OpenError || std.Io.File.Writer.Error || std.Io.File.StatError;
const TraceWriterError = std.Io.Writer.Error;
const TraceAllocError = std.mem.Allocator.Error;
const TraceMsgpackError = error{
    MapTooLong,
    StringTooLong,
    ArrayTooLong,
};

pub const TraceWriteError = TraceDomainError || TraceFsError || TraceWriterError || TraceAllocError || TraceMsgpackError;

pub const HealthOptions = struct {
    tick_start: ?i32 = null,
    tick_end: ?i32 = null,
};

pub const ChannelCounts = struct {
    checkpoint: i32 = 0,
    sim_state: i32 = 0,
    entity_samples: i32 = 0,
    rng_stream: i32 = 0,
    timing_samples: i32 = 0,
};

pub const ChannelRowCounts = struct {
    rng_stream: i32 = 0,
    timing_samples: i32 = 0,
};

pub const TickWindowSummary = struct {
    requested_start: ?i32 = null,
    requested_end: ?i32 = null,
    actual_start: ?i32 = null,
    actual_end: ?i32 = null,
    ticks_in_window: i32 = 0,
};

pub const HealthMetrics = struct {
    ticks_with_dt_ms_i32: i32 = 0,
    rng_stream_rows: i32 = 0,
    sim_state_rows: i32 = 0,
    sample_creature_rows: i32 = 0,
    sample_projectile_rows: i32 = 0,
    sample_secondary_projectile_rows: i32 = 0,
    sample_bonus_rows: i32 = 0,
    timing_samples_rows: i32 = 0,
};

pub const HealthSummary = struct {
    trace_format_version: i32,
    trace_schema_version: i32,
    tick_window: TickWindowSummary,
    channels_present: ChannelCounts,
    channel_row_counts: ChannelRowCounts,
    metrics: HealthMetrics,
    issues: []const []const u8,
    ok_for_parity_analysis: bool,

    pub fn deinit(self: HealthSummary, allocator: std.mem.Allocator) void {
        allocator.free(self.issues);
    }
};

pub const TickCheckpointSummary = struct {
    score_xp: i32,
    kills: i32,
    creature_count: i32,
    perk_pending: i32,
};

pub const TickEntityCounts = struct {
    creatures: i32,
    projectiles: i32,
    secondary_projectiles: i32,
    bonuses: i32,
};

pub const TickSummary = struct {
    tick_index: i32,
    elapsed_ms: i64,
    dt_ms_i32: i32,
    mode_id: i32,
    checkpoint: TickCheckpointSummary,
    entity_counts: TickEntityCounts,
    rng_stream_count: i32,
    timing_samples_count: i32,
    event_count_total: i32,
    top_event_types: []const []const u8,

    pub fn deinit(self: TickSummary, allocator: std.mem.Allocator) void {
        for (self.top_event_types) |entry| allocator.free(entry);
        allocator.free(self.top_event_types);
    }
};

pub const EntityHistoryOptions = struct {
    tick_start: ?i32 = null,
    tick_end: ?i32 = null,
};

pub const TraceVec2Summary = struct {
    x: f32,
    y: f32,
};

pub const EntitySampleSummary = struct {
    tick_index: i32,
    uid: i32,
    generation: i32,
    pool_kind: []const u8,
    index: i32,
    active: bool,
    type_id: ?i32 = null,
    hp: ?f32 = null,
    pos: TraceVec2Summary,
};

pub const EntityHistorySummary = struct {
    entity_uid: i32,
    pool_kind: []const u8,
    spawn_tick: i32,
    despawn_tick: i32,
    samples: []const EntitySampleSummary,

    pub fn deinit(self: EntityHistorySummary, allocator: std.mem.Allocator) void {
        allocator.free(self.samples);
    }
};

pub const QueryScope = enum {
    ticks,
    entities,
};

pub const QueryField = enum {
    tick_index,
    mode_id,
    dt_ms_i32,
    checkpoint_score_xp,
    checkpoint_kills,
    checkpoint_creature_count,
    checkpoint_perk_pending,
    entity_count_creatures,
    entity_count_projectiles,
    entity_count_secondary_projectiles,
    entity_count_bonuses,
    rng_stream_count,
    timing_samples_count,
    event_count_total,
    uid,
    generation,
    index,
    type_id,
    hp,
    pool_kind,
};

pub const QueryOp = enum {
    eq,
    ne,
    gt,
    ge,
    lt,
    le,
};

pub const QueryLiteral = union(enum) {
    int: i64,
    float: f64,
    string: []const u8,
};

pub const QueryRequest = struct {
    scope: QueryScope,
    expression: []const u8,
    field: QueryField,
    op: QueryOp,
    literal: QueryLiteral,
    limit: usize = 256,
};

pub const QueryRow = struct {
    tick_index: i32,
    mode_id: ?i32 = null,
    dt_ms_i32: ?i32 = null,
    uid: ?i32 = null,
    generation: ?i32 = null,
    pool_kind: ?[]const u8 = null,
    index: ?i32 = null,
    type_id: ?i32 = null,
    hp: ?f32 = null,
    entity_count_creatures: ?i32 = null,
    entity_count_projectiles: ?i32 = null,
    entity_count_secondary_projectiles: ?i32 = null,
    entity_count_bonuses: ?i32 = null,
    checkpoint_score_xp: ?i32 = null,
    checkpoint_kills: ?i32 = null,
    checkpoint_creature_count: ?i32 = null,
    checkpoint_perk_pending: ?i32 = null,
    rng_stream_count: ?i32 = null,
    timing_samples_count: ?i32 = null,
    event_count_total: ?i32 = null,
};

pub const QueryResult = struct {
    scope: []const u8,
    expression: []const u8,
    limit: usize,
    match_count: usize,
    truncated: bool,
    rows: []const QueryRow,

    pub fn deinit(self: QueryResult, allocator: std.mem.Allocator) void {
        allocator.free(self.rows);
    }
};

pub const TraceDiffOptions = struct {
    tick_start: ?i32 = null,
    tick_end: ?i32 = null,
};

pub const TraceDiffMismatch = struct {
    kind: []const u8,
    tick_index: i32,
    field: ?[]const u8 = null,
    expected: ?i64 = null,
    actual: ?i64 = null,
};

pub const TraceDiffReport = struct {
    ok: bool,
    checked_count: usize,
    tick_start: ?i32,
    tick_end: ?i32,
    mismatch: ?TraceDiffMismatch = null,
};

pub const TraceBisectReport = struct {
    ok: bool,
    first_bad_tick: ?i32,
    checked_count: usize,
    mismatch: ?TraceDiffMismatch = null,
    window_start: ?i32 = null,
    window_end: ?i32 = null,
};

const TickRange = struct {
    start_tick: i32,
    end_tick: i32,
    tick_count: i32,
};

const Producer = struct {
    impl: []const u8 = "zig",
    impl_version: []const u8 = "",
    platform: []const u8,
    arch: []const u8,
};

const Source = struct {
    path: []const u8,
    sha256: []const u8,
    size: u64,
    mtime_ns: i64,
    tick_rate: i32,
    seed: u32,
    mode_id: i32,
    quest_level: []const u8,
};

const TraceMeta = struct {
    trace_format_version: i32 = @intCast(trace_format_version),
    trace_schema_version: i32 = trace_schema_version,
    created_utc: []const u8,
    producer: Producer,
    source: Source,
    tick_range: TickRange,
    status: replay_codec.ReplayStatus = .{},
};

const TraceStatusRead = struct {
    quest_unlock_index: i32 = 0,
    quest_unlock_index_full: i32 = 0,
    weapon_usage_counts: []const u32 = &.{},
};

const TraceMetaRead = struct {
    trace_format_version: i32 = @intCast(trace_format_version),
    trace_schema_version: i32 = trace_schema_version,
    created_utc: []const u8,
    producer: Producer,
    source: Source,
    tick_range: TickRange,
    status: TraceStatusRead = .{},
};

const TickBlockIndexEntry = struct {
    start_tick: i32,
    end_tick: i32,
    file_offset: i64,
    compressed_len: i32,
    uncompressed_len: i32,
    checksum: u64,
};

const TraceFooter = struct {
    tick_blocks: []const TickBlockIndexEntry,
    tick_count: i32,
    first_tick: i32,
    last_tick: i32,
};

const SnapshotVec2 = struct {
    x: f32,
    y: f32,
};

const SnapshotWeapon = struct {
    weapon_id: i32,
    ammo: f32,
    clip_size: i32,
    reload_active: bool,
    reload_timer: f32,
    reload_timer_max: f32,
    shot_cooldown: f32,
};

const SnapshotPlayer = struct {
    index: i32,
    pos: SnapshotVec2,
    health: f32,
    weapon: SnapshotWeapon,
    experience: i32,
    level: i32,
};

const SnapshotBonusTimers = struct {
    weapon_power_up_ms: i32,
    reflex_boost_ms: i32,
    energizer_ms: i32,
    double_experience_ms: i32,
    freeze_ms: i32,
};

const SnapshotGameplay = struct {
    mode_id: i32,
    quest_stage_major: i32,
    quest_stage_minor: i32,
    perk_pending_count: i32,
    perk_choices_dirty: bool = false,
    bonus_timers: SnapshotBonusTimers,
};

const SimStateSnapshot = struct {
    gameplay: SnapshotGameplay,
    players: []const SnapshotPlayer,
};

const RngStreamRow = struct {
    tick_call_index: i32,
    value_15: i32,
    state_before_u32: i64,
    state_after_u32: i64,
    caller: ?i32 = null,
};

const TimingSampleRow = struct {
    tick_index: i32,
    gameplay_frame: ?i32 = null,
    phase: []const u8 = "",
    write_kind: []const u8 = "snapshot",
    frame_dt_f32: ?f32 = null,
    frame_dt_ms_i32: ?i32 = null,
    frame_dt_ms_f32: ?f32 = null,
    time_scale_active_entry: ?bool = null,
    time_scale_active_current: ?bool = null,
    time_scale_factor: ?f32 = null,
    bonus_reflex_boost_timer: ?f32 = null,
    mode_fn: ?[]const u8 = null,
    player_index: ?i32 = null,
};

const CreatureEntitySample = struct {
    uid: i32,
    generation: i32,
    pool_kind: []const u8,
    index: i32,
    active: bool,
    type_id: i32,
    hp: f32,
    pos: SnapshotVec2,
    flags: i32,
    ai_mode: i32,
    link_index: i32,
    heading: f32,
    target_heading: f32,
    orbit_angle: f32,
    orbit_radius: f32,
    lifecycle_stage: f32,
};

const ProjectileEntitySample = struct {
    uid: i32,
    generation: i32,
    pool_kind: []const u8,
    index: i32,
    active: bool,
    type_id: i32,
    angle: f32,
    pos: SnapshotVec2,
    vel: SnapshotVec2,
    life_timer: f32,
    speed_scale: f32,
    damage_pool: f32,
    hit_radius: f32,
    travel_budget: f32,
    owner_id: i32,
};

const SecondaryProjectileEntitySample = struct {
    uid: i32,
    generation: i32,
    pool_kind: []const u8,
    index: i32,
    active: bool,
    type_id: i32,
    angle: f32,
    pos: SnapshotVec2,
    vel: SnapshotVec2,
    speed: f32,
    trail_timer: f32,
    owner_id: i32,
    target_id: i32,
};

const BonusEntitySample = struct {
    uid: i32,
    generation: i32,
    pool_kind: []const u8,
    index: i32,
    active: bool,
    bonus_id: i32,
    picked: bool,
    time_left: f32,
    time_max: f32,
    pos: SnapshotVec2,
    amount: i32,
};

const EntitySamplesSnapshot = struct {
    creatures: []const CreatureEntitySample,
    projectiles: []const ProjectileEntitySample,
    secondary_projectiles: []const SecondaryProjectileEntitySample,
    bonuses: []const BonusEntitySample,
};

const CheckpointVec2 = struct {
    x: f64,
    y: f64,
};

const ReplayPlayerCheckpointChannel = struct {
    pos: CheckpointVec2,
    health: f64,
    weapon_id: i32,
    ammo: f64,
    experience: i32,
    level: i32,
};

const BonusTimersMap = struct {
    @"4": i32, // weapon_power_up
    @"9": i32, // reflex_boost
    @"2": i32, // energizer
    @"6": i32, // double_experience
    @"11": i32, // freeze
};

const ReplayDeathLedgerEntry = struct {
    creature_index: i32,
    type_id: i32,
    reward_value: f32,
    xp_awarded: i32,
    owner_id: i32,
};

const ReplayPerkSnapshotChannel = struct {
    pending_count: i32,
    choices_dirty: bool = false,
    choices: []const i32 = empty_i32,
    player_nonzero_counts: []const []const [2]i32,
};

const ReplayEventSummaryChannel = struct {
    hit_count: i32 = 0,
    pickup_count: i32 = 0,
    sfx_count: i32 = 0,
    sfx_head: []const []const u8 = empty_strings,
};

const CheckpointChannel = struct {
    tick_index: i32,
    rng_state: i64,
    elapsed_ms: i64,
    score_xp: i32,
    kills: i32,
    creature_count: i32,
    perk_pending: i32,
    players: []const ReplayPlayerCheckpointChannel,
    bonus_timers: BonusTimersMap,
    state_hash: []const u8 = "",
    command_hash: []const u8 = "",
    deaths: []const ReplayDeathLedgerEntry = empty_deaths,
    perk: ReplayPerkSnapshotChannel,
    events: ReplayEventSummaryChannel = .{},
};

const TickChannels = struct {
    checkpoint: CheckpointChannel,
    sim_state: SimStateSnapshot,
    entity_samples: EntitySamplesSnapshot,
    rng_stream: []const RngStreamRow = empty_rng_stream,
    timing_samples: []const TimingSampleRow = empty_timing_samples,
};

const TickRecord = struct {
    tick_index: i32,
    elapsed_ms: i64,
    dt_ms_i32: i32,
    mode_id: i32,
    channels: TickChannels,
};

const TickBlock = struct {
    start_tick: i32,
    end_tick: i32,
    ticks: []const TickRecord,
};

const ReplayPerkSnapshotChannelRead = struct {
    pending_count: i32,
    choices_dirty: bool = false,
    choices: []const i32 = empty_i32,
    player_nonzero_counts: []const []const []const i32,
};

const CheckpointChannelRead = struct {
    tick_index: i32,
    rng_state: i64,
    elapsed_ms: i64,
    score_xp: i32,
    kills: i32,
    creature_count: i32,
    perk_pending: i32,
    players: []const ReplayPlayerCheckpointChannel,
    bonus_timers: BonusTimersMap,
    state_hash: []const u8 = "",
    command_hash: []const u8 = "",
    deaths: []const ReplayDeathLedgerEntry = empty_deaths,
    perk: ReplayPerkSnapshotChannelRead,
    events: ReplayEventSummaryChannel = .{},
};

const TickChannelsRead = struct {
    checkpoint: CheckpointChannelRead,
    sim_state: SimStateSnapshot,
    entity_samples: EntitySamplesSnapshot,
    rng_stream: []const RngStreamRow = empty_rng_stream,
    timing_samples: []const TimingSampleRow = empty_timing_samples,
};

const TickRecordRead = struct {
    tick_index: i32,
    elapsed_ms: i64,
    dt_ms_i32: i32,
    mode_id: i32,
    channels: TickChannelsRead,
};

const TickBlockRead = struct {
    start_tick: i32,
    end_tick: i32,
    ticks: []const TickRecordRead,
};

const ChunkPayload = struct {
    kind: []const u8,
    start_tick: i32,
    end_tick: i32,
    payload: []const u8,
};

pub fn summarizeTraceHealthFile(
    allocator: std.mem.Allocator,
    io: std.Io,
    trace_path: []const u8,
    options: HealthOptions,
) !HealthSummary {
    const bytes = try std.Io.Dir.cwd().readFileAlloc(io, trace_path, allocator, .limited(256 * 1024 * 1024));
    defer allocator.free(bytes);
    return summarizeTraceHealthBytes(allocator, bytes, options);
}

pub fn summarizeTraceHealthBytes(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    options: HealthOptions,
) !HealthSummary {
    if (bytes.len < trace_magic.len + 4 + trailer_magic.len + 8) return error.InvalidTraceHeader;
    if (!std.mem.startsWith(u8, bytes, trace_magic)) return error.InvalidTraceMagic;
    const version = readU32Le(bytes[trace_magic.len..][0..4]);
    if (version != trace_format_version) return error.UnsupportedTraceFormatVersion;

    const meta_offset = trace_magic.len + 4;
    const meta_chunk = try chunkPayloadAt(bytes, meta_offset);
    if (!std.mem.eql(u8, meta_chunk.kind, chunk_kind_meta)) return error.InvalidTraceMetaChunk;
    var decoded_meta = try msgpack.decodeFromSlice(TraceMetaRead, allocator, meta_chunk.payload);
    defer decoded_meta.deinit();
    const meta = decoded_meta.value;

    const trailer_offset = bytes.len - trailer_magic.len - 8;
    if (!std.mem.eql(u8, bytes[trailer_offset..][0..trailer_magic.len], trailer_magic)) return error.InvalidTraceTrailer;
    const footer_offset_u64 = readU64Le(bytes[trailer_offset + trailer_magic.len ..][0..8]);
    if (footer_offset_u64 > std.math.maxInt(usize)) return error.InvalidTraceFooterOffset;
    const footer_offset: usize = @intCast(footer_offset_u64);
    const footer_chunk = try chunkPayloadAt(bytes, footer_offset);
    if (!std.mem.eql(u8, footer_chunk.kind, chunk_kind_footer)) return error.InvalidTraceFooterChunk;
    var decoded_footer = try msgpack.decodeFromSlice(TraceFooter, allocator, footer_chunk.payload);
    defer decoded_footer.deinit();
    const footer = decoded_footer.value;
    if (footer.tick_count <= 0) return error.InvalidTraceFooter;
    if (footer.first_tick < 0 or footer.last_tick < 0) return error.InvalidTraceFooter;
    if (footer.first_tick > footer.last_tick) return error.InvalidTraceFooter;
    if (footer.tick_blocks.len == 0) return error.InvalidTraceFooter;

    var channels_present: ChannelCounts = .{};
    var channel_row_counts: ChannelRowCounts = .{};
    var metrics: HealthMetrics = .{};
    var ticks_total: i32 = 0;
    var actual_start: ?i32 = null;
    var actual_end: ?i32 = null;

    for (footer.tick_blocks) |entry| {
        if (options.tick_start) |tick_start| {
            if (entry.end_tick < tick_start) continue;
        }
        if (options.tick_end) |tick_end| {
            if (entry.start_tick > tick_end) continue;
        }

        if (entry.file_offset < 0) return error.InvalidTraceBlockOffset;
        const block_offset: usize = @intCast(entry.file_offset);
        const tick_chunk = try chunkPayloadAt(bytes, block_offset);
        if (!std.mem.eql(u8, tick_chunk.kind, chunk_kind_tick)) return error.InvalidTraceTickChunk;
        if (tick_chunk.start_tick != entry.start_tick or tick_chunk.end_tick != entry.end_tick) return error.InvalidTraceTickChunk;
        if (entry.uncompressed_len < 0) return error.InvalidTraceTickChunk;
        if (tick_chunk.payload.len != @as(usize, @intCast(entry.uncompressed_len))) return error.InvalidTraceTickChunk;
        if (checksum64(tick_chunk.payload) != entry.checksum) return error.InvalidTraceChecksum;

        var decoded_block = try msgpack.decodeFromSlice(TickBlockRead, allocator, tick_chunk.payload);
        defer decoded_block.deinit();
        const block = decoded_block.value;
        if (block.start_tick != entry.start_tick or block.end_tick != entry.end_tick) return error.InvalidTraceTickBlock;

        for (block.ticks) |tick| {
            if (options.tick_start) |tick_start| {
                if (tick.tick_index < tick_start) continue;
            }
            if (options.tick_end) |tick_end| {
                if (tick.tick_index > tick_end) continue;
            }

            ticks_total += 1;
            metrics.ticks_with_dt_ms_i32 += 1;
            if (actual_start == null or tick.tick_index < actual_start.?) actual_start = tick.tick_index;
            if (actual_end == null or tick.tick_index > actual_end.?) actual_end = tick.tick_index;

            channels_present.checkpoint += 1;
            channels_present.sim_state += 1;
            channels_present.entity_samples += 1;
            channels_present.rng_stream += 1;
            channels_present.timing_samples += 1;

            metrics.sim_state_rows += 1;
            metrics.rng_stream_rows += @intCast(tick.channels.rng_stream.len);
            metrics.timing_samples_rows += @intCast(tick.channels.timing_samples.len);
            metrics.sample_creature_rows += @intCast(tick.channels.entity_samples.creatures.len);
            metrics.sample_projectile_rows += @intCast(tick.channels.entity_samples.projectiles.len);
            metrics.sample_secondary_projectile_rows += @intCast(tick.channels.entity_samples.secondary_projectiles.len);
            metrics.sample_bonus_rows += @intCast(tick.channels.entity_samples.bonuses.len);
        }
    }

    channel_row_counts.rng_stream = metrics.rng_stream_rows;
    channel_row_counts.timing_samples = metrics.timing_samples_rows;

    var issues: std.ArrayList([]const u8) = .empty;
    errdefer issues.deinit(allocator);
    if (ticks_total == 0) {
        try issues.append(allocator, "trace window has no ticks");
    }
    if (channels_present.checkpoint <= 0) try issues.append(allocator, "checkpoint channel missing");
    if (channels_present.sim_state <= 0) try issues.append(allocator, "sim_state channel missing");
    if (channels_present.entity_samples <= 0) try issues.append(allocator, "entity_samples channel missing");
    if (channels_present.rng_stream <= 0) try issues.append(allocator, "rng_stream channel missing");
    if (channels_present.timing_samples <= 0) try issues.append(allocator, "timing_samples channel missing");
    if (ticks_total > 0) {
        if (channel_row_counts.rng_stream <= 0) try issues.append(allocator, "rng_stream channel has no rows in trace window");
        if (channel_row_counts.timing_samples <= 0) try issues.append(allocator, "timing_samples channel has no rows in trace window");
    }

    const owned_issues = try issues.toOwnedSlice(allocator);
    return .{
        .trace_format_version = meta.trace_format_version,
        .trace_schema_version = meta.trace_schema_version,
        .tick_window = .{
            .requested_start = options.tick_start,
            .requested_end = options.tick_end,
            .actual_start = actual_start,
            .actual_end = actual_end,
            .ticks_in_window = ticks_total,
        },
        .channels_present = channels_present,
        .channel_row_counts = channel_row_counts,
        .metrics = metrics,
        .issues = owned_issues,
        .ok_for_parity_analysis = owned_issues.len == 0,
    };
}

pub fn summarizeTraceTickFile(
    allocator: std.mem.Allocator,
    io: std.Io,
    trace_path: []const u8,
    tick_index: i32,
) !TickSummary {
    const bytes = try std.Io.Dir.cwd().readFileAlloc(io, trace_path, allocator, .limited(256 * 1024 * 1024));
    defer allocator.free(bytes);
    return summarizeTraceTickBytes(allocator, bytes, tick_index);
}

pub fn summarizeTraceTickBytes(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    tick_index: i32,
) !TickSummary {
    if (tick_index < 0) return error.TickNotFound;
    if (bytes.len < trace_magic.len + 4 + trailer_magic.len + 8) return error.InvalidTraceHeader;
    if (!std.mem.startsWith(u8, bytes, trace_magic)) return error.InvalidTraceMagic;
    const version = readU32Le(bytes[trace_magic.len..][0..4]);
    if (version != trace_format_version) return error.UnsupportedTraceFormatVersion;

    const trailer_offset = bytes.len - trailer_magic.len - 8;
    if (!std.mem.eql(u8, bytes[trailer_offset..][0..trailer_magic.len], trailer_magic)) return error.InvalidTraceTrailer;
    const footer_offset_u64 = readU64Le(bytes[trailer_offset + trailer_magic.len ..][0..8]);
    if (footer_offset_u64 > std.math.maxInt(usize)) return error.InvalidTraceFooterOffset;
    const footer_offset: usize = @intCast(footer_offset_u64);
    const footer_chunk = try chunkPayloadAt(bytes, footer_offset);
    if (!std.mem.eql(u8, footer_chunk.kind, chunk_kind_footer)) return error.InvalidTraceFooterChunk;
    var decoded_footer = try msgpack.decodeFromSlice(TraceFooter, allocator, footer_chunk.payload);
    defer decoded_footer.deinit();
    const footer = decoded_footer.value;

    for (footer.tick_blocks) |entry| {
        if (tick_index < entry.start_tick or tick_index > entry.end_tick) continue;
        if (entry.file_offset < 0) return error.InvalidTraceBlockOffset;
        const tick_chunk = try chunkPayloadAt(bytes, @intCast(entry.file_offset));
        if (!std.mem.eql(u8, tick_chunk.kind, chunk_kind_tick)) return error.InvalidTraceTickChunk;
        if (tick_chunk.start_tick != entry.start_tick or tick_chunk.end_tick != entry.end_tick) return error.InvalidTraceTickChunk;
        if (entry.uncompressed_len < 0) return error.InvalidTraceTickChunk;
        if (tick_chunk.payload.len != @as(usize, @intCast(entry.uncompressed_len))) return error.InvalidTraceTickChunk;
        if (checksum64(tick_chunk.payload) != entry.checksum) return error.InvalidTraceChecksum;

        var decoded_block = try msgpack.decodeFromSlice(TickBlockRead, allocator, tick_chunk.payload);
        defer decoded_block.deinit();
        const block = decoded_block.value;
        if (block.start_tick != entry.start_tick or block.end_tick != entry.end_tick) return error.InvalidTraceTickBlock;

        for (block.ticks) |tick| {
            if (tick.tick_index == tick_index) {
                return buildTickSummary(allocator, tick);
            }
        }
        return error.TickNotFound;
    }

    return error.TickNotFound;
}

fn buildTickSummary(allocator: std.mem.Allocator, tick: TickRecordRead) !TickSummary {
    const checkpoint = tick.channels.checkpoint;
    const entity_samples = tick.channels.entity_samples;
    const event_counts = .{
        .hit_count = checkpoint.events.hit_count,
        .pickup_count = checkpoint.events.pickup_count,
        .sfx_count = checkpoint.events.sfx_count,
    };

    return .{
        .tick_index = tick.tick_index,
        .elapsed_ms = tick.elapsed_ms,
        .dt_ms_i32 = tick.dt_ms_i32,
        .mode_id = tick.mode_id,
        .checkpoint = .{
            .score_xp = checkpoint.score_xp,
            .kills = checkpoint.kills,
            .creature_count = checkpoint.creature_count,
            .perk_pending = checkpoint.perk_pending,
        },
        .entity_counts = .{
            .creatures = @intCast(entity_samples.creatures.len),
            .projectiles = @intCast(entity_samples.projectiles.len),
            .secondary_projectiles = @intCast(entity_samples.secondary_projectiles.len),
            .bonuses = @intCast(entity_samples.bonuses.len),
        },
        .rng_stream_count = @intCast(tick.channels.rng_stream.len),
        .timing_samples_count = @intCast(tick.channels.timing_samples.len),
        .event_count_total = event_counts.hit_count + event_counts.pickup_count + event_counts.sfx_count,
        .top_event_types = try buildTopEventTypes(allocator, event_counts),
    };
}

const EventCount = struct {
    name: []const u8,
    count: i32,
};

fn buildTopEventTypes(
    allocator: std.mem.Allocator,
    event_counts: anytype,
) ![]const []const u8 {
    var rows = [_]EventCount{
        .{ .name = "hit_count", .count = event_counts.hit_count },
        .{ .name = "pickup_count", .count = event_counts.pickup_count },
        .{ .name = "sfx_count", .count = event_counts.sfx_count },
    };
    std.mem.sort(EventCount, &rows, {}, eventCountLessThan);

    const out = try allocator.alloc([]const u8, rows.len);
    errdefer allocator.free(out);
    var built: usize = 0;
    errdefer {
        for (out[0..built]) |entry| allocator.free(entry);
    }
    for (rows, 0..) |row, idx| {
        out[idx] = try std.fmt.allocPrint(allocator, "{s}:{d}", .{ row.name, row.count });
        built += 1;
    }
    return out;
}

fn eventCountLessThan(_: void, left: EventCount, right: EventCount) bool {
    if (left.count != right.count) return left.count > right.count;
    return std.mem.lessThan(u8, left.name, right.name);
}

pub fn summarizeTraceEntityFile(
    allocator: std.mem.Allocator,
    io: std.Io,
    trace_path: []const u8,
    entity_uid: i32,
    options: EntityHistoryOptions,
) !EntityHistorySummary {
    const bytes = try std.Io.Dir.cwd().readFileAlloc(io, trace_path, allocator, .limited(256 * 1024 * 1024));
    defer allocator.free(bytes);
    return summarizeTraceEntityBytes(allocator, bytes, entity_uid, options);
}

pub fn summarizeTraceEntityBytes(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    entity_uid: i32,
    options: EntityHistoryOptions,
) !EntityHistorySummary {
    if (entity_uid < 0) return error.EntityNotFound;
    if (options.tick_start != null and options.tick_end != null and options.tick_start.? > options.tick_end.?) return error.InvalidTickRange;
    if (bytes.len < trace_magic.len + 4 + trailer_magic.len + 8) return error.InvalidTraceHeader;
    if (!std.mem.startsWith(u8, bytes, trace_magic)) return error.InvalidTraceMagic;
    const version = readU32Le(bytes[trace_magic.len..][0..4]);
    if (version != trace_format_version) return error.UnsupportedTraceFormatVersion;

    const trailer_offset = bytes.len - trailer_magic.len - 8;
    if (!std.mem.eql(u8, bytes[trailer_offset..][0..trailer_magic.len], trailer_magic)) return error.InvalidTraceTrailer;
    const footer_offset_u64 = readU64Le(bytes[trailer_offset + trailer_magic.len ..][0..8]);
    if (footer_offset_u64 > std.math.maxInt(usize)) return error.InvalidTraceFooterOffset;
    const footer_offset: usize = @intCast(footer_offset_u64);
    const footer_chunk = try chunkPayloadAt(bytes, footer_offset);
    if (!std.mem.eql(u8, footer_chunk.kind, chunk_kind_footer)) return error.InvalidTraceFooterChunk;
    var decoded_footer = try msgpack.decodeFromSlice(TraceFooter, allocator, footer_chunk.payload);
    defer decoded_footer.deinit();
    const footer = decoded_footer.value;

    var samples: std.ArrayList(EntitySampleSummary) = .empty;
    errdefer samples.deinit(allocator);
    var spawn_tick: ?i32 = null;
    var despawn_tick: ?i32 = null;
    var pool_kind: []const u8 = "unknown";

    for (footer.tick_blocks) |entry| {
        if (options.tick_start) |tick_start| {
            if (entry.end_tick < tick_start) continue;
        }
        if (options.tick_end) |tick_end| {
            if (entry.start_tick > tick_end) continue;
        }

        if (entry.file_offset < 0) return error.InvalidTraceBlockOffset;
        const tick_chunk = try chunkPayloadAt(bytes, @intCast(entry.file_offset));
        if (!std.mem.eql(u8, tick_chunk.kind, chunk_kind_tick)) return error.InvalidTraceTickChunk;
        if (tick_chunk.start_tick != entry.start_tick or tick_chunk.end_tick != entry.end_tick) return error.InvalidTraceTickChunk;
        if (entry.uncompressed_len < 0) return error.InvalidTraceTickChunk;
        if (tick_chunk.payload.len != @as(usize, @intCast(entry.uncompressed_len))) return error.InvalidTraceTickChunk;
        if (checksum64(tick_chunk.payload) != entry.checksum) return error.InvalidTraceChecksum;

        var decoded_block = try msgpack.decodeFromSlice(TickBlockRead, allocator, tick_chunk.payload);
        defer decoded_block.deinit();
        const block = decoded_block.value;
        if (block.start_tick != entry.start_tick or block.end_tick != entry.end_tick) return error.InvalidTraceTickBlock;

        for (block.ticks) |tick| {
            if (options.tick_start) |tick_start| {
                if (tick.tick_index < tick_start) continue;
            }
            if (options.tick_end) |tick_end| {
                if (tick.tick_index > tick_end) continue;
            }

            const before_len = samples.items.len;
            try appendMatchingEntitySamples(allocator, &samples, entity_uid, tick);
            if (samples.items.len != before_len) {
                if (spawn_tick == null) {
                    spawn_tick = tick.tick_index;
                    pool_kind = samples.items[before_len].pool_kind;
                }
                despawn_tick = tick.tick_index;
            }
        }
    }

    if (samples.items.len == 0) return error.EntityNotFound;
    return .{
        .entity_uid = entity_uid,
        .pool_kind = pool_kind,
        .spawn_tick = spawn_tick.?,
        .despawn_tick = despawn_tick.?,
        .samples = try samples.toOwnedSlice(allocator),
    };
}

fn appendMatchingEntitySamples(
    allocator: std.mem.Allocator,
    out: *std.ArrayList(EntitySampleSummary),
    entity_uid: i32,
    tick: TickRecordRead,
) !void {
    const samples = tick.channels.entity_samples;
    for (samples.creatures) |sample| {
        if (sample.uid != entity_uid) continue;
        try out.append(allocator, .{
            .tick_index = tick.tick_index,
            .uid = sample.uid,
            .generation = sample.generation,
            .pool_kind = "creature",
            .index = sample.index,
            .active = sample.active,
            .type_id = sample.type_id,
            .hp = sample.hp,
            .pos = .{ .x = sample.pos.x, .y = sample.pos.y },
        });
    }
    for (samples.projectiles) |sample| {
        if (sample.uid != entity_uid) continue;
        try out.append(allocator, .{
            .tick_index = tick.tick_index,
            .uid = sample.uid,
            .generation = sample.generation,
            .pool_kind = "projectile",
            .index = sample.index,
            .active = sample.active,
            .type_id = sample.type_id,
            .pos = .{ .x = sample.pos.x, .y = sample.pos.y },
        });
    }
    for (samples.secondary_projectiles) |sample| {
        if (sample.uid != entity_uid) continue;
        try out.append(allocator, .{
            .tick_index = tick.tick_index,
            .uid = sample.uid,
            .generation = sample.generation,
            .pool_kind = "secondary_projectile",
            .index = sample.index,
            .active = sample.active,
            .type_id = sample.type_id,
            .pos = .{ .x = sample.pos.x, .y = sample.pos.y },
        });
    }
    for (samples.bonuses) |sample| {
        if (sample.uid != entity_uid) continue;
        try out.append(allocator, .{
            .tick_index = tick.tick_index,
            .uid = sample.uid,
            .generation = sample.generation,
            .pool_kind = "bonus",
            .index = sample.index,
            .active = sample.active,
            .type_id = sample.bonus_id,
            .pos = .{ .x = sample.pos.x, .y = sample.pos.y },
        });
    }
}

pub fn queryTraceFile(
    allocator: std.mem.Allocator,
    io: std.Io,
    trace_path: []const u8,
    request: QueryRequest,
) !QueryResult {
    const bytes = try std.Io.Dir.cwd().readFileAlloc(io, trace_path, allocator, .limited(256 * 1024 * 1024));
    defer allocator.free(bytes);
    return queryTraceBytes(allocator, bytes, request);
}

pub fn queryTraceBytes(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    request: QueryRequest,
) !QueryResult {
    if (request.limit == 0) return error.InvalidQueryLimit;
    if (bytes.len < trace_magic.len + 4 + trailer_magic.len + 8) return error.InvalidTraceHeader;
    if (!std.mem.startsWith(u8, bytes, trace_magic)) return error.InvalidTraceMagic;
    const version = readU32Le(bytes[trace_magic.len..][0..4]);
    if (version != trace_format_version) return error.UnsupportedTraceFormatVersion;

    const trailer_offset = bytes.len - trailer_magic.len - 8;
    if (!std.mem.eql(u8, bytes[trailer_offset..][0..trailer_magic.len], trailer_magic)) return error.InvalidTraceTrailer;
    const footer_offset_u64 = readU64Le(bytes[trailer_offset + trailer_magic.len ..][0..8]);
    if (footer_offset_u64 > std.math.maxInt(usize)) return error.InvalidTraceFooterOffset;
    const footer_offset: usize = @intCast(footer_offset_u64);
    const footer_chunk = try chunkPayloadAt(bytes, footer_offset);
    if (!std.mem.eql(u8, footer_chunk.kind, chunk_kind_footer)) return error.InvalidTraceFooterChunk;
    var decoded_footer = try msgpack.decodeFromSlice(TraceFooter, allocator, footer_chunk.payload);
    defer decoded_footer.deinit();
    const footer = decoded_footer.value;

    var rows: std.ArrayList(QueryRow) = .empty;
    errdefer rows.deinit(allocator);
    var match_count: usize = 0;

    for (footer.tick_blocks) |entry| {
        if (entry.file_offset < 0) return error.InvalidTraceBlockOffset;
        const tick_chunk = try chunkPayloadAt(bytes, @intCast(entry.file_offset));
        if (!std.mem.eql(u8, tick_chunk.kind, chunk_kind_tick)) return error.InvalidTraceTickChunk;
        if (tick_chunk.start_tick != entry.start_tick or tick_chunk.end_tick != entry.end_tick) return error.InvalidTraceTickChunk;
        if (entry.uncompressed_len < 0) return error.InvalidTraceTickChunk;
        if (tick_chunk.payload.len != @as(usize, @intCast(entry.uncompressed_len))) return error.InvalidTraceTickChunk;
        if (checksum64(tick_chunk.payload) != entry.checksum) return error.InvalidTraceChecksum;

        var decoded_block = try msgpack.decodeFromSlice(TickBlockRead, allocator, tick_chunk.payload);
        defer decoded_block.deinit();
        const block = decoded_block.value;
        if (block.start_tick != entry.start_tick or block.end_tick != entry.end_tick) return error.InvalidTraceTickBlock;

        for (block.ticks) |tick| {
            switch (request.scope) {
                .ticks => {
                    const row = queryRowFromTick(tick);
                    if (queryRowMatches(row, request)) {
                        match_count += 1;
                        if (rows.items.len < request.limit) try rows.append(allocator, row);
                    }
                },
                .entities => {
                    try appendMatchingQueryEntityRows(allocator, &rows, &match_count, request, tick);
                },
            }
        }
    }

    const owned_rows = try rows.toOwnedSlice(allocator);
    return .{
        .scope = @tagName(request.scope),
        .expression = request.expression,
        .limit = request.limit,
        .match_count = match_count,
        .truncated = match_count > owned_rows.len,
        .rows = owned_rows,
    };
}

pub fn diffTraceFiles(
    allocator: std.mem.Allocator,
    io: std.Io,
    expected_path: []const u8,
    actual_path: []const u8,
    options: TraceDiffOptions,
) !TraceDiffReport {
    const expected_bytes = try std.Io.Dir.cwd().readFileAlloc(io, expected_path, allocator, .limited(256 * 1024 * 1024));
    defer allocator.free(expected_bytes);
    const actual_bytes = try std.Io.Dir.cwd().readFileAlloc(io, actual_path, allocator, .limited(256 * 1024 * 1024));
    defer allocator.free(actual_bytes);
    return diffTraceBytes(allocator, expected_bytes, actual_bytes, options);
}

pub fn diffTraceBytes(
    allocator: std.mem.Allocator,
    expected_bytes: []const u8,
    actual_bytes: []const u8,
    options: TraceDiffOptions,
) !TraceDiffReport {
    var expected_rows = try loadTraceDiffRows(allocator, expected_bytes, options);
    defer expected_rows.deinit(allocator);
    var actual_rows = try loadTraceDiffRows(allocator, actual_bytes, options);
    defer actual_rows.deinit(allocator);
    return diffTraceRows(expected_rows.items, actual_rows.items, options);
}

pub fn bisectTraceFiles(
    allocator: std.mem.Allocator,
    io: std.Io,
    expected_path: []const u8,
    actual_path: []const u8,
    options: TraceDiffOptions,
    window_before: i32,
    window_after: i32,
) !TraceBisectReport {
    const expected_bytes = try std.Io.Dir.cwd().readFileAlloc(io, expected_path, allocator, .limited(256 * 1024 * 1024));
    defer allocator.free(expected_bytes);
    const actual_bytes = try std.Io.Dir.cwd().readFileAlloc(io, actual_path, allocator, .limited(256 * 1024 * 1024));
    defer allocator.free(actual_bytes);
    return bisectTraceBytes(allocator, expected_bytes, actual_bytes, options, window_before, window_after);
}

pub fn bisectTraceBytes(
    allocator: std.mem.Allocator,
    expected_bytes: []const u8,
    actual_bytes: []const u8,
    options: TraceDiffOptions,
    window_before: i32,
    window_after: i32,
) !TraceBisectReport {
    const diff = try diffTraceBytes(allocator, expected_bytes, actual_bytes, options);
    return bisectReportFromDiff(diff, window_before, window_after);
}

fn appendMatchingQueryEntityRows(
    allocator: std.mem.Allocator,
    rows: *std.ArrayList(QueryRow),
    match_count: *usize,
    request: QueryRequest,
    tick: TickRecordRead,
) !void {
    const samples = tick.channels.entity_samples;
    for (samples.creatures) |sample| {
        const row: QueryRow = .{
            .tick_index = tick.tick_index,
            .uid = sample.uid,
            .generation = sample.generation,
            .pool_kind = "creature",
            .index = sample.index,
            .type_id = sample.type_id,
            .hp = sample.hp,
        };
        if (queryRowMatches(row, request)) {
            match_count.* += 1;
            if (rows.items.len < request.limit) try rows.append(allocator, row);
        }
    }
    for (samples.projectiles) |sample| {
        const row: QueryRow = .{
            .tick_index = tick.tick_index,
            .uid = sample.uid,
            .generation = sample.generation,
            .pool_kind = "projectile",
            .index = sample.index,
            .type_id = sample.type_id,
        };
        if (queryRowMatches(row, request)) {
            match_count.* += 1;
            if (rows.items.len < request.limit) try rows.append(allocator, row);
        }
    }
    for (samples.secondary_projectiles) |sample| {
        const row: QueryRow = .{
            .tick_index = tick.tick_index,
            .uid = sample.uid,
            .generation = sample.generation,
            .pool_kind = "secondary_projectile",
            .index = sample.index,
            .type_id = sample.type_id,
        };
        if (queryRowMatches(row, request)) {
            match_count.* += 1;
            if (rows.items.len < request.limit) try rows.append(allocator, row);
        }
    }
    for (samples.bonuses) |sample| {
        const row: QueryRow = .{
            .tick_index = tick.tick_index,
            .uid = sample.uid,
            .generation = sample.generation,
            .pool_kind = "bonus",
            .index = sample.index,
            .type_id = sample.bonus_id,
        };
        if (queryRowMatches(row, request)) {
            match_count.* += 1;
            if (rows.items.len < request.limit) try rows.append(allocator, row);
        }
    }
}

fn queryRowFromTick(tick: TickRecordRead) QueryRow {
    const checkpoint = tick.channels.checkpoint;
    const entity_samples = tick.channels.entity_samples;
    const event_count_total = checkpoint.events.hit_count + checkpoint.events.pickup_count + checkpoint.events.sfx_count;
    return .{
        .tick_index = tick.tick_index,
        .mode_id = tick.mode_id,
        .dt_ms_i32 = tick.dt_ms_i32,
        .checkpoint_score_xp = checkpoint.score_xp,
        .checkpoint_kills = checkpoint.kills,
        .checkpoint_creature_count = checkpoint.creature_count,
        .checkpoint_perk_pending = checkpoint.perk_pending,
        .entity_count_creatures = @intCast(entity_samples.creatures.len),
        .entity_count_projectiles = @intCast(entity_samples.projectiles.len),
        .entity_count_secondary_projectiles = @intCast(entity_samples.secondary_projectiles.len),
        .entity_count_bonuses = @intCast(entity_samples.bonuses.len),
        .rng_stream_count = @intCast(tick.channels.rng_stream.len),
        .timing_samples_count = @intCast(tick.channels.timing_samples.len),
        .event_count_total = event_count_total,
    };
}

fn queryRowMatches(row: QueryRow, request: QueryRequest) bool {
    return switch (request.field) {
        .tick_index => compareInt(row.tick_index, request.op, request.literal),
        .mode_id => compareInt(row.mode_id orelse return false, request.op, request.literal),
        .dt_ms_i32 => compareInt(row.dt_ms_i32 orelse return false, request.op, request.literal),
        .checkpoint_score_xp => compareInt(row.checkpoint_score_xp orelse return false, request.op, request.literal),
        .checkpoint_kills => compareInt(row.checkpoint_kills orelse return false, request.op, request.literal),
        .checkpoint_creature_count => compareInt(row.checkpoint_creature_count orelse return false, request.op, request.literal),
        .checkpoint_perk_pending => compareInt(row.checkpoint_perk_pending orelse return false, request.op, request.literal),
        .entity_count_creatures => compareInt(row.entity_count_creatures orelse return false, request.op, request.literal),
        .entity_count_projectiles => compareInt(row.entity_count_projectiles orelse return false, request.op, request.literal),
        .entity_count_secondary_projectiles => compareInt(row.entity_count_secondary_projectiles orelse return false, request.op, request.literal),
        .entity_count_bonuses => compareInt(row.entity_count_bonuses orelse return false, request.op, request.literal),
        .rng_stream_count => compareInt(row.rng_stream_count orelse return false, request.op, request.literal),
        .timing_samples_count => compareInt(row.timing_samples_count orelse return false, request.op, request.literal),
        .event_count_total => compareInt(row.event_count_total orelse return false, request.op, request.literal),
        .uid => compareInt(row.uid orelse return false, request.op, request.literal),
        .generation => compareInt(row.generation orelse return false, request.op, request.literal),
        .index => compareInt(row.index orelse return false, request.op, request.literal),
        .type_id => compareInt(row.type_id orelse return false, request.op, request.literal),
        .hp => compareFloat(row.hp orelse return false, request.op, request.literal),
        .pool_kind => compareString(row.pool_kind orelse return false, request.op, request.literal),
    };
}

fn compareInt(value: i32, op: QueryOp, literal: QueryLiteral) bool {
    return switch (literal) {
        .int => |expected| compareF64(@floatFromInt(value), op, @floatFromInt(expected)),
        .float => |expected| compareF64(@floatFromInt(value), op, expected),
        .string => false,
    };
}

fn compareFloat(value: f32, op: QueryOp, literal: QueryLiteral) bool {
    return switch (literal) {
        .int => |expected| compareF64(value, op, @floatFromInt(expected)),
        .float => |expected| compareF64(value, op, expected),
        .string => false,
    };
}

fn compareF64(value: f64, op: QueryOp, expected: f64) bool {
    return switch (op) {
        .eq => value == expected,
        .ne => value != expected,
        .gt => value > expected,
        .ge => value >= expected,
        .lt => value < expected,
        .le => value <= expected,
    };
}

fn compareString(value: []const u8, op: QueryOp, literal: QueryLiteral) bool {
    const expected = switch (literal) {
        .string => |text| text,
        else => return false,
    };
    return switch (op) {
        .eq => std.mem.eql(u8, value, expected),
        .ne => !std.mem.eql(u8, value, expected),
        else => false,
    };
}

const EntityGenerationState = struct {
    generation_by_index: std.AutoHashMap(usize, i32),
    active_indices: std.AutoHashMap(usize, void),
    seen_in_tick: std.AutoHashMap(usize, void),

    fn init(allocator: std.mem.Allocator) EntityGenerationState {
        return .{
            .generation_by_index = std.AutoHashMap(usize, i32).init(allocator),
            .active_indices = std.AutoHashMap(usize, void).init(allocator),
            .seen_in_tick = std.AutoHashMap(usize, void).init(allocator),
        };
    }

    fn deinit(self: *EntityGenerationState) void {
        self.generation_by_index.deinit();
        self.active_indices.deinit();
        self.seen_in_tick.deinit();
        self.* = undefined;
    }

    fn beginTick(self: *EntityGenerationState) void {
        self.seen_in_tick.clearRetainingCapacity();
    }

    fn nextGeneration(self: *EntityGenerationState, index: usize) !i32 {
        var generation_ptr = self.generation_by_index.getPtr(index);
        if (generation_ptr == null) {
            try self.generation_by_index.put(index, 0);
            generation_ptr = self.generation_by_index.getPtr(index);
        }
        if (generation_ptr == null) return error.OutOfMemory;
        if (!self.active_indices.contains(index)) {
            generation_ptr.?.* += 1;
        }
        try self.seen_in_tick.put(index, {});
        return generation_ptr.?.*;
    }

    fn endTick(self: *EntityGenerationState) !void {
        self.active_indices.clearRetainingCapacity();
        var iter = self.seen_in_tick.iterator();
        while (iter.next()) |entry| {
            try self.active_indices.put(entry.key_ptr.*, {});
        }
    }
};

pub fn writeReplayTickTraceCdt(
    allocator: std.mem.Allocator,
    trace_path: []const u8,
    replay_path: []const u8,
    replay_bytes: []const u8,
    replay: replay_codec.Replay,
    rows: []const replay_runner.ReplayTickTrace,
) TraceWriteError!void {
    if (rows.len == 0) return error.EmptyTrace;

    const io = std.Io.Threaded.global_single_threaded.io();
    if (std.fs.path.dirname(trace_path)) |dir| {
        if (dir.len > 0) try std.Io.Dir.cwd().createDirPath(io, dir);
    }
    const file = try std.Io.Dir.cwd().createFile(io, trace_path, .{
        .truncate = true,
    });
    defer file.close(io);

    var out_buffer: [16384]u8 = undefined;
    var writer = file.writer(io, &out_buffer);
    const out = &writer.interface;
    var file_offset: usize = 0;

    const tick_start = try castI32(rows[0].tick_index);
    const tick_end = try castI32(rows[rows.len - 1].tick_index);
    const tick_count = try castI32(rows.len);

    var replay_sha256: [64]u8 = undefined;
    hash.sha256HexLower(replay_bytes, &replay_sha256);

    const stat = try std.Io.Dir.cwd().statFile(io, replay_path, .{});
    const mtime_ns = castI64Clamp(stat.mtime.nanoseconds);

    const meta: TraceMeta = .{
        .created_utc = "1970-01-01T00:00:00+00:00",
        .producer = .{
            .platform = @tagName(builtin.target.os.tag),
            .arch = @tagName(builtin.target.cpu.arch),
        },
        .source = .{
            .path = replay_path,
            .sha256 = replay_sha256[0..],
            .size = stat.size,
            .mtime_ns = mtime_ns,
            .tick_rate = replay.header.tick_rate,
            .seed = replay.header.seed,
            .mode_id = replay.header.game_mode_id,
            .quest_level = replay.header.quest_level,
        },
        .tick_range = .{
            .start_tick = tick_start,
            .end_tick = tick_end,
            .tick_count = tick_count,
        },
        .status = replay.header.status,
    };

    try out.writeAll(trace_magic);
    file_offset += trace_magic.len;
    try writeU32Le(out, trace_format_version);
    file_offset += 4;

    const meta_payload = try encodeMsgpackOwned(allocator, meta);
    defer allocator.free(meta_payload);
    _ = try writeChunk(
        out,
        &file_offset,
        chunk_kind_meta,
        -1,
        -1,
        meta_payload,
    );

    var tick_blocks: std.ArrayList(TickBlockIndexEntry) = .empty;
    defer tick_blocks.deinit(allocator);

    var creature_state = EntityGenerationState.init(allocator);
    defer creature_state.deinit();
    var projectile_state = EntityGenerationState.init(allocator);
    defer projectile_state.deinit();
    var secondary_state = EntityGenerationState.init(allocator);
    defer secondary_state.deinit();
    var bonus_state = EntityGenerationState.init(allocator);
    defer bonus_state.deinit();

    var tick_records: std.ArrayList(TickRecord) = .empty;
    defer {
        for (tick_records.items) |*record| {
            deinitTickRecord(allocator, record);
        }
        tick_records.deinit(allocator);
    }

    var elapsed_ms_accum: i64 = 0;
    var tick_rng_start_state: u32 = replay.header.seed;

    var last_tick_seen: ?i32 = null;
    for (rows) |row| {
        if (row.tick_index >= replay.dt.len) return error.InvalidTickIndex;
        const dt_ms_i32 = dtSecondsToMsI32(replay.dt[row.tick_index]) catch return error.InvalidReplayDt;
        elapsed_ms_accum += dt_ms_i32;
        const record = try buildTickRecord(
            allocator,
            replay,
            row,
            dt_ms_i32,
            elapsed_ms_accum,
            tick_rng_start_state,
            &creature_state,
            &projectile_state,
            &secondary_state,
            &bonus_state,
        );
        try tick_records.append(allocator, record);
        tick_rng_start_state = row.rng.rng_state;

        const tick_i32 = record.tick_index;
        if (last_tick_seen) |last_tick| {
            if (tick_i32 < last_tick) return error.InvalidTickOrder;
        }
        last_tick_seen = tick_i32;

        if (tick_records.items.len >= trace_chunk_ticks) {
            const entry = try flushTickBlock(allocator, out, &file_offset, tick_records.items);
            try tick_blocks.append(allocator, entry);
            for (tick_records.items) |*tick_record| {
                deinitTickRecord(allocator, tick_record);
            }
            tick_records.clearRetainingCapacity();
        }
    }
    if (tick_records.items.len > 0) {
        const entry = try flushTickBlock(allocator, out, &file_offset, tick_records.items);
        try tick_blocks.append(allocator, entry);
        for (tick_records.items) |*tick_record| {
            deinitTickRecord(allocator, tick_record);
        }
        tick_records.clearRetainingCapacity();
    }

    const footer: TraceFooter = .{
        .tick_blocks = tick_blocks.items,
        .tick_count = tick_count,
        .first_tick = tick_start,
        .last_tick = tick_end,
    };
    const footer_payload = try encodeMsgpackOwned(allocator, footer);
    defer allocator.free(footer_payload);
    const footer_entry = try writeChunk(
        out,
        &file_offset,
        chunk_kind_footer,
        -1,
        -1,
        footer_payload,
    );

    try out.writeAll(trailer_magic);
    try writeU64Le(out, @intCast(footer_entry.file_offset));
    try out.flush();
}

fn flushTickBlock(
    allocator: std.mem.Allocator,
    out: *std.Io.Writer,
    file_offset: *usize,
    tick_records: []const TickRecord,
) TraceWriteError!TickBlockIndexEntry {
    if (tick_records.len == 0) return error.EmptyTrace;
    const block: TickBlock = .{
        .start_tick = tick_records[0].tick_index,
        .end_tick = tick_records[tick_records.len - 1].tick_index,
        .ticks = tick_records,
    };
    const payload = try encodeMsgpackOwned(allocator, block);
    defer allocator.free(payload);
    return writeChunk(
        out,
        file_offset,
        chunk_kind_tick,
        block.start_tick,
        block.end_tick,
        payload,
    );
}

fn writeChunk(
    out: *std.Io.Writer,
    file_offset: *usize,
    kind: []const u8,
    start_tick: i32,
    end_tick: i32,
    payload: []const u8,
) TraceWriteError!TickBlockIndexEntry {
    if (kind.len != 4) return error.PayloadTooLarge;
    if (payload.len > std.math.maxInt(u32)) return error.PayloadTooLarge;
    if (file_offset.* > std.math.maxInt(i64)) return error.NumericOverflow;

    const checksum = checksum64(payload);
    const payload_len_u32: u32 = @intCast(payload.len);
    const offset_before = file_offset.*;

    try out.writeAll(kind);
    try writeI32Le(out, start_tick);
    try writeI32Le(out, end_tick);
    try writeU32Le(out, chunk_flag_msgpack);
    try writeU32Le(out, payload_len_u32);
    try writeU32Le(out, payload_len_u32);
    try writeU64Le(out, checksum);
    try out.writeAll(payload);

    file_offset.* += chunk_header_len + payload.len;

    return .{
        .start_tick = start_tick,
        .end_tick = end_tick,
        .file_offset = @intCast(offset_before),
        .compressed_len = @intCast(payload_len_u32),
        .uncompressed_len = @intCast(payload_len_u32),
        .checksum = checksum,
    };
}

fn buildTickRecord(
    allocator: std.mem.Allocator,
    replay: replay_codec.Replay,
    row: replay_runner.ReplayTickTrace,
    dt_ms_i32: i32,
    elapsed_ms: i64,
    tick_rng_start_state: u32,
    creature_state: *EntityGenerationState,
    projectile_state: *EntityGenerationState,
    secondary_state: *EntityGenerationState,
    bonus_state: *EntityGenerationState,
) TraceWriteError!TickRecord {
    const tick_index_i32 = try castI32(row.tick_index);
    _ = tick_rng_start_state;
    const rng_stream = try buildRngStream(allocator, row);
    errdefer if (rng_stream.len > 0) allocator.free(rng_stream);
    const timing_samples = try buildTimingSamples(allocator, row);
    errdefer if (timing_samples.len > 0) allocator.free(timing_samples);
    const checkpoint = try buildCheckpoint(allocator, row, elapsed_ms);
    errdefer deinitCheckpoint(allocator, &checkpoint);
    const sim_state = try buildSimState(
        allocator,
        row,
        replay.header.game_mode_id,
    );
    errdefer allocator.free(sim_state.players);
    const entity_samples = try buildEntitySamples(
        allocator,
        row,
        creature_state,
        projectile_state,
        secondary_state,
        bonus_state,
    );

    return .{
        .tick_index = tick_index_i32,
        .elapsed_ms = elapsed_ms,
        .dt_ms_i32 = dt_ms_i32,
        .mode_id = replay.header.game_mode_id,
        .channels = .{
            .checkpoint = checkpoint,
            .sim_state = sim_state,
            .entity_samples = entity_samples,
            .rng_stream = rng_stream,
            .timing_samples = timing_samples,
        },
    };
}

fn deinitTickRecord(allocator: std.mem.Allocator, record: *TickRecord) void {
    deinitCheckpoint(allocator, &record.channels.checkpoint);
    allocator.free(record.channels.sim_state.players);
    allocator.free(record.channels.entity_samples.creatures);
    allocator.free(record.channels.entity_samples.projectiles);
    allocator.free(record.channels.entity_samples.secondary_projectiles);
    allocator.free(record.channels.entity_samples.bonuses);
    if (record.channels.rng_stream.len > 0) {
        allocator.free(record.channels.rng_stream);
    }
    if (record.channels.timing_samples.len > 0) {
        allocator.free(record.channels.timing_samples);
    }
}

fn buildEntitySamples(
    allocator: std.mem.Allocator,
    row: replay_runner.ReplayTickTrace,
    creature_state: *EntityGenerationState,
    projectile_state: *EntityGenerationState,
    secondary_state: *EntityGenerationState,
    bonus_state: *EntityGenerationState,
) TraceWriteError!EntitySamplesSnapshot {
    creature_state.beginTick();
    projectile_state.beginTick();
    secondary_state.beginTick();
    bonus_state.beginTick();

    var creatures = try allocator.alloc(CreatureEntitySample, row.entities.creatures.len);
    errdefer allocator.free(creatures);
    for (row.entities.creatures, 0..) |creature, idx| {
        const index_i32 = try castI32(creature.index);
        creatures[idx] = .{
            .uid = index_i32,
            .generation = try creature_state.nextGeneration(creature.index),
            .pool_kind = "creature",
            .index = index_i32,
            .active = true,
            .type_id = creature.type_id,
            .hp = creature.hp,
            .pos = .{ .x = creature.pos.x, .y = creature.pos.y },
            .flags = @bitCast(creature.flags),
            .ai_mode = creature.ai_mode,
            .link_index = creature.link_index,
            .heading = creature.heading,
            .target_heading = creature.target_heading,
            .orbit_angle = creature.orbit_angle,
            .orbit_radius = creature.orbit_radius,
            .lifecycle_stage = creature.lifecycle_stage,
        };
    }

    var projectiles = try allocator.alloc(ProjectileEntitySample, row.entities.projectiles.len);
    errdefer allocator.free(projectiles);
    for (row.entities.projectiles, 0..) |projectile, idx| {
        const index_i32 = try castI32(projectile.index);
        projectiles[idx] = .{
            .uid = index_i32,
            .generation = try projectile_state.nextGeneration(projectile.index),
            .pool_kind = "projectile",
            .index = index_i32,
            .active = true,
            .type_id = projectile.type_id,
            .angle = projectile.angle,
            .pos = .{ .x = projectile.pos.x, .y = projectile.pos.y },
            .vel = .{ .x = projectile.vel.x, .y = projectile.vel.y },
            .life_timer = projectile.life_timer,
            .speed_scale = projectile.speed_scale,
            .damage_pool = projectile.damage_pool,
            .hit_radius = projectile.hit_radius,
            .travel_budget = projectile.travel_budget,
            .owner_id = projectile.owner_id,
        };
    }

    var secondary_projectiles = try allocator.alloc(SecondaryProjectileEntitySample, row.entities.secondary_projectiles.len);
    errdefer allocator.free(secondary_projectiles);
    for (row.entities.secondary_projectiles, 0..) |projectile, idx| {
        const index_i32 = try castI32(projectile.index);
        secondary_projectiles[idx] = .{
            .uid = index_i32,
            .generation = try secondary_state.nextGeneration(projectile.index),
            .pool_kind = "secondary_projectile",
            .index = index_i32,
            .active = true,
            .type_id = projectile.type_id,
            .angle = projectile.angle,
            .pos = .{ .x = projectile.pos.x, .y = projectile.pos.y },
            .vel = .{ .x = projectile.vel.x, .y = projectile.vel.y },
            .speed = projectile.speed,
            .trail_timer = projectile.trail_timer,
            .owner_id = projectile.owner_id,
            .target_id = projectile.target_id,
        };
    }

    var bonuses = try allocator.alloc(BonusEntitySample, row.entities.bonuses.len);
    errdefer allocator.free(bonuses);
    for (row.entities.bonuses, 0..) |bonus, idx| {
        const index_i32 = try castI32(bonus.index);
        bonuses[idx] = .{
            .uid = index_i32,
            .generation = try bonus_state.nextGeneration(bonus.index),
            .pool_kind = "bonus",
            .index = index_i32,
            .active = true,
            .bonus_id = bonus.bonus_id,
            .picked = bonus.picked,
            .time_left = bonus.time_left,
            .time_max = bonus.time_max,
            .pos = .{ .x = bonus.pos.x, .y = bonus.pos.y },
            .amount = bonus.amount,
        };
    }

    try creature_state.endTick();
    try projectile_state.endTick();
    try secondary_state.endTick();
    try bonus_state.endTick();

    return .{
        .creatures = creatures,
        .projectiles = projectiles,
        .secondary_projectiles = secondary_projectiles,
        .bonuses = bonuses,
    };
}

fn buildSimState(
    allocator: std.mem.Allocator,
    row: replay_runner.ReplayTickTrace,
    mode_id: i32,
) TraceWriteError!SimStateSnapshot {
    const fallback_players = [_]state_mod.PlayerState{row.player_state};
    const trace_players = if (row.players.len > 0) row.players else fallback_players[0..];
    const players = try allocator.alloc(SnapshotPlayer, trace_players.len);
    for (trace_players, 0..) |player, idx| {
        players[idx] = .{
            .index = player.index,
            .pos = .{ .x = player.pos.x, .y = player.pos.y },
            .health = player.health,
            .weapon = .{
                .weapon_id = @intFromEnum(player.weapon.weapon_id),
                .ammo = player.weapon.ammo,
                .clip_size = player.weapon.clip_size,
                .reload_active = player.weapon.reload_active,
                .reload_timer = player.weapon.reload_timer,
                .reload_timer_max = player.weapon.reload_timer_max,
                .shot_cooldown = player.weapon.shot_cooldown,
            },
            .experience = player.experience,
            .level = player.level,
        };
    }
    return .{
        .gameplay = .{
            .mode_id = mode_id,
            .quest_stage_major = row.gameplay_state.quest_stage_major,
            .quest_stage_minor = row.gameplay_state.quest_stage_minor,
            .perk_pending_count = row.gameplay_state.perk_selection.pending_count,
            .perk_choices_dirty = row.gameplay_state.perk_selection.choices_dirty,
            .bonus_timers = .{
                .weapon_power_up_ms = bonusTimerMs(row.gameplay_state.bonuses.weapon_power_up),
                .reflex_boost_ms = bonusTimerMs(row.gameplay_state.bonuses.reflex_boost),
                .energizer_ms = bonusTimerMs(row.gameplay_state.bonuses.energizer),
                .double_experience_ms = bonusTimerMs(row.gameplay_state.bonuses.double_experience),
                .freeze_ms = bonusTimerMs(row.gameplay_state.bonuses.freeze),
            },
        },
        .players = players,
    };
}

fn buildCheckpoint(
    allocator: std.mem.Allocator,
    row: replay_runner.ReplayTickTrace,
    elapsed_ms: i64,
) TraceWriteError!CheckpointChannel {
    const fallback_players = [_]state_mod.PlayerState{row.player_state};
    const trace_players = if (row.players.len > 0) row.players else fallback_players[0..];
    const player = trace_players[0];
    const quest_tick0_reload_sfx = row.tick_index == 0 and
        row.gameplay_state.game_mode == .quests and
        player.weapon.weapon_id == .pistol;
    const perk_choices = try buildPerkChoices(
        allocator,
        row.gameplay_state.perk_selection.choices,
        row.gameplay_state.perk_selection.choice_count,
    );
    errdefer if (perk_choices.len > 0) allocator.free(perk_choices);
    const player_nonzero_counts = try allocator.alloc([]const [2]i32, trace_players.len);
    errdefer allocator.free(player_nonzero_counts);
    var built_nonzero_counts: usize = 0;
    errdefer {
        for (player_nonzero_counts[0..built_nonzero_counts]) |pairs| {
            if (pairs.len > 0) allocator.free(pairs);
        }
    }
    for (trace_players, 0..) |entry, idx| {
        player_nonzero_counts[idx] = try buildNonzeroPerkCounts(allocator, entry);
        built_nonzero_counts += 1;
    }

    const players = try allocator.alloc(ReplayPlayerCheckpointChannel, trace_players.len);
    errdefer allocator.free(players);
    for (trace_players, 0..) |entry, idx| {
        players[idx] = .{
            .pos = .{
                .x = round4f64(entry.pos.x),
                .y = round4f64(entry.pos.y),
            },
            .health = round4f64(entry.health),
            .weapon_id = @intFromEnum(entry.weapon.weapon_id),
            .ammo = round4f64(entry.weapon.ammo),
            .experience = entry.experience,
            .level = entry.level,
        };
    }

    return .{
        .tick_index = try castI32(row.tick_index),
        .rng_state = @intCast(row.rng.rng_state),
        .elapsed_ms = elapsed_ms,
        .score_xp = row.summary.score_xp,
        .kills = row.summary.kills,
        .creature_count = @intCast(row.summary.creature_count),
        .perk_pending = row.summary.perk_pending,
        .players = players,
        .bonus_timers = .{
            .@"4" = bonusTimerMs(row.gameplay_state.bonuses.weapon_power_up),
            .@"9" = bonusTimerMs(row.gameplay_state.bonuses.reflex_boost),
            .@"2" = bonusTimerMs(row.gameplay_state.bonuses.energizer),
            .@"6" = bonusTimerMs(row.gameplay_state.bonuses.double_experience),
            .@"11" = bonusTimerMs(row.gameplay_state.bonuses.freeze),
        },
        .perk = .{
            .pending_count = row.gameplay_state.perk_selection.pending_count,
            .choices_dirty = row.gameplay_state.perk_selection.choices_dirty,
            .choices = perk_choices,
            .player_nonzero_counts = player_nonzero_counts,
        },
        .events = if (quest_tick0_reload_sfx) .{
            .sfx_count = 1,
            .sfx_head = quest_reload_sfx_head,
        } else .{},
    };
}

fn deinitCheckpoint(allocator: std.mem.Allocator, checkpoint: *const CheckpointChannel) void {
    if (checkpoint.players.len > 0) {
        allocator.free(checkpoint.players);
    }
    if (checkpoint.perk.choices.len > 0) {
        allocator.free(checkpoint.perk.choices);
    }
    for (checkpoint.perk.player_nonzero_counts) |pairs| {
        if (pairs.len > 0) {
            allocator.free(pairs);
        }
    }
    if (checkpoint.perk.player_nonzero_counts.len > 0) {
        allocator.free(checkpoint.perk.player_nonzero_counts);
    }
}

fn buildPerkChoices(
    allocator: std.mem.Allocator,
    choices: [7]game_ids.PerkId,
    choice_count: usize,
) TraceWriteError![]const i32 {
    const visible_count = @min(choice_count, choices.len);
    if (visible_count == 0) {
        return empty_i32;
    }

    var out = try allocator.alloc(i32, visible_count);
    for (choices[0..visible_count], 0..) |choice, idx| {
        out[idx] = @intFromEnum(choice);
    }
    return out;
}

fn buildNonzeroPerkCounts(
    allocator: std.mem.Allocator,
    player: state_mod.PlayerState,
) TraceWriteError![]const [2]i32 {
    var rows: std.ArrayList([2]i32) = .empty;
    defer rows.deinit(allocator);

    inline for (std.meta.fields(game_ids.PerkId)) |field| {
        const perk_id: game_ids.PerkId = @enumFromInt(field.value);
        const count = player.perk_counts.get(perk_id);
        if (count != 0) {
            try rows.append(allocator, .{
                @intCast(field.value),
                count,
            });
        }
    }
    if (rows.items.len == 0) {
        return empty_perk_pairs;
    }
    return rows.toOwnedSlice(allocator);
}

fn buildRngStream(
    allocator: std.mem.Allocator,
    row: replay_runner.ReplayTickTrace,
) TraceWriteError![]const RngStreamRow {
    if (row.rng_rows.len == 0) {
        return empty_rng_stream;
    }

    const rows = try allocator.alloc(RngStreamRow, row.rng_rows.len);
    for (row.rng_rows, 0..) |draw, idx| {
        rows[idx] = .{
            .tick_call_index = draw.tick_call_index,
            .value_15 = draw.value_15,
            .state_before_u32 = @intCast(draw.state_before_u32),
            .state_after_u32 = @intCast(draw.state_after_u32),
            .caller = if (draw.caller) |caller| @intCast(caller) else null,
        };
    }
    return rows;
}

fn buildTimingSamples(
    allocator: std.mem.Allocator,
    row: replay_runner.ReplayTickTrace,
) TraceWriteError![]const TimingSampleRow {
    if (row.timing_samples.len == 0) {
        return empty_timing_samples;
    }

    const samples = try allocator.alloc(TimingSampleRow, row.timing_samples.len);
    for (row.timing_samples, 0..) |sample, idx| {
        samples[idx] = .{
            .tick_index = sample.tick_index,
            .gameplay_frame = sample.gameplay_frame,
            .phase = sample.phase,
            .write_kind = sample.write_kind,
            .frame_dt_f32 = sample.frame_dt_f32,
            .frame_dt_ms_i32 = sample.frame_dt_ms_i32,
            .frame_dt_ms_f32 = sample.frame_dt_ms_f32,
            .time_scale_active_entry = sample.time_scale_active_entry,
            .time_scale_active_current = sample.time_scale_active_current,
            .time_scale_factor = sample.time_scale_factor,
            .bonus_reflex_boost_timer = sample.bonus_reflex_boost_timer,
            .mode_fn = sample.mode_fn,
            .player_index = sample.player_index,
        };
    }
    return samples;
}

fn encodeMsgpackOwned(allocator: std.mem.Allocator, value: anytype) ![]u8 {
    var writer: std.Io.Writer.Allocating = .init(allocator);
    errdefer writer.deinit();
    try msgpack.encode(value, &writer.writer);
    return writer.toOwnedSlice();
}

const TraceDiffRow = struct {
    tick_index: i32,
    elapsed_ms: i64,
    dt_ms_i32: i32,
    mode_id: i32,
    checkpoint_rng_state: i64,
    checkpoint_elapsed_ms: i64,
    checkpoint_score_xp: i32,
    checkpoint_kills: i32,
    checkpoint_creature_count: i32,
    checkpoint_perk_pending: i32,
    checkpoint_player_count: i64,
    checkpoint_death_count: i64,
    event_hit_count: i32,
    event_pickup_count: i32,
    event_sfx_count: i32,
    event_sfx_head_count: i64,
    entity_creature_count: i64,
    entity_projectile_count: i64,
    entity_secondary_projectile_count: i64,
    entity_bonus_count: i64,
    rng_stream_count: i64,
    timing_samples_count: i64,
};

fn loadTraceDiffRows(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    options: TraceDiffOptions,
) !std.ArrayList(TraceDiffRow) {
    if (bytes.len < trace_magic.len + 4 + trailer_magic.len + 8) return error.InvalidTraceHeader;
    if (!std.mem.startsWith(u8, bytes, trace_magic)) return error.InvalidTraceMagic;
    const version = readU32Le(bytes[trace_magic.len..][0..4]);
    if (version != trace_format_version) return error.UnsupportedTraceFormatVersion;

    const trailer_offset = bytes.len - trailer_magic.len - 8;
    if (!std.mem.eql(u8, bytes[trailer_offset..][0..trailer_magic.len], trailer_magic)) return error.InvalidTraceTrailer;
    const footer_offset_u64 = readU64Le(bytes[trailer_offset + trailer_magic.len ..][0..8]);
    if (footer_offset_u64 > std.math.maxInt(usize)) return error.InvalidTraceFooterOffset;
    const footer_offset: usize = @intCast(footer_offset_u64);
    const footer_chunk = try chunkPayloadAt(bytes, footer_offset);
    if (!std.mem.eql(u8, footer_chunk.kind, chunk_kind_footer)) return error.InvalidTraceFooterChunk;
    var decoded_footer = try msgpack.decodeFromSlice(TraceFooter, allocator, footer_chunk.payload);
    defer decoded_footer.deinit();
    const footer = decoded_footer.value;
    if (footer.tick_count <= 0) return error.InvalidTraceFooter;
    if (footer.first_tick < 0 or footer.last_tick < 0) return error.InvalidTraceFooter;
    if (footer.first_tick > footer.last_tick) return error.InvalidTraceFooter;
    if (footer.tick_blocks.len == 0) return error.InvalidTraceFooter;

    var rows: std.ArrayList(TraceDiffRow) = .empty;
    errdefer rows.deinit(allocator);

    for (footer.tick_blocks) |entry| {
        if (options.tick_start) |tick_start| {
            if (entry.end_tick < tick_start) continue;
        }
        if (options.tick_end) |tick_end| {
            if (entry.start_tick > tick_end) continue;
        }
        if (entry.file_offset < 0) return error.InvalidTraceBlockOffset;
        const tick_chunk = try chunkPayloadAt(bytes, @intCast(entry.file_offset));
        if (!std.mem.eql(u8, tick_chunk.kind, chunk_kind_tick)) return error.InvalidTraceTickChunk;
        if (tick_chunk.start_tick != entry.start_tick or tick_chunk.end_tick != entry.end_tick) return error.InvalidTraceTickChunk;
        if (entry.uncompressed_len < 0) return error.InvalidTraceTickChunk;
        if (tick_chunk.payload.len != @as(usize, @intCast(entry.uncompressed_len))) return error.InvalidTraceTickChunk;
        if (checksum64(tick_chunk.payload) != entry.checksum) return error.InvalidTraceChecksum;

        var decoded_block = try msgpack.decodeFromSlice(TickBlockRead, allocator, tick_chunk.payload);
        defer decoded_block.deinit();
        const block = decoded_block.value;
        if (block.start_tick != entry.start_tick or block.end_tick != entry.end_tick) return error.InvalidTraceTickBlock;

        for (block.ticks) |tick| {
            if (options.tick_start) |tick_start| {
                if (tick.tick_index < tick_start) continue;
            }
            if (options.tick_end) |tick_end| {
                if (tick.tick_index > tick_end) continue;
            }
            try rows.append(allocator, traceDiffRowFromTick(tick));
        }
    }

    return rows;
}

fn traceDiffRowFromTick(tick: TickRecordRead) TraceDiffRow {
    const checkpoint = tick.channels.checkpoint;
    const entities = tick.channels.entity_samples;
    return .{
        .tick_index = tick.tick_index,
        .elapsed_ms = tick.elapsed_ms,
        .dt_ms_i32 = tick.dt_ms_i32,
        .mode_id = tick.mode_id,
        .checkpoint_rng_state = checkpoint.rng_state,
        .checkpoint_elapsed_ms = checkpoint.elapsed_ms,
        .checkpoint_score_xp = checkpoint.score_xp,
        .checkpoint_kills = checkpoint.kills,
        .checkpoint_creature_count = checkpoint.creature_count,
        .checkpoint_perk_pending = checkpoint.perk_pending,
        .checkpoint_player_count = @intCast(checkpoint.players.len),
        .checkpoint_death_count = @intCast(checkpoint.deaths.len),
        .event_hit_count = checkpoint.events.hit_count,
        .event_pickup_count = checkpoint.events.pickup_count,
        .event_sfx_count = checkpoint.events.sfx_count,
        .event_sfx_head_count = @intCast(checkpoint.events.sfx_head.len),
        .entity_creature_count = @intCast(entities.creatures.len),
        .entity_projectile_count = @intCast(entities.projectiles.len),
        .entity_secondary_projectile_count = @intCast(entities.secondary_projectiles.len),
        .entity_bonus_count = @intCast(entities.bonuses.len),
        .rng_stream_count = @intCast(tick.channels.rng_stream.len),
        .timing_samples_count = @intCast(tick.channels.timing_samples.len),
    };
}

fn diffTraceRows(
    expected: []const TraceDiffRow,
    actual: []const TraceDiffRow,
    options: TraceDiffOptions,
) TraceDiffReport {
    var checked_count: usize = 0;
    var expected_idx: usize = 0;
    var actual_idx: usize = 0;

    while (expected_idx < expected.len or actual_idx < actual.len) {
        checked_count += 1;
        if (actual_idx >= actual.len or (expected_idx < expected.len and expected[expected_idx].tick_index < actual[actual_idx].tick_index)) {
            const tick = expected[expected_idx].tick_index;
            return .{
                .ok = false,
                .checked_count = checked_count,
                .tick_start = options.tick_start,
                .tick_end = options.tick_end,
                .mismatch = .{
                    .kind = "missing_tick",
                    .tick_index = tick,
                    .field = "tick_present",
                    .expected = 1,
                    .actual = 0,
                },
            };
        }
        if (expected_idx >= expected.len or actual[actual_idx].tick_index < expected[expected_idx].tick_index) {
            const tick = actual[actual_idx].tick_index;
            return .{
                .ok = false,
                .checked_count = checked_count,
                .tick_start = options.tick_start,
                .tick_end = options.tick_end,
                .mismatch = .{
                    .kind = "extra_tick",
                    .tick_index = tick,
                    .field = "tick_present",
                    .expected = 0,
                    .actual = 1,
                },
            };
        }

        if (firstTraceRowMismatch(&expected[expected_idx], &actual[actual_idx])) |mismatch| {
            return .{
                .ok = false,
                .checked_count = checked_count,
                .tick_start = options.tick_start,
                .tick_end = options.tick_end,
                .mismatch = mismatch,
            };
        }

        expected_idx += 1;
        actual_idx += 1;
    }

    return .{
        .ok = true,
        .checked_count = checked_count,
        .tick_start = options.tick_start,
        .tick_end = options.tick_end,
    };
}

fn bisectReportFromDiff(
    diff: TraceDiffReport,
    window_before: i32,
    window_after: i32,
) TraceBisectReport {
    if (diff.ok) {
        return .{
            .ok = true,
            .first_bad_tick = null,
            .checked_count = diff.checked_count,
            .mismatch = null,
            .window_start = null,
            .window_end = null,
        };
    }

    const mismatch = diff.mismatch.?;
    const before = @max(window_before, 0);
    const after = @max(window_after, 0);
    return .{
        .ok = false,
        .first_bad_tick = mismatch.tick_index,
        .checked_count = diff.checked_count,
        .mismatch = mismatch,
        .window_start = mismatch.tick_index - before,
        .window_end = mismatch.tick_index + after,
    };
}

fn firstTraceRowMismatch(expected: *const TraceDiffRow, actual: *const TraceDiffRow) ?TraceDiffMismatch {
    if (diffI64(expected.tick_index, expected.tick_index, actual.tick_index, "tick_index")) |mismatch| return mismatch;
    if (diffI64(expected.tick_index, expected.elapsed_ms, actual.elapsed_ms, "elapsed_ms")) |mismatch| return mismatch;
    if (diffI64(expected.tick_index, expected.dt_ms_i32, actual.dt_ms_i32, "dt_ms_i32")) |mismatch| return mismatch;
    if (diffI64(expected.tick_index, expected.mode_id, actual.mode_id, "mode_id")) |mismatch| return mismatch;
    if (diffI64(expected.tick_index, expected.checkpoint_rng_state, actual.checkpoint_rng_state, "checkpoint.rng_state")) |mismatch| return mismatch;
    if (diffI64(expected.tick_index, expected.checkpoint_elapsed_ms, actual.checkpoint_elapsed_ms, "checkpoint.elapsed_ms")) |mismatch| return mismatch;
    if (diffI64(expected.tick_index, expected.checkpoint_score_xp, actual.checkpoint_score_xp, "checkpoint.score_xp")) |mismatch| return mismatch;
    if (diffI64(expected.tick_index, expected.checkpoint_kills, actual.checkpoint_kills, "checkpoint.kills")) |mismatch| return mismatch;
    if (diffI64(expected.tick_index, expected.checkpoint_creature_count, actual.checkpoint_creature_count, "checkpoint.creature_count")) |mismatch| return mismatch;
    if (diffI64(expected.tick_index, expected.checkpoint_perk_pending, actual.checkpoint_perk_pending, "checkpoint.perk_pending")) |mismatch| return mismatch;
    if (diffI64(expected.tick_index, expected.checkpoint_player_count, actual.checkpoint_player_count, "checkpoint.players._len")) |mismatch| return mismatch;
    if (diffI64(expected.tick_index, expected.checkpoint_death_count, actual.checkpoint_death_count, "checkpoint.deaths._len")) |mismatch| return mismatch;
    if (diffI64(expected.tick_index, expected.event_hit_count, actual.event_hit_count, "checkpoint.events.hit_count")) |mismatch| return mismatch;
    if (diffI64(expected.tick_index, expected.event_pickup_count, actual.event_pickup_count, "checkpoint.events.pickup_count")) |mismatch| return mismatch;
    if (diffI64(expected.tick_index, expected.event_sfx_count, actual.event_sfx_count, "checkpoint.events.sfx_count")) |mismatch| return mismatch;
    if (diffI64(expected.tick_index, expected.event_sfx_head_count, actual.event_sfx_head_count, "checkpoint.events.sfx_head._len")) |mismatch| return mismatch;
    if (diffI64(expected.tick_index, expected.entity_creature_count, actual.entity_creature_count, "entity_samples.creatures._len")) |mismatch| return mismatch;
    if (diffI64(expected.tick_index, expected.entity_projectile_count, actual.entity_projectile_count, "entity_samples.projectiles._len")) |mismatch| return mismatch;
    if (diffI64(expected.tick_index, expected.entity_secondary_projectile_count, actual.entity_secondary_projectile_count, "entity_samples.secondary_projectiles._len")) |mismatch| return mismatch;
    if (diffI64(expected.tick_index, expected.entity_bonus_count, actual.entity_bonus_count, "entity_samples.bonuses._len")) |mismatch| return mismatch;
    if (diffI64(expected.tick_index, expected.rng_stream_count, actual.rng_stream_count, "rng_stream._len")) |mismatch| return mismatch;
    if (diffI64(expected.tick_index, expected.timing_samples_count, actual.timing_samples_count, "timing_samples._len")) |mismatch| return mismatch;
    return null;
}

fn diffI64(tick_index: i32, expected: anytype, actual: anytype, field: []const u8) ?TraceDiffMismatch {
    const exp: i64 = @intCast(expected);
    const act: i64 = @intCast(actual);
    if (exp == act) return null;
    return .{
        .kind = "field_mismatch",
        .tick_index = tick_index,
        .field = field,
        .expected = exp,
        .actual = act,
    };
}

fn checksum64(payload: []const u8) u64 {
    const Blake2b64 = std.crypto.hash.blake2.Blake2b(64);
    var digest: [Blake2b64.digest_length]u8 = undefined;
    Blake2b64.hash(payload, &digest, .{});
    return std.mem.readInt(u64, digest[0..8], .little);
}

fn chunkPayloadAt(bytes: []const u8, offset: usize) !ChunkPayload {
    if (offset > bytes.len or bytes.len - offset < chunk_header_len) return error.InvalidTraceChunkHeader;
    const header = bytes[offset .. offset + chunk_header_len];
    const compressed_len = readU32Le(header[16..20]);
    const uncompressed_len = readU32Le(header[20..24]);
    const payload_start = offset + chunk_header_len;
    if (compressed_len != uncompressed_len) return error.UnsupportedTraceCompression;
    if (payload_start > bytes.len or bytes.len - payload_start < compressed_len) return error.InvalidTracePayload;

    const flags = readU32Le(header[12..16]);
    if ((flags & chunk_flag_msgpack) == 0) return error.InvalidTraceChunkFlags;
    const payload = bytes[payload_start .. payload_start + compressed_len];
    const expected_checksum = readU64Le(header[24..32]);
    if (checksum64(payload) != expected_checksum) return error.InvalidTraceChecksum;

    return .{
        .kind = header[0..4],
        .start_tick = readI32Le(header[4..8]),
        .end_tick = readI32Le(header[8..12]),
        .payload = payload,
    };
}

fn readI32Le(bytes: *const [4]u8) i32 {
    return std.mem.readInt(i32, bytes, .little);
}

fn readU32Le(bytes: *const [4]u8) u32 {
    return std.mem.readInt(u32, bytes, .little);
}

fn readU64Le(bytes: *const [8]u8) u64 {
    return std.mem.readInt(u64, bytes, .little);
}

fn castI32(value: anytype) TraceWriteError!i32 {
    return std.math.cast(i32, value) orelse error.TickValueTooLarge;
}

fn castI64Clamp(value: i128) i64 {
    if (value > std.math.maxInt(i64)) return std.math.maxInt(i64);
    if (value < std.math.minInt(i64)) return std.math.minInt(i64);
    return @intCast(value);
}

fn round4f64(value: f32) f64 {
    const scaled = @as(f64, @floatCast(value)) * 10000.0;
    const rounded = @round(scaled);
    return rounded / 10000.0;
}

fn dtSecondsToMsI32(dt_seconds: f32) !i32 {
    const scaled_ms = @as(f32, dt_seconds * 1000.0);
    const truncated = @trunc(scaled_ms);
    const ms = std.math.cast(i32, @as(i64, @intFromFloat(truncated))) orelse return error.InvalidReplayDt;
    if (ms < 0) return error.InvalidReplayDt;
    return ms;
}

fn bonusTimerMs(value: f32) i32 {
    const scaled_ms = @as(f32, value * 1000.0);
    const truncated = @as(i64, @intFromFloat(@trunc(scaled_ms)));
    if (truncated < 0) return 0;
    return std.math.cast(i32, truncated) orelse std.math.maxInt(i32);
}

fn writeI32Le(out: *std.Io.Writer, value: i32) !void {
    var buf: [4]u8 = undefined;
    std.mem.writeInt(i32, &buf, value, .little);
    try out.writeAll(buf[0..]);
}

fn writeU32Le(out: *std.Io.Writer, value: u32) !void {
    var buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &buf, value, .little);
    try out.writeAll(buf[0..]);
}

fn writeU64Le(out: *std.Io.Writer, value: u64) !void {
    var buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &buf, value, .little);
    try out.writeAll(buf[0..]);
}

test "trace diff rows report first summary mismatch" {
    const expected = testTraceDiffRow(0);
    var actual = expected;
    actual.checkpoint_score_xp = 7;

    const report = diffTraceRows(&.{expected}, &.{actual}, .{});

    try std.testing.expect(!report.ok);
    try std.testing.expectEqual(@as(usize, 1), report.checked_count);
    try std.testing.expectEqualStrings("field_mismatch", report.mismatch.?.kind);
    try std.testing.expectEqualStrings("checkpoint.score_xp", report.mismatch.?.field.?);
    try std.testing.expectEqual(@as(?i64, 0), report.mismatch.?.expected);
    try std.testing.expectEqual(@as(?i64, 7), report.mismatch.?.actual);
}

test "trace diff rows report missing ticks" {
    const expected = testTraceDiffRow(3);

    const report = diffTraceRows(&.{expected}, &.{}, .{ .tick_start = 3, .tick_end = 3 });

    try std.testing.expect(!report.ok);
    try std.testing.expectEqual(@as(usize, 1), report.checked_count);
    try std.testing.expectEqual(@as(?i32, 3), report.tick_start);
    try std.testing.expectEqualStrings("missing_tick", report.mismatch.?.kind);
    try std.testing.expectEqual(@as(i32, 3), report.mismatch.?.tick_index);
}

test "trace bisect report derives first bad tick window" {
    const expected = testTraceDiffRow(1);
    var actual = expected;
    actual.checkpoint_kills = 2;

    const diff = diffTraceRows(&.{expected}, &.{actual}, .{});
    const report = bisectReportFromDiff(diff, 12, 6);

    try std.testing.expect(!report.ok);
    try std.testing.expectEqual(@as(?i32, 1), report.first_bad_tick);
    try std.testing.expectEqual(@as(usize, 1), report.checked_count);
    try std.testing.expectEqual(@as(?i32, -11), report.window_start);
    try std.testing.expectEqual(@as(?i32, 7), report.window_end);
    try std.testing.expectEqualStrings("checkpoint.kills", report.mismatch.?.field.?);
}

fn testTraceDiffRow(tick_index: i32) TraceDiffRow {
    return .{
        .tick_index = tick_index,
        .elapsed_ms = @as(i64, tick_index) * 17,
        .dt_ms_i32 = 17,
        .mode_id = 1,
        .checkpoint_rng_state = 1,
        .checkpoint_elapsed_ms = @as(i64, tick_index) * 17,
        .checkpoint_score_xp = 0,
        .checkpoint_kills = 0,
        .checkpoint_creature_count = 0,
        .checkpoint_perk_pending = 0,
        .checkpoint_player_count = 1,
        .checkpoint_death_count = 0,
        .event_hit_count = 0,
        .event_pickup_count = 0,
        .event_sfx_count = 0,
        .event_sfx_head_count = 0,
        .entity_creature_count = 0,
        .entity_projectile_count = 0,
        .entity_secondary_projectile_count = 0,
        .entity_bonus_count = 0,
        .rng_stream_count = 0,
        .timing_samples_count = 0,
    };
}
