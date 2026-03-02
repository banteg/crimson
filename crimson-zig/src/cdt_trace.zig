const builtin = @import("builtin");
const std = @import("std");
const msgpack = @import("msgpack");

const hash = @import("hash.zig");
const replay_codec = @import("replay_codec.zig");
const replay_runner = @import("runtime/replay_runner.zig");

const weapon_usage_count = replay_codec.weapon_usage_count;

const trace_magic = "crimson_debug_trace_v1\n";
const trace_format_version: u32 = 1;
const trace_schema_version: i32 = 5;

const chunk_kind_meta = "META";
const chunk_kind_tick = "TICK";
const chunk_kind_footer = "FOTR";
const trailer_magic = "CDTFTR1\n";

const chunk_flag_msgpack: u32 = 1 << 1;
const chunk_header_len: usize = 4 + 4 + 4 + 4 + 4 + 4 + 8;

const channels_list = [_][]const u8{
    "checkpoint",
    "sim_state",
    "entity_samples",
    "rng_marks",
    "rng_stream",
    "timing_samples",
};

const empty_strings: []const []const u8 = &.{};

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
    TickIndexTooLarge,
    TickValueTooLarge,
    PayloadTooLarge,
    NumericOverflow,
};

const TraceFsError = std.fs.Dir.MakeError || std.fs.Dir.StatFileError || std.fs.File.OpenError || std.fs.File.WriteError || std.fs.File.StatError;
const TraceWriterError = std.Io.Writer.Error;
const TraceAllocError = std.mem.Allocator.Error;
const TraceMsgpackError = error{
    MapTooLong,
    StringTooLong,
    ArrayTooLong,
};

pub const TraceWriteError = TraceDomainError || TraceFsError || TraceWriterError || TraceAllocError || TraceMsgpackError;

pub const WriteOptions = struct {
    strict_events: bool = true,
    chunk_ticks: usize = 256,
    verify_exit_code: i32 = 0,
    verify_stderr_present: bool = false,
};

const ChannelVersions = struct {
    checkpoint: i32 = 1,
    sim_state: i32 = 1,
    entity_samples: i32 = 1,
    rng_marks: i32 = 1,
    rng_stream: i32 = 1,
    timing_samples: i32 = 1,
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

const TraceConfig = struct {
    strict_events: bool,
    impl: []const u8 = "zig",
    zig_build_policy: []const u8 = "always",
    zig_exit_code: i32,
    zig_stderr_present: bool,
};

const TraceMeta = struct {
    trace_format_version: i32 = @intCast(trace_format_version),
    trace_schema_version: i32 = trace_schema_version,
    created_utc: []const u8,
    producer: Producer,
    source: Source,
    channels: []const []const u8 = channels_list[0..],
    channel_versions: ChannelVersions = .{},
    tick_range: TickRange,
    config: TraceConfig,
};

const TickBlockIndexEntry = struct {
    start_tick: i32,
    end_tick: i32,
    file_offset: i64,
    compressed_len: i32,
    uncompressed_len: i32,
    checksum: u64,
};

const ChannelCounts = struct {
    checkpoint: i32,
    sim_state: i32,
    entity_samples: i32,
    rng_marks: i32,
    rng_stream: i32,
    timing_samples: i32,
};

const TraceFooter = struct {
    trace_format_version: i32 = @intCast(trace_format_version),
    tick_blocks: []const TickBlockIndexEntry,
    tick_count: i32,
    first_tick: i32,
    last_tick: i32,
    channel_counts: ChannelCounts,
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

const SnapshotStatus = struct {
    quest_unlock_index: i32 = 0,
    quest_unlock_index_full: i32 = 0,
    weapon_usage_counts: [weapon_usage_count]i32,
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
    status: SnapshotStatus,
};

const SimStateSnapshot = struct {
    gameplay: SnapshotGameplay,
    players: [1]SnapshotPlayer,
};

const RngStreamRow = struct {
    tick_call_index: i32,
    value_15: i32,
    state_before_u32: i64,
    state_after_u32: i64,
    caller_static: ?[]const u8 = null,
    branch_id: ?[]const u8 = null,
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

const ReplayPlayerCheckpointChannel = struct {
    pos: SnapshotVec2,
    health: f32,
    weapon_id: i32,
    ammo: f32,
    experience: i32,
    level: i32,
};

const BonusTimersMap = struct {
    weapon_power_up_ms: i32,
    reflex_boost_ms: i32,
    energizer_ms: i32,
    double_experience_ms: i32,
    freeze_ms: i32,

    fn msgpackWrite(self: BonusTimersMap, packer: anytype) !void {
        try packer.writeMapHeader(5);
        try packer.write("4");
        try packer.write(self.weapon_power_up_ms);
        try packer.write("9");
        try packer.write(self.reflex_boost_ms);
        try packer.write("2");
        try packer.write(self.energizer_ms);
        try packer.write("6");
        try packer.write(self.double_experience_ms);
        try packer.write("11");
        try packer.write(self.freeze_ms);
    }
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
    player_nonzero_counts: [1][]const [2]i32,
};

const ReplayEventSummaryChannel = struct {
    hit_count: i32 = 0,
    pickup_count: i32 = 0,
    sfx_count: i32 = 0,
    sfx_head: []const []const u8 = empty_strings,
};

const RngMarks = struct {
    calls_total: i32,
    first_value_15: i32,
    last_value_15: i32,
    first_state_before_u32: i64,
    last_state_after_u32: i64,
    checkpoint_rng_state: i64,
    rng_after_perk_effects: i64,
    rng_after_creatures: i64,
    rng_after_projectiles: i64,
    rng_after_secondary_projectiles: i64,
    rng_after_particles: i64,
    rng_after_player_update: i64,
    rng_after_stage_spawns: i64,
    rng_after_wave_spawns: i64,
    rng_after_spawns: i64,
    rng_after_bonus_update: i64,
};

const CheckpointChannel = struct {
    tick_index: i32,
    rng_state: i64,
    elapsed_ms: i64,
    score_xp: i32,
    kills: i32,
    creature_count: i32,
    perk_pending: i32,
    players: [1]ReplayPlayerCheckpointChannel,
    bonus_timers: BonusTimersMap,
    state_hash: []const u8 = "",
    command_hash: []const u8 = "",
    rng_marks: RngMarks,
    deaths: []const ReplayDeathLedgerEntry = empty_deaths,
    perk: ReplayPerkSnapshotChannel,
    events: ReplayEventSummaryChannel = .{},
};

const TickChannels = struct {
    checkpoint: CheckpointChannel,
    sim_state: SimStateSnapshot,
    entity_samples: EntitySamplesSnapshot,
    rng_marks: RngMarks,
    rng_stream: []const RngStreamRow = empty_rng_stream,
    timing_samples: []const TimingSampleRow = empty_timing_samples,
};

const TickRecord = struct {
    tick_index: i32,
    elapsed_ms: i64,
    dt_ms_i32: i32,
    mode_id: i32,
    phase_markers: []const []const u8 = empty_strings,
    channels: TickChannels,
};

const TickBlock = struct {
    start_tick: i32,
    end_tick: i32,
    ticks: []const TickRecord,
};

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
    options: WriteOptions,
) TraceWriteError!void {
    if (rows.len == 0) return error.EmptyTrace;

    if (std.fs.path.dirname(trace_path)) |dir| {
        if (dir.len > 0) try std.fs.cwd().makePath(dir);
    }
    const file = try std.fs.cwd().createFile(trace_path, .{
        .truncate = true,
    });
    defer file.close();

    var out_buffer: [16384]u8 = undefined;
    var writer = file.writer(&out_buffer);
    const out = &writer.interface;
    var file_offset: usize = 0;

    const tick_start = try castI32(rows[0].tick_index);
    const tick_end = try castI32(rows[rows.len - 1].tick_index);
    const tick_count = try castI32(rows.len);

    var replay_sha256: [64]u8 = undefined;
    hash.sha256HexLower(replay_bytes, &replay_sha256);

    const stat = try std.fs.cwd().statFile(replay_path);
    const mtime_ns = castI64Clamp(stat.mtime);

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
        .config = .{
            .strict_events = options.strict_events,
            .zig_exit_code = options.verify_exit_code,
            .zig_stderr_present = options.verify_stderr_present,
        },
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

    const chunk_ticks = if (options.chunk_ticks == 0) 1 else options.chunk_ticks;
    const usage_counts = replayHeaderUsageCounts(replay.header.status.weapon_usage_counts);
    const quest_stage = parseQuestStage(replay.header.quest_level);

    var last_tick_seen: ?i32 = null;
    for (rows) |row| {
        const record = try buildTickRecord(
            allocator,
            replay,
            row,
            usage_counts,
            quest_stage.major,
            quest_stage.minor,
            &creature_state,
            &projectile_state,
            &secondary_state,
            &bonus_state,
        );
        try tick_records.append(allocator, record);

        const tick_i32 = record.tick_index;
        if (last_tick_seen) |last_tick| {
            if (tick_i32 < last_tick) return error.InvalidTickOrder;
        }
        last_tick_seen = tick_i32;

        if (tick_records.items.len >= chunk_ticks) {
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

    const channel_counts: ChannelCounts = .{
        .checkpoint = tick_count,
        .sim_state = tick_count,
        .entity_samples = tick_count,
        .rng_marks = tick_count,
        .rng_stream = tick_count,
        .timing_samples = tick_count,
    };
    const footer: TraceFooter = .{
        .tick_blocks = tick_blocks.items,
        .tick_count = tick_count,
        .first_tick = tick_start,
        .last_tick = tick_end,
        .channel_counts = channel_counts,
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
    usage_counts: [weapon_usage_count]i32,
    quest_stage_major: i32,
    quest_stage_minor: i32,
    creature_state: *EntityGenerationState,
    projectile_state: *EntityGenerationState,
    secondary_state: *EntityGenerationState,
    bonus_state: *EntityGenerationState,
) TraceWriteError!TickRecord {
    const tick_index_i32 = try castI32(row.tick_index);
    if (row.tick_index >= replay.dt.len) return error.InvalidTickIndex;
    const dt_ms_i32 = dtSecondsToMsI32(replay.dt[row.tick_index]) catch return error.InvalidReplayDt;

    const rng_marks = buildRngMarks(row);
    const checkpoint = buildCheckpoint(row, rng_marks);
    const sim_state = buildSimState(
        row,
        usage_counts,
        replay.header.game_mode_id,
        quest_stage_major,
        quest_stage_minor,
    );
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
        .elapsed_ms = row.timing.elapsed_ms,
        .dt_ms_i32 = dt_ms_i32,
        .mode_id = replay.header.game_mode_id,
        .channels = .{
            .checkpoint = checkpoint,
            .sim_state = sim_state,
            .entity_samples = entity_samples,
            .rng_marks = rng_marks,
        },
    };
}

fn deinitTickRecord(allocator: std.mem.Allocator, record: *TickRecord) void {
    allocator.free(record.channels.entity_samples.creatures);
    allocator.free(record.channels.entity_samples.projectiles);
    allocator.free(record.channels.entity_samples.secondary_projectiles);
    allocator.free(record.channels.entity_samples.bonuses);
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
    row: replay_runner.ReplayTickTrace,
    usage_counts: [weapon_usage_count]i32,
    mode_id: i32,
    quest_stage_major: i32,
    quest_stage_minor: i32,
) SimStateSnapshot {
    const player = row.player_state;
    return .{
        .gameplay = .{
            .mode_id = mode_id,
            .quest_stage_major = quest_stage_major,
            .quest_stage_minor = quest_stage_minor,
            .perk_pending_count = row.gameplay_state.perk_selection.pending_count,
            .bonus_timers = .{
                .weapon_power_up_ms = bonusTimerMs(row.gameplay_state.bonuses.weapon_power_up),
                .reflex_boost_ms = bonusTimerMs(row.gameplay_state.bonuses.reflex_boost),
                .energizer_ms = bonusTimerMs(row.gameplay_state.bonuses.energizer),
                .double_experience_ms = bonusTimerMs(row.gameplay_state.bonuses.double_experience),
                .freeze_ms = bonusTimerMs(row.gameplay_state.bonuses.freeze),
            },
            .status = .{
                .weapon_usage_counts = usage_counts,
            },
        },
        .players = .{
            .{
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
            },
        },
    };
}

fn buildCheckpoint(row: replay_runner.ReplayTickTrace, rng_marks: RngMarks) CheckpointChannel {
    const player = row.player_state;
    return .{
        .tick_index = @intCast(row.tick_index),
        .rng_state = @intCast(row.rng.rng_state),
        .elapsed_ms = row.timing.elapsed_ms,
        .score_xp = row.summary.score_xp,
        .kills = row.summary.kills,
        .creature_count = @intCast(row.summary.creature_count),
        .perk_pending = row.summary.perk_pending,
        .players = .{
            .{
                .pos = .{
                    .x = round4(player.pos.x),
                    .y = round4(player.pos.y),
                },
                .health = round4(player.health),
                .weapon_id = @intFromEnum(player.weapon.weapon_id),
                .ammo = round4(player.weapon.ammo),
                .experience = player.experience,
                .level = player.level,
            },
        },
        .bonus_timers = .{
            .weapon_power_up_ms = bonusTimerMs(row.gameplay_state.bonuses.weapon_power_up),
            .reflex_boost_ms = bonusTimerMs(row.gameplay_state.bonuses.reflex_boost),
            .energizer_ms = bonusTimerMs(row.gameplay_state.bonuses.energizer),
            .double_experience_ms = bonusTimerMs(row.gameplay_state.bonuses.double_experience),
            .freeze_ms = bonusTimerMs(row.gameplay_state.bonuses.freeze),
        },
        .rng_marks = rng_marks,
        .perk = .{
            .pending_count = row.gameplay_state.perk_selection.pending_count,
            .player_nonzero_counts = .{empty_perk_pairs},
        },
    };
}

fn buildRngMarks(row: replay_runner.ReplayTickTrace) RngMarks {
    return .{
        .calls_total = 0,
        .first_value_15 = -1,
        .last_value_15 = -1,
        .first_state_before_u32 = -1,
        .last_state_after_u32 = -1,
        .checkpoint_rng_state = @intCast(row.rng.rng_state),
        .rng_after_perk_effects = @intCast(row.rng.rng_after_perk_effects),
        .rng_after_creatures = @intCast(row.rng.rng_after_creatures),
        .rng_after_projectiles = @intCast(row.rng.rng_after_projectiles),
        .rng_after_secondary_projectiles = @intCast(row.rng.rng_after_secondary_projectiles),
        .rng_after_particles = @intCast(row.rng.rng_after_particles),
        .rng_after_player_update = @intCast(row.rng.rng_after_player_update),
        .rng_after_stage_spawns = @intCast(row.rng.rng_after_stage_spawns),
        .rng_after_wave_spawns = @intCast(row.rng.rng_after_wave_spawns),
        .rng_after_spawns = @intCast(row.rng.rng_after_spawns),
        .rng_after_bonus_update = @intCast(row.rng.rng_after_bonus_update),
    };
}

fn replayHeaderUsageCounts(raw: [weapon_usage_count]u32) [weapon_usage_count]i32 {
    var out: [weapon_usage_count]i32 = [_]i32{0} ** weapon_usage_count;
    for (raw, 0..) |value, idx| {
        out[idx] = @intCast(value);
    }
    return out;
}

const QuestStage = struct {
    major: i32 = 0,
    minor: i32 = 0,
};

fn parseQuestStage(quest_level: []const u8) QuestStage {
    if (quest_level.len == 0) return .{};
    const dot = std.mem.indexOfScalar(u8, quest_level, '.') orelse return .{};
    const major_raw = std.mem.trim(u8, quest_level[0..dot], " ");
    const minor_raw = std.mem.trim(u8, quest_level[dot + 1 ..], " ");
    if (major_raw.len == 0 or minor_raw.len == 0) return .{};
    const major = std.fmt.parseInt(i32, major_raw, 10) catch return .{};
    const minor = std.fmt.parseInt(i32, minor_raw, 10) catch return .{};
    if (major < 0 or minor < 0) return .{};
    return .{
        .major = major,
        .minor = minor,
    };
}

fn encodeMsgpackOwned(allocator: std.mem.Allocator, value: anytype) ![]u8 {
    var writer: std.Io.Writer.Allocating = .init(allocator);
    errdefer writer.deinit();
    try msgpack.encode(value, &writer.writer);
    return writer.toOwnedSlice();
}

fn checksum64(payload: []const u8) u64 {
    const Blake2b64 = std.crypto.hash.blake2.Blake2b(64);
    var digest: [Blake2b64.digest_length]u8 = undefined;
    Blake2b64.hash(payload, &digest, .{});
    return std.mem.readInt(u64, digest[0..8], .little);
}

fn castI32(value: anytype) TraceWriteError!i32 {
    return std.math.cast(i32, value) orelse error.TickValueTooLarge;
}

fn castI64Clamp(value: i128) i64 {
    if (value > std.math.maxInt(i64)) return std.math.maxInt(i64);
    if (value < std.math.minInt(i64)) return std.math.minInt(i64);
    return @intCast(value);
}

fn round4(value: f32) f32 {
    const scaled = @as(f64, @floatCast(value)) * 10000.0;
    const rounded = @round(scaled);
    return @floatCast(rounded / 10000.0);
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
