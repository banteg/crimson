const std = @import("std");
const msgpack = @import("msgpack");

const relay_protocol = @import("relay_protocol.zig");
const spawn_mod = @import("../runtime/spawn.zig");

pub const snapshot_schema_version: i32 = 4;
pub const schema_version: i32 = snapshot_schema_version;
pub const snapshot_codec = "msgpack_state_v4_f32wire";

const chunk_payload_bytes: usize = @intCast(relay_protocol.resync_chunk_payload_bytes);
const default_max_snapshot_bytes: usize = @intCast(relay_protocol.resync_max_snapshot_bytes);

pub const RollbackResyncV5Error = error{
    SnapshotTooLarge,
    CompressedSnapshotTooLarge,
    InvalidCompressedSnapshot,
    UnsupportedSnapshotCodec,
    CompressedSnapshotSizeInvalid,
    SnapshotSizeInvalid,
    ResyncChunkCountInvalid,
    ResyncBeginMissing,
    ResyncRequestIdMismatch,
    ResyncChunkIndexInvalid,
    ResyncTickMismatch,
    ResyncChunksIncomplete,
    ResyncCompressedSizeMismatch,
    ResyncUncompressedSizeMismatch,
    SnapshotDecodeError,
    UnsupportedSnapshotSchema,
    OutOfMemory,
};

pub const ReplayStateSnapshotV2 = struct {
    tick_index: i32 = 0,
    recorded_tick_count: i32 = 0,
};

pub const SurvivalRuntimeSnapshotV2 = struct {
    elapsed_ms: f32 = 0.0,
    stage: i32 = 0,
    spawn_cooldown_ms: f32 = 0.0,
    perk_pending_count: i32 = 0,
};

pub const RushRuntimeSnapshotV2 = struct {
    elapsed_ms: f32 = 0.0,
    spawn_cooldown_ms: f32 = 0.0,
    kill_count: i32 = 0,
};

pub const QuestsRuntimeSnapshotV2 = struct {
    elapsed_ms: f32 = 0.0,
    spawn_entries: []const spawn_mod.QuestSpawnEntry = &.{},
    spawn_timeline_ms: f32 = 0.0,
    no_creatures_timer_ms: f32 = 0.0,
    completion_transition_ms: f32 = 0.0,
    perk_pending_count: i32 = 0,
};

pub const SurvivalStateSnapshotV2 = struct {
    schema_version: i32 = snapshot_schema_version,
    tick_index: i32 = 0,
    replay_state: ?ReplayStateSnapshotV2 = null,
    runtime_state: SurvivalRuntimeSnapshotV2 = .{},
};

pub const RushStateSnapshotV2 = struct {
    schema_version: i32 = snapshot_schema_version,
    tick_index: i32 = 0,
    replay_state: ?ReplayStateSnapshotV2 = null,
    runtime_state: RushRuntimeSnapshotV2 = .{},
};

pub const QuestsStateSnapshotV2 = struct {
    schema_version: i32 = snapshot_schema_version,
    tick_index: i32 = 0,
    replay_state: ?ReplayStateSnapshotV2 = null,
    runtime_state: QuestsRuntimeSnapshotV2 = .{},
};

pub const ModeStateSnapshotV2 = union(enum) {
    survival: SurvivalStateSnapshotV2,
    rush: RushStateSnapshotV2,
    quests: QuestsStateSnapshotV2,

    pub fn msgpackFormat() msgpack.UnionFormat {
        return .{ .as_tagged = .{
            .tag_field = "mode",
            .tag_value = .field_name,
        } };
    }

    pub fn schemaVersion(self: ModeStateSnapshotV2) i32 {
        return switch (self) {
            .survival => |snapshot| snapshot.schema_version,
            .rush => |snapshot| snapshot.schema_version,
            .quests => |snapshot| snapshot.schema_version,
        };
    }

    pub fn tickIndex(self: ModeStateSnapshotV2) i32 {
        return switch (self) {
            .survival => |snapshot| snapshot.tick_index,
            .rush => |snapshot| snapshot.tick_index,
            .quests => |snapshot| snapshot.tick_index,
        };
    }
};

pub fn encodeModeSnapshot(
    allocator: std.mem.Allocator,
    snapshot: ModeStateSnapshotV2,
) RollbackResyncV5Error![]u8 {
    try validateModeSnapshot(snapshot);
    var writer: std.Io.Writer.Allocating = .init(allocator);
    errdefer writer.deinit();
    msgpack.encode(snapshot, &writer.writer) catch return error.OutOfMemory;
    const blob = try writer.toOwnedSlice();
    errdefer allocator.free(blob);
    if (blob.len > default_max_snapshot_bytes) return error.SnapshotTooLarge;
    return blob;
}

pub fn decodeModeSnapshot(
    allocator: std.mem.Allocator,
    blob: []const u8,
) RollbackResyncV5Error!msgpack.Decoded(ModeStateSnapshotV2) {
    if (blob.len > default_max_snapshot_bytes) return error.SnapshotTooLarge;
    var decoded = msgpack.decodeFromSlice(ModeStateSnapshotV2, allocator, blob) catch return error.SnapshotDecodeError;
    errdefer decoded.deinit();
    try validateModeSnapshot(decoded.value);
    return decoded;
}

fn validateModeSnapshot(snapshot: ModeStateSnapshotV2) RollbackResyncV5Error!void {
    if (snapshot.schemaVersion() != snapshot_schema_version) return error.UnsupportedSnapshotSchema;
    _ = snapshot.tickIndex();
}

pub const RbResyncMessageSet = struct {
    begin: relay_protocol.RbResyncBegin,
    chunks: []relay_protocol.RbResyncChunk,
    commit: relay_protocol.RbResyncCommit,

    pub fn deinit(self: *RbResyncMessageSet, allocator: std.mem.Allocator) void {
        freeBytes(allocator, self.begin.request_id);
        freeBytes(allocator, self.begin.codec);
        deinitChunks(allocator, self.chunks);
        freeBytes(allocator, self.commit.request_id);
        self.* = undefined;
    }
};

pub const ResyncSnapshot = struct {
    tick_index: i32,
    payload: []u8,

    pub fn deinit(self: *ResyncSnapshot, allocator: std.mem.Allocator) void {
        allocator.free(self.payload);
        self.* = undefined;
    }
};

pub fn buildRbResyncMessages(
    allocator: std.mem.Allocator,
    request_id: []const u8,
    snapshot_tick: i32,
    snapshot_blob: []const u8,
) RollbackResyncV5Error!RbResyncMessageSet {
    if (snapshot_blob.len > default_max_snapshot_bytes) return error.SnapshotTooLarge;

    const compressed = try compressZlibPayload(allocator, snapshot_blob, default_max_snapshot_bytes);
    defer allocator.free(compressed);
    if (compressed.len > default_max_snapshot_bytes) return error.CompressedSnapshotTooLarge;

    const total_chunks = @max(@as(usize, 1), ceilDiv(compressed.len, chunk_payload_bytes));
    const total_chunks_i32: i32 = @intCast(total_chunks);

    const begin_request_id = try dupeBytes(allocator, request_id);
    errdefer freeBytes(allocator, begin_request_id);
    const begin_codec = try dupeBytes(allocator, snapshot_codec);
    errdefer freeBytes(allocator, begin_codec);

    const chunks = try allocator.alloc(relay_protocol.RbResyncChunk, total_chunks);
    var initialized: usize = 0;
    errdefer {
        freeChunkItems(allocator, chunks[0..initialized]);
        allocator.free(chunks);
    }
    for (chunks, 0..) |*chunk, chunk_index| {
        const start = chunk_index * chunk_payload_bytes;
        const end = @min(start + chunk_payload_bytes, compressed.len);
        const chunk_request_id = try dupeBytes(allocator, request_id);
        const chunk_payload = dupeBytes(allocator, compressed[start..end]) catch |err| {
            freeBytes(allocator, chunk_request_id);
            return err;
        };
        chunk.* = .{
            .request_id = chunk_request_id,
            .chunk_index = @intCast(chunk_index),
            .payload = .{ .data = chunk_payload },
        };
        initialized += 1;
    }

    const commit_request_id = try dupeBytes(allocator, request_id);
    errdefer freeBytes(allocator, commit_request_id);

    return .{
        .begin = .{
            .request_id = begin_request_id,
            .snapshot_tick = snapshot_tick,
            .codec = begin_codec,
            .total_chunks = total_chunks_i32,
            .compressed_size = @intCast(compressed.len),
            .uncompressed_size = @intCast(snapshot_blob.len),
        },
        .chunks = chunks,
        .commit = .{
            .request_id = commit_request_id,
            .snapshot_tick = snapshot_tick,
        },
    };
}

pub const RbResyncAssemblerV5 = struct {
    allocator: std.mem.Allocator,
    max_snapshot_bytes: usize = default_max_snapshot_bytes,
    begin_message: ?relay_protocol.RbResyncBegin = null,
    chunks: []?[]const u8 = &.{},
    received_chunks: usize = 0,

    pub fn init(allocator: std.mem.Allocator) RbResyncAssemblerV5 {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *RbResyncAssemblerV5) void {
        self.clear();
        self.* = undefined;
    }

    pub fn requestId(self: RbResyncAssemblerV5) []const u8 {
        const begin_message = self.begin_message orelse return "";
        return begin_message.request_id;
    }

    pub fn begin(self: *RbResyncAssemblerV5, message: relay_protocol.RbResyncBegin) RollbackResyncV5Error!void {
        if (!std.mem.eql(u8, message.codec, snapshot_codec)) return error.UnsupportedSnapshotCodec;
        if (message.compressed_size < 0 or @as(usize, @intCast(message.compressed_size)) > self.max_snapshot_bytes) {
            return error.CompressedSnapshotSizeInvalid;
        }
        if (message.uncompressed_size < 0 or @as(usize, @intCast(message.uncompressed_size)) > self.max_snapshot_bytes) {
            return error.SnapshotSizeInvalid;
        }
        if (message.total_chunks <= 0 or @as(usize, @intCast(message.total_chunks)) > maxChunkCount(self.max_snapshot_bytes)) {
            return error.ResyncChunkCountInvalid;
        }

        self.clear();

        const request_id = try dupeBytes(self.allocator, message.request_id);
        errdefer freeBytes(self.allocator, request_id);
        const codec = try dupeBytes(self.allocator, message.codec);
        errdefer freeBytes(self.allocator, codec);
        const chunks = try self.allocator.alloc(?[]const u8, @intCast(message.total_chunks));
        @memset(chunks, null);

        self.begin_message = .{
            .request_id = request_id,
            .snapshot_tick = message.snapshot_tick,
            .codec = codec,
            .total_chunks = message.total_chunks,
            .compressed_size = message.compressed_size,
            .uncompressed_size = message.uncompressed_size,
        };
        self.chunks = chunks;
        self.received_chunks = 0;
    }

    pub fn pushChunk(self: *RbResyncAssemblerV5, message: relay_protocol.RbResyncChunk) RollbackResyncV5Error!void {
        const begin_message = self.begin_message orelse return error.ResyncBeginMissing;
        if (!std.mem.eql(u8, message.request_id, begin_message.request_id)) return error.ResyncRequestIdMismatch;
        if (message.chunk_index < 0 or @as(usize, @intCast(message.chunk_index)) >= self.chunks.len) {
            return error.ResyncChunkIndexInvalid;
        }

        const index: usize = @intCast(message.chunk_index);
        const payload = try dupeBytes(self.allocator, message.payload.data);
        errdefer freeBytes(self.allocator, payload);
        if (self.chunks[index]) |old_payload| {
            freeBytes(self.allocator, old_payload);
        } else {
            self.received_chunks += 1;
        }
        self.chunks[index] = payload;
    }

    pub fn finalize(self: *RbResyncAssemblerV5, message: relay_protocol.RbResyncCommit) RollbackResyncV5Error!ResyncSnapshot {
        const begin_message = self.begin_message orelse return error.ResyncBeginMissing;
        if (!std.mem.eql(u8, message.request_id, begin_message.request_id)) return error.ResyncRequestIdMismatch;
        if (message.snapshot_tick != begin_message.snapshot_tick) return error.ResyncTickMismatch;
        if (self.received_chunks != self.chunks.len) return error.ResyncChunksIncomplete;

        var compressed_list: std.ArrayList(u8) = .empty;
        defer compressed_list.deinit(self.allocator);
        for (self.chunks) |maybe_payload| {
            const payload = maybe_payload orelse return error.ResyncChunksIncomplete;
            try compressed_list.appendSlice(self.allocator, payload);
        }

        const compressed = compressed_list.items;
        if (compressed.len != @as(usize, @intCast(begin_message.compressed_size))) return error.ResyncCompressedSizeMismatch;
        if (compressed.len > self.max_snapshot_bytes) return error.CompressedSnapshotTooLarge;

        const payload = try inflateZlibPayload(self.allocator, compressed, self.max_snapshot_bytes);
        errdefer self.allocator.free(payload);
        if (payload.len != @as(usize, @intCast(begin_message.uncompressed_size))) return error.ResyncUncompressedSizeMismatch;
        if (payload.len > self.max_snapshot_bytes) return error.SnapshotTooLarge;

        const tick_index = begin_message.snapshot_tick;
        self.clear();
        return .{ .tick_index = tick_index, .payload = payload };
    }

    fn clear(self: *RbResyncAssemblerV5) void {
        if (self.begin_message) |begin_message| {
            freeBytes(self.allocator, begin_message.request_id);
            freeBytes(self.allocator, begin_message.codec);
        }
        for (self.chunks) |maybe_payload| {
            if (maybe_payload) |payload| freeBytes(self.allocator, payload);
        }
        if (self.chunks.len != 0) self.allocator.free(self.chunks);
        self.begin_message = null;
        self.chunks = &.{};
        self.received_chunks = 0;
    }
};

fn compressZlibPayload(
    allocator: std.mem.Allocator,
    payload: []const u8,
    max_output_bytes: usize,
) RollbackResyncV5Error![]u8 {
    var output = try std.Io.Writer.Allocating.initCapacity(allocator, @min(@max(payload.len + 64, 1024), max_output_bytes + 64));
    defer output.deinit();

    var deflate_buffer: [std.compress.flate.max_window_len * 2]u8 = undefined;
    var compressor = std.compress.flate.Compress.init(
        &output.writer,
        &deflate_buffer,
        .zlib,
        .level_6,
    ) catch return error.OutOfMemory;
    compressor.writer.writeAll(payload) catch return error.OutOfMemory;
    compressor.finish() catch return error.OutOfMemory;

    const compressed = try output.toOwnedSlice();
    errdefer allocator.free(compressed);
    if (compressed.len > max_output_bytes) return error.CompressedSnapshotTooLarge;
    return compressed;
}

fn inflateZlibPayload(
    allocator: std.mem.Allocator,
    compressed: []const u8,
    max_output_bytes: usize,
) RollbackResyncV5Error![]u8 {
    var input: std.Io.Reader = .fixed(compressed);
    var window: [std.compress.flate.max_window_len]u8 = undefined;
    var decompress: std.compress.flate.Decompress = .init(&input, .zlib, &window);

    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);

    var chunk: [8192]u8 = undefined;
    var total: usize = 0;
    while (true) {
        const n = decompress.reader.readSliceShort(&chunk) catch return error.InvalidCompressedSnapshot;
        if (n == 0) break;
        total += n;
        if (total > max_output_bytes) return error.SnapshotTooLarge;
        try out.appendSlice(allocator, chunk[0..n]);
    }

    return out.toOwnedSlice(allocator);
}

fn maxChunkCount(max_snapshot_bytes: usize) usize {
    return @max(@as(usize, 1), ceilDiv(max_snapshot_bytes, chunk_payload_bytes));
}

fn ceilDiv(value: usize, divisor: usize) usize {
    return if (value == 0) 0 else 1 + ((value - 1) / divisor);
}

fn dupeBytes(allocator: std.mem.Allocator, value: []const u8) RollbackResyncV5Error![]const u8 {
    if (value.len == 0) return "";
    return allocator.dupe(u8, value) catch return error.OutOfMemory;
}

fn freeBytes(allocator: std.mem.Allocator, value: []const u8) void {
    if (value.len != 0) allocator.free(value);
}

fn deinitChunks(allocator: std.mem.Allocator, chunks: []relay_protocol.RbResyncChunk) void {
    freeChunkItems(allocator, chunks);
    if (chunks.len != 0) allocator.free(chunks);
}

fn freeChunkItems(allocator: std.mem.Allocator, chunks: []relay_protocol.RbResyncChunk) void {
    for (chunks) |chunk| {
        freeBytes(allocator, chunk.request_id);
        freeBytes(allocator, chunk.payload.data);
    }
}

test "rollback resync v5 encodes and decodes survival mode snapshots" {
    const snapshot: ModeStateSnapshotV2 = .{ .survival = .{
        .tick_index = 12,
        .replay_state = .{ .tick_index = 12, .recorded_tick_count = 13 },
        .runtime_state = .{
            .elapsed_ms = 200.5,
            .stage = 3,
            .spawn_cooldown_ms = 40.25,
            .perk_pending_count = 1,
        },
    } };

    const blob = try encodeModeSnapshot(std.testing.allocator, snapshot);
    defer std.testing.allocator.free(blob);

    var decoded = try decodeModeSnapshot(std.testing.allocator, blob);
    defer decoded.deinit();
    switch (decoded.value) {
        .survival => |survival| {
            try std.testing.expectEqual(@as(i32, snapshot_schema_version), survival.schema_version);
            try std.testing.expectEqual(@as(i32, 12), survival.tick_index);
            try std.testing.expectEqual(@as(i32, 13), survival.replay_state.?.recorded_tick_count);
            try std.testing.expectEqual(@as(i32, 3), survival.runtime_state.stage);
            try std.testing.expectEqual(@as(i32, 1), survival.runtime_state.perk_pending_count);
            try std.testing.expectApproxEqAbs(@as(f32, 200.5), survival.runtime_state.elapsed_ms, 0.001);
        },
        else => return error.ExpectedSurvivalSnapshot,
    }
}

test "rollback resync v5 decodes python msgspec survival snapshot fixture" {
    const fixture =
        "85a46d6f6465a8737572766976616cae736368656d615f76657273696f6e04aa7469636b5f696e6465780cac7265706c61795f737461746582aa7469636b5f696e6465780cb37265636f726465645f7469636b5f636f756e740dad72756e74696d655f737461746584aa656c61707365645f6d73cb4069100000000000a5737461676503b1737061776e5f636f6f6c646f776e5f6d73cb4044200000000000b27065726b5f70656e64696e675f636f756e7401";
    var bytes: [fixture.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&bytes, fixture);

    var decoded = try decodeModeSnapshot(std.testing.allocator, &bytes);
    defer decoded.deinit();
    switch (decoded.value) {
        .survival => |survival| {
            try std.testing.expectEqual(@as(i32, 12), survival.tick_index);
            try std.testing.expectEqual(@as(i32, 13), survival.replay_state.?.recorded_tick_count);
            try std.testing.expectApproxEqAbs(@as(f32, 200.5), survival.runtime_state.elapsed_ms, 0.001);
            try std.testing.expectEqual(@as(i32, 3), survival.runtime_state.stage);
            try std.testing.expectApproxEqAbs(@as(f32, 40.25), survival.runtime_state.spawn_cooldown_ms, 0.001);
            try std.testing.expectEqual(@as(i32, 1), survival.runtime_state.perk_pending_count);
        },
        else => return error.ExpectedSurvivalSnapshot,
    }
}

test "rollback resync v5 encodes mode-specific runtime snapshots" {
    const quest_entries = [_]spawn_mod.QuestSpawnEntry{.{
        .pos = .{ .x = 10.0, .y = 20.0 },
        .heading = 1.5,
        .spawn_id = .alien_random_06,
        .trigger_ms = 300,
        .count = 4,
    }};
    const quest_snapshot: ModeStateSnapshotV2 = .{ .quests = .{
        .tick_index = 8,
        .runtime_state = .{
            .elapsed_ms = 500.0,
            .spawn_entries = &quest_entries,
            .spawn_timeline_ms = 250.0,
            .no_creatures_timer_ms = 20.0,
            .completion_transition_ms = -1.0,
            .perk_pending_count = 2,
        },
    } };

    const quest_blob = try encodeModeSnapshot(std.testing.allocator, quest_snapshot);
    defer std.testing.allocator.free(quest_blob);
    var decoded_quest = try decodeModeSnapshot(std.testing.allocator, quest_blob);
    defer decoded_quest.deinit();
    switch (decoded_quest.value) {
        .quests => |quests| {
            try std.testing.expectEqual(@as(i32, 8), quests.tick_index);
            try std.testing.expectEqual(@as(usize, 1), quests.runtime_state.spawn_entries.len);
            try std.testing.expectEqual(spawn_mod.SpawnId.alien_random_06, quests.runtime_state.spawn_entries[0].spawn_id);
            try std.testing.expectEqual(@as(i32, 2), quests.runtime_state.perk_pending_count);
        },
        else => return error.ExpectedQuestSnapshot,
    }

    const rush_snapshot: ModeStateSnapshotV2 = .{ .rush = .{
        .tick_index = 9,
        .runtime_state = .{
            .elapsed_ms = 900.0,
            .spawn_cooldown_ms = 12.0,
            .kill_count = 5,
        },
    } };
    const rush_blob = try encodeModeSnapshot(std.testing.allocator, rush_snapshot);
    defer std.testing.allocator.free(rush_blob);
    var decoded_rush = try decodeModeSnapshot(std.testing.allocator, rush_blob);
    defer decoded_rush.deinit();
    switch (decoded_rush.value) {
        .rush => |rush| try std.testing.expectEqual(@as(i32, 5), rush.runtime_state.kill_count),
        else => return error.ExpectedRushSnapshot,
    }
}

test "rollback resync v5 rejects unsupported snapshot schema" {
    const blob = try encodeModeSnapshot(std.testing.allocator, .{ .survival = .{ .schema_version = snapshot_schema_version } });
    defer std.testing.allocator.free(blob);
    var decoded = try decodeModeSnapshot(std.testing.allocator, blob);
    defer decoded.deinit();

    try std.testing.expectError(error.UnsupportedSnapshotSchema, encodeModeSnapshot(std.testing.allocator, .{
        .survival = .{ .schema_version = snapshot_schema_version + 1 },
    }));
}

test "rollback resync v5 builds and assembles snapshot stream" {
    const payload = "rush snapshot payload";
    var stream = try buildRbResyncMessages(std.testing.allocator, "rq", 9, payload);
    defer stream.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("rq", stream.begin.request_id);
    try std.testing.expectEqualStrings(snapshot_codec, stream.begin.codec);
    try std.testing.expectEqual(@as(i32, 9), stream.begin.snapshot_tick);
    try std.testing.expectEqual(@as(i32, @intCast(payload.len)), stream.begin.uncompressed_size);
    try std.testing.expect(stream.begin.compressed_size > 0);
    try std.testing.expectEqual(@as(i32, @intCast(stream.chunks.len)), stream.begin.total_chunks);

    var assembler = RbResyncAssemblerV5.init(std.testing.allocator);
    defer assembler.deinit();
    try assembler.begin(stream.begin);
    try std.testing.expectEqualStrings("rq", assembler.requestId());
    for (stream.chunks) |chunk| try assembler.pushChunk(chunk);
    var snapshot = try assembler.finalize(stream.commit);
    defer snapshot.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(i32, 9), snapshot.tick_index);
    try std.testing.expectEqualStrings(payload, snapshot.payload);
}

test "rollback resync v5 chunks payloads at relay boundary" {
    const payload = try std.testing.allocator.alloc(u8, chunk_payload_bytes * 2 + 17);
    defer std.testing.allocator.free(payload);
    var prng = std.Random.DefaultPrng.init(0x4352_494d_534f_4e);
    prng.random().bytes(payload);

    var stream = try buildRbResyncMessages(std.testing.allocator, "rq-big", 12, payload);
    defer stream.deinit(std.testing.allocator);

    try std.testing.expect(stream.chunks.len > 1);
    for (stream.chunks) |chunk| try std.testing.expect(chunk.payload.data.len <= chunk_payload_bytes);

    var assembler = RbResyncAssemblerV5.init(std.testing.allocator);
    defer assembler.deinit();
    try assembler.begin(stream.begin);
    for (stream.chunks) |chunk| try assembler.pushChunk(chunk);
    var snapshot = try assembler.finalize(stream.commit);
    defer snapshot.deinit(std.testing.allocator);

    try std.testing.expectEqualSlices(u8, payload, snapshot.payload);
}

test "rollback resync v5 rejects commit tick mismatch" {
    var stream = try buildRbResyncMessages(std.testing.allocator, "rq2", 12, "payload");
    defer stream.deinit(std.testing.allocator);

    var assembler = RbResyncAssemblerV5.init(std.testing.allocator);
    defer assembler.deinit();
    try assembler.begin(stream.begin);
    for (stream.chunks) |chunk| try assembler.pushChunk(chunk);

    try std.testing.expectError(error.ResyncTickMismatch, assembler.finalize(.{
        .request_id = stream.commit.request_id,
        .snapshot_tick = stream.commit.snapshot_tick + 1,
    }));
}

test "rollback resync v5 rejects incomplete chunks" {
    var stream = try buildRbResyncMessages(std.testing.allocator, "rq3", 20, "payload");
    defer stream.deinit(std.testing.allocator);

    var assembler = RbResyncAssemblerV5.init(std.testing.allocator);
    defer assembler.deinit();
    try assembler.begin(stream.begin);

    try std.testing.expectError(error.ResyncChunksIncomplete, assembler.finalize(stream.commit));
}

test "rollback resync v5 validates begin fields" {
    var assembler = RbResyncAssemblerV5.init(std.testing.allocator);
    defer assembler.deinit();

    try std.testing.expectError(error.UnsupportedSnapshotCodec, assembler.begin(.{ .codec = "msgpack_state_v1" }));
    try std.testing.expectError(error.ResyncChunkCountInvalid, assembler.begin(.{
        .request_id = "rq",
        .codec = snapshot_codec,
        .total_chunks = 0,
    }));
    try std.testing.expectError(error.SnapshotSizeInvalid, assembler.begin(.{
        .request_id = "rq",
        .codec = snapshot_codec,
        .total_chunks = 1,
        .uncompressed_size = relay_protocol.resync_max_snapshot_bytes + 1,
    }));
}
