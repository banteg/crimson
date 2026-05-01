const std = @import("std");

const relay_protocol = @import("relay_protocol.zig");

pub const schema_version: i32 = 4;
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
    OutOfMemory,
};

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
