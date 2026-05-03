const std = @import("std");

const packed_input = @import("packed_input.zig");
const relay_protocol = @import("relay_protocol.zig");
const rollback = @import("rollback.zig");
const rollback_resync_v5 = @import("rollback_resync_v5.zig");

const max_players: usize = @intCast(relay_protocol.max_players);
const snapshot_keep_ticks: i32 = 64;

pub const Role = enum {
    host,
    join,
};

pub const Options = struct {
    role: Role,
    player_count: i32,
    local_slot_index: i32,
    input_delay_ticks: i32 = relay_protocol.input_delay_ticks,
    max_rollback_ticks: i32 = relay_protocol.rollback_max_ticks,
    reconnect_timeout_ms: i32 = relay_protocol.reconnect_timeout_ms,
};

pub const TickFrame = struct {
    tick_index: i32,
    player_count: usize,
    frame_inputs: [max_players]packed_input.PackedPlayerInput = [_]packed_input.PackedPlayerInput{.{}} ** max_players,

    pub fn input(self: TickFrame, slot_index: usize) packed_input.PackedPlayerInput {
        return self.frame_inputs[slot_index];
    }
};

pub const OutgoingMessage = struct {
    reliable: bool = false,
    message: relay_protocol.NetMessage,
};

pub const PendingSnapshot = struct {
    tick_index: i32,
    payload: []u8,

    pub fn deinit(self: *PendingSnapshot, allocator: std.mem.Allocator) void {
        allocator.free(self.payload);
        self.* = undefined;
    }
};

const SnapshotEntry = struct {
    tick_index: i32,
    payload: []u8,
};

pub const RuntimeCore = struct {
    allocator: std.mem.Allocator,
    role: Role,
    controller: rollback.RollbackController,
    reconnect_timeout_ms: i32,

    frame_queue: std.ArrayList(TickFrame) = .empty,
    outbox: std.ArrayList(OutgoingMessage) = .empty,
    snapshot_blobs: std.ArrayList(SnapshotEntry) = .empty,
    rollback_snapshot_ticks: std.ArrayList(i32) = .empty,
    pending_resync_snapshot: ?PendingSnapshot = null,
    resync_assembler: ?rollback_resync_v5.RbResyncAssemblerV5 = null,
    active_resync_request_id: []const u8 = "",
    handled_resync_request_ids: std.StringHashMap(void),
    remote_seen_slots: [max_players]bool = [_]bool{false} ** max_players,

    paused_for_resync: bool = false,
    paused_for_reconnect: bool = false,
    pending_rollback_from: ?i32 = null,
    rollback_count: i32 = 0,
    prediction_mismatches: i32 = 0,
    max_rollback_ticks_seen: i32 = 0,
    resync_count: i32 = 0,
    reconnect_count: i32 = 0,
    resync_deadline_ms: i64 = 0,
    reconnect_deadline_ms: i64 = 0,
    next_resync_id: i32 = 1,
    error_reason: []const u8 = "",

    pub fn init(allocator: std.mem.Allocator, options: Options) RuntimeCore {
        return .{
            .allocator = allocator,
            .role = options.role,
            .controller = rollback.RollbackController.init(allocator, .{
                .player_count = options.player_count,
                .local_slot_index = options.local_slot_index,
                .input_delay_ticks = options.input_delay_ticks,
                .max_rollback_ticks = options.max_rollback_ticks,
            }),
            .reconnect_timeout_ms = @max(1, options.reconnect_timeout_ms),
            .handled_resync_request_ids = std.StringHashMap(void).init(allocator),
        };
    }

    pub fn deinit(self: *RuntimeCore) void {
        self.controller.deinit();
        self.frame_queue.deinit(self.allocator);
        self.clearOutbox();
        self.outbox.deinit(self.allocator);
        self.clearSnapshots();
        self.snapshot_blobs.deinit(self.allocator);
        self.rollback_snapshot_ticks.deinit(self.allocator);
        if (self.pending_resync_snapshot) |*snapshot| snapshot.deinit(self.allocator);
        if (self.resync_assembler) |*assembler| assembler.deinit();
        if (self.active_resync_request_id.len != 0) self.allocator.free(self.active_resync_request_id);
        var it = self.handled_resync_request_ids.keyIterator();
        while (it.next()) |key| self.allocator.free(key.*);
        self.handled_resync_request_ids.deinit();
        if (self.error_reason.len != 0) self.allocator.free(self.error_reason);
        self.* = undefined;
    }

    pub fn queueLocalInput(self: *RuntimeCore, input: packed_input.PackedPlayerInput, now_ms: i64) !void {
        if (self.paused_for_resync or self.paused_for_reconnect) return;
        var batch = try self.controller.queueLocalInput(input);
        defer self.controller.deinitInputBatch(&batch);
        try self.send(.{ .rb_input_sample = batch }, false);
        try self.drainFrames();
        try self.drainRollbackSignals(now_ms);
    }

    pub fn primeInitialDelay(self: *RuntimeCore) !void {
        try self.controller.primeInitialDelay();
        try self.drainFrames();
    }

    pub fn hostRemoteInputsReady(self: *const RuntimeCore) bool {
        if (self.paused_for_resync or self.paused_for_reconnect) return false;
        if (self.role != .host) return true;
        for (0..self.controller.player_count) |slot| {
            if (slot == self.controller.local_slot_index) continue;
            if (!self.remote_seen_slots[slot]) return false;
        }
        return true;
    }

    pub fn handleMessage(self: *RuntimeCore, message: relay_protocol.NetMessage, now_ms: i64) !void {
        switch (message) {
            .rb_input_sample => |batch| {
                if (self.paused_for_resync or self.paused_for_reconnect) return;
                if (batch.slot_index != @as(i32, @intCast(self.controller.local_slot_index))) {
                    self.markRemoteSeen(batch.slot_index);
                    try self.controller.ingestRemoteSamples(batch.slot_index, batch.samples);
                    self.syncMetrics();
                    try self.drainRollbackSignals(now_ms);
                    try self.drainFrames();
                }
            },
            .rb_resync_request => |request| try self.handleResyncRequest(request, now_ms),
            .rb_resync_begin => |begin_message| try self.handleResyncBegin(begin_message),
            .rb_resync_chunk => |chunk| try self.handleResyncChunk(chunk),
            .rb_resync_commit => |commit| try self.handleResyncCommit(commit, now_ms),
            .peer_disconnect => |disconnect| try self.handlePeerDisconnect(disconnect, now_ms),
            else => {},
        }
    }

    fn markRemoteSeen(self: *RuntimeCore, slot_index_raw: i32) void {
        if (slot_index_raw < 0) return;
        const slot_index: usize = @intCast(slot_index_raw);
        if (slot_index >= self.controller.player_count) return;
        if (slot_index == self.controller.local_slot_index) return;
        self.remote_seen_slots[slot_index] = true;
    }

    pub fn storeLocalSnapshot(self: *RuntimeCore, tick_index_raw: i32, snapshot_blob: []const u8) !void {
        const tick_index = @max(0, tick_index_raw);
        const payload = try self.allocator.dupe(u8, snapshot_blob);
        errdefer self.allocator.free(payload);

        for (self.snapshot_blobs.items) |*entry| {
            if (entry.tick_index == tick_index) {
                self.allocator.free(entry.payload);
                entry.payload = payload;
                return;
            }
        }

        try self.snapshot_blobs.append(self.allocator, .{ .tick_index = tick_index, .payload = payload });
        self.pruneSnapshots(tick_index - snapshot_keep_ticks);
    }

    pub fn markLocalRollbackSnapshot(self: *RuntimeCore, tick_index_raw: i32) !void {
        const tick_index = @max(0, tick_index_raw);
        for (self.rollback_snapshot_ticks.items) |existing| {
            if (existing == tick_index) return;
        }
        try self.rollback_snapshot_ticks.append(self.allocator, tick_index);
        self.pruneRollbackSnapshotTicks(tick_index - snapshot_keep_ticks);
    }

    pub fn popFrame(self: *RuntimeCore) ?TickFrame {
        if (self.paused_for_reconnect) return null;
        if (self.frame_queue.items.len == 0) return null;
        return self.frame_queue.orderedRemove(0);
    }

    pub fn drainRollbackFrom(self: *RuntimeCore) ?i32 {
        const value = self.pending_rollback_from;
        self.pending_rollback_from = null;
        return value;
    }

    pub fn takePendingResyncSnapshot(self: *RuntimeCore) ?PendingSnapshot {
        const snapshot = self.pending_resync_snapshot orelse return null;
        self.pending_resync_snapshot = null;
        return snapshot;
    }

    pub fn completeResync(self: *RuntimeCore, snapshot_tick_raw: i32) !void {
        const next_tick = @max(0, snapshot_tick_raw) + 1;
        if (self.pending_resync_snapshot) |*snapshot| {
            snapshot.deinit(self.allocator);
            self.pending_resync_snapshot = null;
        }
        if (self.resync_assembler) |*assembler| {
            assembler.deinit();
            self.resync_assembler = null;
        }
        try self.controller.resetToTick(next_tick);
        self.frame_queue.clearRetainingCapacity();
        self.pending_rollback_from = null;
        self.paused_for_resync = false;
        self.resync_deadline_ms = 0;
        try self.setActiveRequestId("");
    }

    pub fn completeReconnect(self: *RuntimeCore) void {
        self.paused_for_reconnect = false;
        self.reconnect_deadline_ms = 0;
    }

    pub fn beginSelfReconnect(self: *RuntimeCore, now_ms: i64) void {
        if (self.reconnect_deadline_ms <= 0) self.reconnect_count += 1;
        self.paused_for_reconnect = true;
        self.reconnect_deadline_ms = now_ms + self.reconnect_timeout_ms;
    }

    pub fn checkReconnectTimeout(self: *RuntimeCore, now_ms: i64) !void {
        if (self.reconnect_deadline_ms <= 0) return;
        if (now_ms < self.reconnect_deadline_ms) return;
        try self.setError("reconnect_timeout");
    }

    pub fn clearOutbox(self: *RuntimeCore) void {
        for (self.outbox.items) |*item| relay_protocol.deinitMessage(self.allocator, &item.message);
        self.outbox.clearRetainingCapacity();
    }

    fn drainFrames(self: *RuntimeCore) !void {
        if (self.paused_for_resync or self.paused_for_reconnect) return;
        while (self.controller.popFrame()) |frame| {
            var tick_frame: TickFrame = .{
                .tick_index = frame.tick_index,
                .player_count = frame.player_count,
            };
            for (0..frame.player_count) |slot| tick_frame.frame_inputs[slot] = frame.frame_inputs[slot];
            try self.frame_queue.append(self.allocator, tick_frame);
        }
    }

    fn handlePeerDisconnect(self: *RuntimeCore, disconnect: relay_protocol.PeerDisconnect, now_ms: i64) !void {
        if (disconnect.slot_index == @as(i32, @intCast(self.controller.local_slot_index))) {
            try self.setError(if (disconnect.reason.len == 0) "peer_disconnect" else disconnect.reason);
            return;
        }
        if (self.reconnect_deadline_ms <= 0) self.reconnect_count += 1;
        self.paused_for_reconnect = true;
        self.reconnect_deadline_ms = now_ms + self.reconnect_timeout_ms;
    }

    fn drainRollbackSignals(self: *RuntimeCore, now_ms: i64) !void {
        if (self.controller.drainRollbackFrom()) |from_tick| try self.applyRollbackFrom(from_tick, now_ms);
        if (self.controller.drainResyncFrom()) |from_tick| try self.sendResyncRequest(from_tick, "rollback_window_overflow", now_ms);
    }

    fn applyRollbackFrom(self: *RuntimeCore, from_tick_raw: i32, now_ms: i64) !void {
        const from_tick = @max(0, from_tick_raw);
        self.pending_rollback_from = minOptionalTick(self.pending_rollback_from, from_tick);

        if (from_tick == 0 or !self.hasRollbackSnapshotAtOrBefore(from_tick - 1)) {
            try self.sendResyncRequest(from_tick, "rollback_snapshot_missing", now_ms);
            return;
        }

        const rebuilt = try self.controller.rebuildEmittedFrom(from_tick);
        defer self.allocator.free(rebuilt);
        if (rebuilt.len == 0) return;

        var replacement: std.ArrayList(TickFrame) = .empty;
        errdefer replacement.deinit(self.allocator);
        for (self.frame_queue.items) |frame| {
            if (frame.tick_index < from_tick) try replacement.append(self.allocator, frame);
        }
        for (rebuilt) |frame| {
            var tick_frame: TickFrame = .{
                .tick_index = frame.tick_index,
                .player_count = frame.player_count,
            };
            for (0..frame.player_count) |slot| tick_frame.frame_inputs[slot] = frame.frame_inputs[slot];
            try replacement.append(self.allocator, tick_frame);
        }
        self.frame_queue.deinit(self.allocator);
        self.frame_queue = replacement;
    }

    fn sendResyncRequest(self: *RuntimeCore, from_tick_raw: i32, reason: []const u8, now_ms: i64) !void {
        const request_id = try std.fmt.allocPrint(self.allocator, "rq{d}", .{self.next_resync_id});
        defer self.allocator.free(request_id);
        self.next_resync_id += 1;

        self.resync_count += 1;
        self.paused_for_resync = true;
        self.resync_deadline_ms = now_ms + self.reconnect_timeout_ms;
        try self.setActiveRequestId(request_id);
        try self.send(.{ .rb_resync_request = .{
            .request_id = request_id,
            .from_tick = @max(0, from_tick_raw),
            .reason = reason,
            .requested_by_slot = @intCast(self.controller.local_slot_index),
        } }, true);
    }

    fn handleResyncRequest(self: *RuntimeCore, request: relay_protocol.RbResyncRequest, _: i64) !void {
        if (self.role != .host) return;

        const request_id = std.mem.trim(u8, request.request_id, " \t\r\n");
        if (request_id.len == 0) return;
        if (self.handled_resync_request_ids.contains(request_id)) return;
        const owned_request_id = try self.allocator.dupe(u8, request_id);
        self.handled_resync_request_ids.put(owned_request_id, {}) catch |err| {
            self.allocator.free(owned_request_id);
            return err;
        };

        const snapshot = self.latestSnapshotAny() orelse {
            try self.send(.{ .relay_error = .{ .reason = "resync_snapshot_unavailable" } }, true);
            return;
        };

        var stream = rollback_resync_v5.buildRbResyncMessages(
            self.allocator,
            owned_request_id,
            snapshot.tick_index,
            snapshot.payload,
        ) catch {
            try self.send(.{ .relay_error = .{ .reason = "resync_snapshot_invalid" } }, true);
            return;
        };
        defer stream.deinit(self.allocator);

        try self.send(.{ .rb_resync_begin = stream.begin }, true);
        for (stream.chunks) |chunk| try self.send(.{ .rb_resync_chunk = chunk }, true);
        try self.send(.{ .rb_resync_commit = stream.commit }, true);
    }

    fn handleResyncBegin(self: *RuntimeCore, begin_message: relay_protocol.RbResyncBegin) !void {
        if (begin_message.request_id.len == 0) return;
        if (self.active_resync_request_id.len != 0 and !std.mem.eql(u8, begin_message.request_id, self.active_resync_request_id)) return;

        if (self.resync_assembler) |*existing| existing.deinit();
        self.resync_assembler = rollback_resync_v5.RbResyncAssemblerV5.init(self.allocator);
        self.resync_assembler.?.begin(begin_message) catch return;
        try self.setActiveRequestId(begin_message.request_id);
        self.paused_for_resync = true;
    }

    fn handleResyncChunk(self: *RuntimeCore, chunk: relay_protocol.RbResyncChunk) !void {
        const assembler = if (self.resync_assembler) |*assembler| assembler else return;
        if (!std.mem.eql(u8, chunk.request_id, assembler.requestId())) return;
        assembler.pushChunk(chunk) catch {
            try self.setError("resync_chunk_error");
            assembler.deinit();
            self.resync_assembler = null;
        };
    }

    fn handleResyncCommit(self: *RuntimeCore, commit: relay_protocol.RbResyncCommit, now_ms: i64) !void {
        const assembler = if (self.resync_assembler) |*assembler| assembler else return;
        if (!std.mem.eql(u8, commit.request_id, assembler.requestId())) return;

        var snapshot = assembler.finalize(commit) catch {
            try self.setError("resync_commit_error");
            assembler.deinit();
            self.resync_assembler = null;
            return;
        };
        self.resync_assembler = null;
        if (self.pending_resync_snapshot) |*pending| pending.deinit(self.allocator);
        self.pending_resync_snapshot = .{
            .tick_index = snapshot.tick_index,
            .payload = snapshot.payload,
        };
        snapshot.payload = &.{};
        self.paused_for_resync = true;
        self.resync_deadline_ms = now_ms + self.reconnect_timeout_ms;
    }

    fn send(self: *RuntimeCore, message: relay_protocol.NetMessage, reliable: bool) !void {
        const cloned = try relay_protocol.cloneMessage(self.allocator, message);
        errdefer {
            var mutable = cloned;
            relay_protocol.deinitMessage(self.allocator, &mutable);
        }
        try self.outbox.append(self.allocator, .{ .reliable = reliable, .message = cloned });
    }

    fn syncMetrics(self: *RuntimeCore) void {
        self.rollback_count = self.controller.rollback_count;
        self.prediction_mismatches = self.controller.prediction_mismatches;
        self.max_rollback_ticks_seen = self.controller.max_rollback_distance;
    }

    fn latestSnapshotAny(self: RuntimeCore) ?SnapshotEntry {
        var latest: ?SnapshotEntry = null;
        for (self.snapshot_blobs.items) |entry| {
            if (latest == null or entry.tick_index > latest.?.tick_index) latest = entry;
        }
        return latest;
    }

    fn latestSnapshotAtOrBefore(self: RuntimeCore, tick_index: i32) ?SnapshotEntry {
        var latest: ?SnapshotEntry = null;
        for (self.snapshot_blobs.items) |entry| {
            if (entry.tick_index <= tick_index and (latest == null or entry.tick_index > latest.?.tick_index)) latest = entry;
        }
        return latest;
    }

    fn hasRollbackSnapshotAtOrBefore(self: RuntimeCore, tick_index: i32) bool {
        if (self.latestSnapshotAtOrBefore(tick_index) != null) return true;
        for (self.rollback_snapshot_ticks.items) |snapshot_tick| {
            if (snapshot_tick <= tick_index) return true;
        }
        return false;
    }

    fn pruneSnapshots(self: *RuntimeCore, keep_from: i32) void {
        var idx: usize = 0;
        while (idx < self.snapshot_blobs.items.len) {
            if (self.snapshot_blobs.items[idx].tick_index >= keep_from) {
                idx += 1;
                continue;
            }
            self.allocator.free(self.snapshot_blobs.items[idx].payload);
            _ = self.snapshot_blobs.orderedRemove(idx);
        }
    }

    fn pruneRollbackSnapshotTicks(self: *RuntimeCore, keep_from: i32) void {
        var idx: usize = 0;
        while (idx < self.rollback_snapshot_ticks.items.len) {
            if (self.rollback_snapshot_ticks.items[idx] >= keep_from) {
                idx += 1;
                continue;
            }
            _ = self.rollback_snapshot_ticks.orderedRemove(idx);
        }
    }

    fn clearSnapshots(self: *RuntimeCore) void {
        for (self.snapshot_blobs.items) |entry| self.allocator.free(entry.payload);
        self.snapshot_blobs.clearRetainingCapacity();
    }

    fn setActiveRequestId(self: *RuntimeCore, request_id: []const u8) !void {
        if (self.active_resync_request_id.len != 0) self.allocator.free(self.active_resync_request_id);
        self.active_resync_request_id = if (request_id.len == 0) "" else try self.allocator.dupe(u8, request_id);
    }

    fn setError(self: *RuntimeCore, reason: []const u8) !void {
        if (self.error_reason.len != 0) self.allocator.free(self.error_reason);
        self.error_reason = if (reason.len == 0) "" else try self.allocator.dupe(u8, reason);
    }
};

fn minOptionalTick(current: ?i32, candidate: i32) i32 {
    return if (current) |value| @min(value, candidate) else candidate;
}

test "rollback runtime queues local input and emitted frame" {
    var runtime = RuntimeCore.init(std.testing.allocator, .{
        .role = .host,
        .player_count = 1,
        .local_slot_index = 0,
        .input_delay_ticks = 0,
    });
    defer runtime.deinit();

    try runtime.queueLocalInput(.{ .flags = 7 }, 10);

    try std.testing.expectEqual(@as(usize, 1), runtime.outbox.items.len);
    try std.testing.expect(!runtime.outbox.items[0].reliable);
    switch (runtime.outbox.items[0].message) {
        .rb_input_sample => |batch| {
            try std.testing.expectEqual(@as(i32, 0), batch.slot_index);
            try std.testing.expectEqual(@as(usize, 1), batch.samples.len);
            try std.testing.expectEqual(@as(u32, 7), batch.samples[0].packed_input.flags);
        },
        else => return error.ExpectedInputBatch,
    }

    const frame = runtime.popFrame() orelse return error.ExpectedFrame;
    try std.testing.expectEqual(@as(i32, 0), frame.tick_index);
    try std.testing.expectEqual(@as(u32, 7), frame.input(0).flags);
}

test "rollback runtime sends resync request when rollback snapshot is missing" {
    var runtime = RuntimeCore.init(std.testing.allocator, .{
        .role = .host,
        .player_count = 2,
        .local_slot_index = 0,
        .input_delay_ticks = 0,
        .max_rollback_ticks = 8,
    });
    defer runtime.deinit();

    try runtime.queueLocalInput(.{}, 10);
    _ = runtime.popFrame();
    try runtime.handleMessage(.{ .rb_input_sample = .{
        .slot_index = 1,
        .samples = &[_]relay_protocol.RbInputSample{.{ .tick_index = 0, .packed_input = .{ .flags = 3 } }},
    } }, 20);

    try std.testing.expectEqual(@as(i32, 1), runtime.resync_count);
    switch (runtime.outbox.items[runtime.outbox.items.len - 1].message) {
        .rb_resync_request => |request| {
            try std.testing.expectEqualStrings("rq1", request.request_id);
            try std.testing.expectEqualStrings("rollback_snapshot_missing", request.reason);
            try std.testing.expectEqual(@as(i32, 0), request.from_tick);
        },
        else => return error.ExpectedResyncRequest,
    }
}

test "rollback runtime host waits until every remote slot has sent input" {
    var runtime = RuntimeCore.init(std.testing.allocator, .{
        .role = .host,
        .player_count = 3,
        .local_slot_index = 0,
        .input_delay_ticks = 0,
    });
    defer runtime.deinit();

    try std.testing.expect(!runtime.hostRemoteInputsReady());

    try runtime.handleMessage(.{ .rb_input_sample = .{
        .slot_index = 1,
        .samples = &[_]relay_protocol.RbInputSample{.{ .tick_index = 0, .packed_input = .{ .flags = 3 } }},
    } }, 20);
    try std.testing.expect(!runtime.hostRemoteInputsReady());

    try runtime.handleMessage(.{ .rb_input_sample = .{
        .slot_index = 2,
        .samples = &[_]relay_protocol.RbInputSample{.{ .tick_index = 0, .packed_input = .{ .flags = 4 } }},
    } }, 21);
    try std.testing.expect(runtime.hostRemoteInputsReady());

    runtime.paused_for_resync = true;
    try std.testing.expect(!runtime.hostRemoteInputsReady());
}

test "rollback runtime joiner does not wait for remote startup input" {
    var runtime = RuntimeCore.init(std.testing.allocator, .{
        .role = .join,
        .player_count = 2,
        .local_slot_index = 1,
        .input_delay_ticks = 0,
    });
    defer runtime.deinit();

    try std.testing.expect(runtime.hostRemoteInputsReady());
}

test "rollback runtime uses local rollback markers without wire snapshot blobs" {
    var runtime = RuntimeCore.init(std.testing.allocator, .{
        .role = .host,
        .player_count = 2,
        .local_slot_index = 0,
        .input_delay_ticks = 0,
        .max_rollback_ticks = 8,
    });
    defer runtime.deinit();

    try runtime.queueLocalInput(.{}, 10);
    _ = runtime.popFrame();
    try runtime.markLocalRollbackSnapshot(0);
    try runtime.queueLocalInput(.{}, 11);
    _ = runtime.popFrame();

    try runtime.handleMessage(.{ .rb_input_sample = .{
        .slot_index = 1,
        .samples = &[_]relay_protocol.RbInputSample{.{ .tick_index = 1, .packed_input = .{ .flags = 3 } }},
    } }, 20);

    try std.testing.expectEqual(@as(i32, 0), runtime.resync_count);
    try std.testing.expectEqual(@as(?i32, 1), runtime.drainRollbackFrom());
    try std.testing.expectEqual(@as(usize, 0), runtime.snapshot_blobs.items.len);
}

test "rollback runtime host answers resync request from latest snapshot" {
    var runtime = RuntimeCore.init(std.testing.allocator, .{
        .role = .host,
        .player_count = 2,
        .local_slot_index = 0,
        .input_delay_ticks = 0,
    });
    defer runtime.deinit();
    try runtime.storeLocalSnapshot(8, "snapshot-eight");

    try runtime.handleMessage(.{ .rb_resync_request = .{
        .request_id = "rq-host",
        .from_tick = 4,
        .reason = "overflow",
        .requested_by_slot = 1,
    } }, 30);

    try std.testing.expect(runtime.outbox.items.len >= 3);
    try std.testing.expect(runtime.outbox.items[0].reliable);
    switch (runtime.outbox.items[0].message) {
        .rb_resync_begin => |begin_message| {
            try std.testing.expectEqualStrings("rq-host", begin_message.request_id);
            try std.testing.expectEqual(@as(i32, 8), begin_message.snapshot_tick);
        },
        else => return error.ExpectedResyncBegin,
    }
    switch (runtime.outbox.items[runtime.outbox.items.len - 1].message) {
        .rb_resync_commit => |commit| try std.testing.expectEqualStrings("rq-host", commit.request_id),
        else => return error.ExpectedResyncCommit,
    }
}

test "rollback runtime accepts resync stream and exposes pending snapshot" {
    var host = RuntimeCore.init(std.testing.allocator, .{
        .role = .host,
        .player_count = 2,
        .local_slot_index = 0,
        .input_delay_ticks = 0,
    });
    defer host.deinit();
    try host.storeLocalSnapshot(5, "payload-five");
    try host.handleMessage(.{ .rb_resync_request = .{ .request_id = "rq-join", .from_tick = 3, .requested_by_slot = 1 } }, 10);

    var join = RuntimeCore.init(std.testing.allocator, .{
        .role = .join,
        .player_count = 2,
        .local_slot_index = 1,
        .input_delay_ticks = 0,
    });
    defer join.deinit();
    try join.setActiveRequestId("rq-join");

    for (host.outbox.items) |item| try join.handleMessage(item.message, 40);
    var snapshot = join.takePendingResyncSnapshot() orelse return error.ExpectedSnapshot;
    defer snapshot.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(i32, 5), snapshot.tick_index);
    try std.testing.expectEqualStrings("payload-five", snapshot.payload);
    try std.testing.expect(join.takePendingResyncSnapshot() == null);
}

test "rollback runtime completes resync and resumes input capture after snapshot tick" {
    var runtime = RuntimeCore.init(std.testing.allocator, .{
        .role = .join,
        .player_count = 2,
        .local_slot_index = 1,
        .input_delay_ticks = 0,
        .max_rollback_ticks = 2,
    });
    defer runtime.deinit();

    var tick: u32 = 0;
    while (tick < 6) : (tick += 1) {
        try runtime.queueLocalInput(.{ .flags = tick + 1 }, 10 + tick);
        _ = runtime.popFrame();
    }
    try runtime.handleMessage(.{ .rb_input_sample = .{
        .slot_index = 0,
        .samples = &[_]relay_protocol.RbInputSample{.{ .tick_index = 2, .packed_input = .{ .flags = 99 } }},
    } }, 20);
    try std.testing.expect(runtime.paused_for_resync);

    try runtime.completeResync(3);
    try std.testing.expect(!runtime.paused_for_resync);
    try std.testing.expectEqual(@as(i32, 4), runtime.controller.capture_tick);
    try std.testing.expectEqual(@as(i32, 4), runtime.controller.next_emit_tick);
    try std.testing.expectEqual(@as(i64, 0), runtime.resync_deadline_ms);

    try runtime.queueLocalInput(.{ .flags = 7 }, 30);
    const frame = runtime.popFrame() orelse return error.ExpectedFrame;
    try std.testing.expectEqual(@as(i32, 4), frame.tick_index);
    try std.testing.expectEqual(@as(u32, 7), frame.input(1).flags);
}

test "rollback runtime ignores input batches while paused for resync" {
    var runtime = RuntimeCore.init(std.testing.allocator, .{
        .role = .join,
        .player_count = 2,
        .local_slot_index = 1,
        .input_delay_ticks = 0,
        .max_rollback_ticks = 2,
    });
    defer runtime.deinit();

    runtime.paused_for_resync = true;
    try runtime.handleMessage(.{ .rb_input_sample = .{
        .slot_index = 0,
        .samples = &[_]relay_protocol.RbInputSample{.{ .tick_index = 0, .packed_input = .{ .flags = 99 } }},
    } }, 20);

    try std.testing.expect(!runtime.remote_seen_slots[0]);
    try std.testing.expect(runtime.popFrame() == null);
    try std.testing.expect(runtime.drainRollbackFrom() == null);
}

test "rollback runtime pauses on peer disconnect and times out reconnect" {
    var runtime = RuntimeCore.init(std.testing.allocator, .{
        .role = .host,
        .player_count = 2,
        .local_slot_index = 0,
        .input_delay_ticks = 0,
        .reconnect_timeout_ms = 500,
    });
    defer runtime.deinit();

    try runtime.queueLocalInput(.{ .flags = 1 }, 1000);
    try std.testing.expect(runtime.popFrame() != null);

    try runtime.handleMessage(.{ .peer_disconnect = .{ .slot_index = 1, .reason = "timeout" } }, 1200);
    try std.testing.expect(runtime.paused_for_reconnect);
    try std.testing.expectEqual(@as(i32, 1), runtime.reconnect_count);
    try std.testing.expectEqual(@as(i64, 1700), runtime.reconnect_deadline_ms);

    try runtime.queueLocalInput(.{ .flags = 2 }, 1201);
    try std.testing.expect(runtime.popFrame() == null);

    try runtime.checkReconnectTimeout(1699);
    try std.testing.expectEqualStrings("", runtime.error_reason);
    try runtime.checkReconnectTimeout(1700);
    try std.testing.expectEqualStrings("reconnect_timeout", runtime.error_reason);
}

test "rollback runtime resumes input capture after reconnect completes" {
    var runtime = RuntimeCore.init(std.testing.allocator, .{
        .role = .host,
        .player_count = 2,
        .local_slot_index = 0,
        .input_delay_ticks = 0,
    });
    defer runtime.deinit();

    try runtime.handleMessage(.{ .peer_disconnect = .{ .slot_index = 1, .reason = "network_drop" } }, 1000);
    try std.testing.expect(runtime.paused_for_reconnect);

    runtime.completeReconnect();
    try std.testing.expect(!runtime.paused_for_reconnect);
    try std.testing.expectEqual(@as(i64, 0), runtime.reconnect_deadline_ms);

    try runtime.queueLocalInput(.{ .flags = 7 }, 1100);
    const frame = runtime.popFrame() orelse return error.ExpectedFrame;
    try std.testing.expectEqual(@as(u32, 7), frame.input(0).flags);
}
