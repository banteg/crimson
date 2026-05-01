const std = @import("std");

const packed_input = @import("packed_input.zig");
const relay_protocol = @import("relay_protocol.zig");

const max_players: usize = 4;
const max_sent_history_ticks_default: i32 = 256;
const max_resend_samples_default: usize = 64;

pub const RollbackFrame = struct {
    tick_index: i32 = 0,
    player_count: usize = 0,
    frame_inputs: [max_players]packed_input.PackedPlayerInput = [_]packed_input.PackedPlayerInput{.{}} ** max_players,
    predicted_slots: [max_players]bool = [_]bool{false} ** max_players,

    pub fn input(self: RollbackFrame, slot_index: usize) packed_input.PackedPlayerInput {
        return self.frame_inputs[slot_index];
    }

    pub fn predicted(self: RollbackFrame, slot_index: usize) bool {
        return self.predicted_slots[slot_index];
    }
};

const EmittedFrame = struct {
    inputs: [max_players]packed_input.PackedPlayerInput = [_]packed_input.PackedPlayerInput{.{}} ** max_players,
};

pub const Options = struct {
    player_count: i32,
    local_slot_index: i32,
    input_delay_ticks: i32 = 1,
    max_rollback_ticks: i32 = 8,
    max_sent_history_ticks: i32 = max_sent_history_ticks_default,
    max_resend_samples: usize = max_resend_samples_default,
};

pub const RollbackController = struct {
    allocator: std.mem.Allocator,
    player_count: usize,
    local_slot_index: usize,
    input_delay_ticks: i32,
    max_rollback_ticks: i32,
    max_sent_history_ticks: i32,
    max_resend_samples: usize,

    capture_tick: i32 = 0,
    next_emit_tick: i32 = 0,
    known_by_slot: [max_players]std.AutoHashMap(i32, packed_input.PackedPlayerInput),
    emitted_frames: std.AutoHashMap(i32, EmittedFrame),
    pending_frames: std.ArrayList(RollbackFrame) = .empty,
    pending_rollback_from: ?i32 = null,
    pending_resync_from: ?i32 = null,

    rollback_count: i32 = 0,
    prediction_mismatches: i32 = 0,
    max_rollback_distance: i32 = 0,

    pub fn init(allocator: std.mem.Allocator, options: Options) RollbackController {
        const players: usize = @intCast(std.math.clamp(options.player_count, @as(i32, 1), @as(i32, max_players)));
        const local_slot: usize = @intCast(std.math.clamp(options.local_slot_index, @as(i32, 0), @as(i32, @intCast(players - 1))));
        return .{
            .allocator = allocator,
            .player_count = players,
            .local_slot_index = local_slot,
            .input_delay_ticks = @max(0, options.input_delay_ticks),
            .max_rollback_ticks = @max(1, options.max_rollback_ticks),
            .max_sent_history_ticks = @max(1, options.max_sent_history_ticks),
            .max_resend_samples = @max(@as(usize, 1), options.max_resend_samples),
            .known_by_slot = initKnownMaps(allocator),
            .emitted_frames = std.AutoHashMap(i32, EmittedFrame).init(allocator),
        };
    }

    pub fn deinit(self: *RollbackController) void {
        for (&self.known_by_slot) |*map| map.deinit();
        self.emitted_frames.deinit();
        self.pending_frames.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn queueLocalInput(self: *RollbackController, input: packed_input.PackedPlayerInput) !relay_protocol.RbInputBatch {
        const target_tick = self.capture_tick + self.input_delay_ticks;
        var local_known = &self.known_by_slot[self.local_slot_index];
        try local_known.put(target_tick, input);

        const oldest = @max(self.next_emit_tick, target_tick - self.max_sent_history_ticks + 1);
        var samples: std.ArrayList(relay_protocol.RbInputSample) = .empty;
        errdefer samples.deinit(self.allocator);

        var tick = target_tick;
        while (tick >= oldest) : (tick -= 1) {
            if (local_known.get(tick)) |known| {
                try samples.append(self.allocator, .{ .tick_index = tick, .packed_input = known });
                if (samples.items.len >= self.max_resend_samples) break;
            }
            if (tick == std.math.minInt(i32)) break;
        }

        try self.pruneLocalKnown(local_known, oldest, target_tick);
        self.capture_tick += 1;
        try self.emitReadyFrames();

        return .{
            .slot_index = @intCast(self.local_slot_index),
            .samples = try samples.toOwnedSlice(self.allocator),
        };
    }

    pub fn deinitInputBatch(self: *RollbackController, batch: *relay_protocol.RbInputBatch) void {
        self.allocator.free(batch.samples);
        batch.* = .{};
    }

    pub fn ingestRemoteSamples(self: *RollbackController, slot_index_raw: i32, samples: []const relay_protocol.RbInputSample) !void {
        if (slot_index_raw < 0) return;
        const slot_index: usize = @intCast(slot_index_raw);
        if (slot_index >= self.player_count or slot_index == self.local_slot_index) return;

        var known = &self.known_by_slot[slot_index];
        for (samples) |sample| {
            const tick = sample.tick_index;
            if (tick < 0) continue;
            const prev = known.get(tick);
            try known.put(tick, sample.packed_input);
            if (prev) |old| {
                if (packed_input.eql(old, sample.packed_input)) continue;
            }
            self.noteLateMismatch(slot_index, tick, sample.packed_input);
        }
        try self.emitReadyFrames();
    }

    pub fn popFrame(self: *RollbackController) ?RollbackFrame {
        if (self.pending_frames.items.len == 0) return null;
        return self.pending_frames.orderedRemove(0);
    }

    pub fn drainRollbackFrom(self: *RollbackController) ?i32 {
        const value = self.pending_rollback_from;
        self.pending_rollback_from = null;
        return value;
    }

    pub fn drainResyncFrom(self: *RollbackController) ?i32 {
        const value = self.pending_resync_from;
        self.pending_resync_from = null;
        return value;
    }

    pub fn rebuildEmittedFrom(self: *RollbackController, from_tick_raw: i32) ![]RollbackFrame {
        const start = @max(0, from_tick_raw);
        if (start >= self.next_emit_tick) return self.allocator.alloc(RollbackFrame, 0);

        var rebuilt: std.ArrayList(RollbackFrame) = .empty;
        errdefer rebuilt.deinit(self.allocator);

        var tick = start;
        while (tick < self.next_emit_tick) : (tick += 1) {
            const frame = self.buildFrame(tick);
            try self.emitted_frames.put(tick, .{ .inputs = frame.frame_inputs });
            try rebuilt.append(self.allocator, frame);
        }
        return rebuilt.toOwnedSlice(self.allocator);
    }

    pub fn resetToTick(self: *RollbackController, tick_index: i32) !void {
        const target = @max(0, tick_index);
        self.capture_tick = target;
        self.next_emit_tick = target;
        self.pending_frames.clearRetainingCapacity();
        self.pending_rollback_from = null;
        self.pending_resync_from = null;
        for (&self.known_by_slot) |*map| {
            try pruneBefore(self.allocator, map, target);
        }
        try pruneBefore(self.allocator, &self.emitted_frames, target);
    }

    pub fn primeInitialDelay(self: *RollbackController) !void {
        var tick: i32 = 0;
        while (tick < self.input_delay_ticks) : (tick += 1) {
            for (0..self.player_count) |slot| {
                try self.known_by_slot[slot].put(tick, packed_input.neutral);
            }
        }
        try self.emitReadyFrames();
    }

    fn emitReadyFrames(self: *RollbackController) !void {
        const local_known = &self.known_by_slot[self.local_slot_index];
        while (local_known.contains(self.next_emit_tick)) {
            const tick = self.next_emit_tick;
            const frame = self.buildFrame(tick);
            try self.pending_frames.append(self.allocator, frame);
            try self.emitted_frames.put(tick, .{ .inputs = frame.frame_inputs });
            self.next_emit_tick += 1;
            try self.pruneEmitted();
        }
    }

    fn buildFrame(self: *RollbackController, tick: i32) RollbackFrame {
        var frame: RollbackFrame = .{ .tick_index = tick, .player_count = self.player_count };
        for (0..self.player_count) |slot| {
            if (self.knownForTick(slot, tick)) |known| {
                frame.frame_inputs[slot] = known;
            } else {
                frame.predicted_slots[slot] = true;
                frame.frame_inputs[slot] = self.predictForTick(slot, tick);
            }
        }
        return frame;
    }

    fn knownForTick(self: *RollbackController, slot_index: usize, tick: i32) ?packed_input.PackedPlayerInput {
        return self.known_by_slot[slot_index].get(tick);
    }

    fn predictForTick(self: *RollbackController, slot_index: usize, tick: i32) packed_input.PackedPlayerInput {
        var back = tick - 1;
        while (back >= 0) : (back -= 1) {
            if (self.known_by_slot[slot_index].get(back)) |known| return known;
            if (back == 0) break;
        }
        return packed_input.neutral;
    }

    fn noteLateMismatch(self: *RollbackController, slot_index: usize, tick: i32, incoming: packed_input.PackedPlayerInput) void {
        const emitted = self.emitted_frames.get(tick) orelse return;
        if (slot_index >= self.player_count) return;
        if (packed_input.eql(emitted.inputs[slot_index], incoming)) return;

        self.prediction_mismatches += 1;
        const distance = @max(0, self.next_emit_tick - tick);
        self.max_rollback_distance = @max(self.max_rollback_distance, distance);

        if (distance > self.max_rollback_ticks) {
            self.pending_resync_from = minOptionalTick(self.pending_resync_from, tick);
            return;
        }

        self.rollback_count += 1;
        self.pending_rollback_from = minOptionalTick(self.pending_rollback_from, tick);
    }

    fn pruneLocalKnown(self: *RollbackController, local_known: *std.AutoHashMap(i32, packed_input.PackedPlayerInput), oldest: i32, target_tick: i32) !void {
        var remove_keys: std.ArrayList(i32) = .empty;
        defer remove_keys.deinit(self.allocator);

        var iter = local_known.keyIterator();
        while (iter.next()) |key| {
            if (key.* < oldest or key.* > target_tick) try remove_keys.append(self.allocator, key.*);
        }
        for (remove_keys.items) |key| _ = local_known.remove(key);
    }

    fn pruneEmitted(self: *RollbackController) !void {
        const keep_from = self.next_emit_tick - @max(1, self.max_rollback_ticks) - 2;
        try pruneBefore(self.allocator, &self.emitted_frames, keep_from);
    }
};

fn initKnownMaps(allocator: std.mem.Allocator) [max_players]std.AutoHashMap(i32, packed_input.PackedPlayerInput) {
    var maps: [max_players]std.AutoHashMap(i32, packed_input.PackedPlayerInput) = undefined;
    for (&maps) |*map| {
        map.* = std.AutoHashMap(i32, packed_input.PackedPlayerInput).init(allocator);
    }
    return maps;
}

fn minOptionalTick(current: ?i32, tick: i32) i32 {
    return if (current) |value| @min(value, tick) else tick;
}

fn pruneBefore(allocator: std.mem.Allocator, map: anytype, tick_index: i32) !void {
    var remove_keys: std.ArrayList(i32) = .empty;
    defer remove_keys.deinit(allocator);

    var iter = map.keyIterator();
    while (iter.next()) |key| {
        if (key.* < tick_index) try remove_keys.append(allocator, key.*);
    }
    for (remove_keys.items) |key| _ = map.remove(key);
}

test "rollback prediction uses neutral input for missing remote inputs" {
    var controller = RollbackController.init(std.testing.allocator, .{
        .player_count = 2,
        .local_slot_index = 0,
        .input_delay_ticks = 0,
        .max_rollback_ticks = 8,
    });
    defer controller.deinit();

    var batch = try controller.queueLocalInput(.{ .move_x = 1.0, .flags = 1 });
    defer controller.deinitInputBatch(&batch);
    const frame = controller.popFrame() orelse return error.TestExpectedEqual;

    try std.testing.expectEqual(@as(i32, 0), frame.tick_index);
    try std.testing.expect(frame.predicted(1));
    try std.testing.expectEqual(@as(u32, 1), frame.input(0).flags);
    try std.testing.expect(packed_input.eql(packed_input.neutral, frame.input(1)));
}

test "rollback prediction mismatch requests rollback within cap" {
    var controller = RollbackController.init(std.testing.allocator, .{
        .player_count = 2,
        .local_slot_index = 0,
        .input_delay_ticks = 0,
        .max_rollback_ticks = 8,
    });
    defer controller.deinit();

    var batch = try controller.queueLocalInput(.{ .flags = 1 });
    defer controller.deinitInputBatch(&batch);
    try std.testing.expect(controller.popFrame() != null);

    const samples = [_]relay_protocol.RbInputSample{.{ .tick_index = 0, .packed_input = .{ .move_x = 1.0, .flags = 9 } }};
    try controller.ingestRemoteSamples(1, &samples);

    try std.testing.expectEqual(@as(?i32, 0), controller.drainRollbackFrom());
    try std.testing.expectEqual(@as(?i32, null), controller.drainResyncFrom());
    try std.testing.expectEqual(@as(i32, 1), controller.rollback_count);
    try std.testing.expectEqual(@as(i32, 1), controller.prediction_mismatches);
}

test "rollback noop correction does not trigger rollback" {
    var controller = RollbackController.init(std.testing.allocator, .{
        .player_count = 2,
        .local_slot_index = 0,
        .input_delay_ticks = 0,
        .max_rollback_ticks = 8,
    });
    defer controller.deinit();

    var batch = try controller.queueLocalInput(.{ .flags = 1 });
    defer controller.deinitInputBatch(&batch);
    try std.testing.expect(controller.popFrame() != null);

    const samples = [_]relay_protocol.RbInputSample{.{ .tick_index = 0, .packed_input = packed_input.neutral }};
    try controller.ingestRemoteSamples(1, &samples);

    try std.testing.expectEqual(@as(?i32, null), controller.drainRollbackFrom());
    try std.testing.expectEqual(@as(?i32, null), controller.drainResyncFrom());
    try std.testing.expectEqual(@as(i32, 0), controller.rollback_count);
    try std.testing.expectEqual(@as(i32, 0), controller.prediction_mismatches);
}

test "rollback corrections older than cap trigger resync request" {
    var controller = RollbackController.init(std.testing.allocator, .{
        .player_count = 2,
        .local_slot_index = 0,
        .input_delay_ticks = 0,
        .max_rollback_ticks = 2,
    });
    defer controller.deinit();

    var tick: u32 = 0;
    while (tick < 6) : (tick += 1) {
        var batch = try controller.queueLocalInput(.{ .flags = tick });
        defer controller.deinitInputBatch(&batch);
        try std.testing.expect(controller.popFrame() != null);
    }

    const samples = [_]relay_protocol.RbInputSample{.{ .tick_index = 2, .packed_input = .{ .move_x = 1.0, .flags = 99 } }};
    try controller.ingestRemoteSamples(1, &samples);

    try std.testing.expectEqual(@as(?i32, null), controller.drainRollbackFrom());
    try std.testing.expectEqual(@as(?i32, 2), controller.drainResyncFrom());
    try std.testing.expectEqual(@as(i32, 0), controller.rollback_count);
    try std.testing.expectEqual(@as(i32, 1), controller.prediction_mismatches);
}

test "rollback controller reset rewinds emission cursor to snapshot tick" {
    var controller = RollbackController.init(std.testing.allocator, .{
        .player_count = 2,
        .local_slot_index = 0,
        .input_delay_ticks = 0,
        .max_rollback_ticks = 8,
    });
    defer controller.deinit();

    var tick: u32 = 0;
    while (tick < 5) : (tick += 1) {
        var batch = try controller.queueLocalInput(.{ .flags = tick + 1 });
        defer controller.deinitInputBatch(&batch);
        try std.testing.expect(controller.popFrame() != null);
    }

    try controller.resetToTick(2);
    try std.testing.expectEqual(@as(i32, 2), controller.capture_tick);
    try std.testing.expectEqual(@as(i32, 2), controller.next_emit_tick);
    try std.testing.expect(controller.popFrame() == null);
    try std.testing.expect(!controller.emitted_frames.contains(1));
    try std.testing.expect(controller.emitted_frames.contains(2));
}

test "rollback controller primes initial input delay with neutral frames" {
    var controller = RollbackController.init(std.testing.allocator, .{
        .player_count = 2,
        .local_slot_index = 0,
        .input_delay_ticks = 2,
        .max_rollback_ticks = 8,
    });
    defer controller.deinit();

    try controller.primeInitialDelay();

    const first = controller.popFrame() orelse return error.ExpectedFirstFrame;
    try std.testing.expectEqual(@as(i32, 0), first.tick_index);
    try std.testing.expect(!first.predicted(0));
    try std.testing.expect(!first.predicted(1));
    try std.testing.expect(packed_input.eql(packed_input.neutral, first.input(0)));
    try std.testing.expect(packed_input.eql(packed_input.neutral, first.input(1)));

    const second = controller.popFrame() orelse return error.ExpectedSecondFrame;
    try std.testing.expectEqual(@as(i32, 1), second.tick_index);
    try std.testing.expect(packed_input.eql(packed_input.neutral, second.input(0)));
    try std.testing.expect(packed_input.eql(packed_input.neutral, second.input(1)));
}
