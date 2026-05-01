const std = @import("std");

const lockstep_protocol = @import("lockstep_protocol.zig");
const packed_input = @import("packed_input.zig");

pub const client_max_capture_lead_ticks: i32 = 1;
pub const client_max_resend_samples: i32 = 64;
pub const client_max_sent_history_ticks: i32 = 256;

const max_players: usize = @intCast(lockstep_protocol.max_players);

pub const HostReadyTick = struct {
    tick_index: i32 = 0,
    frame_inputs: []packed_input.PackedPlayerInput = &.{},

    pub fn deinit(self: *HostReadyTick, allocator: std.mem.Allocator) void {
        allocator.free(self.frame_inputs);
        self.* = undefined;
    }
};

pub fn deinitHostReadyTicks(allocator: std.mem.Allocator, frames: *std.ArrayList(HostReadyTick)) void {
    for (frames.items) |*frame| frame.deinit(allocator);
    frames.deinit(allocator);
}

pub const HostLockstepState = struct {
    player_count: i32,
    input_delay_ticks: i32 = lockstep_protocol.input_delay_ticks,
    input_stall_timeout_ms: i32 = lockstep_protocol.input_stall_timeout_ms,
    inputs_by_tick: std.ArrayList(TickInputs) = .empty,
    next_emit_tick: i32 = 0,
    last_progress_ms: i64 = 0,
    paused: bool = false,

    pub fn deinit(self: *HostLockstepState, allocator: std.mem.Allocator) void {
        self.inputs_by_tick.deinit(allocator);
        self.* = undefined;
    }

    pub fn bufferedTickCount(self: HostLockstepState) usize {
        return self.inputs_by_tick.items.len;
    }

    pub fn waitingForInputs(self: HostLockstepState, tick_index: ?i32) i32 {
        const tick = tick_index orelse self.next_emit_tick;
        const tick_inputs = self.tickInputs(tick) orelse return clampedPlayerCount(self.player_count);
        return @max(0, clampedPlayerCount(self.player_count) - tick_inputs.count);
    }

    pub fn submitInputSample(
        self: *HostLockstepState,
        allocator: std.mem.Allocator,
        slot_index: i32,
        tick_index: i32,
        input: packed_input.PackedPlayerInput,
    ) !void {
        if (!validSlot(self.player_count, slot_index)) return;
        if (tick_index < self.next_emit_tick) return;

        const idx = try self.tickInputsIndexOrAppend(allocator, tick_index);
        self.inputs_by_tick.items[idx].put(slot_index, input);
    }

    pub fn submitInputBatch(
        self: *HostLockstepState,
        allocator: std.mem.Allocator,
        batch: lockstep_protocol.InputBatch,
    ) !void {
        for (batch.samples) |sample| {
            try self.submitInputSample(allocator, batch.slot_index, sample.tick_index, sample.packed_input);
        }
    }

    pub fn popReadyFrames(self: *HostLockstepState, allocator: std.mem.Allocator, now_ms: i64) !std.ArrayList(HostReadyTick) {
        var frames: std.ArrayList(HostReadyTick) = .empty;
        errdefer deinitHostReadyTicks(allocator, &frames);

        while (self.tickInputsIndex(self.next_emit_tick)) |idx| {
            if (!self.inputs_by_tick.items[idx].complete(self.player_count)) break;

            const tick_inputs = self.inputs_by_tick.orderedRemove(idx);
            const frame_inputs = try allocator.alloc(packed_input.PackedPlayerInput, @intCast(clampedPlayerCount(self.player_count)));
            errdefer allocator.free(frame_inputs);
            for (frame_inputs, 0..) |*input, slot| input.* = tick_inputs.inputs[slot];

            try frames.append(allocator, .{
                .tick_index = self.next_emit_tick,
                .frame_inputs = frame_inputs,
            });
            self.next_emit_tick += 1;
            self.last_progress_ms = now_ms;
        }

        return frames;
    }

    pub fn updatePauseState(self: *HostLockstepState, now_ms: i64) ?lockstep_protocol.PauseState {
        const should_pause = self.waitingForInputs(null) > 0 and
            now_ms - self.last_progress_ms >= self.input_stall_timeout_ms;
        if (should_pause == self.paused) return null;
        self.paused = should_pause;
        return if (should_pause)
            .{ .paused = true, .reason = "waiting_input" }
        else
            .{ .paused = false, .reason = "" };
    }

    fn tickInputs(self: HostLockstepState, tick_index: i32) ?TickInputs {
        const idx = self.tickInputsIndex(tick_index) orelse return null;
        return self.inputs_by_tick.items[idx];
    }

    fn tickInputsIndex(self: HostLockstepState, tick_index: i32) ?usize {
        for (self.inputs_by_tick.items, 0..) |item, idx| {
            if (item.tick_index == tick_index) return idx;
        }
        return null;
    }

    fn tickInputsIndexOrAppend(self: *HostLockstepState, allocator: std.mem.Allocator, tick_index: i32) !usize {
        if (self.tickInputsIndex(tick_index)) |idx| return idx;
        try self.inputs_by_tick.append(allocator, .{ .tick_index = tick_index });
        return self.inputs_by_tick.items.len - 1;
    }
};

pub const ClientLockstepState = struct {
    local_slot_index: i32,
    input_delay_ticks: i32 = lockstep_protocol.input_delay_ticks,
    input_stall_timeout_ms: i32 = lockstep_protocol.input_stall_timeout_ms,
    max_resend_samples: i32 = client_max_resend_samples,
    max_sent_history_ticks: i32 = client_max_sent_history_ticks,
    capture_tick: i32 = 0,
    sent_inputs: std.ArrayList(SentInput) = .empty,
    canonical_by_tick: std.ArrayList(OwnedTickFrame) = .empty,
    next_consume_tick: i32 = 0,
    last_progress_ms: i64 = 0,
    paused: bool = false,

    pub fn deinit(self: *ClientLockstepState, allocator: std.mem.Allocator) void {
        self.sent_inputs.deinit(allocator);
        for (self.canonical_by_tick.items) |*frame| frame.deinit(allocator);
        self.canonical_by_tick.deinit(allocator);
        self.* = undefined;
    }

    pub fn bufferedFrameCount(self: ClientLockstepState) usize {
        return self.canonical_by_tick.items.len;
    }

    pub fn queueLocalInput(
        self: *ClientLockstepState,
        allocator: std.mem.Allocator,
        input: packed_input.PackedPlayerInput,
    ) !lockstep_protocol.InputBatch {
        const max_capture_tick = self.next_consume_tick + client_max_capture_lead_ticks;
        if (self.capture_tick > max_capture_tick) self.capture_tick = max_capture_tick;

        const target_tick = self.capture_tick + self.input_delay_ticks;
        try self.storeSentInput(allocator, target_tick, input);

        var samples: std.ArrayList(lockstep_protocol.InputSample) = .empty;
        errdefer samples.deinit(allocator);

        var oldest_tick = @max(0, self.next_consume_tick);
        const history_ticks = self.max_sent_history_ticks;
        if (history_ticks > 0) oldest_tick = @max(oldest_tick, target_tick - history_ticks + 1);
        const max_samples = @max(1, self.max_resend_samples);

        var tick = target_tick;
        var sample_count: i32 = 0;
        while (tick >= oldest_tick) : (tick -= 1) {
            if (self.sentInput(tick)) |value| {
                try samples.append(allocator, .{ .tick_index = tick, .packed_input = value });
                sample_count += 1;
                if (sample_count >= max_samples) break;
            }
            if (tick == oldest_tick) break;
        }

        self.pruneSentInputs(oldest_tick, target_tick);
        self.capture_tick += 1;

        return .{
            .slot_index = self.local_slot_index,
            .samples = try samples.toOwnedSlice(allocator),
        };
    }

    pub fn ingestTickFrame(
        self: *ClientLockstepState,
        allocator: std.mem.Allocator,
        frame: lockstep_protocol.TickFrame,
        now_ms: i64,
    ) !void {
        if (self.canonicalFrameIndex(frame.tick_index)) |idx| {
            var removed = self.canonical_by_tick.orderedRemove(idx);
            removed.deinit(allocator);
        }
        try self.canonical_by_tick.append(allocator, try OwnedTickFrame.clone(allocator, frame));
        self.last_progress_ms = now_ms;
    }

    pub fn popCanonicalFrame(self: *ClientLockstepState) ?lockstep_protocol.TickFrame {
        const idx = self.canonicalFrameIndex(self.next_consume_tick) orelse return null;
        const frame = self.canonical_by_tick.orderedRemove(idx);
        self.next_consume_tick += 1;
        return frame.toTickFrame();
    }

    pub fn hasCanonicalFrame(self: ClientLockstepState) bool {
        return self.canonicalFrameIndex(self.next_consume_tick) != null;
    }

    pub fn updatePauseState(self: *ClientLockstepState, now_ms: i64) ?lockstep_protocol.PauseState {
        const should_pause = !self.hasCanonicalFrame() and
            now_ms - self.last_progress_ms >= self.input_stall_timeout_ms;
        if (should_pause == self.paused) return null;
        self.paused = should_pause;
        return if (should_pause)
            .{ .paused = true, .reason = "waiting_tick_frame" }
        else
            .{ .paused = false, .reason = "" };
    }

    fn storeSentInput(
        self: *ClientLockstepState,
        allocator: std.mem.Allocator,
        tick_index: i32,
        input: packed_input.PackedPlayerInput,
    ) !void {
        for (self.sent_inputs.items) |*item| {
            if (item.tick_index == tick_index) {
                item.input = input;
                return;
            }
        }
        try self.sent_inputs.append(allocator, .{ .tick_index = tick_index, .input = input });
    }

    fn sentInput(self: ClientLockstepState, tick_index: i32) ?packed_input.PackedPlayerInput {
        for (self.sent_inputs.items) |item| {
            if (item.tick_index == tick_index) return item.input;
        }
        return null;
    }

    fn pruneSentInputs(self: *ClientLockstepState, min_tick: i32, max_tick: i32) void {
        var idx: usize = 0;
        while (idx < self.sent_inputs.items.len) {
            const tick = self.sent_inputs.items[idx].tick_index;
            if (tick < min_tick or tick > max_tick) {
                _ = self.sent_inputs.orderedRemove(idx);
            } else {
                idx += 1;
            }
        }
    }

    fn canonicalFrameIndex(self: ClientLockstepState, tick_index: i32) ?usize {
        for (self.canonical_by_tick.items, 0..) |frame, idx| {
            if (frame.tick_index == tick_index) return idx;
        }
        return null;
    }
};

pub fn deinitInputBatch(allocator: std.mem.Allocator, batch: *lockstep_protocol.InputBatch) void {
    allocator.free(batch.samples);
    batch.* = undefined;
}

pub fn deinitTickFrame(allocator: std.mem.Allocator, frame: *lockstep_protocol.TickFrame) void {
    allocator.free(frame.frame_inputs);
    deinitCommands(allocator, frame.commands);
    frame.* = undefined;
}

const TickInputs = struct {
    tick_index: i32,
    inputs: [max_players]packed_input.PackedPlayerInput = [_]packed_input.PackedPlayerInput{.{}} ** max_players,
    present: [max_players]bool = [_]bool{false} ** max_players,
    count: i32 = 0,

    fn put(self: *TickInputs, slot_index: i32, input: packed_input.PackedPlayerInput) void {
        const slot: usize = @intCast(slot_index);
        if (!self.present[slot]) {
            self.present[slot] = true;
            self.count += 1;
        }
        self.inputs[slot] = input;
    }

    fn complete(self: TickInputs, player_count: i32) bool {
        const count = clampedPlayerCount(player_count);
        if (self.count < count) return false;
        var slot: usize = 0;
        while (slot < @as(usize, @intCast(count))) : (slot += 1) {
            if (!self.present[slot]) return false;
        }
        return true;
    }
};

const SentInput = struct {
    tick_index: i32,
    input: packed_input.PackedPlayerInput,
};

const OwnedTickFrame = struct {
    tick_index: i32,
    frame_inputs: []packed_input.PackedPlayerInput = &.{},
    commands: []lockstep_protocol.GameCommand = &.{},

    fn clone(allocator: std.mem.Allocator, frame: lockstep_protocol.TickFrame) !OwnedTickFrame {
        const frame_inputs = try allocator.dupe(packed_input.PackedPlayerInput, frame.frame_inputs);
        errdefer allocator.free(frame_inputs);

        const commands = try cloneCommands(allocator, frame.commands);
        errdefer deinitCommands(allocator, commands);

        return .{
            .tick_index = frame.tick_index,
            .frame_inputs = frame_inputs,
            .commands = commands,
        };
    }

    fn deinit(self: *OwnedTickFrame, allocator: std.mem.Allocator) void {
        allocator.free(self.frame_inputs);
        deinitCommands(allocator, self.commands);
        self.* = undefined;
    }

    fn toTickFrame(self: OwnedTickFrame) lockstep_protocol.TickFrame {
        return .{
            .tick_index = self.tick_index,
            .frame_inputs = self.frame_inputs,
            .commands = self.commands,
        };
    }
};

fn cloneCommands(allocator: std.mem.Allocator, commands: []const lockstep_protocol.GameCommand) ![]lockstep_protocol.GameCommand {
    const out = try allocator.alloc(lockstep_protocol.GameCommand, commands.len);
    var initialized: usize = 0;
    errdefer {
        for (out[0..initialized]) |command| deinitCommand(allocator, command);
        allocator.free(out);
    }
    for (commands, 0..) |command, idx| {
        out[idx] = try cloneCommand(allocator, command);
        initialized += 1;
    }
    return out;
}

fn cloneCommand(allocator: std.mem.Allocator, command: lockstep_protocol.GameCommand) !lockstep_protocol.GameCommand {
    return switch (command) {
        .perk_menu_open => |value| .{ .perk_menu_open = value },
        .perk_pick => |value| .{ .perk_pick = value },
        .typo_char => |value| .{ .typo_char = .{
            .player_index = value.player_index,
            .ch = try allocator.dupe(u8, value.ch),
        } },
        .typo_backspace => |value| .{ .typo_backspace = value },
        .typo_submit => |value| .{ .typo_submit = value },
    };
}

fn deinitCommands(allocator: std.mem.Allocator, commands: []const lockstep_protocol.GameCommand) void {
    for (commands) |command| deinitCommand(allocator, command);
    allocator.free(commands);
}

fn deinitCommand(allocator: std.mem.Allocator, command: lockstep_protocol.GameCommand) void {
    switch (command) {
        .typo_char => |value| allocator.free(value.ch),
        else => {},
    }
}

fn validSlot(player_count: i32, slot_index: i32) bool {
    return slot_index >= 0 and slot_index < clampedPlayerCount(player_count);
}

fn clampedPlayerCount(player_count: i32) i32 {
    return std.math.clamp(player_count, @as(i32, 1), lockstep_protocol.max_players);
}

test "lockstep host state waits for complete tick and emits ordered frame" {
    const allocator = std.testing.allocator;
    var state: HostLockstepState = .{ .player_count = 2 };
    defer state.deinit(allocator);

    try std.testing.expectEqual(@as(i32, 2), state.waitingForInputs(null));
    try state.submitInputSample(allocator, 1, 0, .{ .flags = 10 });
    try std.testing.expectEqual(@as(i32, 1), state.waitingForInputs(null));

    var empty = try state.popReadyFrames(allocator, 100);
    defer deinitHostReadyTicks(allocator, &empty);
    try std.testing.expectEqual(@as(usize, 0), empty.items.len);

    try state.submitInputSample(allocator, 0, 0, .{ .flags = 3 });
    var frames = try state.popReadyFrames(allocator, 120);
    defer deinitHostReadyTicks(allocator, &frames);
    try std.testing.expectEqual(@as(usize, 1), frames.items.len);
    try std.testing.expectEqual(@as(i32, 0), frames.items[0].tick_index);
    try std.testing.expectEqual(@as(u32, 3), frames.items[0].frame_inputs[0].flags);
    try std.testing.expectEqual(@as(u32, 10), frames.items[0].frame_inputs[1].flags);
    try std.testing.expectEqual(@as(i32, 1), state.next_emit_tick);
    try std.testing.expectEqual(@as(i64, 120), state.last_progress_ms);

    try state.submitInputSample(allocator, 0, 0, .{ .flags = 99 });
    try std.testing.expectEqual(@as(usize, 0), state.bufferedTickCount());
}

test "lockstep host state ingests batches and toggles pause on stalls" {
    const allocator = std.testing.allocator;
    var state: HostLockstepState = .{ .player_count = 2, .input_stall_timeout_ms = 50 };
    defer state.deinit(allocator);

    const samples = [_]lockstep_protocol.InputSample{
        .{ .tick_index = 0, .packed_input = .{ .flags = 1 } },
        .{ .tick_index = 1, .packed_input = .{ .flags = 2 } },
    };
    try state.submitInputBatch(allocator, .{ .slot_index = 0, .samples = samples[0..] });
    try std.testing.expectEqual(@as(i32, 1), state.waitingForInputs(null));

    const paused = state.updatePauseState(50).?;
    try std.testing.expect(paused.paused);
    try std.testing.expectEqualStrings("waiting_input", paused.reason);

    try state.submitInputSample(allocator, 1, 0, .{ .flags = 7 });
    var frames = try state.popReadyFrames(allocator, 75);
    defer deinitHostReadyTicks(allocator, &frames);
    try std.testing.expectEqual(@as(usize, 1), frames.items.len);

    const resumed = state.updatePauseState(75).?;
    try std.testing.expect(!resumed.paused);
}

test "lockstep client queues delayed input with bounded resend history" {
    const allocator = std.testing.allocator;
    var state: ClientLockstepState = .{
        .local_slot_index = 2,
        .input_delay_ticks = 1,
        .max_resend_samples = 2,
        .max_sent_history_ticks = 3,
    };
    defer state.deinit(allocator);

    var first = try state.queueLocalInput(allocator, .{ .flags = 10 });
    defer deinitInputBatch(allocator, &first);
    try std.testing.expectEqual(@as(i32, 2), first.slot_index);
    try std.testing.expectEqual(@as(usize, 1), first.samples.len);
    try std.testing.expectEqual(@as(i32, 1), first.samples[0].tick_index);

    var second = try state.queueLocalInput(allocator, .{ .flags = 11 });
    defer deinitInputBatch(allocator, &second);
    try std.testing.expectEqual(@as(usize, 2), second.samples.len);
    try std.testing.expectEqual(@as(i32, 2), second.samples[0].tick_index);
    try std.testing.expectEqual(@as(i32, 1), second.samples[1].tick_index);

    state.capture_tick = 99;
    var clamped = try state.queueLocalInput(allocator, .{ .flags = 12 });
    defer deinitInputBatch(allocator, &clamped);
    try std.testing.expectEqual(@as(i32, 2), state.capture_tick);
    try std.testing.expectEqual(@as(i32, 2), clamped.samples[0].tick_index);
}

test "lockstep client stores canonical frames and owns command payloads" {
    const allocator = std.testing.allocator;
    var state: ClientLockstepState = .{ .local_slot_index = 1, .input_stall_timeout_ms = 25 };
    defer state.deinit(allocator);

    const paused = state.updatePauseState(25).?;
    try std.testing.expect(paused.paused);

    const inputs = [_]packed_input.PackedPlayerInput{.{ .flags = 3 }};
    const commands = [_]lockstep_protocol.GameCommand{
        .{ .typo_char = .{ .player_index = 1, .ch = "a" } },
    };
    try state.ingestTickFrame(allocator, .{
        .tick_index = 0,
        .frame_inputs = inputs[0..],
        .commands = commands[0..],
    }, 40);
    try std.testing.expect(state.hasCanonicalFrame());
    try std.testing.expectEqual(@as(usize, 1), state.bufferedFrameCount());

    const resumed = state.updatePauseState(40).?;
    try std.testing.expect(!resumed.paused);

    var frame = state.popCanonicalFrame().?;
    defer deinitTickFrame(allocator, &frame);
    try std.testing.expectEqual(@as(i32, 0), frame.tick_index);
    try std.testing.expectEqual(@as(u32, 3), frame.frame_inputs[0].flags);
    switch (frame.commands[0]) {
        .typo_char => |value| try std.testing.expectEqualStrings("a", value.ch),
        else => return error.TestExpectedEqual,
    }
    try std.testing.expectEqual(@as(i32, 1), state.next_consume_tick);
    try std.testing.expect(!state.hasCanonicalFrame());
}
