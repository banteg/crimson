const std = @import("std");
const game_ids = @import("../game_ids.zig");
const replay_codec = @import("../replay_codec.zig");
const replay_runner = @import("replay_runner.zig");

const bonuses_mod = @import("bonuses.zig");
const player_runtime = @import("player.zig");
const replay_events = @import("replay/events.zig");
const runtime_session = @import("session.zig");
const session_builders = @import("session_builders.zig");
const replay_step = @import("replay/step.zig");
const state_mod = @import("state.zig");
const weapon_data = @import("weapon_data.zig");

const GameModeId = game_ids.GameModeId;
const PerkId = game_ids.PerkId;
const SimulationContext = runtime_session.DeterministicSession;
const epsilon: f32 = 1e-6;

pub const ReplayInfoError = replay_runner.ReplayRunnerError || error{
    OutOfMemory,
};

pub const CollectOptions = struct {
    max_ticks: ?usize = null,
    player_index: ?i32 = null,
    include_extra_events: bool = false,
};

pub const EventKind = enum {
    bonus_pickup,
    weapon_change,
    perk_pick,
    level_up,
    health_damage,
    health_heal,
    player_death,
    creature_deaths,
    perk_menu_open,
    typo_backspace,
    typo_char,
    typo_submit,
};

const BonusPickupData = struct {
    bonus_id: i32,
    bonus_name: []const u8,
    amount: i32,
    weapon_id: ?i32 = null,
    weapon_name: ?[]const u8 = null,

    fn jsonStringify(self: BonusPickupData, jws: anytype) !void {
        try jws.beginObject();
        try jws.objectField("bonus_id");
        try jws.write(self.bonus_id);
        try jws.objectField("bonus_name");
        try jws.write(self.bonus_name);
        try jws.objectField("amount");
        try jws.write(self.amount);
        if (self.weapon_id) |weapon_id| {
            try jws.objectField("weapon_id");
            try jws.write(weapon_id);
        }
        if (self.weapon_name) |weapon_name| {
            try jws.objectField("weapon_name");
            try jws.write(weapon_name);
        }
        try jws.endObject();
    }
};

const WeaponChangeData = struct {
    weapon_id_before: i32,
    weapon_name_before: []const u8,
    weapon_id_after: i32,
    weapon_name_after: []const u8,
};

const PerkPickData = struct {
    perk_id: i32,
    perk_name: []const u8,
    count_before: i32,
    count_after: i32,
};

const LevelUpData = struct {
    level_before: i32,
    level_after: i32,
    xp: i32,
};

const HealthDeltaData = struct {
    amount: f32,
    health_before: f32,
    health_after: f32,
};

const PlayerDeathData = struct {
    health_before: f32,
    health_after: f32,
};

const CreatureDeathsData = struct {
    count: i32,
};

const PerkMenuOpenData = struct {
    player_index: i32,
};

const TypoCharData = struct {
    player_index: i32,
    ch: u8,

    fn jsonStringify(self: TypoCharData, jws: anytype) !void {
        try jws.beginObject();
        try jws.objectField("player_index");
        try jws.write(self.player_index);
        try jws.objectField("ch");
        try jws.write(&[_]u8{self.ch});
        try jws.endObject();
    }
};

const TypoCommandData = struct {
    player_index: i32,
};

pub const EventData = union(enum) {
    bonus_pickup: BonusPickupData,
    weapon_change: WeaponChangeData,
    perk_pick: PerkPickData,
    level_up: LevelUpData,
    health_damage: HealthDeltaData,
    health_heal: HealthDeltaData,
    player_death: PlayerDeathData,
    creature_deaths: CreatureDeathsData,
    perk_menu_open: PerkMenuOpenData,
    typo_backspace: TypoCommandData,
    typo_char: TypoCharData,
    typo_submit: TypoCommandData,

    pub fn jsonStringify(self: EventData, jws: anytype) !void {
        switch (self) {
            .typo_char => |payload| try payload.jsonStringify(jws),
            inline else => |payload| try jws.write(payload),
        }
    }
};

pub const TimelineEvent = struct {
    tick_index: i32,
    elapsed_ms: i64,
    elapsed_s: f64,
    kind: EventKind,
    player_index: ?i32,
    detail: []u8,
    data: EventData,
};

pub const ReplayInfoResult = struct {
    game_mode_id: i32,
    tick_rate: i32,
    ticks_simulated: i32,
    elapsed_ms: i64,
    player_count: i32,
    timeline: []TimelineEvent,

    pub fn deinit(self: ReplayInfoResult, allocator: std.mem.Allocator) void {
        for (self.timeline) |event| {
            allocator.free(event.detail);
        }
        allocator.free(self.timeline);
    }
};

pub const EventCountsByKind = struct {
    counts: [@typeInfo(EventKind).@"enum".fields.len]usize = [_]usize{0} ** @typeInfo(EventKind).@"enum".fields.len,

    pub fn add(self: *EventCountsByKind, kind: EventKind) void {
        self.counts[@intFromEnum(kind)] += 1;
    }

    pub fn jsonStringify(self: EventCountsByKind, jws: anytype) !void {
        try jws.beginObject();
        for ([_]EventKind{
            .bonus_pickup,
            .creature_deaths,
            .health_damage,
            .health_heal,
            .level_up,
            .perk_menu_open,
            .typo_backspace,
            .typo_char,
            .typo_submit,
            .perk_pick,
            .player_death,
            .weapon_change,
        }) |kind| {
            const count = self.counts[@intFromEnum(kind)];
            if (count == 0) continue;
            try jws.objectField(@tagName(kind));
            try jws.write(count);
        }
        try jws.endObject();
    }
};

const PlayerSnapshot = struct {
    health: f32,
    level: i32,
    experience: i32,
    weapon_id: game_ids.WeaponId,
    perk_counts: [state_mod.perk_count_size]i32,
};

pub fn eventCountsByKind(timeline: []const TimelineEvent) EventCountsByKind {
    var counts: EventCountsByKind = .{};
    for (timeline) |event| counts.add(event.kind);
    return counts;
}

pub fn collect(
    allocator: std.mem.Allocator,
    replay: replay_codec.Replay,
    options: CollectOptions,
) ReplayInfoError!ReplayInfoResult {
    const header = replay.header;
    const game_mode = std.enums.fromInt(GameModeId, header.game_mode_id) orelse {
        return error.UnsupportedGameMode;
    };
    if (header.player_count <= 0 or header.player_count > state_mod.max_players) {
        return error.UnsupportedPlayerCount;
    }
    if (!std.mem.eql(u8, header.input_quantization, "f32")) {
        return error.UnsupportedInputQuantization;
    }
    if (replay.dt.len != replay.tickCount()) {
        return error.InvalidHeaderValue;
    }

    const events = replay.events;
    var context = session_builders.buildReplaySession(
        game_mode,
        header,
        events,
        .{
            .strict_events = true,
            .inter_tick_rand_draws = 0,
        },
    ) catch |err| switch (err) {
        error.InvalidPlayerCount => return error.UnsupportedPlayerCount,
        error.InvalidWorldSize => return error.InvalidHeaderValue,
        error.InvalidTickRate => return error.InvalidHeaderValue,
        error.UnsupportedGameMode => return error.UnsupportedGameMode,
        error.InvalidQuestSpawnTable => return error.InvalidQuestSpawnTable,
    };

    const ticks_to_simulate: usize = if (options.max_ticks) |max_ticks|
        @min(max_ticks, replay.tickCount())
    else
        replay.tickCount();

    var timeline: std.ArrayList(TimelineEvent) = .empty;
    defer timeline.deinit(allocator);

    for (0..ticks_to_simulate) |tick_index| {
        if (context.event_index < events.len and events[context.event_index].tickIndex() < tick_index) {
            return error.UnsupportedEventOrdering;
        }

        var before_snapshots: [state_mod.max_players]PlayerSnapshot = undefined;
        captureSnapshots(context.playersConst(), before_snapshots[0..]);
        const creature_kills_before = context.creatures.kill_count;

        const dt_tick = replay.dt[tick_index];
        const tick_event_start = context.event_index;
        var tick_event_end = tick_event_start;
        while (tick_event_end < events.len and events[tick_event_end].tickIndex() == tick_index) : (tick_event_end += 1) {}

        var tick_inputs_storage: [state_mod.max_players]player_runtime.GameInput = undefined;
        const replay_tick_inputs = replay.inputs[tick_index];
        const tick_input_len = @min(replay_tick_inputs.len, tick_inputs_storage.len);
        for (replay_tick_inputs[0..tick_input_len], 0..) |input, idx| {
            tick_inputs_storage[idx] = replay_runner.mapReplayInputToGameInput(input);
        }

        _ = try replay_step.stepTick(
            &context,
            tick_index,
            tick_inputs_storage[0..tick_input_len],
            events[tick_event_start..tick_event_end],
            dt_tick,
            .{},
        );

        const elapsed_ms = currentElapsedMs(&context);
        if (game_mode != .rush) {
            try appendExtraReplayCommands(
                allocator,
                &timeline,
                events[tick_event_start..tick_event_end],
                @intCast(tick_index),
                elapsed_ms,
                options.player_index,
                options.include_extra_events,
            );
        }
        try appendBonusPickupEvents(
            allocator,
            &timeline,
            context.tick_bonus_pickups.constSlice(),
            header.preserve_bugs,
            @intCast(tick_index),
            elapsed_ms,
            options.player_index,
        );
        if (options.include_extra_events) {
            const creature_deaths = context.creatures.kill_count - creature_kills_before;
            if (creature_deaths > 0) {
                const detail = try std.fmt.allocPrint(allocator, "creature deaths={d}", .{creature_deaths});
                errdefer allocator.free(detail);
                try timeline.append(allocator, makeEvent(
                    @intCast(tick_index),
                    elapsed_ms,
                    .creature_deaths,
                    null,
                    detail,
                    .{ .creature_deaths = .{ .count = creature_deaths } },
                ));
            }
        }

        var after_snapshots: [state_mod.max_players]PlayerSnapshot = undefined;
        captureSnapshots(context.playersConst(), after_snapshots[0..]);
        try appendSnapshotDiffEvents(
            allocator,
            &timeline,
            before_snapshots[0..context.playersConst().len],
            after_snapshots[0..context.playersConst().len],
            header.preserve_bugs,
            header.gore_disabled,
            @intCast(tick_index),
            elapsed_ms,
            options.player_index,
        );
    }

    if (ticks_to_simulate == replay.tickCount()) {
        const terminal_tick = replay.tickCount();
        if (context.event_index < events.len and events[context.event_index].tickIndex() < terminal_tick) {
            return error.UnsupportedEventOrdering;
        }
        var terminal_menu_open_seen = false;
        const dt_tick = if (replay.dt.len > 0) replay.dt[replay.dt.len - 1] else context.dt_nominal;
        const elapsed_ms = currentElapsedMs(&context);
        while (context.event_index < events.len and events[context.event_index].tickIndex() == terminal_tick) : (context.event_index += 1) {
            const event = events[context.event_index];
            if (game_mode != .rush) {
                try appendExtraReplayCommands(
                    allocator,
                    &timeline,
                    &.{event},
                    @intCast(terminal_tick),
                    elapsed_ms,
                    options.player_index,
                    options.include_extra_events,
                );
            }
            const outcome = try replay_events.applyReplayEvent(
                event,
                &context.state,
                context.players(),
                &context.creatures,
                dt_tick,
                &context.quest_spawn_timeline_ms,
                &context.quest_no_creatures_timer_ms,
                &context.quest_completion_transition_ms,
                .{
                    .game_mode = context.game_mode,
                    .player_count = context.player_count,
                    .quest_unlock_index = context.quest_unlock_index,
                    .strict_events = context.strict_events,
                    .menu_open_seen_this_tick = terminal_menu_open_seen,
                },
            );
            terminal_menu_open_seen = terminal_menu_open_seen or outcome.menu_open_seen_this_tick;
            context.perk_menu_open_count += outcome.perk_menu_open_count_delta;
            context.perk_pick_count += outcome.perk_pick_count_delta;
            if (outcome.signal == .request_capture_state_reset) {
                context.pending_capture_state_reset = true;
            }
        }
        if (context.event_index != events.len) return error.UnsupportedEventOrdering;
    }

    return .{
        .game_mode_id = header.game_mode_id,
        .tick_rate = header.tick_rate,
        .ticks_simulated = @intCast(ticks_to_simulate),
        .elapsed_ms = currentElapsedMs(&context),
        .player_count = @intCast(context.playersConst().len),
        .timeline = try timeline.toOwnedSlice(allocator),
    };
}

fn appendBonusPickupEvents(
    allocator: std.mem.Allocator,
    timeline: *std.ArrayList(TimelineEvent),
    pickups: []const bonuses_mod.BonusPickupRecord,
    preserve_bugs: bool,
    tick_index: i32,
    elapsed_ms: i64,
    player_filter: ?i32,
) ReplayInfoError!void {
    for (pickups) |pickup| {
        if (player_filter) |index| {
            if (pickup.player_index != index) continue;
        }
        const bonus_name = game_ids.bonusDisplayName(pickup.bonus_id, preserve_bugs);
        if (pickup.bonus_id == game_ids.BonusId.weapon) {
            const weapon_id = weapon_data.weaponIdFromInt(pickup.amount);
            const weapon_name = game_ids.weaponDisplayName(weapon_id, preserve_bugs);
            const detail = try std.fmt.allocPrint(
                allocator,
                "p{d} picked {s} ({d}) amount={d} -> {s}",
                .{ pickup.player_index, bonus_name, pickup.bonus_id, pickup.amount, weapon_name },
            );
            errdefer allocator.free(detail);
            try timeline.append(allocator, makeEvent(
                tick_index,
                elapsed_ms,
                .bonus_pickup,
                pickup.player_index,
                detail,
                .{ .bonus_pickup = .{
                    .bonus_id = @intFromEnum(pickup.bonus_id),
                    .bonus_name = bonus_name,
                    .amount = pickup.amount,
                    .weapon_id = @intFromEnum(weapon_id),
                    .weapon_name = weapon_name,
                } },
            ));
            continue;
        }

        const detail = try std.fmt.allocPrint(
            allocator,
            "p{d} picked {s} ({d}) amount={d}",
            .{ pickup.player_index, bonus_name, pickup.bonus_id, pickup.amount },
        );
        errdefer allocator.free(detail);
        try timeline.append(allocator, makeEvent(
            tick_index,
            elapsed_ms,
            .bonus_pickup,
            pickup.player_index,
            detail,
            .{ .bonus_pickup = .{
                .bonus_id = @intFromEnum(pickup.bonus_id),
                .bonus_name = bonus_name,
                .amount = pickup.amount,
            } },
        ));
    }
}

fn appendExtraReplayCommands(
    allocator: std.mem.Allocator,
    timeline: *std.ArrayList(TimelineEvent),
    tick_events: []const replay_codec.ReplayEvent,
    tick_index: i32,
    elapsed_ms: i64,
    player_filter: ?i32,
    include_extra_events: bool,
) ReplayInfoError!void {
    if (!include_extra_events) return;
    for (tick_events) |event| {
        switch (event) {
            .perk_menu_open => |open| {
                if (player_filter) |index| {
                    if (open.player_index != index) continue;
                }
                const detail = try std.fmt.allocPrint(
                    allocator,
                    "p{d} perk menu opened",
                    .{open.player_index},
                );
                errdefer allocator.free(detail);
                try timeline.append(allocator, makeEvent(
                    tick_index,
                    elapsed_ms,
                    .perk_menu_open,
                    open.player_index,
                    detail,
                    .{ .perk_menu_open = .{ .player_index = open.player_index } },
                ));
            },
            .typo_char => |command| {
                if (player_filter) |index| {
                    if (command.player_index != index) continue;
                }
                const detail = try std.fmt.allocPrint(
                    allocator,
                    "p{d} typed '{c}'",
                    .{ command.player_index, command.ch },
                );
                errdefer allocator.free(detail);
                try timeline.append(allocator, makeEvent(
                    tick_index,
                    elapsed_ms,
                    .typo_char,
                    command.player_index,
                    detail,
                    .{ .typo_char = .{ .player_index = command.player_index, .ch = command.ch } },
                ));
            },
            .typo_backspace => |command| {
                if (player_filter) |index| {
                    if (command.player_index != index) continue;
                }
                const detail = try std.fmt.allocPrint(
                    allocator,
                    "p{d} typo backspace",
                    .{command.player_index},
                );
                errdefer allocator.free(detail);
                try timeline.append(allocator, makeEvent(
                    tick_index,
                    elapsed_ms,
                    .typo_backspace,
                    command.player_index,
                    detail,
                    .{ .typo_backspace = .{ .player_index = command.player_index } },
                ));
            },
            .typo_submit => |command| {
                if (player_filter) |index| {
                    if (command.player_index != index) continue;
                }
                const detail = try std.fmt.allocPrint(
                    allocator,
                    "p{d} typo submit",
                    .{command.player_index},
                );
                errdefer allocator.free(detail);
                try timeline.append(allocator, makeEvent(
                    tick_index,
                    elapsed_ms,
                    .typo_submit,
                    command.player_index,
                    detail,
                    .{ .typo_submit = .{ .player_index = command.player_index } },
                ));
            },
            else => {},
        }
    }
}

fn appendSnapshotDiffEvents(
    allocator: std.mem.Allocator,
    timeline: *std.ArrayList(TimelineEvent),
    before: []const PlayerSnapshot,
    after: []const PlayerSnapshot,
    preserve_bugs: bool,
    violence_disabled: i32,
    tick_index: i32,
    elapsed_ms: i64,
    player_filter: ?i32,
) ReplayInfoError!void {
    const players_len = @min(before.len, after.len);
    for (0..players_len) |idx| {
        const player_index: i32 = @intCast(idx);
        if (player_filter) |filter| {
            if (player_index != filter) continue;
        }
        const pre = before[idx];
        const post = after[idx];

        if (pre.weapon_id != post.weapon_id) {
            const weapon_before_name = game_ids.weaponDisplayName(pre.weapon_id, preserve_bugs);
            const weapon_after_name = game_ids.weaponDisplayName(post.weapon_id, preserve_bugs);
            const detail = try std.fmt.allocPrint(
                allocator,
                "p{d} weapon {s} -> {s}",
                .{ player_index, weapon_before_name, weapon_after_name },
            );
            errdefer allocator.free(detail);
            try timeline.append(allocator, makeEvent(
                tick_index,
                elapsed_ms,
                .weapon_change,
                player_index,
                detail,
                .{ .weapon_change = .{
                    .weapon_id_before = @intFromEnum(pre.weapon_id),
                    .weapon_name_before = weapon_before_name,
                    .weapon_id_after = @intFromEnum(post.weapon_id),
                    .weapon_name_after = weapon_after_name,
                } },
            ));
        }

        if (post.level > pre.level) {
            const detail = try std.fmt.allocPrint(
                allocator,
                "p{d} level {d} -> {d} (xp={d})",
                .{ player_index, pre.level, post.level, post.experience },
            );
            errdefer allocator.free(detail);
            try timeline.append(allocator, makeEvent(
                tick_index,
                elapsed_ms,
                .level_up,
                player_index,
                detail,
                .{ .level_up = .{
                    .level_before = pre.level,
                    .level_after = post.level,
                    .xp = post.experience,
                } },
            ));
        }

        for (0..state_mod.perk_count_size) |perk_index| {
            const perk_id: PerkId = @enumFromInt(perk_index);
            const before_count = pre.perk_counts[perk_index];
            const after_count = post.perk_counts[perk_index];
            if (after_count <= before_count) continue;
            const perk_name = game_ids.perkDisplayName(perk_id, violence_disabled, preserve_bugs);
            const detail = try std.fmt.allocPrint(
                allocator,
                "p{d} perk {s} ({d}) x{d}",
                .{ player_index, perk_name, @intFromEnum(perk_id), after_count },
            );
            errdefer allocator.free(detail);
            try timeline.append(allocator, makeEvent(
                tick_index,
                elapsed_ms,
                .perk_pick,
                player_index,
                detail,
                .{ .perk_pick = .{
                    .perk_id = @intFromEnum(perk_id),
                    .perk_name = perk_name,
                    .count_before = before_count,
                    .count_after = after_count,
                } },
            ));
        }

        if (post.health < pre.health - epsilon) {
            const amount = pre.health - post.health;
            const detail = try std.fmt.allocPrint(
                allocator,
                "p{d} damage {d:.6} (health {d:.6}->{d:.6})",
                .{ player_index, amount, pre.health, post.health },
            );
            errdefer allocator.free(detail);
            try timeline.append(allocator, makeEvent(
                tick_index,
                elapsed_ms,
                .health_damage,
                player_index,
                detail,
                .{ .health_damage = .{
                    .amount = amount,
                    .health_before = pre.health,
                    .health_after = post.health,
                } },
            ));
        } else if (post.health > pre.health + epsilon) {
            const amount = post.health - pre.health;
            const detail = try std.fmt.allocPrint(
                allocator,
                "p{d} heal {d:.6} (health {d:.6}->{d:.6})",
                .{ player_index, amount, pre.health, post.health },
            );
            errdefer allocator.free(detail);
            try timeline.append(allocator, makeEvent(
                tick_index,
                elapsed_ms,
                .health_heal,
                player_index,
                detail,
                .{ .health_heal = .{
                    .amount = amount,
                    .health_before = pre.health,
                    .health_after = post.health,
                } },
            ));
        }

        if (pre.health > 0.0 and post.health <= 0.0) {
            const detail = try std.fmt.allocPrint(
                allocator,
                "p{d} died (health {d:.6}->{d:.6})",
                .{ player_index, pre.health, post.health },
            );
            errdefer allocator.free(detail);
            try timeline.append(allocator, makeEvent(
                tick_index,
                elapsed_ms,
                .player_death,
                player_index,
                detail,
                .{ .player_death = .{
                    .health_before = pre.health,
                    .health_after = post.health,
                } },
            ));
        }
    }
}

fn captureSnapshots(players: []const state_mod.PlayerState, out: []PlayerSnapshot) void {
    for (players, 0..) |player, idx| {
        var snapshot: PlayerSnapshot = .{
            .health = player.health,
            .level = player.level,
            .experience = player.experience,
            .weapon_id = player.weapon.weapon_id,
            .perk_counts = [_]i32{0} ** state_mod.perk_count_size,
        };
        for (0..state_mod.perk_count_size) |perk_index| {
            const perk_id: PerkId = @enumFromInt(perk_index);
            snapshot.perk_counts[perk_index] = player.perk_counts.get(perk_id);
        }
        out[idx] = snapshot;
    }
}

fn currentElapsedMs(context: *const SimulationContext) i64 {
    return switch (context.game_mode) {
        .quests => @intFromFloat(context.quest_spawn_timeline_ms),
        .rush => context.elapsed_ms_sim_rush,
        else => @intFromFloat(context.elapsed_ms_sim),
    };
}

fn makeEvent(
    tick_index: i32,
    elapsed_ms: i64,
    kind: EventKind,
    player_index: ?i32,
    detail: []u8,
    data: EventData,
) TimelineEvent {
    return .{
        .tick_index = tick_index,
        .elapsed_ms = elapsed_ms,
        .elapsed_s = @as(f64, @floatFromInt(elapsed_ms)) / 1000.0,
        .kind = kind,
        .player_index = player_index,
        .detail = detail,
        .data = data,
    };
}
