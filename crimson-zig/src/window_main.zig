const std = @import("std");
const builtin = @import("builtin");
const rl = @import("raylib");

const cz = @import("crimson_zig");
const formats = cz.formats;
const persistence = cz.persistence;
const runtime_anim = cz.anim;
const weapon_data = cz.weapon_data;
const app_runtime = @import("app_runtime.zig");
const audio_mod = @import("audio/audio.zig");
const demo_trial = cz.demo_trial;
const input_codes = @import("input_codes.zig");
const local_input = cz.local_input;
const live_audio = @import("audio/live_audio.zig");
const quest_results = @import("quest_results.zig");
const rng_callers = cz.rng_caller_static;
const runtime_bootstrap = cz.bootstrap;
const runtime_paths = cz.runtime_paths;
const spawn_mod = cz.spawn;
const window_assets = @import("window_assets.zig");
const window_atlas = cz.window_atlas;
const window_boot = @import("window_boot.zig");
const window_cursor = @import("window_cursor.zig");
const window_demo_trial = @import("window_demo_trial.zig");
const window_effects = @import("window_effects.zig");
const window_ground = @import("window_ground.zig");
const window_menu = @import("window_menu.zig");
const window_menu_panels = @import("window_menu_panels.zig");
const window_misc_panels = @import("window_misc_panels.zig");
const window_options = @import("window_options.zig");
const window_pause_menu = @import("window_pause_menu.zig");
const window_perk_menu = @import("window_perk_menu.zig");
const window_projectiles = @import("window_projectiles.zig");
const window_statistics = @import("window_statistics.zig");
const window_terrain_fx = @import("window_terrain_fx.zig");
const window_ui = @import("window_ui.zig");
const window_viewport = @import("window_viewport.zig");

const bonuses_runtime = cz.bonuses;
const game_ids = cz.game_ids;
const live_runner = cz.live_runner;
const lockstep_input_adapter = cz.net.lockstep_input_adapter;
const lockstep_live_bridge = cz.net.lockstep_live_bridge;
const lockstep_live_session = cz.net.lockstep_live_session;
const lockstep_session = cz.net.lockstep_session;
const packed_input = cz.net.packed_input;
const relay_reliable = cz.net.relay_reliable;
const relay_protocol = cz.net.relay_protocol;
const relay_transport = cz.net.relay_transport;
const rollback_live_bridge = cz.net.rollback_live_bridge;
const rollback_live_session = cz.net.rollback_live_session;
const room_code = cz.net.room_code;
const runtime_perks = cz.perks;
const runtime_session = cz.session;
const state_mod = cz.state;
const terrain_fx_mod = cz.terrain_fx;
const tutorial_runtime = cz.tutorial_runtime;
const typo_names = cz.typo_names;
const ui_formatting = cz.ui_formatting;

const single_player_alt_move_codes = [_]i32{ 0xC8, 0xD0, 0xCB, 0xCD };
const final_quest_level_key: i32 = 510;
const window_width = 1024;
const window_height = 768;
const demo_attract_variant_count: i32 = 6;
const demo_attract_limit_ms: i32 = 4_000;
const demo_attract_purchase_screen_limit_ms: i32 = 16_000;
const demo_upsell_messages = [_][:0]const u8{
    "Want more Levels?",
    "Want more Weapons?",
    "Want more Perks?",
};
const demo_purchase_title = "Upgrade to the full version of Crimsonland Today!";
const demo_purchase_features_title = "Full version features:";
const demo_purchase_footer = "Purchasing the game is very easy and secure.";

const bg_color = rl.Color.init(16, 12, 10, 255);
const panel_color = rl.Color.init(37, 24, 20, 255);
const panel_outline = rl.Color.init(122, 78, 58, 255);
const accent_color = rl.Color.init(218, 80, 46, 255);
const accent_dim = rl.Color.init(127, 45, 29, 255);
const text_color = rl.Color.init(245, 236, 225, 255);
const muted_text = rl.Color.init(171, 150, 132, 255);
const player_color = rl.Color.init(255, 208, 84, 255);
const dead_player_color = rl.Color.init(90, 76, 72, 255);
const creature_color = rl.Color.init(219, 62, 62, 255);
const corpse_color = rl.Color.init(108, 45, 45, 255);
const projectile_color = rl.Color.init(255, 242, 115, 255);
const secondary_projectile_color = rl.Color.init(255, 146, 58, 255);
const bonus_color = rl.Color.init(88, 183, 113, 255);
const overlay_color = rl.Color.init(8, 6, 5, 208);

const Screen = enum {
    boot,
    main_menu,
    play_game_menu,
    quests_menu,
    statistics_menu,
    mods_menu,
    other_games_menu,
    network_session,
    gameplay,
    pause,
    results,
    end_note,
    options,
    controls,
};

const ResultsReason = enum {
    dead,
    completed,
    runtime_error,
    abandoned,
};

const DemoAttractPurchaseAction = enum {
    none,
    purchase,
    maybe_later,
};

const DemoAttractInactiveAction = enum {
    none,
    purchase,
    close,
};

const DemoPurchaseFeatureLine = struct {
    text: []const u8,
    delta_y: f32,
};

const DemoUpsellOverlayMetrics = struct {
    text: [:0]const u8,
    text_x: f32,
    text_y: f32,
    text_width: f32,
    bg_rect: rl.Rectangle,
    bar_rect: rl.Rectangle,
    text_alpha: u8,
    bg_alpha: u8,
    bar_alpha: u8,
};

const DemoPurchaseBackplasmaColors = struct {
    top_left: rl.Color,
    top_right: rl.Color,
    bottom_right: rl.Color,
    bottom_left: rl.Color,
};

const demo_purchase_feature_lines = [_]DemoPurchaseFeatureLine{
    .{ .text = "-Unlimited Play Time in three thrilling Game Modes!", .delta_y = 22.0 },
    .{ .text = "-The varied weapon arsenal consisting of over 20 unique", .delta_y = 17.0 },
    .{ .text = " weapons that allow you to deal death with plasma, lead,", .delta_y = 17.0 },
    .{ .text = " fire and electricity!", .delta_y = 22.0 },
    .{ .text = "-Over 40 game altering Perks!", .delta_y = 22.0 },
    .{ .text = "-40 insane Levels that give you", .delta_y = 18.0 },
    .{ .text = " hours of intense and fun gameplay!", .delta_y = 22.0 },
    .{ .text = "-The ability to post your high scores online!", .delta_y = 44.0 },
};

const AssetsState = enum {
    loaded,
    unavailable,
    failed,
};

const UiButton = window_ui.UiButton;
const BootSequenceState = window_boot.State;
const MenuScreenState = window_menu.State;

const GameplayScreen = struct {
    runner: live_runner.LiveRunner,
    run_config: live_runner.LiveModeConfig,
    last_update: live_runner.FrameUpdate,
    input_interpreter: local_input.LocalInputInterpreter = .{},
    perk_ui: window_perk_menu.State = .{},
    hud_state: HudRuntimeState = .{},
    ground: ?window_ground.GroundRenderer = null,
    camera: state_mod.Vec2 = .{ .x = -1.0, .y = -1.0 },
    render_time_s: f32 = 0.0,
    tutorial_prompt_selection: usize = 0,
    pending_terrain_fx: [16]terrain_fx_mod.TerrainFxBatch = [_]terrain_fx_mod.TerrainFxBatch{.{}} ** 16,
    pending_terrain_fx_count: usize = 0,
    pause_menu: window_pause_menu.State = .{},

    fn deinit(self: *GameplayScreen) void {
        if (self.ground) |*ground| {
            ground.deinit();
            self.ground = null;
        }
        self.* = undefined;
    }

    fn queueTerrainFxBatch(self: *GameplayScreen, batch: terrain_fx_mod.TerrainFxBatch) void {
        if (batch.isEmpty()) return;
        if (self.pending_terrain_fx_count < self.pending_terrain_fx.len) {
            self.pending_terrain_fx[self.pending_terrain_fx_count] = batch;
            self.pending_terrain_fx_count += 1;
            return;
        }
        var idx: usize = 1;
        while (idx < self.pending_terrain_fx.len) : (idx += 1) {
            self.pending_terrain_fx[idx - 1] = self.pending_terrain_fx[idx];
        }
        self.pending_terrain_fx[self.pending_terrain_fx.len - 1] = batch;
    }

    fn flushPendingTerrainFx(self: *GameplayScreen, assets: *const window_assets.RuntimeAssets) void {
        const ground = &(self.ground orelse return);
        if (!ground.renderTargetReady()) return;

        var kept: usize = 0;
        for (self.pending_terrain_fx[0..self.pending_terrain_fx_count]) |batch| {
            if (window_terrain_fx.bakeTerrainFxBatch(ground, &batch, assets)) continue;
            self.pending_terrain_fx[kept] = batch;
            kept += 1;
        }
        self.pending_terrain_fx_count = kept;
    }
};

const NetworkLiveRuntime = union(enum) {
    host: lockstep_live_session.HostLiveSession,
    client: lockstep_live_session.ClientLiveSession,
    rollback: rollback_live_session.LiveSession,

    fn init(request: window_misc_panels.NetworkLaunchRequest, seed: i32) !NetworkLiveRuntime {
        return switch (request.netcode) {
            .lockstep => switch (request.role) {
                .host => .{
                    .host = try lockstep_live_session.HostLiveSession.init(.{
                        .bind_host = request.bind_host,
                        .bind_port = request.port,
                        .mode_id = request.mode_id,
                        .player_count = request.player_count,
                        .build_id = cz.version,
                        .session_id = "window-lockstep",
                        .seed = seed,
                        .input_delay_ticks = 0,
                        .host_ready = true,
                        .pump_options = .{ .first_timeout_ms = 0 },
                    }),
                },
                .join => .{
                    .client = lockstep_live_session.ClientLiveSession.init(.{
                        .bind_host = "0.0.0.0",
                        .bind_port = 0,
                        .mode_id = request.mode_id,
                        .player_count = request.player_count,
                        .build_id = cz.version,
                        .host_addr = try parseNetworkPeerAddr(request.host, request.port),
                        .input_delay_ticks = 0,
                        .pump_options = .{ .first_timeout_ms = 0 },
                    }),
                },
            },
            .rollback => .{
                .rollback = rollback_live_session.LiveSession.init(.{
                    .server_addr = try parseRelayPeerAddr(request.host, request.port),
                    .bind_host = request.bind_host,
                    .session = .{
                        .role = switch (request.role) {
                            .host => .host,
                            .join => .join,
                        },
                        .mode_id = request.mode_id,
                        .player_count = request.player_count,
                        .build_id = cz.version,
                        .peer_name = "window",
                        .room_code = if (request.room_code_text) |code_text|
                            try cz.net.room_code.parseRoomCode(code_text)
                        else
                            null,
                        .input_delay_ticks = 0,
                    },
                }),
            },
        };
    }

    fn deinit(self: *NetworkLiveRuntime, allocator: std.mem.Allocator, io: std.Io) void {
        switch (self.*) {
            .host => |*host| host.deinit(allocator, io),
            .client => |*client| client.deinit(allocator, io),
            .rollback => |*rollback| rollback.deinit(allocator, io),
        }
        self.* = undefined;
    }

    fn open(self: *NetworkLiveRuntime, io: std.Io) !void {
        switch (self.*) {
            .host => |*host| try host.open(io),
            .client => |*client| try client.open(io),
            .rollback => |*rollback| try rollback.open(io),
        }
    }

    fn start(self: *NetworkLiveRuntime, allocator: std.mem.Allocator, io: std.Io, now_ms: i64) !void {
        try self.open(io);
        switch (self.*) {
            .host => {},
            .client => |*client| try client.sendHello(allocator, now_ms),
            .rollback => |*rollback| try rollback.update(allocator, io, now_ms),
        }
    }

    fn update(self: *NetworkLiveRuntime, allocator: std.mem.Allocator, io: std.Io, now_ms: i64) !NetworkLiveUpdate {
        return switch (self.*) {
            .host => |*host| blk: {
                const stats = try host.update(allocator, io, now_ms);
                const step_summary = if (host.session.runtime.started)
                    try host.stepReadyFrames(allocator, now_ms)
                else
                    lockstep_live_session.HostStepSummary{};
                break :blk .{
                    .stats = stats,
                    .frames_advanced = step_summary.frames_advanced,
                    .ticks_advanced = step_summary.ticks_advanced,
                    .last_tick_index = step_summary.last_tick_index,
                    .last_player_count = step_summary.last_player_count,
                    .last_input_flags = step_summary.last_input_flags,
                    .last_frame_update = step_summary.last_update,
                };
            },
            .client => |*client| blk: {
                const stats = try client.update(allocator, io, now_ms);
                if (client.runner == null) _ = try client.ensureLiveRunner();
                const step_summary = if (client.runner != null)
                    try client.stepCanonicalFrames(allocator)
                else
                    lockstep_live_session.ClientStepSummary{};
                break :blk .{
                    .stats = stats,
                    .frames_advanced = step_summary.frames_advanced,
                    .ticks_advanced = step_summary.ticks_advanced,
                    .last_tick_index = step_summary.last_tick_index,
                    .last_player_count = step_summary.last_player_count,
                    .last_input_flags = step_summary.last_input_flags,
                    .last_frame_update = step_summary.last_update,
                };
            },
            .rollback => |*rollback| blk: {
                try rollback.update(allocator, io, now_ms);
                const step_summary = if (rollback.hostRemoteInputsReady())
                    try rollback.stepFrames(allocator)
                else
                    rollback_live_session.StepSummary{};
                break :blk .{
                    .frames_advanced = step_summary.frames_advanced,
                    .ticks_advanced = step_summary.ticks_advanced,
                    .last_tick_index = step_summary.last_tick_index,
                    .last_player_count = step_summary.last_player_count,
                    .last_input_flags = step_summary.last_input_flags,
                    .last_frame_update = step_summary.last_update,
                };
            },
        };
    }

    fn submitLocalInput(self: *NetworkLiveRuntime, allocator: std.mem.Allocator, io: std.Io, input: packed_input.PackedPlayerInput, now_ms: i64) !void {
        switch (self.*) {
            .host => |*host| try host.submitLocalInput(allocator, input),
            .client => |*client| try client.queueLocalInput(allocator, input, now_ms),
            .rollback => |*rollback| try rollback.queueLocalInput(allocator, io, input, now_ms),
        }
    }

    fn hostRemoteInputsReady(self: *const NetworkLiveRuntime) bool {
        return switch (self.*) {
            .host, .client => true,
            .rollback => |*rollback| rollback.hostRemoteInputsReady(),
        };
    }

    fn submitLocalFrameInput(self: *NetworkLiveRuntime, allocator: std.mem.Allocator, io: std.Io, frame_input: live_runner.FrameInput, now_ms: i64) !bool {
        const slot = self.localInputSlot() orelse return false;
        if (frame_input.player_count != 0 and slot >= frame_input.player_count) return false;
        const local_input_value = if (frame_input.player_count == 0 and slot == 0)
            frame_input.player
        else
            frame_input.players[slot];
        try self.submitLocalInput(allocator, io, lockstep_input_adapter.packGameInput(local_input_value), now_ms);
        return true;
    }

    fn runnerForLocalInput(self: *NetworkLiveRuntime) ?*live_runner.LiveRunner {
        return switch (self.*) {
            .host => |*host| if (host.session.runtime.started and host.session.runtime.lockstep != null)
                &host.runner
            else
                null,
            .client => |*client| if (client.runner) |*runner| runner else null,
            .rollback => |*rollback| if (rollback.runner) |*runner| runner else null,
        };
    }

    fn runConfigForResults(self: *const NetworkLiveRuntime) ?live_runner.LiveModeConfig {
        return switch (self.*) {
            .host => |host| lockstep_live_bridge.liveConfigFromHostRuntime(host.session.runtime) catch null,
            .client => |client| blk: {
                const maybe_config = lockstep_live_bridge.liveConfigFromClientRuntime(client.session.runtime) orelse break :blk null;
                break :blk maybe_config catch null;
            },
            .rollback => |rollback| blk: {
                const match_config = rollback.session.match_config orelse break :blk null;
                break :blk rollback_live_bridge.liveConfigFromMatchConfig(match_config) catch null;
            },
        };
    }

    fn localInputSlot(self: *const NetworkLiveRuntime) ?usize {
        return switch (self.*) {
            .host => 0,
            .client => |client| blk: {
                const lockstep = client.session.runtime.lockstep orelse break :blk null;
                if (lockstep.local_slot_index < 0) break :blk null;
                const slot: usize = @intCast(lockstep.local_slot_index);
                if (slot >= state_mod.max_players) break :blk null;
                break :blk slot;
            },
            .rollback => |rollback| blk: {
                if (rollback.session.local_slot_index < 0) break :blk null;
                const slot: usize = @intCast(rollback.session.local_slot_index);
                if (slot >= state_mod.max_players) break :blk null;
                break :blk slot;
            },
        };
    }

    fn boundPort(self: *const NetworkLiveRuntime) u16 {
        return switch (self.*) {
            .host => |host| host.session.boundPort(),
            .client => |client| client.session.boundPort(),
            .rollback => |rollback| rollback.boundPort(),
        };
    }
};

fn parseNetworkPeerAddr(host: []const u8, port: u16) !lockstep_session.PeerAddr {
    var parts: [4]u8 = undefined;
    var iter = std.mem.splitScalar(u8, host, '.');
    var idx: usize = 0;
    while (iter.next()) |part| {
        if (idx >= parts.len or part.len == 0) return error.InvalidNetworkHost;
        parts[idx] = std.fmt.parseInt(u8, part, 10) catch return error.InvalidNetworkHost;
        idx += 1;
    }
    if (idx != parts.len) return error.InvalidNetworkHost;
    return .{ .host = parts, .port = port };
}

fn parseRelayPeerAddr(host: []const u8, port: u16) !relay_transport.PeerAddr {
    var parts: [4]u8 = undefined;
    var iter = std.mem.splitScalar(u8, host, '.');
    var idx: usize = 0;
    while (iter.next()) |part| {
        if (idx >= parts.len or part.len == 0) return error.InvalidNetworkHost;
        parts[idx] = std.fmt.parseInt(u8, part, 10) catch return error.InvalidNetworkHost;
        idx += 1;
    }
    if (idx != parts.len) return error.InvalidNetworkHost;
    return .{ .host = parts, .port = port };
}

const NetworkLiveUpdate = struct {
    stats: lockstep_session.UpdateStats = .{},
    frames_advanced: usize = 0,
    ticks_advanced: usize = 0,
    last_tick_index: ?i32 = null,
    last_player_count: usize = 0,
    last_input_flags: [state_mod.max_players]u32 = [_]u32{0} ** state_mod.max_players,
    last_frame_update: ?live_runner.FrameUpdate = null,
};

fn networkLiveTerminalReason(game_mode: game_ids.GameModeId, quest_completed: bool, all_players_dead: bool) ?ResultsReason {
    if (game_mode == .quests and quest_completed) return .completed;
    if (all_players_dead) return .dead;
    return null;
}

const BonusHudSlotState = struct {
    active: bool = false,
    bonus_id: game_ids.BonusId = .unused,
    icon_id: i32 = -1,
    slide_x: f32 = -184.0,
    timer_value: f32 = 0.0,
    timer_value_alt: f32 = 0.0,
};

const HudBonusSpec = struct {
    bonus_id: game_ids.BonusId,
    icon_id: i32,
    timer_value: f32,
    timer_value_alt: f32 = 0.0,
};

const HudRuntimeState = struct {
    survival_xp_smoothed: i32 = 0,
    bonus_slots: [16]BonusHudSlotState = [_]BonusHudSlotState{.{}} ** 16,

    fn smoothXp(self: *HudRuntimeState, target_raw: i32, frame_dt_ms_raw: f32) i32 {
        const target = @max(target_raw, 0);
        if (target == 0) {
            self.survival_xp_smoothed = 0;
            return 0;
        }

        var smoothed = self.survival_xp_smoothed;
        if (smoothed == target) return smoothed;

        const frame_dt_ms = @max(frame_dt_ms_raw, 0.0);
        var step = @max(@as(i32, 1), @divTrunc(@as(i32, @intFromFloat(frame_dt_ms)), 2));
        const diff: i32 = @intCast(@abs(smoothed - target));
        if (diff > 1000) {
            step *= @max(@as(i32, 1), @divTrunc(diff, 100));
        }

        if (smoothed < target) {
            smoothed += step;
            if (smoothed > target) smoothed = target;
        } else {
            smoothed -= step;
            if (smoothed < target) smoothed = target;
        }

        self.survival_xp_smoothed = smoothed;
        return smoothed;
    }

    fn update(self: *HudRuntimeState, frame_dt: f32, session: *const runtime_session.DeterministicSession) void {
        const xp_target = if (session.playersConst().len > 0) session.playersConst()[0].experience else 0;
        _ = self.smoothXp(xp_target, @max(frame_dt, 0.0) * 1000.0);

        var desired_specs: [16]HudBonusSpec = undefined;
        var desired_count: usize = 0;
        collectHudBonusSpecs(session, desired_specs[0..], &desired_count);

        var matched = [_]bool{false} ** 16;
        for (desired_specs[0..desired_count]) |spec| {
            var existing_index: ?usize = null;
            for (self.bonus_slots, 0..) |slot, idx| {
                if (slot.active and slot.bonus_id == spec.bonus_id) {
                    existing_index = idx;
                    break;
                }
            }
            const slot_index = existing_index orelse blk: {
                for (self.bonus_slots, 0..) |slot, idx| {
                    if (!slot.active) break :blk idx;
                }
                break :blk self.bonus_slots.len - 1;
            };
            var slot = &self.bonus_slots[slot_index];
            slot.active = true;
            slot.bonus_id = spec.bonus_id;
            slot.icon_id = spec.icon_id;
            slot.timer_value = spec.timer_value;
            slot.timer_value_alt = spec.timer_value_alt;
            slot.slide_x = @min(-2.0, slot.slide_x + @max(frame_dt, 0.0) * 350.0);
            matched[slot_index] = true;
        }

        for (&self.bonus_slots, 0..) |*slot, idx| {
            if (!slot.active or matched[idx]) continue;
            slot.timer_value = 0.0;
            slot.timer_value_alt = 0.0;
            slot.slide_x -= @max(frame_dt, 0.0) * 320.0;
            var later_active = false;
            for (self.bonus_slots[idx + 1 ..]) |other| {
                if (other.active) {
                    later_active = true;
                    break;
                }
            }
            if (slot.slide_x < -184.0 and !later_active) {
                slot.* = .{};
            }
        }
    }
};

const DemoAttractPurchaseState = struct {
    cursor_pulse_time: f32 = 0.0,
    selection: usize = 0,

    fn reset(self: *DemoAttractPurchaseState) void {
        self.* = .{};
    }
};

const ResultsScreen = struct {
    reason: ResultsReason,
    run_config: live_runner.LiveModeConfig,
    summary: runtime_session.SessionSummary,
    player_health_values: [state_mod.max_players]f32 = [_]f32{0.0} ** state_mod.max_players,
    player_health_count: usize = 0,
    runtime_error: ?[]const u8 = null,
    highscore: ?ResultsHighscoreState = null,
    score_too_low_for_top100: bool = false,
    quest_final_time: ?quest_results.QuestFinalTime = null,
    quest_breakdown_anim: quest_results.QuestResultsBreakdownAnim = .{},
    quest_unlock_weapon_name: ?[]const u8 = null,
    quest_unlock_perk_name: ?[]const u8 = null,
};

const ResultsHighscoreState = struct {
    record: persistence.highscores.HighScoreRecord,
    rank_index: usize,
    highlight_rank: ?usize = null,
    selection: usize = 0,
    save_error: ?[]const u8 = null,
    saved: bool = false,
    defer_name_input_until_controls_released: bool = true,
    input: [persistence.highscores.name_size]u8 = [_]u8{0} ** persistence.highscores.name_size,
    input_len: usize = 0,
    input_caret: usize = 0,

    fn setInput(self: *ResultsHighscoreState, value: []const u8) void {
        @memset(self.input[0..], 0);
        self.input_len = @min(value.len, persistence.highscores.name_max_edit);
        @memcpy(self.input[0..self.input_len], value[0..self.input_len]);
        self.input_caret = self.input_len;
    }

    fn inputSlice(self: *const ResultsHighscoreState) []const u8 {
        return self.input[0..self.input_len];
    }

    fn trimmedInputSlice(self: *const ResultsHighscoreState) []const u8 {
        var end = self.input_len;
        while (end > 0 and self.input[end - 1] == 0x20) : (end -= 1) {}
        return self.input[0..end];
    }

    fn insertChar(self: *ResultsHighscoreState, ch: u8) void {
        if (self.input_len >= persistence.highscores.name_max_edit) return;
        self.input_caret = @min(self.input_caret, self.input_len);
        var idx = self.input_len;
        while (idx > self.input_caret) : (idx -= 1) {
            self.input[idx] = self.input[idx - 1];
        }
        self.input[self.input_caret] = ch;
        self.input_len += 1;
        self.input_caret += 1;
        self.input[self.input_len] = 0;
    }

    fn backspace(self: *ResultsHighscoreState) void {
        if (self.input_caret == 0 or self.input_len == 0) return;
        self.input_caret = @min(self.input_caret, self.input_len);
        var idx = self.input_caret - 1;
        while (idx + 1 < self.input_len) : (idx += 1) {
            self.input[idx] = self.input[idx + 1];
        }
        self.input_len -= 1;
        self.input_caret -= 1;
        self.input[self.input_len] = 0;
    }

    fn moveCaretLeft(self: *ResultsHighscoreState) void {
        self.input_caret = @min(self.input_caret, self.input_len);
        self.input_caret -|= 1;
    }

    fn moveCaretRight(self: *ResultsHighscoreState) void {
        self.input_caret = @min(self.input_caret + 1, self.input_len);
    }

    fn moveCaretHome(self: *ResultsHighscoreState) void {
        self.input_caret = 0;
    }

    fn moveCaretEnd(self: *ResultsHighscoreState) void {
        self.input_caret = self.input_len;
    }

    fn promptActive(self: *const ResultsHighscoreState) bool {
        return !self.saved;
    }
};

const ResultsHighscoreBuild = struct {
    highscore: ?ResultsHighscoreState = null,
    score_too_low_for_top100: bool = false,
};

const App = struct {
    allocator: std.mem.Allocator,
    runtime: app_runtime.DesktopRuntime,
    screen: Screen = .boot,
    boot: BootSequenceState = .{},
    menu: MenuScreenState = .{},
    results_selection: usize = 0,
    play_game_menu: window_menu_panels.PlayGameState = .{},
    quests_menu: window_menu_panels.QuestState = .{},
    statistics_menu: window_statistics.State = .{},
    mods_menu: window_misc_panels.ModsState = .{},
    other_games_menu: window_misc_panels.OtherGamesState = .{},
    network_session: window_misc_panels.NetworkState = .{},
    end_note_selection: usize = 0,
    gameplay: ?GameplayScreen = null,
    network_live_session: ?NetworkLiveRuntime = null,
    network_live_input_interpreter: local_input.LocalInputInterpreter = .{},
    network_live_camera: state_mod.Vec2 = .{ .x = -1.0, .y = -1.0 },
    network_live_input_ready: bool = false,
    network_live_render_time_s: f32 = 0.0,
    network_live_hud_state: HudRuntimeState = .{},
    network_live_last_update: ?live_runner.FrameUpdate = null,
    network_live_ground: ?window_ground.GroundRenderer = null,
    network_live_pending_terrain_fx: [16]terrain_fx_mod.TerrainFxBatch = [_]terrain_fx_mod.TerrainFxBatch{.{}} ** 16,
    network_live_pending_terrain_fx_count: usize = 0,
    results: ?ResultsScreen = null,
    options: window_options.OptionsState = .{},
    controls: window_options.ControlsState = .{},
    options_back_to: Screen = .main_menu,
    controls_back_to: Screen = .options,
    runtime_assets: ?window_assets.RuntimeAssets = null,
    audio: live_audio.Bridge,
    assets_state: AssetsState = .unavailable,
    assets_message: ?[]u8 = null,
    next_seed_state: u32 = 0xC0FFEE,
    next_seed_override: ?u32 = null,
    cursor_pulse_time: f32 = 0.0,
    demo_enabled: bool = false,
    preserve_bugs: bool = false,
    demo_trial_elapsed_ms: i32 = 0,
    demo_trial_info: demo_trial.OverlayInfo = .{},
    demo_trial_ui: window_demo_trial.State = .{},
    last_quest_level_key: i32 = 101,
    demo_attract_active: bool = false,
    demo_attract_elapsed_ms: i32 = 0,
    demo_attract_next_variant: i32 = 0,
    demo_attract_current_variant: i32 = 0,
    demo_upsell_message_index: usize = 0,
    demo_attract_purchase_active: bool = false,
    demo_attract_purchase_limit_ms: i32 = 0,
    demo_attract_purchase_ui: DemoAttractPurchaseState = .{},
    quit_requested: bool = false,

    fn init(allocator: std.mem.Allocator, runtime: app_runtime.DesktopRuntime, args: WindowArgs) App {
        var app: App = .{
            .allocator = allocator,
            .runtime = runtime,
            .screen = initialScreenForArgs(args),
            .audio = live_audio.Bridge.init(allocator, audio_mod.audioConfigFromCrimsonCfg(runtime.config), null),
            .demo_enabled = args.demo_enabled,
            .preserve_bugs = args.preserve_bugs,
            .next_seed_override = args.seed,
        };
        app.boot.reset();
        app.menu.reset();
        if (args.no_intro) {
            app.menu.openRoot();
        }
        app.loadAssets();
        return app;
    }

    fn deinit(self: *App) void {
        self.stopNetworkLiveSession();
        if (self.gameplay) |*gameplay| {
            gameplay.deinit();
            self.gameplay = null;
        }
        self.statistics_menu.deinit(self.allocator);
        if (self.runtime_assets) |*runtime_assets| {
            runtime_assets.deinit();
            self.runtime_assets = null;
        }
        self.audio.deinit();
        if (self.assets_message) |message| {
            self.allocator.free(message);
            self.assets_message = null;
        }
        self.runtime.deinit();
        self.* = undefined;
    }

    fn saveAllIfDirty(self: *App) !void {
        if (self.gameplay) |*gameplay| {
            self.runtime.absorbSessionState(&gameplay.runner.session);
        }
        try self.runtime.saveAllIfDirty();
    }

    fn loadAssets(self: *App) void {
        self.runtime_assets = window_assets.loadRuntimeAssetsFromDefaultSearch(self.allocator) catch |err| {
            self.assets_state = .failed;
            self.assets_message = self.allocator.dupe(u8, assetLoadErrorDetail(err)) catch null;
            return;
        };
        self.assets_state = if (self.runtime_assets != null) .loaded else .unavailable;
    }

    fn rootMenuFlags(self: *const App) window_menu.Flags {
        return .{
            .mods_available = self.modsAvailable(),
            .other_games_enabled = self.otherGamesEnabled(),
            .demo_enabled = self.demo_enabled,
        };
    }

    fn modsAvailable(self: *const App) bool {
        var mods_path_buf: [std.fs.max_path_bytes]u8 = undefined;
        const mods_path = std.fmt.bufPrint(&mods_path_buf, "{s}/mods", .{self.runtime.base_dir}) catch return false;
        const io = std.Io.Threaded.global_single_threaded.io();
        var dir = std.Io.Dir.openDirAbsolute(io, mods_path, .{ .iterate = true }) catch return false;
        defer dir.close(io);

        var iter = dir.iterate();
        while (iter.next(io) catch null) |entry| {
            if (entry.kind == .file and std.ascii.endsWithIgnoreCase(entry.name, ".dll")) return true;
        }
        return false;
    }

    fn otherGamesEnabled(self: *const App) bool {
        const raw = runtime_paths.envVarOwned(self.allocator, "CRIMSON_GRIM_CONFIG_VAR_100") catch return false;
        defer self.allocator.free(raw);
        return raw.len != 0;
    }

    fn update(self: *App, frame_dt: f32) void {
        self.tickCursorPulse(frame_dt);
        switch (self.screen) {
            .boot => self.updateBoot(frame_dt),
            .main_menu => self.updateMainMenu(frame_dt),
            .play_game_menu => self.updatePlayGameMenu(frame_dt),
            .quests_menu => self.updateQuestsMenu(frame_dt),
            .statistics_menu => self.updateStatisticsMenu(frame_dt),
            .mods_menu => self.updateModsMenu(frame_dt),
            .other_games_menu => self.updateOtherGamesMenu(frame_dt),
            .network_session => self.updateNetworkSession(frame_dt),
            .gameplay => self.updateGameplay(frame_dt),
            .pause => self.updatePause(frame_dt),
            .results => self.updateResults(frame_dt),
            .end_note => self.updateEndNote(),
            .options => self.updateOptions(frame_dt),
            .controls => self.updateControls(frame_dt),
        }
        self.audio.update(frame_dt);
    }

    fn draw(self: *App) void {
        switch (self.screen) {
            .boot => self.drawBoot(),
            .main_menu => self.drawMainMenu(),
            .play_game_menu => self.drawPlayGameMenu(),
            .quests_menu => self.drawQuestsMenu(),
            .statistics_menu => self.drawStatisticsMenu(),
            .mods_menu => self.drawModsMenu(),
            .other_games_menu => self.drawOtherGamesMenu(),
            .network_session => self.drawNetworkSession(),
            .gameplay => self.drawGameplay(),
            .pause => self.drawPause(),
            .results => self.drawResults(),
            .end_note => self.drawEndNote(),
            .options => self.drawOptions(),
            .controls => self.drawControls(),
        }
        self.drawUiCursor();
    }

    fn setScreen(self: *App, screen: Screen) void {
        if (self.screen != screen) self.cursor_pulse_time = 0.0;
        if (self.screen != screen) {
            self.runtime.saveAllIfDirty() catch |err| {
                std.log.err("saveAllIfDirty failed during screen transition: {s}", .{@errorName(err)});
            };
        }
        self.screen = screen;
    }

    fn tickCursorPulse(self: *App, frame_dt: f32) void {
        if (self.screen == .boot) return;
        self.cursor_pulse_time += @min(@max(frame_dt, 0.0), 0.1) * 1.1;
    }

    fn drawUiCursor(self: *const App) void {
        const assets = if (self.runtime_assets) |*runtime_assets| runtime_assets else return;
        switch (self.screen) {
            .boot => {},
            .main_menu, .play_game_menu, .quests_menu, .statistics_menu, .mods_menu, .other_games_menu, .network_session, .pause, .results, .end_note, .options, .controls => {
                window_cursor.drawMenuCursor(assets, self.cursor_pulse_time);
            },
            .gameplay => {
                if (self.gameplay) |gameplay| {
                    if (gameplay.perk_ui.active()) {
                        window_cursor.drawMenuCursor(assets, self.cursor_pulse_time);
                    }
                }
            },
        }
    }

    fn updateBoot(self: *App, frame_dt: f32) void {
        const result = window_boot.update(&self.boot, frame_dt);
        if (result.finished) {
            self.menu.openRoot();
            self.setScreen(.main_menu);
            return;
        }
        self.audio.ensureIntroMusic();
    }

    fn updateMainMenu(self: *App, frame_dt: f32) void {
        self.audio.ensureMenuThemeForDemo(self.demo_enabled);
        const menu_update = window_menu.update(
            &self.menu,
            frame_dt,
            if (self.runtime_assets) |*assets| assets else null,
            self.rootMenuFlags(),
        );
        if (menu_update.play_panel_click and !self.menu.panel_open_sfx_played) {
            self.audio.playUiPanelClick();
            self.menu.panel_open_sfx_played = true;
        }
        if (menu_update.play_button_click) {
            self.audio.playUiButtonClick();
        }
        if (menu_update.action) |action| {
            switch (action) {
                .open_play_game => {
                    self.play_game_menu.reset();
                    self.setScreen(.play_game_menu);
                },
                .open_options => {
                    self.options.reset();
                    self.options_back_to = .main_menu;
                    self.setScreen(.options);
                },
                .open_statistics => {
                    window_statistics.openRoot(&self.statistics_menu, self.allocator, self.last_quest_level_key);
                    self.setScreen(.statistics_menu);
                },
                .open_mods => {
                    self.mods_menu.reset(self.runtime.base_dir);
                    self.setScreen(.mods_menu);
                },
                .open_other_games => {
                    self.other_games_menu.reset();
                    self.setScreen(.other_games_menu);
                },
                .start_demo => self.startDemoAttractRun(),
                .quit => self.quit_requested = true,
            }
        }
    }

    fn updatePlayGameMenu(self: *App, frame_dt: f32) void {
        self.audio.ensureMenuThemeForDemo(self.demo_enabled);
        const play_game_update = window_menu_panels.updatePlayGame(&self.play_game_menu, frame_dt, &self.runtime.config, self.runtime.status, if (self.runtime_assets) |*assets| assets else null, self.demo_enabled);
        if (play_game_update.config_dirty) self.runtime.config_dirty = true;
        if (play_game_update.play_panel_click and !self.play_game_menu.panel.panel_open_sfx_played) {
            self.audio.playUiPanelClick();
            self.play_game_menu.panel.panel_open_sfx_played = true;
        }
        if (play_game_update.play_button_click) self.audio.playUiButtonClick();
        if (play_game_update.action) |action| switch (action) {
            .start_survival => self.startNewRun(self.liveRunConfig(.survival, null)),
            .start_rush => self.startNewRun(self.liveRunConfig(.rush, null)),
            .start_typo => self.startNewRun(self.liveRunConfig(.typo, null)),
            .start_tutorial => self.startNewRun(self.liveRunConfig(.tutorial, null)),
            .open_quests => {
                self.quests_menu.resetToLevelKey(self.last_quest_level_key);
                self.setScreen(.quests_menu);
            },
            .open_network_session => {
                self.network_session.reset();
                self.setScreen(.network_session);
            },
            .back_to_menu => {
                self.menu.openRoot();
                self.setScreen(.main_menu);
            },
        };
    }

    fn updateQuestsMenu(self: *App, frame_dt: f32) void {
        self.audio.ensureMenuThemeForDemo(self.demo_enabled);
        const quest_update = window_menu_panels.updateQuests(&self.quests_menu, frame_dt, &self.runtime.config, self.runtime.status, self.demo_enabled);
        if (quest_update.config_dirty) self.runtime.config_dirty = true;
        if (quest_update.play_panel_click and !self.quests_menu.panel.panel_open_sfx_played) {
            self.audio.playUiPanelClick();
            self.quests_menu.panel.panel_open_sfx_played = true;
        }
        if (quest_update.play_button_click) self.audio.playUiButtonClick();
        if (quest_update.back_to_play_game) {
            self.play_game_menu.reset();
            self.setScreen(.play_game_menu);
            return;
        }
        if (quest_update.start_level_key) |level_key| {
            self.startNewRun(self.liveRunConfig(.quests, level_key));
        }
    }

    fn updateStatisticsMenu(self: *App, frame_dt: f32) void {
        self.audio.ensureStatisticsTheme();
        const statistics_update = window_statistics.update(
            &self.statistics_menu,
            self.allocator,
            frame_dt,
            self.runtime.base_dir,
            &self.runtime.config,
            self.runtime.status,
            if (self.runtime_assets) |*assets| assets else null,
        );
        if (statistics_update.play_panel_click and !self.statistics_menu.hub.panel.panel_open_sfx_played) {
            self.audio.playUiPanelClick();
            self.statistics_menu.hub.panel.panel_open_sfx_played = true;
        }
        if (statistics_update.play_button_click) {
            self.audio.playUiButtonClick();
        }
        if (statistics_update.quest_level_key) |quest_level_key| {
            self.last_quest_level_key = quest_level_key;
        }
        switch (statistics_update.action) {
            .none => {},
            .open_play_game => {
                self.play_game_menu.reset();
                self.setScreen(.play_game_menu);
            },
            .back_to_menu => {
                self.menu.openRoot();
                self.setScreen(.main_menu);
            },
        }
    }

    fn updateGameplay(self: *App, frame_dt: f32) void {
        if (self.gameplay) |*gameplay| {
            gameplay.render_time_s += @max(frame_dt, 0.0);
            const dt_ms = @as(i32, @intFromFloat(@min(@max(frame_dt, 0.0), 0.1) * 1000.0));
            if (self.demo_attract_active) {
                if (self.demo_attract_purchase_active) {
                    self.demo_attract_elapsed_ms += dt_ms;
                    self.demo_trial_info = .{};
                    switch (updateDemoAttractPurchaseInterstitial(&self.demo_attract_purchase_ui, dt_ms)) {
                        .none => {},
                        .maybe_later => {
                            self.closeGameplayToMenu(gameplay);
                            return;
                        },
                        .purchase => {
                            _ = openDemoPurchaseUrl(self.allocator);
                            self.quit_requested = true;
                            return;
                        },
                    }
                    if (self.demo_attract_elapsed_ms > self.demo_attract_purchase_limit_ms) {
                        self.startDemoAttractRun();
                        return;
                    }
                    gameplay.last_update = gameplay.runner.stepFrame(0.0, .{}) catch unreachable;
                    return;
                }
                switch (demoAttractInactiveAction()) {
                    .none => {},
                    .purchase => {
                        self.beginDemoAttractPurchaseScreen(false);
                        gameplay.last_update = gameplay.runner.stepFrame(0.0, .{}) catch unreachable;
                        return;
                    },
                    .close => {
                        self.closeGameplayToMenu(gameplay);
                        return;
                    },
                }
                self.demo_attract_elapsed_ms += dt_ms;
                if (self.demo_attract_elapsed_ms > demoAttractLimitMs(self.demo_attract_current_variant)) {
                    self.startDemoAttractRun();
                    return;
                }
                self.demo_trial_info = .{};
            } else if (self.demo_enabled) {
                const current_demo_info = self.currentDemoTrialInfo(gameplay);
                const timer_tick = demo_trial.tickDemoTrialTimers(
                    true,
                    gameplay.runner.session.game_mode,
                    current_demo_info.visible,
                    self.runtime.status.game_sequence_id,
                    self.demo_trial_elapsed_ms,
                    dt_ms,
                );
                if (timer_tick.global_playtime_ms != self.runtime.status.game_sequence_id) {
                    self.runtime.status.game_sequence_id = timer_tick.global_playtime_ms;
                    self.runtime.status_dirty = true;
                }
                self.demo_trial_elapsed_ms = timer_tick.quest_grace_elapsed_ms;
                self.demo_trial_info = self.currentDemoTrialInfo(gameplay);

                if (self.demo_trial_info.visible) {
                    switch (window_demo_trial.update(&self.demo_trial_ui, dt_ms)) {
                        .none => {},
                        .maybe_later => {
                            self.closeGameplayToMenu(gameplay);
                            return;
                        },
                        .purchase => {
                            _ = openDemoPurchaseUrl(self.allocator);
                            self.quit_requested = true;
                            return;
                        },
                    }
                    return;
                }
            } else {
                self.demo_trial_info = .{};
            }

            if (!gameplay.perk_ui.active() and rl.isKeyPressed(.escape)) {
                gameplay.pause_menu.reset();
                self.setScreen(.pause);
                return;
            }

            const camera = buildWorldCamera(
                gameplay.runner.session.world_size,
                &self.runtime.config,
                gameplay.camera,
                gameplay.runner.session.state.camera_shake_offset,
            );
            if (!self.demo_enabled) {
                self.runtime.recordGameplayFrame(frame_dt);
            }
            var input = if (self.demo_attract_active)
                collectDemoAttractInput(&gameplay.input_interpreter, &gameplay.runner, camera, &self.runtime, frame_dt)
            else
                collectGameplayInput(&gameplay.input_interpreter, &gameplay.runner, camera, &self.runtime, frame_dt);
            if (gameplay.runner.session.game_mode == .tutorial and
                gameplay.runner.perkPendingCount() > 0 and
                gameplay.runner.session.state.tutorial.stage_index == 6 and
                !gameplay.perk_ui.active())
            {
                gameplay.perk_ui.menu_open = true;
                gameplay.perk_ui.selected_index = 0;
                self.audio.playUiPanelClick();
            }
            const perk_ui_update = window_perk_menu.update(
                &gameplay.perk_ui,
                frame_dt,
                if (self.runtime_assets) |*assets| assets else null,
                &self.runtime.config,
                &gameplay.runner,
                !gameplay.runner.allPlayersDead(),
            );
            input.perk_choice_index = perk_ui_update.perk_choice_index;
            input.perk_menu_active = perk_ui_update.menu_active;
            if (perk_ui_update.play_panel_click) {
                self.audio.playUiPanelClick();
            }
            if (perk_ui_update.play_button_click) {
                self.audio.playUiButtonClick();
            }
            gameplay.last_update = gameplay.runner.stepFrame(frame_dt, input) catch |err| {
                self.finishRun(gameplay, .runtime_error, liveRuntimeErrorDetail(err));
                return;
            };
            gameplay.camera = updateGameplayCamera(
                gameplay.camera,
                &gameplay.runner.session,
                &self.runtime.config,
            );
            gameplay.hud_state.update(frame_dt, &gameplay.runner.session);
            self.audio.handleFrameAudio(gameplay.last_update.audio, gameplay.runner.session.state.bonuses.reflex_boost);
            gameplay.queueTerrainFxBatch(gameplay.last_update.terrain_fx);
            if (self.runtime_assets) |*runtime_assets| {
                gameplay.flushPendingTerrainFx(runtime_assets);
            }

            if (gameplay.runner.session.game_mode == .tutorial) {
                switch (updateTutorialPromptButtons(self, gameplay)) {
                    .none => {},
                    .close_to_menu => {
                        self.closeTutorialRun(gameplay);
                        return;
                    },
                    .restart => {
                        const run_config = gameplay.run_config;
                        self.closeTutorialGameplay(gameplay);
                        self.startNewRun(run_config);
                        return;
                    },
                }
            }

            if (gameplay.runner.session.game_mode == .quests and gameplay.runner.session.quest_completed) {
                self.finishRun(gameplay, .completed, null);
                return;
            }
            if (gameplay.last_update.all_players_dead) {
                self.finishRun(gameplay, .dead, null);
            }
        }
    }

    fn updatePause(self: *App, frame_dt: f32) void {
        if (self.gameplay) |*gameplay| {
            const pause_update = window_pause_menu.update(
                &gameplay.pause_menu,
                frame_dt,
                if (self.runtime_assets) |*assets| assets else null,
            );
            if (pause_update.play_panel_click and !gameplay.pause_menu.panel_open_sfx_played) {
                self.audio.playUiPanelClick();
                gameplay.pause_menu.panel_open_sfx_played = true;
            }
            if (pause_update.play_button_click) self.audio.playUiButtonClick();
            if (pause_update.action) |action| switch (action) {
                .back_to_previous => self.setScreen(.gameplay),
                .open_options => {
                    self.options.reset();
                    self.options_back_to = .pause;
                    self.setScreen(.options);
                },
                .back_to_menu => {
                    gameplay.deinit();
                    self.gameplay = null;
                    self.menu.openRoot();
                    self.setScreen(.main_menu);
                },
            };
        }
    }

    fn updateModsMenu(self: *App, frame_dt: f32) void {
        self.audio.ensureMenuThemeForDemo(self.demo_enabled);
        const panel_update = window_misc_panels.updateMods(&self.mods_menu, frame_dt, if (self.runtime_assets) |*assets| assets else null);
        if (panel_update.play_panel_click and !self.mods_menu.panel.panel_open_sfx_played) {
            self.audio.playUiPanelClick();
            self.mods_menu.panel.panel_open_sfx_played = true;
        }
        if (panel_update.play_button_click) self.audio.playUiButtonClick();
        if (panel_update.action == .back_to_menu) {
            self.menu.openRoot();
            self.setScreen(.main_menu);
        }
    }

    fn updateOtherGamesMenu(self: *App, frame_dt: f32) void {
        self.audio.ensureMenuThemeForDemo(self.demo_enabled);
        const panel_update = window_misc_panels.updateOtherGames(&self.other_games_menu, frame_dt, if (self.runtime_assets) |*assets| assets else null);
        if (panel_update.play_panel_click and !self.other_games_menu.panel.panel_open_sfx_played) {
            self.audio.playUiPanelClick();
            self.other_games_menu.panel.panel_open_sfx_played = true;
        }
        if (panel_update.play_button_click) self.audio.playUiButtonClick();
        if (panel_update.action == .back_to_menu) {
            self.menu.openRoot();
            self.setScreen(.main_menu);
        }
    }

    fn updateNetworkSession(self: *App, frame_dt: f32) void {
        if (self.network_live_session != null) {
            self.network_live_render_time_s += @max(frame_dt, 0.0);
            if (rl.isKeyPressed(.escape)) {
                self.audio.playUiButtonClick();
                self.stopNetworkLiveSession();
                self.play_game_menu.reset();
                self.setScreen(.play_game_menu);
                return;
            }
            self.updateNetworkLiveSession(frame_dt);
            return;
        } else {
            self.audio.ensureMenuThemeForDemo(self.demo_enabled);
        }
        const panel_update = window_misc_panels.updateNetwork(&self.network_session, frame_dt, if (self.runtime_assets) |*assets| assets else null);
        if (panel_update.play_panel_click and !self.network_session.panel.panel_open_sfx_played) {
            self.audio.playUiPanelClick();
            self.network_session.panel.panel_open_sfx_played = true;
        }
        if (panel_update.play_button_click) self.audio.playUiButtonClick();
        if (panel_update.action == .back_to_menu) {
            self.stopNetworkLiveSession();
            self.play_game_menu.reset();
            self.setScreen(.play_game_menu);
        }
        if (panel_update.action == .launch_network) {
            self.startNetworkLiveSession();
        }
        self.updateNetworkLiveSession(frame_dt);
    }

    fn startNetworkLiveSession(self: *App) void {
        const request = window_misc_panels.networkLaunchRequest(&self.network_session) orelse {
            self.network_session.setStatus(window_misc_panels.networkLaunchUnavailableMessage(&self.network_session));
            return;
        };
        self.stopNetworkLiveSession();
        self.audio.stopGameplayMusic();

        const io = std.Io.Threaded.global_single_threaded.io();
        const seed: i32 = @bitCast(self.takeRunSeed());
        var session = NetworkLiveRuntime.init(request, seed) catch |err| {
            self.network_session.setStatusFmt("Lockstep init failed: {s}", .{@errorName(err)});
            return;
        };
        session.start(self.allocator, io, monotonicMs(io)) catch |err| {
            session.deinit(self.allocator, io);
            self.network_session.setStatusFmt("Lockstep open failed: {s}", .{@errorName(err)});
            return;
        };

        const port = session.boundPort();
        self.resetNetworkLiveInput();
        self.network_live_session = session;
        switch (request.role) {
            .host => self.network_session.setStatusFmt("Lockstep host listening on port {d}.", .{port}),
            .join => self.network_session.setStatusFmt("Lockstep join sent hello from port {d}.", .{port}),
        }
    }

    fn updateNetworkLiveSession(self: *App, frame_dt: f32) void {
        const io = std.Io.Threaded.global_single_threaded.io();
        const now_ms = monotonicMs(io);
        self.submitNetworkLiveInput(io, frame_dt, now_ms) catch |err| {
            self.network_session.setStatusFmt("Lockstep input failed: {s}", .{@errorName(err)});
            self.stopNetworkLiveSession();
            return;
        };

        const session = if (self.network_live_session) |*session| session else return;
        const net_update = session.update(self.allocator, io, now_ms) catch |err| {
            self.network_session.setStatusFmt("Lockstep update failed: {s}", .{@errorName(err)});
            self.stopNetworkLiveSession();
            return;
        };
        self.refreshNetworkLiveCamera();
        if (net_update.last_frame_update) |frame_update| {
            self.network_live_last_update = frame_update;
            if (session.runnerForLocalInput()) |runner| {
                self.ensureNetworkLiveGround(runner);
                self.network_live_hud_state.update(frame_dt, &runner.session);
                self.audio.handleFrameAudio(frame_update.audio, runner.session.state.bonuses.reflex_boost);
                self.queueNetworkLiveTerrainFxBatch(frame_update.terrain_fx);
                if (self.runtime_assets) |*runtime_assets| {
                    self.flushNetworkLiveTerrainFx(runtime_assets);
                }
                if (networkLiveTerminalReason(runner.session.game_mode, runner.session.quest_completed, frame_update.all_players_dead)) |reason| {
                    if (session.runConfigForResults()) |run_config| {
                        self.finishLiveRunner(runner, run_config, reason, null);
                    } else {
                        self.network_session.setStatus("Lockstep match finished before results were available.");
                    }
                    self.stopNetworkLiveSession();
                    return;
                }
            }
        }
        if (net_update.frames_advanced != 0) {
            if (net_update.last_tick_index) |tick_index| {
                const local_slot = session.localInputSlot() orelse 0;
                const local_flags = if (local_slot < net_update.last_player_count) net_update.last_input_flags[local_slot] else 0;
                self.network_session.setStatusFmt("Lockstep tick={d} frames={d} flags=0x{x}.", .{ tick_index, net_update.frames_advanced, local_flags });
            } else {
                self.network_session.setStatusFmt("Lockstep frames={d} ticks={d}.", .{ net_update.frames_advanced, net_update.ticks_advanced });
            }
        } else if (net_update.stats.received != 0 or net_update.stats.sent != 0) {
            self.network_session.setStatusFmt("Lockstep packets recv={d} sent={d}.", .{ net_update.stats.received, net_update.stats.sent });
        }
    }

    fn submitNetworkLiveInput(self: *App, io: std.Io, frame_dt: f32, now_ms: i64) !void {
        const session = if (self.network_live_session) |*session| session else return;
        if (!session.hostRemoteInputsReady()) {
            self.network_live_input_ready = false;
            return;
        }
        const runner = session.runnerForLocalInput() orelse {
            self.network_live_input_ready = false;
            return;
        };

        if (!self.network_live_input_ready) {
            self.network_live_input_interpreter.setPreserveBugs(runner.session.state.preserve_bugs);
            self.network_live_input_interpreter.reset(runner.session.playersConst());
            self.network_live_camera = updateGameplayCamera(
                self.network_live_camera,
                &runner.session,
                &self.runtime.config,
            );
            self.network_live_input_ready = true;
        }

        const camera = buildWorldCamera(
            runner.session.world_size,
            &self.runtime.config,
            self.network_live_camera,
            runner.session.state.camera_shake_offset,
        );
        const input = collectGameplayInput(
            &self.network_live_input_interpreter,
            runner,
            camera,
            &self.runtime,
            frame_dt,
        );
        _ = try session.submitLocalFrameInput(self.allocator, io, input, now_ms);
    }

    fn refreshNetworkLiveCamera(self: *App) void {
        const session = if (self.network_live_session) |*session| session else return;
        const runner = session.runnerForLocalInput() orelse return;
        self.network_live_camera = updateGameplayCamera(
            self.network_live_camera,
            &runner.session,
            &self.runtime.config,
        );
    }

    fn ensureNetworkLiveGround(self: *App, runner: *const live_runner.LiveRunner) void {
        if (self.network_live_ground != null) return;
        if (self.runtime_assets) |*runtime_assets| {
            self.network_live_ground = window_ground.GroundRenderer.initForTerrainSetup(
                runtime_assets,
                runner.terrain_setup,
                runner.session.terrain_size,
                runner.session.terrain_size,
                self.runtime.config.texture_scale,
            ) catch null;
        }
    }

    fn queueNetworkLiveTerrainFxBatch(self: *App, batch: terrain_fx_mod.TerrainFxBatch) void {
        if (batch.isEmpty()) return;
        if (self.network_live_pending_terrain_fx_count < self.network_live_pending_terrain_fx.len) {
            self.network_live_pending_terrain_fx[self.network_live_pending_terrain_fx_count] = batch;
            self.network_live_pending_terrain_fx_count += 1;
            return;
        }
        var idx: usize = 1;
        while (idx < self.network_live_pending_terrain_fx.len) : (idx += 1) {
            self.network_live_pending_terrain_fx[idx - 1] = self.network_live_pending_terrain_fx[idx];
        }
        self.network_live_pending_terrain_fx[self.network_live_pending_terrain_fx.len - 1] = batch;
    }

    fn flushNetworkLiveTerrainFx(self: *App, assets: *const window_assets.RuntimeAssets) void {
        const ground = &(self.network_live_ground orelse return);
        if (!ground.renderTargetReady()) return;

        var kept: usize = 0;
        for (self.network_live_pending_terrain_fx[0..self.network_live_pending_terrain_fx_count]) |batch| {
            if (window_terrain_fx.bakeTerrainFxBatch(ground, &batch, assets)) continue;
            self.network_live_pending_terrain_fx[kept] = batch;
            kept += 1;
        }
        self.network_live_pending_terrain_fx_count = kept;
    }

    fn stopNetworkLiveSession(self: *App) void {
        if (self.network_live_session) |*session| {
            session.deinit(self.allocator, std.Io.Threaded.global_single_threaded.io());
            self.network_live_session = null;
        }
        self.resetNetworkLiveInput();
    }

    fn resetNetworkLiveInput(self: *App) void {
        self.network_live_input_interpreter = .{};
        self.network_live_camera = .{ .x = -1.0, .y = -1.0 };
        self.network_live_input_ready = false;
        self.network_live_render_time_s = 0.0;
        self.network_live_hud_state = .{};
        self.network_live_last_update = null;
        if (self.network_live_ground) |*ground| {
            ground.deinit();
            self.network_live_ground = null;
        }
        self.network_live_pending_terrain_fx_count = 0;
    }

    fn updateResults(self: *App, frame_dt: f32) void {
        if (self.results) |*results| {
            if (results.reason == .completed and results.quest_final_time != null and !results.quest_breakdown_anim.done) {
                if (rl.isKeyPressed(.space) or rl.isMouseButtonPressed(.left)) {
                    results.quest_breakdown_anim.setFinal(results.quest_final_time.?);
                    if (results.highscore) |*highscore| {
                        highscore.defer_name_input_until_controls_released = true;
                    }
                    return;
                }
                const frame_dt_ms: i32 = @intFromFloat(frame_dt * 1000.0);
                const clinks = quest_results.tickQuestResultsBreakdownAnim(
                    &results.quest_breakdown_anim,
                    frame_dt_ms,
                    results.quest_final_time.?,
                );
                if (clinks > 0) self.audio.playUiClink();
                if (results.quest_breakdown_anim.done) {
                    if (results.highscore) |*highscore| {
                        highscore.defer_name_input_until_controls_released = true;
                    }
                }
                return;
            }
            if (results.highscore) |*highscore| {
                if (highscore.promptActive()) {
                    self.updateResultsHighscoreEntry(results, highscore);
                    return;
                }
            }
            if (questCompletedShortcutSelection(results)) |selection| {
                self.results_selection = selection;
                self.audio.playUiButtonClick();
                self.activateResultsSelection(results);
                return;
            }
            if (questFailedShortcutSelection(results)) |selection| {
                self.results_selection = selection;
                self.audio.playUiButtonClick();
                self.activateResultsSelection(results);
                return;
            }
            const buttons = resultsButtonsFor(results);
            window_ui.updateSelectionFromPointer(&self.results_selection, buttons.items[0..buttons.len]);
            if (rl.isKeyPressed(.up) or rl.isKeyPressed(.w)) {
                self.results_selection = if (self.results_selection == 0) buttons.len - 1 else self.results_selection - 1;
            }
            if (rl.isKeyPressed(.down) or rl.isKeyPressed(.s)) {
                self.results_selection = (self.results_selection + 1) % buttons.len;
            }

            const activated = window_ui.buttonActivated(buttons.items[0..buttons.len], self.results_selection);
            if (!activated) return;
            self.audio.playUiButtonClick();
            self.activateResultsSelection(results);
            return;
        }
    }

    fn activateResultsSelection(self: *App, results: *const ResultsScreen) void {
        switch (results.run_config.game_mode) {
            .quests => switch (results.reason) {
                .completed => switch (self.results_selection) {
                    0 => self.activateQuestCompletedPrimary(results),
                    1 => {
                        var next_run = results.run_config;
                        next_run.quest_fail_retry_count = 0;
                        self.startNewRun(next_run);
                    },
                    2 => self.openResultsHighScores(results),
                    3 => {
                        self.results = null;
                        self.menu.openRoot();
                        self.setScreen(.main_menu);
                    },
                    else => {},
                },
                .dead => switch (self.results_selection) {
                    0 => {
                        var next_run = results.run_config;
                        next_run.quest_fail_retry_count +%= 1;
                        self.startNewRun(next_run);
                    },
                    1 => {
                        self.results = null;
                        self.quests_menu.reset();
                        self.setScreen(.quests_menu);
                    },
                    2 => {
                        self.results = null;
                        self.menu.openRoot();
                        self.setScreen(.main_menu);
                    },
                    else => {},
                },
                .runtime_error, .abandoned => switch (self.results_selection) {
                    0 => self.startNewRun(results.run_config),
                    1 => {
                        self.results = null;
                        self.menu.openRoot();
                        self.setScreen(.main_menu);
                    },
                    else => {},
                },
            },
            else => switch (self.results_selection) {
                0 => self.startNewRun(results.run_config),
                1 => self.openResultsHighScores(results),
                2 => {
                    self.results = null;
                    self.menu.openRoot();
                    self.setScreen(.main_menu);
                },
                else => {},
            },
        }
    }

    fn activateQuestCompletedPrimary(self: *App, results: *const ResultsScreen) void {
        if (isFinalQuestLevelKey(results.run_config.quest_level_key)) {
            self.results = null;
            self.end_note_selection = 0;
            self.setScreen(.end_note);
            return;
        }
        if (nextQuestLevelKey(results.run_config.quest_level_key)) |next_level_key| {
            var next_run = results.run_config;
            next_run.quest_level_key = next_level_key;
            next_run.quest_fail_retry_count = 0;
            self.startNewRun(next_run);
            return;
        }
        self.results = null;
        self.menu.openRoot();
        self.setScreen(.main_menu);
    }

    fn updateEndNote(self: *App) void {
        self.audio.ensureMenuThemeForDemo(self.demo_enabled);
        const buttons = endNoteButtons();
        window_ui.updateSelectionFromPointer(&self.end_note_selection, buttons[0..]);
        if (rl.isKeyPressed(.up) or rl.isKeyPressed(.w)) {
            self.end_note_selection = if (self.end_note_selection == 0) buttons.len - 1 else self.end_note_selection - 1;
        }
        if (rl.isKeyPressed(.down) or rl.isKeyPressed(.s)) {
            self.end_note_selection = (self.end_note_selection + 1) % buttons.len;
        }
        if (rl.isKeyPressed(.escape)) {
            self.audio.playUiButtonClick();
            self.menu.openRoot();
            self.setScreen(.main_menu);
            return;
        }

        if (!window_ui.buttonActivated(buttons[0..], self.end_note_selection)) return;
        self.audio.playUiButtonClick();
        switch (self.end_note_selection) {
            0 => {
                self.runtime.config.game_mode = @intFromEnum(game_ids.GameModeId.survival);
                self.runtime.config_dirty = true;
                self.startNewRun(self.liveRunConfig(.survival, null));
            },
            1 => {
                self.runtime.config.game_mode = @intFromEnum(game_ids.GameModeId.rush);
                self.runtime.config_dirty = true;
                self.startNewRun(self.liveRunConfig(.rush, null));
            },
            2 => {
                self.runtime.config.game_mode = @intFromEnum(game_ids.GameModeId.typo);
                self.runtime.config_dirty = true;
                self.startNewRun(self.liveRunConfig(.typo, null));
            },
            3 => {
                self.menu.openRoot();
                self.setScreen(.main_menu);
            },
            else => {},
        }
    }

    fn currentDemoTrialInfo(self: *const App, gameplay: *const GameplayScreen) demo_trial.OverlayInfo {
        return demo_trial.demoTrialOverlayInfo(
            self.demo_enabled,
            gameplay.runner.session.game_mode,
            self.runtime.status.game_sequence_id,
            self.demo_trial_elapsed_ms,
            gameplay.run_config.quest_level_key,
        );
    }

    fn closeGameplayToMenu(self: *App, gameplay: *GameplayScreen) void {
        self.audio.stopGameplayMusic();
        gameplay.deinit();
        self.gameplay = null;
        self.demo_trial_info = .{};
        self.demo_trial_ui.reset();
        self.demo_attract_active = false;
        self.demo_attract_elapsed_ms = 0;
        self.demo_attract_current_variant = 0;
        self.demo_attract_purchase_active = false;
        self.demo_attract_purchase_limit_ms = 0;
        self.demo_attract_purchase_ui.reset();
        self.menu.openRoot();
        self.setScreen(.main_menu);
    }

    fn openResultsHighScores(self: *App, results: *const ResultsScreen) void {
        self.runtime.config.game_mode = @intCast(@intFromEnum(results.run_config.game_mode));
        self.runtime.config_dirty = true;
        window_statistics.openHighScores(
            &self.statistics_menu,
            self.allocator,
            self.runtime.base_dir,
            self.runtime.config,
            self.runtime.status,
            .{
                .quest_level_key = if (results.run_config.game_mode == .quests)
                    results.run_config.quest_level_key
                else
                    null,
                .highlight_rank = resultsHighscoreHighlightRank(results),
            },
        );
        self.setScreen(.statistics_menu);
    }

    fn updateOptions(self: *App, frame_dt: f32) void {
        self.audio.ensureMenuThemeForDemo(self.demo_enabled);
        const options_update = window_options.updateOptions(&self.options, frame_dt, &self.runtime.config, if (self.runtime_assets) |*assets| assets else null);
        if (options_update.config_dirty) self.runtime.config_dirty = true;
        if (options_update.window_changed) self.applyWindowConfig();
        if (options_update.reload_audio) self.reloadAudioConfig();
        if (options_update.play_panel_click and !self.options.panel.panel_open_sfx_played) {
            self.audio.playUiPanelClick();
            self.options.panel.panel_open_sfx_played = true;
        }
        if (options_update.play_button_click) self.audio.playUiButtonClick();
        switch (options_update.action) {
            .none => {},
            .open_controls => {
                self.controls.reset();
                self.controls_back_to = .options;
                self.setScreen(.controls);
            },
            .back_to_menu => {
                self.setScreen(self.options_back_to);
            },
        }
    }

    fn updateControls(self: *App, frame_dt: f32) void {
        self.audio.ensureMenuThemeForDemo(self.demo_enabled);
        const controls_update = window_options.updateControls(&self.controls, frame_dt, &self.runtime.config, if (self.runtime_assets) |*assets| assets else null);
        if (controls_update.config_dirty) self.runtime.config_dirty = true;
        if (controls_update.play_panel_click and !self.controls.panel_open_sfx_played) {
            self.audio.playUiPanelClick();
            self.controls.panel_open_sfx_played = true;
        }
        if (controls_update.play_button_click) self.audio.playUiButtonClick();
        switch (controls_update.action) {
            .none => {},
            .back_to_options => self.setScreen(self.controls_back_to),
        }
    }

    fn updateResultsHighscoreEntry(
        self: *App,
        results: *ResultsScreen,
        highscore: *ResultsHighscoreState,
    ) void {
        if (highscore.defer_name_input_until_controls_released) {
            flushNameInputEvents();
            if (!gameplayControlsHeld(&self.runtime.config)) {
                highscore.defer_name_input_until_controls_released = false;
            }
            return;
        }

        self.playNameInputTypeClicks(collectNameInput(highscore));

        const buttons = resultsHighscoreButtonsFor(results);
        window_ui.updateSelectionFromPointer(&highscore.selection, buttons.items[0..buttons.len]);
        if (rl.isKeyPressed(.up) or rl.isKeyPressed(.w)) {
            highscore.selection = if (highscore.selection == 0) buttons.len - 1 else highscore.selection - 1;
        }
        if (rl.isKeyPressed(.down) or rl.isKeyPressed(.s)) {
            highscore.selection = (highscore.selection + 1) % buttons.len;
        }

        if (!window_ui.buttonActivated(buttons.items[0..buttons.len], highscore.selection)) return;
        self.audio.playUiButtonClick();

        switch (highscore.selection) {
            0 => self.saveResultsHighscore(results, highscore),
            else => {},
        }
    }

    fn saveResultsHighscore(
        self: *App,
        results: *const ResultsScreen,
        highscore: *ResultsHighscoreState,
    ) void {
        const trimmed = highscore.trimmedInputSlice();
        if (trimmed.len == 0) {
            highscore.save_error = "name required";
            self.audio.playShockHit();
            return;
        }

        highscore.record.setName(trimmed);
        formats.crimson_cfg.setPlayerNameInput(&self.runtime.config, trimmed);
        self.runtime.config_dirty = true;

        const score_path = persistence.highscores.scoresPathForMode(
            self.allocator,
            self.runtime.base_dir,
            @intFromEnum(results.run_config.game_mode),
            .{
                .hardcore = results.run_config.hardcore,
                .quest_stage_major = @divTrunc(results.run_config.quest_level_key, 100),
                .quest_stage_minor = @mod(results.run_config.quest_level_key, 100),
                .player_count = results.run_config.player_count,
            },
        ) catch |err| {
            highscore.save_error = resultsHighscorePathErrorDetail(err);
            return;
        };
        defer self.allocator.free(score_path);

        var upsert = persistence.highscores.upsertHighscoreRecord(
            self.allocator,
            score_path,
            highscore.record,
            null,
        ) catch |err| {
            highscore.save_error = resultsHighscoreSaveErrorDetail(err);
            return;
        };
        defer upsert.deinit(self.allocator);
        highscore.rank_index = upsert.rank_index;
        highscore.highlight_rank = if (scoreTooLowForTop100(upsert.rank_index)) null else upsert.rank_index;

        self.runtime.saveConfigIfDirty() catch |err| {
            highscore.save_error = resultsConfigSaveErrorDetail(err);
            return;
        };

        highscore.saved = true;
        highscore.save_error = null;
        self.results_selection = 0;
        self.audio.playUiTypeEnter();
    }

    fn playNameInputTypeClicks(self: *App, edits: NameInputEdits) void {
        if (edits.typed) self.playNameInputTypeClick();
        if (edits.backspaced) self.playNameInputTypeClick();
    }

    fn playNameInputTypeClick(self: *App) void {
        var rng = spawn_mod.Crand.init(self.next_seed_state);
        const sfx_id = uiTypeClickSfxFromRoll(rng.randTagged(rng_callers.ui_text_input_update_typeclick));
        self.next_seed_state = rng.state;
        self.audio.playUiTypeClick(sfx_id);
    }

    fn startNewRun(self: *App, run_config: live_runner.LiveModeConfig) void {
        self.audio.stopGameplayMusic();
        var configured_run = run_config;
        const requested_player_count: i32 = if (self.demo_attract_active)
            configured_run.player_count
        else
            @intCast(self.runtime.config.player_count);
        configured_run.player_count = livePlayerCountForMode(configured_run.game_mode, requested_player_count);
        configured_run.detail_preset = @intCast(std.math.clamp(self.runtime.config.detail_preset, @as(u32, 1), @as(u32, 5)));
        configured_run.gore_disabled = @intCast(self.runtime.config.gore_disabled);
        configured_run.hardcore = self.runtime.config.hardcore_flag != 0;
        configured_run.preserve_bugs = configured_run.preserve_bugs or self.preserve_bugs;
        configured_run.status_quest_unlock_index = @intCast(self.runtime.status.quest_unlock_index);
        configured_run.status_quest_unlock_index_full = @intCast(self.runtime.status.quest_unlock_index_full);
        configured_run.status_weapon_usage_counts = statusWeaponUsageCounts(self.runtime.status);
        configured_run.demo_mode_active = configured_run.demo_mode_active or
            (self.demo_enabled and (configured_run.game_mode == .quests or configured_run.game_mode == .tutorial));

        if (!self.demo_attract_active) {
            self.runtime.recordModeStart(configured_run.game_mode);
            if (configured_run.game_mode == .quests) {
                self.last_quest_level_key = configured_run.quest_level_key;
                self.runtime.recordQuestStart(configured_run.quest_level_key);
            }
        }
        var runner = live_runner.LiveRunner.init(configured_run) catch |err| {
            self.demo_attract_active = false;
            self.demo_attract_elapsed_ms = 0;
            self.results = .{
                .reason = .runtime_error,
                .run_config = configured_run,
                .summary = zeroSessionSummary(),
                .player_health_values = [_]f32{0.0} ** state_mod.max_players,
                .player_health_count = 0,
                .runtime_error = liveRuntimeErrorDetail(err),
            };
            self.results_selection = 0;
            self.setScreen(.results);
            return;
        };
        if (configured_run.game_mode == .typo) {
            loadTypoSourcesIntoState(self.allocator, self.runtime.base_dir, &runner.session.state) catch |err| {
                self.results = .{
                    .reason = .runtime_error,
                    .run_config = configured_run,
                    .summary = zeroSessionSummary(),
                    .player_health_values = [_]f32{0.0} ** state_mod.max_players,
                    .player_health_count = 0,
                    .runtime_error = typoSourceErrorDetail(err),
                };
                self.results_selection = 0;
                self.setScreen(.results);
                return;
            };
        }
        const last_update = runner.stepFrame(0.0, .{}) catch unreachable;
        if (self.gameplay) |*gameplay| {
            gameplay.deinit();
            self.gameplay = null;
        }

        var gameplay: GameplayScreen = .{
            .runner = runner,
            .run_config = configured_run,
            .last_update = last_update,
        };
        gameplay.camera = updateGameplayCamera(
            gameplay.camera,
            &gameplay.runner.session,
            &self.runtime.config,
        );
        gameplay.hud_state.update(0.0, &gameplay.runner.session);
        gameplay.input_interpreter.setPreserveBugs(gameplay.runner.session.state.preserve_bugs);
        gameplay.input_interpreter.reset(gameplay.runner.session.playersConst());
        if (self.runtime_assets) |*runtime_assets| {
            gameplay.ground = window_ground.GroundRenderer.initForTerrainSetup(
                runtime_assets,
                gameplay.runner.terrain_setup,
                gameplay.runner.session.terrain_size,
                gameplay.runner.session.terrain_size,
                self.runtime.config.texture_scale,
            ) catch null;
        }
        gameplay.queueTerrainFxBatch(gameplay.last_update.terrain_fx);
        if (self.runtime_assets) |*runtime_assets| {
            gameplay.flushPendingTerrainFx(runtime_assets);
        }
        self.gameplay = gameplay;
        self.results = null;
        self.setScreen(.gameplay);
    }

    fn startDemoAttractRun(self: *App) void {
        const variant_index = self.demo_attract_next_variant;
        self.demo_attract_next_variant = nextDemoAttractVariant(variant_index);
        self.demo_attract_current_variant = variant_index;
        self.demo_attract_active = true;
        self.demo_attract_elapsed_ms = 0;
        self.demo_attract_purchase_active = false;
        self.demo_attract_purchase_limit_ms = 0;
        self.demo_attract_purchase_ui.reset();
        var run_config = self.liveRunConfig(.survival, null);
        run_config.player_count = demoAttractPlayerCount(variant_index);
        run_config.demo_mode_active = true;
        self.startNewRun(run_config);
        if (self.gameplay) |*gameplay| {
            setupDemoAttractVariant(&gameplay.runner, variant_index) catch |err| {
                self.finishRun(gameplay, .runtime_error, liveRuntimeErrorDetail(err));
                return;
            };
            if (demoAttractPurchaseActive(variant_index)) {
                self.beginDemoAttractPurchaseScreen(true);
            } else {
                self.demo_upsell_message_index = nextDemoUpsellMessageIndex(self.demo_upsell_message_index);
            }
            gameplay.last_update = gameplay.runner.stepFrame(0.0, .{}) catch unreachable;
            gameplay.camera = updateGameplayCamera(
                gameplay.camera,
                &gameplay.runner.session,
                &self.runtime.config,
            );
            self.refreshGameplayGround(gameplay);
        }
    }

    fn beginDemoAttractPurchaseScreen(self: *App, reset_timeline: bool) void {
        self.demo_attract_purchase_active = true;
        self.demo_attract_purchase_limit_ms = if (demoAttractPurchaseActive(self.demo_attract_current_variant))
            demoAttractLimitMs(self.demo_attract_current_variant)
        else
            demo_attract_purchase_screen_limit_ms;
        if (reset_timeline) {
            self.demo_attract_elapsed_ms = 0;
        }
        self.demo_attract_purchase_ui.reset();
    }

    fn refreshGameplayGround(self: *App, gameplay: *GameplayScreen) void {
        if (gameplay.ground) |*ground| {
            ground.deinit();
            gameplay.ground = null;
        }
        if (self.runtime_assets) |*runtime_assets| {
            gameplay.ground = window_ground.GroundRenderer.initForTerrainSetup(
                runtime_assets,
                gameplay.runner.terrain_setup,
                gameplay.runner.session.terrain_size,
                gameplay.runner.session.terrain_size,
                self.runtime.config.texture_scale,
            ) catch null;
        }
    }

    fn reloadAudioConfig(self: *App) void {
        self.audio.deinit();
        self.audio = live_audio.Bridge.init(
            self.allocator,
            audio_mod.audioConfigFromCrimsonCfg(self.runtime.config),
            null,
        );
    }

    fn applyWindowConfig(self: *App) void {
        const width = self.runtime.windowWidth(window_width);
        const height = self.runtime.windowHeight(window_height);
        const wants_fullscreen = self.runtime.config.windowed_flag == 0;

        if (rl.isWindowFullscreen() and !wants_fullscreen) {
            rl.toggleFullscreen();
        }
        rl.setWindowSize(width, height);
        if (!rl.isWindowFullscreen() and wants_fullscreen) {
            rl.toggleFullscreen();
        }
    }

    fn finishRun(self: *App, gameplay: *GameplayScreen, reason: ResultsReason, runtime_error: ?[]const u8) void {
        const runner = &gameplay.runner;
        self.finishLiveRunner(runner, gameplay.run_config, reason, runtime_error);
        gameplay.deinit();
        self.gameplay = null;
    }

    fn finishLiveRunner(
        self: *App,
        runner: *const live_runner.LiveRunner,
        run_config: live_runner.LiveModeConfig,
        reason: ResultsReason,
        runtime_error: ?[]const u8,
    ) void {
        self.audio.stopGameplayMusic();
        const level_key = runner.quest_level_key;
        self.runtime.absorbSessionState(&runner.session);
        var player_health_values: [state_mod.max_players]f32 = [_]f32{0.0} ** state_mod.max_players;
        const player_health_count = collectPlayerHealthValues(&player_health_values, &runner.session);
        if (reason == .completed and runner.session.game_mode == .quests) {
            if (level_key) |resolved| self.runtime.recordQuestCompletion(resolved);
        }
        const quest_unlock = questUnlockDisplayNames(
            level_key,
            runner.session.game_mode,
            reason,
            run_config.preserve_bugs,
            self.runtime.config.gore_disabled,
        );
        const save_error: ?[]const u8 = save_err: {
            self.runtime.saveStatusIfDirty() catch |err| break :save_err resultsStatusSaveErrorDetail(err);
            break :save_err null;
        };
        const highscore_build = self.buildResultsHighscore(
            runner,
            reason,
            runtime_error orelse save_error,
            player_health_values[0..player_health_count],
        );
        self.results = .{
            .reason = reason,
            .run_config = run_config,
            .summary = runner.summary(),
            .player_health_values = player_health_values,
            .player_health_count = player_health_count,
            .runtime_error = runtime_error orelse save_error,
            .highscore = highscore_build.highscore,
            .score_too_low_for_top100 = highscore_build.score_too_low_for_top100,
            .quest_final_time = if (runner.session.game_mode == .quests)
                quest_results.computeQuestFinalTime(
                    @intCast(runner.summary().elapsed_ms_sim),
                    player_health_values[0..player_health_count],
                    runner.perkPendingCount(),
                )
            else
                null,
            .quest_unlock_weapon_name = quest_unlock.weapon_name,
            .quest_unlock_perk_name = quest_unlock.perk_name,
        };
        if (highscore_build.highscore != null) {
            self.audio.playUiClink();
        }
        self.results_selection = 0;
        self.setScreen(.results);
    }

    fn closeTutorialGameplay(self: *App, gameplay: *GameplayScreen) void {
        self.audio.stopGameplayMusic();
        self.runtime.absorbSessionState(&gameplay.runner.session);
        self.runtime.saveStatusIfDirty() catch |err| {
            std.log.err("saveStatusIfDirty failed during tutorial close: {s}", .{resultsStatusSaveErrorDetail(err)});
        };
        gameplay.deinit();
        self.gameplay = null;
        self.results = null;
    }

    fn closeTutorialRun(self: *App, gameplay: *GameplayScreen) void {
        self.closeTutorialGameplay(gameplay);
        self.menu.openRoot();
        self.setScreen(.main_menu);
    }

    fn buildResultsHighscore(
        self: *App,
        runner: *const live_runner.LiveRunner,
        reason: ResultsReason,
        runtime_error: ?[]const u8,
        player_health_values: []const f32,
    ) ResultsHighscoreBuild {
        if (runtime_error != null) return .{};
        switch (reason) {
            .dead, .completed => {},
            .abandoned, .runtime_error => return .{},
        }
        if (runner.session.game_mode == .quests and reason == .dead) return .{};

        const player = runner.player0Const() orelse return .{};
        const shot_options: persistence.highscore_record_builder.BuildRecordOptions = switch (runner.session.game_mode) {
            .typo => .{
                .shots_fired = runner.session.state.typo.typing.submit_count,
                .shots_hit = runner.session.state.typo.typing.match_count,
                .clamp_shots_hit = false,
            },
            else => .{},
        };

        const elapsed_ms = if (runner.session.game_mode == .quests)
            quest_results.computeQuestFinalTime(
                @intCast(runner.summary().elapsed_ms_sim),
                player_health_values,
                runner.perkPendingCount(),
            ).final_time_ms
        else
            @as(i32, @intCast(runner.summary().elapsed_ms_sim));

        const record = persistence.highscore_record_builder.buildHighscoreRecordForGameOver(
            runner.session.state,
            player.*,
            elapsed_ms,
            @intCast(runner.session.creatures.kill_count),
            runner.session.game_mode,
            shot_options,
        );

        const score_path = persistence.highscores.scoresPathForMode(
            self.allocator,
            self.runtime.base_dir,
            @intFromEnum(runner.session.game_mode),
            .{
                .hardcore = runner.session.state.hardcore,
                .quest_stage_major = runner.session.state.quest_stage_major,
                .quest_stage_minor = runner.session.state.quest_stage_minor,
                .player_count = runner.session.player_count,
            },
        ) catch return .{};
        defer self.allocator.free(score_path);

        const table = persistence.highscores.readHighscoreTable(
            self.allocator,
            score_path,
            @intFromEnum(runner.session.game_mode),
        ) catch return .{};
        defer table.deinit(self.allocator);

        const rank_index = persistence.highscores.rankIndex(table.items, record);
        if (scoreTooLowForTop100(rank_index)) {
            return .{ .score_too_low_for_top100 = true };
        }

        var highscore: ResultsHighscoreState = .{
            .record = record,
            .rank_index = rank_index,
        };
        highscore.setInput(formats.crimson_cfg.playerName(&self.runtime.config));
        return .{ .highscore = highscore };
    }

    fn drawBoot(self: *const App) void {
        if (self.runtime_assets) |*assets| {
            window_boot.draw(&self.boot, assets);
            return;
        }
        drawBootAssetFallback(self.assets_state, self.assets_message);
    }

    fn drawMainMenu(self: *const App) void {
        window_menu.draw(&self.menu, if (self.runtime_assets) |*assets| assets else null, self.rootMenuFlags());
    }

    fn drawPlayGameMenu(self: *const App) void {
        window_menu_panels.drawPlayGame(
            &self.play_game_menu,
            if (self.runtime_assets) |*assets| assets else null,
            self.runtime.status,
            self.runtime.config.player_count,
            self.demo_enabled,
        );
    }

    fn drawQuestsMenu(self: *const App) void {
        window_menu_panels.drawQuests(
            &self.quests_menu,
            if (self.runtime_assets) |*assets| assets else null,
            self.runtime.config,
            self.runtime.status,
            self.demo_enabled,
        );
    }

    fn drawStatisticsMenu(self: *const App) void {
        window_statistics.draw(
            &self.statistics_menu,
            if (self.runtime_assets) |*assets| assets else null,
            self.runtime.config,
            self.runtime.status,
            self.preserve_bugs,
        );
    }

    fn drawModsMenu(self: *const App) void {
        window_misc_panels.drawMods(&self.mods_menu, if (self.runtime_assets) |*assets| assets else null);
    }

    fn drawOtherGamesMenu(self: *const App) void {
        window_misc_panels.drawOtherGames(&self.other_games_menu, if (self.runtime_assets) |*assets| assets else null);
    }

    fn drawNetworkSession(self: *App) void {
        const runtime_assets: ?*const window_assets.RuntimeAssets = if (self.runtime_assets) |*assets| assets else null;
        if (self.drawNetworkLiveScene(runtime_assets)) {
            return;
        }
        window_misc_panels.drawNetwork(&self.network_session, runtime_assets);
    }

    fn drawNetworkLiveScene(self: *App, runtime_assets: ?*const window_assets.RuntimeAssets) bool {
        const session = if (self.network_live_session) |*session| session else return false;
        const runner = session.runnerForLocalInput() orelse return false;
        rl.clearBackground(rl.Color.init(10, 10, 12, 255));

        if (!self.network_live_input_ready) {
            self.network_live_camera = updateGameplayCamera(
                self.network_live_camera,
                &runner.session,
                &self.runtime.config,
            );
        }
        self.ensureNetworkLiveGround(runner);
        const ground: ?*const window_ground.GroundRenderer = if (self.network_live_ground) |*ground| ground else null;
        const transform = window_viewport.viewTransform(
            runner.session.world_size,
            &self.runtime.config,
            state_mod.Vec2.add(self.network_live_camera, runner.session.state.camera_shake_offset),
            .{
                .x = @floatFromInt(rl.getScreenWidth()),
                .y = @floatFromInt(rl.getScreenHeight()),
            },
        );
        const camera = buildWorldCamera(
            runner.session.world_size,
            &self.runtime.config,
            self.network_live_camera,
            runner.session.state.camera_shake_offset,
        );
        const entity_alpha: f32 = 1.0;
        const fx_detail_0 = self.runtime.config.fx_detail_0 != 0;
        const fx_detail_1 = self.runtime.config.fx_detail_1 != 0;
        const fx_detail_2 = self.runtime.config.fx_detail_2 != 0;

        camera.begin();
        drawWorld(runner, runtime_assets, ground);
        drawPlayers(runner, runtime_assets, self.network_live_render_time_s, entity_alpha, false);
        drawCreatures(runner, runtime_assets, entity_alpha, fx_detail_0);
        drawFreezeOverlay(runner, runtime_assets, entity_alpha);
        drawPlayers(runner, runtime_assets, self.network_live_render_time_s, entity_alpha, true);
        drawProjectiles(runner, runtime_assets, self.network_live_render_time_s, entity_alpha, fx_detail_1);
        drawWorldEffects(runner, runtime_assets, entity_alpha, fx_detail_1, fx_detail_2);
        drawBonuses(runner, runtime_assets, self.network_live_render_time_s, entity_alpha);
        camera.end();

        if (runtime_assets) |assets| {
            drawBonusHoverLabels(runner, assets, transform, entity_alpha);
            drawDirectionArrows(runner, assets, &self.runtime.config, transform, entity_alpha);
            drawAimEnhancements(runner, assets, transform, entity_alpha);
        }
        if (self.network_live_last_update) |frame_update| {
            drawLiveRunnerHud(runner, frame_update, &self.network_live_hud_state, runtime_assets);
        }
        self.drawNetworkLiveStatus(runtime_assets);
        return true;
    }

    fn drawNetworkLiveStatus(self: *const App, runtime_assets: ?*const window_assets.RuntimeAssets) void {
        if (self.network_session.status_len == 0) return;
        const assets = runtime_assets orelse return;
        const y = @as(f32, @floatFromInt(rl.getScreenHeight())) - 30.0;
        window_ui.drawSmallText(assets, self.network_session.statusText(), 18.0, y, rl.Color.init(204, 204, 214, 220));
    }

    fn drawGameplay(self: *App) void {
        rl.clearBackground(rl.Color.init(10, 10, 12, 255));

        if (self.gameplay) |*gameplay| {
            const runner = &gameplay.runner;
            const runtime_assets: ?*const window_assets.RuntimeAssets = if (self.runtime_assets) |*loaded_assets| loaded_assets else null;
            if (self.demo_attract_active and self.demo_attract_purchase_active) {
                drawDemoAttractPurchaseInterstitial(runtime_assets, self.demo_attract_elapsed_ms, self.demo_attract_purchase_limit_ms, &self.demo_attract_purchase_ui);
                return;
            }
            const transform = window_viewport.viewTransform(
                runner.session.world_size,
                &self.runtime.config,
                state_mod.Vec2.add(gameplay.camera, runner.session.state.camera_shake_offset),
                .{
                    .x = @floatFromInt(rl.getScreenWidth()),
                    .y = @floatFromInt(rl.getScreenHeight()),
                },
            );
            const entity_alpha: f32 = 1.0;
            const fx_detail_0 = self.runtime.config.fx_detail_0 != 0;
            const fx_detail_1 = self.runtime.config.fx_detail_1 != 0;
            const fx_detail_2 = self.runtime.config.fx_detail_2 != 0;
            const camera = buildWorldCamera(
                runner.session.world_size,
                &self.runtime.config,
                gameplay.camera,
                runner.session.state.camera_shake_offset,
            );

            camera.begin();
            drawWorld(runner, runtime_assets, if (gameplay.ground) |*ground| ground else null);
            drawPlayers(runner, runtime_assets, gameplay.render_time_s, entity_alpha, false);
            drawCreatures(runner, runtime_assets, entity_alpha, fx_detail_0);
            drawFreezeOverlay(runner, runtime_assets, entity_alpha);
            drawPlayers(runner, runtime_assets, gameplay.render_time_s, entity_alpha, true);
            drawProjectiles(runner, runtime_assets, gameplay.render_time_s, entity_alpha, fx_detail_1);
            drawWorldEffects(runner, runtime_assets, entity_alpha, fx_detail_1, fx_detail_2);
            drawBonuses(runner, runtime_assets, gameplay.render_time_s, entity_alpha);
            camera.end();

            if (runtime_assets) |assets| {
                if (runner.session.game_mode == .typo) {
                    drawTypoNameLabels(runner, assets, transform, entity_alpha);
                }
                drawBonusHoverLabels(runner, assets, transform, entity_alpha);
                if (!gameplay.perk_ui.active()) {
                    drawDirectionArrows(runner, assets, &self.runtime.config, transform, entity_alpha);
                    drawAimEnhancements(runner, assets, transform, entity_alpha);
                }
            }

            if (gameplay.perk_ui.active()) {
                if (runtime_assets) |assets| {
                    window_perk_menu.drawMenu(&gameplay.perk_ui, assets, &self.runtime.config, runner);
                }
            } else {
                if (self.demo_attract_active) {
                    drawDemoAttractOverlay(self.demo_attract_elapsed_ms, demoAttractLimitMs(self.demo_attract_current_variant), self.demo_upsell_message_index);
                } else {
                    drawGameplayHud(gameplay, runtime_assets);
                }
                if (runtime_assets) |assets| {
                    if (runner.session.game_mode == .typo) {
                        drawTypoTypingBox(gameplay, assets);
                    } else if (runner.session.game_mode == .tutorial) {
                        drawTutorialOverlay(gameplay, assets);
                    }
                    window_perk_menu.drawPrompt(&gameplay.perk_ui, assets, &self.runtime.config, runner.perkPendingCount());
                }
            }

            if (self.demo_trial_info.visible) {
                if (runtime_assets) |assets| {
                    window_demo_trial.draw(&self.demo_trial_ui, assets, self.demo_trial_info);
                }
            }
        }
    }

    fn drawPause(self: *App) void {
        self.drawGameplay();
        if (self.gameplay) |gameplay| {
            window_pause_menu.draw(&gameplay.pause_menu, if (self.runtime_assets) |*assets| assets else null);
        }
    }

    fn drawResults(self: *const App) void {
        rl.clearBackground(bg_color);
        drawBackdrop();

        if (self.results) |results| {
            if (self.runtime_assets) |*runtime_assets| {
                drawTextureFit(runtime_assets.texture(.ui_menu_panel), rl.Rectangle.init(262.0, 116.0, 756.0, 392.0), colorWithAlpha(rl.Color.white, 0.96));
                switch (results.reason) {
                    .dead => drawTextureFit(runtime_assets.texture(.ui_text_reaper), rl.Rectangle.init(464.0, 136.0, 354.0, 48.0), colorWithAlpha(rl.Color.white, 0.96)),
                    .completed => drawTextureFit(runtime_assets.texture(.ui_text_level_complete), rl.Rectangle.init(406.0, 136.0, 468.0, 48.0), colorWithAlpha(rl.Color.white, 0.96)),
                    .abandoned, .runtime_error => drawSmallTextCentered(runtime_assets, resultsTitle(results.reason), 152.0, HudTextColor.accent),
                }
                drawSmallTextCentered(runtime_assets, resultsSubtitleFor(&results), 196.0, HudTextColor.primary);
                if (isQuestFailedResult(&results)) {
                    drawQuestFailedPreview(runtime_assets, &results);
                } else {
                    drawSmallText(runtime_assets, "TIME", 370.0, 258.0, HudTextColor.dim);
                    drawSmallText(runtime_assets, "XP", 370.0, 286.0, HudTextColor.dim);
                    drawSmallText(runtime_assets, "LEVEL", 370.0, 314.0, HudTextColor.dim);
                    drawSmallText(runtime_assets, "WEAPON", 370.0, 342.0, HudTextColor.dim);
                    drawSmallText(runtime_assets, "HP", 370.0, 370.0, HudTextColor.dim);
                    const elapsed_ms = if (results.quest_final_time != null)
                        questResultsDisplayBreakdown(&results).final_time_ms
                    else
                        @as(i32, @intCast(results.summary.elapsed_ms_sim));
                    var elapsed_buf: [16]u8 = undefined;
                    drawSmallText(runtime_assets, ui_formatting.formatTimeMmSs(&elapsed_buf, elapsed_ms), 510.0, 258.0, HudTextColor.primary);
                    drawSmallTextFmt("{d}", runtime_assets, .{results.summary.player_experience}, 510.0, 286.0, HudTextColor.primary);
                    drawSmallTextFmt("{d}", runtime_assets, .{results.summary.player_level}, 510.0, 314.0, HudTextColor.primary);
                    drawSmallText(runtime_assets, weaponName(results.summary.player_weapon_id, results.run_config.preserve_bugs), 510.0, 342.0, HudTextColor.primary);
                    const player_health = if (results.player_health_count > 0) results.player_health_values[0] else 0.0;
                    drawSmallTextFmt("{d:.1}", runtime_assets, .{player_health}, 510.0, 370.0, HudTextColor.primary);
                    if (results.quest_final_time != null) {
                        const breakdown = questResultsDisplayBreakdown(&results);
                        const base_color = questResultsBreakdownRowColor(&results, 0, false);
                        const life_color = questResultsBreakdownRowColor(&results, 1, false);
                        const perk_color = questResultsBreakdownRowColor(&results, 2, false);
                        const final_color = questResultsBreakdownRowColor(&results, 3, true);
                        drawSmallText(runtime_assets, "BASE", 690.0, 258.0, HudTextColor.dim);
                        drawSmallText(runtime_assets, "LIFE BONUS", 690.0, 286.0, HudTextColor.dim);
                        drawSmallText(runtime_assets, "PERK BONUS", 690.0, 314.0, HudTextColor.dim);
                        drawSmallText(runtime_assets, "FINAL", 690.0, 342.0, HudTextColor.dim);
                        var base_buf: [16]u8 = undefined;
                        var life_buf: [16]u8 = undefined;
                        var perk_buf: [16]u8 = undefined;
                        var final_buf: [16]u8 = undefined;
                        drawSmallText(runtime_assets, ui_formatting.formatTimeMmSs(&base_buf, breakdown.base_time_ms), 846.0, 258.0, base_color);
                        drawSmallTextFmt("-{s}", runtime_assets, .{ui_formatting.formatTimeMmSs(&life_buf, breakdown.life_bonus_ms)}, 846.0, 286.0, life_color);
                        drawSmallTextFmt("-{s}", runtime_assets, .{ui_formatting.formatTimeMmSs(&perk_buf, breakdown.unpicked_perk_bonus_ms)}, 846.0, 314.0, perk_color);
                        drawSmallText(runtime_assets, ui_formatting.formatTimeMmSs(&final_buf, breakdown.final_time_ms), 846.0, 342.0, final_color);
                    }
                    if (!questResultsBreakdownPending(&results)) {
                        drawQuestUnlockResults(runtime_assets, &results);
                    }
                }

                const breakdown_pending = questResultsBreakdownPending(&results);
                if (results.runtime_error) |runtime_error| {
                    drawSmallText(runtime_assets, runtime_error, 330.0, 430.0, rl.Color.orange);
                }
                if (!breakdown_pending and results.highscore != null) {
                    const highscore = results.highscore.?;
                    drawResultsHighscore(runtime_assets, &results, &highscore, resultsNamePrompt(&results));
                } else if (!breakdown_pending and results.score_too_low_for_top100) {
                    drawSmallTextCentered(runtime_assets, "Score too low for top100.", 452.0, HudTextColor.dim);
                }
            }
        }

        const breakdown_pending = if (self.results) |results|
            questResultsBreakdownPending(&results)
        else
            false;
        const prompt_active = if (!breakdown_pending and self.results != null)
            if (self.results.?.highscore) |highscore| highscore.promptActive() else false
        else
            false;
        const buttons = if (breakdown_pending)
            ResultsButtons{ .items = .{
                .{ .label = "", .rect = rl.Rectangle.init(0.0, 0.0, 0.0, 0.0) },
                .{ .label = "", .rect = rl.Rectangle.init(0.0, 0.0, 0.0, 0.0) },
                .{ .label = "", .rect = rl.Rectangle.init(0.0, 0.0, 0.0, 0.0) },
                .{ .label = "", .rect = rl.Rectangle.init(0.0, 0.0, 0.0, 0.0) },
            }, .len = 0 }
        else if (prompt_active and self.results != null)
            resultsHighscoreButtonsFor(&self.results.?)
        else if (self.results) |results|
            resultsButtonsFor(&results)
        else
            ResultsButtons{ .items = .{
                .{ .label = "", .rect = rl.Rectangle.init(0.0, 0.0, 0.0, 0.0) },
                .{ .label = "", .rect = rl.Rectangle.init(0.0, 0.0, 0.0, 0.0) },
                .{ .label = "", .rect = rl.Rectangle.init(0.0, 0.0, 0.0, 0.0) },
                .{ .label = "", .rect = rl.Rectangle.init(0.0, 0.0, 0.0, 0.0) },
            }, .len = 0 };
        for (buttons.items[0..buttons.len], 0..) |button, idx| {
            const mouse_hovered = rl.checkCollisionPointRec(rl.getMousePosition(), button.rect);
            const selected = if (prompt_active)
                if (self.results) |results|
                    if (results.highscore) |highscore| idx == highscore.selection else false
                else
                    false
            else
                idx == self.results_selection;
            window_ui.drawButton(button, selected, mouse_hovered, if (self.runtime_assets) |*assets| assets else null);
        }
    }

    fn drawEndNote(self: *const App) void {
        rl.clearBackground(bg_color);
        drawBackdrop();

        const panel = endNotePanelRect();
        if (self.runtime_assets) |*runtime_assets| {
            drawTextureFit(runtime_assets.texture(.ui_menu_panel), panel, colorWithAlpha(rl.Color.white, 0.96));
            const hardcore = self.runtime.config.hardcore_flag != 0;
            drawSmallText(runtime_assets, if (hardcore) "   Incredible!" else "Congratulations!", panel.x + 214.0, panel.y + 46.0, colorWithAlpha(rl.Color.white, 0.8));

            var body_y = panel.y + 78.0;
            const body_color = colorWithAlpha(rl.Color.white, 0.5);
            for (endNoteBodyLines(hardcore)) |line| {
                drawSmallText(runtime_assets, line, panel.x + 206.0, body_y, body_color);
                body_y += 14.0;
            }
            body_y += 22.0;
            drawSmallText(runtime_assets, "Good luck with your battles, trooper!", panel.x + 206.0, body_y, body_color);
        } else {
            rl.drawRectangleRounded(panel, 0.08, 8, panel_color);
            rl.drawRectangleRoundedLinesEx(panel, 0.08, 8, 2.0, panel_outline);
            const hardcore = self.runtime.config.hardcore_flag != 0;
            rl.drawText(if (hardcore) "Incredible!" else "Congratulations!", @intFromFloat(panel.x + 210.0), @intFromFloat(panel.y + 42.0), 20, text_color);
            var body_y = panel.y + 76.0;
            for (endNoteBodyLines(hardcore)) |line| {
                rl.drawText(line, @intFromFloat(panel.x + 206.0), @intFromFloat(body_y), 14, muted_text);
                body_y += 18.0;
            }
        }

        const buttons = endNoteButtons();
        for (buttons[0..], 0..) |button, idx| {
            const mouse_hovered = rl.checkCollisionPointRec(rl.getMousePosition(), button.rect);
            window_ui.drawButton(button, idx == self.end_note_selection, mouse_hovered, if (self.runtime_assets) |*assets| assets else null);
        }
    }

    fn drawOptions(self: *const App) void {
        if (self.options_back_to == .pause and self.gameplay != null) {
            @constCast(self).drawGameplay();
        }
        window_options.drawOptions(&self.options, if (self.runtime_assets) |*assets| assets else null, self.runtime.config);
    }

    fn drawControls(self: *const App) void {
        if ((self.controls_back_to == .pause or self.options_back_to == .pause) and self.gameplay != null) {
            @constCast(self).drawGameplay();
        }
        window_options.drawControls(&self.controls, if (self.runtime_assets) |*assets| assets else null, self.runtime.config);
    }

    fn liveRunConfig(self: *App, mode: game_ids.GameModeId, quest_level_key: ?i32) live_runner.LiveModeConfig {
        return runConfigForLiveModeWithSeed(mode, quest_level_key, self.takeRunSeed());
    }

    fn takeRunSeed(self: *App) u32 {
        return takeSeedOverride(&self.next_seed_state, &self.next_seed_override);
    }
};

const WindowArgs = struct {
    demo_enabled: bool = false,
    preserve_bugs: bool = false,
    no_intro: bool = false,
    seed: ?u32 = null,
};

pub fn main(init: std.process.Init) !void {
    runtime_paths.useEnviron(init.environ_map);

    const allocator = init.gpa;
    const argv = try init.minimal.args.toSlice(init.arena.allocator());
    const args = try parseWindowArgs(argv);
    var runtime = try app_runtime.DesktopRuntime.init(allocator);

    rl.setConfigFlags(.{
        .fullscreen_mode = runtime.config.windowed_flag == 0,
    });
    rl.initWindow(runtime.windowWidth(window_width), runtime.windowHeight(window_height), "crimson-zig");
    defer rl.closeWindow();
    rl.hideCursor();
    defer rl.showCursor();

    rl.setTargetFPS(60);

    var app = App.init(allocator, runtime, args);
    defer app.deinit();

    while (!rl.windowShouldClose() and !app.quit_requested) {
        const frame_dt = rl.getFrameTime();
        input_codes.inputBeginFrame();
        app.update(frame_dt);

        rl.beginDrawing();
        defer rl.endDrawing();
        app.draw();
    }

    try app.saveAllIfDirty();
}

fn parseWindowArgs(args: []const []const u8) !WindowArgs {
    var parsed: WindowArgs = .{};
    var index: usize = 1;
    while (index < args.len) : (index += 1) {
        const arg = args[index];
        if (std.mem.eql(u8, arg, "--demo")) {
            parsed.demo_enabled = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--preserve-bugs")) {
            parsed.preserve_bugs = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--no-intro")) {
            parsed.no_intro = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--seed")) {
            index += 1;
            if (index >= args.len) return error.InvalidArgs;
            parsed.seed = try parseWindowSeed(args[index]);
            continue;
        }
        if (std.mem.startsWith(u8, arg, "--seed=")) {
            parsed.seed = try parseWindowSeed(arg["--seed=".len..]);
            continue;
        }
        if (std.mem.eql(u8, arg, "--help")) {
            std.debug.print("usage: crimson-zig-window [--demo] [--preserve-bugs] [--no-intro] [--seed N]\n", .{});
            std.process.exit(0);
        }
        return error.InvalidArgs;
    }
    return parsed;
}

fn parseWindowSeed(raw: []const u8) !u32 {
    const value = std.fmt.parseInt(u64, raw, 0) catch return error.InvalidArgs;
    if (value > std.math.maxInt(u32)) return error.InvalidArgs;
    return @intCast(value);
}

fn initialScreenForArgs(args: WindowArgs) Screen {
    return if (args.no_intro) .main_menu else .boot;
}

fn openDemoPurchaseUrl(allocator: std.mem.Allocator) bool {
    _ = allocator;
    const argv: []const []const u8 = switch (builtin.os.tag) {
        .macos => &.{ "open", window_demo_trial.demo_purchase_url },
        .linux => &.{ "xdg-open", window_demo_trial.demo_purchase_url },
        .windows => &.{ "rundll32", "url.dll,FileProtocolHandler", window_demo_trial.demo_purchase_url },
        else => return false,
    };
    const io = std.Io.Threaded.global_single_threaded.io();
    var child = std.process.spawn(io, .{
        .argv = argv,
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .ignore,
    }) catch return false;
    _ = child.wait(io) catch return false;
    return true;
}

fn drawBackdrop() void {
    const width = rl.getScreenWidth();
    const height = rl.getScreenHeight();
    rl.drawRectangleGradientV(0, 0, width, height, rl.Color.init(32, 18, 16, 255), bg_color);
    rl.drawCircle(width - 180, 120, 200.0, rl.Color.init(93, 31, 22, 80));
    rl.drawCircle(160, height - 80, 220.0, rl.Color.init(58, 23, 18, 90));
}

fn drawTextureFit(texture: rl.Texture2D, dest: rl.Rectangle, tint: rl.Color) void {
    const src = rl.Rectangle.init(0.0, 0.0, @floatFromInt(texture.width), @floatFromInt(texture.height));
    rl.drawTexturePro(texture, src, dest, rl.Vector2.zero(), 0.0, tint);
}

fn drawTextureCentered(texture: rl.Texture2D, center: rl.Vector2, width: f32, height: f32, tint: rl.Color) void {
    drawTextureFit(
        texture,
        rl.Rectangle.init(center.x - width * 0.5, center.y - height * 0.5, width, height),
        tint,
    );
}

fn drawTextureCenteredRotated(texture: rl.Texture2D, center: rl.Vector2, width: f32, height: f32, rotation_deg: f32, tint: rl.Color) void {
    const src = rl.Rectangle.init(0.0, 0.0, @floatFromInt(texture.width), @floatFromInt(texture.height));
    const dest = rl.Rectangle.init(center.x, center.y, width, height);
    rl.drawTexturePro(texture, src, dest, rl.Vector2.init(width * 0.5, height * 0.5), rotation_deg, tint);
}

fn drawTextureRegionCenteredRotated(
    texture: rl.Texture2D,
    src_rect: window_atlas.AtlasRect,
    center: rl.Vector2,
    width: f32,
    height: f32,
    rotation_deg: f32,
    tint: rl.Color,
) void {
    const src = rl.Rectangle.init(src_rect.x, src_rect.y, src_rect.width, src_rect.height);
    const dest = rl.Rectangle.init(center.x, center.y, width, height);
    rl.drawTexturePro(texture, src, dest, rl.Vector2.init(width * 0.5, height * 0.5), rotation_deg, tint);
}

fn drawAtlasFrameCenteredRotated(
    texture: rl.Texture2D,
    grid: i32,
    frame: i32,
    center: rl.Vector2,
    scale: f32,
    rotation_rad: f32,
    tint: rl.Color,
) void {
    const src_rect = window_atlas.atlasRect(texture.width, texture.height, grid, frame);
    drawTextureRegionCenteredRotated(
        texture,
        src_rect,
        center,
        src_rect.width * scale,
        src_rect.height * scale,
        radiansToDegrees(rotation_rad),
        tint,
    );
}

fn radiansToDegrees(radians: f32) f32 {
    return radians * (180.0 / std.math.pi);
}

fn vecAdd(a: rl.Vector2, b: rl.Vector2) rl.Vector2 {
    return .{ .x = a.x + b.x, .y = a.y + b.y };
}

fn vecSub(a: rl.Vector2, b: rl.Vector2) rl.Vector2 {
    return .{ .x = a.x - b.x, .y = a.y - b.y };
}

fn vecScale(vec: rl.Vector2, scale: f32) rl.Vector2 {
    return .{ .x = vec.x * scale, .y = vec.y * scale };
}

fn vecLength(vec: rl.Vector2) f32 {
    return std.math.sqrt(vec.x * vec.x + vec.y * vec.y);
}

fn vecNormalizeOr(vec: rl.Vector2, fallback: rl.Vector2) rl.Vector2 {
    const len = vecLength(vec);
    if (!(len > 1e-6)) return fallback;
    return .{ .x = vec.x / len, .y = vec.y / len };
}

fn colorLerp(a: rl.Color, b: rl.Color, t_raw: f32) rl.Color {
    const t = std.math.clamp(t_raw, @as(f32, 0.0), @as(f32, 1.0));
    return .{
        .r = @intFromFloat(@as(f32, @floatFromInt(a.r)) + (@as(f32, @floatFromInt(b.r)) - @as(f32, @floatFromInt(a.r))) * t),
        .g = @intFromFloat(@as(f32, @floatFromInt(a.g)) + (@as(f32, @floatFromInt(b.g)) - @as(f32, @floatFromInt(a.g))) * t),
        .b = @intFromFloat(@as(f32, @floatFromInt(a.b)) + (@as(f32, @floatFromInt(b.b)) - @as(f32, @floatFromInt(a.b))) * t),
        .a = @intFromFloat(@as(f32, @floatFromInt(a.a)) + (@as(f32, @floatFromInt(b.a)) - @as(f32, @floatFromInt(a.a))) * t),
    };
}

fn drawTextureTiled(texture: rl.Texture2D, area: rl.Rectangle, tint: rl.Color) void {
    const tile_width = @as(f32, @floatFromInt(texture.width));
    const tile_height = @as(f32, @floatFromInt(texture.height));
    if (!(tile_width > 0.0 and tile_height > 0.0 and area.width > 0.0 and area.height > 0.0)) return;

    const max_x = area.x + area.width;
    const max_y = area.y + area.height;
    var y = area.y;
    while (y < max_y - 0.001) : (y += tile_height) {
        const draw_height = @min(tile_height, max_y - y);
        var x = area.x;
        while (x < max_x - 0.001) : (x += tile_width) {
            const draw_width = @min(tile_width, max_x - x);
            const src = rl.Rectangle.init(0.0, 0.0, draw_width, draw_height);
            const dest = rl.Rectangle.init(x, y, draw_width, draw_height);
            rl.drawTexturePro(texture, src, dest, rl.Vector2.zero(), 0.0, tint);
        }
    }
}

const ResultsButtons = struct {
    items: [4]UiButton,
    len: usize,
};

const ResultsButtonLabels = struct {
    items: [4][:0]const u8,
    len: usize,
};

fn resultsButtonsFor(results: *const ResultsScreen) ResultsButtons {
    const labels = resultsButtonLabelsFor(results);
    const layout = resultsActionButtonLayout(results, @floatFromInt(rl.getScreenWidth()));
    return .{
        .items = .{
            .{ .label = labels.items[0], .rect = resultsActionButtonRect(labels.items[0], layout, 0) },
            .{ .label = labels.items[1], .rect = resultsActionButtonRect(labels.items[1], layout, 1) },
            .{ .label = labels.items[2], .rect = if (labels.len > 2) resultsActionButtonRect(labels.items[2], layout, 2) else rl.Rectangle.init(0.0, 0.0, 0.0, 0.0) },
            .{ .label = labels.items[3], .rect = if (labels.len > 3) resultsActionButtonRect(labels.items[3], layout, 3) else rl.Rectangle.init(0.0, 0.0, 0.0, 0.0) },
        },
        .len = labels.len,
    };
}

fn resultsButtonLabelsFor(results: *const ResultsScreen) ResultsButtonLabels {
    if (results.run_config.game_mode == .quests) {
        return switch (results.reason) {
            .completed => .{ .items = .{
                questCompletedPrimaryLabel(results.run_config.quest_level_key),
                "Play Again",
                "High scores",
                "Main Menu",
            }, .len = 4 },
            .dead => .{ .items = .{
                "Play Again",
                "Play Another",
                "Main Menu",
                "",
            }, .len = 3 },
            .runtime_error, .abandoned => .{ .items = .{
                "Play Again",
                "Main Menu",
                "",
                "",
            }, .len = 2 },
        };
    }
    return .{ .items = .{
        "Play Again",
        "High scores",
        "Main Menu",
        "",
    }, .len = 3 };
}

fn questCompletedPrimaryLabel(level_key: i32) [:0]const u8 {
    return if (isFinalQuestLevelKey(level_key)) "Show End Note" else "Play Next";
}

const ResultsPanelLayout = struct {
    top_left: rl.Vector2,
    banner_pos: rl.Vector2,
};

const ResultsActionButtonLayout = struct {
    x: f32,
    y: f32,
    step_y: f32 = 32.0,
};

const ResultsHighscorePromptLayout = struct {
    prompt_x: f32,
    prompt_y: f32,
    input_rect: rl.Rectangle,
    saved_x: f32,
    saved_y: f32,
};

fn gameOverResultsPanelLayout(screen_width: f32) ResultsPanelLayout {
    const top_left = rl.Vector2.init(
        -24.0,
        29.0 + window_menu.menuWidescreenYShift(screen_width),
    );
    return .{
        .top_left = top_left,
        .banner_pos = rl.Vector2.init(top_left.x + 214.0, top_left.y + 40.0),
    };
}

fn questResultsPanelLayout(screen_width: f32) ResultsPanelLayout {
    const top_left = rl.Vector2.init(
        -108.0,
        29.0 + window_menu.menuWidescreenYShift(screen_width),
    );
    return .{
        .top_left = top_left,
        .banner_pos = rl.Vector2.init(top_left.x + 202.0, top_left.y + 36.0),
    };
}

fn resultsQualifiesForTop100(results: *const ResultsScreen) bool {
    if (results.highscore != null) return true;
    return !results.score_too_low_for_top100;
}

fn resultsActionButtonLayout(results: *const ResultsScreen, screen_width: f32) ResultsActionButtonLayout {
    const qualifies = resultsQualifiesForTop100(results);
    if (isQuestCompletedResult(results)) {
        const layout = questResultsPanelLayout(screen_width);
        var y = layout.top_left.y + (if (qualifies) @as(f32, 96.0) else 108.0) + 84.0;
        if (results.quest_unlock_weapon_name != null) y += 30.0;
        if (results.quest_unlock_perk_name != null) y += 30.0;
        return .{
            .x = layout.top_left.x + 270.0,
            .y = y + 6.0,
        };
    }

    const layout = gameOverResultsPanelLayout(screen_width);
    return .{
        .x = layout.banner_pos.x + 52.0,
        .y = layout.banner_pos.y + if (qualifies) @as(f32, 210.0) else 208.0,
    };
}

fn resultsActionButtonRect(label: [:0]const u8, layout: ResultsActionButtonLayout, index: usize) rl.Rectangle {
    return rl.Rectangle.init(
        layout.x,
        layout.y + @as(f32, @floatFromInt(index)) * layout.step_y,
        window_ui.buttonWidth(label, true),
        window_ui.button_plate_height,
    );
}

fn resultsHighscoreOkButtonRect(results: *const ResultsScreen, screen_width: f32) rl.Rectangle {
    if (isQuestCompletedResult(results)) {
        const layout = questResultsPanelLayout(screen_width);
        return window_ui.buttonAt("OK", layout.top_left.x + 390.0, layout.top_left.y + 142.0, false).rect;
    }
    const layout = gameOverResultsPanelLayout(screen_width);
    return window_ui.buttonAt("OK", layout.banner_pos.x + 178.0, layout.banner_pos.y + 116.0, false).rect;
}

fn resultsHighscorePromptLayout(results: *const ResultsScreen, screen_width: f32) ResultsHighscorePromptLayout {
    if (isQuestCompletedResult(results)) {
        const layout = questResultsPanelLayout(screen_width);
        const content_x = layout.top_left.x + 220.0;
        return .{
            .prompt_x = content_x + 42.0,
            .prompt_y = layout.top_left.y + 118.0,
            .input_rect = rl.Rectangle.init(content_x, layout.top_left.y + 150.0, 166.0, 18.0),
            .saved_x = content_x + 8.0,
            .saved_y = layout.top_left.y + 118.0,
        };
    }

    const layout = gameOverResultsPanelLayout(screen_width);
    const form_x = layout.banner_pos.x + 8.0;
    const form_y = layout.banner_pos.y + 84.0;
    return .{
        .prompt_x = form_x + 42.0,
        .prompt_y = form_y,
        .input_rect = rl.Rectangle.init(form_x, form_y + 40.0, 166.0, 18.0),
        .saved_x = form_x + 8.0,
        .saved_y = form_y,
    };
}

fn isQuestFailedResult(results: *const ResultsScreen) bool {
    return results.run_config.game_mode == .quests and results.reason == .dead;
}

fn isQuestCompletedResult(results: *const ResultsScreen) bool {
    return results.run_config.game_mode == .quests and results.reason == .completed;
}

fn questCompletedShortcutSelection(results: *const ResultsScreen) ?usize {
    if (!isQuestCompletedResult(results)) return null;
    return questCompletedShortcutSelectionFor(
        rl.isKeyPressed(.escape),
        rl.isKeyPressed(.enter) or rl.isKeyPressed(.kp_enter),
        rl.isKeyPressed(.n),
        rl.isKeyPressed(.h),
    );
}

fn questCompletedShortcutSelectionFor(escape_pressed: bool, enter_pressed: bool, n_pressed: bool, h_pressed: bool) ?usize {
    if (escape_pressed) return 3;
    if (enter_pressed) return 1;
    if (n_pressed) return 0;
    if (h_pressed) return 2;
    return null;
}

fn questFailedShortcutSelection(results: *const ResultsScreen) ?usize {
    if (!isQuestFailedResult(results)) return null;
    if (rl.isKeyPressed(.escape)) return 2;
    if (rl.isKeyPressed(.q)) return 1;
    if (rl.isKeyPressed(.enter) or rl.isKeyPressed(.kp_enter)) return 0;
    return null;
}

fn questFailedMessage(retry_count: i32, preserve_bugs: bool) [:0]const u8 {
    return switch (retry_count) {
        1 => "You didn't make it, do try again.",
        2 => "Third time no good.",
        3 => "No luck this time, have another go?",
        4 => if (preserve_bugs) "Persistence will be rewared." else "Persistence will be rewarded.",
        5 => "Try one more time?",
        else => "Quest failed, try again.",
    };
}

fn resultsSubtitleFor(results: *const ResultsScreen) [:0]const u8 {
    if (isQuestFailedResult(results)) {
        return questFailedMessage(results.run_config.quest_fail_retry_count, results.run_config.preserve_bugs);
    }
    return resultsSubtitle(results.reason);
}

fn questResultsBreakdownPending(results: *const ResultsScreen) bool {
    return results.reason == .completed and results.quest_final_time != null and !results.quest_breakdown_anim.done;
}

fn questResultsDisplayBreakdown(results: *const ResultsScreen) quest_results.QuestFinalTime {
    const target = results.quest_final_time orelse return .{
        .base_time_ms = 0,
        .life_bonus_ms = 0,
        .unpicked_perk_bonus_ms = 0,
        .final_time_ms = 0,
    };
    const anim = results.quest_breakdown_anim;
    if (results.reason != .completed or anim.done) return target;
    return .{
        .base_time_ms = anim.base_time_ms,
        .life_bonus_ms = anim.life_bonus_ms,
        .unpicked_perk_bonus_ms = anim.perkBonusMs(),
        .final_time_ms = anim.final_time_ms,
    };
}

fn questResultsBreakdownRowColor(results: *const ResultsScreen, row: i32, final_row: bool) rl.Color {
    const anim = results.quest_breakdown_anim;
    if (results.reason != .completed or results.quest_final_time == null or anim.done) {
        return if (final_row) HudTextColor.accent else HudTextColor.primary;
    }
    var alpha: f32 = 0.2;
    if (row < anim.step) {
        alpha = 0.4;
    } else if (row == anim.step) {
        alpha = 1.0;
        if (final_row) alpha *= anim.highlightAlpha();
    }
    const base = if (row == anim.step) HudTextColor.accent else HudTextColor.primary;
    return colorWithAlpha(base, alpha);
}

const QuestUnlockDisplayNames = struct {
    weapon_name: ?[]const u8 = null,
    perk_name: ?[]const u8 = null,
};

fn questUnlockDisplayNames(
    level_key: ?i32,
    game_mode: game_ids.GameModeId,
    reason: ResultsReason,
    preserve_bugs: bool,
    violence_disabled: i32,
) QuestUnlockDisplayNames {
    if (game_mode != .quests or reason != .completed) return .{};
    const index = questLevelKeyToIndex(level_key orelse return .{});
    const weapon_name = if (bonuses_runtime.questUnlockWeaponForIndex(index)) |weapon_id|
        game_ids.weaponDisplayName(weapon_id, preserve_bugs)
    else
        null;
    const perk_name = if (runtime_perks.questUnlockPerkForIndex(index)) |perk_id|
        game_ids.perkDisplayName(perk_id, violence_disabled, preserve_bugs)
    else
        null;
    return .{ .weapon_name = weapon_name, .perk_name = perk_name };
}

fn questLevelKeyToIndex(level_key: i32) i32 {
    const major = @divTrunc(level_key, 100);
    const minor = @mod(level_key, 100);
    return (major - 1) * 10 + (minor - 1);
}

fn drawQuestUnlockResults(runtime_assets: *const window_assets.RuntimeAssets, results: *const ResultsScreen) void {
    if (results.run_config.game_mode != .quests or results.reason != .completed) return;
    var y: f32 = 394.0;
    if (results.quest_unlock_weapon_name) |name| {
        drawSmallText(runtime_assets, "WEAPON UNLOCKED", 690.0, y, HudTextColor.dim);
        drawSmallText(runtime_assets, name, 846.0, y, HudTextColor.accent);
        y += 28.0;
    }
    if (results.quest_unlock_perk_name) |name| {
        drawSmallText(runtime_assets, "PERK UNLOCKED", 690.0, y, HudTextColor.dim);
        drawSmallText(runtime_assets, name, 846.0, y, HudTextColor.accent);
    }
}

fn scoreTooLowForTop100(rank_index: usize) bool {
    return rank_index >= persistence.highscores.table_max;
}

fn resultsHighscoreHighlightRank(results: *const ResultsScreen) ?usize {
    if (results.highscore) |highscore| {
        if (highscore.saved) return highscore.highlight_rank;
    }
    return null;
}

fn resultsNamePrompt(results: *const ResultsScreen) [:0]const u8 {
    if (results.run_config.game_mode == .quests and results.run_config.preserve_bugs) {
        return "State your name trooper!";
    }
    return "State your name, trooper!";
}

fn resultsHighscorePathErrorDetail(err: anyerror) []const u8 {
    return switch (err) {
        error.OutOfMemory => "Unable to build high score file path.",
        else => @errorName(err),
    };
}

fn resultsHighscoreSaveErrorDetail(err: anyerror) []const u8 {
    return switch (err) {
        error.AccessDenied => "Unable to save high score: access denied.",
        error.OutOfMemory => "Unable to save high score: out of memory.",
        error.InvalidSize => "High score file has an invalid record size.",
        error.NoSpaceLeft => "Unable to save high score: not enough disk space.",
        else => @errorName(err),
    };
}

fn resultsConfigSaveErrorDetail(err: anyerror) []const u8 {
    return switch (err) {
        error.AccessDenied => "Unable to save config: access denied.",
        error.OutOfMemory => "Unable to save config: out of memory.",
        error.NoSpaceLeft => "Unable to save config: not enough disk space.",
        else => @errorName(err),
    };
}

fn resultsStatusSaveErrorDetail(err: anyerror) []const u8 {
    return switch (err) {
        error.AccessDenied => "Unable to save status: access denied.",
        error.OutOfMemory => "Unable to save status: out of memory.",
        error.NoSpaceLeft => "Unable to save status: not enough disk space.",
        error.InvalidGameCfgChecksum => "Unable to save status: invalid game.cfg checksum.",
        else => @errorName(err),
    };
}

fn assetLoadErrorDetail(err: anyerror) []const u8 {
    return switch (err) {
        error.AccessDenied => "Unable to read runtime assets: access denied.",
        error.FileNotFound => "Runtime asset archive was not found.",
        error.MissingTextureAsset => "Runtime assets are missing a required texture.",
        error.MissingFontWidths => "Runtime assets are missing small font widths.",
        error.InvalidImageDimensions => "Runtime assets contain an image with invalid dimensions.",
        error.UnsupportedTextureFormat => "Runtime assets contain an unsupported texture format.",
        error.UnsupportedMethod => "Runtime asset archive uses an unsupported compression method.",
        error.OutOfMemory => "Unable to load runtime assets: out of memory.",
        else => @errorName(err),
    };
}

fn liveRuntimeErrorDetail(err: anyerror) []const u8 {
    return switch (err) {
        error.InvalidPlayerCount => "Run configuration has an invalid player count.",
        error.InvalidWorldSize => "Run configuration has an invalid world size.",
        error.InvalidTickRate => "Run configuration has an invalid tick rate.",
        error.UnsupportedGameMode => "Run configuration uses an unsupported game mode.",
        error.InvalidQuestSpawnTable => "Quest spawn table is invalid.",
        error.UnsupportedEventKind => "Runtime event kind is not supported in this mode.",
        error.UnsupportedEventPlayerIndex => "Runtime event references an out-of-range player.",
        error.InvalidCaptureEnumValue => "Runtime capture payload contains an invalid enum value.",
        error.InvalidSpawnTemplate => "Runtime spawn payload references an invalid creature template.",
        else => @errorName(err),
    };
}

fn typoSourceErrorDetail(err: anyerror) []const u8 {
    return switch (err) {
        error.AccessDenied => "Unable to load Typ'o'Shooter sources: access denied.",
        error.OutOfMemory => "Unable to load Typ'o'Shooter sources: out of memory.",
        error.InvalidSize => "Typ'o'Shooter high score file has an invalid record size.",
        else => @errorName(err),
    };
}

fn resultsHighscoreButtonsFor(results: *const ResultsScreen) ResultsButtons {
    return resultsHighscoreButtonsForScreen(results, @floatFromInt(rl.getScreenWidth()));
}

fn resultsHighscoreButtonsForScreen(results: *const ResultsScreen, screen_width: f32) ResultsButtons {
    return .{
        .items = .{
            .{ .label = "OK", .rect = resultsHighscoreOkButtonRect(results, screen_width) },
            .{ .label = "", .rect = rl.Rectangle.init(0.0, 0.0, 0.0, 0.0) },
            .{ .label = "", .rect = rl.Rectangle.init(0.0, 0.0, 0.0, 0.0) },
            .{ .label = "", .rect = rl.Rectangle.init(0.0, 0.0, 0.0, 0.0) },
        },
        .len = 1,
    };
}

fn endNotePanelRect() rl.Rectangle {
    return rl.Rectangle.init(-108.0, 29.0, 510.0, 378.0);
}

fn endNoteButtons() [4]UiButton {
    const panel = endNotePanelRect();
    const x = panel.x + 266.0;
    const y = panel.y + 210.0;
    return .{
        window_ui.buttonAt("Survival", x, y, true),
        window_ui.buttonAt("  Rush  ", x, y + 32.0, true),
        window_ui.buttonAt("Typ'o'Shooter", x, y + 64.0, true),
        window_ui.buttonAt("Main Menu", x, y + 96.0, true),
    };
}

fn endNoteBodyLines(hardcore: bool) []const [:0]const u8 {
    return if (hardcore) &.{
        "You've done the thing we all thought was",
        "virtually impossible. To reward your",
        "efforts a new weapon has been unlocked ",
        "for you: Splitter Gun.",
        "",
        "",
    } else &.{
        "You've completed all the levels, but the battle",
        "isn't over yet! With all of the unlocked perks",
        "and weapons your Survival is just a bit easier.",
        "You can also replay the quests in Hardcore.",
        "As an additional reward for your victorious",
        "playing, a completely new and different game",
        "mode is unlocked for you: Typ'o'Shooter.",
    };
}

const NameInputEdits = struct {
    typed: bool = false,
    backspaced: bool = false,
};

fn collectNameInput(highscore: *ResultsHighscoreState) NameInputEdits {
    var edits: NameInputEdits = .{};
    while (true) {
        const codepoint = rl.getCharPressed();
        if (codepoint == 0) break;
        if (codepoint < 0x20 or codepoint > 0xFF) continue;
        const before_len = highscore.input_len;
        highscore.insertChar(@intCast(codepoint));
        if (highscore.input_len > before_len) edits.typed = true;
    }

    if (rl.isKeyPressed(.backspace) or rl.isKeyPressedRepeat(.backspace)) {
        const before_len = highscore.input_len;
        highscore.backspace();
        edits.backspaced = highscore.input_len < before_len;
    }
    if (rl.isKeyPressed(.left)) highscore.moveCaretLeft();
    if (rl.isKeyPressed(.right)) highscore.moveCaretRight();
    if (rl.isKeyPressed(.home)) highscore.moveCaretHome();
    if (rl.isKeyPressed(.end)) highscore.moveCaretEnd();
    return edits;
}

fn uiTypeClickSfxFromRoll(roll: u32) state_mod.SfxId {
    return if ((roll & 1) == 0) .ui_typeclick_01 else .ui_typeclick_02;
}

fn flushNameInputEvents() void {
    while (rl.getCharPressed() != 0) {}
    while (@intFromEnum(rl.getKeyPressed()) > 0) {}
}

fn gameplayControlsHeld(config: *const formats.crimson_cfg.CrimsonCfg) bool {
    return gameplayControlsHeldWithSampler(config, input_codes.RaylibInputSampler{});
}

fn gameplayControlsHeldWithSampler(config: *const formats.crimson_cfg.CrimsonCfg, sampler: anytype) bool {
    const player_count = @as(usize, @intCast(std.math.clamp(config.player_count, @as(u32, 1), @as(u32, 4))));
    for (0..player_count) |idx| {
        const binds = formats.crimson_cfg.playerBindBlock(config, idx);
        const codes = [_]i32{
            binds.move_forward,
            binds.move_backward,
            binds.turn_left,
            binds.turn_right,
            binds.fire,
        };
        for (codes) |code| {
            if (code == formats.crimson_cfg.keybind_unbound_code) continue;
            if (sampler.codeIsDown(code, @intCast(idx))) return true;
        }
    }

    for (single_player_alt_move_codes) |code| {
        if (sampler.codeIsDown(code, 0)) return true;
    }
    return false;
}

fn collectTypoDictionaryWords(
    allocator: std.mem.Allocator,
    path: []const u8,
    out: *std.ArrayList([]const u8),
) !?[]u8 {
    const io = std.Io.Threaded.global_single_threaded.io();
    const bytes = std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .unlimited) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    errdefer allocator.free(bytes);

    var seen = std.StringHashMap(void).init(allocator);
    defer seen.deinit();

    var lines = std.mem.splitScalar(u8, bytes, '\n');
    while (lines.next()) |raw_line| {
        const comment_cut = std.mem.indexOfScalar(u8, raw_line, '#') orelse raw_line.len;
        const text = std.mem.trim(u8, raw_line[0..comment_cut], &std.ascii.whitespace);
        if (text.len == 0 or text.len >= typo_names.name_max_chars) continue;
        const gop = try seen.getOrPut(text);
        if (gop.found_existing) continue;
        gop.value_ptr.* = {};
        try out.append(allocator, text);
    }

    return bytes;
}

fn isTypoHighscoreNameChar(ch: u8) bool {
    return std.ascii.isAlphabetic(ch) or ch == '.';
}

fn collectTypoHighscoreNames(
    allocator: std.mem.Allocator,
    base_dir: []const u8,
    out: *std.ArrayList([]const u8),
) !void {
    const score_path = try persistence.highscores.scoresPathForMode(
        allocator,
        base_dir,
        @intFromEnum(game_ids.GameModeId.typo),
        .{},
    );
    defer allocator.free(score_path);

    const table = try persistence.highscores.readHighscoreTable(
        allocator,
        score_path,
        @intFromEnum(game_ids.GameModeId.typo),
    );
    defer table.deinit(allocator);

    var seen = std.StringHashMap(void).init(allocator);
    defer seen.deinit();

    for (table.items) |record| {
        const name = record.name();
        if (name.len == 0) continue;
        var valid = true;
        for (name) |ch| {
            if (!isTypoHighscoreNameChar(ch)) {
                valid = false;
                break;
            }
        }
        if (!valid) continue;
        const gop = try seen.getOrPut(name);
        if (gop.found_existing) continue;
        gop.value_ptr.* = {};
        try out.append(allocator, name);
    }
}

fn loadTypoSourcesIntoState(
    allocator: std.mem.Allocator,
    base_dir: []const u8,
    typo: *state_mod.GameplayState,
) !void {
    var dictionary_words: std.ArrayList([]const u8) = .empty;
    defer dictionary_words.deinit(allocator);
    var highscore_names: std.ArrayList([]const u8) = .empty;
    defer highscore_names.deinit(allocator);

    const dictionary_path = try std.fs.path.join(allocator, &.{ base_dir, "typo_dictionary.txt" });
    defer allocator.free(dictionary_path);
    const dictionary_backing = try collectTypoDictionaryWords(allocator, dictionary_path, &dictionary_words);
    defer if (dictionary_backing) |bytes| allocator.free(bytes);

    try collectTypoHighscoreNames(allocator, base_dir, &highscore_names);
    typo.typo.reset(dictionary_words.items, highscore_names.items);
}

fn buildWorldCamera(
    world_size: f32,
    config: *const formats.crimson_cfg.CrimsonCfg,
    camera_pos: state_mod.Vec2,
    shake_offset: state_mod.Vec2,
) rl.Camera2D {
    const transform = window_viewport.viewTransform(
        world_size,
        config,
        state_mod.Vec2.add(camera_pos, shake_offset),
        .{
            .x = @floatFromInt(rl.getScreenWidth()),
            .y = @floatFromInt(rl.getScreenHeight()),
        },
    );
    return .{
        .offset = rl.Vector2.zero(),
        .target = rl.Vector2.init(-transform.camera.x, -transform.camera.y),
        .rotation = 0.0,
        .zoom = window_viewport.viewScaleAvg(transform.view_scale),
    };
}

fn updateGameplayCamera(
    current_camera: state_mod.Vec2,
    session: *const runtime_session.DeterministicSession,
    config: *const formats.crimson_cfg.CrimsonCfg,
) state_mod.Vec2 {
    const players = session.playersConst();
    if (players.len == 0) return current_camera;

    const screen_size = window_viewport.cameraScreenSize(
        session.world_size,
        config,
        @floatFromInt(rl.getScreenWidth()),
        @floatFromInt(rl.getScreenHeight()),
    );

    var alive_count: usize = 0;
    var focus: state_mod.Vec2 = .{};
    for (players) |player| {
        if (!(player.health > 0.0)) continue;
        focus = state_mod.Vec2.add(focus, player.pos);
        alive_count += 1;
    }

    var camera = current_camera;
    if (alive_count > 0) {
        const inv_alive = 1.0 / @as(f32, @floatFromInt(alive_count));
        focus = focus.mul(inv_alive);
        camera = state_mod.Vec2.sub(screen_size.mul(0.5), focus);
    }

    return window_viewport.clampCamera(session.world_size, camera, screen_size);
}

fn collectGameplayInput(
    interpreter: *local_input.LocalInputInterpreter,
    runner: *live_runner.LiveRunner,
    camera: rl.Camera2D,
    runtime: *const app_runtime.DesktopRuntime,
    frame_dt: f32,
) live_runner.FrameInput {
    const mouse_world = rl.getScreenToWorld2D(rl.getMousePosition(), camera);
    const players = runner.session.playersConst();
    if (players.len == 0) return .{};
    const screen_center: state_mod.Vec2 = .{
        .x = @as(f32, @floatFromInt(rl.getScreenWidth())) * 0.5,
        .y = @as(f32, @floatFromInt(rl.getScreenHeight())) * 0.5,
    };

    var frame_input: live_runner.FrameInput = .{};
    const input_count = @min(players.len, state_mod.max_players);
    const sampler: input_codes.RaylibInputSampler = .{};
    for (players[0..input_count], 0..) |*player, idx| {
        frame_input.players[idx] = interpreter.buildPlayerInput(
            sampler,
            idx,
            players.len,
            player,
            &runtime.config,
            .{
                .x = rl.getMousePosition().x,
                .y = rl.getMousePosition().y,
            },
            .{
                .x = mouse_world.x,
                .y = mouse_world.y,
            },
            screen_center,
            frame_dt,
            runner.session.creatures.entries[0..],
        );
    }
    frame_input.player_count = input_count;
    frame_input.player = frame_input.players[0];

    if (runner.session.game_mode == .typo) {
        frame_input.typo_submit = rl.isKeyPressed(.enter) or rl.isKeyPressed(.kp_enter);
        frame_input.typo_backspace = rl.isKeyPressed(.backspace) or rl.isKeyPressedRepeat(.backspace);
        if (!frame_input.typo_backspace) {
            const codepoint = rl.getCharPressed();
            if (codepoint >= 0x20 and codepoint <= 0xFF and codepoint != 13 and codepoint != 8) {
                frame_input.typo_char = @intCast(codepoint);
            }
        }
    }

    return frame_input;
}

fn collectDemoAttractInput(
    interpreter: *local_input.LocalInputInterpreter,
    runner: *live_runner.LiveRunner,
    camera: rl.Camera2D,
    runtime: *const app_runtime.DesktopRuntime,
    frame_dt: f32,
) live_runner.FrameInput {
    var demo_config = runtime.config;
    const players = runner.session.playersConst();
    const input_count = @min(players.len, state_mod.max_players);
    for (0..input_count) |idx| {
        formats.crimson_cfg.setPlayerMovement(&demo_config, idx, @intCast(local_input.movement_control_computer));
        formats.crimson_cfg.setPlayerAimScheme(&demo_config, idx, @intCast(local_input.aim_scheme_computer));
    }

    const mouse_world = rl.getScreenToWorld2D(rl.getMousePosition(), camera);
    const screen_center: state_mod.Vec2 = .{
        .x = @as(f32, @floatFromInt(rl.getScreenWidth())) * 0.5,
        .y = @as(f32, @floatFromInt(rl.getScreenHeight())) * 0.5,
    };
    const sampler: input_codes.RaylibInputSampler = .{};
    var frame_input: live_runner.FrameInput = .{};
    for (players[0..input_count], 0..) |*player, idx| {
        frame_input.players[idx] = interpreter.buildPlayerInput(
            sampler,
            idx,
            players.len,
            player,
            &demo_config,
            .{
                .x = rl.getMousePosition().x,
                .y = rl.getMousePosition().y,
            },
            .{
                .x = mouse_world.x,
                .y = mouse_world.y,
            },
            screen_center,
            frame_dt,
            runner.session.creatures.entries[0..],
        );
    }
    frame_input.player_count = input_count;
    frame_input.player = frame_input.players[0];
    return frame_input;
}

fn demoAttractInactiveAction() DemoAttractInactiveAction {
    const purchase_key = rl.isKeyPressed(.escape) or rl.isKeyPressed(.space);
    const left_click = rl.isMouseButtonPressed(.left);
    const right_click = rl.isMouseButtonPressed(.right);
    const middle_click = rl.isMouseButtonPressed(.middle);
    return demoAttractInactiveActionFor(
        rl.getKeyPressed() != .null,
        purchase_key,
        left_click,
        right_click,
        middle_click,
    );
}

fn demoAttractInactiveActionFor(
    any_key: bool,
    purchase_key: bool,
    left_click: bool,
    right_click: bool,
    middle_click: bool,
) DemoAttractInactiveAction {
    if (purchase_key or left_click) return .purchase;
    if (any_key or right_click or middle_click) return .close;
    return .none;
}

fn demoAttractLimitMs(variant_index: i32) i32 {
    return switch (@mod(variant_index, demo_attract_variant_count)) {
        1, 2 => 5_000,
        5 => 10_000,
        else => demo_attract_limit_ms,
    };
}

fn demoAttractPlayerCount(variant_index: i32) i32 {
    return switch (@mod(variant_index, demo_attract_variant_count)) {
        0, 1, 4 => 2,
        else => 1,
    };
}

fn demoAttractPurchaseActive(variant_index: i32) bool {
    return @mod(variant_index, demo_attract_variant_count) == 5;
}

fn updateDemoAttractPurchaseInterstitial(state: *DemoAttractPurchaseState, dt_ms: i32) DemoAttractPurchaseAction {
    state.cursor_pulse_time += @as(f32, @floatFromInt(@max(dt_ms, 0))) * 0.001 * 1.1;
    const buttons = demoAttractPurchaseButtons();
    window_ui.updateSelectionFromPointer(&state.selection, buttons[0..]);
    if (rl.isKeyPressed(.left) or rl.isKeyPressed(.a)) {
        state.selection = if (state.selection == 0) buttons.len - 1 else state.selection - 1;
    }
    if (rl.isKeyPressed(.right) or rl.isKeyPressed(.d)) {
        state.selection = (state.selection + 1) % buttons.len;
    }
    return demoAttractPurchaseActionFor(
        state.selection,
        window_ui.buttonActivated(buttons[0..], state.selection),
        rl.isKeyPressed(.escape),
    );
}

fn demoAttractPurchaseActionFor(selection: usize, activated: bool, canceled: bool) DemoAttractPurchaseAction {
    if (canceled) return .maybe_later;
    if (!activated) return .none;
    return if (selection == 0) .purchase else .maybe_later;
}

fn demoAttractPurchaseButtons() [2]UiButton {
    return demoAttractPurchaseButtonsForScreen(
        @floatFromInt(rl.getScreenWidth()),
        @floatFromInt(rl.getScreenHeight()),
    );
}

fn demoAttractPurchaseButtonsForScreen(screen_w: f32, screen_h: f32) [2]UiButton {
    const button_w: f32 = 145.0;
    const x = screen_w * 0.5 + 128.0;
    const y = screen_h * 0.5 + 152.0 + demoAttractPurchaseWideShift(screen_w) * 0.3;
    return .{
        .{ .label = "Purchase", .rect = rl.Rectangle.init(x, y, button_w, window_ui.button_plate_height) },
        .{ .label = "Maybe later", .rect = rl.Rectangle.init(x, y + 40.0, button_w, window_ui.button_plate_height) },
    };
}

fn demoAttractPurchaseWideShift(screen_w: f32) f32 {
    if (screen_w == 800.0) return 64.0;
    if (screen_w == 1024.0) return 128.0;
    return 0.0;
}

fn nextDemoAttractVariant(variant_index: i32) i32 {
    return @mod(variant_index + 1, demo_attract_variant_count);
}

fn nextDemoUpsellMessageIndex(index: usize) usize {
    return (index + 1) % demo_upsell_messages.len;
}

fn setupDemoAttractVariant(runner: *live_runner.LiveRunner, variant_index_raw: i32) !void {
    const variant_index = @mod(variant_index_raw, demo_attract_variant_count);
    runner.session.creatures.reset();
    runner.session.bonuses.reset();
    runner.session.state.bonuses.weapon_power_up = 0.0;

    switch (variant_index) {
        0, 4 => try setupDemoAttractVariant0(runner),
        1 => try setupDemoAttractVariant1(runner),
        2 => try setupDemoAttractVariant2(runner),
        3 => try setupDemoAttractVariant3(runner),
        5 => {},
        else => unreachable,
    }
}

fn setupDemoAttractPlayers(runner: *live_runner.LiveRunner, positions: []const state_mod.Vec2, weapon_id: game_ids.WeaponId) void {
    const players = runner.session.players();
    for (players, 0..) |*player, idx| {
        if (idx < positions.len) {
            player.pos = positions[idx];
            player.aim = positions[idx];
        }
        player.weapon = weaponSlotForDemoAttract(weapon_id);
    }
}

fn setupDemoAttractVariant0(runner: *live_runner.LiveRunner) !void {
    const positions = [_]state_mod.Vec2{
        .{ .x = 448.0, .y = 384.0 },
        .{ .x = 546.0, .y = 654.0 },
    };
    setupDemoAttractPlayers(runner, positions[0..], .plasma_minigun);
    var y: i32 = 256;
    var row: i32 = 0;
    while (y < 1696) : ({
        y += 80;
        row += 1;
    }) {
        const col = @mod(row, 2);
        try spawnDemoAttractCreature(runner, .spider_sp1_ai7_timer_38, .{ .x = @floatFromInt((col + 2) * 64), .y = @floatFromInt(y) }, true);
        try spawnDemoAttractCreature(runner, .spider_sp1_ai7_timer_38, .{ .x = @floatFromInt(col * 64 + 798), .y = @floatFromInt(y) }, true);
    }
}

fn setupDemoAttractVariant1(runner: *live_runner.LiveRunner) !void {
    const positions = [_]state_mod.Vec2{
        .{ .x = 490.0, .y = 448.0 },
        .{ .x = 480.0, .y = 576.0 },
    };
    setupDemoAttractPlayers(runner, positions[0..], .submachine_gun);
    runner.terrain_setup = runtime_bootstrap.advanceExplicitTerrain(&runner.session.state.rng, .{ 2, 3, 2 }, 1024, 1024);
    runner.session.state.bonuses.weapon_power_up = 15.0;
    for (0..20) |idx| {
        const x = @as(f32, @floatFromInt(runner.session.state.rng.randTagged(rng_callers.demo_setup_variant_1_spider_sp1_x) % 200)) + 32.0;
        const y = @as(f32, @floatFromInt(runner.session.state.rng.randTagged(rng_callers.demo_setup_variant_1_spider_sp1_y) % 899)) + 64.0;
        try spawnDemoAttractCreature(runner, .spider_sp1_random_green_34, .{ .x = x, .y = y }, true);
        if (@mod(idx, 3) != 0) {
            const x2 = @as(f32, @floatFromInt(runner.session.state.rng.randTagged(rng_callers.demo_setup_variant_1_spider_sp2_x) % 30)) + 32.0;
            const y2 = @as(f32, @floatFromInt(runner.session.state.rng.randTagged(rng_callers.demo_setup_variant_1_spider_sp2_y) % 899)) + 64.0;
            try spawnDemoAttractCreature(runner, .spider_sp2_random_35, .{ .x = x2, .y = y2 }, true);
        }
    }
}

fn setupDemoAttractVariant2(runner: *live_runner.LiveRunner) !void {
    const positions = [_]state_mod.Vec2{.{ .x = 512.0, .y = 512.0 }};
    setupDemoAttractPlayers(runner, positions[0..], .ion_rifle);
    var y: i32 = 128;
    var row: i32 = 0;
    while (y < 848) : ({
        y += 60;
        row += 1;
    }) {
        const col = @mod(row, 2);
        try spawnDemoAttractCreature(runner, .zombie_random_41, .{ .x = @floatFromInt(col * 64 + 32), .y = @floatFromInt(y) }, true);
        try spawnDemoAttractCreature(runner, .zombie_random_41, .{ .x = @floatFromInt((col + 2) * 64), .y = @floatFromInt(y) }, true);
        try spawnDemoAttractCreature(runner, .zombie_random_41, .{ .x = @floatFromInt(col * 64 - 64), .y = @floatFromInt(y) }, true);
        try spawnDemoAttractCreature(runner, .zombie_random_41, .{ .x = @floatFromInt((col + 12) * 64), .y = @floatFromInt(y) }, true);
    }
}

fn setupDemoAttractVariant3(runner: *live_runner.LiveRunner) !void {
    const positions = [_]state_mod.Vec2{.{ .x = 512.0, .y = 512.0 }};
    setupDemoAttractPlayers(runner, positions[0..], .rocket_minigun);
    runner.terrain_setup = runtime_bootstrap.advanceExplicitTerrain(&runner.session.state.rng, runtime_bootstrap.terrainSlotsForQuestLevelKey(101).?, 1024, 1024);
    for (0..20) |idx| {
        const x = @as(f32, @floatFromInt(runner.session.state.rng.randTagged(rng_callers.demo_setup_variant_3_alien_big_x) % 200)) + 32.0;
        const y = @as(f32, @floatFromInt(runner.session.state.rng.randTagged(rng_callers.demo_setup_variant_3_alien_big_y) % 899)) + 64.0;
        try spawnDemoAttractCreature(runner, .alien_const_green_24, .{ .x = x, .y = y }, false);
        if (@mod(idx, 3) != 0) {
            const x2 = @as(f32, @floatFromInt(runner.session.state.rng.randTagged(rng_callers.demo_setup_variant_3_alien_small_x) % 30)) + 32.0;
            const y2 = @as(f32, @floatFromInt(runner.session.state.rng.randTagged(rng_callers.demo_setup_variant_3_alien_small_y) % 899)) + 64.0;
            try spawnDemoAttractCreature(runner, .alien_const_green_small_25, .{ .x = x2, .y = y2 }, false);
        }
    }
}

fn spawnDemoAttractCreature(runner: *live_runner.LiveRunner, spawn_id: spawn_mod.SpawnId, pos: state_mod.Vec2, random_heading: bool) !void {
    const heading = if (random_heading) demoAttractRandomHeading(&runner.session.state.rng) else 0.0;
    try runner.session.creatures.spawnTemplateCallWithRuntimeContext(
        .{
            .template_id = @intFromEnum(spawn_id),
            .pos = .{ .x = pos.x, .y = pos.y },
            .heading = heading,
        },
        &runner.session.state.rng,
        &runner.session.state,
        runner.session.world_size,
    );
}

fn demoAttractRandomHeading(rng: *spawn_mod.Crand) f32 {
    return @as(f32, @floatFromInt(rng.randTagged(rng_callers.creature_spawn_template_random_heading) % 628)) * 0.01;
}

fn weaponSlotForDemoAttract(weapon_id: game_ids.WeaponId) state_mod.WeaponSlotState {
    const stats = weapon_data.weapon_stats.get(weapon_id);
    return .{
        .weapon_id = weapon_id,
        .clip_size = stats.clip_size,
        .ammo = @floatFromInt(@max(0, stats.clip_size)),
    };
}

fn collectPlayerHealthValues(
    out: *[state_mod.max_players]f32,
    session: *const runtime_session.DeterministicSession,
) usize {
    var count: usize = 0;
    for (session.playersConst()) |player| {
        if (count >= out.len) break;
        out[count] = player.health;
        count += 1;
    }
    return count;
}

fn boolAxis(negative: bool, positive: bool) f32 {
    if (negative == positive) return 0.0;
    return if (positive) 1.0 else -1.0;
}

fn statusWeaponUsageCounts(status: formats.game_cfg.Status) [state_mod.weapon_count_size]u32 {
    var counts: [state_mod.weapon_count_size]u32 = [_]u32{0} ** state_mod.weapon_count_size;
    for (0..@min(counts.len, status.weapon_usage_counts.len)) |idx| {
        counts[idx] = status.weapon_usage_counts[idx];
    }
    return counts;
}

test "boolAxis returns signed unit values without overflow" {
    try std.testing.expectEqual(@as(f32, -1.0), boolAxis(true, false));
    try std.testing.expectEqual(@as(f32, 0.0), boolAxis(false, false));
    try std.testing.expectEqual(@as(f32, 0.0), boolAxis(true, true));
    try std.testing.expectEqual(@as(f32, 1.0), boolAxis(false, true));
}

test "window args parse demo and no intro flags" {
    const args = try parseWindowArgs(&.{ "crimson-zig-window", "--demo", "--preserve-bugs", "--no-intro" });
    try std.testing.expect(args.demo_enabled);
    try std.testing.expect(args.preserve_bugs);
    try std.testing.expect(args.no_intro);
    try std.testing.expectEqual(Screen.main_menu, initialScreenForArgs(args));
}

test "window args parse seed flag" {
    const separate = try parseWindowArgs(&.{ "crimson-zig-window", "--seed", "123" });
    try std.testing.expectEqual(@as(?u32, 123), separate.seed);

    const joined = try parseWindowArgs(&.{ "crimson-zig-window", "--seed=0x1234" });
    try std.testing.expectEqual(@as(?u32, 0x1234), joined.seed);
}

test "window args reject invalid seed" {
    try std.testing.expectError(error.InvalidArgs, parseWindowArgs(&.{ "crimson-zig-window", "--seed" }));
    try std.testing.expectError(error.InvalidArgs, parseWindowArgs(&.{ "crimson-zig-window", "--seed", "nope" }));
    try std.testing.expectError(error.InvalidArgs, parseWindowArgs(&.{ "crimson-zig-window", "--seed", "0x100000000" }));
}

test "window args reject unknown flags" {
    try std.testing.expectError(error.InvalidArgs, parseWindowArgs(&.{ "crimson-zig-window", "--wat" }));
}

test "seed override is consumed before generated seeds" {
    var seed_state: u32 = 0xC0FFEE;
    var override: ?u32 = 12345;

    try std.testing.expectEqual(@as(u32, 12345), takeSeedOverride(&seed_state, &override));
    try std.testing.expectEqual(@as(?u32, null), override);
    try std.testing.expectEqual(nextRunSeedFromState(0xC0FFEE), takeSeedOverride(&seed_state, &override));
}

test "zero seed override normalizes to nonzero" {
    var seed_state: u32 = 0xC0FFEE;
    var override: ?u32 = 0;

    try std.testing.expectEqual(@as(u32, 1), takeSeedOverride(&seed_state, &override));
    try std.testing.expectEqual(@as(u32, 0xC0FFEE), seed_state);
}

test "results high score type click follows native random bit" {
    try std.testing.expectEqual(state_mod.SfxId.ui_typeclick_01, uiTypeClickSfxFromRoll(0));
    try std.testing.expectEqual(state_mod.SfxId.ui_typeclick_02, uiTypeClickSfxFromRoll(1));
    try std.testing.expectEqual(state_mod.SfxId.ui_typeclick_01, uiTypeClickSfxFromRoll(2));
}

test "quest failed messages match retry count" {
    try std.testing.expectEqualStrings("Quest failed, try again.", questFailedMessage(0, false));
    try std.testing.expectEqualStrings("You didn't make it, do try again.", questFailedMessage(1, false));
    try std.testing.expectEqualStrings("Third time no good.", questFailedMessage(2, false));
    try std.testing.expectEqualStrings("No luck this time, have another go?", questFailedMessage(3, false));
    try std.testing.expectEqualStrings("Persistence will be rewarded.", questFailedMessage(4, false));
    try std.testing.expectEqualStrings("Persistence will be rewared.", questFailedMessage(4, true));
    try std.testing.expectEqualStrings("Try one more time?", questFailedMessage(5, false));
    try std.testing.expectEqualStrings("Quest failed, try again.", questFailedMessage(6, false));
}

test "quest failed result uses retry subtitle" {
    const results: ResultsScreen = .{
        .reason = .dead,
        .run_config = .{
            .game_mode = .quests,
            .quest_fail_retry_count = 3,
        },
        .summary = undefined,
    };
    try std.testing.expectEqualStrings("No luck this time, have another go?", resultsSubtitleFor(&results));
}

test "quest runtime error result does not expose mismatched high score button" {
    const results: ResultsScreen = .{
        .reason = .runtime_error,
        .run_config = .{
            .game_mode = .quests,
        },
        .summary = undefined,
    };
    const labels = resultsButtonLabelsFor(&results);
    try std.testing.expectEqual(@as(usize, 2), labels.len);
    try std.testing.expectEqualStrings("Play Again", labels.items[0]);
    try std.testing.expectEqualStrings("Main Menu", labels.items[1]);
}

test "result action labels match native casing" {
    const survival_results: ResultsScreen = .{
        .reason = .dead,
        .run_config = .{ .game_mode = .survival },
        .summary = undefined,
    };
    const survival_labels = resultsButtonLabelsFor(&survival_results);
    try std.testing.expectEqualStrings("Play Again", survival_labels.items[0]);
    try std.testing.expectEqualStrings("High scores", survival_labels.items[1]);
    try std.testing.expectEqualStrings("Main Menu", survival_labels.items[2]);

    const quest_completed_results: ResultsScreen = .{
        .reason = .completed,
        .run_config = .{
            .game_mode = .quests,
            .quest_level_key = 109,
        },
        .summary = undefined,
    };
    const quest_labels = resultsButtonLabelsFor(&quest_completed_results);
    try std.testing.expectEqualStrings("Play Next", quest_labels.items[0]);
    try std.testing.expectEqualStrings("Play Again", quest_labels.items[1]);
    try std.testing.expectEqualStrings("High scores", quest_labels.items[2]);
    try std.testing.expectEqualStrings("Main Menu", quest_labels.items[3]);
}

test "quest completed shortcuts match native result actions" {
    try std.testing.expectEqual(@as(?usize, 3), questCompletedShortcutSelectionFor(true, false, false, false));
    try std.testing.expectEqual(@as(?usize, 1), questCompletedShortcutSelectionFor(false, true, false, false));
    try std.testing.expectEqual(@as(?usize, 0), questCompletedShortcutSelectionFor(false, false, true, false));
    try std.testing.expectEqual(@as(?usize, 2), questCompletedShortcutSelectionFor(false, false, false, true));
    try std.testing.expectEqual(@as(?usize, null), questCompletedShortcutSelectionFor(false, false, false, false));
}

test "game over result action buttons use native banner anchor" {
    const results: ResultsScreen = .{
        .reason = .dead,
        .run_config = .{ .game_mode = .survival },
        .summary = undefined,
        .highscore = .{
            .record = persistence.highscores.HighScoreRecord.blank(),
            .rank_index = 0,
        },
    };
    const layout = resultsActionButtonLayout(&results, 640.0);
    try std.testing.expectApproxEqAbs(@as(f32, 242.0), layout.x, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 279.0), layout.y, 1e-6);

    const first = resultsActionButtonRect("Play Again", layout, 0);
    const second = resultsActionButtonRect("High scores", layout, 1);
    try std.testing.expectApproxEqAbs(@as(f32, 242.0), first.x, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 279.0), first.y, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 311.0), second.y, 1e-6);
}

test "quest completed result action buttons use native score card anchor" {
    const results: ResultsScreen = .{
        .reason = .completed,
        .run_config = .{
            .game_mode = .quests,
            .quest_level_key = 109,
        },
        .summary = undefined,
        .highscore = .{
            .record = persistence.highscores.HighScoreRecord.blank(),
            .rank_index = 0,
        },
    };
    const layout = resultsActionButtonLayout(&results, 640.0);
    try std.testing.expectApproxEqAbs(@as(f32, 162.0), layout.x, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 215.0), layout.y, 1e-6);

    const labels = resultsButtonLabelsFor(&results);
    const third = resultsActionButtonRect(labels.items[2], layout, 2);
    try std.testing.expectEqualStrings("High scores", labels.items[2]);
    try std.testing.expectApproxEqAbs(@as(f32, 279.0), third.y, 1e-6);
}

test "quest completed result action buttons move below unlock lines" {
    const results: ResultsScreen = .{
        .reason = .completed,
        .run_config = .{
            .game_mode = .quests,
            .quest_level_key = 109,
        },
        .summary = undefined,
        .quest_unlock_weapon_name = "Plasma Minigun",
        .quest_unlock_perk_name = "Fastloader",
    };
    const layout = resultsActionButtonLayout(&results, 640.0);
    try std.testing.expectApproxEqAbs(@as(f32, 162.0), layout.x, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 275.0), layout.y, 1e-6);
}

test "results high score prompt uses native ok submit button" {
    const results: ResultsScreen = .{
        .reason = .dead,
        .run_config = .{ .game_mode = .survival },
        .summary = undefined,
        .highscore = .{
            .record = persistence.highscores.HighScoreRecord.blank(),
            .rank_index = 0,
        },
    };
    const buttons = resultsHighscoreButtonsForScreen(&results, 640.0);

    try std.testing.expectEqual(@as(usize, 1), buttons.len);
    try std.testing.expectEqualStrings("OK", buttons.items[0].label);
    try std.testing.expectApproxEqAbs(@as(f32, 368.0), buttons.items[0].rect.x, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 185.0), buttons.items[0].rect.y, 1e-6);

    const prompt = resultsHighscorePromptLayout(&results, 640.0);
    try std.testing.expectApproxEqAbs(@as(f32, 240.0), prompt.prompt_x, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 153.0), prompt.prompt_y, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 198.0), prompt.input_rect.x, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 193.0), prompt.input_rect.y, 1e-6);
}

test "quest results high score prompt uses native ok submit button" {
    const results: ResultsScreen = .{
        .reason = .completed,
        .run_config = .{
            .game_mode = .quests,
            .quest_level_key = 109,
        },
        .summary = undefined,
        .highscore = .{
            .record = persistence.highscores.HighScoreRecord.blank(),
            .rank_index = 0,
        },
    };
    const buttons = resultsHighscoreButtonsForScreen(&results, 640.0);

    try std.testing.expectEqual(@as(usize, 1), buttons.len);
    try std.testing.expectEqualStrings("OK", buttons.items[0].label);
    try std.testing.expectApproxEqAbs(@as(f32, 282.0), buttons.items[0].rect.x, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 171.0), buttons.items[0].rect.y, 1e-6);

    const prompt = resultsHighscorePromptLayout(&results, 640.0);
    try std.testing.expectApproxEqAbs(@as(f32, 154.0), prompt.prompt_x, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 147.0), prompt.prompt_y, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 112.0), prompt.input_rect.x, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 179.0), prompt.input_rect.y, 1e-6);
}

test "results high score save errors use user-facing details" {
    try std.testing.expectEqualStrings("Unable to build high score file path.", resultsHighscorePathErrorDetail(error.OutOfMemory));
    try std.testing.expectEqualStrings("Unable to save high score: access denied.", resultsHighscoreSaveErrorDetail(error.AccessDenied));
    try std.testing.expectEqualStrings("High score file has an invalid record size.", resultsHighscoreSaveErrorDetail(error.InvalidSize));
    try std.testing.expectEqualStrings("Unable to save config: not enough disk space.", resultsConfigSaveErrorDetail(error.NoSpaceLeft));
    try std.testing.expectEqualStrings("Unable to save status: invalid game.cfg checksum.", resultsStatusSaveErrorDetail(error.InvalidGameCfgChecksum));
}

test "results high score top100 gate reports non-qualifying rank" {
    try std.testing.expect(!scoreTooLowForTop100(0));
    try std.testing.expect(!scoreTooLowForTop100(persistence.highscores.table_max - 1));
    try std.testing.expect(scoreTooLowForTop100(persistence.highscores.table_max));
}

test "results high score highlight rank is carried only after save" {
    const unsaved_results: ResultsScreen = .{
        .reason = .dead,
        .run_config = .{ .game_mode = .survival },
        .summary = undefined,
        .highscore = .{
            .record = persistence.highscores.HighScoreRecord.blank(),
            .rank_index = 3,
        },
    };
    try std.testing.expectEqual(@as(?usize, null), resultsHighscoreHighlightRank(&unsaved_results));

    const saved_results: ResultsScreen = .{
        .reason = .dead,
        .run_config = .{ .game_mode = .survival },
        .summary = undefined,
        .highscore = .{
            .record = persistence.highscores.HighScoreRecord.blank(),
            .rank_index = 3,
            .highlight_rank = 3,
            .saved = true,
        },
    };
    try std.testing.expectEqual(@as(?usize, 3), resultsHighscoreHighlightRank(&saved_results));
}

test "results high score name prompt follows quest preserve-bugs wording" {
    const survival_results: ResultsScreen = .{
        .reason = .dead,
        .run_config = .{ .game_mode = .survival, .preserve_bugs = true },
        .summary = undefined,
    };
    try std.testing.expectEqualStrings("State your name, trooper!", resultsNamePrompt(&survival_results));

    const quest_results_fixed: ResultsScreen = .{
        .reason = .completed,
        .run_config = .{ .game_mode = .quests, .preserve_bugs = false },
        .summary = undefined,
    };
    try std.testing.expectEqualStrings("State your name, trooper!", resultsNamePrompt(&quest_results_fixed));

    const quest_results_bug_compatible: ResultsScreen = .{
        .reason = .completed,
        .run_config = .{ .game_mode = .quests, .preserve_bugs = true },
        .summary = undefined,
    };
    try std.testing.expectEqualStrings("State your name trooper!", resultsNamePrompt(&quest_results_bug_compatible));
}

test "quest completed results resolve weapon unlock names" {
    const names = questUnlockDisplayNames(101, .quests, .completed, false, 0);

    try std.testing.expectEqualStrings("Assault Rifle", names.weapon_name.?);
    try std.testing.expectEqual(@as(?[]const u8, null), names.perk_name);
}

test "quest completed results resolve perk unlock names" {
    const names = questUnlockDisplayNames(103, .quests, .completed, false, 0);

    try std.testing.expectEqual(@as(?[]const u8, null), names.weapon_name);
    try std.testing.expectEqualStrings("Uranium Filled Bullets", names.perk_name.?);
}

test "quest unlock result names only apply to completed quests" {
    try std.testing.expectEqual(@as(?[]const u8, null), questUnlockDisplayNames(101, .survival, .completed, false, 0).weapon_name);
    try std.testing.expectEqual(@as(?[]const u8, null), questUnlockDisplayNames(101, .quests, .dead, false, 0).weapon_name);
    try std.testing.expectEqual(@as(?[]const u8, null), questUnlockDisplayNames(null, .quests, .completed, false, 0).weapon_name);
}

test "final quest completed primary action opens end note" {
    try std.testing.expectEqualStrings("Play Next", questCompletedPrimaryLabel(509));
    try std.testing.expectEqualStrings("Show End Note", questCompletedPrimaryLabel(510));
    try std.testing.expectEqual(@as(?i32, null), nextQuestLevelKey(510));
    try std.testing.expect(isFinalQuestLevelKey(510));
}

test "asset load errors use user-facing details" {
    try std.testing.expectEqualStrings("Runtime asset archive was not found.", assetLoadErrorDetail(error.FileNotFound));
    try std.testing.expectEqualStrings("Runtime assets are missing a required texture.", assetLoadErrorDetail(error.MissingTextureAsset));
    try std.testing.expectEqualStrings("Runtime assets are missing small font widths.", assetLoadErrorDetail(error.MissingFontWidths));
    try std.testing.expectEqualStrings("Runtime assets contain an unsupported texture format.", assetLoadErrorDetail(error.UnsupportedTextureFormat));
}

test "live runtime errors use user-facing details" {
    try std.testing.expectEqualStrings("Run configuration has an invalid player count.", liveRuntimeErrorDetail(error.InvalidPlayerCount));
    try std.testing.expectEqualStrings("Runtime event references an out-of-range player.", liveRuntimeErrorDetail(error.UnsupportedEventPlayerIndex));
    try std.testing.expectEqualStrings("Runtime spawn payload references an invalid creature template.", liveRuntimeErrorDetail(error.InvalidSpawnTemplate));
    try std.testing.expectEqualStrings("Unable to load Typ'o'Shooter sources: access denied.", typoSourceErrorDetail(error.AccessDenied));
    try std.testing.expectEqualStrings("Typ'o'Shooter high score file has an invalid record size.", typoSourceErrorDetail(error.InvalidSize));
}

test "results high score name entry edits at caret" {
    var highscore: ResultsHighscoreState = .{
        .record = persistence.highscores.HighScoreRecord.blank(),
        .rank_index = 0,
    };
    highscore.setInput("ACE");
    highscore.moveCaretLeft();
    highscore.insertChar('X');
    try std.testing.expectEqualStrings("ACXE", highscore.inputSlice());
    try std.testing.expectEqual(@as(usize, 3), highscore.input_caret);

    highscore.backspace();
    try std.testing.expectEqualStrings("ACE", highscore.inputSlice());
    try std.testing.expectEqual(@as(usize, 2), highscore.input_caret);

    highscore.moveCaretHome();
    highscore.insertChar('>');
    try std.testing.expectEqualStrings(">ACE", highscore.inputSlice());
    highscore.moveCaretEnd();
    highscore.insertChar('<');
    try std.testing.expectEqualStrings(">ACE<", highscore.inputSlice());
}

test "results high score name display shows caret position" {
    var highscore: ResultsHighscoreState = .{
        .record = persistence.highscores.HighScoreRecord.blank(),
        .rank_index = 0,
    };
    highscore.setInput("ACE");
    highscore.moveCaretLeft();
    var buf: [persistence.highscores.name_max_edit + 1]u8 = undefined;
    try std.testing.expectEqualStrings("AC_E", highscoreNameDisplay(&buf, &highscore, true));
    try std.testing.expectEqualStrings("ACE", highscoreNameDisplay(&buf, &highscore, false));
}

test "results weapon names use display labels" {
    try std.testing.expectEqualStrings("Assault Rifle", weaponName(@intFromEnum(game_ids.WeaponId.assault_rifle), false));
    try std.testing.expectEqualStrings("Plague Sphreader Gun", weaponName(@intFromEnum(game_ids.WeaponId.plague_spreader_gun), true));
    try std.testing.expectEqualStrings("unknown", weaponName(999, false));
}

test "gameplayControlsHeldWithSampler follows configured controls and alternate arrows" {
    const FakeSampler = struct {
        const Self = @This();

        down_code: i32,
        down_player: i32 = 0,

        fn codeIsDown(self: Self, code: i32, player_index: i32) bool {
            return code == self.down_code and player_index == self.down_player;
        }
    };

    var config = formats.crimson_cfg.defaultConfig();
    const p1_forward: FakeSampler = .{ .down_code = 0x11 };
    const alt_up: FakeSampler = .{ .down_code = 0xC8 };
    const p2_fire_while_single_player: FakeSampler = .{ .down_code = 0x9D, .down_player = 1 };
    try std.testing.expect(gameplayControlsHeldWithSampler(&config, p1_forward));
    try std.testing.expect(gameplayControlsHeldWithSampler(&config, alt_up));
    try std.testing.expect(!gameplayControlsHeldWithSampler(&config, p2_fire_while_single_player));

    config.player_count = 2;
    try std.testing.expect(gameplayControlsHeldWithSampler(&config, p2_fire_while_single_player));

    var unbound_config = formats.crimson_cfg.defaultConfig();
    var binds = formats.crimson_cfg.playerBindBlock(&unbound_config, 0);
    binds.move_forward = formats.crimson_cfg.keybind_unbound_code;
    formats.crimson_cfg.setPlayerBindBlock(&unbound_config, 0, binds);
    const unbound: FakeSampler = .{ .down_code = formats.crimson_cfg.keybind_unbound_code };
    try std.testing.expect(!gameplayControlsHeldWithSampler(&unbound_config, unbound));
}

test "live run player count forces one-player modes" {
    try std.testing.expectEqual(@as(i32, 1), livePlayerCountForMode(.typo, 4));
    try std.testing.expectEqual(@as(i32, 1), livePlayerCountForMode(.tutorial, 4));
    try std.testing.expectEqual(@as(i32, 4), livePlayerCountForMode(.survival, 9));
    try std.testing.expectEqual(@as(i32, 1), livePlayerCountForMode(.rush, 0));
}

test "window network live runtime opens host session" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var runtime = try NetworkLiveRuntime.init(.{
        .role = .host,
        .mode_id = @intFromEnum(game_ids.GameModeId.survival),
        .player_count = 2,
        .netcode = .lockstep,
        .bind_host = "127.0.0.1",
        .port = 0,
    }, 123);
    defer runtime.deinit(std.testing.allocator, io);

    try runtime.start(std.testing.allocator, io, 10);
    try std.testing.expect(runtime.boundPort() != 0);
    const stats = try runtime.update(std.testing.allocator, io, 20);
    try std.testing.expectEqual(@as(usize, 0), stats.stats.received);
}

test "window network live runtime steps host ready frames" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var runtime = try NetworkLiveRuntime.init(.{
        .role = .host,
        .mode_id = @intFromEnum(game_ids.GameModeId.survival),
        .player_count = 2,
        .netcode = .lockstep,
        .bind_host = "127.0.0.1",
        .port = 0,
    }, 123);
    defer runtime.deinit(std.testing.allocator, io);

    try runtime.start(std.testing.allocator, io, 10);
    switch (runtime) {
        .host => |*host| {
            host.session.runtime.started = true;
            host.session.runtime.lockstep = .{ .player_count = 2, .input_delay_ticks = 0 };
            try host.session.runtime.lockstep.?.submitInputSample(std.testing.allocator, 0, 0, .{ .flags = 3 });
            try host.session.runtime.lockstep.?.submitInputSample(std.testing.allocator, 1, 0, .{ .flags = 7 });
        },
        .client, .rollback => return error.TestUnexpectedResult,
    }

    const net_update = try runtime.update(std.testing.allocator, io, 20);
    try std.testing.expectEqual(@as(usize, 1), net_update.frames_advanced);
    try std.testing.expectEqual(@as(usize, 1), net_update.ticks_advanced);
    try std.testing.expectEqual(@as(i32, 0), net_update.last_tick_index.?);
    try std.testing.expectEqual(@as(usize, 2), net_update.last_player_count);
    try std.testing.expectEqual(@as(u32, 3), net_update.last_input_flags[0]);
    try std.testing.expectEqual(@as(u32, 7), net_update.last_input_flags[1]);
}

test "window network live runtime submits host local input" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var runtime = try NetworkLiveRuntime.init(.{
        .role = .host,
        .mode_id = @intFromEnum(game_ids.GameModeId.survival),
        .player_count = 1,
        .netcode = .lockstep,
        .bind_host = "127.0.0.1",
        .port = 0,
    }, 123);
    defer runtime.deinit(std.testing.allocator, io);

    try runtime.start(std.testing.allocator, io, 10);
    try std.testing.expect(runtime.runnerForLocalInput() == null);
    switch (runtime) {
        .host => |*host| {
            host.session.runtime.started = true;
            host.session.runtime.lockstep = .{ .player_count = 1, .input_delay_ticks = 0 };
        },
        .client, .rollback => return error.TestUnexpectedResult,
    }
    try std.testing.expect(runtime.runnerForLocalInput() != null);

    try runtime.submitLocalInput(std.testing.allocator, io, .{ .flags = 5 }, 20);
    const net_update = try runtime.update(std.testing.allocator, io, 30);
    try std.testing.expectEqual(@as(usize, 1), net_update.frames_advanced);
    try std.testing.expectEqual(@as(usize, 1), net_update.ticks_advanced);
}

test "window network live runtime queues client local input" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var runtime = try NetworkLiveRuntime.init(.{
        .role = .join,
        .mode_id = @intFromEnum(game_ids.GameModeId.survival),
        .player_count = 2,
        .netcode = .lockstep,
        .bind_host = "127.0.0.1",
        .host = "127.0.0.1",
        .port = 31993,
    }, 123);
    defer runtime.deinit(std.testing.allocator, io);

    try runtime.start(std.testing.allocator, io, 10);
    switch (runtime) {
        .client => |*client| {
            client.session.runtime.lockstep = .{ .local_slot_index = 1, .input_delay_ticks = 0 };
            client.session.runtime.started = true;
        },
        .host, .rollback => return error.TestUnexpectedResult,
    }

    try runtime.submitLocalInput(std.testing.allocator, io, .{ .flags = 7 }, 20);
    switch (runtime) {
        .client => |*client| {
            try std.testing.expectEqual(@as(usize, 2), client.session.outbox.packets.items.len);
            switch (client.session.outbox.packets.items[1].packet.message) {
                .input_batch => |batch| {
                    try std.testing.expectEqual(@as(i32, 1), batch.slot_index);
                    try std.testing.expectEqual(@as(usize, 1), batch.samples.len);
                    try std.testing.expectEqual(@as(u32, 7), batch.samples[0].packed_input.flags);
                },
                else => return error.TestUnexpectedResult,
            }
        },
        .host, .rollback => return error.TestUnexpectedResult,
    }
}

test "window network live runtime uses join request host endpoint" {
    var runtime = try NetworkLiveRuntime.init(.{
        .role = .join,
        .mode_id = @intFromEnum(game_ids.GameModeId.survival),
        .player_count = 2,
        .netcode = .lockstep,
        .bind_host = "127.0.0.1",
        .host = "192.168.1.44",
        .port = 31994,
    }, 123);
    defer runtime.deinit(std.testing.allocator, std.Io.Threaded.global_single_threaded.io());

    switch (runtime) {
        .client => |*client| {
            try std.testing.expectEqual(lockstep_session.PeerAddr{
                .host = .{ 192, 168, 1, 44 },
                .port = 31994,
            }, client.session.runtime.host_addr);
        },
        .host, .rollback => return error.TestUnexpectedResult,
    }
    try std.testing.expectError(error.InvalidNetworkHost, NetworkLiveRuntime.init(.{
        .role = .join,
        .mode_id = @intFromEnum(game_ids.GameModeId.survival),
        .player_count = 2,
        .netcode = .lockstep,
        .bind_host = "127.0.0.1",
        .host = "example.invalid",
        .port = 31994,
    }, 123));
}

test "window network live runtime opens rollback relay session" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var runtime = try NetworkLiveRuntime.init(.{
        .role = .host,
        .mode_id = @intFromEnum(game_ids.GameModeId.survival),
        .player_count = 2,
        .netcode = .rollback,
        .bind_host = "127.0.0.1",
        .host = "127.0.0.1",
        .port = 31993,
    }, 123);
    defer runtime.deinit(std.testing.allocator, io);

    try runtime.start(std.testing.allocator, io, 10);
    try std.testing.expect(runtime.boundPort() != 0);
    switch (runtime) {
        .rollback => |rollback| {
            try std.testing.expect(rollback.session.sent_hello);
            try std.testing.expect(!rollback.session.started);
        },
        .host, .client => return error.TestUnexpectedResult,
    }
}

test "window network live runtime steps rollback local frames" {
    const allocator = std.testing.allocator;
    const io = std.Io.Threaded.global_single_threaded.io();
    var runtime = try NetworkLiveRuntime.init(.{
        .role = .host,
        .mode_id = @intFromEnum(game_ids.GameModeId.survival),
        .player_count = 1,
        .netcode = .rollback,
        .bind_host = "127.0.0.1",
        .host = "127.0.0.1",
        .port = 31993,
    }, 123);
    defer runtime.deinit(allocator, io);

    try runtime.start(allocator, io, 10);
    var server_link: relay_reliable.RelayReliableLink = .{};
    defer server_link.deinit(allocator);
    const code = try room_code.parseRoomCode("ABCD");
    switch (runtime) {
        .rollback => |*rollback| try rollback.session.handlePacket(allocator, try server_link.buildPacket(allocator, .{ .room_start = .{
            .room_code = code,
            .session_id = "window-rollback",
            .seed = 4321,
            .mode_id = @intFromEnum(game_ids.GameModeId.survival),
            .player_count = 1,
            .slot_index = 0,
            .input_delay_ticks = 0,
            .rollback_max_ticks = 8,
        } }, true, 20), 20),
        .host, .client => return error.TestUnexpectedResult,
    }

    try std.testing.expect(runtime.runnerForLocalInput() == null);
    try runtime.submitLocalInput(allocator, io, .{ .flags = 5 }, 30);
    const net_update = try runtime.update(allocator, io, 40);
    try std.testing.expectEqual(@as(usize, 1), net_update.frames_advanced);
    try std.testing.expectEqual(@as(usize, 1), net_update.ticks_advanced);
    try std.testing.expectEqual(@as(?i32, 0), net_update.last_tick_index);
    try std.testing.expectEqual(@as(usize, 1), net_update.last_player_count);
    try std.testing.expectEqual(@as(u32, 5), net_update.last_input_flags[0]);
    try std.testing.expect(runtime.runnerForLocalInput() != null);

    const run_config = runtime.runConfigForResults() orelse return error.ExpectedLiveConfig;
    try std.testing.expectEqual(@as(u32, 4321), run_config.seed);
}

test "window rollback host waits for remote input before stepping startup frames" {
    const allocator = std.testing.allocator;
    const io = std.Io.Threaded.global_single_threaded.io();
    var runtime = try NetworkLiveRuntime.init(.{
        .role = .host,
        .mode_id = @intFromEnum(game_ids.GameModeId.survival),
        .player_count = 2,
        .netcode = .rollback,
        .bind_host = "127.0.0.1",
        .host = "127.0.0.1",
        .port = 31993,
    }, 123);
    defer runtime.deinit(allocator, io);

    try runtime.start(allocator, io, 10);
    var server_link: relay_reliable.RelayReliableLink = .{};
    defer server_link.deinit(allocator);
    switch (runtime) {
        .rollback => |*rollback| try rollback.session.handlePacket(allocator, try server_link.buildPacket(allocator, .{ .room_start = .{
            .room_code = try room_code.parseRoomCode("ABCD"),
            .session_id = "window-rollback",
            .seed = 4321,
            .mode_id = @intFromEnum(game_ids.GameModeId.survival),
            .player_count = 2,
            .slot_index = 0,
            .input_delay_ticks = 1,
            .rollback_max_ticks = 8,
        } }, true, 20), 20),
        .host, .client => return error.TestUnexpectedResult,
    }

    try std.testing.expect(!runtime.hostRemoteInputsReady());
    const blocked_update = try runtime.update(allocator, io, 30);
    try std.testing.expectEqual(@as(usize, 0), blocked_update.frames_advanced);

    switch (runtime) {
        .rollback => |*rollback| try rollback.session.handlePacket(allocator, try server_link.buildPacket(allocator, .{ .rb_input_sample = .{
            .slot_index = 1,
            .samples = &[_]relay_protocol.RbInputSample{.{ .tick_index = 1, .packed_input = .{ .flags = 9 } }},
        } }, false, 31), 31),
        .host, .client => return error.TestUnexpectedResult,
    }

    try std.testing.expect(runtime.hostRemoteInputsReady());
    const ready_update = try runtime.update(allocator, io, 32);
    try std.testing.expectEqual(@as(usize, 1), ready_update.frames_advanced);
    try std.testing.expectEqual(@as(?i32, 0), ready_update.last_tick_index);
}

test "window network live runtime packs rollback frame input for local slot" {
    const allocator = std.testing.allocator;
    const io = std.Io.Threaded.global_single_threaded.io();
    var runtime = try NetworkLiveRuntime.init(.{
        .role = .host,
        .mode_id = @intFromEnum(game_ids.GameModeId.survival),
        .player_count = 1,
        .netcode = .rollback,
        .bind_host = "127.0.0.1",
        .host = "127.0.0.1",
        .port = 31993,
    }, 123);
    defer runtime.deinit(allocator, io);

    try runtime.start(allocator, io, 10);
    var server_link: relay_reliable.RelayReliableLink = .{};
    defer server_link.deinit(allocator);
    switch (runtime) {
        .rollback => |*rollback| try rollback.session.handlePacket(allocator, try server_link.buildPacket(allocator, .{ .room_start = .{
            .room_code = try room_code.parseRoomCode("ABCD"),
            .session_id = "window-rollback",
            .mode_id = @intFromEnum(game_ids.GameModeId.survival),
            .player_count = 1,
            .slot_index = 0,
            .input_delay_ticks = 0,
            .rollback_max_ticks = 8,
        } }, true, 20), 20),
        .host, .client => return error.TestUnexpectedResult,
    }

    var frame_input: live_runner.FrameInput = .{};
    frame_input.player_count = 1;
    frame_input.players[0] = live_runner.defaultGameInput();
    frame_input.players[0].flags.fire_pressed = true;
    try std.testing.expect(try runtime.submitLocalFrameInput(allocator, io, frame_input, 30));

    const net_update = try runtime.update(allocator, io, 40);
    try std.testing.expectEqual(@as(usize, 1), net_update.frames_advanced);
    try std.testing.expectEqual(@as(u32, lockstep_input_adapter.fire_pressed_flag), net_update.last_input_flags[0]);
}

test "window network live terminal reason prefers quest completion" {
    try std.testing.expectEqual(@as(?ResultsReason, .completed), networkLiveTerminalReason(.quests, true, false));
    try std.testing.expectEqual(@as(?ResultsReason, .completed), networkLiveTerminalReason(.quests, true, true));
    try std.testing.expectEqual(@as(?ResultsReason, .dead), networkLiveTerminalReason(.survival, false, true));
    try std.testing.expectEqual(@as(?ResultsReason, null), networkLiveTerminalReason(.survival, false, false));
}

test "window network live runtime packs host frame input" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var runtime = try NetworkLiveRuntime.init(.{
        .role = .host,
        .mode_id = @intFromEnum(game_ids.GameModeId.survival),
        .player_count = 1,
        .netcode = .lockstep,
        .bind_host = "127.0.0.1",
        .port = 0,
    }, 123);
    defer runtime.deinit(std.testing.allocator, io);

    try runtime.start(std.testing.allocator, io, 10);
    switch (runtime) {
        .host => |*host| {
            host.session.runtime.started = true;
            host.session.runtime.lockstep = .{ .player_count = 1, .input_delay_ticks = 0 };
        },
        .client, .rollback => return error.TestUnexpectedResult,
    }

    var frame_input: live_runner.FrameInput = .{};
    frame_input.player_count = 1;
    frame_input.players[0] = live_runner.defaultGameInput();
    frame_input.players[0].flags.fire_pressed = true;
    try std.testing.expect(try runtime.submitLocalFrameInput(std.testing.allocator, io, frame_input, 20));

    const net_update = try runtime.update(std.testing.allocator, io, 30);
    try std.testing.expectEqual(@as(usize, 1), net_update.frames_advanced);
    try std.testing.expectEqual(@as(usize, 1), net_update.ticks_advanced);
}

test "window network live runtime packs client frame input for local slot" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var runtime = try NetworkLiveRuntime.init(.{
        .role = .join,
        .mode_id = @intFromEnum(game_ids.GameModeId.survival),
        .player_count = 2,
        .netcode = .lockstep,
        .bind_host = "127.0.0.1",
        .host = "127.0.0.1",
        .port = 31993,
    }, 123);
    defer runtime.deinit(std.testing.allocator, io);

    try runtime.start(std.testing.allocator, io, 10);
    switch (runtime) {
        .client => |*client| {
            client.session.runtime.lockstep = .{ .local_slot_index = 1, .input_delay_ticks = 0 };
            client.session.runtime.started = true;
        },
        .host, .rollback => return error.TestUnexpectedResult,
    }

    var frame_input: live_runner.FrameInput = .{};
    frame_input.player_count = 2;
    frame_input.players[0] = live_runner.defaultGameInput();
    frame_input.players[0].flags.reload_pressed = true;
    frame_input.players[1] = live_runner.defaultGameInput();
    frame_input.players[1].flags.fire_pressed = true;
    try std.testing.expect(try runtime.submitLocalFrameInput(std.testing.allocator, io, frame_input, 20));

    switch (runtime) {
        .client => |*client| {
            try std.testing.expectEqual(@as(usize, 2), client.session.outbox.packets.items.len);
            switch (client.session.outbox.packets.items[1].packet.message) {
                .input_batch => |batch| {
                    try std.testing.expectEqual(@as(i32, 1), batch.slot_index);
                    try std.testing.expectEqual(@as(u32, lockstep_input_adapter.fire_pressed_flag), batch.samples[0].packed_input.flags);
                },
                else => return error.TestUnexpectedResult,
            }
        },
        .host, .rollback => return error.TestUnexpectedResult,
    }
}

test "demo attract variant sequencing mirrors native cycle" {
    try std.testing.expectEqual(@as(i32, 6), demo_attract_variant_count);
    try std.testing.expectEqual(@as(i32, 1), nextDemoAttractVariant(0));
    try std.testing.expectEqual(@as(i32, 5), nextDemoAttractVariant(4));
    try std.testing.expectEqual(@as(i32, 0), nextDemoAttractVariant(5));
    try std.testing.expectEqual(@as(i32, 2), demoAttractPlayerCount(0));
    try std.testing.expectEqual(@as(i32, 2), demoAttractPlayerCount(1));
    try std.testing.expectEqual(@as(i32, 1), demoAttractPlayerCount(2));
    try std.testing.expectEqual(@as(i32, 1), demoAttractPlayerCount(3));
    try std.testing.expectEqual(@as(i32, 2), demoAttractPlayerCount(4));
    try std.testing.expectEqual(@as(i32, 1), demoAttractPlayerCount(5));
    try std.testing.expect(!demoAttractPurchaseActive(4));
    try std.testing.expect(demoAttractPurchaseActive(5));
    try std.testing.expectEqual(@as(i32, 10_000), demoAttractLimitMs(5));
    try std.testing.expectEqual(@as(i32, 16_000), demo_attract_purchase_screen_limit_ms);
}

test "demo attract upsell messages cycle on gameplay variants" {
    try std.testing.expectEqualStrings("Want more Levels?", demo_upsell_messages[0]);
    try std.testing.expectEqual(@as(usize, 1), nextDemoUpsellMessageIndex(0));
    try std.testing.expectEqual(@as(usize, 2), nextDemoUpsellMessageIndex(1));
    try std.testing.expectEqual(@as(usize, 0), nextDemoUpsellMessageIndex(2));
}

test "demo attract upsell overlay follows native fade and progress math" {
    const early = demoUpsellOverlayMetrics(500, 4000, 1);
    try std.testing.expectEqualStrings("Want more Weapons?", early.text);
    try std.testing.expectApproxEqAbs(@as(f32, 50.0), early.text_x, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 58.0), early.text_y, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 230.4), early.text_width, 1e-3);
    try std.testing.expectApproxEqAbs(@as(f32, 28.8), early.bar_rect.width, 1e-3);
    try std.testing.expectEqual(@as(u8, 102), early.text_alpha);
    try std.testing.expectEqual(@as(u8, 51), early.bg_alpha);
    try std.testing.expectEqual(@as(u8, 82), early.bar_alpha);

    const final = demoUpsellOverlayMetrics(3900, 4000, 4);
    try std.testing.expectEqualStrings("Want more Weapons?", final.text);
    try std.testing.expectEqual(@as(u8, 51), final.text_alpha);
    try std.testing.expectApproxEqAbs(@as(f32, 224.64), final.bar_rect.width, 1e-3);
}

test "demo attract inactive input opens purchase before generic close" {
    try std.testing.expectEqual(DemoAttractInactiveAction.none, demoAttractInactiveActionFor(false, false, false, false, false));
    try std.testing.expectEqual(DemoAttractInactiveAction.purchase, demoAttractInactiveActionFor(false, true, false, false, false));
    try std.testing.expectEqual(DemoAttractInactiveAction.purchase, demoAttractInactiveActionFor(false, false, true, false, false));
    try std.testing.expectEqual(DemoAttractInactiveAction.purchase, demoAttractInactiveActionFor(true, true, false, false, false));
    try std.testing.expectEqual(DemoAttractInactiveAction.close, demoAttractInactiveActionFor(true, false, false, false, false));
    try std.testing.expectEqual(DemoAttractInactiveAction.close, demoAttractInactiveActionFor(false, false, false, true, false));
}

test "demo attract purchase actions map buttons and cancel" {
    try std.testing.expectEqual(DemoAttractPurchaseAction.none, demoAttractPurchaseActionFor(0, false, false));
    try std.testing.expectEqual(DemoAttractPurchaseAction.purchase, demoAttractPurchaseActionFor(0, true, false));
    try std.testing.expectEqual(DemoAttractPurchaseAction.maybe_later, demoAttractPurchaseActionFor(1, true, false));
    try std.testing.expectEqual(DemoAttractPurchaseAction.maybe_later, demoAttractPurchaseActionFor(0, true, true));
}

test "demo attract purchase buttons follow native right-side layout" {
    const buttons = demoAttractPurchaseButtonsForScreen(1024.0, 768.0);
    try std.testing.expectEqualStrings("Purchase", buttons[0].label);
    try std.testing.expectEqualStrings("Maybe later", buttons[1].label);
    try std.testing.expectApproxEqAbs(@as(f32, 640.0), buttons[0].rect.x, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 640.0), buttons[1].rect.x, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 574.4), buttons[0].rect.y, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 614.4), buttons[1].rect.y, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 145.0), buttons[0].rect.width, 1e-6);
    try std.testing.expectApproxEqAbs(window_ui.button_plate_height, buttons[0].rect.height, 1e-6);
}

test "demo purchase backplasma colors follow native corner pulse" {
    const dark = demoPurchaseBackplasmaColors(0);
    try std.testing.expectEqualDeep(rl.Color.init(0, 0, 0, 255), dark.top_left);
    try std.testing.expectEqualDeep(rl.Color.init(0, 0, 77, 255), dark.top_right);
    try std.testing.expectEqualDeep(rl.Color.init(0, 102, 0, 0), dark.bottom_right);
    try std.testing.expectEqualDeep(rl.Color.init(0, 102, 102, 255), dark.bottom_left);

    const bright = demoPurchaseBackplasmaColors(250);
    try std.testing.expectEqualDeep(rl.Color.init(0, 102, 140, 255), bright.bottom_right);
}

test "demo attract variant 0 sets two-player spider setup" {
    var runner = try live_runner.LiveRunner.init(.{
        .seed = 1234,
        .game_mode = .survival,
        .player_count = 2,
        .demo_mode_active = true,
    });
    try setupDemoAttractVariant(&runner, 0);
    try std.testing.expectEqual(@as(usize, 2), runner.session.playersConst().len);
    try std.testing.expectEqual(game_ids.WeaponId.plasma_minigun, runner.session.playersConst()[0].weapon.weapon_id);
    try std.testing.expectEqual(game_ids.WeaponId.plasma_minigun, runner.session.playersConst()[1].weapon.weapon_id);
    try std.testing.expectEqual(@as(usize, 36), runner.session.creatures.activeCount());
}

test "demo attract variant 2 sets one-player zombie column setup" {
    var runner = try live_runner.LiveRunner.init(.{
        .seed = 1234,
        .game_mode = .survival,
        .player_count = 1,
        .demo_mode_active = true,
    });
    try setupDemoAttractVariant(&runner, 2);
    try std.testing.expectEqual(@as(usize, 1), runner.session.playersConst().len);
    try std.testing.expectEqual(game_ids.WeaponId.ion_rifle, runner.session.playersConst()[0].weapon.weapon_id);
    try std.testing.expectEqual(@as(usize, 48), runner.session.creatures.activeCount());
}

test "demo attract random variants use expected terrain and spawn counts" {
    var variant1 = try live_runner.LiveRunner.init(.{
        .seed = 1234,
        .game_mode = .survival,
        .player_count = 2,
        .demo_mode_active = true,
    });
    try setupDemoAttractVariant(&variant1, 1);
    try std.testing.expectEqualDeep(runtime_bootstrap.TerrainSlotTriplet{ 2, 3, 2 }, variant1.terrain_setup.terrain_slots);
    try std.testing.expectEqual(game_ids.WeaponId.submachine_gun, variant1.session.playersConst()[0].weapon.weapon_id);
    try std.testing.expectEqual(@as(usize, 33), variant1.session.creatures.activeCount());
    try std.testing.expectApproxEqAbs(@as(f32, 15.0), variant1.session.state.bonuses.weapon_power_up, 1e-6);

    var variant3 = try live_runner.LiveRunner.init(.{
        .seed = 1234,
        .game_mode = .survival,
        .player_count = 1,
        .demo_mode_active = true,
    });
    try setupDemoAttractVariant(&variant3, 3);
    try std.testing.expectEqualDeep(runtime_bootstrap.terrainSlotsForQuestLevelKey(101).?, variant3.terrain_setup.terrain_slots);
    try std.testing.expectEqual(game_ids.WeaponId.rocket_minigun, variant3.session.playersConst()[0].weapon.weapon_id);
    try std.testing.expectEqual(@as(usize, 33), variant3.session.creatures.activeCount());
}

test "demo attract variant 5 is purchase interstitial without gameplay spawns" {
    var runner = try live_runner.LiveRunner.init(.{
        .seed = 1234,
        .game_mode = .survival,
        .player_count = 1,
        .demo_mode_active = true,
    });
    try setupDemoAttractVariant(&runner, 5);
    try std.testing.expectEqual(@as(usize, 1), runner.session.playersConst().len);
    try std.testing.expectEqual(@as(usize, 0), runner.session.creatures.activeCount());
}

test "hudPlayerRowLayout preserves single-player top bar coordinates" {
    const row = hudPlayerRowLayout(1, 0, 1.0);
    try std.testing.expectApproxEqAbs(@as(f32, 27.0), row.heart_center.x, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 21.0), row.heart_center.y, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 64.0), row.health_bar.x, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 16.0), row.health_bar.y, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 120.0), row.health_bar.width, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 9.0), row.health_bar.height, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 220.0), row.weapon_icon.x, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 2.0), row.weapon_icon.y, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 64.0), row.weapon_icon.width, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 32.0), row.weapon_icon.height, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 300.0), row.ammo_base.x, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 10.0), row.ammo_base.y, 1e-6);
}

test "hudPlayerRowLayout stacks multiplayer rows like the Python HUD" {
    const row0 = hudPlayerRowLayout(2, 0, 1.0);
    const row1 = hudPlayerRowLayout(2, 1, 1.0);
    try std.testing.expectApproxEqAbs(@as(f32, 64.0), row0.health_bar.x, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 6.0), row0.health_bar.y, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 64.0), row1.health_bar.x, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 22.0), row1.health_bar.y, 1e-6);

    const fill0 = hudHealthFillRect(row0, 80.0).?;
    const fill1 = hudHealthFillRect(row1, 50.0).?;
    try std.testing.expectApproxEqAbs(@as(f32, 96.0), fill0.width, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 60.0), fill1.width, 1e-6);

    try std.testing.expectApproxEqAbs(@as(f32, 220.0), row0.weapon_icon.x, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 4.0), row0.weapon_icon.y, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 32.0), row0.weapon_icon.width, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 16.0), row0.weapon_icon.height, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 220.0), row1.weapon_icon.x, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 20.0), row1.weapon_icon.y, 1e-6);

    try std.testing.expectApproxEqAbs(@as(f32, 290.0), row0.ammo_base.x, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 4.0), row0.ammo_base.y, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 290.0), row1.ammo_base.x, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 18.0), row1.ammo_base.y, 1e-6);
}

fn drawWorld(
    runner: *const live_runner.LiveRunner,
    runtime_assets: ?*const window_assets.RuntimeAssets,
    ground: ?*const window_ground.GroundRenderer,
) void {
    const world_size = runner.session.world_size;
    const world_rect = rl.Rectangle.init(0.0, 0.0, world_size, world_size);

    if (ground) |rendered_ground| {
        rendered_ground.draw();
    } else if (runtime_assets) |assets| {
        const terrain_set = terrainTextureSet(runner.session.quest_unlock_index);
        drawTextureTiled(assets.texture(terrain_set.base), world_rect, rl.Color.white);
        drawTextureTiled(assets.texture(terrain_set.overlay), world_rect, rl.Color.init(255, 255, 255, 124));
    } else {
        rl.drawRectangleRec(world_rect, rl.Color.init(63, 56, 25, 255));
    }
}

fn drawPlayers(
    runner: *const live_runner.LiveRunner,
    runtime_assets: ?*const window_assets.RuntimeAssets,
    render_time_s: f32,
    entity_alpha: f32,
    alive: bool,
) void {
    for (runner.session.playersConst()) |player| {
        if (alive and player.health <= 0.0) continue;
        if (!alive and player.health > 0.0) continue;
        const center = toRlVec(player.pos);
        const radius = @max(10.0, player.size * 0.28);
        const color = colorWithAlpha(if (player.health > 0.0) player_color else dead_player_color, entity_alpha);

        if (runtime_assets) |assets| {
            const trooper_texture = assets.texture(.trooper);
            const cell = @as(f32, @floatFromInt(trooper_texture.width)) / 8.0;
            if (cell > 0.0) {
                const base_scale = player.size / cell;
                const shadow_tint = colorWithAlpha(rl.Color.black, (90.0 / 255.0) * entity_alpha);
                const elapsed_s = render_time_s;

                if (player.health > 0.0) {
                    if (runtime_perks.perkActive(&player, .radioactive)) {
                        if (window_atlas.effectRect(assets.texture(.particles).width, assets.texture(.particles).height, .aura)) |src_rect| {
                            const aura_alpha = ((std.math.sin(elapsed_s) + 1.0) * 0.1875 + 0.25);
                            if (aura_alpha > 1e-3) {
                                rl.beginBlendMode(.additive);
                                drawTextureRegionCenteredRotated(
                                    assets.texture(.particles),
                                    src_rect,
                                    center,
                                    100.0,
                                    100.0,
                                    0.0,
                                    colorWithAlpha(rl.Color.init(77, 153, 77, 255), aura_alpha * entity_alpha),
                                );
                                rl.endBlendMode();
                            }
                        }
                    }

                    const leg_frame = std.math.clamp(@as(i32, @intFromFloat(player.move_phase + 0.5)), @as(i32, 0), @as(i32, 14));
                    const torso_frame = leg_frame + 16;
                    const recoil_dir = player.aim_heading + std.math.pi / 2.0;
                    const recoil = player.muzzle_flash_alpha * 12.0;
                    const recoil_offset = state_mod.Vec2.fromAngle(recoil_dir).mul(recoil);
                    const torso_center = center;
                    const torso_draw_center = rl.Vector2.init(torso_center.x + recoil_offset.x, torso_center.y + recoil_offset.y);

                    drawAtlasFrameCenteredRotated(
                        trooper_texture,
                        8,
                        leg_frame,
                        .{ .x = center.x + 3.0 + player.size * 0.01, .y = center.y + 3.0 + player.size * 0.01 },
                        base_scale * 1.02,
                        player.heading,
                        shadow_tint,
                    );
                    drawAtlasFrameCenteredRotated(
                        trooper_texture,
                        8,
                        torso_frame,
                        .{ .x = torso_draw_center.x + 1.0 + player.size * 0.015, .y = torso_draw_center.y + 1.0 + player.size * 0.015 },
                        base_scale * 1.03,
                        player.aim_heading,
                        shadow_tint,
                    );
                    drawAtlasFrameCenteredRotated(trooper_texture, 8, leg_frame, center, base_scale, player.heading, colorWithAlpha(rl.Color.white, entity_alpha));
                    drawAtlasFrameCenteredRotated(trooper_texture, 8, torso_frame, torso_draw_center, base_scale, player.aim_heading, colorWithAlpha(rl.Color.white, entity_alpha));

                    if (player.shield_timer > 1e-3) {
                        if (window_atlas.effectRect(assets.texture(.particles).width, assets.texture(.particles).height, .shield_ring)) |src_rect| {
                            const timer = player.shield_timer;
                            var strength = ((std.math.sin(elapsed_s) + 1.0) * 0.25 + timer);
                            if (timer < 1.0) strength *= timer;
                            strength = @min(1.0, strength);
                            if (strength > 1e-3) {
                                const offset_dir = player.aim_heading - std.math.pi / 2.0;
                                const shield_center_off = state_mod.Vec2.fromAngle(offset_dir).mul(3.0);
                                const shield_center = rl.Vector2.init(center.x + shield_center_off.x, center.y + shield_center_off.y);
                                const half_1 = std.math.sin(elapsed_s * 3.0) + 17.5;
                                const size_1 = half_1 * 2.0;
                                const half_2 = std.math.sin(elapsed_s * 3.0) * 4.0 + 24.0;
                                const size_2 = half_2 * 2.0;
                                rl.beginBlendMode(.additive);
                                drawTextureRegionCenteredRotated(
                                    assets.texture(.particles),
                                    src_rect,
                                    shield_center,
                                    size_1,
                                    size_1,
                                    radiansToDegrees(elapsed_s * 2.0),
                                    colorWithAlpha(rl.Color.init(91, 180, 255, 255), strength * 0.4 * entity_alpha),
                                );
                                drawTextureRegionCenteredRotated(
                                    assets.texture(.particles),
                                    src_rect,
                                    shield_center,
                                    size_2,
                                    size_2,
                                    radiansToDegrees(elapsed_s * -2.0),
                                    colorWithAlpha(rl.Color.init(91, 180, 255, 255), strength * 0.3 * entity_alpha),
                                );
                                rl.endBlendMode();
                            }
                        }
                    }

                    if (player.muzzle_flash_alpha > 0.02) {
                        const flags = weapon_data.weapon_stats.get(player.weapon.weapon_id).flags;
                        if ((flags & 0x8) == 0) {
                            const flash_alpha = std.math.clamp(player.muzzle_flash_alpha * 0.8, @as(f32, 0.0), @as(f32, 1.0));
                            if (flash_alpha > 1e-3) {
                                const flash_size = player.size * (if ((flags & 0x4) != 0) @as(f32, 0.5) else @as(f32, 1.0));
                                const flash_heading = player.aim_heading + std.math.pi / 2.0;
                                const flash_offset = (player.muzzle_flash_alpha * 12.0) - 21.0;
                                const flash_pos_off = state_mod.Vec2.fromAngle(flash_heading).mul(flash_offset);
                                const flash_center = rl.Vector2.init(center.x + flash_pos_off.x, center.y + flash_pos_off.y);
                                rl.beginBlendMode(.additive);
                                drawTextureCenteredRotated(
                                    assets.texture(.muzzle_flash),
                                    flash_center,
                                    flash_size,
                                    flash_size,
                                    radiansToDegrees(player.aim_heading),
                                    colorWithAlpha(rl.Color.white, flash_alpha * entity_alpha),
                                );
                                rl.endBlendMode();
                            }
                        }
                    }
                    continue;
                }

                var dead_frame: i32 = 52;
                if (player.death_timer >= 0.0) {
                    dead_frame = 32 + @as(i32, @intFromFloat((16.0 - player.death_timer) * 1.25));
                    dead_frame = std.math.clamp(dead_frame, @as(i32, 32), @as(i32, 52));
                }
                drawAtlasFrameCenteredRotated(
                    trooper_texture,
                    8,
                    dead_frame,
                    .{ .x = center.x + 1.0 + player.size * 0.015, .y = center.y + 1.0 + player.size * 0.015 },
                    base_scale * 1.03,
                    player.aim_heading,
                    shadow_tint,
                );
                drawAtlasFrameCenteredRotated(trooper_texture, 8, dead_frame, center, base_scale, player.aim_heading, colorWithAlpha(dead_player_color, entity_alpha));
                continue;
            }
        } else {
            rl.drawCircleV(center, radius, color);
            rl.drawCircleLinesV(center, radius + 2.0, rl.Color.black);
            rl.drawLineEx(center, toRlVec(player.aim), 2.0, rl.Color.gold);
        }
    }
}

fn drawCreatures(
    runner: *const live_runner.LiveRunner,
    runtime_assets: ?*const window_assets.RuntimeAssets,
    entity_alpha: f32,
    fx_detail_0: bool,
) void {
    const monster_vision_active = if (runner.player0Const()) |player|
        runtime_perks.perkActive(player, .monster_vision)
    else
        false;

    for (runner.session.creatures.entries) |creature| {
        if (!creature.active) continue;
        const color = if (creature.hp > 0.0) creature_color else corpse_color;
        const radius = @max(6.0, creature.size * 0.24);
        if (runtime_assets) |assets| {
            if (window_atlas.creatureRenderFrame(creature)) |render_frame| {
                const texture = assets.texture(switch (render_frame.texture_kind) {
                    .alien => .alien,
                    .lizard => .lizard,
                    .spider_sp1 => .spider_sp1,
                    .spider_sp2 => .spider_sp2,
                    .trooper => .trooper,
                    .zombie => .zombie,
                });
                const cell = @as(f32, @floatFromInt(texture.width)) / 8.0;
                if (cell > 0.0) {
                    const base_scale = creature.size / cell;
                    var tint = rl.Color.white;
                    if (runner.session.state.bonuses.energizer > 0.0 and creature.max_hp < 500.0) {
                        tint = colorLerp(
                            rl.Color.white,
                            rl.Color.init(128, 128, 255, 255),
                            @min(runner.session.state.bonuses.energizer, 1.0),
                        );
                    }
                    if (creature.lifecycle_stage < 0.0) {
                        tint = colorWithAlpha(tint, @max(0.0, 1.0 + creature.lifecycle_stage * 0.1));
                    }
                    const shadow_enabled = !monster_vision_active;
                    if (shadow_enabled and fx_detail_0) {
                        const is_long = runtime_anim.creatureAnimIsLongStrip(creature.flags);
                        var shadow_alpha: f32 = 0.4;
                        if (creature.lifecycle_stage < 0.0) {
                            shadow_alpha = @max(
                                @as(f32, 0.0),
                                shadow_alpha + creature.lifecycle_stage * (if (is_long) @as(f32, 0.5) else @as(f32, 0.1)),
                            );
                        }
                        if (shadow_alpha > 1e-3) {
                            drawAtlasFrameCenteredRotated(
                                texture,
                                8,
                                render_frame.frame,
                                .{
                                    .x = creature.pos.x + creature.size * 0.035 - 0.7,
                                    .y = creature.pos.y + creature.size * 0.035 - 0.7,
                                },
                                base_scale * 1.07,
                                creature.heading - std.math.pi / 2.0,
                                colorWithAlpha(rl.Color.black, shadow_alpha),
                            );
                        }
                    }
                    drawAtlasFrameCenteredRotated(
                        texture,
                        8,
                        render_frame.frame,
                        toRlVec(creature.pos),
                        base_scale,
                        creature.heading - std.math.pi / 2.0,
                        colorWithAlpha(tint, entity_alpha),
                    );
                    continue;
                }
            }
        }
        rl.drawCircleV(toRlVec(creature.pos), radius, colorWithAlpha(color, entity_alpha));
    }
}

fn drawFreezeOverlay(runner: *const live_runner.LiveRunner, runtime_assets: ?*const window_assets.RuntimeAssets, entity_alpha: f32) void {
    const assets = runtime_assets orelse return;
    const freeze_timer = runner.session.state.bonuses.freeze;
    if (!(freeze_timer > 0.0)) return;
    const src_rect = window_atlas.effectRect(assets.texture(.particles).width, assets.texture(.particles).height, .freeze_shatter) orelse return;
    const fade: f32 = if (freeze_timer >= 1.0) 1.0 else std.math.clamp(freeze_timer, @as(f32, 0.0), @as(f32, 1.0));
    const alpha = std.math.clamp(fade * entity_alpha * 0.7, @as(f32, 0.0), @as(f32, 1.0));
    if (!(alpha > 1e-3)) return;

    rl.beginBlendMode(.alpha);
    defer rl.endBlendMode();
    for (runner.session.creatures.entries, 0..) |creature, idx| {
        if (!creature.active) continue;
        const size = creature.size;
        if (!(size > 1e-3)) continue;
        drawTextureRegionCenteredRotated(
            assets.texture(.particles),
            src_rect,
            toRlVec(creature.pos),
            size,
            size,
            radiansToDegrees(@as(f32, @floatFromInt(idx)) * 0.01 + creature.heading),
            colorWithAlpha(rl.Color.white, alpha),
        );
    }
}

fn drawProjectiles(
    runner: *const live_runner.LiveRunner,
    runtime_assets: ?*const window_assets.RuntimeAssets,
    render_time_s: f32,
    entity_alpha: f32,
    fx_detail_1: bool,
) void {
    for (runner.session.projectiles.entries, 0..) |projectile, proj_index| {
        if (!projectile.active) continue;
        if (runtime_assets) |assets| {
            if (window_projectiles.drawMainProjectile(projectile, proj_index, .{
                .session = &runner.session,
                .assets = assets,
                .render_time_s = render_time_s,
                .entity_alpha = entity_alpha,
                .fx_detail_1 = fx_detail_1,
            })) continue;
        }
        rl.drawCircleV(toRlVec(projectile.pos), 3.0, colorWithAlpha(projectile_color, entity_alpha));
    }
}

fn drawWorldEffects(
    runner: *const live_runner.LiveRunner,
    runtime_assets: ?*const window_assets.RuntimeAssets,
    entity_alpha: f32,
    fx_detail_1: bool,
    fx_detail_2: bool,
) void {
    if (runtime_assets) |assets| {
        window_effects.drawParticlePool(.{
            .session = &runner.session,
            .assets = assets,
            .entity_alpha = entity_alpha,
            .fx_detail_1 = fx_detail_1,
            .fx_detail_2 = fx_detail_2,
        });
    }
    for (runner.session.secondary_projectiles.entries) |projectile| {
        if (!projectile.active) continue;
        if (runtime_assets) |assets| {
            if (window_projectiles.drawSecondaryProjectile(projectile, .{
                .session = &runner.session,
                .assets = assets,
                .entity_alpha = entity_alpha,
                .fx_detail_1 = fx_detail_1,
            })) continue;
        }
        rl.drawCircleV(toRlVec(projectile.pos), 6.0, colorWithAlpha(secondary_projectile_color, entity_alpha));
    }
    if (runtime_assets) |assets| {
        window_effects.drawSpriteEffectPool(.{
            .session = &runner.session,
            .assets = assets,
            .entity_alpha = entity_alpha,
            .fx_detail_1 = fx_detail_1,
            .fx_detail_2 = fx_detail_2,
        });
        window_effects.drawEffectPool(.{
            .session = &runner.session,
            .assets = assets,
            .entity_alpha = entity_alpha,
            .fx_detail_1 = fx_detail_1,
            .fx_detail_2 = fx_detail_2,
        });
    }
}

fn drawBonuses(
    runner: *const live_runner.LiveRunner,
    runtime_assets: ?*const window_assets.RuntimeAssets,
    render_time_s: f32,
    entity_alpha: f32,
) void {
    const bonus_phase = render_time_s * 1.3;
    for (runner.session.bonuses.entries, 0..) |entry, idx| {
        if (entry.bonus_id == .unused) continue;
        if (runtime_assets) |assets| {
            const bonuses_texture = assets.texture(.bonuses);
            const bubble_src = window_atlas.bonusIconRect(bonuses_texture.width, bonuses_texture.height, 0);
            const fade = window_atlas.bonusFade(entry.time_left, entry.time_max);
            const bubble_alpha = fade * 0.9 * entity_alpha;
            const center = toRlVec(entry.pos);
            drawTextureRegionCenteredRotated(
                bonuses_texture,
                bubble_src,
                center,
                32.0,
                32.0,
                0.0,
                colorWithAlpha(rl.Color.white, bubble_alpha),
            );

            if (entry.bonus_id == .weapon) {
                const weapon_id = std.enums.fromInt(game_ids.WeaponId, entry.amount) orelse {
                    continue;
                };
                const icon_index = weapon_data.weaponIconIndex(weapon_id);
                if (icon_index >= 0) {
                    const pulse_sin = std.math.sin(bonus_phase);
                    const pulse = pulse_sin * pulse_sin * pulse_sin * pulse_sin * 0.25 + 0.75;
                    const icon_scale = fade * pulse;
                    if (icon_scale > 1e-3) {
                        const src_rect = window_atlas.weaponIconRect(assets.texture(.ui_wicons).width, assets.texture(.ui_wicons).height, icon_index);
                        drawTextureRegionCenteredRotated(
                            assets.texture(.ui_wicons),
                            src_rect,
                            center,
                            60.0 * icon_scale,
                            30.0 * icon_scale,
                            0.0,
                            colorWithAlpha(rl.Color.white, bubble_alpha),
                        );
                    }
                }
                continue;
            }

            if (window_atlas.bonusIconId(entry)) |icon_id| {
                const idx_f: f32 = @floatFromInt(idx);
                const pulse_sin = std.math.sin(idx_f + bonus_phase);
                const pulse = pulse_sin * pulse_sin * pulse_sin * pulse_sin * 0.25 + 0.75;
                const icon_scale = fade * pulse;
                if (icon_scale > 1e-3) {
                    drawTextureRegionCenteredRotated(
                        bonuses_texture,
                        window_atlas.bonusIconRect(bonuses_texture.width, bonuses_texture.height, icon_id),
                        center,
                        32.0 * icon_scale,
                        32.0 * icon_scale,
                        radiansToDegrees(std.math.sin(idx_f - render_time_s * 3.0) * 0.2),
                        colorWithAlpha(rl.Color.white, bubble_alpha),
                    );
                }
                continue;
            }
        }
        rl.drawRectangleRec(
            .{
                .x = entry.pos.x - 8.0,
                .y = entry.pos.y - 8.0,
                .width = 16.0,
                .height = 16.0,
            },
            colorWithAlpha(bonus_color, entity_alpha),
        );
    }
}

fn drawAimEnhancements(
    runner: *const live_runner.LiveRunner,
    runtime_assets: *const window_assets.RuntimeAssets,
    transform: window_viewport.ViewTransform,
    entity_alpha: f32,
) void {
    const scale = window_viewport.viewScaleAvg(transform.view_scale);
    for (runner.session.playersConst()) |player| {
        if (player.health <= 0.0) continue;
        const aim_screen = worldToScreen(player.aim, transform);
        window_cursor.drawAimIndicators(runtime_assets, player, aim_screen, scale, entity_alpha);
    }
    for (runner.session.playersConst()) |player| {
        if (player.health <= 0.0) continue;
        const aim_screen = worldToScreen(player.aim, transform);
        window_cursor.drawAimReticle(runtime_assets, aim_screen, scale);
    }
}

fn drawDirectionArrows(
    runner: *const live_runner.LiveRunner,
    runtime_assets: *const window_assets.RuntimeAssets,
    config: *const formats.crimson_cfg.CrimsonCfg,
    transform: window_viewport.ViewTransform,
    entity_alpha: f32,
) void {
    const arrow = runtime_assets.texture(.arrow);
    const scale = window_viewport.viewScaleAvg(transform.view_scale);
    const width = @max(1.0, @as(f32, @floatFromInt(arrow.width)) * scale);
    const height = @max(1.0, @as(f32, @floatFromInt(arrow.height)) * scale);
    const src = rl.Rectangle.init(0.0, 0.0, @floatFromInt(arrow.width), @floatFromInt(arrow.height));
    const origin = rl.Vector2.init(width * 0.5, height * 0.5);

    for (runner.session.playersConst(), 0..) |player, idx| {
        if (player.health <= 0.0) continue;
        if (!formats.crimson_cfg.playerShowDirectionArrow(config, idx)) continue;
        const marker = state_mod.Vec2.add(player.pos, state_mod.Vec2.fromAngle(player.heading).mul(60.0));
        const pos = worldToScreen(marker, transform);
        const tint = directionArrowTint(runner.session.player_count, idx, entity_alpha);
        rl.drawTexturePro(
            arrow,
            src,
            rl.Rectangle.init(pos.x, pos.y, width, height),
            origin,
            radiansToDegrees(player.heading),
            tint,
        );
    }
}

fn drawBonusHoverLabels(
    runner: *const live_runner.LiveRunner,
    runtime_assets: *const window_assets.RuntimeAssets,
    transform: window_viewport.ViewTransform,
    entity_alpha: f32,
) void {
    const shadow = rl.Color.init(0, 0, 0, @intFromFloat(180.0 * entity_alpha + 0.5));
    const color = rl.Color.init(230, 230, 230, @intFromFloat(255.0 * entity_alpha + 0.5));
    const screen_w: f32 = @floatFromInt(rl.getScreenWidth());

    for (runner.session.playersConst()) |player| {
        if (player.health <= 0.0) continue;
        if (player.bonus_aim_hover_index < 0 or player.bonus_aim_hover_index >= runner.session.bonuses.entries.len) continue;
        const entry = runner.session.bonuses.entries[@intCast(player.bonus_aim_hover_index)];
        if (entry.bonus_id == .unused) continue;

        var buf: [96]u8 = undefined;
        const label = bonusHoverLabel(entry, runner.session.state.preserve_bugs, &buf) orelse continue;
        var pos = worldToScreen(player.aim, transform);
        pos.x += 16.0;
        pos.y -= 7.0;
        const text_w = measureSmallText(runtime_assets, label);
        if (pos.x + text_w > screen_w) {
            pos.x = @max(0.0, screen_w - text_w);
        }
        drawSmallText(runtime_assets, label, pos.x + 1.0, pos.y + 1.0, shadow);
        drawSmallText(runtime_assets, label, pos.x, pos.y, color);
    }
}

fn worldToScreen(pos: state_mod.Vec2, transform: window_viewport.ViewTransform) rl.Vector2 {
    return .{
        .x = (pos.x + transform.camera.x) * transform.view_scale.x,
        .y = (pos.y + transform.camera.y) * transform.view_scale.y,
    };
}

fn directionArrowTint(player_count: i32, player_index: usize, alpha: f32) rl.Color {
    if (player_count == 2) {
        return if (player_index == 0)
            rl.Color.init(204, 230, 255, @intFromFloat(153.0 * alpha + 0.5))
        else
            rl.Color.init(255, 230, 204, @intFromFloat(153.0 * alpha + 0.5));
    }
    return rl.Color.init(255, 255, 255, @intFromFloat(77.0 * alpha + 0.5));
}

fn bonusHoverLabel(
    entry: bonuses_runtime.BonusEntry,
    preserve_bugs: bool,
    buf: *[96]u8,
) ?[]const u8 {
    return switch (entry.bonus_id) {
        .weapon => blk: {
            const weapon_id = std.enums.fromInt(game_ids.WeaponId, entry.amount) orelse break :blk null;
            break :blk game_ids.weaponDisplayName(weapon_id, preserve_bugs);
        },
        .points => std.fmt.bufPrint(buf, "{s}: {d}", .{
            game_ids.bonusDisplayName(.points, preserve_bugs),
            entry.amount,
        }) catch null,
        else => game_ids.bonusDisplayName(entry.bonus_id, preserve_bugs),
    };
}

const TerrainTextureSet = struct {
    base: window_assets.TextureId,
    overlay: window_assets.TextureId,
};

fn terrainTextureSet(quest_unlock_index: i32) TerrainTextureSet {
    return if (quest_unlock_index >= 40)
        .{ .base = .ter_q4_base, .overlay = .ter_q4_overlay }
    else if (quest_unlock_index >= 30)
        .{ .base = .ter_q3_base, .overlay = .ter_q3_overlay }
    else if (quest_unlock_index >= 20)
        .{ .base = .ter_q2_base, .overlay = .ter_q2_overlay }
    else
        .{ .base = .ter_q1_base, .overlay = .ter_q1_overlay };
}

fn colorWithAlpha(color: rl.Color, alpha: f32) rl.Color {
    return rl.Color.init(
        color.r,
        color.g,
        color.b,
        @intFromFloat(std.math.clamp(alpha, @as(f32, 0.0), @as(f32, 1.0)) * 255.0),
    );
}

fn drawResultsHighscore(
    runtime_assets: *const window_assets.RuntimeAssets,
    results: *const ResultsScreen,
    highscore: *const ResultsHighscoreState,
    name_prompt: []const u8,
) void {
    const layout = resultsHighscorePromptLayout(results, @floatFromInt(rl.getScreenWidth()));
    var rank_buf: [16]u8 = undefined;
    const rank_text = ui_formatting.formatOrdinal(&rank_buf, @intCast(highscore.rank_index + 1));
    if (highscore.promptActive()) {
        drawSmallText(runtime_assets, name_prompt, layout.prompt_x, layout.prompt_y, HudTextColor.accent);

        rl.drawRectangleLines(
            @intFromFloat(layout.input_rect.x),
            @intFromFloat(layout.input_rect.y),
            @intFromFloat(layout.input_rect.width),
            @intFromFloat(layout.input_rect.height),
            rl.Color.white,
        );
        rl.drawRectangle(
            @intFromFloat(layout.input_rect.x + 1.0),
            @intFromFloat(layout.input_rect.y + 1.0),
            @intFromFloat(layout.input_rect.width - 2.0),
            @intFromFloat(layout.input_rect.height - 2.0),
            rl.Color.black,
        );

        const caret_visible = @mod(@as(i32, @intFromFloat(rl.getTime() * 2.5)), 2) == 0;
        var shown_name_buf: [persistence.highscores.name_max_edit + 1]u8 = undefined;
        const shown_name = highscoreNameDisplay(&shown_name_buf, highscore, caret_visible);
        drawSmallText(runtime_assets, shown_name, layout.input_rect.x + 4.0, layout.input_rect.y + 2.0, colorWithAlpha(rl.Color.white, 0.8));

        if (highscore.save_error) |save_error| {
            drawSmallText(runtime_assets, save_error, layout.input_rect.x, layout.input_rect.y + 30.0, rl.Color.orange);
        }
    } else {
        drawSmallText(runtime_assets, "SCORE SAVED", layout.saved_x, layout.saved_y, HudTextColor.accent);
        drawSmallTextFmt("Rank: {s}  Name: {s}", runtime_assets, .{ rank_text, highscore.record.name() }, layout.saved_x, layout.saved_y + 18.0, HudTextColor.primary);
    }
}

fn highscoreNameDisplay(
    buf: *[persistence.highscores.name_max_edit + 1]u8,
    highscore: *const ResultsHighscoreState,
    caret_visible: bool,
) []const u8 {
    if (!caret_visible) return highscore.inputSlice();
    const caret = @min(highscore.input_caret, highscore.input_len);
    @memcpy(buf[0..caret], highscore.input[0..caret]);
    buf[caret] = '_';
    @memcpy(buf[caret + 1 .. caret + 1 + highscore.input_len - caret], highscore.input[caret..highscore.input_len]);
    return buf[0 .. highscore.input_len + 1];
}

const HudTextColor = struct {
    const primary = rl.Color.init(220, 220, 220, 255);
    const dim = rl.Color.init(170, 170, 180, 255);
    const accent = rl.Color.init(240, 200, 80, 255);
};

const HudFlags = struct {
    show_health: bool,
    show_weapon: bool,
    show_xp: bool,
    show_time: bool,
    show_quest_hud: bool,
};

const HudPlayerRowLayout = struct {
    heart_center: rl.Vector2,
    heart_scale: f32,
    health_bar: rl.Rectangle,
    weapon_icon: rl.Rectangle,
    ammo_base: rl.Vector2,
};

fn hudPlayerRowLayout(player_count_raw: usize, player_index: usize, scale: f32) HudPlayerRowLayout {
    const player_count = @max(player_count_raw, 1);
    const idx: f32 = @floatFromInt(player_index);
    if (player_count == 1) {
        return .{
            .heart_center = rl.Vector2.init(hs(27.0, scale), hs(21.0, scale)),
            .heart_scale = 1.0,
            .health_bar = rl.Rectangle.init(hs(64.0, scale), hs(16.0, scale), hs(120.0, scale), hs(9.0, scale)),
            .weapon_icon = rl.Rectangle.init(hs(220.0, scale), hs(2.0, scale), hs(64.0, scale), hs(32.0, scale)),
            .ammo_base = rl.Vector2.init(hs(300.0, scale), hs(10.0, scale)),
        };
    }
    return .{
        .heart_center = rl.Vector2.init(hs(27.0, scale), hs(12.0 + idx * 15.0, scale)),
        .heart_scale = 0.5,
        .health_bar = rl.Rectangle.init(hs(64.0, scale), hs(6.0 + idx * 16.0, scale), hs(120.0, scale), hs(9.0, scale)),
        .weapon_icon = rl.Rectangle.init(hs(220.0, scale), hs(4.0 + idx * 16.0, scale), hs(32.0, scale), hs(16.0, scale)),
        .ammo_base = rl.Vector2.init(hs(290.0, scale), hs(4.0 + idx * 14.0, scale)),
    };
}

fn hudHealthFillRect(row: HudPlayerRowLayout, health: f32) ?rl.Rectangle {
    const health_ratio = std.math.clamp(health / 100.0, @as(f32, 0.0), @as(f32, 1.0));
    if (!(health_ratio > 0.0)) return null;
    return rl.Rectangle.init(row.health_bar.x, row.health_bar.y, row.health_bar.width * health_ratio, row.health_bar.height);
}

fn hudFlagsForGameMode(game_mode: game_ids.GameModeId) HudFlags {
    return switch (game_mode) {
        .quests => .{
            .show_health = true,
            .show_weapon = true,
            .show_xp = true,
            .show_time = false,
            .show_quest_hud = true,
        },
        .survival => .{
            .show_health = true,
            .show_weapon = true,
            .show_xp = true,
            .show_time = false,
            .show_quest_hud = false,
        },
        .rush => .{
            .show_health = true,
            .show_weapon = false,
            .show_xp = false,
            .show_time = true,
            .show_quest_hud = false,
        },
        .typo => .{
            .show_health = true,
            .show_weapon = false,
            .show_xp = true,
            .show_time = true,
            .show_quest_hud = false,
        },
        .tutorial => .{
            .show_health = false,
            .show_weapon = false,
            .show_xp = false,
            .show_time = false,
            .show_quest_hud = false,
        },
    };
}

fn hudBonusIconId(bonus_id: game_ids.BonusId) ?i32 {
    return switch (bonus_id) {
        .energizer => 10,
        .weapon_power_up => 7,
        .double_experience => 4,
        .reflex_boost => 5,
        .shield => 6,
        .freeze => 8,
        .speed => 9,
        .fire_bullets => 11,
        else => null,
    };
}

fn collectHudBonusSpecs(session: *const runtime_session.DeterministicSession, dest: []HudBonusSpec, count: *usize) void {
    count.* = 0;
    const state = &session.state;
    const players = session.playersConst();

    appendHudBonusSpec(dest, count, .weapon_power_up, state.bonuses.weapon_power_up, 0.0);
    appendHudBonusSpec(dest, count, .reflex_boost, state.bonuses.reflex_boost, 0.0);
    appendHudBonusSpec(dest, count, .energizer, state.bonuses.energizer, 0.0);
    appendHudBonusSpec(dest, count, .double_experience, state.bonuses.double_experience, 0.0);
    appendHudBonusSpec(dest, count, .freeze, state.bonuses.freeze, 0.0);

    const player0 = if (players.len > 0) players[0] else null;
    const player1 = if (players.len > 1) players[1] else null;
    appendHudBonusSpec(
        dest,
        count,
        .fire_bullets,
        if (player0) |player| player.fire_bullets_timer else 0.0,
        if (player1) |player| player.fire_bullets_timer else 0.0,
    );
    appendHudBonusSpec(
        dest,
        count,
        .shield,
        if (player0) |player| player.shield_timer else 0.0,
        if (player1) |player| player.shield_timer else 0.0,
    );
    appendHudBonusSpec(
        dest,
        count,
        .speed,
        if (player0) |player| player.speed_bonus_timer else 0.0,
        if (player1) |player| player.speed_bonus_timer else 0.0,
    );
}

fn appendHudBonusSpec(dest: []HudBonusSpec, count: *usize, bonus_id: game_ids.BonusId, timer_value: f32, timer_value_alt: f32) void {
    if (!(timer_value > 0.0 or timer_value_alt > 0.0)) return;
    if (count.* >= dest.len) return;
    dest[count.*] = .{
        .bonus_id = bonus_id,
        .icon_id = hudBonusIconId(bonus_id) orelse -1,
        .timer_value = @max(timer_value, 0.0),
        .timer_value_alt = @max(timer_value_alt, 0.0),
    };
    count.* += 1;
}

fn hudUiScale() f32 {
    const screen_w: f32 = @floatFromInt(rl.getScreenWidth());
    const screen_h: f32 = @floatFromInt(rl.getScreenHeight());
    const scale = @min(screen_w / 1024.0, screen_h / 768.0);
    if (scale < 0.75) return 0.75;
    if (scale > 1.5) return 1.5;
    return scale;
}

fn hs(value: f32, scale: f32) f32 {
    return value * scale;
}

fn drawProgressBar(pos: rl.Vector2, width: f32, ratio_raw: f32, fg_color: rl.Color, scale: f32) void {
    const ratio = std.math.clamp(ratio_raw, @as(f32, 0.0), @as(f32, 1.0));
    rl.drawRectangle(@intFromFloat(pos.x), @intFromFloat(pos.y), @intFromFloat(width), @intFromFloat(4.0 * scale), rl.Color.init(
        @intFromFloat(@as(f32, @floatFromInt(fg_color.r)) * 0.6),
        @intFromFloat(@as(f32, @floatFromInt(fg_color.g)) * 0.6),
        @intFromFloat(@as(f32, @floatFromInt(fg_color.b)) * 0.6),
        102,
    ));
    rl.drawRectangle(
        @intFromFloat(pos.x + 1.0 * scale),
        @intFromFloat(pos.y + 1.0 * scale),
        @intFromFloat(@max(0.0, width - 2.0 * scale) * ratio),
        @intFromFloat(2.0 * scale),
        fg_color,
    );
}

fn drawSliderRow(assets: *const window_assets.RuntimeAssets, pos: rl.Vector2, count: i32, value: i32) void {
    const rect_on = assets.texture(.ui_rect_on);
    const rect_off = assets.texture(.ui_rect_off);
    var idx: i32 = 0;
    while (idx < count) : (idx += 1) {
        const tex = if (idx < value) rect_on else rect_off;
        const tint = if (idx < value) rl.Color.white else colorWithAlpha(rl.Color.white, 0.5);
        rl.drawTexturePro(
            tex,
            rl.Rectangle.init(0.0, 0.0, @floatFromInt(tex.width), @floatFromInt(tex.height)),
            rl.Rectangle.init(pos.x + @as(f32, @floatFromInt(idx * tex.width)), pos.y, @floatFromInt(tex.width), @floatFromInt(tex.height)),
            rl.Vector2.zero(),
            0.0,
            tint,
        );
    }
}

fn questProgressRatio(session: *const runtime_session.DeterministicSession) ?f32 {
    if (session.game_mode != .quests) return null;
    if (session.quest_completed or session.quest_completion_transition_ms >= 0.0) return 1.0;
    if (session.reset_quest_spawn_entries_len == 0) return null;
    const last_trigger_ms = session.quest_spawn_entries_storage[session.reset_quest_spawn_entries_len - 1].trigger_ms;
    if (last_trigger_ms <= 0) return null;
    return std.math.clamp(session.quest_spawn_timeline_ms / @as(f32, @floatFromInt(last_trigger_ms)), @as(f32, 0.0), @as(f32, 1.0));
}

fn drawModeClock(assets: *const window_assets.RuntimeAssets, elapsed_ms: f32, x: f32, y: f32, scale: f32) void {
    drawTextureFit(assets.texture(.ui_clock_table), rl.Rectangle.init(x, y, hs(32.0, scale), hs(32.0, scale)), colorWithAlpha(rl.Color.white, 0.9));
    rl.drawTexturePro(
        assets.texture(.ui_clock_pointer),
        rl.Rectangle.init(0.0, 0.0, @floatFromInt(assets.texture(.ui_clock_pointer).width), @floatFromInt(assets.texture(.ui_clock_pointer).height)),
        rl.Rectangle.init(x + hs(16.0, scale), y + hs(16.0, scale), hs(32.0, scale), hs(32.0, scale)),
        rl.Vector2.init(hs(16.0, scale), hs(16.0, scale)),
        elapsed_ms * 0.006,
        colorWithAlpha(rl.Color.white, 0.9),
    );
}

fn drawQuestHud(runner: *const live_runner.LiveRunner, update: live_runner.FrameUpdate, assets: *const window_assets.RuntimeAssets, scale: f32) void {
    const elapsed_ms = @as(f32, @floatFromInt(update.elapsed_ms_sim));
    const slide_x = if (elapsed_ms < 1000.0) (1000.0 - elapsed_ms) * -0.128 * scale else 0.0;

    drawTextureFit(assets.texture(.ui_ind_panel), rl.Rectangle.init(slide_x - hs(90.0, scale), hs(67.0, scale), hs(182.0, scale), hs(53.0, scale)), colorWithAlpha(rl.Color.white, 0.7));
    drawTextureFit(assets.texture(.ui_ind_panel), rl.Rectangle.init(-hs(80.0, scale), hs(107.0, scale), hs(182.0, scale), hs(53.0, scale)), colorWithAlpha(rl.Color.white, 0.7));
    drawModeClock(assets, elapsed_ms, slide_x + hs(2.0, scale), hs(78.0, scale), scale);
    drawSmallTextFmt("{d}:{d:0>2}", assets, .{ @divTrunc(update.elapsed_ms_sim, 60_000), @mod(@divTrunc(update.elapsed_ms_sim, 1000), 60) }, slide_x + hs(32.0, scale), hs(86.0, scale), HudTextColor.primary);
    drawSmallText(assets, "Progress", hs(18.0, scale), hs(122.0, scale), HudTextColor.primary);
    if (questProgressRatio(&runner.session)) |ratio| {
        drawProgressBar(rl.Vector2.init(hs(10.0, scale), hs(139.0, scale)), hs(70.0, scale), ratio, rl.Color.init(51, 204, 77, 204), scale);
    }
}

fn drawBonusHud(runner: *const live_runner.LiveRunner, hud_state: *const HudRuntimeState, assets: *const window_assets.RuntimeAssets, scale: f32) void {
    var bonus_y: f32 = if (runner.session.game_mode == .quests) hs(201.0, scale) else hs(121.0, scale);
    const bonuses_texture = assets.texture(.bonuses);
    for (hud_state.bonus_slots) |slot| {
        if (!slot.active) continue;
        if (slot.slide_x < -hs(184.0, scale)) {
            bonus_y += hs(52.0, scale);
            continue;
        }
        const slide_x = slot.slide_x * scale;
        drawTextureFit(assets.texture(.ui_ind_panel), rl.Rectangle.init(slide_x, bonus_y - hs(11.0, scale), hs(182.0, scale), hs(53.0, scale)), colorWithAlpha(rl.Color.white, 0.7));
        if (slot.icon_id >= 0) {
            drawTextureRegionCenteredRotated(
                bonuses_texture,
                window_atlas.bonusIconRect(bonuses_texture.width, bonuses_texture.height, slot.icon_id),
                rl.Vector2.init(slide_x + hs(15.0, scale), bonus_y + hs(16.0, scale)),
                hs(32.0, scale),
                hs(32.0, scale),
                0.0,
                rl.Color.white,
            );
        }
        drawSmallText(assets, game_ids.bonusDisplayName(slot.bonus_id, runner.session.state.preserve_bugs), slide_x + hs(36.0, scale), bonus_y + hs(6.0, scale), HudTextColor.primary);
        drawProgressBar(rl.Vector2.init(slide_x + hs(36.0, scale), bonus_y + hs(21.0, scale)), hs(100.0, scale), slot.timer_value * 0.05, rl.Color.init(26, 77, 153, 179), scale);
        if (slot.timer_value_alt > 0.0) {
            drawProgressBar(rl.Vector2.init(slide_x + hs(36.0, scale), bonus_y + hs(27.0, scale)), hs(100.0, scale), slot.timer_value_alt * 0.05, rl.Color.init(26, 77, 153, 179), scale);
        }
        bonus_y += hs(52.0, scale);
    }
}

fn drawWeaponAuxHud(runner: *const live_runner.LiveRunner, hud_state: *const HudRuntimeState, assets: *const window_assets.RuntimeAssets, scale: f32) void {
    const players = runner.session.playersConst();
    var bonus_bottom_y: f32 = if (runner.session.game_mode == .quests) hs(201.0, scale) else hs(121.0, scale);
    for (hud_state.bonus_slots) |slot| {
        if (slot.active) bonus_bottom_y += hs(52.0, scale);
    }
    for (players, 0..) |player, idx| {
        if (!(player.aux_timer > 0.0)) continue;
        const fade_raw = if (player.aux_timer > 1.0) 2.0 - player.aux_timer else player.aux_timer;
        const fade = std.math.clamp(fade_raw, @as(f32, 0.0), @as(f32, 1.0));
        if (fade <= 1e-3) continue;
        const y = bonus_bottom_y - hs(17.0, scale) + @as(f32, @floatFromInt(idx)) * hs(32.0, scale);
        drawTextureFit(assets.texture(.ui_ind_panel), rl.Rectangle.init(-hs(12.0, scale), y, hs(182.0, scale), hs(53.0, scale)), colorWithAlpha(rl.Color.white, fade * 0.8));
        const icon_index = weapon_data.weaponIconIndex(player.weapon.weapon_id);
        if (icon_index >= 0) {
            drawTextureRegionCenteredRotated(
                assets.texture(.ui_wicons),
                window_atlas.weaponIconRect(assets.texture(.ui_wicons).width, assets.texture(.ui_wicons).height, icon_index),
                rl.Vector2.init(hs(135.0, scale), y + hs(20.0, scale)),
                hs(60.0, scale),
                hs(30.0, scale),
                0.0,
                colorWithAlpha(rl.Color.white, fade * 0.8),
            );
        }
        drawSmallText(assets, game_ids.weaponDisplayName(player.weapon.weapon_id, runner.session.state.preserve_bugs), hs(8.0, scale), y + hs(18.0, scale), colorWithAlpha(HudTextColor.primary, fade));
    }
}

fn drawAmmoIndicatorsAt(assets: *const window_assets.RuntimeAssets, texture_id: window_assets.TextureId, ammo: f32, clip_size: i32, scale: f32, base: rl.Vector2) void {
    const texture = assets.texture(texture_id);
    const ammo_count = @max(0, @as(i32, @intFromFloat(ammo)));
    var bars = @max(0, clip_size);
    if (bars > 30) bars = 20;
    var idx: i32 = 0;
    while (idx < bars) : (idx += 1) {
        const alpha: f32 = if (idx < ammo_count) 0.8 else 0.24;
        drawTextureFit(
            texture,
            rl.Rectangle.init(base.x + @as(f32, @floatFromInt(idx)) * hs(6.0, scale), base.y, hs(6.0, scale), hs(16.0, scale)),
            colorWithAlpha(rl.Color.white, alpha),
        );
    }
    if (ammo_count > bars) {
        drawSmallTextFmt("+ {d}", assets, .{ammo_count - bars}, base.x + @as(f32, @floatFromInt(bars)) * hs(6.0, scale) + hs(8.0, scale), base.y + hs(1.0, scale), HudTextColor.primary);
    }
}

fn weaponIndicatorTextureId(weapon_id: game_ids.WeaponId) window_assets.TextureId {
    return switch (weapon_id) {
        .rocket_launcher, .seeker_rockets, .mini_rocket_swarmers, .rocket_minigun, .nuke_launcher => .ui_ind_rocket,
        .ion_rifle, .ion_minigun, .ion_cannon, .ion_shotgun, .lightning_rifle => .ui_ind_electric,
        .flamethrower, .blow_torch, .hr_flamer, .flameburst, .fire_bullets => .ui_ind_fire,
        else => .ui_ind_bullet,
    };
}

fn xpProgressRatio(xp: i32, level: i32) f32 {
    const safe_level = @max(level, 1);
    const prev_threshold = if (safe_level <= 1) 0 else survivalLevelThreshold(safe_level - 1);
    const next_threshold = survivalLevelThreshold(safe_level);
    if (next_threshold <= prev_threshold) return 0.0;
    return std.math.clamp(
        @as(f32, @floatFromInt(xp - prev_threshold)) / @as(f32, @floatFromInt(next_threshold - prev_threshold)),
        @as(f32, 0.0),
        @as(f32, 1.0),
    );
}

fn survivalLevelThreshold(level: i32) i32 {
    const safe_level = @max(level, 1);
    return @intFromFloat(1000.0 + std.math.pow(f32, @floatFromInt(safe_level), 1.8) * 1000.0);
}

fn drawSmallText(
    runtime_assets: *const window_assets.RuntimeAssets,
    text: []const u8,
    x: f32,
    y: f32,
    color: rl.Color,
) void {
    const texture = runtime_assets.texture(.small_white);
    var x_pos = @floor(x);
    var y_pos = @floor(y);
    const base_x = x_pos;
    for (text) |value| {
        switch (value) {
            '\n' => {
                x_pos = base_x;
                y_pos += 16.0;
                continue;
            },
            '\r' => continue,
            else => {},
        }

        const width = runtime_assets.small_font_widths[value];
        if (width == 0) continue;
        const col = value % 16;
        const row = value / 16;
        rl.drawTexturePro(
            texture,
            rl.Rectangle.init(@as(f32, @floatFromInt(col * 16)), @as(f32, @floatFromInt(row * 16)), @floatFromInt(width), 16.0),
            rl.Rectangle.init(x_pos, y_pos, @floatFromInt(width), 16.0),
            rl.Vector2.zero(),
            0.0,
            color,
        );
        x_pos += @as(f32, @floatFromInt(width));
    }
}

fn measureSmallText(runtime_assets: *const window_assets.RuntimeAssets, text: []const u8) f32 {
    var width: f32 = 0.0;
    var best: f32 = 0.0;
    for (text) |value| {
        switch (value) {
            '\n' => {
                best = @max(best, width);
                width = 0.0;
                continue;
            },
            '\r' => continue,
            else => {},
        }
        width += @as(f32, @floatFromInt(runtime_assets.small_font_widths[value]));
    }
    return @max(best, width);
}

fn drawSmallTextFmt(
    comptime fmt: []const u8,
    runtime_assets: *const window_assets.RuntimeAssets,
    args: anytype,
    x: f32,
    y: f32,
    color: rl.Color,
) void {
    var buf: [256]u8 = undefined;
    const text = std.fmt.bufPrint(&buf, fmt, args) catch return;
    drawSmallText(runtime_assets, text, x, y, color);
}

fn drawSmallTextCentered(
    runtime_assets: *const window_assets.RuntimeAssets,
    text: []const u8,
    y: f32,
    color: rl.Color,
) void {
    const width = measureSmallText(runtime_assets, text);
    const x = (@as(f32, @floatFromInt(rl.getScreenWidth())) - width) * 0.5;
    drawSmallText(runtime_assets, text, x, y, color);
}

fn drawSmallTextCenteredAtX(
    runtime_assets: *const window_assets.RuntimeAssets,
    text: []const u8,
    center_x: f32,
    y: f32,
    color: rl.Color,
) void {
    const width = measureSmallText(runtime_assets, text);
    drawSmallText(runtime_assets, text, center_x - width * 0.5, y, color);
}

fn drawSmallTextCenteredFmtAtX(
    comptime fmt: []const u8,
    runtime_assets: *const window_assets.RuntimeAssets,
    args: anytype,
    center_x: f32,
    y: f32,
    color: rl.Color,
) void {
    var buf: [64]u8 = undefined;
    const text = std.fmt.bufPrint(&buf, fmt, args) catch return;
    drawSmallTextCenteredAtX(runtime_assets, text, center_x, y, color);
}

fn drawQuestFailedPreview(runtime_assets: *const window_assets.RuntimeAssets, results: *const ResultsScreen) void {
    const score_center_x = 500.0;
    const xp_center_x = 652.0;
    const top_y = 258.0;
    const value_y = top_y + 22.0;
    const separator_color = colorWithAlpha(rl.Color.init(149, 175, 198, 255), 0.7);
    const elapsed_seconds = @as(f32, @floatFromInt(results.summary.elapsed_ms_sim)) * 0.001;

    drawSmallTextCenteredAtX(runtime_assets, "Score", score_center_x, top_y, HudTextColor.dim);
    drawSmallTextCenteredFmtAtX("{d:.2} secs", runtime_assets, .{elapsed_seconds}, score_center_x, value_y, HudTextColor.primary);
    rl.drawLine(@intFromFloat((score_center_x + xp_center_x) * 0.5), @intFromFloat(top_y - 2.0), @intFromFloat((score_center_x + xp_center_x) * 0.5), @intFromFloat(value_y + 24.0), separator_color);
    drawSmallTextCenteredAtX(runtime_assets, "Experience", xp_center_x, top_y, HudTextColor.primary);
    drawSmallTextCenteredFmtAtX("{d}", runtime_assets, .{results.summary.player_experience}, xp_center_x, value_y, HudTextColor.dim);
}

fn drawBootAssetFallback(assets_state: AssetsState, assets_message: ?[]const u8) void {
    rl.clearBackground(rl.Color.black);
    const title = switch (assets_state) {
        .failed => "Failed to load runtime assets",
        .unavailable => "Runtime assets not found",
        .loaded => return,
    };
    const body = switch (assets_state) {
        .failed => assets_message orelse "Unknown asset load error.",
        .unavailable => "Set CRIMSON_ASSETS_DIR or run from a checkout with artifacts/assets.",
        .loaded => return,
    };
    rl.drawText(title, 48, 96, 28, rl.Color.init(245, 236, 225, 255));
    drawTextSlice(body, 48, 140, 18, rl.Color.init(204, 204, 214, 255));
}

fn drawGameplayHud(gameplay: *const GameplayScreen, runtime_assets: ?*const window_assets.RuntimeAssets) void {
    drawLiveRunnerHud(&gameplay.runner, gameplay.last_update, &gameplay.hud_state, runtime_assets);
}

fn drawLiveRunnerHud(runner: *const live_runner.LiveRunner, update: live_runner.FrameUpdate, hud_state: *const HudRuntimeState, runtime_assets: ?*const window_assets.RuntimeAssets) void {
    const players = runner.session.playersConst();
    if (players.len == 0) return;
    const player = players[0];
    if (runtime_assets) |assets| {
        const flags = hudFlagsForGameMode(runner.session.game_mode);
        const elapsed_ms = @as(f32, @floatFromInt(update.elapsed_ms_sim));
        const top_alpha = 0.7;
        const scale = hudUiScale();

        drawTextureFit(
            assets.texture(.ui_game_top),
            rl.Rectangle.init(0.0, 0.0, hs(512.0, scale), hs(64.0, scale)),
            colorWithAlpha(rl.Color.white, top_alpha),
        );

        if (flags.show_health) {
            const t = elapsed_ms * 0.001;
            const player0_low_health = player.health < 30.0;
            const ind_life = assets.texture(.ui_ind_life);

            for (players, 0..) |hud_player, idx| {
                const row = hudPlayerRowLayout(players.len, idx, scale);
                var pulse_speed: f32 = if (hud_player.health < 30.0) 5.0 else 2.0;
                if (runner.session.state.preserve_bugs and players.len > 1 and idx > 0 and player0_low_health) {
                    pulse_speed = 5.0;
                }
                const phase = @as(f32, @floatFromInt(idx)) * (std.math.pi * 0.5);
                const pulse = (std.math.pow(f32, std.math.sin(t * pulse_speed + phase), 4) * 4.0 + 14.0) * row.heart_scale;
                drawTextureCentered(
                    assets.texture(.ui_life_heart),
                    row.heart_center,
                    pulse * 2.0 * scale,
                    pulse * 2.0 * scale,
                    colorWithAlpha(rl.Color.white, 0.8),
                );

                drawTextureFit(ind_life, row.health_bar, colorWithAlpha(rl.Color.white, 0.5));
                if (hudHealthFillRect(row, hud_player.health)) |fill_rect| {
                    const health_ratio = fill_rect.width / row.health_bar.width;
                    rl.drawTexturePro(
                        ind_life,
                        rl.Rectangle.init(0.0, 0.0, @as(f32, @floatFromInt(ind_life.width)) * health_ratio, @floatFromInt(ind_life.height)),
                        fill_rect,
                        rl.Vector2.zero(),
                        0.0,
                        colorWithAlpha(rl.Color.white, 0.8),
                    );
                }
            }
        }

        if (flags.show_weapon) {
            for (players, 0..) |hud_player, idx| {
                const row = hudPlayerRowLayout(players.len, idx, scale);
                const weapon_id = hud_player.weapon.weapon_id;
                const icon_index = weapon_data.weaponIconIndex(weapon_id);
                if (icon_index >= 0) {
                    drawTextureRegionCenteredRotated(
                        assets.texture(.ui_wicons),
                        window_atlas.weaponIconRect(assets.texture(.ui_wicons).width, assets.texture(.ui_wicons).height, icon_index),
                        rl.Vector2.init(row.weapon_icon.x + row.weapon_icon.width * 0.5, row.weapon_icon.y + row.weapon_icon.height * 0.5),
                        row.weapon_icon.width,
                        row.weapon_icon.height,
                        0.0,
                        colorWithAlpha(rl.Color.white, 0.8),
                    );
                }
                drawAmmoIndicatorsAt(assets, weaponIndicatorTextureId(weapon_id), hud_player.weapon.ammo, hud_player.weapon.clip_size, scale, row.ammo_base);
            }
        }

        if (flags.show_quest_hud) {
            drawQuestHud(runner, update, assets, scale);
        }

        if (flags.show_xp) {
            const hud_y_shift: f32 = if (flags.show_quest_hud) hs(80.0, scale) else 0.0;
            drawTextureFit(
                assets.texture(.ui_ind_panel),
                rl.Rectangle.init(-hs(68.0, scale), hs(60.0, scale) + hud_y_shift, hs(182.0, scale), hs(53.0, scale)),
                colorWithAlpha(rl.Color.white, 0.9),
            );
            const xp_display = hud_state.survival_xp_smoothed;
            drawSmallText(assets, "Xp", hs(4.0, scale), hs(78.0, scale) + hud_y_shift, HudTextColor.dim);
            drawSmallTextFmt("{d}", assets, .{xp_display}, hs(26.0, scale), hs(74.0, scale) + hud_y_shift, HudTextColor.primary);
            drawSmallTextFmt("{d}", assets, .{update.player_level}, hs(85.0, scale), hs(79.0, scale) + hud_y_shift, HudTextColor.primary);
            drawProgressBar(rl.Vector2.init(hs(26.0, scale), hs(91.0, scale) + hud_y_shift), hs(54.0, scale), xpProgressRatio(update.player_experience, update.player_level), rl.Color.init(26, 77, 153, 255), scale);
        }

        if (flags.show_time) {
            drawModeClock(assets, elapsed_ms, hs(220.0, scale), hs(2.0, scale), scale);
            drawSmallTextFmt("{d} seconds", assets, .{@divTrunc(update.elapsed_ms_sim, 1000)}, hs(255.0, scale), hs(10.0, scale), HudTextColor.primary);
        }

        drawBonusHud(runner, hud_state, assets, scale);
        drawWeaponAuxHud(runner, hud_state, assets, scale);
        return;
    }

    rl.drawRectangleRounded(
        .{
            .x = 22.0,
            .y = 20.0,
            .width = 380.0,
            .height = 132.0,
        },
        0.14,
        8,
        overlay_color,
    );
    drawTextFmt("hp {d:.1}  level {d}  xp {d}", .{ player.health, update.player_level, update.player_experience }, 36, 34, 22, text_color);
    drawTextFmt("weapon {s}  ammo {d:.1}", .{ weaponName(update.player_weapon_id, false), player.weapon.ammo }, 36, 62, 22, text_color);
    drawTextFmt("shots {d}  hits {d}  creatures {d}", .{ update.shots_fired, update.shots_hit, update.creature_active_count }, 36, 90, 20, muted_text);
    drawTextFmt("elapsed {d}ms  pickups {d}  pending perks {d}", .{ update.elapsed_ms_sim, update.bonus_active_count, runner.perkPendingCount() }, 36, 116, 20, muted_text);
}

fn drawDemoAttractOverlay(elapsed_ms: i32, limit_ms: i32, message_index: usize) void {
    const metrics = demoUpsellOverlayMetrics(elapsed_ms, limit_ms, message_index);
    rl.drawRectangleRec(metrics.bg_rect, rl.Color.init(0, 0, 0, metrics.bg_alpha));
    rl.drawRectangleRec(metrics.bar_rect, rl.Color.init(128, 26, 26, metrics.bar_alpha));
    drawTextSlice(metrics.text, @intFromFloat(metrics.text_x), @intFromFloat(metrics.text_y), 16, rl.Color.init(255, 255, 255, metrics.text_alpha));
}

fn demoUpsellOverlayMetrics(timeline_ms: i32, limit_ms: i32, message_index: usize) DemoUpsellOverlayMetrics {
    const text = demo_upsell_messages[message_index % demo_upsell_messages.len];
    const timeline = @max(timeline_ms, 0);
    const limit = @max(limit_ms, 0);
    const vertical = @as(f32, @floatFromInt(timeline)) * 0.016;
    var alpha: f32 = 1.0;
    if (vertical < 20.0) {
        alpha = vertical * 0.05;
    }
    if (timeline > limit - 500) {
        alpha = @as(f32, @floatFromInt(limit - timeline)) * 0.002;
    }
    alpha = std.math.clamp(alpha, @as(f32, 0.0), @as(f32, 1.0));

    const text_width = @as(f32, @floatFromInt(text.len)) * 12.8;
    const text_y = vertical + 50.0;
    const progress = if (limit > 0)
        std.math.clamp(@as(f32, @floatFromInt(timeline)) / @as(f32, @floatFromInt(limit)), @as(f32, 0.0), @as(f32, 1.0))
    else
        0.0;

    return .{
        .text = text,
        .text_x = 50.0,
        .text_y = text_y,
        .text_width = text_width,
        .bg_rect = rl.Rectangle.init(60.0, text_y - 4.0, text_width + 12.0, 30.0),
        .bar_rect = rl.Rectangle.init(64.0, vertical + 72.0, text_width * progress, 3.0),
        .text_alpha = alphaByte(alpha),
        .bg_alpha = alphaByte(alpha * 0.5),
        .bar_alpha = alphaByte(alpha * 0.8),
    };
}

fn alphaByte(alpha: f32) u8 {
    return @intFromFloat(@round(std.math.clamp(alpha, @as(f32, 0.0), @as(f32, 1.0)) * 255.0));
}

fn drawDemoAttractPurchaseInterstitial(
    runtime_assets: ?*const window_assets.RuntimeAssets,
    elapsed_ms: i32,
    limit_ms: i32,
    state: *const DemoAttractPurchaseState,
) void {
    if (runtime_assets) |assets| {
        drawDemoAttractPurchaseScreenAssets(assets, elapsed_ms);
    } else {
        const remaining_ms = @max(0, limit_ms - elapsed_ms);
        const remaining_tenths = @divTrunc(remaining_ms + 99, 100);
        const remaining_whole = @divTrunc(remaining_tenths, 10);
        const remaining_frac = @mod(remaining_tenths, 10);
        const center_y = @divTrunc(rl.getScreenHeight(), 2);
        drawCenteredText(demo_purchase_title, center_y - 72, 24, text_color);
        drawCenteredText("Full version features more levels, weapons, perks, and unlimited play time.", center_y - 34, 18, text_color);
        drawCenteredText("Choose an option", center_y + 8, 18, muted_text);
        drawCenteredTextFmt("demo resumes in {d}.{d}s", .{ remaining_whole, remaining_frac }, center_y + 42, 18, muted_text);
    }
    const buttons = demoAttractPurchaseButtons();
    for (buttons, 0..) |button, idx| {
        const hovered = rl.checkCollisionPointRec(rl.getMousePosition(), button.rect);
        window_ui.drawButton(button, idx == state.selection, hovered, runtime_assets);
    }
    if (runtime_assets) |assets| {
        window_cursor.drawMenuCursor(assets, state.cursor_pulse_time);
    }
}

fn drawDemoAttractPurchaseScreenAssets(assets: *const window_assets.RuntimeAssets, elapsed_ms: i32) void {
    const screen_w = @as(f32, @floatFromInt(rl.getScreenWidth()));
    const screen_h = @as(f32, @floatFromInt(rl.getScreenHeight()));
    const wide_shift = demoAttractPurchaseWideShift(screen_w);
    drawDemoPurchaseBackplasma(assets.texture(.backplasma), screen_w, screen_h, elapsed_ms);
    drawTextureFit(
        assets.texture(.mockup),
        rl.Rectangle.init(screen_w * 0.5 - 128.0 + wide_shift, screen_h * 0.5 - 140.0, 512.0, 256.0),
        rl.Color.white,
    );
    drawTextureFit(
        assets.texture(.cl_logo),
        rl.Rectangle.init(screen_w * 0.5 - 256.0, screen_h * 0.5 - 200.0 - wide_shift * 0.4, 512.0, 64.0),
        rl.Color.white,
    );

    const text_x = screen_w * 0.5 - 296.0 - wide_shift * 0.8;
    var y = screen_h * 0.5 - 104.0;
    drawSmallText(assets, demo_purchase_title, text_x, y, rl.Color.white);
    y += 28.0;
    drawSmallText(assets, demo_purchase_features_title, text_x, y, rl.Color.white);
    rl.drawRectangleRec(
        rl.Rectangle.init(text_x, y + 15.0, measureSmallText(assets, demo_purchase_features_title), 2.0),
        rl.Color.init(255, 255, 255, 160),
    );

    y += 22.0;
    for (demo_purchase_feature_lines) |line| {
        drawSmallText(assets, line.text, text_x + 8.0, y, rl.Color.white);
        y += line.delta_y;
    }
    drawSmallText(assets, demo_purchase_footer, text_x, y, rl.Color.white);
}

fn drawDemoPurchaseBackplasma(texture: rl.Texture2D, screen_w: f32, screen_h: f32, elapsed_ms: i32) void {
    const colors = demoPurchaseBackplasmaColors(elapsed_ms);
    rl.beginBlendMode(.alpha);
    rl.gl.rlSetTexture(texture.id);
    rl.gl.rlBegin(rl.gl.rl_quads);
    rl.gl.rlColor4ub(colors.top_left.r, colors.top_left.g, colors.top_left.b, colors.top_left.a);
    rl.gl.rlTexCoord2f(0.0, 0.0);
    rl.gl.rlVertex2f(0.0, 0.0);
    rl.gl.rlColor4ub(colors.top_right.r, colors.top_right.g, colors.top_right.b, colors.top_right.a);
    rl.gl.rlTexCoord2f(0.5, 0.0);
    rl.gl.rlVertex2f(screen_w, 0.0);
    rl.gl.rlColor4ub(colors.bottom_right.r, colors.bottom_right.g, colors.bottom_right.b, colors.bottom_right.a);
    rl.gl.rlTexCoord2f(0.5, 0.5);
    rl.gl.rlVertex2f(screen_w, screen_h);
    rl.gl.rlColor4ub(colors.bottom_left.r, colors.bottom_left.g, colors.bottom_left.b, colors.bottom_left.a);
    rl.gl.rlTexCoord2f(0.0, 0.5);
    rl.gl.rlVertex2f(0.0, screen_h);
    rl.gl.rlEnd();
    rl.gl.rlSetTexture(0);
    rl.endBlendMode();
}

fn demoPurchaseBackplasmaColors(elapsed_ms: i32) DemoPurchaseBackplasmaColors {
    const pulse_phase = @mod(@as(f32, @floatFromInt(@max(elapsed_ms, 0))), 1000.0);
    const pulse_s = @sin(pulse_phase * 0.0062831855);
    const pulse = pulse_s * pulse_s;
    return .{
        .top_left = colorFromUnitRgba(0.0, 0.0, 0.0, 1.0),
        .top_right = colorFromUnitRgba(0.0, 0.0, 0.3, 1.0),
        .bottom_right = colorFromUnitRgba(0.0, 0.4, pulse * 0.55, pulse),
        .bottom_left = colorFromUnitRgba(0.0, 0.4, 0.4, 1.0),
    };
}

fn colorFromUnitRgba(r: f32, g: f32, b: f32, a: f32) rl.Color {
    return rl.Color.init(alphaByte(r), alphaByte(g), alphaByte(b), alphaByte(a));
}

fn drawTypoNameLabels(
    runner: *const live_runner.LiveRunner,
    assets: *const window_assets.RuntimeAssets,
    transform: window_viewport.ViewTransform,
    entity_alpha: f32,
) void {
    for (runner.session.creatures.entries, 0..) |creature, idx| {
        if (!creature.active) continue;
        const label = runner.session.state.typo.names.nameSlice(idx);
        if (label.len == 0) continue;

        var label_alpha = entity_alpha;
        if (creature.lifecycle_stage < 0.0) {
            label_alpha *= std.math.clamp((creature.lifecycle_stage + 10.0) * 0.1, @as(f32, 0.0), @as(f32, 1.0));
        }
        if (!(label_alpha > 1e-3)) continue;

        const screen_x = (creature.pos.x + transform.camera.x) * transform.view_scale.x;
        const screen_y = (creature.pos.y + transform.camera.y) * transform.view_scale.y;
        const text_w = measureSmallText(assets, label);
        const x = screen_x - text_w * 0.5;
        const y = screen_y - 50.0;

        rl.drawRectangleRec(
            .{
                .x = x - 4.0,
                .y = y,
                .width = text_w + 8.0,
                .height = 15.0,
            },
            colorWithAlpha(rl.Color.black, label_alpha * 0.67),
        );
        drawSmallText(assets, label, x, y, colorWithAlpha(rl.Color.white, label_alpha));
    }
}

fn drawTypoTypingBox(gameplay: *const GameplayScreen, assets: *const window_assets.RuntimeAssets) void {
    const screen_h: f32 = @floatFromInt(rl.getScreenHeight());
    const panel_y = screen_h - 144.0;
    const text_y = screen_h - 127.0;

    drawTextureFit(
        assets.texture(.ui_ind_panel),
        rl.Rectangle.init(-1.0, panel_y, 182.0, 53.0),
        colorWithAlpha(rl.Color.white, 0.7),
    );

    const text = gameplay.runner.session.state.typo.typing.slice();
    drawSmallTextFmt(">{s}", assets, .{text}, 6.0, text_y, rl.Color.white);

    const cursor_dim = std.math.sin(gameplay.render_time_s * 4.0) > 0.0;
    const cursor_alpha: f32 = if (cursor_dim) 0.4 else 1.0;
    const cursor_x = measureSmallText(assets, text) + 14.0;
    drawSmallText(assets, "_", cursor_x, text_y, colorWithAlpha(rl.Color.white, cursor_alpha));
}

fn drawTutorialOverlay(gameplay: *const GameplayScreen, assets: *const window_assets.RuntimeAssets) void {
    const overlay = gameplay.runner.session.state.tutorial_overlay;
    if (overlay.prompt_stage_index >= 0 and overlay.prompt_alpha > 1e-3) {
        drawTutorialPanel(
            assets,
            tutorial_runtime.promptText(overlay.prompt_stage_index),
            64.0,
            overlay.prompt_alpha,
        );
    }
    if (overlay.hint_index >= 0 and overlay.hint_alpha > 1e-3) {
        drawTutorialPanel(
            assets,
            tutorial_runtime.hintText(overlay.hint_index, gameplay.runner.session.state.tutorial.preserve_bugs),
            148.0,
            overlay.hint_alpha,
        );
    }

    drawTutorialPromptButtons(gameplay, assets);
}

fn tutorialPanelRect(
    assets: *const window_assets.RuntimeAssets,
    text: []const u8,
    top_y: f32,
) ?rl.Rectangle {
    if (text.len == 0) return null;
    var lines = std.mem.splitScalar(u8, text, '\n');
    var max_w: f32 = 0.0;
    var line_count: usize = 0;
    while (lines.next()) |line| {
        max_w = @max(max_w, measureSmallText(assets, line));
        line_count += 1;
    }

    const line_h: f32 = 14.0;
    const pad_x: f32 = 20.0;
    const pad_y: f32 = 8.0;
    const width = max_w + pad_x * 2.0;
    const height = @as(f32, @floatFromInt(line_count)) * line_h + pad_y * 2.0;
    const left = (@as(f32, @floatFromInt(rl.getScreenWidth())) - width) * 0.5;
    return rl.Rectangle.init(left, top_y, width, height);
}

fn drawTutorialPanel(
    assets: *const window_assets.RuntimeAssets,
    text: []const u8,
    top_y: f32,
    alpha: f32,
) void {
    if (text.len == 0 or !(alpha > 1e-3)) return;

    const rect = tutorialPanelRect(assets, text, top_y) orelse return;
    rl.drawRectangle(
        @intFromFloat(rect.x),
        @intFromFloat(rect.y),
        @intFromFloat(rect.width),
        @intFromFloat(rect.height),
        colorWithAlpha(rl.Color.black, alpha * 0.8),
    );
    rl.drawRectangleLines(
        @intFromFloat(rect.x),
        @intFromFloat(rect.y),
        @intFromFloat(rect.width),
        @intFromFloat(rect.height),
        colorWithAlpha(rl.Color.white, alpha),
    );

    const pad_x: f32 = 20.0;
    const pad_y: f32 = 8.0;
    const line_h: f32 = 14.0;
    var lines = std.mem.splitScalar(u8, text, '\n');
    var y = rect.y + pad_y;
    while (lines.next()) |line| : (y += line_h) {
        drawSmallText(assets, line, rect.x + pad_x, y, colorWithAlpha(rl.Color.white, alpha * 0.9));
    }
}

const TutorialPromptAction = enum {
    none,
    close_to_menu,
    restart,
};

fn tutorialSkipButton() UiButton {
    return window_ui.buttonAt("Skip tutorial", 10.0, @as(f32, @floatFromInt(rl.getScreenHeight())) - 50.0, true);
}

fn tutorialCompleteButtons(gameplay: *const GameplayScreen, assets: *const window_assets.RuntimeAssets) [2]UiButton {
    const text = tutorial_runtime.promptText(gameplay.runner.session.state.tutorial_overlay.prompt_stage_index);
    const rect = tutorialPanelRect(assets, text, 64.0) orelse rl.Rectangle.init(0.0, 64.0, 320.0, 40.0);
    const gap: f32 = 18.0;
    const top_y = rect.y + rect.height + 10.0;
    const play_w = window_ui.buttonWidth("Play a game", true);
    const repeat_w = window_ui.buttonWidth("Repeat tutorial", true);
    return .{
        .{
            .label = "Play a game",
            .rect = rl.Rectangle.init(rect.x + 10.0, top_y, play_w, window_ui.button_plate_height),
        },
        .{
            .label = "Repeat tutorial",
            .rect = rl.Rectangle.init(rect.x + 10.0 + play_w + gap, top_y, repeat_w, window_ui.button_plate_height),
        },
    };
}

fn updateTutorialPromptButtons(self: *App, gameplay: *GameplayScreen) TutorialPromptAction {
    const overlay = gameplay.runner.session.state.tutorial_overlay;
    const tutorial = gameplay.runner.session.state.tutorial;
    if (overlay.prompt_stage_index < 0 or overlay.prompt_alpha <= 1e-3) return .none;

    if (tutorial.stage_index == 8) {
        const assets = if (self.runtime_assets) |*runtime_assets| runtime_assets else return .none;
        const buttons = tutorialCompleteButtons(gameplay, assets);
        window_ui.updateSelectionFromPointer(&gameplay.tutorial_prompt_selection, buttons[0..]);
        if (rl.isKeyPressed(.left) or rl.isKeyPressed(.a)) {
            gameplay.tutorial_prompt_selection = if (gameplay.tutorial_prompt_selection == 0) buttons.len - 1 else gameplay.tutorial_prompt_selection - 1;
        }
        if (rl.isKeyPressed(.right) or rl.isKeyPressed(.d)) {
            gameplay.tutorial_prompt_selection = (gameplay.tutorial_prompt_selection + 1) % buttons.len;
        }
        if (!window_ui.buttonActivated(buttons[0..], gameplay.tutorial_prompt_selection)) return .none;
        self.audio.playUiButtonClick();
        return if (gameplay.tutorial_prompt_selection == 0) .close_to_menu else .restart;
    }

    const skip_alpha = std.math.clamp(@as(f32, @floatFromInt(tutorial.stage_timer_ms - 1000)) * 0.001, @as(f32, 0.0), @as(f32, 1.0));
    if (skip_alpha <= 1e-3) return .none;
    const button = tutorialSkipButton();
    gameplay.tutorial_prompt_selection = 0;
    if (!window_ui.buttonActivated(&.{button}, 0)) return .none;
    self.audio.playUiButtonClick();
    return .close_to_menu;
}

fn drawTutorialPromptButtons(gameplay: *const GameplayScreen, assets: *const window_assets.RuntimeAssets) void {
    const overlay = gameplay.runner.session.state.tutorial_overlay;
    if (overlay.prompt_stage_index < 0 or overlay.prompt_alpha <= 1e-3) return;

    if (gameplay.runner.session.state.tutorial.stage_index == 8) {
        const buttons = tutorialCompleteButtons(gameplay, assets);
        for (buttons, 0..) |button, idx| {
            const hovered = rl.checkCollisionPointRec(rl.getMousePosition(), button.rect);
            window_ui.drawButton(
                button,
                idx == gameplay.tutorial_prompt_selection,
                hovered,
                assets,
            );
        }
        return;
    }

    const skip_alpha = std.math.clamp(@as(f32, @floatFromInt(gameplay.runner.session.state.tutorial.stage_timer_ms - 1000)) * 0.001, @as(f32, 0.0), @as(f32, 1.0));
    if (skip_alpha <= 1e-3) return;
    const button = tutorialSkipButton();
    const hovered = rl.checkCollisionPointRec(rl.getMousePosition(), button.rect);
    window_ui.drawButton(button, false, hovered, assets);
}

fn zeroSessionSummary() runtime_session.SessionSummary {
    return .{
        .ticks_processed = 0,
        .event_index = 0,
        .elapsed_ms_sim = 0,
        .perk_menu_open_count = 0,
        .perk_pick_count = 0,
        .fire_pressed_count = 0,
        .reload_pressed_count = 0,
        .stage_spawn_count = 0,
        .wave_spawn_count = 0,
        .wave_spawn_rng_state = 0,
        .player_level = 0,
        .player_experience = 0,
        .player_weapon_id = @intFromEnum(game_ids.WeaponId.pistol),
        .perk_pending_count = 0,
        .creature_active_count = 0,
    };
}

fn nextRunSeed(seed_state: *u32) u32 {
    seed_state.* = nextRunSeedFromState(seed_state.*);
    return seed_state.*;
}

fn nextRunSeedFromState(seed_state: u32) u32 {
    const next_seed = seed_state *% 1664525 +% 1013904223;
    return if (next_seed == 0) 1 else next_seed;
}

fn takeSeedOverride(seed_state: *u32, seed_override: *?u32) u32 {
    if (seed_override.*) |seed| {
        seed_override.* = null;
        return if (seed == 0) 1 else seed;
    }
    return nextRunSeed(seed_state);
}

fn nextQuestLevelKey(level_key: i32) ?i32 {
    const stage = @divTrunc(level_key, 100);
    const minor = @mod(level_key, 100);
    if (stage < 1 or stage > 5 or minor < 1 or minor > 10) return null;
    if (isFinalQuestLevelKey(level_key)) return null;
    if (minor < 10) return stage * 100 + minor + 1;
    return (stage + 1) * 100 + 1;
}

fn isFinalQuestLevelKey(level_key: i32) bool {
    return level_key == final_quest_level_key;
}

fn runConfigForLiveMode(mode: game_ids.GameModeId, quest_level_key: ?i32, seed_state: *u32) live_runner.LiveModeConfig {
    return runConfigForLiveModeWithSeed(mode, quest_level_key, nextRunSeed(seed_state));
}

fn runConfigForLiveModeWithSeed(mode: game_ids.GameModeId, quest_level_key: ?i32, seed: u32) live_runner.LiveModeConfig {
    return switch (mode) {
        .rush => .{
            .seed = seed,
            .game_mode = .rush,
        },
        .quests => .{
            .seed = seed,
            .game_mode = .quests,
            .quest_level_key = quest_level_key orelse 101,
        },
        .typo => .{
            .seed = seed,
            .game_mode = .typo,
        },
        .tutorial => .{
            .seed = seed,
            .game_mode = .tutorial,
        },
        else => .{
            .seed = seed,
            .game_mode = .survival,
        },
    };
}

fn monotonicMs(io: std.Io) i64 {
    return std.Io.Timestamp.now(io, .awake).toMilliseconds();
}

fn livePlayerCountForMode(mode: game_ids.GameModeId, requested_player_count: i32) i32 {
    return switch (mode) {
        .typo, .tutorial => 1,
        else => std.math.clamp(requested_player_count, @as(i32, 1), @as(i32, 4)),
    };
}

fn resultsTitle(reason: ResultsReason) [:0]const u8 {
    return switch (reason) {
        .dead => "Run Over",
        .completed => "Quest Complete",
        .runtime_error => "Run Interrupted",
        .abandoned => "Run Abandoned",
    };
}

fn resultsSubtitle(reason: ResultsReason) [:0]const u8 {
    return switch (reason) {
        .dead => "All players are down.",
        .completed => "Quest objectives cleared.",
        .abandoned => "Run returned to menu before completion.",
        .runtime_error => "Runtime could not complete the run.",
    };
}

fn weaponName(weapon_id_raw: i32, preserve_bugs: bool) []const u8 {
    const weapon_id = std.enums.fromInt(game_ids.WeaponId, weapon_id_raw) orelse return "unknown";
    return game_ids.weaponDisplayName(weapon_id, preserve_bugs);
}

fn toRlVec(vec: state_mod.Vec2) rl.Vector2 {
    return .{
        .x = vec.x,
        .y = vec.y,
    };
}

fn drawCenteredText(text: [:0]const u8, y: i32, font_size: i32, color: rl.Color) void {
    const width = rl.measureText(text, font_size);
    const x = @divTrunc(rl.getScreenWidth() - width, 2);
    rl.drawText(text, x, y, font_size, color);
}

fn drawCenteredTextFmt(comptime fmt: []const u8, args: anytype, y: i32, font_size: i32, color: rl.Color) void {
    var buf: [256]u8 = undefined;
    const text = std.fmt.bufPrintZ(&buf, fmt, args) catch return;
    drawCenteredText(text, y, font_size, color);
}

fn drawTextFmt(comptime fmt: []const u8, args: anytype, x: i32, y: i32, font_size: i32, color: rl.Color) void {
    var buf: [256]u8 = undefined;
    const text = std.fmt.bufPrintZ(&buf, fmt, args) catch return;
    rl.drawText(text, x, y, font_size, color);
}

fn drawTextSlice(text: []const u8, x: i32, y: i32, font_size: i32, color: rl.Color) void {
    var buf: [256]u8 = undefined;
    const z = std.fmt.bufPrintZ(&buf, "{s}", .{text}) catch return;
    rl.drawText(z, x, y, font_size, color);
}
