test {
    const std = @import("std");
    const cz = @import("crimson_zig");

    _ = @import("app_runtime.zig");
    _ = cz.anim;
    _ = @import("audio/mod.zig");
    _ = cz.bonuses;
    _ = cz.checkpoint_diff_native;
    _ = cz.config_native;
    _ = cz.creatures;
    _ = cz.dbg_record_native;
    _ = cz.dbg_verify_native;
    _ = cz.effects;
    _ = cz.terrain_fx;
    _ = cz.demo_trial;
    _ = cz.hash;
    _ = cz.formats;
    _ = cz.helpers;
    _ = @import("input_codes.zig");
    _ = cz.local_input;
    _ = cz.lifecycle;
    _ = cz.live_runner;
    std.testing.refAllDecls(cz.net_lockstep_smoke_native);
    _ = cz.net_lockstep_smoke_native;
    std.testing.refAllDecls(cz.net_rollback_smoke_native);
    _ = cz.net_rollback_smoke_native;
    _ = cz.net_session_native;
    _ = cz.net;
    std.testing.refAllDecls(cz.net.lockstep_live_bridge);
    std.testing.refAllDecls(cz.net.lockstep_live_session);
    std.testing.refAllDecls(cz.net.rollback_live_bridge);
    std.testing.refAllDecls(cz.net.rollback_live_session);

    var host_status = std.mem.zeroes(cz.formats.game_cfg.Status);
    host_status.quest_unlock_index = 2;
    var host_runtime = cz.net.lockstep_host_runtime.HostRuntime.init(.{
        .mode_id = @intFromEnum(cz.game_ids.GameModeId.rush),
        .player_count = 2,
        .build_id = "0.1.0",
        .session_id = "test-root",
        .seed = 2468,
        .status = host_status,
        .input_delay_ticks = 0,
    });
    defer host_runtime.deinit(std.testing.allocator);
    const host_config = try cz.net.lockstep_live_bridge.liveConfigFromHostRuntime(host_runtime);
    try std.testing.expectEqual(cz.game_ids.GameModeId.rush, host_config.game_mode);
    try std.testing.expectEqual(@as(u32, 2468), host_config.seed);
    try std.testing.expectEqual(@as(i32, 2), host_config.status_quest_unlock_index);

    var client_runtime = cz.net.lockstep_client_runtime.ClientRuntime.init(.{
        .mode_id = @intFromEnum(cz.game_ids.GameModeId.survival),
        .player_count = 2,
        .build_id = "0.1.0",
        .host_addr = cz.net.lockstep_transport.PeerAddr.loopback(cz.net.lockstep_protocol.default_port),
        .input_delay_ticks = 0,
    });
    defer {
        client_runtime.lobby.match_start = null;
        client_runtime.deinit(std.testing.allocator);
    }
    client_runtime.lobby.ingestMatchStart(.{
        .session_id = "test-root",
        .mode_id = @intFromEnum(cz.game_ids.GameModeId.survival),
        .player_count = 2,
        .seed = 8642,
        .status = std.mem.zeroes(cz.formats.game_cfg.Status),
    });
    const client_config = try (cz.net.lockstep_live_bridge.liveConfigFromClientRuntime(client_runtime) orelse return error.ExpectedLiveConfig);
    try std.testing.expectEqual(cz.game_ids.GameModeId.survival, client_config.game_mode);
    try std.testing.expectEqual(@as(u32, 8642), client_config.seed);

    var bridge_runner = try cz.live_runner.LiveRunner.init(.{ .player_count = 2 });
    var bridge_inputs = [_]cz.net.packed_input.PackedPlayerInput{
        .{ .move_x = 1.0, .flags = cz.net.lockstep_input_adapter.move_mode_present_flag | (@as(u32, 3) << cz.net.lockstep_input_adapter.move_mode_shift) },
        .{ .move_y = 1.0, .flags = cz.net.lockstep_input_adapter.move_mode_present_flag | (@as(u32, 3) << cz.net.lockstep_input_adapter.move_mode_shift) },
    };
    const bridge_update = try cz.net.lockstep_live_bridge.stepHostReadyTick(&bridge_runner, .{
        .tick_index = 0,
        .frame_inputs = bridge_inputs[0..],
    });
    try std.testing.expectEqual(@as(usize, 1), bridge_update.ticks_advanced);
    try std.testing.expectEqual(@as(usize, 1), bridge_runner.session.tick_index);

    const bridge_commands = [_]cz.net.lockstep_protocol.GameCommand{
        .{ .perk_pick = .{ .player_index = 0, .choice_index = 1 } },
        .{ .typo_char = .{ .player_index = 0, .ch = "x" } },
    };
    const command_input = try cz.net.lockstep_live_bridge.frameInputFromTickFrame(.{
        .frame_inputs = &[_]cz.net.packed_input.PackedPlayerInput{.{ .flags = cz.net.lockstep_input_adapter.fire_pressed_flag }},
        .commands = &bridge_commands,
    });
    try std.testing.expect(command_input.players[0].flags.fire_pressed);
    try std.testing.expectEqual(@as(?i32, 1), command_input.perk_choice_index);
    try std.testing.expectEqual(@as(?u8, 'x'), command_input.typo_char);

    var rollback_runner = try cz.live_runner.LiveRunner.init(.{ .game_mode = .survival });
    rollback_runner.session.elapsed_ms_sim = 123.0;
    rollback_runner.session.spawn_stage = 3;
    rollback_runner.session.spawn_cooldown = 45.0;
    const rollback_snapshot = (try cz.net.rollback_live_bridge.modeSnapshotFromRunner(&rollback_runner, 10)).?;
    var rollback_restored = try cz.live_runner.LiveRunner.init(.{ .game_mode = .survival });
    try cz.net.rollback_live_bridge.applyModeSnapshotToRunner(&rollback_restored, rollback_snapshot);
    try std.testing.expectEqual(@as(usize, 11), rollback_restored.session.tick_index);
    try std.testing.expectApproxEqAbs(@as(f32, 123.0), rollback_restored.session.elapsed_ms_sim, 0.001);
    try std.testing.expectEqual(@as(i32, 3), rollback_restored.session.spawn_stage);

    var rollback_live = cz.net.rollback_live_session.LiveSession.init(.{
        .server_addr = cz.net.relay_transport.PeerAddr.loopback(1),
        .bind_host = "127.0.0.1",
        .session = .{
            .role = .join,
            .mode_id = @intFromEnum(cz.game_ids.GameModeId.survival),
            .player_count = 1,
            .build_id = "0.1.0",
            .input_delay_ticks = 0,
        },
    });
    defer rollback_live.deinit(std.testing.allocator, std.Io.Threaded.global_single_threaded.io());
    rollback_live.session.match_config = .{
        .seed = 1234,
        .mode_id = @intFromEnum(cz.game_ids.GameModeId.survival),
        .player_count = 1,
        .input_delay_ticks = 0,
    };
    rollback_live.session.local_slot_index = 0;
    rollback_live.session.runtime = cz.net.rollback_runtime.RuntimeCore.init(std.testing.allocator, .{
        .role = .join,
        .player_count = 1,
        .local_slot_index = 0,
        .input_delay_ticks = 0,
        .max_rollback_ticks = 8,
    });
    _ = try rollback_live.ensureLiveRunner();
    for (0..5) |idx| {
        try rollback_live.session.runtime.?.queueLocalInput(.{ .flags = @intCast(idx) }, 1000 + @as(i64, @intCast(idx)));
    }
    _ = try rollback_live.stepFrames(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 2), rollback_live.session.runtime.?.snapshot_blobs.items.len);
    try std.testing.expectEqual(@as(i32, 4), rollback_live.session.runtime.?.snapshot_blobs.items[1].tick_index);

    const resync_payload = try cz.net.rollback_resync_v5.encodeModeSnapshot(std.testing.allocator, .{ .survival = .{
        .tick_index = 8,
        .runtime_state = .{
            .elapsed_ms = 144.0,
            .stage = 2,
            .spawn_cooldown_ms = 88.0,
            .perk_pending_count = 5,
        },
    } });
    rollback_live.session.runtime.?.pending_resync_snapshot = .{
        .tick_index = 8,
        .payload = resync_payload,
    };
    rollback_live.session.runtime.?.paused_for_resync = true;
    _ = try rollback_live.stepFrames(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 9), rollback_live.runner.?.session.tick_index);
    try std.testing.expectApproxEqAbs(@as(f32, 144.0), rollback_live.runner.?.session.elapsed_ms_sim, 0.001);
    try std.testing.expect(!rollback_live.session.runtime.?.paused_for_resync);

    var host_live = try cz.net.lockstep_live_session.HostLiveSession.init(.{
        .mode_id = @intFromEnum(cz.game_ids.GameModeId.survival),
        .player_count = 2,
        .build_id = "0.1.0",
        .session_id = "test-root-live",
        .seed = 9753,
        .input_delay_ticks = 0,
    });
    defer host_live.deinit(std.testing.allocator, std.Io.Threaded.global_single_threaded.io());
    try std.testing.expectEqual(@as(u32, 9753), host_live.runner.seed);
    host_live.session.runtime.lockstep = .{ .player_count = 2, .input_delay_ticks = 0 };
    try host_live.session.runtime.lockstep.?.submitInputSample(std.testing.allocator, 0, 0, .{
        .move_x = 1.0,
        .flags = cz.net.lockstep_input_adapter.move_mode_present_flag |
            (@as(u32, 3) << cz.net.lockstep_input_adapter.move_mode_shift),
    });
    try host_live.session.runtime.lockstep.?.submitInputSample(std.testing.allocator, 1, 0, .{
        .move_y = 1.0,
        .flags = cz.net.lockstep_input_adapter.move_mode_present_flag |
            (@as(u32, 3) << cz.net.lockstep_input_adapter.move_mode_shift),
    });
    const host_live_steps = try host_live.stepReadyFrames(std.testing.allocator, 10);
    try std.testing.expectEqual(@as(usize, 1), host_live_steps.frames_advanced);
    try std.testing.expectEqual(@as(?i32, 0), host_live_steps.last_tick_index);
    try std.testing.expectEqual(@as(usize, 2), host_live_steps.last_player_count);
    try std.testing.expect(host_live_steps.last_input_flags[0] != 0);
    try std.testing.expect(host_live_steps.last_input_flags[1] != 0);
    try std.testing.expectEqual(@as(usize, 1), host_live.runner.session.tick_index);

    var client_live = cz.net.lockstep_live_session.ClientLiveSession.init(.{
        .mode_id = @intFromEnum(cz.game_ids.GameModeId.survival),
        .player_count = 2,
        .build_id = "0.1.0",
        .host_addr = cz.net.lockstep_transport.PeerAddr.loopback(cz.net.lockstep_protocol.default_port),
        .input_delay_ticks = 0,
    });
    defer {
        client_live.session.runtime.lobby.match_start = null;
        client_live.deinit(std.testing.allocator, std.Io.Threaded.global_single_threaded.io());
    }
    try std.testing.expect(!try client_live.ensureLiveRunner());
    client_live.session.runtime.lobby.ingestMatchStart(.{
        .session_id = "test-root-live",
        .mode_id = @intFromEnum(cz.game_ids.GameModeId.survival),
        .player_count = 2,
        .seed = 7531,
    });
    try std.testing.expect(try client_live.ensureLiveRunner());
    try std.testing.expectEqual(@as(u32, 7531), client_live.runner.?.seed);
    client_live.session.runtime.lockstep = .{ .local_slot_index = 1, .input_delay_ticks = 0 };
    try client_live.session.runtime.lockstep.?.ingestTickFrame(std.testing.allocator, .{
        .tick_index = 0,
        .frame_inputs = &bridge_inputs,
    }, 20);
    const client_live_steps = try client_live.stepCanonicalFrames(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), client_live_steps.frames_advanced);
    try std.testing.expectEqual(@as(?i32, 0), client_live_steps.last_tick_index);
    try std.testing.expectEqual(@as(usize, 2), client_live_steps.last_player_count);
    try std.testing.expectEqual(bridge_inputs[0].flags, client_live_steps.last_input_flags[0]);
    try std.testing.expectEqual(bridge_inputs[1].flags, client_live_steps.last_input_flags[1]);
    try std.testing.expectEqual(@as(usize, 1), client_live.runner.?.session.tick_index);

    const smoke_output = try cz.net_lockstep_smoke_native.runLockstepSmoke(
        std.testing.allocator,
        std.Io.Threaded.global_single_threaded.io(),
        &.{"--json"},
    );
    defer smoke_output.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u8, 0), smoke_output.exit_code);
    try std.testing.expect(std.mem.indexOf(u8, smoke_output.stdout, "\"host_input_flags\": 3") != null);

    const rollback_smoke_output = try cz.net_rollback_smoke_native.runRollbackSmoke(
        std.testing.allocator,
        std.Io.Threaded.global_single_threaded.io(),
        &.{ "--json", "--impair", "guest-double-reconnect" },
    );
    defer rollback_smoke_output.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u8, 0), rollback_smoke_output.exit_code);
    try std.testing.expect(std.mem.indexOf(u8, rollback_smoke_output.stdout, "\"host_reconnect_count\": 2") != null);
    try std.testing.expect(std.mem.indexOf(u8, rollback_smoke_output.stdout, "\"guest_reconnect_count\": 2") != null);

    _ = cz.perks;
    _ = cz.persistence;
    _ = cz.projectiles;
    _ = cz.quest_level;
    _ = cz.quest_spawn_logic_full;
    _ = cz.quest_spawn_native;
    _ = cz.spawn_plan_native;
    _ = cz.replay_benchmark_native;
    _ = cz.replay_codec;
    _ = cz.replay_runner;
    _ = cz.secondary_projectiles;
    _ = cz.session;
    _ = cz.session_builders;
    _ = cz.spawn;
    _ = cz.state;
    _ = cz.status_native;
    _ = cz.ui_formatting;
    _ = cz.weapon_data;
    _ = cz.weapons;
    _ = cz.window_atlas;
    _ = @import("window_cursor.zig");
    _ = @import("window_demo_trial.zig");
    _ = @import("window_main.zig");
    _ = @import("window_menu.zig");
    _ = @import("window_menu_panels.zig");
    _ = @import("window_misc_panels.zig");
    _ = @import("window_options.zig");
    _ = @import("window_statistics.zig");
    _ = @import("asset_smoke_main.zig");
    _ = @import("wasm_exports.zig");
}
