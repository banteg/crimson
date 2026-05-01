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
    _ = cz.net_session_native;
    _ = cz.net;
    std.testing.refAllDecls(cz.net.lockstep_live_bridge);

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

    const smoke_output = try cz.net_lockstep_smoke_native.runLockstepSmoke(
        std.testing.allocator,
        std.Io.Threaded.global_single_threaded.io(),
        &.{"--json"},
    );
    defer smoke_output.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u8, 0), smoke_output.exit_code);
    try std.testing.expect(std.mem.indexOf(u8, smoke_output.stdout, "\"host_input_flags\": 3") != null);

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
    _ = @import("window_misc_panels.zig");
    _ = @import("window_options.zig");
    _ = @import("window_statistics.zig");
    _ = @import("wasm_exports.zig");
}
