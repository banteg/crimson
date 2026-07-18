const std = @import("std");
const cz = @import("crimson_zig");

pub const NoInputSampler = struct {
    pub fn codeIsDown(_: NoInputSampler, _: i32, _: i32) bool {
        return false;
    }

    pub fn codeIsPressed(_: NoInputSampler, _: i32, _: i32) bool {
        return false;
    }

    pub fn axisValue(_: NoInputSampler, _: i32, _: i32) f32 {
        return 0.0;
    }
};

test {
    _ = @import("app_runtime.zig");
    _ = cz.anim;
    _ = @import("audio/mod.zig");
    _ = cz.bonuses;
    _ = cz.checkpoint_diff_native;
    _ = cz.config_native;
    std.testing.refAllDecls(cz.dbg_bisect_native);
    _ = cz.dbg_bisect_native;
    std.testing.refAllDecls(cz.dbg_diff_native);
    _ = cz.dbg_diff_native;
    std.testing.refAllDecls(cz.dbg_entity_native);
    _ = cz.dbg_entity_native;
    std.testing.refAllDecls(cz.dbg_focus_native);
    _ = cz.dbg_focus_native;
    std.testing.refAllDecls(cz.dbg_health_native);
    _ = cz.dbg_health_native;
    _ = cz.creatures;
    std.testing.refAllDecls(cz.dbg_query_native);
    _ = cz.dbg_query_native;
    _ = cz.dbg_record_native;
    std.testing.refAllDecls(cz.dbg_tick_native);
    _ = cz.dbg_tick_native;
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

    const reconnect_jitter_smoke_output = try cz.net_rollback_smoke_native.runRollbackSmoke(
        std.testing.allocator,
        std.Io.Threaded.global_single_threaded.io(),
        &.{ "--json", "--impair", "guest-reconnect-bidirectional-jitter-burst" },
    );
    defer reconnect_jitter_smoke_output.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u8, 0), reconnect_jitter_smoke_output.exit_code);
    try std.testing.expect(std.mem.indexOf(u8, reconnect_jitter_smoke_output.stdout, "\"impairment\": \"guest-reconnect-bidirectional-jitter-burst\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, reconnect_jitter_smoke_output.stdout, "\"host_reconnect_count\": 1") != null);
    try std.testing.expect(std.mem.indexOf(u8, reconnect_jitter_smoke_output.stdout, "\"delayed_packets\": 6") != null);

    _ = cz.perks;
    _ = cz.persistence;
    _ = cz.projectiles;
    _ = @import("quest_results.zig");
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
    _ = @import("window_assets.zig");
    _ = @import("window_cursor.zig");
    _ = @import("window_demo_trial.zig");
    _ = @import("window_ground.zig");
    _ = @import("window_main.zig");
    _ = @import("window_menu.zig");
    _ = @import("window_menu_panels.zig");
    _ = @import("window_misc_panels.zig");
    _ = @import("window_options.zig");
    _ = @import("window_perk_menu.zig");
    _ = @import("window_statistics.zig");
    _ = @import("asset_extract_main.zig");
    _ = @import("asset_smoke_main.zig");
    _ = @import("wasm_exports.zig");
}

test "native movement uses player zero perk source" {
    var state = cz.state.GameplayState.init(1);
    state.preserve_bugs = true;
    var players = [_]cz.state.PlayerState{
        .{ .index = 0, .pos = .{} },
        .{ .index = 1, .pos = .{}, .move_speed = 2.1 },
    };
    players[0].perk_counts.set(.long_distance_runner, 1);
    const input: cz.movement.GameInput = .{
        .move_x = 1.0,
        .move_y = 0.0,
        .aim_x = 1.0,
        .aim_y = 0.0,
        .flags = .{
            .fire_down = false,
            .fire_pressed = false,
            .reload_pressed = false,
        },
    };

    cz.movement.updatePlayerFromGameInputWithPlayers(
        &players[1],
        input,
        &state,
        players[0..],
        null,
        0.1,
    );

    try std.testing.expectApproxEqAbs(cz.native_math.roundF32(2.2), players[1].move_speed, 1e-6);
}

test "native computer aim preserves configured movement" {
    var interpreter: cz.local_input.LocalInputInterpreter = .{};
    const player: cz.state.PlayerState = .{
        .index = 0,
        .pos = .{ .x = 500.0, .y = 500.0 },
        .aim = .{ .x = 560.0, .y = 500.0 },
    };
    var config = cz.formats.crimson_cfg.defaultConfig();
    config.player_mode_flag_p1 = @intCast(cz.local_input.movement_control_dual_action_pad);
    config.aim_scheme_p1 = @bitCast(@as(i32, cz.local_input.aim_scheme_computer));
    const creatures = [_]struct { active: bool, hp: f32, pos: cz.state.Vec2 }{
        .{ .active = true, .hp = 20.0, .pos = .{ .x = 560.0, .y = 500.0 } },
    };
    const sampler: NoInputSampler = .{};

    const input = interpreter.buildPlayerInput(
        sampler,
        0,
        1,
        &player,
        &config,
        .{},
        .{},
        .{},
        0.1,
        creatures[0..],
    );

    try std.testing.expectEqual(@as(f32, 0.0), input.move_x);
    try std.testing.expectEqual(@as(f32, 0.0), input.move_y);
}

test "native computer movement without a target orbits center" {
    var interpreter: cz.local_input.LocalInputInterpreter = .{};
    const player: cz.state.PlayerState = .{
        .index = 0,
        .pos = .{ .x = 612.0, .y = 512.0 },
        .aim = .{ .x = 672.0, .y = 512.0 },
    };
    var config = cz.formats.crimson_cfg.defaultConfig();
    config.player_mode_flag_p1 = @intCast(cz.local_input.movement_control_computer);
    const no_creatures = [_]struct { active: bool, hp: f32, pos: cz.state.Vec2 }{
        .{ .active = false, .hp = 0.0, .pos = .{} },
    };
    const sampler: NoInputSampler = .{};

    const input = interpreter.buildPlayerInput(
        sampler,
        0,
        1,
        &player,
        &config,
        .{},
        .{},
        .{},
        0.1,
        no_creatures[0..],
    );

    try std.testing.expectApproxEqAbs(@as(f32, 0.0), input.move_x, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 1.0), input.move_y, 1e-6);
}

test "native movement dispatcher ignores computer aim" {
    var state = cz.state.GameplayState.init(1);
    var player: cz.state.PlayerState = .{ .index = 0, .pos = .{} };
    const input: cz.movement.GameInput = .{
        .move_x = 0.0,
        .move_y = 0.0,
        .aim_x = 1.0,
        .aim_y = 0.0,
        .flags = .{
            .fire_down = false,
            .fire_pressed = false,
            .reload_pressed = false,
            .move_mode = cz.local_input.movement_control_relative,
            .aim_scheme = cz.local_input.aim_scheme_computer,
            .move_forward_pressed = true,
        },
    };

    cz.movement.updatePlayerFromGameInput(&player, input, &state, null, 0.1);

    try std.testing.expectApproxEqAbs(@as(f32, 0.5), player.move_speed, 1e-6);
}

test "native demo movement accepts sub-deadzone vectors" {
    var state = cz.state.GameplayState.init(1);
    state.demo_mode_active = true;
    var player: cz.state.PlayerState = .{ .index = 0, .pos = .{} };
    const input: cz.movement.GameInput = .{
        .move_x = 0.05,
        .move_y = 0.0,
        .aim_x = 1.0,
        .aim_y = 0.0,
        .flags = .{
            .fire_down = false,
            .fire_pressed = false,
            .reload_pressed = false,
            .move_mode = cz.local_input.movement_control_dual_action_pad,
        },
    };

    cz.movement.updatePlayerFromGameInput(&player, input, &state, null, 0.1);

    try std.testing.expectApproxEqAbs(@as(f32, 0.5), player.move_speed, 1e-6);
}

test "native player update uses player zero perk source" {
    var state = cz.state.GameplayState.init(1);
    state.preserve_bugs = true;
    var players = [_]cz.state.PlayerState{
        .{ .index = 0, .pos = .{} },
        .{
            .index = 1,
            .pos = .{},
            .aim = .{ .x = 10.0, .y = 0.0 },
            .weapon = .{ .weapon_id = .pistol, .ammo = 2.0 },
        },
    };
    players[0].perk_counts.set(.living_fortress, 1);
    players[0].perk_counts.set(.fastshot, 1);
    var projectiles: cz.projectiles.ProjectilePool = .{};
    var secondary_projectiles: cz.secondary_projectiles.SecondaryProjectilePool = .{};
    var creatures: cz.creatures.CreaturePool = .{};
    var particles: cz.particles.ParticlePool = .{};
    var effects: cz.effects.EffectPool = .{};
    var sprite_effects: cz.effects.SpriteEffectPool = .{};

    cz.weapons.applyPlayerPerkTicksWithEffects(
        &state,
        &players[1],
        players[0..],
        &projectiles,
        &sprite_effects,
        0.1,
    );
    try std.testing.expectApproxEqAbs(@as(f32, 0.1), players[1].living_fortress_timer, 1e-6);

    try cz.weapons.stepPlayerForTickWithEffects(
        &state,
        &players[1],
        players[0..],
        &projectiles,
        &secondary_projectiles,
        &creatures,
        &particles,
        &effects,
        &sprite_effects,
        null,
        5,
        .{ .fire_down = true, .preprocessed_player_tick = true },
        0.1,
    );

    const base_cooldown = cz.weapon_data.weapon_stats.get(.pistol).shot_cooldown;
    try std.testing.expectApproxEqAbs(
        cz.native_math.roundF32(base_cooldown * 0.88),
        players[1].weapon.shot_cooldown,
        1e-6,
    );
}

test "projectile movement and ion perk sources follow bug mode" {
    for ([_]bool{ true, false }) |preserve_bugs| {
        var state = cz.state.GameplayState.init(1);
        state.preserve_bugs = preserve_bugs;
        var players = [_]cz.state.PlayerState{
            .{ .index = 0, .pos = .{} },
            .{ .index = 1, .pos = .{} },
        };
        players[1].perk_counts.set(.barrel_greaser, 1);
        players[1].perk_counts.set(.ion_gun_master, 1);
        var creatures: cz.creatures.CreaturePool = .{};
        var bonuses: cz.bonuses.BonusPool = .{};

        var movement_pool: cz.projectiles.ProjectilePool = .{};
        _ = movement_pool.spawn(
            .{},
            std.math.pi / 2.0,
            @intFromEnum(cz.game_ids.ProjectileTypeId.pistol),
            .{ .player = .{ .index = 1 } },
            cz.weapon_data.weapon_stats.get(.pistol).travel_budget,
            false,
        );
        _ = movement_pool.update(
            &state,
            players[0..],
            &creatures,
            &bonuses,
            0.016,
            10_000.0,
        );
        try std.testing.expectApproxEqAbs(
            if (preserve_bugs) @as(f32, 18.240001678466797) else @as(f32, 35.519996643066406),
            movement_pool.entries[0].pos.x,
            1e-6,
        );

        var ion_creatures: cz.creatures.CreaturePool = .{};
        _ = ion_creatures.spawnInit(.{
            .origin_template_id = -1,
            .pos = .{ .x = 105.0, .y = 0.0 },
            .heading = 0.0,
            .phase_seed = 0,
            .type_id = .alien,
            .size = 50.0,
            .move_speed = 0.0,
            .health = 10.0,
            .max_health = 10.0,
            .reward_value = 50.0,
            .contact_damage = 4.0,
        });
        var ion_bonuses: cz.bonuses.BonusPool = .{};
        var ion_pool: cz.projectiles.ProjectilePool = .{};
        const ion_idx = ion_pool.spawn(
            .{},
            0.0,
            @intFromEnum(cz.game_ids.ProjectileTypeId.ion_rifle),
            .{ .player = .{ .index = 1 } },
            45.0,
            false,
        );
        ion_pool.entries[ion_idx].life_timer = 0.39;
        _ = ion_pool.update(
            &state,
            players[0..],
            &ion_creatures,
            &ion_bonuses,
            0.016,
            10_000.0,
        );
        try std.testing.expectEqual(!preserve_bugs, ion_creatures.entries[0].hp < 10.0);
    }
}

test "projectile poison bullets source follows bug mode" {
    for ([_]bool{ true, false }) |preserve_bugs| {
        var state = cz.state.GameplayState.init(1);
        state.preserve_bugs = preserve_bugs;
        state.rng.state = 1;
        var players = [_]cz.state.PlayerState{
            .{ .index = 0, .pos = .{ .x = 100.0, .y = 100.0 } },
            .{ .index = 1, .pos = .{ .x = 100.0, .y = 100.0 } },
        };
        players[1].perk_counts.set(.poison_bullets, 1);
        var creatures: cz.creatures.CreaturePool = .{};
        _ = creatures.spawnInit(.{
            .origin_template_id = -1,
            .pos = .{ .x = 102.0, .y = 100.0 },
            .heading = 0.0,
            .phase_seed = 0,
            .type_id = .alien,
            .flags = cz.spawn.CreatureFlags.anim_ping_pong,
            .size = 44.0,
            .move_speed = 0.0,
            .health = 1000.0,
            .max_health = 1000.0,
            .reward_value = 50.0,
            .contact_damage = 4.0,
        });
        var bonuses: cz.bonuses.BonusPool = .{};
        var pool: cz.projectiles.ProjectilePool = .{};
        _ = pool.spawn(
            players[1].pos,
            0.0,
            @intFromEnum(cz.game_ids.ProjectileTypeId.pistol),
            .{ .player = .{ .index = 1 } },
            45.0,
            false,
        );

        const tick = pool.update(&state, players[0..], &creatures, &bonuses, 0.016, 1024.0);
        try std.testing.expect(tick.hit_count > 0);
        try std.testing.expectEqual(
            !preserve_bugs,
            (creatures.entries[0].flags & cz.spawn.CreatureFlags.self_damage_tick) != 0,
        );
    }
}

test "projectile bloody mess source follows bug mode" {
    var decal_counts: [2]usize = undefined;
    for ([_]bool{ true, false }, 0..) |preserve_bugs, case_idx| {
        var state = cz.state.GameplayState.init(1);
        state.preserve_bugs = preserve_bugs;
        var players = [_]cz.state.PlayerState{
            .{ .index = 0, .pos = .{ .x = 100.0, .y = 100.0 } },
            .{ .index = 1, .pos = .{ .x = 100.0, .y = 100.0 } },
        };
        players[1].perk_counts.set(.bloody_mess_quick_learner, 1);
        var creatures: cz.creatures.CreaturePool = .{};
        _ = creatures.spawnInit(.{
            .origin_template_id = -1,
            .pos = .{ .x = 102.0, .y = 100.0 },
            .heading = 0.0,
            .phase_seed = 0,
            .type_id = .alien,
            .flags = cz.spawn.CreatureFlags.anim_ping_pong,
            .size = 44.0,
            .move_speed = 0.0,
            .health = 1000.0,
            .max_health = 1000.0,
            .reward_value = 50.0,
            .contact_damage = 4.0,
        });
        var bonuses: cz.bonuses.BonusPool = .{};
        var effects: cz.effects.EffectPool = .{};
        var terrain_fx: cz.terrain_fx.TerrainFxScratch = .{};
        var pool: cz.projectiles.ProjectilePool = .{};
        _ = pool.spawn(
            players[1].pos,
            0.0,
            @intFromEnum(cz.game_ids.ProjectileTypeId.pistol),
            .{ .player = .{ .index = 1 } },
            45.0,
            false,
        );

        const tick = pool.updateWithEffects(
            &state,
            players[0..],
            &creatures,
            &bonuses,
            &effects,
            &terrain_fx,
            5,
            0.016,
            1024.0,
        );
        try std.testing.expect(tick.hit_count > 0);
        decal_counts[case_idx] = terrain_fx.decals.count;
    }

    try std.testing.expectEqual(decal_counts[0] + 6, decal_counts[1]);
}

test "shock-chain retarget compares stored pc24 distances" {
    var creatures: cz.creatures.CreaturePool = .{};
    creatures.entries[0] = .{
        .active = true,
        .pos = .{ .x = -1727.156494140625, .y = -1351.4605712890625 },
    };
    creatures.entries[1] = .{
        .active = true,
        .pos = .{ .x = 1722.1292724609375, .y = -1357.8604736328125 },
    };

    try std.testing.expectEqual(
        @as(?usize, 0),
        cz.projectiles.creatureFindNearestActive(&creatures, .{}, 2, 100.0, false),
    );
}

test "corrected shock-chain retarget has no fallback target" {
    var creatures: cz.creatures.CreaturePool = .{};
    try std.testing.expectEqual(
        @as(?usize, null),
        cz.projectiles.creatureFindNearestActive(&creatures, .{}, 1, 100.0, false),
    );
    try std.testing.expectEqual(
        @as(?usize, 0),
        cz.projectiles.creatureFindNearestActive(&creatures, .{}, 1, 100.0, true),
    );
}

test "creature death xp source follows bug mode" {
    for ([_]bool{ true, false }) |preserve_bugs| {
        var state = cz.state.GameplayState.init(2);
        state.preserve_bugs = preserve_bugs;
        state.bonus_spawn_guard = true;
        var players = [_]cz.state.PlayerState{
            .{ .index = 0, .pos = .{} },
            .{ .index = 1, .pos = .{} },
        };
        players[0].perk_counts.set(.bloody_mess_quick_learner, 1);
        var creatures: cz.creatures.CreaturePool = .{};
        var effects: cz.effects.EffectPool = .{};
        var bonuses: cz.bonuses.BonusPool = .{};
        var terrain_fx: cz.terrain_fx.TerrainFxScratch = .{};
        creatures.effects = &effects;
        _ = creatures.spawnInit(.{
            .origin_template_id = -1,
            .pos = .{ .x = 0.0, .y = 0.0 },
            .heading = 0.0,
            .phase_seed = 0,
            .type_id = .alien,
            .flags = cz.spawn.CreatureFlags.anim_ping_pong,
            .size = 44.0,
            .move_speed = 0.0,
            .health = 10.0,
            .max_health = 10.0,
            .reward_value = 10.0,
            .contact_damage = 0.0,
        });

        const gained = creatures.applyProjectileDamage(
            &state,
            players[0..],
            &bonuses,
            &terrain_fx,
            0,
            20.0,
            .{},
            .{ .player = .{ .index = 1 } },
            1.0 / 60.0,
            1024.0,
        );

        if (preserve_bugs) {
            try std.testing.expectEqual(@as(i32, 13), gained);
            try std.testing.expectEqual(@as(i32, 13), players[0].experience);
            try std.testing.expectEqual(@as(i32, 0), players[1].experience);
        } else {
            try std.testing.expectEqual(@as(i32, 10), gained);
            try std.testing.expectEqual(@as(i32, 0), players[0].experience);
            try std.testing.expectEqual(@as(i32, 10), players[1].experience);
        }
    }
}

test "perk aim effect source follows bug mode" {
    for ([_]bool{ true, false }) |preserve_bugs| {
        var state = cz.state.GameplayState.init(2);
        state.preserve_bugs = preserve_bugs;
        var players = [_]cz.state.PlayerState{
            .{
                .index = 0,
                .pos = .{},
                .health = 0.0,
                .aim = .{ .x = 100.0, .y = 200.0 },
            },
            .{
                .index = 1,
                .pos = .{},
                .health = 100.0,
                .aim = .{ .x = 200.0, .y = 200.0 },
            },
        };
        players[0].perk_counts.set(.evil_eyes, 1);
        players[0].perk_counts.set(.pyrokinetic, 1);
        players[1].perk_counts.set(.evil_eyes, 1);
        players[1].perk_counts.set(.pyrokinetic, 1);

        var creatures: cz.creatures.CreaturePool = .{};
        for (0..2) |idx| {
            creatures.entries[idx] = .{
                .active = true,
                .pos = .{ .x = 100.0 + @as(f32, @floatFromInt(idx)) * 100.0, .y = 200.0 },
                .lifecycle_stage = cz.lifecycle.CreatureLifecycle.alive,
                .size = 50.0,
                .hp = 100.0,
                .collision_timer = 0.1,
            };
        }

        cz.perks.updateEvilEyesTargets(
            preserve_bugs,
            players[0..],
            creatures.entries[0..],
        );
        var particles: cz.particles.ParticlePool = .{};
        var terrain_fx: cz.terrain_fx.TerrainFxScratch = .{};
        cz.perks.applyPyrokineticEffects(
            &state,
            players[0..],
            &creatures,
            &particles,
            &terrain_fx,
            0.2,
        );

        if (preserve_bugs) {
            try std.testing.expectEqual(@as(i32, 0), players[0].evil_eyes_target_creature);
            try std.testing.expectEqual(@as(i32, -1), players[1].evil_eyes_target_creature);
            try std.testing.expectApproxEqAbs(@as(f32, 0.5), creatures.entries[0].collision_timer, 1e-6);
            try std.testing.expectApproxEqAbs(@as(f32, 0.1), creatures.entries[1].collision_timer, 1e-6);
        } else {
            try std.testing.expectEqual(@as(i32, -1), players[0].evil_eyes_target_creature);
            try std.testing.expectEqual(@as(i32, 1), players[1].evil_eyes_target_creature);
            try std.testing.expectApproxEqAbs(@as(f32, 0.1), creatures.entries[0].collision_timer, 1e-6);
            try std.testing.expectApproxEqAbs(@as(f32, 0.5), creatures.entries[1].collision_timer, 1e-6);
        }
    }
}

test "infernal contract player scope follows bug mode" {
    for ([_]bool{ true, false }) |preserve_bugs| {
        var state = cz.state.GameplayState.init(3);
        state.preserve_bugs = preserve_bugs;
        var players = [_]cz.state.PlayerState{
            .{ .index = 0, .pos = .{}, .health = 100.0 },
            .{ .index = 1, .pos = .{}, .health = 80.0 },
            .{ .index = 2, .pos = .{}, .health = 60.0 },
        };

        try cz.perks.applyPerk(&state, players[0..], .infernal_contract);

        try std.testing.expectApproxEqAbs(@as(f32, 0.1), players[0].health, 1e-6);
        try std.testing.expectApproxEqAbs(@as(f32, 0.1), players[1].health, 1e-6);
        const expected_player2_health: f32 = if (preserve_bugs) 60.0 else 0.1;
        try std.testing.expectApproxEqAbs(expected_player2_health, players[2].health, 1e-6);
    }
}

test "survival handout centroid keeps native pc24 radius boundary" {
    var state = cz.state.GameplayState.init(1);
    state.survival_reward_handout_enabled = false;
    state.survival_reward_damage_seen = true;
    state.survival_reward_fire_seen = false;
    state.survival_recent_death_count = 3;
    state.survival_recent_death_pos = .{
        .{ .x = 315.8760681152344, .y = 836.8428344726562 },
        .{ .x = 1131.1593017578125, .y = 1372.648681640625 },
        .{ .x = -1691.9703369140625, .y = -574.5670776367188 },
    };
    var players = [_]cz.state.PlayerState{
        .{
            .index = 0,
            .pos = .{ .x = -97.64498138427734, .y = 544.9747924804688 },
            .health = 14.0,
            .weapon = .{ .weapon_id = .pistol },
        },
    };

    cz.survival_progression.survivalUpdateWeaponHandouts(
        &state,
        players[0..],
        0.0,
    );

    try std.testing.expectEqual(cz.game_ids.WeaponId.pistol, players[0].weapon.weapon_id);
    try std.testing.expect(!state.survival_reward_fire_seen);
}

test "perk target search rejects native radius equality" {
    var players = [_]cz.state.PlayerState{
        .{ .index = 0, .pos = .{}, .aim = .{} },
    };
    players[0].perk_counts.set(.evil_eyes, 1);
    var creatures: cz.creatures.CreaturePool = .{};
    creatures.entries[0] = .{
        .active = true,
        .pos = .{ .x = 21.0, .y = 0.0 },
        .lifecycle_stage = cz.lifecycle.CreatureLifecycle.alive,
        .size = 42.0,
        .hp = 100.0,
    };

    cz.perks.updateEvilEyesTargets(false, players[0..], creatures.entries[0..]);

    try std.testing.expectEqual(@as(i32, -1), players[0].evil_eyes_target_creature);
}

test "particle hits reject native radius equality" {
    var state = cz.state.GameplayState.init(1);
    var players = [_]cz.state.PlayerState{.{ .index = 0, .pos = .{} }};
    var creatures: cz.creatures.CreaturePool = .{};
    creatures.entries[0] = .{
        .active = true,
        .pos = .{ .x = 17.0, .y = 0.0 },
        .lifecycle_stage = cz.lifecycle.CreatureLifecycle.alive,
        .size = 42.0,
        .hp = 100.0,
    };
    var particles: cz.particles.ParticlePool = .{};
    particles.entries[0] = .{
        .active = true,
        .render_flag = true,
        .intensity = 1.11,
        .style_id = .bubblegun,
    };
    var bonuses: cz.bonuses.BonusPool = .{};
    var sprite_effects: cz.effects.SpriteEffectPool = .{};
    var terrain_fx: cz.terrain_fx.TerrainFxScratch = .{};

    particles.update(
        &state,
        players[0..],
        &creatures,
        &bonuses,
        &sprite_effects,
        &terrain_fx,
        1.0,
        1024.0,
    );

    try std.testing.expect(particles.entries[0].render_flag);
    try std.testing.expectEqual(@as(i32, -1), particles.entries[0].target_id);
}

test "bubblegun expiry reenters active corpse death with native sound draw" {
    const FirstDrawTrace = struct {
        const Self = @This();

        first: ?cz.spawn.Crand.TraceDraw = null,

        fn onDraw(ctx: ?*anyopaque, draw: cz.spawn.Crand.TraceDraw) void {
            const self: *Self = @ptrCast(@alignCast(ctx orelse return));
            if (self.first == null) self.first = draw;
        }
    };

    var state = cz.state.GameplayState.init(2);
    var trace: FirstDrawTrace = .{};
    state.rng.setTraceSink(&trace, FirstDrawTrace.onDraw, true);
    var expected_rng = cz.spawn.Crand.init(2);
    const sound_slot = expected_rng.rand() % 3;
    const expected_sfx: cz.state.SfxId = switch (sound_slot) {
        0 => .zombie_die_01,
        1 => .zombie_die_02,
        else => .zombie_die_03,
    };

    var players = [_]cz.state.PlayerState{.{ .index = 0, .pos = .{} }};
    var effects: cz.effects.EffectPool = .{};
    var creatures: cz.creatures.CreaturePool = .{ .effects = &effects };
    creatures.entries[0] = .{
        .active = true,
        .type_id = @intFromEnum(cz.spawn.CreatureTypeId.zombie),
        .pos = .{ .x = 64.0, .y = 96.0 },
        .lifecycle_stage = cz.lifecycle.CreatureLifecycle.alive,
        .size = 50.0,
        .hp = 0.0,
    };
    var particles: cz.particles.ParticlePool = .{};
    particles.entries[0] = .{
        .active = true,
        .render_flag = false,
        .intensity = 0.81,
        .style_id = .bubblegun,
        .target_id = 0,
    };
    var bonuses: cz.bonuses.BonusPool = .{};
    var sprite_effects: cz.effects.SpriteEffectPool = .{};
    var terrain_fx: cz.terrain_fx.TerrainFxScratch = .{};

    particles.update(
        &state,
        players[0..],
        &creatures,
        &bonuses,
        &sprite_effects,
        &terrain_fx,
        0.1,
        1024.0,
    );

    try std.testing.expect(!particles.entries[0].active);
    try std.testing.expectEqual(@as(i32, 0), particles.entries[0].target_id);
    try std.testing.expect(!creatures.entries[0].active);
    try std.testing.expectEqual(@as(usize, 1), state.sfx_queue.len);
    try std.testing.expectEqual(expected_sfx, state.sfx_queue.items[0]);
    try std.testing.expectEqual(
        cz.rng_caller_static.projectile_update_particle_bubblegun_expiry_sfx,
        trace.first.?.caller.?,
    );
    try std.testing.expect(!state.rng.consumeMissingTraceCaller());
}

test "particle hits apply native tint fade and creature displacement" {
    var state = cz.state.GameplayState.init(1);
    var players = [_]cz.state.PlayerState{.{ .index = 0, .pos = .{} }};
    var creatures: cz.creatures.CreaturePool = .{};
    creatures.entries[0] = .{
        .active = true,
        .pos = .{},
        .lifecycle_stage = cz.lifecycle.CreatureLifecycle.alive,
        .size = 50.0,
        .hp = 100.0,
        .tint = .{ 0.9, 0.6, 0.2, 0.8 },
    };
    var particles: cz.particles.ParticlePool = .{};
    particles.entries[0] = .{
        .active = true,
        .render_flag = true,
        .intensity = 1.0,
        .style_id = .flamethrower,
    };
    var bonuses: cz.bonuses.BonusPool = .{};
    var sprite_effects: cz.effects.SpriteEffectPool = .{};
    var terrain_fx: cz.terrain_fx.TerrainFxScratch = .{};
    const dt: f32 = 0.016;

    particles.update(
        &state,
        players[0..],
        &creatures,
        &bonuses,
        &sprite_effects,
        &terrain_fx,
        dt,
        1024.0,
    );

    const particle = particles.entries[0];
    const creature = creatures.entries[0];
    const tint_factor = cz.native_math.pc24Sub(
        @as(f32, 1.0),
        cz.native_math.pc24Mul(particle.intensity, @as(f32, 0.01)),
    );
    try std.testing.expectApproxEqAbs(
        cz.native_math.pc24Mul(tint_factor, @as(f32, 0.9)),
        creature.tint[0],
        1e-6,
    );
    try std.testing.expectApproxEqAbs(
        cz.native_math.pc24Mul(tint_factor, @as(f32, 0.6)),
        creature.tint[1],
        1e-6,
    );
    try std.testing.expectApproxEqAbs(
        cz.native_math.pc24Mul(tint_factor, @as(f32, 0.2)),
        creature.tint[2],
        1e-6,
    );
    try std.testing.expectApproxEqAbs(@as(f32, 0.8), creature.tint[3], 1e-6);
    try std.testing.expectApproxEqAbs(
        cz.native_math.pc24Mul(particle.vel.x, dt),
        creature.pos.x,
        1e-6,
    );
    try std.testing.expectApproxEqAbs(
        cz.native_math.pc24Mul(particle.vel.y, dt),
        creature.pos.y,
        1e-6,
    );
    try std.testing.expect(@abs(creature.pos.x) > 0.0 or @abs(creature.pos.y) > 0.0);
}

test "bonus pickup uses native pc24 radius boundary" {
    var state = cz.state.GameplayState.init(1);
    var pool: cz.bonuses.BonusPool = .{};
    pool.entries[0] = .{
        .bonus_id = .shield,
        .time_left = 1.0,
        .time_max = 1.0,
        .pos = .{},
    };
    var players = [_]cz.state.PlayerState{
        .{
            .index = 0,
            .pos = .{ .x = 25.999998092651367, .y = 0.009600000455975533 },
        },
    };
    var pickup_bonus_ids = [_]cz.game_ids.BonusId{.unused} ** cz.bonuses.bonus_pool_size;
    var pickup_count: usize = 0;

    try pool.update(
        &state,
        players[0..],
        0.01,
        &pickup_bonus_ids,
        &pickup_count,
        null,
    );

    try std.testing.expectEqual(@as(usize, 0), pickup_count);
    try std.testing.expect(!pool.entries[0].picked);
    try std.testing.expectEqual(@as(f32, 0.0), players[0].shield_timer);
}

test "creature target selection follows native two-player cadence" {
    var creature: cz.creatures.CreatureState = .{
        .pos = .{ .x = 0.0, .y = 0.0 },
        .target_player = 0,
    };
    var players = [_]cz.state.PlayerState{
        .{ .index = 0, .pos = .{ .x = 100.0, .y = 0.0 } },
        .{ .index = 1, .pos = .{ .x = 10.0, .y = 0.0 } },
    };

    try std.testing.expectEqual(
        @as(usize, 1),
        cz.creatures.resolveNativeTargetPlayer(&creature, players[0..], 1),
    );
    try std.testing.expectEqual(@as(i32, 1), creature.target_player);

    creature.target_player = 0;
    try std.testing.expectEqual(
        @as(usize, 0),
        cz.creatures.resolveNativeTargetPlayer(&creature, players[0..], 70),
    );

    players[0].health = 0.0;
    try std.testing.expectEqual(
        @as(usize, 1),
        cz.creatures.resolveNativeTargetPlayer(&creature, players[0..], 70),
    );
}

test "creature target selection preserves native rounded-distance ties" {
    var creature: cz.creatures.CreatureState = .{
        .pos = .{ .x = 0.0, .y = 0.0 },
        .target_player = 0,
    };
    var players = [_]cz.state.PlayerState{
        .{ .index = 0, .pos = .{ .x = @bitCast(@as(u32, 0x42C80001)), .y = 100.0 } },
        .{ .index = 1, .pos = .{ .x = 100.0, .y = 100.0 } },
    };

    try std.testing.expectEqual(
        @as(usize, 0),
        cz.creatures.resolveNativeTargetPlayer(&creature, players[0..], 1),
    );
    try std.testing.expectEqual(@as(i32, 0), creature.target_player);
}

test "creature contact perk source follows bug mode" {
    const cases = [_]struct {
        preserve_bugs: bool,
        expected_hp: f32,
        expected_strong_poison: bool,
    }{
        .{ .preserve_bugs = true, .expected_hp = 75.0, .expected_strong_poison = false },
        .{ .preserve_bugs = false, .expected_hp = 100.0, .expected_strong_poison = true },
    };

    for (cases) |case| {
        var pool: cz.creatures.CreaturePool = .{};
        var effects: cz.effects.EffectPool = .{};
        var terrain_fx: cz.terrain_fx.TerrainFxScratch = .{};
        var state = cz.state.GameplayState.init(1);
        state.preserve_bugs = case.preserve_bugs;
        var bonuses: cz.bonuses.BonusPool = .{};
        var players = [_]cz.state.PlayerState{
            .{ .index = 0, .pos = .{ .x = 900.0, .y = 900.0 }, .health = 100.0 },
            .{ .index = 1, .pos = .{ .x = 100.0, .y = 100.0 }, .health = 100.0 },
        };
        players[0].perk_counts.set(.mr_melee, 1);
        players[0].perk_counts.set(.veins_of_poison, 1);
        players[1].perk_counts.set(.toxic_avenger, 1);
        pool.effects = &effects;

        _ = pool.spawnInit(.{
            .origin_template_id = -1,
            .pos = .{ .x = 100.0, .y = 100.0 },
            .heading = 0.0,
            .phase_seed = 0,
            .type_id = .alien,
            .flags = cz.spawn.CreatureFlags.anim_ping_pong,
            .size = 44.0,
            .move_speed = 0.0,
            .health = 100.0,
            .max_health = 100.0,
            .reward_value = 60.0,
            .contact_damage = 10.0,
        });
        pool.entries[0].target_player = 1;

        try pool.updateWithTerrainFx(&state, players[0..], 0.2, 1024.0, &bonuses, &terrain_fx, 5);

        try std.testing.expectApproxEqAbs(case.expected_hp, pool.entries[0].hp, 1e-6);
        try std.testing.expect((pool.entries[0].flags & cz.spawn.CreatureFlags.self_damage_tick) != 0);
        try std.testing.expectEqual(
            case.expected_strong_poison,
            (pool.entries[0].flags & cz.spawn.CreatureFlags.self_damage_tick_strong) != 0,
        );
        try std.testing.expectApproxEqAbs(@as(f32, 90.0), players[1].health, 1e-6);
    }
}

test "creature radioactive perk source follows bug mode" {
    for ([_]bool{ true, false }) |preserve_bugs| {
        var pool: cz.creatures.CreaturePool = .{};
        var effects: cz.effects.EffectPool = .{};
        var terrain_fx: cz.terrain_fx.TerrainFxScratch = .{};
        var state = cz.state.GameplayState.init(1);
        state.preserve_bugs = preserve_bugs;
        var bonuses: cz.bonuses.BonusPool = .{};
        var players = [_]cz.state.PlayerState{
            .{ .index = 0, .pos = .{ .x = 900.0, .y = 900.0 }, .health = 100.0 },
            .{ .index = 1, .pos = .{}, .health = 100.0 },
        };
        players[1].perk_counts.set(.radioactive, 1);
        pool.effects = &effects;

        _ = pool.spawnInit(.{
            .origin_template_id = -1,
            .pos = .{ .x = 46.0, .y = 0.0 },
            .heading = 0.0,
            .phase_seed = 0,
            .type_id = .alien,
            .flags = cz.spawn.CreatureFlags.anim_ping_pong,
            .size = 44.0,
            .move_speed = 0.0,
            .health = 50.0,
            .max_health = 50.0,
            .reward_value = 0.0,
            .contact_damage = 0.0,
        });
        pool.entries[0].collision_timer = 0.1;
        pool.entries[0].target_player = 1;

        try pool.updateWithTerrainFx(&state, players[0..], 0.2, 1024.0, &bonuses, &terrain_fx, 5);

        if (preserve_bugs) {
            try std.testing.expectApproxEqAbs(@as(f32, 50.0), pool.entries[0].hp, 1e-6);
            try std.testing.expectApproxEqAbs(@as(f32, 0.1), pool.entries[0].collision_timer, 1e-6);
        } else {
            try std.testing.expect(pool.entries[0].hp < 50.0);
            try std.testing.expectApproxEqAbs(@as(f32, 0.5), pool.entries[0].collision_timer, 1e-6);
        }
    }
}

test "freeze pauses native creature spawn-slot timers" {
    var pool: cz.creatures.CreaturePool = .{};
    var effects: cz.effects.EffectPool = .{};
    var terrain_fx: cz.terrain_fx.TerrainFxScratch = .{};
    var state = cz.state.GameplayState.init(1);
    var bonuses: cz.bonuses.BonusPool = .{};
    var players = [_]cz.state.PlayerState{
        .{ .index = 0, .pos = .{ .x = 512.0, .y = 512.0 } },
    };
    pool.effects = &effects;

    try pool.spawnTemplateCall(
        .{
            .template_id = 0x07,
            .pos = .{ .x = 512.0, .y = 512.0 },
            .heading = std.math.pi,
        },
        &state.rng,
    );

    state.bonuses.freeze = 5.0;
    try pool.updateWithTerrainFx(&state, players[0..], 1.1, 1024.0, &bonuses, &terrain_fx, 5);
    try std.testing.expectEqual(@as(i32, 0), pool.spawn_slots[0].count);
    try std.testing.expectEqual(@as(f32, 1.0), pool.spawn_slots[0].timer);
    try std.testing.expectEqual(@as(usize, 1), pool.activeCount());

    state.bonuses.freeze = 0.0;
    try pool.updateWithTerrainFx(&state, players[0..], 1.1, 1024.0, &bonuses, &terrain_fx, 5);
    try std.testing.expectEqual(@as(i32, 1), pool.spawn_slots[0].count);
    try std.testing.expectEqual(@as(usize, 2), pool.activeCount());
}

test "spawn-slot child templates resolve the native random-heading sentinel" {
    const child_template_ids = [_]i32{ 0x1C, 0x1D, 0x31, 0x32, 0x3C, 0x41 };

    for (child_template_ids, 0..) |template_id, idx| {
        const seed: u32 = @intCast(0x1234 + idx);
        var expected_rng = cz.spawn.Crand.init(seed);
        const expected_phase_seed: i32 = @intCast(
            expected_rng.randTagged(cz.rng_caller_static.creature_alloc_slot_phase_seed) & 0x17f,
        );
        const heading_roll = expected_rng.randTagged(
            cz.rng_caller_static.creature_spawn_template_random_heading,
        ) % 628;
        const expected_heading = cz.native_math.pc24Mul(
            @as(f32, @floatFromInt(heading_roll)),
            @as(f32, 0.01),
        );

        var pool: cz.creatures.CreaturePool = .{};
        var rng = cz.spawn.Crand.init(seed);
        try pool.spawnTemplateCall(
            .{
                .template_id = template_id,
                .pos = .{ .x = 512.0, .y = 512.0 },
                .heading = -100.0,
            },
            &rng,
        );

        try std.testing.expectEqual(expected_phase_seed, pool.entries[0].phase_seed);
        try std.testing.expectApproxEqAbs(expected_heading, pool.entries[0].heading, 0.000001);
    }
}

test "demo creature templates resolve the native random-heading sentinel" {
    const template_ids = [_]i32{ 0x34, 0x35, 0x38, 0x41 };

    for (template_ids, 0..) |template_id, idx| {
        const seed: u32 = @intCast(0x4567 + idx);
        var expected_rng = cz.spawn.Crand.init(seed);
        const expected_phase_seed: i32 = @intCast(
            expected_rng.randTagged(cz.rng_caller_static.creature_alloc_slot_phase_seed) & 0x17f,
        );
        const heading_roll = expected_rng.randTagged(
            cz.rng_caller_static.creature_spawn_template_random_heading,
        ) % 628;
        const expected_heading = cz.native_math.pc24Mul(
            @as(f32, @floatFromInt(heading_roll)),
            @as(f32, 0.01),
        );

        var pool: cz.creatures.CreaturePool = .{};
        var rng = cz.spawn.Crand.init(seed);
        try pool.spawnTemplateCall(
            .{
                .template_id = template_id,
                .pos = .{ .x = 512.0, .y = 512.0 },
                .heading = -100.0,
            },
            &rng,
        );

        try std.testing.expectEqual(expected_phase_seed, pool.entries[0].phase_seed);
        try std.testing.expectEqual(expected_heading, pool.entries[0].heading);
    }
}

test "spawn templates clear root force target but preserve formation children" {
    var pool: cz.creatures.CreaturePool = .{};
    pool.entries[0].force_target = 1;
    pool.entries[1].force_target = 1;
    var rng = cz.spawn.Crand.init(0xBEEF);

    try pool.spawnTemplateCall(
        .{
            .template_id = 0x12,
            .pos = .{ .x = 512.0, .y = 512.0 },
            .heading = 0.0,
        },
        &rng,
    );

    try std.testing.expectEqual(@as(u8, 0), pool.entries[0].force_target);
    try std.testing.expectEqual(@as(u8, 1), pool.entries[1].force_target);
}

test "spawn template tail modifiers follow the final formation child" {
    var hardcore_pool: cz.creatures.CreaturePool = .{};
    hardcore_pool.hardcore = true;
    var hardcore_rng = cz.spawn.Crand.init(0xBEEF);

    try hardcore_pool.spawnTemplateCall(
        .{
            .template_id = 0x12,
            .pos = .{ .x = 512.0, .y = 512.0 },
            .heading = 0.0,
        },
        &hardcore_rng,
    );

    try std.testing.expectEqual(@as(f32, 200.0), hardcore_pool.entries[0].hp);
    try std.testing.expectEqual(@as(f32, 20.0), hardcore_pool.entries[8].max_hp);
    try std.testing.expectEqual(
        cz.native_math.pc24Mul(@as(f32, 20.0), @as(f32, 1.2)),
        hardcore_pool.entries[8].hp,
    );
    try std.testing.expectEqual(
        cz.native_math.pc24Mul(@as(f32, 2.4), @as(f32, 1.05)),
        hardcore_pool.entries[8].move_speed,
    );

    var spawner_pool: cz.creatures.CreaturePool = .{};
    var spawner_rng = cz.spawn.Crand.init(0xBEEF);

    try spawner_pool.spawnTemplateCall(
        .{
            .template_id = 0x0E,
            .pos = .{ .x = 512.0, .y = 512.0 },
            .heading = 0.0,
        },
        &spawner_rng,
    );

    try std.testing.expectEqual(@as(f32, 1.05), spawner_pool.spawn_slots[0].interval);
}

test "formation roots retain transient headings and untouched max health" {
    var expected_rng = cz.spawn.Crand.init(0xBEEF);
    _ = expected_rng.randTagged(cz.rng_caller_static.creature_alloc_slot_phase_seed);
    const transient_heading = cz.native_math.pc24Mul(
        @as(f32, @floatFromInt(
            expected_rng.randTagged(cz.rng_caller_static.creature_spawn_template_base_heading) % 314,
        )),
        @as(f32, 0.01),
    );

    var chain_pool: cz.creatures.CreaturePool = .{};
    var chain_rng = cz.spawn.Crand.init(0xBEEF);
    try chain_pool.spawnTemplateCall(
        .{
            .template_id = 0x11,
            .pos = .{ .x = 512.0, .y = 512.0 },
            .heading = 0.75,
        },
        &chain_rng,
    );

    try std.testing.expectEqual(transient_heading, chain_pool.entries[0].heading);
    try std.testing.expectEqual(@as(f32, 0.75), chain_pool.entries[4].heading);

    var spawner_pool: cz.creatures.CreaturePool = .{};
    spawner_pool.entries[0].max_hp = 321.0;
    var spawner_rng = cz.spawn.Crand.init(0xBEEF);
    try spawner_pool.spawnTemplateCall(
        .{
            .template_id = 0x0E,
            .pos = .{ .x = 512.0, .y = 512.0 },
            .heading = 0.75,
        },
        &spawner_rng,
    );

    try std.testing.expectEqual(transient_heading, spawner_pool.entries[0].heading);
    try std.testing.expectEqual(@as(f32, 321.0), spawner_pool.entries[0].max_hp);
    try std.testing.expectEqual(@as(f32, 0.75), spawner_pool.entries[24].heading);
}

test "formation child headings preserve or clear recycled slot state" {
    const preserved_cases = [_]struct {
        template_id: i32,
        final_idx: usize,
    }{
        .{ .template_id = 0x11, .final_idx = 4 },
        .{ .template_id = 0x12, .final_idx = 8 },
        .{ .template_id = 0x13, .final_idx = 10 },
        .{ .template_id = 0x19, .final_idx = 5 },
    };

    for (preserved_cases) |case| {
        var pool: cz.creatures.CreaturePool = .{};
        pool.entries[1].heading = 1.25;
        pool.entries[2].heading = 2.5;
        var rng = cz.spawn.Crand.init(0xBEEF);

        try pool.spawnTemplateCall(
            .{
                .template_id = case.template_id,
                .pos = .{ .x = 512.0, .y = 512.0 },
                .heading = 0.75,
            },
            &rng,
        );

        try std.testing.expectEqual(@as(f32, 1.25), pool.entries[1].heading);
        try std.testing.expectEqual(@as(f32, 2.5), pool.entries[2].heading);
        try std.testing.expectEqual(@as(f32, 0.75), pool.entries[case.final_idx].heading);
    }

    const zeroed_cases = [_]struct {
        template_id: i32,
        final_idx: usize,
    }{
        .{ .template_id = 0x0E, .final_idx = 24 },
        .{ .template_id = 0x14, .final_idx = 81 },
        .{ .template_id = 0x15, .final_idx = 81 },
        .{ .template_id = 0x16, .final_idx = 81 },
        .{ .template_id = 0x17, .final_idx = 81 },
        .{ .template_id = 0x18, .final_idx = 81 },
    };

    for (zeroed_cases) |case| {
        var pool: cz.creatures.CreaturePool = .{};
        pool.entries[1].heading = 1.25;
        pool.entries[2].heading = 2.5;
        var rng = cz.spawn.Crand.init(0xBEEF);

        try pool.spawnTemplateCall(
            .{
                .template_id = case.template_id,
                .pos = .{ .x = 512.0, .y = 512.0 },
                .heading = 0.75,
            },
            &rng,
        );

        try std.testing.expectEqual(@as(f32, 0.0), pool.entries[1].heading);
        try std.testing.expectEqual(@as(f32, 0.0), pool.entries[2].heading);
        try std.testing.expectEqual(@as(f32, 0.75), pool.entries[case.final_idx].heading);
    }
}

test "alien chain formation uses the native twenty-degree literal" {
    var pool: cz.creatures.CreaturePool = .{};
    var rng = cz.spawn.Crand.init(0xBEEF);

    try pool.spawnTemplateCall(
        .{
            .template_id = 0x13,
            .pos = .{ .x = 512.0, .y = 512.0 },
            .heading = 0.0,
        },
        &rng,
    );

    try std.testing.expectEqual(@as(f32, @bitCast(@as(u32, 0x443106DE))), pool.entries[10].pos.x);
    try std.testing.expectEqual(@as(f32, @bitCast(@as(u32, 0x44292370))), pool.entries[10].pos.y);
}

test "spawn templates preserve recycled ranged orbit fields" {
    const projectile_type = @intFromEnum(cz.game_ids.ProjectileTypeId.spider_plasma);
    var pool: cz.creatures.CreaturePool = .{};
    pool.entries[0].orbit_angle = 0.4;
    pool.entries[0].orbit_radius = @bitCast(projectile_type);
    pool.entries[0].ranged_projectile_type = projectile_type;
    var rng = cz.spawn.Crand.init(0xBEEF);

    try pool.spawnTemplateCall(
        .{
            .template_id = 0x37,
            .pos = .{ .x = 512.0, .y = 512.0 },
            .heading = 0.0,
        },
        &rng,
    );

    try std.testing.expectEqual(@as(f32, 0.4), pool.entries[0].orbit_angle);
    try std.testing.expectEqual(projectile_type, pool.entries[0].ranged_projectile_type);
}

test "spawn difficulty scales current health but preserves base max health" {
    const retry_counts = [_]i32{ 1, 2, 3, 4, 5 };
    const health_scales = [_]f32{ 0.95, 0.9, 0.8, 0.7, 0.5 };

    for (retry_counts, health_scales) |retry_count, health_scale| {
        var pool: cz.creatures.CreaturePool = .{};
        pool.quest_fail_retry_count = retry_count;
        var rng = cz.spawn.Crand.init(0xBEEF);

        try pool.spawnTemplateCall(
            .{
                .template_id = 0x21,
                .pos = .{ .x = 512.0, .y = 512.0 },
                .heading = 0.0,
            },
            &rng,
        );

        try std.testing.expectApproxEqAbs(@as(f32, 53.0) * health_scale, pool.entries[0].hp, 0.000001);
        try std.testing.expectEqual(@as(f32, 53.0), pool.entries[0].max_hp);
    }

    var hardcore_pool: cz.creatures.CreaturePool = .{};
    hardcore_pool.hardcore = true;
    var hardcore_rng = cz.spawn.Crand.init(0xBEEF);

    try hardcore_pool.spawnTemplateCall(
        .{
            .template_id = 0x21,
            .pos = .{ .x = 512.0, .y = 512.0 },
            .heading = 0.0,
        },
        &hardcore_rng,
    );

    try std.testing.expectApproxEqAbs(@as(f32, 53.0) * 1.2, hardcore_pool.entries[0].hp, 0.000001);
    try std.testing.expectEqual(@as(f32, 53.0), hardcore_pool.entries[0].max_hp);
}

test "hardcore template spawn clears shared quest retry state" {
    var pool: cz.creatures.CreaturePool = .{};
    pool.hardcore = true;
    pool.quest_fail_retry_count = 4;
    var state = cz.state.GameplayState.init(1);
    state.demo_mode_active = true;
    state.quest_fail_retry_count = 4;
    var rng = cz.spawn.Crand.init(0xBEEF);

    try pool.spawnTemplateCallWithRuntimeContext(
        .{
            .template_id = 0x21,
            .pos = .{ .x = 512.0, .y = 512.0 },
            .heading = 0.0,
        },
        &rng,
        &state,
        1024.0,
    );

    try std.testing.expectEqual(@as(i32, 0), pool.quest_fail_retry_count);
    try std.testing.expectEqual(@as(i32, 0), state.quest_fail_retry_count);
}

test "hardcore applies the template 0x38 speed penalty before its global buff" {
    var penalized_pool: cz.creatures.CreaturePool = .{};
    penalized_pool.hardcore = true;
    var penalized_rng = cz.spawn.Crand.init(0xBEEF);

    try penalized_pool.spawnTemplateCall(
        .{
            .template_id = 0x38,
            .pos = .{ .x = 512.0, .y = 512.0 },
            .heading = 0.0,
        },
        &penalized_rng,
    );

    const penalized_speed = cz.native_math.pc24Mul(
        cz.native_math.pc24Mul(@as(f32, 4.8), @as(f32, 0.7)),
        @as(f32, 1.05),
    );
    try std.testing.expectEqual(penalized_speed, penalized_pool.entries[0].move_speed);

    var ordinary_pool: cz.creatures.CreaturePool = .{};
    ordinary_pool.hardcore = true;
    var ordinary_rng = cz.spawn.Crand.init(0xBEEF);

    try ordinary_pool.spawnTemplateCall(
        .{
            .template_id = 0x39,
            .pos = .{ .x = 512.0, .y = 512.0 },
            .heading = 0.0,
        },
        &ordinary_rng,
    );

    const ordinary_speed = cz.native_math.pc24Mul(@as(f32, 4.8), @as(f32, 1.05));
    try std.testing.expectEqual(ordinary_speed, ordinary_pool.entries[0].move_speed);
}

test "aggregate dbg health summarizes native CDT trace" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base_dir = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer allocator.free(base_dir);
    const replay_path = try std.fs.path.join(allocator, &.{ base_dir, "sample.crd" });
    defer allocator.free(replay_path);
    const trace_path = try std.fs.path.join(allocator, &.{ base_dir, "sample.cdt" });
    defer allocator.free(trace_path);
    const json_path = try std.fs.path.join(allocator, &.{ base_dir, "reports", "health.json" });
    defer allocator.free(json_path);

    const replay_bytes = try cz.replay_codec.buildSmokeTestReplayFile(allocator);
    defer allocator.free(replay_bytes);

    const io = std.Io.Threaded.global_single_threaded.io();
    try std.Io.Dir.cwd().writeFile(io, .{
        .sub_path = replay_path,
        .data = replay_bytes,
    });

    const record_output = try cz.dbg_record_native.runDbgRecord(allocator, &.{ replay_path, "--out", trace_path });
    defer record_output.deinit(allocator);
    try std.testing.expectEqual(@as(u8, 0), record_output.exit_code);
    try std.testing.expect(std.mem.indexOf(u8, record_output.stdout, "trace=") != null);

    const health_output = try cz.dbg_health_native.runDbgHealth(allocator, &.{ trace_path, "--format", "json", "--json-out", json_path });
    defer health_output.deinit(allocator);
    try std.testing.expectEqual(@as(u8, 0), health_output.exit_code);
    try std.testing.expectEqualStrings("", health_output.stderr);
    try std.testing.expect(std.mem.indexOf(u8, health_output.stdout, "\"status\":\"ok\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, health_output.stdout, "\"trace_schema_version\":16") != null);
    try std.testing.expect(std.mem.indexOf(u8, health_output.stdout, "\"ticks_in_window\":") != null);
    try std.testing.expect(std.mem.indexOf(u8, health_output.stdout, "\"ok_for_parity_analysis\":true") != null);

    const artifact = try std.Io.Dir.cwd().readFileAlloc(io, json_path, allocator, .limited(64 * 1024));
    defer allocator.free(artifact);
    try std.testing.expectEqualStrings(health_output.stdout, artifact);
}

test "aggregate dbg tick summarizes native CDT tick" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base_dir = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer allocator.free(base_dir);
    const replay_path = try std.fs.path.join(allocator, &.{ base_dir, "sample.crd" });
    defer allocator.free(replay_path);
    const trace_path = try std.fs.path.join(allocator, &.{ base_dir, "sample.cdt" });
    defer allocator.free(trace_path);
    const json_path = try std.fs.path.join(allocator, &.{ base_dir, "reports", "tick.json" });
    defer allocator.free(json_path);

    const replay_bytes = try cz.replay_codec.buildSmokeTestReplayFile(allocator);
    defer allocator.free(replay_bytes);

    const io = std.Io.Threaded.global_single_threaded.io();
    try std.Io.Dir.cwd().writeFile(io, .{
        .sub_path = replay_path,
        .data = replay_bytes,
    });

    const record_output = try cz.dbg_record_native.runDbgRecord(allocator, &.{ replay_path, "--out", trace_path });
    defer record_output.deinit(allocator);
    try std.testing.expectEqual(@as(u8, 0), record_output.exit_code);
    try std.testing.expect(std.mem.indexOf(u8, record_output.stdout, "trace=") != null);

    const tick_output = try cz.dbg_tick_native.runDbgTick(allocator, &.{ trace_path, "0", "--json", "--json-out", json_path });
    defer tick_output.deinit(allocator);
    try std.testing.expectEqual(@as(u8, 0), tick_output.exit_code);
    try std.testing.expectEqualStrings("", tick_output.stderr);
    try std.testing.expect(std.mem.indexOf(u8, tick_output.stdout, "\"tick_index\":0") != null);
    try std.testing.expect(std.mem.indexOf(u8, tick_output.stdout, "\"event_count_total\":") != null);

    const artifact = try std.Io.Dir.cwd().readFileAlloc(io, json_path, allocator, .limited(64 * 1024));
    defer allocator.free(artifact);
    try std.testing.expectEqualStrings(tick_output.stdout, artifact);
}

test "aggregate dbg diff compares native CDT traces" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base_dir = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer allocator.free(base_dir);
    const replay_path = try std.fs.path.join(allocator, &.{ base_dir, "sample.crd" });
    defer allocator.free(replay_path);
    const trace_path = try std.fs.path.join(allocator, &.{ base_dir, "sample.cdt" });
    defer allocator.free(trace_path);
    const json_path = try std.fs.path.join(allocator, &.{ base_dir, "reports", "diff.json" });
    defer allocator.free(json_path);

    const replay_bytes = try cz.replay_codec.buildSmokeTestReplayFile(allocator);
    defer allocator.free(replay_bytes);

    const io = std.Io.Threaded.global_single_threaded.io();
    try std.Io.Dir.cwd().writeFile(io, .{
        .sub_path = replay_path,
        .data = replay_bytes,
    });

    const record_output = try cz.dbg_record_native.runDbgRecord(allocator, &.{ replay_path, "--out", trace_path });
    defer record_output.deinit(allocator);
    try std.testing.expectEqual(@as(u8, 0), record_output.exit_code);
    try std.testing.expect(std.mem.indexOf(u8, record_output.stdout, "trace=") != null);

    const diff_output = try cz.dbg_diff_native.runDbgDiff(allocator, &.{ trace_path, trace_path, "--json", "--json-out", json_path });
    defer diff_output.deinit(allocator);
    try std.testing.expectEqual(@as(u8, 0), diff_output.exit_code);
    try std.testing.expectEqualStrings("", diff_output.stderr);
    try std.testing.expect(std.mem.indexOf(u8, diff_output.stdout, "\"status\":\"ok\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, diff_output.stdout, "\"checked_count\":2") != null);

    const artifact = try std.Io.Dir.cwd().readFileAlloc(io, json_path, allocator, .limited(64 * 1024));
    defer allocator.free(artifact);
    try std.testing.expectEqualStrings(diff_output.stdout, artifact);
}

test "aggregate dbg bisect compares native CDT traces" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base_dir = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer allocator.free(base_dir);
    const replay_path = try std.fs.path.join(allocator, &.{ base_dir, "sample.crd" });
    defer allocator.free(replay_path);
    const trace_path = try std.fs.path.join(allocator, &.{ base_dir, "sample.cdt" });
    defer allocator.free(trace_path);
    const json_path = try std.fs.path.join(allocator, &.{ base_dir, "reports", "bisect.json" });
    defer allocator.free(json_path);

    const replay_bytes = try cz.replay_codec.buildSmokeTestReplayFile(allocator);
    defer allocator.free(replay_bytes);

    const io = std.Io.Threaded.global_single_threaded.io();
    try std.Io.Dir.cwd().writeFile(io, .{
        .sub_path = replay_path,
        .data = replay_bytes,
    });

    const record_output = try cz.dbg_record_native.runDbgRecord(allocator, &.{ replay_path, "--out", trace_path });
    defer record_output.deinit(allocator);
    try std.testing.expectEqual(@as(u8, 0), record_output.exit_code);
    try std.testing.expect(std.mem.indexOf(u8, record_output.stdout, "trace=") != null);

    const bisect_output = try cz.dbg_bisect_native.runDbgBisect(allocator, &.{ trace_path, trace_path, "--json", "--json-out", json_path });
    defer bisect_output.deinit(allocator);
    try std.testing.expectEqual(@as(u8, 0), bisect_output.exit_code);
    try std.testing.expectEqualStrings("", bisect_output.stderr);
    try std.testing.expect(std.mem.indexOf(u8, bisect_output.stdout, "\"status\":\"ok\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, bisect_output.stdout, "\"first_bad_tick\":null") != null);

    const artifact = try std.Io.Dir.cwd().readFileAlloc(io, json_path, allocator, .limited(64 * 1024));
    defer allocator.free(artifact);
    try std.testing.expectEqualStrings(bisect_output.stdout, artifact);
}

test "aggregate dbg focus compares one native CDT tick" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base_dir = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer allocator.free(base_dir);
    const replay_path = try std.fs.path.join(allocator, &.{ base_dir, "sample.crd" });
    defer allocator.free(replay_path);
    const trace_path = try std.fs.path.join(allocator, &.{ base_dir, "sample.cdt" });
    defer allocator.free(trace_path);
    const json_path = try std.fs.path.join(allocator, &.{ base_dir, "reports", "focus.json" });
    defer allocator.free(json_path);

    const replay_bytes = try cz.replay_codec.buildSmokeTestReplayFile(allocator);
    defer allocator.free(replay_bytes);

    const io = std.Io.Threaded.global_single_threaded.io();
    try std.Io.Dir.cwd().writeFile(io, .{
        .sub_path = replay_path,
        .data = replay_bytes,
    });

    const record_output = try cz.dbg_record_native.runDbgRecord(allocator, &.{ replay_path, "--out", trace_path });
    defer record_output.deinit(allocator);
    try std.testing.expectEqual(@as(u8, 0), record_output.exit_code);
    try std.testing.expect(std.mem.indexOf(u8, record_output.stdout, "trace=") != null);

    const focus_output = try cz.dbg_focus_native.runDbgFocus(allocator, &.{ trace_path, trace_path, "--tick", "0", "--json", "--json-out", json_path });
    defer focus_output.deinit(allocator);
    try std.testing.expectEqual(@as(u8, 0), focus_output.exit_code);
    try std.testing.expectEqualStrings("", focus_output.stderr);
    try std.testing.expect(std.mem.indexOf(u8, focus_output.stdout, "\"status\":\"ok\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, focus_output.stdout, "\"checkpoint_diff_count\":0") != null);

    const artifact = try std.Io.Dir.cwd().readFileAlloc(io, json_path, allocator, .limited(64 * 1024));
    defer allocator.free(artifact);
    try std.testing.expectEqualStrings(focus_output.stdout, artifact);
}

test "aggregate dbg entity summarizes native CDT entity" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base_dir = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer allocator.free(base_dir);
    const replay_path = try std.fs.path.join(allocator, &.{ base_dir, "sample.crd" });
    defer allocator.free(replay_path);
    const trace_path = try std.fs.path.join(allocator, &.{ base_dir, "sample.cdt" });
    defer allocator.free(trace_path);
    const json_path = try std.fs.path.join(allocator, &.{ base_dir, "reports", "entity.json" });
    defer allocator.free(json_path);

    const replay_bytes = try cz.replay_codec.buildSmokeTestReplayFile(allocator);
    defer allocator.free(replay_bytes);

    const io = std.Io.Threaded.global_single_threaded.io();
    try std.Io.Dir.cwd().writeFile(io, .{
        .sub_path = replay_path,
        .data = replay_bytes,
    });

    const record_output = try cz.dbg_record_native.runDbgRecord(allocator, &.{ replay_path, "--out", trace_path });
    defer record_output.deinit(allocator);
    try std.testing.expectEqual(@as(u8, 0), record_output.exit_code);
    try std.testing.expect(std.mem.indexOf(u8, record_output.stdout, "trace=") != null);

    const entity_output = try cz.dbg_entity_native.runDbgEntity(allocator, &.{ trace_path, "1001000000", "--json", "--json-out", json_path });
    defer entity_output.deinit(allocator);
    try std.testing.expectEqual(@as(u8, 0), entity_output.exit_code);
    try std.testing.expectEqualStrings("", entity_output.stderr);
    try std.testing.expect(std.mem.indexOf(u8, entity_output.stdout, "\"entity_uid\":1001000000") != null);
    try std.testing.expect(std.mem.indexOf(u8, entity_output.stdout, "\"pool_kind\":\"creature\"") != null);

    const artifact = try std.Io.Dir.cwd().readFileAlloc(io, json_path, allocator, .limited(64 * 1024));
    defer allocator.free(artifact);
    try std.testing.expectEqualStrings(entity_output.stdout, artifact);
}

test "aggregate dbg query filters native CDT rows" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base_dir = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer allocator.free(base_dir);
    const replay_path = try std.fs.path.join(allocator, &.{ base_dir, "sample.crd" });
    defer allocator.free(replay_path);
    const trace_path = try std.fs.path.join(allocator, &.{ base_dir, "sample.cdt" });
    defer allocator.free(trace_path);
    const json_path = try std.fs.path.join(allocator, &.{ base_dir, "reports", "query.json" });
    defer allocator.free(json_path);

    const replay_bytes = try cz.replay_codec.buildSmokeTestReplayFile(allocator);
    defer allocator.free(replay_bytes);

    const io = std.Io.Threaded.global_single_threaded.io();
    try std.Io.Dir.cwd().writeFile(io, .{
        .sub_path = replay_path,
        .data = replay_bytes,
    });

    const record_output = try cz.dbg_record_native.runDbgRecord(allocator, &.{ replay_path, "--out", trace_path });
    defer record_output.deinit(allocator);
    try std.testing.expectEqual(@as(u8, 0), record_output.exit_code);
    try std.testing.expect(std.mem.indexOf(u8, record_output.stdout, "trace=") != null);

    const query_output = try cz.dbg_query_native.runDbgQuery(allocator, &.{ trace_path, "entities where uid == 1001000000", "--json", "--json-out", json_path });
    defer query_output.deinit(allocator);
    try std.testing.expectEqual(@as(u8, 0), query_output.exit_code);
    try std.testing.expectEqualStrings("", query_output.stderr);
    try std.testing.expect(std.mem.indexOf(u8, query_output.stdout, "\"scope\":\"entities\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, query_output.stdout, "\"uid\":1001000000") != null);

    const artifact = try std.Io.Dir.cwd().readFileAlloc(io, json_path, allocator, .limited(64 * 1024));
    defer allocator.free(artifact);
    try std.testing.expectEqualStrings(query_output.stdout, artifact);
}
