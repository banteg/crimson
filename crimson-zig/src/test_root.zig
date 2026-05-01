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
