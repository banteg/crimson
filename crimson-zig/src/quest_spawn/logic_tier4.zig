const std = @import("std");

const common = @import("logic_common.zig");
const game_ids = @import("../game_ids.zig");
const spawn_runtime = @import("../runtime/spawn.zig");

pub const tier4_builders = [_]common.LevelBuilder{
    .{ .level_key = 401, .start_weapon_id = game_ids.WeaponId.rocket_minigun, .build = build_401_major_alien_breach },
    .{ .level_key = 402, .start_weapon_id = game_ids.WeaponId.pistol, .build = build_402_zombie_time },
    .{ .level_key = 403, .start_weapon_id = game_ids.WeaponId.pistol, .build = build_403_lizard_zombie_pact },
    .{ .level_key = 404, .start_weapon_id = game_ids.WeaponId.pistol, .build = build_404_the_collaboration },
    .{ .level_key = 405, .start_weapon_id = game_ids.WeaponId.pistol, .build = build_405_the_massacre },
    .{ .level_key = 406, .start_weapon_id = game_ids.WeaponId.pistol, .build = build_406_the_unblitzkrieg },
    .{ .level_key = 407, .start_weapon_id = game_ids.WeaponId.pistol, .build = build_407_gauntlet },
    .{ .level_key = 408, .start_weapon_id = game_ids.WeaponId.pistol, .build = build_408_syntax_terror },
    .{ .level_key = 409, .start_weapon_id = game_ids.WeaponId.pistol, .build = build_409_the_annihilation },
    .{ .level_key = 410, .start_weapon_id = game_ids.WeaponId.pistol, .build = build_410_the_end_of_all },
};

fn build_401_major_alien_breach(
    ctx: common.BuildContext,
    _: *common.PythonRandom,
    out_entries: []spawn_runtime.QuestSpawnEntry,
    len: *usize,
) common.QuestSpawnBuildError!void {
    const edges = common.edgeMidpoints(ctx.width, ctx.width, 64.0);
    var trigger: i32 = 4000;
    var offset: i32 = 0;
    while (offset < 0x5DC) : (offset += 0xF) {
        try common.appendSpawn(
            out_entries,
            len,
            edges.right,
            0.0,
            common.SpawnId.alien_random_green_20,
            trigger,
            2,
        );
        try common.appendSpawn(
            out_entries,
            len,
            edges.top,
            0.0,
            common.SpawnId.alien_random_green_20,
            trigger,
            2,
        );
        trigger += 2000 - offset;
        if (trigger < 1000) {
            trigger = 1000;
        }
    }
}

fn build_402_zombie_time(
    ctx: common.BuildContext,
    _: *common.PythonRandom,
    out_entries: []spawn_runtime.QuestSpawnEntry,
    len: *usize,
) common.QuestSpawnBuildError!void {
    const edges = common.edgeMidpoints(ctx.width, ctx.width, 64.0);
    var trigger: i32 = 1500;
    while (trigger < 0x17CDC) {
        try common.appendSpawn(
            out_entries,
            len,
            edges.right,
            0.0,
            common.SpawnId.zombie_random_41,
            trigger,
            8,
        );
        try common.appendSpawn(
            out_entries,
            len,
            edges.left,
            0.0,
            common.SpawnId.zombie_random_41,
            trigger,
            8,
        );
        trigger += 8000;
    }
}

fn build_403_lizard_zombie_pact(
    ctx: common.BuildContext,
    _: *common.PythonRandom,
    out_entries: []spawn_runtime.QuestSpawnEntry,
    len: *usize,
) common.QuestSpawnBuildError!void {
    const edges = common.edgeMidpoints(ctx.width, ctx.width, 64.0);
    var trigger: i32 = 1500;
    var wave: i32 = 0;
    while (trigger < 0x1BB5C) {
        try common.appendSpawn(
            out_entries,
            len,
            edges.right,
            0.0,
            common.SpawnId.zombie_random_41,
            trigger,
            6,
        );
        try common.appendSpawn(
            out_entries,
            len,
            edges.left,
            0.0,
            common.SpawnId.zombie_random_41,
            trigger,
            6,
        );
        if (@mod(wave, 5) == 0) {
            const idx = @divTrunc(wave, 5);
            try common.appendSpawn(
                out_entries,
                len,
                .{
                    .x = 356.0,
                    .y = @floatFromInt(idx * 0xB4 + 0x100),
                },
                0.0,
                common.SpawnId.alien_spawner_child_31_fast_0c,
                trigger,
                idx + 1,
            );
            try common.appendSpawn(
                out_entries,
                len,
                .{
                    .x = 356.0,
                    .y = @floatFromInt(idx * 0xB4 + 0x180),
                },
                0.0,
                common.SpawnId.alien_spawner_child_31_fast_0c,
                trigger,
                idx + 2,
            );
        }
        trigger += 7000;
        wave += 1;
    }
}

fn build_404_the_collaboration(
    ctx: common.BuildContext,
    _: *common.PythonRandom,
    out_entries: []spawn_runtime.QuestSpawnEntry,
    len: *usize,
) common.QuestSpawnBuildError!void {
    const edges = common.edgeMidpoints(ctx.width, ctx.width, 64.0);
    var trigger: i32 = 1500;
    var wave: i32 = 0;
    while (trigger < 0x2B55C) {
        const count = @as(i32, @intFromFloat(@as(f64, @floatFromInt(wave)) * 0.8 + 7.0));
        try common.appendSpawn(
            out_entries,
            len,
            edges.right,
            0.0,
            common.SpawnId.ai1_alien_blue_tint_1a,
            trigger,
            count,
        );
        try common.appendSpawn(
            out_entries,
            len,
            edges.bottom,
            0.0,
            common.SpawnId.ai1_spider_sp1_blue_tint_1b,
            trigger,
            count,
        );
        try common.appendSpawn(
            out_entries,
            len,
            edges.left,
            0.0,
            common.SpawnId.ai1_lizard_blue_tint_1c,
            trigger,
            count,
        );
        try common.appendSpawn(
            out_entries,
            len,
            edges.top,
            0.0,
            common.SpawnId.zombie_random_41,
            trigger,
            count,
        );
        trigger += 11_000;
        wave += 1;
    }
}

fn build_405_the_massacre(
    ctx: common.BuildContext,
    _: *common.PythonRandom,
    out_entries: []spawn_runtime.QuestSpawnEntry,
    len: *usize,
) common.QuestSpawnBuildError!void {
    const edges = common.edgeMidpoints(ctx.width, ctx.width, 64.0);
    const edges_wide = common.edgeMidpoints(ctx.width, ctx.width, 128.0);

    var trigger: i32 = 1500;
    var wave: i32 = 0;
    while (trigger < 0x1656C) {
        try common.appendSpawn(
            out_entries,
            len,
            edges.right,
            0.0,
            common.SpawnId.zombie_random_41,
            trigger,
            wave + 3,
        );
        if (@mod(wave, 2) == 0) {
            try common.appendSpawn(
                out_entries,
                len,
                edges_wide.right,
                0.0,
                common.SpawnId.alien_const_red_fast_2b,
                trigger,
                wave + 1,
            );
        }
        trigger += 5000;
        wave += 1;
    }
}

fn build_406_the_unblitzkrieg(
    _: common.BuildContext,
    _: *common.PythonRandom,
    out_entries: []spawn_runtime.QuestSpawnEntry,
    len: *usize,
) common.QuestSpawnBuildError!void {
    var trigger: i32 = 500;

    var i_var5: i32 = 0;
    var idx: i32 = 0;
    while (idx < 10) : (idx += 1) {
        const y = @as(f64, @floatFromInt(@divTrunc(i_var5, 10) + 200));
        try common.appendSpawn(
            out_entries,
            len,
            .{ .x = 824.0, .y = y },
            0.0,
            unblitzkrieg_spawn_id_for(@mod(idx, 2) == 1),
            trigger,
            1,
        );
        trigger += 1800;
        i_var5 += 0x270;
    }

    i_var5 = 0;
    var toggle = false;
    idx = 0;
    while (idx < 10) : (idx += 1) {
        const x = @as(f64, @floatFromInt(0x338 - @divTrunc(i_var5, 10)));
        try common.appendSpawn(
            out_entries,
            len,
            .{ .x = x, .y = 824.0 },
            0.0,
            unblitzkrieg_spawn_id_for(toggle),
            trigger,
            1,
        );
        trigger += 1500;
        toggle = !toggle;
        i_var5 += 0x270;
    }

    try common.appendSpawn(
        out_entries,
        len,
        .{ .x = 512.0, .y = 512.0 },
        0.0,
        common.SpawnId.alien_spawner_child_1d_fast_07,
        trigger,
        1,
    );

    i_var5 = 0;
    toggle = false;
    idx = 0;
    while (idx < 10) : (idx += 1) {
        const y = @as(f64, @floatFromInt(0x338 - @divTrunc(i_var5, 10)));
        try common.appendSpawn(
            out_entries,
            len,
            .{ .x = 200.0, .y = y },
            0.0,
            unblitzkrieg_spawn_id_for(toggle),
            trigger,
            1,
        );
        trigger += 1200;
        toggle = !toggle;
        i_var5 += 0x270;
    }

    i_var5 = 0;
    toggle = false;
    idx = 0;
    while (idx < 10) : (idx += 1) {
        const x = @as(f64, @floatFromInt(@divTrunc(i_var5, 10) + 200));
        try common.appendSpawn(
            out_entries,
            len,
            .{ .x = x, .y = 200.0 },
            0.0,
            unblitzkrieg_spawn_id_for(toggle),
            trigger,
            1,
        );
        trigger += 800;
        toggle = !toggle;
        i_var5 += 0x270;
    }

    i_var5 = 0;
    toggle = false;
    idx = 0;
    while (idx < 10) : (idx += 1) {
        const y = @as(f64, @floatFromInt(@divTrunc(i_var5, 10) + 200));
        try common.appendSpawn(
            out_entries,
            len,
            .{ .x = 824.0, .y = y },
            0.0,
            unblitzkrieg_spawn_id_for(toggle),
            trigger,
            1,
        );
        trigger += 800;
        toggle = !toggle;
        i_var5 += 0x270;
    }

    i_var5 = 0;
    toggle = false;
    idx = 0;
    while (idx < 10) : (idx += 1) {
        const x = @as(f64, @floatFromInt(0x338 - @divTrunc(i_var5, 10)));
        try common.appendSpawn(
            out_entries,
            len,
            .{ .x = x, .y = 824.0 },
            0.0,
            unblitzkrieg_spawn_id_for(toggle),
            trigger,
            1,
        );
        trigger += 700;
        toggle = !toggle;
        i_var5 += 0x270;
    }

    i_var5 = 0;
    toggle = false;
    idx = 0;
    while (idx < 10) : (idx += 1) {
        const y = @as(f64, @floatFromInt(0x338 - @divTrunc(i_var5, 10)));
        try common.appendSpawn(
            out_entries,
            len,
            .{ .x = 200.0, .y = y },
            0.0,
            unblitzkrieg_spawn_id_for(toggle),
            trigger,
            1,
        );
        trigger += 700;
        toggle = !toggle;
        i_var5 += 0x270;
    }

    i_var5 = 0;
    toggle = false;
    idx = 0;
    while (idx < 10) : (idx += 1) {
        const x = @as(f64, @floatFromInt(@divTrunc(i_var5, 10) + 200));
        try common.appendSpawn(
            out_entries,
            len,
            .{ .x = x, .y = 200.0 },
            0.0,
            unblitzkrieg_spawn_id_for(toggle),
            trigger,
            1,
        );
        trigger += 800;
        toggle = !toggle;
        i_var5 += 0x270;
    }
}

fn build_407_gauntlet(
    ctx: common.BuildContext,
    _: *common.PythonRandom,
    out_entries: []spawn_runtime.QuestSpawnEntry,
    len: *usize,
) common.QuestSpawnBuildError!void {
    const player_count = ctx.player_count + 4;
    const center = common.centerPoint(ctx.width, ctx.height);
    const edges = common.edgeMidpoints(ctx.width, ctx.width, 64.0);

    const ring_count = player_count + 9;
    if (ring_count > 0) {
        var trigger: i32 = 0;
        const step = std.math.tau / @as(f64, @floatFromInt(ring_count));
        var idx: i32 = 0;
        while (idx < ring_count) : (idx += 1) {
            const angle = @as(f64, @floatFromInt(idx)) * step;
            const pos = ring_point(center, 158.0, angle);
            try common.appendSpawn(
                out_entries,
                len,
                pos,
                0.0,
                common.SpawnId.alien_spawner_child_32_slow_0a,
                trigger,
                1,
            );
            trigger += 200;
        }
    }

    if (ring_count > 0) {
        var trigger: i32 = 4000;
        var count: i32 = 2;
        while (count < ring_count + 2) : (count += 1) {
            try common.appendSpawn(
                out_entries,
                len,
                edges.right,
                0.0,
                common.SpawnId.zombie_random_41,
                trigger,
                count,
            );
            try common.appendSpawn(
                out_entries,
                len,
                edges.left,
                0.0,
                common.SpawnId.zombie_random_41,
                trigger,
                count,
            );
            try common.appendSpawn(
                out_entries,
                len,
                edges.bottom,
                0.0,
                common.SpawnId.zombie_random_41,
                trigger,
                count,
            );
            try common.appendSpawn(
                out_entries,
                len,
                edges.top,
                0.0,
                common.SpawnId.zombie_random_41,
                trigger,
                count,
            );
            trigger += 5500;
        }
    }

    const outer_count = player_count + 0x11;
    if (outer_count > 0) {
        var trigger: i32 = 42_500;
        const step = std.math.tau / @as(f64, @floatFromInt(outer_count));
        var idx: i32 = 0;
        while (idx < outer_count) : (idx += 1) {
            const angle = @as(f64, @floatFromInt(idx)) * step;
            const pos = ring_point(center, 258.0, angle);
            try common.appendSpawn(
                out_entries,
                len,
                pos,
                0.0,
                common.SpawnId.alien_spawner_child_32_slow_0a,
                trigger,
                1,
            );
            trigger += 500;
        }
    }
}

fn build_408_syntax_terror(
    ctx: common.BuildContext,
    _: *common.PythonRandom,
    out_entries: []spawn_runtime.QuestSpawnEntry,
    len: *usize,
) common.QuestSpawnBuildError!void {
    const player_count = ctx.player_count + 4;
    const loop_count = player_count + 9;

    var outer_seed: i32 = 0x14C9;
    var outer_index: i32 = 0;
    var trigger_base: i32 = 1500;

    while (outer_seed < 0x159D) {
        if (loop_count > 0) {
            var trigger = trigger_base;
            var inner_seed: i32 = 0x4C5;
            var i: i32 = 0;
            while (i < loop_count) : (i += 1) {
                const x = @mod((((i * i * 0x4C + 0xEC) * i) + outer_seed * outer_index), 0x380) + 0x40;
                const y = @mod((inner_seed * i + (outer_index * outer_index * 0x4C + 0x1B) * outer_index), 0x380) + 0x40;
                try common.appendSpawn(
                    out_entries,
                    len,
                    .{
                        .x = @floatFromInt(x),
                        .y = @floatFromInt(y),
                    },
                    0.0,
                    common.SpawnId.alien_spawner_child_1d_fast_07,
                    trigger,
                    1,
                );
                trigger += 300;
                inner_seed += 0x15;
            }
            trigger_base += 30_000;
        }
        outer_seed += 0x35;
        outer_index += 1;
    }
}

fn build_409_the_annihilation(
    ctx: common.BuildContext,
    _: *common.PythonRandom,
    out_entries: []spawn_runtime.QuestSpawnEntry,
    len: *usize,
) common.QuestSpawnBuildError!void {
    const half_w = @floor(ctx.width / 2.0);
    try common.appendSpawn(
        out_entries,
        len,
        .{ .x = 128.0, .y = half_w },
        0.0,
        common.SpawnId.alien_const_red_fast_2b,
        500,
        2,
    );

    var trigger: i32 = 500;
    var i_var5: i32 = 0;
    var idx: i32 = 0;
    while (idx < 12) : (idx += 1) {
        const y = @as(f64, @floatFromInt(@divTrunc(i_var5, 12) + 0x80));
        const x: f64 = if (@mod(idx, 2) == 0) 832.0 else 896.0;
        try common.appendSpawn(
            out_entries,
            len,
            .{ .x = x, .y = y },
            0.0,
            common.SpawnId.alien_spawner_child_1d_fast_07,
            trigger,
            1,
        );
        trigger += 500;
        i_var5 += 0x300;
    }

    trigger = 45_000;
    i_var5 = 0;
    var toggle = false;
    idx = 0;
    while (idx < 12) : (idx += 1) {
        const y = @as(f64, @floatFromInt(@divTrunc(i_var5, 12) + 0x80));
        const x: f64 = if (toggle) 832.0 else 896.0;
        try common.appendSpawn(
            out_entries,
            len,
            .{ .x = x, .y = y },
            0.0,
            common.SpawnId.alien_spawner_child_1d_fast_07,
            trigger,
            1,
        );
        trigger += 300;
        toggle = !toggle;
        i_var5 += 0x300;
    }
}

fn build_410_the_end_of_all(
    ctx: common.BuildContext,
    _: *common.PythonRandom,
    out_entries: []spawn_runtime.QuestSpawnEntry,
    len: *usize,
) common.QuestSpawnBuildError!void {
    try common.appendSpawn(
        out_entries,
        len,
        .{ .x = 128.0, .y = 128.0 },
        0.0,
        common.SpawnId.spider_sp1_const_ranged_variant_3c,
        3000,
        1,
    );
    try common.appendSpawn(
        out_entries,
        len,
        .{ .x = 896.0, .y = 128.0 },
        0.0,
        common.SpawnId.spider_sp1_const_ranged_variant_3c,
        6000,
        1,
    );
    try common.appendSpawn(
        out_entries,
        len,
        .{ .x = 128.0, .y = 896.0 },
        0.0,
        common.SpawnId.spider_sp1_const_ranged_variant_3c,
        9000,
        1,
    );
    try common.appendSpawn(
        out_entries,
        len,
        .{ .x = 896.0, .y = 896.0 },
        0.0,
        common.SpawnId.spider_sp1_const_ranged_variant_3c,
        12_000,
        1,
    );

    const center = common.centerPoint(ctx.width, ctx.height);
    const edges_wide = common.edgeMidpoints(ctx.width, ctx.height, 128.0);

    var trigger: i32 = 13_000;
    var idx: i32 = 0;
    while (idx < 6) : (idx += 1) {
        const angle = @as(f64, @floatFromInt(idx)) * 1.0471976;
        const pos = ring_point(center, 80.0, angle);
        try common.appendSpawn(
            out_entries,
            len,
            pos,
            0.0,
            common.SpawnId.alien_spawner_child_1d_fast_07,
            trigger,
            1,
        );
        trigger += 300;
    }

    try common.appendSpawn(
        out_entries,
        len,
        .{ .x = 512.0, .y = 512.0 },
        0.0,
        common.SpawnId.alien_spawner_child_3c_slow_0b,
        trigger,
        1,
    );

    trigger = 18_000;
    var y: i32 = 0x100;
    var toggle = false;
    while (y < 0x300) : (y += 0x80) {
        const x = if (toggle) edges_wide.right.x else edges_wide.left.x;
        try common.appendSpawn(
            out_entries,
            len,
            .{ .x = x, .y = @floatFromInt(y) },
            0.0,
            common.SpawnId.spider_sp1_const_ranged_variant_3c,
            trigger,
            2,
        );
        trigger += 1000;
        toggle = !toggle;
    }

    trigger = 43_000;
    idx = 0;
    while (idx < 6) : (idx += 1) {
        const angle = 0.5235988 + @as(f64, @floatFromInt(idx)) * 1.0471976;
        const pos = ring_point(center, 80.0, angle);
        try common.appendSpawn(
            out_entries,
            len,
            pos,
            0.0,
            common.SpawnId.alien_spawner_child_1d_fast_07,
            trigger,
            1,
        );
        trigger += 300;
    }

    trigger = 62_800;
    idx = 0;
    while (idx < 12) : (idx += 1) {
        const angle = 0.5235988 + @as(f64, @floatFromInt(idx)) * 0.5235988;
        const pos = ring_point(center, 180.0, angle);
        try common.appendSpawn(
            out_entries,
            len,
            pos,
            0.0,
            common.SpawnId.alien_spawner_child_1d_fast_07,
            trigger,
            1,
        );
        trigger += 500;
    }

    trigger = 48_000;
    y = 0x100;
    toggle = false;
    while (y < 0x300) : (y += 0x80) {
        const x = if (toggle) edges_wide.right.x else edges_wide.left.x;
        try common.appendSpawn(
            out_entries,
            len,
            .{ .x = x, .y = @floatFromInt(y) },
            0.0,
            common.SpawnId.spider_sp1_const_ranged_variant_3c,
            trigger,
            2,
        );
        trigger += 1000;
        toggle = !toggle;
    }
}

fn unblitzkrieg_spawn_id_for(toggle: bool) i32 {
    return if (toggle)
        common.SpawnId.alien_spawner_child_31_slow_0d
    else
        common.SpawnId.alien_spawner_child_1d_fast_07;
}

fn ring_point(center: spawn_runtime.Vec2, radius: f64, angle: f64) spawn_runtime.Vec2 {
    return common.addVec(center, common.mulVec(common.vecFromAngle(angle), radius));
}
