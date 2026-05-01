const common = @import("logic_common.zig");
const spawn_runtime = @import("../runtime/spawn.zig");
const game_ids = @import("../game_ids.zig");

pub const tier2_builders = [_]common.LevelBuilder{
    .{ .level_key = 201, .start_weapon_id = game_ids.WeaponId.pistol, .build = build21EverredPastures },
    .{ .level_key = 202, .start_weapon_id = game_ids.WeaponId.pistol, .build = build22SpiderSpawns },
    .{ .level_key = 203, .start_weapon_id = game_ids.WeaponId.pistol, .build = build23ArachnoidFarm },
    .{ .level_key = 204, .start_weapon_id = game_ids.WeaponId.pistol, .build = build24TwoFronts },
    .{ .level_key = 205, .start_weapon_id = game_ids.WeaponId.gauss_gun, .build = build25SweepStakes },
    .{ .level_key = 206, .start_weapon_id = game_ids.WeaponId.pistol, .build = build26EvilZombiesAtLarge },
    .{ .level_key = 207, .start_weapon_id = game_ids.WeaponId.submachine_gun, .build = build27SurvivalOfTheFastest },
    .{ .level_key = 208, .start_weapon_id = game_ids.WeaponId.pistol, .build = build28LandOfLizards },
    .{ .level_key = 209, .start_weapon_id = game_ids.WeaponId.pistol, .build = build29GhostPatrols },
    .{ .level_key = 210, .start_weapon_id = game_ids.WeaponId.pistol, .build = build210Spideroids },
};

fn build21EverredPastures(
    ctx: common.BuildContext,
    rng: *common.QuestRng,
    out_entries: []spawn_runtime.QuestSpawnEntry,
    len: *usize,
) common.QuestSpawnBuildError!void {
    _ = rng;
    const edges = common.squareEdgeMidpoints(ctx.width, 64.0);
    var wave: i32 = 1;
    while (wave <= 8) : (wave += 1) {
        const trigger = (wave - 1) * 13_000 + 1_500;
        try common.appendSpawn(
            out_entries,
            len,
            edges.right,
            0.0,
            common.SpawnId.spider_sp1_random_32,
            trigger,
            wave,
        );
        try common.appendSpawn(
            out_entries,
            len,
            edges.left,
            0.0,
            common.SpawnId.spider_sp1_random_red_33,
            trigger,
            wave,
        );
        try common.appendSpawn(
            out_entries,
            len,
            edges.bottom,
            0.0,
            common.SpawnId.spider_sp1_random_green_34,
            trigger,
            wave,
        );
        try common.appendSpawn(
            out_entries,
            len,
            edges.top,
            0.0,
            common.SpawnId.spider_sp2_random_35,
            trigger,
            wave,
        );
        if (wave == 4) {
            try common.appendSpawn(
                out_entries,
                len,
                edges.top,
                0.0,
                common.SpawnId.ai1_spider_sp1_blue_tint_1b,
                40_500,
                8,
            );
            try common.appendSpawn(
                out_entries,
                len,
                edges.bottom,
                0.0,
                common.SpawnId.ai1_spider_sp1_blue_tint_1b,
                40_500,
                8,
            );
        }
    }
}

fn build22SpiderSpawns(
    ctx: common.BuildContext,
    rng: *common.QuestRng,
    out_entries: []spawn_runtime.QuestSpawnEntry,
    len: *usize,
) common.QuestSpawnBuildError!void {
    _ = rng;
    const corners = common.insetCornerPoints(ctx.width, ctx.height, 128.0);
    const edges = common.squareEdgeMidpoints(ctx.width, 64.0);
    try common.appendSpawn(
        out_entries,
        len,
        corners.top_left,
        0.0,
        common.SpawnId.alien_spawner_child_32_fast_10,
        1_500,
        1,
    );
    try common.appendSpawn(
        out_entries,
        len,
        corners.bottom_right,
        0.0,
        common.SpawnId.alien_spawner_child_32_fast_10,
        1_500,
        1,
    );
    try common.appendSpawn(
        out_entries,
        len,
        corners.top_right,
        0.0,
        common.SpawnId.alien_spawner_child_32_fast_10,
        1_500,
        1,
    );
    try common.appendSpawn(
        out_entries,
        len,
        corners.bottom_left,
        0.0,
        common.SpawnId.alien_spawner_child_32_fast_10,
        1_500,
        1,
    );
    try common.appendSpawn(
        out_entries,
        len,
        edges.left,
        0.0,
        common.SpawnId.spider_sp1_ai7_timer_38,
        3_000,
        2,
    );
    try common.appendSpawn(
        out_entries,
        len,
        .{ .x = 512.0, .y = 512.0 },
        0.0,
        common.SpawnId.alien_spawner_child_32_slow_0a,
        18_000,
        1,
    );
    try common.appendSpawn(
        out_entries,
        len,
        .{ .x = 448.0, .y = 448.0 },
        0.0,
        common.SpawnId.alien_spawner_child_32_fast_10,
        20_500,
        1,
    );
    try common.appendSpawn(
        out_entries,
        len,
        .{ .x = 576.0, .y = 448.0 },
        0.0,
        common.SpawnId.alien_spawner_child_32_fast_10,
        26_000,
        1,
    );
    try common.appendSpawn(
        out_entries,
        len,
        edges.right,
        0.0,
        common.SpawnId.spider_sp1_ai7_timer_38,
        21_000,
        2,
    );
    try common.appendSpawn(
        out_entries,
        len,
        .{ .x = 576.0, .y = 576.0 },
        0.0,
        common.SpawnId.alien_spawner_child_32_fast_10,
        31_500,
        1,
    );
    try common.appendSpawn(
        out_entries,
        len,
        .{ .x = 448.0, .y = 576.0 },
        0.0,
        common.SpawnId.alien_spawner_child_32_fast_10,
        22_000,
        1,
    );
}

fn build23ArachnoidFarm(
    ctx: common.BuildContext,
    rng: *common.QuestRng,
    out_entries: []spawn_runtime.QuestSpawnEntry,
    len: *usize,
) common.QuestSpawnBuildError!void {
    _ = rng;
    const count_a = ctx.player_count + 4;
    if (count_a >= 0) {
        const top_start: spawn_runtime.Vec2 = .{ .x = 256.0, .y = 256.0 };
        const bottom_start: spawn_runtime.Vec2 = .{ .x = 256.0, .y = 768.0 };
        const line_step: spawn_runtime.Vec2 = .{ .x = 102.4, .y = 0.0 };
        var trigger: i32 = 500;
        var idx: i32 = 0;
        while (idx < count_a) : (idx += 1) {
            const pos = common.linePointAt(top_start, line_step, idx);
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
        trigger = 10_500;
        idx = 0;
        while (idx < count_a) : (idx += 1) {
            const pos = common.linePointAt(bottom_start, line_step, idx);
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

    const count_b = ctx.player_count + 7;
    if (count_b >= 0) {
        const mid_start: spawn_runtime.Vec2 = .{ .x = 256.0, .y = 512.0 };
        const mid_step: spawn_runtime.Vec2 = .{ .x = 64.0, .y = 0.0 };
        var trigger: i32 = 40_500;
        var idx: i32 = 0;
        while (idx < count_b) : (idx += 1) {
            const pos = common.linePointAt(mid_start, mid_step, idx);
            try common.appendSpawn(
                out_entries,
                len,
                pos,
                0.0,
                common.SpawnId.alien_spawner_child_32_fast_10,
                trigger,
                1,
            );
            trigger += 3_500;
        }
    }
}

fn build24TwoFronts(
    ctx: common.BuildContext,
    rng: *common.QuestRng,
    out_entries: []spawn_runtime.QuestSpawnEntry,
    len: *usize,
) common.QuestSpawnBuildError!void {
    _ = rng;
    const edges = common.squareEdgeMidpoints(ctx.width, 64.0);
    var wave: i32 = 0;
    while (wave < 40) : (wave += 1) {
        const trigger_a = wave * 2_000 + 1_000;
        const trigger_b = (wave * 5 + 5) * 400;
        try common.appendSpawn(
            out_entries,
            len,
            edges.right,
            0.0,
            common.SpawnId.ai1_alien_blue_tint_1a,
            trigger_a,
            1,
        );
        try common.appendSpawn(
            out_entries,
            len,
            edges.left,
            0.0,
            common.SpawnId.ai1_spider_sp1_blue_tint_1b,
            trigger_b,
            1,
        );
        if (wave == 10 or wave == 20) {
            const trigger = wave * 2_000 + 2_500;
            try common.appendSpawn(
                out_entries,
                len,
                .{ .x = 256.0, .y = 256.0 },
                0.0,
                common.SpawnId.alien_spawner_child_32_slow_0a,
                trigger,
                1,
            );
            try common.appendSpawn(
                out_entries,
                len,
                .{ .x = 768.0, .y = 768.0 },
                0.0,
                common.SpawnId.alien_spawner_child_1d_fast_07,
                trigger,
                1,
            );
        }
        if (wave == 30) {
            try common.appendSpawn(
                out_entries,
                len,
                .{ .x = 768.0, .y = 256.0 },
                0.0,
                common.SpawnId.alien_spawner_child_32_slow_0a,
                62_500,
                1,
            );
            try common.appendSpawn(
                out_entries,
                len,
                .{ .x = 256.0, .y = 768.0 },
                0.0,
                common.SpawnId.alien_spawner_child_1d_fast_07,
                62_500,
                1,
            );
        }
    }
}

fn build25SweepStakes(
    ctx: common.BuildContext,
    rng: *common.QuestRng,
    out_entries: []spawn_runtime.QuestSpawnEntry,
    len: *usize,
) common.QuestSpawnBuildError!void {
    const center = common.centerPoint(ctx.width, ctx.height);
    var trigger: i32 = 2_000;
    var step: i32 = 2_000;
    while (step > 720) {
        const angle = common.randomAngle(rng);
        try common.appendRadialSpawns(
            out_entries,
            len,
            center,
            angle,
            84.0,
            252.0,
            42.0,
            .from_center,
            common.SpawnId.alien_ai7_orbiter_36,
            trigger,
            1,
        );
        trigger += @max(step, 600);
        step -= 0x50;
    }
}

fn build26EvilZombiesAtLarge(
    ctx: common.BuildContext,
    rng: *common.QuestRng,
    out_entries: []spawn_runtime.QuestSpawnEntry,
    len: *usize,
) common.QuestSpawnBuildError!void {
    _ = rng;
    const edges = common.squareEdgeMidpoints(ctx.width, 64.0);
    var trigger: i32 = 1_500;
    var count: i32 = 4;
    while (count <= 13) : (count += 1) {
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
        trigger += 5_500;
    }
}

fn build27SurvivalOfTheFastest(
    ctx: common.BuildContext,
    rng: *common.QuestRng,
    out_entries: []spawn_runtime.QuestSpawnEntry,
    len: *usize,
) common.QuestSpawnBuildError!void {
    _ = rng;
    const corners = common.insetCornerPoints(ctx.width, ctx.height, 128.0);

    var trigger: i32 = 500;
    var x: i32 = 0x100;
    while (x < 0x2B0) : (x += 0x48) {
        try common.appendSpawn(
            out_entries,
            len,
            .{ .x = @as(f32, @floatFromInt(x)), .y = 256.0 },
            0.0,
            common.SpawnId.alien_spawner_child_32_fast_10,
            trigger,
            1,
        );
        trigger += 900;
    }

    trigger = 5_900;
    var y: i32 = 0x100;
    while (y < 0x2B0) : (y += 0x48) {
        try common.appendSpawn(
            out_entries,
            len,
            .{ .x = 688.0, .y = @as(f32, @floatFromInt(y)) },
            0.0,
            common.SpawnId.alien_spawner_child_32_fast_10,
            trigger,
            1,
        );
        trigger += 900;
    }

    trigger = 11_300;
    const loop3_x = [_]i32{ 0x2B0, 0x268, 0x220, 0x1D8 };
    for (loop3_x) |x_value| {
        try common.appendSpawn(
            out_entries,
            len,
            .{ .x = @as(f32, @floatFromInt(x_value)), .y = 688.0 },
            0.0,
            common.SpawnId.alien_spawner_child_32_fast_10,
            trigger,
            1,
        );
        trigger += 900;
    }

    trigger = 14_900;
    const loop4_y = [_]i32{ 0x2B0, 0x268, 0x220, 0x1D8 };
    for (loop4_y) |y_value| {
        try common.appendSpawn(
            out_entries,
            len,
            .{ .x = 400.0, .y = @as(f32, @floatFromInt(y_value)) },
            0.0,
            common.SpawnId.alien_spawner_child_32_fast_10,
            trigger,
            1,
        );
        trigger += 900;
    }

    trigger = 18_500;
    x = 400;
    while (x < 0x220) : (x += 0x48) {
        try common.appendSpawn(
            out_entries,
            len,
            .{ .x = @as(f32, @floatFromInt(x)), .y = 400.0 },
            0.0,
            common.SpawnId.alien_spawner_child_32_fast_10,
            trigger,
            1,
        );
        trigger += 900;
    }

    try common.appendSpawn(
        out_entries,
        len,
        corners.top_left,
        0.0,
        common.SpawnId.alien_spawner_child_32_fast_10,
        22_300,
        1,
    );
    try common.appendSpawn(
        out_entries,
        len,
        corners.top_right,
        0.0,
        common.SpawnId.alien_spawner_child_1d_fast_07,
        22_300,
        1,
    );
    try common.appendSpawn(
        out_entries,
        len,
        corners.bottom_left,
        0.0,
        common.SpawnId.alien_spawner_child_1d_fast_07,
        24_300,
        1,
    );
    try common.appendSpawn(
        out_entries,
        len,
        corners.bottom_right,
        0.0,
        common.SpawnId.alien_spawner_child_32_fast_10,
        24_300,
        1,
    );
}

fn build28LandOfLizards(
    ctx: common.BuildContext,
    rng: *common.QuestRng,
    out_entries: []spawn_runtime.QuestSpawnEntry,
    len: *usize,
) common.QuestSpawnBuildError!void {
    _ = ctx;
    _ = rng;
    try common.appendSpawn(
        out_entries,
        len,
        .{ .x = 256.0, .y = 256.0 },
        0.0,
        common.SpawnId.alien_spawner_ring_24_0e,
        2_000,
        1,
    );
    try common.appendSpawn(
        out_entries,
        len,
        .{ .x = 768.0, .y = 256.0 },
        0.0,
        common.SpawnId.alien_spawner_ring_24_0e,
        12_000,
        1,
    );
    try common.appendSpawn(
        out_entries,
        len,
        .{ .x = 256.0, .y = 768.0 },
        0.0,
        common.SpawnId.alien_spawner_ring_24_0e,
        22_000,
        1,
    );
    try common.appendSpawn(
        out_entries,
        len,
        .{ .x = 768.0, .y = 768.0 },
        0.0,
        common.SpawnId.alien_spawner_ring_24_0e,
        32_000,
        1,
    );
}

fn build29GhostPatrols(
    ctx: common.BuildContext,
    rng: *common.QuestRng,
    out_entries: []spawn_runtime.QuestSpawnEntry,
    len: *usize,
) common.QuestSpawnBuildError!void {
    _ = rng;
    const edges = common.edgeMidpoints(ctx.width, ctx.height, 128.0);
    try common.appendSpawn(
        out_entries,
        len,
        edges.right,
        0.0,
        common.SpawnId.alien_const_red_fast_2b,
        1_500,
        2,
    );

    var trigger: i32 = 2_500;
    var i: i32 = 0;
    while (i < 12) : (i += 1) {
        const x = if (@mod(i, 2) == 0) edges.left.x else edges.right.x;
        try common.appendSpawn(
            out_entries,
            len,
            .{ .x = x, .y = edges.left.y },
            0.0,
            common.SpawnId.formation_ring_alien_5_19,
            trigger,
            1,
        );
        trigger += 2_500;
    }

    const loop_count: i32 = 12;
    try common.appendSpawn(
        out_entries,
        len,
        .{ .x = -264.0, .y = edges.left.y },
        0.0,
        common.SpawnId.alien_const_red_fast_2b,
        (loop_count - 1) * 2_500,
        1,
    );
    try common.appendSpawn(
        out_entries,
        len,
        .{ .x = edges.left.x, .y = edges.left.y },
        0.0,
        common.SpawnId.formation_grid_alien_bronze_18,
        (5 * loop_count + 15) * 500,
        1,
    );
}

fn build210Spideroids(
    ctx: common.BuildContext,
    rng: *common.QuestRng,
    out_entries: []spawn_runtime.QuestSpawnEntry,
    len: *usize,
) common.QuestSpawnBuildError!void {
    _ = rng;
    const edges = common.squareEdgeMidpoints(ctx.width, 64.0);
    try common.appendSpawn(
        out_entries,
        len,
        edges.right,
        0.0,
        common.SpawnId.spider_sp2_splitter_01,
        1_000,
        1,
    );
    try common.appendSpawn(
        out_entries,
        len,
        edges.left,
        0.0,
        common.SpawnId.spider_sp2_splitter_01,
        3_000,
        1,
    );
    try common.appendSpawn(
        out_entries,
        len,
        .{ .x = edges.right.x, .y = 256.0 },
        0.0,
        common.SpawnId.spider_sp2_splitter_01,
        6_000,
        1,
    );
    try common.appendSpawn(
        out_entries,
        len,
        .{ .x = edges.right.x, .y = 762.0 },
        0.0,
        common.SpawnId.spider_sp2_splitter_01,
        9_000,
        1,
    );
    try common.appendSpawn(
        out_entries,
        len,
        edges.bottom,
        0.0,
        common.SpawnId.spider_sp2_splitter_01,
        9_000,
        1,
    );
    try common.appendSpawn(
        out_entries,
        len,
        .{ .x = edges.left.x, .y = 762.0 },
        0.0,
        common.SpawnId.spider_sp2_splitter_01,
        9_000,
        1,
    );
}
