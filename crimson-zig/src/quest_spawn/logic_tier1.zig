const common = @import("logic_common.zig");
const game_ids = @import("../game_ids.zig");
const spawn_runtime = @import("../runtime/spawn.zig");

const default_edge_offset: f32 = 64.0;

pub const tier1_builders = [_]common.LevelBuilder{
    .{ .level_key = 101, .start_weapon_id = game_ids.WeaponId.pistol, .build = build_1_1_land_hostile },
    .{ .level_key = 102, .start_weapon_id = game_ids.WeaponId.pistol, .build = build_1_2_minor_alien_breach },
    .{ .level_key = 103, .start_weapon_id = game_ids.WeaponId.pistol, .build = build_1_3_target_practice },
    .{ .level_key = 104, .start_weapon_id = game_ids.WeaponId.pistol, .build = build_1_4_frontline_assault },
    .{ .level_key = 105, .start_weapon_id = game_ids.WeaponId.pistol, .build = build_1_5_alien_dens },
    .{ .level_key = 106, .start_weapon_id = game_ids.WeaponId.pistol, .build = build_1_6_the_random_factor },
    .{ .level_key = 107, .start_weapon_id = game_ids.WeaponId.pistol, .build = build_1_7_spider_wave_syndrome },
    .{ .level_key = 108, .start_weapon_id = game_ids.WeaponId.pistol, .build = build_1_8_alien_squads },
    .{ .level_key = 109, .start_weapon_id = game_ids.WeaponId.pistol, .build = build_1_9_nesting_grounds },
    .{ .level_key = 110, .start_weapon_id = game_ids.WeaponId.pistol, .build = build_1_10_8_legged_terror },
};

fn build_1_1_land_hostile(
    ctx: common.BuildContext,
    rng: *common.QuestRng,
    out_entries: []spawn_runtime.QuestSpawnEntry,
    len: *usize,
) common.QuestSpawnBuildError!void {
    _ = rng;
    const edges = common.edgeMidpoints(ctx.width, ctx.height, default_edge_offset);
    const corners = common.cornerPoints(ctx.width, ctx.height, default_edge_offset);

    try common.appendSpawn(out_entries, len, edges.bottom, 0.0, common.SpawnId.alien_const_pale_green_26, 500, 1);
    try common.appendSpawn(out_entries, len, corners.bottom_left, 0.0, common.SpawnId.alien_const_pale_green_26, 2500, 2);
    try common.appendSpawn(out_entries, len, corners.top_left, 0.0, common.SpawnId.alien_const_pale_green_26, 6500, 3);
    try common.appendSpawn(out_entries, len, corners.top_right, 0.0, common.SpawnId.alien_const_pale_green_26, 11500, 4);
}

fn build_1_2_minor_alien_breach(
    ctx: common.BuildContext,
    rng: *common.QuestRng,
    out_entries: []spawn_runtime.QuestSpawnEntry,
    len: *usize,
) common.QuestSpawnBuildError!void {
    _ = rng;
    const center = common.centerPoint(ctx.width, ctx.height);
    const edges = common.edgeMidpoints(ctx.width, ctx.height, default_edge_offset);

    try common.appendSpawn(out_entries, len, .{ .x = 256.0, .y = 256.0 }, 0.0, common.SpawnId.alien_const_pale_green_26, 1000, 2);
    try common.appendSpawn(out_entries, len, .{ .x = 256.0, .y = 128.0 }, 0.0, common.SpawnId.alien_const_pale_green_26, 1700, 2);

    for (2..18) |i_usize| {
        const i: i32 = @intCast(i_usize);
        const trigger = (i * 5 - 10) * 720;

        try common.appendSpawn(
            out_entries,
            len,
            edges.right,
            0.0,
            common.SpawnId.alien_const_pale_green_26,
            trigger,
            1,
        );

        if (i > 6) {
            try common.appendSpawn(
                out_entries,
                len,
                .{ .x = edges.right.x, .y = center.y - 256.0 },
                0.0,
                common.SpawnId.alien_const_pale_green_26,
                trigger,
                1,
            );
        }

        if (i == 13) {
            try common.appendSpawn(
                out_entries,
                len,
                edges.bottom,
                0.0,
                common.SpawnId.alien_const_grey_brute_29,
                39600,
                1,
            );
        }

        if (i > 10) {
            try common.appendSpawn(
                out_entries,
                len,
                .{ .x = edges.left.x, .y = center.y + 256.0 },
                0.0,
                common.SpawnId.alien_const_pale_green_26,
                trigger,
                1,
            );
        }
    }
}

fn build_1_3_target_practice(
    ctx: common.BuildContext,
    rng: *common.QuestRng,
    out_entries: []spawn_runtime.QuestSpawnEntry,
    len: *usize,
) common.QuestSpawnBuildError!void {
    const center = common.centerPoint(ctx.width, ctx.height);
    var trigger: i32 = 2000;
    var step: i32 = 2000;

    while (true) {
        const angle = common.randomAngle(rng);
        const radius = @as(f32, @floatFromInt(rng.randBelow(8) + 2)) * 32.0;
        const point = common.addVec(center, common.mulVec(common.vecFromAngle(angle), radius));
        const heading = common.headingFromCenter(point, center);

        try common.appendSpawn(
            out_entries,
            len,
            point,
            heading,
            common.SpawnId.alien_ai7_orbiter_36,
            trigger,
            1,
        );

        trigger += @max(step, 1100);
        step -= 50;
        if (step <= 500) break;
    }
}

fn build_1_4_frontline_assault(
    ctx: common.BuildContext,
    rng: *common.QuestRng,
    out_entries: []spawn_runtime.QuestSpawnEntry,
    len: *usize,
) common.QuestSpawnBuildError!void {
    _ = rng;
    const edges = common.edgeMidpoints(ctx.width, ctx.height, default_edge_offset);
    const corners = common.cornerPoints(ctx.width, ctx.height, default_edge_offset);
    var step: i32 = 2500;

    for (2..22) |i_usize| {
        const i: i32 = @intCast(i_usize);
        const spawn_id = if (i < 5)
            common.SpawnId.alien_const_pale_green_26
        else if (i < 10)
            common.SpawnId.ai1_alien_blue_tint_1a
        else
            common.SpawnId.alien_const_pale_green_26;
        const trigger = i * step - 5000;

        try common.appendSpawn(out_entries, len, edges.bottom, 0.0, spawn_id, trigger, 1);

        if (i > 4) {
            try common.appendSpawn(
                out_entries,
                len,
                corners.top_left,
                0.0,
                common.SpawnId.alien_const_pale_green_26,
                trigger,
                1,
            );
        }

        if (i > 10) {
            try common.appendSpawn(
                out_entries,
                len,
                corners.top_right,
                0.0,
                common.SpawnId.alien_const_pale_green_26,
                trigger,
                1,
            );
        }

        if (i == 10) {
            const burst_trigger = (step * 5 - 2500) * 2;
            try common.appendSpawn(
                out_entries,
                len,
                edges.right,
                0.0,
                common.SpawnId.alien_const_grey_brute_29,
                burst_trigger,
                1,
            );
            try common.appendSpawn(
                out_entries,
                len,
                edges.left,
                0.0,
                common.SpawnId.alien_const_grey_brute_29,
                burst_trigger,
                1,
            );
        }

        step = @max(step - 50, 1800);
    }
}

fn build_1_5_alien_dens(
    ctx: common.BuildContext,
    rng: *common.QuestRng,
    out_entries: []spawn_runtime.QuestSpawnEntry,
    len: *usize,
) common.QuestSpawnBuildError!void {
    _ = rng;
    try common.appendSpawn(out_entries, len, .{ .x = 256.0, .y = 256.0 }, 0.0, common.SpawnId.alien_spawner_child_1d_slow_08, 1500, 1);
    try common.appendSpawn(out_entries, len, .{ .x = 768.0, .y = 768.0 }, 0.0, common.SpawnId.alien_spawner_child_1d_slow_08, 1500, 1);
    try common.appendSpawn(
        out_entries,
        len,
        .{ .x = 512.0, .y = 512.0 },
        0.0,
        common.SpawnId.alien_spawner_child_1d_slow_08,
        23500,
        ctx.player_count,
    );
    try common.appendSpawn(out_entries, len, .{ .x = 256.0, .y = 768.0 }, 0.0, common.SpawnId.alien_spawner_child_1d_slow_08, 38500, 1);
    try common.appendSpawn(out_entries, len, .{ .x = 768.0, .y = 256.0 }, 0.0, common.SpawnId.alien_spawner_child_1d_slow_08, 38500, 1);
}

fn build_1_6_the_random_factor(
    ctx: common.BuildContext,
    rng: *common.QuestRng,
    out_entries: []spawn_runtime.QuestSpawnEntry,
    len: *usize,
) common.QuestSpawnBuildError!void {
    const center = common.centerPoint(ctx.width, ctx.height);
    const edges = common.edgeMidpoints(ctx.width, ctx.height, default_edge_offset);
    var trigger: i32 = 1500;

    while (trigger < 101500) {
        try common.appendSpawn(
            out_entries,
            len,
            edges.right,
            0.0,
            common.SpawnId.alien_random_1d,
            trigger,
            ctx.player_count * 2 + 4,
        );
        try common.appendSpawn(
            out_entries,
            len,
            edges.left,
            0.0,
            common.SpawnId.alien_random_1d,
            trigger + 200,
            6,
        );

        if (rng.randBelow(5) == 3) {
            try common.appendSpawn(
                out_entries,
                len,
                .{ .x = center.x, .y = edges.bottom.y },
                0.0,
                common.SpawnId.alien_const_grey_brute_29,
                trigger,
                ctx.player_count,
            );
        }

        trigger += 10000;
    }
}

fn build_1_7_spider_wave_syndrome(
    ctx: common.BuildContext,
    rng: *common.QuestRng,
    out_entries: []spawn_runtime.QuestSpawnEntry,
    len: *usize,
) common.QuestSpawnBuildError!void {
    _ = rng;
    const edges = common.edgeMidpoints(ctx.width, ctx.height, default_edge_offset);
    var trigger: i32 = 1500;

    while (trigger < 100500) {
        try common.appendSpawn(
            out_entries,
            len,
            edges.left,
            0.0,
            common.SpawnId.spider_sp1_const_blue_40,
            trigger,
            ctx.player_count * 2 + 6,
        );
        trigger += 5500;
    }
}

fn build_1_8_alien_squads(
    _: common.BuildContext,
    rng: *common.QuestRng,
    out_entries: []spawn_runtime.QuestSpawnEntry,
    len: *usize,
) common.QuestSpawnBuildError!void {
    _ = rng;
    try common.appendSpawn(out_entries, len, .{ .x = -256.0, .y = 256.0 }, 0.0, common.SpawnId.formation_ring_alien_8_12, 1500, 1);
    try common.appendSpawn(out_entries, len, .{ .x = -256.0, .y = 768.0 }, 0.0, common.SpawnId.formation_ring_alien_8_12, 2500, 1);
    try common.appendSpawn(out_entries, len, .{ .x = 768.0, .y = -256.0 }, 0.0, common.SpawnId.formation_ring_alien_8_12, 5500, 1);
    try common.appendSpawn(out_entries, len, .{ .x = 768.0, .y = 1280.0 }, 0.0, common.SpawnId.formation_ring_alien_8_12, 8500, 1);
    try common.appendSpawn(out_entries, len, .{ .x = 1280.0, .y = 1280.0 }, 0.0, common.SpawnId.formation_ring_alien_8_12, 14500, 1);
    try common.appendSpawn(out_entries, len, .{ .x = 1280.0, .y = 768.0 }, 0.0, common.SpawnId.formation_ring_alien_8_12, 18500, 1);
    try common.appendSpawn(out_entries, len, .{ .x = -256.0, .y = 256.0 }, 0.0, common.SpawnId.formation_ring_alien_8_12, 25000, 1);
    try common.appendSpawn(out_entries, len, .{ .x = -256.0, .y = 768.0 }, 0.0, common.SpawnId.formation_ring_alien_8_12, 30000, 1);

    var trigger: i32 = 36200;
    while (trigger < 83000) {
        try common.appendSpawn(
            out_entries,
            len,
            .{ .x = -64.0, .y = -64.0 },
            0.0,
            common.SpawnId.alien_const_pale_green_26,
            trigger - 400,
            1,
        );
        try common.appendSpawn(
            out_entries,
            len,
            .{ .x = 1088.0, .y = 1088.0 },
            0.0,
            common.SpawnId.alien_const_pale_green_26,
            trigger,
            1,
        );
        trigger += 1800;
    }
}

fn build_1_9_nesting_grounds(
    ctx: common.BuildContext,
    rng: *common.QuestRng,
    out_entries: []spawn_runtime.QuestSpawnEntry,
    len: *usize,
) common.QuestSpawnBuildError!void {
    _ = rng;
    const center = common.centerPoint(ctx.width, ctx.height);
    const edges = common.edgeMidpoints(ctx.width, ctx.height, default_edge_offset);

    try common.appendSpawn(
        out_entries,
        len,
        .{ .x = center.x, .y = edges.bottom.y },
        0.0,
        common.SpawnId.alien_random_1d,
        1500,
        ctx.player_count * 2 + 6,
    );
    try common.appendSpawn(out_entries, len, .{ .x = 256.0, .y = 256.0 }, 0.0, common.SpawnId.alien_spawner_child_1d_limited_09, 8000, 1);
    try common.appendSpawn(out_entries, len, .{ .x = 512.0, .y = 512.0 }, 0.0, common.SpawnId.alien_spawner_child_1d_limited_09, 13000, 1);
    try common.appendSpawn(out_entries, len, .{ .x = 768.0, .y = 768.0 }, 0.0, common.SpawnId.alien_spawner_child_1d_limited_09, 18000, 1);
    try common.appendSpawn(
        out_entries,
        len,
        .{ .x = center.x, .y = edges.bottom.y },
        0.0,
        common.SpawnId.alien_random_1d,
        25000,
        ctx.player_count * 2 + 6,
    );
    try common.appendSpawn(
        out_entries,
        len,
        .{ .x = center.x, .y = edges.bottom.y },
        0.0,
        common.SpawnId.alien_random_1d,
        39000,
        ctx.player_count * 3 + 3,
    );
    try common.appendSpawn(out_entries, len, .{ .x = 384.0, .y = 512.0 }, 0.0, common.SpawnId.alien_spawner_child_1d_limited_09, 41100, 1);
    try common.appendSpawn(out_entries, len, .{ .x = 640.0, .y = 512.0 }, 0.0, common.SpawnId.alien_spawner_child_1d_limited_09, 42100, 1);
    try common.appendSpawn(out_entries, len, .{ .x = 512.0, .y = 640.0 }, 0.0, common.SpawnId.alien_spawner_child_1d_limited_09, 43100, 1);
    try common.appendSpawn(out_entries, len, .{ .x = 512.0, .y = 512.0 }, 0.0, common.SpawnId.alien_spawner_child_1d_slow_08, 44100, 1);
    try common.appendSpawn(
        out_entries,
        len,
        .{ .x = center.x, .y = edges.bottom.y },
        0.0,
        common.SpawnId.alien_random_1e,
        50000,
        ctx.player_count * 2 + 5,
    );
    try common.appendSpawn(
        out_entries,
        len,
        .{ .x = center.x, .y = edges.bottom.y },
        0.0,
        common.SpawnId.alien_random_1f,
        55000,
        ctx.player_count * 2 + 2,
    );
}

fn build_1_10_8_legged_terror(
    ctx: common.BuildContext,
    rng: *common.QuestRng,
    out_entries: []spawn_runtime.QuestSpawnEntry,
    len: *usize,
) common.QuestSpawnBuildError!void {
    _ = rng;
    try common.appendSpawn(
        out_entries,
        len,
        .{ .x = ctx.width - 256.0, .y = @floor(ctx.height / 2.0) },
        0.0,
        common.SpawnId.spider_sp1_const_shock_boss_3a,
        1000,
        1,
    );

    const corners = common.cornerPoints(ctx.width, ctx.height, 25.0);

    var trigger: i32 = 6000;
    while (trigger < 36800) {
        try common.appendSpawn(
            out_entries,
            len,
            corners.top_left,
            0.0,
            common.SpawnId.spider_sp1_random_3d,
            trigger,
            ctx.player_count,
        );
        try common.appendSpawn(
            out_entries,
            len,
            corners.top_right,
            0.0,
            common.SpawnId.spider_sp1_random_3d,
            trigger,
            1,
        );
        try common.appendSpawn(
            out_entries,
            len,
            corners.bottom_left,
            0.0,
            common.SpawnId.spider_sp1_random_3d,
            trigger,
            ctx.player_count,
        );
        try common.appendSpawn(
            out_entries,
            len,
            corners.bottom_right,
            0.0,
            common.SpawnId.spider_sp1_random_3d,
            trigger,
            1,
        );
        trigger += 2200;
    }
}
