const common = @import("logic_common.zig");
const game_ids = @import("../game_ids.zig");
const spawn_runtime = @import("../runtime/spawn.zig");

pub const tier3_builders = [_]common.LevelBuilder{
    .{ .level_key = 301, .start_weapon_id = game_ids.WeaponId.pistol, .build = build301TheBlighting },
    .{ .level_key = 302, .start_weapon_id = game_ids.WeaponId.pistol, .build = build302LizardKings },
    .{ .level_key = 303, .start_weapon_id = game_ids.WeaponId.pistol, .build = build303TheKilling },
    .{ .level_key = 304, .start_weapon_id = game_ids.WeaponId.pistol, .build = build304HiddenEvil },
    .{ .level_key = 305, .start_weapon_id = game_ids.WeaponId.pistol, .build = build305SurroundedByReptiles },
    .{ .level_key = 306, .start_weapon_id = game_ids.WeaponId.pistol, .build = build306TheLizquidation },
    .{ .level_key = 307, .start_weapon_id = game_ids.WeaponId.plasma_minigun, .build = build307SpidersInc },
    .{ .level_key = 308, .start_weapon_id = game_ids.WeaponId.pistol, .build = build308LizardRaze },
    .{ .level_key = 309, .start_weapon_id = game_ids.WeaponId.gauss_gun, .build = build309DejaVu },
    .{ .level_key = 310, .start_weapon_id = game_ids.WeaponId.pistol, .build = build310ZombieMasters },
};

fn build301TheBlighting(
    ctx: common.BuildContext,
    rng: *common.QuestRng,
    out_entries: []spawn_runtime.QuestSpawnEntry,
    len: *usize,
) common.QuestSpawnBuildError!void {
    _ = rng;
    const edges = common.squareEdgeMidpoints(ctx.width, 64.0);
    const edges_wide = common.squareEdgeMidpoints(ctx.width, 128.0);
    const corners = common.insetCornerPoints(ctx.width, ctx.height, 128.0);

    try common.appendSpawn(
        out_entries,
        len,
        edges_wide.right,
        0.0,
        common.SpawnId.alien_const_red_fast_2b,
        1500,
        2,
    );
    try common.appendSpawn(
        out_entries,
        len,
        edges_wide.left,
        0.0,
        common.SpawnId.alien_const_red_fast_2b,
        1500,
        2,
    );
    try common.appendSpawn(
        out_entries,
        len,
        corners.top_right,
        0.0,
        common.SpawnId.alien_spawner_child_1d_fast_07,
        2000,
        1,
    );
    try common.appendSpawn(
        out_entries,
        len,
        corners.top_left,
        0.0,
        common.SpawnId.alien_spawner_child_1d_fast_07,
        2000,
        1,
    );
    try common.appendSpawn(
        out_entries,
        len,
        corners.bottom_left,
        0.0,
        common.SpawnId.alien_spawner_child_1d_fast_07,
        2000,
        1,
    );
    try common.appendSpawn(
        out_entries,
        len,
        corners.bottom_right,
        0.0,
        common.SpawnId.alien_spawner_child_1d_fast_07,
        2000,
        1,
    );

    var trigger: i32 = 4000;
    var wave: i32 = 0;
    while (wave < 8) : (wave += 1) {
        if (wave == 2 or wave == 4) {
            try common.appendSpawn(
                out_entries,
                len,
                edges_wide.left,
                0.0,
                common.SpawnId.alien_const_red_fast_2b,
                trigger,
                4,
            );
        }
        if (wave == 3 or wave == 5) {
            try common.appendSpawn(
                out_entries,
                len,
                edges_wide.right,
                0.0,
                common.SpawnId.alien_const_red_fast_2b,
                trigger,
                4,
            );
        }

        const spawn_id = if (@mod(wave, 2) == 0) common.SpawnId.ai1_alien_blue_tint_1a else common.SpawnId.ai1_lizard_blue_tint_1c;
        switch (@mod(wave, 5)) {
            0 => {
                try common.appendSpawn(out_entries, len, edges.right, 0.0, spawn_id, trigger, 12);
                trigger += 15000;
            },
            1 => {
                try common.appendSpawn(out_entries, len, edges.left, 0.0, spawn_id, trigger, 12);
                trigger += 15000;
            },
            2 => {
                try common.appendSpawn(out_entries, len, edges.bottom, 0.0, spawn_id, trigger, 12);
                trigger += 15000;
            },
            3 => {
                try common.appendSpawn(out_entries, len, edges.top, 0.0, spawn_id, trigger, 12);
                trigger += 15000;
            },
            else => {},
        }
        trigger += 1000;
    }
}

fn build302LizardKings(
    ctx: common.BuildContext,
    rng: *common.QuestRng,
    out_entries: []spawn_runtime.QuestSpawnEntry,
    len: *usize,
) common.QuestSpawnBuildError!void {
    _ = rng;
    const center = common.centerPoint(ctx.width, ctx.height);

    try common.appendSpawn(
        out_entries,
        len,
        common.squareEdgeMidpoints(ctx.width, 128.0).right,
        0.0,
        common.SpawnId.formation_chain_lizard_4_11,
        1500,
        1,
    );
    try common.appendSpawn(
        out_entries,
        len,
        .{ .x = -128.0, .y = 512.0 },
        0.0,
        common.SpawnId.formation_chain_lizard_4_11,
        1500,
        1,
    );
    try common.appendSpawn(
        out_entries,
        len,
        .{ .x = 1152.0, .y = 896.0 },
        0.0,
        common.SpawnId.formation_chain_lizard_4_11,
        1500,
        1,
    );

    var trigger: i32 = 1500;
    var angle: f32 = 0.0;
    var idx: i32 = 0;
    while (idx < 28) : (idx += 1) {
        const point = common.ringPoint(center, 256.0, angle);
        try common.appendSpawn(
            out_entries,
            len,
            point,
            -angle,
            common.SpawnId.lizard_random_31,
            trigger,
            1,
        );
        trigger += 900;
        angle += 0.34906587;
    }
}

fn build303TheKilling(
    ctx: common.BuildContext,
    rng: *common.QuestRng,
    out_entries: []spawn_runtime.QuestSpawnEntry,
    len: *usize,
) common.QuestSpawnBuildError!void {
    const edges = common.squareEdgeMidpoints(ctx.width, 64.0);
    var trigger: i32 = 2000;
    var wave: i32 = 0;
    while (wave < 10) : (wave += 1) {
        // Intentional throwaway draws to keep RNG phase aligned with native script flow.
        _ = rng.randBelow(0x8000);
        _ = rng.randBelow(0x8000);

        const spawn_id = switch (@mod(wave, 3)) {
            0 => common.SpawnId.ai1_alien_blue_tint_1a,
            1 => common.SpawnId.ai1_spider_sp1_blue_tint_1b,
            else => common.SpawnId.ai1_lizard_blue_tint_1c,
        };

        switch (@mod(wave, 5)) {
            0 => try common.appendSpawn(out_entries, len, edges.right, 0.0, spawn_id, trigger, 12),
            1 => try common.appendSpawn(out_entries, len, edges.left, 0.0, spawn_id, trigger, 12),
            2 => try common.appendSpawn(out_entries, len, edges.bottom, 0.0, spawn_id, trigger, 12),
            3 => try common.appendSpawn(out_entries, len, edges.top, 0.0, spawn_id, trigger, 12),
            else => {
                const offsets = [_]i32{ 0, 1000, 2000 };
                for (offsets) |offset| {
                    // Native rolls pos_y first, then pos_x (0x4385d7/0x4385f5).
                    const y: i32 = @as(i32, @intCast(rng.randBelow(0x300))) + 0x80;
                    const x: i32 = @as(i32, @intCast(rng.randBelow(0x300))) + 0x80;
                    try common.appendSpawn(
                        out_entries,
                        len,
                        .{
                            .x = @as(f32, @floatFromInt(x)),
                            .y = @as(f32, @floatFromInt(y)),
                        },
                        0.0,
                        common.SpawnId.alien_spawner_child_1d_fast_07,
                        trigger + offset,
                        3,
                    );
                }
            },
        }
        trigger += 6000;
    }
}

fn build304HiddenEvil(
    ctx: common.BuildContext,
    rng: *common.QuestRng,
    out_entries: []spawn_runtime.QuestSpawnEntry,
    len: *usize,
) common.QuestSpawnBuildError!void {
    _ = rng;
    const edges = common.edgeMidpoints(ctx.width, ctx.height, 64.0);
    try common.appendSpawn(
        out_entries,
        len,
        edges.bottom,
        0.0,
        common.SpawnId.alien_const_purple_ghost_21,
        500,
        50,
    );
    try common.appendSpawn(
        out_entries,
        len,
        edges.bottom,
        0.0,
        common.SpawnId.alien_const_green_ghost_22,
        15000,
        30,
    );
    try common.appendSpawn(
        out_entries,
        len,
        edges.bottom,
        0.0,
        common.SpawnId.alien_const_green_ghost_small_23,
        25000,
        20,
    );
    try common.appendSpawn(
        out_entries,
        len,
        edges.bottom,
        0.0,
        common.SpawnId.alien_const_green_ghost_small_23,
        30000,
        30,
    );
    try common.appendSpawn(
        out_entries,
        len,
        edges.bottom,
        0.0,
        common.SpawnId.alien_const_green_ghost_22,
        35000,
        30,
    );
}

fn build305SurroundedByReptiles(
    ctx: common.BuildContext,
    rng: *common.QuestRng,
    out_entries: []spawn_runtime.QuestSpawnEntry,
    len: *usize,
) common.QuestSpawnBuildError!void {
    _ = ctx;
    _ = rng;
    const vertical_start_left: spawn_runtime.Vec2 = .{ .x = 256.0, .y = 256.0 };
    const vertical_start_right: spawn_runtime.Vec2 = .{ .x = 768.0, .y = 256.0 };
    const vertical_step: spawn_runtime.Vec2 = .{ .x = 0.0, .y = 102.4 };
    const horizontal_start_top: spawn_runtime.Vec2 = .{ .x = 256.0, .y = 256.0 };
    const horizontal_start_bottom: spawn_runtime.Vec2 = .{ .x = 256.0, .y = 768.0 };
    const horizontal_step: spawn_runtime.Vec2 = .{ .x = 102.4, .y = 0.0 };

    var trigger: i32 = 1000;
    var idx: i32 = 0;
    while (idx < 5) : (idx += 1) {
        const left_pos = common.linePointAt(vertical_start_left, vertical_step, idx);
        const right_pos = common.linePointAt(vertical_start_right, vertical_step, idx);
        try common.appendSpawn(
            out_entries,
            len,
            left_pos,
            0.0,
            common.SpawnId.alien_spawner_child_31_slow_0d,
            trigger,
            1,
        );
        try common.appendSpawn(
            out_entries,
            len,
            right_pos,
            0.0,
            common.SpawnId.alien_spawner_child_31_slow_0d,
            trigger,
            1,
        );
        trigger += 800;
    }

    trigger = 8000;
    idx = 0;
    while (idx < 5) : (idx += 1) {
        const top_pos = common.linePointAt(horizontal_start_top, horizontal_step, idx);
        const bottom_pos = common.linePointAt(horizontal_start_bottom, horizontal_step, idx);
        try common.appendSpawn(
            out_entries,
            len,
            top_pos,
            0.0,
            common.SpawnId.alien_spawner_child_31_slow_0d,
            trigger,
            1,
        );
        try common.appendSpawn(
            out_entries,
            len,
            bottom_pos,
            0.0,
            common.SpawnId.alien_spawner_child_31_slow_0d,
            trigger,
            1,
        );
        trigger += 800;
    }
}

fn build306TheLizquidation(
    ctx: common.BuildContext,
    rng: *common.QuestRng,
    out_entries: []spawn_runtime.QuestSpawnEntry,
    len: *usize,
) common.QuestSpawnBuildError!void {
    _ = rng;
    const edges = common.squareEdgeMidpoints(ctx.width, 64.0);
    var trigger: i32 = 1500;
    var wave: i32 = 0;
    while (wave < 10) : (wave += 1) {
        const count = wave + 6;
        try common.appendSpawn(
            out_entries,
            len,
            edges.right,
            0.0,
            common.SpawnId.lizard_random_2e,
            trigger,
            count,
        );
        try common.appendSpawn(
            out_entries,
            len,
            edges.left,
            0.0,
            common.SpawnId.lizard_random_2e,
            trigger,
            count,
        );
        if (wave == 4) {
            try common.appendSpawn(
                out_entries,
                len,
                .{ .x = ctx.width + 128.0, .y = edges.right.y },
                0.0,
                common.SpawnId.alien_const_red_fast_2b,
                1500,
                2,
            );
        }
        trigger += 8000;
    }
}

fn build307SpidersInc(
    ctx: common.BuildContext,
    rng: *common.QuestRng,
    out_entries: []spawn_runtime.QuestSpawnEntry,
    len: *usize,
) common.QuestSpawnBuildError!void {
    _ = rng;
    const edges = common.squareEdgeMidpoints(ctx.width, 64.0);
    const center = common.centerPoint(ctx.width, ctx.height);

    try common.appendSpawn(
        out_entries,
        len,
        edges.bottom,
        0.0,
        common.SpawnId.spider_sp1_ai7_timer_38,
        500,
        1,
    );
    try common.appendSpawn(
        out_entries,
        len,
        .{ .x = center.x + 64.0, .y = edges.bottom.y },
        0.0,
        common.SpawnId.spider_sp1_ai7_timer_38,
        500,
        1,
    );
    try common.appendSpawn(
        out_entries,
        len,
        edges.top,
        0.0,
        common.SpawnId.spider_sp1_const_blue_40,
        500,
        4,
    );

    var trigger: i32 = 17000;
    var step_count: i32 = 0;
    while (trigger < 107000) {
        const count = @divTrunc(step_count, 2) + 3;
        try common.appendSpawn(
            out_entries,
            len,
            edges.bottom,
            0.0,
            common.SpawnId.spider_sp1_ai7_timer_38,
            trigger,
            count,
        );
        try common.appendSpawn(
            out_entries,
            len,
            edges.top,
            0.0,
            common.SpawnId.spider_sp1_ai7_timer_38,
            trigger,
            count,
        );
        trigger += 6000;
        step_count += 1;
    }
}

fn build308LizardRaze(
    ctx: common.BuildContext,
    rng: *common.QuestRng,
    out_entries: []spawn_runtime.QuestSpawnEntry,
    len: *usize,
) common.QuestSpawnBuildError!void {
    _ = rng;
    const edges = common.squareEdgeMidpoints(ctx.width, 64.0);
    var trigger: i32 = 1500;
    while (trigger < 91500) : (trigger += 6000) {
        try common.appendSpawn(
            out_entries,
            len,
            edges.right,
            0.0,
            common.SpawnId.lizard_random_2e,
            trigger,
            6,
        );
        try common.appendSpawn(
            out_entries,
            len,
            edges.left,
            0.0,
            common.SpawnId.lizard_random_2e,
            trigger,
            6,
        );
    }

    try common.appendSpawn(
        out_entries,
        len,
        .{ .x = 128.0, .y = 256.0 },
        0.0,
        common.SpawnId.alien_spawner_child_31_fast_0c,
        10000,
        1,
    );
    try common.appendSpawn(
        out_entries,
        len,
        .{ .x = 128.0, .y = 384.0 },
        0.0,
        common.SpawnId.alien_spawner_child_31_fast_0c,
        10000,
        1,
    );
    try common.appendSpawn(
        out_entries,
        len,
        .{ .x = 128.0, .y = 512.0 },
        0.0,
        common.SpawnId.alien_spawner_child_31_fast_0c,
        10000,
        1,
    );
}

fn build309DejaVu(
    ctx: common.BuildContext,
    rng: *common.QuestRng,
    out_entries: []spawn_runtime.QuestSpawnEntry,
    len: *usize,
) common.QuestSpawnBuildError!void {
    const center = common.centerPoint(ctx.width, ctx.height);
    var trigger: i32 = 2000;
    var step: i32 = 2000;
    while (step > 560) : (step -= 0x50) {
        const angle = common.randomAngle(rng);
        try common.appendRadialSpawns(
            out_entries,
            len,
            center,
            angle,
            84.0,
            252.0,
            42.0,
            .zero,
            common.SpawnId.alien_spawner_child_31_slow_0d,
            trigger,
            1,
        );
        trigger += step;
    }
}

fn build310ZombieMasters(
    ctx: common.BuildContext,
    rng: *common.QuestRng,
    out_entries: []spawn_runtime.QuestSpawnEntry,
    len: *usize,
) common.QuestSpawnBuildError!void {
    _ = rng;
    try common.appendSpawn(
        out_entries,
        len,
        .{ .x = 256.0, .y = 256.0 },
        0.0,
        common.SpawnId.zombie_boss_spawner_00,
        1000,
        ctx.player_count,
    );
    try common.appendSpawn(
        out_entries,
        len,
        .{ .x = 512.0, .y = 256.0 },
        0.0,
        common.SpawnId.zombie_boss_spawner_00,
        6000,
        1,
    );
    try common.appendSpawn(
        out_entries,
        len,
        .{ .x = 768.0, .y = 256.0 },
        0.0,
        common.SpawnId.zombie_boss_spawner_00,
        14000,
        ctx.player_count,
    );
    try common.appendSpawn(
        out_entries,
        len,
        .{ .x = 768.0, .y = 768.0 },
        0.0,
        common.SpawnId.zombie_boss_spawner_00,
        18000,
        1,
    );
}
