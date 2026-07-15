const std = @import("std");

const common = @import("logic_common.zig");
const game_ids = @import("../game_ids.zig");
const spawn_runtime = @import("../runtime/spawn.zig");

pub const tier5_builders = [_]common.LevelBuilder{
    .{ .level_key = 501, .start_weapon_id = game_ids.WeaponId.pistol, .build = build501TheBeating },
    .{ .level_key = 502, .start_weapon_id = game_ids.WeaponId.pistol, .build = build502TheSpankingOfTheDead },
    .{ .level_key = 503, .start_weapon_id = game_ids.WeaponId.pistol, .build = build503TheFortress },
    .{ .level_key = 504, .start_weapon_id = game_ids.WeaponId.pistol, .build = build504TheGangWars },
    .{ .level_key = 505, .start_weapon_id = game_ids.WeaponId.pistol, .build = build505KneeDeepInTheDead },
    .{ .level_key = 506, .start_weapon_id = game_ids.WeaponId.pistol, .build = build506CrossFire },
    .{ .level_key = 507, .start_weapon_id = game_ids.WeaponId.pistol, .build = build507ArmyOfThree },
    .{ .level_key = 508, .start_weapon_id = game_ids.WeaponId.pistol, .build = build508MonsterBlues },
    .{ .level_key = 509, .start_weapon_id = game_ids.WeaponId.pistol, .build = build509Nagolipoli },
    .{ .level_key = 510, .start_weapon_id = game_ids.WeaponId.pistol, .build = build510TheGathering },
};

fn halfFloor(value: f32) f32 {
    return @floor(value * 0.5);
}

fn build501TheBeating(
    ctx: common.BuildContext,
    rng: *common.QuestRng,
    out_entries: []spawn_runtime.QuestSpawnEntry,
    len: *usize,
) common.QuestSpawnBuildError!void {
    _ = rng;

    const half_height = halfFloor(ctx.height);
    const half_width = halfFloor(ctx.width);

    try common.appendSpawn(
        out_entries,
        len,
        .{ .x = 256.0, .y = 256.0 },
        0.0,
        common.SpawnId.alien_const_weapon_bonus_27,
        500,
        1,
    );
    try common.appendSpawn(
        out_entries,
        len,
        .{ .x = ctx.width + 32.0, .y = half_height },
        0.0,
        common.SpawnId.alien_const_grey_brute_29,
        8000,
        3,
    );

    var trigger: i32 = 10_000;
    var x_offset: i32 = 0x40;
    var wave_idx: usize = 0;
    while (wave_idx < 8) : (wave_idx += 1) {
        try common.appendSpawn(
            out_entries,
            len,
            .{
                .x = ctx.width + @as(f32, @floatFromInt(x_offset)),
                .y = half_height,
            },
            0.0,
            common.SpawnId.alien_const_green_small_25,
            trigger,
            8,
        );
        trigger += 100;
        x_offset += 0x20;
    }

    try common.appendSpawn(
        out_entries,
        len,
        .{ .x = -32.0, .y = half_height },
        0.0,
        common.SpawnId.alien_const_grey_brute_29,
        18_000,
        3,
    );

    trigger = 20_000;
    var x: i32 = -64;
    wave_idx = 0;
    while (wave_idx < 8) : (wave_idx += 1) {
        try common.appendSpawn(
            out_entries,
            len,
            .{ .x = @as(f32, @floatFromInt(x)), .y = half_height },
            0.0,
            common.SpawnId.alien_const_green_small_25,
            trigger,
            8,
        );
        trigger += 100;
        x -= 32;
    }

    trigger = 40_000;
    var y: i32 = -64;
    wave_idx = 0;
    while (wave_idx < 6) : (wave_idx += 1) {
        try common.appendSpawn(
            out_entries,
            len,
            .{ .x = half_width, .y = @as(f32, @floatFromInt(y)) },
            0.0,
            common.SpawnId.alien_const_brown_transparent_0f,
            trigger,
            4,
        );
        trigger += 100;
        y -= 42;
    }

    trigger = 40_000;
    var y2: f32 = ctx.width + 44.0;
    wave_idx = 0;
    while (wave_idx < 6) : (wave_idx += 1) {
        try common.appendSpawn(
            out_entries,
            len,
            .{ .x = half_width, .y = y2 },
            0.0,
            common.SpawnId.formation_ring_alien_8_12,
            trigger,
            2,
        );
        trigger += 100;
        y2 += 32.0;
    }
}

fn build502TheSpankingOfTheDead(
    ctx: common.BuildContext,
    rng: *common.QuestRng,
    out_entries: []spawn_runtime.QuestSpawnEntry,
    len: *usize,
) common.QuestSpawnBuildError!void {
    _ = rng;
    _ = ctx;

    try common.appendSpawn(
        out_entries,
        len,
        .{ .x = 256.0, .y = 512.0 },
        0.0,
        common.SpawnId.alien_const_weapon_bonus_27,
        500,
        1,
    );
    try common.appendSpawn(
        out_entries,
        len,
        .{ .x = 768.0, .y = 512.0 },
        0.0,
        common.SpawnId.alien_const_weapon_bonus_27,
        500,
        1,
    );

    var trigger: i32 = 5000;
    var step_index: i32 = 0;
    while (trigger < 0xA988) {
        const angle = @as(f32, @floatFromInt(step_index)) * 0.33333334;
        const radius = 512.0 - (@as(f32, @floatFromInt(step_index)) * 3.8);
        const pos = common.addVec(
            .{ .x = 512.0, .y = 512.0 },
            common.mulVec(common.vecFromAngle(angle), radius),
        );
        try common.appendSpawn(
            out_entries,
            len,
            pos,
            angle,
            common.SpawnId.zombie_random_41,
            trigger,
            1,
        );
        trigger += 300;
        step_index += 1;
    }

    const offset = step_index * 300;
    try common.appendSpawn(
        out_entries,
        len,
        .{ .x = 1280.0, .y = 512.0 },
        0.0,
        common.SpawnId.zombie_const_grey_42,
        offset + 10_000,
        16,
    );
    try common.appendSpawn(
        out_entries,
        len,
        .{ .x = -256.0, .y = 512.0 },
        0.0,
        common.SpawnId.zombie_const_grey_42,
        offset + 20_000,
        16,
    );
}

fn build503TheFortress(
    ctx: common.BuildContext,
    rng: *common.QuestRng,
    out_entries: []spawn_runtime.QuestSpawnEntry,
    len: *usize,
) common.QuestSpawnBuildError!void {
    _ = rng;

    const half_height = ctx.height * 0.5;

    try common.appendSpawnExact(
        out_entries,
        len,
        .{ .x = -50.0, .y = half_height },
        0.0,
        common.SpawnId.spider_sp1_const_blue_40,
        100,
        6,
    );

    var trigger: i32 = 1100;
    var y_seed: i32 = 0x200;
    while (trigger < 0x14B4) {
        const y: f32 = @floatCast((@as(f64, @floatFromInt(y_seed)) * 0.125) + 256.0);
        try common.appendSpawnExact(
            out_entries,
            len,
            .{ .x = 768.0, .y = y },
            0.0,
            common.SpawnId.alien_spawner_child_1d_limited_09,
            trigger,
            1,
        );
        trigger += 600;
        y_seed += 0x200;
    }

    var entry_count: i32 = 8;
    var x_seed: i32 = 0x180;
    const one_sixth: f64 = @floatCast(@as(f32, 0.16666667));
    while (x_seed < 0x901) {
        trigger = entry_count * 600 + 0x157C;

        var row: i32 = 1;
        while (row < 7) : (row += 1) {
            if (row != 1 or (x_seed != 0x480 and x_seed != 0x600)) {
                const x: f32 = @floatCast((@as(f64, @floatFromInt(x_seed)) * one_sixth) + 256.0);
                const y: f32 = @floatCast(512.0 - (@as(f64, @floatFromInt(row * 0x180)) * one_sixth));
                try common.appendSpawnExact(
                    out_entries,
                    len,
                    .{ .x = x, .y = y },
                    0.0,
                    common.SpawnId.alien_spawner_child_32_slow_0a,
                    trigger,
                    1,
                );
                trigger += 600;
                entry_count += 1;
            }
        }

        x_seed += 0x180;
    }
}

fn build504TheGangWars(
    ctx: common.BuildContext,
    rng: *common.QuestRng,
    out_entries: []spawn_runtime.QuestSpawnEntry,
    len: *usize,
) common.QuestSpawnBuildError!void {
    _ = rng;

    const half_height = ctx.height * 0.5;

    try common.appendSpawnExact(
        out_entries,
        len,
        .{ .x = -150.0, .y = half_height },
        0.0,
        common.SpawnId.formation_ring_alien_8_12,
        100,
        1,
    );
    try common.appendSpawnExact(
        out_entries,
        len,
        .{ .x = 1174.0, .y = half_height },
        0.0,
        common.SpawnId.formation_ring_alien_8_12,
        2500,
        1,
    );

    var trigger: i32 = 5500;
    var wave: usize = 0;
    while (wave < 10) : (wave += 1) {
        try common.appendSpawnExact(
            out_entries,
            len,
            .{ .x = 1174.0, .y = half_height },
            0.0,
            common.SpawnId.formation_ring_alien_8_12,
            trigger,
            2,
        );
        trigger += 4000;
    }

    try common.appendSpawnExact(
        out_entries,
        len,
        .{ .x = 512.0, .y = 1152.0 },
        0.0,
        common.SpawnId.formation_chain_alien_10_13,
        50_500,
        1,
    );

    trigger = 59_500;
    while (trigger < 0x184AC) {
        try common.appendSpawnExact(
            out_entries,
            len,
            .{ .x = -150.0, .y = half_height },
            0.0,
            common.SpawnId.formation_ring_alien_8_12,
            trigger,
            2,
        );
        trigger += 4000;
    }

    try common.appendSpawnExact(
        out_entries,
        len,
        .{ .x = 512.0, .y = 1152.0 },
        0.0,
        common.SpawnId.formation_chain_alien_10_13,
        107_500,
        3,
    );
}

fn build505KneeDeepInTheDead(
    ctx: common.BuildContext,
    rng: *common.QuestRng,
    out_entries: []spawn_runtime.QuestSpawnEntry,
    len: *usize,
) common.QuestSpawnBuildError!void {
    _ = rng;

    const mid_y = ctx.height * 0.5;

    try common.appendSpawn(
        out_entries,
        len,
        .{ .x = -50.0, .y = mid_y },
        0.0,
        common.SpawnId.zombie_const_green_brute_43,
        100,
        1,
    );

    var trigger: i32 = 500;
    var wave: i32 = 0;
    while (trigger < 0x178F4) {
        if (@mod(wave, 8) == 0) {
            try common.appendSpawn(
                out_entries,
                len,
                .{ .x = -50.0, .y = mid_y },
                0.0,
                common.SpawnId.zombie_const_green_brute_43,
                trigger - 2,
                1,
            );
        }

        const count: i32 = if (wave > 0x20) 2 else 1;
        try common.appendSpawn(
            out_entries,
            len,
            .{ .x = -50.0, .y = mid_y },
            0.0,
            common.SpawnId.zombie_random_41,
            trigger,
            count,
        );

        if (trigger > 0x30D4) {
            try common.appendSpawn(
                out_entries,
                len,
                .{ .x = -50.0, .y = mid_y + 158.0 },
                0.0,
                common.SpawnId.zombie_random_41,
                trigger + 500,
                1,
            );
        }
        if (trigger > 0x5FB4) {
            try common.appendSpawn(
                out_entries,
                len,
                .{ .x = -50.0, .y = mid_y - 158.0 },
                0.0,
                common.SpawnId.zombie_random_41,
                trigger + 1000,
                1,
            );
        }
        if (trigger > 0x8E94) {
            try common.appendSpawn(
                out_entries,
                len,
                .{ .x = -50.0, .y = mid_y - 258.0 },
                0.0,
                common.SpawnId.zombie_const_grey_42,
                trigger + 0x514,
                1,
            );
        }
        if (trigger > 0xBD74) {
            try common.appendSpawn(
                out_entries,
                len,
                .{ .x = -50.0, .y = mid_y + 258.0 },
                0.0,
                common.SpawnId.zombie_const_grey_42,
                trigger + 300,
                1,
            );
        }

        trigger += 0x5DC;
        wave += 1;
    }
}

fn build506CrossFire(
    ctx: common.BuildContext,
    rng: *common.QuestRng,
    out_entries: []spawn_runtime.QuestSpawnEntry,
    len: *usize,
) common.QuestSpawnBuildError!void {
    _ = rng;

    const mid_y = ctx.height * 0.5;

    try common.appendSpawn(
        out_entries,
        len,
        .{ .x = 1074.0, .y = mid_y },
        0.0,
        common.SpawnId.spider_sp1_const_blue_40,
        100,
        6,
    );
    try common.appendSpawn(
        out_entries,
        len,
        .{ .x = -40.0, .y = 512.0 },
        0.0,
        common.SpawnId.spider_sp1_const_ranged_variant_3c,
        5500,
        4,
    );
    try common.appendSpawn(
        out_entries,
        len,
        .{ .x = -40.0, .y = 512.0 },
        0.0,
        common.SpawnId.spider_sp1_const_ranged_variant_3c,
        15_500,
        6,
    );
    try common.appendSpawn(
        out_entries,
        len,
        .{ .x = 512.0, .y = 512.0 },
        0.0,
        common.SpawnId.spider_sp2_splitter_01,
        18_500,
        2,
    );
    try common.appendSpawn(
        out_entries,
        len,
        .{ .x = -100.0, .y = 512.0 },
        0.0,
        common.SpawnId.spider_sp1_const_ranged_variant_3c,
        25_500,
        8,
    );
    try common.appendSpawn(
        out_entries,
        len,
        .{ .x = 512.0, .y = 1152.0 },
        0.0,
        common.SpawnId.spider_sp1_const_blue_40,
        26_000,
        6,
    );
    try common.appendSpawn(
        out_entries,
        len,
        .{ .x = 512.0, .y = -128.0 },
        0.0,
        common.SpawnId.spider_sp1_const_blue_40,
        26_000,
        6,
    );
}

fn build507ArmyOfThree(
    ctx: common.BuildContext,
    rng: *common.QuestRng,
    out_entries: []spawn_runtime.QuestSpawnEntry,
    len: *usize,
) common.QuestSpawnBuildError!void {
    _ = rng;
    const edges = common.squareEdgeMidpoints(ctx.width, 64.0);
    const edges_wide = common.squareEdgeMidpoints(ctx.width, 128.0);

    try common.appendSpawn(
        out_entries,
        len,
        .{ .x = -64.0, .y = 256.0 },
        0.0,
        common.SpawnId.formation_grid_alien_white_15,
        500,
        1,
    );
    try common.appendSpawn(
        out_entries,
        len,
        edges.left,
        0.0,
        common.SpawnId.formation_grid_alien_white_15,
        5500,
        1,
    );
    try common.appendSpawn(
        out_entries,
        len,
        .{ .x = -64.0, .y = 768.0 },
        0.0,
        common.SpawnId.formation_grid_alien_white_15,
        15_000,
        1,
    );
    try common.appendSpawn(
        out_entries,
        len,
        .{ .x = -64.0, .y = 768.0 },
        0.0,
        common.SpawnId.formation_grid_spider_sp1_white_17,
        19_500,
        1,
    );
    try common.appendSpawn(
        out_entries,
        len,
        edges.left,
        0.0,
        common.SpawnId.formation_grid_spider_sp1_white_17,
        22_500,
        1,
    );
    try common.appendSpawn(
        out_entries,
        len,
        .{ .x = -64.0, .y = 256.0 },
        0.0,
        common.SpawnId.formation_grid_spider_sp1_white_17,
        26_500,
        1,
    );
    try common.appendSpawn(
        out_entries,
        len,
        .{ .x = -64.0, .y = 256.0 },
        0.0,
        common.SpawnId.formation_grid_lizard_white_16,
        35_500,
        1,
    );
    try common.appendSpawn(
        out_entries,
        len,
        edges.left,
        0.0,
        common.SpawnId.formation_grid_lizard_white_16,
        39_500,
        1,
    );
    try common.appendSpawn(
        out_entries,
        len,
        .{ .x = -64.0, .y = 768.0 },
        0.0,
        common.SpawnId.formation_grid_lizard_white_16,
        42_500,
        1,
    );
    try common.appendSpawn(
        out_entries,
        len,
        edges_wide.bottom,
        0.0,
        common.SpawnId.formation_grid_alien_white_15,
        52_500,
        3,
    );
    try common.appendSpawn(
        out_entries,
        len,
        .{ .x = 512.0, .y = -256.0 },
        0.0,
        common.SpawnId.formation_grid_spider_sp1_white_17,
        56_500,
        3,
    );
}

fn build508MonsterBlues(
    ctx: common.BuildContext,
    rng: *common.QuestRng,
    out_entries: []spawn_runtime.QuestSpawnEntry,
    len: *usize,
) common.QuestSpawnBuildError!void {
    _ = rng;

    const mid_y = ctx.height * 0.5;
    const edges = common.squareEdgeMidpoints(ctx.width, 64.0);

    try common.appendSpawn(
        out_entries,
        len,
        .{ .x = -50.0, .y = mid_y },
        0.0,
        common.SpawnId.lizard_random_04,
        500,
        10,
    );
    try common.appendSpawn(
        out_entries,
        len,
        .{ .x = 1074.0, .y = mid_y },
        0.0,
        common.SpawnId.alien_random_06,
        7500,
        10,
    );
    try common.appendSpawn(
        out_entries,
        len,
        edges.bottom,
        0.0,
        common.SpawnId.spider_sp1_random_03,
        17_500,
        12,
    );
    try common.appendSpawn(
        out_entries,
        len,
        edges.top,
        0.0,
        common.SpawnId.spider_sp1_random_03,
        17_500,
        12,
    );

    var trigger: i32 = 27_500;
    for (0..0x40) |idx_usize| {
        const idx: i32 = @intCast(idx_usize);
        const spawn_id = switch (@mod(idx, 4)) {
            0 => common.SpawnId.alien_random_06,
            1 => common.SpawnId.spider_sp1_random_03,
            else => common.SpawnId.spider_sp2_random_05,
        };
        const count = @divTrunc(idx, 8) + 2;
        try common.appendSpawn(
            out_entries,
            len,
            edges.left,
            0.0,
            spawn_id,
            trigger,
            count,
        );
        trigger += 900;
    }
}

fn build509Nagolipoli(
    ctx: common.BuildContext,
    rng: *common.QuestRng,
    out_entries: []spawn_runtime.QuestSpawnEntry,
    len: *usize,
) common.QuestSpawnBuildError!void {
    _ = rng;

    const center = common.centerPoint(ctx.width, ctx.height);
    const edges = common.squareEdgeMidpoints(ctx.width, 64.0);
    try common.appendRingSpawns(
        out_entries,
        len,
        center,
        128.0,
        8,
        0.7853982,
        0.0,
        .angle,
        common.SpawnId.spider_sp1_const_blue_40,
        2000,
        0,
        1,
    );
    try common.appendRingSpawns(
        out_entries,
        len,
        center,
        178.0,
        12,
        0.5235988,
        0.0,
        .angle,
        common.SpawnId.spider_sp1_const_blue_40,
        8000,
        0,
        1,
    );

    var trigger: i32 = 13_000;
    var wave: i32 = 0;
    while (trigger < 0x96C8) {
        const count = @divTrunc(wave, 8) + 1;
        try common.appendSpawn(
            out_entries,
            len,
            .{ .x = -64.0, .y = -64.0 },
            1.0471976,
            common.SpawnId.ai1_lizard_blue_tint_1c,
            trigger,
            count,
        );
        try common.appendSpawn(
            out_entries,
            len,
            .{ .x = 1088.0, .y = -64.0 },
            -1.0471976,
            common.SpawnId.ai1_lizard_blue_tint_1c,
            trigger,
            count,
        );
        try common.appendSpawn(
            out_entries,
            len,
            .{ .x = -64.0, .y = 1088.0 },
            -1.0471976,
            common.SpawnId.ai1_lizard_blue_tint_1c,
            trigger,
            count,
        );
        try common.appendSpawn(
            out_entries,
            len,
            .{ .x = 1088.0, .y = 1088.0 },
            3.926991,
            common.SpawnId.ai1_lizard_blue_tint_1c,
            trigger,
            count,
        );

        trigger += 800;
        wave += 1;
    }

    const last_wave = if (wave > 0) wave - 1 else 0;

    var base_left = (last_wave + 0x97 + wave * 4) * 0xA0;
    const left_line_start: spawn_runtime.Vec2 = .{ .x = 64.0, .y = 256.0 };
    const right_line_start: spawn_runtime.Vec2 = .{ .x = 960.0, .y = 256.0 };
    const vertical_step: spawn_runtime.Vec2 = .{ .x = 0.0, .y = 85.333336 };
    var idx: i32 = 0;
    while (idx < 6) : (idx += 1) {
        const pos = common.linePointAt(left_line_start, vertical_step, idx);
        try common.appendSpawn(
            out_entries,
            len,
            pos,
            0.0,
            common.SpawnId.alien_spawner_child_32_slow_0a,
            base_left,
            1,
        );
        base_left += 100;
    }

    var base_right = wave * 800 + 25_000;
    idx = 0;
    while (idx < 6) : (idx += 1) {
        const pos = common.linePointAt(right_line_start, vertical_step, idx);
        try common.appendSpawn(
            out_entries,
            len,
            pos,
            0.0,
            common.SpawnId.alien_spawner_child_32_slow_0a,
            base_right,
            1,
        );
        base_right += 100;
    }

    const base_mid = (last_wave + 0xB0 + wave * 4) * 0xA0;
    try common.appendSpawn(
        out_entries,
        len,
        .{ .x = 512.0, .y = 256.0 },
        std.math.pi,
        common.SpawnId.alien_spawner_child_3c_slow_0b,
        base_mid,
        1,
    );
    try common.appendSpawn(
        out_entries,
        len,
        .{ .x = 512.0, .y = 768.0 },
        std.math.pi,
        common.SpawnId.alien_spawner_child_3c_slow_0b,
        base_mid,
        1,
    );

    const base_vertical = wave * 800 + 0x6F54;
    try common.appendSpawn(
        out_entries,
        len,
        edges.bottom,
        3.926991,
        common.SpawnId.ai1_lizard_blue_tint_1c,
        base_vertical,
        8,
    );
    try common.appendSpawn(
        out_entries,
        len,
        edges.top,
        3.926991,
        common.SpawnId.ai1_lizard_blue_tint_1c,
        base_vertical,
        8,
    );
}

fn build510TheGathering(
    ctx: common.BuildContext,
    rng: *common.QuestRng,
    out_entries: []spawn_runtime.QuestSpawnEntry,
    len: *usize,
) common.QuestSpawnBuildError!void {
    _ = rng;
    const edges_wide = common.squareEdgeMidpoints(ctx.width, 128.0);

    try common.appendSpawn(
        out_entries,
        len,
        .{ .x = 256.0, .y = 512.0 },
        0.0,
        common.SpawnId.spider_sp2_splitter_01,
        500,
        1,
    );
    try common.appendSpawn(
        out_entries,
        len,
        .{ .x = 768.0, .y = 512.0 },
        0.0,
        common.SpawnId.spider_sp2_splitter_01,
        9500,
        2,
    );
    try common.appendSpawn(
        out_entries,
        len,
        .{ .x = 256.0, .y = 512.0 },
        0.0,
        common.SpawnId.spider_sp1_const_shock_boss_3a,
        15_500,
        2,
    );
    try common.appendSpawn(
        out_entries,
        len,
        .{ .x = 768.0, .y = 512.0 },
        0.0,
        common.SpawnId.spider_sp1_const_shock_boss_3a,
        24_500,
        2,
    );
    try common.appendSpawn(
        out_entries,
        len,
        .{ .x = 256.0, .y = 512.0 },
        0.0,
        common.SpawnId.zombie_boss_spawner_00,
        30_500,
        2,
    );
    try common.appendSpawn(
        out_entries,
        len,
        .{ .x = 768.0, .y = 512.0 },
        0.0,
        common.SpawnId.zombie_boss_spawner_00,
        39_500,
        2,
    );
    try common.appendSpawn(
        out_entries,
        len,
        .{ .x = 64.0, .y = 64.0 },
        0.0,
        common.SpawnId.spider_sp1_const_ranged_variant_3c,
        54_500,
        2,
    );
    try common.appendSpawn(
        out_entries,
        len,
        .{ .x = 960.0, .y = 64.0 },
        0.0,
        common.SpawnId.spider_sp1_const_ranged_variant_3c,
        54_500,
        1,
    );
    try common.appendSpawn(
        out_entries,
        len,
        .{ .x = 64.0, .y = 960.0 },
        0.0,
        common.SpawnId.spider_sp1_const_ranged_variant_3c,
        54_500,
        2,
    );
    try common.appendSpawn(
        out_entries,
        len,
        .{ .x = 960.0, .y = 960.0 },
        0.0,
        common.SpawnId.spider_sp1_const_ranged_variant_3c,
        54_500,
        1,
    );
    try common.appendSpawn(
        out_entries,
        len,
        edges_wide.left,
        0.0,
        common.SpawnId.spider_sp1_const_shock_boss_3a,
        90_500,
        6,
    );
    try common.appendSpawn(
        out_entries,
        len,
        edges_wide.right,
        0.0,
        common.SpawnId.spider_sp2_splitter_01,
        99_500,
        4,
    );
    try common.appendSpawn(
        out_entries,
        len,
        edges_wide.right,
        0.0,
        common.SpawnId.spider_sp2_splitter_01,
        109_500,
        2,
    );
}
