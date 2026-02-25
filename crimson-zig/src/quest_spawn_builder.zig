const std = @import("std");

const quest_spawn_tables = @import("quest_spawn_tables.zig");
const survival_math = @import("survival_math.zig");
const survival_spawn = @import("survival_spawn.zig");

pub const QuestSpawnBuildError = error{
    UnsupportedQuestSpawnTable,
    OutOfSpace,
};

pub const QuestSpawnBuildResult = struct {
    entries: []const survival_spawn.QuestSpawnEntry,
    start_weapon_id: i32,
};

const dynamic_level_target_practice: i32 = 103;
const dynamic_level_random_factor: i32 = 106;
const dynamic_level_sweep_stakes: i32 = 205;
const dynamic_level_the_killing: i32 = 303;
const dynamic_level_deja_vu: i32 = 309;

const spawn_id_alien_spawner_child_1d_fast_07: i32 = 0x07;
const spawn_id_ai1_alien_blue_tint_1a: i32 = 0x1A;
const spawn_id_ai1_spider_sp1_blue_tint_1b: i32 = 0x1B;
const spawn_id_ai1_lizard_blue_tint_1c: i32 = 0x1C;
const spawn_id_alien_random_1d: i32 = 0x1D;
const spawn_id_alien_const_grey_brute_29: i32 = 0x29;
const spawn_id_alien_ai7_orbiter_36: i32 = 0x36;
const spawn_id_alien_spawner_child_31_slow_0d: i32 = 0x0D;

pub fn buildQuestSpawnTable(
    level_key: i32,
    player_count: i32,
    seed: u32,
    world_size: f64,
    out_entries: []survival_spawn.QuestSpawnEntry,
) QuestSpawnBuildError!QuestSpawnBuildResult {
    if (player_count < 1 or player_count > 4) return error.UnsupportedQuestSpawnTable;

    var len: usize = 0;
    if (isDynamicSeedLevel(level_key)) {
        var rng = PythonRandom.init(seed);
        switch (level_key) {
            dynamic_level_target_practice => try build13TargetPractice(&rng, world_size, out_entries, &len),
            dynamic_level_random_factor => try build16RandomFactor(&rng, world_size, player_count, out_entries, &len),
            dynamic_level_sweep_stakes => try build25SweepStakes(&rng, world_size, out_entries, &len),
            dynamic_level_the_killing => try build33TheKilling(&rng, world_size, out_entries, &len),
            dynamic_level_deja_vu => try build39DejaVu(&rng, world_size, out_entries, &len),
            else => return error.UnsupportedQuestSpawnTable,
        }
        return .{
            .entries = out_entries[0..len],
            .start_weapon_id = startWeaponForLevel(level_key),
        };
    }

    const preset = quest_spawn_tables.lookupPreset(level_key, player_count) orelse {
        return error.UnsupportedQuestSpawnTable;
    };
    if (preset.entries.len > out_entries.len) return error.OutOfSpace;
    @memcpy(out_entries[0..preset.entries.len], preset.entries);
    return .{
        .entries = out_entries[0..preset.entries.len],
        .start_weapon_id = preset.start_weapon_id,
    };
}

fn isDynamicSeedLevel(level_key: i32) bool {
    return switch (level_key) {
        dynamic_level_target_practice,
        dynamic_level_random_factor,
        dynamic_level_sweep_stakes,
        dynamic_level_the_killing,
        dynamic_level_deja_vu,
        => true,
        else => false,
    };
}

fn startWeaponForLevel(level_key: i32) i32 {
    return switch (level_key) {
        dynamic_level_sweep_stakes,
        dynamic_level_deja_vu,
        => 6,
        else => 1,
    };
}

fn build13TargetPractice(
    rng: *PythonRandom,
    world_size: f64,
    out_entries: []survival_spawn.QuestSpawnEntry,
    len: *usize,
) QuestSpawnBuildError!void {
    const center = centerPoint(world_size, world_size);
    var trigger: i32 = 2000;
    var step: i32 = 2000;
    while (true) {
        const angle = randomAngle(rng);
        const radius = @as(f64, @floatFromInt(rng.randBelow(8) + 2)) * 32.0;
        const point = addVec(center, mulVec(fromAngle(angle), radius));
        const heading = headingFromCenter(point, center);
        try appendEntry(out_entries, len, .{
            .pos = point,
            .heading = heading,
            .spawn_id = spawn_id_alien_ai7_orbiter_36,
            .trigger_ms = trigger,
            .count = 1,
        });
        trigger += @max(step, 1100);
        step -= 50;
        if (step <= 500) break;
    }
}

fn build16RandomFactor(
    rng: *PythonRandom,
    world_size: f64,
    player_count: i32,
    out_entries: []survival_spawn.QuestSpawnEntry,
    len: *usize,
) QuestSpawnBuildError!void {
    const center = centerPoint(world_size, world_size);
    const edges = edgeMidpoints(world_size, world_size);
    var trigger: i32 = 1500;
    while (trigger < 101_500) {
        try appendEntry(out_entries, len, .{
            .pos = edges.right,
            .heading = 0.0,
            .spawn_id = spawn_id_alien_random_1d,
            .trigger_ms = trigger,
            .count = player_count * 2 + 4,
        });
        try appendEntry(out_entries, len, .{
            .pos = edges.left,
            .heading = 0.0,
            .spawn_id = spawn_id_alien_random_1d,
            .trigger_ms = trigger + 200,
            .count = 6,
        });
        if (rng.randBelow(5) == 3) {
            try appendEntry(out_entries, len, .{
                .pos = .{ .x = center.x, .y = edges.bottom.y },
                .heading = 0.0,
                .spawn_id = spawn_id_alien_const_grey_brute_29,
                .trigger_ms = trigger,
                .count = player_count,
            });
        }
        trigger += 10_000;
    }
}

fn build25SweepStakes(
    rng: *PythonRandom,
    world_size: f64,
    out_entries: []survival_spawn.QuestSpawnEntry,
    len: *usize,
) QuestSpawnBuildError!void {
    const center = centerPoint(world_size, world_size);
    var trigger: i32 = 2000;
    var step: i32 = 2000;
    while (step > 720) {
        const angle = randomAngle(rng);
        var radius: f64 = 84.0;
        while (radius < 252.0) : (radius += 42.0) {
            const pos = addVec(center, mulVec(fromAngle(angle), radius));
            try appendEntry(out_entries, len, .{
                .pos = pos,
                .heading = headingFromCenter(pos, center),
                .spawn_id = spawn_id_alien_ai7_orbiter_36,
                .trigger_ms = trigger,
                .count = 1,
            });
        }
        trigger += @max(step, 600);
        step -= 80;
    }
}

fn build33TheKilling(
    rng: *PythonRandom,
    world_size: f64,
    out_entries: []survival_spawn.QuestSpawnEntry,
    len: *usize,
) QuestSpawnBuildError!void {
    const edges = edgeMidpoints(world_size, world_size);
    var trigger: i32 = 2000;
    for (0..10) |wave| {
        _ = rng.randBelow(0x8000);
        _ = rng.randBelow(0x8000);
        const spawn_id = switch (@as(i32, @intCast(wave % 3))) {
            0 => spawn_id_ai1_alien_blue_tint_1a,
            1 => spawn_id_ai1_spider_sp1_blue_tint_1b,
            else => spawn_id_ai1_lizard_blue_tint_1c,
        };
        switch (@as(i32, @intCast(wave % 5))) {
            0 => try appendEntry(out_entries, len, .{
                .pos = edges.right,
                .heading = 0.0,
                .spawn_id = spawn_id,
                .trigger_ms = trigger,
                .count = 12,
            }),
            1 => try appendEntry(out_entries, len, .{
                .pos = edges.left,
                .heading = 0.0,
                .spawn_id = spawn_id,
                .trigger_ms = trigger,
                .count = 12,
            }),
            2 => try appendEntry(out_entries, len, .{
                .pos = edges.bottom,
                .heading = 0.0,
                .spawn_id = spawn_id,
                .trigger_ms = trigger,
                .count = 12,
            }),
            3 => try appendEntry(out_entries, len, .{
                .pos = edges.top,
                .heading = 0.0,
                .spawn_id = spawn_id,
                .trigger_ms = trigger,
                .count = 12,
            }),
            else => {
                const offsets = [_]i32{ 0, 1000, 2000 };
                for (offsets) |offset| {
                    const x: i32 = @intCast(rng.randBelow(0x300) + 0x80);
                    const y: i32 = @intCast(rng.randBelow(0x300) + 0x80);
                    try appendEntry(out_entries, len, .{
                        .pos = .{
                            .x = @floatFromInt(x),
                            .y = @floatFromInt(y),
                        },
                        .heading = 0.0,
                        .spawn_id = spawn_id_alien_spawner_child_1d_fast_07,
                        .trigger_ms = trigger + offset,
                        .count = 3,
                    });
                }
            },
        }
        trigger += 6000;
    }
}

fn build39DejaVu(
    rng: *PythonRandom,
    world_size: f64,
    out_entries: []survival_spawn.QuestSpawnEntry,
    len: *usize,
) QuestSpawnBuildError!void {
    const center = centerPoint(world_size, world_size);
    var trigger: i32 = 2000;
    var step: i32 = 2000;
    while (step > 560) {
        const angle = randomAngle(rng);
        var radius: f64 = 84.0;
        while (radius < 252.0) : (radius += 42.0) {
            try appendEntry(out_entries, len, .{
                .pos = addVec(center, mulVec(fromAngle(angle), radius)),
                .heading = 0.0,
                .spawn_id = spawn_id_alien_spawner_child_31_slow_0d,
                .trigger_ms = trigger,
                .count = 1,
            });
        }
        trigger += step;
        step -= 80;
    }
}

fn appendEntry(
    out_entries: []survival_spawn.QuestSpawnEntry,
    len: *usize,
    entry: survival_spawn.QuestSpawnEntry,
) QuestSpawnBuildError!void {
    if (len.* >= out_entries.len) return error.OutOfSpace;
    out_entries[len.*] = entry;
    len.* += 1;
}

const EdgePoints = struct {
    left: survival_spawn.Vec2,
    right: survival_spawn.Vec2,
    top: survival_spawn.Vec2,
    bottom: survival_spawn.Vec2,
};

fn centerPoint(width: f64, height: f64) survival_spawn.Vec2 {
    return .{
        .x = width * 0.5,
        .y = height * 0.5,
    };
}

fn edgeMidpoints(width: f64, height: f64) EdgePoints {
    const center = centerPoint(width, height);
    return .{
        .left = .{ .x = -64.0, .y = center.y },
        .right = .{ .x = width + 64.0, .y = center.y },
        .top = .{ .x = center.x, .y = -64.0 },
        .bottom = .{ .x = center.x, .y = height + 64.0 },
    };
}

fn randomAngle(rng: *PythonRandom) f64 {
    return @as(f64, @floatFromInt(rng.randBelow(0x264))) * 0.01;
}

fn headingFromCenter(point: survival_spawn.Vec2, center: survival_spawn.Vec2) f64 {
    return survival_math.atan2(point.y - center.y, point.x - center.x) - (std.math.pi / 2.0);
}

fn fromAngle(angle: f64) survival_spawn.Vec2 {
    return .{
        .x = survival_math.cos(angle),
        .y = survival_math.sin(angle),
    };
}

fn addVec(a: survival_spawn.Vec2, b: survival_spawn.Vec2) survival_spawn.Vec2 {
    return .{
        .x = a.x + b.x,
        .y = a.y + b.y,
    };
}

fn mulVec(vec: survival_spawn.Vec2, scalar: f64) survival_spawn.Vec2 {
    return .{
        .x = vec.x * scalar,
        .y = vec.y * scalar,
    };
}

const PythonRandom = struct {
    const n: usize = 624;
    const m: usize = 397;
    const matrix_a: u32 = 0x9908B0DF;
    const upper_mask: u32 = 0x80000000;
    const lower_mask: u32 = 0x7fffffff;

    state: [n]u32 = [_]u32{0} ** n,
    index: usize = n,

    fn init(seed_value: u32) PythonRandom {
        var rng = PythonRandom{};
        rng.seed(seed_value);
        return rng;
    }

    fn seed(self: *PythonRandom, seed_value: u32) void {
        self.initGenrand(19_650_218);

        var i: usize = 1;
        var j: u32 = 0;
        var k: usize = @max(n, @as(usize, 1));
        while (k > 0) : (k -= 1) {
            const prev = self.state[i - 1];
            self.state[i] = (self.state[i] ^ ((prev ^ (prev >> 30)) *% 1_664_525)) +% seed_value +% j;
            i += 1;
            j +%= 1;
            if (i >= n) {
                self.state[0] = self.state[n - 1];
                i = 1;
            }
            if (j >= 1) {
                j = 0;
            }
        }

        var rounds: usize = n - 1;
        while (rounds > 0) : (rounds -= 1) {
            const prev = self.state[i - 1];
            self.state[i] = (self.state[i] ^ ((prev ^ (prev >> 30)) *% 1_566_083_941)) -% @as(u32, @intCast(i));
            i += 1;
            if (i >= n) {
                self.state[0] = self.state[n - 1];
                i = 1;
            }
        }
        self.state[0] = upper_mask;
        self.index = n;
    }

    fn initGenrand(self: *PythonRandom, seed_value: u32) void {
        self.state[0] = seed_value;
        var i: usize = 1;
        while (i < n) : (i += 1) {
            const prev = self.state[i - 1];
            self.state[i] = 1_812_433_253 *% (prev ^ (prev >> 30)) +% @as(u32, @intCast(i));
        }
        self.index = n;
    }

    fn randBelow(self: *PythonRandom, n_in: u32) u32 {
        std.debug.assert(n_in > 0);
        const bits = bitLength(n_in);
        while (true) {
            const value = self.getRandBits(bits);
            if (value < n_in) return value;
        }
    }

    fn getRandBits(self: *PythonRandom, bits: u32) u32 {
        std.debug.assert(bits > 0 and bits <= 32);
        if (bits == 32) return self.rand32();
        return self.rand32() >> @as(u5, @intCast(32 - bits));
    }

    fn rand32(self: *PythonRandom) u32 {
        if (self.index >= n) {
            self.twist();
        }
        var y = self.state[self.index];
        self.index += 1;
        y ^= y >> 11;
        y ^= (y << 7) & 0x9D2C5680;
        y ^= (y << 15) & 0xEFC60000;
        y ^= y >> 18;
        return y;
    }

    fn twist(self: *PythonRandom) void {
        var kk: usize = 0;
        while (kk < n - m) : (kk += 1) {
            const y = (self.state[kk] & upper_mask) | (self.state[kk + 1] & lower_mask);
            self.state[kk] = self.state[kk + m] ^ (y >> 1) ^ mag01(y & 1);
        }
        while (kk < n - 1) : (kk += 1) {
            const y = (self.state[kk] & upper_mask) | (self.state[kk + 1] & lower_mask);
            self.state[kk] = self.state[kk - (n - m)] ^ (y >> 1) ^ mag01(y & 1);
        }
        const y_last = (self.state[n - 1] & upper_mask) | (self.state[0] & lower_mask);
        self.state[n - 1] = self.state[m - 1] ^ (y_last >> 1) ^ mag01(y_last & 1);
        self.index = 0;
    }
};

fn mag01(value: u32) u32 {
    return if ((value & 1) == 0) 0 else PythonRandom.matrix_a;
}

fn bitLength(value: u32) u32 {
    var bits: u32 = 0;
    var v = value;
    while (v > 0) : (v >>= 1) {
        bits += 1;
    }
    return bits;
}

fn expectFloatApprox(expected: f64, actual: f64) !void {
    try std.testing.expectApproxEqAbs(expected, actual, 1e-6);
}

test "quest spawn build uses static presets for seed-invariant levels" {
    var storage_a = [_]survival_spawn.QuestSpawnEntry{undefined} ** 64;
    var storage_b = [_]survival_spawn.QuestSpawnEntry{undefined} ** 64;
    const a = try buildQuestSpawnTable(101, 1, 101, 1024.0, storage_a[0..]);
    const b = try buildQuestSpawnTable(101, 1, 999, 1024.0, storage_b[0..]);
    try std.testing.expectEqual(@as(i32, 1), a.start_weapon_id);
    try std.testing.expectEqual(@as(usize, 4), a.entries.len);
    try std.testing.expectEqual(a.entries.len, b.entries.len);
    for (a.entries, b.entries) |left, right| {
        try expectFloatApprox(left.pos.x, right.pos.x);
        try expectFloatApprox(left.pos.y, right.pos.y);
        try std.testing.expectEqual(left.spawn_id, right.spawn_id);
        try std.testing.expectEqual(left.trigger_ms, right.trigger_ms);
        try std.testing.expectEqual(left.count, right.count);
    }
}

test "quest spawn build parity for level 1.3 seed 205" {
    var storage = [_]survival_spawn.QuestSpawnEntry{undefined} ** 128;
    const result = try buildQuestSpawnTable(103, 1, 205, 1024.0, storage[0..]);
    try std.testing.expectEqual(@as(i32, 1), result.start_weapon_id);
    try std.testing.expectEqual(@as(usize, 30), result.entries.len);

    const first = result.entries[0];
    try expectFloatApprox(434.518466, first.pos.x);
    try expectFloatApprox(234.618292, first.pos.y);
    try expectFloatApprox(-3.413982, first.heading);
    try std.testing.expectEqual(@as(i32, 54), first.spawn_id);
    try std.testing.expectEqual(@as(i32, 2000), first.trigger_ms);
    try std.testing.expectEqual(@as(i32, 1), first.count);

    const mid = result.entries[15];
    try expectFloatApprox(621.706349, mid.pos.x);
    try expectFloatApprox(778.286532, mid.pos.y);
    try expectFloatApprox(-0.390796, mid.heading);
    try std.testing.expectEqual(@as(i32, 26750), mid.trigger_ms);

    const last = result.entries[result.entries.len - 1];
    try expectFloatApprox(730.408220, last.pos.x);
    try expectFloatApprox(699.728126, last.pos.y);
    try expectFloatApprox(-0.860796, last.heading);
    try std.testing.expectEqual(@as(i32, 42450), last.trigger_ms);
}

test "quest spawn build parity for level 1.6 seed 205 player scaling" {
    var storage = [_]survival_spawn.QuestSpawnEntry{undefined} ** 128;
    const result = try buildQuestSpawnTable(106, 4, 205, 1024.0, storage[0..]);
    try std.testing.expectEqual(@as(i32, 1), result.start_weapon_id);
    try std.testing.expectEqual(@as(usize, 24), result.entries.len);

    var brute_count: usize = 0;
    for (result.entries) |entry| {
        if (entry.spawn_id == 0x29) {
            brute_count += 1;
            try std.testing.expectEqual(@as(i32, 4), entry.count);
        }
    }
    try std.testing.expectEqual(@as(usize, 4), brute_count);
}

test "quest spawn build parity for level 2.5 seed 999" {
    var storage = [_]survival_spawn.QuestSpawnEntry{undefined} ** 128;
    const result = try buildQuestSpawnTable(205, 1, 999, 1024.0, storage[0..]);
    try std.testing.expectEqual(@as(i32, 6), result.start_weapon_id);
    try std.testing.expectEqual(@as(usize, 64), result.entries.len);

    const first = result.entries[0];
    try expectFloatApprox(569.917868, first.pos.x);
    try expectFloatApprox(572.840123, first.pos.y);
    try expectFloatApprox(-0.760796, first.heading);
    try std.testing.expectEqual(@as(i32, 2000), first.trigger_ms);

    const mid = result.entries[32];
    try expectFloatApprox(558.089948, mid.pos.x);
    try expectFloatApprox(582.226182, mid.pos.y);
    try expectFloatApprox(-0.580796, mid.heading);
    try std.testing.expectEqual(@as(i32, 15760), mid.trigger_ms);
}

test "quest spawn build parity for level 3.3 seed 205" {
    var storage = [_]survival_spawn.QuestSpawnEntry{undefined} ** 128;
    const result = try buildQuestSpawnTable(303, 1, 205, 1024.0, storage[0..]);
    try std.testing.expectEqual(@as(i32, 1), result.start_weapon_id);
    try std.testing.expectEqual(@as(usize, 14), result.entries.len);
    const last = result.entries[result.entries.len - 1];
    try std.testing.expectEqual(@as(i32, 7), last.spawn_id);
    try expectFloatApprox(673.0, last.pos.x);
    try expectFloatApprox(843.0, last.pos.y);
    try std.testing.expectEqual(@as(i32, 58_000), last.trigger_ms);
    try std.testing.expectEqual(@as(i32, 3), last.count);
}

test "quest spawn build parity for level 3.9 seed 999" {
    var storage = [_]survival_spawn.QuestSpawnEntry{undefined} ** 128;
    const result = try buildQuestSpawnTable(309, 4, 999, 1024.0, storage[0..]);
    try std.testing.expectEqual(@as(i32, 6), result.start_weapon_id);
    try std.testing.expectEqual(@as(usize, 72), result.entries.len);
    const last = result.entries[result.entries.len - 1];
    try std.testing.expectEqual(@as(i32, 13), last.spawn_id);
    try expectFloatApprox(393.011360, last.pos.x);
    try expectFloatApprox(338.963288, last.pos.y);
    try std.testing.expectEqual(@as(i32, 25_120), last.trigger_ms);
    try std.testing.expectEqual(@as(i32, 1), last.count);
}

test "quest spawn build supports all preset and dynamic levels across player counts" {
    var storage = [_]survival_spawn.QuestSpawnEntry{undefined} ** 4096;

    for (quest_spawn_tables.presets) |preset| {
        if (isDynamicSeedLevel(preset.level_key)) continue;
        const result = try buildQuestSpawnTable(
            preset.level_key,
            preset.player_count,
            0x1234,
            1024.0,
            storage[0..],
        );
        try std.testing.expectEqual(preset.start_weapon_id, result.start_weapon_id);
        try std.testing.expectEqual(preset.entries.len, result.entries.len);
    }

    const dynamic_levels = [_]i32{
        dynamic_level_target_practice,
        dynamic_level_random_factor,
        dynamic_level_sweep_stakes,
        dynamic_level_the_killing,
        dynamic_level_deja_vu,
    };
    const seeds = [_]u32{ 205, 999 };
    for (dynamic_levels) |level_key| {
        var player_count: i32 = 1;
        while (player_count <= 4) : (player_count += 1) {
            for (seeds) |seed| {
                const result = try buildQuestSpawnTable(
                    level_key,
                    player_count,
                    seed,
                    1024.0,
                    storage[0..],
                );
                try std.testing.expect(result.entries.len > 0);
                try std.testing.expectEqual(startWeaponForLevel(level_key), result.start_weapon_id);
            }
        }
    }
}
