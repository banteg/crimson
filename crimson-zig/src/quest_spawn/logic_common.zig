const std = @import("std");
const game_ids = @import("../game_ids.zig");

const math_runtime = @import("../runtime/math.zig");
const spawn_runtime = @import("../runtime/spawn.zig");

pub const QuestSpawnBuildError = error{
    UnsupportedQuestSpawnTable,
    OutOfSpace,
};

pub const QuestSpawnBuildResult = struct {
    entries: []const spawn_runtime.QuestSpawnEntry,
    start_weapon_id: game_ids.WeaponId,
};

pub const BuildContext = struct {
    width: f64,
    height: f64,
    player_count: i32,
};

pub const BuildFn = *const fn (
    ctx: BuildContext,
    rng: *PythonRandom,
    out_entries: []spawn_runtime.QuestSpawnEntry,
    len: *usize,
) QuestSpawnBuildError!void;

pub const LevelBuilder = struct {
    level_key: i32,
    start_weapon_id: game_ids.WeaponId,
    build: BuildFn,
};

pub const EdgePoints = struct {
    left: spawn_runtime.Vec2,
    right: spawn_runtime.Vec2,
    top: spawn_runtime.Vec2,
    bottom: spawn_runtime.Vec2,
};

pub inline fn appendEntry(
    out_entries: []spawn_runtime.QuestSpawnEntry,
    len: *usize,
    entry: spawn_runtime.QuestSpawnEntry,
) QuestSpawnBuildError!void {
    if (len.* >= out_entries.len) return error.OutOfSpace;
    out_entries[len.*] = entry;
    len.* += 1;
}

pub inline fn appendSpawn(
    out_entries: []spawn_runtime.QuestSpawnEntry,
    len: *usize,
    pos: spawn_runtime.Vec2,
    heading: f64,
    spawn_id: SpawnId,
    trigger_ms: i32,
    count: i32,
) QuestSpawnBuildError!void {
    try appendEntry(out_entries, len, .{
        .pos = pos,
        .heading = heading,
        .spawn_id = @intFromEnum(spawn_id),
        .trigger_ms = trigger_ms,
        .count = count,
    });
}

pub inline fn centerPoint(width: f64, height: f64) spawn_runtime.Vec2 {
    return .{
        .x = width * 0.5,
        .y = height * 0.5,
    };
}

pub inline fn edgeMidpoints(width: f64, height: f64, offset: f64) EdgePoints {
    const center = centerPoint(width, height);
    return .{
        .left = .{ .x = -offset, .y = center.y },
        .right = .{ .x = width + offset, .y = center.y },
        .top = .{ .x = center.x, .y = -offset },
        .bottom = .{ .x = center.x, .y = height + offset },
    };
}

pub inline fn cornerPointTopLeft(width: f64, height: f64, offset: f64) spawn_runtime.Vec2 {
    _ = width;
    _ = height;
    return .{ .x = -offset, .y = -offset };
}

pub inline fn cornerPointTopRight(width: f64, height: f64, offset: f64) spawn_runtime.Vec2 {
    _ = height;
    return .{ .x = width + offset, .y = -offset };
}

pub inline fn cornerPointBottomLeft(width: f64, height: f64, offset: f64) spawn_runtime.Vec2 {
    _ = width;
    return .{ .x = -offset, .y = height + offset };
}

pub inline fn cornerPointBottomRight(width: f64, height: f64, offset: f64) spawn_runtime.Vec2 {
    return .{ .x = width + offset, .y = height + offset };
}

pub inline fn randomAngle(rng: *PythonRandom) f64 {
    return @as(f64, @floatFromInt(rng.randBelow(0x264))) * 0.01;
}

pub inline fn headingFromCenter(point: spawn_runtime.Vec2, center: spawn_runtime.Vec2) f64 {
    return math_runtime.atan2(point.y - center.y, point.x - center.x) - (std.math.pi / 2.0);
}

pub inline fn vecFromAngle(angle: f64) spawn_runtime.Vec2 {
    return .{
        .x = math_runtime.cos(angle),
        .y = math_runtime.sin(angle),
    };
}

pub inline fn addVec(a: spawn_runtime.Vec2, b: spawn_runtime.Vec2) spawn_runtime.Vec2 {
    return .{
        .x = a.x + b.x,
        .y = a.y + b.y,
    };
}

pub inline fn subVec(a: spawn_runtime.Vec2, b: spawn_runtime.Vec2) spawn_runtime.Vec2 {
    return .{
        .x = a.x - b.x,
        .y = a.y - b.y,
    };
}

pub inline fn mulVec(vec: spawn_runtime.Vec2, scalar: f64) spawn_runtime.Vec2 {
    return .{
        .x = vec.x * scalar,
        .y = vec.y * scalar,
    };
}

pub inline fn toAngle(vec: spawn_runtime.Vec2) f64 {
    return math_runtime.atan2(vec.y, vec.x);
}

pub const PythonRandom = struct {
    const n: usize = 624;
    const m: usize = 397;
    const matrix_a: u32 = 0x9908B0DF;
    const upper_mask: u32 = 0x80000000;
    const lower_mask: u32 = 0x7fffffff;

    state: [n]u32 = [_]u32{0} ** n,
    index: usize = n,

    pub fn init(seed_value: u32) PythonRandom {
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

    pub fn randBelow(self: *PythonRandom, n_in: u32) u32 {
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

pub const SpawnId = enum(i32) {
    zombie_boss_spawner_00 = 0x00,
    spider_sp2_splitter_01 = 0x01,
    spider_sp1_random_03 = 0x03,
    lizard_random_04 = 0x04,
    spider_sp2_random_05 = 0x05,
    alien_random_06 = 0x06,
    alien_spawner_child_1d_fast_07 = 0x07,
    alien_spawner_child_1d_slow_08 = 0x08,
    alien_spawner_child_1d_limited_09 = 0x09,
    alien_spawner_child_32_slow_0a = 0x0A,
    alien_spawner_child_3c_slow_0b = 0x0B,
    alien_spawner_child_31_fast_0c = 0x0C,
    alien_spawner_child_31_slow_0d = 0x0D,
    alien_spawner_ring_24_0e = 0x0E,
    alien_const_brown_transparent_0f = 0x0F,
    alien_spawner_child_32_fast_10 = 0x10,
    formation_chain_lizard_4_11 = 0x11,
    formation_ring_alien_8_12 = 0x12,
    formation_chain_alien_10_13 = 0x13,
    formation_grid_alien_green_14 = 0x14,
    formation_grid_alien_white_15 = 0x15,
    formation_grid_lizard_white_16 = 0x16,
    formation_grid_spider_sp1_white_17 = 0x17,
    formation_grid_alien_bronze_18 = 0x18,
    formation_ring_alien_5_19 = 0x19,
    ai1_alien_blue_tint_1a = 0x1A,
    ai1_spider_sp1_blue_tint_1b = 0x1B,
    ai1_lizard_blue_tint_1c = 0x1C,
    alien_random_1d = 0x1D,
    alien_random_1e = 0x1E,
    alien_random_1f = 0x1F,
    alien_random_green_20 = 0x20,
    alien_const_purple_ghost_21 = 0x21,
    alien_const_green_ghost_22 = 0x22,
    alien_const_green_ghost_small_23 = 0x23,
    alien_const_green_24 = 0x24,
    alien_const_green_small_25 = 0x25,
    alien_const_pale_green_26 = 0x26,
    alien_const_weapon_bonus_27 = 0x27,
    alien_const_purple_28 = 0x28,
    alien_const_grey_brute_29 = 0x29,
    alien_const_grey_fast_2a = 0x2A,
    alien_const_red_fast_2b = 0x2B,
    alien_const_red_boss_2c = 0x2C,
    alien_const_cyan_ai2_2d = 0x2D,
    lizard_random_2e = 0x2E,
    lizard_const_grey_2f = 0x2F,
    lizard_const_yellow_boss_30 = 0x30,
    lizard_random_31 = 0x31,
    spider_sp1_random_32 = 0x32,
    spider_sp1_random_red_33 = 0x33,
    spider_sp1_random_green_34 = 0x34,
    spider_sp2_random_35 = 0x35,
    alien_ai7_orbiter_36 = 0x36,
    spider_sp2_ranged_variant_37 = 0x37,
    spider_sp1_ai7_timer_38 = 0x38,
    spider_sp1_ai7_timer_weak_39 = 0x39,
    spider_sp1_const_shock_boss_3a = 0x3A,
    spider_sp1_const_red_boss_3b = 0x3B,
    spider_sp1_const_ranged_variant_3c = 0x3C,
    spider_sp1_random_3d = 0x3D,
    spider_sp1_const_white_fast_3e = 0x3E,
    spider_sp1_const_brown_small_3f = 0x3F,
    spider_sp1_const_blue_40 = 0x40,
    zombie_random_41 = 0x41,
    zombie_const_grey_42 = 0x42,
    zombie_const_green_brute_43 = 0x43,
};
