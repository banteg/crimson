const std = @import("std");
const native_math = @import("../runtime/native_math.zig");
const spawn_mod = @import("../runtime/spawn.zig");

pub const TypoSpawnCall = struct {
    pos_x: f32,
    pos_y: f32,
    type_id: spawn_mod.CreatureTypeId,
    tint_r: f32,
    tint_g: f32,
    tint_b: f32,
};

pub const TypoSpawnBatch = struct {
    cooldown_ms: i32,
    count: usize = 0,
    calls: [8]TypoSpawnCall = [_]TypoSpawnCall{undefined} ** 8,

    pub fn slice(self: *const TypoSpawnBatch) []const TypoSpawnCall {
        return self.calls[0..self.count];
    }
};

fn clamp01(value: f32) f32 {
    return std.math.clamp(value, @as(f32, 0.0), @as(f32, 1.0));
}

pub fn tickTypoSpawns(
    elapsed_ms: i32,
    spawn_cooldown_ms: i32,
    frame_dt_ms: i32,
    player_count: i32,
    world_width: f32,
    world_height: f32,
) TypoSpawnBatch {
    var batch: TypoSpawnBatch = .{
        .cooldown_ms = spawn_cooldown_ms,
    };
    const safe_player_count = @max(1, player_count);
    batch.cooldown_ms -= frame_dt_ms * safe_player_count;

    while (batch.cooldown_ms < 0 and batch.count + 2 <= batch.calls.len) {
        batch.cooldown_ms += 3500 - @divTrunc(elapsed_ms, 800);
        batch.cooldown_ms = @max(100, batch.cooldown_ms);

        // typo_gameplay_update_and_render (0x00445af4..0x00445c15): float
        // literals at PC24; fsin/fcos stay wide until the next op rounds.
        const tint_t = @as(f32, @floatFromInt(elapsed_ms + 1));
        const tint_r = clamp01(native_math.pc24Add(native_math.pc24Mul(tint_t, @as(f32, 0.00000833333343)), @as(f32, 0.3)));
        const tint_g = clamp01(native_math.pc24Add(native_math.pc24Mul(tint_t, @as(f32, 10000.0)), @as(f32, 0.3)));
        const tint_b = clamp01(native_math.pc24Add(
            @sin(@as(f64, native_math.pc24Mul(tint_t, @as(f32, 0.000100000005)))),
            @as(f32, 0.3),
        ));

        const t = native_math.pc24Mul(@as(f32, @floatFromInt(elapsed_ms)), @as(f32, 0.001));
        const y = native_math.pc24Add(
            native_math.pc24Mul(@cos(@as(f64, t)), @as(f32, 256.0)),
            native_math.pc24Mul(world_height, @as(f32, 0.5)),
        );

        batch.calls[batch.count] = .{
            .pos_x = native_math.pc24Add(world_width, @as(f32, 64.0)),
            .pos_y = y,
            .type_id = .spider_sp2,
            .tint_r = tint_r,
            .tint_g = tint_g,
            .tint_b = tint_b,
        };
        batch.count += 1;
        batch.calls[batch.count] = .{
            .pos_x = -64.0,
            .pos_y = y,
            .type_id = .alien,
            .tint_r = tint_r,
            .tint_g = tint_g,
            .tint_b = tint_b,
        };
        batch.count += 1;
    }

    return batch;
}

test "typo spawns produce left/right pair" {
    const batch = tickTypoSpawns(1000, 0, 16, 1, 1024.0, 1024.0);
    try std.testing.expectEqual(@as(usize, 2), batch.count);
    try std.testing.expect(batch.calls[0].pos_x > 1024.0);
    try std.testing.expect(batch.calls[1].pos_x < 0.0);
}
