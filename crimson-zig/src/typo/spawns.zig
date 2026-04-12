const std = @import("std");
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

        const t = @as(f32, @floatFromInt(elapsed_ms)) * 0.001;
        const y = @cos(t) * 256.0 + world_height * 0.5;

        const tint_t = @as(f32, @floatFromInt(elapsed_ms + 1));
        const tint_r = clamp01(tint_t * 0.0000083333334 + 0.3);
        const tint_g = clamp01(tint_t * 10000.0 + 0.3);
        const tint_b = clamp01(@sin(tint_t * 0.0001) + 0.3);

        batch.calls[batch.count] = .{
            .pos_x = world_width + 64.0,
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
