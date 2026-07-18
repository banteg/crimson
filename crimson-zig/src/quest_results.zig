const std = @import("std");
const native_math = @import("crimson_zig").native_math;

pub const QuestFinalTime = struct {
    base_time_ms: i32,
    life_bonus_ms: i32,
    unpicked_perk_bonus_ms: i32,
    final_time_ms: i32,
};

pub const QuestResultsBreakdownAnim = struct {
    step: i32 = 0,
    step_timer_ms: i32 = 700,
    base_time_ms: i32 = 0,
    life_bonus_ms: i32 = 0,
    unpicked_perk_bonus_s: i32 = 0,
    final_time_ms: i32 = 0,
    blink_ticks: i32 = 0,
    done: bool = false,

    pub fn setFinal(self: *QuestResultsBreakdownAnim, target: QuestFinalTime) void {
        self.step = 4;
        self.done = true;
        self.step_timer_ms = 0;
        self.base_time_ms = target.base_time_ms;
        self.life_bonus_ms = target.life_bonus_ms;
        self.unpicked_perk_bonus_s = @max(0, @divTrunc(target.unpicked_perk_bonus_ms, 1000));
        self.final_time_ms = target.final_time_ms;
        self.blink_ticks = 0;
    }

    pub fn highlightAlpha(self: QuestResultsBreakdownAnim) f32 {
        if (self.step != 3) return 1.0;
        return std.math.clamp(1.0 - @as(f32, @floatFromInt(self.blink_ticks)) * 0.1, 0.0, 1.0);
    }

    pub fn perkBonusMs(self: QuestResultsBreakdownAnim) i32 {
        return self.unpicked_perk_bonus_s * 1000;
    }
};

pub fn computeQuestFinalTime(
    base_time_ms: i32,
    player_health_values: []const f32,
    pending_perk_count: i32,
) QuestFinalTime {
    const base_ms = base_time_ms;
    var life_bonus_ms: i32 = 0;
    if (player_health_values.len > 0) {
        // Native stores player 0's __ftol-truncated health back to the player
        // record before multiplying it by 50. Later players multiply first.
        const player0_health: i32 = @intFromFloat(@trunc(player_health_values[0]));
        life_bonus_ms = @intFromFloat(@trunc(native_math.pc24Mul(
            @as(f32, @floatFromInt(player0_health)),
            @as(f32, 50.0),
        )));
        for (player_health_values[1..]) |health| {
            life_bonus_ms += @intFromFloat(@trunc(native_math.pc24Mul(health, @as(f32, 50.0))));
        }
    }
    const unpicked_perk_bonus_ms = pending_perk_count * 1000;
    // Native records negative final times; only an exactly-zero result is
    // remapped to 1 ms.
    var final_time_ms = base_ms - life_bonus_ms - unpicked_perk_bonus_ms;
    if (final_time_ms == 0) final_time_ms = 1;
    return .{
        .base_time_ms = base_ms,
        .life_bonus_ms = life_bonus_ms,
        .unpicked_perk_bonus_ms = unpicked_perk_bonus_ms,
        .final_time_ms = final_time_ms,
    };
}

pub fn tickQuestResultsBreakdownAnim(
    anim: *QuestResultsBreakdownAnim,
    frame_dt_ms: i32,
    target: QuestFinalTime,
) i32 {
    if (anim.done) return 0;
    var clinks: i32 = 0;
    var remaining: i32 = @max(0, frame_dt_ms);
    if (remaining <= 0) return 0;

    const base_target_ms = @max(0, target.base_time_ms);
    const life_target_ms = @max(0, target.life_bonus_ms);
    const perk_target_s = @max(0, @divTrunc(target.unpicked_perk_bonus_ms, 1000));

    while (remaining > 0 and !anim.done) {
        const step_timer: i32 = anim.step_timer_ms;
        const take: i32 = if (step_timer <= 0) remaining else @min(remaining, step_timer);
        anim.step_timer_ms -= take;
        remaining -= take;

        while (anim.step_timer_ms <= 0 and !anim.done) {
            switch (anim.step) {
                0 => {
                    anim.base_time_ms = @min(base_target_ms, anim.base_time_ms + 2000);
                    anim.final_time_ms = anim.base_time_ms;
                    anim.step_timer_ms += 40;
                    clinks += 1;
                    if (anim.base_time_ms >= base_target_ms) anim.step = 1;
                },
                1 => {
                    anim.life_bonus_ms = @min(life_target_ms, anim.life_bonus_ms + 1000);
                    anim.final_time_ms = @max(1, base_target_ms - anim.life_bonus_ms - anim.unpicked_perk_bonus_s * 1000);
                    anim.step_timer_ms += 150;
                    clinks += 1;
                    if (anim.life_bonus_ms >= life_target_ms) anim.step = 2;
                },
                2 => {
                    anim.unpicked_perk_bonus_s = @min(perk_target_s, anim.unpicked_perk_bonus_s + 1);
                    anim.final_time_ms = @max(1, base_target_ms - anim.life_bonus_ms - anim.unpicked_perk_bonus_s * 1000);
                    clinks += 1;
                    if (anim.unpicked_perk_bonus_s >= perk_target_s) {
                        anim.final_time_ms = target.final_time_ms;
                        anim.step_timer_ms += 1000;
                        anim.step = 3;
                    } else {
                        anim.step_timer_ms += 300;
                    }
                },
                3 => {
                    anim.blink_ticks += 1;
                    anim.step_timer_ms += 50;
                    if (anim.blink_ticks > 10) anim.setFinal(target);
                },
                else => anim.setFinal(target),
            }
        }
    }

    return clinks;
}

test "compute quest final time mirrors native formula" {
    const breakdown = computeQuestFinalTime(32_500, &.{ 83.6, 41.2 }, 2);
    try std.testing.expectEqual(@as(i32, 32_500), breakdown.base_time_ms);
    // Player 0 truncates before the multiply; player 1 multiplies first.
    try std.testing.expectEqual(@as(i32, 6_210), breakdown.life_bonus_ms);
    try std.testing.expectEqual(@as(i32, 2_000), breakdown.unpicked_perk_bonus_ms);
    try std.testing.expectEqual(@as(i32, 24_290), breakdown.final_time_ms);
}

test "quest life bonus rounds later-player multiplication at native pc24" {
    const boundary_health: f32 = @bitCast(@as(u32, 0x3d23d70a));
    const breakdown = computeQuestFinalTime(100, &.{ 0.0, boundary_health }, 0);
    try std.testing.expectEqual(@as(i32, 2), breakdown.life_bonus_ms);
    try std.testing.expectEqual(@as(i32, 98), breakdown.final_time_ms);
}

test "compute quest final time keeps negative results" {
    // Native only remaps an exactly-zero result to 1 ms.
    const breakdown = computeQuestFinalTime(100, &.{ 60.0, 60.0 }, 5);
    try std.testing.expectEqual(@as(i32, -10_900), breakdown.final_time_ms);
    const zero = computeQuestFinalTime(11_000, &.{ 60.0, 60.0 }, 5);
    try std.testing.expectEqual(@as(i32, 1), zero.final_time_ms);
}

test "quest results breakdown anim advances in native phases" {
    const target: QuestFinalTime = .{
        .base_time_ms = 5_000,
        .life_bonus_ms = 1_200,
        .unpicked_perk_bonus_ms = 2_000,
        .final_time_ms = 1_800,
    };
    var anim: QuestResultsBreakdownAnim = .{};

    try std.testing.expectEqual(@as(i32, 1), tickQuestResultsBreakdownAnim(&anim, 700, target));
    try std.testing.expectEqual(@as(i32, 0), anim.step);
    try std.testing.expectEqual(@as(i32, 2_000), anim.base_time_ms);
    try std.testing.expectEqual(@as(i32, 2_000), anim.final_time_ms);

    var total_clinks: i32 = 1;
    var guard: usize = 0;
    while (!anim.done and guard < 200) : (guard += 1) {
        total_clinks += tickQuestResultsBreakdownAnim(&anim, 100, target);
    }
    try std.testing.expect(anim.done);
    try std.testing.expectEqual(@as(i32, 7), total_clinks);
    try std.testing.expectEqual(@as(i32, 5_000), anim.base_time_ms);
    try std.testing.expectEqual(@as(i32, 1_200), anim.life_bonus_ms);
    try std.testing.expectEqual(@as(i32, 2), anim.unpicked_perk_bonus_s);
    try std.testing.expectEqual(@as(i32, 1_800), anim.final_time_ms);
    try std.testing.expectEqual(@as(f32, 1.0), anim.highlightAlpha());
}

test "quest results breakdown anim can skip to final values" {
    const target: QuestFinalTime = .{
        .base_time_ms = 9_000,
        .life_bonus_ms = 250,
        .unpicked_perk_bonus_ms = 1_000,
        .final_time_ms = 7_750,
    };
    var anim: QuestResultsBreakdownAnim = .{};
    anim.setFinal(target);
    try std.testing.expect(anim.done);
    try std.testing.expectEqual(@as(i32, 4), anim.step);
    try std.testing.expectEqual(@as(i32, 9_000), anim.base_time_ms);
    try std.testing.expectEqual(@as(i32, 250), anim.life_bonus_ms);
    try std.testing.expectEqual(@as(i32, 1_000), anim.perkBonusMs());
    try std.testing.expectEqual(@as(i32, 7_750), anim.final_time_ms);
}
