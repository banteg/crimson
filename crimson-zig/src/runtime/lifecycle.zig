const std = @import("std");

pub const CreatureLifecycle = struct {
    pub const Stage = f32;

    pub const alive: Stage = 16.0;
    pub const collidable_min: Stage = 5.0;
    pub const corpse_despawn: Stage = -10.0;

    pub const Phase = enum(u8) {
        alive,
        death_staging,
        corpse_fading,
        despawned,
    };

    pub inline fn isAlive(stage: Stage) bool {
        return stage == alive;
    }

    pub inline fn isCollidable(stage: Stage) bool {
        return stage > collidable_min;
    }

    pub inline fn classify(stage: Stage) Phase {
        if (isAlive(stage)) return .alive;
        if (stage > 0.0) return .death_staging;
        if (stage >= corpse_despawn) return .corpse_fading;
        return .despawned;
    }

    pub inline fn isDespawned(stage: Stage) bool {
        return classify(stage) == .despawned;
    }
};

test "alive and collidable predicates match native sentinels" {
    try std.testing.expect(CreatureLifecycle.isAlive(CreatureLifecycle.alive));
    try std.testing.expect(CreatureLifecycle.isCollidable(CreatureLifecycle.alive));
    try std.testing.expect(!CreatureLifecycle.isAlive(15.0));
    try std.testing.expect(!CreatureLifecycle.isCollidable(CreatureLifecycle.collidable_min));
}

test "phase classification uses lifecycle boundaries" {
    try std.testing.expectEqual(CreatureLifecycle.Phase.alive, CreatureLifecycle.classify(CreatureLifecycle.alive));
    try std.testing.expectEqual(CreatureLifecycle.Phase.death_staging, CreatureLifecycle.classify(0.5));
    try std.testing.expectEqual(CreatureLifecycle.Phase.corpse_fading, CreatureLifecycle.classify(0.0));
    try std.testing.expectEqual(CreatureLifecycle.Phase.corpse_fading, CreatureLifecycle.classify(CreatureLifecycle.corpse_despawn));
    try std.testing.expectEqual(CreatureLifecycle.Phase.despawned, CreatureLifecycle.classify(CreatureLifecycle.corpse_despawn - 0.001));
}
