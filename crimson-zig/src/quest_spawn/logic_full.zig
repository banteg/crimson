const common = @import("logic_common.zig");
const tier1 = @import("logic_tier1.zig");
const tier2 = @import("logic_tier2.zig");
const tier3 = @import("logic_tier3.zig");
const tier4 = @import("logic_tier4.zig");
const tier5 = @import("logic_tier5.zig");
const survival_spawn = @import("../survival_spawn.zig");

pub const QuestSpawnBuildError = common.QuestSpawnBuildError;
pub const QuestSpawnBuildResult = common.QuestSpawnBuildResult;
pub const LevelBuilder = common.LevelBuilder;
pub const BuildContext = common.BuildContext;

pub const level_builders = tier1.tier1_builders ++
    tier2.tier2_builders ++
    tier3.tier3_builders ++
    tier4.tier4_builders ++
    tier5.tier5_builders;

pub fn buildQuestSpawnTable(
    level_key: i32,
    player_count: i32,
    seed: u32,
    world_size: f64,
    out_entries: []survival_spawn.QuestSpawnEntry,
) QuestSpawnBuildError!QuestSpawnBuildResult {
    if (player_count < 1 or player_count > 4) return error.UnsupportedQuestSpawnTable;
    const descriptor = lookupLevelBuilder(level_key) orelse return error.UnsupportedQuestSpawnTable;

    const ctx = BuildContext{
        .width = world_size,
        .height = world_size,
        .player_count = player_count,
    };
    var rng = common.PythonRandom.init(seed);
    var len: usize = 0;
    try descriptor.build(ctx, &rng, out_entries, &len);

    return .{
        .entries = out_entries[0..len],
        .start_weapon_id = descriptor.start_weapon_id,
    };
}

pub fn lookupLevelBuilder(level_key: i32) ?LevelBuilder {
    for (level_builders) |descriptor| {
        if (descriptor.level_key == level_key) return descriptor;
    }
    return null;
}
