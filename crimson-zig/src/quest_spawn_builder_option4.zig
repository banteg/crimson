const quest_spawn_logic_common = @import("quest_spawn_logic_common.zig");
const quest_spawn_logic_full = @import("quest_spawn_logic_full.zig");
const survival_spawn = @import("survival_spawn.zig");

pub const QuestSpawnBuildError = quest_spawn_logic_common.QuestSpawnBuildError;
pub const QuestSpawnBuildResult = quest_spawn_logic_common.QuestSpawnBuildResult;

pub fn buildQuestSpawnTable(
    level_key: i32,
    player_count: i32,
    seed: u32,
    world_size: f64,
    out_entries: []survival_spawn.QuestSpawnEntry,
) QuestSpawnBuildError!QuestSpawnBuildResult {
    if (player_count < 1 or player_count > 4) return error.UnsupportedQuestSpawnTable;
    const descriptor = quest_spawn_logic_full.lookupLevelBuilder(level_key) orelse return error.UnsupportedQuestSpawnTable;

    const ctx: quest_spawn_logic_common.BuildContext = .{
        .width = world_size,
        .height = world_size,
        .player_count = player_count,
    };
    var rng = quest_spawn_logic_common.PythonRandom.init(seed);
    var len: usize = 0;
    try descriptor.build(ctx, &rng, out_entries, &len);

    return .{
        .entries = out_entries[0..len],
        .start_weapon_id = descriptor.start_weapon_id,
    };
}
