const quest_spawn_logic_full = @import("quest_spawn_logic_full.zig");
const survival_spawn = @import("survival_spawn.zig");

pub const QuestSpawnBuildError = quest_spawn_logic_full.QuestSpawnBuildError;
pub const QuestSpawnBuildResult = quest_spawn_logic_full.QuestSpawnBuildResult;

pub fn buildQuestSpawnTable(
    level_key: i32,
    player_count: i32,
    seed: u32,
    world_size: f64,
    out_entries: []survival_spawn.QuestSpawnEntry,
) QuestSpawnBuildError!QuestSpawnBuildResult {
    return quest_spawn_logic_full.buildQuestSpawnTable(
        level_key,
        player_count,
        seed,
        world_size,
        out_entries,
    );
}
