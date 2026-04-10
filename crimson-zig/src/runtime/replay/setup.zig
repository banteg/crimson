const game_ids = @import("../../game_ids.zig");
const replay_codec = @import("../../replay_codec.zig");
const runtime_session = @import("../session.zig");
const runtime_session_builders = @import("../session_builders.zig");

pub const max_sim_quest_spawn_entries = runtime_session.max_sim_quest_spawn_entries;
pub const PrepareContextOptions = runtime_session_builders.BuildReplaySessionOptions;
pub const ReplayExecutionMode = runtime_session_builders.ReplayExecutionMode;
pub const deriveReplayExecutionMode = runtime_session_builders.deriveReplayExecutionMode;

pub fn prepareSimulationContext(
    game_mode: game_ids.GameModeId,
    header: replay_codec.ReplayHeader,
    events: []const replay_codec.ReplayEvent,
    options: PrepareContextOptions,
) runtime_session.DeterministicSessionError!runtime_session.DeterministicSession {
    return runtime_session_builders.buildReplaySession(game_mode, header, events, options);
}
