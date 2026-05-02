const std = @import("std");
const checkpoint_diff_native = @import("checkpoint_diff_native.zig");
const config_native = @import("config_native.zig");
const dbg_diff_native = @import("dbg_diff_native.zig");
const dbg_entity_native = @import("dbg_entity_native.zig");
const dbg_health_native = @import("dbg_health_native.zig");
const dbg_query_native = @import("dbg_query_native.zig");
const dbg_record_native = @import("dbg_record_native.zig");
const dbg_tick_native = @import("dbg_tick_native.zig");
const dbg_verify_native = @import("dbg_verify_native.zig");
const quest_spawn_native = @import("quest_spawn_native.zig");
const replay_benchmark_native = @import("replay_benchmark_native.zig");
const replay_info_native = @import("replay_info_native.zig");
const replay_list_native = @import("replay_list_native.zig");
const net_lockstep_smoke_native = @import("net_lockstep_smoke_native.zig");
const net_rollback_smoke_native = @import("net_rollback_smoke_native.zig");
const net_session_native = @import("net_session_native.zig");
const relay_udp_server = @import("net/relay_udp_server.zig");
const spawn_plan_native = @import("spawn_plan_native.zig");
const status_native = @import("status_native.zig");
const verify_native = @import("verify_native.zig");

const usage =
    \\Usage:
    \\  crimson-zig replay list [list options]
    \\  crimson-zig replay verify <replay.crd> [verify options]
    \\  crimson-zig replay benchmark <replay.crd> [benchmark options]
    \\  crimson-zig replay verify-checkpoints <replay.crd> [checkpoint options]
    \\  crimson-zig replay info <replay.crd> [info options]
    \\  crimson-zig replay diff-checkpoints <expected.chk> <actual.chk>
    \\  crimson-zig dbg record <replay.crd> --out <trace.cdt>
    \\  crimson-zig dbg diff <expected.cdt> <actual.cdt> [diff options]
    \\  crimson-zig dbg health <trace.cdt> [health options]
    \\  crimson-zig dbg tick <trace.cdt> <tick> [tick options]
    \\  crimson-zig dbg entity <trace.cdt> <entity_uid> [entity options]
    \\  crimson-zig dbg query <trace.cdt> <expression> [query options]
    \\  crimson-zig dbg verify
    \\  crimson-zig config [config options]
    \\  crimson-zig status [status options]
    \\  crimson-zig quests <level> [quest options]
    \\  crimson-zig spawn-plan <template_id> [spawn-plan options]
    \\  crimson-zig net host --mode <mode> --players <count> [net options]
    \\  crimson-zig net join --code <room> [net options]
    \\  crimson-zig net smoke-lockstep [smoke options]
    \\  crimson-zig net smoke-rollback [smoke options]
    \\  crimson-zig relay serve [relay options]
    \\  crimson-zig --help
    \\
    \\Examples:
    \\  crimson-zig replay list --base-dir .
    \\  crimson-zig replay list --base-dir . --format json
    \\  crimson-zig replay verify survival_20260224_041009_score76661.crd
    \\  crimson-zig replay verify replay.crd --format json
    \\  crimson-zig replay benchmark replay.crd --runs 5
    \\  crimson-zig replay verify-checkpoints replay.crd
    \\  crimson-zig replay verify-checkpoints replay.crd --format json
    \\  crimson-zig replay info replay.crd --format json
    \\  crimson-zig replay diff-checkpoints replay.crd.chk replay.candidate.crd.chk --format json
    \\  crimson-zig dbg record replay.crd --out replay.cdt
    \\  crimson-zig dbg diff golden.cdt candidate.cdt --json
    \\  crimson-zig dbg health replay.cdt
    \\  crimson-zig dbg tick replay.cdt 0 --json
    \\  crimson-zig dbg entity replay.cdt 0 --json
    \\  crimson-zig dbg query replay.cdt "entities where uid == 0" --json
    \\  crimson-zig dbg verify
    \\  crimson-zig config --path crimson.cfg --format json
    \\  crimson-zig status --path game.cfg --format json
    \\  crimson-zig quests 1.1 --format json --seed 101
    \\  crimson-zig spawn-plan 0x12 --json
    \\  crimson-zig net host --mode survival --players 2 --format json
    \\  crimson-zig net join --code ab12 --format json
    \\  crimson-zig net smoke-lockstep --json
    \\  crimson-zig net smoke-rollback --json
    \\  crimson-zig relay serve --bind 127.0.0.1 --port 31993
    \\
;

pub fn run(allocator: std.mem.Allocator, args: []const []const u8) !u8 {
    if (args.len <= 1) {
        try printUsage();
        return 0;
    }

    if (std.mem.eql(u8, args[1], "--help") or std.mem.eql(u8, args[1], "-h")) {
        try printUsage();
        return 0;
    }

    if (args.len >= 3 and std.mem.eql(u8, args[1], "replay") and std.mem.eql(u8, args[2], "verify")) {
        const output = try verify_native.runReplayVerify(allocator, args[3..]);
        defer output.deinit(allocator);

        try writeStdout(output.stdout);
        try writeStderr(output.stderr);
        return output.exit_code;
    }
    if (args.len >= 3 and std.mem.eql(u8, args[1], "replay") and std.mem.eql(u8, args[2], "list")) {
        const output = try replay_list_native.runReplayList(allocator, args[3..]);
        defer output.deinit(allocator);

        try writeStdout(output.stdout);
        try writeStderr(output.stderr);
        return output.exit_code;
    }
    if (args.len >= 3 and std.mem.eql(u8, args[1], "replay") and std.mem.eql(u8, args[2], "benchmark")) {
        const output = try replay_benchmark_native.runReplayBenchmark(allocator, args[3..]);
        defer output.deinit(allocator);

        try writeStdout(output.stdout);
        try writeStderr(output.stderr);
        return output.exit_code;
    }
    if (args.len >= 3 and std.mem.eql(u8, args[1], "replay") and std.mem.eql(u8, args[2], "verify-checkpoints")) {
        const output = try checkpoint_diff_native.runReplayVerifyCheckpoints(allocator, args[3..]);
        defer output.deinit(allocator);

        try writeStdout(output.stdout);
        try writeStderr(output.stderr);
        return output.exit_code;
    }
    if (args.len >= 3 and std.mem.eql(u8, args[1], "replay") and std.mem.eql(u8, args[2], "info")) {
        const output = try replay_info_native.runReplayInfo(allocator, args[3..]);
        defer output.deinit(allocator);

        try writeStdout(output.stdout);
        try writeStderr(output.stderr);
        return output.exit_code;
    }
    if (args.len >= 3 and std.mem.eql(u8, args[1], "replay") and std.mem.eql(u8, args[2], "diff-checkpoints")) {
        const output = try checkpoint_diff_native.runReplayDiffCheckpoints(allocator, args[3..]);
        defer output.deinit(allocator);

        try writeStdout(output.stdout);
        try writeStderr(output.stderr);
        return output.exit_code;
    }
    if (args.len >= 3 and std.mem.eql(u8, args[1], "dbg") and std.mem.eql(u8, args[2], "record")) {
        const output = try dbg_record_native.runDbgRecord(allocator, args[3..]);
        defer output.deinit(allocator);

        try writeStdout(output.stdout);
        try writeStderr(output.stderr);
        return output.exit_code;
    }
    if (args.len >= 3 and std.mem.eql(u8, args[1], "dbg") and std.mem.eql(u8, args[2], "diff")) {
        const output = try dbg_diff_native.runDbgDiff(allocator, args[3..]);
        defer output.deinit(allocator);

        try writeStdout(output.stdout);
        try writeStderr(output.stderr);
        return output.exit_code;
    }
    if (args.len >= 3 and std.mem.eql(u8, args[1], "dbg") and std.mem.eql(u8, args[2], "health")) {
        const output = try dbg_health_native.runDbgHealth(allocator, args[3..]);
        defer output.deinit(allocator);

        try writeStdout(output.stdout);
        try writeStderr(output.stderr);
        return output.exit_code;
    }
    if (args.len >= 3 and std.mem.eql(u8, args[1], "dbg") and std.mem.eql(u8, args[2], "tick")) {
        const output = try dbg_tick_native.runDbgTick(allocator, args[3..]);
        defer output.deinit(allocator);

        try writeStdout(output.stdout);
        try writeStderr(output.stderr);
        return output.exit_code;
    }
    if (args.len >= 3 and std.mem.eql(u8, args[1], "dbg") and std.mem.eql(u8, args[2], "entity")) {
        const output = try dbg_entity_native.runDbgEntity(allocator, args[3..]);
        defer output.deinit(allocator);

        try writeStdout(output.stdout);
        try writeStderr(output.stderr);
        return output.exit_code;
    }
    if (args.len >= 3 and std.mem.eql(u8, args[1], "dbg") and std.mem.eql(u8, args[2], "query")) {
        const output = try dbg_query_native.runDbgQuery(allocator, args[3..]);
        defer output.deinit(allocator);

        try writeStdout(output.stdout);
        try writeStderr(output.stderr);
        return output.exit_code;
    }
    if (args.len >= 3 and std.mem.eql(u8, args[1], "dbg") and std.mem.eql(u8, args[2], "verify")) {
        const output = try dbg_verify_native.runDbgVerify(allocator, args[3..]);
        defer output.deinit(allocator);

        try writeStdout(output.stdout);
        try writeStderr(output.stderr);
        return output.exit_code;
    }
    if (args.len >= 2 and std.mem.eql(u8, args[1], "config")) {
        const output = try config_native.runConfig(allocator, args[2..]);
        defer output.deinit(allocator);

        try writeStdout(output.stdout);
        try writeStderr(output.stderr);
        return output.exit_code;
    }
    if (args.len >= 2 and std.mem.eql(u8, args[1], "status")) {
        const output = try status_native.runStatus(allocator, args[2..]);
        defer output.deinit(allocator);

        try writeStdout(output.stdout);
        try writeStderr(output.stderr);
        return output.exit_code;
    }
    if (args.len >= 2 and std.mem.eql(u8, args[1], "quests")) {
        const output = try quest_spawn_native.runQuests(allocator, args[2..]);
        defer output.deinit(allocator);

        try writeStdout(output.stdout);
        try writeStderr(output.stderr);
        return output.exit_code;
    }
    if (args.len >= 2 and std.mem.eql(u8, args[1], "spawn-plan")) {
        const output = try spawn_plan_native.runSpawnPlan(allocator, args[2..]);
        defer output.deinit(allocator);

        try writeStdout(output.stdout);
        try writeStderr(output.stderr);
        return output.exit_code;
    }
    if (args.len >= 2 and std.mem.eql(u8, args[1], "net")) {
        if (args.len >= 3 and std.mem.eql(u8, args[2], "smoke-lockstep")) {
            const output = try net_lockstep_smoke_native.runLockstepSmoke(allocator, std.Io.Threaded.global_single_threaded.io(), args[3..]);
            defer output.deinit(allocator);

            try writeStdout(output.stdout);
            try writeStderr(output.stderr);
            return output.exit_code;
        }
        if (args.len >= 3 and std.mem.eql(u8, args[2], "smoke-rollback")) {
            const output = try net_rollback_smoke_native.runRollbackSmoke(allocator, std.Io.Threaded.global_single_threaded.io(), args[3..]);
            defer output.deinit(allocator);

            try writeStdout(output.stdout);
            try writeStderr(output.stderr);
            return output.exit_code;
        }

        const output = try net_session_native.runNet(allocator, args[2..]);
        defer output.deinit(allocator);

        try writeStdout(output.stdout);
        try writeStderr(output.stderr);
        return output.exit_code;
    }
    if (args.len >= 3 and std.mem.eql(u8, args[1], "relay") and std.mem.eql(u8, args[2], "serve")) {
        const output = try relay_udp_server.runRelayServe(allocator, std.Io.Threaded.global_single_threaded.io(), args[3..]);
        defer output.deinit(allocator);

        try writeStdout(output.stdout);
        try writeStderr(output.stderr);
        return output.exit_code;
    }

    try writeStderr("error: unsupported command\n");
    try printUsage();
    return 1;
}

fn printUsage() !void {
    try writeStdout(usage);
}

fn writeStdout(bytes: []const u8) !void {
    var buffer: [4096]u8 = undefined;
    var writer = std.Io.File.stdout().writer(std.Io.Threaded.global_single_threaded.io(), &buffer);
    const out = &writer.interface;
    try out.writeAll(bytes);
    try out.flush();
}

fn writeStderr(bytes: []const u8) !void {
    var buffer: [4096]u8 = undefined;
    var writer = std.Io.File.stderr().writer(std.Io.Threaded.global_single_threaded.io(), &buffer);
    const err = &writer.interface;
    try err.writeAll(bytes);
    try err.flush();
}
