const std = @import("std");
const checkpoint_diff_native = @import("checkpoint_diff_native.zig");
const dbg_record_native = @import("dbg_record_native.zig");
const replay_benchmark_native = @import("replay_benchmark_native.zig");
const replay_info_native = @import("replay_info_native.zig");
const replay_list_native = @import("replay_list_native.zig");
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
    \\  crimson-zig --help
    \\
    \\Examples:
    \\  crimson-zig replay list --base-dir .
    \\  crimson-zig replay verify survival_20260224_041009_score76661.crd
    \\  crimson-zig replay verify replay.crd --format json
    \\  crimson-zig replay benchmark replay.crd --runs 5
    \\  crimson-zig replay verify-checkpoints replay.crd
    \\  crimson-zig replay info replay.crd --format json
    \\  crimson-zig replay diff-checkpoints replay.crd.chk replay.candidate.crd.chk
    \\  crimson-zig dbg record replay.crd --out replay.cdt
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
