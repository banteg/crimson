const std = @import("std");

const cdt_trace = @import("cdt_trace.zig");
const checkpoint_diff_native = @import("checkpoint_diff_native.zig");
const replay_codec = @import("replay_codec.zig");
const verify_native = @import("verify_native.zig");

pub const CommandOutput = verify_native.CommandOutput;
pub const frida_capture_format_version: i32 = 20;
pub const frida_evidence_format_version: i32 = 2;
pub const frida_runtime_version = "17.15.4";

pub fn runDbgVerify(allocator: std.mem.Allocator, args: []const []const u8) !CommandOutput {
    if (args.len != 0) {
        return buildInvalidArgsOutput(allocator, "dbg verify does not take arguments");
    }

    var stdout_buf: std.Io.Writer.Allocating = .init(allocator);
    defer stdout_buf.deinit();
    const writer = &stdout_buf.writer;

    try writer.print(
        \\trace_format_version={d}
        \\trace_schema_version={d}
        \\replay_format_version={d}
        \\checkpoint_format_version={d}
        \\frida_capture_format_version={d}
        \\frida_evidence_format_version={d}
        \\frida_runtime_version={s}
        \\required_channels={s}
        \\result=ok
        \\
    , .{
        cdt_trace.trace_format_version,
        cdt_trace.trace_schema_version,
        replay_codec.replay_format_version,
        checkpoint_diff_native.checkpoints_format_version,
        frida_capture_format_version,
        frida_evidence_format_version,
        frida_runtime_version,
        cdt_trace.trace_required_channels,
    });

    return .{
        .stdout = try stdout_buf.toOwnedSlice(),
        .stderr = try allocator.dupe(u8, ""),
        .exit_code = 0,
    };
}

fn buildInvalidArgsOutput(
    allocator: std.mem.Allocator,
    detail: []const u8,
) !CommandOutput {
    const stdout = try allocator.dupe(u8, "");
    errdefer allocator.free(stdout);
    const stderr = try std.fmt.allocPrint(allocator, "invalid dbg verify args: {s}\n", .{detail});
    return .{
        .stdout = stdout,
        .stderr = stderr,
        .exit_code = 1,
    };
}

test "dbg verify emits complete ordered format contract" {
    const allocator = std.testing.allocator;

    const output = try runDbgVerify(allocator, &.{});
    defer output.deinit(allocator);

    try std.testing.expectEqual(@as(u8, 0), output.exit_code);
    try std.testing.expectEqualStrings("", output.stderr);
    try std.testing.expectEqualStrings(
        \\trace_format_version=2
        \\trace_schema_version=14
        \\replay_format_version=15
        \\checkpoint_format_version=5
        \\frida_capture_format_version=20
        \\frida_evidence_format_version=2
        \\frida_runtime_version=17.15.4
        \\required_channels=replay_step,checkpoint,sim_state,entity_samples,rng_stream,timing_samples
        \\result=ok
        \\
    , output.stdout);
}
