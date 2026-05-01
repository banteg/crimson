const std = @import("std");

const cdt_trace = @import("cdt_trace.zig");
const replay_codec = @import("replay_codec.zig");
const verify_native = @import("verify_native.zig");

pub const CommandOutput = verify_native.CommandOutput;

pub fn runDbgVerify(allocator: std.mem.Allocator, args: []const []const u8) !CommandOutput {
    if (args.len != 0) {
        return buildInvalidArgsOutput(allocator, "dbg verify does not take arguments");
    }

    var stdout_buf: std.Io.Writer.Allocating = .init(allocator);
    defer stdout_buf.deinit();
    const writer = &stdout_buf.writer;

    try writer.print("trace_schema_version={d}\n", .{cdt_trace.trace_schema_version});
    try writer.print("replay_format_version={d}\n", .{replay_codec.replay_format_version});
    try writer.print("required_channels={s}\n", .{cdt_trace.trace_required_channels});
    try writer.writeAll("result=ok\n");

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

test "dbg verify emits schema contract" {
    const allocator = std.testing.allocator;

    const output = try runDbgVerify(allocator, &.{});
    defer output.deinit(allocator);

    try std.testing.expectEqual(@as(u8, 0), output.exit_code);
    try std.testing.expectEqualStrings("", output.stderr);
    try std.testing.expect(std.mem.indexOf(u8, output.stdout, "trace_schema_version=12\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.stdout, "replay_format_version=11\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.stdout, "required_channels=checkpoint,sim_state,entity_samples,rng_stream,timing_samples\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.stdout, "result=ok\n") != null);
}
