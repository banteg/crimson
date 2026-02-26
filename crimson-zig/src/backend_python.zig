const std = @import("std");

pub const CommandOutput = struct {
    stdout: []u8,
    stderr: []u8,
    exit_code: u8,

    pub fn deinit(self: CommandOutput, allocator: std.mem.Allocator) void {
        allocator.free(self.stdout);
        allocator.free(self.stderr);
    }
};

pub fn runReplayVerifyPassthrough(
    allocator: std.mem.Allocator,
    verify_args: []const []const u8,
) !CommandOutput {
    var argv = try std.ArrayList([]const u8).initCapacity(allocator, 5 + verify_args.len);
    defer argv.deinit(allocator);

    argv.appendAssumeCapacity("uv");
    argv.appendAssumeCapacity("run");
    argv.appendAssumeCapacity("crimson");
    argv.appendAssumeCapacity("replay");
    argv.appendAssumeCapacity("verify");
    argv.appendSliceAssumeCapacity(verify_args);

    const result = try std.process.Child.run(.{
        .allocator = allocator,
        .argv = argv.items,
        .max_output_bytes = 64 * 1024 * 1024,
    });

    return .{
        .stdout = result.stdout,
        .stderr = result.stderr,
        .exit_code = termToExitCode(result.term),
    };
}

fn termToExitCode(term: std.process.Child.Term) u8 {
    return switch (term) {
        .Exited => |code| @intCast(@min(code, 255)),
        .Signal => 1,
        .Stopped => 1,
        .Unknown => 1,
    };
}
