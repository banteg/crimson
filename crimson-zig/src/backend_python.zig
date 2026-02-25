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
    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(allocator);

    try argv.append(allocator, "uv");
    try argv.append(allocator, "run");
    try argv.append(allocator, "crimson");
    try argv.append(allocator, "replay");
    try argv.append(allocator, "verify");
    try argv.appendSlice(allocator, verify_args);

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
