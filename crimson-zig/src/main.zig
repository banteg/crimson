const std = @import("std");
const crimson_zig = @import("crimson_zig");

pub fn main() !void {
    var gpa_state: std.heap.GeneralPurposeAllocator(.{}) = .{};
    defer _ = gpa_state.deinit();
    const allocator = gpa_state.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    const code = crimson_zig.cli.run(allocator, args) catch |err| {
        var buffer: [4096]u8 = undefined;
        var writer = std.fs.File.stderr().writer(&buffer);
        const stderr = &writer.interface;
        try stderr.print("crimson-zig: {s}\n", .{@errorName(err)});
        try stderr.flush();
        std.process.exit(1);
    };

    if (code != 0) {
        std.process.exit(code);
    }
}
