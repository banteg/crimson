const std = @import("std");
const crimson_zig = @import("crimson_zig");
const runtime_paths = crimson_zig.runtime_paths;

pub fn main(init: std.process.Init) !void {
    runtime_paths.useEnviron(init.environ_map);
    const allocator = init.gpa;
    const args = try init.minimal.args.toSlice(init.arena.allocator());

    const code = crimson_zig.cli.run(allocator, args) catch |err| {
        var buffer: [4096]u8 = undefined;
        var writer = std.Io.File.stderr().writer(std.Io.Threaded.global_single_threaded.io(), &buffer);
        const stderr = &writer.interface;
        try stderr.print("crimson-zig: {s}\n", .{@errorName(err)});
        try stderr.flush();
        std.process.exit(1);
    };

    if (code != 0) {
        std.process.exit(code);
    }
}
