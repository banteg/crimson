const std = @import("std");
const crimson_zig = @import("crimson_zig");

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const output = try crimson_zig.net.relay_udp_server.runRelayServe(allocator, init.io, args[1..]);
    defer output.deinit(allocator);

    try writeAll(init.io, std.Io.File.stdout(), output.stdout);
    try writeAll(init.io, std.Io.File.stderr(), output.stderr);
    if (output.exit_code != 0) std.process.exit(output.exit_code);
}

fn writeAll(io: std.Io, file: std.Io.File, bytes: []const u8) !void {
    var buffer: [4096]u8 = undefined;
    var writer = file.writer(io, &buffer);
    try writer.interface.writeAll(bytes);
    try writer.interface.flush();
}
