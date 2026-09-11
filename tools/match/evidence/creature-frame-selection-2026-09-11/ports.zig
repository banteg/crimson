const std = @import("std");
const app = @import("app");

const Witness = struct {
    type_id: i32,
    flags: u32,
    lifecycle_stage: f32,
    phase: f32,
};

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    const args = try init.minimal.args.toSlice(allocator);
    if (args.len != 2) return error.ExpectedWitnessFile;
    const bytes = try std.Io.Dir.cwd().readFileAlloc(init.io, args[1], allocator, .limited(4 * 1024 * 1024));
    const parsed = try std.json.parseFromSlice(struct { witnesses: []const Witness }, allocator, bytes, .{ .ignore_unknown_fields = true });
    var buffer: [4096]u8 = undefined;
    var file_writer = std.Io.File.stdout().writer(init.io, &buffer);
    const writer = &file_writer.interface;
    for (parsed.value.witnesses) |witness| {
        const creature: app.creatures.CreatureState = .{
            .active = true,
            .type_id = witness.type_id,
            .flags = witness.flags,
            .lifecycle_stage = witness.lifecycle_stage,
            .anim_phase = witness.phase,
        };
        const frame = app.window_atlas.creatureRenderFrame(creature) orelse return error.UnknownCreatureType;
        try writer.print("{d}\n", .{frame.frame});
        // Preserve the completed prefix if the old implementation panics.
        try writer.flush();
    }
}
