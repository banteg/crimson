const std = @import("std");
const app = @import("app");

const Witness = struct {
    position_x: f32,
    position_y: f32,
    heading: f32,
};
const Sampler = struct {
    pub fn codeIsDown(_: Sampler, _: i32, _: i32) bool {
        return false;
    }
    pub fn codeIsPressed(_: Sampler, _: i32, _: i32) bool {
        return false;
    }
    pub fn axisValue(_: Sampler, _: i32, _: i32) f32 {
        return 0.0;
    }
};

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    const args = try init.minimal.args.toSlice(allocator);
    if (args.len != 2) return error.ExpectedWitnessFile;
    const bytes = try std.Io.Dir.cwd().readFileAlloc(init.io, args[1], allocator, .limited(4 * 1024 * 1024));
    const parsed = try std.json.parseFromSlice(struct { witnesses: []const Witness }, allocator, bytes, .{ .ignore_unknown_fields = true });
    var cfg = app.formats.crimson_cfg.defaultConfig();
    cfg.aim_schemes[0] = @bitCast(app.local_input.aim_scheme_joystick);
    cfg.movement_schemes[0] = @intCast(app.local_input.movement_control_static);
    const creatures = [_]struct { active: bool, hp: f32, pos: app.state.Vec2 }{
        .{ .active = false, .hp = 0.0, .pos = .{} },
    };
    var buffer: [4096]u8 = undefined;
    var file_writer = std.Io.File.stdout().writer(init.io, &buffer);
    const writer = &file_writer.interface;
    for (parsed.value.witnesses) |witness| {
        var interpreter: app.local_input.LocalInputInterpreter = .{};
        interpreter.states[0].aim_heading = witness.heading;
        const player: app.state.PlayerState = .{
            .index = 0,
            .pos = .{ .x = witness.position_x, .y = witness.position_y },
            .aim_heading = witness.heading,
        };
        const result = interpreter.buildPlayerInput(Sampler{}, 0, 1, &player, &cfg, .{}, .{}, .{}, 0.0, creatures[0..]);
        try writer.print("{d} {d}\n", .{ @as(u32, @bitCast(result.aim_x)), @as(u32, @bitCast(result.aim_y)) });
    }
    try writer.flush();
}
