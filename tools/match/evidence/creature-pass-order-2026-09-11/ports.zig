// The verifier appends unchanged production rendering functions to this observer.
const std = @import("std");
const app = @import("app");
const window_atlas = app.window_atlas;
const runtime_anim = app.anim;
const runtime_perks = app.perks;
const state_mod = app.state;

const TextureKind = enum(i32) { zombie = 0, lizard = 1, alien = 2, spider_sp1 = 3, spider_sp2 = 4, trooper = 5 };
const rl = struct {
    const Vector2 = struct { x: f32, y: f32 };
    const Texture2D = struct { width: i32, height: i32, kind: TextureKind };
    const Color = struct {
        r: u8,
        g: u8,
        b: u8,
        a: u8,
        const black = init(0, 0, 0, 255);
        fn init(r: u8, g: u8, b: u8, a: u8) Color {
            return .{ .r = r, .g = g, .b = b, .a = a };
        }
    };
    fn beginBlendMode(_: enum { additive }) void {
        std.debug.assert(!additive);
        additive = true;
    }
    fn endBlendMode() void {
        std.debug.assert(additive);
        additive = false;
    }
    fn drawCircleV(_: Vector2, _: f32, _: Color) void {
        @panic("unexpected missing-texture fallback");
    }
};
const creature_color = rl.Color.init(219, 62, 62, 255);
const corpse_color = rl.Color.init(108, 45, 45, 255);
const live_runner = struct {
    // Only the state read by the extracted draw functions is bound here.
    const LiveRunner = struct {
        session: struct {
            creatures: struct { entries: [384]app.creatures.CreatureState = @splat(.{}) } = .{},
            state: struct { bonuses: struct { energizer: f32 = 0 } = .{} } = .{},
            gore_disabled: i32 = 0,
        } = .{},
        player: state_mod.PlayerState = .{ .index = 0, .pos = .{} },
        fn player0Const(self: *const LiveRunner) ?*const state_mod.PlayerState {
            return &self.player;
        }
    };
};
const window_assets = struct {
    const RuntimeAssets = struct {
        fn texture(_: *const RuntimeAssets, kind: TextureKind) rl.Texture2D {
            return .{ .width = texture_size, .height = texture_size, .kind = kind };
        }
    };
};
const InputCreature = struct {
    index: usize,
    type_id: i32,
    active: i32,
    size: f32,
    pos_x: f32,
    pos_y: f32,
    heading: f32,
    anim_phase: f32,
    flags: u32,
    lifecycle_stage: f32,
    hit_flash_timer: f32,
    max_health: f32,
    tint_r: f32,
    tint_g: f32,
    tint_b: f32,
    tint_a: f32,
};
const Case = struct { input: struct {
    creatures: []const InputCreature,
    shadows: i32,
    monster_vision: i32,
    flash: i32,
    energizer: f32,
    transition: f32,
} };
var additive = false;
var texture_size: i32 = 512;
var case_index: usize = 0;
var current_creatures: []const InputCreature = &.{};
var output: *std.Io.Writer = undefined;

fn drawTextureRegionCenteredRotated(
    texture: rl.Texture2D,
    src: window_atlas.AtlasRect,
    center: rl.Vector2,
    width: f32,
    height: f32,
    _: f32,
    tint: rl.Color,
) void {
    const kind = @intFromEnum(texture.kind);
    var distance: f32 = std.math.inf(f32);
    var index: usize = 999;
    for (current_creatures) |creature| {
        if (creature.active == 0 or creature.type_id != kind) continue;
        const difference = @abs(creature.pos_x - center.x);
        if (difference < distance) {
            distance = difference;
            index = creature.index;
        }
    }
    std.debug.assert(distance < 8.0);
    const pass = if (additive) "flash" else if (tint.r == 0 and tint.g == 0 and tint.b == 0) "shadow" else "body";
    const cell = @as(f32, @floatFromInt(texture.width)) / 8.0;
    const frame: i32 = @as(i32, @intFromFloat(src.x / cell)) + @as(i32, @intFromFloat(src.y / cell)) * 8;
    output.print("{d} {s} {d} {d} {d} {d} {d}\n", .{ case_index, pass, index, kind, frame, width, height }) catch unreachable;
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    const args = try init.minimal.args.toSlice(allocator);
    if (args.len != 3) return error.ExpectedWitnessFileAndTextureSize;
    texture_size = try std.fmt.parseInt(i32, args[2], 10);
    const bytes = try std.Io.Dir.cwd().readFileAlloc(init.io, args[1], allocator, .limited(4 * 1024 * 1024));
    const parsed = try std.json.parseFromSlice(struct { cases: []const Case }, allocator, bytes, .{ .ignore_unknown_fields = true });
    var buffer: [4096]u8 = undefined;
    var file_writer = std.Io.File.stdout().writer(init.io, &buffer);
    output = &file_writer.interface;
    const assets: window_assets.RuntimeAssets = .{};
    for (parsed.value.cases, 0..) |case, ordinal| {
        case_index = ordinal;
        current_creatures = case.input.creatures;
        var runner: live_runner.LiveRunner = .{};
        runner.player.perk_counts.set(.monster_vision, case.input.monster_vision);
        runner.session.gore_disabled = case.input.flash;
        runner.session.state.bonuses.energizer = case.input.energizer;
        for (case.input.creatures) |creature| {
            runner.session.creatures.entries[creature.index] = .{
                .active = creature.active != 0,
                .type_id = creature.type_id,
                .pos = .{ .x = creature.pos_x, .y = creature.pos_y },
                .size = creature.size,
                .flags = creature.flags,
                .lifecycle_stage = creature.lifecycle_stage,
                .heading = creature.heading,
                .anim_phase = creature.anim_phase,
                .hit_flash_timer = creature.hit_flash_timer,
                .hp = 100.0,
                .max_hp = creature.max_health,
                .tint = .{ creature.tint_r, creature.tint_g, creature.tint_b, creature.tint_a },
            };
        }
        drawCreatures(&runner, &assets, case.input.transition, case.input.shadows != 0);
        std.debug.assert(!additive);
    }
    try output.flush();
}
