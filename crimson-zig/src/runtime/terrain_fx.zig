const rng_callers = @import("../rng_caller_static.zig");
const native_math = @import("native_math.zig");

const state_mod = @import("state.zig");

pub const fx_queue_capacity: usize = 0x80;
pub const fx_queue_max_count: usize = 0x7F;
pub const fx_queue_rotated_capacity: usize = 0x40;
pub const fx_queue_rotated_max_count: usize = 0x3F;

pub const Color = struct {
    r: f32 = 1.0,
    g: f32 = 1.0,
    b: f32 = 1.0,
    a: f32 = 1.0,
};

pub const TerrainDecalFx = struct {
    effect_id: i32 = 0,
    rotation: f32 = 0.0,
    pos: state_mod.Vec2 = .{},
    width: f32 = 0.0,
    height: f32 = 0.0,
    color: Color = .{},
};

pub const TerrainCorpseFx = struct {
    top_left: state_mod.Vec2 = .{},
    color: Color = .{},
    rotation: f32 = 0.0,
    scale: f32 = 1.0,
    creature_type_id: i32 = 0,
};

pub const TerrainFxBatch = struct {
    decals: [fx_queue_max_count]TerrainDecalFx = undefined,
    decal_count: usize = 0,
    corpses: [fx_queue_rotated_max_count]TerrainCorpseFx = undefined,
    corpse_count: usize = 0,

    pub fn isEmpty(self: *const TerrainFxBatch) bool {
        return self.decal_count == 0 and self.corpse_count == 0;
    }

    pub fn decalsSlice(self: *const TerrainFxBatch) []const TerrainDecalFx {
        return self.decals[0..self.decal_count];
    }

    pub fn corpsesSlice(self: *const TerrainFxBatch) []const TerrainCorpseFx {
        return self.corpses[0..self.corpse_count];
    }
};

pub const FxQueue = struct {
    entries: [fx_queue_capacity]TerrainDecalFx = undefined,
    count: usize = 0,

    pub fn clear(self: *FxQueue) void {
        self.count = 0;
    }

    pub fn add(
        self: *FxQueue,
        effect_id: i32,
        pos: state_mod.Vec2,
        width: f32,
        height: f32,
        rotation: f32,
        color: Color,
    ) bool {
        if (self.count >= fx_queue_max_count) return false;
        self.entries[self.count] = .{
            .effect_id = effect_id,
            .rotation = rotation,
            .pos = pos,
            .width = width,
            .height = height,
            .color = color,
        };
        self.count += 1;
        return true;
    }

    pub fn addRandom(self: *FxQueue, state: *state_mod.GameplayState, pos: state_mod.Vec2) bool {
        if (state.gore_disabled != 0) return false;
        const gray = @as(f32, @floatFromInt(state.rng.randTagged(rng_callers.fx_queue_add_random_gray) & 0xF)) * 0.01 + 0.84;
        const width = @as(f32, @floatFromInt(state.rng.randTagged(rng_callers.fx_queue_add_random_width) % 24)) - 12.0 + 30.0;
        const rotation = @as(f32, @floatFromInt(state.rng.randTagged(rng_callers.fx_queue_add_random_rotation) % 628)) * 0.01;
        const effect_id = @as(i32, @intCast(state.rng.randTagged(rng_callers.fx_queue_add_random_effect_id) % 5)) + 3;
        return self.add(
            effect_id,
            pos,
            width,
            width,
            rotation,
            // Native keeps the statically initialized alpha (0x3f47ae14).
            .{ .r = gray, .g = gray, .b = gray, .a = 0.7799999713897705 },
        );
    }
};

pub const FxQueueRotated = struct {
    entries: [fx_queue_rotated_capacity]TerrainCorpseFx = undefined,
    count: usize = 0,

    pub const Options = struct {
        terrain_bodies_transparency: f32 = 0.0,
        terrain_texture_failed: bool = false,
    };

    pub fn clear(self: *FxQueueRotated) void {
        self.count = 0;
    }

    pub fn add(
        self: *FxQueueRotated,
        top_left: state_mod.Vec2,
        color: Color,
        rotation: f32,
        scale: f32,
        creature_type_id: i32,
    ) bool {
        return self.addWithOptions(top_left, color, rotation, scale, creature_type_id, .{});
    }

    pub fn addWithOptions(
        self: *FxQueueRotated,
        top_left: state_mod.Vec2,
        color: Color,
        rotation: f32,
        scale: f32,
        creature_type_id: i32,
        options: Options,
    ) bool {
        // Native reports success without allocating when the terrain texture failed.
        if (options.terrain_texture_failed) return true;
        if (self.count >= fx_queue_rotated_max_count) return false;
        const alpha_scale = if (options.terrain_bodies_transparency == 0.0)
            0.8
        else
            native_math.pc24Div(1.0, options.terrain_bodies_transparency);
        return self.append(.{
            .top_left = top_left,
            .color = .{ .r = color.r, .g = color.g, .b = color.b, .a = native_math.pc24Mul(color.a, alpha_scale) },
            .rotation = rotation,
            .scale = scale,
            .creature_type_id = creature_type_id,
        });
    }

    /// Merge an already adjusted entry into a presentation batch.
    pub fn append(self: *FxQueueRotated, entry: TerrainCorpseFx) bool {
        if (self.count >= fx_queue_rotated_max_count) return false;
        self.entries[self.count] = entry;
        self.count += 1;
        return true;
    }
};

pub const TerrainFxScratch = struct {
    decals: FxQueue = .{},
    corpses: FxQueueRotated = .{},

    pub fn clear(self: *TerrainFxScratch) void {
        self.decals.clear();
        self.corpses.clear();
    }

    pub fn takeBatch(self: *TerrainFxScratch) TerrainFxBatch {
        var batch: TerrainFxBatch = .{};
        for (self.decals.entries[0..self.decals.count], 0..) |entry, idx| {
            batch.decals[idx] = entry;
        }
        batch.decal_count = self.decals.count;
        for (self.corpses.entries[0..self.corpses.count], 0..) |entry, idx| {
            batch.corpses[idx] = entry;
        }
        batch.corpse_count = self.corpses.count;
        self.clear();
        return batch;
    }
};

test "corpse queue matches native alpha capacity and texture failure witnesses" {
    const std = @import("std");
    const Entry = struct { pos_bits: [2]u32, color_bits: [4]u32, rotation_bits: u32, scale_bits: u32, type_id: i32 };
    const Case = struct {
        input: struct { count: usize, failed: u8, transparency: f32, pos: [2]f32, color: [4]f32, rotation: f32, scale: f32, type_id: i32 },
        expected: struct { @"return": u8, count: usize, entry: ?Entry },
    };
    const parsed = try std.json.parseFromSlice(struct { queue: []Case }, std.testing.allocator, @embedFile("testdata/corpse-queue.json"), .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    try std.testing.expectEqual(@as(usize, 240), parsed.value.queue.len);
    for (parsed.value.queue) |case| {
        const row = case.input;
        const sentinel: TerrainCorpseFx = .{ .top_left = .{ .x = 9, .y = -3 }, .color = .{ .r = 0.2, .g = 0.3, .b = 0.4, .a = 0.5 }, .rotation = 1, .scale = 3, .creature_type_id = 2 };
        var queue: FxQueueRotated = .{ .entries = [_]TerrainCorpseFx{sentinel} ** fx_queue_rotated_capacity, .count = row.count };
        const accepted = queue.addWithOptions(.{ .x = row.pos[0], .y = row.pos[1] }, .{ .r = row.color[0], .g = row.color[1], .b = row.color[2], .a = row.color[3] }, row.rotation, row.scale, row.type_id, .{ .terrain_bodies_transparency = row.transparency, .terrain_texture_failed = row.failed != 0 });
        try std.testing.expectEqual(case.expected.@"return" != 0, accepted);
        try std.testing.expectEqual(case.expected.count, queue.count);
        for (queue.entries, 0..) |entry, index| {
            if (case.expected.entry != null and index == row.count) {
                const expected = case.expected.entry.?;
                const actual: Entry = .{
                    .pos_bits = .{ @bitCast(entry.top_left.x), @bitCast(entry.top_left.y) },
                    .color_bits = .{ @bitCast(entry.color.r), @bitCast(entry.color.g), @bitCast(entry.color.b), @bitCast(entry.color.a) },
                    .rotation_bits = @bitCast(entry.rotation),
                    .scale_bits = @bitCast(entry.scale),
                    .type_id = entry.creature_type_id,
                };
                try std.testing.expectEqual(expected, actual);
            } else {
                try std.testing.expectEqual(sentinel, entry);
            }
        }
    }
}
