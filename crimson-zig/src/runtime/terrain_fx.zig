const rng_callers = @import("../rng_caller_static.zig");

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
        if (self.count >= fx_queue_rotated_max_count) return false;
        self.entries[self.count] = .{
            .top_left = top_left,
            .color = .{
                .r = color.r,
                .g = color.g,
                .b = color.b,
                .a = color.a,
            },
            .rotation = rotation,
            .scale = scale,
            .creature_type_id = creature_type_id,
        };
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
