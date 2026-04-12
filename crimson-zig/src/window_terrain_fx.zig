const rl = @import("raylib");

const cz = @import("crimson_zig");
const window_assets = @import("window_assets.zig");
const window_atlas = cz.window_atlas;
const window_ground = @import("window_ground.zig");

const runtime_anim = cz.anim;
const terrain_fx_mod = cz.terrain_fx;

pub fn bakeTerrainFxBatch(
    ground: *window_ground.GroundRenderer,
    batch: *const terrain_fx_mod.TerrainFxBatch,
    assets: *const window_assets.RuntimeAssets,
) bool {
    if (batch.isEmpty()) return true;

    var decals: [terrain_fx_mod.fx_queue_max_count]window_ground.GroundDecal = undefined;
    var decal_count: usize = 0;
    const particles = assets.texture(.particles);
    for (batch.decalsSlice()) |entry| {
        const src = window_atlas.effectRectById(particles.width, particles.height, entry.effect_id) orelse continue;
        decals[decal_count] = .{
            .texture = particles,
            .src = src,
            .pos = .{ .x = entry.pos.x, .y = entry.pos.y },
            .width = entry.width,
            .height = entry.height,
            .rotation_rad = entry.rotation,
            .tint = rlColor(entry.color),
        };
        decal_count += 1;
    }

    var corpses: [terrain_fx_mod.fx_queue_rotated_max_count]window_ground.GroundCorpseDecal = undefined;
    var corpse_count: usize = 0;
    for (batch.corpsesSlice()) |entry| {
        corpses[corpse_count] = .{
            .bodyset_frame = runtime_anim.creatureCorpseFrameForType(entry.creature_type_id),
            .top_left = .{ .x = entry.top_left.x, .y = entry.top_left.y },
            .size = entry.scale,
            .rotation_rad = entry.rotation,
            .tint = rlColor(entry.color),
        };
        corpse_count += 1;
    }

    const decals_ok = if (decal_count > 0) ground.bakeDecals(decals[0..decal_count]) else true;
    const corpses_ok = if (corpse_count > 0) ground.bakeCorpseDecals(assets.texture(.bodyset), corpses[0..corpse_count]) else true;
    return decals_ok and corpses_ok;
}

fn rlColor(color: terrain_fx_mod.Color) rl.Color {
    return rl.Color.init(
        floatByte(color.r),
        floatByte(color.g),
        floatByte(color.b),
        floatByte(color.a),
    );
}

fn floatByte(value: f32) u8 {
    return @intFromFloat(@min(@max(value, 0.0), 1.0) * 255.0 + 0.5);
}
