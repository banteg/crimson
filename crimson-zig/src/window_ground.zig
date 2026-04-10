const std = @import("std");
const rl = @import("raylib");

const cz = @import("crimson_zig");
const window_assets = @import("window_assets.zig");

const runtime_bootstrap = cz.bootstrap;
const spawn_runtime = cz.spawn;

const terrain_texture_size: i32 = 1024;
const terrain_patch_size: f32 = 128.0;
const terrain_patch_overscan: i32 = 64;
const terrain_density_base: i64 = 800;
const terrain_density_overlay: i64 = 0x23;
const terrain_density_detail: i64 = 0x0F;
const terrain_density_shift: u6 = 19;
const terrain_rotation_max: u32 = 0x13A;

const terrain_clear_color = rl.Color.init(63, 56, 25, 255);
const terrain_base_tint = rl.Color.init(178, 178, 178, 230);
const terrain_overlay_tint = rl.Color.init(178, 178, 178, 230);
const terrain_detail_tint = rl.Color.init(178, 178, 178, 153);

const alpha_test_vs: [:0]const u8 =
    \\#version 330
    \\
    \\in vec3 vertexPosition;
    \\in vec2 vertexTexCoord;
    \\in vec4 vertexColor;
    \\
    \\out vec2 fragTexCoord;
    \\out vec4 fragColor;
    \\
    \\uniform mat4 mvp;
    \\
    \\void main() {
    \\    fragTexCoord = vertexTexCoord;
    \\    fragColor = vertexColor;
    \\    gl_Position = mvp * vec4(vertexPosition, 1.0);
    \\}
;

const alpha_test_fs: [:0]const u8 =
    \\#version 330
    \\
    \\in vec2 fragTexCoord;
    \\in vec4 fragColor;
    \\
    \\uniform sampler2D texture0;
    \\uniform vec4 colDiffuse;
    \\
    \\out vec4 finalColor;
    \\
    \\void main() {
    \\    vec4 texel = texture(texture0, fragTexCoord) * fragColor * colDiffuse;
    \\    if (texel.a <= 0.0156862745) discard;
    \\    finalColor = texel;
    \\}
;

pub const GroundRenderError = rl.RaylibError;

pub const TerrainTextureSet = struct {
    base: window_assets.TextureId,
    overlay: window_assets.TextureId,
    detail: window_assets.TextureId,
};

pub const GroundRenderer = struct {
    base: rl.Texture2D,
    overlay: rl.Texture2D,
    detail: rl.Texture2D,
    width: i32 = terrain_texture_size,
    height: i32 = terrain_texture_size,
    render_target: ?rl.RenderTexture2D = null,
    alpha_test_shader: ?rl.Shader = null,
    ready: bool = false,

    pub fn initForUnlockTerrain(
        runtime_assets: *const window_assets.RuntimeAssets,
        seed: u32,
        unlock_index: i32,
        width: i32,
        height: i32,
    ) GroundRenderError!GroundRenderer {
        const terrain = runtime_bootstrap.previewUnlockTerrain(seed, unlock_index, width, height);
        const texture_ids = terrainTextureSet(terrain.terrain_slots);

        var renderer: GroundRenderer = .{
            .base = runtime_assets.texture(texture_ids.base),
            .overlay = runtime_assets.texture(texture_ids.overlay),
            .detail = runtime_assets.texture(texture_ids.detail),
            .width = width,
            .height = height,
        };
        errdefer renderer.deinit();

        try renderer.ensureResources();
        try renderer.generate(terrain.terrain_seed);
        return renderer;
    }

    pub fn deinit(self: *GroundRenderer) void {
        if (self.alpha_test_shader) |shader| {
            shader.unload();
            self.alpha_test_shader = null;
        }
        if (self.render_target) |target| {
            rl.unloadRenderTexture(target);
            self.render_target = null;
        }
        self.ready = false;
        self.* = undefined;
    }

    pub fn draw(self: *const GroundRenderer) void {
        if (!self.ready) {
            rl.drawRectangle(
                0,
                0,
                self.width,
                self.height,
                terrain_clear_color,
            );
            return;
        }

        const target = self.render_target orelse return;
        const src = rl.Rectangle.init(
            0.0,
            0.0,
            @floatFromInt(target.texture.width),
            -@as(f32, @floatFromInt(target.texture.height)),
        );
        const dst = rl.Rectangle.init(
            0.0,
            0.0,
            @floatFromInt(self.width),
            @floatFromInt(self.height),
        );
        beginCustomBlend(rl.gl.rl_one, rl.gl.rl_zero, rl.gl.rl_func_add);
        defer endCustomBlend();
        rl.drawTexturePro(target.texture, src, dst, rl.Vector2.zero(), 0.0, rl.Color.white);
    }

    fn generate(self: *GroundRenderer, terrain_seed: u32) GroundRenderError!void {
        try self.ensureResources();
        const target = self.render_target orelse return;

        var rng = spawn_runtime.Crand.init(terrain_seed);
        rl.beginTextureMode(target);
        defer rl.endTextureMode();

        rl.clearBackground(terrain_clear_color);
        if (self.alpha_test_shader) |shader| {
            shader.activate();
            defer shader.deactivate();
        }

        beginTerrainRenderTargetBlend();
        defer endTerrainRenderTargetBlend();
        self.scatterTexture(self.base, terrain_base_tint, &rng, terrain_density_base);
        self.scatterTexture(self.overlay, terrain_overlay_tint, &rng, terrain_density_overlay);
        self.scatterTexture(self.detail, terrain_detail_tint, &rng, terrain_density_detail);
        self.ready = true;
    }

    fn ensureResources(self: *GroundRenderer) GroundRenderError!void {
        if (self.alpha_test_shader == null) {
            self.alpha_test_shader = try rl.loadShaderFromMemory(alpha_test_vs, alpha_test_fs);
        }

        if (self.render_target) |target| {
            if (target.texture.width == self.width and target.texture.height == self.height) {
                return;
            }
            rl.unloadRenderTexture(target);
            self.render_target = null;
        }

        const render_target = try rl.loadRenderTexture(self.width, self.height);
        rl.setTextureFilter(render_target.texture, .bilinear);
        rl.setTextureWrap(render_target.texture, .clamp);
        self.render_target = render_target;
        self.ready = false;
    }

    fn scatterTexture(
        self: *GroundRenderer,
        texture: rl.Texture2D,
        tint: rl.Color,
        rng: *spawn_runtime.Crand,
        density: i64,
    ) void {
        const area = @as(i64, self.width) * @as(i64, self.height);
        const count = (area * density) >> terrain_density_shift;
        if (count <= 0) return;

        const src = rl.Rectangle.init(
            0.0,
            0.0,
            @floatFromInt(texture.width),
            @floatFromInt(texture.height),
        );
        const origin = rl.Vector2.init(terrain_patch_size * 0.5, terrain_patch_size * 0.5);
        const span_w = self.width + terrain_patch_overscan * 2;
        const span_h = span_w;

        var idx: i64 = 0;
        while (idx < count) : (idx += 1) {
            const angle = @as(f32, @floatFromInt(rng.rand() % terrain_rotation_max)) * 0.01;
            const y = @as(f32, @floatFromInt(@as(i32, @intCast(rng.rand() % @as(u32, @intCast(span_h)))) - terrain_patch_overscan));
            const x = @as(f32, @floatFromInt(@as(i32, @intCast(rng.rand() % @as(u32, @intCast(span_w)))) - terrain_patch_overscan));
            const dst = rl.Rectangle.init(
                x + terrain_patch_size * 0.5,
                y + terrain_patch_size * 0.5,
                terrain_patch_size,
                terrain_patch_size,
            );
            rl.drawTexturePro(
                texture,
                src,
                dst,
                origin,
                radiansToDegrees(angle),
                tint,
            );
        }
    }
};

pub fn terrainTextureSet(slots: runtime_bootstrap.TerrainSlotTriplet) TerrainTextureSet {
    return .{
        .base = terrainSlotTextureId(slots[0]),
        .overlay = terrainSlotTextureId(slots[1]),
        .detail = terrainSlotTextureId(slots[2]),
    };
}

fn terrainSlotTextureId(slot: u8) window_assets.TextureId {
    return switch (slot) {
        0 => .ter_q1_base,
        1 => .ter_q1_overlay,
        2 => .ter_q2_base,
        3 => .ter_q2_overlay,
        4 => .ter_q3_base,
        5 => .ter_q3_overlay,
        6 => .ter_q4_base,
        7 => .ter_q4_overlay,
        else => .ter_q1_base,
    };
}

fn radiansToDegrees(radians: f32) f32 {
    return radians * (180.0 / std.math.pi);
}

fn beginCustomBlend(src_factor: i32, dst_factor: i32, blend_equation: i32) void {
    rl.gl.rlSetBlendFactors(src_factor, dst_factor, blend_equation);
    rl.beginBlendMode(.custom);
    rl.gl.rlSetBlendFactors(src_factor, dst_factor, blend_equation);
}

fn endCustomBlend() void {
    rl.endBlendMode();
}

fn beginTerrainRenderTargetBlend() void {
    rl.gl.rlColorMask(true, true, true, false);
    beginCustomBlend(rl.gl.rl_src_alpha, rl.gl.rl_one_minus_src_alpha, rl.gl.rl_func_add);
}

fn endTerrainRenderTargetBlend() void {
    endCustomBlend();
    rl.gl.rlColorMask(true, true, true, true);
}

test "terrain slot mapping follows python ids" {
    const set = terrainTextureSet(.{ 4, 5, 4 });
    try std.testing.expectEqual(window_assets.TextureId.ter_q3_base, set.base);
    try std.testing.expectEqual(window_assets.TextureId.ter_q3_overlay, set.overlay);
    try std.testing.expectEqual(window_assets.TextureId.ter_q3_base, set.detail);
}
