const std = @import("std");
const rl = @import("raylib");

const window_assets = @import("window_assets.zig");
const window_ui = @import("window_ui.zig");

pub const splash_alpha_scale: f32 = 2.0;
pub const logo_time_scale: f32 = 1.1;
pub const logo_time_offset: f32 = 2.0;
pub const logo_skip_accel: f32 = 4.0;
pub const logo_skip_jump: f32 = 16.0;
pub const logo_theme_trigger: f32 = 14.0;
pub const logo_10_in_start: f32 = 1.0;
pub const logo_10_in_end: f32 = 2.0;
pub const logo_10_hold_end: f32 = 4.0;
pub const logo_10_out_end: f32 = 5.0;
pub const logo_ref_in_start: f32 = 7.0;
pub const logo_ref_in_end: f32 = 8.0;
pub const logo_ref_hold_end: f32 = 10.0;
pub const logo_ref_out_end: f32 = 11.0;

pub const State = struct {
    boot_time: f32 = 0.5,
    fade_out_ready: bool = true,
    fade_out_done: bool = false,
    logo_delay_ticks: i32 = 0,
    logo_skip: bool = false,
    logo_active: bool = false,

    pub fn reset(self: *State) void {
        self.* = .{};
    }
};

pub const UpdateResult = struct {
    finished: bool = false,
};

pub fn update(state: *State, frame_dt: f32) UpdateResult {
    const dt = @min(frame_dt, 0.1);
    if (!state.fade_out_done) {
        state.boot_time -= dt;
        if (state.boot_time <= 0.0) {
            state.boot_time = 0.0;
            state.fade_out_done = true;
        }
        return .{};
    }

    if (state.logo_delay_ticks < 5) {
        state.logo_delay_ticks += 1;
        return .{};
    }

    state.logo_active = true;
    if (state.boot_time > logo_theme_trigger) {
        return .{ .finished = true };
    }
    if (!state.logo_skip and skipTriggered()) {
        state.logo_skip = true;
    }
    state.boot_time += dt * logo_time_scale;
    var t = state.boot_time - logo_time_offset;
    if (state.logo_skip) {
        if (t < logo_10_in_start or (t >= logo_10_out_end and (t < logo_ref_in_start or t >= logo_ref_out_end))) {
            t = logo_skip_jump;
        } else {
            t += dt * logo_skip_accel;
        }
        state.boot_time = t + logo_time_offset;
    }
    return .{};
}

pub fn draw(state: *const State, runtime_assets: ?*const window_assets.RuntimeAssets) void {
    rl.clearBackground(rl.Color.black);
    if (runtime_assets) |assets| {
        if (!state.fade_out_done) {
            drawSplash(assets, clamp01(state.boot_time * splash_alpha_scale));
        } else if (state.logo_active) {
            drawCompanyLogo(assets, state.boot_time - logo_time_offset);
        }
    }
}

fn clamp01(value: f32) f32 {
    return std.math.clamp(value, @as(f32, 0.0), @as(f32, 1.0));
}

fn skipTriggered() bool {
    if (rl.getKeyPressed() != .null) return true;
    if (rl.isMouseButtonPressed(.left)) return true;
    if (rl.isMouseButtonPressed(.right)) return true;
    return false;
}

fn logoAlpha(t: f32, in_start: f32, in_end: f32, hold_end: f32, out_end: f32) ?f32 {
    if (t < in_start or t >= out_end) return null;
    if (t < in_end) return clamp01(t - in_start);
    if (t < hold_end) return 1.0;
    return clamp01(1.0 - (t - hold_end));
}

fn drawCompanyLogo(runtime_assets: *const window_assets.RuntimeAssets, t: f32) void {
    const LogoState = struct {
        texture: rl.Texture2D,
        alpha: f32,
    };
    const logo_state: LogoState = blk: {
        if (logoAlpha(t, logo_10_in_start, logo_10_in_end, logo_10_hold_end, logo_10_out_end)) |alpha| {
            break :blk .{ .texture = runtime_assets.texture(.splash_10tons), .alpha = alpha };
        }
        if (logoAlpha(t, logo_ref_in_start, logo_ref_in_end, logo_ref_hold_end, logo_ref_out_end)) |alpha| {
            break :blk .{ .texture = runtime_assets.texture(.splash_reflexive), .alpha = alpha };
        }
        return;
    };

    const texture = logo_state.texture;
    const x = (@as(f32, @floatFromInt(rl.getScreenWidth())) - @as(f32, @floatFromInt(texture.width))) * 0.5;
    const y = (@as(f32, @floatFromInt(rl.getScreenHeight())) - @as(f32, @floatFromInt(texture.height))) * 0.5;
    window_ui.drawTextureFit(
        texture,
        rl.Rectangle.init(x, y, @floatFromInt(texture.width), @floatFromInt(texture.height)),
        window_ui.colorWithAlpha(rl.Color.white, logo_state.alpha),
    );
}

fn drawSplash(runtime_assets: *const window_assets.RuntimeAssets, alpha: f32) void {
    if (!(alpha > 0.0)) return;
    const screen_w = @as(f32, @floatFromInt(rl.getScreenWidth()));
    const screen_h = @as(f32, @floatFromInt(rl.getScreenHeight()));
    const logo = runtime_assets.texture(.cl_logo);
    const band_height = @as(f32, @floatFromInt(logo.height)) * 2.0;
    const band_top = (screen_h - band_height) * 0.5 - 4.0;
    const band_bottom = band_top + band_height;
    const line_color = window_ui.colorWithAlpha(rl.Color.init(149, 175, 198, 255), alpha * 0.7);
    rl.drawRectangle(0, @intFromFloat(band_top), rl.getScreenWidth(), 1, line_color);
    rl.drawRectangle(0, @intFromFloat(band_bottom), rl.getScreenWidth(), 1, line_color);
    rl.drawRectangle(0, @intFromFloat(band_top), 1, @intFromFloat(band_height), line_color);
    rl.drawRectangle(rl.getScreenWidth() - 1, @intFromFloat(band_top), 1, @intFromFloat(band_height), line_color);

    const logo_x = (screen_w - @as(f32, @floatFromInt(logo.width))) * 0.5;
    const logo_y = (screen_h - @as(f32, @floatFromInt(logo.height))) * 0.5;
    window_ui.drawTextureFit(logo, rl.Rectangle.init(logo_x, logo_y, @floatFromInt(logo.width), @floatFromInt(logo.height)), window_ui.colorWithAlpha(rl.Color.white, alpha));
    const loading = runtime_assets.texture(.loading);
    window_ui.drawTextureFit(loading, rl.Rectangle.init(screen_w * 0.5 + 128.0, screen_h * 0.5 + 16.0, @floatFromInt(loading.width), @floatFromInt(loading.height)), window_ui.colorWithAlpha(rl.Color.white, alpha));
    const esrb = runtime_assets.texture(.logo_esrb);
    window_ui.drawTextureFit(esrb, rl.Rectangle.init(screen_w - @as(f32, @floatFromInt(esrb.width)) - 1.0, screen_h - @as(f32, @floatFromInt(esrb.height)) - 1.0, @floatFromInt(esrb.width), @floatFromInt(esrb.height)), window_ui.colorWithAlpha(rl.Color.white, alpha));
}
