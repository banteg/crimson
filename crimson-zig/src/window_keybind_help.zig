const std = @import("std");
const rl = @import("raylib");

const cz = @import("crimson_zig");
const input_codes = @import("input_codes.zig");
const window_assets = @import("window_assets.zig");
const window_ui = @import("window_ui.zig");

const crimson_cfg = cz.formats.crimson_cfg;

/// Native `game_paused_flag` and `pause_keybind_help_alpha_ms` of `gameplay_update_and_render`.
pub const State = struct {
    paused: bool = false,
    alpha_ms: i32 = 0,

    /// F1 toggles the pause; the key info fades in at twice and out at four times the frame.
    pub fn update(self: *State, toggle_pressed: bool, frame_dt_ms: i32) void {
        if (toggle_pressed) self.paused = !self.paused;
        const step = if (self.paused) frame_dt_ms * 2 else -frame_dt_ms * 4;
        self.alpha_ms = std.math.clamp(self.alpha_ms + step, 0, 1000);
    }
};

/// `grim_draw_rect_outline`: four 1px quads, the bottom one a pixel wider.
fn drawRectOutline(x: f32, y: f32, width: f32, height: f32, color: rl.Color) void {
    rl.drawRectangleRec(rl.Rectangle.init(x, y, width, 1.0), color);
    rl.drawRectangleRec(rl.Rectangle.init(x, y, 1.0, height), color);
    rl.drawRectangleRec(rl.Rectangle.init(x, y + height, width + 1.0, 1.0), color);
    rl.drawRectangleRec(rl.Rectangle.init(x + width, y, 1.0, height), color);
}

/// `ui_render_keybind_help`: the key info panel the F1 pause shows, centred on the screen.
pub fn draw(assets: *const window_assets.RuntimeAssets, config: *const crimson_cfg.CrimsonCfg, state: *const State) void {
    if (state.alpha_ms <= 0) return;
    const alpha = @as(f32, @floatFromInt(state.alpha_ms)) * 0.001;
    const origin_x = @as(f32, @floatFromInt(rl.getScreenWidth())) * 0.5 - 256.0;
    const origin_y = @as(f32, @floatFromInt(rl.getScreenHeight())) * 0.5 - 128.0;

    rl.drawRectangleRec(rl.Rectangle.init(origin_x, origin_y, 512.0, 256.0), window_ui.colorWithAlpha(rl.Color.black, alpha * 0.8));
    const color = window_ui.colorWithAlpha(rl.Color.white, alpha);
    drawRectOutline(origin_x, origin_y, 512.0, 256.0, color);
    window_ui.drawGrimMonoText(assets, "key info", origin_x + 16.0, origin_y + 16.0, 0.8, color);

    var x = origin_x + 32.0;
    var y = origin_y + 50.0;
    window_ui.drawSmallText(assets, "Level Up:", x, y, color);
    const value_x = x + 128.0;
    window_ui.drawSmallTextFmt("{s} or SPACE BAR or KeyPadAdd", assets, .{input_codes.inputCodeName(@bitCast(config.keybind_pick_perk))}, value_x, y, color);
    y += 18.0;
    window_ui.drawSmallText(assets, "Reload:", x, y, color);
    window_ui.drawSmallText(assets, input_codes.inputCodeName(@bitCast(config.keybind_reload)), value_x, y, color);
    y += 18.0;
    y += 20.0;
    for (0..2) |player| {
        if (player == 1) x += 256.0;
        window_ui.drawSmallTextFmt("Player {d}", assets, .{player + 1}, x, y, color);
        const binds = crimson_cfg.playerBindBlock(config, player);
        y += 22.0;
        const rows = [_]struct { label: []const u8, code: i32 }{
            .{ .label = "Up:", .code = binds.move_forward },
            .{ .label = "Down:", .code = binds.move_backward },
            .{ .label = "Left:", .code = binds.turn_left },
            .{ .label = "Right:", .code = binds.turn_right },
            .{ .label = "Fire:", .code = binds.fire },
        };
        for (rows, 0..) |row, index| {
            if (index != 0) y += 16.0;
            window_ui.drawSmallText(assets, row.label, x, y, color);
            window_ui.drawSmallText(assets, input_codes.inputCodeName(row.code), x + 64.0, y, color);
        }
        if (player == 0) y -= 94.0;
    }
    window_ui.drawSmallText(assets, "Press F1 to return to game", x - 20.0, y + 32.0, color);
}

test "key info fades in at twice and out at four times the frame while F1 toggles the pause" {
    var state: State = .{};
    state.update(true, 100);
    try std.testing.expect(state.paused);
    try std.testing.expectEqual(@as(i32, 200), state.alpha_ms);
    for (0..10) |_| state.update(false, 100);
    try std.testing.expectEqual(@as(i32, 1000), state.alpha_ms);
    state.update(true, 100);
    try std.testing.expect(!state.paused);
    try std.testing.expectEqual(@as(i32, 600), state.alpha_ms);
    state.update(false, 200);
    try std.testing.expectEqual(@as(i32, 0), state.alpha_ms);
}
