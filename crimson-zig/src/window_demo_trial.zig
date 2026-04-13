const std = @import("std");
const rl = @import("raylib");

const cz = @import("crimson_zig");

const demo_trial = cz.demo_trial;
const window_assets = @import("window_assets.zig");
const window_cursor = @import("window_cursor.zig");
const window_ui = @import("window_ui.zig");

pub const demo_purchase_url = "http://buy.crimsonland.com";

const demo_header_text = "You've been playing the Demo version of";
const quest_completed_text = "You've completed all Quest mode levels available in the Demo version.";
const quest_limit_remaining_text = "However, you still have {s} time left to play Survival and Rush game modes.";
const quest_grace_used_up_text = "You have used up your play time in this game mode. However, you still";
const quest_grace_remaining_text = "have {s} time left to play Quest mode levels only.";
const upgrade_all_features_text = "If you would like to have unlimited play time and access to all features,";
const upgrade_features_line_text = "The full version features unrestricted access to all 3";
const upgrade_buy_full_text = "Buy the full version to gain unrestricted access to all 3";
const upgrade_buy_line_text = "game modes and be able to post your scores on the Internet. Why not buy";
const upgrade_trailer_text = "it now? You'll have a great time!";
const upgrade_please_text = "please upgrade to the full version of Crimsonland.";
const upgrade_process_text = "please upgrade to the full version of Crimsonland.  The process is very easy";
const upgrade_process_cont_text = "and takes just minutes. ";
const upgrade_easy_text = "is very easy and takes just minutes.";
const time_up_text = "Trial time is up. If you would like to have unlimited play time and access to";
const time_up_all_features_text = "all features, please upgrade to the full version of Crimsonland.  The process";

pub const Action = enum {
    none,
    purchase,
    maybe_later,
};

pub const State = struct {
    cursor_pulse_time: f32 = 0.0,
    selection: usize = 0,

    pub fn reset(self: *State) void {
        self.* = .{};
    }
};

pub fn update(state: *State, dt_ms: i32) Action {
    state.cursor_pulse_time += @as(f32, @floatFromInt(@max(dt_ms, 0))) * 0.001 * 1.1;
    const buttons = overlayButtons();
    window_ui.updateSelectionFromPointer(&state.selection, buttons[0..]);
    if (rl.isKeyPressed(.left) or rl.isKeyPressed(.a)) {
        state.selection = if (state.selection == 0) buttons.len - 1 else state.selection - 1;
    }
    if (rl.isKeyPressed(.right) or rl.isKeyPressed(.d)) {
        state.selection = (state.selection + 1) % buttons.len;
    }
    if (rl.isKeyPressed(.escape)) return .maybe_later;
    if (!window_ui.buttonActivated(buttons[0..], state.selection)) return .none;
    return if (state.selection == 0) .purchase else .maybe_later;
}

pub fn draw(state: *const State, assets: *const window_assets.RuntimeAssets, info: demo_trial.OverlayInfo) void {
    if (!info.visible) return;

    const panel = panelRect();
    rl.drawRectangle(
        @intFromFloat(panel.x),
        @intFromFloat(panel.y),
        @intFromFloat(panel.width),
        @intFromFloat(panel.height),
        rl.Color.init(18, 18, 22, 230),
    );
    rl.drawRectangleLines(
        @intFromFloat(panel.x),
        @intFromFloat(panel.y),
        @intFromFloat(panel.width),
        @intFromFloat(panel.height),
        rl.Color.white,
    );

    const logo = assets.texture(.cl_logo);
    window_ui.drawTextureFit(
        logo,
        rl.Rectangle.init(panel.x + 72.0, panel.y + 22.0, 371.2, 46.4),
        rl.Color.white,
    );
    window_ui.drawSmallText(assets, demo_header_text, panel.x + 131.0, panel.y + 9.0, rl.Color.init(220, 220, 220, 255));

    var remaining_buf: [16]u8 = undefined;
    const remaining = demo_trial.formatDemoTrialTime(info.remaining_ms, remaining_buf[0..]);
    drawBodyLines(assets, panel, info, remaining);

    const buttons = overlayButtons();
    for (buttons, 0..) |button, idx| {
        const hovered = rl.checkCollisionPointRec(rl.getMousePosition(), button.rect);
        window_ui.drawButton(button, idx == state.selection, hovered, assets);
    }
    window_cursor.drawMenuCursor(assets, state.cursor_pulse_time);
}

fn drawBodyLines(
    assets: *const window_assets.RuntimeAssets,
    panel: rl.Rectangle,
    info: demo_trial.OverlayInfo,
    remaining: []const u8,
) void {
    const body_x = panel.x + 26.0;
    const body_color = rl.Color.init(220, 220, 220, 255);
    switch (info.kind) {
        .quest_tier_limit => {
            if (info.show_remaining_line) {
                drawLine(assets, body_x, panel.y + 74.0, quest_completed_text, body_color);
                drawFmtLine(assets, body_x, panel.y + 92.0, quest_limit_remaining_text, remaining, body_color);
                drawLine(assets, body_x, panel.y + 124.0, upgrade_all_features_text, body_color);
                drawLine(assets, body_x, panel.y + 142.0, upgrade_please_text, body_color);
                drawLine(assets, body_x, panel.y + 164.0, upgrade_features_line_text, body_color);
                drawLine(assets, body_x, panel.y + 182.0, upgrade_buy_line_text, body_color);
                drawLine(assets, body_x, panel.y + 200.0, upgrade_trailer_text, body_color);
                return;
            }
            drawLine(assets, body_x, panel.y + 86.0, quest_completed_text, body_color);
            drawLine(assets, body_x, panel.y + 104.0, upgrade_all_features_text, body_color);
            drawLine(assets, body_x, panel.y + 122.0, upgrade_please_text, body_color);
            drawLine(assets, body_x, panel.y + 144.0, upgrade_features_line_text, body_color);
            drawLine(assets, body_x, panel.y + 162.0, upgrade_buy_line_text, body_color);
            drawLine(assets, body_x, panel.y + 180.0, upgrade_trailer_text, body_color);
        },
        .quest_grace_left => {
            drawLine(assets, body_x, panel.y + 73.0, quest_grace_used_up_text, body_color);
            drawFmtLine(assets, body_x, panel.y + 89.0, quest_grace_remaining_text, remaining, body_color);
            drawLine(assets, body_x, panel.y + 111.0, upgrade_all_features_text, body_color);
            drawLine(assets, body_x, panel.y + 127.0, upgrade_process_text, body_color);
            drawLine(assets, body_x, panel.y + 143.0, upgrade_process_cont_text, body_color);
            drawLine(assets, body_x, panel.y + 165.0, upgrade_buy_full_text, body_color);
            drawLine(assets, body_x, panel.y + 181.0, upgrade_buy_line_text, body_color);
            drawLine(assets, body_x, panel.y + 197.0, upgrade_trailer_text, body_color);
        },
        .time_up, .none => {
            drawLine(assets, body_x, panel.y + 80.0, time_up_text, body_color);
            drawLine(assets, body_x, panel.y + 98.0, time_up_all_features_text, body_color);
            drawLine(assets, body_x, panel.y + 116.0, upgrade_easy_text, body_color);
            drawLine(assets, body_x, panel.y + 140.0, upgrade_buy_full_text, body_color);
            drawLine(assets, body_x, panel.y + 158.0, upgrade_buy_line_text, body_color);
            drawLine(assets, body_x, panel.y + 176.0, upgrade_trailer_text, body_color);
        },
    }
}

fn drawLine(assets: *const window_assets.RuntimeAssets, x: f32, y: f32, text: []const u8, color: rl.Color) void {
    window_ui.drawSmallText(assets, text, x, y, color);
}

fn drawFmtLine(
    comptime fmt: []const u8,
    assets: *const window_assets.RuntimeAssets,
    x: f32,
    y: f32,
    remaining: []const u8,
    color: rl.Color,
) void {
    var buf: [192]u8 = undefined;
    const line = std.fmt.bufPrint(buf[0..], fmt, .{remaining}) catch return;
    window_ui.drawSmallText(assets, line, x, y, color);
}

fn panelRect() rl.Rectangle {
    const screen_w = @as(f32, @floatFromInt(rl.getScreenWidth()));
    const screen_h = @as(f32, @floatFromInt(rl.getScreenHeight()));
    return rl.Rectangle.init(screen_w * 0.5 - 256.0, screen_h * 0.5 - 128.0, 512.0, 256.0);
}

fn overlayButtons() [2]window_ui.UiButton {
    const panel = panelRect();
    const button_w: f32 = 145.0;
    const gap: f32 = 20.0;
    const row_w = button_w * 2.0 + gap;
    const x = panel.x + 256.0 - row_w * 0.5;
    const y = panel.y + 214.0;
    return .{
        .{ .label = "Purchase", .rect = rl.Rectangle.init(x, y, button_w, window_ui.button_plate_height) },
        .{ .label = "Maybe later", .rect = rl.Rectangle.init(x + button_w + gap, y, button_w, window_ui.button_plate_height) },
    };
}
